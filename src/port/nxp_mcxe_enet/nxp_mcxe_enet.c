/* nxp_mcxe_enet.c
 *
 * NXP MCX E247 ethernet driver for wolfIP. Standalone: it programs the ENET
 * MAC, the LAN8741 PHY and the eDMA directly and needs no vendor SDK.
 *
 * Build options (see nxp_mcxe_enet.h):
 *   NXP_MCXE_ENET_IRQ          0: polled. 1: receive and transmit complete
 *                              interrupts. The application routes ENET IRQs
 *                              73-75 to nxp_mcxe_enet_irq_handler().
 *   NXP_MCXE_ENET_EDMA         copy frames between the descriptor rings and
 *                              wolfIP buffers with an eDMA channel instead
 *                              of memcpy.
 *   NXP_MCXE_ENET_STATS        count frames and core cycles spent in the
 *                              driver, read with nxp_mcxe_enet_stats_get().
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfIP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#include <stdint.h>
#include <string.h>

#include "config.h"
#include "wolfip.h"
#include "nxp_mcxe_enet.h"
#include "nxp_mcxe_enet_regs.h"

#define ENET_RX_BD_NUM          8U
#define ENET_TX_BD_NUM          4U
/* Receive buffer size: a multiple of 16 that holds a maximum frame, so
 * every frame fits in one descriptor */
#define ENET_BUF_SIZE           1536U
#define ENET_MAX_FRAME_LEN      1518U
#define ENET_MIN_FRAME_LEN      60U
#define ENET_MDC_HZ             2500000U

#define PHY_RESET_PIN           3U      /* PTC3 */
#define PHY_RESET_US            25000U
#define PHY_LINK_POLL_US        10000U
#define PHY_LINK_POLLS          500U    /* 5 seconds */
#define PHY_ID_POLLS            100U
#define PHY_RESET_POLLS         500U

/* IEEE 802.3 clause 22 and LAN8741 registers */
#define PHY_BMCR                0x00U
#define PHY_BSR                 0x01U
#define PHY_ID1                 0x02U
#define PHY_ID2                 0x03U
#define PHY_ANAR                0x04U
#define PHY_SCSR                0x1FU   /* special control/status */
#define PHY_BMCR_RESET          0x8000U
#define PHY_BMCR_ANEN           0x1000U
#define PHY_BMCR_ANRESTART      0x0200U
#define PHY_BSR_LINK            0x0004U
#define PHY_ANAR_ALL            0x01E1U /* 10/100 half/full, 802.3 */
#define PHY_SCSR_ANDONE         0x1000U
#define PHY_SCSR_FULL           0x0010U
#define PHY_SCSR_100M           0x0008U
#define PHY_LAN8741_ID          0x0007C120UL
#define PHY_ID_REV_MASK         0xFFFFFFF0UL

#define MDIO_TIMEOUT_US         1000U
#define ENET_RESET_TIMEOUT_US   1000U
#define EDMA_TIMEOUT_US         1000U
#define TX_TIMEOUT_US           5000U   /* a maximum frame at 10 Mbit/s */

#define ENET_ALIGN16            __attribute__((aligned(16)))
/* Frame buffers. The RM asks for 16-byte alignment, but the enet dma gets
 * stuck with receive FIFO overflow (UDP flood at line rate).
 * 32 seems to work, but using 64 like other nxp enets */
#define ENET_BUF_ALIGN          __attribute__((aligned(64)))
/* Keeps every buffer of the arrays below aligned */
typedef char enet_buf_size_check[((ENET_BUF_SIZE % 64U) == 0U) ? 1 : -1];

/* Legacy buffer descriptor, little-endian with ECR[DBSWP] set */
struct enet_bd {
    volatile uint16_t length;
    volatile uint16_t control;
    volatile uint32_t buffer;
};

/* The ENET DMA and the eDMA read and write these. They must be in memory
 * outside the code cache (SRAM_U). */
static struct enet_bd g_rx_bd[ENET_RX_BD_NUM] ENET_ALIGN16;
static struct enet_bd g_tx_bd[ENET_TX_BD_NUM] ENET_ALIGN16;
static uint8_t g_rx_buf[ENET_RX_BD_NUM][ENET_BUF_SIZE] ENET_BUF_ALIGN;
static uint8_t g_tx_buf[ENET_TX_BD_NUM][ENET_BUF_SIZE] ENET_BUF_ALIGN;

static uint32_t g_rx_idx;
static uint32_t g_tx_idx;
static uint32_t g_core_hz;
static int g_running;
static int g_phy_addr = -1;

#if NXP_MCXE_ENET_IRQ
static volatile uint32_t g_rx_pending;
#endif
static volatile uint32_t g_bus_errors;
#if NXP_MCXE_ENET_STATS
static struct nxp_mcxe_enet_stats g_stats;
#endif

static uint32_t core_clock_hz(void)
{
    uint32_t csr = SCG_CSR;
    uint32_t cfg;
    uint32_t src;

    switch (SCG_CSR_SCS(csr)) {
        case SCG_SCS_SOSC:
            src = NXP_MCXE_ENET_SOSC_HZ;
            break;
        case SCG_SCS_SIRC:
            src = 8000000U;
            break;
        case SCG_SCS_SPLL:
            cfg = SCG_SPLLCFG;
            src = (NXP_MCXE_ENET_SOSC_HZ / (SCG_SPLLCFG_PREDIV(cfg) + 1U)) *
                  (SCG_SPLLCFG_MULT(cfg) + 16U) / 2U;
            break;
        case SCG_SCS_FIRC:
        default:
            src = 48000000U;
            break;
    }
    return src / (SCG_CSR_DIVCORE(csr) + 1U);
}

/* Core cycles in us microseconds. */
static uint32_t us_to_cycles(uint32_t us)
{
    return us * (g_core_hz / 1000000U);
}

static void delay_us(uint32_t us)
{
    uint32_t start = DWT_CYCCNT;
    uint32_t ticks = us_to_cycles(us);

    while ((DWT_CYCCNT - start) < ticks) {
    }
}

static int mdio_wait(void)
{
    uint32_t start = DWT_CYCCNT;
    uint32_t ticks = us_to_cycles(MDIO_TIMEOUT_US);

    while ((ENET_EIR & ENET_EIR_MII) == 0U) {
        if ((DWT_CYCCNT - start) >= ticks)
            return -1;
    }
    ENET_EIR = ENET_EIR_MII;
    return 0;
}

static int mdio_read(uint8_t phy, uint8_t reg, uint16_t *value)
{
    int ret;

    ENET_EIR = ENET_EIR_MII;
    ENET_MMFR = ENET_MMFR_ST | ENET_MMFR_OP_READ | ENET_MMFR_PA(phy) |
                ENET_MMFR_RA(reg) | ENET_MMFR_TA;
    ret = mdio_wait();
    if (ret == 0)
        *value = (uint16_t)(ENET_MMFR & ENET_MMFR_DATA_MASK);
    return ret;
}

static int mdio_write(uint8_t phy, uint8_t reg, uint16_t value)
{
    ENET_EIR = ENET_EIR_MII;
    ENET_MMFR = ENET_MMFR_ST | ENET_MMFR_OP_WRITE | ENET_MMFR_PA(phy) |
                ENET_MMFR_RA(reg) | ENET_MMFR_TA | value;
    return mdio_wait();
}

#if NXP_MCXE_ENET_EDMA
static uint16_t edma_size(uintptr_t addr, uint32_t *bytes)
{
    if ((addr & 3U) == 0U) {
        *bytes = 4U;
        return DMA_SIZE_32BIT;
    }
    if ((addr & 1U) == 0U) {
        *bytes = 2U;
        return DMA_SIZE_16BIT;
    }
    *bytes = 1U;
    return DMA_SIZE_8BIT;
}

/* Copy with the eDMA channel and wait for it. Each side uses the widest
 * access its alignment allows. Copies the bytes past the last whole word with
 * the CPU. Returns 0, or -1 on a transfer error or timeout (nothing is then
 * known about the destination). */
static int edma_copy(uint8_t *dst, const uint8_t *src, uint32_t len)
{
    const uint32_t ch = NXP_MCXE_ENET_EDMA_CH;
    uint32_t sbytes;
    uint32_t dbytes;
    uint32_t body = len & ~3U;
    uint32_t start;
    uint32_t ticks;
    uint16_t ssize = edma_size((uintptr_t)src, &sbytes);
    uint16_t dsize = edma_size((uintptr_t)dst, &dbytes);
    int ret = 0;

    if (body > 0U) {
        DMA_CDNE = (uint8_t)ch;
        DMA_TCD_SADDR(ch) = (uint32_t)(uintptr_t)src;
        DMA_TCD_SOFF(ch) = (uint16_t)sbytes;
        DMA_TCD_ATTR(ch) = (uint16_t)(DMA_ATTR_SSIZE(ssize) |
                                      DMA_ATTR_DSIZE(dsize));
        DMA_TCD_NBYTES(ch) = body;
        DMA_TCD_SLAST(ch) = 0U;
        DMA_TCD_DADDR(ch) = (uint32_t)(uintptr_t)dst;
        DMA_TCD_DOFF(ch) = (uint16_t)dbytes;
        DMA_TCD_CITER(ch) = 1U;
        DMA_TCD_DLASTSGA(ch) = 0U;
        DMA_TCD_BITER(ch) = 1U;
        __asm__ volatile ("dsb" ::: "memory");
        DMA_TCD_CSR(ch) = DMA_CSR_START;

        start = DWT_CYCCNT;
        ticks = us_to_cycles(EDMA_TIMEOUT_US);
        while ((DMA_TCD_CSR(ch) & DMA_CSR_DONE) == 0U) {
            if ((DMA_ERR & (1UL << ch)) != 0U ||
                    (DWT_CYCCNT - start) >= ticks) {
                ret = -1;
                break;
            }
        }
        if ((DMA_ERR & (1UL << ch)) != 0U) {
            DMA_CERR = (uint8_t)ch;
            ret = -1;
        }
        DMA_CDNE = (uint8_t)ch;
        __asm__ volatile ("dmb" ::: "memory");
    }
    if (ret == 0 && body < len)
        memcpy(dst + body, src + body, len - body);
    return ret;
}
#endif

static void frame_copy(uint8_t *dst, const uint8_t *src, uint32_t len)
{
    int done = 0;
#if NXP_MCXE_ENET_STATS
    uint32_t start = DWT_CYCCNT;
#endif

#if NXP_MCXE_ENET_EDMA
    if (len >= NXP_MCXE_ENET_EDMA_MIN && edma_copy(dst, src, len) == 0)
        done = 1;
#endif
    if (!done)
        memcpy(dst, src, len);
#if NXP_MCXE_ENET_STATS
    g_stats.copy_cycles += DWT_CYCCNT - start;
#endif
}

static void enet_pins_init(void)
{
    /* Enable clocks */
    PCC_PORTB |= PCC_CGC;
    PCC_PORTC |= PCC_CGC;
    PCC_PORTD |= PCC_CGC;
    PCC_PORTE |= PCC_CGC;

    /* MDIO needs its GPIO direction set as an output before use (RM 51.1) */
    PORT_PCR(PORTB_BASE, 4) = PORT_PCR_MUX(5);      /* MDIO */
    GPIO_PDDR(GPIOB_BASE) |= (1UL << 4);
    PORT_PCR(PORTC_BASE, 0) = PORT_PCR_MUX(4);      /* RXD1 */
    PORT_PCR(PORTC_BASE, 1) = PORT_PCR_MUX(5);      /* RXD0 */
    PORT_PCR(PORTC_BASE, 17) = PORT_PCR_MUX(5);     /* RX_DV */
    PORT_PCR(PORTD_BASE, 11) = PORT_PCR_MUX(5);     /* TX_CLK (50 MHz ref) */
    /* Transmit pads need high drive strength (RM 51.1) */
    PORT_PCR(PORTC_BASE, 2) = PORT_PCR_MUX(5) | PORT_PCR_DSE;   /* TXD0 */
    PORT_PCR(PORTD_BASE, 7) = PORT_PCR_MUX(5) | PORT_PCR_DSE;   /* TXD1 */
    PORT_PCR(PORTD_BASE, 12) = PORT_PCR_MUX(5) | PORT_PCR_DSE;  /* TX_EN */
    PORT_PCR(PORTE_BASE, 8) = PORT_PCR_MUX(5) | PORT_PCR_DSE;   /* MDC */

    /* Pulse the PHY reset */
    PORT_PCR(PORTC_BASE, PHY_RESET_PIN) = PORT_PCR_MUX(1);
    GPIO_PCOR(GPIOC_BASE) = (1UL << PHY_RESET_PIN);
    GPIO_PDDR(GPIOC_BASE) |= (1UL << PHY_RESET_PIN);
    delay_us(PHY_RESET_US);
    GPIO_PSOR(GPIOC_BASE) = (1UL << PHY_RESET_PIN);
    delay_us(PHY_RESET_US);
}

static void enet_irq_disable(void)
{
    ENET_EIMR = 0U;
    NVIC_ICER(ENET_TX_IRQN / 32U) = (1UL << (ENET_TX_IRQN % 32U));
    NVIC_ICER(ENET_RX_IRQN / 32U) = (1UL << (ENET_RX_IRQN % 32U));
    NVIC_ICER(ENET_ERR_IRQN / 32U) = (1UL << (ENET_ERR_IRQN % 32U));
}

#if NXP_MCXE_ENET_IRQ
static void enet_irq_enable(void)
{
    const uint32_t irqs[3] = { ENET_TX_IRQN, ENET_RX_IRQN, ENET_ERR_IRQN };
    uint32_t i;

    g_rx_pending = 1U;  /* look at the ring once, frames may be waiting */
    ENET_EIR = ENET_EIR_ALL;
    ENET_EIMR = ENET_EIR_RXF | ENET_EIR_TXF | ENET_EIR_EBERR;
    for (i = 0; i < 3U; i++) {
        NVIC_IPR(irqs[i]) = (uint8_t)NXP_MCXE_ENET_IRQ_PRIO;
        NVIC_ICPR(irqs[i] / 32U) = (1UL << (irqs[i] % 32U));
        NVIC_ISER(irqs[i] / 32U) = (1UL << (irqs[i] % 32U));
    }
}

void nxp_mcxe_enet_irq_handler(void)
{
    uint32_t eir = ENET_EIR & ENET_EIMR;

    ENET_EIR = eir;
    /* TXF needs no action: it only wakes tx_wait() from wfi when the
     * transmit ring is full */
    if ((eir & ENET_EIR_RXF) != 0U)
        g_rx_pending = 1U;
    if ((eir & ENET_EIR_EBERR) != 0U)
        g_bus_errors++;
    __asm__ volatile ("dsb" ::: "memory");
}
#endif

static int phy_init(uint8_t phy)
{
    uint16_t id1 = 0;
    uint16_t id2 = 0;
    uint16_t bmcr = PHY_BMCR_RESET;
    uint32_t i;
    int ret = -1;

    for (i = 0; i < PHY_ID_POLLS && ret != 0; i++) {
        if (mdio_read(phy, PHY_ID1, &id1) == 0 &&
                mdio_read(phy, PHY_ID2, &id2) == 0 &&
                ((((uint32_t)id1 << 16) | id2) & PHY_ID_REV_MASK) ==
                PHY_LAN8741_ID) {
            ret = 0;
        }
        else {
            delay_us(1000U);
        }
    }
    if (ret == 0)
        ret = mdio_write(phy, PHY_BMCR, PHY_BMCR_RESET);
    for (i = 0; ret == 0 && (bmcr & PHY_BMCR_RESET) != 0U; i++) {
        if (i >= PHY_RESET_POLLS)
            ret = -1;
        else {
            delay_us(1000U);
            ret = mdio_read(phy, PHY_BMCR, &bmcr);
        }
    }
    if (ret == 0)
        ret = mdio_write(phy, PHY_ANAR, PHY_ANAR_ALL);
    if (ret == 0)
        ret = mdio_write(phy, PHY_BMCR, PHY_BMCR_ANEN | PHY_BMCR_ANRESTART);
    return ret;
}

/* Wait for link and auto-negotiation. Returns 0 with the special
 * control/status register in scsr, or -1 without link. */
static int phy_wait_link(uint8_t phy, uint16_t *scsr)
{
    uint16_t bsr = 0;
    uint32_t polls;

    for (polls = 0; polls < PHY_LINK_POLLS; polls++) {
        if (mdio_read(phy, PHY_BSR, &bsr) == 0 &&
                (bsr & PHY_BSR_LINK) != 0U &&
                mdio_read(phy, PHY_SCSR, scsr) == 0 &&
                (*scsr & PHY_SCSR_ANDONE) != 0U) {
            return 0;
        }
        delay_us(PHY_LINK_POLL_US);
    }
    return -1;
}

static void enet_rings_init(void)
{
    uint32_t i;

    for (i = 0; i < ENET_RX_BD_NUM; i++) {
        g_rx_bd[i].buffer = (uint32_t)(uintptr_t)g_rx_buf[i];
        g_rx_bd[i].length = 0U;
        g_rx_bd[i].control = (uint16_t)(ENET_RXBD_EMPTY |
            ((i == ENET_RX_BD_NUM - 1U) ? ENET_RXBD_WRAP : 0U));
    }
    for (i = 0; i < ENET_TX_BD_NUM; i++) {
        g_tx_bd[i].buffer = (uint32_t)(uintptr_t)g_tx_buf[i];
        g_tx_bd[i].length = 0U;
        g_tx_bd[i].control = (uint16_t)
            ((i == ENET_TX_BD_NUM - 1U) ? ENET_TXBD_WRAP : 0U);
    }
    g_rx_idx = 0U;
    g_tx_idx = 0U;
    __asm__ volatile ("dsb" ::: "memory");
}

static void enet_mac_start(const uint8_t *mac, uint16_t scsr)
{
    uint32_t rcr = ENET_RCR_MAX_FL(ENET_MAX_FRAME_LEN) | ENET_RCR_CRCFWD |
                   ENET_RCR_MII_MODE | ENET_RCR_RMII_MODE;
    int full = ((scsr & PHY_SCSR_FULL) != 0U);

    if ((scsr & PHY_SCSR_100M) == 0U)
        rcr |= ENET_RCR_RMII_10T;
    if (!full)
        rcr |= ENET_RCR_DRT;
    ENET_RCR = rcr;
    ENET_TCR = full ? ENET_TCR_FDEN : 0U;
    ENET_TACC = 0U;
    ENET_RACC = 0U;
    ENET_TFWR = ENET_TFWR_STRFWD;
    ENET_RSFL = 0U;

    ENET_PALR = ((uint32_t)mac[0] << 24) | ((uint32_t)mac[1] << 16) |
                ((uint32_t)mac[2] << 8) | (uint32_t)mac[3];
    ENET_PAUR = (((uint32_t)mac[4] << 8) | (uint32_t)mac[5]) << 16;
    ENET_IAUR = 0U;
    ENET_IALR = 0U;
    ENET_GAUR = 0U;
    ENET_GALR = 0U;

    enet_rings_init();
    ENET_TDSR = (uint32_t)(uintptr_t)g_tx_bd;
    ENET_RDSR = (uint32_t)(uintptr_t)g_rx_bd;
    ENET_MRBR = ENET_BUF_SIZE;

    ENET_EIR = ENET_EIR_ALL;
#if NXP_MCXE_ENET_IRQ
    enet_irq_enable();
#endif
    ENET_ECR = ENET_ECR_ETHEREN | ENET_ECR_DBSWP;
    ENET_RDAR = ENET_RDAR_RDAR;
}

/* Give the current receive descriptor back to the MAC. */
static void rx_release(uint16_t control)
{
    struct enet_bd *bd = &g_rx_bd[g_rx_idx];

    __asm__ volatile ("dmb" ::: "memory");
    bd->control = (uint16_t)((control & ENET_RXBD_WRAP) | ENET_RXBD_EMPTY);
    __asm__ volatile ("dsb" ::: "memory");
    g_rx_idx = (g_rx_idx + 1U) % ENET_RX_BD_NUM;
    ENET_RDAR = ENET_RDAR_RDAR;
}

static int eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct enet_bd *bd;
    uint16_t control;
    uint32_t flen;
    uint32_t n;
    int ret = 0;
    (void)dev;

#if NXP_MCXE_ENET_IRQ
    if (g_rx_pending == 0U)
        return 0;
#else
    if ((ENET_EIR & ENET_EIR_EBERR) != 0U) {
        ENET_EIR = ENET_EIR_EBERR;
        g_bus_errors++;
    }
#endif
    /* Skip errored frames (FIFO overruns, CRC errors) and look at the next
     * descriptor. wolfIP takes 0 as "ring empty", so returning 0 for a bad
     * frame would leave the rest of a full ring for the next poll; under a
     * flood the MAC then fills each freed descriptor with another overrun
     * fragment and the ring never drains. */
    for (n = 0; n < ENET_RX_BD_NUM && ret == 0; n++) {
        bd = &g_rx_bd[g_rx_idx];
        control = bd->control;
#if NXP_MCXE_ENET_IRQ
        if ((control & ENET_RXBD_EMPTY) != 0U) {
            /* Ring drained: wait for the next receive interrupt. Look
             * again after clearing, in case a frame landed in between. */
            g_rx_pending = 0U;
            __asm__ volatile ("dmb" ::: "memory");
            control = bd->control;
            if ((control & ENET_RXBD_EMPTY) == 0U)
                g_rx_pending = 1U;
        }
#endif
        if ((control & ENET_RXBD_EMPTY) != 0U)
            break;

        __asm__ volatile ("dmb" ::: "memory");
        flen = bd->length;
        if ((control & ENET_RXBD_LAST) != 0U &&
                (control & ENET_RXBD_ERRORS) == 0U &&
                flen > 0U && flen <= len && frame != NULL) {
            frame_copy((uint8_t *)frame,
                       (const uint8_t *)(uintptr_t)bd->buffer, flen);
            ret = (int)flen;
        }
        rx_release(control);
    }
    return ret;
}

/* Wait until the MAC has sent the frame in descriptor bd. */
static int tx_wait(const struct enet_bd *bd)
{
    uint32_t start = DWT_CYCCNT;
    uint32_t ticks = us_to_cycles(TX_TIMEOUT_US);
#if NXP_MCXE_ENET_IRQ
    uint32_t primask;
#endif

    while ((bd->control & ENET_TXBD_READY) != 0U) {
        if ((DWT_CYCCNT - start) >= ticks)
            return -1;
#if NXP_MCXE_ENET_IRQ
        /* Sleep until the transmit-complete interrupt. Interrupts are
         * masked around the check so one that fires just before wfi still
         * wakes it (a pending interrupt ends wfi even while masked). */
        __asm__ volatile ("mrs %0, primask" : "=r"(primask));
        __asm__ volatile ("cpsid i" ::: "memory");
        if ((bd->control & ENET_TXBD_READY) != 0U)
            __asm__ volatile ("wfi");
        __asm__ volatile ("msr primask, %0" :: "r"(primask) : "memory");
#endif
    }
    return 0;
}

static int eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    uint32_t idx = g_tx_idx;
    struct enet_bd *bd = &g_tx_bd[idx];
    const uint8_t *data = (const uint8_t *)frame;
    uint32_t tx_len = len;
    (void)dev;

    if (frame == NULL || len == 0U || len > ENET_MAX_FRAME_LEN)
        return -1;
    /* Ring full: wait for the oldest frame rather than fail, since wolfIP
     * does not retry a dropped ACK */
    if ((bd->control & ENET_TXBD_READY) != 0U) {
#if NXP_MCXE_ENET_STATS
        uint32_t start = DWT_CYCCNT;
        int rc = tx_wait(bd);

        g_stats.tx_wait_cycles += DWT_CYCCNT - start;
        g_stats.tx_ring_full++;
        if (rc != 0)
            return -WOLFIP_EAGAIN;
#else
        if (tx_wait(bd) != 0)
            return -WOLFIP_EAGAIN;
#endif
    }

    /* wolfIP reuses its buffer when send() returns, so the frame is copied
     * into the ring and sent in the background */
    frame_copy(g_tx_buf[idx], data, len);
    if (len < ENET_MIN_FRAME_LEN) {
        memset(g_tx_buf[idx] + len, 0, ENET_MIN_FRAME_LEN - len);
        tx_len = ENET_MIN_FRAME_LEN;
    }
    bd->buffer = (uint32_t)(uintptr_t)g_tx_buf[idx];
    bd->length = (uint16_t)tx_len;

    __asm__ volatile ("dmb" ::: "memory");
    bd->control = (uint16_t)(ENET_TXBD_READY | ENET_TXBD_LAST | ENET_TXBD_TC |
        ((idx == ENET_TX_BD_NUM - 1U) ? ENET_TXBD_WRAP : 0U));
    __asm__ volatile ("dsb" ::: "memory");
    ENET_TDAR = ENET_TDAR_TDAR;
    g_tx_idx = (idx + 1U) % ENET_TX_BD_NUM;
    return (int)len;
}

#if NXP_MCXE_ENET_STATS
static int eth_poll_stats(struct wolfIP_ll_dev *dev, void *frame,
                          uint32_t len)
{
    uint32_t start = DWT_CYCCNT;
    int ret = eth_poll(dev, frame, len);
    uint32_t cycles = DWT_CYCCNT - start;

    if (ret > 0) {
        g_stats.rx_cycles += cycles;
        g_stats.rx_bytes += (uint32_t)ret;
        g_stats.rx_frames++;
    }
    else {
        g_stats.idle_cycles += cycles;
    }
    return ret;
}

static int eth_send_stats(struct wolfIP_ll_dev *dev, void *frame,
                          uint32_t len)
{
    uint32_t start = DWT_CYCCNT;
    int ret = eth_send(dev, frame, len);

    g_stats.tx_cycles += DWT_CYCCNT - start;
    if (ret > 0) {
        g_stats.tx_bytes += (uint32_t)ret;
        g_stats.tx_frames++;
    }
    return ret;
}

void nxp_mcxe_enet_stats_get(struct nxp_mcxe_enet_stats *st)
{
    if (st != NULL) {
        memcpy(st, &g_stats, sizeof(*st));
        st->core_hz = g_core_hz;
    }
}

void nxp_mcxe_enet_stats_reset(void)
{
    memset(&g_stats, 0, sizeof(g_stats));
}
#endif

int nxp_mcxe_enet_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    static const uint8_t default_mac[6] = NXP_MCXE_ENET_MAC;
    const uint8_t phy = (uint8_t)NXP_MCXE_ENET_PHY_ADDR;
    uint16_t scsr = 0;
    uint32_t start;
    uint32_t mii_speed;
    uint32_t hold;

    if (ll == NULL)
        return -1;
    if (mac == NULL)
        mac = default_mac;

    g_core_hz = core_clock_hz();
    DEMCR |= DEMCR_TRCENA;
    DWT_CTRL |= DWT_CTRL_CYCCNTENA;

    if (g_running) {
        enet_irq_disable();
        ENET_ECR = 0U;
        g_running = 0;
    }
    g_phy_addr = -1;

    /* The system MPU blocks the ENET and eDMA bus masters by default */
    SYSMPU_CESR &= ~SYSMPU_CESR_VLD;
#if NXP_MCXE_ENET_EDMA
    SIM_PLATCGC |= SIM_PLATCGC_CGCDMA;
#endif

    enet_pins_init();
    PCC_ENET |= PCC_CGC;

    /* Reset the MAC; it clears itself in a few clocks */
    ENET_ECR = ENET_ECR_RESET;
    start = DWT_CYCCNT;
    while ((ENET_ECR & ENET_ECR_RESET) != 0U) {
        if ((DWT_CYCCNT - start) >= us_to_cycles(ENET_RESET_TIMEOUT_US))
            return -4;
    }
    enet_irq_disable();

    /* MDC = core clock / (2 * (MII_SPEED + 1)) <= 2.5 MHz, MDIO hold
     * time >= 10 ns */
    mii_speed = (g_core_hz + 2U * ENET_MDC_HZ - 1U) / (2U * ENET_MDC_HZ) - 1U;
    hold = (10U + 1000000000U / g_core_hz - 1U) / (1000000000U / g_core_hz);
    ENET_MSCR = ENET_MSCR_MII_SPEED(mii_speed) |
                ENET_MSCR_HOLDTIME(hold > 0U ? hold - 1U : 0U);

    if (phy_init(phy) != 0)
        return -2;
    g_phy_addr = (int)phy;
    if (phy_wait_link(phy, &scsr) != 0)
        return -3;

    enet_mac_start(mac, scsr);
    g_running = 1;

    memcpy(ll->mac, mac, 6);
    memset(ll->ifname, 0, sizeof(ll->ifname));
    memcpy(ll->ifname, "eth0", 4);
    ll->mtu = LINK_MTU;
#if NXP_MCXE_ENET_STATS
    ll->poll = eth_poll_stats;
    ll->send = eth_send_stats;
#else
    ll->poll = eth_poll;
    ll->send = eth_send;
#endif
    return 0;
}

int nxp_mcxe_enet_phy_addr(void)
{
    return g_phy_addr;
}

uint16_t nxp_mcxe_enet_phy_read(uint8_t reg)
{
    uint16_t value = 0xFFFFU;

    if (g_phy_addr < 0 || mdio_read((uint8_t)g_phy_addr, reg, &value) != 0)
        return 0xFFFFU;
    return value;
}

uint32_t nxp_mcxe_enet_link_up(void)
{
    uint16_t bsr = 0;

    if (g_phy_addr < 0)
        return 0;
    /* The link bit latches low: the first read reports a past drop */
    if (mdio_read((uint8_t)g_phy_addr, PHY_BSR, &bsr) != 0 ||
            mdio_read((uint8_t)g_phy_addr, PHY_BSR, &bsr) != 0) {
        return 0;
    }
    return ((bsr & PHY_BSR_LINK) != 0U) ? 1U : 0U;
}

uint32_t nxp_mcxe_enet_bus_errors(void)
{
    return g_bus_errors;
}

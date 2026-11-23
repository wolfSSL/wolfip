/* nxp_mcxe_emac.c
 *
 * wolfIP ethernet driver for the EMAC (Synopsys Ethernet QoS) of NXP MCX E
 * parts, written and tested on the MCX E31B. Standalone: it programs the
 * EMAC, its clocks and pins and the LAN8741 PHY directly and needs no vendor
 * SDK.
 *
 * Build options (see nxp_mcxe_emac.h):
 *   NXP_MCXE_EMAC_IRQ          0: polled. 1: receive interrupt. The
 *                              application routes EMAC IRQ 105 to
 *                              nxp_mcxe_emac_irq_handler().
 *   NXP_MCXE_EMAC_STATS        count frames and core cycles spent in the
 *                              driver, read with nxp_mcxe_emac_stats_get().
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
#include "nxp_mcxe_emac.h"
#include "nxp_mcxe_emac_regs.h"

#define EMAC_RX_DESC_NUM        NXP_MCXE_EMAC_RX_DESC
#define EMAC_TX_DESC_NUM        NXP_MCXE_EMAC_TX_DESC
/* Frame buffer size: holds a maximum frame (1522 bytes with a VLAN tag;
 * the FCS is stripped), so every frame fits in one descriptor */
#define EMAC_BUF_SIZE           1536U
#define EMAC_MAX_FRAME_LEN      1518U

/* RMII reference clock and the MAC transmit/receive clocks derived from
 * it: 25 MHz at 100 Mbit/s, 2.5 MHz at 10 Mbit/s */
#define EMAC_RMII_DIV_100M      2U
#define EMAC_RMII_DIV_10M       20U

#define FIRC_HZ                 48000000U

/* FRDM-MCXE31B pads (32 * port + pin) */
#define PAD_PTB4                36U     /* MDIO */
#define PAD_PTB5                37U     /* MDC */
#define PAD_PTC0                64U     /* RXD1 */
#define PAD_PTC1                65U     /* RXD0 */
#define PAD_PTC2                66U     /* TXD0 */
#define PAD_PTC3                67U     /* PHY reset, active low */
#define PAD_PTC17               81U     /* RX_DV */
#define PAD_PTD7                103U    /* TXD1 */
#define PAD_PTD11               107U    /* RMII reference clock in */
#define PAD_PTD12               108U    /* TX_EN */

/* Input muxes (SIUL_IMCR803..808 of the MCX E31B IOMUX attachment) */
#define IMCR_EMAC_MDIO          291U
#define IMCR_EMAC_RX_DV         292U
#define IMCR_EMAC_RXD0          294U
#define IMCR_EMAC_RXD1          295U
#define IMCR_EMAC_RMII_CLK      296U

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
#define CLOCK_TIMEOUT_US        1000U
#define EMAC_RESET_TIMEOUT_US   10000U
#define TX_TIMEOUT_US           5000U   /* a maximum frame at 10 Mbit/s */

/* Frame buffers and descriptors are 64-byte aligned */
#define EMAC_ALIGN              __attribute__((aligned(64)))
/* Keeps every buffer of the arrays below aligned */
typedef char emac_buf_size_check[((EMAC_BUF_SIZE % 64U) == 0U) ? 1 : -1];

/* Normal descriptor, four words. The driver writes the read format; the
 * DMA overwrites it with the write-back format. */
struct emac_desc {
    volatile uint32_t des0;
    volatile uint32_t des1;
    volatile uint32_t des2;
    volatile uint32_t des3;
};

/* The EMAC DMA reads and writes these. They must be in the DTCM, which the
 * core does not cache and the EMAC reaches through its backdoor port (the
 * linker script places this file's .bss there). */
static struct emac_desc g_rx_desc[EMAC_RX_DESC_NUM] EMAC_ALIGN;
static struct emac_desc g_tx_desc[EMAC_TX_DESC_NUM] EMAC_ALIGN;
static uint8_t g_rx_buf[EMAC_RX_DESC_NUM][EMAC_BUF_SIZE] EMAC_ALIGN;
static uint8_t g_tx_buf[EMAC_TX_DESC_NUM][EMAC_BUF_SIZE] EMAC_ALIGN;

static uint32_t g_rx_idx;
static uint32_t g_tx_idx;
static uint32_t g_core_hz;
static int g_running;
static int g_phy_addr = -1;

#if NXP_MCXE_EMAC_IRQ
static volatile uint32_t g_rx_pending;
#endif
static volatile uint32_t g_bus_errors;
#if NXP_MCXE_EMAC_STATS
static struct nxp_mcxe_emac_stats g_stats;
#endif

/* MC_CGM mux 0 source: FIRC or PLL_PHI0 */
static uint32_t mux0_src_hz(void)
{
    uint32_t dv;
    uint32_t rdiv;
    uint32_t odiv2;
    uint32_t vco;

    if (MC_CGM_CSS_SELSTAT(MC_CGM_MUX_CSS(0)) != MC_CGM_SEL_PLL_PHI0)
        return FIRC_HZ;
    dv = PLL_PLLDV;
    rdiv = PLL_PLLDV_RDIV(dv);
    odiv2 = PLL_PLLDV_ODIV2(dv);
    if (rdiv == 0U)
        rdiv = 1U;
    if (odiv2 == 0U)
        odiv2 = 1U;
    vco = (NXP_MCXE_EMAC_FXOSC_HZ / rdiv) * PLL_PLLDV_MFI(dv);
    return vco / odiv2 / (PLL_PLLODIV_DIV(PLL_PLLODIV(0)) + 1U);
}

/* Frequency of mux 0 divider div (core clock, AIPS_PLAT_CLK) */
static uint32_t mux0_clock_hz(uint32_t div)
{
    return mux0_src_hz() /
           (MC_CGM_DC_GET_DIV(MC_CGM_MUX_DC(0, div)) + 1U);
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

/* Wait until (reg & mask) == value, for at most us microseconds. */
static int wait_reg(volatile uint32_t *reg, uint32_t mask, uint32_t value,
                    uint32_t us)
{
    uint32_t start = DWT_CYCCNT;
    uint32_t ticks = us_to_cycles(us);

    while ((*reg & mask) != value) {
        if ((DWT_CYCCNT - start) >= ticks)
            return -1;
    }
    return 0;
}

/* Address of p as the EMAC DMA sees it */
static uint32_t dma_addr(const volatile void *p)
{
    uint32_t addr = (uint32_t)(uintptr_t)p;

    if (addr >= EMAC_DTCM_BASE && addr < EMAC_DTCM_BASE + EMAC_DTCM_SIZE)
        addr += EMAC_DTCM_BACKDOOR_OFFSET;
    return addr;
}

static int in_dtcm(const volatile void *p, uint32_t len)
{
    uint32_t addr = (uint32_t)(uintptr_t)p;

    return (addr >= EMAC_DTCM_BASE &&
            addr + len <= EMAC_DTCM_BASE + EMAC_DTCM_SIZE);
}

static int mdio_wait(void)
{
    return wait_reg(&EMAC_MAC_MDIO_ADDR, EMAC_MDIO_ADDR_GB, 0U,
                    MDIO_TIMEOUT_US);
}

static int mdio_read(uint8_t phy, uint8_t reg, uint16_t *value)
{
    uint32_t cr = EMAC_MAC_MDIO_ADDR & EMAC_MDIO_ADDR_CR_MASK;
    int ret = mdio_wait();

    if (ret == 0) {
        EMAC_MAC_MDIO_ADDR = cr | EMAC_MDIO_ADDR_GOC_READ |
                             EMAC_MDIO_ADDR_PA(phy) |
                             EMAC_MDIO_ADDR_RDA(reg) | EMAC_MDIO_ADDR_GB;
        ret = mdio_wait();
    }
    if (ret == 0)
        *value = (uint16_t)(EMAC_MAC_MDIO_DATA & EMAC_MDIO_DATA_GD_MASK);
    return ret;
}

static int mdio_write(uint8_t phy, uint8_t reg, uint16_t value)
{
    uint32_t cr = EMAC_MAC_MDIO_ADDR & EMAC_MDIO_ADDR_CR_MASK;
    int ret = mdio_wait();

    if (ret == 0) {
        EMAC_MAC_MDIO_DATA = value;
        EMAC_MAC_MDIO_ADDR = cr | EMAC_MDIO_ADDR_GOC_WRITE |
                             EMAC_MDIO_ADDR_PA(phy) |
                             EMAC_MDIO_ADDR_RDA(reg) | EMAC_MDIO_ADDR_GB;
        ret = mdio_wait();
    }
    return ret;
}

/* MDC = CSR clock (AIPS_PLAT_CLK) / divider, at most 2.5 MHz */
static uint32_t mdio_cr(uint32_t csr_hz)
{
    uint32_t mhz = csr_hz / 1000000U;

    if (mhz < 35U)
        return 2U;      /* / 16 */
    if (mhz < 60U)
        return 3U;      /* / 26 */
    if (mhz < 100U)
        return 0U;      /* / 42 */
    if (mhz < 150U)
        return 1U;      /* / 62 */
    if (mhz < 250U)
        return 4U;      /* / 102 */
    return 5U;          /* / 124 */
}

static void frame_copy(uint8_t *dst, const uint8_t *src, uint32_t len)
{
#if NXP_MCXE_EMAC_STATS
    uint32_t start = DWT_CYCCNT;
#endif

    memcpy(dst, src, len);
#if NXP_MCXE_EMAC_STATS
    g_stats.copy_cycles += DWT_CYCCNT - start;
#endif
}

static int emac_clock_enable(void)
{
    int ret = 0;

    if ((MC_ME_PRTN2_COFB1_STAT & MC_ME_EMAC_BIT) == 0U) {
        MC_ME_PRTN2_COFB1_CLKEN |= MC_ME_EMAC_BIT;
        MC_ME_PRTN2_PCONF |= MC_ME_PCONF_PCE;
        MC_ME_PRTN2_PUPD = MC_ME_PUPD_PCUD;
        MC_ME_CTL_KEY = MC_ME_KEY;
        MC_ME_CTL_KEY = MC_ME_INVKEY;
        ret = wait_reg(&MC_ME_PRTN2_PUPD, MC_ME_PUPD_PCUD, 0U,
                       CLOCK_TIMEOUT_US);
        if (ret == 0) {
            ret = wait_reg(&MC_ME_PRTN2_COFB1_STAT, MC_ME_EMAC_BIT,
                           MC_ME_EMAC_BIT, CLOCK_TIMEOUT_US);
        }
    }
    return ret;
}

/* Select the RMII reference clock pin for EMAC clock mux n. The mux only
 * switches while the new source runs. */
static int emac_mux_select(uint32_t n)
{
    int ret = 0;

    if (MC_CGM_CSS_SELSTAT(MC_CGM_MUX_CSS(n)) !=
            MC_CGM_SEL_EMAC_RMII_TX_CLK) {
        ret = wait_reg(&MC_CGM_MUX_CSS(n), MC_CGM_CSS_SWIP, 0U,
                       CLOCK_TIMEOUT_US);
        if (ret == 0) {
            MC_CGM_MUX_CSC(n) =
                MC_CGM_CSC_SELCTL(MC_CGM_SEL_EMAC_RMII_TX_CLK) |
                MC_CGM_CSC_CLK_SW;
            ret = wait_reg(&MC_CGM_MUX_CSS(n), MC_CGM_CSS_CLK_SW,
                           MC_CGM_CSS_CLK_SW, CLOCK_TIMEOUT_US);
        }
        if (ret == 0) {
            ret = wait_reg(&MC_CGM_MUX_CSS(n), MC_CGM_CSS_SWIP, 0U,
                           CLOCK_TIMEOUT_US);
        }
        if (ret == 0 && MC_CGM_CSS_SELSTAT(MC_CGM_MUX_CSS(n)) !=
                MC_CGM_SEL_EMAC_RMII_TX_CLK) {
            ret = -1;
        }
    }
    return ret;
}

static int emac_mux_div(uint32_t n, uint32_t div)
{
    MC_CGM_MUX_DC(n, 0) = MC_CGM_DC_DE | MC_CGM_DC_DIV(div - 1U);
    return wait_reg(&MC_CGM_MUX_DIV_UPD_STAT(n), MC_CGM_DIV_UPD_STAT_BUSY,
                    0U, CLOCK_TIMEOUT_US);
}

/* MAC receive and transmit clocks for the link speed */
static int emac_rmii_clocks(uint32_t div)
{
    int ret = emac_mux_div(MC_CGM_MUX_EMAC_RX, div);

    if (ret == 0)
        ret = emac_mux_div(MC_CGM_MUX_EMAC_TX, div);
    return ret;
}

static int emac_clocks_init(void)
{
    int ret = emac_mux_select(MC_CGM_MUX_EMAC_RX);

    if (ret == 0)
        ret = emac_mux_select(MC_CGM_MUX_EMAC_TX);
    if (ret == 0)
        ret = emac_mux_select(MC_CGM_MUX_EMAC_TS);
    if (ret == 0)
        ret = emac_rmii_clocks(EMAC_RMII_DIV_100M);
    if (ret == 0)
        ret = emac_mux_div(MC_CGM_MUX_EMAC_TS, EMAC_RMII_DIV_100M);
    return ret;
}

static void emac_pins_init(void)
{
    const uint32_t out = SIUL2_MSCR_OBE | SIUL2_MSCR_SRC;
    const uint32_t in = SIUL2_MSCR_IBE;

    SIUL2_MSCR(PAD_PTB4) = SIUL2_MSCR_SSS(5) | SIUL2_MSCR_OBE | in;
    SIUL2_IMCR(IMCR_EMAC_MDIO) = 1U;
    SIUL2_MSCR(PAD_PTB5) = SIUL2_MSCR_SSS(7) | SIUL2_MSCR_OBE;  /* MDC */
    SIUL2_MSCR(PAD_PTC2) = SIUL2_MSCR_SSS(5) | out;             /* TXD0 */
    SIUL2_MSCR(PAD_PTD7) = SIUL2_MSCR_SSS(5) | out;             /* TXD1 */
    SIUL2_MSCR(PAD_PTD12) = SIUL2_MSCR_SSS(5) | out;            /* TX_EN */
    SIUL2_MSCR(PAD_PTC17) = in;                                 /* RX_DV */
    SIUL2_IMCR(IMCR_EMAC_RX_DV) = 1U;
    SIUL2_MSCR(PAD_PTC1) = in;                                  /* RXD0 */
    SIUL2_IMCR(IMCR_EMAC_RXD0) = 1U;
    SIUL2_MSCR(PAD_PTC0) = in;                                  /* RXD1 */
    SIUL2_IMCR(IMCR_EMAC_RXD1) = 1U;
    SIUL2_MSCR(PAD_PTD11) = in;                                 /* REF_CLK */
    SIUL2_IMCR(IMCR_EMAC_RMII_CLK) = 1U;

    /* Pulse the PHY reset */
    SIUL2_GPDO(PAD_PTC3) = 0U;
    SIUL2_MSCR(PAD_PTC3) = SIUL2_MSCR_SSS(0) | out | in;
    delay_us(PHY_RESET_US);
    SIUL2_GPDO(PAD_PTC3) = 1U;
    delay_us(PHY_RESET_US);
}

static void emac_irq_disable(void)
{
    EMAC_DMA_CH0_INT_EN = 0U;
    NVIC_ICER(EMAC_IRQN / 32U) = (1UL << (EMAC_IRQN % 32U));
}

#if NXP_MCXE_EMAC_IRQ
static void emac_irq_enable(void)
{
    g_rx_pending = 1U;  /* look at the ring once, frames may be waiting */
    EMAC_DMA_CH0_STAT = EMAC_DMA_INT_RI | EMAC_DMA_INT_FBE |
                        EMAC_DMA_INT_NI | EMAC_DMA_INT_AI;
    EMAC_DMA_CH0_INT_EN = EMAC_DMA_INT_RI | EMAC_DMA_INT_NI |
                          EMAC_DMA_INT_FBE | EMAC_DMA_INT_AI;
    NVIC_IPR(EMAC_IRQN) = (uint8_t)NXP_MCXE_EMAC_IRQ_PRIO;
    NVIC_ICPR(EMAC_IRQN / 32U) = (1UL << (EMAC_IRQN % 32U));
    NVIC_ISER(EMAC_IRQN / 32U) = (1UL << (EMAC_IRQN % 32U));
}

void nxp_mcxe_emac_irq_handler(void)
{
    uint32_t stat = EMAC_DMA_CH0_STAT & (EMAC_DMA_INT_RI | EMAC_DMA_INT_FBE |
                                         EMAC_DMA_INT_NI | EMAC_DMA_INT_AI);

    EMAC_DMA_CH0_STAT = stat;
    if ((stat & EMAC_DMA_INT_RI) != 0U)
        g_rx_pending = 1U;
    if ((stat & EMAC_DMA_INT_FBE) != 0U)
        g_bus_errors++;
    __asm__ volatile ("dsb" ::: "memory");
}
#endif

static void emac_stop(void)
{
    emac_irq_disable();
    EMAC_MAC_CONFIG &= ~(EMAC_MAC_CONFIG_RE | EMAC_MAC_CONFIG_TE);
    EMAC_DMA_CH0_TX_CTRL &= ~EMAC_DMA_TX_CTRL_ST;
    EMAC_DMA_CH0_RX_CTRL &= ~EMAC_DMA_RX_CTRL_SR;
}

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

/* Hand receive descriptor idx (back) to the DMA. The write-back overwrote
 * the buffer address, so the whole read format is rewritten. */
static void rx_desc_arm(uint32_t idx)
{
    struct emac_desc *d = &g_rx_desc[idx];

    d->des0 = dma_addr(g_rx_buf[idx]);
    d->des1 = 0U;
    d->des2 = 0U;
    __asm__ volatile ("dmb" ::: "memory");
    d->des3 = EMAC_DES3_OWN | EMAC_RDES3_BUF1V
#if NXP_MCXE_EMAC_IRQ
              | EMAC_RDES3_IOC
#endif
              ;
}

static void emac_rings_init(void)
{
    uint32_t i;

    for (i = 0; i < EMAC_RX_DESC_NUM; i++)
        rx_desc_arm(i);
    for (i = 0; i < EMAC_TX_DESC_NUM; i++) {
        g_tx_desc[i].des0 = 0U;
        g_tx_desc[i].des1 = 0U;
        g_tx_desc[i].des2 = 0U;
        g_tx_desc[i].des3 = 0U;
    }
    g_rx_idx = 0U;
    g_tx_idx = 0U;
    __asm__ volatile ("dsb" ::: "memory");
}

static void emac_start(const uint8_t *mac, uint16_t scsr)
{
    uint32_t hw = EMAC_MAC_HW_FEATURE1;
    uint32_t txq = (128UL << EMAC_HW_FEATURE1_TXFIFOSIZE(hw)) / 256U;
    uint32_t rxq = (128UL << EMAC_HW_FEATURE1_RXFIFOSIZE(hw)) / 256U;
    uint32_t cfg = EMAC_MAC_CONFIG_PS | EMAC_MAC_CONFIG_ACS |
                   EMAC_MAC_CONFIG_CST;

    if ((scsr & PHY_SCSR_100M) != 0U)
        cfg |= EMAC_MAC_CONFIG_FES;
    if ((scsr & PHY_SCSR_FULL) != 0U)
        cfg |= EMAC_MAC_CONFIG_DM;

    /* DMA channel 0: 16-byte descriptors in a ring, one buffer each */
    emac_rings_init();
    EMAC_DMA_CH0_CTRL = 0U;
    EMAC_DMA_CH0_TXDESC_RLEN = EMAC_TX_DESC_NUM - 1U;
    EMAC_DMA_CH0_RXDESC_RLEN = EMAC_RX_DESC_NUM - 1U;
    EMAC_DMA_CH0_TXDESC_LIST = dma_addr(&g_tx_desc[0]);
    EMAC_DMA_CH0_RXDESC_LIST = dma_addr(&g_rx_desc[0]);
    EMAC_DMA_CH0_TXDESC_TAIL = dma_addr(&g_tx_desc[0]);
    EMAC_DMA_CH0_RXDESC_TAIL = dma_addr(&g_rx_desc[EMAC_RX_DESC_NUM]);
    EMAC_DMA_SYSBUS_MODE = NXP_MCXE_EMAC_SYSBUS;
    EMAC_DMA_CH0_TX_CTRL = EMAC_DMA_TX_CTRL_TXPBL(NXP_MCXE_EMAC_PBL)
#if NXP_MCXE_EMAC_TX_OSF
                           | EMAC_DMA_TX_CTRL_OSF
#endif
                           ;
    EMAC_DMA_CH0_RX_CTRL = EMAC_DMA_RX_CTRL_RXPBL(NXP_MCXE_EMAC_PBL) |
                           EMAC_DMA_RX_CTRL_RBSZ(EMAC_BUF_SIZE);

    /* MTL: queue 0 gets the whole FIFOs, store and forward */
    EMAC_MTL_TXQ0_OP_MODE = EMAC_MTL_TXQ_OP_TSF | EMAC_MTL_TXQ_OP_TXQEN |
                            EMAC_MTL_TXQ_OP_TQS(txq - 1U);
    EMAC_MTL_RXQ0_OP_MODE = EMAC_MTL_RXQ_OP_RSF |
                            EMAC_MTL_RXQ_OP_RQS(rxq - 1U);

    /* MAC. The address registers latch on the write of the low word. */
    EMAC_MAC_ADDR0_HIGH = EMAC_MAC_ADDR_HIGH_AE |
                          ((uint32_t)mac[5] << 8) | (uint32_t)mac[4];
    EMAC_MAC_ADDR0_LOW = ((uint32_t)mac[3] << 24) | ((uint32_t)mac[2] << 16) |
                         ((uint32_t)mac[1] << 8) | (uint32_t)mac[0];
    EMAC_MAC_PKT_FILTER = EMAC_MAC_PKT_FILTER_PM;
    EMAC_MAC_RXQ_CTRL0 = EMAC_MAC_RXQ_CTRL0_RXQ0EN_DCB;
    EMAC_MAC_INT_ENABLE = 0U;
    EMAC_MMC_RX_INT_MASK = 0xFFFFFFFFUL;
    EMAC_MMC_TX_INT_MASK = 0xFFFFFFFFUL;
    EMAC_MMC_FPE_TX_INT_MASK = 0xFFFFFFFFUL;
    EMAC_MMC_FPE_RX_INT_MASK = 0xFFFFFFFFUL;
    EMAC_MAC_CONFIG = cfg;

    EMAC_DMA_CH0_STAT = 0xFFFFFFFFUL;
#if NXP_MCXE_EMAC_IRQ
    emac_irq_enable();
#endif
    /* Start the DMA before the MAC receiver, so that frames do not fill
     * the receive FIFO first */
    EMAC_DMA_CH0_TX_CTRL |= EMAC_DMA_TX_CTRL_ST;
    EMAC_DMA_CH0_RX_CTRL |= EMAC_DMA_RX_CTRL_SR;
    EMAC_MAC_CONFIG = cfg | EMAC_MAC_CONFIG_TE | EMAC_MAC_CONFIG_RE;
}

/* Give the current receive descriptor back to the DMA and tell it, in case
 * it suspended on a full ring. */
static void rx_release(void)
{
    rx_desc_arm(g_rx_idx);
    __asm__ volatile ("dsb" ::: "memory");
    g_rx_idx = (g_rx_idx + 1U) % EMAC_RX_DESC_NUM;
    EMAC_DMA_CH0_RXDESC_TAIL = dma_addr(&g_rx_desc[EMAC_RX_DESC_NUM]);
}

static int eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct emac_desc *d;
    uint32_t des3;
    uint32_t flen;
    uint32_t n;
    int ret = 0;
    (void)dev;

#if NXP_MCXE_EMAC_IRQ
    if (g_rx_pending == 0U)
        return 0;
#else
    if ((EMAC_DMA_CH0_STAT & EMAC_DMA_INT_FBE) != 0U) {
        EMAC_DMA_CH0_STAT = EMAC_DMA_INT_FBE | EMAC_DMA_INT_AI;
        g_bus_errors++;
    }
#endif
    /* Skip errored frames (FIFO overruns, CRC errors) and look at the next
     * descriptor. wolfIP takes 0 as "ring empty", so returning 0 for a bad
     * frame would leave the rest of a full ring for the next poll. */
    for (n = 0; n < EMAC_RX_DESC_NUM && ret == 0; n++) {
        d = &g_rx_desc[g_rx_idx];
        des3 = d->des3;
#if NXP_MCXE_EMAC_IRQ
        if ((des3 & EMAC_DES3_OWN) != 0U) {
            /* Ring drained: wait for the next receive interrupt. Look
             * again after clearing, in case a frame landed in between. */
            g_rx_pending = 0U;
            __asm__ volatile ("dmb" ::: "memory");
            des3 = d->des3;
            if ((des3 & EMAC_DES3_OWN) == 0U)
                g_rx_pending = 1U;
        }
#endif
        if ((des3 & EMAC_DES3_OWN) != 0U)
            break;

        __asm__ volatile ("dmb" ::: "memory");
        flen = des3 & EMAC_RDES3_PL_MASK;
        if ((des3 & (EMAC_RDES3_FD | EMAC_RDES3_LD | EMAC_RDES3_ES |
                     EMAC_RDES3_CTXT)) == (EMAC_RDES3_FD | EMAC_RDES3_LD) &&
                flen > 0U && flen <= len && flen <= EMAC_BUF_SIZE &&
                frame != NULL) {
            frame_copy((uint8_t *)frame, g_rx_buf[g_rx_idx], flen);
            ret = (int)flen;
        }
#if NXP_MCXE_EMAC_STATS
        else {
            g_stats.rx_errors++;
        }
#endif
        rx_release();
    }
    return ret;
}

/* Wait until the DMA has sent the frame in descriptor d. This polls rather
 * than sleeping in wfi: the core cycle counter stops while the core sleeps,
 * so a transmitter that never raises its interrupt would never time out. */
static int tx_wait(const struct emac_desc *d)
{
    uint32_t start = DWT_CYCCNT;
    uint32_t ticks = us_to_cycles(TX_TIMEOUT_US);

    while ((d->des3 & EMAC_DES3_OWN) != 0U) {
        if ((DWT_CYCCNT - start) >= ticks)
            return -1;
    }
    return 0;
}

static int eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    uint32_t idx = g_tx_idx;
    uint32_t next = (idx + 1U) % EMAC_TX_DESC_NUM;
    struct emac_desc *d = &g_tx_desc[idx];
    int rc;
#if NXP_MCXE_EMAC_STATS
    uint32_t start;
#endif
    (void)dev;

    if (frame == NULL || len == 0U || len > EMAC_MAX_FRAME_LEN)
        return -1;
    /* Ring full: wait for the oldest frame rather than fail, since wolfIP
     * does not retry a dropped ACK */
    if ((d->des3 & EMAC_DES3_OWN) != 0U) {
#if NXP_MCXE_EMAC_STATS
        start = DWT_CYCCNT;
        rc = tx_wait(d);
        g_stats.tx_wait_cycles += DWT_CYCCNT - start;
        g_stats.tx_ring_full++;
#else
        rc = tx_wait(d);
#endif
        if (rc != 0)
            return -WOLFIP_EAGAIN;
    }

    /* wolfIP reuses its buffer when send() returns, so the frame is copied
     * into the ring and sent in the background. The MAC pads short frames
     * and appends the FCS. */
    frame_copy(g_tx_buf[idx], (const uint8_t *)frame, len);
    d->des0 = dma_addr(g_tx_buf[idx]);
    d->des1 = 0U;
    d->des2 = EMAC_TDES2_B1L(len);
    __asm__ volatile ("dmb" ::: "memory");
    d->des3 = EMAC_DES3_OWN | EMAC_TDES3_FD | EMAC_TDES3_LD |
              EMAC_TDES3_FL(len);
    __asm__ volatile ("dsb" ::: "memory");
    g_tx_idx = next;
    /* The tail points past the last descriptor handed over: the end of
     * the ring after the last one */
    EMAC_DMA_CH0_TXDESC_TAIL = dma_addr((next == 0U) ?
        &g_tx_desc[EMAC_TX_DESC_NUM] : &g_tx_desc[next]);
    return (int)len;
}

#if NXP_MCXE_EMAC_STATS
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

void nxp_mcxe_emac_stats_get(struct nxp_mcxe_emac_stats *st)
{
    if (st != NULL) {
        memcpy(st, &g_stats, sizeof(*st));
        st->core_hz = g_core_hz;
    }
}

void nxp_mcxe_emac_stats_reset(void)
{
    memset(&g_stats, 0, sizeof(g_stats));
}
#endif

int nxp_mcxe_emac_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    static const uint8_t default_mac[6] = NXP_MCXE_EMAC_MAC;
    const uint8_t phy = (uint8_t)NXP_MCXE_EMAC_PHY_ADDR;
    uint16_t scsr = 0;
    int ret = 0;

    if (ll == NULL)
        return -1;
    if (mac == NULL)
        mac = default_mac;
    /* The core caches SRAM but not the DTCM, and the driver does no cache
     * maintenance */
    if ((SCB_CCR & SCB_CCR_DC) != 0U &&
            (!in_dtcm(g_rx_desc, sizeof(g_rx_desc)) ||
             !in_dtcm(g_tx_desc, sizeof(g_tx_desc)) ||
             !in_dtcm(g_rx_buf, sizeof(g_rx_buf)) ||
             !in_dtcm(g_tx_buf, sizeof(g_tx_buf)))) {
        return -5;
    }

    g_core_hz = mux0_clock_hz(MC_CGM_DIV_CORE);
    DWT_LAR = DWT_LAR_KEY;
    DEMCR |= DEMCR_TRCENA;
    DWT_CTRL |= DWT_CTRL_CYCCNTENA;

    if (g_running) {
        emac_stop();
        g_running = 0;
    }
    g_phy_addr = -1;

    emac_pins_init();
    /* Switch the EMAC clocks to the RMII reference clock before the EMAC
     * clock is enabled, as the vendor SDK does */
    if (emac_clocks_init() != 0 || emac_clock_enable() != 0)
        return -4;
    /* RMII, sampled by the EMAC reset below */
    DCM_GPR_DCMRWF1 = (DCM_GPR_DCMRWF1 & ~DCM_GPR_DCMRWF1_MAC_CONF_SEL_MASK) |
                      DCM_GPR_DCMRWF1_MAC_CONF_SEL_RMII;

    /* Reset the MAC and DMA. Like the vendor driver, select the 10/100 port
     * while the reset runs: it completes only with the port clocks running */
    EMAC_DMA_MODE |= EMAC_DMA_MODE_SWR;
    EMAC_MAC_CONFIG = EMAC_MAC_CONFIG_PS | EMAC_MAC_CONFIG_FES |
                      EMAC_MAC_CONFIG_DM;
    if (wait_reg(&EMAC_DMA_MODE, EMAC_DMA_MODE_SWR, 0U,
                 EMAC_RESET_TIMEOUT_US) != 0) {
        return -4;
    }
    emac_irq_disable();
    EMAC_MAC_MDIO_ADDR = EMAC_MDIO_ADDR_CR(
        mdio_cr(mux0_clock_hz(MC_CGM_DIV_AIPS_PLAT)));

    if (phy_init(phy) != 0)
        return -2;
    g_phy_addr = (int)phy;
    if (phy_wait_link(phy, &scsr) != 0)
        return -3;
    if ((scsr & PHY_SCSR_100M) == 0U)
        ret = emac_rmii_clocks(EMAC_RMII_DIV_10M);
    if (ret != 0)
        return -4;

    emac_start(mac, scsr);
    g_running = 1;

    memcpy(ll->mac, mac, 6);
    memset(ll->ifname, 0, sizeof(ll->ifname));
    memcpy(ll->ifname, "eth0", 4);
    ll->mtu = LINK_MTU;
#if NXP_MCXE_EMAC_STATS
    ll->poll = eth_poll_stats;
    ll->send = eth_send_stats;
#else
    ll->poll = eth_poll;
    ll->send = eth_send;
#endif
    return 0;
}

int nxp_mcxe_emac_phy_addr(void)
{
    return g_phy_addr;
}

uint16_t nxp_mcxe_emac_phy_read(uint8_t reg)
{
    uint16_t value = 0xFFFFU;

    if (g_phy_addr < 0 || mdio_read((uint8_t)g_phy_addr, reg, &value) != 0)
        return 0xFFFFU;
    return value;
}

uint32_t nxp_mcxe_emac_link_up(void)
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

uint32_t nxp_mcxe_emac_bus_errors(void)
{
    return g_bus_errors;
}

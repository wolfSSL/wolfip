/* stm32h5_eth.c
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
#include "stm32h5_eth.h"

#if TZEN_ENABLED
#define ETH_BASE            0x50028000UL  /* Secure alias */
#else
#define ETH_BASE            0x40028000UL  /* Non-secure alias */
#endif
#define ETH_REG(offset)     (*(volatile uint32_t *)(ETH_BASE + (offset)))
#define ETH_TPDR            ETH_REG(0x1180U)

/* MAC registers */
#define ETH_MACCR           ETH_REG(0x0000U)
#define ETH_MACPFR          ETH_REG(0x0004U)
#define ETH_MACA0HR         ETH_REG(0x0300U)
#define ETH_MACA0LR         ETH_REG(0x0304U)

/* MTL registers */
#define ETH_MTLTXQOMR       ETH_REG(0x0D00U)
#define ETH_MTLRXQOMR       ETH_REG(0x0D30U)

/* DMA registers */
#define ETH_DMAMR           ETH_REG(0x1000U)
#define ETH_DMASBMR         ETH_REG(0x1004U)
#define ETH_DMACTXCR        ETH_REG(0x1104U)
#define ETH_DMACRXCR        ETH_REG(0x1108U)
#define ETH_DMACTXDLAR      ETH_REG(0x1114U)
#define ETH_DMACRXDLAR      ETH_REG(0x111CU)
#define ETH_DMACTXDTPR      ETH_REG(0x1120U)
#define ETH_DMACRXDTPR      ETH_REG(0x1128U)
#define ETH_DMACTXRLR       ETH_REG(0x112CU)
#define ETH_DMACRXRLR       ETH_REG(0x1130U)
#define ETH_DMACSR          ETH_REG(0x1160U)
#define ETH_MACMDIOAR       ETH_REG(0x0200U)
#define ETH_MACMDIODR       ETH_REG(0x0204U)

/* MAC control bits */
#define ETH_MACCR_RE        (1U << 0)
#define ETH_MACCR_TE        (1U << 1)
#define ETH_MACCR_DM        (1U << 13)
#define ETH_MACCR_FES       (1U << 14)

/* DMA bits */
#define ETH_DMAMR_SWR       (1U << 0)
#define ETH_DMASBMR_FB      (1U << 0)
#define ETH_DMASBMR_AAL     (1U << 12)

#define ETH_DMACTXCR_ST     (1U << 0)
#define ETH_DMACTXCR_OSF    (1U << 4)
#define ETH_DMACRXCR_SR     (1U << 0)
#define ETH_DMACRXCR_RBSZ_SHIFT 1
#define ETH_DMACSR_TBU      (1U << 2)
#define ETH_DMACTXCR_TPBL_SHIFT 16
#define ETH_DMACTXCR_TPBL(val) (((uint32_t)(val) & 0x3FU) << ETH_DMACTXCR_TPBL_SHIFT)
#define ETH_DMACRXCR_RPBL_SHIFT 16
#define ETH_DMACRXCR_RPBL(val) (((uint32_t)(val) & 0x3FU) << ETH_DMACRXCR_RPBL_SHIFT)

/* MTL bits */
#define ETH_MTLTXQOMR_FTQ           (1U << 0)
#define ETH_MTLTXQOMR_TSF           (1U << 1)
#define ETH_MTLTXQOMR_TXQEN_SHIFT   2
#define ETH_MTLTXQOMR_TXQEN_ENABLE  (2U << ETH_MTLTXQOMR_TXQEN_SHIFT)
#define ETH_MTLTXQOMR_MASK          0x00000072U
#define ETH_MTLRXQOMR_RSF           (1U << 5)
#define ETH_MTLRXQOMR_MASK          0x0000007BU

#define ETH_MACMDIOAR_MB        (1U << 0)
#define ETH_MACMDIOAR_GOC_SHIFT 2
#define ETH_MACMDIOAR_GOC_WRITE 0x1U
#define ETH_MACMDIOAR_GOC_READ  0x3U
#define ETH_MACMDIOAR_CR_SHIFT  8
#define ETH_MACMDIOAR_RDA_SHIFT 16
#define ETH_MACMDIOAR_PA_SHIFT  21

#define PHY_REG_BCR      0x00U
#define PHY_REG_BSR      0x01U
#define PHY_REG_ID1      0x02U
#define PHY_REG_ANAR     0x04U
#define PHY_REG_SCSR     0x1FU

#define PHY_BCR_RESET            (1U << 15)
#define PHY_BCR_SPEED_100        (1U << 13)
#define PHY_BCR_AUTONEG_ENABLE   (1U << 12)
#define PHY_BCR_POWER_DOWN       (1U << 11)
#define PHY_BCR_ISOLATE          (1U << 10)
#define PHY_BCR_RESTART_AUTONEG  (1U << 9)
#define PHY_BCR_FULL_DUPLEX      (1U << 8)

#define PHY_BSR_LINK_STATUS      (1U << 2)
#define PHY_BSR_AUTONEG_COMPLETE (1U << 5)
#define PHY_BSR_10_HALF          (1U << 11)
#define PHY_BSR_10_FULL          (1U << 12)
#define PHY_BSR_100_HALF         (1U << 13)
#define PHY_BSR_100_FULL         (1U << 14)

#define PHY_ANAR_DEFAULT 0x01E1U

struct eth_desc {
    volatile uint32_t des0;
    volatile uint32_t des1;
    volatile uint32_t des2;
    volatile uint32_t des3;
};

#define ETH_TDES3_OWN      (1U << 31)
#define ETH_TDES3_FD       (1U << 29)
#define ETH_TDES3_LD       (1U << 28)
#define ETH_TDES2_B1L_MASK (0x3FFFU)
#define ETH_TDES3_FL_MASK  (0x7FFFU)

#define ETH_RDES3_OWN      (1U << 31)
#define ETH_RDES3_IOC      (1U << 30)
#define ETH_RDES3_BUF1V    (1U << 24)
#define ETH_RDES3_FS       (1U << 29)
#define ETH_RDES3_LS       (1U << 28)
#define ETH_RDES3_PL_MASK  (0x3FFFU)

#define RX_DESC_COUNT  4U
#define TX_DESC_COUNT  3U
#define RX_BUF_SIZE    LINK_MTU
#define TX_BUF_SIZE    LINK_MTU
#define FRAME_MIN_LEN  60U
#define DMA_TPBL       32U
#define DMA_RPBL       32U

/* When TZEN=1, place Ethernet buffers in non-secure SRAM section for DMA access */
#if TZEN_ENABLED
#define ETH_SECTION __attribute__((section(".eth_buffers")))
#else
#define ETH_SECTION
#endif

static struct eth_desc rx_ring[RX_DESC_COUNT] __attribute__((aligned(32))) ETH_SECTION;
static struct eth_desc tx_ring[TX_DESC_COUNT] __attribute__((aligned(32))) ETH_SECTION;
static uint8_t rx_buffers[RX_DESC_COUNT][RX_BUF_SIZE] __attribute__((aligned(32))) ETH_SECTION;
static uint8_t tx_buffers[TX_DESC_COUNT][TX_BUF_SIZE] __attribute__((aligned(32))) ETH_SECTION;
static uint8_t rx_staging_buffer[RX_BUF_SIZE] __attribute__((aligned(32)));

static uint32_t rx_idx;
static uint32_t tx_idx;
static int32_t phy_addr = -1;

static int eth_hw_reset(void)
{
    uint32_t timeout = 1000000U;

    /* DMA software reset */
    ETH_DMAMR |= ETH_DMAMR_SWR;
    while ((ETH_DMAMR & ETH_DMAMR_SWR) && (timeout > 0U)) {
        timeout--;
    }
    return (timeout > 0U) ? 0 : -1;
}

static void eth_trigger_tx(void)
{
    ETH_TPDR = 0U;
    __asm volatile ("dsb sy" ::: "memory");
}

static uint16_t eth_mdio_read(uint32_t phy, uint32_t reg);
static void eth_mdio_write(uint32_t phy, uint32_t reg, uint16_t value);

static void eth_config_mac(const uint8_t mac[6])
{
    uint32_t maccr = ETH_MACCR;
    maccr &= ~(ETH_MACCR_DM | ETH_MACCR_FES);
    maccr |= ETH_MACCR_DM | ETH_MACCR_FES;
    ETH_MACCR = maccr;
    /* Enable promiscuous mode for debugging (bit 0 = PR) */
    ETH_MACPFR = (1u << 0);  /* Promiscuous mode */
    ETH_MACA0HR = ((uint32_t)mac[5] << 8) | (uint32_t)mac[4];
    ETH_MACA0LR = ((uint32_t)mac[3] << 24) |
                  ((uint32_t)mac[2] << 16) |
                  ((uint32_t)mac[1] << 8) |
                   (uint32_t)mac[0];
}

static void eth_config_speed_duplex(void)
{
    uint32_t maccr;
    uint16_t bsr;

    if (phy_addr < 0) return;

    maccr = ETH_MACCR;
    maccr &= ~(ETH_MACCR_FES | ETH_MACCR_DM);
    bsr = eth_mdio_read((uint32_t)phy_addr, PHY_REG_BSR);
    bsr |= eth_mdio_read((uint32_t)phy_addr, PHY_REG_BSR);

    if ((bsr & PHY_BSR_100_FULL) != 0U) {
        maccr |= ETH_MACCR_FES | ETH_MACCR_DM;
    } else if ((bsr & PHY_BSR_100_HALF) != 0U) {
        maccr |= ETH_MACCR_FES;
    } else if ((bsr & PHY_BSR_10_FULL) != 0U) {
        maccr |= ETH_MACCR_DM;
    }
    ETH_MACCR = maccr;
}

static void eth_config_mtl(void)
{
    uint32_t txqomr = ETH_MTLTXQOMR;
    uint32_t rxqomr = ETH_MTLRXQOMR;

    txqomr &= ~ETH_MTLTXQOMR_MASK;
    txqomr |= (ETH_MTLTXQOMR_TSF | ETH_MTLTXQOMR_TXQEN_ENABLE);
    ETH_MTLTXQOMR = txqomr;

    rxqomr &= ~ETH_MTLRXQOMR_MASK;
    rxqomr |= ETH_MTLRXQOMR_RSF;
    ETH_MTLRXQOMR = rxqomr;
}

static void eth_init_desc(void)
{
    uint32_t i;

    /* Step 1: Clear all descriptors (like HAL does) */
    for (i = 0; i < TX_DESC_COUNT; i++) {
        tx_ring[i].des0 = 0;
        tx_ring[i].des1 = 0;
        tx_ring[i].des2 = 0;
        tx_ring[i].des3 = 0;
    }
    for (i = 0; i < RX_DESC_COUNT; i++) {
        rx_ring[i].des0 = 0;
        rx_ring[i].des1 = 0;
        rx_ring[i].des2 = 0;
        rx_ring[i].des3 = 0;
    }
    rx_idx = 0;
    tx_idx = 0;

    /* Step 2: Configure DMA registers */
    __asm volatile ("dsb sy" ::: "memory");
    ETH_DMACTXDLAR = (uint32_t)&tx_ring[0];
    ETH_DMACRXDLAR = (uint32_t)&rx_ring[0];
    ETH_DMACTXRLR = TX_DESC_COUNT - 1U;
    ETH_DMACRXRLR = RX_DESC_COUNT - 1U;
    ETH_DMACTXDTPR = (uint32_t)&tx_ring[0];
    ETH_DMACRXDTPR = (uint32_t)&rx_ring[RX_DESC_COUNT - 1U];
    __asm volatile ("dsb sy" ::: "memory");

    /* Step 3: Now set buffer addresses and OWN bit */
    for (i = 0; i < TX_DESC_COUNT; i++) {
        *(volatile uint32_t *)&tx_ring[i].des0 = (uint32_t)tx_buffers[i];
    }
    for (i = 0; i < RX_DESC_COUNT; i++) {
        *(volatile uint32_t *)&rx_ring[i].des0 = (uint32_t)rx_buffers[i];
        *(volatile uint32_t *)&rx_ring[i].des3 = ETH_RDES3_OWN | ETH_RDES3_IOC | ETH_RDES3_BUF1V;
    }

    /* Data synchronization barrier before updating tail pointer */
    __asm volatile ("dsb sy" ::: "memory");
    __asm volatile ("isb sy" ::: "memory");

    /* Step 4: Update tail pointer to signal DMA that descriptors are ready */
    ETH_DMACRXDTPR = (uint32_t)&rx_ring[RX_DESC_COUNT - 1U];

    /* Final barrier */
    __asm volatile ("dsb sy" ::: "memory");
}

/* ETH_DMACCR - DMA Channel Control Register at offset 0x1100 */
#define ETH_DMACCR      (*(volatile uint32_t *)(ETH_BASE + 0x1100u))
#define ETH_DMACCR_DSL_0BIT  (0x00000000u)  /* No skip between descriptors */

static void eth_config_dma(void)
{
    ETH_DMASBMR = ETH_DMASBMR_FB | ETH_DMASBMR_AAL;
    /* Set DSL=0 for 16-byte descriptors (no skip) */
    ETH_DMACCR = ETH_DMACCR_DSL_0BIT;
    ETH_DMACRXCR = ((RX_BUF_SIZE & ETH_RDES3_PL_MASK) << ETH_DMACRXCR_RBSZ_SHIFT) |
                   ETH_DMACRXCR_RPBL(DMA_RPBL);
    ETH_DMACTXCR = ETH_DMACTXCR_OSF | ETH_DMACTXCR_TPBL(DMA_TPBL);
}

#define ETH_DMACSR_TPS  (1U << 1)   /* TX Process Stopped */
#define ETH_DMACSR_RPS  (1U << 8)   /* RX Process Stopped */

static void eth_start(void)
{
    ETH_MACCR |= ETH_MACCR_TE | ETH_MACCR_RE;
    ETH_MTLTXQOMR |= ETH_MTLTXQOMR_FTQ;
    ETH_DMACTXCR |= ETH_DMACTXCR_ST;
    ETH_DMACRXCR |= ETH_DMACRXCR_SR;

    /* Clear TX and RX process stopped flags (like HAL does) */
    ETH_DMACSR = ETH_DMACSR_TPS | ETH_DMACSR_RPS;

    __asm volatile ("dsb sy" ::: "memory");

    /* Write tail pointer to start RX DMA processing */
    ETH_DMACRXDTPR = (uint32_t)&rx_ring[RX_DESC_COUNT - 1U];
}

static void eth_stop(void)
{
    ETH_DMACTXCR &= ~ETH_DMACTXCR_ST;
    ETH_DMACRXCR &= ~ETH_DMACRXCR_SR;
    ETH_MACCR &= ~ETH_MACCR_RE;
    ETH_MTLTXQOMR |= ETH_MTLTXQOMR_FTQ;
    ETH_MACCR &= ~ETH_MACCR_TE;
}

static void eth_mdio_wait_ready(void)
{
    uint32_t timeout = 100000U;
    while ((ETH_MACMDIOAR & ETH_MACMDIOAR_MB) != 0U && timeout != 0U) {
        timeout--;
    }
}

static uint16_t eth_mdio_read(uint32_t phy, uint32_t reg)
{
    uint32_t cfg;
    eth_mdio_wait_ready();
    cfg = (4U << ETH_MACMDIOAR_CR_SHIFT) |
          (reg << ETH_MACMDIOAR_RDA_SHIFT) |
          (phy << ETH_MACMDIOAR_PA_SHIFT) |
          (ETH_MACMDIOAR_GOC_READ << ETH_MACMDIOAR_GOC_SHIFT);
    ETH_MACMDIOAR = cfg | ETH_MACMDIOAR_MB;
    eth_mdio_wait_ready();
    return (uint16_t)(ETH_MACMDIODR & 0xFFFFU);
}

static void eth_mdio_write(uint32_t phy, uint32_t reg, uint16_t value)
{
    uint32_t cfg;
    eth_mdio_wait_ready();
    ETH_MACMDIODR = (uint32_t)value;
    cfg = (4U << ETH_MACMDIOAR_CR_SHIFT) |
          (reg << ETH_MACMDIOAR_RDA_SHIFT) |
          (phy << ETH_MACMDIOAR_PA_SHIFT) |
          (ETH_MACMDIOAR_GOC_WRITE << ETH_MACMDIOAR_GOC_SHIFT);
    ETH_MACMDIOAR = cfg | ETH_MACMDIOAR_MB;
    eth_mdio_wait_ready();
}

static int32_t eth_detect_phy(void)
{
    uint32_t addr;
    for (addr = 0U; addr < 32U; addr++) {
        uint16_t id1 = eth_mdio_read(addr, PHY_REG_ID1);
        if (id1 != 0xFFFFU && id1 != 0x0000U) {
            return (int32_t)addr;
        }
    }
    return -1;
}

static void eth_phy_init(void)
{
    uint32_t timeout;
    uint16_t ctrl;
    uint16_t bsr;

    if (phy_addr < 0) {
        phy_addr = eth_detect_phy();
        if (phy_addr < 0) phy_addr = 0;
    }

    eth_mdio_write((uint32_t)phy_addr, PHY_REG_BCR, PHY_BCR_RESET);
    timeout = 100000U;
    do {
        ctrl = eth_mdio_read((uint32_t)phy_addr, PHY_REG_BCR);
    } while ((ctrl & PHY_BCR_RESET) != 0U && --timeout != 0U);

    ctrl &= ~(PHY_BCR_POWER_DOWN | PHY_BCR_ISOLATE | PHY_BCR_SPEED_100 | PHY_BCR_FULL_DUPLEX);
    eth_mdio_write((uint32_t)phy_addr, PHY_REG_ANAR, PHY_ANAR_DEFAULT);
    ctrl |= PHY_BCR_AUTONEG_ENABLE | PHY_BCR_RESTART_AUTONEG;
    eth_mdio_write((uint32_t)phy_addr, PHY_REG_BCR, ctrl);

    timeout = 100000U;
    do {
        bsr = eth_mdio_read((uint32_t)phy_addr, PHY_REG_BSR);
        bsr |= eth_mdio_read((uint32_t)phy_addr, PHY_REG_BSR);
    } while ((bsr & PHY_BSR_AUTONEG_COMPLETE) == 0U && --timeout != 0U);

    timeout = 100000U;
    do {
        bsr = eth_mdio_read((uint32_t)phy_addr, PHY_REG_BSR);
        bsr |= eth_mdio_read((uint32_t)phy_addr, PHY_REG_BSR);
    } while ((bsr & PHY_BSR_LINK_STATUS) == 0U && --timeout != 0U);
}

static uint32_t rx_poll_count = 0;
static uint32_t rx_pkt_count = 0;

static int eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct eth_desc *desc;
    uint32_t status;
    uint32_t frame_len = 0;

    (void)dev;
    rx_poll_count++;
    desc = &rx_ring[rx_idx];
    if (desc->des3 & ETH_RDES3_OWN) return 0;
    rx_pkt_count++;
    status = desc->des3;
    if ((status & (ETH_RDES3_FS | ETH_RDES3_LS)) ==
            (ETH_RDES3_FS | ETH_RDES3_LS)) {
        frame_len = status & ETH_RDES3_PL_MASK;
        if (frame_len > len) frame_len = len;
        memcpy(rx_staging_buffer, rx_buffers[rx_idx], frame_len);
        memcpy(frame, rx_staging_buffer, frame_len);
    }
    desc->des1 = 0;
    desc->des3 = ETH_RDES3_OWN | ETH_RDES3_IOC | ETH_RDES3_BUF1V;
    __asm volatile ("dsb sy" ::: "memory");
    ETH_DMACRXDTPR = (uint32_t)desc;
    rx_idx = (rx_idx + 1U) % RX_DESC_COUNT;
    return (int)frame_len;
}

static int eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct eth_desc *desc;
    uint32_t dma_len;
    uint32_t next_idx;

    (void)dev;
    if (len == 0 || len > TX_BUF_SIZE) return -1;
    desc = &tx_ring[tx_idx];
    if (desc->des3 & ETH_TDES3_OWN) return -2;
    memcpy(tx_buffers[tx_idx], frame, len);
    dma_len = (len < FRAME_MIN_LEN) ? FRAME_MIN_LEN : len;
    if (dma_len > len) memset(tx_buffers[tx_idx] + len, 0, dma_len - len);
    desc->des0 = (uint32_t)tx_buffers[tx_idx];
    desc->des1 = 0;
    desc->des2 = (dma_len & ETH_TDES2_B1L_MASK);
    __asm volatile ("dsb sy" ::: "memory");
    desc->des3 = (dma_len & ETH_TDES3_FL_MASK) |
                 ETH_TDES3_FD |
                 ETH_TDES3_LD |
                 ETH_TDES3_OWN;
    __asm volatile ("dsb sy" ::: "memory");
    ETH_DMACSR = ETH_DMACSR_TBU;
    if (tx_idx == 0U) eth_trigger_tx();
    next_idx = (tx_idx + 1U) % TX_DESC_COUNT;
    ETH_DMACTXDTPR = (uint32_t)&tx_ring[next_idx];
    tx_idx = next_idx;
    return (int)len;
}

static void stm32h5_eth_generate_mac(uint8_t mac[6])
{
    mac[0] = 0x02;
    mac[1] = 0x11;
    mac[2] = 0xAA;
    mac[3] = 0xBB;
    mac[4] = 0x22;
    mac[5] = 0x33;
}

void stm32h5_eth_get_stats(uint32_t *polls, uint32_t *pkts)
{
    if (polls) *polls = rx_poll_count;
    if (pkts) *pkts = rx_pkt_count;
}

uint32_t stm32h5_eth_get_rx_des3(void)
{
    return rx_ring[0].des3;
}

uint32_t stm32h5_eth_get_rx_des0(void)
{
    return rx_ring[0].des0;
}

uint32_t stm32h5_eth_get_rx_ring_addr(void)
{
    return (uint32_t)&rx_ring[0];
}

uint32_t stm32h5_eth_get_dmacsr(void)
{
    /* ETH_DMAC0SR at offset 0x1160 - clear RBU by writing 1 to bit 7 */
    uint32_t val = ETH_DMACSR;
    if (val & 0x80) {
        ETH_DMACSR = 0x80;  /* Clear RBU by writing 1 */
    }
    return val;
}

uint32_t stm32h5_eth_get_rx_tail(void)
{
    /* ETH_DMAC0RXDTPR */
    return ETH_DMACRXDTPR;
}

uint32_t stm32h5_eth_get_macpfr(void)
{
    return ETH_MACPFR;
}

uint32_t stm32h5_eth_get_mac_debug(void)
{
    /* ETH_MTLRXQDR - MTL Rx Queue Debug */
    return *(volatile uint32_t *)(ETH_BASE + 0x0C38u);
}

uint32_t stm32h5_eth_get_dma_debug(void)
{
    /* ETH_DMADSR - DMA Debug Status */
    return *(volatile uint32_t *)(ETH_BASE + 0x100Cu);
}

uint32_t stm32h5_eth_get_rx_list_addr(void)
{
    /* ETH_DMAC0RXDLAR - RX Descriptor List Address */
    return ETH_DMACRXDLAR;
}

uint32_t stm32h5_eth_get_rx_ring_len(void)
{
    /* ETH_DMAC0RXRLR - RX Ring Length */
    return ETH_DMACRXRLR;
}

uint32_t stm32h5_eth_get_rx_curr_desc(void)
{
    /* ETH_DMAC0CXRXLAR - Current RX Descriptor, offset 0x114C */
    return *(volatile uint32_t *)(ETH_BASE + 0x114Cu);
}

uint32_t stm32h5_eth_read_desc_at_addr(uint32_t addr)
{
    /* Read DES3 at the given descriptor address + 12 bytes (offset of des3) */
    return *(volatile uint32_t *)(addr + 12u);
}

void stm32h5_eth_kick_rx(void)
{
    uint32_t i;
    /* Reinitialize all RX descriptors and kick DMA */
    for (i = 0; i < RX_DESC_COUNT; i++) {
        *(volatile uint32_t *)&rx_ring[i].des0 = (uint32_t)rx_buffers[i];
        *(volatile uint32_t *)&rx_ring[i].des1 = 0;
        *(volatile uint32_t *)&rx_ring[i].des2 = 0;
        *(volatile uint32_t *)&rx_ring[i].des3 = ETH_RDES3_OWN | ETH_RDES3_IOC | ETH_RDES3_BUF1V;
    }
    __asm volatile ("dsb sy" ::: "memory");
    __asm volatile ("isb sy" ::: "memory");
    ETH_DMACRXDTPR = (uint32_t)&rx_ring[RX_DESC_COUNT - 1U];
}

int stm32h5_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    uint8_t local_mac[6];
    uint16_t phy_id1, phy_bsr;

    if (ll == NULL) return -1;
    if (mac == NULL) {
        stm32h5_eth_generate_mac(local_mac);
        mac = local_mac;
    }
    memcpy(ll->mac, mac, 6);
    strncpy(ll->ifname, "eth0", sizeof(ll->ifname) - 1);
    ll->ifname[sizeof(ll->ifname) - 1] = '\0';
    ll->poll = eth_poll;
    ll->send = eth_send;

    eth_stop();
    if (eth_hw_reset() != 0) {
        return -2;  /* DMA reset timeout - check RMII clock */
    }
    eth_config_mac(mac);
    eth_config_mtl();
    eth_init_desc();
    eth_config_dma();
    eth_phy_init();
    eth_config_speed_duplex();
    eth_start();

    /* Read PHY info for debug */
    phy_id1 = eth_mdio_read((uint32_t)phy_addr, PHY_REG_ID1);
    phy_bsr = eth_mdio_read((uint32_t)phy_addr, PHY_REG_BSR);
    /* Pack debug info: PHY_ADDR in bits 0-7, link in bit 8, id1 high byte in 16-23 */
    return ((phy_id1 & 0xFF00u) << 8) | ((phy_bsr & 0x04u) ? 0x100 : 0) | (phy_addr & 0xFF);
}

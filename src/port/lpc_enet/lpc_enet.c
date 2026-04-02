/* lpc_enet.c
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
 * 
 * Common NXP LPC Ethernet MAC/PHY driver for wolfIP.
 * Synopsys DesignWare Ethernet QoS, enhanced descriptor format.
 * Shared across LPC54018, LPC54S018, LPC546xx, and similar NXP MCUs.
 *
 * Board must define via CFLAGS or board header before compiling:
 *   LPC_ENET_BASE    - ENET peripheral base address
 *   LPC_ENET_MDIO_CR - MDIO clock divider value
 *   LPC_ENET_1US_TIC - MAC 1us tick counter (AHB_MHz - 1)
 */

#include <stdint.h>
#include <string.h>
#include "config.h"
#include "lpc_enet.h"

/* Register access */
#define ETH_REG(offset)     (*(volatile uint32_t *)(LPC_ENET_BASE + (offset)))

/* MAC registers */
#define ETH_MACCR           ETH_REG(0x0000U)
#define ETH_MACECR          ETH_REG(0x0004U)
#define ETH_MACPFR          ETH_REG(0x0008U)
#define ETH_MACWTR          ETH_REG(0x000CU)
#define ETH_MACQ0TXFCR      ETH_REG(0x0070U)
#define ETH_MACRXFCR        ETH_REG(0x0090U)
#define ETH_MACRXQC0R       ETH_REG(0x00A0U)
#define ETH_MAC1USTCR       ETH_REG(0x00DCU)
#define ETH_MACMDIOAR       ETH_REG(0x0200U)
#define ETH_MACMDIODR       ETH_REG(0x0204U)
#define ETH_MACA0HR         ETH_REG(0x0300U)
#define ETH_MACA0LR         ETH_REG(0x0304U)

/* MTL registers */
#define ETH_MTLOMR          ETH_REG(0x0C00U)
#define ETH_MTLTXQOMR       ETH_REG(0x0D00U)
#define ETH_MTLRXQOMR       ETH_REG(0x0D30U)

/* DMA registers */
#define ETH_DMAMR           ETH_REG(0x1000U)
#define ETH_DMASBMR         ETH_REG(0x1004U)
#define ETH_DMACCR          ETH_REG(0x1100U)
#define ETH_DMACTXCR        ETH_REG(0x1104U)
#define ETH_DMACRXCR        ETH_REG(0x1108U)
#define ETH_DMACTXDLAR      ETH_REG(0x1114U)
#define ETH_DMACRXDLAR      ETH_REG(0x111CU)
#define ETH_DMACTXDTPR      ETH_REG(0x1120U)
#define ETH_DMACRXDTPR      ETH_REG(0x1128U)
#define ETH_DMACTXRLR       ETH_REG(0x112CU)
#define ETH_DMACRXRLR       ETH_REG(0x1130U)
#define ETH_DMACIER         ETH_REG(0x1134U)
#define ETH_DMACSR          ETH_REG(0x1160U)

/* MAC bits */
#define MACCR_RE        (1U << 0)
#define MACCR_TE        (1U << 1)
#define MACCR_DM        (1U << 13)
#define MACCR_FES       (1U << 14)
#define MACCR_PS        (1U << 15)

/* DMA bits */
#define DMAMR_SWR       (1U << 0)
#define DMASBMR_FB      (1U << 0)
#define DMASBMR_AAL     (1U << 12)
#define DMACTXCR_ST     (1U << 0)
#define DMACTXCR_OSF    (1U << 4)
#define DMACRXCR_SR     (1U << 0)
#define DMACRXCR_RBSZ_SHIFT 1
#define DMACSR_TBU      (1U << 2)
#define DMACSR_TPS      (1U << 1)
#define DMACSR_RPS      (1U << 8)
#define DMACSR_RBU      (1U << 7)
#define DMACTXCR_TPBL(v) (((uint32_t)(v) & 0x3FU) << 16)
#define DMACRXCR_RPBL(v) (((uint32_t)(v) & 0x3FU) << 16)
#define DMACIER_NIE     (1U << 15)
#define DMACIER_AIE     (1U << 14)
#define DMACIER_RBUE    (1U << 7)
#define DMACIER_RIE     (1U << 6)
#define DMACIER_TIE     (1U << 0)

/* MTL bits */
#define TXQOMR_FTQ           (1U << 0)
#define TXQOMR_TSF           (1U << 1)
#define TXQOMR_TXQEN_ENABLE  (2U << 2)
#define TXQOMR_TQS_2048      (0x7U << 16)
#define TXQOMR_MASK          0x00070072U
#define RXQOMR_RSF           (1U << 5)
#define RXQOMR_RQS_4096      (0xFU << 20)
#define RXQOMR_MASK          0x00F0007FU

/* MDIO bits */
#define MDIOAR_MB        (1U << 0)
#define MDIOAR_GOC_SHIFT 2
#define MDIOAR_GOC_WRITE 0x1U
#define MDIOAR_GOC_READ  0x3U
#define MDIOAR_CR_SHIFT  8
#define MDIOAR_CR_MASK   (0xFU << 8)
#define MDIOAR_RDA_SHIFT 16
#define MDIOAR_PA_SHIFT  21

/* PHY registers */
#define PHY_BCR      0x00U
#define PHY_BSR      0x01U
#define PHY_ID1      0x02U
#define PHY_ANAR     0x04U

#define BCR_RESET            (1U << 15)
#define BCR_SPEED_100        (1U << 13)
#define BCR_AUTONEG_ENABLE   (1U << 12)
#define BCR_POWER_DOWN       (1U << 11)
#define BCR_ISOLATE          (1U << 10)
#define BCR_RESTART_AUTONEG  (1U << 9)
#define BCR_FULL_DUPLEX      (1U << 8)
#define BSR_LINK_STATUS      (1U << 2)
#define BSR_AUTONEG_COMPLETE (1U << 5)
#define BSR_10_HALF          (1U << 11)
#define BSR_10_FULL          (1U << 12)
#define BSR_100_HALF         (1U << 13)
#define BSR_100_FULL         (1U << 14)
#define ANAR_DEFAULT         0x01E1U

/* DMA descriptor (enhanced format, 4 words) */
struct eth_desc {
    volatile uint32_t des0;
    volatile uint32_t des1;
    volatile uint32_t des2;
    volatile uint32_t des3;
};

#define TDES3_OWN      (1U << 31)
#define TDES3_FD       (1U << 29)
#define TDES3_LD       (1U << 28)
#define TDES2_B1L_MASK (0x3FFFU)
#define TDES3_FL_MASK  (0x7FFFU)
#define RDES3_OWN      (1U << 31)
#define RDES3_IOC      (1U << 30)
#define RDES3_BUF1V    (1U << 24)
#define RDES3_FS       (1U << 29)
#define RDES3_LS       (1U << 28)
#define RDES3_PL_MASK  (0x3FFFU)

#define RX_DESC_COUNT  4U
#define TX_DESC_COUNT  3U
#define RX_BUF_SIZE    LINK_MTU
#define TX_BUF_SIZE    LINK_MTU
#define FRAME_MIN_LEN  60U
#define DMA_PBL        32U

#define DMA_ADDR(ptr) ((uint32_t)(ptr))

static struct eth_desc rx_ring[RX_DESC_COUNT] __attribute__((aligned(32)));
static struct eth_desc tx_ring[TX_DESC_COUNT] __attribute__((aligned(32)));
static uint8_t rx_buffers[RX_DESC_COUNT][RX_BUF_SIZE] __attribute__((aligned(32)));
static uint8_t tx_buffers[TX_DESC_COUNT][TX_BUF_SIZE] __attribute__((aligned(32)));

static uint32_t rx_idx;
static uint32_t tx_idx;
static int32_t phy_addr = -1;
static uint32_t rx_poll_count;
static uint32_t rx_pkt_count;

/* MDIO */

static void mdio_wait(void)
{
    uint32_t t = 100000U;
    while ((ETH_MACMDIOAR & MDIOAR_MB) && --t) { }
}

static void mdio_init(void)
{
    ETH_MACMDIOAR = (LPC_ENET_MDIO_CR << MDIOAR_CR_SHIFT);
}

static uint16_t mdio_read(uint32_t phy, uint32_t reg)
{
    uint32_t cr;
    mdio_wait();
    cr = ETH_MACMDIOAR & MDIOAR_CR_MASK;
    ETH_MACMDIOAR = cr | (MDIOAR_GOC_READ << MDIOAR_GOC_SHIFT) |
                    (phy << MDIOAR_PA_SHIFT) | (reg << MDIOAR_RDA_SHIFT);
    ETH_MACMDIOAR |= MDIOAR_MB;
    mdio_wait();
    return (uint16_t)(ETH_MACMDIODR & 0xFFFFU);
}

static void mdio_write(uint32_t phy, uint32_t reg, uint16_t value)
{
    uint32_t cr;
    mdio_wait();
    cr = ETH_MACMDIOAR & MDIOAR_CR_MASK;
    ETH_MACMDIOAR = cr | (MDIOAR_GOC_WRITE << MDIOAR_GOC_SHIFT) |
                    (phy << MDIOAR_PA_SHIFT) | (reg << MDIOAR_RDA_SHIFT);
    ETH_MACMDIODR = (uint32_t)value;
    ETH_MACMDIOAR |= MDIOAR_MB;
    mdio_wait();
}

/* PHY */

static int32_t phy_detect(void)
{
    uint32_t addr;
    for (addr = 0; addr < 32; addr++) {
        uint16_t id = mdio_read(addr, PHY_ID1);
        if (id != 0xFFFFU && id != 0x0000U)
            return (int32_t)addr;
    }
    return -1;
}

static void phy_init(void)
{
    uint32_t timeout;
    uint16_t ctrl, bsr;

    if (phy_addr < 0) {
        phy_addr = phy_detect();
        if (phy_addr < 0) { phy_addr = 0; return; }
    }

    mdio_write((uint32_t)phy_addr, PHY_BCR, BCR_RESET);
    timeout = 100000U;
    do { ctrl = mdio_read((uint32_t)phy_addr, PHY_BCR);
    } while ((ctrl & BCR_RESET) && --timeout);

    ctrl &= ~(BCR_POWER_DOWN | BCR_ISOLATE | BCR_SPEED_100 | BCR_FULL_DUPLEX);
    mdio_write((uint32_t)phy_addr, PHY_ANAR, ANAR_DEFAULT);
    ctrl |= BCR_AUTONEG_ENABLE | BCR_RESTART_AUTONEG;
    mdio_write((uint32_t)phy_addr, PHY_BCR, ctrl);

    timeout = 100000U;
    do { bsr = mdio_read((uint32_t)phy_addr, PHY_BSR);
         bsr |= mdio_read((uint32_t)phy_addr, PHY_BSR);
    } while (!(bsr & BSR_AUTONEG_COMPLETE) && --timeout);

    timeout = 100000U;
    do { bsr = mdio_read((uint32_t)phy_addr, PHY_BSR);
         bsr |= mdio_read((uint32_t)phy_addr, PHY_BSR);
    } while (!(bsr & BSR_LINK_STATUS) && --timeout);
}

/* MAC/DMA */

static int hw_reset(void)
{
    uint32_t t = 1000000U;
    ETH_DMAMR |= DMAMR_SWR;
    while ((ETH_DMAMR & DMAMR_SWR) && --t) { }
    return t ? 0 : -1;
}

static void config_mac(const uint8_t mac[6])
{
    ETH_MAC1USTCR = LPC_ENET_1US_TIC;
    ETH_MACCR = (1U << 20) | (1U << 21) | (1U << 27) |
                MACCR_DM | MACCR_FES | MACCR_PS;
    ETH_MACRXQC0R = 0x02U;  /* Enable RX Queue 0 (required on LPC) */
    ETH_MACPFR = 0;
    ETH_MACECR = 0x618U;
    ETH_MACWTR = 0;
    ETH_MACQ0TXFCR = (1U << 7);
    ETH_MACRXFCR = 0;
    ETH_MACA0HR = ((uint32_t)mac[5] << 8) | (uint32_t)mac[4];
    ETH_MACA0LR = ((uint32_t)mac[3] << 24) | ((uint32_t)mac[2] << 16) |
                  ((uint32_t)mac[1] << 8) | (uint32_t)mac[0];
}

static void config_speed_duplex(void)
{
    uint32_t maccr;
    uint16_t bsr;
    if (phy_addr < 0) return;
    maccr = ETH_MACCR & ~(MACCR_FES | MACCR_DM);
    bsr = mdio_read((uint32_t)phy_addr, PHY_BSR);
    bsr |= mdio_read((uint32_t)phy_addr, PHY_BSR);
    if (bsr & BSR_100_FULL)       maccr |= MACCR_FES | MACCR_DM;
    else if (bsr & BSR_100_HALF)  maccr |= MACCR_FES;
    else if (bsr & BSR_10_FULL)   maccr |= MACCR_DM;
    ETH_MACCR = maccr;
}

static void config_mtl(void)
{
    uint32_t txq, rxq;
    ETH_MTLOMR = 0x60U;
    txq = (ETH_MTLTXQOMR & ~TXQOMR_MASK) |
          TXQOMR_TSF | TXQOMR_TXQEN_ENABLE | TXQOMR_TQS_2048;
    ETH_MTLTXQOMR = txq;
    rxq = (ETH_MTLRXQOMR & ~RXQOMR_MASK) | RXQOMR_RSF | RXQOMR_RQS_4096;
    ETH_MTLRXQOMR = rxq;
}

static void config_dma(void)
{
    ETH_DMASBMR = DMASBMR_AAL | DMASBMR_FB;
    ETH_DMACCR = 0;
    ETH_DMACRXCR = ((RX_BUF_SIZE & RDES3_PL_MASK) << DMACRXCR_RBSZ_SHIFT) |
                   DMACRXCR_RPBL(DMA_PBL);
    ETH_DMACTXCR = DMACTXCR_OSF | DMACTXCR_TPBL(DMA_PBL);
}

static void init_desc(void)
{
    uint32_t i;
    for (i = 0; i < TX_DESC_COUNT; i++) {
        tx_ring[i].des0 = 0; tx_ring[i].des1 = 0;
        tx_ring[i].des2 = 0; tx_ring[i].des3 = 0;
    }
    for (i = 0; i < RX_DESC_COUNT; i++) {
        rx_ring[i].des0 = 0; rx_ring[i].des1 = 0;
        rx_ring[i].des2 = 0; rx_ring[i].des3 = 0;
    }
    rx_idx = tx_idx = 0;

    __asm volatile ("dsb sy" ::: "memory");
    ETH_DMACTXDLAR = DMA_ADDR(&tx_ring[0]);
    ETH_DMACRXDLAR = DMA_ADDR(&rx_ring[0]);
    ETH_DMACTXRLR = TX_DESC_COUNT - 1;
    ETH_DMACRXRLR = RX_DESC_COUNT - 1;
    ETH_DMACTXDTPR = DMA_ADDR(&tx_ring[0]);
    ETH_DMACRXDTPR = DMA_ADDR(&rx_ring[RX_DESC_COUNT - 1]);
    __asm volatile ("dsb sy" ::: "memory");

    for (i = 0; i < TX_DESC_COUNT; i++)
        *(volatile uint32_t *)&tx_ring[i].des0 = DMA_ADDR(tx_buffers[i]);
    __asm volatile ("dsb sy" ::: "memory");
}

static void arm_rx(void)
{
    uint32_t i;
    for (i = 0; i < RX_DESC_COUNT; i++) {
        rx_ring[i].des0 = DMA_ADDR(rx_buffers[i]);
        rx_ring[i].des1 = 0; rx_ring[i].des2 = 0;
        __asm volatile ("dsb sy" ::: "memory");
        rx_ring[i].des3 = RDES3_OWN | RDES3_IOC | RDES3_BUF1V;
    }
    __asm volatile ("dmb sy" ::: "memory");
    ETH_DMACRXDTPR = DMA_ADDR(&rx_ring[RX_DESC_COUNT - 1]);
}

static void mac_start(void)
{
    ETH_MACCR |= MACCR_TE | MACCR_RE;
    ETH_MTLTXQOMR |= TXQOMR_FTQ;
    ETH_DMACTXCR |= DMACTXCR_ST;
    ETH_DMACRXCR |= DMACRXCR_SR;
    ETH_DMACIER = DMACIER_NIE | DMACIER_AIE | DMACIER_RBUE |
                  DMACIER_RIE | DMACIER_TIE;
    ETH_DMACSR = DMACSR_TPS | DMACSR_RPS | DMACSR_RBU;
    __asm volatile ("dsb sy" ::: "memory");
    arm_rx();
}

static void mac_stop(void)
{
    ETH_DMACTXCR &= ~DMACTXCR_ST;
    ETH_DMACRXCR &= ~DMACRXCR_SR;
    ETH_MACCR &= ~MACCR_RE;
    ETH_MTLTXQOMR |= TXQOMR_FTQ;
    ETH_MACCR &= ~MACCR_TE;
}

/* wolfIP poll/send callbacks */

static int eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct eth_desc *desc;
    uint32_t status, frame_len = 0;
    (void)dev;

    rx_poll_count++;

    if (ETH_DMACSR & DMACSR_RBU) {
        ETH_DMACSR = DMACSR_RBU;
        __asm volatile ("dsb sy" ::: "memory");
        ETH_DMACRXDTPR = DMA_ADDR(&rx_ring[RX_DESC_COUNT - 1]);
    }

    desc = &rx_ring[rx_idx];
    if (desc->des3 & RDES3_OWN) return 0;

    rx_pkt_count++;
    status = desc->des3;
    if ((status & (RDES3_FS | RDES3_LS)) == (RDES3_FS | RDES3_LS)) {
        frame_len = status & RDES3_PL_MASK;
        if (frame_len > RX_BUF_SIZE) frame_len = RX_BUF_SIZE;
        if (frame_len > len) frame_len = len;
        if (frame_len > 0)
            memcpy(frame, rx_buffers[rx_idx], frame_len);
    }

    desc->des0 = DMA_ADDR(rx_buffers[rx_idx]);
    desc->des1 = 0; desc->des2 = 0;
    __asm volatile ("dsb sy" ::: "memory");
    desc->des3 = RDES3_OWN | RDES3_IOC | RDES3_BUF1V;
    __asm volatile ("dsb sy" ::: "memory");
    ETH_DMACRXDTPR = DMA_ADDR(desc);
    rx_idx = (rx_idx + 1) % RX_DESC_COUNT;

    return (int)frame_len;
}

static int eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct eth_desc *desc;
    uint32_t dma_len, next;
    (void)dev;

    if (len == 0 || len > TX_BUF_SIZE) return -1;
    desc = &tx_ring[tx_idx];
    if (desc->des3 & TDES3_OWN) return -2;

    memcpy(tx_buffers[tx_idx], frame, len);
    dma_len = (len < FRAME_MIN_LEN) ? FRAME_MIN_LEN : len;
    if (dma_len > len) memset(tx_buffers[tx_idx] + len, 0, dma_len - len);

    desc->des0 = DMA_ADDR(tx_buffers[tx_idx]);
    desc->des1 = 0;
    desc->des2 = (dma_len & TDES2_B1L_MASK);
    __asm volatile ("dsb sy" ::: "memory");
    desc->des3 = (dma_len & TDES3_FL_MASK) | TDES3_FD | TDES3_LD | TDES3_OWN;
    __asm volatile ("dsb sy" ::: "memory");

    ETH_DMACSR = DMACSR_TBU;
    next = (tx_idx + 1) % TX_DESC_COUNT;
    ETH_DMACTXDTPR = DMA_ADDR(&tx_ring[next]);
    tx_idx = next;
    return (int)len;
}

/* Public API */

void lpc_enet_get_stats(uint32_t *polls, uint32_t *pkts)
{
    if (polls) *polls = rx_poll_count;
    if (pkts) *pkts = rx_pkt_count;
}

uint32_t lpc_enet_get_dmacsr(void)
{
    return ETH_DMACSR;
}

int lpc_enet_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    uint8_t local_mac[6];
    uint16_t id1, bsr;

    if (!ll) return -1;

    if (!mac) {
        local_mac[0] = 0x02; local_mac[1] = 0x11;
        local_mac[2] = 0x54; local_mac[3] = 0x18;
        local_mac[4] = 0x00; local_mac[5] = 0x01;
        mac = local_mac;
    }

    memcpy(ll->mac, mac, 6);
    strncpy(ll->ifname, "eth0", sizeof(ll->ifname) - 1);
    ll->ifname[sizeof(ll->ifname) - 1] = '\0';
    ll->poll = eth_poll;
    ll->send = eth_send;

    mac_stop();
    if (hw_reset() != 0) return -2;

    mdio_init();
    config_mac(mac);
    config_mtl();
    config_dma();
    init_desc();
    phy_init();
    config_speed_duplex();
    mac_start();

    id1 = mdio_read((uint32_t)phy_addr, PHY_ID1);
    bsr = mdio_read((uint32_t)phy_addr, PHY_BSR);

    return ((id1 & 0xFF00U) << 8) |
           ((bsr & 0x04U) ? 0x100 : 0) |
           (phy_addr & 0xFF);
}

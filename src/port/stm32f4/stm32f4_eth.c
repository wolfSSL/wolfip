/* stm32f4_eth.c
 *
 * STM32F4xx Ethernet driver for wolfIP.
 *
 * Targets the Synopsys DWC GMAC (legacy 16-byte descriptors, ATDS=0)
 * found on STM32F407/F417/F427/F437/F439/F469/F479.  The descriptor
 * layout for these MAC variants differs from the EQOS used on STM32H5
 * /H7/N6 (see src/port/stm32/stm32_eth.c) and also from the legacy
 * GMAC variant on the Vorago VA416xx (which uses control bits in
 * TDES1).  On STM32F4 the control bits live in TDES0.
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
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "stm32f4_eth.h"

/* Define DEBUG_ETH to enable verbose hardware diagnostic output. */
#ifdef DEBUG_ETH
#define ETH_DEBUG(...) printf(__VA_ARGS__)
#else
#define ETH_DEBUG(...) do { } while (0)
#endif

/* HAL_time_ms (declared in stm32f4_eth.h) is the SysTick-driven millisecond
 * tick maintained by the board port.  Use stm32f4_hal_time_ms() to read it
 * tear-free. */

/* HCLK frequency provided by the board port (used to pick MDIO divider). */
extern uint32_t stm32f4_eth_hclk_hz(void);

/* PHY address.  Must be set by the board port (via -DSTM32F4_ETH_PHY_ADDR
 * in CFLAGS) to match the strap pins on the attached PHY.  Common values:
 * 0 = LAN8742A on NUCLEO-F439ZI, 1 = DP83848 on STM32439I-EVAL. */
#ifndef STM32F4_ETH_PHY_ADDR
#define STM32F4_ETH_PHY_ADDR  1U
#endif

/* ===================================================================== */
/* Register layout                                                       */
/* ===================================================================== */

#define ETH_BASE        0x40028000UL

#define ETH_REG(off)    (*(volatile uint32_t *)(ETH_BASE + (off)))

/* MAC registers */
#define ETH_MACCR       ETH_REG(0x0000U)
#define ETH_MACFFR      ETH_REG(0x0004U)
#define ETH_MACMIIAR    ETH_REG(0x0010U)
#define ETH_MACMIIDR    ETH_REG(0x0014U)
#define ETH_MACDBGR     ETH_REG(0x0024U)
#define ETH_MACA0HR     ETH_REG(0x0040U)
#define ETH_MACA0LR     ETH_REG(0x0044U)

/* DMA registers */
#define ETH_DMABMR      ETH_REG(0x1000U)
#define ETH_DMATPDR     ETH_REG(0x1004U)
#define ETH_DMARPDR     ETH_REG(0x1008U)
#define ETH_DMARDLAR    ETH_REG(0x100CU)
#define ETH_DMATDLAR    ETH_REG(0x1010U)
#define ETH_DMASR       ETH_REG(0x1014U)
#define ETH_DMAOMR      ETH_REG(0x1018U)
#define ETH_DMAIER      ETH_REG(0x101CU)

/* MACCR bits */
#define MACCR_RE        (1U << 2)   /* Receiver enable */
#define MACCR_TE        (1U << 3)   /* Transmitter enable */
#define MACCR_ACS       (1U << 7)   /* Auto pad/CRC strip */
#define MACCR_IPCO      (1U << 10)  /* IPv4 checksum offload */
#define MACCR_DM        (1U << 11)  /* Duplex mode (1=Full) */
#define MACCR_FES       (1U << 14)  /* Fast Ethernet Speed (1=100M) */

/* MACMIIAR bits */
#define MACMIIAR_MB     (1U << 0)
#define MACMIIAR_MW     (1U << 1)
#define MACMIIAR_CR_POS 2
#define MACMIIAR_MR_POS 6
#define MACMIIAR_PA_POS 11

/* DMABMR bits */
#define DMABMR_SR       (1U << 0)
#define DMABMR_PBL_POS  8            /* Burst length, bits 13:8 */

/* DMAOMR bits */
#define DMAOMR_SR       (1U << 1)    /* Start RX */
#define DMAOMR_OSF      (1U << 2)    /* Operate On Second Frame */
#define DMAOMR_ST       (1U << 13)   /* Start TX */
#define DMAOMR_FTF      (1U << 20)   /* Flush TX FIFO */
#define DMAOMR_TSF      (1U << 21)   /* Transmit Store and Forward */
#define DMAOMR_RSF      (1U << 25)   /* Receive Store and Forward */

/* DMASR bits we react to (clear-on-write-1) */
#define DMASR_TBUS      (1U << 2)
#define DMASR_RBUS      (1U << 7)

/* ===================================================================== */
/* TX descriptor bits (TDES0)                                            */
/*                                                                       */
/* STM32F4 GMAC normal-mode TDES0 holds OWN + frame control + status.    */
/* CPU sets: OWN | IC | LS | FS | TCH (chain mode).                      */
/* DMA writes back error/status bits on completion.                      */
/* ===================================================================== */
#define TDES0_OWN       (1U << 31)
#define TDES0_IC        (1U << 30)
#define TDES0_LS        (1U << 29)
#define TDES0_FS        (1U << 28)
#define TDES0_TCH       (1U << 20)

/* TDES1: buffer sizes */
#define TDES1_TBS1_MASK 0x00001FFFU  /* bits 12:0 */

/* RX descriptor bits */
#define RDES0_OWN       (1U << 31)
#define RDES0_FL_SHIFT  16
#define RDES0_FL_MASK   (0x3FFFU << RDES0_FL_SHIFT)
#define RDES0_ES        (1U << 15)
#define RDES0_FS        (1U <<  9)
#define RDES0_LS        (1U <<  8)

#define RDES1_RER       (1U << 15)
#define RDES1_RBS1_MASK 0x00001FFFU

/* Generic PHY register set */
#define PHY_BCR         0x00U
#define PHY_BSR         0x01U
#define PHY_ID1         0x02U
#define PHY_ID2         0x03U
#define PHY_ANAR        0x04U
#define PHY_ANLPAR      0x05U

#define BCR_RESET           (1U << 15)
#define BCR_AUTONEG         (1U << 12)
#define BCR_RESTART_AN      (1U << 9)

#define BSR_LINK            (1U << 2)
#define BSR_AN_COMPLETE     (1U << 5)

#define ANAR_100_FD         (1U << 8)
#define ANAR_100_HD         (1U << 7)
#define ANAR_10_FD          (1U << 6)
#define ANAR_10_HD          (1U << 5)
#define ANAR_SELECTOR_802_3 0x01U

/* ===================================================================== */
/* Descriptor + buffer storage                                            */
/*                                                                       */
/* The STM32F4 Ethernet DMA can access main SRAM (0x20000000) but not    */
/* CCM data RAM (0x10000000).  The linker places .bss in main SRAM by   */
/* default, so plain static placement is fine here -- no special section */
/* attribute is required.  We over-align to 32 bytes for cleanliness    */
/* (matches HAL ETH driver) and to ensure burst-aligned DMA bursts.     */
/* ===================================================================== */

#define RX_DESC_COUNT   4U
#define TX_DESC_COUNT   3U
#define RX_BUF_SIZE     LINK_MTU
#define TX_BUF_SIZE     LINK_MTU
#define FRAME_MIN_LEN   60U

struct eth_desc {
    volatile uint32_t des0;
    volatile uint32_t des1;
    volatile uint32_t des2;
    volatile uint32_t des3;
};

static struct eth_desc rx_ring[RX_DESC_COUNT] __attribute__((aligned(32)));
static struct eth_desc tx_ring[TX_DESC_COUNT] __attribute__((aligned(32)));
static uint8_t rx_buffers[RX_DESC_COUNT][RX_BUF_SIZE] __attribute__((aligned(4)));
static uint8_t tx_buffers[TX_DESC_COUNT][TX_BUF_SIZE] __attribute__((aligned(4)));

static uint32_t rx_idx;
static uint32_t tx_idx;

static uint32_t rx_poll_count;
static uint32_t rx_pkt_count;
static uint32_t tx_pkt_count;
static uint32_t tx_err_count;

/* ===================================================================== */
/* MDIO                                                                  */
/* ===================================================================== */

static uint32_t mdio_cr_for_hclk(uint32_t hz)
{
    /* CR field encoding for STM32F4 GMAC (RM0090 sec 33.6.7) */
    if      (hz <  35000000U) return 2U; /* HCLK 20-35   -> /16 */
    else if (hz <  60000000U) return 3U; /* HCLK 35-60   -> /26 */
    else if (hz < 100000000U) return 0U; /* HCLK 60-100  -> /42 */
    else if (hz < 150000000U) return 1U; /* HCLK 100-150 -> /62 */
    else                       return 4U; /* HCLK 150-168 -> /102 */
}

static int mdio_wait_idle(void)
{
    uint32_t timeout = 100000U;
    while ((ETH_MACMIIAR & MACMIIAR_MB) && (timeout > 0U)) {
        timeout--;
    }
    return (timeout > 0U) ? 0 : -1;
}

static uint16_t mdio_read(uint32_t phy, uint32_t reg)
{
    uint32_t cr;

    if (mdio_wait_idle() != 0)
        return 0xFFFFU;

    cr = mdio_cr_for_hclk(stm32f4_eth_hclk_hz());

    ETH_MACMIIAR = ((phy & 0x1FU) << MACMIIAR_PA_POS) |
                   ((reg & 0x1FU) << MACMIIAR_MR_POS) |
                   ((cr  & 0x07U) << MACMIIAR_CR_POS) |
                   MACMIIAR_MB;

    if (mdio_wait_idle() != 0)
        return 0xFFFFU;

    return (uint16_t)(ETH_MACMIIDR & 0xFFFFU);
}

static int mdio_write(uint32_t phy, uint32_t reg, uint16_t value)
{
    uint32_t cr;

    if (mdio_wait_idle() != 0)
        return -1;

    cr = mdio_cr_for_hclk(stm32f4_eth_hclk_hz());

    ETH_MACMIIDR = value;
    ETH_MACMIIAR = ((phy & 0x1FU) << MACMIIAR_PA_POS) |
                   ((reg & 0x1FU) << MACMIIAR_MR_POS) |
                   ((cr  & 0x07U) << MACMIIAR_CR_POS) |
                   MACMIIAR_MW |
                   MACMIIAR_MB;

    return mdio_wait_idle();
}

/* ===================================================================== */
/* Hardware reset / MAC config                                            */
/* ===================================================================== */

static int eth_hw_reset(void)
{
    uint32_t timeout = 1000000U;

    ETH_DMABMR |= DMABMR_SR;
    while ((ETH_DMABMR & DMABMR_SR) && (timeout > 0U)) {
        timeout--;
    }
    return (timeout > 0U) ? 0 : -1;
}

static void eth_config_mac(const uint8_t *mac)
{
    /* MAC address in MACA0HR/MACA0LR.  MACA0HR bit 31 must be set. */
    ETH_MACA0HR = ((uint32_t)mac[5] << 8) | (uint32_t)mac[4] | 0x80000000U;
    ETH_MACA0LR = ((uint32_t)mac[3] << 24) | ((uint32_t)mac[2] << 16) |
                  ((uint32_t)mac[1] <<  8) |  (uint32_t)mac[0];

    /* Initial MACCR: ACS + IPCO + DM.  FES is filled in later by
     * eth_config_speed_duplex() from PHY auto-neg result.  STM32F4 GMAC has
     * no PS bit (no GMII support). */
    ETH_MACCR = MACCR_ACS | MACCR_IPCO | MACCR_DM;

    /* Set PM=1 (Promiscuous Mode).  On this STM32F4 GMAC IP the hardware
     * address filter rejects every incoming frame -- including broadcast
     * ARP and multicast -- when PM=0, even with BFD=0 (broadcasts
     * supposedly enabled), PAM=1 (pass-all-multicast), or RA=1
     * (receive-all) set.  Only PM=1 opens the RX path.  Verified on
     * NUCLEO-F439ZI with all four bits exercised individually.  wolfIP
     * does its own destination-MAC check in software (wolfip.c
     * recv_on()), so accepting extra frames here is benign aside from a
     * small CPU cost in the polling loop. */
    ETH_MACFFR = (1U << 0);
}

static void eth_config_speed_duplex(void)
{
    uint32_t maccr;
    uint16_t adv, lpa;
    uint16_t common;
    int full_duplex, speed_100;

    adv = mdio_read(STM32F4_ETH_PHY_ADDR, PHY_ANAR);
    lpa = mdio_read(STM32F4_ETH_PHY_ADDR, PHY_ANLPAR);
    common = adv & lpa;

    if (common & ANAR_100_FD) {
        full_duplex = 1;
        speed_100   = 1;
    } else if (common & ANAR_100_HD) {
        full_duplex = 0;
        speed_100   = 1;
    } else if (common & ANAR_10_FD) {
        full_duplex = 1;
        speed_100   = 0;
    } else {
        /* Includes 10-HD or no overlap (default to 10-HD). */
        full_duplex = 0;
        speed_100   = 0;
    }

    ETH_DEBUG("  PHY AN_ADV=0x%04X AN_LPA=0x%04X common=0x%04X -> %s %s\n",
              adv, lpa, common,
              speed_100   ? "100M" : "10M",
              full_duplex ? "FD"   : "HD");

    maccr = MACCR_ACS | MACCR_IPCO;
    if (full_duplex) maccr |= MACCR_DM;
    if (speed_100)   maccr |= MACCR_FES;

    ETH_MACCR = maccr;
}

/* ===================================================================== */
/* DMA config + descriptor init                                           */
/* ===================================================================== */

static void eth_config_dma(void)
{
    /* DMA bus mode: PBL=32, no fixed burst.  ATDS=0 (16-byte legacy
     * descriptors).  DA=0 (round-robin TX/RX). */
    ETH_DMABMR = (32U << DMABMR_PBL_POS);

    /* Op mode: RX store-and-forward, TX store-and-forward, OSF on. */
    ETH_DMAOMR = DMAOMR_RSF | DMAOMR_TSF | DMAOMR_OSF;

    /* Polling mode -- disable DMA interrupts. */
    ETH_DMAIER = 0U;
}

static void eth_init_desc(void)
{
    uint32_t i;

    /* TX ring: chain mode (TCH=1).  des3 = next descriptor pointer; last
     * wraps to first.  TER is unused -- the DMA always follows des3 in
     * chain mode.  CPU owns initially (OWN=0). */
    for (i = 0; i < TX_DESC_COUNT; i++) {
        tx_ring[i].des0 = TDES0_TCH;     /* TCH set permanently */
        tx_ring[i].des1 = 0U;
        tx_ring[i].des2 = (uint32_t)tx_buffers[i];
        tx_ring[i].des3 = (uint32_t)&tx_ring[(i + 1U) % TX_DESC_COUNT];
    }

    /* RX ring: ring mode with RER on last descriptor.  DMA owns all
     * (OWN=1). */
    for (i = 0; i < RX_DESC_COUNT; i++) {
        rx_ring[i].des0 = RDES0_OWN;
        rx_ring[i].des1 = (RX_BUF_SIZE & RDES1_RBS1_MASK);
        rx_ring[i].des2 = (uint32_t)rx_buffers[i];
        rx_ring[i].des3 = 0U;
    }
    rx_ring[RX_DESC_COUNT - 1U].des1 |= RDES1_RER;

    rx_idx = 0U;
    tx_idx = 0U;

    __asm volatile ("dsb sy" ::: "memory");

    ETH_DMARDLAR = (uint32_t)&rx_ring[0];
    ETH_DMATDLAR = (uint32_t)&tx_ring[0];

    __asm volatile ("dsb sy" ::: "memory");
}

/* ===================================================================== */
/* PHY init                                                              */
/* ===================================================================== */

static int eth_phy_init(void)
{
    uint16_t id1, id2;
    uint16_t bmcr, bsr;
    uint16_t adv;
    uint64_t deadline;

    id1 = mdio_read(STM32F4_ETH_PHY_ADDR, PHY_ID1);
    id2 = mdio_read(STM32F4_ETH_PHY_ADDR, PHY_ID2);
    if (id1 == 0xFFFFU || (id1 == 0U && id2 == 0U)) {
        printf("  PHY: not found at addr %u (ID1=0x%04X ID2=0x%04X)\n",
               (unsigned)STM32F4_ETH_PHY_ADDR, id1, id2);
        return -1;
    }
    printf("  PHY ID at addr %u: 0x%04X / 0x%04X\n",
           (unsigned)STM32F4_ETH_PHY_ADDR, id1, id2);

    /* Soft reset and wait. */
    (void)mdio_write(STM32F4_ETH_PHY_ADDR, PHY_BCR, BCR_RESET);
    deadline = stm32f4_hal_time_ms() + 500U;
    do {
        bmcr = mdio_read(STM32F4_ETH_PHY_ADDR, PHY_BCR);
    } while ((bmcr & BCR_RESET) && (stm32f4_hal_time_ms() < deadline));
    if (bmcr & BCR_RESET) {
        printf("  PHY: reset did not clear\n");
        return -1;
    }

    /* Advertise full set of 10/100 capabilities. */
    adv = ANAR_100_FD | ANAR_100_HD | ANAR_10_FD | ANAR_10_HD |
          ANAR_SELECTOR_802_3;
    (void)mdio_write(STM32F4_ETH_PHY_ADDR, PHY_ANAR, adv);

    /* Enable + restart auto-neg. */
    (void)mdio_write(STM32F4_ETH_PHY_ADDR, PHY_BCR,
                     BCR_AUTONEG | BCR_RESTART_AN);

    /* Wait up to 5s for link up + AN complete. */
    deadline = stm32f4_hal_time_ms() + 5000U;
    do {
        bsr = mdio_read(STM32F4_ETH_PHY_ADDR, PHY_BSR);
        bsr = mdio_read(STM32F4_ETH_PHY_ADDR, PHY_BSR); /* latch-clear */
    } while (((bsr & (BSR_LINK | BSR_AN_COMPLETE)) !=
              (BSR_LINK | BSR_AN_COMPLETE)) &&
             (stm32f4_hal_time_ms() < deadline));

    printf("  PHY link: %s, AN: %s\n",
           (bsr & BSR_LINK) ? "UP" : "DOWN",
           (bsr & BSR_AN_COMPLETE) ? "complete" : "incomplete");

    return (bsr & BSR_LINK) ? 0 : -2;
}

/* ===================================================================== */
/* Start / stop                                                          */
/* ===================================================================== */

static void eth_start(void)
{
    /* Enable MAC TX and RX. */
    ETH_MACCR |= MACCR_TE | MACCR_RE;

    /* Small settle for FIFO controllers. */
    { volatile uint32_t d; for (d = 0; d < 10000U; d++) { } }

    /* Flush TX FIFO before starting DMA TX (matches u-boot DWC reference). */
    ETH_DMAOMR |= DMAOMR_FTF;
    {
        uint32_t t = 100000U;
        while ((ETH_DMAOMR & DMAOMR_FTF) && (t > 0U)) {
            t--;
        }
    }

    /* Start DMA RX + TX. */
    ETH_DMAOMR |= DMAOMR_SR | DMAOMR_ST;

    __asm volatile ("dsb sy" ::: "memory");

    /* Kick RX. */
    ETH_DMARPDR = 0U;
}

static void eth_stop(void)
{
    ETH_DMAOMR &= ~(DMAOMR_SR | DMAOMR_ST);
    ETH_MACCR  &= ~(MACCR_RE | MACCR_TE);
}

/* ===================================================================== */
/* RX poll / TX send                                                      */
/* ===================================================================== */

static int eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct eth_desc *desc;
    uint32_t status;
    uint32_t frame_len = 0U;

    (void)dev;
    rx_poll_count++;

    desc = &rx_ring[rx_idx];
    if (desc->des0 & RDES0_OWN)
        return 0;

    rx_pkt_count++;
    status = desc->des0;

    if (((status & (RDES0_FS | RDES0_LS)) == (RDES0_FS | RDES0_LS)) &&
        !(status & RDES0_ES)) {
        frame_len = (status & RDES0_FL_MASK) >> RDES0_FL_SHIFT;
        if (frame_len > len)
            frame_len = len;
        memcpy(frame, rx_buffers[rx_idx], frame_len);
    }

    /* Re-arm. */
    desc->des0 = RDES0_OWN;
    desc->des1 = (RX_BUF_SIZE & RDES1_RBS1_MASK);
    if (rx_idx == (RX_DESC_COUNT - 1U))
        desc->des1 |= RDES1_RER;

    __asm volatile ("dsb sy" ::: "memory");

    /* Clear RBUS if set, then kick RX. */
    if (ETH_DMASR & DMASR_RBUS)
        ETH_DMASR = DMASR_RBUS;
    ETH_DMARPDR = 0U;

    rx_idx = (rx_idx + 1U) % RX_DESC_COUNT;
    return (int)frame_len;
}

static int eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct eth_desc *desc;
    uint32_t dma_len;

    (void)dev;
    if (len == 0U || len > TX_BUF_SIZE) {
        tx_err_count++;
        return -1;
    }

    desc = &tx_ring[tx_idx];
    if (desc->des0 & TDES0_OWN) {
        tx_err_count++;
        return -2;
    }

    tx_pkt_count++;

    memcpy(tx_buffers[tx_idx], frame, len);
    dma_len = (len < FRAME_MIN_LEN) ? FRAME_MIN_LEN : len;
    if (dma_len > len)
        memset(tx_buffers[tx_idx] + len, 0, dma_len - len);

    desc->des2 = (uint32_t)tx_buffers[tx_idx];
    desc->des1 = (dma_len & TDES1_TBS1_MASK);

    __asm volatile ("dsb sy" ::: "memory");

    /* On STM32F4 GMAC, frame control (FS/LS/IC/TCH) lives in TDES0
     * alongside the OWN doorbell.  Write everything together; the DMA
     * latches the bits after OWN flips to 1. */
    desc->des0 = TDES0_OWN | TDES0_IC | TDES0_LS | TDES0_FS | TDES0_TCH;

    __asm volatile ("dsb sy" ::: "memory");

    /* Clear TBUS if set, then kick TX. */
    if (ETH_DMASR & DMASR_TBUS)
        ETH_DMASR = DMASR_TBUS;
    ETH_DMATPDR = 0U;

    tx_idx = (tx_idx + 1U) % TX_DESC_COUNT;
    return (int)len;
}

/* ===================================================================== */
/* Public                                                                */
/* ===================================================================== */

static void stm32f4_eth_default_mac(uint8_t mac[6])
{
    mac[0] = 0x02; /* locally administered */
    mac[1] = 0x55;
    mac[2] = 0xAA;
    mac[3] = 0xBB;
    mac[4] = 0xF4; /* 'F4' family */
    mac[5] = 0x37; /* '37' */
}

void stm32f4_eth_get_stats(uint32_t *polls, uint32_t *pkts, uint32_t *tx_pkts,
                           uint32_t *tx_errs)
{
    if (polls)    *polls    = rx_poll_count;
    if (pkts)     *pkts     = rx_pkt_count;
    if (tx_pkts)  *tx_pkts  = tx_pkt_count;
    if (tx_errs)  *tx_errs  = tx_err_count;
}

uint32_t stm32f4_eth_get_dma_status(void)
{
    return ETH_DMASR;
}

void stm32f4_eth_get_mac_diag(uint32_t *mac_cfg, uint32_t *mac_dbg)
{
    if (mac_cfg) *mac_cfg = ETH_MACCR;
    if (mac_dbg) *mac_dbg = ETH_MACDBGR;
}

int stm32f4_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    uint8_t local_mac[6];
    int ret;

    if (ll == NULL)
        return -1;

    if (mac == NULL) {
        stm32f4_eth_default_mac(local_mac);
        mac = local_mac;
    }

    memcpy(ll->mac, mac, 6);
    strncpy(ll->ifname, "eth0", sizeof(ll->ifname) - 1);
    ll->ifname[sizeof(ll->ifname) - 1] = '\0';
    ll->poll = eth_poll;
    ll->send = eth_send;

    eth_stop();

    if (eth_hw_reset() != 0)
        return -1;

    eth_config_dma();
    eth_init_desc();
    eth_config_mac(mac);

    ret = eth_phy_init();

    eth_config_speed_duplex();
    eth_start();

    return ret;
}

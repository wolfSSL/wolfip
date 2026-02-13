/* va416xx_eth.c
 *
 * VA416xx Ethernet driver for wolfIP
 * Synopsys DesignWare GMAC with normal (legacy) descriptor format
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
#include "va416xx_eth.h"
#include "va416xx.h"
#include "va416xx_hal_ethernet.h"

/* ========================================================================= */
/* Normal (Legacy) DMA Descriptor Bit Definitions                            */
/*                                                                           */
/* The VA416xx uses the Synopsys DesignWare GMAC with normal descriptors.    */
/* This is fundamentally different from the STM32H5 enhanced/QoS format:    */
/*   - OWN/FS/LS/FL are in des0 (not des3)                                  */
/*   - Buffer address is in des2 (not des0)                                  */
/*   - Ring wraps via TER/RER bits (not tail pointer registers)             */
/*   - DMA kicked via poll demand registers (not tail pointer updates)       */
/* ========================================================================= */

/* --- TX Descriptor TDES0 bits --- */
#define TDES0_OWN       (1U << 31)  /* DMA owns descriptor */
#define TDES0_IC        (1U << 30)  /* Interrupt on Completion */
#define TDES0_LS        (1U << 29)  /* Last Segment */
#define TDES0_FS        (1U << 28)  /* First Segment */
#define TDES0_DC        (1U << 27)  /* Disable CRC */
#define TDES0_DP        (1U << 26)  /* Disable Padding */
#define TDES0_TER       (1U << 21)  /* Transmit End of Ring */
#define TDES0_TCH       (1U << 20)  /* Second Address Chained */

/* --- TX Descriptor TDES1 bits --- */
#define TDES1_TBS1_MASK  0x1FFFU    /* Buffer 1 Size [12:0] */
#define TDES1_TBS2_SHIFT 16
#define TDES1_TBS2_MASK  0x1FFF0000U /* Buffer 2 Size [28:16] */

/* --- RX Descriptor RDES0 bits --- */
#define RDES0_OWN       (1U << 31)  /* DMA owns descriptor */
#define RDES0_AFM       (1U << 30)  /* DA Filter Fail */
#define RDES0_FL_SHIFT  16          /* Frame Length shift */
#define RDES0_FL_MASK   0x3FFF0000U /* Frame Length [29:16] */
#define RDES0_ES        (1U << 15)  /* Error Summary */
#define RDES0_FS        (1U <<  9)  /* First Descriptor */
#define RDES0_LS        (1U <<  8)  /* Last Descriptor */

/* --- RX Descriptor RDES1 bits --- */
#define RDES1_DIC       (1U << 31)  /* Disable Interrupt on Completion */
#define RDES1_RER       (1U << 25)  /* Receive End of Ring */
#define RDES1_RCH       (1U << 24)  /* Second Address Chained */
#define RDES1_RBS2_SHIFT 11
#define RDES1_RBS2_MASK  0x003FF800U /* Buffer 2 Size [21:11] */
#define RDES1_RBS1_MASK  0x000007FFU /* Buffer 1 Size [10:0] */

/* ========================================================================= */
/* DMA Descriptor Structure (4 x 32-bit words, 16 bytes)                    */
/* ========================================================================= */

struct eth_desc {
    volatile uint32_t des0;  /* TX: status/OWN/FS/LS  RX: status/OWN/FL */
    volatile uint32_t des1;  /* TX: TBS1/TBS2         RX: RBS1/RBS2/RER */
    volatile uint32_t des2;  /* Buffer 1 address */
    volatile uint32_t des3;  /* Buffer 2 / next descriptor address */
};

/* ========================================================================= */
/* Static Buffers and Descriptor Rings                                       */
/* ========================================================================= */

#define RX_DESC_COUNT   3U
#define TX_DESC_COUNT   3U
#define RX_BUF_SIZE     LINK_MTU
#define TX_BUF_SIZE     LINK_MTU
#define FRAME_MIN_LEN   60U

static struct eth_desc rx_ring[RX_DESC_COUNT] __attribute__((aligned(16)));
static struct eth_desc tx_ring[TX_DESC_COUNT] __attribute__((aligned(16)));
static uint8_t rx_buffers[RX_DESC_COUNT][RX_BUF_SIZE] __attribute__((aligned(4)));
static uint8_t tx_buffers[TX_DESC_COUNT][TX_BUF_SIZE] __attribute__((aligned(4)));
static uint8_t rx_staging_buffer[RX_BUF_SIZE] __attribute__((aligned(4)));

static uint32_t rx_idx;
static uint32_t tx_idx;

static uint32_t rx_poll_count;
static uint32_t rx_pkt_count;

/* ========================================================================= */
/* Hardware Reset                                                            */
/* ========================================================================= */

static int eth_hw_reset(void)
{
    uint32_t timeout = 1000000U;

    /* DMA software reset */
    VOR_ETH->DMA_BUS_MODE |= ETH_DMA_BUS_MODE_SWR_Msk;
    while ((VOR_ETH->DMA_BUS_MODE & ETH_DMA_BUS_MODE_SWR_Msk) && (timeout > 0U)) {
        timeout--;
    }
    return (timeout > 0U) ? 0 : -1;
}

/* ========================================================================= */
/* MAC Configuration                                                         */
/* ========================================================================= */

static void eth_config_mac(const uint8_t *mac)
{
    /* Set MAC address via SDK HAL */
    HAL_SetMacAddr((uint8_t *)mac);

    /* Configure MAC: 100Mbps, Full Duplex, Auto Pad/CRC Strip, IP Checksum */
    VOR_ETH->MAC_CONFIG = ETH_MAC_CONFIG_FES_Msk |
                          ETH_MAC_CONFIG_DM_Msk |
                          ETH_MAC_CONFIG_ACS_Msk |
                          ETH_MAC_CONFIG_IPC_Msk;

    /* Frame filter: promiscuous for initial bring-up */
    VOR_ETH->MAC_FRAME_FLTR = ETH_MAC_FRAME_FLTR_PR_Msk;
}

/* ========================================================================= */
/* Speed/Duplex Configuration from PHY                                       */
/* ========================================================================= */

static void eth_config_speed_duplex(void)
{
    uint32_t maccr;
    uint16_t phy_ctrl2;

    maccr = VOR_ETH->MAC_CONFIG;
    maccr &= ~(ETH_MAC_CONFIG_FES_Msk | ETH_MAC_CONFIG_DM_Msk);

    /* Read PHY Control 2 register for negotiated speed/duplex */
    HAL_ReadPhyReg(PHY_CONTROL_TWO, &phy_ctrl2);
    HAL_ReadPhyReg(PHY_CONTROL_TWO, &phy_ctrl2); /* double-read per SDK pattern */

    /* KSZ8041TL PHY Control 2 register bits [4:2]:
     * Bit 4: MDI/MDI-X state
     * Bit 3: 1=Full Duplex
     * Bit 2: 1=100Mbps, 0=10Mbps
     */
    if (phy_ctrl2 & (1U << 2)) {
        maccr |= ETH_MAC_CONFIG_FES_Msk;  /* 100 Mbps */
    }
    if (phy_ctrl2 & (1U << 3)) {
        maccr |= ETH_MAC_CONFIG_DM_Msk;   /* Full Duplex */
    }

    VOR_ETH->MAC_CONFIG = maccr;
}

/* ========================================================================= */
/* DMA Configuration                                                         */
/* ========================================================================= */

static void eth_config_dma(void)
{
    /* DMA Bus Mode: PBL=8, Fixed Burst, Address-Aligned Beats */
    VOR_ETH->DMA_BUS_MODE = (8U << ETH_DMA_BUS_MODE_PBL_Pos) |
                             ETH_DMA_BUS_MODE_FB_Msk |
                             ETH_DMA_BUS_MODE_AAL_Msk;

    /* Operation Mode: Store-and-Forward TX+RX, Operate on Second Frame */
    VOR_ETH->DMA_OPER_MODE = ETH_DMA_OPER_MODE_TSF_Msk |
                              ETH_DMA_OPER_MODE_RSF_Msk |
                              ETH_DMA_OPER_MODE_OSF_Msk;

    /* Disable all DMA interrupts (polling mode) */
    VOR_ETH->DMA_INTR_EN = 0;
}

/* ========================================================================= */
/* Descriptor Ring Initialization                                            */
/* ========================================================================= */

static void eth_init_desc(void)
{
    uint32_t i;

    /* Clear all TX descriptors - CPU owns (OWN=0) */
    for (i = 0; i < TX_DESC_COUNT; i++) {
        tx_ring[i].des0 = 0;
        tx_ring[i].des1 = 0;
        tx_ring[i].des2 = (uint32_t)tx_buffers[i];
        tx_ring[i].des3 = 0;
    }
    /* Set TER on last TX descriptor for ring wrap */
    tx_ring[TX_DESC_COUNT - 1U].des0 = TDES0_TER;

    /* Initialize RX descriptors - DMA owns (OWN=1) */
    for (i = 0; i < RX_DESC_COUNT; i++) {
        rx_ring[i].des0 = RDES0_OWN;
        rx_ring[i].des1 = (RX_BUF_SIZE & RDES1_RBS1_MASK);
        rx_ring[i].des2 = (uint32_t)rx_buffers[i];
        rx_ring[i].des3 = 0;
    }
    /* Set RER on last RX descriptor for ring wrap */
    rx_ring[RX_DESC_COUNT - 1U].des1 |= RDES1_RER;

    rx_idx = 0;
    tx_idx = 0;

    __DSB();

    /* Program descriptor list base addresses */
    VOR_ETH->DMA_RX_DESC_LIST_ADDR = (uint32_t)&rx_ring[0];
    VOR_ETH->DMA_TX_DESC_LIST_ADDR = (uint32_t)&tx_ring[0];

    __DSB();
}

/* ========================================================================= */
/* Start / Stop                                                              */
/* ========================================================================= */

static void eth_start(void)
{
    /* Enable MAC TX and RX */
    VOR_ETH->MAC_CONFIG |= ETH_MAC_CONFIG_TE_Msk | ETH_MAC_CONFIG_RE_Msk;

    /* Start DMA TX and RX via DMA_OPER_MODE */
    VOR_ETH->DMA_OPER_MODE |= ETH_DMA_OPER_MODE_ST_Msk |
                               ETH_DMA_OPER_MODE_SR_Msk;

    __DSB();

    /* Kick RX DMA to start processing descriptors */
    VOR_ETH->DMA_RX_POLL_DEMAND = 0;
}

static void eth_stop(void)
{
    /* Stop DMA TX and RX */
    VOR_ETH->DMA_OPER_MODE &= ~(ETH_DMA_OPER_MODE_ST_Msk |
                                  ETH_DMA_OPER_MODE_SR_Msk);

    /* Disable MAC TX and RX */
    VOR_ETH->MAC_CONFIG &= ~(ETH_MAC_CONFIG_TE_Msk | ETH_MAC_CONFIG_RE_Msk);
}

/* ========================================================================= */
/* PHY Initialization (uses SDK HAL)                                         */
/* ========================================================================= */

static int eth_phy_init(void)
{
    uint16_t phy_status;
    uint16_t phy_id_hi;
    uint32_t timeout;

    /* Set GMII clock divider in MAC_GMII_ADDR.CR field
     * VA416xx default HBO = 20MHz -> use DIV16 (20-35 MHz range)
     * If using EXTCLK=40MHz with PLL, may need DIV26 or DIV42
     */
    VOR_ETH->MAC_GMII_ADDR = (VOR_ETH->MAC_GMII_ADDR &
        ~ETH_MAC_GMII_ADDR_CR_Msk) |
        (PHY_MACMII_CR_DIV16 << ETH_MAC_GMII_ADDR_CR_Pos);

    /* Read PHY ID to verify communication */
    HAL_ReadPhyReg(PHY_ID_HI_REG, &phy_id_hi);
    HAL_ReadPhyReg(PHY_ID_HI_REG, &phy_id_hi); /* double-read */
    if (phy_id_hi == 0xFFFFU || phy_id_hi == 0x0000U) {
        return -1; /* PHY not found */
    }

    /* Reset PHY */
    HAL_ResetPHY();

    /* Wait for reset to complete */
    for (volatile uint32_t i = 0; i < 100000; i++) { }

    /* Enable auto-negotiation */
    HAL_SetPhyAutoNegotiate(PHYAUTONEGEN);

    /* Wait for link up */
    timeout = 500000U;
    do {
        HAL_ReadPhyReg(PHY_STATUS_REG, &phy_status);
        HAL_ReadPhyReg(PHY_STATUS_REG, &phy_status); /* double-read */
    } while (!(phy_status & MIISTATUS_PHY_LINK) && --timeout);

    return (phy_status & MIISTATUS_PHY_LINK) ? 0 : -2;
}

/* ========================================================================= */
/* Poll (RX) - Called from wolfIP_poll()                                     */
/* ========================================================================= */

static int eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct eth_desc *desc;
    uint32_t status;
    uint32_t frame_len = 0;

    (void)dev;
    rx_poll_count++;

    desc = &rx_ring[rx_idx];

    /* Check if DMA still owns this descriptor */
    if (desc->des0 & RDES0_OWN)
        return 0;

    rx_pkt_count++;
    status = desc->des0;

    /* Check for complete single-frame (FS + LS) with no errors */
    if (((status & (RDES0_FS | RDES0_LS)) == (RDES0_FS | RDES0_LS)) &&
        !(status & RDES0_ES)) {
        /* Extract frame length from RDES0[29:16] */
        frame_len = (status & RDES0_FL_MASK) >> RDES0_FL_SHIFT;
        if (frame_len > len)
            frame_len = len;

        /* Copy via staging buffer (avoids DMA/CPU bus contention) */
        memcpy(rx_staging_buffer, rx_buffers[rx_idx], frame_len);
        memcpy(frame, rx_staging_buffer, frame_len);
    }

    /* Re-arm descriptor: give back to DMA */
    desc->des0 = RDES0_OWN;
    desc->des1 = (RX_BUF_SIZE & RDES1_RBS1_MASK);
    /* Preserve RER on last descriptor */
    if (rx_idx == (RX_DESC_COUNT - 1U))
        desc->des1 |= RDES1_RER;

    __DSB();

    /* Clear RU (Receive Buffer Unavailable) if set */
    if (VOR_ETH->DMA_STATUS & ETH_DMA_STATUS_RU_Msk) {
        VOR_ETH->DMA_STATUS = ETH_DMA_STATUS_RU_Msk;
    }

    /* Kick RX DMA to resume polling */
    VOR_ETH->DMA_RX_POLL_DEMAND = 0;

    rx_idx = (rx_idx + 1U) % RX_DESC_COUNT;
    return (int)frame_len;
}

/* ========================================================================= */
/* Send (TX) - Called from wolfIP stack                                      */
/* ========================================================================= */

static int eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct eth_desc *desc;
    uint32_t dma_len;

    (void)dev;
    if (len == 0 || len > TX_BUF_SIZE)
        return -1;

    desc = &tx_ring[tx_idx];

    /* Check if CPU owns this descriptor (OWN=0) */
    if (desc->des0 & TDES0_OWN)
        return -2;

    /* Copy frame to DMA buffer */
    memcpy(tx_buffers[tx_idx], frame, len);

    /* Pad to minimum frame size */
    dma_len = (len < FRAME_MIN_LEN) ? FRAME_MIN_LEN : len;
    if (dma_len > len)
        memset(tx_buffers[tx_idx] + len, 0, dma_len - len);

    /* Set buffer address in des2 */
    desc->des2 = (uint32_t)tx_buffers[tx_idx];

    /* Set buffer size in des1 */
    desc->des1 = (dma_len & TDES1_TBS1_MASK);

    __DSB();

    /* Set des0: OWN + FS + LS + IC, preserve TER on last descriptor */
    desc->des0 = TDES0_OWN | TDES0_FS | TDES0_LS | TDES0_IC;
    if (tx_idx == (TX_DESC_COUNT - 1U))
        desc->des0 |= TDES0_TER;

    __DSB();

    /* Clear TU (Transmit Buffer Unavailable) if set */
    if (VOR_ETH->DMA_STATUS & ETH_DMA_STATUS_TU_Msk) {
        VOR_ETH->DMA_STATUS = ETH_DMA_STATUS_TU_Msk;
    }

    /* Kick TX DMA to start polling descriptors */
    VOR_ETH->DMA_TX_POLL_DEMAND = 0;

    tx_idx = (tx_idx + 1U) % TX_DESC_COUNT;
    return (int)len;
}

/* ========================================================================= */
/* Default MAC Address                                                       */
/* ========================================================================= */

static void va416xx_eth_generate_mac(uint8_t mac[6])
{
    mac[0] = 0x02;  /* locally administered */
    mac[1] = 0x11;
    mac[2] = 0xAA;
    mac[3] = 0xBB;
    mac[4] = 0x44; /* '4' for VA416xx */
    mac[5] = 0x16;
}

/* ========================================================================= */
/* Statistics                                                                */
/* ========================================================================= */

void va416xx_eth_get_stats(uint32_t *polls, uint32_t *pkts)
{
    if (polls) *polls = rx_poll_count;
    if (pkts) *pkts = rx_pkt_count;
}

/* ========================================================================= */
/* Initialization                                                            */
/* ========================================================================= */

int va416xx_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    uint8_t local_mac[6];
    int ret;

    if (ll == NULL)
        return -1;

    if (mac == NULL) {
        va416xx_eth_generate_mac(local_mac);
        mac = local_mac;
    }

    memcpy(ll->mac, mac, 6);
    strncpy(ll->ifname, "eth0", sizeof(ll->ifname) - 1);
    ll->ifname[sizeof(ll->ifname) - 1] = '\0';
    ll->poll = eth_poll;
    ll->send = eth_send;

    /* 1. Stop any running DMA/MAC */
    eth_stop();

    /* 2. DMA Software Reset */
    if (eth_hw_reset() != 0)
        return -2;

    /* 3. Configure DMA (bus mode, operation mode) */
    eth_config_dma();

    /* 4. Initialize descriptor rings */
    eth_init_desc();

    /* 5. Configure MAC (address, speed, duplex, filter) */
    eth_config_mac(mac);

    /* 6. Initialize PHY via SDK HAL */
    ret = eth_phy_init();

    /* 7. Update MAC speed/duplex from PHY negotiation result */
    if (ret == 0) {
        eth_config_speed_duplex();
    }

    /* 8. Start MAC and DMA */
    eth_start();

    return ret;
}

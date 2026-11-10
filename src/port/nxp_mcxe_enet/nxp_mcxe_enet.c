/* nxp_mcxe_enet.c
 *
 * NXP MCX E247 ethernet driver for wolfIP, built on the MCUXpresso SDK
 * fsl_enet driver and the LAN8741 PHY component. The driver is polled and
 * uses no interrupts.
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
#include "fsl_enet.h"
#include "fsl_phylan8741.h"
#include "nxp_mcxe_enet.h"

#define ENET_RX_BD_NUM      8U
#define ENET_TX_BD_NUM      4U
#define ENET_BUF_SIZE       SDK_SIZEALIGN(ENET_FRAME_MAX_FRAMELEN, \
                                ENET_BUFF_ALIGNMENT)
#define ENET_MIN_FRAME_LEN  60U

#define PHY_RESET_PIN       3U      /* PTC3 */
#define PHY_RESET_US        25000U
#define PHY_LINK_POLL_US    10000U
#define PHY_LINK_POLLS      500U    /* 5 seconds */

/* The linker must place these in SRAM_U, which is outside the code cache. */
SDK_ALIGN(static enet_rx_bd_struct_t g_rx_bd[ENET_RX_BD_NUM],
    ENET_BUFF_ALIGNMENT);
SDK_ALIGN(static enet_tx_bd_struct_t g_tx_bd[ENET_TX_BD_NUM],
    ENET_BUFF_ALIGNMENT);
SDK_ALIGN(static uint8_t g_rx_buf[ENET_RX_BD_NUM][ENET_BUF_SIZE],
    ENET_BUFF_ALIGNMENT);
SDK_ALIGN(static uint8_t g_tx_buf[ENET_TX_BD_NUM][ENET_BUF_SIZE],
    ENET_BUFF_ALIGNMENT);

static enet_handle_t g_handle;
static phy_handle_t g_phy;
static phy_lan8741_resource_t g_phy_resource;
static int g_running;
static int g_phy_addr = -1;

static status_t mdio_write(uint8_t phy, uint8_t reg, uint16_t data)
{
    return ENET_MDIOWrite(ENET, phy, reg, data);
}

static status_t mdio_read(uint8_t phy, uint8_t reg, uint16_t *data)
{
    return ENET_MDIORead(ENET, phy, reg, data);
}

static void enet_pins_init(uint32_t sysclk)
{
    CLOCK_EnableClock(kCLOCK_PortB);
    CLOCK_EnableClock(kCLOCK_PortC);
    CLOCK_EnableClock(kCLOCK_PortD);
    CLOCK_EnableClock(kCLOCK_PortE);

    /* MDIO needs its GPIO direction set as an output before use (RM 51.1) */
    PORTB->PCR[4] = PORT_PCR_MUX(5);        /* MDIO */
    GPIOB->PDDR |= (1UL << 4);
    PORTC->PCR[0] = PORT_PCR_MUX(4);        /* RXD1 */
    PORTC->PCR[1] = PORT_PCR_MUX(5);        /* RXD0 */
    PORTC->PCR[17] = PORT_PCR_MUX(5);       /* RX_DV */
    PORTD->PCR[11] = PORT_PCR_MUX(5);       /* TX_CLK (50 MHz reference) */
    /* Transmit pads need high drive strength (RM 51.1) */
    PORTC->PCR[2] = PORT_PCR_MUX(5) | PORT_PCR_DSE_MASK;    /* TXD0 */
    PORTD->PCR[7] = PORT_PCR_MUX(5) | PORT_PCR_DSE_MASK;    /* TXD1 */
    PORTD->PCR[12] = PORT_PCR_MUX(5) | PORT_PCR_DSE_MASK;   /* TX_EN */
    PORTE->PCR[8] = PORT_PCR_MUX(5) | PORT_PCR_DSE_MASK;    /* MDC */

    /* Pulse the PHY reset */
    PORTC->PCR[PHY_RESET_PIN] = PORT_PCR_MUX(1);
    GPIOC->PCOR = (1UL << PHY_RESET_PIN);
    GPIOC->PDDR |= (1UL << PHY_RESET_PIN);
    SDK_DelayAtLeastUs(PHY_RESET_US, sysclk);
    GPIOC->PSOR = (1UL << PHY_RESET_PIN);
    SDK_DelayAtLeastUs(PHY_RESET_US, sysclk);
}

static int eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    uint32_t flen = 0;
    status_t status;
    (void)dev;

    status = ENET_GetRxFrameSize(&g_handle, &flen, 0);
    if (status == kStatus_ENET_RxFrameEmpty)
        return 0;
    if (status != kStatus_Success || flen > len) {
        (void)ENET_ReadFrame(ENET, &g_handle, NULL, 0, 0, NULL);
        return 0;
    }
    if (ENET_ReadFrame(ENET, &g_handle, frame, flen, 0, NULL) != kStatus_Success)
        return 0;
    return (int)flen;
}

static int eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    uint8_t padded[ENET_MIN_FRAME_LEN];
    const uint8_t *data = (const uint8_t *)frame;
    uint32_t tx_len = len;
    status_t status;
    (void)dev;

    if (len == 0 || len > ENET_FRAME_MAX_FRAMELEN)
        return -1;
    if (len < ENET_MIN_FRAME_LEN) {
        memcpy(padded, frame, len);
        memset(padded + len, 0, ENET_MIN_FRAME_LEN - len);
        data = padded;
        tx_len = ENET_MIN_FRAME_LEN;
    }
    status = ENET_SendFrame(ENET, &g_handle, data, tx_len, 0, false, NULL);
    if (status == kStatus_ENET_TxFrameBusy)
        return -2;
    return (status == kStatus_Success) ? (int)len : -1;
}

int nxp_mcxe_enet_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    static const uint8_t default_mac[6] = NXP_MCXE_ENET_MAC;
    enet_config_t config;
    enet_buffer_config_t buffers;
    phy_config_t phy_config;
    phy_speed_t speed = kPHY_Speed100M;
    phy_duplex_t duplex = kPHY_FullDuplex;
    bool link = false;
    bool autoneg = false;
    uint32_t sysclk;
    uint32_t polls;

    if (ll == NULL)
        return -1;
    if (mac == NULL)
        mac = default_mac;

    if (g_running) {
        ENET_Deinit(ENET);
        g_running = 0;
    }
    g_phy_addr = -1;

    /* The system MPU blocks the ENET bus master by default */
    SYSMPU->CESR &= ~SYSMPU_CESR_VLD_MASK;

    sysclk = CLOCK_GetCoreSysClkFreq();
    enet_pins_init(sysclk);

    CLOCK_EnableClock(kCLOCK_Enet);
    ENET_SetSMI(ENET, sysclk, false);

    g_phy_resource.read = mdio_read;
    g_phy_resource.write = mdio_write;
    memset(&phy_config, 0, sizeof(phy_config));
    phy_config.phyAddr = NXP_MCXE_ENET_PHY_ADDR;
    phy_config.ops = &phylan8741_ops;
    phy_config.resource = &g_phy_resource;
    phy_config.autoNeg = true;
    if (PHY_Init(&g_phy, &phy_config) != kStatus_Success)
        return -2;
    g_phy_addr = (int)NXP_MCXE_ENET_PHY_ADDR;

    for (polls = 0; polls < PHY_LINK_POLLS; polls++) {
        (void)PHY_GetLinkStatus(&g_phy, &link);
        if (link) {
            (void)PHY_GetAutoNegotiationStatus(&g_phy, &autoneg);
            if (autoneg)
                break;
        }
        SDK_DelayAtLeastUs(PHY_LINK_POLL_US, sysclk);
    }
    if (link && autoneg)
        (void)PHY_GetLinkSpeedDuplex(&g_phy, &speed, &duplex);

    ENET_GetDefaultConfig(&config);
    config.miiMode = kENET_RmiiMode;
    config.miiSpeed = (enet_mii_speed_t)speed;
    config.miiDuplex = (enet_mii_duplex_t)duplex;

    memset(&buffers, 0, sizeof(buffers));
    buffers.rxBdNumber = ENET_RX_BD_NUM;
    buffers.txBdNumber = ENET_TX_BD_NUM;
    buffers.rxBuffSizeAlign = ENET_BUF_SIZE;
    buffers.txBuffSizeAlign = ENET_BUF_SIZE;
    buffers.rxBdStartAddrAlign = g_rx_bd;
    buffers.txBdStartAddrAlign = g_tx_bd;
    buffers.rxBufferAlign = &g_rx_buf[0][0];
    buffers.txBufferAlign = &g_tx_buf[0][0];

    if (ENET_Init(ENET, &g_handle, &config, &buffers, (uint8_t *)mac,
            sysclk) != kStatus_Success) {
        return -3;
    }
    g_running = 1;
    ENET_ActiveRead(ENET);

    memcpy(ll->mac, mac, 6);
    memset(ll->ifname, 0, sizeof(ll->ifname));
    memcpy(ll->ifname, "eth0", 4);
    ll->mtu = LINK_MTU;
    ll->poll = eth_poll;
    ll->send = eth_send;
    return 0;
}

int nxp_mcxe_enet_phy_addr(void)
{
    return g_phy_addr;
}

uint16_t nxp_mcxe_enet_phy_read(uint8_t reg)
{
    uint16_t value = 0xFFFFU;

    if (g_phy_addr < 0 ||
        ENET_MDIORead(ENET, (uint8_t)g_phy_addr, reg, &value) != kStatus_Success) {
        return 0xFFFFU;
    }
    return value;
}

uint32_t nxp_mcxe_enet_link_up(void)
{
    bool link = false;

    if (g_phy_addr < 0)
        return 0;
    (void)PHY_GetLinkStatus(&g_phy, &link);
    return link ? 1U : 0U;
}

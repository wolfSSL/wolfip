/* board.h
 *
 * Copyright (C) 2024-2026 wolfSSL Inc.
 *
 * Minimal board configuration for STM32H563ZI Nucleo-144
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

#ifndef BOARD_H
#define BOARD_H

#include <stdint.h>
#include <stddef.h>
#include <wolfHAL/wolfHAL.h>

extern whal_Eth g_whalEth;
extern whal_EthPhy g_whalEthPhy;
extern whal_Uart g_whalUart;
extern whal_Rng g_whalRng;

extern whal_Timeout g_whalTimeout;
extern volatile uint32_t g_tick;

/* Ethernet PHY: LAN8742A on MDIO address 0 */
#define BOARD_ETH_PHY_ADDR 0

enum {
    UART_TX_PIN,
    UART_RX_PIN,
    ETH_RMII_REF_CLK_PIN,
    ETH_RMII_MDIO_PIN,
    ETH_RMII_MDC_PIN,
    ETH_RMII_CRS_DV_PIN,
    ETH_RMII_RXD0_PIN,
    ETH_RMII_RXD1_PIN,
    ETH_RMII_TX_EN_PIN,
    ETH_RMII_TXD0_PIN,
    ETH_RMII_TXD1_PIN,
    PIN_COUNT,
};

whal_Error board_init(void);
whal_Error board_deinit(void);
uint32_t board_get_tick(void);
#endif /* BOARD_H */

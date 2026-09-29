/* tc4xx_eth_board.h
 *
 * Board defaults for the TC4xx GETH driver: KIT_TC4D7_LITE.
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
#ifndef TC4XX_ETH_BOARD_H
#define TC4XX_ETH_BOARD_H

#include "IfxGeth_PinMap.h"

#ifndef TC4XX_ETH_PIN_REFCLK
#define TC4XX_ETH_PIN_REFCLK    IfxGeth0_P0_REFCLKD_P16_2_IN
#endif
#ifndef TC4XX_ETH_PIN_CRSDV
#define TC4XX_ETH_PIN_CRSDV     IfxGeth0_P0_CRSDVC_P16_1_IN
#endif
#ifndef TC4XX_ETH_PIN_RXD0
#define TC4XX_ETH_PIN_RXD0      IfxGeth0_P0_RXD0D_P16_4_IN
#endif
#ifndef TC4XX_ETH_PIN_RXD1
#define TC4XX_ETH_PIN_RXD1      IfxGeth0_P0_RXD1D_P16_0_IN
#endif
#ifndef TC4XX_ETH_PIN_TXEN
#define TC4XX_ETH_PIN_TXEN      IfxGeth0_P0_RMIIC_TXEN_P16_13_OUT
#endif
#ifndef TC4XX_ETH_PIN_TXD0
#define TC4XX_ETH_PIN_TXD0      IfxGeth0_P0_RMIIC_TXD0_P16_6_OUT
#endif
#ifndef TC4XX_ETH_PIN_TXD1
#define TC4XX_ETH_PIN_TXD1      IfxGeth0_P0_RMIIC_TXD1_P16_8_OUT
#endif
#ifndef TC4XX_ETH_PIN_MDC
#define TC4XX_ETH_PIN_MDC       IfxGeth0_P0_MDC_P21_2_OUT
#endif
#ifndef TC4XX_ETH_PIN_MDIO
#define TC4XX_ETH_PIN_MDIO      IfxGeth0_PX_MDIO_P21_3_INOUT
#endif

/* Tried first; the driver scans the bus if nothing answers there. */
#ifndef TC4XX_ETH_PHY_ADDR
#define TC4XX_ETH_PHY_ADDR      0u
#endif

#ifndef TC4XX_ETH_DEFAULT_MAC
#define TC4XX_ETH_DEFAULT_MAC   { 0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u }
#endif

#ifndef TC4XX_ETH_PHY_TIMEOUT_MS
#define TC4XX_ETH_PHY_TIMEOUT_MS   1000u
#endif
#ifndef TC4XX_ETH_LINK_TIMEOUT_MS
#define TC4XX_ETH_LINK_TIMEOUT_MS  5000u
#endif

#ifndef TC4XX_ETH_RX_IRQ
#define TC4XX_ETH_RX_IRQ           0
#endif
#if TC4XX_ETH_RX_IRQ
#ifndef TC4XX_ETH_RX_IRQ_PRIO
#error "TC4XX_ETH_RX_IRQ needs TC4XX_ETH_RX_IRQ_PRIO, unique on its CPU"
#endif
#ifndef TC4XX_ETH_RX_IRQ_TOS
#define TC4XX_ETH_RX_IRQ_TOS    IfxSrc_Tos_cpu0
#endif
#ifndef TC4XX_ETH_RX_IRQ_VECTAB
#define TC4XX_ETH_RX_IRQ_VECTAB 0
#endif
#endif

#endif /* TC4XX_ETH_BOARD_H */

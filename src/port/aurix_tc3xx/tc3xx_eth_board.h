/* tc3xx_eth_board.h
 *
 * Board defaults for the TC3xx GETH driver: KIT_A2G_TC375_LITE.
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
#ifndef TC3XX_ETH_BOARD_H
#define TC3XX_ETH_BOARD_H

#include "IfxGeth_PinMap.h"

#ifndef TC3XX_ETH_MODULE
#define TC3XX_ETH_MODULE        MODULE_GETH
#endif

#ifndef TC3XX_ETH_PIN_REFCLK
#define TC3XX_ETH_PIN_REFCLK    IfxGeth_REFCLKA_P11_12_IN
#endif
#ifndef TC3XX_ETH_PIN_CRSDV
#define TC3XX_ETH_PIN_CRSDV     IfxGeth_CRSDVA_P11_11_IN
#endif
#ifndef TC3XX_ETH_PIN_RXD0
#define TC3XX_ETH_PIN_RXD0      IfxGeth_RXD0A_P11_10_IN
#endif
#ifndef TC3XX_ETH_PIN_RXD1
#define TC3XX_ETH_PIN_RXD1      IfxGeth_RXD1A_P11_9_IN
#endif
#ifndef TC3XX_ETH_PIN_TXEN
#define TC3XX_ETH_PIN_TXEN      IfxGeth_TXEN_P11_6_OUT
#endif
#ifndef TC3XX_ETH_PIN_TXD0
#define TC3XX_ETH_PIN_TXD0      IfxGeth_TXD0_P11_3_OUT
#endif
#ifndef TC3XX_ETH_PIN_TXD1
#define TC3XX_ETH_PIN_TXD1      IfxGeth_TXD1_P11_2_OUT
#endif
#ifndef TC3XX_ETH_PIN_MDC
#define TC3XX_ETH_PIN_MDC       IfxGeth_MDC_P21_2_OUT
#endif
#ifndef TC3XX_ETH_PIN_MDIO
#define TC3XX_ETH_PIN_MDIO      IfxGeth_MDIO_P21_3_INOUT
#endif

/* Tried first; the driver scans the bus if nothing answers there. */
#ifndef TC3XX_ETH_PHY_ADDR
#define TC3XX_ETH_PHY_ADDR      0u
#endif

/* Locally administered; the kit's EUI-48 sits in an I2C EEPROM. */
#ifndef TC3XX_ETH_DEFAULT_MAC
#define TC3XX_ETH_DEFAULT_MAC   { 0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x03u }
#endif

#ifndef TC3XX_ETH_PHY_TIMEOUT_MS
#define TC3XX_ETH_PHY_TIMEOUT_MS   1000u
#endif
#ifndef TC3XX_ETH_LINK_TIMEOUT_MS
#define TC3XX_ETH_LINK_TIMEOUT_MS  5000u
#endif

#ifndef TC3XX_ETH_RX_IRQ
#define TC3XX_ETH_RX_IRQ           0
#endif
#if TC3XX_ETH_RX_IRQ
#ifndef TC3XX_ETH_RX_IRQ_PRIO
#error "TC3XX_ETH_RX_IRQ needs TC3XX_ETH_RX_IRQ_PRIO, unique on its CPU"
#endif
#ifndef TC3XX_ETH_RX_IRQ_TOS
#define TC3XX_ETH_RX_IRQ_TOS    IfxSrc_Tos_cpu0
#endif
#ifndef TC3XX_ETH_RX_IRQ_VECTAB
#define TC3XX_ETH_RX_IRQ_VECTAB 0
#endif
#endif

#endif /* TC3XX_ETH_BOARD_H */

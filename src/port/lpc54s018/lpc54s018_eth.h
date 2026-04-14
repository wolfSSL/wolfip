/* lpc54s018_eth.h
 *
 * LPC54S018 board-specific Ethernet configuration.
 * Wraps the shared lpc_enet driver with board parameters.
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
#ifndef WOLFIP_LPC54S018_ETH_H
#define WOLFIP_LPC54S018_ETH_H

/* Board-specific ENET parameters for LPC54S018M-EVK */
#define LPC_ENET_BASE     0x40092000UL  /* ENET peripheral base */
#define LPC_ENET_MDIO_CR  3U            /* CR=3: 35-60MHz (AHB=48MHz) */
#define LPC_ENET_1US_TIC  47U           /* (48MHz / 1MHz) - 1 */

#include "lpc_enet.h"

/* Convenience aliases matching board-specific naming */
#define lpc54s018_eth_init      lpc_enet_init
#define lpc54s018_eth_get_stats lpc_enet_get_stats

#endif /* WOLFIP_LPC54S018_ETH_H */

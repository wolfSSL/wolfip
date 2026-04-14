/* lpc_enet.h
 *
 * Common NXP LPC Ethernet driver for wolfIP.
 * Synopsys DesignWare Ethernet QoS, enhanced descriptor format.
 * Shared across LPC54018, LPC54S018, LPC546xx, and similar NXP MCUs.
 *
 * Board-specific code must define LPC_ENET_BASE, LPC_ENET_MDIO_CR,
 * and LPC_ENET_1US_TIC before compiling lpc_enet.c.
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
#ifndef WOLFIP_LPC_ENET_H
#define WOLFIP_LPC_ENET_H

#include <stdint.h>
#include "wolfip.h"

/*
 * Board must define these via CFLAGS or a board header:
 *
 *   LPC_ENET_BASE     ENET peripheral base address
 *                      (0x40092000 for LPC54S018/LPC54608)
 *
 *   LPC_ENET_MDIO_CR  MDIO clock divider (NXP LPC mapping):
 *                      CR=2: <35MHz, CR=3: 35-60MHz, CR=0: 60-100MHz,
 *                      CR=1: 100-150MHz, CR=4: 150-250MHz
 *
 *   LPC_ENET_1US_TIC  MAC 1us tick counter value: (AHB_clock_MHz - 1)
 */

int lpc_enet_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);
void lpc_enet_get_stats(uint32_t *polls, uint32_t *pkts);
uint32_t lpc_enet_get_dmacsr(void);

/* PHY diagnostic / link-state helpers */
int      lpc_enet_phy_addr(void);            /* -1 if scan failed, else 0..31 */
uint16_t lpc_enet_phy_read(uint8_t reg);     /* MDIO read of current phy_addr */

#endif /* WOLFIP_LPC_ENET_H */

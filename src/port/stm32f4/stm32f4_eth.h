/* stm32f4_eth.h
 *
 * Shared Ethernet driver for STM32F4xx (DWC GMAC legacy v1 descriptors).
 * Used by STM32F407/F417/F427/F437/F439/F469/F479 wolfIP ports.
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
#ifndef WOLFIP_STM32F4_ETH_H
#define WOLFIP_STM32F4_ETH_H

#include <stdint.h>
#include "wolfip.h"

/* Initialize the STM32F4 Ethernet MAC + DMA + PHY and hook the driver into
 * the wolfIP link-layer device.  PHY auto-negotiation is run synchronously
 * with a 5-second timeout.  Returns 0 on success, -2 if the PHY is reachable
 * but link did not come up (MAC/DMA still left running so a late link comes
 * up naturally), or -1 on a fatal init error.
 *
 * The caller must already have configured the RCC (ETHMAC/ETHMACTX/ETHMACRX
 * clocks), SYSCFG_PMC.MII_RMII_SEL, and the RMII GPIO pinmux before calling.
 */
int stm32f4_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);

void stm32f4_eth_get_stats(uint32_t *polls, uint32_t *pkts, uint32_t *tx_pkts,
                           uint32_t *tx_errs);
uint32_t stm32f4_eth_get_dma_status(void);
void stm32f4_eth_get_mac_diag(uint32_t *mac_cfg, uint32_t *mac_dbg);

#endif /* WOLFIP_STM32F4_ETH_H */

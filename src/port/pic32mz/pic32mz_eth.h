/* pic32mz_eth.h
 *
 * PIC32MZ Ethernet controller (EMAC) driver for wolfIP.
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
#ifndef PIC32MZ_ETH_H
#define PIC32MZ_ETH_H

#include <stdint.h>
#include "wolfip.h"

/* Full Ethernet init: EMAC/RMII/MDIO bring-up, LAN8740 link, MAC config, DMA
 * descriptor rings, and wiring of ll->poll / ll->send / ll->mac. Pass a 6-byte
 * MAC, or NULL for a locally-administered default. Returns 0 on link up, -2 if
 * the MAC/DMA are up but the PHY link is down (traffic flows once link rises),
 * negative on a fatal init error. */
int pic32mz_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);

/* Frames received / transmitted since init (for diagnostics). */
void pic32mz_eth_stats(uint32_t *rx, uint32_t *tx);

#ifdef PIC32_ETH_TRACE
void pic32mz_eth_diag(void);   /* dump EMAC/controller registers + descriptors */
#endif

/* Phase 2: bring the Ethernet module, RMII and MII-management block out of
 * reset and program the MDC clock divisor. Must be called before any MDIO
 * access. Returns 0 on success, negative if the controller never went idle
 * (ETHBUSY stuck). */
int pic32mz_emac_mii_init(void);

/* Clause-22 MDIO primitives. Return 0 on success, negative on timeout.
 * Signatures match the mdio_read_fn / mdio_write_fn types in phy_lan8740.h. */
int pic32mz_mdio_read(uint8_t phy_addr, uint8_t reg, uint16_t *val);
int pic32mz_mdio_write(uint8_t phy_addr, uint8_t reg, uint16_t val);

#endif /* PIC32MZ_ETH_H */

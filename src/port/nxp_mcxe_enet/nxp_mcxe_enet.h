/* nxp_mcxe_enet.h
 *
 * NXP MCX E247 ethernet driver for wolfIP, built on the MCUXpresso SDK
 * fsl_enet driver and the LAN8741 PHY component. Defaults target the
 * FRDM-MCXE247 board (RMII, PHY at MDIO address 0, reset on PTC3).
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
#ifndef WOLFIP_NXP_MCXE_ENET_H
#define WOLFIP_NXP_MCXE_ENET_H

#include <stdint.h>
#include "wolfip.h"

/* MDIO address of the PHY. */
#ifndef NXP_MCXE_ENET_PHY_ADDR
#define NXP_MCXE_ENET_PHY_ADDR  0U
#endif

/* Address used when nxp_mcxe_enet_init() is passed mac=NULL. Locally
 * administered: override it when more than one board shares a network. */
#ifndef NXP_MCXE_ENET_MAC
#define NXP_MCXE_ENET_MAC       { 0x02, 0x00, 0xE2, 0x47, 0x00, 0x01 }
#endif

/* Reset the PHY, wait for link, start the MAC, and populate ll with the MAC
 * address, interface name and poll/send callbacks. May be called again to
 * restart the interface. Returns 0 when the MAC is running, even without
 * link, or a negative value when the PHY or MAC cannot be initialized. */
int nxp_mcxe_enet_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);

/* MDIO address of the PHY, or -1 before a successful init. */
int nxp_mcxe_enet_phy_addr(void);

/* MDIO clause-22 read of the PHY (0xFFFF on error). */
uint16_t nxp_mcxe_enet_phy_read(uint8_t reg);

/* Non-zero when the PHY reports link up. */
uint32_t nxp_mcxe_enet_link_up(void);

#endif /* WOLFIP_NXP_MCXE_ENET_H */

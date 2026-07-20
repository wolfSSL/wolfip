/* phy_lan8740.h
 *
 * Microchip LAN8740 (clause-22 MDIO) PHY driver for the PIC32MZ wolfIP port.
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
#ifndef PHY_LAN8740_H
#define PHY_LAN8740_H

#include <stdint.h>

/* MDIO accessors supplied by the MAC driver (see pic32mz_eth.h). */
typedef int (*mdio_read_fn)(uint8_t phy_addr, uint8_t reg, uint16_t *val);
typedef int (*mdio_write_fn)(uint8_t phy_addr, uint8_t reg, uint16_t val);

struct phy_link {
    uint8_t  found;        /* 1 if a PHY responded on the bus */
    uint8_t  addr;         /* MDIO address of the PHY */
    uint16_t id1;          /* PHYID1 (LAN8740 OUI high = 0x0007) */
    uint16_t id2;          /* PHYID2 */
    uint8_t  link_up;      /* 1 if link is up */
    uint8_t  speed_100;    /* 1 = 100 Mbps, 0 = 10 Mbps */
    uint8_t  full_duplex;  /* 1 = full duplex, 0 = half */
};

/* Scan for the PHY, reset it, advertise all modes, run auto-negotiation and
 * wait for link. Fills *out. link_up_timeout_ms bounds the link wait.
 * Returns:
 *    0  link up (out->speed_100 / out->full_duplex are the negotiated result)
 *   -2  link-down / auto-negotiation timeout: the PHY responded and out->addr
 *       is valid, but out->link_up / speed_100 / full_duplex are all 0 (the
 *       speed/duplex read only happens after link is up). MAC bring-up may
 *       still proceed; poll phy_lan8740_link_status() for a later link-up.
 *   -1  PHY/MDIO error (no PHY found, reset stuck, or MDIO access failed) */
int phy_lan8740_bringup(mdio_read_fn rd, mdio_write_fn wr,
                        uint32_t link_up_timeout_ms, struct phy_link *out);

/* Lightweight link-status refresh for a PHY already located by bringup: read
 * BMSR and, if link is up, the SCSR speed/duplex. addr is out->addr from a
 * prior phy_lan8740_bringup(). Does NOT reset the PHY or restart auto-neg, so
 * it is safe to poll periodically on an established link. Fills out->link_up
 * and, when up, out->speed_100 / out->full_duplex (both left 0 when down).
 * Returns 0 on success, -1 on MDIO error. */
int phy_lan8740_link_status(mdio_read_fn rd, uint8_t addr, struct phy_link *out);

#endif /* PHY_LAN8740_H */

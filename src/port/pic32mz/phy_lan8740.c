/* phy_lan8740.c
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
#include <stddef.h>
#include "phy_lan8740.h"
#include "timebase.h"

#ifdef PIC32_ETH_TRACE
#include <stdio.h>
#define PHY_TRACE(s)   do { printf("[PHY] " s "\r\n"); } while (0)
#else
#define PHY_TRACE(s)   do { } while (0)
#endif

/* Standard clause-22 register addresses. */
#define REG_BMCR        0x00    /* Basic control */
#define REG_BMSR        0x01    /* Basic status */
#define REG_PHYID1      0x02
#define REG_PHYID2      0x03
#define REG_ANAR        0x04    /* Auto-neg advertisement */
#define REG_SCSR        0x1F    /* LAN8740 Special Control/Status */

#define BMCR_RESET      0x8000
#define BMCR_ANEN       0x1000
#define BMCR_ANRESTART  0x0200

#define BMSR_LINK       0x0004

/* Advertise 100/10 full and half duplex, IEEE 802.3 selector. */
#define ANAR_DEFAULT    0x01E1

/* LAN8740 OUI high word. */
#define LAN8740_ID1     0x0007

/* SCSR resolved speed/duplex (HCDSPEED, bits [4:2]). */
#define SCSR_SPD_MASK   0x001C
#define SCSR_SPD_10HD   0x0004
#define SCSR_SPD_100HD  0x0008
#define SCSR_SPD_10FD   0x0014
#define SCSR_SPD_100FD  0x0018

static int phy_scan(mdio_read_fn rd, struct phy_link *out)
{
    uint16_t id1;
    uint16_t id2;
    int addr;
    int candidate;

    candidate = -1;
    for (addr = 0; addr < 32; addr++) {
        if (rd((uint8_t)addr, REG_PHYID1, &id1) != 0)
            continue;
        if (id1 == 0xFFFF || id1 == 0x0000)
            continue;
        if (rd((uint8_t)addr, REG_PHYID2, &id2) != 0)
            continue;
        /* Prefer a LAN8740, but remember any responding PHY as a fallback. */
        if (id1 == LAN8740_ID1) {
            out->found = 1;
            out->addr = (uint8_t)addr;
            out->id1 = id1;
            out->id2 = id2;
            return 0;
        }
        if (candidate < 0) {
            candidate = addr;
            out->id1 = id1;
            out->id2 = id2;
        }
    }

    if (candidate >= 0) {
        out->found = 1;
        out->addr = (uint8_t)candidate;
        return 0;
    }
    return -1;
}

/* Decode the LAN8740 SCSR HCDSPEED field into speed_100 / full_duplex. */
static void phy_scsr_decode(uint16_t spd, struct phy_link *out)
{
    switch (spd & SCSR_SPD_MASK) {
        case SCSR_SPD_100FD:
            out->speed_100 = 1;
            out->full_duplex = 1;
            break;
        case SCSR_SPD_100HD:
            out->speed_100 = 1;
            out->full_duplex = 0;
            break;
        case SCSR_SPD_10FD:
            out->speed_100 = 0;
            out->full_duplex = 1;
            break;
        case SCSR_SPD_10HD:
        default:
            out->speed_100 = 0;
            out->full_duplex = 0;
            break;
    }
}

int phy_lan8740_bringup(mdio_read_fn rd, mdio_write_fn wr,
                        uint32_t link_up_timeout_ms, struct phy_link *out)
{
    uint16_t reg;
    uint16_t spd;
    uint64_t deadline;

    if (rd == NULL || wr == NULL || out == NULL)
        return -1;

    out->found = 0;
    out->addr = 0;
    out->id1 = 0;
    out->id2 = 0;
    out->link_up = 0;
    out->speed_100 = 0;
    out->full_duplex = 0;

    PHY_TRACE("scan: reading PHY IDs over MDIO");
    if (phy_scan(rd, out) != 0) {
        PHY_TRACE("scan: no PHY responded");
        return -1;
    }
    PHY_TRACE("scan: PHY found, resetting");

    /* Software reset and wait for it to self-clear. */
    if (wr(out->addr, REG_BMCR, BMCR_RESET) != 0)
        return -1;
    deadline = millis() + 1000u;
    do {
        if (rd(out->addr, REG_BMCR, &reg) != 0)
            return -1;
    } while ((reg & BMCR_RESET) && (millis() < deadline));
    if (reg & BMCR_RESET)
        return -1;

    /* Advertise all speeds/duplex and restart auto-negotiation. */
    if (wr(out->addr, REG_ANAR, ANAR_DEFAULT) != 0)
        return -1;
    if (wr(out->addr, REG_BMCR, BMCR_ANEN | BMCR_ANRESTART) != 0)
        return -1;

    /* Wait for link. BMSR latches link-low, so read it twice. Return -2 (not
     * -1) on timeout so the caller can tell "link down" from a real PHY/MDIO
     * error and continue MAC bring-up for a later cable insert. */
    deadline = millis() + link_up_timeout_ms;
    for (;;) {
        if (rd(out->addr, REG_BMSR, &reg) != 0)
            return -1;
        if (rd(out->addr, REG_BMSR, &reg) != 0)
            return -1;
        if (reg & BMSR_LINK)
            break;
        if (millis() >= deadline)
            return -2;
    }
    out->link_up = 1;

    /* Resolved speed/duplex from the LAN8740 Special Control/Status reg. */
    if (rd(out->addr, REG_SCSR, &spd) != 0)
        return -1;
    phy_scsr_decode(spd, out);

    return 0;
}

int phy_lan8740_link_status(mdio_read_fn rd, uint8_t addr, struct phy_link *out)
{
    uint16_t reg;
    uint16_t spd;

    if (rd == NULL || out == NULL)
        return -1;

    out->link_up = 0;
    out->speed_100 = 0;
    out->full_duplex = 0;

    /* BMSR latches link-low, so read it twice for the current state. */
    if (rd(addr, REG_BMSR, &reg) != 0)
        return -1;
    if (rd(addr, REG_BMSR, &reg) != 0)
        return -1;
    if ((reg & BMSR_LINK) == 0)
        return 0;                   /* link down; speed/duplex left 0 */
    out->link_up = 1;

    if (rd(addr, REG_SCSR, &spd) != 0)
        return -1;
    phy_scsr_decode(spd, out);

    return 0;
}

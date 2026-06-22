/* nxp_phy.h
 *
 * Shared clause-22 PHY register map and bring-up (reset + auto-negotiation +
 * address discovery) for the NXP wolfIP ethernet ports. The logic is identical
 * across the ports; only the MDIO-controller accessor differs, so the including
 * port defines NXP_MDIO_READ(phy,reg) -> uint16_t and NXP_MDIO_WRITE(phy,reg,
 * val) -> int (0 on success) before including this header, e.g.:
 *     #define NXP_MDIO_READ  phy_read
 *     #define NXP_MDIO_WRITE phy_write
 *     #include "../common/nxp_phy.h"
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
#ifndef WOLFIP_NXP_PHY_H
#define WOLFIP_NXP_PHY_H

#include <stdint.h>

/* Clause-22 PHY register map + bits (IEEE 802.3). */
#define PHY_BMCR        0x00U
#define PHY_BMSR        0x01U
#define PHY_ID1         0x02U
#define PHY_ID2         0x03U
#define PHY_ANAR        0x04U

#define BMCR_RESET          (1U << 15)
#define BMCR_AUTONEG_EN     (1U << 12)
#define BMCR_POWER_DOWN     (1U << 11)
#define BMCR_ISOLATE        (1U << 10)
#define BMCR_RESTART_ANEG   (1U << 9)
#define BMSR_LINK           (1U << 2)
#define BMSR_ANEG_COMPLETE  (1U << 5)
#define ANAR_DEFAULT        0x01E1U
#define MDIO_TIMEOUT        1000000U

/* The reset/autoneg helpers are provided only when the including port defines
 * NXP_PHY_HELPERS (i.e. it has an MDIO write path). A fixed-link port includes
 * this header for the register defines alone. */
#ifdef NXP_PHY_HELPERS
#if !defined(NXP_MDIO_READ) || !defined(NXP_MDIO_WRITE)
#error "define NXP_MDIO_READ and NXP_MDIO_WRITE before including nxp_phy.h"
#endif

/* Probe the configured PHY address, else scan 0..31. Returns the PHY MDIO
 * address, or -1 if none responds. */
static inline int32_t nxp_phy_detect(uint32_t cfg_addr)
{
    uint32_t addr;
    uint16_t id;

    id = NXP_MDIO_READ(cfg_addr, PHY_ID1);
    if (id != 0xFFFFU && id != 0x0000U)
        return (int32_t)cfg_addr;
    for (addr = 0; addr < 32U; addr++) {
        id = NXP_MDIO_READ(addr, PHY_ID1);
        if (id != 0xFFFFU && id != 0x0000U)
            return (int32_t)addr;
    }
    return -1;
}

/* Reset the PHY and restart auto-negotiation. Returns 0 on success, <0 on a
 * hard failure (reset never cleared or an MDIO write failed), or 1 if
 * auto-negotiation did not complete in time (a soft condition, e.g. no cable --
 * the caller can still bring the datapath up and read the live link state). */
static inline int nxp_phy_init(uint32_t phy)
{
    uint32_t timeout;
    uint16_t ctrl, bsr;

    if (NXP_MDIO_WRITE(phy, PHY_BMCR, BMCR_RESET) != 0)
        return -1;
    timeout = MDIO_TIMEOUT;
    do {
        ctrl = NXP_MDIO_READ(phy, PHY_BMCR);
    } while ((ctrl & BMCR_RESET) && --timeout);
    if (timeout == 0)
        return -1; /* reset never cleared: PHY absent/stuck */

    if (NXP_MDIO_WRITE(phy, PHY_ANAR, ANAR_DEFAULT) != 0)
        return -1;

    ctrl &= ~(BMCR_POWER_DOWN | BMCR_ISOLATE);
    ctrl |= BMCR_AUTONEG_EN | BMCR_RESTART_ANEG;
    if (NXP_MDIO_WRITE(phy, PHY_BMCR, ctrl) != 0)
        return -1;

    timeout = MDIO_TIMEOUT;
    do {
        bsr = NXP_MDIO_READ(phy, PHY_BMSR);
    } while (!(bsr & BMSR_ANEG_COMPLETE) && --timeout);
    if (timeout == 0)
        return 1;
    return 0;
}
#endif /* NXP_PHY_HELPERS */

#endif /* WOLFIP_NXP_PHY_H */

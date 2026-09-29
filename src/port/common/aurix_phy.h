/* aurix_phy.h
 *
 * Clause-22 PHY bring-up shared by the AURIX TC3xx and TC4xx GETH drivers.
 * The including driver first defines int AURIX_MDIO_READ(addr, reg, *value)
 * and int AURIX_MDIO_WRITE(addr, reg, value), both returning 0 on success and
 * nonzero on an MDIO failure, and AURIX_DELAY_MS(ms), which must wait at
 * least ms milliseconds.
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
#ifndef WOLFIP_AURIX_PHY_H
#define WOLFIP_AURIX_PHY_H

#include <stdint.h>

#if !defined(AURIX_MDIO_READ) || !defined(AURIX_MDIO_WRITE) || \
    !defined(AURIX_DELAY_MS)
#error "define AURIX_MDIO_READ, AURIX_MDIO_WRITE and AURIX_DELAY_MS first"
#endif

#define AURIX_PHY_BMCR      0x00u
#define AURIX_PHY_BMSR      0x01u
#define AURIX_PHY_ID1       0x02u
#define AURIX_PHY_ID2       0x03u
#define AURIX_PHY_ANAR      0x04u
#define AURIX_PHY_ANLPAR    0x05u

#define AURIX_BMCR_RESET        (1u << 15)
#define AURIX_BMCR_ANEG_EN      (1u << 12)
#define AURIX_BMCR_POWER_DOWN   (1u << 11)
#define AURIX_BMCR_ISOLATE      (1u << 10)
#define AURIX_BMCR_ANEG_RESTART (1u << 9)
#define AURIX_BMSR_ANEG_DONE    (1u << 5)
#define AURIX_BMSR_LINK         (1u << 2)
#define AURIX_ANAR_10_100       0x01E1u
#define AURIX_ADV_100_FULL      (1u << 8)
#define AURIX_ADV_100_HALF      (1u << 7)
#define AURIX_ADV_10_FULL       (1u << 6)

#define AURIX_PHY_RESET_MS      500u
#define AURIX_PHY_NONE          (-1)
#define AURIX_PHY_EMDIO         (-2)
#define AURIX_PHY_RESET_HOLD_MS 10u

/* All-ones is an unanswered read on a pulled-up bus, all-zeroes a PHY still
 * held in reset. Returns 1, 0, or -1 on an MDIO failure. */
static inline int aurix_phy_answers(uint8_t addr)
{
    uint16_t id1 = 0xFFFFu;
    uint16_t id2 = 0xFFFFu;

    if (AURIX_MDIO_READ(addr, AURIX_PHY_ID1, &id1) != 0 ||
        AURIX_MDIO_READ(addr, AURIX_PHY_ID2, &id2) != 0) {
        return -1;
    }
    if ((id1 == 0xFFFFu && id2 == 0xFFFFu) || (id1 == 0u && id2 == 0u)) {
        return 0;
    }
    return 1;
}

/* Wait for cfg_addr to answer, then fall back to a scan of the bus. Returns
 * the PHY address, AURIX_PHY_NONE, or AURIX_PHY_EMDIO on an MDIO failure. */
static inline int aurix_phy_detect(uint8_t cfg_addr, uint32_t timeout_ms)
{
    uint32_t waited;
    uint8_t  addr;
    int      rc;

    for (waited = 0u; ; waited++) {
        rc = aurix_phy_answers(cfg_addr);
        if (rc != 0) {
            return (rc > 0) ? (int)cfg_addr : AURIX_PHY_EMDIO;
        }
        if (waited >= timeout_ms) {
            break;
        }
        AURIX_DELAY_MS(1u);
    }
    for (addr = 0u; addr < 32u; addr++) {
        rc = aurix_phy_answers(addr);
        if (rc != 0) {
            return (rc > 0) ? (int)addr : AURIX_PHY_EMDIO;
        }
    }
    return AURIX_PHY_NONE;
}

/* 0 once RESET self-clears, -1 on an MDIO failure or a timeout. */
static inline int aurix_phy_reset(uint8_t addr)
{
    uint16_t bmcr = AURIX_BMCR_RESET;
    uint32_t waited;

    if (AURIX_MDIO_WRITE(addr, AURIX_PHY_BMCR, AURIX_BMCR_RESET) != 0) {
        return -1;
    }
    AURIX_DELAY_MS(AURIX_PHY_RESET_HOLD_MS);
    for (waited = 0u; waited < AURIX_PHY_RESET_MS; waited++) {
        AURIX_DELAY_MS(1u);
        if (AURIX_MDIO_READ(addr, AURIX_PHY_BMCR, &bmcr) != 0) {
            return -1;
        }
        if ((bmcr & AURIX_BMCR_RESET) == 0u) {
            return 0;
        }
    }
    return -1;
}

/* 0, or -1 on an MDIO failure. */
static inline int aurix_phy_start_autoneg(uint8_t addr)
{
    uint16_t bmcr;

    if (AURIX_MDIO_WRITE(addr, AURIX_PHY_ANAR, AURIX_ANAR_10_100) != 0 ||
        AURIX_MDIO_READ(addr, AURIX_PHY_BMCR, &bmcr) != 0) {
        return -1;
    }
    bmcr &= (uint16_t)~(AURIX_BMCR_POWER_DOWN | AURIX_BMCR_ISOLATE);
    bmcr |= AURIX_BMCR_ANEG_EN | AURIX_BMCR_ANEG_RESTART;
    return AURIX_MDIO_WRITE(addr, AURIX_PHY_BMCR, bmcr);
}

/* Returns 1 with the negotiated mode, 0 with no link, or -1 on an MDIO
 * failure. */
static inline int aurix_phy_link(uint8_t addr, int *speed_100, int *full_duplex)
{
    uint16_t bmsr = 0u;
    uint16_t anar;
    uint16_t anlpar;
    uint16_t common;

    /* The link bit latches low; the second read is the current state. */
    if (AURIX_MDIO_READ(addr, AURIX_PHY_BMSR, &bmsr) != 0 ||
        AURIX_MDIO_READ(addr, AURIX_PHY_BMSR, &bmsr) != 0) {
        return -1;
    }
    if ((bmsr & AURIX_BMSR_LINK) == 0u || (bmsr & AURIX_BMSR_ANEG_DONE) == 0u) {
        return 0;
    }
    if (AURIX_MDIO_READ(addr, AURIX_PHY_ANAR, &anar) != 0 ||
        AURIX_MDIO_READ(addr, AURIX_PHY_ANLPAR, &anlpar) != 0) {
        return -1;
    }

    common       = (uint16_t)(anar & anlpar);
    *speed_100   = (common & (AURIX_ADV_100_FULL | AURIX_ADV_100_HALF)) != 0u;
    *full_duplex = (*speed_100) ? ((common & AURIX_ADV_100_FULL) != 0u)
                                : ((common & AURIX_ADV_10_FULL) != 0u);
    return 1;
}

#endif /* WOLFIP_AURIX_PHY_H */

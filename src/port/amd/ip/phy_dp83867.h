/* phy_dp83867.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * TI DP83867IR PHY driver: 10/100/1000 RGMII PHY. On some boards the
 * PHY vendor varies (e.g. the ZC702 fits a Marvell 88E1518; the GEM
 * driver dispatches on the MDIO vendor ID). We only need configuration
 * (reset, RGMII TX/RX skew, auto-negotiation) and link status; no
 * advanced features.
 */
#ifndef AMD_PHY_DP83867_H
#define AMD_PHY_DP83867_H

#include <stdint.h>

/* Returns 0 on success, < 0 on failure. On success *speed and *fd are
 * the negotiated speed (10/100/1000) and full-duplex flag. */
int dp83867_init(uint8_t phy_addr, int *speed_out, int *full_duplex_out);

/* Returns 1 if link is up, 0 if down, < 0 on MDIO error. */
int dp83867_link_status(uint8_t phy_addr);

#endif /* AMD_PHY_DP83867_H */

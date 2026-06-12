/* phy_marvell.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Marvell 88E1518 (Alaska) RGMII PHY driver. This is the PHY fitted to
 * the on-board PS-GEM RJ45 on the Xilinx ZC702 (PHY OUI 0x0141), as
 * opposed to the TI DP83867 used on the ZCU102. We only need RGMII
 * delay configuration, auto-negotiation and link/speed status.
 */
#ifndef AMD_PHY_MARVELL_H
#define AMD_PHY_MARVELL_H

#include <stdint.h>

/* PHY ID1 (MII register 2) OUI high word for Marvell. */
#define MARVELL_PHY_ID1     0x0141u

/* Returns 0 on success, < 0 on failure. On success *speed_out and
 * *full_duplex_out are the negotiated speed (10/100/1000) and FD flag. */
int marvell_88e1518_init(uint8_t phy_addr, int *speed_out, int *full_duplex_out);

#endif /* AMD_PHY_MARVELL_H */

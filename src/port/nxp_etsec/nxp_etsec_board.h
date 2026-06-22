/* nxp_etsec_board.h
 *
 * Board parameters for the NXP eTSEC (Gianfar) ethernet driver
 * (nxp_etsec.c). Defaults target the NXP P1021RDB (eTSEC1, RGMII).
 *
 * Every value here is overridable from CFLAGS or a consumer header so the
 * same driver can serve other eTSEC boards (P1020/P1021/P2020, ...).
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
#ifndef WOLFIP_NXP_ETSEC_BOARD_H
#define WOLFIP_NXP_ETSEC_BOARD_H

/* CCSRBAR as seen by the booted application. wolfBoot RELOCATES CCSRBAR to
 * 0xFFE00000 for the main/app stage on the P1021 (hal/nxp_ppc.h), so the
 * eTSEC registers live there -- NOT at the 0xFF700000 reset default. */
#ifndef NXP_ETSEC_CCSRBAR
#define NXP_ETSEC_CCSRBAR       0xFFE00000UL
#endif

/* eTSEC index: 0 = eTSEC1, 1 = eTSEC2, 2 = eTSEC3. On the P1021RDB eTSEC1
 * is RGMII to the VSC7385 switch (fixed link, no external PHY); eTSEC2/3
 * are SGMII to external PHYs. */
#ifndef NXP_ETSEC_INDEX
#define NXP_ETSEC_INDEX         0U
#endif

/* MAC-to-PHY interface: 0 = RGMII, 1 = SGMII. */
#ifndef NXP_ETSEC_IF_SGMII
#define NXP_ETSEC_IF_SGMII      0
#endif

/* Fixed link (no external PHY autoneg) -- use for the eTSEC1->switch RGMII
 * uplink. When 1 the driver skips PHY detect and forces NXP_ETSEC_SPEED. */
#ifndef NXP_ETSEC_FIXED_LINK
#define NXP_ETSEC_FIXED_LINK    1
#endif

/* Forced/expected link speed in Mbps (10/100/1000). */
#ifndef NXP_ETSEC_SPEED
#define NXP_ETSEC_SPEED         1000
#endif

/* External PHY MDIO address (used when not a fixed link). The P1021RDB
 * convention is eTSEC1/2/3 PHYs at 0x0/0x1/0x2. nxp_etsec_init() also scans
 * the bus. All external MDIO goes through eTSEC1's MDIO window. */
#ifndef NXP_ETSEC_PHY_ADDR
#define NXP_ETSEC_PHY_ADDR      0x1U
#endif

/* TBI (internal SGMII PHY) MDIO address -- kept off the external 0..2 range. */
#ifndef NXP_ETSEC_TBIPA
#define NXP_ETSEC_TBIPA         0x1FU
#endif

#endif /* WOLFIP_NXP_ETSEC_BOARD_H */

/* nxp_fman_board.h
 *
 * Board parameters for the NXP QorIQ FMan ethernet driver (nxp_fman.c).
 * Defaults target the Curtiss-Wright VPX3-152 (T2080, FM1@DTSEC1).
 *
 * Every value here is overridable from CFLAGS or a consumer header so the
 * same driver can serve other QorIQ boards (T1024, T1040, NAII 68PPC2).
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
#ifndef WOLFIP_NXP_FMAN_BOARD_H
#define WOLFIP_NXP_FMAN_BOARD_H

/* CCSRBAR (Configuration, Control and Status Register Base Address).
 * The CW VPX3-152 relocates CCSRBAR to 0xEF000000 so it does not overlap
 * the board's 256MB NOR flash window; other T2080 boards (RDB, NAII 68PPC2)
 * keep the reset default 0xFE000000. Match wolfBoot's per-board CCSRBAR. */
#ifndef NXP_FMAN_CCSRBAR
#ifdef BOARD_CW_VPX3152
#define NXP_FMAN_CCSRBAR        0xEF000000UL
#else
#define NXP_FMAN_CCSRBAR        0xFE000000UL
#endif
#endif

/* mEMAC index driving the PHY (1-based). FM1@DTSEC1 -> mEMAC1. */
#ifndef NXP_FMAN_MEMAC_IDX
#define NXP_FMAN_MEMAC_IDX      1
#endif

/* External MDIO interface (EMI) index for the dedicated 1G MDIO bus
 * (1 = first 1G MDIO at FMAN_BASE + 0xFC000). */
#ifndef NXP_FMAN_MDIO_EMI
#define NXP_FMAN_MDIO_EMI       1
#endif

/* PHY MDIO bus address. The VPX3-152 board wires the AR8031 on
 * FM1@DTSEC1 at address 0x2 (NOT wolfBoot's generic SGMII default 0x1). */
#ifndef NXP_FMAN_PHY_ADDR
#define NXP_FMAN_PHY_ADDR       0x2
#endif

/* MDIO clock divider. ratio = (2 * CLKDIV) + 1; 258 is the QorIQ default. */
#ifndef NXP_FMAN_MDIO_CLKDIV
#define NXP_FMAN_MDIO_CLKDIV    258
#endif

/* MAC-to-PHY interface mode: 1 = SGMII (VPX3-152 FM1@DTSEC1), 0 = RGMII. */
#ifndef NXP_FMAN_IF_SGMII
#define NXP_FMAN_IF_SGMII       1
#endif

#endif /* WOLFIP_NXP_FMAN_BOARD_H */

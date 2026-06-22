/* nxp_enetc_board.h
 *
 * Board parameters for the NXP ENETC ethernet driver (nxp_enetc.c).
 * Defaults target the NXP LS1028A (port 0, external SGMII PHY).
 *
 * Every value here is overridable from CFLAGS or a consumer header so the
 * same driver can serve other Layerscape ENETC boards.
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
#ifndef WOLFIP_NXP_ENETC_BOARD_H
#define WOLFIP_NXP_ENETC_BOARD_H

/* ECAM configuration-space base (generic ECAM, bus 0). LS1028A reset
 * default per the reference manual. wolfBoot keeps the default CCSR/ECAM
 * layout (hal/nxp_ls1028a.h ECAMCFG_BASE). */
#ifndef NXP_ENETC_ECAM_BASE
#define NXP_ENETC_ECAM_BASE     0x01F0000000ULL
#endif

/* IERB register space base. On LS1028A the persistent (Linux-visible) MAC
 * address is programmed in the IERB; we also write the port PSIPMAR for the
 * immediate bring-up. hal/nxp_ls1028a.h ECAMREG_BASE. */
#ifndef NXP_ENETC_IERB_BASE
#define NXP_ENETC_IERB_BASE     0x01F0800000ULL
#endif

/* ECAM PCI function for the ENETC port to use. On LS1028A:
 *   fn0 = port0 (external SGMII PHY on the RDB),
 *   fn1 = port1, fn2 = port2 (internal 2.5G to Felix switch),
 *   fn6 = port3. Port 0 is the wire-facing path with a real PHY. */
#ifndef NXP_ENETC_PORT_FN
#define NXP_ENETC_PORT_FN       0U
#endif

/* ECAM PCI function for the shared ENETC MDIO controller (LS1028A fn3). */
#ifndef NXP_ENETC_MDIO_FN
#define NXP_ENETC_MDIO_FN       3U
#endif

/* External PHY MDIO address. LS1028A-RDB wires the port0 SGMII PHY at
 * address 0x2. nxp_enetc_init() also scans the bus, so a board with the
 * PHY elsewhere is still detected. */
#ifndef NXP_ENETC_PHY_ADDR
#define NXP_ENETC_PHY_ADDR      0x2U
#endif

/* MAC-to-PHY interface: 1 = SGMII / in-band (default, no MAC speed force),
 * 0 = RGMII (the driver forces 1000/full on the MAC). */
#ifndef NXP_ENETC_IF_SGMII
#define NXP_ENETC_IF_SGMII      1
#endif

/* Fallback BAR0 window used ONLY if a function's BAR0 reads back
 * unassigned (the IERB normally programs these from reset; reading the
 * live BAR is the primary path). LS1028A ENETC PF BARs live in the
 * 0x01F8000000 region. Verify on hardware before relying on the fallback. */
#ifndef NXP_ENETC_BAR_WINDOW
#define NXP_ENETC_BAR_WINDOW    0x01F8000000ULL
#endif
#ifndef NXP_ENETC_BAR_STRIDE
#define NXP_ENETC_BAR_STRIDE    0x00040000ULL
#endif

#endif /* WOLFIP_NXP_ENETC_BOARD_H */

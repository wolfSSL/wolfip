/* nxp_qe_uec_board.h
 *
 * Board parameters for the NXP QUICC Engine UCC ethernet driver
 * (nxp_qe_uec.c). Defaults target the NXP P1021 (UCC1).
 *
 * Every value here is overridable from CFLAGS or a consumer header so the
 * same driver can serve other QE/UCC boards.
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
#ifndef WOLFIP_NXP_QE_UEC_BOARD_H
#define WOLFIP_NXP_QE_UEC_BOARD_H

/* CCSRBAR (P1021 reset default, kept by wolfBoot). hal/nxp_ppc.h. */
#ifndef NXP_QE_CCSRBAR
#define NXP_QE_CCSRBAR          0xFF700000UL
#endif

/* QE engine block (QE_IMMR) = CCSRBAR + 0x80000 (wolfBoot QE_ENGINE_BASE). */
#ifndef NXP_QE_IMMR_OFFSET
#define NXP_QE_IMMR_OFFSET      0x80000UL
#endif

/* UCC index (0-based): UCC1=0, UCC2=1, UCC3=2, UCC4=3, UCC5=4, ...
 * wolfBoot pin-muxes UCC1 as MII and UCC5 as RMII on the P1021. */
#ifndef NXP_QE_UCC_NUM
#define NXP_QE_UCC_NUM          0U
#endif

/* External PHY MDIO address. nxp_qe_uec_init() also scans the bus. */
#ifndef NXP_QE_PHY_ADDR
#define NXP_QE_PHY_ADDR         0x0U
#endif

/* MAC-to-PHY interface mode:
 *   0 = MII   (10/100, wolfBoot default mux for UCC1)
 *   1 = RMII  (10/100, wolfBoot default mux for UCC5; P1025RDB style)
 *   2 = RGMII (10/100/1000, custom boards)
 * The P1021RDB stock copper is on eTSEC, not the QE UCC -- pick the mode
 * matching your board's actual UCC-to-PHY wiring. */
#ifndef NXP_QE_IF_MODE
#define NXP_QE_IF_MODE          0
#endif

/* Link speed in Mbps used to program the MAC interface (10/100/1000). */
#ifndef NXP_QE_SPEED
#define NXP_QE_SPEED            100
#endif

/* SNUMs handed to the RX and TX threads (distinct entries from the P1021
 * 28-snum pool: 0x04,0x05,0x0c,0x0d,0x14,0x15,...). The init-enet RX thread
 * table carries num_rx+1 entries, so two RX SNUMs are used. */
#ifndef NXP_QE_SNUM_RX
#define NXP_QE_SNUM_RX          0x04U
#endif
#ifndef NXP_QE_SNUM_RX2
#define NXP_QE_SNUM_RX2         0x0CU
#endif
#ifndef NXP_QE_SNUM_TX
#define NXP_QE_SNUM_TX          0x05U
#endif

#endif /* WOLFIP_NXP_QE_UEC_BOARD_H */

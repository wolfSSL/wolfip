/* board.h
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
 *
 * Xilinx Versal Gen 1 (VCxxxx / VMK180 board) PS register base
 * addresses and GIC SPI IDs. Values are derived from the Versal ACAP
 * Technical Reference Manual (AM011), the VMK180 board user guide,
 * and the published `versal.dtsi` device tree. No Xilinx BSP header
 * (xparameters.h) or xilstandalone code is referenced.
 *
 * Brought up on a VMK180 (Cortex-A72). The structure mirrors
 * src/port/zcu102/. Key differences from ZynqMP are:
 *   - Cortex-A72 (not A53); the PLM -> TF-A (BL31) chain hands off at EL3
 *   - GICv3 distributor + redistributor (no GICv2 legacy GICC)
 *   - ARM PL011 UART (not Cadence)
 *   - 2 GEMs (GEM0/GEM1) instead of 4; on-board RJ45 is GEM0 on VMK180
 */
#ifndef VERSAL_BOARD_H
#define VERSAL_BOARD_H

#include <stdint.h>

/* ---------------------------------------------------------------------
 * Memory map (Versal PS)
 * ------------------------------------------------------------------- */
#define DDR_BASE                0x00000000UL
#define DDR_SIZE                0x80000000UL   /* 2 GB lower bank */

/* OCM on Versal lives at 0xFFFC0000 (256 KB). Same as ZynqMP. */
#define OCM_BASE                0xFFFC0000UL
#define OCM_SIZE                0x00040000UL

/* ---------------------------------------------------------------------
 * PS peripherals
 * ------------------------------------------------------------------- */
#define UART0_BASE              0xFF000000UL   /* PL011 */
#define UART1_BASE              0xFF010000UL   /* PL011 */

#define UART_BASE               UART0_BASE     /* console PL011 */

#define GEM0_BASE               0xFF0C0000UL   /* on-board GEM (VMK180) */

/* On-board RJ45 is GEM0 on the VMK180. */
#define GEM_BASE                GEM0_BASE
#define IRQ_GEM                 IRQ_GEM0
#define GEM1_BASE               0xFF0D0000UL

#define CRL_APB_BASE            0xFF5E0000UL   /* LPD clock & reset */
#define IOU_SLCR_BASE           0xFF180000UL

/* GICv3: distributor + redistributor */
#define GICD_BASE               0xF9000000UL
#define GICR_BASE               0xF9080000UL   /* per-CPU redistributors */

/* ---------------------------------------------------------------------
 * GIC SPI numbers as GIC INTIDs (ARM GIC numbering: SPI N -> INTID 32+N).
 * Versal versal.dtsi:
 *     GEM0: GIC_SPI 56 -> INTID 88
 *     GEM1: GIC_SPI 58 -> INTID 90
 * ------------------------------------------------------------------- */
#define IRQ_GEM0                (32 + 56)  /* GIC_SPI 56 -> INTID 88,
                                            * on-board VMK180 RJ45 */
#define IRQ_GEM1                (32 + 58)  /* GIC_SPI 58 -> INTID 90 */

/* ---------------------------------------------------------------------
 * CRL clock and reset registers (LPD). Versal's CRL register map is NOT
 * the same as ZynqMP: the GEM clock/reset offsets differ. Verified
 * against the Versal PSM firmware crl.h (Vitis embeddedsw):
 *   CRL.GEM0_REF_CTRL = CRL + 0x118  (CLKACT bit 25, DIVISOR0 [13:8],
 *                                     SRCSEL [2:0])
 *   CRL.RST_GEM0      = CRL + 0x308  (RESET bit 0)
 * ------------------------------------------------------------------- */
#define CRL_APB_GEM0_REF_CTRL   (CRL_APB_BASE + 0x118)  /* Versal CRL.GEM0_REF_CTRL */
#define CRL_GEM0_RST            (CRL_APB_BASE + 0x308)  /* Versal CRL.RST_GEM0 */
#define CRL_GEM0_REF_CTRL_CLKACT (1u << 25)
#define CRL_RST_GEM0_RESET       (1u << 0)

/* ---------------------------------------------------------------------
 * PL011 UART0 - on-board USB-UART on VMK180
 * ------------------------------------------------------------------- */
#define UART_BAUD               115200

/* MAC address for eth0. Locally-administered, even first octet. */
#ifndef WOLFIP_MAC_0
#define WOLFIP_MAC_0            0x02
#endif
#ifndef WOLFIP_MAC_1
#define WOLFIP_MAC_1            0x00
#endif
#ifndef WOLFIP_MAC_2
#define WOLFIP_MAC_2            0x5A
#endif
#ifndef WOLFIP_MAC_3
#define WOLFIP_MAC_3            0x11
#endif
#ifndef WOLFIP_MAC_4
#define WOLFIP_MAC_4            0x22
#endif
#ifndef WOLFIP_MAC_5
#define WOLFIP_MAC_5            0x33
#endif

#endif /* VERSAL_BOARD_H */

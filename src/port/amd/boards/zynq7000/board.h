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
 * Xilinx Zynq-7000 (Cortex-A9, ARMv7-A 32-bit) PS register base
 * addresses and GIC interrupt IDs. Derived from the Zynq-7000 TRM
 * (UG585). No Xilinx Standalone BSP header is required.
 *
 * Brought up on a ZC702 (Cortex-A9). Mirrors src/port/zcu102/
 * structurally. Key differences:
 *   - Cortex-A9 (not A53), ARMv7-A 32-bit (not AArch64)
 *   - SLCR replaces ZynqMP's CRL_APB
 *   - GIC-390 (GICv2) inside the SCU at different base addresses
 *   - Cadence UART (same IP as ZynqMP; different base address)
 *   - Cadence GEM (older revision; 32-bit BD format default)
 *   - 2 GEMs (GEM0 / GEM1); on-board RJ45 is typically GEM0
 */
#ifndef ZYNQ7000_BOARD_H
#define ZYNQ7000_BOARD_H

#include <stdint.h>

/* ---------------------------------------------------------------------
 * Memory map (Zynq-7000 PS)
 * ------------------------------------------------------------------- */
#define DDR_BASE                0x00000000UL
#define DDR_SIZE                0x40000000UL   /* 1 GB typical, e.g. ZC702 */

/* OCM is mappable to 0x00000000 (low) or 0xFFFC0000 (high). Most
 * bare-metal apps use the high mapping; FSBL configures the OCM
 * address filter via SLCR.OCM_CFG. We assume the high mapping. */
#define OCM_BASE                0xFFFC0000UL
#define OCM_SIZE                0x00040000UL   /* 256 KB */

/* ---------------------------------------------------------------------
 * PS peripherals
 * ------------------------------------------------------------------- */
#define UART0_BASE              0xE0000000UL   /* Cadence */
#define UART1_BASE              0xE0001000UL

/* Console UART: ZC702 routes UART1 to the on-board USB-UART. The FSBL
 * already set the baud for the board ref clock; do not reprogram. */
#define UART_BASE               UART1_BASE

#define GEM0_BASE               0xE000B000UL   /* on-board RJ45 typical */

/* On-board RJ45 is GEM0 on the ZC702. */
#define GEM_BASE                GEM0_BASE
#define IRQ_GEM                 IRQ_GEM0
#define GEM1_BASE               0xE000C000UL

#define SLCR_BASE               0xF8000000UL   /* clock + reset */

/* GIC-390 (ARMv7 GICv2 compatible). Distributor + CPU IF are in the
 * SCU (Snoop Control Unit) memory region on Zynq-7000. */
#define GICD_BASE               0xF8F01000UL
#define GICC_BASE               0xF8F00100UL

/* ---------------------------------------------------------------------
 * GIC interrupt IDs (raw GIC INTIDs, not GIC_SPI offsets).
 * Per Zynq-7000 TRM Table 7-3:
 *   GEM0: INTID 54
 *   GEM1: INTID 77
 * ------------------------------------------------------------------- */
#define IRQ_GEM0                54
#define IRQ_GEM1                77

/* ---------------------------------------------------------------------
 * SLCR clock and reset registers
 * ------------------------------------------------------------------- */
#define SLCR_LOCK               (SLCR_BASE + 0x004)
#define SLCR_UNLOCK             (SLCR_BASE + 0x008)
#define SLCR_GEM0_CLK_CTRL      (SLCR_BASE + 0x140)
#define SLCR_GEM0_RCLK_CTRL     (SLCR_BASE + 0x138)  /* RGMII RX clock src */
#define SLCR_GEM1_CLK_CTRL      (SLCR_BASE + 0x144)
#define SLCR_GEM_RST_CTRL       (SLCR_BASE + 0x214)

#define SLCR_UNLOCK_KEY         0xDF0D     /* per TRM */

/* ---------------------------------------------------------------------
 * Cadence UART0 baud
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

#endif /* ZYNQ7000_BOARD_H */

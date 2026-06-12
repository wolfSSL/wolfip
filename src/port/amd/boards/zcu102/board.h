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
 * Xilinx UltraScale+ MPSoC PS register base addresses, GIC SPI IDs,
 * and clock parents for the ZCU102 board. All values are derived from
 * the ZynqMP TRM (UG1085) and the ZCU102 board user guide (UG1182).
 * No Xilinx BSP header (xparameters.h) is required.
 */
#ifndef ZCU102_BOARD_H
#define ZCU102_BOARD_H

#include <stdint.h>

/* ---------------------------------------------------------------------
 * Memory map (ZynqMP PS)
 * ------------------------------------------------------------------- */
#define DDR_BASE                0x00000000UL
#define DDR_SIZE                0x80000000UL   /* 2 GB lower bank */

#define OCM_BASE                0xFFFC0000UL
#define OCM_SIZE                0x00040000UL   /* 256 KB */

/* ---------------------------------------------------------------------
 * PS peripherals
 * ------------------------------------------------------------------- */
#define UART0_BASE              0xFF000000UL
#define UART1_BASE              0xFF010000UL

/* Console UART: ZCU102 routes UART0 to the on-board FTDI. The FSBL ref
 * clock is the known 100 MHz (IOPLL/15), so we program the divisors. */
#define UART_BASE               UART0_BASE
#define UART_PROGRAM_BAUD
#define UART_BAUDGEN_CD         124
#define UART_BAUDDIV_BDIV       6

#define GEM0_BASE               0xFF0B0000UL
#define GEM1_BASE               0xFF0C0000UL
#define GEM2_BASE               0xFF0D0000UL
#define GEM3_BASE               0xFF0E0000UL

/* On-board RJ45 is GEM3 on the ZCU102. */
#define GEM_BASE                GEM3_BASE
#define IRQ_GEM                 IRQ_GEM3

#define CRL_APB_BASE            0xFF5E0000UL
#define IOU_SLCR_BASE           0xFF180000UL

/* GIC-400 distributor and CPU interface (per ZynqMP TRM). */
#define GICD_BASE               0xF9010000UL
#define GICC_BASE               0xF9020000UL

/* ---------------------------------------------------------------------
 * GIC SPI numbers as GIC INTIDs (ARM GIC numbering: SPI N -> INTID 32+N).
 * The ZynqMP TRM Table 13-1 column "SPI ID" is the GIC_SPI offset (0..)
 * used in Linux device trees; the actual GIC INTID is 32 + that offset.
 * We use INTIDs directly throughout this driver, so add 32.
 * ------------------------------------------------------------------- */
#define IRQ_GEM0                (32 + 57)  /* GIC_SPI 57 -> INTID 89 */
#define IRQ_GEM1                (32 + 59)  /* GIC_SPI 59 -> INTID 91 */
#define IRQ_GEM2                (32 + 61)  /* GIC_SPI 61 -> INTID 93 */
#define IRQ_GEM3                (32 + 63)  /* GIC_SPI 63 -> INTID 95
                                            * on-board ZCU102 RJ45 */

/* ---------------------------------------------------------------------
 * CRL_APB clock and reset registers
 * ------------------------------------------------------------------- */
#define CRL_APB_GEM3_REF_CTRL   (CRL_APB_BASE + 0x5C)
#define CRL_APB_RST_LPD_IOU0    (CRL_APB_BASE + 0x230)  /* GEM3 reset bit 3 */

/* ---------------------------------------------------------------------
 * PS UART0 (Cadence) - on-board USB-UART on ZCU102 via U104 FT4232
 * ------------------------------------------------------------------- */
#define UART_BAUD               115200

/* MAC address for eth0. Locally-administered, even first octet:
 * 02:00:5A:11:22:33. Each byte is individually overridable via
 * build-time -DWOLFIP_MAC_n=0xXX so callers can swap any subset
 * (e.g. only the last three bytes from an EEPROM-derived value). */
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

#endif /* ZCU102_BOARD_H */

/* board.h
 *
 * Board constants for the PIC32MZ EF Starter Kit (DM320007) + LAN8740 PHY DB.
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
#ifndef PIC32MZ_BOARD_H
#define PIC32MZ_BOARD_H

/* Clock tree (set by DEVCFG config words at reset; see device_config.c) */
#define SYS_CLK_FREQ    200000000ul     /* SYSCLK from SPLL */
#define PBCLK2_FREQ     100000000ul     /* peripheral bus 2 (UART) = SYSCLK/2 */
#define PBCLK5_FREQ     100000000ul     /* peripheral bus 5 (EMAC) = SYSCLK/2 */

/* Console UART: U2TX on RPB14, U2RX on RPG6 (external MCP2221 USB-UART) */
#define CONSOLE_BAUD    115200u

/* On-board LEDs LED1/LED2/LED3 on RH0/RH1/RH2 (active high) */
#define LED_MASK        0x0007u
#define LED_HEARTBEAT   0x0001u         /* LED1 = RH0 */

#endif /* PIC32MZ_BOARD_H */

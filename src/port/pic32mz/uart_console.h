/* uart_console.h
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
#ifndef PIC32MZ_UART_CONSOLE_H
#define PIC32MZ_UART_CONSOLE_H

/* UART2 on RPB14 (U2TX) / RPG6 (U2RX) at 115200 8N1, via the external
 * MCP2221 USB-UART bridge. Also retargets XC32 stdout (printf) to this UART
 * through _mon_putc(). */
void uart_init(void);
void uart_putc(char c);
void uart_write(const char *buf, unsigned int len);
int  uart_rx_ready(void);
int  uart_getc(void);   /* returns byte, or -1 if none available */

#endif /* PIC32MZ_UART_CONSOLE_H */

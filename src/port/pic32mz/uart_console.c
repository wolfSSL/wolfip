/* uart_console.c
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
#include <xc.h>
#include <stdint.h>
#include "uart_console.h"
#include "board.h"

/* BRGH = 0 -> 16x oversampling. BRG = PBCLK2 / (16 * baud) - 1. */
#define UART_BRG    ((PBCLK2_FREQ / (16u * CONSOLE_BAUD)) - 1u)

void uart_init(void)
{
    /* Make the two pins digital and set direction. */
    ANSELBCLR = (1u << 14);     /* RB14 digital */
    ANSELGCLR = (1u << 6);      /* RG6  digital */
    TRISBCLR  = (1u << 14);     /* RB14 output (U2TX) */
    TRISGSET  = (1u << 6);      /* RG6  input  (U2RX) */

    /* Peripheral Pin Select: RPB14 -> U2TX, U2RX <- RPG6. */
    RPB14R = 0x02;              /* output function 2 = U2TX */
    U2RXR  = 0x01;              /* input  selection 1 = RPG6 */

    U2BRG  = (uint32_t)UART_BRG;
    U2STA  = 0;
    U2MODE = (1u << 15);        /* ON, 8N1, BRGH=0, no flow control */
    U2STAbits.URXEN = 1;
    U2STAbits.UTXEN = 1;
}

void uart_putc(char c)
{
    while (U2STAbits.UTXBF) {
        /* wait for room in the TX FIFO */
    }
    U2TXREG = (uint8_t)c;
}

void uart_write(const char *buf, unsigned int len)
{
    unsigned int i;

    if (buf == NULL)
        return;
    for (i = 0; i < len; i++)
        uart_putc(buf[i]);
}

int uart_rx_ready(void)
{
    return (int)U2STAbits.URXDA;
}

int uart_getc(void)
{
    if (U2STAbits.URXDA == 0)
        return -1;
    return (int)(U2RXREG & 0xFF);
}

/* XC32 retargets stdout (printf) through _mon_putc(). Map LF -> CRLF. */
void _mon_putc(char c)
{
    if (c == '\n')
        uart_putc('\r');
    uart_putc(c);
}

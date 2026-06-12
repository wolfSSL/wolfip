/* uart_pl011.c
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
 * ARM PL011 UART polled driver. Versal routes UART0 to the on-board
 * USB-UART on VMK180. We assume the PLM has already pinned the UART
 * pins via the LPD configuration object and enabled the reference
 * clock (typically 100 MHz IOPLL-derived); this driver programs the
 * baud divisors and enables TX/RX.
 *
 * Register reference: ARM PrimeCell PL011 UART (DDI 0183). The Versal
 * versal.dtsi maps PL011 base addresses to 0xFF000000 (UART0) and
 * 0xFF010000 (UART1).
 *
 * Brought up on a VMK180 (Cortex-A72 EL3).
 */
#include <stdint.h>
#include "board.h"
#include "uart.h"

/* PL011 registers, all 32-bit. */
#define UART_DR     (*(volatile uint32_t *)(UART_BASE + 0x000))  /* data */
#define UART_FR     (*(volatile uint32_t *)(UART_BASE + 0x018))  /* flag */
#define UART_IBRD   (*(volatile uint32_t *)(UART_BASE + 0x024))  /* int baud */
#define UART_FBRD   (*(volatile uint32_t *)(UART_BASE + 0x028))  /* frac baud */
#define UART_LCR_H  (*(volatile uint32_t *)(UART_BASE + 0x02C))  /* line ctrl */
#define UART_CR     (*(volatile uint32_t *)(UART_BASE + 0x030))  /* control */
#define UART_IMSC   (*(volatile uint32_t *)(UART_BASE + 0x038))  /* irq mask */
#define UART_ICR    (*(volatile uint32_t *)(UART_BASE + 0x044))  /* irq clr */

#define UART_FR_TXFF        (1u << 5)
#define UART_FR_TXFE        (1u << 7)
#define UART_FR_BUSY        (1u << 3)

#define UART_LCR_H_WLEN_8   (3u << 5)   /* 8-bit word length */
#define UART_LCR_H_FEN      (1u << 4)   /* FIFO enable */

#define UART_CR_UARTEN      (1u << 0)
#define UART_CR_TXE         (1u << 8)
#define UART_CR_RXE         (1u << 9)

/* Baud formulas (PL011):
 *   BAUDDIV = (UARTCLK * 4) / baud
 *   IBRD    = BAUDDIV / 64
 *   FBRD    = BAUDDIV % 64
 * For UARTCLK = 100 MHz, baud = 115200:
 *   BAUDDIV = (100e6 * 4) / 115200 = 3472
 *   IBRD    = 3472 / 64 = 54
 *   FBRD    = 3472 % 64 = 16
 * Actual baud = (100e6 * 4) / ((54 * 64) + 16) = 100e6 / 868 = 115207  */
#define UART_IBRD_115200    54
#define UART_FBRD_115200    16

void uart_init(void)
{
    UART_CR  = 0;                       /* disable while configuring */
    UART_ICR = 0x7FF;                   /* clear all interrupts */
    UART_IMSC = 0;                      /* mask all interrupts */
    UART_IBRD = UART_IBRD_115200;
    UART_FBRD = UART_FBRD_115200;
    UART_LCR_H = UART_LCR_H_WLEN_8 | UART_LCR_H_FEN;
    UART_CR = UART_CR_UARTEN | UART_CR_TXE | UART_CR_RXE;
}

void uart_putc(char c)
{
    while (UART_FR & UART_FR_TXFF)
        ;
    UART_DR = (uint32_t)(unsigned char)c;
}

/* uart_puts / uart_puthex / uart_putdec / uart_putip4 are shared and live
 * in common/uart_util.c. */

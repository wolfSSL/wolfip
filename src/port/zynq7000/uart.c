/* uart.c
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
 * Cadence (Xilinx PS) UART0 polled driver. ZCU102 routes UART0 to the
 * on-board FTDI USB-UART (channel B / /dev/ttyUSB0 on the host). We
 * assume FSBL has already pinned MIO 18/19 to UART0 and enabled its
 * reference clock at 100 MHz (UART_REF_CLK divided to 6.25 MHz baudgen
 * input by FSBL default); we just program the divisors for 115200 baud.
 *
 * Register reference: ZynqMP TRM (UG1085) chapter "UART Controller".
 */
#include <stdint.h>
#include "board.h"
#include "uart.h"

#define UART_CR             (*(volatile uint32_t *)(UART0_BASE + 0x00))
#define UART_MR             (*(volatile uint32_t *)(UART0_BASE + 0x04))
#define UART_BAUDGEN        (*(volatile uint32_t *)(UART0_BASE + 0x18))
#define UART_BAUD_DIV       (*(volatile uint32_t *)(UART0_BASE + 0x34))
#define UART_CHANNEL_STS    (*(volatile uint32_t *)(UART0_BASE + 0x2C))
#define UART_TX_RX_FIFO     (*(volatile uint32_t *)(UART0_BASE + 0x30))

/* Control register bits */
#define UART_CR_TXRES       (1u << 1)  /* TX software reset */
#define UART_CR_RXRES       (1u << 0)  /* RX software reset */
#define UART_CR_TXEN        (1u << 4)
#define UART_CR_TXDIS       (1u << 5)
#define UART_CR_RXEN        (1u << 2)
#define UART_CR_RXDIS       (1u << 3)
#define UART_CR_STPBRK      (1u << 8)

/* Mode register: 8N1, normal, no parity */
#define UART_MR_8N1         ((0u << 8) | (4u << 3) | (0u << 1))

/* Channel status */
#define UART_SR_TXFULL      (1u << 4)
#define UART_SR_TXEMPTY     (1u << 3)

void uart_init(void)
{
    /* PetaLinux/Vitis FSBL's psu_init programs:
     *   IOPLL                = 1500 MHz
     *   CRL_APB.UART0_REF_CTRL: SRCSEL=IOPLL, DIVISOR0=15, DIVISOR1=1
     *   -> uart_ref_clk      = 1500 / 15 / 1 = 100 MHz   (sel_clk to baudgen)
     *
     * Cadence UART baud formula:
     *   baud = sel_clk / (CD * (BDIV + 1))
     *
     * For 115200 with BDIV=6:
     *   CD = 100e6 / (115200 * 7) = 124  -> actual 115207, well under UART tol.
     *
     * If you change ref_clk (e.g. RPLL source, different divisors), recompute
     * CD - this driver does not auto-detect from CRL_APB yet. */
    UART_CR = UART_CR_TXDIS | UART_CR_RXDIS;
    UART_CR |= UART_CR_TXRES | UART_CR_RXRES;
    while (UART_CR & (UART_CR_TXRES | UART_CR_RXRES))
        ; /* wait for reset to self-clear */

    UART_MR = UART_MR_8N1;
    UART_BAUDGEN = 124;
    UART_BAUD_DIV = 6;

    UART_CR = UART_CR_TXEN | UART_CR_RXEN | UART_CR_STPBRK;
}

void uart_putc(char c)
{
    while (UART_CHANNEL_STS & UART_SR_TXFULL)
        ;
    UART_TX_RX_FIFO = (uint32_t)(unsigned char)c;
}

void uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n')
            uart_putc('\r');
        uart_putc(*s++);
    }
}

void uart_puthex(uint32_t val)
{
    static const char hex[] = "0123456789ABCDEF";
    int i;
    uart_puts("0x");
    for (i = 28; i >= 0; i -= 4)
        uart_putc(hex[(val >> i) & 0xF]);
}

void uart_putdec(uint32_t val)
{
    char buf[11];
    int i = 0;
    if (val == 0) {
        uart_putc('0');
        return;
    }
    while (val > 0 && i < (int)sizeof(buf)) {
        buf[i++] = '0' + (char)(val % 10);
        val /= 10;
    }
    while (i > 0)
        uart_putc(buf[--i]);
}

void uart_putip4(ip4 ip)
{
    uart_putdec((ip >> 24) & 0xFF);
    uart_putc('.');
    uart_putdec((ip >> 16) & 0xFF);
    uart_putc('.');
    uart_putdec((ip >> 8) & 0xFF);
    uart_putc('.');
    uart_putdec(ip & 0xFF);
}

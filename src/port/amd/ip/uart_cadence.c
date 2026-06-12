/* uart_cadence.c
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
 * Cadence (Xilinx PS) UART polled driver, shared by the Cadence-UART
 * boards (ZynqMP UART0, Zynq-7000 UART1). The console base is UART_BASE
 * (board.h). If the board defines UART_PROGRAM_BAUD we program 8N1 and
 * the board's baud divisors (UART_BAUDGEN_CD / UART_BAUDDIV_BDIV);
 * otherwise we trust the FSBL's baud setup and only enable TX/RX.
 *
 * Register reference: Xilinx PS UART (Cadence) -- ZynqMP UG1085 /
 * Zynq-7000 UG585 "UART Controller".
 */
#include <stdint.h>
#include "board.h"
#include "uart.h"

#define UART_CR             (*(volatile uint32_t *)(UART_BASE + 0x00))
#define UART_MR             (*(volatile uint32_t *)(UART_BASE + 0x04))
#define UART_BAUDGEN        (*(volatile uint32_t *)(UART_BASE + 0x18))
#define UART_BAUD_DIV       (*(volatile uint32_t *)(UART_BASE + 0x34))
#define UART_CHANNEL_STS    (*(volatile uint32_t *)(UART_BASE + 0x2C))
#define UART_TX_RX_FIFO     (*(volatile uint32_t *)(UART_BASE + 0x30))

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
#ifdef UART_PROGRAM_BAUD
    /* Program 8N1 + baud. The board supplies divisors sized for its
     * UART_REF_CLK via UART_BAUDGEN_CD / UART_BAUDDIV_BDIV (Cadence:
     * baud = sel_clk / (CD * (BDIV + 1))). Boards whose FSBL already set
     * the baud (and whose ref clock is not known here) leave
     * UART_PROGRAM_BAUD undefined -- reprogramming would garble output. */
    UART_CR = UART_CR_TXDIS | UART_CR_RXDIS;
    UART_CR |= UART_CR_TXRES | UART_CR_RXRES;
    while (UART_CR & (UART_CR_TXRES | UART_CR_RXRES))
        ; /* wait for reset to self-clear */

    UART_MR = UART_MR_8N1;
    UART_BAUDGEN = UART_BAUDGEN_CD;
    UART_BAUD_DIV = UART_BAUDDIV_BDIV;
#endif
    UART_CR = UART_CR_TXEN | UART_CR_RXEN | UART_CR_STPBRK;
}

void uart_putc(char c)
{
    while (UART_CHANNEL_STS & UART_SR_TXFULL)
        ;
    UART_TX_RX_FIFO = (uint32_t)(unsigned char)c;
}

/* uart_puts / uart_puthex / uart_putdec / uart_putip4 are shared and live
 * in common/uart_util.c. */

/* uart_selftest.c - maximally-robust raw UART0 bring-up probe (RP2350)
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
 * Self-contained: no clocks.c, no uart.c, no syscalls, no libc heap.
 * Every register touch is inline so there is exactly one thing under
 * test - can the core run from XIP and drive a byte out GP0 (UART0 TX)?
 * Transmits continuously so any escaping byte is caught.
 */
#include <stdint.h>

#define MMIO(a) (*(volatile uint32_t *)(a))

/* RESETS (RP2350 datasheet 2.7); atomic CLR alias at +0x3000. */
#define RESETS_BASE   0x40020000UL
#define RESETS_DONE   (RESETS_BASE + 0x008U)
#define RESETS_CLR    (RESETS_BASE + 0x3000U)
#define R_IO_BANK0    (1U << 6)
#define R_PADS_BANK0  (1U << 9)
#define R_UART0       (1U << 26)

/* IO_BANK0 / PADS_BANK0. */
#define IO_BANK0      0x40028000UL
#define IO_CTRL(n)    (IO_BANK0 + 0x004U + (n) * 8U)
#define PADS_BANK0    0x40038000UL
#define PAD(n)        (PADS_BANK0 + 0x004U + (n) * 4U)
#define PAD_IE        (1U << 6)            /* input enable; ISO(bit8)=0 */

/* CLOCKS / XOSC. */
#define XOSC_BASE     0x40048000UL
#define XOSC_CTRL     (XOSC_BASE + 0x00U)
#define XOSC_STARTUP  (XOSC_BASE + 0x0CU)
#define CLOCKS_BASE   0x40010000UL
#define CLK_PERI_CTRL (CLOCKS_BASE + 0x48U)

/* UART0 (PL011). */
#define UART0         0x40070000UL
#define U_DR          (UART0 + 0x000U)
#define U_FR          (UART0 + 0x018U)
#define U_IBRD        (UART0 + 0x024U)
#define U_FBRD        (UART0 + 0x028U)
#define U_LCRH        (UART0 + 0x02CU)
#define U_CR          (UART0 + 0x030U)
#define U_FR_TXFF     (1U << 5)

static void busy(uint32_t n) { while (n-- != 0U) { __asm volatile("nop"); } }

static void clr_reset(uint32_t bits)
{
    MMIO(RESETS_CLR) = bits;
    while ((MMIO(RESETS_DONE) & bits) != bits) { }
}

static void putc_raw(char c)
{
    while ((MMIO(U_FR) & U_FR_TXFF) != 0U) { }
    MMIO(U_DR) = (uint32_t)(uint8_t)c;
}

int main(void)
{
    const char *msg = "RP2350 UART ALIVE\r\n";
    const char *p;

    /* Bring crystal up, give it a generous fixed settle (no status poll
     * that could early-out), then run clk_peri off the 12 MHz XOSC. */
    MMIO(XOSC_STARTUP) = 0xC4U;
    MMIO(XOSC_CTRL)    = (0xFABU << 12) | 0xAA0U;
    busy(2000000U);
    MMIO(CLK_PERI_CTRL) = 0U;
    MMIO(CLK_PERI_CTRL) = (4U << 5);              /* AUXSRC = XOSC        */
    MMIO(CLK_PERI_CTRL) = (4U << 5) | (1U << 11); /* + ENABLE             */

    /* UART0 + its GPIO pads/mux out of reset; clear pad ISO. */
    clr_reset(R_IO_BANK0 | R_PADS_BANK0);
    clr_reset(R_UART0);
    MMIO(PAD(0)) = PAD_IE;          /* GP0 = UART0 TX, ISO=0 */
    MMIO(PAD(1)) = PAD_IE;          /* GP1 = UART0 RX, ISO=0 */
    MMIO(IO_CTRL(0)) = 2U;          /* FUNCSEL 2 = UART0 */
    MMIO(IO_CTRL(1)) = 2U;

    /* 115200 from 12 MHz: div*128 = 8*12e6/115200 = 833 -> IBRD 6 FBRD 33. */
    MMIO(U_CR)   = 0U;
    MMIO(U_IBRD) = 6U;
    MMIO(U_FBRD) = 33U;
    MMIO(U_LCRH) = (3U << 5) | (1U << 4);          /* 8N1, FIFO enable    */
    MMIO(U_CR)   = (1U << 0) | (1U << 8) | (1U << 9); /* UARTEN|TXE|RXE   */

    /* Transmit forever so any escaping byte is observable. */
    for (;;) {
        for (p = msg; *p != '\0'; p++) {
            putc_raw(*p);
        }
        busy(2000000U);
    }
    return 0;
}

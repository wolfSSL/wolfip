/* rp2350_uart.c - RP2350 UART0 console (PL011 PrimeCell)
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */
#include <stdint.h>

#include "board.h"
#include "rp2350_clocks.h"

/* PL011 register offsets (RP2350 datasheet 12.1). */
#define UART0_BASE          0x40070000UL
#define UART_DR             0x000U
#define UART_FR             0x018U
#define UART_IBRD           0x024U
#define UART_FBRD           0x028U
#define UART_LCR_H          0x02CU
#define UART_CR             0x030U

/* RESETS: PADS_BANK0 (bit 9), IO_BANK0 (bit 6), UART0 (bit 23). */
#define RESETS_BASE         0x40020000UL
#define RESETS_RESET        0x000U
#define RESETS_RESET_DONE   0x008U
/* RP2350 RESETS bit indices (datasheet 2.7.2) - these differ from RP2040
 * because PIO2/HSTX/SHA256/etc. were inserted. UART0 is bit 26, NOT the
 * RP2040-era bit 23 (which is TIMER0 on RP2350). */
#define RESETS_UART0_BIT    (1U << 26)
#define RESETS_IO_BANK0     (1U << 6)
#define RESETS_PADS_BANK0   (1U << 9)

/* IO_BANK0 GPIO function select for the UART pins. */
#define IO_BANK0_BASE       0x40028000UL
#define IO_BANK0_GPIO_CTRL(n) (IO_BANK0_BASE + 0x004U + (n) * 8U)
#define PADS_BANK0_BASE     0x40038000UL
#define PADS_BANK0_GPIO(n)  (PADS_BANK0_BASE + 0x004U + (n) * 4U)
/* RP2350 pad bits. ISO (bit 8) powers up SET and isolates the pad from
 * its peripheral - it MUST be cleared or the pin never drives. This bit
 * does not exist on RP2040. IE (bit 6) enables the input buffer. */
#define PAD_IE              (1U << 6)
#define PAD_ISO             (1U << 8)

/* Function 2 on GP0/GP1 = UART0 TX/RX. */
#define GPIO_FUNC_UART      2U

#define MMIO(addr)          (*(volatile uint32_t *)(addr))

static void clear_reset(uint32_t bits)
{
    /* Atomic-clear region at +0x3000 (RP2350 datasheet 2.2). */
    MMIO(RESETS_BASE + 0x3000U + RESETS_RESET) = bits;
    while ((MMIO(RESETS_BASE + RESETS_RESET_DONE) & bits) != bits) { }
}

void rp2350_uart_init(void)
{
    uint32_t ibrd;
    uint32_t fbrd;
    uint32_t clk_peri = RP2350_CLK_PERI_HZ;  /* set by rp2350_clocks_init */
    uint32_t baud_div_x128;

    /* Bring up the pad + IO bank + UART peripheral. */
    clear_reset(RESETS_PADS_BANK0 | RESETS_IO_BANK0);
    clear_reset(RESETS_UART0_BIT);

    /* Clear the RP2350 pad isolation latch and enable the input buffer
     * for both UART pins, then mux them to UART0. Without clearing ISO
     * the pad stays disconnected from the peripheral and TX never drives
     * the wire (RP2350-only gotcha). */
    MMIO(PADS_BANK0_GPIO(UART0_PIN_TX)) = PAD_IE;   /* ISO=0, OD=0       */
    MMIO(PADS_BANK0_GPIO(UART0_PIN_RX)) = PAD_IE;

    /* Mux GP0/GP1 to UART0 (FUNCSEL field in GPIOx_CTRL[4:0]). */
    MMIO(IO_BANK0_GPIO_CTRL(UART0_PIN_TX)) = GPIO_FUNC_UART;
    MMIO(IO_BANK0_GPIO_CTRL(UART0_PIN_RX)) = GPIO_FUNC_UART;

    /* Disable UART, program baud, enable. PL011 baud math (pico-sdk
     * canonical form): compute div*128, then
     *   IBRD = (div*128) >> 7
     *   FBRD = ((div*128 & 0x7F) + 1) >> 1     (round-to-nearest 1/64)
     */
    MMIO(UART0_BASE + UART_CR) = 0;
    baud_div_x128 = (uint32_t)(((uint64_t)clk_peri * 8U) / UART0_BAUD);
    ibrd = baud_div_x128 >> 7;
    fbrd = ((baud_div_x128 & 0x7FU) + 1U) >> 1;
    MMIO(UART0_BASE + UART_IBRD) = ibrd;
    MMIO(UART0_BASE + UART_FBRD) = fbrd;
    /* Word length = 8 (bits 6:5 = 0b11), FIFO enable (bit 4). */
    MMIO(UART0_BASE + UART_LCR_H) = (3U << 5) | (1U << 4);
    /* UARTEN | TXE | RXE. */
    MMIO(UART0_BASE + UART_CR) = (1U << 0) | (1U << 8) | (1U << 9);
}

void rp2350_uart_tx(const char *buf, int len)
{
    int i;
    if (buf == 0 || len <= 0) return;
    for (i = 0; i < len; i++) {
        /* Spin while TX FIFO full (FR bit 5). */
        while ((MMIO(UART0_BASE + UART_FR) & (1U << 5)) != 0) { }
        MMIO(UART0_BASE + UART_DR) = (uint32_t)(uint8_t)buf[i];
    }
}

/* rp2350_pio.c - PIO-based gSPI transport for the CYW43439
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
 * Drives the CYW43439 half-duplex gSPI via PIO0 SM0 (the approach the
 * pico-sdk / PicoWi reference drivers use, because the link needs a
 * gap-free clock with deterministic edges that bit-bang struggles to
 * produce). The PIO program is cyw43.pio, assembled to cyw43_pio.h.
 *
 * Pin roles (board.h): CLK = side-set (GP29), DATA = OUT/IN/SET (GP24).
 */
#include <stdint.h>

#include "board.h"
#include "rp2350_pio.h"

/* Assembled program: pull instruction array out of the generated header
 * (we ignore the pico-sdk helper structs it also defines). */
#define PICO_NO_HARDWARE 1
#include "cyw43_pio.h"

#define MMIO(a) (*(volatile uint32_t *)(a))

/* PIO0 (RP2350 datasheet 11.x). */
#define PIO0_BASE        0x50200000UL
#define PIO_CTRL         (PIO0_BASE + 0x000U)
#define PIO_FSTAT        (PIO0_BASE + 0x004U)
#define PIO_TXF0         (PIO0_BASE + 0x010U)
#define PIO_RXF0         (PIO0_BASE + 0x020U)
#define PIO_INSTR_MEM0   (PIO0_BASE + 0x048U)
#define PIO_SM0_CLKDIV   (PIO0_BASE + 0x0C8U)
#define PIO_SM0_EXECCTRL (PIO0_BASE + 0x0CCU)
#define PIO_SM0_SHIFTCTRL (PIO0_BASE + 0x0D0U)
#define PIO_SM0_INSTR    (PIO0_BASE + 0x0D8U)
#define PIO_SM0_PINCTRL  (PIO0_BASE + 0x0DCU)

/* FSTAT bits: RXEMPTY in [8+sm], TXFULL in [16+sm]. */
#define FSTAT_RXEMPTY_SM0 (1U << 8)
#define FSTAT_TXFULL_SM0  (1U << 16)

/* CTRL bit: SM0 enable [0]. */
#define CTRL_SM0_ENABLE   (1U << 0)

/* RESETS (PIO0 = bit 11 on RP2350). */
#define RESETS_BASE      0x40020000UL
#define RESETS_RESET_DONE (RESETS_BASE + 0x008U)
#define RESETS_RESET_CLR  (RESETS_BASE + 0x3000U)
#define RESETS_PIO0      (1U << 11)

/* IO_BANK0 / PADS_BANK0; FUNCSEL 6 = PIO0 on RP2350. */
#define IO_BANK0_BASE    0x40028000UL
#define IO_CTRL(n)       (IO_BANK0_BASE + 0x004U + (n) * 8U)
#define PADS_BANK0_BASE  0x40038000UL
#define PAD(n)           (PADS_BANK0_BASE + 0x004U + (n) * 4U)
#define PAD_IE           (1U << 6)
#define GPIO_FUNC_PIO0   6U

/* clk_sys is pinned to 12 MHz; divide to a conservative SM clock. Each
 * shifted bit is 2 SM cycles, so SM=2 MHz -> ~1 MHz gSPI. */
#define PIO_CLKDIV_INT   6U

/* Execute one instruction immediately on SM0 (used to set pin dirs). */
static void sm0_exec(uint16_t instr)
{
    MMIO(PIO_SM0_INSTR) = instr;
}

static void pio_gpio_setup(uint32_t pin)
{
    MMIO(PAD(pin)) = PAD_IE;              /* clear ISO, enable IO */
    MMIO(IO_CTRL(pin)) = GPIO_FUNC_PIO0;  /* mux to PIO0 */
}

void rp2350_pio_init(void)
{
    uint32_t i;
    uint32_t pinctrl;

    /* PIO0 out of reset. */
    MMIO(RESETS_RESET_CLR) = RESETS_PIO0;
    while ((MMIO(RESETS_RESET_DONE) & RESETS_PIO0) == 0U) { }

    /* Route CLK + DATA to PIO0. */
    pio_gpio_setup(CYW43_PIN_SPI_CLK);
    pio_gpio_setup(CYW43_PIN_SPI_DATA);

    /* Load the program at offset 0. */
    for (i = 0; i < (uint32_t)(sizeof(cyw43_pio_program_instructions)
                               / sizeof(cyw43_pio_program_instructions[0]));
         i++) {
        MMIO(PIO_INSTR_MEM0 + i * 4U) = cyw43_pio_program_instructions[i];
    }

    /* Clock divider: integer part in [31:16]. */
    MMIO(PIO_SM0_CLKDIV) = (PIO_CLKDIV_INT << 16);

    /* SHIFTCTRL: AUTOPULL (bit17) + AUTOPUSH (bit16) ON, thresholds 32
     * (PULL_THRESH [29:25]=0, PUSH_THRESH [24:20]=0 => 32), OUT and IN
     * shift LEFT/MSB-first (OUT_SHIFTDIR bit19=0, IN_SHIFTDIR bit18=0). */
    MMIO(PIO_SM0_SHIFTCTRL) = (1U << 17) | (1U << 16);

    /* EXECCTRL: wrap bottom = 0, wrap top = wrap index. Bits:
     * WRAP_BOTTOM [11:7], WRAP_TOP [16:12]. */
    MMIO(PIO_SM0_EXECCTRL) =
        ((uint32_t)cyw43_pio_wrap << 12) |
        ((uint32_t)cyw43_pio_wrap_target << 7);

    /* Set CLK and DATA pin directions to output before run. Use SM0_INSTR
     * to execute `set pindirs,1` with the SET base pointed at each pin in
     * turn. set pindirs,1 (no side-set) = 0xE081. */
    MMIO(PIO_SM0_PINCTRL) = (1U << 26)                       /* SET_COUNT=1 */
                          | ((uint32_t)CYW43_PIN_SPI_CLK << 5); /* SET_BASE */
    sm0_exec(0xE081U);
    MMIO(PIO_SM0_PINCTRL) = (1U << 26)
                          | ((uint32_t)CYW43_PIN_SPI_DATA << 5);
    sm0_exec(0xE081U);

    /* Final PINCTRL for the running program:
     *   SIDESET_COUNT [31:29] = 1   (CLK)
     *   SET_COUNT     [28:26] = 1   (DATA)
     *   OUT_COUNT     [25:20] = 1   (DATA)
     *   IN_BASE       [19:15] = DATA
     *   SIDESET_BASE  [14:10] = CLK
     *   SET_BASE      [9:5]   = DATA
     *   OUT_BASE      [4:0]   = DATA
     */
    pinctrl = ((uint32_t)1 << 29)
            | ((uint32_t)1 << 26)
            | ((uint32_t)1 << 20)
            | ((uint32_t)CYW43_PIN_SPI_DATA << 15)
            | ((uint32_t)CYW43_PIN_SPI_CLK  << 10)
            | ((uint32_t)CYW43_PIN_SPI_DATA << 5)
            | ((uint32_t)CYW43_PIN_SPI_DATA);
    MMIO(PIO_SM0_PINCTRL) = pinctrl;

    /* Restart SM0 PC to the wrap target and enable it (CTRL bit0 = SM0
     * enable; bits [7:4] restart, [11:8] clkdiv restart). */
    sm0_exec(0x0000U | cyw43_pio_wrap_target);  /* jmp 0 (set PC = 0) */
    MMIO(PIO_CTRL) = CTRL_SM0_ENABLE;
}

static void txfifo_put(uint32_t w)
{
    while ((MMIO(PIO_FSTAT) & FSTAT_TXFULL_SM0) != 0U) { }
    MMIO(PIO_TXF0) = w;
}

uint32_t rp2350_pio_xfer(const uint32_t *out_words, uint32_t n_out_words,
                         uint32_t out_bits, uint32_t in_bits)
{
    uint32_t i;
    uint32_t rx;

    /* Program reads: out_bits-1, in_bits-1, then the out data word(s).
     * BOTH out_bits and in_bits MUST be multiples of 32 so the OSR is
     * fully drained and the ISR autopush fires each word - otherwise
     * leftover OSR bits carry into the next transaction and desync the
     * SM. Callers pad sub-word register writes up to a full word and set
     * the gSPI command length to the real byte count (the chip ignores
     * the extra clocked bytes), so this always holds. */
    txfifo_put(out_bits - 1U);
    txfifo_put(in_bits - 1U);
    for (i = 0; i < n_out_words; i++) {
        txfifo_put(out_words[i]);
    }

    /* Drain the in_bits/32 response words; return the last (single-word
     * reads return the value, multi-word write-discards toss them). */
    rx = 0;
    for (i = 0; i < (in_bits / 32U); i++) {
        while ((MMIO(PIO_FSTAT) & FSTAT_RXEMPTY_SM0) != 0U) { }
        rx = MMIO(PIO_RXF0);
    }
    return rx;
}

uint32_t rp2350_pio_xfer32(uint32_t cmd_word, uint32_t out_bits,
                           uint32_t in_bits)
{
    return rp2350_pio_xfer(&cmd_word, 1U, out_bits, in_bits);
}

void rp2350_pio_write_bytes(uint32_t cmd_word, const uint8_t *data,
                            uint32_t nbytes)
{
    uint32_t i;
    /* Guard against nbytes==0: nbytes*8-1 would underflow to ~4 billion bits
     * and hang the state machine. Callers always pass >=4, but be safe. */
    if (nbytes == 0U) {
        return;
    }
    /* The PIO packs 4 bytes per 32-bit word; reject a non-multiple-of-4 length
     * so the data[i+1..i+3] accesses can never exceed the caller buffer. */
    if ((nbytes & 3U) != 0U) {
        return;
    }
    /* out_bits = command + data (both multiples of 32); in 32 to drain. */
    txfifo_put(32U + nbytes * 8U - 1U);
    txfifo_put(32U - 1U);
    txfifo_put(cmd_word);
    for (i = 0; i < nbytes; i += 4U) {
        uint32_t w = ((uint32_t)data[i] << 24) | ((uint32_t)data[i + 1U] << 16)
                   | ((uint32_t)data[i + 2U] << 8) | (uint32_t)data[i + 3U];
        txfifo_put(w);
    }
    while ((MMIO(PIO_FSTAT) & FSTAT_RXEMPTY_SM0) != 0U) { }
    (void)MMIO(PIO_RXF0);
}

void rp2350_pio_read_bytes(uint32_t cmd_word, uint8_t *data, uint32_t nbytes)
{
    uint32_t i;
    /* Guard against nbytes==0 (nbytes*8-1 would underflow and hang). */
    if (nbytes == 0U) {
        return;
    }
    /* 4-byte packing: reject a non-multiple-of-4 length so the data[i+1..i+3]
     * stores below cannot exceed the caller buffer. */
    if ((nbytes & 3U) != 0U) {
        return;
    }
    txfifo_put(32U - 1U);
    txfifo_put(nbytes * 8U - 1U);
    txfifo_put(cmd_word);
    for (i = 0; i < nbytes; i += 4U) {
        uint32_t w;
        while ((MMIO(PIO_FSTAT) & FSTAT_RXEMPTY_SM0) != 0U) { }
        w = MMIO(PIO_RXF0);
        data[i]      = (uint8_t)(w >> 24);
        data[i + 1U] = (uint8_t)(w >> 16);
        data[i + 2U] = (uint8_t)(w >> 8);
        data[i + 3U] = (uint8_t)(w);
    }
}

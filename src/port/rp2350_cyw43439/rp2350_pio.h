/* rp2350_pio.h - PIO-based gSPI transport for the CYW43439
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

#ifndef WOLFIP_RP2350_PIO_H
#define WOLFIP_RP2350_PIO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Load the cyw43 PIO program into PIO0 SM0 and configure pins: CLK on
 * the side-set pin, DATA on the OUT/IN/SET pin (see board.h). CS and
 * WL_REG_ON remain CPU-driven GPIOs (rp2350_spi.c). Call once after
 * clocks are up. */
void rp2350_pio_init(void);

/* One half-duplex gSPI transaction. The command/write words in `tx`
 * (MSB-first, already byte-permuted for the bus mode) are clocked out
 * (out_bits total), then in_bits are clocked in and returned in `rx`
 * (one 32-bit word, MSB-first). CS is asserted/deasserted by the
 * caller. out_bits and in_bits are each 1..32 for register access. */
uint32_t rp2350_pio_xfer32(uint32_t cmd_word, uint32_t out_bits,
                           uint32_t in_bits);

/* General transfer: clock out `out_bits` from out_words[] (MSB-first,
 * 32 bits per word), then clock in `in_bits` and return the last 32-bit
 * word read. in_bits must be a multiple of 32 (use 32 to read one word,
 * or to read+discard after a write). */
uint32_t rp2350_pio_xfer(const uint32_t *out_words, uint32_t n_out_words,
                         uint32_t out_bits, uint32_t in_bits);

/* Streaming byte transfers for F2 data packets (no big stack array).
 * `cmd_word` is the 32-bit gSPI command (already byte-ordered by the
 * caller). `nbytes` must be a multiple of 4. Data bytes go on the wire
 * in ascending order (byte stream, not register byte-swapped). CS is
 * framed by the caller. */
void rp2350_pio_write_bytes(uint32_t cmd_word, const uint8_t *data,
                            uint32_t nbytes);
void rp2350_pio_read_bytes(uint32_t cmd_word, uint8_t *data,
                           uint32_t nbytes);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_RP2350_PIO_H */

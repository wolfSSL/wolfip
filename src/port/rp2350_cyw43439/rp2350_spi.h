/* rp2350_spi.h - RP2350 host SPI driver for CYW43439 gSPI
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

#ifndef WOLFIP_RP2350_SPI_H
#define WOLFIP_RP2350_SPI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise the CPU-driven control lines for the CYW43439 gSPI bus:
 * CS deasserted and WL_REG_ON driven low (radio held off). Pin
 * assignment lives in board.h (CYW43_PIN_*). CLK and DATA are owned by
 * the PIO transport (rp2350_pio_init), not this function. Call once,
 * before power-up: repeating it while the radio is running drives
 * WL_REG_ON low and powers the CYW43439 down. */
void rp2350_spi_init(void);

/* Drive WL_REG_ON high to power the CYW43439. Caller should wait
 * >= 4.5 ms before issuing the first gSPI command (per CYW43439
 * power-on timing). */
void rp2350_cyw43_power_up(void);

/* Drive WL_REG_ON low (radio off). Used on disconnect / suspend. */
void rp2350_cyw43_power_down(void);

/* Assert (1) / deassert (0) the CYW43439 chip-select. CLK and DATA are
 * driven by the PIO transport (rp2350_pio.c); this module owns only the
 * CPU-driven control lines (CS, WL_REG_ON). */
void rp2350_spi_cs(int assert);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_RP2350_SPI_H */

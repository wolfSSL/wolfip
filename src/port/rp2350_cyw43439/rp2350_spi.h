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

/* Initialise the GPIO and SPI peripheral for the CYW43439 gSPI bus.
 * Pin assignment lives in board.h (CYW43_PIN_SPI_*); this function
 * configures pad strength, function-mux, clock divider, and brings the
 * SPI controller out of reset. Safe to call multiple times. */
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

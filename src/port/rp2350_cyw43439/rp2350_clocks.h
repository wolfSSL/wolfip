/* rp2350_clocks.h - RP2350 XOSC + PLL_SYS bring-up
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

#ifndef WOLFIP_RP2350_CLOCKS_H
#define WOLFIP_RP2350_CLOCKS_H

#include <stdint.h>

/* clk_peri after rp2350_clocks_init(). For first bring-up clk_peri is
 * sourced directly from the 12 MHz crystal (no PLL) - see the rationale
 * in rp2350_clocks.c. The UART/SPI drivers divide this for baud/clock. */
#define RP2350_CLK_PERI_HZ 12000000U

#ifdef __cplusplus
extern "C" {
#endif

void rp2350_clocks_init(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_RP2350_CLOCKS_H */

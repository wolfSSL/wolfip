/* timebase.c
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
 */
#include <xc.h>
#include "timebase.h"
#include "board.h"

/* The CP0 Count register increments at SYSCLK/2. It is 32-bit and wraps
 * roughly every 42 s at 100 MHz, so it is extended to 64 bits by tracking
 * wraps. millis() must be polled at least once per wrap period; the wolfIP
 * main loop calls it continuously, so this is trivially satisfied.
 * Single-threaded; not interrupt-safe. */
#define COUNT_HZ        (SYS_CLK_FREQ / 2u)
#define COUNT_PER_MS    (COUNT_HZ / 1000u)

static uint32_t s_last_count;
static uint64_t s_accum;

static uint64_t cp0_count64(void)
{
    uint32_t c = _CP0_GET_COUNT();

    if (c < s_last_count)
        s_accum += 0x100000000ull;
    s_last_count = c;
    return s_accum + (uint64_t)c;
}

uint64_t millis(void)
{
    return cp0_count64() / COUNT_PER_MS;
}

void delay_ms(uint32_t ms)
{
    uint64_t target = millis() + (uint64_t)ms;

    while (millis() < target) {
        /* busy wait */
    }
}

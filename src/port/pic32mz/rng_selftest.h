/* rng_selftest.h
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
#ifndef PIC32MZ_RNG_SELFTEST_H
#define PIC32MZ_RNG_SELFTEST_H

#include <stdint.h>

/* Exercise wolfCrypt's WOLFSSL_PIC32MZ_RNG hardware TRNG path: seed a DRBG,
 * generate two blocks, and sanity-check the output. Prints results over the
 * console UART. Returns 0 on pass, negative on failure. */
int rng_selftest(void);

/* Draw a 32-bit value from the hardware TRNG for seeding a non-crypto PRNG
 * (e.g. the wolfIP ISN/port/xid generator). Returns 0 if the TRNG is
 * unavailable; callers should mix in another source so a 0 is not relied on. */
uint32_t rng_getseed(void);

#endif /* PIC32MZ_RNG_SELFTEST_H */

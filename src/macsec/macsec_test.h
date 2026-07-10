/* macsec_test.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfIP.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfIP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Shared helpers for the standalone macsec test binaries: a pass/fail
 * reporter, a hex compare, and hex/payload builders. Header-only (static
 * inline) so each test stays a single self-contained executable. */

#ifndef WOLFIP_MACSEC_TEST_H
#define WOLFIP_MACSEC_TEST_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static inline int expect_true(int cond, const char *label)
{
    printf(cond ? "  [OK]   %s\n" : "  [FAIL] %s\n", label);
    return cond ? 0 : 1;
}

static inline int hex_eq(const uint8_t *got, const uint8_t *expect, size_t n,
                         const char *label)
{
    size_t i;
    if (memcmp(got, expect, n) == 0) {
        printf("  [OK]   %s\n", label);
        return 0;
    }
    printf("  [FAIL] %s\n    got:    ", label);
    for (i = 0; i < n; i++) printf("%02x", got[i]);
    printf("\n    expect: ");
    for (i = 0; i < n; i++) printf("%02x", expect[i]);
    printf("\n");
    return 1;
}

static inline size_t macsec_unhex(const char *h, uint8_t *o, size_t cap)
{
    size_t   n = 0;
    unsigned v;
    while (h[0] && h[1] && n < cap) {
        if (sscanf(h, "%2x", &v) != 1) break;
        o[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

/* Deterministic MSDU: an IPv4 EtherType (0x0800) followed by a seeded ramp. */
static inline void fill_payload(uint8_t *p, size_t n, uint8_t seed)
{
    size_t i;
    p[0] = 0x08;
    p[1] = 0x00;
    for (i = 2; i < n; i++) p[i] = (uint8_t)(seed + i);
}

#endif /* WOLFIP_MACSEC_TEST_H */

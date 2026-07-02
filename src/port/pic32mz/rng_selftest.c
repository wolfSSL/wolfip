/* rng_selftest.c
 *
 * Standalone wolfCrypt RNG self-test for the PIC32MZ EF hardware TRNG.
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
#include <stdio.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include "rng_selftest.h"

#define RNG_BLOCK_LEN   32

static void print_hex(const char *label, const unsigned char *p, int n)
{
    int i;

    printf("%s", label);
    for (i = 0; i < n; i++)
        printf("%02X", p[i]);
    printf("\r\n");
}

int rng_selftest(void)
{
    WC_RNG rng;
    unsigned char a[RNG_BLOCK_LEN];
    unsigned char b[RNG_BLOCK_LEN];
    int ret;
    int i;
    int all_zero;
    int all_ff;
    int identical;

    printf("\r\n[RNG] WOLFSSL_PIC32MZ_RNG hardware TRNG self-test\r\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("[RNG] wc_InitRng failed: %d (%s)\r\n",
               ret, wc_GetErrorString(ret));
        return -1;
    }

    ret = wc_RNG_GenerateBlock(&rng, a, sizeof(a));
    if (ret != 0) {
        printf("[RNG] GenerateBlock A failed: %d (%s)\r\n",
               ret, wc_GetErrorString(ret));
        (void)wc_FreeRng(&rng);
        return -1;
    }

    ret = wc_RNG_GenerateBlock(&rng, b, sizeof(b));
    if (ret != 0) {
        printf("[RNG] GenerateBlock B failed: %d (%s)\r\n",
               ret, wc_GetErrorString(ret));
        (void)wc_FreeRng(&rng);
        return -1;
    }

    (void)wc_FreeRng(&rng);

    print_hex("[RNG] block A: ", a, RNG_BLOCK_LEN);
    print_hex("[RNG] block B: ", b, RNG_BLOCK_LEN);

    /* Coarse sanity checks: blocks must not be trivial or identical. */
    all_zero = 1;
    all_ff = 1;
    identical = 1;
    for (i = 0; i < RNG_BLOCK_LEN; i++) {
        if (a[i] != 0x00)
            all_zero = 0;
        if (a[i] != 0xFF)
            all_ff = 0;
        if (a[i] != b[i])
            identical = 0;
    }

    if (all_zero || all_ff || identical) {
        printf("[RNG] self-test: FAIL (all_zero=%d all_ff=%d identical=%d)\r\n",
               all_zero, all_ff, identical);
        return -1;
    }

    printf("[RNG] self-test: PASS\r\n");
    return 0;
}

uint32_t rng_getseed(void)
{
    WC_RNG rng;
    uint32_t v;

    v = 0;
    if (wc_InitRng(&rng) != 0)
        return 0;
    if (wc_RNG_GenerateBlock(&rng, (unsigned char *)&v, sizeof(v)) != 0)
        v = 0;
    (void)wc_FreeRng(&rng);
    return v;
}

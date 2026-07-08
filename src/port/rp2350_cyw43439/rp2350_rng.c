/* rp2350_rng.c - RP2350 hardware TRNG seed source for wolfCrypt
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
 * Provides the seed source wolfCrypt's Hash-DRBG pulls from
 * (CUSTOM_RAND_GENERATE_SEED in user_settings.h), which in turn generates the
 * WPA 4-way SNonce and the WPA3-SAE ephemeral rand/mask scalars.
 *
 * Entropy comes from the RP2350 hardware TRNG (0x400f0000): a ring-oscillator
 * true-RNG with built-in autocorrelation, continuous (CRNGT) and von-Neumann
 * health tests (RP2350 datasheet sec. 12.12). Its 192-bit EHR output is a NIST
 * SP800-90B entropy source, so it is fed straight into the DRBG seed buffer -
 * wolfCrypt's Hash-DRBG (SP800-90A) does the conditioning. The register access
 * lives in rp2350_rng.h so the non-crypto wolfIP_getrandom() path can share it.
 *
 * A block read fails closed (returns -1) if the source is stuck or a health
 * test does not clear, rather than emitting a weak seed.
 */
#include <stdint.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/memory.h>   /* wc_ForceZero */

#include "rp2350_rng.h"

int rp2350_wc_genseed(unsigned char *output, unsigned int sz)
{
    uint32_t     block[RP2350_TRNG_EHR_WORDS];
    unsigned int produced, take, i;

    if (output == NULL) {
        return -1;
    }

    for (produced = 0; produced < sz; ) {
        if (rp2350_trng_read_block(block) != 0) {
            /* Health test failed: fail closed, do not emit a weak seed. */
            wc_ForceZero(block, sizeof(block));
            return -1;
        }
        take = sz - produced;
        if (take > (unsigned int)sizeof(block)) {
            take = (unsigned int)sizeof(block);
        }
        for (i = 0; i < take; i++) {
            output[produced + i] = ((const unsigned char *)block)[i];
        }
        produced += take;
    }

    wc_ForceZero(block, sizeof(block));
    return 0;
}

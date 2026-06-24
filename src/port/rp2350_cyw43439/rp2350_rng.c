/* rp2350_rng.c - RP2350 ring-oscillator entropy for wolfCrypt
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
 * The RP2350 ROSC_RANDOMBIT register is documented as biased and strongly
 * autocorrelated and is explicitly NOT a cryptographic entropy source on its
 * own. So this does three things before handing bytes to the DRBG:
 *   1. von Neumann debiasing - sample raw ROSC bits in pairs and keep one only
 *      when the pair differs, removing first-order bias;
 *   2. heavy oversampling - a large debiased pool feeds each output block;
 *   3. cryptographic conditioning - SHA-256 over the pool produces the seed
 *      block, compressing a conservative per-bit entropy estimate into a
 *      full-entropy 256-bit block.
 * A startup/continuous health test fails closed (returns -1) if the oscillator
 * stops producing differing pairs, rather than emitting a weak seed.
 *
 * NOTE: this conditioning is the minimum bar for enabling the SAE/EAP
 * supplicant paths on real hardware; if the RP2350 TRNG/SHA hardware entropy
 * peripheral is brought up later it should supersede the ROSC pool here.
 */
#include <stdint.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>

/* ROSC random-bit register (RP2350: ROSC base 0x400C8000, RANDOMBIT
 * at offset 0x1C). Bit 0 is the raw oscillator-jitter bit. */
#define ROSC_RANDOMBIT (*(volatile uint32_t *)0x400C801CUL)

/* Per debiased bit: how many raw pairs to sample before declaring the
 * oscillator stuck. A healthy ROSC produces a differing pair roughly every
 * other sample, so this budget is only hit on a hardware fault. */
#define ROSC_VN_MAX_PAIRS 1024U
/* Debiased bytes hashed into each 32-byte conditioned output block. */
#define ROSC_POOL_BYTES   64U

static unsigned int rosc_bit(void)
{
    volatile int d;
    /* Let the ROSC bit settle so consecutive raw samples decorrelate. */
    for (d = 0; d < 16; d++) {
    }
    return (unsigned int)(ROSC_RANDOMBIT & 1U);
}

/* von Neumann extractor: emit a bit only when a raw pair differs (10 -> 1,
 * 01 -> 0). Returns 0 and sets *out_bit on success, -1 if the per-bit pair
 * budget is exhausted (oscillator stuck). */
static int rosc_vn_bit(unsigned int *out_bit)
{
    unsigned int a, b, tries;

    for (tries = 0; tries < ROSC_VN_MAX_PAIRS; tries++) {
        a = rosc_bit();
        b = rosc_bit();
        if (a != b) {
            *out_bit = a;
            return 0;
        }
    }
    return -1;
}

int rp2350_wc_genseed(unsigned char *output, unsigned int sz)
{
    wc_Sha256     sha;
    unsigned char digest[WC_SHA256_DIGEST_SIZE];
    unsigned char pool[ROSC_POOL_BYTES];
    unsigned int  produced;
    unsigned int  pi, nbits, bit, take, j;
    unsigned char byte;
    int           ret;

    if (output == NULL) {
        return -1;
    }

    for (produced = 0; produced < sz; ) {
        /* Fill the pool with von Neumann-debiased ROSC bits. */
        for (pi = 0; pi < ROSC_POOL_BYTES; pi++) {
            byte = 0;
            for (nbits = 0; nbits < 8U; nbits++) {
                if (rosc_vn_bit(&bit) != 0) {
                    /* Health test failed: fail closed, do not emit weak seed. */
                    wc_ForceZero(pool, sizeof(pool));
                    return -1;
                }
                byte = (unsigned char)((byte << 1) | (bit & 1U));
            }
            pool[pi] = byte;
        }

        /* SHA-256 conditioner over the pool (+ running offset so per-block
         * hashes never collide even on an identical pool). */
        ret = wc_InitSha256(&sha);
        if (ret == 0) {
            ret = wc_Sha256Update(&sha, pool, (word32)sizeof(pool));
        }
        if (ret == 0) {
            ret = wc_Sha256Update(&sha, (const unsigned char *)&produced,
                                  (word32)sizeof(produced));
        }
        if (ret == 0) {
            ret = wc_Sha256Final(&sha, digest);
        }
        wc_Sha256Free(&sha);
        if (ret != 0) {
            wc_ForceZero(pool, sizeof(pool));
            wc_ForceZero(digest, sizeof(digest));
            return -1;
        }

        take = sz - produced;
        if (take > (unsigned int)sizeof(digest)) {
            take = (unsigned int)sizeof(digest);
        }
        for (j = 0; j < take; j++) {
            output[produced + j] = digest[j];
        }
        produced += take;
    }

    wc_ForceZero(pool, sizeof(pool));
    wc_ForceZero(digest, sizeof(digest));
    return 0;
}

/* rand.c
 *
 * Copyright (C) 2024 wolfSSL Inc.
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

/* Entropy for wolfIP_getrandom() (see main.c): TCP initial sequence numbers,
 * ephemeral ports, DHCP / DNS transaction ids.
 *
 * The RP2040 has no hardware TRNG, so this uses the ROSC (ring oscillator)
 * RANDOMBIT jitter - the same source the pico-sdk pico_rand uses - von-Neumann
 * debiased to remove first-order bias. This replaces the previous 3-LSB ADC
 * sampler, which was slow (1 ms/sample) and weakly random. There is no
 * cryptographic consumer in this build (no wolfCrypt / TLS is linked), so no
 * SHA-256 conditioning stage is applied; debiased ROSC bits are sufficient for
 * protocol randomization. A crypto build should instead feed a DRBG from a
 * conditioned source (cf. the RP2350 hardware TRNG port).
 */
#include "pico/stdlib.h"
#include "hardware/structs/rosc.h"
#include <string.h>

/* Per debiased bit: raw pairs to sample before giving up on a differing pair.
 * A healthy ROSC differs roughly every other sample; this budget is only
 * approached on a hardware fault. */
#define ROSC_VN_MAX_PAIRS 1024u

/* One raw ROSC jitter bit, with a short settle so consecutive samples
 * decorrelate. */
static unsigned int rosc_raw_bit(void)
{
    volatile int d;
    for (d = 0; d < 16; d++) {
    }
    return (unsigned int)(rosc_hw->randombit & 1u);
}

/* von Neumann extractor: emit a bit only when a raw pair differs (10 -> 1,
 * 01 -> 0). Falls back to a single raw bit if the pair budget is exhausted so
 * a seed is always produced (best-effort, non-crypto path). */
static unsigned int rosc_vn_bit(void)
{
    unsigned int a, b, tries;

    for (tries = 0; tries < ROSC_VN_MAX_PAIRS; tries++) {
        a = rosc_raw_bit();
        b = rosc_raw_bit();
        if (a != b) {
            return a;
        }
    }
    return rosc_raw_bit();
}

int custom_random_seed(unsigned char *output, unsigned int sz)
{
    unsigned int  i, nbits;
    unsigned char byte;

    if (output == NULL) {
        return -1;
    }

    for (i = 0; i < sz; i++) {
        byte = 0;
        for (nbits = 0; nbits < 8u; nbits++) {
            byte = (unsigned char)((byte << 1) | (rosc_vn_bit() & 1u));
        }
        output[i] = byte;
    }

    return 0;
}

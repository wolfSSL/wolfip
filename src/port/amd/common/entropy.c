/* entropy.c
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
 *
 * MemUse-pattern entropy source for the wolfIP AMD/Xilinx ports.
 *
 * These PS SoCs do not ship a hardware TRNG usable from bare-metal
 * without the platform firmware. This source produces non-deterministic
 * 32-bit words from the timing variance of a data-dependent memory-access
 * loop over a small state buffer, sampled with a free-running counter
 * (arch_counter64(), arch-specific: AArch64 CNTVCT_EL0 / ARMv7 MPCore
 * global timer) before and after the walk. It is the same primitive
 * wolfCrypt's wc_Entropy_Get() (HAVE_ENTROPY_MEMUSE) uses internally.
 *
 * This implementation skips wolfCrypt's SHA3-256 conditioning because the
 * consumers in wolfIP (TCP ISN, DHCP/DNS transaction IDs, ephemeral source
 * ports, IP fragment ID) need unpredictable bits, not crypto-grade
 * randomness. For crypto-grade seeding the port should be rebuilt with the
 * full wolfCrypt wc_Entropy_Get() in place of amd_get_random32().
 *
 * NOTE: the 1 KB state buffer fits within L1 (it is NOT "larger than the
 * cache"), so the dominant entropy is the counter granularity and the
 * data-dependent walk timing rather than guaranteed cache misses. The
 * output is intentionally non-crypto-grade -- see above.
 *
 * Algorithm per call:
 *   1. t0 = arch_counter64()
 *   2. Walk state[] performing read+xor+write (data-dependent stride).
 *   3. t1 = arch_counter64()
 *   4. Fold (t1 - t0) into the rolling 64-bit accumulator and perturb
 *      state[] so the next call diverges.
 *   5. Apply a non-cryptographic finaliser (xorshift) and return the low
 *      32 bits.
 */
#include <stdint.h>
#include "timer.h"   /* arch_counter64() */

#define ENTROPY_STATE_WORDS     128u   /* 1024 bytes, 16 cache lines */
#define ENTROPY_WALK_ITERS      256u

static volatile uint64_t entropy_state[ENTROPY_STATE_WORDS];
static volatile uint64_t entropy_acc;
static volatile uint32_t entropy_idx;
static volatile int      entropy_seeded;

/* Return a 32-bit value with low predictability, suitable for
 * protocol identifiers (DHCP xid, DNS id, TCP ISN, ephemeral port,
 * IP fragment id). Not crypto-grade; see file header. */
uint32_t amd_get_random32(void)
{
    uint64_t t0, t1, delta;
    uint64_t acc;
    uint32_t i;
    uint32_t walk_idx;
    uint64_t seed;
    uint32_t k;

    /* One-time seed so the earliest outputs (TCP ISN, DHCP xid, ephemeral
     * port, ...) do not derive from a single timing delta over all-zero
     * state. Fold the hardware counter, this frame's stack address, and a
     * per-word counter re-read (each carries a little timing variance) into
     * the rolling state. Still non-crypto-grade - see the file header. */
    if (!entropy_seeded) {
        seed = arch_counter64() ^ (uint64_t)(uintptr_t)&seed;
        for (k = 0; k < ENTROPY_STATE_WORDS; k++) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            entropy_state[k] ^= seed ^ arch_counter64();
        }
        entropy_acc ^= seed;
        entropy_seeded = 1;
    }

    t0 = arch_counter64();

    /* Memory-access loop: stride through the state array. Using a
     * data-dependent index (acc & mask) keeps the prefetcher from
     * predicting cache lines, which is exactly the timing noise we
     * want to harvest. */
    acc = entropy_acc;
    walk_idx = entropy_idx;
    for (i = 0; i < ENTROPY_WALK_ITERS; i++) {
        uint32_t pos = (walk_idx + (uint32_t)(acc & 0x7Fu))
                     & (ENTROPY_STATE_WORDS - 1u);
        uint64_t v = entropy_state[pos];
        v ^= acc;
        v = (v << 1) | (v >> 63);   /* rotate left 1 */
        entropy_state[pos] = v;
        acc += v;
        walk_idx++;
    }

    t1 = arch_counter64();
    delta = t1 - t0;

    /* Fold the timing delta into the accumulator and the head of
     * the state ring. */
    acc ^= delta;
    acc ^= (delta << 17) | (delta >> 47);
    entropy_state[walk_idx & (ENTROPY_STATE_WORDS - 1u)] ^= acc;
    entropy_acc = acc;
    entropy_idx = walk_idx;

    /* xorshift64 finaliser to whiten the output word. */
    acc ^= acc << 13;
    acc ^= acc >> 7;
    acc ^= acc << 17;

    return (uint32_t)acc;
}

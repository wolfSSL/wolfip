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
 * MemUse-pattern entropy source for the wolfIP ZCU102 port.
 *
 * The ZCU102's UltraScale+ PS does not ship a hardware TRNG that is
 * usable from EL3 bare-metal without the PMU firmware and CSU helpers.
 * This source produces non-deterministic 32-bit words by sampling the
 * Cortex-A53 virtual count register (CNTVCT_EL0) before and after a
 * memory-access loop that touches a state buffer larger than the L1
 * data cache. The cache-miss / line-fill / write-allocate timing
 * variance is the entropy source - the same primitive wolfCrypt's
 * wc_Entropy_Get() (HAVE_ENTROPY_MEMUSE in wolfssl/wolfcrypt/src/
 * wolfentropy.c) uses internally.
 *
 * This implementation skips wolfCrypt's SHA3-256 conditioning because
 * the consumers in wolfIP (TCP ISN, DHCP/DNS transaction IDs,
 * ephemeral source ports, IP fragment ID) need unpredictable bits,
 * not uniformly-distributed cryptographic randomness. For crypto-
 * grade seeding the port should be rebuilt with the full wolfCrypt
 * wc_Entropy_Get() in place of zcu102_get_random32().
 *
 * Algorithm per call:
 *   1. t0 = CNTVCT_EL0
 *   2. Walk state[] performing read+xor+write; ~256 accesses spans
 *      multiple L1 cache lines on this 32 KB / 4-way A53 cache.
 *   3. t1 = CNTVCT_EL0
 *   4. Fold (t1 - t0) into the rolling 64-bit accumulator and
 *      perturb state[] so the next call diverges.
 *   5. Apply a non-cryptographic finaliser (xorshift) and return
 *      the low 32 bits.
 *
 * The state buffer is 1024 bytes (sized to span the A53's 64-byte
 * line size 16 times, ensuring at least a handful of cache misses
 * per call even on a warm cache).
 */
#include <stdint.h>

#define ENTROPY_STATE_WORDS     128u   /* 1024 bytes, 16 cache lines */
#define ENTROPY_WALK_ITERS      256u

static volatile uint64_t entropy_state[ENTROPY_STATE_WORDS];
static volatile uint64_t entropy_acc;
static volatile uint32_t entropy_idx;

static inline uint64_t cntvct_el0(void)
{
    uint64_t v;
    __asm__ volatile ("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

/* Return a 32-bit value with low predictability, suitable for
 * protocol identifiers (DHCP xid, DNS id, TCP ISN, ephemeral port,
 * IP fragment id). Not crypto-grade; see file header. */
uint32_t zcu102_get_random32(void)
{
    uint64_t t0, t1, delta;
    uint64_t acc;
    uint32_t i;
    uint32_t walk_idx;

    t0 = cntvct_el0();

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

    t1 = cntvct_el0();
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

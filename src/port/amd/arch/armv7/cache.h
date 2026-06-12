/* cache.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * ARMv7-A (Cortex-A9) cache maintenance for GEM DMA coherency. The A9
 * L1 cache line is 32 bytes (NOT the 64 bytes of the AArch64 cores this
 * driver is shared with); the stride below must match or the ops skip
 * lines. In this port the GEM rings/buffers live in OCM which the MMU
 * maps non-cacheable (see mmu_armv7.c), so these are effectively no-ops,
 * but they stay correct for a cacheable layout.
 */
#ifndef AMD_CACHE_H
#define AMD_CACHE_H

#include <stdint.h>

#define CACHE_LINE 32u

static inline void cache_clean(const void *p, uint32_t sz)
{
    uintptr_t start = (uintptr_t)p & ~(CACHE_LINE - 1u);
    uintptr_t end   = ((uintptr_t)p + sz + CACHE_LINE - 1u) & ~(CACHE_LINE - 1u);
    uintptr_t a;
    /* ARMv7 DCCMVAC (Clean Data cache by MVA to PoC):
     *   MCR p15, 0, Rt, c7, c10, 1 */
    for (a = start; a < end; a += CACHE_LINE)
        __asm__ volatile ("mcr p15, 0, %0, c7, c10, 1" :: "r"(a) : "memory");
    __asm__ volatile ("dsb" ::: "memory");
}

static inline void cache_inval(const void *p, uint32_t sz)
{
    uintptr_t start = (uintptr_t)p & ~(CACHE_LINE - 1u);
    uintptr_t end   = ((uintptr_t)p + sz + CACHE_LINE - 1u) & ~(CACHE_LINE - 1u);
    uintptr_t a;
    /* ARMv7 DCIMVAC (Invalidate Data cache by MVA to PoC):
     *   MCR p15, 0, Rt, c7, c6, 1 */
    for (a = start; a < end; a += CACHE_LINE)
        __asm__ volatile ("mcr p15, 0, %0, c7, c6, 1" :: "r"(a) : "memory");
    __asm__ volatile ("dsb" ::: "memory");
}

#endif /* AMD_CACHE_H */

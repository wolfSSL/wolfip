/* cache.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * AArch64 (Cortex-A53/A72) cache maintenance for GEM DMA coherency. The
 * cache line is 64 bytes. With D-cache enabled and BD/buffers in normal
 * cacheable memory, CPU writes may sit in L1 and not be visible to the
 * MAC's DMA path. cache_clean() writes back dirty lines before DMA
 * reads; cache_inval() invalidates lines so CPU reads pull fresh
 * DMA-written data.
 */
#ifndef AMD_CACHE_H
#define AMD_CACHE_H

#include <stdint.h>

#define CACHE_LINE 64u

static inline void cache_clean(const void *p, uint32_t sz)
{
    uintptr_t start = (uintptr_t)p & ~(CACHE_LINE - 1u);
    uintptr_t end   = ((uintptr_t)p + sz + CACHE_LINE - 1u) & ~(CACHE_LINE - 1u);
    uintptr_t a;
    for (a = start; a < end; a += CACHE_LINE)
        __asm__ volatile ("dc cvac, %0" :: "r"(a) : "memory");
    __asm__ volatile ("dsb sy" ::: "memory");
}

static inline void cache_inval(const void *p, uint32_t sz)
{
    uintptr_t start = (uintptr_t)p & ~(CACHE_LINE - 1u);
    uintptr_t end   = ((uintptr_t)p + sz + CACHE_LINE - 1u) & ~(CACHE_LINE - 1u);
    uintptr_t a;
    for (a = start; a < end; a += CACHE_LINE)
        __asm__ volatile ("dc ivac, %0" :: "r"(a) : "memory");
    __asm__ volatile ("dsb sy" ::: "memory");
}

#endif /* AMD_CACHE_H */

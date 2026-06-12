/* timer.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * AArch64 generic-timer based delay helpers (Cortex-A53/A72). The PLM/
 * FSBL/ATF programs CNTFRQ_EL0; we fall back to 100 MHz if it reads 0.
 *
 * CNTPCT_EL0/CNTVCT_EL0 are readable at every EL without trap setup.
 */
#ifndef AMD_TIMER_H
#define AMD_TIMER_H

#include <stdint.h>

static inline uint64_t timer_now(void)
{
    uint64_t v;
    __asm__ volatile ("isb; mrs %0, cntpct_el0" : "=r"(v) :: "memory");
    return v;
}

static inline uint32_t timer_freq(void)
{
    uint64_t v;
    __asm__ volatile ("mrs %0, cntfrq_el0" : "=r"(v));
    return v ? (uint32_t)v : 100000000u;
}

/* Free-running 64-bit counter for the entropy source (virtual count,
 * readable at every EL). */
static inline uint64_t arch_counter64(void)
{
    uint64_t v;
    __asm__ volatile ("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

static inline void delay_us(uint32_t us)
{
    uint64_t start = timer_now();
    uint64_t target = ((uint64_t)us * (uint64_t)timer_freq()) / 1000000ULL;
    while ((timer_now() - start) < target) { }
}

static inline void delay_ms(uint32_t ms)
{
    delay_us(ms * 1000u);
}

#endif /* AMD_TIMER_H */

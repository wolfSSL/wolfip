/* timer.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * AArch64 generic-timer based delay helpers. ZynqMP FSBL/ATF programs
 * CNTFRQ_EL0 to 100 MHz; we fall back to that if the register reads 0.
 *
 * CNTPCT_EL0 is readable at every EL on Cortex-A53 without trap setup.
 */
#ifndef ZCU102_TIMER_H
#define ZCU102_TIMER_H

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

#endif /* ZCU102_TIMER_H */

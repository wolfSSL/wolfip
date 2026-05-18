/* timer.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * ARMv7 generic timer delay helpers. Zynq-7000 FSBL leaves CNTFRQ
 * programmed (PS reference clock divided to typically 333.333 MHz);
 * we fall back to that if the register reads 0. CNTPCT (physical
 * count, 64-bit) is read via the CP15 MRRC two-register move.
 *
 * UNTESTED ON HARDWARE.
 */
#ifndef ZYNQ7000_TIMER_H
#define ZYNQ7000_TIMER_H

#include <stdint.h>

static inline uint64_t timer_now(void)
{
    uint32_t lo, hi;
    __asm__ volatile ("isb" ::: "memory");
    /* MRRC p15, 0, Rlo, Rhi, c14 -> CNTPCT 64-bit physical counter */
    __asm__ volatile ("mrrc p15, 0, %0, %1, c14" : "=r"(lo), "=r"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint32_t timer_freq(void)
{
    uint32_t v;
    /* MRC p15, 0, R, c14, c0, 0 -> CNTFRQ */
    __asm__ volatile ("mrc p15, 0, %0, c14, c0, 0" : "=r"(v));
    return v ? v : 333333333u;
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

#endif /* ZYNQ7000_TIMER_H */

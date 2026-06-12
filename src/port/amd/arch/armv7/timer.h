/* timer.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Cortex-A9 (Zynq-7000) delay helpers.
 *
 * The Cortex-A9 does NOT implement the ARMv7 generic timer
 * (CNTPCT/CNTFRQ via CP15 c14) -- those encodings are UNDEFINED on this
 * core and trap to the undefined-instruction vector. The MPCore provides
 * a 64-bit free-running Global Timer at PERIPHBASE+0x200 instead. It is
 * clocked at PERIPHCLK = CPU_3x2x = 333.33 MHz on the ZC702 with the
 * default FSBL clock plan (ARM_PLL 1.333 GHz, CPU_6x4x 666.67 MHz).
 * Override Z7_GTIMER_FREQ_HZ if you reclock the CPU.
 */
#ifndef AMD_TIMER_H
#define AMD_TIMER_H

#include <stdint.h>

#define Z7_GTIMER_BASE      0xF8F00200u
#define Z7_GTIMER_LO        (*(volatile uint32_t *)(Z7_GTIMER_BASE + 0x00))
#define Z7_GTIMER_HI        (*(volatile uint32_t *)(Z7_GTIMER_BASE + 0x04))
#define Z7_GTIMER_CTRL      (*(volatile uint32_t *)(Z7_GTIMER_BASE + 0x08))
#define Z7_GTIMER_CTRL_EN   0x00000001u

#ifndef Z7_GTIMER_FREQ_HZ
#define Z7_GTIMER_FREQ_HZ   333333333u
#endif

static inline uint64_t timer_now(void)
{
    uint32_t hi1, lo, hi2;

    /* Enable the Global Timer once if the FSBL left it stopped. */
    if ((Z7_GTIMER_CTRL & Z7_GTIMER_CTRL_EN) == 0)
        Z7_GTIMER_CTRL = Z7_GTIMER_CTRL_EN;

    /* Read high, low, high again; retry if a wrap happened mid-read. */
    do {
        hi1 = Z7_GTIMER_HI;
        lo  = Z7_GTIMER_LO;
        hi2 = Z7_GTIMER_HI;
    } while (hi1 != hi2);

    return ((uint64_t)hi2 << 32) | (uint64_t)lo;
}

static inline uint32_t timer_freq(void)
{
    return Z7_GTIMER_FREQ_HZ;
}

/* Free-running 64-bit counter for the entropy source (MPCore global
 * timer; the A9 has no ARMv7 generic timer). */
static inline uint64_t arch_counter64(void)
{
    return timer_now();
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

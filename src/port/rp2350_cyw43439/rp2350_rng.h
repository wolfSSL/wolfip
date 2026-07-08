/* rp2350_rng.h - RP2350 hardware TRNG register access (dependency-free)
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
 * The RP2350 has a hardware true-RNG (an ARM TrustZone-style ring-oscillator
 * TRNG with autocorrelation / continuous / von-Neumann health tests; RP2350
 * datasheet sec. 12.12), mapped at 0x400f0000. This header exposes the raw
 * block read with no wolfCrypt dependency so both the wolfCrypt seed hook
 * (rp2350_rng.c) and the plain wolfIP_getrandom() path (main.c, which is also
 * compiled in non-supplicant builds without wolfSSL) can share one copy of the
 * register map.
 */
#ifndef RP2350_RNG_H
#define RP2350_RNG_H

#include <stdint.h>

/* TRNG base and register offsets (per RP2350 datasheet / pico-sdk
 * hardware/regs/trng.h). Only the registers this driver uses are listed. */
#define RP2350_TRNG_BASE            0x400f0000UL
#define RP2350_TRNG_REG(off)        (*(volatile uint32_t *)(RP2350_TRNG_BASE + (off)))

#define RP2350_TRNG_RNG_ISR         RP2350_TRNG_REG(0x104UL) /* status         */
#define RP2350_TRNG_RNG_ICR         RP2350_TRNG_REG(0x108UL) /* clear (write 1)*/
#define RP2350_TRNG_CONFIG          RP2350_TRNG_REG(0x10cUL) /* ROSC len select*/
#define RP2350_TRNG_RND_SOURCE_EN   RP2350_TRNG_REG(0x12cUL) /* bit0 enable    */
#define RP2350_TRNG_SAMPLE_CNT1     RP2350_TRNG_REG(0x130UL) /* sample divider */
#define RP2350_TRNG_SW_RESET        RP2350_TRNG_REG(0x140UL) /* write 1: reset */
#define RP2350_TRNG_RNG_IMR         RP2350_TRNG_REG(0x100UL) /* irq mask       */
#define RP2350_TRNG_EHR_DATA0_OFF   0x114UL                  /* EHR_DATA0..5   */

/* RNG_ISR status bits. */
#define RP2350_TRNG_ISR_EHR_VALID   (1U << 0) /* 192-bit block ready         */
#define RP2350_TRNG_ISR_AUTOCORR    (1U << 1) /* autocorrelation test failed */
#define RP2350_TRNG_ISR_CRNGT       (1U << 2) /* continuous (repeat) failed  */
#define RP2350_TRNG_ISR_VN          (1U << 3) /* von Neumann balancer error  */
#define RP2350_TRNG_ISR_ERR_MASK    (RP2350_TRNG_ISR_AUTOCORR \
                                     | RP2350_TRNG_ISR_CRNGT   \
                                     | RP2350_TRNG_ISR_VN)

#define RP2350_TRNG_EHR_WORDS       6U        /* 6 x 32-bit = 192 bits       */
#define RP2350_TRNG_SAMPLE_RATE     1000U     /* ROSC samples per bit (tune  */
                                              /* per datasheet)              */
#define RP2350_TRNG_POLL_LIMIT      1000000UL /* bounded spin per block      */
#define RP2350_TRNG_MAX_RETRIES     32U       /* health-test retries         */

/* Configure and start the TRNG noise source. Idempotent. */
static inline void rp2350_trng_start(void)
{
    RP2350_TRNG_SW_RESET      = 1U;         /* self-clearing core reset      */
    RP2350_TRNG_RND_SOURCE_EN = 0U;         /* stop while (re)configuring    */
    RP2350_TRNG_RNG_IMR       = 0xFFFFFFFFU;/* mask all irqs - we poll       */
    RP2350_TRNG_RNG_ICR       = 0xFFFFFFFFU;/* clear stale status            */
    RP2350_TRNG_CONFIG        = 0U;         /* ROSC chain length 0           */
    RP2350_TRNG_SAMPLE_CNT1   = RP2350_TRNG_SAMPLE_RATE;
    RP2350_TRNG_RND_SOURCE_EN = 1U;         /* start collecting entropy      */
}

/* Read one 192-bit entropy block into out[RP2350_TRNG_EHR_WORDS]. Returns 0
 * on success, -1 (fail closed) if the source is stuck or a health-test error
 * does not clear within the retry budget - never returns weak/partial data.
 * Self-heals: (re)starts the source if it is not enabled. */
static inline int rp2350_trng_read_block(uint32_t out[RP2350_TRNG_EHR_WORDS])
{
    volatile uint32_t *ehr;
    uint32_t isr, spin, retries;
    unsigned int i;

    if ((RP2350_TRNG_RND_SOURCE_EN & 1U) == 0U) {
        rp2350_trng_start();
    }
    ehr = (volatile uint32_t *)(RP2350_TRNG_BASE + RP2350_TRNG_EHR_DATA0_OFF);

    for (retries = 0; retries < RP2350_TRNG_MAX_RETRIES; retries++) {
        for (spin = 0; spin < RP2350_TRNG_POLL_LIMIT; spin++) {
            isr = RP2350_TRNG_RNG_ISR;
            if ((isr & RP2350_TRNG_ISR_ERR_MASK) != 0U) {
                break;              /* health-test error - restart source    */
            }
            if ((isr & RP2350_TRNG_ISR_EHR_VALID) != 0U) {
                for (i = 0; i < RP2350_TRNG_EHR_WORDS; i++) {
                    out[i] = ehr[i];
                }
                RP2350_TRNG_RNG_ICR = 0xFFFFFFFFU; /* ack + re-arm next block*/
                return 0;
            }
        }
        rp2350_trng_start();        /* timed out or errored - reset + retry  */
    }
    return -1;
}

#endif /* RP2350_RNG_H */

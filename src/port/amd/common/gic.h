/* gic.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 */
#ifndef AMD_GIC_H
#define AMD_GIC_H

#include <stdint.h>

typedef void (*gic_handler_t)(void);

void gic_init(void);
void gic_register_handler(uint32_t intid, gic_handler_t fn);
void gic_enable_spi(uint32_t intid, uint32_t priority);
void gic_disable_spi(uint32_t intid);

/* Returns 1 if interrupt is currently pending at the distributor,
 * 0 otherwise. Diagnostic only. */
uint32_t gic_is_pending(uint32_t intid);

/* Fire a software-generated interrupt to self (CPU0) for testing.
 * intid must be < 16. */
void gic_self_test_sgi(uint32_t intid);

/* Total IRQs taken (any intid) and the last intid we saw. */
uint32_t gic_total_irqs(void);
uint32_t gic_last_intid(void);

/* Polled-mode IRQ dispatch: drains any pending IRQ from the GIC
 * by reading GICC_IAR, calling the registered handler, and EOI'ing.
 * Returns the number of interrupts dispatched in this call.
 *
 * Workaround: on some of these Cortex-A / GIC combinations the GIC
 * latches pending interrupts correctly but the CPU never takes the
 * IRQ exception (root cause not pinned). Calling this function from
 * the main loop is functionally equivalent. */
uint32_t gic_poll_dispatch(void);

/* Provided by startup.S, asm helpers. */
void irq_enable(void);
void irq_disable(void);

/* Called by the IRQ vector trampoline in startup.S. Acknowledges,
 * dispatches, and EOIs the current interrupt. */
void irq_dispatch(void);

#endif /* AMD_GIC_H */

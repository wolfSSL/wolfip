/* gem_rx_swq_poll.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Poll-drained swq RX policy (Versal): the GICv3 CPU interface did not
 * deliver the GEM SPI in this EL3 bring-up, so gem_eth_poll() calls gem_isr()
 * itself from the main loop to drain the hardware RX BD ring into swq[],
 * then consumes one slot. The swq machinery and gem_isr/gem_swq_drain live
 * in gem_swq.c.
 */
#include "gem_port.h"

int gem_eth_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    gem_isr();
    return gem_swq_drain(buf, len);
}

/* Poll-only on this board: gem_eth_poll drives gem_isr from the main loop, so
 * we deliberately do NOT register/enable the GEM IRQ here. Arming it would
 * put a second gem_isr producer (IRQ context) on the single-producer swq
 * if GICv3 delivery ever starts working (see the root-cause note on the
 * GICv3 group configuration in gic_gicv3.c). */
void gem_rx_install(void)
{
}

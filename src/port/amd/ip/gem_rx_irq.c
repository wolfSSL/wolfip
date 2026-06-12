/* gem_rx_irq.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * IRQ-driven RX policy: gem_isr() runs off the real GIC SPI and fills swq[];
 * gem_eth_poll() only drains the SW queue. The swq machinery and
 * gem_isr/gem_swq_drain live in gem_swq.c.
 *
 * NOTE: this file is intentionally NOT compiled by any shipped board Makefile
 * (it is therefore not covered by -Wall -Wextra -Werror; keep it in sync with
 * the gem_port.h / IXR_* / gic_* interfaces by hand). All three boards select
 * the poll-driven RX models instead (ip/gem_rx_swq_poll.c on ZCU102/Versal,
 * ip/gem_rx_poll.c on Zynq-7000): an enabled RX-complete interrupt storms the
 * CPU under sustained (TCP-rate) RX and wedges the stack. This file is retained
 * as the reference IRQ wiring for a future NAPI-style model (mask the GEM RX
 * IRQ in the ISR, re-enable after the main loop drains).
 */
#include "gem_regs.h"
#include "gem_port.h"
#include "board.h"
#include "gic.h"

int gem_eth_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    return gem_swq_drain(buf, len);
}

/* Register the GEM ISR, enable its SPI at the GIC distributor, and arm the
 * RX-side GEM interrupts. gem_isr is the single (IRQ-context) producer. */
void gem_rx_install(void)
{
    gic_register_handler(IRQ_GEM, gem_isr);
    gic_enable_spi(IRQ_GEM, 0xA0);
    GEM_IER = IXR_FRAMERX | IXR_RXUSED | IXR_RXOVR | IXR_HRESPNOK;
}

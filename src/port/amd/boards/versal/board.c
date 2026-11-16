/* board.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Versal (VMK180) board hooks for the shared demo (app.c).
 */
#include "app.h"
#include "gic.h"

const char *board_banner(void)
{
#ifdef WOLFIP_EL2
    return "\n\n=== wolfIP Versal Gen 1 (VMK180, Cortex-A72 EL2) ===\n"
           "MMU on, caches on. GIC left to BL31, RX polled.\n";
#else
    return "\n\n=== wolfIP Versal Gen 1 (VMK180, Cortex-A72 EL3) ===\n"
           "MMU on, caches on. Bringing up GIC-600 (GICv3)...\n";
#endif
}

void board_irq_setup(void)
{
    /* The GICv3 CPU interface did not deliver the GEM SPI in this EL3
     * bring-up (eth_poll drives gem_isr from the main loop instead), but
     * we still unmask at the CPU defensively. At EL2 the GIC belongs to
     * BL31 and nothing is routed to us, so stay masked. */
#ifndef WOLFIP_EL2
    irq_enable();
#endif
}

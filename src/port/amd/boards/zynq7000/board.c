/* board.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Zynq-7000 (ZC702) board hooks for the shared demo (app.c).
 */
#include "app.h"

const char *board_banner(void)
{
    return "\n\n=== wolfIP Zynq-7000 (Cortex-A9 SVC) ===\n"
           "MMU on, caches on. Bringing up GIC-390...\n";
}

void board_irq_setup(void)
{
    /* RX is poll-driven and the GEM interrupt is left masked, so there is
     * nothing to unmask at the CPU here. */
}

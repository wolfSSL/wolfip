/* board.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * ZCU102 board hooks for the shared demo (app.c).
 */
#include "app.h"
#include "gic.h"

const char *board_banner(void)
{
    return "\n\n=== wolfIP ZCU102 (UltraScale+ A53-0 EL3) ===\n"
           "MMU on, caches on. Bringing up GIC-400 (GICv2)...\n";
}

void board_irq_setup(void)
{
    /* RX is poll-driven (gem_rx_swq_poll: gem_isr() is called from the main
     * loop and gem_rx_install() is a no-op, so no GEM SPI is armed). The
     * IRQ-driven RX model stormed the CPU under sustained TCP-rate RX and
     * wedged the stack, so this board now uses the same poll model as the
     * other two. Unmasking CPU IRQs here is harmless (no source enabled). */
    irq_enable();
}

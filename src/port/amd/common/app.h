/* app.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Board hooks consumed by the shared UDP-echo + DHCP demo (app.c).
 * Implemented per board in boards/<b>/board.c.
 */
#ifndef AMD_APP_H
#define AMD_APP_H

/* Multi-line intro banner (board name + GIC type) printed at startup. */
const char *board_banner(void);

/* Called after the GEM is up: unmask CPU IRQs on boards that use
 * IRQ-driven RX; a no-op on poll-only boards. */
void board_irq_setup(void);

#endif /* AMD_APP_H */

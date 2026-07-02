/* clock_init.c
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
 * wolfIP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#include <xc.h>
#include "clock_init.h"

void clock_init(void)
{
    /* Flash wait-states + prefetch for 200 MHz SYSCLK.
     * PFMWS = 2 wait-states is required above ~134 MHz on PIC32MZ EF.
     * PREFEN = 3 enables predictive prefetch for cacheable and
     * non-cacheable regions. PRECON is not lock-protected. */
    PRECONbits.PFMWS  = 2;
    PRECONbits.PREFEN = 3;

    /* Peripheral buses PBCLK2 (UART) and PBCLK5 (EMAC) remain at their
     * reset default of SYSCLK/2 = 100 MHz, which is what this port targets.
     * The L1 cache and KSEG0 coherency are enabled by the XC32 reset
     * startup code, so nothing is done here for v1. */
}

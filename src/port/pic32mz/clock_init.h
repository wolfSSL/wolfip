/* clock_init.h
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
#ifndef PIC32MZ_CLOCK_INIT_H
#define PIC32MZ_CLOCK_INIT_H

/* Configure flash wait-states / prefetch for 200 MHz operation.
 * The PLL itself is brought up at reset from the DEVCFG config words
 * (FNOSC=SPLL), so by the time main() runs SYSCLK is already 200 MHz.
 * Bare-metal reusable (intended to be lifted into a future wolfBoot port). */
void clock_init(void);

#endif /* PIC32MZ_CLOCK_INIT_H */

/* startup.c
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
#include <stdint.h>

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;

int main(void);

/* Enable SRAM1/2 clocks before touching BSS or stack in those regions */
#define AHBCLKCTRLSET0 (*(volatile uint32_t *)0x40000220UL)

void Reset_Handler(void)
{
    uint32_t *src, *dst;

    /* SRAM1/2/3/X clocks (bits 3-6) must be on before BSS zeroing */
    AHBCLKCTRLSET0 = (1U << 3) | (1U << 4) | (1U << 5) | (1U << 6);

    src = &_sidata;
    for (dst = &_sdata; dst < &_edata; )
        *dst++ = *src++;

    for (dst = &_sbss; dst < &_ebss; )
        *dst++ = 0u;

    (void)main();
    while (1) { }
}

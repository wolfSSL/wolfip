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
extern void __libc_init_array(void);

int main(void);

void Reset_Handler(void)
{
    uint32_t *src;
    uint32_t *dst;

#if TZEN_ENABLED
    /* Point VTOR_NS at our vector table. wolfBoot's BLXNS sets VTOR_S
     * but does not write VTOR_NS; without this, NS exceptions vector
     * to address 0 (wolfBoot's S vectors) and lock the CPU. The NS
     * vector table is at the start of FLASH (0x08060400, after the
     * 1024-byte wolfBoot header). */
    *(volatile uint32_t *)0xE000ED08u = 0x08060400u;
    __asm volatile ("dsb sy" ::: "memory");
#endif

    src = &_sidata;
    for (dst = &_sdata; dst < &_edata; ) {
        *dst++ = *src++;
    }
    for (dst = &_sbss; dst < &_ebss; ) {
        *dst++ = 0u;
    }
    __libc_init_array();
    (void)main();
    while (1) { }
}

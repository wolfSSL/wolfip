/* ivt.c
 *
 * LPC54S018 SPIFI Config Block + Cortex-M4 Interrupt Vector Table
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

/* Vector table (at flash offset 0x000 — boot ROM expects vectors at flash base).
 * Entry[7] is patched by fix_checksum.py (entries 0-7 must sum to 0).
 * LPC54S018 has up to 73 external interrupts; we declare 65 to keep the
 * table under 0x144 so the enhanced boot header at 0x160 has room. */
extern void Reset_Handler(void);
extern void SysTick_Handler(void);
extern unsigned long _estack;

static void default_handler(void) { while (1) { } }

void NMI_Handler(void)       __attribute__((weak, alias("default_handler")));
void HardFault_Handler(void) __attribute__((weak, alias("default_handler")));
void MemManage_Handler(void) __attribute__((weak, alias("default_handler")));
void BusFault_Handler(void)  __attribute__((weak, alias("default_handler")));
void UsageFault_Handler(void)__attribute__((weak, alias("default_handler")));
void SVC_Handler(void)       __attribute__((weak, alias("default_handler")));
void DebugMon_Handler(void)  __attribute__((weak, alias("default_handler")));
void PendSV_Handler(void)    __attribute__((weak, alias("default_handler")));

__attribute__((section(".isr_vector"), used))
/* 81 entries total (16 Cortex-M core + 65 IRQs). Keeps vector table
 * under 0x144 so enhanced boot header can live at 0x160 like wolfBoot. */
const uint32_t vector_table[16 + 65] = {
    [0] = (uint32_t)&_estack,
    [1] = (uint32_t)&Reset_Handler,
    [2] = (uint32_t)&NMI_Handler,
    [3] = (uint32_t)&HardFault_Handler,
    [4] = (uint32_t)&MemManage_Handler,
    [5] = (uint32_t)&BusFault_Handler,
    [6] = (uint32_t)&UsageFault_Handler,
    [7] = 0,  /* Checksum (patched by fix_checksum.py) */
    [8] = 0, [9] = 0, [10] = 0,
    [11] = (uint32_t)&SVC_Handler,
    [12] = (uint32_t)&DebugMon_Handler,
    [13] = 0,
    [14] = (uint32_t)&PendSV_Handler,
    [15] = (uint32_t)&SysTick_Handler,
    [16 ... 80] = (uint32_t)&default_handler
};

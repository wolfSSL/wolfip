/* ivt.c
 *
 * Cortex-M55 interrupt vector table for STM32N6.
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

extern void Reset_Handler(void);
extern unsigned long _estack;

static void default_handler(void)
{
    while (1) { }
}

void NMI_Handler(void)        __attribute__((weak, alias("default_handler")));
void HardFault_Handler(void)  __attribute__((weak, alias("default_handler")));
void MemManage_Handler(void)  __attribute__((weak, alias("default_handler")));
void BusFault_Handler(void)   __attribute__((weak, alias("default_handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("default_handler")));
void SecureFault_Handler(void)__attribute__((weak, alias("default_handler")));
void SVC_Handler(void)        __attribute__((weak, alias("default_handler")));
void DebugMon_Handler(void)   __attribute__((weak, alias("default_handler")));
void PendSV_Handler(void)     __attribute__((weak, alias("default_handler")));
void SysTick_Handler(void)    __attribute__((weak, alias("default_handler")));

/* Repeat macros for filling IRQ entries portably */
#define DH       (uint32_t)&default_handler
#define DH5      DH, DH, DH, DH, DH
#define DH10     DH5, DH5
#define DH50     DH10, DH10, DH10, DH10, DH10
#define DH200    DH50, DH50, DH50, DH50

/* Cortex-M55 vector table: 16 system + 200 IRQs (ETH1_IRQn = 179) */
__attribute__((section(".isr_vector")))
const uint32_t vector_table[16 + 200] = {
    (uint32_t)&_estack,
    (uint32_t)&Reset_Handler,
    (uint32_t)&NMI_Handler,
    (uint32_t)&HardFault_Handler,
    (uint32_t)&MemManage_Handler,
    (uint32_t)&BusFault_Handler,
    (uint32_t)&UsageFault_Handler,
    (uint32_t)&SecureFault_Handler,
    0, 0, 0,
    (uint32_t)&SVC_Handler,
    (uint32_t)&DebugMon_Handler,
    0,
    (uint32_t)&PendSV_Handler,
    (uint32_t)&SysTick_Handler,
    DH200
};

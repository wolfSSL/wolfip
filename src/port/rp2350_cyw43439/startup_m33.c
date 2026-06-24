/* startup_m33.c - RP2350 Cortex-M33 reset handler + interrupt vector
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */
#include <stdint.h>

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern void __libc_init_array(void);
extern unsigned long _estack;

int main(void);

void Reset_Handler(void)
{
    uint32_t *src;
    uint32_t *dst;

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

/* RP2350 reports 53 external IRQ lines (datasheet 3.2). Reserve 64
 * vector slots for forward-compat with future RP2 variants. */
__attribute__((section(".isr_vector")))
const uint32_t vector_table[16 + 64] = {
    [0]  = (uint32_t)&_estack,
    [1]  = (uint32_t)&Reset_Handler,
    [2]  = (uint32_t)&NMI_Handler,
    [3]  = (uint32_t)&HardFault_Handler,
    [4]  = (uint32_t)&MemManage_Handler,
    [5]  = (uint32_t)&BusFault_Handler,
    [6]  = (uint32_t)&UsageFault_Handler,
    [7]  = (uint32_t)&SecureFault_Handler,
    [8]  = 0, [9] = 0, [10] = 0,
    [11] = (uint32_t)&SVC_Handler,
    [12] = (uint32_t)&DebugMon_Handler,
    [13] = 0,
    [14] = (uint32_t)&PendSV_Handler,
    [15] = (uint32_t)&SysTick_Handler,
    [16 ... 79] = (uint32_t)&default_handler
};

/* RP2350 IMAGE_DEF in .boot_metadata. The bootrom walks the first 4 KB
 * of flash for this block. Format per RP2350 datasheet 5.9 + picobin
 * headers in pico-sdk:
 *
 *   word 0: PICOBIN_BLOCK_MARKER_START (0xFFFFDED3)
 *
 *   word 1: ITEM_TYPE_IMAGE_DEF
 *           byte 0 = tag         (0x42 = IMAGE_TYPE)
 *           byte 1 = size_words  (1 - this item is one word total)
 *           bytes 2..3 = flags16:
 *             [3:0]  image_type  (1 = EXE)
 *             [7:4]  security    (2 = s-mode for non-secure boot)
 *             [11:8] arch        (0 = ARM, 1 = RISC-V)
 *
 *   word 2: ITEM_TYPE_LAST
 *           byte 0 = tag         (0xFF)
 *           byte 1 = size_words  (1)
 *           bytes 2..3 = pad     (0)
 *
 *   word 3: relative offset to next block (signed). 0 = block loops to
 *           itself (valid for a single-block image).
 *
 *   word 4: PICOBIN_BLOCK_MARKER_END (0xAB123579)
 */
__attribute__((section(".boot_metadata"), used))
const uint32_t boot_image_def[5] = {
    0xFFFFDED3U,
    /* IMAGE_TYPE: tag=0x42 size=1 flags=0x1021 :
     *   bit 0   : EXE       = 1
     *   bit 4-7 : security  = 2 (NS - bootrom does not enforce secure)
     *   bit 8-11: CPU       = 0 (ARM)
     *   bit 12-15:CHIP      = 1 (RP2350) */
    0x10210142U,
    0x000001FFU,              /* LAST item: tag=0xFF size_words=1         */
    0x00000000U,              /* next-block offset (0 = block loops here) */
    0xAB123579U
};

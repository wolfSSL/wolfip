/* startup_hazard3.c - RP2350 Hazard3 (RISC-V) entry stub
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
extern unsigned long _estack;
extern void __libc_init_array(void) __attribute__((weak));

int main(void);

__attribute__((naked, section(".text._start")))
void _start(void)
{
    __asm__ volatile(
        ".option push                  \n"
        ".option norelax               \n"
        "la   gp, __global_pointer$    \n"
        ".option pop                   \n"
        "la   sp, _estack              \n"
        "call _startup_c               \n"
        "1:  j 1b                      \n"
    );
}

void _startup_c(void)
{
    uint32_t *src = &_sidata;
    uint32_t *dst;
    for (dst = &_sdata; dst < &_edata; ) {
        *dst++ = *src++;
    }
    for (dst = &_sbss; dst < &_ebss; ) {
        *dst++ = 0u;
    }
    if (__libc_init_array != 0) {
        __libc_init_array();
    }
    (void)main();
    for (;;) { }
}

/* RP2350 IMAGE_DEF for the RISC-V variant. Identical layout to the ARM block
 * (see startup_m33.c) but the image_type flags select CPU=RISC-V. The word is
 * the M33 value 0x10210142 with only the CPU nibble [11:8] changed 0->1:
 *   tag=0x42 (IMAGE_TYPE), size_words=0x01, flags16=0x1121:
 *     [3:0]  image_type = 1 (EXE)
 *     [7:4]  security   = 2 (NS - bootrom does not enforce secure)
 *     [11:8] CPU        = 1 (RISC-V)   <-- M33 has 0 (ARM)
 *     [15:12]CHIP       = 1 (RP2350)
 *   0x00: PICOBIN_BLOCK_MARKER_START
 *   0x04: image_type item (EXE | RISC-V)
 *   0x08: LAST_ITEM
 *   0x0C: next-block offset
 *   0x10: PICOBIN_BLOCK_MARKER_END
 *
 * NOTE: the Hazard3/RISC-V target is NOT boot-validated - it is in no CI and
 * has not been booted on real RISC-V silicon; the RP2350 bootrom is the only
 * validator of this block. The bytes are byte-for-byte correct per the
 * picobin encoding above, but a real RISC-V boot test is still required.
 */
__attribute__((section(".boot_metadata"), used))
const uint32_t boot_image_def[5] = {
    0xFFFFDED3U,
    0x11210142U,             /* IMAGE_TYPE: tag=0x42 size=1 flags=0x1121 RISC-V EXE */
    0x000001FFU,             /* LAST item: tag=0xFF size_words=1            */
    0x00000000U,
    0xAB123579U
};

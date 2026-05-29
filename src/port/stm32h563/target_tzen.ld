/* Linker script for STM32H563 wolfIP NS application under wolfBoot
 * (TZEN=1, with wolfBoot acting as the Secure boot stub).
 *
 * Memory layout matches wolfBoot config/examples/stm32h5-tz.config:
 *   wolfBoot (Secure):    0x0C000000 .. 0x0C040000
 *   wolfBoot keyvault:    0x0C040000 .. 0x0C05C000
 *   wolfBoot NSC veneer:  0x0C05C000 .. 0x0C060000
 *   wolfBoot image hdr:   0x08060000 .. 0x08060400 (1024 B, prepended by sign)
 *   NS app vectors+text:  0x08060400 .. 0x080FFFFF (boot partition end)
 *
 * RAM: wolfBoot (patched hal_gtzc_init / hal_tz_sau_init) keeps SRAM1
 * secure for its own use and cedes SRAM2 + SRAM3 to NS:
 *   NS RAM: 0x20040000 .. 0x2009FFFF (384 KB, SRAM2 + SRAM3)
 * SRAM2 (0x20040000, 64 KB) is non-secure + UNPRIVILEGED; SRAM3
 * (0x20050000, 320 KB) is non-secure + PRIVILEGED. The .eth_buffers
 * section is placed first so the ETH DMA descriptors/buffers land in
 * SRAM2: the H5 ETH DMA master is unprivileged and can only reach the
 * unprivileged window. The privileged NS CPU uses the rest of RAM.
 *
 * The NS app runs in Non-Secure world; plain LDR/STR carry HNONSEC=1,
 * matching the H5 product-default NS attribution for the ETH peripheral
 * and DMA.
 */

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08060400, LENGTH = 0x0009FC00 /* 639 KB */
    RAM   (rwx) : ORIGIN = 0x20040000, LENGTH = 0x00060000 /* 384 KB */
}

_estack = ORIGIN(RAM) + LENGTH(RAM);
_sidata = LOADADDR(.data);

/* Heap and stack sizes. Smaller than the TZEN=0 build because the NS
 * RAM window is 384 KB (SRAM2+SRAM3) instead of 640 KB (full SRAM).
 * SP math is fine on a 16 KB stack for the bare TCP echo build; TLS
 * configurations should override these via EXTRA_LDFLAGS or revisit. */
_Min_Heap_Size = 0x8000;    /* 32KB heap */
_Min_Stack_Size = 0x4000;   /* 16KB stack */
_heap_limit = _estack - _Min_Stack_Size;

SECTIONS
{
    .isr_vector :
    {
        . = ALIGN(4);
        KEEP(*(.isr_vector))
        . = ALIGN(4);
    } > FLASH

    .text :
    {
        . = ALIGN(4);
        *(.text*)
        *(.rodata*)
        *(.ARM.extab* .gnu.linkonce.armextab.*)
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
        *(.glue_7)
        *(.glue_7t)
        *(.eh_frame)
        . = ALIGN(4);
    } > FLASH

    .preinit_array :
    {
        __preinit_array_start = .;
        KEEP(*(.preinit_array*))
        __preinit_array_end = .;
    } > FLASH

    .init_array :
    {
        __init_array_start = .;
        KEEP(*(.init_array*))
        __init_array_end = .;
    } > FLASH

    .fini_array :
    {
        __fini_array_start = .;
        KEEP(*(.fini_array*))
        __fini_array_end = .;
    } > FLASH

    /* ETH DMA arena: placed first in RAM (RAM ORIGIN = 0x20040000 =
     * SRAM2 base) so descriptors/buffers stay in the unprivileged SRAM2
     * window reachable by the unprivileged ETH DMA master. NOLOAD: no
     * FLASH load image, so LOADADDR(.data) below is unaffected. */
    .eth_buffers (NOLOAD) :
    {
        . = ALIGN(32);
        KEEP(*(.eth_buffers))
        . = ALIGN(32);
    } > RAM
    ASSERT(. <= 0x20050000, ".eth_buffers must fit within SRAM2 (0x20040000-0x2004FFFF)")

    .data :
    {
        . = ALIGN(4);
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > RAM AT > FLASH

    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > RAM

    /* Reserve minimum heap + stack space so the linker errors if RAM is full.
     * Heap starts just after BSS at 'end'/'_end'. Stack grows down from
     * _estack (top of RAM); _heap_limit = _estack - _Min_Stack_Size is the
     * enforced upper bound used by _sbrk(). */
    ._user_heap_stack (NOLOAD) :
    {
        . = ALIGN(8);
        PROVIDE ( end = . );
        PROVIDE ( _end = . );
        . = . + _Min_Heap_Size;
        . = . + _Min_Stack_Size;
        . = ALIGN(8);
    } > RAM
}

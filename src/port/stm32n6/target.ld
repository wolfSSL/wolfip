/* STM32N6 Linker Script — AXISRAM execution via JTAG
 *
 * Memory Map (all execution from SRAM, no flash):
 *   AXISRAM1: 512K @ 0x34000000 — code + rodata + data + bss + heap + stack
 *
 * Note: Only AXISRAM1 is guaranteed accessible after boot ROM.
 * Other regions (AXISRAM2-6) may need explicit RCC enable.
 * ETH DMA buffers are placed in AXISRAM2 at 0x341F8000,
 * with MPU marking them non-cacheable.
 */

MEMORY
{
    SRAM     (rwx) : ORIGIN = 0x34000000, LENGTH = 512K
    AXISRAM2 (rwx) : ORIGIN = 0x341F8000, LENGTH = 32K
}

_estack = ORIGIN(SRAM) + LENGTH(SRAM);
_sidata = LOADADDR(.data);

/* Heap and stack sizes */
_Min_Heap_Size = 0x4000;    /* 16KB heap */
_Min_Stack_Size = 0x4000;   /* 16KB stack */
_heap_limit = _estack - _Min_Stack_Size;

SECTIONS
{
    .isr_vector :
    {
        . = ALIGN(4);
        KEEP(*(.isr_vector))
        . = ALIGN(4);
    } > SRAM

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
    } > SRAM

    .preinit_array :
    {
        __preinit_array_start = .;
        KEEP(*(.preinit_array*))
        __preinit_array_end = .;
    } > SRAM

    .init_array :
    {
        __init_array_start = .;
        KEEP(*(.init_array*))
        __init_array_end = .;
    } > SRAM

    .fini_array :
    {
        __fini_array_start = .;
        KEEP(*(.fini_array*))
        __fini_array_end = .;
    } > SRAM

    .data :
    {
        . = ALIGN(4);
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > SRAM

    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > SRAM

    .eth_buffers (NOLOAD) :
    {
        . = ALIGN(32);
        _eth_start = .;
        *(.eth_buffers*)
        . = ALIGN(32);
        _eth_end = .;
    } > AXISRAM2

    ._user_heap_stack (NOLOAD) :
    {
        . = ALIGN(8);
        PROVIDE ( end = . );
        PROVIDE ( _end = . );
        . = . + _Min_Heap_Size;
        . = . + _Min_Stack_Size;
        . = ALIGN(8);
    } > SRAM
}

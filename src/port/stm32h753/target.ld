/* STM32H753ZI Linker Script
 *
 * Memory Map:
 *   FLASH: 1MB @ 0x08000000
 *   DTCM:  128KB @ 0x20000000 (fast, but NOT accessible by ETH DMA)
 *   D1 AXI-SRAM: 512KB @ 0x24000000 (accessible by ETH DMA)
 *   D2 SRAM1: 128KB @ 0x30000000 (accessible by ETH DMA, cache-coherent)
 *   D2 SRAM2: 128KB @ 0x30020000
 *   D2 SRAM3: 32KB @ 0x30040000
 *   D3 SRAM4: 64KB @ 0x38000000
 *
 * Note: Ethernet DMA cannot access DTCM (0x20000000).
 *       We use D1 AXI-SRAM for main RAM and place ETH buffers in D2 SRAM.
 */

MEMORY
{
    FLASH (rx)    : ORIGIN = 0x08000000, LENGTH = 1024K
    RAM   (rwx)   : ORIGIN = 0x24000000, LENGTH = 512K   /* D1 AXI-SRAM */
    SRAM2 (rwx)   : ORIGIN = 0x30000000, LENGTH = 128K   /* D2 SRAM1 for ETH DMA */
}

_estack = ORIGIN(RAM) + LENGTH(RAM);
_sidata = LOADADDR(.data);

/* Heap and stack sizes */
_Min_Heap_Size = 0x10000;   /* 64KB heap */
_Min_Stack_Size = 0x4000;   /* 16KB stack */

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

    /* Ethernet DMA buffers - must be in D2 SRAM for DMA access */
    .eth_buffers (NOLOAD) :
    {
        . = ALIGN(32);
        *(.eth_buffers)
        . = ALIGN(32);
    } > SRAM2

    /* Heap starts after BSS */
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

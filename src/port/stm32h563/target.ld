/* STM32H563ZI Linker Script
 *
 * Memory Map:
 *   FLASH: 2MB @ 0x08000000
 *   SRAM:  640KB @ 0x20000000 (contiguous SRAM1+SRAM2+SRAM3)
 *
 * Non-secure addresses (TrustZone disabled).
 *
 * The top 32KB of flash (4x 8KB sectors, 0x081F8000-0x08200000) are
 * carved out of the code region and reserved for the MQTT broker
 * persistence key/value store (see mqtt_broker_persist_flash.c, which
 * hard-codes KVF_REGION_BASE = 0x081F8000 and derives the region extent
 * from KVF_SECTOR_SIZE/KVF_BANK_SIZE - two 16KB banks - to match this
 * 32KB carve-out). The linker can never place code there, so an
 * erase/program of the KV region cannot corrupt the firmware image.
 */

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 2016K  /* 2048K - 32K KV store */
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 640K
}

_estack = ORIGIN(RAM) + LENGTH(RAM);
_sidata = LOADADDR(.data);

/* Heap and stack sizes */
_Min_Heap_Size = 0x10000;   /* 64KB heap */
_Min_Stack_Size = 0x8000;   /* 32KB stack (SP math needs headroom) */
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

    /* ETH DMA arena. TrustZone is disabled here so there is no privilege
     * constraint, but stm32_eth.c emits descriptors/buffers into the
     * named .eth_buffers section for all STM32H5 builds, so give it an
     * explicit home in RAM. */
    .eth_buffers (NOLOAD) :
    {
        . = ALIGN(32);
        KEEP(*(.eth_buffers))
        . = ALIGN(32);
    } > RAM

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

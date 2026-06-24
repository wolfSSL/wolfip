/* RP2350 Cortex-M33 linker script
 *
 * Memory map (RP2350 datasheet 2.2):
 *   XIP   : 16 MB window @ 0x10000000, mapped to QSPI flash (4 MB on Pico 2 W)
 *   SRAM  : 520 KB contiguous @ 0x20000000
 *
 * The RP2350 bootrom, for an Arm image, loads the initial MSP from
 * flash[0] and the reset vector from flash[4] - i.e. the Cortex-M
 * vector table MUST be at the image base (0x10000000). The IMAGE_DEF
 * block does NOT need to be first: the bootrom scans the first 4 KB
 * for its start marker, so we place it immediately after the vector
 * table. (Putting the block at the base instead makes the bootrom read
 * the marker words as SP/PC and jump into garbage - silent lockup.)
 */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x10000000, LENGTH = 4M
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 520K
}

_estack = ORIGIN(RAM) + LENGTH(RAM);
_sidata = LOADADDR(.data);

SECTIONS
{
    .isr_vector :
    {
        KEEP(*(.isr_vector))
    } > FLASH

    .boot_metadata :
    {
        KEEP(*(.boot_metadata))
    } > FLASH

    .text :
    {
        *(.text*)
        *(.rodata*)
        *(.ARM.extab* .gnu.linkonce.armextab.*)
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
        *(.glue_7)
        *(.glue_7t)
        *(.eh_frame)
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

    /* The CYW43439 firmware blob is read-only and large (~225 KB). Pin
     * it to a .cyw43_fw input section so users can pad and align it
     * independently of normal .rodata. */
    .cyw43_fw : ALIGN(256)
    {
        _scyw43_fw = .;
        KEEP(*(.cyw43_fw*))
        _ecyw43_fw = .;
    } > FLASH

    .data :
    {
        _sdata = .;
        *(.data*)
        _edata = .;
    } > RAM AT > FLASH

    .bss (NOLOAD) :
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        _ebss = .;
    } > RAM

    /* Heap grows up from end of bss; stack grows down from end of RAM.
     * _sbrk in syscalls.c enforces the boundary at _heap_limit. */
    _heap_start = _ebss;
    _heap_limit = ORIGIN(RAM) + LENGTH(RAM) - 0x4000;  /* 16 KB main stack */
}

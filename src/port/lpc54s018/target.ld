/* LPC54S018 Linker Script (SPIFI flash boot)
 * SPIFI Flash: 16MB at 0x10000000 (Winbond W25Q128JV, XIP)
 * SRAM: 160KB total on the J4M package:
 *   SRAM0: 64KB @ 0x20000000 (CPU + ENET DMA)
 *   SRAM1: 64KB @ 0x20010000 (CPU + ENET DMA)
 *   SRAM2: 32KB @ 0x20020000 (CPU + ENET DMA)
 *   SRAMX: 32KB @ 0x04000000 (code bus only, NOT DMA accessible)
 *
 * SPIFI flash is NOT DMA-accessible. All DMA buffers (Ethernet descriptors
 * and frame buffers) must be in SRAM at 0x20000000+.
 *
 * Image layout (matches wolfBoot HAL pattern):
 *   0x10000000: .isr_vector - Cortex-M4 vector table at start of flash
 *   0x100000xx: .text, .rodata
 *   0x20000000: .data (copied from flash), .bss
 */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x10000000, LENGTH = 16M
    SRAM0 (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
    SRAM1 (rwx) : ORIGIN = 0x20010000, LENGTH = 64K
    SRAM2 (rwx) : ORIGIN = 0x20020000, LENGTH = 32K
}

_estack = ORIGIN(SRAM0) + LENGTH(SRAM0);
_sidata = LOADADDR(.data);

SECTIONS
{
    /* Vector table at very start of flash (0x10000000).
     * Boot ROM reads:
     *   - 0x10000000: stack pointer
     *   - 0x10000004: reset handler
     *   - 0x1000001C: vector checksum (must make vectors[0..7] sum to 0)
     *   - 0x10000024: image type magic 0xEDDC94BD (in reserved slot, OK)
     *   - 0x10000028: boot header offset (0x160, in reserved slot)
     *   - 0x10000160: 25-word boot header (100 bytes)
     * fix_checksum.py writes the magic, header offset, header content, and
     * vector checksum into the binary post-build. */
    .isr_vector :
    {
        KEEP(*(.isr_vector))
        /* Vector table is 81 entries = 0x144 bytes. Boot header at 0x160
         * (written by fix_checksum.py). Pad to 0x1C4 to reserve that space. */
        . = 0x1C4;
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

    .data :
    {
        _sdata = .;
        *(.data*)
        _edata = .;
    } > SRAM0 AT > FLASH

    .bss (NOLOAD) :
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        _ebss = .;
    } > SRAM0

    /* Minimum stack: 2KB */
    ASSERT(_ebss + 2048 <= _estack,
           "ERROR: BSS too large, less than 2KB left for stack in SRAM0")
}

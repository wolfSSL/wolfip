/* Zynq-7000 (Cortex-A9) Linker Script - DDR layout
 *
 * Used when the app runs from DDR (cached code, much faster than the
 * uncached OCM layout) - e.g. loaded by wolfBoot or JTAG-dow'd after the
 * FSBL has trained DDR.
 *
 * Memory map:
 *   DDR : 0x10000000 .. 0x10FFFFFF   (16 MB window; matches wolfBoot's
 *                                      WOLFBOOT_LOAD_ADDRESS = 0x10000000)
 *   OCM : 0xFFFC0000 .. 0xFFFFFFFF   (still mapped; unused by this layout)
 *
 * The first instruction of the image (the reset vector at 0x10000000) is
 * `b _start` (.vectors leads the image), so a loader that jumps to the load
 * address - and wolfBoot's image format - both reach the entry. _start
 * reprograms VBAR to _vectors afterwards.
 */

OUTPUT_FORMAT("elf32-littlearm", "elf32-bigarm", "elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(_start)

MEMORY
{
    DDR (rwx)  : ORIGIN = 0x10000000, LENGTH = 0x01000000   /* 16 MB */
    OCM (rwx)  : ORIGIN = 0xFFFC0000, LENGTH = 0x00040000   /* still mapped */
}

_stack_top = 0x10FFF000;

PHDRS
{
    text PT_LOAD FLAGS(5);    /* RX */
    data PT_LOAD FLAGS(6);    /* RW */
}

SECTIONS
{
    /* .vectors leads the image so the word at 0x10000000 is `b _start`
     * (the reset vector doubles as the wolfBoot entry header). */
    .vectors :
    {
        . = ALIGN(32);          /* VBAR alignment requirement */
        KEEP(*(.vectors))
    } > DDR :text

    .text :
    {
        . = ALIGN(4);
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
    } > DDR :text

    .data :
    {
        . = ALIGN(4);
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > DDR :text

    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > DDR :text

    .page_tables (NOLOAD) :
    {
        . = ALIGN(16384);       /* TTBR0 wants 16 KB alignment */
        _page_tables_start = .;
        *(.page_tables)
        . = ALIGN(16384);
        _page_tables_end = .;
    } > DDR :text

    /* DMA buffers get their own 1 MB-aligned block so the MMU can map just
     * this range Normal-NC (the ARMv7 section granularity is 1 MB) without
     * making the .text block non-cacheable. NC is required for the GEM
     * rings - see mmu_armv7.c (HIGH-2). */
    .dma_buffers (NOLOAD) :
    {
        . = ALIGN(0x100000);
        _dma_buffers_start = .;
        *(.dma_buffers)
        . = ALIGN(64);
        _dma_buffers_end = .;
    } > DDR :text

    /DISCARD/ :
    {
        *(.note.*)
        *(.comment)
        *(.ARM.attributes)
        *(.eh_frame*)
    }
}

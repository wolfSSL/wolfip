/* Zynq-7000 (Cortex-A9) Linker Script - OCM-only layout
 *
 * Memory map (Zynq-7000 PS):
 *   DDR : 0x00000000 .. 0x3FFFFFFF (1 GB on ZC702 / Zynq-7020 typical)
 *   OCM : 0xFFFC0000 .. 0xFFFFFFFF (256 KB, high-mapped by SLCR.OCM_CFG)
 *
 * We keep everything in OCM by default for JTAG-iteration symmetry
 * with the ZCU102 port. The page tables alone take 16 KB (4096
 * section descriptors x 4 bytes) so we have less spare OCM than the
 * AArch64 builds; track sizes and spill to DDR when needed.
 *
 * Brought up on a ZC702 (Cortex-A9).
 */

OUTPUT_FORMAT("elf32-littlearm", "elf32-bigarm", "elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(_start)

MEMORY
{
    OCM (rwx)  : ORIGIN = 0xFFFC0000, LENGTH = 0x00040000
    DDR (rw)   : ORIGIN = 0x00010000, LENGTH = 0x10000000
}

_stack_top = 0xFFFFF000;

PHDRS
{
    text PT_LOAD FLAGS(5);    /* RX */
    data PT_LOAD FLAGS(6);    /* RW */
}

SECTIONS
{
    .boot_entry :
    {
        KEEP(*(.boot_entry))
    } > OCM :text

    .vectors :
    {
        . = ALIGN(32);          /* VBAR alignment requirement */
        KEEP(*(.vectors))
    } > OCM :text

    .text :
    {
        . = ALIGN(4);
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
    } > OCM :text

    .data :
    {
        . = ALIGN(4);
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > OCM :text

    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > OCM :text

    .page_tables (NOLOAD) :
    {
        . = ALIGN(16384);       /* TTBR0 wants 16 KB alignment */
        _page_tables_start = .;
        *(.page_tables)
        . = ALIGN(16384);
        _page_tables_end = .;
    } > OCM :text

    .dma_buffers (NOLOAD) :
    {
        . = ALIGN(64);
        _dma_buffers_start = .;
        *(.dma_buffers)
        . = ALIGN(64);
        _dma_buffers_end = .;
    } > OCM :text

    /DISCARD/ :
    {
        *(.note.*)
        *(.comment)
        *(.ARM.attributes)
        *(.eh_frame*)
    }
}

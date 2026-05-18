/* ZCU102 (Xilinx UltraScale+ MPSoC, Cortex-A53) Linker Script - DDR layout
 *
 * Used when the app is loaded by wolfBoot (or any loader that places
 * the signed image into DDR at a known LOAD_ADDRESS). FSBL + PMU FW +
 * BL31 are all running by the time control reaches us, so the DDR
 * controller is fully initialised and the DDR DAP 16-KB alias bug is
 * a non-issue (the loader writes via the AXI master path).
 *
 * Memory map:
 *   DDR : 0x10000000 .. 0x10FFFFFF   (16 MB; matches WOLFBOOT_LOAD_ADDRESS
 *                                     in wolfBoot's config/examples/zynqmp.config)
 *   OCM : 0xFFFC0000 .. 0xFFFFFFFF   (256 KB, still mapped Normal-WB
 *                                     executable by L2_PERIPH[511]; unused
 *                                     for this layout but left in MEMORY
 *                                     so MMU page-table addresses inside
 *                                     mmu.c remain valid)
 *
 * App layout in DDR (16 MB region @ 0x10000000):
 *   .vectors / .text / .rodata / .data / .bss / .page_tables / .dma_buffers
 *   stack grows down from _stack_top at the top of the region
 *
 * Stack top is set near the end of the DDR region with plenty of head
 * room (4 MB) below for .bss + page tables + DMA buffers. Increase
 * the LENGTH below if a larger heap or more DMA buffers are needed.
 */

OUTPUT_FORMAT("elf64-littleaarch64", "elf64-bigaarch64", "elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

MEMORY
{
    DDR (rwx)  : ORIGIN = 0x10000000, LENGTH = 0x01000000   /* 16 MB */
    OCM (rwx)  : ORIGIN = 0xFFFC0000, LENGTH = 0x00040000   /* still mapped */
}

/* Stack near the top of the DDR region. 16 MB - 4 KB gives the stack
 * a safe red zone. */
_stack_top = 0x10FFF000;
/* Dormant DMA carve-out markers (the cache-coherency path in gem.c is
 * the active mechanism). Set _dma_size to 0 so mmu.c does not insert
 * any Normal-NC blocks in the L2_DDR table for this layout. */
_dma_base  = 0x10E00000;
_dma_size  = 0;

PHDRS
{
    text PT_LOAD FLAGS(5);    /* RX */
    data PT_LOAD FLAGS(6);    /* RW */
}

SECTIONS
{
    /* First 4 bytes of the image must be a `b _start` so wolfBoot's
     * do_boot() (which branches to LOAD_ADDRESS, not the ELF entry)
     * lands on a valid instruction. */
    .boot_entry :
    {
        KEEP(*(.boot_entry))
    } > DDR :text

    .vectors :
    {
        . = ALIGN(2048);
        KEEP(*(.vectors))
    } > DDR :text

    .text :
    {
        . = ALIGN(8);
        *(.text*)
        *(.rodata*)
        . = ALIGN(8);
    } > DDR :text

    .data :
    {
        . = ALIGN(8);
        _sdata = .;
        *(.data*)
        . = ALIGN(8);
        _edata = .;
    } > DDR :text

    .bss (NOLOAD) :
    {
        . = ALIGN(8);
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(8);
        _ebss = .;
    } > DDR :text

    .page_tables (NOLOAD) :
    {
        . = ALIGN(4096);
        _page_tables_start = .;
        *(.page_tables)
        . = ALIGN(4096);
        _page_tables_end = .;
    } > DDR :text

    /* DMA buffers stay in the DDR region as plain Normal-WB cacheable
     * memory; gem.c maintains coherency with explicit DC CVAC / IVAC
     * ops at every BD hand-off. The L2_DDR table has a Normal-NC
     * carve-out for any 2 MB block overlapping this range but it is
     * currently dormant (cache_clean / cache_inval suffices), so no
     * special alignment beyond 64-byte cache lines is required. */
    .dma_buffers (NOLOAD) :
    {
        . = ALIGN(64);
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

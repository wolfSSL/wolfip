/* ZCU102 (Xilinx UltraScale+ MPSoC, Cortex-A53) Linker Script
 *
 * Memory map (current OCM-only layout):
 *   OCM     : 256 KB @ 0xFFFC0000 (everything lives here)
 *   DDR low : 2 GB  @ 0x00000000 (initialized by FSBL, currently unused
 *                                 by this app; reserved for future
 *                                 heap or larger ring buffers)
 *
 * App layout in OCM:
 *   0xFFFC0000          .vectors (2 KB-aligned)
 *   ...                 .text, .rodata, .data, .bss, .page_tables,
 *                       .dma_buffers (linker packs them in order)
 *   0x100000000         _stack_top (top of OCM, stack grows down)
 *
 * Why OCM-only:
 *   - JTAG iteration: psu_init alone (no PMU FW) doesn't reliably
 *     bring up DDR for mwr-force loads. OCM is independent of the
 *     DDR controller and always works.
 *   - SD boot: bootgen will emit a warning about OCM overlap with
 *     FSBL, but FSBL's jump-to-image happens after partition load,
 *     so the overlay is safe.
 *   - The 16-KB JTAG DAP alias bug at the low DDR window is avoided
 *     entirely.
 *
 * .dma_buffers stays inside OCM (Normal-WB per L2_PERIPH[511]); GEM
 * DMA coherency is handled with explicit DC CVAC / IVAC ops in gem.c
 * rather than via an MMU attribute carve-out.
 */

OUTPUT_FORMAT("elf64-littleaarch64", "elf64-bigaarch64", "elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

/* Single-region layout: everything in OCM. DDR and DMA region
 * definitions are kept as placeholders for a future layout that
 * spills .dma_buffers (and possibly .bss) into DDR once the JTAG
 * iteration path supports it. They are not referenced by any SECTION
 * in the current layout. */
MEMORY
{
    OCM (rwx)  : ORIGIN = 0xFFFC0000, LENGTH = 0x00040000
    DDR (rw)   : ORIGIN = 0x00010000, LENGTH = 0x001F0000
    DMA (rw)   : ORIGIN = 0x00200000, LENGTH = 0x00200000
}

/* Stack at top of OCM (we keep stack in OCM with the rest since
 * DDR-via-JTAG is unreliable without PMU FW). The 24 KB free area
 * above DMA buffers gives plenty of stack room for our app. */
_stack_top = 0x100000000;

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
        . = ALIGN(2048);
        KEEP(*(.vectors))
    } > OCM :text

    .text :
    {
        . = ALIGN(8);
        *(.text*)
        *(.rodata*)
        . = ALIGN(8);
    } > OCM :text

    .data :
    {
        . = ALIGN(8);
        _sdata = .;
        *(.data*)
        . = ALIGN(8);
        _edata = .;
    } > OCM :text

    /* BSS in OCM as well - DDR-via-JTAG isn't reliable without PMU
     * FW, so we keep all writeable state in OCM (256 KB total). */
    .bss (NOLOAD) :
    {
        . = ALIGN(8);
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(8);
        _ebss = .;
    } > OCM :text

    /* Page tables in OCM so MMU walker isn't dependent on DDR being
     * fully up (DDR-via-JTAG is unreliable without PMU FW; CPU
     * fetch from OCM is bulletproof). 12 KB total (3x4KB tables). */
    .page_tables (NOLOAD) :
    {
        . = ALIGN(4096);
        _page_tables_start = .;
        *(.page_tables)
        . = ALIGN(4096);
        _page_tables_end = .;
    } > OCM :text

    /* DMA buffers also in OCM - OCM is accessible to all AXI masters
     * including the GEM DMA. With everything in OCM there's no DDR
     * dependency for the basic bring-up. */
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

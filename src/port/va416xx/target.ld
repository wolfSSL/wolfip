/* VA416xx Linker Script
 * Flash: 256KB at 0x00000000
 * SRAM:  64KB total, split across two bus domains:
 *   RAM0: 32KB @ 0x1FFF8000 (code bus / D-Code bus) - CPU only
 *   RAM1: 32KB @ 0x20000000 (system bus / AHB)      - CPU + DMA
 *
 * Both regions are contiguous from the CPU's perspective (64KB total).
 * The Ethernet DMA is an AHB system bus master and can ONLY access
 * memory at 0x20000000+.  All DMA descriptors and buffers are placed
 * in the .dma_bss section which is forced to start at 0x20000000.
 */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 256K
    RAM   (rwx) : ORIGIN = 0x1FFF8000, LENGTH = 64K
}

_estack = ORIGIN(RAM) + LENGTH(RAM);
_sidata = LOADADDR(.data);

SECTIONS
{
    .isr_vector :
    {
        KEEP(*(.isr_vector))
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
    } > RAM AT > FLASH

    .bss (NOLOAD) :
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        _ebss = .;
    } > RAM

    /* Force location counter to system bus boundary (0x20000000).
     * DMA descriptors and buffers MUST be at 0x20000000+ for the
     * Ethernet DMA controller (AHB system bus master) to access them. */
    . = MAX(., 0x20000000);

    .dma_bss (NOLOAD) :
    {
        . = ALIGN(16);
        _sdma_bss = .;
        *(.dma_bss*)
        _edma_bss = .;
    } > RAM

    /* Verify DMA buffers are in system bus region */
    ASSERT(_sdma_bss >= 0x20000000, "ERROR: .dma_bss must be at 0x20000000+ for Ethernet DMA access")
}

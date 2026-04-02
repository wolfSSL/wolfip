/* LPC54S018 Linker Script
 * SPIFI Flash: 16MB at 0x10000000 (Winbond W25Q128JV, XIP)
 * SRAM:  192KB total across three AHB-accessible banks:
 *   SRAM0: 64KB @ 0x20000000 (CPU + ENET DMA)
 *   SRAM1: 64KB @ 0x20010000 (CPU + ENET DMA)
 *   SRAM2: 64KB @ 0x20020000 (CPU + ENET DMA)
 *   SRAMX: 32KB @ 0x04000000 (code bus only — NOT DMA accessible)
 *
 * SPIFI flash is NOT DMA-accessible. All DMA buffers (Ethernet descriptors
 * and frame buffers) must be in SRAM at 0x20000000+.
 *
 * Image layout:
 *   0x10000000: .spifi_config (512 bytes) — SPIFI boot ROM configuration
 *   0x10000200: .isr_vector — Cortex-M4 vector table
 *   0x100002xx: .text, .rodata
 *   0x20000000: .data (copied from flash), .bss
 */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x10000000, LENGTH = 16M
    SRAM0 (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
    SRAM1 (rwx) : ORIGIN = 0x20010000, LENGTH = 64K
    SRAM2 (rwx) : ORIGIN = 0x20020000, LENGTH = 64K
}

_estack = ORIGIN(SRAM0) + LENGTH(SRAM0);
_sidata = LOADADDR(.data);

SECTIONS
{
    /* SPIFI configuration block — must be at very start of flash.
     * The boot ROM reads this to configure the SPIFI controller. */
    .spifi_config :
    {
        KEEP(*(.spifi_config))
        . = 0x200;  /* Pad to 512 bytes */
    } > FLASH

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
    } > SRAM0 AT > FLASH

    .bss (NOLOAD) :
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        _ebss = .;
    } > SRAM0
}

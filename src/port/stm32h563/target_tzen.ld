/* Linker script for STM32H563 with TrustZone ENABLED (TZEN=1)
 *
 * When TrustZone is enabled:
 * - Secure flash alias: 0x0C000000
 * - Secure SRAM alias: 0x30000000
 * - We run in secure mode and configure GTZC to allow DMA access
 */

MEMORY
{
    /* Secure addresses (TrustZone enabled) */
    FLASH (rx)  : ORIGIN = 0x0C000000, LENGTH = 0x00200000
    RAM   (rwx) : ORIGIN = 0x30000000, LENGTH = 0x00090000  /* 576KB secure SRAM (SRAM1+SRAM2+part of SRAM3) */

    /* Non-secure SRAM for Ethernet DMA buffers (must be marked NS in GTZC) */
    /* Using end of SRAM3 at 0x20098000 - 0x200A0000 (32KB for ETH) */
    ETHMEM (rwx) : ORIGIN = 0x20098000, LENGTH = 0x00008000
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

    /* Ethernet DMA buffers - placed in non-secure memory region */
    .eth_buffers (NOLOAD) : ALIGN(32)
    {
        _eth_start = .;
        *(.eth_buffers*)
        . = ALIGN(32);
        _eth_end = .;
    } > ETHMEM
}

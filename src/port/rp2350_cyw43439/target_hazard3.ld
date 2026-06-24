/* RP2350 Hazard3 (RISC-V RV32IMACB) linker script
 *
 * Same RP2350 silicon as the M33 variant, same memory map; the
 * difference is the toolchain (riscv32-unknown-elf-*) and the entry
 * stub. The bootrom decides between ARM and RISC-V images via an
 * IMAGE_DEF block in .boot_metadata.
 */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x10000000, LENGTH = 4M
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 520K
}

_estack = ORIGIN(RAM) + LENGTH(RAM);
_sidata = LOADADDR(.data);

ENTRY(_start)

SECTIONS
{
    .boot_metadata :
    {
        KEEP(*(.boot_metadata))
        . = 0x100;
    } > FLASH

    .text :
    {
        KEEP(*(.text._start))
        *(.text*)
        *(.rodata*)
        *(.eh_frame)
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
        /* RISC-V global-pointer for gp-relative addressing relaxation;
         * place it near the middle of the small-data area. */
        . = ALIGN(4);
        PROVIDE(__global_pointer$ = . + 0x800);
        *(.sdata*)
        _edata = .;
    } > RAM AT > FLASH

    .bss (NOLOAD) :
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        _ebss = .;
    } > RAM

    _heap_start = _ebss;
    _heap_limit = ORIGIN(RAM) + LENGTH(RAM) - 0x4000;
}

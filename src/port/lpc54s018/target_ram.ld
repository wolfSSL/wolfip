/* LPC54S018 RAM-only Linker Script (debugger-loaded)
 *
 * SRAM0: 64KB @ 0x20000000 - code, data, BSS
 * SRAM1: 64KB @ 0x20010000 - BSS overflow
 * SRAM2: 32KB @ 0x20020000 - stack (separate to avoid BSS/stack overlap)
 */
MEMORY
{
    CODE (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
    STACK (rw) : ORIGIN = 0x20020000, LENGTH = 32K
}

_estack = ORIGIN(STACK) + LENGTH(STACK);

SECTIONS
{
    .isr_vector : { KEEP(*(.isr_vector)) } > CODE

    .text :
    {
        *(.text*)
        *(.rodata*)
        *(.ARM.extab* .gnu.linkonce.armextab.*)
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
        *(.glue_7)
        *(.glue_7t)
        *(.eh_frame)
    } > CODE

    .preinit_array :
    {
        __preinit_array_start = .;
        KEEP(*(.preinit_array*))
        __preinit_array_end = .;
    } > CODE

    .init_array :
    {
        __init_array_start = .;
        KEEP(*(.init_array*))
        __init_array_end = .;
    } > CODE

    .fini_array :
    {
        __fini_array_start = .;
        KEEP(*(.fini_array*))
        __fini_array_end = .;
    } > CODE

    .data :
    {
        _sidata = .;
        _sdata = .;
        *(.data*)
        _edata = .;
    } > CODE

    .bss (NOLOAD) :
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        _ebss = .;
    } > CODE

    ASSERT(_ebss <= ORIGIN(STACK),
           "ERROR: code+data+BSS exceeds 128KB, collides with stack")
}

/* startup.S
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfIP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 * AArch64 EL3 entry shared by the ZynqMP (Cortex-A53) and Versal
 * (Cortex-A72) boards. A loader (FSBL / PLM->BL31 / wolfBoot) drops us
 * at EL3 with caches/MMU off (we force them off again to be safe) and
 * branches to _start. The early UART breadcrumb offset differs per UART
 * IP (Cadence TX FIFO at 0x30, PL011 DR at 0x00); the board Makefile
 * passes it as UART_EARLY_TX_OFF.
 */
#ifndef UART_EARLY_TX_OFF
#define UART_EARLY_TX_OFF 0x30     /* Cadence TX FIFO; PL011 boards pass 0x00 */
#endif

    /* A loader (FSBL, wolfBoot, ...) that respects the ELF entry
     * point in the program header branches to _start directly. A
     * loader that simply branches to the first byte of the binary
     * (wolfBoot's do_boot path does this -- it uses LOAD_ADDRESS,
     * not the ELF entry) lands on this stub instead, which forwards
     * to _start. Linker scripts place this section first in the
     * output image so it always sits at offset 0 of the binary. */
    .section .boot_entry, "ax"
    .global _boot_entry
_boot_entry:
    b       _start

    .section .vectors, "ax"
    .align 11                  /* 2048 byte align required by VBAR */
    .global _vectors
_vectors:
    /* Current EL with SP0 (not used; we always use SPx). */
    .align 7
    b       el3_sync_trampoline /* sync */
    .align 7
    b       el3_irq_trampoline  /* IRQ */
    .align 7
    b       el3_irq_trampoline  /* FIQ - same handler (see note below) */
    .align 7
    b       el3_serror_trampoline /* SError */
    /* Current EL with SPx */
    .align 7
    b       el3_sync_trampoline /* sync */
    .align 7
    b       el3_irq_trampoline  /* IRQ */
    .align 7
    b       el3_irq_trampoline  /* FIQ - same handler; the GIC in
                                 * secure mode may deliver Group 0
                                 * interrupts via nFIQ depending on
                                 * GICC_CTLR.FIQEn. We route both to
                                 * the same trampoline so the C
                                 * dispatcher sees the INTID either
                                 * way. */
    .align 7
    b       el3_serror_trampoline /* SError */
    /* Lower EL using AArch64 (unused, we stay at EL3) */
    .align 7
    b       _hang
    .align 7
    b       _hang
    .align 7
    b       _hang
    .align 7
    b       _hang
    /* Lower EL using AArch32 (unused) */
    .align 7
    b       _hang
    .align 7
    b       _hang
    .align 7
    b       _hang
    .align 7
    b       _hang

    .section .text, "ax"
    .global _start
    .type _start, %function
_start:
    /* VERY FIRST INSTRUCTIONS - prove we're running. Write '@' to
     * UART0 TX FIFO. No register-bank-dependent ops here. */
    mov     x1, #0xFF000000
    mov     w2, #'@'
    str     w2, [x1, #UART_EARLY_TX_OFF]
    str     w2, [x1, #UART_EARLY_TX_OFF]
    str     w2, [x1, #UART_EARLY_TX_OFF]

    /* Make sure we are on A53-0. If FSBL released us as A53-1/2/3 by
     * accident, park them. */
    mrs     x0, mpidr_el1
    and     x0, x0, #0xff       /* Aff0 */
    cbnz    x0, _park_secondary

    /* Disable MMU + caches in case FSBL left them on. */
    mrs     x0, sctlr_el3
    bic     x0, x0, #(1 << 0)   /* M  - MMU off */
    bic     x0, x0, #(1 << 2)   /* C  - D-cache off */
    bic     x0, x0, #(1 << 12)  /* I  - I-cache off */
    msr     sctlr_el3, x0
    isb

    /* Allow FP/SIMD at EL3 (FSBL does this too, but be explicit). */
    msr     cptr_el3, xzr

    /* Force SPSel = 1 (use SP_ELx). The IRQ vector at offset 0x280
     * (Current EL with SPx) is what we wired el3_irq_trampoline to.
     * FSBL may have left SPSel at 0 (SP_EL0); fix it deterministically. */
    msr     spsel, #1

    /* Force SCR_EL3 to a known state. We run entirely at EL3 in
     * Secure world. The wolfBoot AArch64 startup explicitly sets the
     * IRQ + FIQ + EA routing bits even though the ARM ARM says they
     * only affect lower-EL interrupts; reusing that convention here
     * because empirically the A53 does not enter the IRQ exception
     * unless these are set (ISR_EL1.I went high but no exception
     * fired with these bits clear).
     *   bit 0  NS  = 0  (stay Secure)
     *   bit 1  IRQ = 1  (route IRQ to EL3)
     *   bit 2  FIQ = 1  (route FIQ to EL3)
     *   bit 3  EA  = 1  (route SError/abort to EL3)
     *   bit 10 RW  = 0  (no lower EL64; we never drop to lower EL) */
    mov     x0, #((1 << 1) | (1 << 2) | (1 << 3))
    msr     scr_el3, x0
    isb

    /* Vector base. */
    adrp    x0, _vectors
    add     x0, x0, :lo12:_vectors
    msr     vbar_el3, x0

    /* Stack pointer. After 'msr spsel, #1' this writes SP_EL3. */
    ldr     x0, =_stack_top
    mov     sp, x0

    /* Very early UART poke - one char before any C code, so even if a
     * later step hangs we know _start was reached. Writes '!' to
     * UART0 TX FIFO (0xFF000030). Assumes FSBL/psu_init already
     * configured UART0 baud. */
    mov     x1, #0xFF000000
    mov     w2, #'!'
    str     w2, [x1, #UART_EARLY_TX_OFF]

    /* Clear BSS. */
    ldr     x0, =_sbss
    ldr     x1, =_ebss
1:  cmp     x0, x1
    b.ge    2f
    str     xzr, [x0], #8
    b       1b
2:
    /* Breadcrumb: BSS cleared. */
    mov     x1, #0xFF000000
    mov     w2, #'B'
    str     w2, [x1, #UART_EARLY_TX_OFF]

    /* Bring up the MMU + caches. C function in mmu.c. */
    bl      mmu_enable

    /* Breadcrumb: MMU enabled. */
    mov     x1, #0xFF000000
    mov     w2, #'M'
    str     w2, [x1, #UART_EARLY_TX_OFF]

    /* Branch to main. */
    bl      main

    /* main() should not return. If it does, hang. */
    b       _hang

    .type _park_secondary, %function
_park_secondary:
    wfe
    b       _park_secondary

    .global _hang
    .type _hang, %function
_hang:
    b       _hang

/* ---------------------------------------------------------------------
 * IRQ trampoline. EL3 IRQ vector -> save GP regs, call C handler, restore.
 * Keeps the C handler clean and avoids __attribute__((interrupt)) tricks
 * which are not reliable on aarch64.
 * ------------------------------------------------------------------- */
    .type el3_irq_trampoline, %function
el3_irq_trampoline:
    /* Save full integer register file (x0-x30) plus SPSR_EL3/ELR_EL3.
     * Frame is 18 * 16 = 288 bytes (16-byte aligned). Callee-saved
     * x19-x28 must be preserved too: irq_dispatch is an ordinary C
     * function and may clobber them, while the interrupted code
     * almost certainly relies on them. */
    sub     sp, sp, #(18 * 16)
    stp     x0,  x1,  [sp, #(0  * 16)]
    stp     x2,  x3,  [sp, #(1  * 16)]
    stp     x4,  x5,  [sp, #(2  * 16)]
    stp     x6,  x7,  [sp, #(3  * 16)]
    stp     x8,  x9,  [sp, #(4  * 16)]
    stp     x10, x11, [sp, #(5  * 16)]
    stp     x12, x13, [sp, #(6  * 16)]
    stp     x14, x15, [sp, #(7  * 16)]
    stp     x16, x17, [sp, #(8  * 16)]
    stp     x18, x19, [sp, #(9  * 16)]
    stp     x20, x21, [sp, #(10 * 16)]
    stp     x22, x23, [sp, #(11 * 16)]
    stp     x24, x25, [sp, #(12 * 16)]
    stp     x26, x27, [sp, #(13 * 16)]
    stp     x28, x29, [sp, #(14 * 16)]
    str     x30,      [sp, #(15 * 16)]
    /* Snapshot exception return state in case irq_dispatch (or any
     * nested exception inside it) clobbers SPSR_EL3 / ELR_EL3. */
    mrs     x0,  spsr_el3
    mrs     x1,  elr_el3
    stp     x0,  x1,  [sp, #(16 * 16)]

    bl      irq_dispatch

    ldp     x0,  x1,  [sp, #(16 * 16)]
    msr     spsr_el3, x0
    msr     elr_el3,  x1
    ldp     x0,  x1,  [sp, #(0  * 16)]
    ldp     x2,  x3,  [sp, #(1  * 16)]
    ldp     x4,  x5,  [sp, #(2  * 16)]
    ldp     x6,  x7,  [sp, #(3  * 16)]
    ldp     x8,  x9,  [sp, #(4  * 16)]
    ldp     x10, x11, [sp, #(5  * 16)]
    ldp     x12, x13, [sp, #(6  * 16)]
    ldp     x14, x15, [sp, #(7  * 16)]
    ldp     x16, x17, [sp, #(8  * 16)]
    ldp     x18, x19, [sp, #(9  * 16)]
    ldp     x20, x21, [sp, #(10 * 16)]
    ldp     x22, x23, [sp, #(11 * 16)]
    ldp     x24, x25, [sp, #(12 * 16)]
    ldp     x26, x27, [sp, #(13 * 16)]
    ldp     x28, x29, [sp, #(14 * 16)]
    ldr     x30,      [sp, #(15 * 16)]
    add     sp, sp, #(18 * 16)
    eret

    .global irq_enable
    .type irq_enable, %function
irq_enable:
    msr     daifclr, #3        /* unmask IRQ (bit 1) + FIQ (bit 0) */
    ret

    .global irq_disable
    .type irq_disable, %function
irq_disable:
    msr     daifset, #2        /* mask IRQ */
    ret

/* ---------------------------------------------------------------------
 * Synchronous exception handler - print ESR_EL3 / ELR_EL3 / FAR_EL3
 * then hang. Anything that previously fell to _hang silently (alignment
 * fault, translation fault, undefined instruction) now produces a
 * UART dump.
 * ------------------------------------------------------------------- */
    .type el3_sync_trampoline, %function
el3_sync_trampoline:
    mrs     x0, esr_el3
    mrs     x1, elr_el3
    mrs     x2, far_el3
    mrs     x3, spsr_el3
    bl      exception_report
    b       _hang

    .type el3_serror_trampoline, %function
el3_serror_trampoline:
    mrs     x0, esr_el3
    mrs     x1, elr_el3
    mrs     x2, far_el3
    mrs     x3, spsr_el3
    mov     x4, #1              /* indicate SError to C */
    bl      exception_report_serror
    b       _hang

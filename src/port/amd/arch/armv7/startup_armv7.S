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
 * ARMv7-A entry for Cortex-A9 on Xilinx Zynq-7000. Stock Xilinx FSBL
 * configures DDR, clocks, MIO, then jumps to _start at the image
 * entry. We bring up the SVC-mode stack, install the exception
 * vector table, clear BSS, and call mmu_enable + main.
 *
 * Brought up on a ZC702 (Cortex-A9): the ARMv7 mode switching,
 * exception vectors and MMU enable below run on real hardware.
 */
    .arch armv7-a
    .syntax unified

    .section .vectors, "ax"
    .global _vectors
_vectors:
    b       _start                  /* 0x00: reset */
    b       _undef_handler          /* 0x04: undefined instruction */
    b       _svc_handler            /* 0x08: SVC */
    b       _prefetch_abort         /* 0x0C: prefetch abort */
    b       _data_abort             /* 0x10: data abort */
    nop                             /* 0x14: reserved */
    b       _irq_handler            /* 0x18: IRQ */
    b       _fiq_handler            /* 0x1C: FIQ */

    .section .text, "ax"
    .global _start
    .type _start, %function
    .arm
_start:
    /* Disable IRQ + FIQ until we have a stack. */
    cpsid   if

    /* Switch to SVC mode (FSBL may have left us in another mode). */
    cps     #0x13                   /* SVC mode */

    /* Set the SVC-mode stack. */
    ldr     sp, =_stack_top

    /* Install vector base address (VBAR). VBAR is implemented on
     * Cortex-A9 (CP15 c12 c0 0). */
    ldr     r0, =_vectors
    mcr     p15, 0, r0, c12, c0, 0  /* MCR VBAR, r0 */
    isb

    /* Disable MMU + caches in case FSBL left them on. SCTLR is CP15
     * c1 c0 0. */
    mrc     p15, 0, r0, c1, c0, 0
    bic     r0, r0, #(1 << 0)       /* M -- MMU disable */
    bic     r0, r0, #(1 << 2)       /* C -- D-cache disable */
    bic     r0, r0, #(1 << 12)      /* I -- I-cache disable */
    mcr     p15, 0, r0, c1, c0, 0
    isb

    /* Very-early UART poke - one char before any C code. The ZC702
     * routes the USB console to Cadence UART1; its TX FIFO is at
     * 0xE0001030. */
    ldr     r1, =0xE0001000
    mov     r2, #'!'
    str     r2, [r1, #0x30]

    /* Clear BSS. */
    ldr     r0, =_sbss
    ldr     r1, =_ebss
    mov     r2, #0
1:  cmp     r0, r1
    bge     2f
    str     r2, [r0], #4
    b       1b
2:

    /* Bring up the MMU + caches (C function in mmu.c). */
    bl      mmu_enable

    /* Breadcrumb: MMU enabled. */
    ldr     r1, =0xE0001000
    mov     r2, #'M'
    str     r2, [r1, #0x30]

    /* Call main(). */
    bl      main

    /* main() should not return. */
    b       _hang

    .global _hang
    .type _hang, %function
_hang:
    b       _hang

/* ----------------------------------------------------------------------
 * Exception handlers. The IRQ vector funnels into irq_dispatch (C),
 * mirroring the AArch64 trampoline in src/port/zcu102/startup.S. We
 * save AAPCS caller-saved + lr to make irq_dispatch safe to call.
 * -------------------------------------------------------------------- */
    .type _irq_handler, %function
_irq_handler:
    /* Adjust lr_irq for return-from-exception (LR points past). */
    sub     lr, lr, #4
    srsdb   sp!, #0x13              /* save lr_irq, spsr_irq to SVC stack */
    cpsid   if, #0x13               /* switch to SVC mode for the handler */
    push    {r0-r12, lr}
    bl      irq_dispatch
    pop     {r0-r12, lr}
    rfeia   sp!                     /* return from exception */

    .type _fiq_handler, %function
_fiq_handler:
    b       _hang                   /* FIQ unused */

    .type _undef_handler, %function
_undef_handler:
    b       _hang

    .type _svc_handler, %function
_svc_handler:
    b       _hang

    .type _prefetch_abort, %function
_prefetch_abort:
    b       _hang

    .type _data_abort, %function
_data_abort:
    b       _hang

    .global irq_enable
    .type irq_enable, %function
irq_enable:
    cpsie   if                      /* enable IRQ + FIQ */
    bx      lr

    .global irq_disable
    .type irq_disable, %function
irq_disable:
    cpsid   if
    bx      lr

/* exception_aarch64.c
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
 * AArch64 EL3 fault reporters, called from the startup.S vector
 * trampolines on a synchronous exception or SError/FIQ. ARMv7 ports
 * just hang on faults (no C reporter), so this file is AArch64-only.
 */
#include <stdint.h>
#include "uart.h"

/* Called from startup.S vector trampoline on synchronous/SError fault. */
void exception_report(uint64_t esr, uint64_t elr, uint64_t far, uint64_t spsr)
{
    uart_puts("\n\n*** EL3 SYNC EXCEPTION ***\n");
    uart_puts("  ESR_EL3 : "); uart_puthex((uint32_t)(esr >> 32));
    uart_puthex((uint32_t)esr); uart_puts("\n");
    uart_puts("  EC      = "); uart_puthex((uint32_t)((esr >> 26) & 0x3F));
    uart_puts(" (0x21=instr abort, 0x25=data abort, 0x24=alignment)\n");
    uart_puts("  ELR_EL3 : "); uart_puthex((uint32_t)(elr >> 32));
    uart_puthex((uint32_t)elr); uart_puts("\n");
    uart_puts("  FAR_EL3 : "); uart_puthex((uint32_t)(far >> 32));
    uart_puthex((uint32_t)far); uart_puts("\n");
    uart_puts("  SPSR_EL3: "); uart_puthex((uint32_t)spsr); uart_puts("\n");
}

void exception_report_serror(uint64_t esr, uint64_t elr, uint64_t far,
                             uint64_t spsr, uint64_t kind)
{
    (void)kind;
    uart_puts("\n\n*** EL3 SError / FIQ ***\n");
    uart_puts("  ESR_EL3 : "); uart_puthex((uint32_t)(esr >> 32));
    uart_puthex((uint32_t)esr); uart_puts("\n");
    uart_puts("  ELR_EL3 : "); uart_puthex((uint32_t)(elr >> 32));
    uart_puthex((uint32_t)elr); uart_puts("\n");
    uart_puts("  FAR_EL3 : "); uart_puthex((uint32_t)(far >> 32));
    uart_puthex((uint32_t)far); uart_puts("\n");
    uart_puts("  SPSR_EL3: "); uart_puthex((uint32_t)spsr); uart_puts("\n");
}

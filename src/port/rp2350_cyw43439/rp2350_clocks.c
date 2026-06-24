/* rp2350_clocks.c - RP2350 XOSC clock bring-up (12 MHz, no PLL_SYS)
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
 * After the RP2350 bootrom hands off to the user image, clk_sys and
 * clk_peri are both driven by the on-chip Ring Oscillator (~6 MHz +/-).
 * That is fine for ROM execution but produces unusable baud rates for
 * UART traffic.  This file pins the clock tree to the 12 MHz crystal
 * (XOSC) - it deliberately does NOT stand up PLL_SYS:
 *
 *   1. Enable the 12 MHz XOSC.
 *   2. Switch clk_ref from ROSC to XOSC.
 *   3. Switch clk_sys to clk_ref (= XOSC 12 MHz). PLL_SYS is left off:
 *      bringing it up via the glitchless mux can halt the core during
 *      first bring-up, and 12 MHz is plenty for this port. busy-loop
 *      timing assumes this 12 MHz clk_sys.
 *   4. Source clk_peri from XOSC (no divider) - that's the value the
 *      UART driver expects via the RP2350_CLK_PERI_HZ macro.
 */
#include <stdint.h>

#include "rp2350_clocks.h"

#define MMIO(addr)              (*(volatile uint32_t *)(addr))

/* CLOCKS controller (RP2350 datasheet 8.7). */
#define CLOCKS_BASE             0x40010000UL
#define CLK_REF_CTRL            (CLOCKS_BASE + 0x30U)
#define CLK_REF_SELECTED        (CLOCKS_BASE + 0x38U)
#define CLK_SYS_CTRL            (CLOCKS_BASE + 0x3CU)
#define CLK_SYS_SELECTED        (CLOCKS_BASE + 0x44U)
#define CLK_PERI_CTRL           (CLOCKS_BASE + 0x48U)

/* XOSC (RP2350 datasheet 8.5). */
#define XOSC_BASE               0x40048000UL
#define XOSC_CTRL               (XOSC_BASE + 0x00U)
#define XOSC_STATUS             (XOSC_BASE + 0x04U)
#define XOSC_STARTUP            (XOSC_BASE + 0x0CU)
#define XOSC_CTRL_ENABLE_FAB    (0xFABU << 12)
#define XOSC_CTRL_FREQ_1_15MHZ  (0xAA0U)
#define XOSC_STATUS_STABLE      (1U << 31)

/* PLL_SYS (RP2350 datasheet 8.6). */
#define PLL_SYS_BASE            0x40050000UL
#define PLL_CS                  (PLL_SYS_BASE + 0x00U)
#define PLL_PWR                 (PLL_SYS_BASE + 0x04U)
#define PLL_FBDIV_INT           (PLL_SYS_BASE + 0x08U)
#define PLL_PRIM                (PLL_SYS_BASE + 0x0CU)
#define PLL_CS_LOCK             (1U << 31)
#define PLL_PWR_PD              (1U << 0)
#define PLL_PWR_VCOPD           (1U << 5)
#define PLL_PWR_POSTDIVPD       (1U << 3)

/* RESETS (RP2350 datasheet 2.7). */
#define RESETS_BASE             0x40020000UL
#define RESETS_RESET            (RESETS_BASE + 0x00U)
#define RESETS_RESET_DONE       (RESETS_BASE + 0x08U)
#define RESETS_RESET_CLR        (RESETS_BASE + 0x3000U)
#define RESETS_BIT_PLL_SYS      (1U << 14)

/* Bounded spin on a register bit. Returns 1 if the masked bits matched
 * `want` before the timeout, 0 if it timed out. Every clock-bring-up
 * wait uses this so a mis-programmed XOSC / PLL / reset bit degrades to
 * a wrong-but-running clock (garbage UART) instead of a silent forever
 * hang - which is far easier to diagnose on a board with only a UART. */
static int wait_bit(uint32_t addr, uint32_t mask, uint32_t want)
{
    volatile uint32_t spins = 2000000U;
    while (spins-- != 0U) {
        if ((MMIO(addr) & mask) == want) {
            return 1;
        }
    }
    return 0;
}

/* clk_peri AUXSRC field (CLK_PERI_CTRL bits [7:5]).
 *   0 = clk_sys, 1 = pll_sys, 2 = pll_usb, 3 = rosc, 4 = xosc, ... */
#define CLK_PERI_AUXSRC_XOSC    (4U << 5)
#define CLK_PERI_ENABLE         (1U << 11)

/* First-bring-up clock policy: pin everything to the 12 MHz crystal.
 *
 * We do NOT stand up PLL_SYS: switching clk_sys onto the PLL is a
 * glitchless-mux op that HALTS the core if the PLL output isn't cleanly
 * present (dead CPU, no fault, no UART). But we DO move clk_sys onto
 * clk_ref = XOSC: that is the safe glitchless direction (XOSC is already
 * running) and it makes clk_sys a KNOWN 12 MHz. A known clk_sys matters
 * because the CYW43439 bring-up needs calibrated >250 ms delays, and
 * busy-loops only have a known duration if clk_sys is known. clk_peri
 * (UART/SPI) also runs off XOSC. 12 MHz gives 115200 at 0.16% error.
 */
void rp2350_clocks_init(void)
{
    /* Enable the 12 MHz crystal oscillator. */
    MMIO(XOSC_STARTUP) = 0xC4U;
    MMIO(XOSC_CTRL)    = XOSC_CTRL_ENABLE_FAB | XOSC_CTRL_FREQ_1_15MHZ;
    if (!wait_bit(XOSC_STATUS, XOSC_STATUS_STABLE, XOSC_STATUS_STABLE)) {
        return;  /* XOSC dead: leave clocks on the bootrom default. */
    }

    /* clk_ref <- XOSC (CLK_REF_CTRL SRC bits[1:0] = 2 = XOSC). */
    MMIO(CLK_REF_CTRL) = 2U;
    (void)wait_bit(CLK_REF_SELECTED, 0x4U, 0x4U);  /* XOSC = selected[2] */

    /* clk_sys <- clk_ref (CLK_SYS_CTRL SRC bit0 = 0). Safe: clk_ref is
     * the always-present glitchless source, no PLL stall risk. After
     * this clk_sys = 12 MHz, deterministic. */
    MMIO(CLK_SYS_CTRL) = 0U;
    (void)wait_bit(CLK_SYS_SELECTED, 0x1U, 0x1U);  /* clk_ref selected[0] */

    /* clk_peri <- XOSC (disable -> select -> enable per datasheet 8.1.4). */
    MMIO(CLK_PERI_CTRL) = 0U;
    MMIO(CLK_PERI_CTRL) = CLK_PERI_AUXSRC_XOSC;
    MMIO(CLK_PERI_CTRL) = CLK_PERI_AUXSRC_XOSC | CLK_PERI_ENABLE;
}

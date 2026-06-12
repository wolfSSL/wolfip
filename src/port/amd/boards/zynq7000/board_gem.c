/* board_gem.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Zynq-7000 GEM clock/reset hooks for the shared GEM core. The GEM0
 * reference clock and reset live in the SLCR (write-locked, different
 * layout from ZynqMP's CRL_APB). Also disables the PL310 L2 before MAC
 * config so the bare-metal L1-only cache ops give correct DMA coherency.
 */
#include <stdint.h>
#include "board.h"
#include "gem_port.h"
#include "timer.h"   /* delay_us / delay_ms - deterministic, counter-backed */

#define SLCR_GEM0_RST_BIT   (1u << 3)   /* GEM0 reset bit in GEM_RST_CTRL */

/* The FSBL enables the PL310 L2 cache, but this port's L1-only cache ops
 * only maintain the A9 L1 to the PoC. Once a GEM descriptor lands in L2,
 * the MAC's DMA writes to it are invisible to the CPU (stale L2 copy),
 * stalling RX after the first burst. Disable L2 so the PoC is main
 * memory. PL310 controller is at 0xF8F02000 on Zynq-7000. */
#define PL310_BASE          0xF8F02000u
#define PL310_CONTROL       (*(volatile uint32_t *)(PL310_BASE + 0x100))
#define PL310_CLEAN_INV_WAY (*(volatile uint32_t *)(PL310_BASE + 0x7FC))
#define PL310_CACHE_SYNC    (*(volatile uint32_t *)(PL310_BASE + 0x730))
#define PL310_ALL_WAYS      0x000000FFu   /* 8-way associative on Z-7000 */

static void pl310_l2_disable(void)
{
    if ((PL310_CONTROL & 1u) == 0u)
        return;                          /* already disabled */
    PL310_CLEAN_INV_WAY = PL310_ALL_WAYS;
    while (PL310_CLEAN_INV_WAY & PL310_ALL_WAYS)
        ;                                /* wait for clean+invalidate */
    PL310_CACHE_SYNC = 0u;
    PL310_CONTROL = 0u;                  /* disable L2 */
    __asm__ volatile ("dsb" ::: "memory");
}

void gem_soc_pre_init(void)
{
    pl310_l2_disable();
}

/* Configure SLCR.GEM0_CLK_CTRL for the negotiated link speed. With
 * SRCSEL=IO_PLL (~1000 MHz) and DIVISOR0=8 the base is 125 MHz, so
 * DIVISOR1 selects the line rate: 1 -> 125 MHz (1G), 5 -> 25 MHz (100M),
 * 50 -> 2.5 MHz (10M). The SLCR is write-protected; unlock it first. */
void gem_set_ref_clk(int speed_mbps)
{
    volatile uint32_t *unlock    = (volatile uint32_t *)SLCR_UNLOCK;
    volatile uint32_t *gem0_clk  = (volatile uint32_t *)SLCR_GEM0_CLK_CTRL;
    volatile uint32_t *gem0_rclk = (volatile uint32_t *)SLCR_GEM0_RCLK_CTRL;
    uint32_t div1;
    uint32_t val;

    switch (speed_mbps) {
    case 1000: div1 = 1;  break;
    case 100:  div1 = 5;  break;
    case 10:   div1 = 50; break;
    default:   div1 = 1;  break;
    }
    val = ((div1 & 0x3Fu) << 20)   /* DIVISOR1 */
        | ((8u   & 0x3Fu) << 8)    /* DIVISOR0 = 8 (IO_PLL/8 = 125 MHz) */
        | (0u << 4)                /* SRCSEL = IO_PLL */
        | (1u << 0);               /* CLKACT */
    *unlock = SLCR_UNLOCK_KEY;
    /* GEM0_RCLK_CTRL: source the RGMII RX clock from the PHY's RXC pin via
     * MIO (SRCSEL=0) and enable it (CLKACT=1), or the MAC receives
     * nothing. Matches the Xilinx ps7_init write. */
    *gem0_rclk = (*gem0_rclk & ~0x11u) | 0x01u;
    *gem0_clk = val;
    /* Re-lock the SLCR so stray writes can't scribble the clock/reset/
     * pinmux block for the rest of runtime. */
    *(volatile uint32_t *)SLCR_LOCK = 0x767Bu;
}

/* Pulse the GEM0 reset bit so the MAC starts from a known state, then
 * force the 125 MHz reference (amd_eth_init downshifts later if needed). */
void gem_clk_reset(void)
{
    volatile uint32_t *rst    = (volatile uint32_t *)SLCR_GEM_RST_CTRL;
    volatile uint32_t *unlock = (volatile uint32_t *)SLCR_UNLOCK;

    /* The SLCR is write-protected; the reset writes below are silently
     * dropped unless we unlock first. gem_set_ref_clk() re-locks it. */
    *unlock = SLCR_UNLOCK_KEY;
    *rst |= SLCR_GEM0_RST_BIT;
    delay_us(10);                /* hold the reset asserted */
    *rst &= ~SLCR_GEM0_RST_BIT;
    delay_ms(10);                /* settle after deassert (counter-backed) */

    gem_set_ref_clk(1000);
}

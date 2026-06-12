/* board_gem.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * ZCU102 (ZynqMP) GEM clock/reset hooks for the shared GEM core. The GEM3
 * reference clock and reset live in CRL_APB, which bare-metal may poke on
 * ZynqMP.
 */
#include <stdint.h>
#include "board.h"
#include "gem_port.h"
#include "timer.h"   /* delay_us / delay_ms - deterministic, counter-backed */

#define CRL_RST_GEM3        (1u << 3)   /* GEM3 reset bit in RST_LPD_IOU0 */

void gem_soc_pre_init(void)
{
    /* No SoC quirk needed before MAC config on ZynqMP. */
}

/* Configure CRL_APB.GEM3_REF_CTRL for the negotiated link speed. The MAC
 * sources TX_CLK to the PHY at this rate (RGMII): 125/25/2.5 MHz for
 * 1G/100M/10M. IOPLL = 1500 MHz, /12 base. Register layout (TRM):
 * CLKACT bit26, CLKACT_RX bit25, DIVISOR1 [21:16], DIVISOR0 [13:8],
 * SRCSEL [2:0]. */
void gem_set_ref_clk(int speed_mbps)
{
    volatile uint32_t *gem3_ref = (volatile uint32_t *)CRL_APB_GEM3_REF_CTRL;
    uint32_t div1;
    uint32_t val;

    switch (speed_mbps) {
    case 1000: div1 = 1;  break;
    case 100:  div1 = 5;  break;
    case 10:   div1 = 50; break;
    default:   div1 = 1;  break;
    }
    val = (1u << 26)               /* CLKACT */
        | (1u << 25)               /* CLKACT_RX */
        | ((div1 & 0x3Fu) << 16)   /* DIVISOR1 */
        | ((12u  & 0x3Fu) << 8)    /* DIVISOR0 */
        | (0u);                    /* SRCSEL = IOPLL */
    *gem3_ref = val;
}

/* Pulse the GEM3 reset bit so the MAC starts from a known state, then
 * force the 125 MHz reference (amd_eth_init downshifts later if the PHY
 * negotiates 100/10). */
void gem_clk_reset(void)
{
    volatile uint32_t *rst = (volatile uint32_t *)CRL_APB_RST_LPD_IOU0;

    *rst |= CRL_RST_GEM3;
    delay_us(10);                /* hold the reset asserted */
    *rst &= ~CRL_RST_GEM3;
    delay_ms(10);                /* settle after deassert (counter-backed) */

    gem_set_ref_clk(1000);
}

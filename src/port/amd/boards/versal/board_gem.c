/* board_gem.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Versal GEM clock/reset hooks for the shared GEM core. On Versal the GEM
 * clock/reset live in the CRL block, owned by the PMC/PLM: a direct APU
 * *write* to a protected CRL register (e.g. CRL.GEM0_REF_CTRL) stalls the
 * bus and hangs the core. The PLM has already brought GEM0 out of reset
 * and programmed its reference clock and MIO, so these hooks touch
 * nothing -- the per-MAC soft reset in amd_eth_init is enough.
 */
#include "gem_port.h"

void gem_soc_pre_init(void)
{
    /* No SoC quirk needed before MAC config. */
}

void gem_set_ref_clk(int speed_mbps)
{
    (void)speed_mbps;   /* clock owned by the PLM; nothing to do */
}

void gem_clk_reset(void)
{
    /* GEM0 is already out of reset and clocked by the PLM; do not poke
     * the protected CRL registers (would stall the bus). */
}

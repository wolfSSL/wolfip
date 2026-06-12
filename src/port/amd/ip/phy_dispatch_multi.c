/* phy_dispatch_multi.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * PHY dispatch for boards that may fit either a Marvell 88E1518 or a TI
 * DP83867 (Zynq-7000: the ZC702 fits the Marvell). Dispatch is on the
 * PHY vendor OUI in MII register 2 (id1).
 */
#include "gem_port.h"
#include "phy_dp83867.h"
#include "phy_marvell.h"
#include "uart.h"

int gem_phy_init(uint8_t phy_addr, uint16_t id1, int *speed, int *full_duplex)
{
    if ((id1 & 0xFFFFu) == MARVELL_PHY_ID1) {
        uart_puts("GEM: PHY is Marvell 88E1518\n");
        return marvell_88e1518_init(phy_addr, speed, full_duplex);
    }
    return dp83867_init(phy_addr, speed, full_duplex);
}

int gem_phy_link_status(uint8_t phy_addr)
{
    /* Generic clause-22 BMSR read works for both PHYs. */
    return dp83867_link_status(phy_addr);
}

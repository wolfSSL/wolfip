/* phy_dispatch_dp83867.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * PHY dispatch for boards that fit only the TI DP83867 (ZCU102, VMK180).
 */
#include "gem_port.h"
#include "phy_dp83867.h"

int gem_phy_init(uint8_t phy_addr, uint16_t id1, int *speed, int *full_duplex)
{
    (void)id1;
    return dp83867_init(phy_addr, speed, full_duplex);
}

int gem_phy_link_status(uint8_t phy_addr)
{
    return dp83867_link_status(phy_addr);
}

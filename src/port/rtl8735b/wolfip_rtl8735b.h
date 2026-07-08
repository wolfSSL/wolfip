/* wolfip_rtl8735b.h
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
 * wolfIP Ethernet driver for the RealTek RTL8735B (AmebaPro2). A thin adapter
 * binding wolfIP's poll/send callbacks onto the vendor FreeRTOS SDK mbed
 * Ethernet HAL, which owns the DMA rings and cache handling. Only compiles in
 * the AmebaPro2 SDK build; wolfIP owns the stack (the vendor lwIP glue is not
 * used).
 */
#ifndef WOLFIP_RTL8735B_H
#define WOLFIP_RTL8735B_H

#include <stdint.h>
#include "wolfip.h"

/* Bring up the MAC + FEPHY and install poll/send on ll. mac may be NULL to use
 * the chip efuse MAC (falling back to a locally-administered one if blank).
 * Returns 0 on success, negative on error. */
int rtl8735b_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);

/* 1 if link is up, 0 if down (updated by the MAC IRQ hook). */
int rtl8735b_eth_link_up(void);

/* Periodic FEPHY software-patch check; call ~every 10s while linked (no-op when
 * link is down). */
void rtl8735b_eth_phy_maintain(void);

#endif /* WOLFIP_RTL8735B_H */

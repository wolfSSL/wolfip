/* stm32h5_eth.h
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
 */
#ifndef WOLFIP_STM32H5_ETH_H
#define WOLFIP_STM32H5_ETH_H

#include <stdint.h>
#include "wolfip.h"

int stm32h5_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);
void stm32h5_eth_get_stats(uint32_t *polls, uint32_t *pkts);
uint32_t stm32h5_eth_get_rx_des3(void);
uint32_t stm32h5_eth_get_rx_des0(void);
uint32_t stm32h5_eth_get_rx_ring_addr(void);
uint32_t stm32h5_eth_get_dmacsr(void);
uint32_t stm32h5_eth_get_rx_tail(void);
uint32_t stm32h5_eth_get_macpfr(void);
uint32_t stm32h5_eth_get_mac_debug(void);
uint32_t stm32h5_eth_get_dma_debug(void);
uint32_t stm32h5_eth_get_rx_list_addr(void);
uint32_t stm32h5_eth_get_rx_ring_len(void);
uint32_t stm32h5_eth_get_rx_curr_desc(void);
uint32_t stm32h5_eth_read_desc_at_addr(uint32_t addr);
void stm32h5_eth_kick_rx(void);

#endif

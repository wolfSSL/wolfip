/* stm32_eth.h
 *
 * Common STM32H5/STM32H7 Ethernet driver interface.
 *
 * Copyright (C) 2024-2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 */
#ifndef WOLFIP_STM32_ETH_H
#define WOLFIP_STM32_ETH_H

#include <stdint.h>
#include "wolfip.h"

int stm32_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);
void stm32_eth_get_stats(uint32_t *polls, uint32_t *pkts);
uint32_t stm32_eth_get_rx_des3(void);
uint32_t stm32_eth_get_rx_des0(void);
uint32_t stm32_eth_get_rx_ring_addr(void);
uint32_t stm32_eth_get_dmacsr(void);
uint32_t stm32_eth_get_rx_tail(void);
void stm32_eth_kick_rx(void);

#endif /* WOLFIP_STM32_ETH_H */

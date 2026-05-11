/* stm32_eth.h
 *
 * Common STM32H5/STM32H7/STM32N6 Ethernet driver interface.
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
uint32_t stm32_eth_get_dmacsr(void);
#ifdef DEBUG_H5_ETH
uint32_t stm32_eth_get_tx_count(void);
uint32_t stm32_eth_get_tx_des3(uint32_t i);
uint32_t stm32_eth_get_mac_rx_frames(void);
uint32_t stm32_eth_get_mac_tx_frames(void);
uint32_t stm32_eth_get_mac_rx_errors(void);
#endif

#endif /* WOLFIP_STM32_ETH_H */

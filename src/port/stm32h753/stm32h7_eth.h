/* stm32h7_eth.h
 *
 * STM32H753ZI Ethernet driver header
 *
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 */
#ifndef STM32H7_ETH_H
#define STM32H7_ETH_H

#include <stdint.h>
#include "wolfip.h"

/**
 * Initialize the STM32H7 Ethernet MAC and PHY
 *
 * @param ll    Pointer to wolfIP link-layer device structure
 * @param mac   MAC address to use (NULL for auto-generated)
 * @return      PHY info on success (link status in bit 8), negative on error
 */
int stm32h7_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);

/**
 * Get Ethernet statistics
 */
void stm32h7_eth_get_stats(uint32_t *polls, uint32_t *pkts);

/**
 * Debug functions
 */
uint32_t stm32h7_eth_get_rx_des3(void);
uint32_t stm32h7_eth_get_rx_des0(void);
uint32_t stm32h7_eth_get_rx_ring_addr(void);
uint32_t stm32h7_eth_get_dmacsr(void);
uint32_t stm32h7_eth_get_rx_tail(void);
void stm32h7_eth_kick_rx(void);

#endif /* STM32H7_ETH_H */

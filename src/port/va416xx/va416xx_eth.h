/* va416xx_eth.h
 *
 * VA416xx Ethernet driver for wolfIP
 * Synopsys DesignWare GMAC with normal (legacy) descriptor format
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
#ifndef WOLFIP_VA416XX_ETH_H
#define WOLFIP_VA416XX_ETH_H

#include <stdint.h>
#include "wolfip.h"

int va416xx_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);
void va416xx_eth_get_stats(uint32_t *polls, uint32_t *pkts, uint32_t *tx_pkts,
                           uint32_t *tx_errs);
uint32_t va416xx_eth_get_dma_status(void);

#endif /* WOLFIP_VA416XX_ETH_H */

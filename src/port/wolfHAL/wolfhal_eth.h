/* wolfhal_eth.h
 *
 * Copyright (C) 2024-2026 wolfSSL Inc.
 *
 * Generic wolfHAL Ethernet port for wolfIP
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

/**
 * @file wolfhal_eth.h
 * @brief Generic wolfHAL Ethernet port for wolfIP
 *
 * This port bridges wolfIP's link-layer device interface to wolfHAL's
 * Ethernet MAC and PHY APIs. It works with any board that provides a
 * configured whal_Eth and whal_EthPhy — no platform-specific code needed.
 *
 * ## Quick Start
 *
 * @code
 * #include "wolfip.h"
 * #include "wolfhal_eth.h"
 * #include "board.h"
 *
 * int main(void)
 * {
 *     struct wolfIP *ipstack;
 *
 *     board_init();
 *
 *     struct wolfhal_eth_ctx eth_ctx = {
 *         .eth = &g_whalEth,
 *         .phy = &g_whalEthPhy,
 *     };
 *
 *     wolfIP_init_static(&ipstack);
 *     wolfhal_eth_init(wolfIP_getdev(ipstack), &eth_ctx);
 *     wolfIP_ipconfig_set(ipstack,
 *         atoip4("192.168.1.100"),
 *         atoip4("255.255.255.0"),
 *         atoip4("192.168.1.1"));
 *
 *     while (1) {
 *         wolfIP_poll(ipstack, board_get_tick());
 *     }
 * }
 * @endcode
 */

#ifndef WOLFIP_WOLFHAL_ETH_H
#define WOLFIP_WOLFHAL_ETH_H

#include <stdint.h>
#include "wolfip.h"
#include <wolfHAL/eth/eth.h>
#include <wolfHAL/eth_phy/eth_phy.h>

#ifdef __cplusplus
extern "C" {
#endif

struct wolfhal_eth_ctx {
    whal_Eth *eth;
    whal_EthPhy *phy;
};

/**
 * @brief Initialize the wolfHAL Ethernet port for wolfIP
 *
 * Queries the PHY for link state, starts the MAC with the negotiated
 * speed and duplex, and registers poll/send callbacks on the wolfIP
 * device.
 *
 * Prerequisites:
 * - board_init() (or equivalent) has already called whal_Eth_Init()
 *   and whal_EthPhy_Init() to set up the hardware.
 *
 * @param ll   Pointer to wolfIP low-level device (from wolfIP_getdev())
 * @param ctx  Caller-owned context with eth and phy already set
 *
 * @return 0 on success
 * @return -1 if any argument is NULL
 * @return -2 if PHY link state query fails
 * @return -3 if MAC start fails
 * @return -4 if PHY link did not come up within timeout
 */
int wolfhal_eth_init(struct wolfIP_ll_dev *ll, struct wolfhal_eth_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_WOLFHAL_ETH_H */

/* wolfhal_eth.c
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

#include "wolfhal_eth.h"
#include "board.h"
#include <string.h>

#ifndef WOLFHAL_ETH_LINK_TIMEOUT_MS
#define WOLFHAL_ETH_LINK_TIMEOUT_MS 5000
#endif

static int wolfhal_eth_poll(struct wolfIP_ll_dev *dev, void *buf, uint32_t len)
{
    struct wolfhal_eth_ctx *ctx = (struct wolfhal_eth_ctx *)dev->priv;
    size_t recv_len = (size_t)len;
    whal_Error err;

    err = whal_Eth_Recv(ctx->eth, buf, &recv_len);
    if (err == WHAL_ENOTREADY)
        return 0;
    if (err != WHAL_SUCCESS)
        return -1;

    return (int)recv_len;
}

static int wolfhal_eth_send(struct wolfIP_ll_dev *dev, void *buf, uint32_t len)
{
    struct wolfhal_eth_ctx *ctx = (struct wolfhal_eth_ctx *)dev->priv;
    whal_Error err;

    err = whal_Eth_Send(ctx->eth, buf, (size_t)len);
    if (err != WHAL_SUCCESS)
        return -1;

    return (int)len;
}

int wolfhal_eth_init(struct wolfIP_ll_dev *ll, struct wolfhal_eth_ctx *ctx)
{
    uint8_t link_up, speed, duplex;
    whal_Error err;
    uint32_t start;

    if (ll == NULL || ctx == NULL || ctx->eth == NULL || ctx->phy == NULL)
        return -1;

    /* Wait for PHY link to come up */
    link_up = 0;
    start = board_get_tick();
    do {
        err = whal_EthPhy_GetLinkState(ctx->phy, &link_up, &speed, &duplex);
        if (err != WHAL_SUCCESS)
            return -2;
        if (link_up)
            break;
    } while ((board_get_tick() - start) < WOLFHAL_ETH_LINK_TIMEOUT_MS);

    if (!link_up)
        return -4;

    /* Start the MAC with negotiated link parameters */
    err = whal_Eth_Start(ctx->eth, speed, duplex);
    if (err != WHAL_SUCCESS)
        return -3;

    /* Configure wolfIP device */
    memcpy(ll->mac, ctx->eth->macAddr, 6);
    strncpy(ll->ifname, "eth0", sizeof(ll->ifname) - 1);
    ll->ifname[sizeof(ll->ifname) - 1] = '\0';
    ll->poll = wolfhal_eth_poll;
    ll->send = wolfhal_eth_send;
    ll->priv = ctx;

    return 0;
}

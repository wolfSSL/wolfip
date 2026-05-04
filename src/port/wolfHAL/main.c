/* main.c
 *
 * Copyright (C) 2024-2026 wolfSSL Inc.
 *
 * Generic wolfHAL main for wolfIP — works with any wolfHAL board that
 * provides whal_Eth and whal_EthPhy.
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "wolfip.h"
#include "wolfhal_eth.h"
#include "board.h"

#ifndef WOLFIP_IP
#define WOLFIP_IP      "192.168.1.100"
#endif
#ifndef WOLFIP_NETMASK
#define WOLFIP_NETMASK "255.255.255.0"
#endif
#ifndef WOLFIP_GW
#define WOLFIP_GW      "192.168.1.1"
#endif

#define ECHO_PORT 7

static int listen_fd = -1;

static void echo_cb(int sockfd, uint16_t events, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    uint8_t buf[512];
    int ret;

    if ((events & CB_EVENT_CLOSED) && sockfd != listen_fd) {
        wolfIP_sock_close(s, sockfd);
        return;
    }

    if (events & CB_EVENT_READABLE) {
        if (sockfd == listen_fd) {
            wolfIP_sock_accept(s, listen_fd, NULL, NULL);
        } else {
            ret = wolfIP_sock_read(s, sockfd, buf, sizeof(buf));
            if (ret > 0)
                wolfIP_sock_write(s, sockfd, buf, ret);
            else if (ret == 0)
                wolfIP_sock_close(s, sockfd);
        }
    }
}

uint32_t wolfIP_getrandom(void)
{
    uint32_t val = 0;
    whal_Rng_Generate(&g_whalRng, &val, sizeof(val));
    return val;
}

uint64_t wolfip_get_time_ms(void)
{
    return (uint64_t)board_get_tick();
}

int main(void)
{
    struct wolfIP_ll_dev *ll;
    struct wolfIP_sockaddr_in addr;
    struct wolfIP *ipstack;
    struct wolfhal_eth_ctx eth_ctx;
    uint8_t up, speed, duplex;
    int ret;

    ret = board_init();
    if (ret != WHAL_SUCCESS) {
        printf("board_init failed\r\n");
        return 1;
    }

    eth_ctx.eth = &g_whalEth;
    eth_ctx.phy = &g_whalEthPhy;

    printf("\r\n=== wolfIP + wolfHAL ===\r\n");

    printf("Initializing wolfIP stack...\r\n");
    wolfIP_init_static(&ipstack);

    printf("Initializing Ethernet (waiting for link)...\r\n");
    ll = wolfIP_getdev(ipstack);
    ret = wolfhal_eth_init(ll, &eth_ctx);
    if (ret == -4) {
        printf("PHY link timeout\r\n");
        return 1;
    } else if (ret < 0) {
        printf("wolfhal_eth_init failed (%d)\r\n", ret);
        return 1;
    }

    ret = whal_EthPhy_GetLinkState(eth_ctx.phy, &up, &speed, &duplex);
    if (ret == WHAL_SUCCESS)
        printf("Link up: %d Mbps %s duplex\r\n", speed,
               duplex ? "full" : "half");
    else
        printf("Link up (could not read speed/duplex)\r\n");

    printf("Setting IP: %s\r\n", WOLFIP_IP);
    wolfIP_ipconfig_set(ipstack,
        atoip4(WOLFIP_IP),
        atoip4(WOLFIP_NETMASK),
        atoip4(WOLFIP_GW));

    printf("Starting TCP echo server on port %d...\r\n", ECHO_PORT);
    listen_fd = wolfIP_sock_socket(ipstack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    wolfIP_register_callback(ipstack, listen_fd, echo_cb, ipstack);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(ECHO_PORT);
    addr.sin_addr.s_addr = 0;
    wolfIP_sock_bind(ipstack, listen_fd,
                     (struct wolfIP_sockaddr *)&addr, sizeof(addr));
    wolfIP_sock_listen(ipstack, listen_fd, 1);

    printf("Ready.\r\n");

    for (;;) {
        wolfIP_poll(ipstack, board_get_tick());
    }

    return 0;
}

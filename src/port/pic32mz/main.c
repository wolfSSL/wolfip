/* main.c
 *
 * wolfIP PIC32MZ EF port: hardware TRNG self-test, DHCP, and a TCP echo /
 * throughput server over the LAN8740.
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
#include <xc.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "wolfip.h"
#include "board.h"
#include "clock_init.h"
#include "uart_console.h"
#include "timebase.h"
#include "rng_selftest.h"
#include "pic32mz_eth.h"

#define DHCP_TIMEOUT_MS     30000U      /* wait this long before static IP */

static struct wolfIP *IPStack;
static uint8_t app_buf[1024];

/* wolfIP entropy: a fast xorshift PRNG whose state is seeded once from the
 * on-board hardware TRNG (rng_getseed()) so the boot-time ISN/port/xid values
 * are not predictable across resets, then remixed with the CP0 cycle counter
 * each call. This is adequate for ISN/port/xid selection but is NOT
 * crypto-grade; use wolfCrypt's RNG (WOLFSSL_PIC32MZ_RNG, exercised by
 * rng_selftest()) directly for keys/nonces. */
uint32_t wolfIP_getrandom(void)
{
    static uint32_t s;

    if (s == 0)
        s = (rng_getseed() ^ _CP0_GET_COUNT()) | 1u;
    s ^= _CP0_GET_COUNT();
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    return s;
}

/* Unrecoverable bring-up failure on this bare-metal demo: park here and blink
 * the heartbeat LED so the fault is visible on the board. */
static void fatal_halt(void)
{
    for (;;) {
        LATHINV = LED_HEARTBEAT;
        delay_ms(200);
    }
}

static void print_ip(const char *label, ip4 ip)
{
    printf("%s%u.%u.%u.%u\r\n", label,
           (unsigned)((ip >> 24) & 0xFF), (unsigned)((ip >> 16) & 0xFF),
           (unsigned)((ip >> 8) & 0xFF), (unsigned)(ip & 0xFF));
}

#ifdef SPEED_TEST

/* Throughput service on port 9: discard incoming (RX test) and stream data
 * (TX test), measured together.
 *   RX: dd if=/dev/zero bs=1460 count=700 | nc <ip> 9
 *   TX: nc <ip> 9 </dev/null | pv >/dev/null                                */
#define APP_PORT        9
static int listen_fd = -1;
static int client_fd = -1;
static uint32_t rx_bytes, tx_bytes;
static uint64_t start_ms;

static void app_cb(int fd, uint16_t event, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    int ret;

    if ((fd == listen_fd) && (event & CB_EVENT_READABLE) && (client_fd == -1)) {
        client_fd = wolfIP_sock_accept(s, listen_fd, NULL, NULL);
        if (client_fd > 0) {
            wolfIP_register_callback(s, client_fd, app_cb, s);
            rx_bytes = 0;
            tx_bytes = 0;
            start_ms = millis();
        }
        return;
    }
    if (fd != client_fd)
        return;

    if (event & CB_EVENT_READABLE) {
        ret = wolfIP_sock_recvfrom(s, client_fd, app_buf, sizeof(app_buf),
                                   0, NULL, NULL);
        if (ret > 0)
            rx_bytes += (uint32_t)ret;
    }
    if (event & CB_EVENT_WRITABLE) {
        ret = wolfIP_sock_send(s, client_fd, app_buf, sizeof(app_buf), 0);
        if (ret > 0)
            tx_bytes += (uint32_t)ret;
    }
    if (event & CB_EVENT_CLOSED) {
        uint32_t ms = (uint32_t)(millis() - start_ms);
        if (ms == 0)
            ms = 1;
        printf("Speed: %lu ms RX %lu B (~%lu B/s) TX %lu B (~%lu B/s)\r\n",
               (unsigned long)ms, (unsigned long)rx_bytes,
               (unsigned long)((uint64_t)rx_bytes * 1000U / ms),
               (unsigned long)tx_bytes,
               (unsigned long)((uint64_t)tx_bytes * 1000U / ms));
        wolfIP_sock_close(s, client_fd);
        client_fd = -1;
    }
}

#else /* echo server on port 7 */

#define APP_PORT        7
static int listen_fd = -1;
static int client_fd = -1;

static void app_cb(int fd, uint16_t event, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    int ret;

    if ((fd == listen_fd) && (event & CB_EVENT_READABLE) && (client_fd == -1)) {
        client_fd = wolfIP_sock_accept(s, listen_fd, NULL, NULL);
        if (client_fd > 0)
            wolfIP_register_callback(s, client_fd, app_cb, s);
        return;
    }
    if (fd != client_fd)
        return;

    if (event & CB_EVENT_READABLE) {
        ret = wolfIP_sock_recvfrom(s, client_fd, app_buf, sizeof(app_buf),
                                   0, NULL, NULL);
        if (ret > 0)
            (void)wolfIP_sock_sendto(s, client_fd, app_buf, (uint32_t)ret,
                                     0, NULL, 0);
        else if (ret == 0)
            event |= CB_EVENT_CLOSED;
    }
    if (event & CB_EVENT_CLOSED) {
        wolfIP_sock_close(s, client_fd);
        client_fd = -1;
    }
}

#endif /* SPEED_TEST */

int main(void)
{
    struct wolfIP_ll_dev *ll;
    struct wolfIP_sockaddr_in addr;
    uint64_t now, next_beat = 0;
    uint32_t tick = 0;
    int eth_ret;
    int rc;
    int dhcp_done = 0;
    uint64_t dhcp_start = 0;

    clock_init();
    uart_init();
    ANSELHCLR = LED_MASK;
    TRISHCLR  = LED_MASK;
    LATHCLR   = LED_MASK;

    printf("\r\n=== wolfIP PIC32MZ EF port ===\r\n");
    printf("Device : PIC32MZ2048EFM144  SYSCLK %lu Hz\r\n",
           (unsigned long)SYS_CLK_FREQ);
    printf("Build  : %s %s\r\n", __DATE__, __TIME__);

    /* The hardware TRNG is the point of this port milestone: a failing
     * self-test is fatal rather than silently continuing into networking. */
    if (rng_selftest() != 0) {
        printf("  FATAL: RNG self-test failed - halting\r\n");
        fatal_halt();
    }

    wolfIP_init_static(&IPStack);
    ll = wolfIP_getdev(IPStack);
    printf("\r\nEthernet init (LAN8740 over RMII)...\r\n");
    eth_ret = pic32mz_eth_init(ll, NULL);
    if (eth_ret == -2)
        printf("  PHY link down at startup (check cable) - continuing\r\n");
    else if (eth_ret < 0) {
        /* Fatal PHY/MDIO/EMAC failure: ll is only partially initialized, so
         * do not proceed into DHCP/socket setup. */
        printf("  FATAL: eth init failed (%d) - halting\r\n", eth_ret);
        fatal_halt();
    }
    printf("  MAC %02X:%02X:%02X:%02X:%02X:%02X\r\n",
           ll->mac[0], ll->mac[1], ll->mac[2],
           ll->mac[3], ll->mac[4], ll->mac[5]);
#ifdef PIC32_ETH_TRACE
    pic32mz_eth_diag();
#endif

    (void)wolfIP_poll(IPStack, millis());       /* prime last_tick */
#ifdef DHCP
    printf("Starting DHCP...\r\n");
    (void)dhcp_client_init(IPStack);
    dhcp_start = millis();
#else
    wolfIP_ipconfig_set(IPStack, atoip4(WOLFIP_IP), atoip4(WOLFIP_NETMASK),
                        atoip4(WOLFIP_GW));
    print_ip("Static IP: ", atoip4(WOLFIP_IP));
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = 0;
    addr.sin_port = ee16(APP_PORT);
    listen_fd = wolfIP_sock_socket(IPStack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (listen_fd < 0) {
        printf("  FATAL: socket() failed (%d) - halting\r\n", listen_fd);
        fatal_halt();
    }
    wolfIP_register_callback(IPStack, listen_fd, app_cb, IPStack);
    rc = wolfIP_sock_bind(IPStack, listen_fd,
                          (struct wolfIP_sockaddr *)&addr, sizeof(addr));
    if (rc < 0) {
        printf("  FATAL: bind() failed (%d) - halting\r\n", rc);
        fatal_halt();
    }
    rc = wolfIP_sock_listen(IPStack, listen_fd, 1);
    if (rc < 0) {
        printf("  FATAL: listen() failed (%d) - halting\r\n", rc);
        fatal_halt();
    }
    printf("TCP service listening on port %d\r\n", APP_PORT);

    for (;;) {
        now = millis();
        (void)wolfIP_poll(IPStack, now);

#ifdef DHCP
        if (!dhcp_done) {
            ip4 ip = 0, nm = 0, gw = 0;
            if (dhcp_bound(IPStack)) {
                wolfIP_ipconfig_get(IPStack, &ip, &nm, &gw);
                print_ip("DHCP bound: ", ip);
                dhcp_done = 1;
            }
            else if ((now - dhcp_start) > DHCP_TIMEOUT_MS) {
                wolfIP_ipconfig_set(IPStack, atoip4(WOLFIP_IP),
                                    atoip4(WOLFIP_NETMASK), atoip4(WOLFIP_GW));
                print_ip("DHCP timeout, static IP: ", atoip4(WOLFIP_IP));
                dhcp_done = 1;
            }
        }
#endif

        if (now >= next_beat) {
            next_beat = now + 1000;
            tick++;
            LATHINV = LED_HEARTBEAT;
            if ((tick % 10u) == 0u) {
                uint32_t rx = 0, tx = 0;
                ip4 ip = 0, nm = 0, gw = 0;
                pic32mz_eth_stats(&rx, &tx);
                wolfIP_ipconfig_get(IPStack, &ip, &nm, &gw);
                printf("[t=%lus] rx=%lu tx=%lu ip=%u.%u.%u.%u\r\n",
                       (unsigned long)(now / 1000U),
                       (unsigned long)rx, (unsigned long)tx,
                       (unsigned)((ip >> 24) & 0xFF),
                       (unsigned)((ip >> 16) & 0xFF),
                       (unsigned)((ip >> 8) & 0xFF), (unsigned)(ip & 0xFF));
#ifdef PIC32_ETH_TRACE
                pic32mz_eth_diag();
#endif
            }
        }
    }
    /* not reached */
}

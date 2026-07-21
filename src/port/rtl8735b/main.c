/* main.c
 *
 * RTL8735B (AmebaPro2) wolfIP Echo Server / TLS Client demo.
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
 * Built inside the RealTek AmebaPro2 FreeRTOS SDK (replaces src/main.c). A
 * single FreeRTOS task owns the wolfIP stack: it brings up the RTL8735B MAC
 * via the mbed HAL glue, waits for link + DHCP, serves a TCP echo server, and
 * (when ENABLE_TLS_CLIENT is defined) runs a wolfSSL TLS client. Running the
 * whole stack in one task means no wolfIP locking is required.
 *
 * Build: configure with -DEXAMPLE=wolfip_eth (see wolfip_eth.cmake).
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "FreeRTOS.h"
#include "task.h"

#include "config.h"
#include "wolfip.h"
#include "wolfip_rtl8735b.h"

#ifdef ENABLE_TLS_CLIENT
#include "tls_client.h"
/* TLS target (DNS is not wired in, so use an IP). Override at build time with
 * -DTLS_TARGET_IP=... -DTLS_TARGET_HOST=... -DTLS_TARGET_PORT=..., or point at
 * a bench server, e.g. openssl s_server -tls1_3 -cert server-ecc.pem
 * -key ecc-key.pem -accept 11111 -www. */
#ifndef TLS_TARGET_IP
#define TLS_TARGET_IP    "142.250.189.174" /* placeholder: www.google.com */
#endif
#ifndef TLS_TARGET_HOST
#define TLS_TARGET_HOST  "www.google.com"
#endif
#ifndef TLS_TARGET_PORT
#define TLS_TARGET_PORT  443
#endif
#endif /* ENABLE_TLS_CLIENT */

/* SDK entry-point helpers (provided by the AmebaPro2 example project). The
 * stock setup() (WLAN/FTL bring-up) is intentionally not used: this is a
 * wired-Ethernet-only demo and does not need the Wi-Fi stack. */
extern void console_init(void);
extern void voe_t2ff_prealloc(void);

#ifndef ECHO_PORT
#define ECHO_PORT          7
#endif
#ifndef WOLFIP_TASK_STACK_WORDS
#define WOLFIP_TASK_STACK_WORDS  4096   /* words; generous for the TLS path */
#endif
#define WOLFIP_POLL_DELAY_MS     5
#define PHY_MAINTAIN_MS          10000

static struct wolfIP *IPStack;
static int listen_fd = -1;
static int client_fd = -1;
static uint8_t rx_buf[1536];

/* Monotonic milliseconds for wolfIP_poll()'s "now". */
static uint32_t now_ms(void)
{
    return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

/* Apply the static-IP fallback from config.h. */
static void use_static_ip(void)
{
    wolfIP_ipconfig_set(IPStack, atoip4(WOLFIP_IP), atoip4(WOLFIP_NETMASK),
                        atoip4(WOLFIP_GW));
    printf("Static IP %s\r\n", WOLFIP_IP);
}

/* TCP echo server: accept one client, echo everything it sends. */
static void echo_cb(int fd, uint16_t event, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    int ret;
    int sent;

    if ((fd == listen_fd) && (event & CB_EVENT_READABLE) && (client_fd == -1)) {
        int c = wolfIP_sock_accept(s, listen_fd, NULL, NULL);
        if (c > 0) {
            client_fd = c;   /* keep the -1 sentinel on a negative errno */
            wolfIP_register_callback(s, client_fd, echo_cb, s);
            printf("echo: client connected (fd=%d)\r\n", client_fd);
        }
        return;
    }

    if ((fd == client_fd) && (event & CB_EVENT_READABLE)) {
        /* Drain all buffered data this event (recvfrom < 0 => nothing left). */
        do {
            ret = wolfIP_sock_recvfrom(s, client_fd, rx_buf, sizeof(rx_buf), 0,
                                       NULL, NULL);
            if (ret > 0) {
                /* Demo echo: no TX backpressure buffering. If the TX buffer
                 * is full (EAGAIN) or the write is short, the excess is
                 * dropped; log it so the drop is visible instead of silent. */
                sent = wolfIP_sock_sendto(s, client_fd, rx_buf, (uint32_t)ret,
                                          0, NULL, 0);
                if (sent != ret)
                    printf("echo: TX drop (sent=%d of %d)\r\n", sent, ret);
            }
        } while (ret > 0);
        if (ret == 0) {
            wolfIP_sock_close(s, client_fd);
            client_fd = -1;
            printf("echo: client closed\r\n");
        }
    }

    if ((fd == client_fd) && (event & CB_EVENT_CLOSED)) {
        wolfIP_sock_close(s, client_fd);
        client_fd = -1;
        printf("echo: client closed\r\n");
    }
}

#ifdef ENABLE_TLS_CLIENT
static void tls_response_cb(const char *data, int len, void *ctx)
{
    (void)ctx;
    printf("TLS: received %d bytes\r\n", len);
    if (len > 0)
        printf("%.*s\r\n", len, data);
}

static void tls_debug_cb(const char *msg)
{
    printf("%s", msg);
}
#endif

static void wolfip_task(void *arg)
{
    struct wolfIP_ll_dev *ll;
    struct wolfIP_sockaddr_in addr;
    uint32_t last_phy_ms;
    int ret;
    (void)arg;

    printf("\r\nwolfIP RTL8735B demo starting\r\n");

    wolfIP_init_static(&IPStack);
    ll = wolfIP_getdev(IPStack);

    ret = rtl8735b_eth_init(ll, NULL);
    if (ret != 0) {
        printf("ERROR: rtl8735b_eth_init failed (%d)\r\n", ret);
        vTaskDelete(NULL);
        return;
    }
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\r\n",
           (unsigned)ll->mac[0], (unsigned)ll->mac[1], (unsigned)ll->mac[2],
           (unsigned)ll->mac[3], (unsigned)ll->mac[4], (unsigned)ll->mac[5]);

    /* Wait for PHY link (up to ~10s), polling the stack meanwhile. */
    printf("Waiting for Ethernet link...\r\n");
    {
        int i;
        for (i = 0; i < 2000 && !rtl8735b_eth_link_up(); i++) {
            (void)wolfIP_poll(IPStack, now_ms());
            vTaskDelay(pdMS_TO_TICKS(WOLFIP_POLL_DELAY_MS));
        }
    }
    printf(rtl8735b_eth_link_up() ? "Link up\r\n" : "Link still down; continuing\r\n");

#ifdef DHCP
    {
        uint32_t start = now_ms();
        if (dhcp_client_init(IPStack) >= 0) {
            printf("Waiting for DHCP...\r\n");
            while (!dhcp_bound(IPStack) && dhcp_client_is_running(IPStack)
                   && (now_ms() - start) <= 20000) {
                (void)wolfIP_poll(IPStack, now_ms());
                vTaskDelay(pdMS_TO_TICKS(WOLFIP_POLL_DELAY_MS));
            }
        }
        if (dhcp_bound(IPStack)) {
            ip4 ip = 0, nm = 0, gw = 0;
            char ipstr[16];
            wolfIP_ipconfig_get(IPStack, &ip, &nm, &gw);
            iptoa(ip, ipstr);
            printf("DHCP bound: ip=%s\r\n", ipstr);
        }
        else {
            printf("DHCP timeout; falling back to ");
            use_static_ip();
        }
    }
#else
    use_static_ip();
#endif

    /* TCP echo server. */
    listen_fd = wolfIP_sock_socket(IPStack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (listen_fd < 0) {
        printf("ERROR: echo server socket() failed (%d)\r\n", listen_fd);
    }
    else {
        wolfIP_register_callback(IPStack, listen_fd, echo_cb, IPStack);
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = ee16(ECHO_PORT);
        addr.sin_addr.s_addr = 0;
        (void)wolfIP_sock_bind(IPStack, listen_fd,
                               (struct wolfIP_sockaddr *)&addr, sizeof(addr));
        (void)wolfIP_sock_listen(IPStack, listen_fd, 1);
        printf("TCP echo server listening on port %d\r\n", ECHO_PORT);
    }

#ifdef ENABLE_TLS_CLIENT
    printf("Initializing TLS client...\r\n");
    if (tls_client_init(IPStack, tls_debug_cb) < 0)
        printf("ERROR: TLS client init failed\r\n");
    else
        tls_client_set_sni(TLS_TARGET_HOST);
#endif

    /* Main service loop. */
    last_phy_ms = now_ms();
#ifdef ENABLE_TLS_CLIENT
    {
        int tls_started = 0;
        int req_sent = 0;
        static const char http_req[] =
            "GET / HTTP/1.0\r\nHost: " TLS_TARGET_HOST "\r\n\r\n";
        for (;;) {
            (void)wolfIP_poll(IPStack, now_ms());
            if (!tls_started && rtl8735b_eth_link_up()) {
                printf("TLS: connecting to %s:%d\r\n",
                       TLS_TARGET_IP, TLS_TARGET_PORT);
                if (tls_client_connect(TLS_TARGET_IP, TLS_TARGET_PORT,
                                       tls_response_cb, NULL) == 0)
                    tls_started = 1;
            }
            (void)tls_client_poll();
            if (tls_started && !req_sent && tls_client_is_connected()) {
                /* Retry if the TX buffer is momentarily full (send <= 0). */
                if (tls_client_send(http_req, (int)(sizeof(http_req) - 1)) > 0) {
                    printf("TLS: handshake done; request sent\r\n");
                    req_sent = 1;
                }
            }
            if ((now_ms() - last_phy_ms) >= PHY_MAINTAIN_MS) {
                rtl8735b_eth_phy_maintain();
                last_phy_ms = now_ms();
            }
            vTaskDelay(pdMS_TO_TICKS(WOLFIP_POLL_DELAY_MS));
        }
    }
#else
    for (;;) {
        (void)wolfIP_poll(IPStack, now_ms());
        if ((now_ms() - last_phy_ms) >= PHY_MAINTAIN_MS) {
            rtl8735b_eth_phy_maintain();
            last_phy_ms = now_ms();
        }
        vTaskDelay(pdMS_TO_TICKS(WOLFIP_POLL_DELAY_MS));
    }
#endif
}

int main(void)
{
    console_init();
    voe_t2ff_prealloc();

    if (xTaskCreate(wolfip_task, "wolfip", WOLFIP_TASK_STACK_WORDS, NULL,
                    tskIDLE_PRIORITY + 4, NULL) != pdPASS) {
        printf("ERROR: failed to create wolfip task\r\n");
    }

    vTaskStartScheduler();
    while (1) {
    }
    return 0;
}

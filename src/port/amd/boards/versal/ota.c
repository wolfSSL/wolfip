/* ota.c
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
 * Network-delivered firmware update for the Versal wolfBoot + wolfIP demo,
 * HTTPS transport.
 *
 * The update server is authenticated with TLS 1.3 (ML-KEM hybrid key
 * exchange, mutual certificate authentication). "GET /version" names the
 * version on offer and "GET /firmware.bin" returns the signed and encrypted
 * image, which ota_store.c writes to the inactive QSPI slot before the board
 * resets. wolfBoot decrypts and verifies it on the next boot. An image booted
 * on probation is confirmed only once it has reached the server again.
 */
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include "wolfip.h"
#include "httpc.h"
#include "uart.h"
#include "timer.h"
#include "ota.h"
#include "ota_store.h"
#include "ota_certs.h"

#ifndef OTA_APP_VERSION
#define OTA_APP_VERSION 1
#endif
#ifndef OTA_SERVER_IP
#define OTA_SERVER_IP "10.0.4.24"
#endif
#ifndef OTA_SERVER_PORT
#define OTA_SERVER_PORT 4443
#endif
/* Name the server certificate must carry. */
#ifndef OTA_SERVER_NAME
#define OTA_SERVER_NAME "ota-server.local"
#endif
#ifndef OTA_TLS_GROUP
#define OTA_TLS_GROUP WOLFSSL_SECP384R1MLKEM1024
#endif
#ifndef OTA_IMG_MAX
#define OTA_IMG_MAX (4U * 1024U * 1024U)
#endif
#ifndef OTA_BUILD_EPOCH
#error "OTA_BUILD_EPOCH (build time, seconds since 1970) must be defined"
#endif

#define OTA_NET_TIMEOUT_MS      10000U
/* On probation: retry interval, and how long to keep trying before giving
 * up and resetting so that wolfBoot rolls back. */
#define OTA_CONFIRM_RETRY_MS    3000U
#define OTA_CONFIRM_TIMEOUT_MS  30000U

struct ota_conn {
    WOLFSSL *ssl;
    int fd;
    uint32_t rx_total;
};

static struct wolfIP *g_stack;
static WOLFSSL_CTX *g_ctx;
static int g_pending;
static int g_busy;
static int g_started;
static uint32_t g_t0;
static uint32_t g_next_confirm;

static uint8_t g_image[OTA_IMG_MAX] __attribute__((aligned(64)));

static uint32_t ota_ms(void)
{
    uint64_t ticks = timer_now();
    uint64_t freq = timer_freq();

    return (uint32_t)((ticks / freq) * 1000ULL +
        ((ticks % freq) * 1000ULL) / freq);
}

time_t ota_time(time_t *t)
{
    time_t now = (time_t)OTA_BUILD_EPOCH + (time_t)(timer_now() / timer_freq());

    if (t != NULL)
        *t = now;
    return now;
}

static void net_poll(void)
{
    (void)wolfIP_poll(g_stack, ota_ms());
}

static int tls_init(void)
{
    if (g_ctx != NULL)
        return 0;
    if (wolfSSL_Init() != WOLFSSL_SUCCESS)
        return -1;
    g_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (g_ctx == NULL)
        return -1;
    if (wolfSSL_CTX_load_verify_buffer(g_ctx, ca_cert_der,
                sizeof(ca_cert_der), WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ||
            wolfSSL_CTX_use_certificate_buffer(g_ctx, device_cert_der,
                sizeof(device_cert_der), WOLFSSL_FILETYPE_ASN1)
                != WOLFSSL_SUCCESS ||
            wolfSSL_CTX_use_PrivateKey_buffer(g_ctx, device_key_der,
                sizeof(device_key_der), WOLFSSL_FILETYPE_ASN1)
                != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(g_ctx);
        g_ctx = NULL;
        return -1;
    }
    wolfSSL_CTX_set_verify(g_ctx, WOLFSSL_VERIFY_PEER, NULL);
    wolfSSL_SetIO_wolfIP_CTX(g_ctx, g_stack);
    return 0;
}

static void conn_close(struct ota_conn *c)
{
    uint32_t t0;

    if (c->ssl != NULL) {
        (void)wolfSSL_shutdown(c->ssl);
        wolfSSL_CleanupIO_wolfIP(c->ssl);
        wolfSSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->fd >= 0) {
        (void)wolfIP_sock_close(g_stack, c->fd);
        c->fd = -1;
    }
    /* Let the close_notify and FIN leave. */
    t0 = ota_ms();
    while ((ota_ms() - t0) < 20U)
        net_poll();
}

static int conn_open(struct ota_conn *c)
{
    struct wolfIP_sockaddr_in addr;
    const char *name;
    int group = OTA_TLS_GROUP;
    uint32_t t0;
    int ret;
    int err;

    c->ssl = NULL;
    c->rx_total = 0;
    if (tls_init() != 0) {
        uart_puts("OTA: TLS setup failed\n");
        c->fd = -1;
        return -1;
    }
    c->fd = wolfIP_sock_socket(g_stack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (c->fd < 0) {
        uart_puts("OTA: no free TCP socket\n");
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(OTA_SERVER_PORT);
    addr.sin_addr.s_addr = ee32(atoip4(OTA_SERVER_IP));
    t0 = ota_ms();
    for (;;) {
        ret = wolfIP_sock_connect(g_stack, c->fd,
            (struct wolfIP_sockaddr *)&addr, sizeof(addr));
        if (ret >= 0)
            break;
        if (ret != -WOLFIP_EAGAIN || (ota_ms() - t0) > OTA_NET_TIMEOUT_MS) {
            uart_puts("OTA: cannot connect to " OTA_SERVER_IP "\n");
            conn_close(c);
            return -1;
        }
        net_poll();
    }

    ret = 1;
    c->ssl = wolfSSL_new(g_ctx);
    if (c->ssl != NULL) {
        ret = 2;
        if (wolfSSL_set_groups(c->ssl, &group, 1) == WOLFSSL_SUCCESS) {
            ret = 3;
            err = wolfSSL_UseKeyShare(c->ssl, (word16)group);
            if (err == WOLFSSL_SUCCESS) {
                ret = 4;
                if (wolfSSL_check_domain_name(c->ssl, OTA_SERVER_NAME)
                        == WOLFSSL_SUCCESS) {
                    ret = 5;
                    if (wolfSSL_SetIO_wolfIP(c->ssl, c->fd) == 0)
                        ret = 0;
                }
            }
        }
    }
    if (ret != 0) {
        uart_puts("OTA: TLS session setup failed at step ");
        uart_putdec((uint32_t)ret);
        uart_puts("\n");
        conn_close(c);
        return -1;
    }
    t0 = ota_ms();
    for (;;) {
        ret = wolfSSL_connect(c->ssl);
        if (ret == WOLFSSL_SUCCESS)
            break;
        err = wolfSSL_get_error(c->ssl, ret);
        if ((err != WOLFSSL_ERROR_WANT_READ &&
                err != WOLFSSL_ERROR_WANT_WRITE) ||
                (ota_ms() - t0) > OTA_NET_TIMEOUT_MS) {
            uart_puts("OTA: TLS handshake failed, error -");
            uart_putdec((uint32_t)(-err));
            uart_puts("\n");
            conn_close(c);
            return -1;
        }
        net_poll();
    }
    name = wolfSSL_get_curve_name(c->ssl);
    uart_puts("OTA: TLS 1.3 "); uart_puts(wolfSSL_get_cipher(c->ssl));
    uart_puts(", key exchange "); uart_puts(name != NULL ? name : "?");
    uart_puts(", "); uart_putdec(ota_ms() - t0);
    uart_puts(" ms, server verified as " OTA_SERVER_NAME "\n");
    return 0;
}

static int conn_send(void *ctx, const uint8_t *buf, uint32_t len)
{
    struct ota_conn *c = (struct ota_conn *)ctx;
    uint32_t t0 = ota_ms();
    int ret;
    int err;

    for (;;) {
        ret = wolfSSL_write(c->ssl, buf, (int)len);
        if (ret == (int)len)
            return 0;
        err = wolfSSL_get_error(c->ssl, ret);
        if ((err != WOLFSSL_ERROR_WANT_READ &&
                err != WOLFSSL_ERROR_WANT_WRITE) ||
                (ota_ms() - t0) > OTA_NET_TIMEOUT_MS)
            return -1;
        net_poll();
    }
}

static int conn_recv(void *ctx, uint8_t *buf, uint32_t len)
{
    struct ota_conn *c = (struct ota_conn *)ctx;
    uint32_t t0 = ota_ms();
    int ret;
    int err;

    if (len > 16384U)
        len = 16384U;
    for (;;) {
        ret = wolfSSL_read(c->ssl, buf, (int)len);
        if (ret > 0) {
            /* One dot per 64 KB so a large download shows progress. */
            if ((c->rx_total >> 16) != ((c->rx_total + (uint32_t)ret) >> 16))
                uart_putc('.');
            c->rx_total += (uint32_t)ret;
            return ret;
        }
        err = wolfSSL_get_error(c->ssl, ret);
        if (err == WOLFSSL_ERROR_ZERO_RETURN)
            return 0;
        if ((err != WOLFSSL_ERROR_WANT_READ &&
                err != WOLFSSL_ERROR_WANT_WRITE) ||
                (ota_ms() - t0) > OTA_NET_TIMEOUT_MS)
            return -1;
        net_poll();
    }
}

/* One GET over its own TLS connection. Returns 0 on a 200 response. */
static int https_get(const char *path, uint8_t *body, uint32_t body_max,
    uint32_t *body_len)
{
    struct ota_conn c;
    struct httpc_io io;
    int ret;

    if (conn_open(&c) != 0)
        return -1;
    io.send = conn_send;
    io.recv = conn_recv;
    io.ctx = &c;
    ret = httpc_get(&io, OTA_SERVER_NAME, path, body, body_max, body_len);
    if (c.rx_total >= 65536U)
        uart_puts("\n");
    conn_close(&c);
    if (ret != 200) {
        uart_puts("OTA: GET "); uart_puts(path); uart_puts(" failed: ");
        if (ret < 0) {
            uart_puts("-"); uart_putdec((uint32_t)(-ret));
        }
        else {
            uart_putdec((uint32_t)ret);
        }
        uart_puts("\n");
        return -1;
    }
    return 0;
}

static int fetch_version(uint32_t *version)
{
    uint8_t txt[16];
    uint32_t len = 0;
    uint32_t v = 0;
    uint32_t i;
    uint32_t digits;

    if (https_get("/version", txt, sizeof(txt), &len) != 0)
        return -1;
    for (i = 0; i < len && txt[i] >= '0' && txt[i] <= '9'; i++) {
        uint32_t d = (uint32_t)(txt[i] - '0');
        if (v > (0xFFFFFFFFU - d) / 10U)
            break;
        v = v * 10U + d;
    }
    digits = i;
    while (i < len && (txt[i] == '\r' || txt[i] == '\n' || txt[i] == ' '))
        i++;
    if (digits == 0 || i != len) {
        uart_puts("OTA: bad /version reply\n");
        return -1;
    }
    *version = v;
    return 0;
}

static void update_check(void)
{
    uint32_t version = 0;
    uint32_t len = 0;

    uart_puts("OTA: checking " OTA_SERVER_IP " for an update\n");
    if (fetch_version(&version) != 0)
        return;
    uart_puts("OTA: server offers version "); uart_putdec(version);
    uart_puts(", running version "); uart_putdec(OTA_APP_VERSION);
    uart_puts("\n");
    if (version <= OTA_APP_VERSION) {
        uart_puts("OTA: already up to date\n");
        return;
    }
    uart_puts("OTA: downloading /firmware.bin\n");
    if (https_get("/firmware.bin", g_image, sizeof(g_image), &len) != 0)
        return;
    if (ota_store_write(g_image, len) != 0) {
        uart_puts("OTA: keeping current image\n");
        return;
    }
    uart_puts("OTA: download complete - resetting to apply update\n\n");
    ota_system_reset();
}

static int ip_ready(void)
{
    ip4 ip = 0;
    ip4 mask = 0;
    ip4 gw = 0;

    wolfIP_ipconfig_get(g_stack, &ip, &mask, &gw);
    return ip != 0;
}

int ota_trigger(struct wolfIP *stack, uint32_t server_ip_be,
    const char *filename)
{
    (void)stack;
    (void)server_ip_be;
    (void)filename;
    if (g_pending || g_busy)
        return -1;
    g_pending = 1;
    return 0;
}

void ota_poll(struct wolfIP *stack, uint32_t now_ms)
{
    uint32_t version = 0;

    g_stack = stack;
    ota_store_poll(now_ms);
    if (!g_started) {
        g_started = 1;
        g_t0 = now_ms;
        g_next_confirm = now_ms;
    }

    if (ota_store_on_probation()) {
        if (ip_ready() && (int32_t)(now_ms - g_next_confirm) >= 0) {
            g_busy = 1;
            uart_puts("OTA: on probation, contacting " OTA_SERVER_IP "\n");
            if (fetch_version(&version) == 0)
                ota_store_confirm();
            g_busy = 0;
            now_ms = ota_ms();
            g_next_confirm = now_ms + OTA_CONFIRM_RETRY_MS;
        }
        if (ota_store_on_probation() &&
                (now_ms - g_t0) > OTA_CONFIRM_TIMEOUT_MS) {
            uart_puts("OTA: update server not reached, not confirming\n");
            ota_system_reset();
        }
        return;
    }

    if (g_pending) {
        g_pending = 0;
        g_busy = 1;
        update_check();
        g_busy = 0;
    }
}

int ota_in_progress(void)
{
    return g_pending || g_busy;
}

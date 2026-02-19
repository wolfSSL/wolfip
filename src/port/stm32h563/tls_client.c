/* tls_client.c
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

#include "tls_client.h"
#include "wolfip.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <string.h>

/* Configuration */
#ifndef TLS_CLIENT_BUF_SIZE
#define TLS_CLIENT_BUF_SIZE 2048
#endif

/* Client state */
typedef enum {
    TLS_CLIENT_STATE_IDLE = 0,
    TLS_CLIENT_STATE_DNS_LOOKUP,
    TLS_CLIENT_STATE_CONNECTING,
    TLS_CLIENT_STATE_HANDSHAKE,
    TLS_CLIENT_STATE_CONNECTED,
    TLS_CLIENT_STATE_DONE,
    TLS_CLIENT_STATE_ERROR
} tls_client_state_t;

/* Client context */
static struct {
    struct wolfIP *stack;
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    int fd;
    tls_client_state_t state;
    tls_client_debug_cb debug_cb;
    tls_client_response_cb response_cb;
    void *user_ctx;
    uint8_t rx_buf[TLS_CLIENT_BUF_SIZE];
    ip4 server_ip;
    uint16_t server_port;
    int got_response;
} client;

/* External functions from wolfssl_io.c */
extern int wolfSSL_SetIO_wolfIP_CTX(WOLFSSL_CTX *ctx, struct wolfIP *s);
extern int wolfSSL_SetIO_wolfIP(WOLFSSL *ssl, int fd);

/* Debug output helper */
static void debug_print(const char *msg)
{
    if (client.debug_cb) {
        client.debug_cb(msg);
    }
}

int tls_client_init(struct wolfIP *stack, tls_client_debug_cb debug)
{
    int ret;

    memset(&client, 0, sizeof(client));
    client.stack = stack;
    client.debug_cb = debug;
    client.fd = -1;
    client.state = TLS_CLIENT_STATE_IDLE;

    debug_print("TLS Client: Initializing wolfSSL\n");

    /* Initialize wolfSSL library (may already be done by server) */
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        debug_print("TLS Client: wolfSSL_Init failed\n");
        return -1;
    }

    /* Create TLS 1.3 client context */
    client.ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (client.ctx == NULL) {
        debug_print("TLS Client: CTX_new failed\n");
        return -1;
    }

    /* Don't verify server certificate (for testing without root CAs) */
    wolfSSL_CTX_set_verify(client.ctx, WOLFSSL_VERIFY_NONE, NULL);

    /* Register wolfIP I/O callbacks */
    wolfSSL_SetIO_wolfIP_CTX(client.ctx, stack);

    debug_print("TLS Client: Initialized\n");
    return 0;
}

int tls_client_connect(const char *host, uint16_t port,
                       tls_client_response_cb response_cb, void *user_ctx)
{
    struct wolfIP_sockaddr_in addr;
    int ret;

    if (client.state != TLS_CLIENT_STATE_IDLE) {
        debug_print("TLS Client: Already busy\n");
        return -1;
    }

    client.response_cb = response_cb;
    client.user_ctx = user_ctx;
    client.server_port = port;

    /* Try to parse as IP address first */
    client.server_ip = atoip4(host);
    if (client.server_ip == 0) {
        /* TODO: DNS lookup - for now require IP address */
        debug_print("TLS Client: DNS not implemented, use IP address\n");
        return -1;
    }

    /* Create socket */
    client.fd = wolfIP_sock_socket(client.stack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (client.fd < 0) {
        debug_print("TLS Client: Failed! socket() error\n");
        return -1;
    }

    /* Connect to server */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(port);
    addr.sin_addr.s_addr = ee32(client.server_ip);

    ret = wolfIP_sock_connect(client.stack, client.fd,
                              (struct wolfIP_sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && ret != -WOLFIP_EAGAIN) {
        debug_print("TLS Client: Failed! connect() error\n");
        wolfIP_sock_close(client.stack, client.fd);
        client.fd = -1;
        return -1;
    }

    client.state = TLS_CLIENT_STATE_CONNECTING;
    debug_print("TLS Client: Connecting...\n");
    return 0;
}

/* Call this from main loop to drive the TLS client state machine */
int tls_client_poll(void)
{
    int ret;
    int err;

    switch (client.state) {
        case TLS_CLIENT_STATE_IDLE:
        case TLS_CLIENT_STATE_DONE:
        case TLS_CLIENT_STATE_ERROR:
            return 0;

        case TLS_CLIENT_STATE_CONNECTING:
            /* Check if TCP connection is established by calling connect again */
            {
                struct wolfIP_sockaddr_in addr;
                static int connect_ready_count = 0;

                memset(&addr, 0, sizeof(addr));
                addr.sin_family = AF_INET;
                addr.sin_port = ee16(client.server_port);
                addr.sin_addr.s_addr = ee32(client.server_ip);

                ret = wolfIP_sock_connect(client.stack, client.fd,
                                          (struct wolfIP_sockaddr *)&addr, sizeof(addr));
                if (ret == -WOLFIP_EAGAIN) {
                    /* Still connecting, keep polling */
                    connect_ready_count = 0;
                    return 0;
                }
                if (ret < 0) {
                    debug_print("TLS Client: Failed! TCP connect error\n");
                    client.state = TLS_CLIENT_STATE_ERROR;
                    return -1;
                }
                /* Connection established - wait a few poll cycles to let stack settle */
                connect_ready_count++;
                if (connect_ready_count < 100) {
                    return 0;
                }
                connect_ready_count = 0;
            }
            debug_print("TLS Client: TLS handshake...\n");

            /* Create SSL object */
            client.ssl = wolfSSL_new(client.ctx);
            if (client.ssl == NULL) {
                debug_print("TLS Client: Failed! SSL context error\n");
                client.state = TLS_CLIENT_STATE_ERROR;
                return -1;
            }

            /* Set SNI (Server Name Indication) - required by most servers */
#ifndef M33MU_TEST
            wolfSSL_UseSNI(client.ssl, WOLFSSL_SNI_HOST_NAME, "google.com", 10);
#endif

            /* Associate SSL with socket */
            ret = wolfSSL_SetIO_wolfIP(client.ssl, client.fd);
            if (ret != 0) {
                debug_print("TLS Client: Failed! I/O setup error\n");
                client.state = TLS_CLIENT_STATE_ERROR;
                return -1;
            }
            client.state = TLS_CLIENT_STATE_HANDSHAKE;
            __attribute__((fallthrough));

        case TLS_CLIENT_STATE_HANDSHAKE:
            ret = wolfSSL_connect(client.ssl);
            if (ret == WOLFSSL_SUCCESS) {
                debug_print("TLS Client: Connected!\n");
                client.state = TLS_CLIENT_STATE_CONNECTED;
            } else {
                err = wolfSSL_get_error(client.ssl, ret);
                if (err == WOLFSSL_ERROR_WANT_READ ||
                    err == WOLFSSL_ERROR_WANT_WRITE) {
                    /* Handshake in progress, continue polling */
                    return 0;
                }
                (void)err;
                debug_print("TLS Client: Failed! Handshake error\n");
                client.state = TLS_CLIENT_STATE_ERROR;
                return -1;
            }
            break;

        case TLS_CLIENT_STATE_CONNECTED:
            /* Try to read any response */
            ret = wolfSSL_read(client.ssl, client.rx_buf,
                               sizeof(client.rx_buf) - 1);
            if (ret > 0) {
                client.rx_buf[ret] = '\0';
                client.got_response = 1;
                if (client.response_cb) {
                    client.response_cb((char *)client.rx_buf, ret, client.user_ctx);
                }
            } else {
                err = wolfSSL_get_error(client.ssl, ret);
                if (err == WOLFSSL_ERROR_ZERO_RETURN) {
                    /* Server closed connection - normal after sending response */
                    if (client.got_response) {
                        debug_print("TLS Client: Passed! Received response from server\n");
                    } else {
                        debug_print("TLS Client: Failed! Server closed connection (no data received)\n");
                    }
                    client.state = TLS_CLIENT_STATE_DONE;
                } else if (err != WOLFSSL_ERROR_WANT_READ) {
                    /* Connection closed/reset - check if we got data first */
                    if (client.got_response) {
                        debug_print("TLS Client: Passed! Connection closed after response\n");
                        client.state = TLS_CLIENT_STATE_DONE;
                    } else {
                        debug_print("TLS Client: Failed! Read error (no response received)\n");
                        client.state = TLS_CLIENT_STATE_ERROR;
                    }
                }
            }
            break;

        default:
            break;
    }

    return 0;
}

int tls_client_send(const void *data, int len)
{
    int ret;
    int err;

    if (client.state != TLS_CLIENT_STATE_CONNECTED) {
        return -1;
    }

    ret = wolfSSL_write(client.ssl, data, len);
    if (ret <= 0) {
        err = wolfSSL_get_error(client.ssl, ret);
        if (err != WOLFSSL_ERROR_WANT_WRITE) {
            debug_print("TLS Client: Write failed\n");
            return -1;
        }
    }

    return ret;
}

void tls_client_close(void)
{
    if (client.ssl) {
        wolfSSL_shutdown(client.ssl);
        wolfSSL_free(client.ssl);
        client.ssl = NULL;
    }
    if (client.fd >= 0 && client.stack) {
        wolfIP_sock_close(client.stack, client.fd);
        client.fd = -1;
    }
    client.state = TLS_CLIENT_STATE_IDLE;
}

int tls_client_is_connected(void)
{
    return (client.state == TLS_CLIENT_STATE_CONNECTED);
}

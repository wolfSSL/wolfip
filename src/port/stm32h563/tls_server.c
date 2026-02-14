/* tls_server.c
 *
 * TLS Echo Server for STM32H563 using wolfSSL and wolfIP
 *
 * Copyright (C) 2024 wolfSSL Inc.
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

#include "tls_server.h"
#include "certs.h"
#include "wolfip.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <string.h>

/* Configuration */
#ifndef TLS_SERVER_PORT
#define TLS_SERVER_PORT 8443
#endif

#ifndef TLS_RX_BUF_SIZE
#define TLS_RX_BUF_SIZE 1024
#endif

#ifndef TLS_MAX_CLIENTS
#define TLS_MAX_CLIENTS 2
#endif

/* Client connection state */
typedef enum {
    TLS_CLIENT_STATE_FREE = 0,
    TLS_CLIENT_STATE_ACCEPTING,
    TLS_CLIENT_STATE_HANDSHAKE,
    TLS_CLIENT_STATE_CONNECTED,
    TLS_CLIENT_STATE_CLOSING
} tls_client_state_t;

/* Client context */
typedef struct {
    tls_client_state_t state;
    int fd;
    WOLFSSL *ssl;
} tls_client_t;

/* Server context */
static struct {
    struct wolfIP *stack;
    WOLFSSL_CTX *ctx;
    int listen_fd;
    tls_client_t clients[TLS_MAX_CLIENTS];
    uint8_t rx_buf[TLS_RX_BUF_SIZE];
    tls_server_debug_cb debug_cb;
} server;

/* Forward declarations */
static void tls_listen_cb(int fd, uint16_t event, void *arg);
static void tls_client_cb(int fd, uint16_t event, void *arg);
static tls_client_t *tls_client_alloc(void);
static void tls_client_free(tls_client_t *client);

/* External functions from wolfssl_io.c */
extern int wolfSSL_SetIO_wolfIP_CTX(WOLFSSL_CTX *ctx, struct wolfIP *s);
extern int wolfSSL_SetIO_wolfIP(WOLFSSL *ssl, int fd);

/* Debug output helper */
static void debug_print(const char *msg)
{
    if (server.debug_cb) {
        server.debug_cb(msg);
    }
}

/* Custom random block generator for wolfSSL RNG
 * Note: For production, use a hardware RNG like STM32 RNG peripheral.
 * This uses wolfIP's LFSR PRNG which is NOT cryptographically secure.
 */
int custom_rand_gen_block(unsigned char *output, unsigned int sz)
{
    unsigned int i;
    for (i = 0; i < sz; i++) {
        output[i] = (unsigned char)(wolfIP_getrandom() & 0xFF);
    }
    return 0;
}

int tls_server_init(struct wolfIP *stack, uint16_t port,
                    tls_server_debug_cb debug)
{
    struct wolfIP_sockaddr_in addr;
    int ret;
    int i;

    /* Store references */
    server.stack = stack;
    server.debug_cb = debug;
    server.listen_fd = -1;
    server.ctx = NULL;

    /* Initialize client slots */
    for (i = 0; i < TLS_MAX_CLIENTS; i++) {
        server.clients[i].state = TLS_CLIENT_STATE_FREE;
        server.clients[i].fd = -1;
        server.clients[i].ssl = NULL;
    }

    debug_print("TLS: Initializing wolfSSL\n");

    /* Initialize wolfSSL library */
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        debug_print("TLS: wolfSSL_Init failed\n");
        return -1;
    }

    /* Create TLS 1.3 server context */
    server.ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (server.ctx == NULL) {
        debug_print("TLS: CTX_new failed\n");
        return -1;
    }

    /* Load certificate */
    debug_print("TLS: Loading certificate\n");
    ret = wolfSSL_CTX_use_certificate_buffer(server.ctx,
            (const unsigned char *)server_cert_pem,
            server_cert_pem_len - 1, /* exclude null terminator */
            WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        debug_print("TLS: Failed to load certificate\n");
        wolfSSL_CTX_free(server.ctx);
        server.ctx = NULL;
        return -1;
    }

    /* Load private key */
    debug_print("TLS: Loading private key\n");
    ret = wolfSSL_CTX_use_PrivateKey_buffer(server.ctx,
            (const unsigned char *)server_key_pem,
            server_key_pem_len - 1, /* exclude null terminator */
            WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        debug_print("TLS: Failed to load private key\n");
        wolfSSL_CTX_free(server.ctx);
        server.ctx = NULL;
        return -1;
    }

    /* Register wolfIP I/O callbacks */
    wolfSSL_SetIO_wolfIP_CTX(server.ctx, stack);

    /* Create listening socket */
    debug_print("TLS: Creating listen socket\n");
    server.listen_fd = wolfIP_sock_socket(stack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (server.listen_fd < 0) {
        debug_print("TLS: socket() failed\n");
        wolfSSL_CTX_free(server.ctx);
        server.ctx = NULL;
        return -1;
    }

    /* Bind to port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(port);
    addr.sin_addr.s_addr = 0; /* INADDR_ANY */

    ret = wolfIP_sock_bind(stack, server.listen_fd,
            (struct wolfIP_sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        debug_print("TLS: bind() failed\n");
        wolfIP_sock_close(stack, server.listen_fd);
        wolfSSL_CTX_free(server.ctx);
        server.ctx = NULL;
        return -1;
    }

    /* Start listening */
    ret = wolfIP_sock_listen(stack, server.listen_fd, TLS_MAX_CLIENTS);
    if (ret < 0) {
        debug_print("TLS: listen() failed\n");
        wolfIP_sock_close(stack, server.listen_fd);
        wolfSSL_CTX_free(server.ctx);
        server.ctx = NULL;
        return -1;
    }

    /* Register callback for incoming connections */
    wolfIP_register_callback(stack, server.listen_fd, tls_listen_cb, NULL);

    debug_print("TLS: Server ready on port 8443\n");
    return 0;
}

void tls_server_cleanup(void)
{
    int i;

    /* Close all client connections */
    for (i = 0; i < TLS_MAX_CLIENTS; i++) {
        if (server.clients[i].state != TLS_CLIENT_STATE_FREE) {
            tls_client_free(&server.clients[i]);
        }
    }

    /* Close listen socket */
    if (server.listen_fd >= 0 && server.stack) {
        wolfIP_sock_close(server.stack, server.listen_fd);
        server.listen_fd = -1;
    }

    /* Free SSL context */
    if (server.ctx) {
        wolfSSL_CTX_free(server.ctx);
        server.ctx = NULL;
    }

    /* Cleanup wolfSSL */
    wolfSSL_Cleanup();
}

static tls_client_t *tls_client_alloc(void)
{
    int i;
    for (i = 0; i < TLS_MAX_CLIENTS; i++) {
        if (server.clients[i].state == TLS_CLIENT_STATE_FREE) {
            return &server.clients[i];
        }
    }
    return NULL;
}

static void tls_client_free(tls_client_t *client)
{
    if (client->ssl) {
        wolfSSL_shutdown(client->ssl);
        wolfSSL_free(client->ssl);
        client->ssl = NULL;
    }
    if (client->fd >= 0 && server.stack) {
        wolfIP_sock_close(server.stack, client->fd);
        client->fd = -1;
    }
    client->state = TLS_CLIENT_STATE_FREE;
}

static void tls_listen_cb(int fd, uint16_t event, void *arg)
{
    tls_client_t *client;
    int client_fd;
    (void)arg;

    if (fd != server.listen_fd) {
        return;
    }

    if (!(event & CB_EVENT_READABLE)) {
        return;
    }

    /* Accept new connection */
    client_fd = wolfIP_sock_accept(server.stack, server.listen_fd, NULL, NULL);
    if (client_fd < 0) {
        return;
    }

    /* Allocate client slot */
    client = tls_client_alloc();
    if (client == NULL) {
        debug_print("TLS: No free client slots\n");
        wolfIP_sock_close(server.stack, client_fd);
        return;
    }

    debug_print("TLS: Client connected, starting handshake\n");

    /* Create SSL object */
    client->ssl = wolfSSL_new(server.ctx);
    if (client->ssl == NULL) {
        debug_print("TLS: wolfSSL_new failed\n");
        wolfIP_sock_close(server.stack, client_fd);
        client->state = TLS_CLIENT_STATE_FREE;
        return;
    }

    /* Associate SSL with socket */
    wolfSSL_SetIO_wolfIP(client->ssl, client_fd);

    client->fd = client_fd;
    client->state = TLS_CLIENT_STATE_HANDSHAKE;

    /* Register callback for this client */
    wolfIP_register_callback(server.stack, client_fd, tls_client_cb, client);
}

static void tls_client_cb(int fd, uint16_t event, void *arg)
{
    tls_client_t *client = (tls_client_t *)arg;
    int ret;
    int err;

    if (client == NULL || client->fd != fd) {
        return;
    }

    /* Handle connection closed */
    if (event & CB_EVENT_CLOSED) {
        debug_print("TLS: Client disconnected\n");
        tls_client_free(client);
        return;
    }

    /* Handle based on state */
    switch (client->state) {
        case TLS_CLIENT_STATE_HANDSHAKE:
            if (!(event & (CB_EVENT_READABLE | CB_EVENT_WRITABLE))) {
                break;
            }

            /* Continue TLS handshake */
            ret = wolfSSL_accept(client->ssl);
            if (ret == WOLFSSL_SUCCESS) {
                debug_print("TLS: Handshake complete\n");
                client->state = TLS_CLIENT_STATE_CONNECTED;
            } else {
                err = wolfSSL_get_error(client->ssl, ret);
                if (err != WOLFSSL_ERROR_WANT_READ &&
                    err != WOLFSSL_ERROR_WANT_WRITE) {
                    debug_print("TLS: Handshake failed\n");
                    tls_client_free(client);
                }
                /* WANT_READ/WANT_WRITE: handshake continues next callback */
            }
            break;

        case TLS_CLIENT_STATE_CONNECTED:
            if (!(event & CB_EVENT_READABLE)) {
                break;
            }

            /* Read encrypted data */
            ret = wolfSSL_read(client->ssl, server.rx_buf,
                               sizeof(server.rx_buf) - 1);
            if (ret > 0) {
                /* Echo data back */
                ret = wolfSSL_write(client->ssl, server.rx_buf, ret);
                if (ret > 0) {
#ifdef M33MU_TEST
                    debug_print("M33MU_TEST: TLS server echoed data successfully\n");
                    debug_print("M33MU_TEST: TLS server test PASSED\n");
                    /* Trigger breakpoint for m33mu to detect success */
                    __asm volatile("bkpt #0x7f");
#endif
                } else {
                    err = wolfSSL_get_error(client->ssl, ret);
                    if (err != WOLFSSL_ERROR_WANT_WRITE) {
                        debug_print("TLS: Write error\n");
                        tls_client_free(client);
                    }
                }
            } else {
                err = wolfSSL_get_error(client->ssl, ret);
                if (err == WOLFSSL_ERROR_ZERO_RETURN) {
                    /* Clean shutdown */
                    debug_print("TLS: Client closed connection\n");
                    tls_client_free(client);
                } else if (err != WOLFSSL_ERROR_WANT_READ) {
                    debug_print("TLS: Read error\n");
                    tls_client_free(client);
                }
            }
            break;

        default:
            break;
    }
}

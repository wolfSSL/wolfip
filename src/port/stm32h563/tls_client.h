/* tls_client.h
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

#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration */
struct wolfIP;

/* Debug callback - receives status messages */
typedef void (*tls_client_debug_cb)(const char *msg);

/* Response callback - receives data from server */
typedef void (*tls_client_response_cb)(const char *data, int len, void *ctx);

/**
 * Initialize the TLS client
 *
 * @param stack  wolfIP stack instance
 * @param debug  Optional debug callback (can be NULL)
 *
 * @return 0 on success, negative on error
 */
int tls_client_init(struct wolfIP *stack, tls_client_debug_cb debug);

/**
 * Start TLS connection to a server
 *
 * @param host         Server IP address (DNS not yet supported)
 * @param port         Server port (e.g., 443 for HTTPS)
 * @param response_cb  Callback for received data
 * @param user_ctx     User context passed to callback
 *
 * @return 0 on success, negative on error
 *
 * Example:
 *   tls_client_connect("142.250.80.46", 443, my_response_cb, NULL);
 */
int tls_client_connect(const char *host, uint16_t port,
                       tls_client_response_cb response_cb, void *user_ctx);

/**
 * Poll the TLS client state machine
 *
 * Call this regularly from main loop to drive handshake and receive data.
 *
 * @return 0 on success, negative on error
 */
int tls_client_poll(void);

/**
 * Send data to the server
 *
 * @param data  Data to send
 * @param len   Length of data
 *
 * @return bytes sent, or negative on error
 */
int tls_client_send(const void *data, int len);

/**
 * Close the TLS connection
 */
void tls_client_close(void);

/**
 * Check if client is connected
 *
 * @return 1 if connected, 0 otherwise
 */
int tls_client_is_connected(void);

#ifdef __cplusplus
}
#endif

#endif /* TLS_CLIENT_H */

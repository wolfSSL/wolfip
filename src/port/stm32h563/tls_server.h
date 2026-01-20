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

#ifndef TLS_SERVER_H
#define TLS_SERVER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration */
struct wolfIP;

/* Debug callback type - receives status messages */
typedef void (*tls_server_debug_cb)(const char *msg);

/**
 * Initialize the TLS echo server
 *
 * @param stack  wolfIP stack instance
 * @param port   TCP port to listen on (default: 8443)
 * @param debug  Optional debug callback for status messages (can be NULL)
 *
 * @return 0 on success, negative on error
 *
 * Example:
 *   tls_server_init(stack, 8443, uart_puts);
 */
int tls_server_init(struct wolfIP *stack, uint16_t port,
                    tls_server_debug_cb debug);

/**
 * Cleanup TLS server resources
 *
 * Call this to shutdown the server and free all resources.
 */
void tls_server_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* TLS_SERVER_H */

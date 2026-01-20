/* https_server.h
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

#ifndef HTTPS_SERVER_H
#define HTTPS_SERVER_H

#include "wolfip.h"

/* Debug callback type */
typedef void (*https_debug_cb)(const char *msg);

/* Initialize HTTPS server on specified port
 * Returns 0 on success, -1 on failure */
int https_server_init(struct wolfIP *stack, uint16_t port, https_debug_cb debug);

/* Poll HTTPS server - call from main loop
 * Returns 0 on success */
int https_server_poll(void);

/* Set device info for status page */
void https_server_set_info(uint32_t ip_addr, uint32_t uptime_sec);

#endif /* HTTPS_SERVER_H */

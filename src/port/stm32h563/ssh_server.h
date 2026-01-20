/* ssh_server.h
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

#ifndef SSH_SERVER_H
#define SSH_SERVER_H

#include "wolfip.h"

/* Debug callback type */
typedef void (*ssh_debug_cb)(const char *msg);

/* Initialize SSH server on specified port
 * Returns 0 on success, -1 on failure */
int ssh_server_init(struct wolfIP *stack, uint16_t port, ssh_debug_cb debug);

/* Poll SSH server - call from main loop
 * Returns 0 on success */
int ssh_server_poll(void);

/* Get SSH server uptime in seconds (for status display) */
uint32_t ssh_server_get_uptime(void);

#endif /* SSH_SERVER_H */

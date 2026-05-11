/* tftp_client_demo.h
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
#ifndef TFTP_CLIENT_DEMO_H
#define TFTP_CLIENT_DEMO_H

#include <stdint.h>

struct wolfIP;

typedef void (*tftp_client_demo_debug_cb)(const char *msg);

/* Start a one-shot TFTP RRQ GET of `filename` from `server_ip` (network
 * byte order, big-endian uint32). The received bytes are programmed
 * into the wolfBoot update partition at WOLFBOOT_PARTITION_UPDATE_ADDRESS;
 * on successful completion the update flag is set so wolfBoot picks the
 * staged image up on the next reset.
 *
 * Returns 0 on successful kickoff, negative on error. The actual
 * transfer runs asynchronously - call tftp_client_demo_poll() from the
 * main loop. */
int tftp_client_demo_start(struct wolfIP *stack, uint32_t server_ip,
    const char *filename, tftp_client_demo_debug_cb debug_cb);

/* Drive the TFTP client state machine. `now_ms` is monotonic
 * milliseconds (same source the main loop already passes to
 * wolfIP_poll). Safe to call when no transfer is active. */
void tftp_client_demo_poll(uint32_t now_ms);

/* Returns the last status of the transfer:
 *   1  - in progress
 *   0  - complete success (update flag set)
 *  <0  - WOLFTFTP_ERR_* or other failure
 * INT32_MIN until the first transfer is started. */
int tftp_client_demo_status(void);

#endif /* TFTP_CLIENT_DEMO_H */

/* dot1x_client.h
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

#ifndef DOT1X_CLIENT_H
#define DOT1X_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration */
struct wolfIP;

/* Run a wired IEEE 802.1X EAP-TLS authentication to completion (one shot).
 *
 * Opens a wolfIP packet socket bound to the EAPOL ethertype (0x888E),
 * drives the in-tree wolfSupplicant through the EAP-TLS exchange against an
 * 802.1X authenticator (e.g. a Linux host running hostapd with
 * driver=wired), and returns once EAP-Success is received. On wired there
 * is no WPA 4-way handshake, so success is the point at which the
 * supplicant has the MSK-derived PMK and parks waiting for an M1 that never
 * arrives (SUPP_STATE_4WAY_M1_WAIT).
 *
 * stack must already have its Ethernet device initialised (link up). No IP
 * address is required - 802.1X runs at layer 2.
 *
 * log is an optional line-logging callback (UART puts); may be NULL.
 *
 * Returns 0 on EAP-TLS success, negative on failure or timeout.
 */
int dot1x_eaptls_run(struct wolfIP *stack, void (*log)(const char *msg));

#ifdef __cplusplus
}
#endif

#endif /* DOT1X_CLIENT_H */

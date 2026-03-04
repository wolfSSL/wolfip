/* wolfip_wolfguard.h
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

#ifndef WOLFIP_WOLFGUARD_H
#define WOLFIP_WOLFGUARD_H

#ifdef WOLFIP_WOLFGUARD

#include <stdint.h>
#include <sys/socket.h>  /* struct sockaddr_storage */
#include "wolfip.h"      /* wolfIP_ll_dev, ip4 */

/* WolfGuard Generic Netlink family name and version */
#define WG_GENL_NAME    "wolfguard"
#define WG_GENL_VERSION 1

/*
 * Key sizes (SECP256R1).
 * Public key length depends on whether compressed keys are used.
 * Default (no WG_USE_PUBLIC_KEY_COMPRESSION): 65-byte uncompressed point.
 */
#define WG_PRIVATE_KEY_LEN   32
#ifndef WG_USE_PUBLIC_KEY_COMPRESSION
# define WG_PUBLIC_KEY_LEN   65
#else
# define WG_PUBLIC_KEY_LEN   33
#endif
#define WG_SYMMETRIC_KEY_LEN 32  /* reserved for future preshared key support */

/* Maximum number of peers per wolfguard interface */
#ifndef WOLFIP_WG_MAX_PEERS
# define WOLFIP_WG_MAX_PEERS 4
#endif

/*
 * Per-peer configuration.
 *
 * endpoint:     Peer's UDP endpoint (AF_INET or AF_INET6).
 * allowed_ip:   IPv4 address in host byte order (ip4 convention, e.g. from
 *               atoip4() or ntohl(inet_addr("..."))).
 * allowed_cidr: Prefix length (0-32).
 * keepalive_interval: Persistent keep-alive in seconds; 0 = disabled.
 */
struct wolfIP_wg_peer {
    uint8_t                 public_key[WG_PUBLIC_KEY_LEN];
    struct sockaddr_storage endpoint;
    ip4                     allowed_ip;
    uint8_t                 allowed_cidr;
    uint16_t                keepalive_interval;
};

/*
 * Device configuration passed to wolfIP_wg_init().
 *
 * ifname:       Interface name (e.g. "wg0").
 * private_key:  32-byte SECP256R1 private key scalar.
 * listen_port:  UDP listen port (host byte order); 0 = kernel picks randomly.
 * num_peers:    Number of valid entries in peers[].
 */
struct wolfIP_wg_config {
    char                 ifname[16];
    uint8_t              private_key[WG_PRIVATE_KEY_LEN];
    uint16_t             listen_port;
    int                  num_peers;
    struct wolfIP_wg_peer peers[WOLFIP_WG_MAX_PEERS];
};

/*
 * wolfIP_wg_init() - Create, configure, and open a wolfguard interface.
 *
 * Creates the wolfguard network interface, configures it via the wolfguard
 * generic-netlink API, brings it UP, opens an AF_PACKET/SOCK_DGRAM socket
 * bound to the interface, and populates @ll with poll/send callbacks and a
 * synthetic MAC address.
 *
 * The caller passes the returned @ll to wolfIP_ipconfig_set_ex() and
 * wolfIP_getdev_ex() to attach it as a wolfip network interface.
 *
 * Returns 0 on success, negative errno on failure.
 */
int wolfIP_wg_init(struct wolfIP_wg_config *cfg, struct wolfIP_ll_dev *ll);

/*
 * wolfIP_wg_teardown() - Bring down and delete the wolfguard interface.
 *
 * Closes the TUN file descriptor and removes the interface via RTM_DELLINK.
 * @ifname must match what was passed to wolfIP_wg_init().
 */
void wolfIP_wg_teardown(const char *ifname);

#endif /* WOLFIP_WOLFGUARD */
#endif /* WOLFIP_WOLFGUARD_H */

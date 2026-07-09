/* config.h
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
#ifndef WOLF_CONFIG_H
#define WOLF_CONFIG_H

#ifndef CONFIG_IPFILTER
#define CONFIG_IPFILTER         0
#endif

#define ETHERNET
#define LINK_MTU                1536

/* Socket configuration - STM32C5A3ZG has only 256KB SRAM. Each tsocket
 * embeds rxmem[RXBUF_SIZE] + txmem[TXBUF_SIZE], so the static pool is
 * (MAX_*SOCKETS) * (RXBUF_SIZE + TXBUF_SIZE). Keep these small enough that
 * the pool + heap + stack fit in 256KB (see target.ld for heap/stack). */
#define MAX_TCPSOCKETS          4
#define MAX_UDPSOCKETS          2
#define MAX_ICMPSOCKETS         1
#define RXBUF_SIZE              (LINK_MTU * 2)   /* 3KB */
#define TXBUF_SIZE              (LINK_MTU * 2)   /* 3KB */

#define MAX_NEIGHBORS           16

#ifndef WOLFIP_MAX_INTERFACES
#define WOLFIP_MAX_INTERFACES   1
#endif

#ifndef WOLFIP_ENABLE_FORWARDING
#define WOLFIP_ENABLE_FORWARDING 0
#endif

#ifndef WOLFIP_ENABLE_LOOPBACK
#define WOLFIP_ENABLE_LOOPBACK  0
#endif

#ifndef WOLFIP_ENABLE_DHCP
#define WOLFIP_ENABLE_DHCP      1
#endif

/* Static IP fallback (used when DHCP is disabled or times out).
 * Bench segment is 10.0.4.0/24 (host enp5s0 = 10.0.4.24, GW 10.0.4.1). */
#define WOLFIP_IP               "10.0.4.123"
#define WOLFIP_NETMASK          "255.255.255.0"
#define WOLFIP_GW               "10.0.4.1"
#define WOLFIP_STATIC_DNS_IP    "8.8.8.8"

#if WOLFIP_ENABLE_DHCP
#define DHCP
/* Reduce DHCP retries for faster fallback to static IP on demo boards */
#define DHCP_DISCOVER_RETRIES 1
#define DHCP_REQUEST_RETRIES  1
#endif

/* TLS 1.3 mutual-auth client target (ENABLE_TLS_CLIENT build, milestone 3A.0).
 * The device connects to an openssl s_server here after the network is up.
 * Change these to point at your test server. */
#ifndef TLS_SERVER_IP
#define TLS_SERVER_IP           "10.0.4.24"
#endif
#ifndef TLS_SERVER_PORT
#define TLS_SERVER_PORT         11111
#endif

/* Hardware debug: uncomment to enable verbose GPIO/ETH/MDIO/DHCP logging */
/* #define DEBUG_HW */

#endif /* WOLF_CONFIG_H */

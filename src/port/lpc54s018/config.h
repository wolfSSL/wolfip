/* config.h
 *
 * wolfIP configuration for LPC54S018M-EVK
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

#define MAX_TCPSOCKETS          2
#define MAX_UDPSOCKETS          1
#define MAX_ICMPSOCKETS         1
#define RXBUF_SIZE              LINK_MTU
#define TXBUF_SIZE              LINK_MTU

#define MAX_NEIGHBORS           4
#define WOLFIP_ARP_PENDING_MAX  2

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

/* Static IP fallback (used when DHCP is disabled or times out) */
#define WOLFIP_IP               "192.168.1.10"
#define WOLFIP_NETMASK          "255.255.255.0"
#define WOLFIP_GW               "192.168.1.1"
#define WOLFIP_STATIC_DNS_IP    "8.8.8.8"

#if WOLFIP_ENABLE_DHCP
#define DHCP
#endif

#endif /* WOLF_CONFIG_H */

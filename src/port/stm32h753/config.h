/* config.h
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
#ifndef WOLF_CONFIG_H
#define WOLF_CONFIG_H

#ifndef CONFIG_IPFILTER
#define CONFIG_IPFILTER         0
#endif

#define ETHERNET
#define LINK_MTU                1536

/* Socket configuration - STM32H753 has 512KB SRAM, can be generous */
#define MAX_TCPSOCKETS          8
#define MAX_UDPSOCKETS          2
#define MAX_ICMPSOCKETS         1
#define RXBUF_SIZE              (LINK_MTU * 8)   /* 12KB */
#define TXBUF_SIZE              (LINK_MTU * 8)   /* 12KB */

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

#if WOLFIP_ENABLE_DHCP
#define DHCP
#else
/* Static IP configuration (when DHCP disabled) */
#define WOLFIP_IP               "192.168.1.100"
#define WOLFIP_NETMASK          "255.255.255.0"
#define WOLFIP_GW               "192.168.1.1"
#define WOLFIP_STATIC_DNS_IP    "8.8.8.8"
#endif

/* Hardware debug: uncomment to enable verbose GPIO/ETH/MDIO/DHCP logging */
/* #define DEBUG_HW */

#endif /* WOLF_CONFIG_H */

/* config.h
 *
 * wolfIP configuration for VA416xx (memory-optimized for 64KB SRAM)
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

/* Memory-constrained: 64KB SRAM total
 * Socket buffers: 4 sockets * (1536 + 1536) = 12,288 bytes
 * DMA buffers: 6 * 1536 + 1536 staging = 10,752 bytes
 * OOO reassembly: 2 TCP * 4 segs * 1460 = 11,680 bytes
 * ARP pending: 2 * 1536 = 3,072 bytes
 * TCP state, timers, misc: ~4KB
 * Total estimated: ~42KB (fits in 64KB)
 */
#define MAX_TCPSOCKETS          2    /* listen + 1 client */
#define MAX_UDPSOCKETS          1    /* for DHCP */
#define MAX_ICMPSOCKETS         1
#define RXBUF_SIZE              LINK_MTU         /* 1536 per socket */
#define TXBUF_SIZE              LINK_MTU         /* 1536 per socket */

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

#if WOLFIP_ENABLE_DHCP
#define DHCP
#else
#define WOLFIP_IP               "10.0.4.90"
#define WOLFIP_NETMASK          "255.255.255.0"
#define WOLFIP_GW               "10.0.4.1"
#define WOLFIP_STATIC_DNS_IP    "8.8.8.8"
#endif

#endif /* WOLF_CONFIG_H */

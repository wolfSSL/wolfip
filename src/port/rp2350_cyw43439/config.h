/* config.h - wolfIP configuration for Pi Pico 2 W (RP2350 + CYW43439)
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef WOLF_CONFIG_H
#define WOLF_CONFIG_H

#ifndef CONFIG_IPFILTER
#define CONFIG_IPFILTER         0
#endif

/* 802.11 air MTU is 2304 (CCMP/QoS overhead); after SDPCM + WHD
 * encapsulation the host sees standard 1500-byte Ethernet frames. Keep
 * LINK_MTU at 1536 to leave room for VLAN tags. */
#define ETHERNET
#define LINK_MTU                1536

/* RP2350 has 520 KB SRAM; we can afford generous socket budgets.
 *   8 TCP * ~9 KB = ~72 KB
 *   3 UDP * ~3 KB = ~9 KB  (DHCP + DNS + app)
 *   1 ICMP        = ~3 KB
 *   wolfIP core + supplicant + driver = ~80 KB
 *   CYW43439 firmware blob (XIP, not SRAM) = ~225 KB in flash
 * Total static SRAM ~170 KB, leaves >300 KB for stack + heap (libc).
 */
#define MAX_TCPSOCKETS          8
#define MAX_UDPSOCKETS          3
#define MAX_ICMPSOCKETS         1
#define RXBUF_SIZE              LINK_MTU
#define TXBUF_SIZE              LINK_MTU

#define MAX_NEIGHBORS           8
#define WOLFIP_ARP_PENDING_MAX  4

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

/* Default Wi-Fi credentials baked into the firmware. Override at build
 * time via -DWOLFIP_WIFI_SSID=... -DWOLFIP_WIFI_PSK=... or edit. */
#ifndef WOLFIP_WIFI_SSID
#define WOLFIP_WIFI_SSID        "wolfIP-test"
#endif
#ifndef WOLFIP_WIFI_PSK
#define WOLFIP_WIFI_PSK         "ThisIsAPassword!"
#endif

/* Static IP fallback when DHCP is disabled. */
#define WOLFIP_IP               "192.168.12.11"
#define WOLFIP_NETMASK          "255.255.255.0"
#define WOLFIP_GW               "192.168.12.1"
#define WOLFIP_STATIC_DNS_IP    "8.8.8.8"

#if WOLFIP_ENABLE_DHCP
#define DHCP
#endif

#endif /* WOLF_CONFIG_H */

/* wolfip6_config.h
 *
 * Default sizing and feature switches for the IPv6 support.
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
#ifndef WOLFIP6_CONFIG_H
#define WOLFIP6_CONFIG_H

/* Included by src/wolfip.c immediately after the configuration header,
 * whichever one that is.
 *
 * These defaults deliberately do NOT live in config.h. Every board port
 * ships its own config.h with the same WOLF_CONFIG_H guard and replaces the
 * one at the top of the tree, so anything defined only there is invisible to
 * a port build - and src/wolfip.c refers to WOLFIP_IF_CONF_MAX and
 * WOLFIP_IFADDR_MAX outside any WOLFIP_IPV6 guard. Putting the defaults here
 * means every configuration gets them, while a config.h that sets one first
 * still wins: every macro below is #ifndef-guarded.
 */

/* IPv6 support. Off by default; when off, all IPv6 code is removed by the
 * preprocessor and the behavior/ABI of the stack is unchanged.
 *
 * Defined first because WOLFIP_IF_MULTICONF and the table sizes below key
 * off it. */
#ifndef WOLFIP_IPV6
#define WOLFIP_IPV6 0
#endif

/* Multiple IP configurations (addresses) per interface. Off by default; when
 * off, each interface carries exactly one configuration and the layout,
 * behavior and ABI of the stack are unchanged.
 *
 * IPv6 cannot work with a single address per interface: a link-local address
 * always coexists with any global address obtained by SLAAC or DHCPv6, so
 * WOLFIP_IPV6 forces this feature on. A minimal IPv4-only build can leave it
 * at 0 and keep the historical one-configuration-per-interface layout.
 *
 * WOLFIP_IF_CONF_MAX is a hard cap on the number of configurations that may
 * be live on a *single* interface. WOLFIP_IFADDR_MAX sizes the flat pool
 * shared by every interface, and so grows independently of
 * WOLFIP_MAX_INTERFACES. */
#ifndef WOLFIP_IF_MULTICONF
#if WOLFIP_IPV6
#define WOLFIP_IF_MULTICONF 1
#else
#define WOLFIP_IF_MULTICONF 0
#endif
#endif

#if WOLFIP_IPV6 && !WOLFIP_IF_MULTICONF
#error "WOLFIP_IPV6 requires WOLFIP_IF_MULTICONF"
#endif

#ifndef WOLFIP_IF_CONF_MAX
#if WOLFIP_IF_MULTICONF
#define WOLFIP_IF_CONF_MAX 4
#else
#define WOLFIP_IF_CONF_MAX 1
#endif
#endif

#if WOLFIP_IF_CONF_MAX < 1
#error "WOLFIP_IF_CONF_MAX must be at least 1"
#endif

#if !WOLFIP_IF_MULTICONF && (WOLFIP_IF_CONF_MAX != 1)
#error "WOLFIP_IF_CONF_MAX must be 1 unless WOLFIP_IF_MULTICONF is enabled"
#endif

/* IPv6 needs at least a link-local address plus one other per interface. */
#if WOLFIP_IPV6 && (WOLFIP_IF_CONF_MAX < 2)
#error "WOLFIP_IPV6 requires WOLFIP_IF_CONF_MAX >= 2 (link-local + one more)"
#endif

#ifndef WOLFIP_IFADDR_MAX
#define WOLFIP_IFADDR_MAX (WOLFIP_MAX_INTERFACES * WOLFIP_IF_CONF_MAX)
#endif

#if WOLFIP_IFADDR_MAX < WOLFIP_MAX_INTERFACES
#error "WOLFIP_IFADDR_MAX must provide at least one address per interface"
#endif

/* WOLFIP_IPV6_PROFILE_LARGE raises every IPv6 table below in one switch, for
 * networks larger than the small embedded default this stack targets. Each
 * table can still be overridden individually. */
#ifndef WOLFIP_IPV6_PROFILE_LARGE
#define WOLFIP_IPV6_PROFILE_LARGE 0
#endif

/* Addresses per interface (link-local, SLAAC/DHCPv6 globals, ULA). */
#ifndef WOLFIP_IP6_ADDR_MAX
#if WOLFIP_IPV6_PROFILE_LARGE
#define WOLFIP_IP6_ADDR_MAX 8
#else
#define WOLFIP_IP6_ADDR_MAX 4
#endif
#endif

#if WOLFIP_IPV6 && (WOLFIP_IP6_ADDR_MAX < 2)
#error "WOLFIP_IP6_ADDR_MAX must be at least 2 (link-local + one more)"
#endif

/* Neighbor cache (RFC 4861 section 5.1). IPv6 counterpart of MAX_NEIGHBORS. */
#ifndef WOLFIP_ND6_CACHE_SIZE
#if WOLFIP_IPV6_PROFILE_LARGE
#define WOLFIP_ND6_CACHE_SIZE 64
#else
#define WOLFIP_ND6_CACHE_SIZE 16
#endif
#endif

/* On-link prefix list (RFC 4861 section 5.1). */
#ifndef WOLFIP_ND6_PREFIX_MAX
#if WOLFIP_IPV6_PROFILE_LARGE
#define WOLFIP_ND6_PREFIX_MAX 16
#else
#define WOLFIP_ND6_PREFIX_MAX 4
#endif
#endif

/* Default router list (RFC 4861 section 5.1). */
#ifndef WOLFIP_ND6_ROUTER_MAX
#if WOLFIP_IPV6_PROFILE_LARGE
#define WOLFIP_ND6_ROUTER_MAX 4
#else
#define WOLFIP_ND6_ROUTER_MAX 2
#endif
#endif

/* DHCPv6 client message buffer (RFC 8415). */
#ifndef WOLFIP_DHCP6_BUF_SIZE
#if WOLFIP_IPV6_PROFILE_LARGE
#define WOLFIP_DHCP6_BUF_SIZE 1024
#else
#define WOLFIP_DHCP6_BUF_SIZE 512
#endif
#endif

#if WOLFIP_IPV6 && !defined(ETHERNET)
/* This is about the *build*, not about any one interface. Without ETHERNET
 * the stack has no link layer at all: no frame headroom, no demux, no
 * neighbour cache to key on. That is a different shape of stack, and the
 * IPv6 code is written against the Ethernet-shaped one.
 *
 * A point-to-point link is not this case and is supported. It is a runtime
 * property of an interface (ll->non_ethernet), set by drivers such as
 * linux_tun.c and utun_darwin.c, in a build that has ETHERNET: the stack
 * still reserves the link header and still runs the demux, and the driver
 * simply never sees those bytes. See WOLFIP_IPV6_IID_OVERRIDE below for
 * what such a link needs that Ethernet does not. */
#error "WOLFIP_IPV6 currently requires ETHERNET"
#endif

/* Interface identifier override for links without a link-layer address.
 *
 * RFC 4862 section 5.3 forms the interface identifier from the link-layer
 * address, which a point-to-point link does not have. wolfIP's default
 * there is a random identifier verified by duplicate address detection:
 * correct, needs no configuration, and unique on a link with one peer with
 * near-certainty - but a different one after every reboot.
 *
 * Enabling this compiles in wolfIP_ipv6_set_iid()/get_iid(), so an
 * application can supply the identifier instead. What it supplies is its
 * own business: an RFC 7217 semantically opaque identifier
 * F(prefix, interface, network, DAD_counter, secret) is the form RFC 8064
 * recommends, but a value read back from a previous boot with get_iid() and
 * stored in flash does just as well. Deliberately not computed here: the
 * pseudo-random function and the secret that keys it belong to the
 * application, and stable storage is not something this stack has.
 *
 * Off by default. The generated identifier is correct on its own, and this
 * costs a little state per interface plus the API surface. */
#ifndef WOLFIP_IPV6_IID_OVERRIDE
#define WOLFIP_IPV6_IID_OVERRIDE 0
#endif

/* Per-feature switches for IPv6 functionality that is not implemented yet.
 * Each one is flipped to 1 by the phase that implements it, which also
 * enables the matching requirement-derived tests. They are named (rather
 * than plain #if 0) so the amount of pending work stays greppable. */
#ifndef WOLFIP_IPV6_HAVE_EXTHDR
#define WOLFIP_IPV6_HAVE_EXTHDR 0
#endif
#ifndef WOLFIP_IPV6_HAVE_ICMP6
#define WOLFIP_IPV6_HAVE_ICMP6 1
#endif
#ifndef WOLFIP_IPV6_HAVE_FORWARDING
#define WOLFIP_IPV6_HAVE_FORWARDING 0
#endif
#ifndef WOLFIP_IPV6_HAVE_ND6
#define WOLFIP_IPV6_HAVE_ND6 0
#endif
#ifndef WOLFIP_IPV6_HAVE_SLAAC
#define WOLFIP_IPV6_HAVE_SLAAC 0
#endif
#ifndef WOLFIP_IPV6_HAVE_DHCP6
#define WOLFIP_IPV6_HAVE_DHCP6 0
#endif
#ifndef WOLFIP_IPV6_HAVE_SOCKETS
#define WOLFIP_IPV6_HAVE_SOCKETS 1
#endif

#endif /* WOLFIP6_CONFIG_H */

#ifndef WOLF_CONFIG_H
#define WOLF_CONFIG_H

#ifndef CONFIG_IPFILTER
#define CONFIG_IPFILTER 0
#endif

#define ETHERNET
#define LINK_MTU 1536
#ifndef LINK_MTU_MIN
#define LINK_MTU_MIN 64U
#endif
#if LINK_MTU < LINK_MTU_MIN
#error "LINK_MTU must be greater than or equal to LINK_MTU_MIN"
#endif

#define MAX_TCPSOCKETS 4
#define MAX_UDPSOCKETS 2
#define MAX_ICMPSOCKETS 2
#define RXBUF_SIZE (20 * 1024)
#define TXBUF_SIZE (32 * 1024)

#ifndef WOLFIP_POSIX_TCPDUMP
#define WOLFIP_POSIX_TCPDUMP 0
#endif

/* POSIX Network Device Selection */
#ifndef WOLFIP_USE_VDE
#define WOLFIP_USE_VDE 0  /* 0 = TAP device (default), 1 = VDE */
#endif

#define MAX_NEIGHBORS 16

#ifndef WOLFIP_MAX_INTERFACES
#define WOLFIP_MAX_INTERFACES 2
#endif

#ifndef WOLFIP_RAWSOCKETS
#define WOLFIP_RAWSOCKETS 0
#endif

#ifndef WOLFIP_MAX_RAWSOCKETS
#define WOLFIP_MAX_RAWSOCKETS 4
#endif

#ifndef WOLFIP_PACKET_SOCKETS
#define WOLFIP_PACKET_SOCKETS 0
#endif

#if WOLFIP_PACKET_SOCKETS && !defined(ETHERNET)
#undef WOLFIP_PACKET_SOCKETS
#define WOLFIP_PACKET_SOCKETS 0
#error "WOLFIP_PACKET_SOCKETS requires ETHERNET to be defined. Please adjust your configuration."
#endif

#ifndef WOLFIP_MAX_PACKETSOCKETS
#define WOLFIP_MAX_PACKETSOCKETS 2
#endif

#ifndef WOLFIP_ENABLE_FORWARDING
#define WOLFIP_ENABLE_FORWARDING 0
#endif

#ifndef WOLFIP_ENABLE_LOOPBACK
#define WOLFIP_ENABLE_LOOPBACK 0
#endif

/* Enable HTTP server for POSIX builds */
#ifndef WOLFIP_ENABLE_HTTP
#define WOLFIP_ENABLE_HTTP
#endif

#ifndef WOLFIP_ENABLE_TFTP
#define WOLFIP_ENABLE_TFTP 0
#endif

#if WOLFIP_ENABLE_LOOPBACK && WOLFIP_MAX_INTERFACES < 2
#error "WOLFIP_ENABLE_LOOPBACK requires WOLFIP_MAX_INTERFACES > 1"
#endif

/* 802.1Q VLAN support. Off by default; when off, all VLAN code is removed
 * by the preprocessor and behavior/ABI of the stack is unchanged.
 *
 * WOLFIP_VLAN_MAX is a hard cap on the number of *simultaneously live*
 * VLAN sub-interfaces. The capacity must fit alongside the physical
 * interface and, when loopback is enabled, also the loopback slot. */
#ifndef WOLFIP_VLAN
#define WOLFIP_VLAN 0
#endif
#ifndef WOLFIP_VLAN_MAX
#define WOLFIP_VLAN_MAX 4
#endif
#if WOLFIP_VLAN
#if WOLFIP_ENABLE_LOOPBACK
#define WOLFIP_VLAN_RESERVED_SLOTS 2 /* loopback + 1 physical */
#else
#define WOLFIP_VLAN_RESERVED_SLOTS 1 /* 1 physical */
#endif
#if (WOLFIP_MAX_INTERFACES < (WOLFIP_VLAN_RESERVED_SLOTS + WOLFIP_VLAN_MAX))
#error "WOLFIP_VLAN requires WOLFIP_MAX_INTERFACES >= 1 (physical) + (WOLFIP_ENABLE_LOOPBACK ? 1 : 0) + WOLFIP_VLAN_MAX"
#endif
#endif

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
/* Neighbor Discovery replaces ARP and is defined over link layers with
 * addresses. A non-Ethernet (raw IP) build has no link-layer address to
 * resolve, so only statically configured IPv6 peers would work. */
#error "WOLFIP_IPV6 currently requires ETHERNET"
#endif

/* Per-feature switches for IPv6 functionality that is not implemented yet.
 * Each one is flipped to 1 by the phase that implements it, which also
 * enables the matching requirement-derived tests. They are named (rather
 * than plain #if 0) so the amount of pending work stays greppable. */
#ifndef WOLFIP_IPV6_HAVE_EXTHDR
#define WOLFIP_IPV6_HAVE_EXTHDR 0
#endif
#ifndef WOLFIP_IPV6_HAVE_ICMP6
#define WOLFIP_IPV6_HAVE_ICMP6 0
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
#define WOLFIP_IPV6_HAVE_SOCKETS 0
#endif

/* Linux test configuration */
#define WOLFIP_IP "10.10.10.2"
#define HOST_STACK_IP "10.10.10.1"
#define WOLFIP_STATIC_DNS_IP "9.9.9.9"

#endif

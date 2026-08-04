#ifndef WOLFIP_H
#define WOLFIP_H
#include <stdint.h>

#if !defined(_SIZE_T) && !defined(_SIZE_T_DEFINED) && !defined(_SIZE_T_DECLARED) && \
    !defined(_BSD_SIZE_T_DEFINED_) && !defined(__DEFINED_size_t) && \
    !defined(__size_t_defined)
#if defined(__SIZE_TYPE__)
typedef __SIZE_TYPE__ size_t;
#elif defined(_MSC_VER)
#ifdef _WIN64
typedef unsigned __int64 size_t;
#else
typedef unsigned int size_t;
#endif
#else
typedef unsigned long size_t;
#endif
#define _SIZE_T
#define _SIZE_T_DEFINED
#define _SIZE_T_DECLARED
#define _BSD_SIZE_T_DEFINED_
#define __DEFINED_size_t
#define __size_t_defined
#endif

#ifndef WOLFIP_SOL_IP
#ifdef SOL_IP
#define WOLFIP_SOL_IP SOL_IP
#else
#define WOLFIP_SOL_IP 0
#endif
#endif

#ifndef WOLFIP_SOL_SOCKET
#ifdef SOL_SOCKET
#define WOLFIP_SOL_SOCKET SOL_SOCKET
#else
#define WOLFIP_SOL_SOCKET 1
#endif
#endif

#ifndef WOLFIP_SOL_PACKET
#ifdef SOL_PACKET
#define WOLFIP_SOL_PACKET SOL_PACKET
#else
#define WOLFIP_SOL_PACKET 263
#endif
#endif

#ifndef WOLFIP_IP_RECVTTL
#ifdef IP_RECVTTL
#define WOLFIP_IP_RECVTTL IP_RECVTTL
#else
#define WOLFIP_IP_RECVTTL 12
#endif
#endif

#ifndef WOLFIP_IP_HDRINCL
#ifdef IP_HDRINCL
#define WOLFIP_IP_HDRINCL IP_HDRINCL
#else
#define WOLFIP_IP_HDRINCL 3
#endif
#endif

#ifndef WOLFIP_SO_DONTROUTE
#ifdef SO_DONTROUTE
#define WOLFIP_SO_DONTROUTE SO_DONTROUTE
#else
#define WOLFIP_SO_DONTROUTE 5
#endif
#endif

#ifdef IP_MULTICAST
#ifndef WOLFIP_IP_ADD_MEMBERSHIP
#ifdef IP_ADD_MEMBERSHIP
#define WOLFIP_IP_ADD_MEMBERSHIP IP_ADD_MEMBERSHIP
#else
#define WOLFIP_IP_ADD_MEMBERSHIP 35
#endif
#endif

#ifndef WOLFIP_IP_DROP_MEMBERSHIP
#ifdef IP_DROP_MEMBERSHIP
#define WOLFIP_IP_DROP_MEMBERSHIP IP_DROP_MEMBERSHIP
#else
#define WOLFIP_IP_DROP_MEMBERSHIP 36
#endif
#endif

#ifndef WOLFIP_IP_MULTICAST_IF
#ifdef IP_MULTICAST_IF
#define WOLFIP_IP_MULTICAST_IF IP_MULTICAST_IF
#else
#define WOLFIP_IP_MULTICAST_IF 32
#endif
#endif

#ifndef WOLFIP_IP_MULTICAST_TTL
#ifdef IP_MULTICAST_TTL
#define WOLFIP_IP_MULTICAST_TTL IP_MULTICAST_TTL
#else
#define WOLFIP_IP_MULTICAST_TTL 33
#endif
#endif

#ifndef WOLFIP_IP_MULTICAST_LOOP
#ifdef IP_MULTICAST_LOOP
#define WOLFIP_IP_MULTICAST_LOOP IP_MULTICAST_LOOP
#else
#define WOLFIP_IP_MULTICAST_LOOP 34
#endif
#endif
#endif /* IP_MULTICAST */

/* Types */
struct wolfIP;
typedef uint32_t ip4;

/* Macros, compiler specific. */
#define PACKED __attribute__((packed))
/* ee16/ee32 convert between host and network (big-endian) byte order.
 * On a big-endian host (e.g. PowerPC e5500/e6500) host order already
 * matches network order, so these must be no-ops; only swap on a
 * little-endian host. */
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#  define ee16(x) ((uint16_t)(x))
#  define ee32(x) ((uint32_t)(x))
#elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#  define ee16(x) __builtin_bswap16(x)
#  define ee32(x) __builtin_bswap32(x)
#elif defined(_MSC_VER)  /* MSVC targets (x86/x64/ARM64) are little-endian */
#  define ee16(x) ((uint16_t)(((uint16_t)(x) >> 8) | ((uint16_t)(x) << 8)))
#  define ee32(x) ((uint32_t)(((uint32_t)(x) >> 24) | \
        (((uint32_t)(x) >> 8) & 0x0000FF00U) | \
        (((uint32_t)(x) << 8) & 0x00FF0000U) | ((uint32_t)(x) << 24)))
#else
#  error "Cannot determine byte order; define __BYTE_ORDER__"
#endif

/* IPv6 address type and helpers. Included unconditionally: the header holds
 * only a typedef and static inline functions, so it adds no code when IPv6 is
 * disabled and cannot alter the layout of any structure below. The parts of
 * IPv6 that *do* affect layout live behind WOLFIP_IPV6 inside wolfip.c, which
 * includes config.h. */
#include "wolfip6.h"

#ifndef WOLFIP_EAGAIN
#ifdef EAGAIN
#define WOLFIP_EAGAIN EAGAIN
#else
#define WOLFIP_EAGAIN (11)
#endif
#endif

#ifndef WOLFIP_EINVAL
#ifdef EINVAL
#define WOLFIP_EINVAL EINVAL
#else
#define WOLFIP_EINVAL (22)
#endif
#endif

#ifndef WOLFIP_ENOMEM
#ifdef ENOMEM
#define WOLFIP_ENOMEM ENOMEM
#else
#define WOLFIP_ENOMEM (12)
#endif
#endif

#ifndef WOLFIP_EACCES
#ifdef EACCES
#define WOLFIP_EACCES EACCES
#else
#define WOLFIP_EACCES (13)
#endif
#endif


#ifdef DEBUG
#include <stdio.h>
#define LOG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define LOG(fmt, ...) do{}while(0)
#endif

/* Device driver interface */

/* Optional Wi-Fi control surface. Populated only by Wi-Fi ports
 * (CYW43439, ESP32, etc.). For wired/Ethernet ports, the wifi_ops
 * pointer on wolfIP_ll_dev is NULL and these callbacks are ignored.
 *
 * The wolfIP supplicant (src/supplicant/) consumes this vtable when
 * present: scan + connect drive the chip's MAC layer, set_key installs
 * PTK/GTK after the 4-way handshake completes, and inbound EAPOL
 * frames (ethertype 0x888E) are demuxed to the supplicant before the
 * IP stack sees them.
 */
struct wolfIP_ll_dev; /* forward */

struct wolfIP_wifi_scan_entry {
    uint8_t  bssid[6];
    int8_t   rssi_dbm;
    uint8_t  channel;
    uint8_t  ssid_len;
    uint8_t  ssid[32];
    uint8_t  flags;           /* bit 0 = WPA2-PSK supported */
};

#define WOLFIP_WIFI_KEY_PAIRWISE 0
#define WOLFIP_WIFI_KEY_GROUP    1

struct wolfIP_wifi_ops {
    int (*scan)(struct wolfIP_ll_dev *ll,
                struct wolfIP_wifi_scan_entry *out, int max_entries);
    int (*connect)(struct wolfIP_ll_dev *ll,
                   const uint8_t *ssid, uint8_t ssid_len,
                   const uint8_t bssid[6]);
    int (*disconnect)(struct wolfIP_ll_dev *ll);
    int (*set_key)(struct wolfIP_ll_dev *ll,
                   int key_type,         /* PAIRWISE or GROUP */
                   uint8_t key_idx,
                   const uint8_t *key, uint16_t key_len);
    int (*get_bssid)(struct wolfIP_ll_dev *ll, uint8_t out_bssid[6]);
};

/* Optional embedded-switch control surface.
 *
 * Populated only by drivers for parts with a multi-port switch that the CPU
 * shares, which is what Ethernet ring-redundancy protocols require. The
 * motivating case is DLR (Device Level Ring, ODVA CIP Networks Library
 * Vol. 2 chapter 9, also IEC 61784-2): a DLR node has two ports on one MAC,
 * and the ring supervisor breaks the loop by blocking ordinary traffic on
 * one of them while still passing ring-protocol frames.
 *
 * wolfIP does not implement DLR. This vtable, together with the L2 protocol
 * hook below, is the contract a third-party DLR implementation needs from
 * the stack and from the driver, so that adding one later requires no
 * changes to the core.
 *
 * A note on timing, because it constrains any such implementation: wolfIP's
 * poll loop is millisecond-granular (wolfIP_poll takes `now` in
 * milliseconds) and its timer heap is built on that. DLR beacon intervals
 * are sub-millisecond. A DLR implementation must therefore drive beacon
 * transmission and the beacon timeout from its own hardware timer; the
 * stack's timers are not suitable and this vtable does not pretend
 * otherwise.
 */
struct wolfIP_switch_ops {
    /* Number of external ports behind this interface (2 for a DLR node). */
    int (*port_count)(struct wolfIP_ll_dev *ll);
    /* Per-port link state: 1 up, 0 down, negative on error. A ring
     * implementation needs the transition, not just the level, so drivers
     * that can report link change events should do so via link_changed. */
    int (*port_link_state)(struct wolfIP_ll_dev *ll, unsigned int port);
    /* Register a callback invoked when a port's link state changes. This is
     * what lets a ring detect a break in well under the beacon timeout. */
    int (*set_link_change_cb)(struct wolfIP_ll_dev *ll,
                              void (*cb)(void *ctx, unsigned int port,
                                         int up),
                              void *ctx);
    /* Block or unblock ordinary traffic on a port. A blocked port must
     * still pass frames whose ethertype has been claimed via
     * wolfIP_register_l2_handler(), otherwise the ring protocol cannot see
     * its own beacons across the block. */
    int (*port_set_blocked)(struct wolfIP_ll_dev *ll, unsigned int port,
                            int blocked);
    /* Flush the switch's learned MAC address table, for the whole device or
     * for one port. Required after a ring topology change, or traffic keeps
     * being forwarded towards the broken segment. */
    int (*flush_mac_table)(struct wolfIP_ll_dev *ll, int port_or_all);
    /* Transmit a raw frame out of one specific port, bypassing normal
     * forwarding. Ring protocols must be able to address each port
     * individually; wolfIP's ordinary send path targets an interface. */
    int (*send_on_port)(struct wolfIP_ll_dev *ll, unsigned int port,
                        void *buf, uint32_t len);
    /* Report which port a received frame arrived on, for the most recent
     * frame handed to the stack. Negative if the driver cannot tell. */
    int (*last_rx_port)(struct wolfIP_ll_dev *ll);
};

/* Struct to contain link-layer (ll) device description
 */
struct wolfIP_ll_dev {
    uint8_t mac[6];
    char ifname[16];
    uint8_t non_ethernet;
    uint32_t mtu;
    /* poll function */
    int (*poll)(struct wolfIP_ll_dev *ll, void *buf, uint32_t len);
    /* send function */
    int (*send)(struct wolfIP_ll_dev *ll, void *buf, uint32_t len);
    /* optional context private pointer */
    void *priv;
#if WOLFIP_VLAN
    /* 802.1Q VLAN sub-interface descriptor. When vlan_active is 0, this slot
     * is either a physical interface or a deleted/empty slot. */
    struct wolfIP_ll_dev *vlan_parent; /* NULL => physical; else points into ll_dev[] */
    uint16_t vlan_vid;                  /* 0..4094 */
    uint8_t  vlan_pcp;                  /* 0..7 (802.1p priority) */
    uint8_t  vlan_dei;                  /* 0..1 (drop-eligible indicator) */
    uint8_t  vlan_active;               /* 1 if this slot is a live sub-iface */
#endif
    /* Optional Wi-Fi vtable. NULL on Ethernet ports. Appended last so adding
     * it does not shift the offsets of the pre-existing members. */
    const struct wolfIP_wifi_ops *wifi_ops;
    /* Optional embedded-switch vtable. NULL on ordinary single-port drivers.
     * Appended last, after wifi_ops, for the same ABI reason. */
    const struct wolfIP_switch_ops *switch_ops;
};

/* Struct to contain an IP device configuration */
struct ipconf {
    struct wolfIP_ll_dev *ll;
    ip4 ip;
    ip4 mask;
    ip4 gw;
};

struct wolfIP_route_info {
    ip4 prefix;
    ip4 gateway;
    uint8_t prefix_len;
    uint8_t if_idx;
};

#ifdef IP_MULTICAST
struct wolfIP_mreq_addr {
    uint32_t s_addr;
};

struct wolfIP_ip_mreq {
    struct wolfIP_mreq_addr imr_multiaddr;
    struct wolfIP_mreq_addr imr_interface;
};
#endif

/* Socket interface */
#define MARK_TCP_SOCKET 0x100 /* Mark a socket as TCP */
#define MARK_UDP_SOCKET 0x200 /* Mark a socket as UDP */
#define MARK_ICMP_SOCKET 0x400 /* Mark a socket as ICMP */
#define MARK_RAW_SOCKET 0x800 /* Mark a socket as RAW */
#define MARK_PACKET_SOCKET 0x1000 /* Mark a socket as PACKET */

#define IS_SOCKET_TCP(fd) (((fd) & MARK_TCP_SOCKET) == MARK_TCP_SOCKET)
#define IS_SOCKET_UDP(fd) (((fd) & MARK_UDP_SOCKET) == MARK_UDP_SOCKET)
#define IS_SOCKET_ICMP(fd)(((fd) & MARK_ICMP_SOCKET) == MARK_ICMP_SOCKET)
#define IS_SOCKET_RAW(fd) (((fd) & MARK_RAW_SOCKET) == MARK_RAW_SOCKET)
#define IS_SOCKET_PACKET(fd) (((fd) & MARK_PACKET_SOCKET) == MARK_PACKET_SOCKET)
#define SOCKET_UNMARK(fd) ((fd) & 0xFF)

/* Compile-time sanity check for socket marks & number of sockets */
#if (MARK_TCP_SOCKET >= MARK_UDP_SOCKET)
#error "MARK_TCP_SOCKET must be less than MARK_UDP_SOCKET"
#endif

#if (MARK_UDP_SOCKET >= MARK_ICMP_SOCKET)
#error "MARK_UDP_SOCKET must be less than MARK_ICMP_SOCKET"
#endif

#if (MARK_ICMP_SOCKET >= MARK_RAW_SOCKET)
#error "MARK_ICMP_SOCKET must be less than MARK_RAW_SOCKET"
#endif

#if (MARK_RAW_SOCKET >= MARK_PACKET_SOCKET)
#error "MARK_RAW_SOCKET must be less than MARK_PACKET_SOCKET"
#endif

#if MAX_TCPSOCKETS > 255
#error "MAX_TCPSOCKETS must be less than 256"
#endif

#if MAX_UDPSOCKETS > 255
#error "MAX_UDPSOCKETS must be less than 256"
#endif

#if MAX_ICMPSOCKETS > 255
#error "MAX_ICMPSOCKETS must be less than 256"
#endif

#if WOLFIP_RAWSOCKETS
#if WOLFIP_MAX_RAWSOCKETS > 255
#error "WOLFIP_MAX_RAWSOCKETS must be less than 256"
#endif
#endif

#if WOLFIP_PACKET_SOCKETS
#if WOLFIP_MAX_PACKETSOCKETS > 255
#error "WOLFIP_MAX_PACKETSOCKETS must be less than 256"
#endif
#endif


#ifndef WOLF_POSIX
#define IPSTACK_SOCK_STREAM 1
#define IPSTACK_SOCK_DGRAM 2
#define IPSTACK_SOCK_RAW 3


struct wolfIP_sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    struct sin_addr { uint32_t s_addr; } sin_addr;
};
struct wolfIP_sockaddr { uint16_t sa_family; };
typedef uint32_t socklen_t;

/* Pull in the system socket types when available, but only declare
 * WOLFIP_HAVE_POSIX_TYPES once BOTH <sys/socket.h> AND <sys/uio.h> are
 * confirmed present. Zephyr is a special case: its POSIX socket layer
 * provides iovec/msghdr via macros from <sys/socket.h>, even though it
 * does not ship <sys/uio.h>.
 */
#ifdef __ZEPHYR__
#define WOLFIP_HAVE_POSIX_TYPES 1
#endif

/* WOLFIP_NO_SYS_HEADERS: opt out of probing for system socket headers. Some
 * bare-metal/RTOS SDKs (e.g. an lwIP posix-compat layer) put a <sys/socket.h>
 * on the include path that is NOT the host libc's -- it redefines iovec/msghdr
 * and a send() macro that collide with wolfIP. Define WOLFIP_NO_SYS_HEADERS to
 * skip the probe and use wolfIP's own POSIX type fallbacks below. */
#if defined(__has_include) && !defined(WOLFIP_NO_SYS_HEADERS)
#if __has_include(<sys/socket.h>)
#include <sys/socket.h>
#if !defined(WOLFIP_HAVE_POSIX_TYPES) && __has_include(<sys/uio.h>)
#include <sys/uio.h>
#define WOLFIP_HAVE_POSIX_TYPES 1
#endif
#endif
#endif

#ifndef WOLFIP_HAVE_POSIX_TYPES
struct iovec { void *iov_base; size_t iov_len; };
struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};
#endif

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_PACKET
#define AF_PACKET 17
#endif
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/uio.h>
#include <net/if.h>
#ifdef __has_include
#if __has_include(<netpacket/packet.h>)
#include <netpacket/packet.h>
#define wolfIP_sockaddr_ll sockaddr_ll
#endif
#endif
#define wolfIP_sockaddr_in sockaddr_in
#define wolfIP_sockaddr sockaddr
#define IPSTACK_SOCK_RAW SOCK_RAW
#endif

#ifndef wolfIP_sockaddr_ll
struct wolfIP_sockaddr_ll {
    unsigned short sll_family;
    unsigned short sll_protocol;
    int sll_ifindex;
    unsigned short sll_hatype;
    unsigned char sll_pkttype;
    unsigned char sll_halen;
    unsigned char sll_addr[8];
};
typedef struct wolfIP_sockaddr_ll wolfIP_sockaddr_ll;
#endif

/* AF_INET6 is not guaranteed to exist on a bare-metal target, and its value
 * is not the same everywhere: 10 on Linux, 28 on FreeBSD, 30 on macOS. When
 * a system header supplies one it wins; this is only the fallback, and it
 * matters solely for values crossing the wolfIP API boundary, never on the
 * wire. */
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* Per-interface address list.
 *
 * struct ipconf above holds the *primary* IPv4 address of an interface and
 * keeps doing so: it is reached by every board port and by wolfIP_ipconfig_*,
 * and none of that changes. This list is additive - it holds the additional
 * addresses, meaning IPv4 aliases and every IPv6 address. The primary is
 * never copied into it, so the two cannot drift apart.
 *
 * Index 0 of an interface's IPv4 list is therefore always the primary, and
 * higher indices are aliases in insertion order.
 *
 * WOLFIP_IF_CONF_MAX caps the total per interface, primary included. It is 1
 * unless WOLFIP_IF_MULTICONF is enabled, so with the feature off these calls
 * still work but an interface holds exactly one address and struct wolfIP
 * does not grow at all. IPv6 requires the feature, because a link-local
 * address always coexists with any global one; IPv4 aliasing is the same
 * machinery and is available without IPv6.
 */
#define WOLFIP_IFADDR_PREFERRED  0
#define WOLFIP_IFADDR_TENTATIVE  1  /* IPv6: duplicate address detection */
#define WOLFIP_IFADDR_DEPRECATED 2  /* IPv6: preferred lifetime expired */

#define WOLFIP_IFADDR_FLAG_PRIMARY   0x01
#define WOLFIP_IFADDR_FLAG_LINKLOCAL 0x02
#define WOLFIP_IFADDR_FLAG_SLAAC     0x04
#define WOLFIP_IFADDR_FLAG_DHCP      0x08

struct wolfIP_ifaddr_info {
    uint16_t family;      /* AF_INET or AF_INET6 */
    uint8_t  if_idx;
    uint8_t  prefix_len;
    uint8_t  state;       /* WOLFIP_IFADDR_* */
    uint8_t  flags;       /* WOLFIP_IFADDR_FLAG_* */
    ip4      v4;          /* valid when family == AF_INET */
    ip6      v6;          /* valid when family == AF_INET6 */
    uint32_t valid_lifetime;      /* seconds; 0 means unlimited */
    uint32_t preferred_lifetime;  /* seconds; 0 means unlimited */
};

/* Add an address. Returns 0, or negative on a bad argument, a duplicate, or
 * when the interface has reached WOLFIP_IF_CONF_MAX. Adding the first IPv4
 * address of an interface sets the primary, so a single-address build is
 * fully usable through this API alone. */
int wolfIP_ifaddr_add4(struct wolfIP *s, unsigned int if_idx, ip4 addr,
                       uint8_t prefix_len);
int wolfIP_ifaddr_add6(struct wolfIP *s, unsigned int if_idx, const ip6 *addr,
                       uint8_t prefix_len);

/* Remove an address. Returns 0, or negative if it is not configured on that
 * interface. Removing the primary does not disturb the aliases. */
int wolfIP_ifaddr_del4(struct wolfIP *s, unsigned int if_idx, ip4 addr);
int wolfIP_ifaddr_del6(struct wolfIP *s, unsigned int if_idx, const ip6 *addr);

/* Number of addresses of `family` on an interface. Zero for a bad argument,
 * an unknown family, or an unconfigured interface. */
unsigned int wolfIP_ifaddr_count(struct wolfIP *s, unsigned int if_idx,
                                 int family);

/* Fetch the index'th address of `family`. Returns 0 on success. */
int wolfIP_ifaddr_get(struct wolfIP *s, unsigned int if_idx, int family,
                      unsigned int index, struct wolfIP_ifaddr_info *out);

/* Is this IPv4 address configured on any interface? Returns 1 and, when
 * if_idx is non-NULL, the owning interface. Aliases count: an address that
 * did not would be decorative, since inbound traffic to it would be
 * dropped. IPADDR_ANY is never local. */
int wolfIP_ifaddr_is_local4(struct wolfIP *s, ip4 addr, unsigned int *if_idx);

int wolfIP_sock_socket(struct wolfIP *s, int domain, int type, int protocol);
int wolfIP_sock_bind(struct wolfIP *s, int sockfd, const struct wolfIP_sockaddr *addr,
                     socklen_t addrlen);
int wolfIP_sock_listen(struct wolfIP *s, int sockfd, int backlog);
int wolfIP_sock_accept(struct wolfIP *s, int sockfd, struct wolfIP_sockaddr *addr,
                       socklen_t *addrlen);
int wolfIP_sock_connect(struct wolfIP *s, int sockfd, const struct wolfIP_sockaddr *addr,
                        socklen_t addrlen);
int wolfIP_sock_sendto(struct wolfIP *s, int sockfd, const void *buf, size_t len,
                       int flags, const struct wolfIP_sockaddr *dest_addr,
                       socklen_t addrlen);
int wolfIP_sock_send(struct wolfIP *s, int sockfd, const void *buf, size_t len,
                     int flags);
int wolfIP_sock_write(struct wolfIP *s, int sockfd, const void *buf, size_t len);
int wolfIP_sock_recvfrom(struct wolfIP *s, int sockfd, void *buf, size_t len,
                         int flags, struct wolfIP_sockaddr *src_addr, socklen_t *addrlen);
int wolfIP_sock_recv(struct wolfIP *s, int sockfd, void *buf, size_t len, int flags);
int wolfIP_sock_sendmsg(struct wolfIP *s, int sockfd, const struct msghdr *msg,
                        int flags);
int wolfIP_sock_recvmsg(struct wolfIP *s, int sockfd, struct msghdr *msg,
                        int flags);
int wolfIP_dns_ptr_lookup(struct wolfIP *s, uint32_t ip, uint16_t *id,
                          void (*lookup_cb)(const char *name));
int wolfIP_sock_get_recv_ttl(struct wolfIP *s, int sockfd, int *ttl);
int wolfIP_sock_setsockopt(struct wolfIP *s, int sockfd, int level, int optname,
                           const void *optval, socklen_t optlen);
int wolfIP_sock_getsockopt(struct wolfIP *s, int sockfd, int level, int optname,
                           void *optval, socklen_t *optlen);
int wolfIP_sock_read(struct wolfIP *s, int sockfd, void *buf, size_t len);
int wolfIP_sock_close(struct wolfIP *s, int sockfd);
int wolfIP_sock_getpeername(struct wolfIP *s, int sockfd, struct wolfIP_sockaddr *addr,
                            const socklen_t *addrlen);
int wolfIP_sock_getsockname(struct wolfIP *s, int sockfd, struct wolfIP_sockaddr *addr,
                            const socklen_t *addrlen);
int wolfIP_sock_can_read(struct wolfIP *s, int sockfd);
int wolfIP_sock_can_write(struct wolfIP *s, int sockfd);

int dhcp_client_init(struct wolfIP *s);
int dhcp_bound(struct wolfIP *s);
int dhcp_client_is_running(struct wolfIP *s);
int wolfIP_dns_server_get(struct wolfIP *s, ip4 *dns_server);

/* DNS client */

int nslookup(struct wolfIP *s, const char *name, uint16_t *id,
             void (*lookup_cb)(uint32_t ip));

#if CONFIG_IPFILTER
#include "wolfip-filter.h"
#endif

/* IP stack interface */
void wolfIP_init(struct wolfIP *s);
void wolfIP_init_static(struct wolfIP **s);

/* Register a callback invoked by wolfIP_recv_on() whenever an inbound
 * Ethernet frame on a Wi-Fi interface (ll->wifi_ops != NULL) carries
 * ethertype 0x888E (EAPOL / 802.1X). The supplicant module
 * (src/supplicant/) wires itself in here to receive 4-way handshake
 * and Group Key handshake frames. `frame`/`len` cover the 802.1X
 * payload only (Ethernet header already stripped). Pass NULL handler
 * to unregister. Returns 0 on success, negative if s is NULL. */
int wolfIP_register_eapol_handler(struct wolfIP *s,
                                  int (*handler)(void *ctx,
                                                 unsigned int if_idx,
                                                 const uint8_t *frame,
                                                 uint32_t len),
                                  void *ctx);
/* Generic link-layer protocol hook.
 *
 * wolfIP_register_eapol_handler() above is hardwired to ethertype 0x888E.
 * This is the same idea without the hardwiring: a module claims an
 * ethertype and receives every frame carrying it, so that protocols the
 * stack does not implement can be layered on without editing the demux.
 *
 * The motivating consumer is a third-party DLR (Device Level Ring)
 * implementation, which claims ethertype 0x80E1 and drives the switch
 * through struct wolfIP_switch_ops. Nothing here is DLR-specific.
 *
 * `accept_macs` addresses the second half of the problem. The ingress path
 * filters on destination MAC before dispatch - unicast to us, broadcast,
 * and the IP multicast mappings - so a protocol using its own multicast
 * group would never see a frame. A registered handler declares the
 * destination MACs it wants delivered; `count` entries of 6 bytes each,
 * matched exactly. Pass NULL/0 to receive only unicast and broadcast.
 *
 * `frame`/`len` cover the whole Ethernet frame including the header, since
 * a ring protocol needs the source MAC and the ingress port. The ingress
 * port, when the driver can report it, comes from
 * switch_ops->last_rx_port().
 *
 * Returns 0 on success, negative on bad arguments or when the table of
 * registered protocols is full. Pass a NULL handler to unregister.
 *
 * NOTE: declared, not yet implemented. See docs/dlr_integration.md.
 */
int wolfIP_register_l2_handler(struct wolfIP *s, uint16_t ethertype,
                               int (*handler)(void *ctx, unsigned int if_idx,
                                              const uint8_t *frame,
                                              uint32_t len),
                               void *ctx,
                               const uint8_t *accept_macs, unsigned int count);

size_t wolfIP_instance_size(void);
int wolfIP_poll(struct wolfIP *s, uint64_t now);
void wolfIP_recv(struct wolfIP *s, void *buf, uint32_t len);
void wolfIP_recv_ex(struct wolfIP *s, unsigned int if_idx, void *buf, uint32_t len);
void wolfIP_ipconfig_set(struct wolfIP *s, ip4 ip, ip4 mask, ip4 gw);
void wolfIP_ipconfig_get(struct wolfIP *s, ip4 *ip, ip4 *mask, ip4 *gw);

struct wolfIP_ll_dev *wolfIP_getdev(struct wolfIP *s);
struct wolfIP_ll_dev *wolfIP_getdev_ex(struct wolfIP *s, unsigned int if_idx);
int wolfIP_mtu_set(struct wolfIP *s, unsigned int if_idx, uint32_t mtu);
int wolfIP_mtu_get(struct wolfIP *s, unsigned int if_idx, uint32_t *mtu);
void wolfIP_ipconfig_set_ex(struct wolfIP *s, unsigned int if_idx, ip4 ip, ip4 mask, ip4 gw);
void wolfIP_ipconfig_get_ex(struct wolfIP *s, unsigned int if_idx, ip4 *ip, ip4 *mask, ip4 *gw);
int wolfIP_arp_lookup_ex(struct wolfIP *s, unsigned int if_idx, ip4 ip, uint8_t *mac);
#if WOLFIP_ENABLE_FORWARDING
int wolfIP_route_add(struct wolfIP *s, unsigned int if_idx, ip4 prefix,
                     uint8_t prefix_len, ip4 gateway);
int wolfIP_route_delete(struct wolfIP *s, unsigned int if_idx, ip4 prefix,
                        uint8_t prefix_len);
int wolfIP_route_lookup(struct wolfIP *s, ip4 dest, unsigned int *if_idx,
                        ip4 *nexthop);
int wolfIP_route_get(struct wolfIP *s, unsigned int route_idx,
                     struct wolfIP_route_info *info);
unsigned int wolfIP_route_count(struct wolfIP *s);
#endif /* WOLFIP_ENABLE_FORWARDING */

#if WOLFIP_VLAN
/* 802.1Q VLAN sub-interface management.
 *
 * A VLAN sub-interface is a logical interface that sits on top of a physical
 * (untagged) interface. Frames sent out of a sub-interface are 802.1Q-tagged
 * with the configured VID/PCP/DEI; frames arriving on the physical interface
 * with a matching tag are stripped and delivered as if they had arrived on
 * the sub-interface. Each sub-interface gets its own ipconf slot (own IP,
 * mask, gateway, DHCP, ARP table behavior).
 *
 * Returns 0 on success, -WOLFIP_EINVAL on validation failure (null stack,
 * bad parent index, parent not physical, VID >= 4095, PCP > 7, DEI > 1,
 * duplicate VID on the same parent, no free ll_dev slot, exhausted
 * WOLFIP_VLAN_MAX).
 */
int wolfIP_vlan_create(struct wolfIP *s, unsigned int parent_if_idx,
                       uint16_t vid, uint8_t pcp, uint8_t dei,
                       unsigned int *out_if_idx);

/* Remove a VLAN sub-interface. Refuses to delete a physical interface or an
 * already-inactive slot. The slot is marked inactive (vlan_active = 0) but
 * the index remains valid; subsequent wolfIP_vlan_create may reuse it. */
int wolfIP_vlan_delete(struct wolfIP *s, unsigned int if_idx);

/* Query VLAN configuration on a sub-interface. Returns -WOLFIP_EINVAL if
 * if_idx is not a live sub-interface or any output pointer is NULL. */
int wolfIP_vlan_get(struct wolfIP *s, unsigned int if_idx,
                    unsigned int *parent_if_idx, uint16_t *vid,
                    uint8_t *pcp, uint8_t *dei);
#endif /* WOLFIP_VLAN */

/* Callback flags */
#define CB_EVENT_READABLE 0x01 /* Accepted connection or data available */
#define CB_EVENT_TIMEOUT 0x02  /* Timeout */
#define CB_EVENT_WRITABLE 0x04 /* Connected or space available to send */
#define CB_EVENT_CLOSED 0x10   /* Connection closed by peer */
typedef void (*tsocket_cb)(int sock_fd, uint16_t events, void *arg);
void wolfIP_register_callback(struct wolfIP *s, int sock_fd, tsocket_cb cb,
                              void *arg);

/* External requirements */
uint32_t wolfIP_getrandom(void);

/* Inline utility functions */
static inline uint32_t atou(const char *s)
{
    uint32_t ret = 0;
    while (*s >= '0' && *s <= '9') {
        ret = (ret * 10u) + (uint32_t)(*s - '0');
        s++;
    }
    return ret;
}

static inline ip4 atoip4(const char *ip)
{
    ip4 ret = 0;
    int i = 0;
    int j = 0;
    for (i = 0; i < 4; i++) {
        ret |= (atou(ip + j) << (24 - i * 8));
        while (ip[j] != '.' && ip[j] != '\0') j++;
        if (ip[j] == '\0') break;
        j++;
    }
    return ret;
}

static inline void iptoa(ip4 ip, char *buf)
{
    int i, j = 0;
    buf[0] = 0;
    for (i = 0; i < 4; i++) {
        uint8_t x = (ip >> (24 - i * 8)) & 0xFF;
        if (x > 99) buf[j++] = (char)(x / 100 + '0');
        if (x > 9) buf[j++] = (char)(((x / 10) % 10) + '0');
        buf[j++] = (char)((x % 10) + '0');
        if (i < 3) buf[j++] = '.';
    }
    buf[j] = 0;
}

#ifdef WOLFSSL_WOLFIP
    #ifdef WOLFSSL_USER_SETTINGS
        #include "user_settings.h"
    #else
        #include <wolfssl/options.h>
    #endif /* WOLFSSL_USER_SETTINGS */
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/ssl.h>
    int wolfSSL_SetIO_wolfIP(WOLFSSL* ssl, int fd);
    int wolfSSL_SetIO_wolfIP_CTX(WOLFSSL_CTX *ctx, struct wolfIP *s);
    void wolfSSL_CleanupIO_wolfIP(WOLFSSL* ssl);

    #ifdef  WOLFIP_ESP
        #include <wolfssl/wolfcrypt/aes.h>
        #include <wolfssl/wolfcrypt/des3.h>
        #include <wolfssl/wolfcrypt/hmac.h>
        #include <wolfssl/wolfcrypt/random.h>
    #endif /* WOLFIP_ESP */
#endif /* WOLFSSL_WOLFIP */

#endif /* !WOLFIP_H */

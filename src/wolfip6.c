/* wolfip6.c
 *
 * IPv6 header encapsulation and parsing for the wolfIP TCP/IP stack.
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

/* This file is textually included into src/wolfip.c under #if WOLFIP_IPV6,
 * after ip_output_add_header(), the same way src/wolfesp.c is included. It is
 * not a separate translation unit: struct wolfIP and the checksum, Ethernet
 * and link-layer helpers it needs are all static symbols inside wolfip.c.
 *
 * Scope of this file today is deliberately narrow: the IPv6 header itself.
 * Parsing and validation on receive, encapsulation on transmit, and the
 * upper-layer checksum that both need. ICMPv6, Neighbor Discovery, SLAAC and
 * DHCPv6 are not here yet; the receive path classifies what it cannot handle
 * and reports a distinct reason rather than pretending to process it.
 */

/* ---------------------------------------------------------------------- */
/* Constants                                                              */
/* ---------------------------------------------------------------------- */

#define IP6_HEADER_LEN 40
/* Guarded on the macro being defined at all, not just on its value: this
 * file is #included into src/wolfip.c and never compiled alone, but static
 * analysers do parse it alone, and an undefined macro in #if evaluates to 0
 * and would trip the check. wolfip.c cannot compile without
 * IP6_HEADER_LEN_PUB, so nothing is lost by skipping the comparison when it
 * is absent. */
#ifdef IP6_HEADER_LEN_PUB
#if IP6_HEADER_LEN != IP6_HEADER_LEN_PUB
#error "IP6_HEADER_LEN and IP6_HEADER_LEN_PUB disagree"
#endif
#endif
#define IP6_VERSION 6
#define IP6_HOP_LIMIT_DEFAULT 64
/* RFC 8200 section 5: every IPv6 link must carry 1280 octets, and a node
 * that cannot fragment may always assume that much. It is the floor the
 * transmit paths clamp to when an interface reports something smaller. */
#define IP6_MIN_MTU 1280

/* Next Header values (RFC 8200 section 4.1). The extension headers are
 * listed so the receive path can name what it is refusing, rather than
 * lumping them in with unknown protocols. */
#define IP6_NEXTHDR_HOPOPT   0
#define IP6_NEXTHDR_TCP      6
#define IP6_NEXTHDR_UDP     17
#define IP6_NEXTHDR_ROUTING 43
#define IP6_NEXTHDR_FRAGMENT 44
#define IP6_NEXTHDR_ESP     50
#define IP6_NEXTHDR_AH      51
#define IP6_NEXTHDR_ICMPV6  58
#define IP6_NEXTHDR_NONE    59
#define IP6_NEXTHDR_DSTOPTS 60

/* ICMPv6 message types (RFC 4443 sections 4.1 and 4.2, RFC 4861 section 4). */
/* Error messages (RFC 4443 section 3). Types below 128 are errors, 128 and
 * above are informational, and the split governs how an unrecognised type
 * is handled (section 2.4 (b)). */
#define ICMP6_DEST_UNREACH     1
#define ICMP6_PACKET_TOO_BIG   2
#define ICMP6_TIME_EXCEEDED    3
#define ICMP6_PARAM_PROBLEM    4

/* Destination Unreachable codes (RFC 4443 section 3.1). */
#define ICMP6_DST_NO_ROUTE     0
#define ICMP6_DST_PROHIBITED   1
#define ICMP6_DST_BEYOND_SCOPE 2
#define ICMP6_DST_ADDR_UNREACH 3
#define ICMP6_DST_PORT_UNREACH 4

/* Time Exceeded codes (RFC 4443 section 3.3). */
#define ICMP6_TIME_HOP_LIMIT   0
#define ICMP6_TIME_FRAGMENT    1

/* Parameter Problem codes (RFC 4443 section 3.4). */
#define ICMP6_PARAM_HEADER     0
#define ICMP6_PARAM_NEXTHDR    1
#define ICMP6_PARAM_OPTION     2

/* Type 128 is the first informational type. */
#define ICMP6_INFORMATIONAL_MIN 128

#define ICMP6_ECHO_REQUEST     128
#define ICMP6_ECHO_REPLY       129
#define ICMP6_ROUTER_SOLICIT   133
#define ICMP6_ROUTER_ADVERT    134
#define ICMP6_NEIGHBOR_SOLICIT 135
#define ICMP6_NEIGHBOR_ADVERT  136
#define ICMP6_REDIRECT         137

/* An Echo message carries type, code and checksum, then an identifier and a
 * sequence number: eight bytes before any payload. */
#define ICMP6_ECHO_MIN_LEN 8

/* Minimum bytes an upper-layer header needs before it can be parsed. */
#define IP6_MIN_TCP_LEN 20
#define IP6_MIN_UDP_LEN 8
#define IP6_MIN_ICMPV6_LEN 4

/* Outcome of ip6_recv(). Zero means the packet was accepted; every rejection
 * has its own value so the malformed-input tests can assert precisely why a
 * frame was dropped instead of merely that it was. */
enum ip6_recv_result {
    IP6_ACCEPTED = 0,
    IP6_DROP_SHORT_FRAME = -1,
    IP6_DROP_BAD_VERSION = -2,
    IP6_DROP_TRUNCATED_PAYLOAD = -3,
    IP6_DROP_MCAST_SOURCE = -4,
    IP6_DROP_LOOPBACK_ON_WIRE = -5,
    IP6_DROP_V4MAPPED_ON_WIRE = -6,
    IP6_DROP_V4COMPAT_ON_WIRE = -7,
    IP6_DROP_MCAST_DESTINATION_IS_SOURCE_ONLY = -8,
    IP6_DROP_EXTENSION_HEADER = -9,
    IP6_DROP_UNKNOWN_NEXTHDR = -10,
    IP6_DROP_SHORT_TRANSPORT = -11,
    IP6_DROP_UNSPECIFIED_DESTINATION = -12
};

/* ---------------------------------------------------------------------- */
/* Wire structures                                                        */
/* ---------------------------------------------------------------------- */

/* The IPv4 structures in wolfip.c embed the link-layer and network headers
 * by value, so the transport payload sits at a fixed offset of eth(14) +
 * ip(20). The IPv6 header is 40 bytes, so these are parallel definitions
 * rather than a reuse of the IPv4 ones; there is no headroom mechanism to
 * borrow. */
struct PACKED wolfIP_ip6_packet {
#ifdef ETHERNET
    struct wolfIP_eth_frame eth;
#endif
    uint32_t ver_tc_fl;   /* version(4) | traffic class(8) | flow label(20) */
    uint16_t payload_len;
    uint8_t next_hdr;
    uint8_t hop_limit;
    uint8_t src[16];
    uint8_t dst[16];
    uint8_t data[0];
};

/* The same header without the Ethernet prefix, for quoting inside ICMPv6
 * error messages later (mirrors struct wolfIP_ip_wire). */
struct PACKED wolfIP_ip6_wire {
    uint32_t ver_tc_fl;
    uint16_t payload_len;
    uint8_t next_hdr;
    uint8_t hop_limit;
    uint8_t src[16];
    uint8_t dst[16];
    uint8_t data[0];
};

struct PACKED wolfIP_tcp6_seg {
    struct wolfIP_ip6_packet ip6;
    uint16_t src_port, dst_port;
    uint32_t seq, ack;
    uint8_t hlen, flags;
    uint16_t win, csum, urg;
    uint8_t data[0];
};

struct PACKED wolfIP_udp6_datagram {
    struct wolfIP_ip6_packet ip6;
    uint16_t src_port, dst_port, len, csum;
    uint8_t data[0];
};

struct PACKED wolfIP_icmp6_packet {
    struct wolfIP_ip6_packet ip6;
    uint8_t type, code;
    uint16_t csum;
    uint8_t data[0];
};

/* The IPv6 pseudo-header (RFC 8200 section 8.1): 40 bytes, with a 32-bit
 * upper-layer length and the next header in the last octet. Structurally
 * different enough from the IPv4 one that it gets its own union and its own
 * checksum routine rather than a widened shared version. */
union transport6_pseudo_header {
    struct PACKED ph6 {
        uint8_t src[16];
        uint8_t dst[16];
        uint32_t len;
        uint8_t zero[3];
        uint8_t proto;
    } ph;
    uint16_t buf[20];
};

/* IPv6 multicast maps onto 33:33:xx:xx:xx:xx (RFC 2464 section 7). Used by
 * the ingress MAC filter, which would otherwise discard every Neighbor
 * Discovery and Router Advertisement frame as "not for us". */
static inline int eth_is_ipv6_multicast_mac(const uint8_t *mac)
{
    return ((mac[0] == 0x33) && (mac[1] == 0x33)) ? 1 : 0;
}

/* ---------------------------------------------------------------------- */
/* Header field accessors                                                 */
/* ---------------------------------------------------------------------- */

static inline uint8_t ip6_hdr_version(const struct wolfIP_ip6_packet *pkt)
{
    return (uint8_t)((ee32(pkt->ver_tc_fl) >> 28) & 0x0Fu);
}

static inline uint8_t ip6_hdr_traffic_class(const struct wolfIP_ip6_packet *pkt)
{
    return (uint8_t)((ee32(pkt->ver_tc_fl) >> 20) & 0xFFu);
}

static inline uint32_t ip6_hdr_flow_label(const struct wolfIP_ip6_packet *pkt)
{
    return ee32(pkt->ver_tc_fl) & 0xFFFFFu;
}

static inline void ip6_hdr_set_vtf(struct wolfIP_ip6_packet *pkt,
                                   uint8_t traffic_class, uint32_t flow_label)
{
    uint32_t v = ((uint32_t)IP6_VERSION << 28) |
                 ((uint32_t)traffic_class << 20) |
                 (flow_label & 0xFFFFFu);

    pkt->ver_tc_fl = ee32(v);
}

/* The address fields are plain byte arrays on the wire, so they are copied
 * in and out rather than aliased: the header sits at an odd offset behind
 * the 14-byte Ethernet header, and wolfIP runs on strict-alignment targets. */
static inline void ip6_hdr_get_src(const struct wolfIP_ip6_packet *pkt, ip6 *out)
{
    int i;

    for (i = 0; i < 16; i++)
        out->addr[i] = pkt->src[i];
}

static inline void ip6_hdr_get_dst(const struct wolfIP_ip6_packet *pkt, ip6 *out)
{
    int i;

    for (i = 0; i < 16; i++)
        out->addr[i] = pkt->dst[i];
}

static inline void ip6_hdr_set_src(struct wolfIP_ip6_packet *pkt, const ip6 *a)
{
    int i;

    for (i = 0; i < 16; i++)
        pkt->src[i] = a->addr[i];
}

static inline void ip6_hdr_set_dst(struct wolfIP_ip6_packet *pkt, const ip6 *a)
{
    int i;

    for (i = 0; i < 16; i++)
        pkt->dst[i] = a->addr[i];
}

/* ---------------------------------------------------------------------- */
/* Checksums                                                              */
/* ---------------------------------------------------------------------- */

/* Fill the pseudo-header for an upper-layer checksum. upper_len is the
 * length of the upper-layer header plus its payload. */
static void transport6_pseudo_header_init(union transport6_pseudo_header *ph,
                                          const ip6 *src, const ip6 *dst,
                                          uint32_t upper_len, uint8_t next_hdr)
{
    int i;

    for (i = 0; i < 16; i++) {
        ph->ph.src[i] = src->addr[i];
        ph->ph.dst[i] = dst->addr[i];
    }
    ph->ph.len = ee32(upper_len);
    ph->ph.zero[0] = 0;
    ph->ph.zero[1] = 0;
    ph->ph.zero[2] = 0;
    ph->ph.proto = next_hdr;
}

/* One's complement sum over the 40-byte pseudo-header followed by the
 * upper-layer data, per RFC 1071. The data length is taken from the
 * pseudo-header, which the caller has already validated against the frame. */
static uint16_t transport6_checksum(union transport6_pseudo_header *ph,
                                    const void *_data)
{
    uint32_t sum = 0;
    uint32_t i;
    const uint8_t *ptr = (const uint8_t *)ph->buf;
    const uint8_t *data = (const uint8_t *)_data;
    uint32_t len = ee32(ph->ph.len);
    uint16_t word;

    for (i = 0; i < 40u; i += 2) {
        memcpy(&word, ptr + i, sizeof(word));
        sum += ee16(word);
    }
    for (i = 0; i < (len & ~1u); i += 2) {
        memcpy(&word, data + i, sizeof(word));
        sum += ee16(word);
    }
    if ((len & 0x01u) != 0) {
        uint16_t spare = (uint16_t)((uint16_t)data[len - 1] << 8);

        sum += spare;
    }
    while ((sum >> 16) != 0)
        sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static int transport6_verify_checksum(union transport6_pseudo_header *ph,
                                      const void *data)
{
    return (transport6_checksum(ph, data) == 0) ? 0 : -1;
}

/* ---------------------------------------------------------------------- */
/* Receive path                                                           */
/* ---------------------------------------------------------------------- */

/* Is this Next Header value an extension header we deliberately refuse?
 *
 * Phase 0 parses the upper-layer header only. Walking a Next Header chain is
 * a well known denial-of-service surface (nested and looping option headers),
 * so rather than half-implement it these are recognised and dropped with a
 * reason of their own. */
static int ip6_nexthdr_is_extension(uint8_t next_hdr)
{
    switch (next_hdr) {
        case IP6_NEXTHDR_HOPOPT:
        case IP6_NEXTHDR_ROUTING:
        case IP6_NEXTHDR_FRAGMENT:
        case IP6_NEXTHDR_ESP:
        case IP6_NEXTHDR_AH:
        case IP6_NEXTHDR_DSTOPTS:
        case IP6_NEXTHDR_NONE:
            return 1;
        default:
            return 0;
    }
}

/* Smallest upper-layer header for a Next Header we accept, or 0 if we do not
 * recognise it as an upper-layer protocol at all. */
static uint32_t ip6_upper_min_len(uint8_t next_hdr)
{
    switch (next_hdr) {
        case IP6_NEXTHDR_TCP:
            return IP6_MIN_TCP_LEN;
        case IP6_NEXTHDR_UDP:
            return IP6_MIN_UDP_LEN;
        case IP6_NEXTHDR_ICMPV6:
            return IP6_MIN_ICMPV6_LEN;
        default:
            return 0;
    }
}

static void icmp6_input(struct wolfIP *s, unsigned int if_idx,
                        struct wolfIP_ip6_packet *pkt, uint32_t len);
static unsigned int wolfIP_if_for_local_ip6(struct wolfIP *s,
                                            unsigned int ingress_if,
                                            const ip6 *addr, int *found);
static void icmp6_send_error(struct wolfIP *s, unsigned int if_idx,
                             const struct wolfIP_ip6_packet *orig,
                             uint32_t orig_frame_len, uint8_t type,
                             uint8_t code, uint32_t param);
static void icmp6_try_recv(struct wolfIP *s, unsigned int if_idx,
                           struct wolfIP_icmp6_packet *icmp,
                           uint32_t frame_len);
static int icmp6_type_is_error(uint8_t type);
static uint32_t udp6_max_payload(struct wolfIP *s, unsigned int if_idx);
static int sock_addr_from_ip6(struct wolfIP_sockaddr *addr, socklen_t *addrlen,
                              const ip6 *v6, uint16_t port,
                              unsigned int scope_id);
static void udp6_try_recv(struct wolfIP *s, unsigned int if_idx,
                          struct wolfIP_udp6_datagram *udp, uint32_t frame_len);
static void tcp6_input(struct wolfIP *s, unsigned int if_idx,
                       struct wolfIP_tcp6_seg *seg, uint32_t frame_len);
static int ip6_select_source(struct wolfIP *s, unsigned int if_idx,
                             const ip6 *dst, ip6 *src);
static unsigned int ip6_route_for_dest(struct wolfIP *s, const ip6 *dst);
static int nd6_resolve(struct wolfIP *s, unsigned int *tx_if, const ip6 *dst,
                       uint8_t *mac);
static void tcp_input_flow(struct wolfIP *S, unsigned int if_idx,
                           struct wolfIP_tcp_seg *tcp, uint32_t frame_len,
                           const struct ip_flow *flow);

/* Validate an inbound IPv6 packet.
 *
 * Returns IP6_ACCEPTED when the header is well formed and carries an
 * upper-layer protocol we handle, otherwise a negative ip6_recv_result
 * saying why it was rejected.
 *
 * `len` is the whole frame length including the Ethernet header. Note the
 * frame may legitimately be *longer* than the header plus payload_len:
 * Ethernet pads anything under 60 bytes, so the length check is "at least",
 * never "exactly".
 *
 * Deliberately NOT checked here: the hop limit. RFC 8200 section 3 has the
 * hop limit decremented and tested by forwarding nodes only; a destination
 * host must accept a packet addressed to it even with a hop limit of zero.
 * Dropping such packets is a common bug, so there is a test asserting the
 * RFC behaviour.
 */
static int ip6_recv(struct wolfIP *s, unsigned int if_idx,
                    struct wolfIP_ip6_packet *pkt, uint32_t len)
{
    uint32_t payload_len;
    uint32_t min_upper;
    ip6 src;
    ip6 dst;

    if (len < (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN))
        return IP6_DROP_SHORT_FRAME;
    if (ip6_hdr_version(pkt) != IP6_VERSION)
        return IP6_DROP_BAD_VERSION;

    payload_len = ee16(pkt->payload_len);
    /* Ethernet padding means the frame can be longer, never shorter. */
    if (len < ((uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) + payload_len))
        return IP6_DROP_TRUNCATED_PAYLOAD;

    ip6_hdr_get_src(pkt, &src);
    ip6_hdr_get_dst(pkt, &dst);

    /* RFC 4291 section 2.7: a multicast address is never a valid source. */
    if (ip6_is_multicast(&src))
        return IP6_DROP_MCAST_SOURCE;
    /* RFC 4291 section 2.5.2: the unspecified address must never be a
     * destination. It is legitimate as a source, during duplicate address
     * detection, so only the destination is rejected here. */
    if (ip6_is_unspecified(&dst))
        return IP6_DROP_UNSPECIFIED_DESTINATION;
    /* RFC 4291 section 2.5.3: ::1 must never appear on a real link. */
    if (ip6_is_loopback(&src) || ip6_is_loopback(&dst))
        return IP6_DROP_LOOPBACK_ON_WIRE;
    /* RFC 4291 section 2.5.5.2: IPv4-mapped addresses exist only inside the
     * socket API. Seeing one on the wire means either a broken peer or an
     * attempt to smuggle an IPv4 identity through the IPv6 path, which
     * matters here because wolfIP presents v4-mapped addresses to
     * dual-stack AF_INET6 sockets. */
    if (ip6_is_v4mapped(&src) || ip6_is_v4mapped(&dst))
        return IP6_DROP_V4MAPPED_ON_WIRE;
    /* RFC 4291 section 2.5.5.1: IPv4-compatible addresses are deprecated. */
    if (ip6_is_v4compat(&src) || ip6_is_v4compat(&dst))
        return IP6_DROP_V4COMPAT_ON_WIRE;

    if (ip6_nexthdr_is_extension(pkt->next_hdr))
        return IP6_DROP_EXTENSION_HEADER;

    min_upper = ip6_upper_min_len(pkt->next_hdr);
    if (min_upper == 0) {
        /* RFC 4443 section 3.4: a node that cannot process the Next Header
         * reports it, pointing at the field that named it. The offset is
         * from the start of the IPv6 header, and next_hdr is its 7th octet.
         * Reporting rather than dropping silently is what lets the sender
         * fall back instead of retrying forever - and the destination is
         * checked because a packet that was not for us is not ours to
         * complain about. */
        int local = 0;

        (void)wolfIP_if_for_local_ip6(s, if_idx, &dst, &local);
        if (local)
            icmp6_send_error(s, if_idx, pkt, len, ICMP6_PARAM_PROBLEM,
                             ICMP6_PARAM_NEXTHDR, 6);
        return IP6_DROP_UNKNOWN_NEXTHDR;
    }
    if (payload_len < min_upper)
        return IP6_DROP_SHORT_TRANSPORT;

    /* ICMPv6 is handled in the stack itself and needs no socket. Everything
     * else waits for the socket phase. The header is fully validated at this
     * point and the payload bounds are known good. */
    if (pkt->next_hdr == IP6_NEXTHDR_ICMPV6)
        icmp6_input(s, if_idx, pkt, len);
    else if (pkt->next_hdr == IP6_NEXTHDR_UDP)
        udp6_try_recv(s, if_idx, (struct wolfIP_udp6_datagram *)pkt, len);
    else if (pkt->next_hdr == IP6_NEXTHDR_TCP)
        tcp6_input(s, if_idx, (struct wolfIP_tcp6_seg *)pkt, len);
    return IP6_ACCEPTED;
}

/* Verify the upper-layer checksum of a validated IPv6 packet. Split out from
 * ip6_recv() so the transport demux can call it once it exists, and so it can
 * be tested against known-good vectors on its own. */
static inline int ip6_verify_transport_checksum(const struct wolfIP_ip6_packet *pkt)
{
    union transport6_pseudo_header ph;
    ip6 src;
    ip6 dst;
    uint32_t payload_len = ee16(pkt->payload_len);

    ip6_hdr_get_src(pkt, &src);
    ip6_hdr_get_dst(pkt, &dst);
    transport6_pseudo_header_init(&ph, &src, &dst, payload_len, pkt->next_hdr);
    return transport6_verify_checksum(&ph, pkt->data);
}

/* ---------------------------------------------------------------------- */
/* Transmit path                                                          */
/* ---------------------------------------------------------------------- */

/* Build an IPv6 header in front of an already-assembled upper-layer payload
 * and compute its checksum. The sibling of ip_output_add_header().
 *
 * `payload_len` is the upper-layer length: the transport header plus its
 * data, excluding the 40-byte IPv6 header. Unlike IPv4 there is no header
 * checksum to compute, and the flow label is left at zero (RFC 8200 section
 * 6 permits this for a source that does not use flow labelling).
 *
 * `nexthop_mac` may be NULL, in which case no Ethernet header is added and
 * the caller is responsible for the link layer - the raw-IP (non-Ethernet)
 * ports need that.
 */
static inline int ip6_output_add_header(struct wolfIP *s, unsigned int if_idx,
                                        struct wolfIP_ip6_packet *pkt,
                                        const ip6 *src, const ip6 *dst,
                                        uint8_t next_hdr, uint16_t payload_len,
                                        uint8_t hop_limit,
                                        const uint8_t *nexthop_mac)
{
    union transport6_pseudo_header ph;

    if ((pkt == NULL) || (src == NULL) || (dst == NULL))
        return -WOLFIP_EINVAL;

    ip6_hdr_set_vtf(pkt, 0, 0);
    pkt->payload_len = ee16(payload_len);
    pkt->next_hdr = next_hdr;
    pkt->hop_limit = (hop_limit != 0) ? hop_limit : IP6_HOP_LIMIT_DEFAULT;
    ip6_hdr_set_src(pkt, src);
    ip6_hdr_set_dst(pkt, dst);

    transport6_pseudo_header_init(&ph, src, dst, payload_len, next_hdr);
    if (next_hdr == IP6_NEXTHDR_TCP) {
        struct wolfIP_tcp6_seg *tcp = (struct wolfIP_tcp6_seg *)pkt;

        tcp->csum = 0;
        tcp->csum = ee16(transport6_checksum(&ph, &tcp->src_port));
    } else if (next_hdr == IP6_NEXTHDR_UDP) {
        struct wolfIP_udp6_datagram *udp = (struct wolfIP_udp6_datagram *)pkt;

        udp->csum = 0;
        /* RFC 8200 section 8.1: unlike IPv4, a zero UDP checksum is not
         * permitted over IPv6, so a computed zero is transmitted as 0xFFFF. */
        udp->csum = ee16(transport6_checksum(&ph, &udp->src_port));
        if (udp->csum == 0)
            udp->csum = 0xFFFFu;
    } else if (next_hdr == IP6_NEXTHDR_ICMPV6) {
        struct wolfIP_icmp6_packet *icmp6 = (struct wolfIP_icmp6_packet *)pkt;

        /* ICMPv6 checksums cover the pseudo-header, which is the notable
         * difference from ICMPv4. */
        icmp6->csum = 0;
        icmp6->csum = ee16(transport6_checksum(&ph, &icmp6->type));
    }

#ifdef ETHERNET
    if ((nexthop_mac != NULL) && !wolfIP_ll_is_non_ethernet(s, if_idx)) {
        eth_output_add_header(s, if_idx, nexthop_mac,
                              (struct wolfIP_eth_frame *)pkt, ETH_TYPE_IPV6);
    }
#else
    (void)s;
    (void)if_idx;
    (void)nexthop_mac;
#endif
    return 0;
}

/* ---------------------------------------------------------------------- */
/* ICMPv6                                                                 */
/* ---------------------------------------------------------------------- */

/* IPv6 counterpart of wolfIP_if_for_local_ip(): which interface holds this
 * address, and is it one of ours at all? Same shape as the IPv4 helper, and
 * like it this searches every interface for global addresses (the weak
 * end-system model), while link-local addresses remain scoped to the ingress
 * interface as required by RFC 4007. */
static unsigned int wolfIP_if_for_local_ip6(struct wolfIP *s,
                                            unsigned int ingress_if,
                                            const ip6 *addr, int *found)
{
    struct wolfIP_ifaddr_info info;
    unsigned int i;

    if (found)
        *found = 0;
    if (!s || !addr)
        return 0;
    for (i = 0; i < WOLFIP_MAX_INTERFACES; i++) {
        unsigned int count;
        unsigned int j;

        /* Link-local addresses are scoped to one link. The same address may
         * legitimately exist on another interface, but it is not local to
         * the link on which this packet arrived (RFC 4007 section 5). */
        if (ip6_is_link_local(addr) && (i != ingress_if))
            continue;
        count = wolfIP_ifaddr_count(s, i, AF_INET6);

        for (j = 0; j < count; j++) {
            if (wolfIP_ifaddr_get(s, i, AF_INET6, j, &info) != 0)
                continue;
            /* RFC 4862 section 5.4.5: tentative addresses are not assigned
             * yet and are usable only by Duplicate Address Detection. */
            if ((info.state != WOLFIP_IFADDR_TENTATIVE) &&
                    (ip6_cmp(&info.v6, addr) == 0)) {
                if (found)
                    *found = 1;
                return i;
            }
        }
    }
    return 0;
}

/* Is this source port (or ICMPv6 Echo identifier) already taken by another
 * socket framing as IPv6 on the same local address?
 *
 * Wider than bind_port_in_use6(), deliberately: that answers "may this bind
 * be accepted", so it only considers sockets that did bind. An automatic
 * allocation has to avoid a port some other socket took automatically too,
 * and such a socket has no bind to show for it - only a local address and a
 * source port. */
static int port_in_use6(const struct tsocket *arr, int n,
                        const struct tsocket *self, const ip6 *local,
                        uint16_t port)
{
    int i;

    if (port == 0)
        return 0;
    for (i = 0; i < n; i++) {
        const struct tsocket *tk = &arr[i];

        if (tk == self)
            continue;
        if (tk->src_port != port)
            continue;
        if (!TSOCKET_IS_V6(tk) && !tk->bound_v6)
            continue;
        /* Either side unspecified is a wildcard and collides with anything
         * on the port, as in the IPv4 test. */
        if (!ip6_is_unspecified(&tk->local_ip6) && !ip6_is_unspecified(local) &&
                (ip6_cmp(&tk->local_ip6, local) != 0))
            continue;
        return 1;
    }
    return 0;
}

/* The IPv6 twin of port_alloc_random(): pick at random, then walk forward to
 * the first free value. Returns 0 when the range is exhausted, which the
 * caller reports rather than handing out a port already in use. */
static uint16_t port_alloc_random6(const struct tsocket *arr, int n,
                                   const struct tsocket *self,
                                   const ip6 *local, uint16_t min_port)
{
    uint16_t port;
    uint16_t scanned;
    uint16_t range;

    range = (uint16_t)(0x10000 - min_port);
    port = (uint16_t)(wolfIP_getrandom() & 0xFFFF);
    if (port < min_port)
        port = (uint16_t)(min_port + (port % range));
    scanned = 0;
    do {
        if (!port_in_use6(arr, n, self, local, port))
            return port;
        port++;
        if (port < min_port)
            port = min_port;
        scanned++;
    } while (scanned < range);
    return 0;
}

static void nd6_input(struct wolfIP *s, unsigned int if_idx,
                      struct wolfIP_ip6_packet *pkt, uint32_t payload_len);

/* ICMPv6 receive path. Deliberately laid out like icmp_input() above it:
 * length checks, then the checksum, then one arm per message type, with the
 * echo reply built in place over the request.
 *
 * Only Echo is handled so far. That is useful on its own because it needs
 * neither sockets nor Neighbor Discovery - the reply goes back to the source
 * MAC of the request, exactly as the IPv4 path does - and it gives
 * ip6_output_add_header() its first production caller.
 *
 * Not handled yet, each with its requirement test already written in
 * unit_tests_ipv6_pending.c: the error messages of RFC 4443 sections 3.1 to
 * 3.4, and Echo Requests addressed to a multicast group, which need a
 * unicast source chosen per RFC 4443 section 4.2.
 *
 * Unlike icmp_input() there is no wolfIP_filter_notify_icmp() call: the
 * packet filter has no IPv6 hooks yet. It belongs here when it grows them.
 */
static void icmp6_input(struct wolfIP *s, unsigned int if_idx,
                        struct wolfIP_ip6_packet *pkt, uint32_t len)
{
    struct wolfIP_icmp6_packet *icmp = (struct wolfIP_icmp6_packet *)pkt;
    uint32_t payload_len = ee16(pkt->payload_len);
    uint8_t peer_mac[6];
    ip6 src;
    ip6 dst;

    /* validate minimum ICMPv6 packet length */
    if (len < sizeof(struct wolfIP_icmp6_packet))
        return;
    /* validate payload_len covers at least the ICMPv6 header */
    if (payload_len < IP6_MIN_ICMPV6_LEN)
        return;
    /* validate payload_len doesn't exceed actual received data */
    if (len < ((uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) + payload_len))
        return;
    /* validate ICMPv6 checksum before processing (RFC 4443 section 2.3).
     * Unlike ICMPv4 this covers the IPv6 pseudo-header. */
    if (ip6_verify_transport_checksum(pkt) != 0)
        return;

    ip6_hdr_get_src(pkt, &src);
    ip6_hdr_get_dst(pkt, &dst);

    /* Neighbor Discovery is ICMPv6 but has its own validation rules, most
     * importantly the hop limit of 255 that confines it to the local link. */
    if ((icmp->type >= ICMP6_ROUTER_SOLICIT) &&
            (icmp->type <= ICMP6_REDIRECT)) {
        nd6_input(s, if_idx, pkt, payload_len);
        return;
    }
    /* RFC 4443 section 2.4 (b) splits the remaining types two ways, and the
     * split decides what reaches an application ICMPv6 socket.
     *
     * An error message is passed to the upper layer even when its type is
     * unrecognised - that is how a program learns its destination was
     * unreachable, and refusing to relay a type this stack happens not to
     * know would hide exactly the reports worth having. An Echo Reply goes
     * the same way; answering it would loop between two hosts.
     *
     * An unrecognised informational message gets the opposite treatment and
     * is silently discarded. A node that cannot interpret it has nothing
     * useful to say back, and passing it up would hand an application
     * traffic it never asked for. */
    if (icmp6_type_is_error(icmp->type) ||
            (icmp->type == ICMP6_ECHO_REPLY)) {
        icmp6_try_recv(s, if_idx, icmp, len);
        return;
    }
    if (icmp->type != ICMP6_ECHO_REQUEST)
        return;

    if (icmp->type == ICMP6_ECHO_REQUEST) {
        int dst_match = 0;

        /* An Echo needs identifier and sequence as well as the header. */
        if (payload_len < ICMP6_ECHO_MIN_LEN)
            return;
        /* RFC 4443 section 4.1 assigns only Code 0 to Echo Request. */
        if (icmp->code != 0)
            return;
        /* Nowhere to send a reply, and :: as a source is reserved for
         * duplicate address detection (RFC 4862 section 5.4.2). */
        if (ip6_is_unspecified(&src))
            return;
        /* Same guard as the ICMPv4 arm, for the same reason: only reply to
         * requests destined to one of our own addresses. Without it an
         * L2-adjacent attacker can address a frame to our MAC with an
         * arbitrary destination and have us emit a reply with a source of
         * their choosing. This also declines multicast destinations, which
         * need a unicast source selected explicitly. */
        (void)wolfIP_if_for_local_ip6(s, if_idx, &dst, &dst_match);
        if (!dst_match)
            return;

        /* The Ethernet header is about to be rewritten, so keep the
         * requester's address first. */
        memcpy(peer_mac, pkt->eth.src, 6);

        /* Reply in place, as icmp_input() does: the identifier, sequence
         * number and payload are already where they belong and are left
         * untouched. Source and destination swap, so the reply comes from
         * the address that was pinged. */
        icmp->type = ICMP6_ECHO_REPLY;
        icmp->code = 0;
        ip6_output_add_header(s, if_idx, pkt, &dst, &src, IP6_NEXTHDR_ICMPV6,
                              (uint16_t)payload_len, IP6_HOP_LIMIT_DEFAULT,
                              peer_mac);

        /* Send exactly the packet, never any Ethernet padding that arrived
         * with the request. */
        wolfIP_ll_send_frame(s, if_idx, pkt,
                             (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) +
                             payload_len);
    }
}

/* ---------------------------------------------------------------------- */
/* Neighbor Discovery (RFC 4861) and DAD (RFC 4862 section 5.4)            */
/* ---------------------------------------------------------------------- */

/* Option types (RFC 4861 section 4.6). */
#define ND6_OPT_SLLA   1
#define ND6_OPT_TLLA   2
#define ND6_OPT_PREFIX 3
#define ND6_OPT_MTU    5

/* Neighbor Advertisement flags (RFC 4861 section 4.4). */
#define ND6_NA_ROUTER    0x80
#define ND6_NA_SOLICITED 0x40
#define ND6_NA_OVERRIDE  0x20

/* Prefix Information flags (RFC 4861 section 4.6.2). */
#define ND6_PREFIX_ONLINK 0x80  /* L */
#define ND6_PREFIX_AUTO   0x40  /* A */

/* Protocol constants (RFC 4861 section 10, RFC 4862 section 5.1). Values are
 * the defaults; a Router Advertisement may override the reachable and
 * retransmit timers, which is not implemented. */
#define ND6_RETRANS_TIMER_MS        1000U
#define ND6_REACHABLE_TIME_MS      30000U
#define ND6_DELAY_FIRST_PROBE_MS    5000U
#define ND6_MAX_MULTICAST_SOLICIT      3U
#define ND6_MAX_UNICAST_SOLICIT        3U
#define ND6_MAX_RTR_SOLICITATIONS      3U
#define ND6_RTR_SOLICITATION_INTERVAL_MS 4000U
#define ND6_DUP_ADDR_DETECT_TRANSMITS  1U

/* Every Neighbor Discovery message must arrive with a hop limit of exactly
 * 255 (RFC 4861 sections 6.1.1, 6.1.2, 7.1.1 and 7.1.2). A router cannot
 * forward a packet and leave the hop limit at 255, so this single check is
 * what confines Neighbor Discovery to the local link. It is the most
 * important validation in this file. */
#define ND6_HOP_LIMIT 255

/* One periodic tick drives duplicate address detection, router solicitation
 * retries and every cache expiry. One timer for the whole subsystem rather
 * than one per address or per neighbour, which keeps the shared timer heap
 * small and makes the behaviour easy to drive from a test. */
#define ND6_TICK_MS 100U

/* Neighbor Solicitation and Advertisement share a layout up to the target
 * address; the byte at `flags` is reserved (and must be zero) in a
 * solicitation. */
struct PACKED nd6_msg {
    struct wolfIP_ip6_packet ip6;
    uint8_t type, code;
    uint16_t csum;
    uint8_t flags;
    uint8_t reserved[3];
    uint8_t target[16];
    uint8_t options[0];
};

struct PACKED nd6_rs_msg {
    struct wolfIP_ip6_packet ip6;
    uint8_t type, code;
    uint16_t csum;
    uint32_t reserved;
    uint8_t options[0];
};

struct PACKED nd6_ra_msg {
    struct wolfIP_ip6_packet ip6;
    uint8_t type, code;
    uint16_t csum;
    uint8_t cur_hop_limit;
    uint8_t flags;
    uint16_t router_lifetime;
    uint32_t reachable_time;
    uint32_t retrans_timer;
    uint8_t options[0];
};

struct PACKED nd6_opt_lla {
    uint8_t type, len;
    uint8_t mac[6];
};

struct PACKED nd6_opt_prefix {
    uint8_t type, len, prefix_len, flags;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
    uint32_t reserved;
    uint8_t prefix[16];
};

static void nd6_tick_cb(void *arg);
static void nd6_arm_tick(struct wolfIP *s);
static int nd6_has_work(struct wolfIP *s);

/* ---------------------------------------------------------------------- */
/* Option parsing                                                         */
/* ---------------------------------------------------------------------- */

/* Walk the option area, returning the first option of `want`, or NULL.
 *
 * Option lengths are in units of 8 octets and a length of zero is invalid
 * (RFC 4861 section 4.6). Accepting zero makes this loop run forever on a
 * frame an attacker controls, so it is rejected explicitly - the same class
 * of bug as an extension-header chain with no progress. */
static const uint8_t *nd6_find_option(const uint8_t *opts, uint32_t len,
                                      uint8_t want)
{
    uint32_t off = 0;

    while ((off + 2u) <= len) {
        uint8_t type = opts[off];
        uint32_t olen = (uint32_t)opts[off + 1] * 8u;

        if (olen == 0)
            return NULL;            /* malformed: no forward progress */
        if ((off + olen) > len)
            return NULL;            /* runs past the end of the message */
        if (type == want)
            return &opts[off];
        off += olen;
    }
    return NULL;
}

/* Validate the framing of the entire option area before acting on any one
 * option. RFC 4861 section 4.6 requires an ND packet containing a zero-length
 * option to be discarded. Doing this as a separate first pass also prevents
 * an RA from installing a router or prefix before a malformed later option
 * is discovered. */
static int nd6_options_valid(const uint8_t *opts, uint32_t len)
{
    uint32_t off = 0;

    while (off < len) {
        uint32_t olen;

        if ((len - off) < 2u)
            return 0;
        olen = (uint32_t)opts[off + 1] * 8u;
        if ((olen == 0) || (olen > (len - off)))
            return 0;
        off += olen;
    }
    return 1;
}

/* ---------------------------------------------------------------------- */
/* Neighbour cache - the IPv6 counterpart of the arp_* helpers             */
/* ---------------------------------------------------------------------- */

/* Linear scan by {address, interface}, expiring stale entries lazily the way
 * arp_neighbor_index() does. Returns the slot index or -1. */
static int nd6_neighbor_index(struct wolfIP *s, unsigned int if_idx,
                              const ip6 *addr)
{
    unsigned int i;

    for (i = 0; i < WOLFIP_ND6_CACHE_SIZE; i++) {
        struct nd6_neighbor *n = &s->nd6.neighbors[i];

        if (n->state == 0)
            continue;
        if (n->if_idx != (uint8_t)if_idx)
            continue;
        if (ip6_cmp(&n->addr, addr) != 0)
            continue;
        return (int)i;
    }
    return -1;
}

/* Insert or refresh an entry. `mac` may be NULL to create an INCOMPLETE
 * entry for an address whose link-layer address is still unknown.
 *
 * Unlike arp_store_neighbor(), which silently refuses when the table is
 * full, this evicts the oldest entry. A full table that cannot be reclaimed
 * means one burst of scan traffic locks out every real neighbour. */
static int nd6_store_neighbor(struct wolfIP *s, unsigned int if_idx,
                              const ip6 *addr, const uint8_t *mac,
                              uint8_t state, int is_router)
{
    struct nd6_neighbor *n;
    int idx = nd6_neighbor_index(s, if_idx, addr);
    unsigned int i;

    if (idx < 0) {
        int oldest = 0;

        for (i = 0; i < WOLFIP_ND6_CACHE_SIZE; i++) {
            if (s->nd6.neighbors[i].state == 0) {
                idx = (int)i;
                break;
            }
            if (s->nd6.neighbors[i].ts < s->nd6.neighbors[oldest].ts)
                oldest = (int)i;
        }
        if (idx < 0)
            idx = oldest;
        memset(&s->nd6.neighbors[idx], 0, sizeof(struct nd6_neighbor));
        ip6_copy(&s->nd6.neighbors[idx].addr, addr);
        s->nd6.neighbors[idx].if_idx = (uint8_t)if_idx;
    }
    n = &s->nd6.neighbors[idx];
    if (mac != NULL)
        memcpy(n->mac, mac, 6);
    n->state = state;
    n->probes = 0;
    n->ts = s->last_tick;
    if (is_router)
        n->is_router = 1;
    return idx;
}

/* Resolve an address to a link-layer address. Returns 0 and fills `mac` when
 * the entry is usable, negative otherwise. Counterpart of arp_lookup(). */
static int nd6_lookup(struct wolfIP *s, unsigned int if_idx, const ip6 *addr,
                      uint8_t *mac)
{
    int idx;

    /* Multicast needs no resolution: the mapping is algorithmic. */
    if (ip6_is_multicast(addr)) {
        ip6_mcast_to_eth(addr, mac);
        return 0;
    }
    idx = nd6_neighbor_index(s, if_idx, addr);
    if (idx < 0)
        return -1;
    if (s->nd6.neighbors[idx].state == ND6_INCOMPLETE)
        return -1;
    memcpy(mac, s->nd6.neighbors[idx].mac, 6);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Transmit                                                               */
/* ---------------------------------------------------------------------- */

/* Send a Neighbor Solicitation for `target`.
 *
 * There is no rate limit here, unlike arp_request()'s one per second per
 * interface. The only caller is duplicate address detection, which is
 * already paced by dad_due. When address resolution is driven from the
 * transmit path it will be able to ask for the same neighbour repeatedly,
 * and will need a throttle at that point.
 *
 * `src` is the source address: a real address of ours for ordinary address
 * resolution, or the unspecified address during duplicate address detection.
 * RFC 4861 section 4.3 forbids the Source Link-Layer Address option when the
 * source is unspecified, which is exactly the DAD case - there is no address
 * to advertise yet. */
static void nd6_send_ns(struct wolfIP *s, unsigned int if_idx,
                        const ip6 *target, const ip6 *src)
{
    uint8_t frame[LINK_MTU];
    struct nd6_msg *ns = (struct nd6_msg *)frame;
    struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, if_idx);
    struct nd6_opt_lla *opt;
    ip6 dst;
    uint8_t mac[6];
    uint16_t payload_len = 24; /* type,code,csum,reserved + target */
    /* RFC 4861 section 4.6.1: the option carries "the link-layer address of
     * the sender", so it is meaningless on a link that has none, and RFC
     * 4861 section 4.3 forbids it when the source is unspecified - the
     * duplicate address detection case, where there is no address to
     * advertise yet. */
    int with_slla = !ip6_is_unspecified(src) &&
            !wolfIP_ll_is_non_ethernet(s, if_idx);

    if (!ll)
        return;
    memset(frame, 0, ETH_HEADER_LEN + IP6_HEADER_LEN + 32);
    ns->type = ICMP6_NEIGHBOR_SOLICIT;
    ns->code = 0;
    memcpy(ns->target, target->addr, 16);
    if (with_slla) {
        opt = (struct nd6_opt_lla *)ns->options;
        opt->type = ND6_OPT_SLLA;
        opt->len = 1; /* 8 octets */
        memcpy(opt->mac, ll->mac, 6);
        payload_len = (uint16_t)(payload_len + 8u);
    }

    /* Solicitations go to the target's solicited-node group, so only the
     * handful of nodes sharing its low 24 bits are interrupted. */
    ip6_set_solicited_node(&dst, target);
    ip6_mcast_to_eth(&dst, mac);
    ip6_output_add_header(s, if_idx, &ns->ip6, src, &dst, IP6_NEXTHDR_ICMPV6,
                          payload_len, ND6_HOP_LIMIT, mac);
    wolfIP_ll_send_frame(s, if_idx, frame,
                         (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) +
                         payload_len);
}

/* Send a Neighbor Advertisement for `target` to `dst`/`dst_mac`. */
static void nd6_send_na(struct wolfIP *s, unsigned int if_idx,
                        const ip6 *target, const ip6 *src, const ip6 *dst,
                        const uint8_t *dst_mac, uint8_t flags)
{
    uint8_t frame[LINK_MTU];
    struct nd6_msg *na = (struct nd6_msg *)frame;
    struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, if_idx);
    struct nd6_opt_lla *opt;
    uint16_t payload_len = 24 + 8;

    if (!ll)
        return;
    memset(frame, 0, ETH_HEADER_LEN + IP6_HEADER_LEN + 32);
    na->type = ICMP6_NEIGHBOR_ADVERT;
    na->code = 0;
    na->flags = flags;
    memcpy(na->target, target->addr, 16);
    /* The Target Link-Layer Address option is what actually answers the
     * question the solicitation asked - unless the link has no link-layer
     * addresses, where there was no question: the peer is reached by the
     * link itself and address resolution is not performed at all (RFC 4861
     * section 3). The advertisement is still worth sending, because it is
     * also what fails somebody else's duplicate address detection. */
    if (!wolfIP_ll_is_non_ethernet(s, if_idx)) {
        opt = (struct nd6_opt_lla *)na->options;
        opt->type = ND6_OPT_TLLA;
        opt->len = 1;
        memcpy(opt->mac, ll->mac, 6);
    } else {
        payload_len = 24;
    }

    ip6_output_add_header(s, if_idx, &na->ip6, src, dst, IP6_NEXTHDR_ICMPV6,
                          payload_len, ND6_HOP_LIMIT, dst_mac);
    wolfIP_ll_send_frame(s, if_idx, frame,
                         (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) +
                         payload_len);
}

/* Send a Router Solicitation to the all-routers group (RFC 4861 s6.3.7). */
static void nd6_send_rs(struct wolfIP *s, unsigned int if_idx)
{
    uint8_t frame[LINK_MTU];
    struct nd6_rs_msg *rs = (struct nd6_rs_msg *)frame;
    struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, if_idx);
    struct nd6_opt_lla *opt;
    struct wolfIP_ifaddr_info info;
    ip6 src;
    ip6 dst;
    uint8_t mac[6];
    uint16_t payload_len = 8;
    unsigned int count;
    unsigned int i;
    int have_src = 0;

    if (!ll)
        return;
    /* Prefer a link-local source; until DAD completes there may be none, in
     * which case the unspecified address is used and the Source Link-Layer
     * Address option must be omitted (RFC 4861 section 4.1). */
    ip6_set_unspecified(&src);
    count = wolfIP_ifaddr_count(s, if_idx, AF_INET6);
    for (i = 0; i < count; i++) {
        if (wolfIP_ifaddr_get(s, if_idx, AF_INET6, i, &info) != 0)
            continue;
        if ((info.state == WOLFIP_IFADDR_PREFERRED) &&
                ip6_is_link_local(&info.v6)) {
            ip6_copy(&src, &info.v6);
            have_src = 1;
            break;
        }
    }

    memset(frame, 0, ETH_HEADER_LEN + IP6_HEADER_LEN + 16);
    rs->type = ICMP6_ROUTER_SOLICIT;
    rs->code = 0;
    if (have_src && !wolfIP_ll_is_non_ethernet(s, if_idx)) {
        opt = (struct nd6_opt_lla *)rs->options;
        opt->type = ND6_OPT_SLLA;
        opt->len = 1;
        memcpy(opt->mac, ll->mac, 6);
        payload_len = (uint16_t)(payload_len + 8u);
    }

    ip6_set_all_routers(&dst);
    ip6_mcast_to_eth(&dst, mac);
    ip6_output_add_header(s, if_idx, &rs->ip6, &src, &dst, IP6_NEXTHDR_ICMPV6,
                          payload_len, ND6_HOP_LIMIT, mac);
    wolfIP_ll_send_frame(s, if_idx, frame,
                         (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) +
                         payload_len);
}

/* ---------------------------------------------------------------------- */
/* Duplicate address detection (RFC 4862 section 5.4)                     */
/* ---------------------------------------------------------------------- */

/* Find the address slot holding `addr` on `if_idx`, or NULL. */
static struct wolfIP_ifaddr_slot *nd6_slot_for(struct wolfIP *s,
                                               unsigned int if_idx,
                                               const ip6 *addr)
{
    unsigned int i;

    for (i = 0; i < WOLFIP_IFADDR_MAX; i++) {
        struct wolfIP_ifaddr_slot *slot = &s->ifaddr[i];

        if (!slot->used)
            continue;
        if (slot->info.family != AF_INET6)
            continue;
        if (slot->info.if_idx != (uint8_t)if_idx)
            continue;
        if (ip6_cmp(&slot->info.v6, addr) == 0)
            return slot;
    }
    return NULL;
}

/* Neighbor Discovery is link-scoped even for globally routable addresses.
 * A unicast destination is actionable only when it is assigned on the
 * ingress interface and has completed DAD. Unsolicited RA/NA messages may
 * instead use the all-nodes multicast group. */
static int nd6_destination_is_local(struct wolfIP *s, unsigned int if_idx,
                                    const ip6 *dst)
{
    struct wolfIP_ifaddr_slot *slot;

    if (ip6_is_all_nodes(dst))
        return 1;
    slot = nd6_slot_for(s, if_idx, dst);
    return ((slot != NULL) &&
            (slot->info.state != WOLFIP_IFADDR_TENTATIVE)) ? 1 : 0;
}

/* Abandon a tentative address that turned out to be a duplicate.
 *
 * RFC 4862 section 5.4.5: the address must not be assigned. If it was the
 * link-local address the interface has no usable IPv6 configuration at all,
 * which is reported by leaving the interface with no link-local address
 * rather than by retrying with a different identifier. */
static void nd6_dad_failed(struct wolfIP *s, struct wolfIP_ifaddr_slot *slot)
{
    (void)s;
    slot->info.state = WOLFIP_IFADDR_DEPRECATED;
    slot->used = 0;
}

/* Two hours, the constant RFC 4862 section 5.5.3 (e) is written around. */
#define ND6_SLAAC_TWO_HOURS_MS (2u * 60u * 60u * 1000u)

/* Remaining valid lifetime of a SLAAC address, in milliseconds. Only called
 * for an address whose valid lifetime is finite. */
static uint64_t nd6_slaac_valid_remaining_ms(struct wolfIP *s,
                                             const struct wolfIP_ifaddr_slot *slot)
{
    uint64_t total = (uint64_t)slot->info.valid_lifetime * 1000u;
    uint64_t elapsed = (s->last_tick > slot->lifetime_ts) ?
                       (s->last_tick - slot->lifetime_ts) : 0u;

    return (total > elapsed) ? (total - elapsed) : 0u;
}

/* Apply a Prefix Information option's lifetimes to an address formed from
 * it (RFC 4862 section 5.5.3 (e)).
 *
 * The preferred lifetime is simply reset. The valid lifetime is not: taking
 * it at face value would let one forged advertisement with a short lifetime
 * delete a working address. The rule is that it may always be raised, and
 * may only be lowered to no less than two hours, unless the advertisement is
 * authenticated - which nothing here is, so the two-hour floor always
 * applies. */
static void nd6_slaac_apply_lifetimes(struct wolfIP *s,
                                      struct wolfIP_ifaddr_slot *slot,
                                      uint32_t valid, uint32_t preferred,
                                      int is_new)
{
    slot->info.flags |= WOLFIP_IFADDR_FLAG_SLAAC;
    slot->info.preferred_lifetime = preferred;
    if (is_new) {
        slot->info.valid_lifetime = valid;
        slot->lifetime_ts = s->last_tick;
        return;
    }
    if (slot->info.valid_lifetime == 0) {
        /* Already unlimited; an advertisement cannot take that away. */
        slot->lifetime_ts = s->last_tick;
        return;
    }
    {
        uint64_t remaining = nd6_slaac_valid_remaining_ms(s, slot);
        uint64_t advertised = (uint64_t)valid * 1000u;

        if ((advertised > ND6_SLAAC_TWO_HOURS_MS) ||
                (advertised > remaining)) {
            slot->info.valid_lifetime = valid;
        } else if (remaining <= ND6_SLAAC_TWO_HOURS_MS) {
            /* Ignore the advertised value and let the address run out its
             * remaining time: re-anchoring would extend it. */
            slot->info.valid_lifetime =
                (uint32_t)((remaining + 999u) / 1000u);
        } else {
            slot->info.valid_lifetime =
                (uint32_t)(ND6_SLAAC_TWO_HOURS_MS / 1000u);
        }
    }
    slot->lifetime_ts = s->last_tick;
}

/* Start duplicate address detection on a tentative address. */
static void nd6_dad_start(struct wolfIP *s, struct wolfIP_ifaddr_slot *slot)
{
    slot->info.state = WOLFIP_IFADDR_TENTATIVE;
    slot->dad_probes = ND6_DUP_ADDR_DETECT_TRANSMITS;
    /* Send the first solicitation on the next tick, so that a caller adding
     * an address mid-poll does not transmit from inside its own call. */
    slot->dad_due = s->last_tick;
}

/* The interface identifier for an interface: the low 64 bits of every IPv6
 * address formed on it, both the link-local one and anything SLAAC derives
 * from an advertised prefix. Those must share an identifier, which is why it
 * is chosen once and cached rather than recomputed per address.
 *
 * Three sources, in order:
 *
 * 1. An identifier the application supplied through wolfIP_ipv6_set_iid().
 *    That is where an RFC 7217 opaque identifier, or one restored from
 *    storage, comes from - see WOLFIP_IPV6_IID_OVERRIDE.
 * 2. A modified EUI-64 from the interface MAC (RFC 4862 section 5.3), on a
 *    link that has a link-layer address.
 * 3. A random draw, which is what a point-to-point link gets. RFC 4862
 *    requires an identifier unique on the link and says nothing about where
 *    it comes from; with one peer on the link, 64 random bits collide with
 *    probability that duplicate address detection then catches anyway.
 *
 * The 'u' bit is cleared on a generated identifier: it is not derived from a
 * universal IEEE identifier and must not claim to be (RFC 7217 section 5).
 * Reserved identifiers are redrawn (RFC 5453). */
static void nd6_iface_iid(struct wolfIP *s, unsigned int if_idx, ip6 *iid)
{
    struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, if_idx);
    uint8_t *cached = s->nd6.iid[if_idx];
    unsigned int tries;

    if (s->nd6.iid_valid[if_idx]) {
        ip6_iid_from_bytes(iid, cached);
        return;
    }

    if ((ll != NULL) && !ll->non_ethernet) {
        ip6_iid_from_mac(iid, ll->mac);
        memcpy(cached, &iid->addr[8], 8);
        s->nd6.iid_valid[if_idx] = 1;
        return;
    }

    for (tries = 0; tries < 8u; tries++) {
        uint32_t hi = wolfIP_getrandom();
        uint32_t lo = wolfIP_getrandom();

        cached[0] = (uint8_t)((hi >> 24) & 0xFFu);
        cached[1] = (uint8_t)((hi >> 16) & 0xFFu);
        cached[2] = (uint8_t)((hi >> 8) & 0xFFu);
        cached[3] = (uint8_t)(hi & 0xFFu);
        cached[4] = (uint8_t)((lo >> 24) & 0xFFu);
        cached[5] = (uint8_t)((lo >> 16) & 0xFFu);
        cached[6] = (uint8_t)((lo >> 8) & 0xFFu);
        cached[7] = (uint8_t)(lo & 0xFFu);
        cached[0] &= (uint8_t)~0x02u;
        if (!ip6_iid_is_reserved(cached))
            break;
    }
    if (ip6_iid_is_reserved(cached)) {
        /* Eight reserved draws in a row means the generator is stuck or
         * absent, not bad luck. Anything outside the reserved ranges beats
         * honouring the draw; duplicate address detection is what decides
         * whether the result is usable on this link. */
        memset(cached, 0, 8);
        cached[6] = 0xACu;
        cached[7] = (uint8_t)(if_idx + 1u);
    }
    ip6_iid_from_bytes(iid, cached);
    s->nd6.iid_valid[if_idx] = 1;
}

/* ---------------------------------------------------------------------- */
/* Prefix and router lists                                                */
/* ---------------------------------------------------------------------- */

static void nd6_prefix_store(struct wolfIP *s, unsigned int if_idx,
                             const ip6 *prefix, uint8_t prefix_len,
                             uint8_t onlink, uint8_t autonomous,
                             uint32_t valid, uint32_t preferred)
{
    unsigned int i;
    int free_slot = -1;

    for (i = 0; i < WOLFIP_ND6_PREFIX_MAX; i++) {
        struct nd6_prefix *p = &s->nd6.prefixes[i];

        if (!p->used) {
            if (free_slot < 0)
                free_slot = (int)i;
            continue;
        }
        if ((p->if_idx == (uint8_t)if_idx) && (p->prefix_len == prefix_len) &&
                (ip6_prefix_cmp(&p->prefix, prefix, prefix_len) == 0)) {
            /* RFC 4861 section 6.3.4: zero invalidates an on-link prefix
             * immediately, rather than at the next timer tick. */
            if (valid == 0) {
                p->used = 0;
                return;
            }
            p->onlink = onlink;
            p->autonomous = autonomous;
            p->valid_lifetime = valid;
            p->preferred_lifetime = preferred;
            p->ts = s->last_tick;
            return;
        }
    }
    if (valid == 0)
        return;
    if (free_slot < 0)
        return; /* table full: the advertisement is ignored, never truncated */
    {
        struct nd6_prefix *p = &s->nd6.prefixes[free_slot];

        memset(p, 0, sizeof(*p));
        ip6_copy(&p->prefix, prefix);
        p->prefix_len = prefix_len;
        p->if_idx = (uint8_t)if_idx;
        p->used = 1;
        p->onlink = onlink;
        p->autonomous = autonomous;
        p->valid_lifetime = valid;
        p->preferred_lifetime = preferred;
        p->ts = s->last_tick;
    }
}

static void nd6_router_store(struct wolfIP *s, unsigned int if_idx,
                             const ip6 *addr, uint16_t lifetime)
{
    unsigned int i;
    int free_slot = -1;

    for (i = 0; i < WOLFIP_ND6_ROUTER_MAX; i++) {
        struct nd6_router *r = &s->nd6.routers[i];

        if (!r->used) {
            if (free_slot < 0)
                free_slot = (int)i;
            continue;
        }
        if ((r->if_idx == (uint8_t)if_idx) && (ip6_cmp(&r->addr, addr) == 0)) {
            /* RFC 4861 section 6.3.4: a lifetime of zero means the sender is
             * no longer a default router. */
            if (lifetime == 0) {
                r->used = 0;
                return;
            }
            r->lifetime = lifetime;
            r->ts = s->last_tick;
            return;
        }
    }
    if ((lifetime == 0) || (free_slot < 0))
        return;
    {
        struct nd6_router *r = &s->nd6.routers[free_slot];

        memset(r, 0, sizeof(*r));
        ip6_copy(&r->addr, addr);
        r->if_idx = (uint8_t)if_idx;
        r->used = 1;
        r->lifetime = lifetime;
        r->ts = s->last_tick;
    }
}

/* Forget a default router. RFC 4861 section 7.2.5: a node that learns a
 * router is no longer one must remove it from the Default Router List. */
static void nd6_router_forget(struct wolfIP *s, unsigned int if_idx,
                              const ip6 *addr)
{
    unsigned int i;

    for (i = 0; i < WOLFIP_ND6_ROUTER_MAX; i++) {
        struct nd6_router *r = &s->nd6.routers[i];

        if (!r->used)
            continue;
        if ((r->if_idx == (uint8_t)if_idx) && (ip6_cmp(&r->addr, addr) == 0))
            r->used = 0;
    }
}

/* Is this destination on-link, according to the prefix list? */
static int nd6_is_onlink(struct wolfIP *s, unsigned int if_idx,
                         const ip6 *dst)
{
    struct wolfIP_ifaddr_info info;
    unsigned int count;
    unsigned int i;

    if (ip6_is_link_local(dst) || ip6_is_multicast(dst))
        return 1;
    for (i = 0; i < WOLFIP_ND6_PREFIX_MAX; i++) {
        struct nd6_prefix *p = &s->nd6.prefixes[i];

        if (!p->used || !p->onlink)
            continue;
        if (p->if_idx != (uint8_t)if_idx)
            continue;
        if (ip6_prefix_cmp(&p->prefix, dst, p->prefix_len) == 0)
            return 1;
    }
    /* The prefix of an address configured on the interface.
     *
     * RFC 5942 section 4 is explicit that in IPv6 an address's prefix
     * length does not by itself make that prefix on-link - on-link
     * determination is meant to come from Router Advertisements. Applied
     * literally that leaves a statically configured node unable to reach
     * its own subnet until a router speaks, which is not a useful stack:
     * wolfIP is routinely configured by hand with no router present at
     * all. Linux resolves this the same way, by adding a connected route
     * for a manually assigned address, and this is the equivalent. A
     * prefix learned from an advertisement still takes the path above and
     * still carries its L flag faithfully. */
    count = wolfIP_ifaddr_count(s, if_idx, AF_INET6);
    for (i = 0; i < count; i++) {
        if (wolfIP_ifaddr_get(s, if_idx, AF_INET6, i, &info) != 0)
            continue;
        if (info.state == WOLFIP_IFADDR_TENTATIVE)
            continue;
        if (info.prefix_len == 0)
            continue;
        if (ip6_prefix_cmp(&info.v6, dst, info.prefix_len) == 0)
            return 1;
    }
    return 0;
}

/* Pick the next hop for a destination: the destination itself when it is
 * on-link, otherwise a default router. The IPv6 counterpart of
 * wolfIP_select_nexthop_ex(), driven by the prefix and router lists rather
 * than by a configured netmask and gateway. Returns 0 on success. */
static int nd6_select_nexthop(struct wolfIP *s, unsigned int if_idx,
                              const ip6 *dst, ip6 *nexthop)
{
    unsigned int i;

    if (nd6_is_onlink(s, if_idx, dst)) {
        ip6_copy(nexthop, dst);
        return 0;
    }
    for (i = 0; i < WOLFIP_ND6_ROUTER_MAX; i++) {
        struct nd6_router *r = &s->nd6.routers[i];

        if (!r->used || (r->if_idx != (uint8_t)if_idx))
            continue;
        ip6_copy(nexthop, &r->addr);
        return 0;
    }
    return -1; /* no route */
}

/* ---------------------------------------------------------------------- */
/* ICMPv6 sockets                                                         */
/* ---------------------------------------------------------------------- */

/* The Echo identifier, which is the first half of the four type-specific
 * octets of an Echo Request or Reply (RFC 4443 section 4.1). An ICMPv6
 * socket binds to one, the way the IPv4 ICMP socket does, so several
 * pingers can share the stack. */
static uint16_t icmp6_echo_id(const struct wolfIP_icmp6_packet *icmp)
{
    return (uint16_t)((icmp->data[0] << 8) | icmp->data[1]);
}

/* Deliver an ICMPv6 message to any socket that wants it.
 *
 * Matching mirrors the IPv4 ICMP socket: the local address if the socket
 * is bound to one, the Echo identifier if it has claimed one, and the peer
 * if it is connected. An error message carries the identifier of whatever
 * provoked it rather than one of its own, so identifier matching applies
 * only to Echo Replies - otherwise a socket would never see the errors its
 * own traffic caused, which is the main reason to have the socket at all. */
static void icmp6_try_recv(struct wolfIP *s, unsigned int if_idx,
                           struct wolfIP_icmp6_packet *icmp, uint32_t frame_len)
{
    int is_echo_reply = (icmp->type == ICMP6_ECHO_REPLY);
    uint16_t echo_id = 0;
    int dst_is_local = 0;
    ip6 src;
    ip6 dst;
    int i;

    if (frame_len < sizeof(struct wolfIP_icmp6_packet))
        return;
    if (is_echo_reply) {
        if (ee16(icmp->ip6.payload_len) < ICMP6_ECHO_MIN_LEN)
            return;
        echo_id = icmp6_echo_id(icmp);
    }
    ip6_hdr_get_src(&icmp->ip6, &src);
    ip6_hdr_get_dst(&icmp->ip6, &dst);

    /* Addressed to one of our addresses on the interface it arrived over.
     * The zone is part of the identity of a link-local address (RFC 4007
     * section 6), so matching the address alone let a socket bound to
     * fe80::x on one interface take messages for the identical address on
     * another. */
    (void)wolfIP_if_for_local_ip6(s, if_idx, &dst, &dst_is_local);
    if (!dst_is_local)
        return;

    for (i = 0; i < MAX_ICMPSOCKETS; i++) {
        struct tsocket *t = &s->icmpsockets[i];

        if (t->proto != WI_IPPROTO_ICMP)
            continue;
        if (t->domain != AF_INET6)
            continue;
        /* A socket bound to a link-local address is scoped to that link and
         * does not take another's traffic for the same address (RFC 4007
         * section 6). An unbound socket carries no zone. */
        if (t->bound_v6 && ip6_is_link_local(&t->bound_local_ip6) &&
                (t->if_idx != (uint8_t)if_idx))
            continue;
        if (!ip6_is_unspecified(&t->bound_local_ip6) &&
                (ip6_cmp(&t->bound_local_ip6, &dst) != 0))
            continue;
        if (is_echo_reply && (t->src_port != 0) && (t->src_port != echo_id))
            continue;
        if (t->peer_is_v6 && !ip6_is_unspecified(&t->remote_ip6) &&
                (ip6_cmp(&t->remote_ip6, &src) != 0))
            continue;
        if (fifo_push(&t->sock.udp.rxbuf, icmp, frame_len) == 0) {
            t->last_pkt_ttl = icmp->ip6.hop_limit;
            t->events |= CB_EVENT_READABLE;
        }
    }
}

/* sendto() on an ICMPv6 socket. The application supplies the whole ICMPv6
 * message from the type octet onwards; the stack fills in the checksum,
 * which it must, because that checksum covers the IPv6 pseudo-header and so
 * cannot be computed until the source address has been selected. That is
 * the one real difference from the IPv4 ICMP socket, where an application
 * can and often does checksum its own packet. */
static int icmp6_sendto(struct wolfIP *s, struct tsocket *t, uint8_t *frame,
                        const void *buf, size_t len)
{
    struct wolfIP_icmp6_packet *icmp = (struct wolfIP_icmp6_packet *)frame;
    uint32_t frame_len;
    uint32_t max_payload;
    unsigned int if_idx;
    ip6 src;

    if (len < ICMP6_ECHO_MIN_LEN)
        return -WOLFIP_EINVAL; /* type, code, checksum and the 4-byte word */
    if (ip6_is_unspecified(&t->remote_ip6))
        return -1;

    if (!ip6_is_unspecified(&t->bound_local_ip6)) {
        int match = 0;

        if_idx = wolfIP_if_for_local_ip6(s, t->if_idx, &t->bound_local_ip6,
                                         &match);
        if (!match)
            return -WOLFIP_EINVAL;
        ip6_copy(&src, &t->bound_local_ip6);
    } else {
        if_idx = ip6_route_for_dest(s, &t->remote_ip6);
        if (ip6_select_source(s, if_idx, &t->remote_ip6, &src) != 0)
            return -1;
    }
    t->if_idx = (uint8_t)if_idx;
    ip6_copy(&t->local_ip6, &src);

    max_payload = udp6_max_payload(s, t->if_idx) + UDP_HEADER_LEN;
    if ((max_payload == 0) || (len > max_payload))
        return -WOLFIP_EINVAL;

    /* The application's message starts at the type octet, which is where
     * the ICMPv6 header begins, so it lands on the header itself rather
     * than after it. */
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) + (uint32_t)len;
    if (!fifo_can_push_len(&t->sock.udp.txbuf, frame_len))
        return -WOLFIP_EAGAIN;

    memset(frame, 0, ETH_HEADER_LEN + IP6_HEADER_LEN);
    memcpy(&icmp->type, buf, len);
    /* The Echo identifier is what demultiplexes replies back to a socket, so
     * the socket owns it rather than the application: an unclaimed socket is
     * given a free one and every Echo Request carries it, which is the
     * contract the IPv4 ICMP socket offers (icmp_set_echo_id there). Letting
     * the application's value through unchecked let two sockets claim one
     * identifier and take each other's replies. */
    if (icmp->type == ICMP6_ECHO_REQUEST) {
        if (t->src_port == 0) {
            t->src_port = port_alloc_random6(s->icmpsockets, MAX_ICMPSOCKETS,
                                             t, &t->local_ip6, 1);
            if (t->src_port == 0)
                return -WOLFIP_EAGAIN;
        }
        icmp->data[0] = (uint8_t)((t->src_port >> 8) & 0xFFu);
        icmp->data[1] = (uint8_t)(t->src_port & 0xFFu);
    }
    if (ip6_output_add_header(s, t->if_idx, &icmp->ip6, &t->local_ip6,
                              &t->remote_ip6, IP6_NEXTHDR_ICMPV6,
                              (uint16_t)len, 0, NULL) != 0)
        return -1;
    if (fifo_push(&t->sock.udp.txbuf, frame, frame_len) < 0)
        return -WOLFIP_EAGAIN;
    return (int)len;
}

/* recvfrom() on an ICMPv6 socket: the whole ICMPv6 message from the type
 * octet onwards, and the peer as a sockaddr_in6. */
static int icmp6_recvfrom(struct wolfIP *s, struct tsocket *t, void *buf,
                          size_t len, struct wolfIP_sockaddr *src_addr,
                          socklen_t *addrlen)
{
    struct pkt_desc *desc = fifo_peek(&t->sock.udp.rxbuf);
    struct wolfIP_icmp6_packet *icmp;
    uint32_t msg_len;
    ip6 src;

    (void)s;
    if (!desc)
        return -WOLFIP_EAGAIN;
    icmp = (struct wolfIP_icmp6_packet *)(t->rxmem + desc->pos + sizeof(*desc));
    msg_len = ee16(icmp->ip6.payload_len);
    if (msg_len > (desc->len - (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN)))
        msg_len = desc->len - (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN);
    if (msg_len > len) {
        fifo_pop(&t->sock.udp.rxbuf);
        if (fifo_peek(&t->sock.udp.rxbuf) == NULL)
            t->events &= ~CB_EVENT_READABLE;
        return -WOLFIP_EINVAL;
    }
    ip6_hdr_get_src(&icmp->ip6, &src);
    if (src_addr) {
        socklen_t want = sizeof(struct wolfIP_sockaddr_in6);

        if (addrlen && (*addrlen < want))
            return -WOLFIP_EINVAL;
        /* ICMPv6 has no ports, so the reported port is zero, as the IPv4
         * ICMP socket also reports. */
        if (sock_addr_from_ip6(src_addr, &want, &src, 0, t->if_idx) != 0)
            return -WOLFIP_EINVAL;
        if (addrlen)
            *addrlen = want;
    }
    memcpy(buf, &icmp->type, msg_len);
    fifo_pop(&t->sock.udp.rxbuf);
    if (fifo_peek(&t->sock.udp.rxbuf) == NULL)
        t->events &= ~CB_EVENT_READABLE;
    return (int)msg_len;
}

/* ---------------------------------------------------------------------- */
/* ICMPv6 error messages (RFC 4443 section 2.4 and 3)                     */
/* ---------------------------------------------------------------------- */

/* Is this an ICMPv6 error message rather than an informational one?
 * The type space is split at 128 precisely so this question has a cheap
 * answer (RFC 4443 section 2.1). */
static int icmp6_type_is_error(uint8_t type)
{
    return (type < ICMP6_INFORMATIONAL_MIN) ? 1 : 0;
}

/* May an error be generated in response to this packet?
 *
 * RFC 4443 section 2.4 (e) lists what must never provoke one, and every
 * item on that list exists to stop the stack being turned into an
 * amplifier or into one half of a loop:
 *
 *   (e.1) another ICMPv6 error message - two nodes would sustain it forever
 *   (e.2) a packet destined to a multicast address, with two exceptions:
 *         Packet Too Big, without which multicast path MTU discovery cannot
 *         work, and Parameter Problem code 2, which reports an unrecognised
 *         option the sender genuinely has to hear about
 *   (e.3) a link-layer multicast or broadcast - the IPv6 destination being
 *         multicast is what this stack can see of that
 *   (e.5) a source that does not uniquely identify a single node: the
 *         unspecified address, or any multicast address
 *
 * `orig_next_hdr` and `orig_type` describe the offending packet; orig_type
 * is only meaningful when it is ICMPv6. */
static int icmp6_error_allowed(uint8_t out_type, uint8_t out_code,
                               uint8_t orig_next_hdr, uint8_t orig_type,
                               const ip6 *orig_src, const ip6 *orig_dst)
{
    /* (e.1) */
    if ((orig_next_hdr == IP6_NEXTHDR_ICMPV6) && icmp6_type_is_error(orig_type))
        return 0;
    /* (e.5) */
    if (ip6_is_unspecified(orig_src) || ip6_is_multicast(orig_src))
        return 0;
    /* (e.2) and (e.3) */
    if (ip6_is_multicast(orig_dst)) {
        if (out_type == ICMP6_PACKET_TOO_BIG)
            return 1;
        if ((out_type == ICMP6_PARAM_PROBLEM) &&
                (out_code == ICMP6_PARAM_OPTION))
            return 1;
        return 0;
    }
    return 1;
}

/* Send an ICMPv6 error about `orig`.
 *
 * `param` is the type-specific word: the MTU for Packet Too Big, the offset
 * of the offending octet for Parameter Problem, zero otherwise.
 *
 * RFC 4443 section 2.4 (c): the message carries as much of the offending
 * packet as fits without the result exceeding the minimum IPv6 MTU. That is
 * a cap on the whole datagram, not on the quotation, which is why the
 * budget is computed from 1280 downwards rather than from the payload up.
 * Unlike ICMPv4's fixed 8 bytes, this is deliberately as much as possible:
 * it is what lets the receiving node match the error to a connection. */
static void icmp6_send_error(struct wolfIP *s, unsigned int if_idx,
                             const struct wolfIP_ip6_packet *orig,
                             uint32_t orig_frame_len, uint8_t type,
                             uint8_t code, uint32_t param)
{
    uint8_t frame[IP6_MIN_MTU + ETH_HEADER_LEN];
    struct wolfIP_icmp6_packet *err = (struct wolfIP_icmp6_packet *)frame;
    unsigned int tx_if = if_idx;
    uint32_t orig_len;
    uint32_t quote;
    uint32_t payload_len;
    uint8_t mac[6];
    ip6 orig_src;
    ip6 orig_dst;
    ip6 src;
    uint8_t orig_type = 0;

    if (!s || !orig)
        return;
    if (orig_frame_len < (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN))
        return;
    ip6_hdr_get_src(orig, &orig_src);
    ip6_hdr_get_dst(orig, &orig_dst);
    if ((orig->next_hdr == IP6_NEXTHDR_ICMPV6) &&
            (orig_frame_len >= sizeof(struct wolfIP_icmp6_packet)))
        orig_type = ((const struct wolfIP_icmp6_packet *)orig)->type;
    if (!icmp6_error_allowed(type, code, orig->next_hdr, orig_type,
                             &orig_src, &orig_dst))
        return;

    /* The reply is sourced from the address the offending packet was sent
     * to when that is one of ours, so the peer recognises it; otherwise
     * source selection picks one. */
    tx_if = ip6_route_for_dest(s, &orig_src);
    {
        int local = 0;

        (void)wolfIP_if_for_local_ip6(s, if_idx, &orig_dst, &local);
        if (local && !ip6_is_multicast(&orig_dst))
            ip6_copy(&src, &orig_dst);
        else if (ip6_select_source(s, tx_if, &orig_src, &src) != 0)
            return;
    }

    orig_len = orig_frame_len - (uint32_t)ETH_HEADER_LEN;
    /* 1280 total, less our own IPv6 header, less the 8-byte ICMPv6 header
     * (4 bytes of type/code/checksum and the 4-byte type-specific word). */
    quote = IP6_MIN_MTU - IP6_HEADER_LEN - ICMP6_ECHO_MIN_LEN;
    if (orig_len < quote)
        quote = orig_len;

    memset(frame, 0, ETH_HEADER_LEN + IP6_HEADER_LEN + ICMP6_ECHO_MIN_LEN);
    err->type = type;
    err->code = code;
    /* The four octets after the checksum are the type-specific word: the
     * MTU, the pointer, or unused-and-zero (RFC 4443 sections 3.1 to 3.4). */
    err->data[0] = (uint8_t)((param >> 24) & 0xFFu);
    err->data[1] = (uint8_t)((param >> 16) & 0xFFu);
    err->data[2] = (uint8_t)((param >> 8) & 0xFFu);
    err->data[3] = (uint8_t)(param & 0xFFu);
    memcpy(err->data + 4, (const uint8_t *)orig + ETH_HEADER_LEN, quote);
    payload_len = ICMP6_ECHO_MIN_LEN + quote;

    if (ip6_output_add_header(s, tx_if, &err->ip6, &src, &orig_src,
                              IP6_NEXTHDR_ICMPV6, (uint16_t)payload_len,
                              0, NULL) != 0)
        return;
    if (nd6_resolve(s, &tx_if, &orig_src, mac) != 0)
        return; /* unresolved: an error is not worth queueing for later */
#ifdef ETHERNET
    if (!wolfIP_ll_is_non_ethernet(s, tx_if))
        eth_output_add_header(s, tx_if, mac, &err->ip6.eth, ETH_TYPE_IPV6);
#endif
    (void)wolfIP_ll_send_frame(s, tx_if, frame,
                               (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) +
                               payload_len);
}

/* ---------------------------------------------------------------------- */
/* UDP over IPv6                                                          */
/* ---------------------------------------------------------------------- */

/* Is this socket entitled to receive an IPv6 datagram addressed to `dst`?
 *
 * Only an AF_INET6 socket ever is: an AF_INET socket has no way to report
 * an IPv6 peer to its application. Beyond that the rule is the one the IPv4
 * path uses, applied to the address the application asked for rather than
 * the one source selection chose - a wildcard bind takes anything addressed
 * to us, a specific bind takes only its own address. A socket bound to a
 * v4-mapped address is excluded by exactly this: its bound address is the
 * mapped one, which no IPv6 destination equals. */
static int udp6_socket_accepts(const struct tsocket *t, unsigned int if_idx,
                               const ip6 *dst)
{
    if (t->domain != AF_INET6)
        return 0;
    /* A link-local address names an endpoint only together with its link,
     * and the same one may sit on several interfaces (RFC 4007 section 6).
     * A socket bound to one is scoped to the interface that bind resolved
     * to; a wildcard bind carries no zone and is unaffected. */
    if (t->bound_v6 && ip6_is_link_local(&t->bound_local_ip6) &&
            (t->if_idx != (uint8_t)if_idx))
        return 0;
    if (ip6_is_unspecified(&t->bound_local_ip6))
        return 1;
    return (ip6_cmp(&t->bound_local_ip6, dst) == 0) ? 1 : 0;
}

static void udp6_try_recv(struct wolfIP *s, unsigned int if_idx,
                          struct wolfIP_udp6_datagram *udp, uint32_t frame_len)
{
    uint32_t udp_len;
    ip6 src;
    ip6 dst;
    int i;
    int matched;

    if (frame_len < sizeof(struct wolfIP_udp6_datagram))
        return;
    udp_len = ee16(udp->len);
    /* RFC 768: the length field covers the header and the payload, and RFC
     * 8200 section 8.1 forbids the zero checksum IPv4 permits. Both are
     * checked before anything reads the payload. */
    if (udp_len < UDP_HEADER_LEN)
        return;
    /* The frame may carry link-layer padding, so its length only bounds the
     * datagram from above. What fixes the datagram is the IPv6 Payload
     * Length: RFC 8200 section 8.1 makes that the Upper-Layer Packet Length
     * the checksum covers, and with no extension headers accepted here it is
     * the whole UDP datagram. A UDP Length larger than it would hand the
     * application trailing bytes no checksum ever covered. */
    if (udp_len != (uint32_t)ee16(udp->ip6.payload_len))
        return;
    if (frame_len < (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) + udp_len)
        return;
    if (udp->csum == 0)
        return;
    if (ip6_verify_transport_checksum(&udp->ip6) != 0)
        return;

    ip6_hdr_get_src(&udp->ip6, &src);
    ip6_hdr_get_dst(&udp->ip6, &dst);

    /* The datagram has to be addressed to us. The ingress filter admits
     * every 33:33:* destination MAC, because Neighbor Discovery and Router
     * Advertisements arrive that way, so without this any on-link host
     * could put payload into a socket bound to :: by aiming it at an
     * arbitrary group. Multicast delivery needs group membership, which
     * this stack does not keep for IPv6 yet; until it does, the honest
     * answer is that no group carries UDP for us. The IPv4 path requires
     * mcast_is_joined() and tcp6_input() drops multicast outright. */
    {
        int dst_is_local = 0;

        (void)wolfIP_if_for_local_ip6(s, if_idx, &dst, &dst_is_local);
        if (!dst_is_local)
            return;
    }

    matched = 0;
    for (i = 0; i < MAX_UDPSOCKETS; i++) {
        struct tsocket *t = &s->udpsockets[i];
        int peer_match;

        if (t->proto != WI_IPPROTO_UDP)
            continue;
        if (t->src_port != ee16(udp->dst_port))
            continue;
        if (!udp6_socket_accepts(t, if_idx, &dst))
            continue;
        /* As on the IPv4 side, only a connected socket filters by peer;
         * an unconnected one must take datagrams from any source. A
         * connected socket whose peer is IPv4 has no IPv6 peer to compare
         * against, and "no peer to compare" is not "any peer will do" - it
         * takes no IPv6 datagram at all. */
        peer_match = (t->sock.udp.connected == 0) ||
                (t->peer_is_v6 &&
                 (t->dst_port == 0 || t->dst_port == ee16(udp->src_port)) &&
                 (ip6_is_unspecified(&t->remote_ip6) ||
                  (ip6_cmp(&t->remote_ip6, &src) == 0)));
        if (!peer_match)
            continue;
        matched = 1;
        if (fifo_push(&t->sock.udp.rxbuf, udp, frame_len) == 0) {
            t->last_pkt_ttl = udp->ip6.hop_limit;
            t->events |= CB_EVENT_READABLE;
        }
    }
    if (!matched) {
        /* RFC 4443 section 3.1 code 4: nothing holds the port. The
         * destination was checked to be ours above, and
         * icmp6_send_error() applies the rest of the suppression rules. */
        icmp6_send_error(s, if_idx, &udp->ip6, frame_len,
                         ICMP6_DEST_UNREACH, ICMP6_DST_PORT_UNREACH, 0);
    }
}

/* ---------------------------------------------------------------------- */
/* Transmit-path address selection and resolution                         */
/* ---------------------------------------------------------------------- */

/* Source address selection (RFC 6724, reduced to what this stack needs).
 *
 * The full rules rank candidates by scope, preference, longest match and
 * more. wolfIP has at most a handful of addresses per interface, so the two
 * rules that actually change the outcome here are applied and no others:
 * prefer an address of the destination's scope, which is what makes a
 * link-local destination use a link-local source rather than a global one
 * (RFC 6724 rule 2), and never offer a tentative or deprecated address
 * (rule 3). Returns 0 on success. */
static int ip6_select_source(struct wolfIP *s, unsigned int if_idx,
                             const ip6 *dst, ip6 *src)
{
    struct wolfIP_ifaddr_info info;
    unsigned int count;
    unsigned int i;
    int want_ll = ip6_is_link_local(dst) || ip6_is_mcast_link_local(dst);
    int have_fallback = 0;

    if (!s || !dst || !src)
        return -1;
    count = wolfIP_ifaddr_count(s, if_idx, AF_INET6);
    for (i = 0; i < count; i++) {
        if (wolfIP_ifaddr_get(s, if_idx, AF_INET6, i, &info) != 0)
            continue;
        if (info.state != WOLFIP_IFADDR_PREFERRED)
            continue;
        if (ip6_is_link_local(&info.v6) == want_ll) {
            ip6_copy(src, &info.v6);
            return 0;
        }
        if (!have_fallback) {
            ip6_copy(src, &info.v6);
            have_fallback = 1;
        }
    }
    return have_fallback ? 0 : -1;
}

/* Which interface carries this destination. Mirrors wolfIP_route_for_ip():
 * the interface whose on-link prefix covers it, or the one holding a
 * default router, falling back to the primary. */
static unsigned int ip6_route_for_dest(struct wolfIP *s, const ip6 *dst)
{
    unsigned int i;

    for (i = 0; i < WOLFIP_MAX_INTERFACES; i++) {
        if (wolfIP_ifaddr_count(s, i, AF_INET6) == 0)
            continue;
        if (nd6_is_onlink(s, i, dst))
            return i;
    }
    for (i = 0; i < WOLFIP_ND6_ROUTER_MAX; i++) {
        if (s->nd6.routers[i].used)
            return s->nd6.routers[i].if_idx;
    }
    for (i = 0; i < WOLFIP_MAX_INTERFACES; i++) {
        if (wolfIP_ifaddr_count(s, i, AF_INET6) > 0)
            return i;
    }
    return WOLFIP_PRIMARY_IF_IDX;
}

/* Resolve the link-layer address for a destination, starting resolution if
 * it is not known yet. Returns 0 when `mac` is usable, -1 when the caller
 * must hold the packet and retry.
 *
 * The IPv6 counterpart of arp_lookup()+arp_request(), and like the ARP path
 * it throttles: an unanswered solicitation would otherwise be re-sent on
 * every pass of the transmit queue. RFC 4861 section 7.2.2 allows one
 * solicitation per retransmit timer, and the INCOMPLETE entry's timestamp
 * is what paces it. A link with no link-layer addresses resolves trivially
 * - there is one peer and the link reaches it (RFC 4861 section 3). */
static int nd6_resolve(struct wolfIP *s, unsigned int *tx_if, const ip6 *dst,
                       uint8_t *mac)
{
    ip6 nexthop;
    ip6 src;
    int idx;

    if (wolfIP_ll_is_non_ethernet(s, *tx_if)) {
        memset(mac, 0, 6);
        return 0;
    }
    if (nd6_select_nexthop(s, *tx_if, dst, &nexthop) != 0)
        return -1; /* no route */
    if (nd6_lookup(s, *tx_if, &nexthop, mac) == 0)
        return 0;

    if (ip6_select_source(s, *tx_if, &nexthop, &src) != 0)
        return -1; /* nothing to solicit from yet */
    idx = nd6_neighbor_index(s, *tx_if, &nexthop);
    if (idx < 0) {
        nd6_store_neighbor(s, *tx_if, &nexthop, NULL, ND6_INCOMPLETE, 0);
        nd6_send_ns(s, *tx_if, &nexthop, &src);
        nd6_arm_tick(s);
    } else if ((s->last_tick - s->nd6.neighbors[idx].ts) >=
               ND6_RETRANS_TIMER_MS) {
        s->nd6.neighbors[idx].ts = s->last_tick;
        s->nd6.neighbors[idx].probes++;
        nd6_send_ns(s, *tx_if, &nexthop, &src);
    }
    return -1;
}

/* Settle a datagram socket's IPv6 egress state for `dst`: which interface
 * carries it and which of our addresses to send from. Called from sendto()
 * before the datagram is built, because the source address is part of the
 * checksum and so has to be known first. Returns 0 on success. */
static int udp6_prepare_tx(struct wolfIP *s, struct tsocket *t, const ip6 *dst)
{
    unsigned int if_idx;
    ip6 src;

    /* A bound socket transmits from the address it was bound to; only an
     * unbound one gets to have a source selected for it. */
    if (!ip6_is_unspecified(&t->bound_local_ip6)) {
        int match = 0;

        if_idx = wolfIP_if_for_local_ip6(s, t->if_idx, &t->bound_local_ip6,
                                         &match);
        if (!match)
            return -1;
        ip6_copy(&src, &t->bound_local_ip6);
    } else {
        if_idx = ip6_route_for_dest(s, dst);
        if (ip6_select_source(s, if_idx, dst, &src) != 0)
            return -1; /* no usable source address yet */
    }
    t->if_idx = (uint8_t)if_idx;
    ip6_copy(&t->local_ip6, &src);
    return 0;
}

/* The largest UDP payload this socket can send over IPv6.
 *
 * IPv6 routers do not fragment (RFC 8200 section 4.5), and this stack does
 * not fragment at the source either, so anything that does not fit is
 * refused at sendto() rather than truncated on the way out. */
static uint32_t udp6_max_payload(struct wolfIP *s, unsigned int if_idx)
{
    uint32_t mtu = wolfIP_ip_mtu(s, if_idx);

    if (mtu < IP6_MIN_MTU)
        mtu = IP6_MIN_MTU;
    if (mtu <= (uint32_t)(IP6_HEADER_LEN + UDP_HEADER_LEN))
        return 0;
    return mtu - IP6_HEADER_LEN - UDP_HEADER_LEN;
}

/* ---------------------------------------------------------------------- */
/* Socket address conversion, AF_INET6                                    */
/* ---------------------------------------------------------------------- */

/* Read a sockaddr into an ip6 plus the port, whichever family it carries.
 * An AF_INET address becomes its v4-mapped form, so a caller working on an
 * AF_INET6 socket sees one address type; sock_addr_is_v6() below is what
 * distinguishes the two afterwards. Returns 0 on success. */
static int sock_addr_to_ip6(const struct wolfIP_sockaddr *addr,
                            socklen_t addrlen, ip6 *out, uint16_t *port)
{
    if (!addr || !out)
        return -WOLFIP_EINVAL;
    if (addr->sa_family == AF_INET6) {
        const struct wolfIP_sockaddr_in6 *sin6 =
            (const struct wolfIP_sockaddr_in6 *)addr;

        if (addrlen < sizeof(struct wolfIP_sockaddr_in6))
            return -WOLFIP_EINVAL;
        memcpy(out->addr, &sin6->sin6_addr, 16);
        if (port)
            *port = ee16(sin6->sin6_port);
        return 0;
    }
    if (addr->sa_family == AF_INET) {
        const struct wolfIP_sockaddr_in *sin =
            (const struct wolfIP_sockaddr_in *)addr;

        if (addrlen < sizeof(struct wolfIP_sockaddr_in))
            return -WOLFIP_EINVAL;
        ip6_set_v4mapped(out, ee32(sin->sin_addr.s_addr));
        if (port)
            *port = ee16(sin->sin_port);
        return 0;
    }
    return -WOLFIP_EINVAL;
}

/* Does this address make the socket speak IPv6 on the wire?
 *
 * The unspecified address is the awkward one: :: means "any" rather than a
 * destination, so a bind to it settles nothing about framing and is treated
 * as not-yet-v6. A v4-mapped address is IPv4 on the wire by definition. */
static int ip6_addr_is_wire_v6(const ip6 *a)
{
    return (!ip6_is_v4mapped(a) && !ip6_is_unspecified(a)) ? 1 : 0;
}

/* Render an address back to the application in the family of its socket. An
 * AF_INET6 socket always gets a sockaddr_in6, with an IPv4 peer appearing as
 * ::ffff:a.b.c.d (RFC 3493 section 3.7), because that is the one address
 * type such an application is prepared to parse. */
static int sock_addr_from_ip6(struct wolfIP_sockaddr *addr, socklen_t *addrlen,
                              const ip6 *v6, uint16_t port,
                              unsigned int scope_id)
{
    struct wolfIP_sockaddr_in6 *sin6 = (struct wolfIP_sockaddr_in6 *)addr;

    if (!addr)
        return -WOLFIP_EINVAL;
    if (addrlen && (*addrlen < sizeof(struct wolfIP_sockaddr_in6)))
        return -WOLFIP_EINVAL;
    memset(sin6, 0, sizeof(*sin6));
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = ee16(port);
    memcpy(&sin6->sin6_addr, v6->addr, 16);
    /* Only a link-local address is ambiguous without one (RFC 4007 s6). */
    if (ip6_is_link_local(v6))
        sin6->sin6_scope_id = scope_id;
    if (addrlen)
        *addrlen = sizeof(struct wolfIP_sockaddr_in6);
    return 0;
}

/* sendto() for a UDP socket whose destination is a real IPv6 address.
 *
 * `frame` is the caller's staging buffer rather than one of our own: the
 * datagram has to be contiguous for fifo_push(), and a second LINK_MTU
 * buffer live at the same time as the caller's would double the stack cost
 * of every sendto on a target where that matters.
 *
 * The IPv6 header is filled here rather than at flush time, as the IPv4
 * path does, because the checksum covers the addresses and so must be
 * computed while the socket's routing state still matches this datagram. */
static int udp6_sendto(struct wolfIP *s, struct tsocket *t, uint8_t *frame,
                       const void *buf, size_t len)
{
    struct wolfIP_udp6_datagram *udp = (struct wolfIP_udp6_datagram *)frame;
    uint32_t frame_len;
    uint32_t max_payload;

    if (t->dst_port == 0)
        return -1;
    if (ip6_is_unspecified(&t->remote_ip6) || ip6_is_multicast(&t->remote_ip6)) {
        /* A multicast destination needs group state this stack does not
         * keep for IPv6 yet, and the unspecified address is not a
         * destination at all (RFC 4291 section 2.5.2). */
        if (!ip6_is_multicast(&t->remote_ip6))
            return -1;
        return -1;
    }
    if (t->src_port == 0) {
        /* Probe for a free port rather than trusting one draw, as the IPv4
         * path does: a collision would match one flow to two sockets. */
        t->src_port = port_alloc_random6(s->udpsockets, MAX_UDPSOCKETS, t,
                                         &t->local_ip6, 1024);
        if (t->src_port == 0)
            return -WOLFIP_EAGAIN;
    }
    if (udp6_prepare_tx(s, t, &t->remote_ip6) != 0)
        return -1;

    max_payload = udp6_max_payload(s, t->if_idx);
    if ((max_payload == 0) || (len > max_payload))
        return -1; /* no fragmentation: refused rather than truncated */

    frame_len = (uint32_t)sizeof(struct wolfIP_udp6_datagram) + (uint32_t)len;
    if (!fifo_can_push_len(&t->sock.udp.txbuf, frame_len))
        return -WOLFIP_EAGAIN;

    memset(frame, 0, sizeof(struct wolfIP_udp6_datagram));
    udp->src_port = ee16(t->src_port);
    udp->dst_port = ee16(t->dst_port);
    udp->len = ee16((uint16_t)(len + UDP_HEADER_LEN));
    memcpy(udp->data, buf, len);
    if (ip6_output_add_header(s, t->if_idx, &udp->ip6, &t->local_ip6,
                              &t->remote_ip6, IP6_NEXTHDR_UDP,
                              (uint16_t)(len + UDP_HEADER_LEN),
                              0, NULL) != 0)
        return -1;
    if (fifo_push(&t->sock.udp.txbuf, frame, frame_len) < 0)
        return -WOLFIP_EAGAIN;
    return (int)len;
}

/* Transmit one queued IPv6 datagram: route it, resolve the next hop, add
 * the link header and hand it to the driver. Returns 0 when the descriptor
 * has been sent and may be popped, -1 when it must stay queued - no route,
 * address resolution still in flight, or driver backpressure.
 *
 * The IPv4 flush does this inline; it is a function here because the same
 * sequence is needed by the TCP path, and because doing it in one place is
 * what keeps the two families from drifting apart. */
static int flush_datagram6_one(struct wolfIP *s, struct tsocket *t,
                               struct pkt_desc *desc, unsigned int *tx_if)
{
    struct wolfIP_ip6_packet *pkt =
        (struct wolfIP_ip6_packet *)(t->txmem + desc->pos + sizeof(*desc));
    uint8_t mac[6];
    ip6 dst;

    ip6_hdr_get_dst(pkt, &dst);
    /* Route for this descriptor's destination rather than the socket's
     * current one: a sendto() to another peer may have moved it since. */
    *tx_if = ip6_route_for_dest(s, &dst);
    if (nd6_resolve(s, tx_if, &dst, mac) != 0)
        return -1;
#ifdef ETHERNET
    if (!wolfIP_ll_is_non_ethernet(s, *tx_if))
        eth_output_add_header(s, *tx_if, mac, &pkt->eth, ETH_TYPE_IPV6);
#endif
    if (wolfIP_ll_send_frame(s, *tx_if, pkt, desc->len) < 0)
        return -1;
    return 0;
}

/* recvfrom() for a queued IPv6 datagram. The peer is reported as a
 * sockaddr_in6, which is what an AF_INET6 application expects; a datagram
 * that arrived over IPv4 on the same socket is handled by the caller and
 * never reaches here. */
static int udp6_recvfrom(struct wolfIP *s, struct tsocket *t, void *buf,
                         size_t len, struct wolfIP_sockaddr *src_addr,
                         socklen_t *addrlen)
{
    struct pkt_desc *desc = fifo_peek(&t->sock.udp.rxbuf);
    struct wolfIP_udp6_datagram *udp;
    uint32_t seg_len;
    ip6 src;

    (void)s;
    if (!desc)
        return -WOLFIP_EAGAIN;
    udp = (struct wolfIP_udp6_datagram *)(t->rxmem + desc->pos + sizeof(*desc));
    if (ee16(udp->len) < UDP_HEADER_LEN) {
        fifo_pop(&t->sock.udp.rxbuf);
        return -WOLFIP_EINVAL;
    }
    seg_len = (uint32_t)ee16(udp->len) - UDP_HEADER_LEN;
    if (seg_len > len) {
        /* Same rule as the IPv4 arm: an oversized datagram is dropped
         * rather than silently truncated. */
        fifo_pop(&t->sock.udp.rxbuf);
        if (fifo_peek(&t->sock.udp.rxbuf) == NULL)
            t->events &= ~CB_EVENT_READABLE;
        return -WOLFIP_EINVAL;
    }
    ip6_hdr_get_src(&udp->ip6, &src);
    /* An unconnected socket learns its peer from the first datagram, the
     * way the IPv4 path does, so a reply with no explicit destination goes
     * back where the request came from. */
    if (!t->peer_is_v6 && ip6_is_unspecified(&t->remote_ip6)) {
        t->peer_is_v6 = 1;
        ip6_copy(&t->remote_ip6, &src);
    }
    if (src_addr) {
        socklen_t want = sizeof(struct wolfIP_sockaddr_in6);

        if (addrlen && (*addrlen < want))
            return -WOLFIP_EINVAL;
        if (sock_addr_from_ip6(src_addr, &want, &src, ee16(udp->src_port),
                               t->if_idx) != 0)
            return -WOLFIP_EINVAL;
        if (addrlen)
            *addrlen = want;
    }
    memcpy(buf, udp->data, seg_len);
    fifo_pop(&t->sock.udp.rxbuf);
    if (fifo_peek(&t->sock.udp.rxbuf) == NULL)
        t->events &= ~CB_EVENT_READABLE;
    return (int)seg_len;
}

/* ---------------------------------------------------------------------- */
/* TCP over IPv6                                                          */
/* ---------------------------------------------------------------------- */

/* The TCP transmit builders all construct an IPv4-shaped frame - Ethernet
 * header, 20 bytes of room for the IP header, then the segment - and leave
 * the IP header to be filled at send time. Rather than a second set of
 * builders differing only in an offset, the segment is moved 20 bytes later
 * here and an IPv6 header written in front of it.
 *
 * `staging` is the caller's buffer because the queued frame has no spare
 * room: the FIFO slot was sized for the IPv4 layout. Returns the length of
 * the promoted frame, or 0 if it would not fit. */
static uint32_t tcp6_promote(const struct tsocket *t, const void *v4frame,
                             uint32_t frame_len, uint8_t *staging,
                             uint32_t staging_len)
{
    uint32_t seg_len;
    uint32_t out_len;

    if (frame_len < (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN))
        return 0;
    seg_len = frame_len - (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN);
    out_len = (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) + seg_len;
    if (out_len > staging_len)
        return 0;
    memset(staging, 0, ETH_HEADER_LEN + IP6_HEADER_LEN);
    memcpy(staging + ETH_HEADER_LEN + IP6_HEADER_LEN,
           (const uint8_t *)v4frame + ETH_HEADER_LEN + IP_HEADER_LEN, seg_len);
    (void)t;
    return out_len;
}

/* Promote, address, resolve and transmit one TCP segment over IPv6.
 * Returns 0 on success, -WOLFIP_EAGAIN while address resolution is still in
 * flight so the caller holds the segment, or -1 on a hard failure. */
static int tcp6_send_seg(struct wolfIP *s, struct tsocket *t,
                         const void *v4frame, uint32_t frame_len)
{
    uint8_t staging[LINK_MTU];
    struct wolfIP_tcp6_seg *out;
    unsigned int tx_if;
    uint32_t out_len;
    uint8_t mac[6];

    out_len = tcp6_promote(t, v4frame, frame_len, staging, sizeof(staging));
    if (out_len == 0)
        return -1;
    out = (struct wolfIP_tcp6_seg *)staging;
    if (ip6_output_add_header(s, t->if_idx, &out->ip6, &t->local_ip6,
                              &t->remote_ip6, IP6_NEXTHDR_TCP,
                              (uint16_t)(out_len - ETH_HEADER_LEN -
                                         IP6_HEADER_LEN),
                              0, NULL) != 0)
        return -1;
    tx_if = ip6_route_for_dest(s, &t->remote_ip6);
    if (nd6_resolve(s, &tx_if, &t->remote_ip6, mac) != 0)
        return -WOLFIP_EAGAIN;
    t->if_idx = (uint8_t)tx_if;
#ifdef ETHERNET
    if (!wolfIP_ll_is_non_ethernet(s, tx_if))
        eth_output_add_header(s, tx_if, mac, &out->ip6.eth, ETH_TYPE_IPV6);
#endif
    if (wolfIP_ll_send_frame(s, tx_if, staging, out_len) < 0)
        return -WOLFIP_EAGAIN;
    return 0;
}

/* Reset in reply to a segment matching no socket. Built from the incoming
 * segment rather than from a socket, since by definition there is none, so
 * it takes the addresses from the flow and swaps them. */
static void tcp6_send_reset_reply(struct wolfIP *s, unsigned int if_idx,
                                  const struct wolfIP_tcp_seg *in,
                                  const struct ip_flow *flow)
{
    uint8_t staging[ETH_HEADER_LEN + IP6_HEADER_LEN + TCP_HEADER_LEN];
    struct wolfIP_tcp6_seg *out = (struct wolfIP_tcp6_seg *)staging;
    uint32_t tcp_hlen;
    uint32_t seg_ack;
    uint8_t mac[6];
    unsigned int tx_if = if_idx;

    /* RFC 4443 in spirit and RFC 9293 outright: never answer a reset with a
     * reset, or two nodes sustain the exchange forever. */
    if (in->flags & TCP_FLAG_RST)
        return;
    tcp_hlen = tcp_data_offset_bytes(in->hlen);
    if (tcp_hlen < TCP_HEADER_LEN)
        return;
    if (flow->transport_len < tcp_hlen)
        return;

    memset(staging, 0, sizeof(staging));
    out->src_port = in->dst_port;
    out->dst_port = in->src_port;
    out->hlen = (uint8_t)(TCP_HEADER_LEN << 2);
    if (in->flags & TCP_FLAG_ACK) {
        out->seq = in->ack;
        out->flags = TCP_FLAG_RST;
    } else {
        seg_ack = ee32(in->seq);
        seg_ack = tcp_seq_inc(seg_ack,
                              (uint32_t)(flow->transport_len - tcp_hlen));
        if (in->flags & TCP_FLAG_SYN)
            seg_ack = tcp_seq_inc(seg_ack, 1);
        if (in->flags & TCP_FLAG_FIN)
            seg_ack = tcp_seq_inc(seg_ack, 1);
        out->ack = ee32(seg_ack);
        out->flags = TCP_FLAG_RST | TCP_FLAG_ACK;
    }
    /* Source and destination swap: the reply comes from the address that
     * was addressed. */
    if (ip6_output_add_header(s, if_idx, &out->ip6, &flow->dst6, &flow->src6,
                              IP6_NEXTHDR_TCP, TCP_HEADER_LEN, 0, NULL) != 0)
        return;
    if (nd6_resolve(s, &tx_if, &flow->src6, mac) != 0)
        return; /* unresolved: the reset is not worth queueing */
#ifdef ETHERNET
    if (!wolfIP_ll_is_non_ethernet(s, tx_if))
        eth_output_add_header(s, tx_if, mac, &out->ip6.eth, ETH_TYPE_IPV6);
#endif
    (void)wolfIP_ll_send_frame(s, tx_if, staging, sizeof(staging));
}

/* Active open to an IPv6 peer. The IPv4 arm of wolfIP_sock_connect() with
 * the address handling replaced: same state transition, same ephemeral port
 * rule, same SYN. Local state is resolved into locals and only committed
 * once it has validated, so a failure cannot leave the socket stuck in
 * SYN_SENT with no SYN queued and no timer - the same care the IPv4 arm
 * takes for the same reason. */
static int tcp6_connect(struct wolfIP *s, struct tsocket *t, const ip6 *dst,
                        uint16_t dport)
{
    unsigned int if_idx;
    ip6 src;

    if (t->sock.tcp.state == TCP_ESTABLISHED)
        return 0;
    if (t->sock.tcp.state == TCP_SYN_SENT)
        return -WOLFIP_EAGAIN;
    if (t->sock.tcp.state != TCP_CLOSED)
        return -WOLFIP_EINVAL;

    if (!ip6_is_unspecified(&t->bound_local_ip6)) {
        int match = 0;

        if_idx = wolfIP_if_for_local_ip6(s, t->if_idx, &t->bound_local_ip6,
                                         &match);
        if (!match)
            return -WOLFIP_EINVAL;
        ip6_copy(&src, &t->bound_local_ip6);
    } else {
        if_idx = ip6_route_for_dest(s, dst);
        if (ip6_select_source(s, if_idx, dst, &src) != 0)
            return -WOLFIP_EINVAL;
    }

    t->peer_is_v6 = 1;
    t->if_idx = (uint8_t)if_idx;
    ip6_copy(&t->local_ip6, &src);
    ip6_copy(&t->remote_ip6, dst);
    t->sock.tcp.state = TCP_SYN_SENT;
    if (!t->src_port) {
        /* Probed, not drawn once: a repeated ephemeral port would give two
         * connections the same local endpoint. Same rule as the IPv4
         * connect() path. */
        t->src_port = port_alloc_random6(s->tcpsockets, MAX_TCPSOCKETS, t,
                                         &t->local_ip6, 1024);
        if (t->src_port == 0) {
            t->sock.tcp.state = TCP_CLOSED;
            return -WOLFIP_EAGAIN;
        }
    }
    if (t->src_port < 1024)
        t->src_port = (uint16_t)(t->src_port + 1024);
    t->dst_port = dport;
    t->sock.tcp.seq = wolfIP_getrandom();
    t->sock.tcp.snd_una = t->sock.tcp.seq;
    if (tcp_send_syn(t, TCP_FLAG_SYN) < 0) {
        t->sock.tcp.state = TCP_CLOSED;
        return -1;
    }
    t->sock.tcp.ctrl_rto_retries = 0;
    tcp_ctrl_rto_start(t, s->last_tick);
    return -WOLFIP_EAGAIN; /* in progress, as the IPv4 arm reports it */
}

/* Ingress for TCP over IPv6.
 *
 * The length and checksum rules are the IPv6 ones and are applied here;
 * everything after that is the shared state machine, reached by pointing a
 * v4-shaped segment pointer at the TCP header. That pointer's `ip` member
 * overlaps the tail of the IPv6 header and is never read: tcp_input() takes
 * its addresses from the flow, which is the whole reason the flow exists. */
static void tcp6_input(struct wolfIP *s, unsigned int if_idx,
                       struct wolfIP_tcp6_seg *seg, uint32_t frame_len)
{
    struct ip_flow flow;
    struct wolfIP_tcp_seg *aliased;
    uint32_t payload_len;

    if (frame_len < sizeof(struct wolfIP_tcp6_seg))
        return;
    payload_len = ee16(seg->ip6.payload_len);
    if (payload_len < TCP_HEADER_LEN)
        return;
    if (frame_len < (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) + payload_len)
        return;
    if (ip6_verify_transport_checksum(&seg->ip6) != 0)
        return;

    memset(&flow, 0, sizeof(flow));
    flow.is_v6 = 1;
    flow.if_idx = (uint8_t)if_idx;
    flow.ttl = seg->ip6.hop_limit;
    flow.hdr_len = IP6_HEADER_LEN;
    flow.transport_len = payload_len;
    ip6_hdr_get_src(&seg->ip6, &flow.src6);
    ip6_hdr_get_dst(&seg->ip6, &flow.dst6);
    /* A multicast destination is never a TCP endpoint. */
    if (ip6_is_multicast(&flow.dst6))
        return;
    /* The segment has to be addressed to an address of ours on the link it
     * arrived over, the same gate udp6_try_recv() applies. The interface
     * matters, not just the address: a link-local address identifies an
     * endpoint only together with its zone (RFC 4007 section 6), and the
     * same one may legitimately exist on another interface. Without this a
     * listener bound to fe80::x on one interface answered segments for the
     * identical address on another, and a wildcard listener answered
     * segments not addressed to this host at all. */
    {
        int dst_is_local = 0;

        (void)wolfIP_if_for_local_ip6(s, if_idx, &flow.dst6, &dst_is_local);
        if (!dst_is_local)
            return;
    }

    aliased = (struct wolfIP_tcp_seg *)((uint8_t *)seg +
                                        (IP6_HEADER_LEN - IP_HEADER_LEN));
    tcp_input_flow(s, if_idx, aliased,
                   frame_len - (uint32_t)(IP6_HEADER_LEN - IP_HEADER_LEN),
                   &flow);
}

/* ---------------------------------------------------------------------- */
/* Receive                                                                */
/* ---------------------------------------------------------------------- */

/* Neighbor Solicitation (RFC 4861 section 7.1.1 and 7.2.3). */
static void nd6_recv_ns(struct wolfIP *s, unsigned int if_idx,
                        struct wolfIP_ip6_packet *pkt, uint32_t payload_len)
{
    struct nd6_msg *ns = (struct nd6_msg *)pkt;
    const uint8_t *opt;
    struct wolfIP_ifaddr_slot *slot;
    ip6 target;
    ip6 src;
    ip6 dst;
    ip6 reply_dst;
    uint8_t reply_mac[6];
    uint8_t flags = ND6_NA_SOLICITED | ND6_NA_OVERRIDE;

    if (payload_len < 24u)
        return;
    if (!nd6_options_valid(ns->options, payload_len - 24u))
        return;
    memcpy(target.addr, ns->target, 16);
    /* RFC 4861 section 7.1.1: the target must not be a multicast address. */
    if (ip6_is_multicast(&target))
        return;
    ip6_hdr_get_src(pkt, &src);
    ip6_hdr_get_dst(pkt, &dst);

    slot = nd6_slot_for(s, if_idx, &target);
    if (slot == NULL)
        return; /* not our address: nothing to answer */

    if (ip6_is_unspecified(&src)) {
        ip6 solicited;

        ip6_set_solicited_node(&solicited, &target);
        /* RFC 4861 section 7.1.1: a DAD solicitation must go to the
         * target's solicited-node multicast address and must not carry a
         * Source Link-Layer Address option. */
        if ((ip6_cmp(&dst, &solicited) != 0) ||
                (nd6_find_option(ns->options, payload_len - 24u,
                                 ND6_OPT_SLLA) != NULL))
            return;
        /* Somebody else is running duplicate address detection for this
         * address (RFC 4862 section 5.4.3).
         *
         * If it is still tentative for us too, we are both probing at the
         * same time and neither may use it. If it is already ours, they
         * must be told, and the answer goes to the all-nodes group because
         * a node with no address cannot be addressed directly. */
        if (slot->info.state == WOLFIP_IFADDR_TENTATIVE) {
            nd6_dad_failed(s, slot);
            return;
        }
        ip6_set_all_nodes(&reply_dst);
        ip6_mcast_to_eth(&reply_dst, reply_mac);
        /* Unsolicited: the requester is not yet addressable. */
        flags = ND6_NA_OVERRIDE;
        nd6_send_na(s, if_idx, &target, &target, &reply_dst, reply_mac, flags);
        return;
    }

    {
        ip6 solicited;

        /* RFC 4861 sections 4.3 and 7.1.1: ordinary address resolution uses
         * either the target's solicited-node group or the target itself for
         * Neighbor Unreachability Detection. */
        ip6_set_solicited_node(&solicited, &target);
        if ((ip6_cmp(&dst, &target) != 0) &&
                (ip6_cmp(&dst, &solicited) != 0))
            return;
    }

    /* A tentative address must not be defended and must not answer: it is
     * not ours yet. */
    if (slot->info.state == WOLFIP_IFADDR_TENTATIVE)
        return;

    /* RFC 4861 section 7.2.3: record the sender so the advertisement has
     * somewhere to go and the reverse direction is already resolved. */
    if (wolfIP_ll_is_non_ethernet(s, if_idx)) {
        /* A link with no link-layer addresses. The solicitation cannot
         * carry a meaningful Source Link-Layer Address option and there is
         * no frame header to cross-check one against, so any option present
         * is ignored rather than treated as a mismatch - the sender is
         * wrong, but the solicitation is still a solicitation. The reply
         * goes back over the link itself, so the cache entry records
         * reachability with no address (RFC 4861 section 3). */
        memset(reply_mac, 0, sizeof(reply_mac));
        nd6_store_neighbor(s, if_idx, &src, reply_mac, ND6_STALE, 0);
    } else {
        opt = nd6_find_option(ns->options, payload_len - 24u, ND6_OPT_SLLA);
        if (opt != NULL) {
            const struct nd6_opt_lla *lla = (const struct nd6_opt_lla *)opt;

            if (lla->len != 1u)
                return;
            /* RFC 2464 section 6: on Ethernet the SLLA is the sender's
             * link-layer address. A disagreement would redirect both our
             * reply and cache entry to an uninvolved host. */
            if (memcmp(lla->mac, pkt->eth.src, 6) != 0)
                return;
            nd6_store_neighbor(s, if_idx, &src, lla->mac, ND6_STALE, 0);
            memcpy(reply_mac, lla->mac, 6);
        } else {
            memcpy(reply_mac, pkt->eth.src, 6);
        }
    }
    ip6_copy(&reply_dst, &src);
    nd6_send_na(s, if_idx, &target, &target, &reply_dst, reply_mac, flags);
}

/* Neighbor Advertisement (RFC 4861 section 7.1.2 and 7.2.5). */
static void nd6_recv_na(struct wolfIP *s, unsigned int if_idx,
                        struct wolfIP_ip6_packet *pkt, uint32_t payload_len)
{
    struct nd6_msg *na = (struct nd6_msg *)pkt;
    const uint8_t *opt;
    struct wolfIP_ifaddr_slot *slot;
    struct nd6_neighbor *n;
    ip6 target;
    ip6 src;
    ip6 dst;
    int idx;

    if (payload_len < 24u)
        return;
    if (!nd6_options_valid(na->options, payload_len - 24u))
        return;
    memcpy(target.addr, na->target, 16);
    if (ip6_is_multicast(&target))
        return;
    ip6_hdr_get_src(pkt, &src);
    /* RFC 4861 section 7.1.2: an Advertisement source must be unicast. */
    if (ip6_is_unspecified(&src))
        return;
    ip6_hdr_get_dst(pkt, &dst);
    if (!nd6_destination_is_local(s, if_idx, &dst))
        return;
    /* RFC 4861 section 7.1.2: a solicited advertisement must not be sent to
     * a multicast address. */
    if ((na->flags & ND6_NA_SOLICITED) && ip6_is_multicast(&dst))
        return;

    /* Somebody is using an address we are still probing for. */
    slot = nd6_slot_for(s, if_idx, &target);
    if ((slot != NULL) && (slot->info.state == WOLFIP_IFADDR_TENTATIVE)) {
        nd6_dad_failed(s, slot);
        return;
    }

    idx = nd6_neighbor_index(s, if_idx, &target);
    if (idx < 0)
        return; /* unsolicited advertisement for an unknown neighbour */
    n = &s->nd6.neighbors[idx];

    opt = nd6_find_option(na->options, payload_len - 24u, ND6_OPT_TLLA);
    if (opt != NULL) {
        const struct nd6_opt_lla *lla = (const struct nd6_opt_lla *)opt;

        if (lla->len != 1u)
            return;
        if (n->state == ND6_INCOMPLETE) {
            /* The answer we were waiting for. */
            memcpy(n->mac, lla->mac, 6);
        } else if ((na->flags & ND6_NA_OVERRIDE) == 0) {
            if (memcmp(n->mac, lla->mac, 6) != 0) {
                /* RFC 4861 section 7.2.5: without the Override flag a
                 * differing link-layer address must not replace the one we
                 * hold - that is what stops an advertisement hijacking an
                 * established neighbour. A REACHABLE entry still drops to
                 * STALE so its reachability is re-verified; in any other
                 * state the advertisement is ignored outright. */
                if (n->state == ND6_REACHABLE) {
                    n->state = ND6_STALE;
                    n->ts = s->last_tick;
                }
                return;
            }
        } else {
            memcpy(n->mac, lla->mac, 6);
        }
    } else if (n->state == ND6_INCOMPLETE) {
        /* No Target Link-Layer Address option. Where the link has
         * link-layer addresses that means nothing was learned and the entry
         * stays unresolved. Where it does not, there was never anything to
         * learn - reaching the peer is what the link does - so the
         * advertisement on its own completes the entry (RFC 4861 s3). */
        if (!wolfIP_ll_is_non_ethernet(s, if_idx))
            return;
        memset(n->mac, 0, sizeof(n->mac));
    }

    if (na->flags & ND6_NA_SOLICITED)
        n->state = ND6_REACHABLE;
    else if (n->state == ND6_INCOMPLETE)
        n->state = ND6_STALE;
    n->probes = 0;
    n->ts = s->last_tick;
    /* RFC 4861 section 7.2.5: IsRouter is set from the Router flag of the
     * advertisement, in both directions. A node that stops being a router
     * says so by clearing the flag, and when IsRouter goes from true to
     * false the node must also leave the Default Router List - otherwise
     * traffic keeps being handed to a host that has just disclaimed the
     * job. */
    if (na->flags & ND6_NA_ROUTER) {
        n->is_router = 1;
    } else {
        if (n->is_router)
            nd6_router_forget(s, if_idx, &target);
        n->is_router = 0;
    }
}

/* Router Advertisement (RFC 4861 section 6.3.4). Minimal on purpose: the
 * default router and the Prefix Information options, which is what an
 * ordinary site network needs to hand out an address. Managed/Other flags,
 * MTU, retransmit and reachable timer overrides are parsed past but not
 * acted on. */
static void nd6_recv_ra(struct wolfIP *s, unsigned int if_idx,
                        struct wolfIP_ip6_packet *pkt, uint32_t payload_len)
{
    struct nd6_ra_msg *ra = (struct nd6_ra_msg *)pkt;
    const uint8_t *opts;
    uint32_t opt_len;
    uint32_t off;
    ip6 src;
    ip6 dst;

    if (payload_len < 16u)
        return;
    ip6_hdr_get_src(pkt, &src);
    /* RFC 4861 section 6.1.2: the source of a Router Advertisement must be a
     * link-local address. Accepting a global source would let anything off
     * the link install a default route. */
    if (!ip6_is_link_local(&src))
        return;
    ip6_hdr_get_dst(pkt, &dst);
    if (!nd6_destination_is_local(s, if_idx, &dst))
        return;

    opts = ra->options;
    opt_len = payload_len - 16u;
    if (!nd6_options_valid(opts, opt_len))
        return;

    /* Only mutate the router, neighbor and prefix tables after the complete
     * option area has passed framing validation. */
    nd6_router_store(s, if_idx, &src, ee16(ra->router_lifetime));
    nd6_store_neighbor(s, if_idx, &src, pkt->eth.src, ND6_STALE, 1);
    off = 0;
    while ((off + 2u) <= opt_len) {
        uint8_t type = opts[off];
        uint32_t olen = (uint32_t)opts[off + 1] * 8u;

        if (olen == 0)
            return;                 /* malformed: would not terminate */
        if ((off + olen) > opt_len)
            return;
        if ((type == ND6_OPT_PREFIX) &&
                (olen == sizeof(struct nd6_opt_prefix))) {
            const struct nd6_opt_prefix *po =
                (const struct nd6_opt_prefix *)&opts[off];
            ip6 prefix;
            uint32_t valid = ee32(po->valid_lifetime);
            uint32_t preferred = ee32(po->preferred_lifetime);

            memcpy(prefix.addr, po->prefix, 16);
            /* RFC 4862 section 5.5.3 (a): an advertised link-local prefix is
             * silently ignored, which stops a hostile advertisement from
             * redefining fe80::/10. */
            if ((po->prefix_len <= 128u) && !ip6_is_link_local(&prefix) &&
                    (preferred <= valid)) {
                nd6_prefix_store(s, if_idx, &prefix, po->prefix_len,
                                 (po->flags & ND6_PREFIX_ONLINK) ? 1 : 0,
                                 (po->flags & ND6_PREFIX_AUTO) ? 1 : 0,
                                 valid, preferred);
                /* RFC 4862 section 5.5.3 (d): only a prefix of exactly 64
                 * bits leaves room for a 64-bit interface identifier. */
                if ((po->flags & ND6_PREFIX_AUTO) && (po->prefix_len == 64u) &&
                        (valid != 0)) {
                    struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, if_idx);
                    ip6 iid;
                    ip6 formed;

                    if (ll != NULL) {
                        struct wolfIP_ifaddr_slot *slot;
                        int is_new = 0;

                        nd6_iface_iid(s, if_idx, &iid);
                        ip6_make_addr(&formed, &prefix, 64, &iid);
                        /* Adding it is a no-op when it is already there, so
                         * a repeated advertisement does not restart DAD. */
                        slot = nd6_slot_for(s, if_idx, &formed);
                        if (slot == NULL) {
                            if (wolfIP_ifaddr_add6(s, if_idx, &formed, 64) == 0) {
                                slot = nd6_slot_for(s, if_idx, &formed);
                                is_new = 1;
                                if (slot != NULL)
                                    nd6_dad_start(s, slot);
                            }
                        }
                        /* A repeated advertisement refreshes the lifetimes
                         * rather than being ignored: that is how a router
                         * keeps an address alive, and without it the
                         * address would age out under a router that is
                         * still advertising the prefix. */
                        if (slot != NULL)
                            nd6_slaac_apply_lifetimes(s, slot, valid,
                                                      preferred, is_new);
                    }
                }
            }
        }
        off += olen;
    }
}

/* Neighbor Discovery entry point, called from icmp6_input(). */
static void nd6_input(struct wolfIP *s, unsigned int if_idx,
                      struct wolfIP_ip6_packet *pkt, uint32_t payload_len)
{
    struct nd6_msg *msg = (struct nd6_msg *)pkt;

    /* RFC 4861 sections 6.1 and 7.1: a hop limit other than 255 means the
     * message crossed a router and cannot be trusted. This one check is what
     * keeps Neighbor Discovery on the local link. */
    if (pkt->hop_limit != ND6_HOP_LIMIT)
        return;
    /* All Neighbor Discovery messages carry code 0. */
    if (msg->code != 0)
        return;

    switch (msg->type) {
        case ICMP6_NEIGHBOR_SOLICIT:
            nd6_recv_ns(s, if_idx, pkt, payload_len);
            break;
        case ICMP6_NEIGHBOR_ADVERT:
            nd6_recv_na(s, if_idx, pkt, payload_len);
            break;
        case ICMP6_ROUTER_ADVERT:
            nd6_recv_ra(s, if_idx, pkt, payload_len);
            break;
        case ICMP6_ROUTER_SOLICIT:
        case ICMP6_REDIRECT:
        default:
            /* Router Solicitations are a router's job. Redirect is out of
             * scope for a host-only stack and must be ignored rather than
             * acted on. */
            break;
    }
}

/* ---------------------------------------------------------------------- */
/* Periodic work                                                          */
/* ---------------------------------------------------------------------- */

/* Arm the periodic tick, replacing any timer already armed.
 *
 * Shaped like dhcp_schedule_timer_at(): the id is simply overwritten, so
 * there is no "am I already running" flag for callers to keep in sync. Any
 * live timer is cancelled first, which makes calling this twice harmless
 * rather than leaving a stray entry in the heap.
 *
 * timers_binheap_insert() returns 0 when the heap is full, and NO_TIMER is
 * 0, so a failed insert simply leaves the tick disarmed. That is not fatal
 * because nd6_poll() retries from the main loop; without that retry a
 * momentarily full heap would stop duplicate address detection, router
 * solicitation and every expiry permanently, with nothing to notice. */
static void nd6_arm_tick(struct wolfIP *s)
{
    struct wolfIP_timer tmr;

    /* Before the first wolfIP_poll() the tick domain is unknown: last_tick
     * is still zero while the application's clock may start anywhere, and
     * tick_expired() compares in 32 bits, so a deadline anchored at zero can
     * sit weeks ahead of the first real tick and never fire. Leave the tick
     * unarmed; nd6_poll() runs at the top of every poll and arms it there,
     * once last_tick is a value the tick source actually produced. */
    if (!s->tick_valid)
        return;

    if (s->nd6.tick_timer != NO_TIMER)
        timer_binheap_cancel(&s->timers, s->nd6.tick_timer);
    memset(&tmr, 0, sizeof(tmr));
    tmr.expires = s->last_tick + ND6_TICK_MS;
    tmr.arg = s;
    tmr.cb = nd6_tick_cb;
    s->nd6.tick_timer = timers_binheap_insert(&s->timers, tmr);
}

/* Is there anything for the tick to do?
 *
 * Deliberately conservative: it answers yes if any one of the five sources
 * of periodic work is live, so the tick is never stopped with work still
 * queued. A quiescent but populated cache therefore keeps it running, which
 * is the safe direction to err in. */
static int nd6_has_work(struct wolfIP *s)
{
    unsigned int i;

    for (i = 0; i < WOLFIP_MAX_INTERFACES; i++) {
        if (s->nd6.rs_left[i] != 0)
            return 1;
    }
    for (i = 0; i < WOLFIP_IFADDR_MAX; i++) {
        if (!s->ifaddr[i].used)
            continue;
        if (s->ifaddr[i].info.family != AF_INET6)
            continue;
        if (s->ifaddr[i].info.state == WOLFIP_IFADDR_TENTATIVE)
            return 1;
        /* A SLAAC address with a finite lifetime has to be aged. */
        if ((s->ifaddr[i].info.flags & WOLFIP_IFADDR_FLAG_SLAAC) &&
                ((s->ifaddr[i].info.valid_lifetime != 0) ||
                 (s->ifaddr[i].info.preferred_lifetime != 0)))
            return 1;
    }
    for (i = 0; i < WOLFIP_ND6_CACHE_SIZE; i++) {
        uint8_t st = s->nd6.neighbors[i].state;

        /* REACHABLE and STALE need the tick only to age, which the two
         * transient states below cover; INCOMPLETE, DELAY and PROBE are
         * mid-resolution and must be driven. REACHABLE also ages out, so it
         * counts as work. */
        if ((st == ND6_INCOMPLETE) || (st == ND6_DELAY) ||
                (st == ND6_PROBE) || (st == ND6_REACHABLE))
            return 1;
    }
    for (i = 0; i < WOLFIP_ND6_PREFIX_MAX; i++) {
        if (s->nd6.prefixes[i].used &&
                (s->nd6.prefixes[i].valid_lifetime != 0xFFFFFFFFu))
            return 1;
    }
    for (i = 0; i < WOLFIP_ND6_ROUTER_MAX; i++) {
        if (s->nd6.routers[i].used)
            return 1;
    }
    return 0;
}

/* Called from wolfIP_poll(). Arms the tick whenever there is work and no
 * timer running - which is both the normal wake-up after an idle period and
 * the recovery path when an earlier insert failed on a full heap. */
/* Move every Neighbor Discovery deadline and timestamp into the current tick
 * domain after a rollback (see wolfIP_poll). The timer heap, DHCP deadlines
 * and the ARP rate limit are rebased there; ND6 keeps its own absolute
 * values outside the heap and needs the same treatment, or DAD and Router
 * Solicitation stall on deadlines the restarted clock never reaches, while
 * the unsigned `now - ts` ages underflow and expire the whole neighbour,
 * prefix and router state at once.
 *
 * Deadlines are rebased; timestamps are simply re-anchored to `now`. How old
 * an entry is cannot be known across a discontinuity, and treating it as
 * freshly seen keeps it for one more bounded lifetime instead of discarding
 * it - the same conservative choice the ARP rate limit makes. */
static void nd6_rebase_ticks(struct wolfIP *s, uint64_t now)
{
    unsigned int i;

    if (!s)
        return;
    for (i = 0; i < WOLFIP_IFADDR_MAX; i++) {
        struct wolfIP_ifaddr_slot *slot = &s->ifaddr[i];

        if (!slot->used || (slot->info.family != AF_INET6))
            continue;
        if (slot->dad_due != 0)
            slot->dad_due = tick_rebase(slot->dad_due, now);
        /* The lifetime anchor is a timestamp, re-anchored like the rest. */
        slot->lifetime_ts = now;
    }
    for (i = 0; i < WOLFIP_MAX_INTERFACES; i++) {
        if (s->nd6.rs_due[i] != 0)
            s->nd6.rs_due[i] = tick_rebase(s->nd6.rs_due[i], now);
    }
    for (i = 0; i < WOLFIP_ND6_CACHE_SIZE; i++) {
        if (s->nd6.neighbors[i].state != 0)
            s->nd6.neighbors[i].ts = now;
    }
    for (i = 0; i < WOLFIP_ND6_PREFIX_MAX; i++) {
        if (s->nd6.prefixes[i].used)
            s->nd6.prefixes[i].ts = now;
    }
    for (i = 0; i < WOLFIP_ND6_ROUTER_MAX; i++) {
        if (s->nd6.routers[i].used)
            s->nd6.routers[i].ts = now;
    }
    /* The tick this pass is armed against is gone with the old domain. */
    if (s->nd6.tick_timer != NO_TIMER)
        s->nd6.tick_timer = NO_TIMER;
}

static void nd6_poll(struct wolfIP *s)
{
    if (s->nd6.tick_timer != NO_TIMER)
        return;
    if (nd6_has_work(s))
        nd6_arm_tick(s);
}

static void nd6_tick_cb(void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    unsigned int i;

    if (!s)
        return;
    /* The heap has already popped this entry, so the recorded id is stale.
     * Clearing it here keeps the field truthful for the rest of the tick:
     * nd6_arm_tick() then has nothing to cancel, and nd6_poll() sees the
     * tick as unarmed if this pass decides not to re-arm. */
    s->nd6.tick_timer = NO_TIMER;

    /* Duplicate address detection. */
    for (i = 0; i < WOLFIP_IFADDR_MAX; i++) {
        struct wolfIP_ifaddr_slot *slot = &s->ifaddr[i];

        if (!slot->used || (slot->info.family != AF_INET6))
            continue;
        if (slot->info.state != WOLFIP_IFADDR_TENTATIVE)
            continue;
        if (s->last_tick < slot->dad_due)
            continue;
        if (slot->dad_probes > 0) {
            ip6 unspec;

            slot->dad_probes--;
            ip6_set_unspecified(&unspec);
            nd6_send_ns(s, slot->info.if_idx, &slot->info.v6, &unspec);
            slot->dad_due = s->last_tick + ND6_RETRANS_TIMER_MS;
        } else {
            /* RFC 4862 section 5.4.4: no answer within the retransmit
             * interval means the address is unique. */
            slot->info.state = WOLFIP_IFADDR_PREFERRED;
        }
    }

    /* SLAAC address lifetimes (RFC 4862 sections 5.5.4 and 5.5.3). A zero
     * lifetime here means unlimited, which is what a manually added address
     * carries, so only autoconfigured addresses age. An address whose
     * preferred lifetime has run out is deprecated - still usable for an
     * established connection, no longer chosen as a source - and one whose
     * valid lifetime has run out stops being ours at all. */
    for (i = 0; i < WOLFIP_IFADDR_MAX; i++) {
        struct wolfIP_ifaddr_slot *slot = &s->ifaddr[i];

        if (!slot->used || (slot->info.family != AF_INET6))
            continue;
        if (!(slot->info.flags & WOLFIP_IFADDR_FLAG_SLAAC))
            continue;
        if (slot->info.state == WOLFIP_IFADDR_TENTATIVE)
            continue;
        if (slot->info.valid_lifetime != 0) {
            if (nd6_slaac_valid_remaining_ms(s, slot) == 0) {
                slot->used = 0;
                continue;
            }
        }
        if ((slot->info.preferred_lifetime != 0) &&
                (slot->info.state == WOLFIP_IFADDR_PREFERRED)) {
            uint64_t pref = (uint64_t)slot->info.preferred_lifetime * 1000u;

            if ((s->last_tick - slot->lifetime_ts) >= pref)
                slot->info.state = WOLFIP_IFADDR_DEPRECATED;
        }
    }

    /* Router solicitation, once the link-local address is usable. */
    for (i = 0; i < WOLFIP_MAX_INTERFACES; i++) {
        if (!s->nd6.started[i] || (s->nd6.rs_left[i] == 0))
            continue;
        if (s->last_tick < s->nd6.rs_due[i])
            continue;
        s->nd6.rs_left[i]--;
        nd6_send_rs(s, i);
        s->nd6.rs_due[i] = s->last_tick + ND6_RTR_SOLICITATION_INTERVAL_MS;
    }

    /* Neighbour cache ageing: a REACHABLE entry whose confirmation has timed
     * out drops to STALE rather than being discarded, so the link-layer
     * address is kept and only its reachability is in doubt. */
    for (i = 0; i < WOLFIP_ND6_CACHE_SIZE; i++) {
        struct nd6_neighbor *n = &s->nd6.neighbors[i];

        if (n->state == 0)
            continue;
        if ((n->state == ND6_REACHABLE) &&
                ((s->last_tick - n->ts) > ND6_REACHABLE_TIME_MS)) {
            n->state = ND6_STALE;
            n->ts = s->last_tick;
        }
        if ((n->state == ND6_INCOMPLETE) &&
                ((s->last_tick - n->ts) > (ND6_RETRANS_TIMER_MS *
                                           ND6_MAX_MULTICAST_SOLICIT))) {
            n->state = 0; /* resolution gave up */
        }
    }

    /* Prefix and router lifetimes, both in seconds on the wire. */
    for (i = 0; i < WOLFIP_ND6_PREFIX_MAX; i++) {
        struct nd6_prefix *p = &s->nd6.prefixes[i];

        if (!p->used || (p->valid_lifetime == 0xFFFFFFFFu))
            continue;
        if ((s->last_tick - p->ts) > ((uint64_t)p->valid_lifetime * 1000u))
            p->used = 0;
    }
    for (i = 0; i < WOLFIP_ND6_ROUTER_MAX; i++) {
        struct nd6_router *r = &s->nd6.routers[i];

        if (!r->used)
            continue;
        if ((s->last_tick - r->ts) > ((uint64_t)r->lifetime * 1000u))
            r->used = 0;
    }

    /* Only keep ticking while something needs it. An interface that has
     * been stopped, with no tentative address, no solicitation outstanding,
     * no neighbour mid-resolution and no finite lifetime to expire, has
     * nothing for this to do. nd6_poll() arms it again when work appears. */
    if (nd6_has_work(s))
        nd6_arm_tick(s);
}

/* ---------------------------------------------------------------------- */
/* Public entry points                                                    */
/* ---------------------------------------------------------------------- */

int wolfIP_ipv6_start(struct wolfIP *s, unsigned int if_idx)
{
    struct wolfIP_ll_dev *ll;
    struct wolfIP_ifaddr_slot *slot;
    ip6 prefix;
    ip6 iid;
    ip6 link_local;

    if (!s || (if_idx >= WOLFIP_MAX_INTERFACES))
        return -WOLFIP_EINVAL;
    ll = wolfIP_ll_at(s, if_idx);
    if (!ll)
        return -WOLFIP_EINVAL;

    /* RFC 4862 section 5.3: the link-local address is formed from fe80::/64
     * and a modified EUI-64 interface identifier, then verified with
     * duplicate address detection before it may be used. */
    if (atoip6("fe80::", &prefix) != 0)
        return -WOLFIP_EINVAL;
    nd6_iface_iid(s, if_idx, &iid);
    ip6_make_addr(&link_local, &prefix, 64, &iid);

    slot = nd6_slot_for(s, if_idx, &link_local);
    if (slot == NULL) {
        if (wolfIP_ifaddr_add6(s, if_idx, &link_local, 64) != 0)
            return -WOLFIP_ENOMEM;
        slot = nd6_slot_for(s, if_idx, &link_local);
        if (slot == NULL)
            return -WOLFIP_ENOMEM;
    }
    slot->info.flags |= WOLFIP_IFADDR_FLAG_LINKLOCAL;
    nd6_dad_start(s, slot);

    /* Router solicitations begin once there is a source address to send
     * them from; the tick handles the ordering. */
    s->nd6.started[if_idx] = 1;
    s->nd6.rs_left[if_idx] = (uint8_t)ND6_MAX_RTR_SOLICITATIONS;
    s->nd6.rs_due[if_idx] = s->last_tick + ND6_RETRANS_TIMER_MS;

    nd6_arm_tick(s);
    return 0;
}

/* Stop Neighbor Discovery on an interface.
 *
 * Halts what the tick drives: router solicitation, and duplicate address
 * detection for anything still tentative, which is dropped because it never
 * completed. Addresses that had already passed detection are left alone and
 * are still defended by nd6_recv_ns(); remove them with wolfIP_ifaddr_del6()
 * if that is wanted. When no interface is left running, the tick releases
 * its slot in the shared timer heap. */
int wolfIP_ipv6_stop(struct wolfIP *s, unsigned int if_idx)
{
    unsigned int i;

    if (!s || (if_idx >= WOLFIP_MAX_INTERFACES))
        return -WOLFIP_EINVAL;

    s->nd6.started[if_idx] = 0;
    s->nd6.rs_left[if_idx] = 0;
    s->nd6.rs_due[if_idx] = 0;

    for (i = 0; i < WOLFIP_IFADDR_MAX; i++) {
        struct wolfIP_ifaddr_slot *slot = &s->ifaddr[i];

        if (!slot->used || (slot->info.family != AF_INET6))
            continue;
        if (slot->info.if_idx != (uint8_t)if_idx)
            continue;
        if (slot->info.state == WOLFIP_IFADDR_TENTATIVE) {
            slot->used = 0;
            slot->dad_probes = 0;
        }
    }

    if (!nd6_has_work(s) && (s->nd6.tick_timer != NO_TIMER)) {
        timer_binheap_cancel(&s->timers, s->nd6.tick_timer);
        s->nd6.tick_timer = NO_TIMER;
    }
    return 0;
}

int wolfIP_ipv6_addr_add(struct wolfIP *s, unsigned int if_idx,
                         const ip6 *addr, uint8_t prefix_len)
{
    struct wolfIP_ifaddr_slot *slot;
    int ret;

    if (!s || !addr || (if_idx >= WOLFIP_MAX_INTERFACES))
        return -WOLFIP_EINVAL;
    ret = wolfIP_ifaddr_add6(s, if_idx, addr, prefix_len);
    if (ret != 0)
        return ret;
    slot = nd6_slot_for(s, if_idx, addr);
    if (slot == NULL)
        return -WOLFIP_EINVAL;
    /* RFC 4862 section 5.4: duplicate address detection applies to every
     * unicast address, however it was obtained - statically configured ones
     * included. */
    nd6_dad_start(s, slot);
    return 0;
}

int wolfIP_ipv6_set_iid(struct wolfIP *s, unsigned int if_idx,
                        const uint8_t *iid)
{
#if WOLFIP_IPV6_IID_OVERRIDE
    if (!s || !iid || (if_idx >= WOLFIP_MAX_INTERFACES))
        return -WOLFIP_EINVAL;
    /* RFC 5453: these must never be assigned to an interface. Refusing here
     * rather than silently substituting one keeps the caller's generator
     * honest - an RFC 7217 implementation is required to redraw on a hit,
     * and would otherwise never learn that it had to. */
    if (ip6_iid_is_reserved(iid))
        return -WOLFIP_EINVAL;
    memcpy(s->nd6.iid[if_idx], iid, 8);
    s->nd6.iid_valid[if_idx] = 1;
    return 0;
#else
    (void)s;
    (void)if_idx;
    (void)iid;
    return -WOLFIP_ENOSYS;
#endif
}

int wolfIP_ipv6_get_iid(struct wolfIP *s, unsigned int if_idx, uint8_t *iid)
{
#if WOLFIP_IPV6_IID_OVERRIDE
    ip6 tmp;

    if (!s || !iid || (if_idx >= WOLFIP_MAX_INTERFACES))
        return -WOLFIP_EINVAL;
    /* Answers even before the first address is formed, by choosing the
     * identifier now: an application that wants to persist a generated one
     * should not have to wait for duplicate address detection, and the
     * choice is cached, so what is read back is what will be used. */
    nd6_iface_iid(s, if_idx, &tmp);
    memcpy(iid, &tmp.addr[8], 8);
    return 0;
#else
    (void)s;
    (void)if_idx;
    (void)iid;
    return -WOLFIP_ENOSYS;
#endif
}

int wolfIP_nd6_neighbor_add(struct wolfIP *s, unsigned int if_idx,
                            const ip6 *addr, const uint8_t *mac)
{
    if (!s || !addr || !mac || (if_idx >= WOLFIP_MAX_INTERFACES))
        return -WOLFIP_EINVAL;
    if (ip6_is_multicast(addr) || ip6_is_unspecified(addr) ||
            ip6_is_loopback(addr) || ip6_is_v4mapped(addr) ||
            ip6_is_v4compat(addr))
        return -WOLFIP_EINVAL;
    (void)nd6_store_neighbor(s, if_idx, addr, mac, ND6_REACHABLE, 0);
    return 0;
}

int wolfIP_nd6_lookup(struct wolfIP *s, unsigned int if_idx, const ip6 *addr,
                      uint8_t *mac)
{
    if (!s || !addr || !mac || (if_idx >= WOLFIP_MAX_INTERFACES))
        return -WOLFIP_EINVAL;
    return (nd6_lookup(s, if_idx, addr, mac) == 0) ? 0 : -1;
}

int wolfIP_ipv6_nexthop(struct wolfIP *s, unsigned int if_idx, const ip6 *dst,
                        ip6 *nexthop)
{
    if (!s || !dst || !nexthop || (if_idx >= WOLFIP_MAX_INTERFACES))
        return -WOLFIP_EINVAL;
    return nd6_select_nexthop(s, if_idx, dst, nexthop);
}

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
#define IP6_VERSION 6
#define IP6_HOP_LIMIT_DEFAULT 64

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

    (void)s;
    (void)if_idx;

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
    if (min_upper == 0)
        return IP6_DROP_UNKNOWN_NEXTHDR;
    if (payload_len < min_upper)
        return IP6_DROP_SHORT_TRANSPORT;

    /* ICMPv6 is handled in the stack itself and needs no socket. Everything
     * else waits for the socket phase. The header is fully validated at this
     * point and the payload bounds are known good. */
    if (pkt->next_hdr == IP6_NEXTHDR_ICMPV6)
        icmp6_input(s, if_idx, pkt, len);
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
    if (icmp->type == ICMP6_ECHO_REPLY) {
        /* icmp_input() hands this to icmp_try_recv() for delivery to an
         * application ICMP socket. There is no IPv6 socket yet, so the reply
         * is consumed here; answering it would loop between two hosts. */
        return;
    }
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
    int with_slla = !ip6_is_unspecified(src);

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
     * question the solicitation asked. */
    opt = (struct nd6_opt_lla *)na->options;
    opt->type = ND6_OPT_TLLA;
    opt->len = 1;
    memcpy(opt->mac, ll->mac, 6);

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
    if (have_src) {
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

/* Start duplicate address detection on a tentative address. */
static void nd6_dad_start(struct wolfIP *s, struct wolfIP_ifaddr_slot *slot)
{
    slot->info.state = WOLFIP_IFADDR_TENTATIVE;
    slot->dad_probes = ND6_DUP_ADDR_DETECT_TRANSMITS;
    /* Send the first solicitation on the next tick, so that a caller adding
     * an address mid-poll does not transmit from inside its own call. */
    slot->dad_due = s->last_tick;
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

/* Is this destination on-link, according to the prefix list? */
static int nd6_is_onlink(struct wolfIP *s, unsigned int if_idx,
                         const ip6 *dst)
{
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
    opt = nd6_find_option(ns->options, payload_len - 24u, ND6_OPT_SLLA);
    if (opt != NULL) {
        const struct nd6_opt_lla *lla = (const struct nd6_opt_lla *)opt;

        if (lla->len != 1u)
            return;
        /* RFC 2464 section 6: on Ethernet the SLLA is the sender's link-layer
         * address. A disagreement would redirect both our reply and cache
         * entry to an uninvolved host. */
        if (memcmp(lla->mac, pkt->eth.src, 6) != 0)
            return;
        nd6_store_neighbor(s, if_idx, &src, lla->mac, ND6_STALE, 0);
        memcpy(reply_mac, lla->mac, 6);
    } else {
        memcpy(reply_mac, pkt->eth.src, 6);
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
        /* No link-layer address and none known: nothing has been learned. */
        return;
    }

    if (na->flags & ND6_NA_SOLICITED)
        n->state = ND6_REACHABLE;
    else if (n->state == ND6_INCOMPLETE)
        n->state = ND6_STALE;
    n->probes = 0;
    n->ts = s->last_tick;
    if (na->flags & ND6_NA_ROUTER)
        n->is_router = 1;
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
                        ip6_iid_from_mac(&iid, ll->mac);
                        ip6_make_addr(&formed, &prefix, 64, &iid);
                        /* Adding it is a no-op when it is already there, so
                         * a repeated advertisement does not restart DAD. */
                        if (nd6_slot_for(s, if_idx, &formed) == NULL) {
                            if (wolfIP_ifaddr_add6(s, if_idx, &formed, 64) == 0) {
                                struct wolfIP_ifaddr_slot *slot =
                                    nd6_slot_for(s, if_idx, &formed);

                                if (slot != NULL)
                                    nd6_dad_start(s, slot);
                            }
                        }
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
    ip6_iid_from_mac(&iid, ll->mac);
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

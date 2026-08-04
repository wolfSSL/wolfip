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

/* ICMPv6 message types (RFC 4443 sections 4.1 and 4.2). */
#define ICMP6_ECHO_REQUEST 128
#define ICMP6_ECHO_REPLY   129

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
 * like it this searches every interface rather than only the one the packet
 * arrived on - the weak end-system model of RFC 1122 section 3.3.4.2, which
 * is what the IPv4 path already implements.
 *
 * Once Neighbor Discovery lands this will also need to honour the zone of a
 * link-local address (RFC 4007): fe80::1 on one interface is a different
 * address from fe80::1 on another. */
static unsigned int wolfIP_if_for_local_ip6(struct wolfIP *s, const ip6 *addr,
                                            int *found)
{
    struct wolfIP_ifaddr_info info;
    unsigned int i;

    if (found)
        *found = 0;
    if (!s || !addr)
        return 0;
    for (i = 0; i < WOLFIP_MAX_INTERFACES; i++) {
        unsigned int count = wolfIP_ifaddr_count(s, i, AF_INET6);
        unsigned int j;

        for (j = 0; j < count; j++) {
            if (wolfIP_ifaddr_get(s, i, AF_INET6, j, &info) != 0)
                continue;
            if (ip6_cmp(&info.v6, addr) == 0) {
                if (found)
                    *found = 1;
                return i;
            }
        }
    }
    return 0;
}

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
        (void)wolfIP_if_for_local_ip6(s, &dst, &dst_match);
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

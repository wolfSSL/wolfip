/* unit_tests_ipv6_recv.c
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

#if WOLFIP_IPV6

/* =========================================================================
 * Environment note
 * =========================================================================
 * Receive-path tests for the IPv6 header: ip6_recv() validation, the
 * ethertype and MAC-layer demux in wolfIP_recv_on(), and the adversarial
 * corpus of malformed frames.
 *
 * ip6_recv() deliberately returns a distinct negative code per rejection
 * reason rather than a bare "dropped", so these tests assert *why* a frame
 * was refused. A frame rejected for the wrong reason is a real bug - it
 * usually means an earlier check is shadowing a later one - and would go
 * unnoticed against a boolean result.
 *
 * Built only by `make unit-ipv6`.
 */

/* =========================================================================
 * Local helpers
 * ========================================================================= */

static const uint8_t ip6_test_peer_mac[6] = {0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x11};

/* Build a complete, valid IPv6 frame carrying `payload_len` bytes of upper
 * layer. Returns the total frame length including the Ethernet header. */
static uint32_t ip6_build_frame(uint8_t *buf, const char *src, const char *dst,
                                uint8_t next_hdr, uint16_t payload_len)
{
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    ip6 s6;
    ip6 d6;

    memset(buf, 0, LINK_MTU);
    ck_assert_int_eq(atoip6(src, &s6), 0);
    ck_assert_int_eq(atoip6(dst, &d6), 0);
    ip6_hdr_set_vtf(pkt, 0, 0);
    pkt->payload_len = ee16(payload_len);
    pkt->next_hdr = next_hdr;
    pkt->hop_limit = 64;
    ip6_hdr_set_src(pkt, &s6);
    ip6_hdr_set_dst(pkt, &d6);
    return (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN + payload_len);
}

/* Build a valid UDP-carrying frame and hand it to ip6_recv(). */
static int ip6_recv_frame(const char *src, const char *dst)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    uint32_t len = ip6_build_frame(buf, src, dst, IP6_NEXTHDR_UDP, 8);

    wolfIP_init(&s);
    mock_link_init(&s);
    return ip6_recv(&s, TEST_PRIMARY_IF, (struct wolfIP_ip6_packet *)buf, len);
}

/* =========================================================================
 * Well formed frames are accepted
 * ========================================================================= */

START_TEST(test_ip6_recv_accepts_upper_layer_protocols)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    uint32_t len;

    wolfIP_init(&s);
    mock_link_init(&s);

    len = ip6_build_frame(buf, "2001:db8::1", "2001:db8::2",
                          IP6_NEXTHDR_UDP, 8);
    ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF,
                              (struct wolfIP_ip6_packet *)buf, len),
                     IP6_ACCEPTED);

    len = ip6_build_frame(buf, "2001:db8::1", "2001:db8::2",
                          IP6_NEXTHDR_TCP, 20);
    ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF,
                              (struct wolfIP_ip6_packet *)buf, len),
                     IP6_ACCEPTED);

    len = ip6_build_frame(buf, "fe80::1", "ff02::1", IP6_NEXTHDR_ICMPV6, 8);
    ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF,
                              (struct wolfIP_ip6_packet *)buf, len),
                     IP6_ACCEPTED);
}
END_TEST

START_TEST(test_ip6_recv_tolerates_ethernet_padding)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    uint32_t len;

    wolfIP_init(&s);
    mock_link_init(&s);
    len = ip6_build_frame(buf, "2001:db8::1", "2001:db8::2",
                          IP6_NEXTHDR_UDP, 8);

    /* Ethernet pads anything below 60 bytes, so the frame handed up may be
     * longer than the header plus payload_len. Requiring an exact match
     * would drop every small packet on a real link. */
    ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF,
                              (struct wolfIP_ip6_packet *)buf, len + 18),
                     IP6_ACCEPTED);
    ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF,
                              (struct wolfIP_ip6_packet *)buf, 64),
                     IP6_ACCEPTED);
}
END_TEST

START_TEST(test_ip6_recv_accepts_hop_limit_zero)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    uint32_t len;

    wolfIP_init(&s);
    mock_link_init(&s);
    len = ip6_build_frame(buf, "2001:db8::1", "2001:db8::2",
                          IP6_NEXTHDR_UDP, 8);
    pkt->hop_limit = 0;

    /* RFC 8200 section 3: the hop limit is decremented and tested by
     * forwarding nodes. A destination host must accept a packet addressed
     * to it even at hop limit zero. Dropping it here is a common bug. */
    ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF, pkt, len), IP6_ACCEPTED);
}
END_TEST

START_TEST(test_ip6_recv_accepts_unspecified_source)
{
    /* RFC 4862 section 5.4.2: duplicate address detection sends a Neighbor
     * Solicitation from :: . Rejecting an unspecified source outright would
     * break DAD before it is even implemented. */
    ck_assert_int_eq(ip6_recv_frame("::", "ff02::1:ff00:1"), IP6_ACCEPTED);
}
END_TEST

START_TEST(test_ip6_recv_accepts_all_scopes_as_destination)
{
    ck_assert_int_eq(ip6_recv_frame("fe80::1", "fe80::2"), IP6_ACCEPTED);
    ck_assert_int_eq(ip6_recv_frame("fd00::1", "fd00::2"), IP6_ACCEPTED);
    ck_assert_int_eq(ip6_recv_frame("2001:db8::1", "2001:db8::2"),
                     IP6_ACCEPTED);
    ck_assert_int_eq(ip6_recv_frame("fe80::1", "ff02::1"), IP6_ACCEPTED);
}
END_TEST

/* =========================================================================
 * Malformed frames - length and version
 * ========================================================================= */

START_TEST(test_ip6_recv_rejects_short_frame)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    uint32_t full;
    uint32_t len;

    wolfIP_init(&s);
    mock_link_init(&s);
    full = ip6_build_frame(buf, "2001:db8::1", "2001:db8::2",
                           IP6_NEXTHDR_UDP, 8);

    /* Every length short of a complete header must be refused, and refused
     * before any header field is read - reading src/dst out of a 20-byte
     * frame would be an overread. */
    for (len = 0; len < (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN); len++) {
        ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF,
                                  (struct wolfIP_ip6_packet *)buf, len),
                         IP6_DROP_SHORT_FRAME);
    }
    /* Exactly a header with no payload declared is structurally fine. */
    ck_assert_int_ne(ip6_recv(&s, TEST_PRIMARY_IF,
                              (struct wolfIP_ip6_packet *)buf, full),
                     IP6_DROP_SHORT_FRAME);
}
END_TEST

START_TEST(test_ip6_recv_rejects_wrong_version)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    uint32_t len;
    unsigned int v;

    wolfIP_init(&s);
    mock_link_init(&s);
    len = ip6_build_frame(buf, "2001:db8::1", "2001:db8::2",
                          IP6_NEXTHDR_UDP, 8);

    for (v = 0; v < 16u; v++) {
        uint32_t vtf = ((uint32_t)v << 28);

        pkt->ver_tc_fl = ee32(vtf);
        if (v == 6)
            ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF, pkt, len),
                             IP6_ACCEPTED);
        else
            ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF, pkt, len),
                             IP6_DROP_BAD_VERSION);
    }
}
END_TEST

START_TEST(test_ip6_recv_rejects_truncated_payload)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;

    wolfIP_init(&s);
    mock_link_init(&s);
    ip6_build_frame(buf, "2001:db8::1", "2001:db8::2", IP6_NEXTHDR_UDP, 8);

    /* payload_len claims more than the frame actually holds. Trusting it
     * would let a peer walk the checksum routine off the end of the
     * buffer. */
    pkt->payload_len = ee16(1200);
    ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF, pkt,
                              (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN + 8)),
                     IP6_DROP_TRUNCATED_PAYLOAD);

    /* One byte short is still short. */
    pkt->payload_len = ee16(9);
    ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF, pkt,
                              (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN + 8)),
                     IP6_DROP_TRUNCATED_PAYLOAD);

    /* The maximum declarable payload against a minimal frame. */
    pkt->payload_len = ee16(0xFFFF);
    ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF, pkt,
                              (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN + 8)),
                     IP6_DROP_TRUNCATED_PAYLOAD);
}
END_TEST

/* =========================================================================
 * Malformed frames - address sanity
 * ========================================================================= */

START_TEST(test_ip6_recv_rejects_multicast_source)
{
    /* RFC 4291 section 2.7: a multicast address is never a valid source.
     * Accepting one invites reflection and amplification. */
    ck_assert_int_eq(ip6_recv_frame("ff02::1", "2001:db8::2"),
                     IP6_DROP_MCAST_SOURCE);
    ck_assert_int_eq(ip6_recv_frame("ff0e::1", "2001:db8::2"),
                     IP6_DROP_MCAST_SOURCE);
}
END_TEST

START_TEST(test_ip6_recv_rejects_unspecified_destination)
{
    /* RFC 4291 section 2.5.2: :: must never appear as a destination. */
    ck_assert_int_eq(ip6_recv_frame("2001:db8::1", "::"),
                     IP6_DROP_UNSPECIFIED_DESTINATION);
}
END_TEST

START_TEST(test_ip6_recv_rejects_loopback_on_the_wire)
{
    /* RFC 4291 section 2.5.3: ::1 must never cross a real link. The source
     * check is what stops an off-link attacker forging a loopback identity
     * to impersonate locally originated traffic. */
    ck_assert_int_eq(ip6_recv_frame("::1", "2001:db8::2"),
                     IP6_DROP_LOOPBACK_ON_WIRE);
    ck_assert_int_eq(ip6_recv_frame("2001:db8::1", "::1"),
                     IP6_DROP_LOOPBACK_ON_WIRE);
}
END_TEST

START_TEST(test_ip6_recv_rejects_v4mapped_on_the_wire)
{
    /* RFC 4291 section 2.5.5.2: IPv4-mapped addresses exist only inside the
     * socket API. wolfIP presents them to dual-stack AF_INET6 sockets, so a
     * peer that could smuggle one in over the wire could present an
     * arbitrary IPv4 identity to an application. Both fields are checked. */
    ck_assert_int_eq(ip6_recv_frame("::ffff:10.0.0.1", "2001:db8::2"),
                     IP6_DROP_V4MAPPED_ON_WIRE);
    ck_assert_int_eq(ip6_recv_frame("2001:db8::1", "::ffff:10.0.0.1"),
                     IP6_DROP_V4MAPPED_ON_WIRE);
    ck_assert_int_eq(ip6_recv_frame("::ffff:127.0.0.1", "2001:db8::2"),
                     IP6_DROP_V4MAPPED_ON_WIRE);
}
END_TEST

START_TEST(test_ip6_recv_rejects_v4compat_on_the_wire)
{
    /* RFC 4291 section 2.5.5.1: IPv4-compatible addresses are deprecated. */
    ck_assert_int_eq(ip6_recv_frame("::1.2.3.4", "2001:db8::2"),
                     IP6_DROP_V4COMPAT_ON_WIRE);
    ck_assert_int_eq(ip6_recv_frame("2001:db8::1", "::1.2.3.4"),
                     IP6_DROP_V4COMPAT_ON_WIRE);
}
END_TEST

/* =========================================================================
 * Next Header handling
 * ========================================================================= */

START_TEST(test_ip6_recv_rejects_every_extension_header)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    uint32_t len;
    unsigned int i;
    static const uint8_t ext[] = {
        IP6_NEXTHDR_HOPOPT, IP6_NEXTHDR_ROUTING, IP6_NEXTHDR_FRAGMENT,
        IP6_NEXTHDR_ESP, IP6_NEXTHDR_AH, IP6_NEXTHDR_DSTOPTS,
        IP6_NEXTHDR_NONE
    };

    wolfIP_init(&s);
    mock_link_init(&s);
    len = ip6_build_frame(buf, "2001:db8::1", "2001:db8::2",
                          IP6_NEXTHDR_UDP, 40);

    /* Phase 0 parses the upper-layer header only. Walking a Next Header
     * chain is a denial-of-service surface (nested and looping option
     * headers), so each extension header is named and refused rather than
     * half-processed. Routing headers in particular were a documented
     * amplification vector before RFC 5095 deprecated type 0. */
    for (i = 0; i < (sizeof(ext) / sizeof(ext[0])); i++) {
        pkt->next_hdr = ext[i];
        ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF, pkt, len),
                         IP6_DROP_EXTENSION_HEADER);
    }
}
END_TEST

START_TEST(test_ip6_recv_rejects_unknown_next_header)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    uint32_t len;
    unsigned int nh;

    wolfIP_init(&s);
    mock_link_init(&s);
    len = ip6_build_frame(buf, "2001:db8::1", "2001:db8::2",
                          IP6_NEXTHDR_UDP, 40);

    /* Sweep the whole 8-bit space. Exactly three values are upper-layer
     * protocols we accept; the extension headers get their own reason; and
     * everything else is unknown. */
    for (nh = 0; nh < 256u; nh++) {
        int expect;

        pkt->next_hdr = (uint8_t)nh;
        if ((nh == IP6_NEXTHDR_TCP) || (nh == IP6_NEXTHDR_UDP) ||
                (nh == IP6_NEXTHDR_ICMPV6))
            expect = IP6_ACCEPTED;
        else if (ip6_nexthdr_is_extension((uint8_t)nh))
            expect = IP6_DROP_EXTENSION_HEADER;
        else
            expect = IP6_DROP_UNKNOWN_NEXTHDR;
        ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF, pkt, len), expect);
    }
}
END_TEST

START_TEST(test_ip6_recv_rejects_short_upper_layer_header)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    uint32_t len;
    uint16_t payload;

    wolfIP_init(&s);
    mock_link_init(&s);

    /* A declared payload too small to hold the upper-layer header at all.
     * Without this check the transport demux would parse fields that are
     * not there. */
    for (payload = 0; payload < IP6_MIN_TCP_LEN; payload++) {
        len = ip6_build_frame(buf, "2001:db8::1", "2001:db8::2",
                              IP6_NEXTHDR_TCP, payload);
        ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF, pkt, len),
                         IP6_DROP_SHORT_TRANSPORT);
    }
    len = ip6_build_frame(buf, "2001:db8::1", "2001:db8::2",
                          IP6_NEXTHDR_TCP, IP6_MIN_TCP_LEN);
    ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF, pkt, len), IP6_ACCEPTED);

    for (payload = 0; payload < IP6_MIN_UDP_LEN; payload++) {
        len = ip6_build_frame(buf, "2001:db8::1", "2001:db8::2",
                              IP6_NEXTHDR_UDP, payload);
        ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF, pkt, len),
                         IP6_DROP_SHORT_TRANSPORT);
    }

    for (payload = 0; payload < IP6_MIN_ICMPV6_LEN; payload++) {
        len = ip6_build_frame(buf, "fe80::1", "ff02::1",
                              IP6_NEXTHDR_ICMPV6, payload);
        ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF, pkt, len),
                         IP6_DROP_SHORT_TRANSPORT);
    }
}
END_TEST

/* =========================================================================
 * Check ordering
 * ========================================================================= */

START_TEST(test_ip6_recv_checks_structure_before_addresses)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    uint32_t len;

    wolfIP_init(&s);
    mock_link_init(&s);

    /* A frame that is both too short and carries a bad source address must
     * be rejected for being short: the address fields have not been proven
     * to be inside the buffer yet. */
    len = ip6_build_frame(buf, "ff02::1", "2001:db8::2", IP6_NEXTHDR_UDP, 8);
    ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF, pkt, 20),
                     IP6_DROP_SHORT_FRAME);

    /* Likewise version is checked before the addresses are interpreted. */
    pkt->ver_tc_fl = ee32(0x40000000u);
    ck_assert_int_eq(ip6_recv(&s, TEST_PRIMARY_IF, pkt, len),
                     IP6_DROP_BAD_VERSION);
}
END_TEST

/* =========================================================================
 * Ethertype and MAC demux
 * ========================================================================= */

START_TEST(test_eth_is_ipv6_multicast_mac)
{
    const uint8_t sol[6] = {0x33, 0x33, 0xFF, 0x00, 0x00, 0x01};
    const uint8_t nodes[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
    const uint8_t unicast[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    const uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t ipv4_mcast[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};
    const uint8_t near_miss[6] = {0x33, 0x34, 0x00, 0x00, 0x00, 0x01};

    ck_assert_int_eq(eth_is_ipv6_multicast_mac(sol), 1);
    ck_assert_int_eq(eth_is_ipv6_multicast_mac(nodes), 1);
    ck_assert_int_eq(eth_is_ipv6_multicast_mac(unicast), 0);
    ck_assert_int_eq(eth_is_ipv6_multicast_mac(broadcast), 0);
    ck_assert_int_eq(eth_is_ipv6_multicast_mac(ipv4_mcast), 0);
    ck_assert_int_eq(eth_is_ipv6_multicast_mac(near_miss), 0);
}
END_TEST

START_TEST(test_ip6_demux_accepts_unicast_and_multicast_frames)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    struct wolfIP_ll_dev *ll;
    uint32_t len;

    wolfIP_init(&s);
    mock_link_init(&s);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    len = ip6_build_frame(buf, "fe80::1", "ff02::1", IP6_NEXTHDR_ICMPV6, 8);
    pkt->eth.type = ee16(ETH_TYPE_IPV6);
    memcpy(pkt->eth.src, ip6_test_peer_mac, 6);

    /* Unicast to our own MAC. */
    memcpy(pkt->eth.dst, ll->mac, 6);
    last_frame_sent_size = 0;
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, buf, len);
    /* Phase 0 has no upper-layer delivery, so nothing is transmitted; the
     * check here is that a well formed frame traverses the demux without
     * crashing or provoking a spurious reply. */
    ck_assert_uint_eq((uint32_t)last_frame_sent_size, 0u);

    /* 33:33:.. multicast must also be accepted: Neighbor Discovery and
     * Router Advertisements never arrive on our unicast MAC. */
    ip6_mcast_to_eth(&(ip6)WOLFIP_IN6ADDR_ANY_INIT, pkt->eth.dst);
    pkt->eth.dst[0] = 0x33;
    pkt->eth.dst[1] = 0x33;
    last_frame_sent_size = 0;
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, buf, len);
    ck_assert_uint_eq((uint32_t)last_frame_sent_size, 0u);
}
END_TEST

START_TEST(test_ip6_demux_ignores_frames_for_other_hosts)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    const uint8_t other[6] = {0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x99};
    uint32_t len;

    wolfIP_init(&s);
    mock_link_init(&s);
    len = ip6_build_frame(buf, "fe80::1", "ff02::1", IP6_NEXTHDR_ICMPV6, 8);
    pkt->eth.type = ee16(ETH_TYPE_IPV6);
    memcpy(pkt->eth.src, ip6_test_peer_mac, 6);
    memcpy(pkt->eth.dst, other, 6);

    last_frame_sent_size = 0;
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, buf, len);
    ck_assert_uint_eq((uint32_t)last_frame_sent_size, 0u);
}
END_TEST

START_TEST(test_ip6_demux_survives_a_truncated_frame)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    struct wolfIP_ll_dev *ll;
    uint32_t len;

    wolfIP_init(&s);
    mock_link_init(&s);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    ip6_build_frame(buf, "fe80::1", "ff02::1", IP6_NEXTHDR_ICMPV6, 8);
    pkt->eth.type = ee16(ETH_TYPE_IPV6);
    memcpy(pkt->eth.dst, ll->mac, 6);
    memcpy(pkt->eth.src, ip6_test_peer_mac, 6);

    /* Drivers do not always pad. Every truncation from a bare Ethernet
     * header upwards must be survivable; under ASan this is where an
     * overread would surface. */
    for (len = ETH_HEADER_LEN;
            len < (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN + 8); len++) {
        last_frame_sent_size = 0;
        wolfIP_recv_ex(&s, TEST_PRIMARY_IF, buf, len);
        ck_assert_uint_eq((uint32_t)last_frame_sent_size, 0u);
    }
}
END_TEST

START_TEST(test_ip6_ethertype_does_not_disturb_ipv4_or_arp)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    struct wolfIP_ll_dev *ll;
    uint32_t len;

    wolfIP_init(&s);
    mock_link_init(&s);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    len = ip6_build_frame(buf, "fe80::1", "ff02::1", IP6_NEXTHDR_ICMPV6, 8);
    memcpy(pkt->eth.dst, ll->mac, 6);
    memcpy(pkt->eth.src, ip6_test_peer_mac, 6);

    /* An IPv6 payload announced as IPv4 must be handled by the IPv4 path
     * and dropped there (version nibble is 6), never leak into ip6_recv. */
    pkt->eth.type = ee16(ETH_TYPE_IP);
    last_frame_sent_size = 0;
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, buf, len);
    ck_assert_uint_eq((uint32_t)last_frame_sent_size, 0u);

    /* An unknown ethertype is ignored entirely. */
    pkt->eth.type = ee16(0x1234);
    last_frame_sent_size = 0;
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, buf, len);
    ck_assert_uint_eq((uint32_t)last_frame_sent_size, 0u);
}
END_TEST

#endif /* WOLFIP_IPV6 */

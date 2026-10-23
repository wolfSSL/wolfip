/* unit_tests_forwarding.c
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

/* Forwarding-path tests (router build). This module forces
 * WOLFIP_ENABLE_FORWARDING=1 so it is self-contained: every test here is
 * dead code in a non-forwarding build, and the module must not silently
 * lose coverage if the shared harness default changes.
 *
 * Covers the branches the general ip_recv tests leave open:
 *  - RFC 1812 4.3.2.7: no ICMP error for a non-first fragment (Time
 *    Exceeded, Fragmentation Needed, Parameter Problem all suppressed),
 *    while the first fragment of the same datagram still gets its reply.
 *  - RFC 1812 4.3.2.4: Parameter Problem suppressed for multicast
 *    destinations.
 *  - RFC 1858: the SENDING L4 filter hooks must not be notified for a
 *    non-first fragment, whose bytes at the IHL offset are payload, not a
 *    transport header (port-based policy matching on garbage).
 */
#undef  WOLFIP_ENABLE_FORWARDING
#define WOLFIP_ENABLE_FORWARDING 1

/* Test-local filter counters for the L4-notify suppression test. */
static int fwd_filter_notify_count;
static uint16_t fwd_filter_last_dport;

static int fwd_filter_count_cb(void *arg,
                               const struct wolfIP_filter_event *event)
{
    (void)arg;
    if (event->reason == WOLFIP_FILT_SENDING &&
        event->meta.ip_proto == WOLFIP_FILTER_PROTO_TCP) {
        fwd_filter_notify_count++;
        fwd_filter_last_dport = event->meta.l4.tcp.dst_port;
    }
    return 0;
}

static void fwd_arp_store(struct wolfIP *s, unsigned int if_idx, ip4 ip,
                          const uint8_t *mac)
{
    s->arp.neighbors[0].ip = ip;
    s->arp.neighbors[0].if_idx = if_idx;
    memcpy(s->arp.neighbors[0].mac, mac, 6);
}

/* =========================================================================
 * Fragment, TTL=1 - silent drop
 * =========================================================================
 * Fragments are dropped at arrival, before the forwarding decision, so a
 * TTL-expired fragment must not generate a Time Exceeded: the router
 * cannot validate what the fragment does not carry. The datagram is not
 * relayed and no ICMP is sent.
 */
START_TEST(test_fwd_nonfirst_frag_ttl1_silent_drop)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip      = 0xC0A80155U;
    ip4 src_ip       = 0x0A000002U;
    static const uint8_t dest_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    fwd_arp_store(&s, TEST_SECOND_IF, dest_ip, dest_mac);
    last_frame_sent_count = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type  = ee16(ETH_TYPE_IP);
    ip->ver_ihl   = 0x45;
    ip->flags_fo  = ee16(0x0001U); /* MF=0, offset=1 (8 bytes) */
    ip->ttl       = 1;
    ip->proto     = WI_IPPROTO_UDP;
    ip->len       = ee16(IP_HEADER_LEN + 8);
    ip->src       = ee32(src_ip);
    ip->dst       = ee32(dest_ip);
    fix_ip_checksum(ip);

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Silent: no Time Exceeded, no relay. */
    ck_assert_uint_eq(last_frame_sent_count, 0);
}
END_TEST

/* =========================================================================
 * First fragment, TTL=1 - silent drop
 * =========================================================================
 * Fragments are dropped at arrival, before the forwarding decision, so
 * even the first fragment of an expired datagram is dropped silently:
 * no Time Exceeded, no relay.
 */
START_TEST(test_fwd_first_frag_ttl1_silent_drop)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip      = 0xC0A80155U;
    ip4 src_ip       = 0x0A000002U;
    static const uint8_t dest_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    fwd_arp_store(&s, TEST_SECOND_IF, dest_ip, dest_mac);
    last_frame_sent_count = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type  = ee16(ETH_TYPE_IP);
    ip->ver_ihl   = 0x45;
    ip->flags_fo  = ee16(0x2000U); /* MF=1, offset=0 */
    ip->ttl       = 1;
    ip->proto     = WI_IPPROTO_UDP;
    ip->len       = ee16(IP_HEADER_LEN + 8);
    ip->src       = ee32(src_ip);
    ip->dst       = ee32(dest_ip);
    fix_ip_checksum(ip);

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Silent: no Time Exceeded, no relay. */
    ck_assert_uint_eq(last_frame_sent_count, 0);
}
END_TEST

/* =========================================================================
 * RFC 1812 4.3.2.7: zero-network-prefix source, transit, TTL=1 - silent
 * drop
 * =========================================================================
 * The general per-packet filter lets src=0.0.0.0 through while the DHCP
 * client is unbound (for local DHCP/BOOTP traffic). A non-local (transit)
 * packet with a zero source must not be relayed or used as an ICMP-error
 * destination: RFC 1812 4.3.2.7 forbids an ICMP error for a packet whose
 * source has a zero network prefix. Drop it in the forwarding RPF block,
 * not a Time Exceeded addressed to 0.0.0.0.
 */
START_TEST(test_fwd_zero_source_transit_ttl1_silent_drop)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip      = 0xC0A80155U;
    static const uint8_t dest_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    fwd_arp_store(&s, TEST_SECOND_IF, dest_ip, dest_mac);
    /* Unbound DHCP: the general zero-source filter is bypassed, so the
     * forwarding RPF block is what must drop the zero-source transit packet. */
    s.dhcp_state = DHCP_DISCOVER_SENT;
    last_frame_sent_count = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type  = ee16(ETH_TYPE_IP);
    ip->ver_ihl   = 0x45;
    ip->flags_fo  = 0; /* not a fragment: must reach the forwarding RPF block */
    ip->ttl       = 1;
    ip->proto     = WI_IPPROTO_UDP;
    ip->len       = ee16(IP_HEADER_LEN + 8);
    ip->src       = ee32(0x00010203U); /* 0.1.2.3: in 0/8, not the exact zero */
    ip->dst       = ee32(dest_ip);
    fix_ip_checksum(ip);

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Silent: no Time Exceeded addressed to 0.1.2.3, no relay. */
    ck_assert_uint_eq(last_frame_sent_count, 0);
}
END_TEST

/* =========================================================================
 * Fragment, DF set, larger than egress MTU - silent drop
 * =========================================================================
 * Fragments are dropped at arrival, before the forwarding decision, so a
 * DF fragment that does not fit the egress MTU must not generate a
 * Fragmentation Needed: the datagram is simply dropped.
 */
START_TEST(test_fwd_nonfirst_frag_df_oversize_silent_drop)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + 580];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip      = 0xC0A80155U;
    ip4 src_ip       = 0x0A000002U;
    static const uint8_t dest_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    /* Egress frame budget 590 bytes: IP MTU 576 (the IPv4 minimum). */
    s.ll_dev[TEST_SECOND_IF].mtu = 590;
    fwd_arp_store(&s, TEST_SECOND_IF, dest_ip, dest_mac);
    last_frame_sent_count = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type  = ee16(ETH_TYPE_IP);
    ip->ver_ihl   = 0x45;
    ip->flags_fo  = ee16(0x4001U); /* DF=1, offset=1 (8 bytes) */
    ip->ttl       = 64;
    ip->proto     = WI_IPPROTO_UDP;
    ip->len       = ee16(IP_HEADER_LEN + 580); /* 600 > egress MTU 576 */
    ip->src       = ee32(src_ip);
    ip->dst       = ee32(dest_ip);
    fix_ip_checksum(ip);

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Silent: no Fragmentation Needed, no relay. */
    ck_assert_uint_eq(last_frame_sent_count, 0);
}
END_TEST

/* =========================================================================
 * DF set, larger than egress MTU - Fragmentation Needed
 * =========================================================================
 * A DF datagram that does not fit the egress MTU is not a fragment (MF
 * clear, offset zero), so it is not dropped at arrival: RFC 1812 4.3.2.4
 * requires the Fragmentation Needed reply carrying the egress next-hop
 * MTU.
 */
START_TEST(test_fwd_df_oversize_sends_frag_needed)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + 580];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip      = 0xC0A80155U;
    ip4 src_ip       = 0x0A000002U;
    static const uint8_t dest_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    s.ll_dev[TEST_SECOND_IF].mtu = 590;
    fwd_arp_store(&s, TEST_SECOND_IF, dest_ip, dest_mac);
    last_frame_sent_count = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type  = ee16(ETH_TYPE_IP);
    ip->ver_ihl   = 0x45;
    ip->flags_fo  = ee16(0x4000U); /* DF=1, offset=0: complete datagram, not a fragment */
    ip->ttl       = 64;
    ip->proto     = WI_IPPROTO_UDP;
    ip->len       = ee16(IP_HEADER_LEN + 580); /* 600 > egress MTU 576 */
    ip->src       = ee32(src_ip);
    ip->dst       = ee32(dest_ip);
    fix_ip_checksum(ip);

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Fragmentation Needed with the egress next-hop MTU (576 = 0x0240). */
    ck_assert_uint_eq(last_frame_sent_count, 1);
    ck_assert_uint_eq(last_frame_sent[ETH_HEADER_LEN + IP_HEADER_LEN],
            ICMP_DEST_UNREACH);
    ck_assert_uint_eq(last_frame_sent[ETH_HEADER_LEN + IP_HEADER_LEN + 1],
            ICMP_FRAG_NEEDED);
    ck_assert_uint_eq(last_frame_sent[ETH_HEADER_LEN + IP_HEADER_LEN + 6],
            0x02);
    ck_assert_uint_eq(last_frame_sent[ETH_HEADER_LEN + IP_HEADER_LEN + 7],
            0x40);
}
END_TEST

/* =========================================================================
 * Fragment with a malformed IP option - silent drop
 * =========================================================================
 * Fragments are dropped at arrival, before the option policy below, so a
 * fragment with a malformed IP option must not generate a Parameter
 * Problem: the datagram is simply dropped.
 */
START_TEST(test_fwd_nonfirst_frag_bad_option_silent_drop)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + 24 + 8];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip      = 0xC0A80155U;
    ip4 src_ip       = 0x0A000002U;
    static const uint8_t dest_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t *opt;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    fwd_arp_store(&s, TEST_SECOND_IF, dest_ip, dest_mac);
    last_frame_sent_count = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type  = ee16(ETH_TYPE_IP);
    ip->ver_ihl   = 0x46; /* IHL 6: 20-byte header + 4 option bytes */
    ip->flags_fo  = ee16(0x0001U); /* MF=0, offset=1 (8 bytes) */
    ip->ttl       = 64;
    ip->proto     = WI_IPPROTO_UDP;
    ip->len       = ee16(24 + 8);
    ip->src       = ee32(src_ip);
    ip->dst       = ee32(dest_ip);
    /* Record Route option at offset 20 with length 100: runs past the end
     * of the 4-byte option area. */
    opt = frame + ETH_HEADER_LEN + IP_HEADER_LEN;
    opt[0] = 0x44;
    opt[1] = 100;
    fix_ip_checksum(ip);

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Silent: no Parameter Problem, no relay. */
    ck_assert_uint_eq(last_frame_sent_count, 0);
}
END_TEST

/* =========================================================================
 * RFC 1812 4.3.2.4: multicast destination with a malformed IP option -
 * silent drop
 * =========================================================================
 * Multicast destinations are exempt from the Parameter Problem reply
 * (error storms on group traffic); the datagram is dropped.
 */
START_TEST(test_fwd_multicast_dest_bad_option_silent_drop)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + 24 + 8];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip      = 0xE0000001U; /* 224.0.0.1, all-hosts */
    ip4 src_ip       = 0x0A000002U;
    ip4 gw_ip        = 0xC0A801FEU;
    static const uint8_t gw_mac[6] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25};
    uint8_t *opt;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    /* The multicast destination is not on any connected subnet: a default
     * route gives the forwarding path an egress so the option check runs. */
    ck_assert_int_eq(wolfIP_route_add(&s, TEST_SECOND_IF, 0x00000000U, 0,
                                      gw_ip), 0);
    fwd_arp_store(&s, TEST_SECOND_IF, gw_ip, gw_mac);
    last_frame_sent_count = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type  = ee16(ETH_TYPE_IP);
    ip->ver_ihl   = 0x46; /* IHL 6: 20-byte header + 4 option bytes */
    ip->flags_fo  = 0;
    ip->ttl       = 64;
    ip->proto     = WI_IPPROTO_UDP;
    ip->len       = ee16(24 + 8);
    ip->src       = ee32(src_ip);
    ip->dst       = ee32(dest_ip);
    opt = frame + ETH_HEADER_LEN + IP_HEADER_LEN;
    opt[0] = 0x44;
    opt[1] = 100;
    fix_ip_checksum(ip);

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Silent: multicast destination is exempt, no relay. */
    ck_assert_uint_eq(last_frame_sent_count, 0);
}
END_TEST

/* =========================================================================
 * RFC 1812 4.3.2.7: multicast destination - no Time Exceeded / Frag Needed
 * =========================================================================
 * No ICMP error may be sent in response to a datagram addressed to an IP
 * multicast destination, so an expiring TTL or a DF datagram larger than the
 * egress MTU is dropped silently, like the Parameter Problem case above.
 */
static void fwd_multicast_error_setup(struct wolfIP *s, uint8_t *frame,
        uint32_t frame_len, uint16_t flags_fo, uint8_t ttl, uint16_t ip_len)
{
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 gw_ip = 0xC0A801FEU;
    static const uint8_t gw_mac[6] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25};

    setup_stack_with_two_ifaces(s, 0x0A000001U, 0xC0A80101U);
    wolfIP_filter_set_callback(NULL, NULL);
    ck_assert_int_eq(wolfIP_route_add(s, TEST_SECOND_IF, 0x00000000U, 0,
                                      gw_ip), 0);
    s->ll_dev[TEST_SECOND_IF].mtu = 590;
    fwd_arp_store(s, TEST_SECOND_IF, gw_ip, gw_mac);
    last_frame_sent_count = 0;

    memset(frame, 0, frame_len);
    memcpy(ip->eth.dst, s->ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type  = ee16(ETH_TYPE_IP);
    ip->ver_ihl   = 0x45;
    ip->flags_fo  = ee16(flags_fo);
    ip->ttl       = ttl;
    ip->proto     = WI_IPPROTO_UDP;
    ip->len       = ee16(ip_len);
    ip->src       = ee32(0x0A000002U);
    ip->dst       = ee32(0xE0000001U); /* 224.0.0.1 */
    fix_ip_checksum(ip);
}

START_TEST(test_fwd_multicast_dest_ttl_expired_silent_drop)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + 8];

    fwd_multicast_error_setup(&s, frame, sizeof(frame), 0, 1,
            IP_HEADER_LEN + 8);
    ip_recv(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)frame,
            (uint32_t)sizeof(frame));

    /* Silent: no Time Exceeded, no relay. */
    ck_assert_uint_eq(last_frame_sent_count, 0);
}
END_TEST

START_TEST(test_fwd_multicast_dest_df_oversize_silent_drop)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + 580];

    fwd_multicast_error_setup(&s, frame, sizeof(frame), 0x4000U, 64,
            IP_HEADER_LEN + 580);
    ip_recv(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)frame,
            (uint32_t)sizeof(frame));

    /* Silent: no Fragmentation Needed, no relay. */
    ck_assert_uint_eq(last_frame_sent_count, 0);
}
END_TEST

/* =========================================================================
 * RFC 1858: fragments are dropped at arrival, before the SENDING L4
 * filter hooks
 * =========================================================================
 * Relaying fragments lets a fragment set bypass port-based policy
 * (RFC 1858): a first fragment shorter than a full TCP header is allowed
 * by the length guard, and a non-first fragment carries no transport
 * header to match. All fragments are now dropped at arrival, so neither
 * fragment of a TCP datagram is relayed or reaches the TCP sending filter.
 */
START_TEST(test_fwd_fragments_dropped_before_l4_filter)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip      = 0xC0A80155U;
    ip4 src_ip       = 0x0A000002U;
    static const uint8_t dest_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t *payload;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(fwd_filter_count_cb, NULL);
    wolfIP_filter_set_tcp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    wolfIP_filter_set_udp_mask(0);
    wolfIP_filter_set_icmp_mask(0);
    wolfIP_filter_set_ip_mask(0);
    fwd_arp_store(&s, TEST_SECOND_IF, dest_ip, dest_mac);
    fwd_filter_notify_count = 0;
    fwd_filter_last_dport = 0;
    last_frame_sent_count = 0;

    /* Non-first fragment: the 20 payload bytes are crafted to look like a
     * TCP header (src port 80, dst port 443). If the notify fired on them,
     * the counter would move. */
    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type  = ee16(ETH_TYPE_IP);
    ip->ver_ihl   = 0x45;
    ip->flags_fo  = ee16(0x0001U); /* MF=0, offset=1: non-first fragment */
    ip->ttl       = 64;
    ip->proto     = WI_IPPROTO_TCP;
    ip->len       = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ip->src       = ee32(src_ip);
    ip->dst       = ee32(dest_ip);
    payload = frame + ETH_HEADER_LEN + IP_HEADER_LEN;
    payload[0] = 0x00; payload[1] = 0x50; /* src port 80 */
    payload[2] = 0x01; payload[3] = 0xBB; /* dst port 443 */
    fix_ip_checksum(ip);

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Dropped at arrival: no relay, no TCP notification. */
    ck_assert_uint_eq(last_frame_sent_count, 0);
    ck_assert_uint_eq(fwd_filter_notify_count, 0);

    /* First fragment of the same TCP datagram: dropped the same way. */
    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type  = ee16(ETH_TYPE_IP);
    ip->ver_ihl   = 0x45;
    ip->flags_fo  = ee16(0x2000U); /* MF=1, offset=0 */
    ip->ttl       = 64;
    ip->proto     = WI_IPPROTO_TCP;
    ip->len       = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ip->src       = ee32(src_ip);
    ip->dst       = ee32(dest_ip);
    payload = frame + ETH_HEADER_LEN + IP_HEADER_LEN;
    payload[0] = 0x00; payload[1] = 0x50; /* src port 80 */
    payload[2] = 0x01; payload[3] = 0xBB; /* dst port 443 */
    fix_ip_checksum(ip);

    last_frame_sent_count = 0;
    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    ck_assert_uint_eq(last_frame_sent_count, 0);
    ck_assert_uint_eq(fwd_filter_notify_count, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_tcp_mask(0);
}
END_TEST

/* =========================================================================
 * Fragment-drop mask covers the full 13-bit offset, not just the low 12
 * =========================================================================
 * A non-first fragment whose offset has only bit 12 set (flags_fo 0x1000,
 * MF clear, offset 32768 bytes) must be dropped: it is a fragment by the
 * non-zero offset, and the arrival drop must catch every offset bit. The
 * mask is MF (0x2000) plus the 13-bit offset (0x1FFF) = 0x3FFF; a 0x2FFF
 * mask would let 0x1000 through. */
START_TEST(test_fwd_frag_offset_bit12_dropped)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip      = 0xC0A80155U;
    ip4 src_ip       = 0x0A000002U;
    static const uint8_t dest_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t *payload;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(fwd_filter_count_cb, NULL);
    wolfIP_filter_set_tcp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    wolfIP_filter_set_udp_mask(0);
    wolfIP_filter_set_icmp_mask(0);
    wolfIP_filter_set_ip_mask(0);
    fwd_arp_store(&s, TEST_SECOND_IF, dest_ip, dest_mac);
    fwd_filter_notify_count = 0;
    fwd_filter_last_dport = 0;
    last_frame_sent_count = 0;

    /* MF clear, offset bit 12 only: a non-first fragment the 0x2FFF mask
     * would miss. The payload looks like a TCP header (dport 443) so a
     * leak would fire the SENDING notify. */
    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type  = ee16(ETH_TYPE_IP);
    ip->ver_ihl   = 0x45;
    ip->flags_fo  = ee16(0x1000U); /* MF=0, offset=0x1000 (bit 12) */
    ip->ttl       = 64;
    ip->proto     = WI_IPPROTO_TCP;
    ip->len       = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ip->src       = ee32(src_ip);
    ip->dst       = ee32(dest_ip);
    payload = frame + ETH_HEADER_LEN + IP_HEADER_LEN;
    payload[0] = 0x00; payload[1] = 0x50; /* src port 80 */
    payload[2] = 0x01; payload[3] = 0xBB; /* dst port 443 */
    fix_ip_checksum(ip);

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Dropped at arrival: no relay, no TCP notification. */
    ck_assert_uint_eq(last_frame_sent_count, 0);
    ck_assert_uint_eq(fwd_filter_notify_count, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_tcp_mask(0);
}
END_TEST

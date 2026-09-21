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
 * RFC 1812 4.3.2.7: non-first fragment, TTL=1 - silent drop
 * =========================================================================
 * A router must not generate an ICMP error for a non-first fragment: it
 * cannot validate what the fragment does not carry. The datagram is not
 * relayed (TTL expired) and no Time Exceeded is sent.
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
 * RFC 1812 4.3.2.7 selectivity: first fragment, TTL=1 - Time Exceeded
 * =========================================================================
 * The same datagram's first fragment (offset 0) carries a valid transport
 * header, so the Time Exceeded reply is generated. Pairs with the
 * non-first-fragment silent drop above to prove the guard is selective.
 */
START_TEST(test_fwd_first_frag_ttl1_sends_ttl_exceeded)
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

    /* Time Exceeded quoting header + the 8 payload bytes present. */
    ck_assert_uint_eq(last_frame_sent_count, 1);
    ck_assert_uint_eq(last_frame_sent_size,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + 8 + IP_HEADER_LEN + 8));
    ck_assert_uint_eq(last_frame_sent[ETH_HEADER_LEN + IP_HEADER_LEN],
            ICMP_TTL_EXCEEDED);
}
END_TEST

/* =========================================================================
 * RFC 1812 4.3.2.7: non-first fragment, DF set, larger than egress MTU
 * - silent drop
 * =========================================================================
 * The Fragmentation Needed reply is suppressed for a non-first fragment;
 * the datagram is dropped (it does not fit the egress and cannot be
 * fragmented further).
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
 * RFC 1812 4.3.2.7 selectivity: first fragment, DF set, larger than
 * egress MTU - Fragmentation Needed
 * =========================================================================
 * Pairs with the non-first-fragment silent drop above: the first fragment
 * carries a valid transport header, so the Fragmentation Needed reply is
 * generated.
 */
START_TEST(test_fwd_first_frag_df_oversize_sends_frag_needed)
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
    ip->flags_fo  = ee16(0x4000U); /* DF=1, offset=0 */
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
 * RFC 1812 4.3.2.7: non-first fragment with a malformed IP option -
 * silent drop
 * =========================================================================
 * The Parameter Problem reply is suppressed for a non-first fragment; the
 * datagram is dropped either way.
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
 * RFC 1858: SENDING L4 filter hooks are not notified for a non-first
 * fragment
 * =========================================================================
 * The bytes at the IHL offset of a non-first fragment are payload, not a
 * transport header. Notifying the TCP/UDP hooks would let port-based
 * policy match on garbage. The non-first fragment is relayed without a
 * TCP notification; the first fragment of a TCP datagram is notified with
 * the real header's destination port.
 */
START_TEST(test_fwd_nonfirst_frag_l4_filter_not_notified)
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

    /* Relayed, and no TCP notification was generated from the payload. */
    ck_assert_uint_eq(last_frame_sent_count, 1);
    ck_assert_uint_eq(fwd_filter_notify_count, 0);

    /* First fragment of a TCP datagram: the notify fires with the real
     * header's destination port. */
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

    ck_assert_uint_eq(last_frame_sent_count, 1);
    ck_assert_uint_eq(fwd_filter_notify_count, 1);
    ck_assert_uint_eq(fwd_filter_last_dport, ee16(443));

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_tcp_mask(0);
}
END_TEST

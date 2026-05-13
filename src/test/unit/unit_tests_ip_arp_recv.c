/* unit_tests_ip_arp_recv.c
 *
 * Copyright (C) 2024 wolfSSL Inc.
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
/* =========================================================================
 * Helpers shared by multiple tests
 * ========================================================================= */

/* Build a valid ARP packet in 'arp_out'. Caller fills htype/ptype/hlen/plen
 * and sip after calling this. */
static void build_valid_arp_request(struct arp_packet *arp_out,
                                    struct wolfIP_ll_dev *ll,
                                    ip4 own_ip,
                                    ip4 sender_ip)
{
    static const uint8_t sender_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};

    memset(arp_out, 0, sizeof(*arp_out));
    memcpy(arp_out->eth.dst, ll->mac, 6);
    memcpy(arp_out->eth.src, sender_mac, 6);
    arp_out->eth.type = ee16(ETH_TYPE_ARP);
    arp_out->htype  = ee16(1);
    arp_out->ptype  = ee16(0x0800);
    arp_out->hlen   = 6;
    arp_out->plen   = 4;
    arp_out->opcode = ee16(ARP_REQUEST);
    memcpy(arp_out->sma, sender_mac, 6);
    arp_out->sip = ee32(sender_ip);
    memset(arp_out->tma, 0, 6);
    arp_out->tip = ee32(own_ip);
}

/* =========================================================================
 * ip_recv: limited broadcast destination (255.255.255.255) treated as local
 * =========================================================================
 * Branch: wolfIP_ip_is_broadcast(s, dest) → is_local = 1
 * We verify this via the forwarding path: with two interfaces, a broadcast
 * dst must not cause a forwarding ARP request (it is local, not forwarded).
 */
START_TEST(test_ip_recv_limited_broadcast_dst_is_local)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 src_ip       = 0x0A000002U;
    ip4 bcast_dst    = 0xFFFFFFFFU;  /* 255.255.255.255 limited broadcast */

    /* Two interfaces enable forwarding logic; broadcast must stay is_local=1 */
    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x45;
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    ip->src      = ee32(src_ip);
    ip->dst      = ee32(bcast_dst);
    fix_ip_checksum(ip);
    {
        uint16_t *udp = (uint16_t *)(frame + ETH_HEADER_LEN + IP_HEADER_LEN);
        udp[0] = ee16(9999); udp[1] = ee16(1234);
        udp[2] = ee16(UDP_HEADER_LEN); udp[3] = 0;
    }

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN));

    /* Broadcast dst → is_local=1 → no forwarding → no ARP request sent for
     * a remote host (last_frame_sent may be 0 or an ARP request, but NO
     * forwarding ARP pending for the broadcast address should exist) */
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

/* =========================================================================
 * ip_recv: directed broadcast hits the is_local=1 branch too
 * =========================================================================
 * Branch: wolfIP_ip_is_broadcast(s, dest) where dest == directed broadcast
 * 10.0.0.255 is the directed broadcast for 10.0.0.0/24.
 * With two interfaces, this must NOT be forwarded out the second interface.
 */
START_TEST(test_ip_recv_directed_broadcast_dst_is_local)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;   /* 10.0.0.1/24 */
    ip4 secondary_ip = 0xC0A80101U;   /* 192.168.1.1/24 */
    ip4 src_ip       = 0x0A000002U;
    ip4 dir_bcast    = 0x0A0000FFU;   /* 10.0.0.255 — directed broadcast */

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x45;
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    ip->src      = ee32(src_ip);
    ip->dst      = ee32(dir_bcast);
    fix_ip_checksum(ip);
    {
        uint16_t *udp = (uint16_t *)(frame + ETH_HEADER_LEN + IP_HEADER_LEN);
        udp[0] = ee16(9999); udp[1] = ee16(1234);
        udp[2] = ee16(UDP_HEADER_LEN); udp[3] = 0;
    }

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Directed broadcast → is_local=1 → not forwarded to secondary iface */
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

/* =========================================================================
 * ip_recv: IPADDR_ANY destination treated as local
 * =========================================================================
 * Branch: dest == IPADDR_ANY → is_local = 1
 * Packet to 0.0.0.0 must not be forwarded, even with two interfaces.
 */
START_TEST(test_ip_recv_ipaddr_any_dst_is_local)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 src_ip       = 0x0A000002U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x45;
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    ip->src      = ee32(src_ip);
    ip->dst      = ee32(IPADDR_ANY);  /* 0.0.0.0 */
    fix_ip_checksum(ip);
    {
        uint16_t *udp = (uint16_t *)(frame + ETH_HEADER_LEN + IP_HEADER_LEN);
        udp[0] = ee16(9999); udp[1] = ee16(1234);
        udp[2] = ee16(UDP_HEADER_LEN); udp[3] = 0;
    }

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* 0.0.0.0 dst → is_local=1 → never forwarded */
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

/* =========================================================================
 * ip_recv: forward with ARP cache HIT — packet forwarded immediately
 * =========================================================================
 * Branch: wolfIP_forward_prepare returns 1 (ARP hit) → wolfIP_forward_packet
 * called without queuing.  Tests the "direct forward" arm at line 8468.
 */
START_TEST(test_ip_recv_forward_arp_hit_sends_immediately)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;   /* 10.0.0.1  on if1 */
    ip4 secondary_ip = 0xC0A80101U;   /* 192.168.1.1 on if2 */
    ip4 dest_ip      = 0xC0A80155U;   /* 192.168.1.85 — local to if2 */
    ip4 src_ip       = 0x0A000002U;   /* sender */
    static const uint8_t dest_mac[6] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15};

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);

    /* Pre-populate ARP cache for dest on if2 so prepare returns 1 (HIT) */
    arp_store_neighbor(&s, TEST_SECOND_IF, dest_ip, dest_mac);

    last_frame_sent_size = 0;

    /* Build a packet to forward: src on primary subnet, dst on secondary */
    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x45;
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    ip->src      = ee32(src_ip);
    ip->dst      = ee32(dest_ip);
    fix_ip_checksum(ip);
    /* Append minimal UDP header so length arithmetic holds */
    {
        uint16_t *udp = (uint16_t *)(frame + ETH_HEADER_LEN + IP_HEADER_LEN);
        udp[0] = ee16(9999); udp[1] = ee16(53);
        udp[2] = ee16(UDP_HEADER_LEN); udp[3] = 0;
    }

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Frame must have been sent out immediately (ARP cache hit) */
    ck_assert_uint_gt(last_frame_sent_size, 0);
    /* Destination MAC in sent frame must match the cached entry */
    ck_assert_mem_eq(last_frame_sent + 0, dest_mac, 6);
    /* No pending ARP slot should have been allocated */
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

/* =========================================================================
 * ip_recv: forward interface with no configured IP is skipped
 * =========================================================================
 * Branch: in wolfIP_forward_interface, conf->ip == IPADDR_ANY → continue
 * A second interface with no IP should never be selected as forward egress.
 */
START_TEST(test_ip_recv_forward_unconfigured_iface_skipped)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip = 0x0A000001U;
    ip4 dest_ip    = 0xC0A80155U;  /* 192.168.1.85 — not local anywhere */
    ip4 src_ip     = 0x0A000002U;

    /* Only configure primary interface; leave second with ip=IPADDR_ANY */
    wolfIP_init(&s);
    mock_link_init(&s);
    mock_link_init_idx(&s, TEST_SECOND_IF, NULL);
    wolfIP_ipconfig_set(&s, primary_ip, 0xFFFFFF00U, 0);
    /* TEST_SECOND_IF ip remains IPADDR_ANY (no call to set_ex) */

    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x45;
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    ip->src      = ee32(src_ip);
    ip->dst      = ee32(dest_ip);
    fix_ip_checksum(ip);

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN));

    /* No forward route found → no packet sent */
    ck_assert_uint_eq(last_frame_sent_size, 0);
    /* No ARP pending slot allocated */
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

/* =========================================================================
 * ip_recv: link-local source (169.254.x.x) is not routable — RPF drop
 * =========================================================================
 * Branch: (src & 0xFFFF0000U) == 0xA9FE0000U → rpf_drop = 1
 */
START_TEST(test_ip_recv_forward_link_local_src_rpf_drop)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 src_ip       = 0xA9FE0002U;  /* 169.254.0.2 — link-local */
    ip4 dest_ip      = 0xC0A80155U;  /* would be forwarded if src were ok */

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x45;
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    ip->src      = ee32(src_ip);
    ip->dst      = ee32(dest_ip);
    fix_ip_checksum(ip);

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Link-local source is not routable; must be dropped silently */
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

/* =========================================================================
 * ip_recv: IP with NOP options — options parsed, payload delivered
 * =========================================================================
 * Branch: type == 1 (NOP) inside option parser → opt++ continue
 * Ensures NOP bytes in the option list are skipped and not mis-identified
 * as bad options.
 */
START_TEST(test_ip_recv_options_nop_delivered)
{
    struct wolfIP s;
    /* 4 bytes of IP options: NOP NOP NOP EOL */
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + 4 + UDP_HEADER_LEN + 4];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    uint8_t *udp_hdr = frame + ETH_HEADER_LEN + IP_HEADER_LEN + 4;
    uint16_t udp_len = UDP_HEADER_LEN + 4;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x46;   /* IHL=6 → 24-byte header, 4 bytes of options */
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN + 4 + udp_len);
    ip->src      = ee32(remote_ip);
    ip->dst      = ee32(local_ip);
    /* Options: NOP NOP NOP EOL */
    ip->data[0]  = 1; ip->data[1] = 1; ip->data[2] = 1; ip->data[3] = 0;

    /* UDP header right after options */
    ((uint16_t *)udp_hdr)[0] = ee16(9999);  /* sport */
    ((uint16_t *)udp_hdr)[1] = ee16(1234);  /* dport */
    ((uint16_t *)udp_hdr)[2] = ee16(udp_len);
    memcpy(udp_hdr + UDP_HEADER_LEN, "nop!", 4);

    fix_udp_checksum_raw(ip, udp_hdr, udp_len);
    fix_ip_checksum_with_hlen(ip, (uint16_t)(IP_HEADER_LEN + 4));

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* NOP options must be stripped and UDP payload delivered */
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.rxbuf));
    ck_assert_int_ne(ts->events & CB_EVENT_READABLE, 0);
}
END_TEST

/* =========================================================================
 * ip_recv: option type unknown (non-NOP, non-EOL, non-source-route)
 * =========================================================================
 * Branch: generic option walking (opt += opt[1]) for type != 0/1/0x83/0x89
 * RR (record-route = 0x07) is a benign option that must be parsed, stripped,
 * then the payload delivered.
 */
START_TEST(test_ip_recv_options_rr_stripped_and_delivered)
{
    struct wolfIP s;
    /* 4-byte RR option: type=0x07, len=3, ptr=4, then EOL */
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + 4 + UDP_HEADER_LEN + 4];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    uint8_t *udp_hdr = frame + ETH_HEADER_LEN + IP_HEADER_LEN + 4;
    uint16_t udp_len = UDP_HEADER_LEN + 4;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x46;
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN + 4 + udp_len);
    ip->src      = ee32(remote_ip);
    ip->dst      = ee32(local_ip);
    /* Options: type=0x07 (RR), len=3, ptr=4, then EOL */
    ip->data[0]  = 0x07; ip->data[1] = 3; ip->data[2] = 4; ip->data[3] = 0;

    ((uint16_t *)udp_hdr)[0] = ee16(9999);
    ((uint16_t *)udp_hdr)[1] = ee16(1234);
    ((uint16_t *)udp_hdr)[2] = ee16(udp_len);
    memcpy(udp_hdr + UDP_HEADER_LEN, "rr!!", 4);

    fix_udp_checksum_raw(ip, udp_hdr, udp_len);
    fix_ip_checksum_with_hlen(ip, (uint16_t)(IP_HEADER_LEN + 4));

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* RR option stripped, UDP payload delivered */
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.rxbuf));
    ck_assert_int_ne(ts->events & CB_EVENT_READABLE, 0);
}
END_TEST

/* =========================================================================
 * ip_recv: option bad length (opt[1] < 2) — parsing aborts (break)
 * =========================================================================
 * Branch: opt + 1 >= opt_end || opt[1] < 2 → break
 * A malformed option with length=1 must not loop infinitely.
 */
START_TEST(test_ip_recv_options_bad_length_aborts_parse)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + 4 + UDP_HEADER_LEN + 4];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    uint8_t *udp_hdr = frame + ETH_HEADER_LEN + IP_HEADER_LEN + 4;
    uint16_t udp_len = UDP_HEADER_LEN + 4;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x46;
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN + 4 + udp_len);
    ip->src      = ee32(remote_ip);
    ip->dst      = ee32(local_ip);
    /* Options: type=0x44 (timestamp), length=1 (bad — must be >=2) */
    ip->data[0]  = 0x44; ip->data[1] = 1; ip->data[2] = 0; ip->data[3] = 0;

    ((uint16_t *)udp_hdr)[0] = ee16(9999);
    ((uint16_t *)udp_hdr)[1] = ee16(1234);
    ((uint16_t *)udp_hdr)[2] = ee16(udp_len);
    memcpy(udp_hdr + UDP_HEADER_LEN, "bad!", 4);

    fix_udp_checksum_raw(ip, udp_hdr, udp_len);
    fix_ip_checksum_with_hlen(ip, (uint16_t)(IP_HEADER_LEN + 4));

    /* Must not crash; packet may or may not be delivered, but parse terminates */
    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));
    /* (no assertion on delivery — the goal is no infinite loop / crash) */
}
END_TEST

/* =========================================================================
 * ip_recv: IP options present but total length is well-formed (normal strip)
 * =========================================================================
 * Branch: ip_hlen > IP_HEADER_LEN → option-strip code path executed
 * Options stripped, adjusted csum recomputed, payload dispatched.
 */
START_TEST(test_ip_recv_options_strip_checksum_recomputed)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + 4 + UDP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    uint8_t *udp_hdr = frame + ETH_HEADER_LEN + IP_HEADER_LEN + 4;
    uint16_t udp_len = UDP_HEADER_LEN;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x46;
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN + 4 + udp_len);
    ip->src      = ee32(remote_ip);
    ip->dst      = ee32(local_ip);
    /* Options: 4 NOPs */
    ip->data[0] = 1; ip->data[1] = 1; ip->data[2] = 1; ip->data[3] = 1;

    ((uint16_t *)udp_hdr)[0] = ee16(8888);  /* sport */
    ((uint16_t *)udp_hdr)[1] = ee16(1234);  /* dport */
    ((uint16_t *)udp_hdr)[2] = ee16(udp_len);
    ((uint16_t *)udp_hdr)[3] = 0;

    fix_udp_checksum_raw(ip, udp_hdr, udp_len);
    fix_ip_checksum_with_hlen(ip, (uint16_t)(IP_HEADER_LEN + 4));

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.rxbuf));
}
END_TEST

/* =========================================================================
 * ip_recv: LSRR source route option — packet dropped
 * =========================================================================
 * Branch: type == 0x83 (LSRR) → return immediately (RFC 7126)
 * Already registered as test_ip_recv_drops_source_routed_packet but we
 * verify the LSRR (0x83) path specifically in our own test to cover both
 * sub-arms of the || check.  This test uses SSRR (0x89) for the alt arm.
 * NOTE: Only adding SSRR test since LSRR (0x83) is already registered.
 */
START_TEST(test_ip_recv_options_ssrr_dropped)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + 8 + UDP_HEADER_LEN + 4];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    uint8_t *udp_hdr = frame + ETH_HEADER_LEN + IP_HEADER_LEN + 8;
    uint16_t udp_len = UDP_HEADER_LEN + 4;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x47;   /* IHL=7 → 28 bytes (8 bytes of options) */
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN + 8 + udp_len);
    ip->src      = ee32(remote_ip);
    ip->dst      = ee32(local_ip);
    /* Options: SSRR (0x89), len=7, ptr=4, then 3-byte route + EOL */
    ip->data[0] = 0x89; ip->data[1] = 7; ip->data[2] = 4;
    ip->data[3] = 0x0A; ip->data[4] = 0x00; ip->data[5] = 0x00; ip->data[6] = 0x01;
    ip->data[7] = 0;  /* EOL */

    ((uint16_t *)udp_hdr)[0] = ee16(9999);
    ((uint16_t *)udp_hdr)[1] = ee16(1234);
    ((uint16_t *)udp_hdr)[2] = ee16(udp_len);
    memcpy(udp_hdr + UDP_HEADER_LEN, "ssrr", 4);

    fix_udp_checksum_raw(ip, udp_hdr, udp_len);
    fix_ip_checksum_with_hlen(ip, (uint16_t)(IP_HEADER_LEN + 8));

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* SSRR option → packet must be silently dropped */
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, 0);
}
END_TEST

/* =========================================================================
 * ip_recv: loopback destination on non-loopback interface — dropped
 * =========================================================================
 * Branch: (dest & WOLFIP_LOOPBACK_MASK) == loopback prefix && !loopback_if
 */
START_TEST(test_ip_recv_loopback_dst_on_non_loopback_dropped)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    ip4 loop_dst  = 0x7F000001U;  /* 127.0.0.1 */

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = IPADDR_ANY;

    /* Inject from non-loopback interface to loopback destination */
    inject_udp_datagram(&s, TEST_PRIMARY_IF, remote_ip, loop_dst,
                        9999, 1234, NULL, 0);

    /* Must be dropped — loopback addresses must not arrive on wire */
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, 0);
}
END_TEST

/* =========================================================================
 * ip_recv: loopback source on non-loopback interface — dropped
 * =========================================================================
 * Branch: (src & WOLFIP_LOOPBACK_MASK) == loopback prefix && !loopback_if
 */
START_TEST(test_ip_recv_loopback_src_on_non_loopback_dropped)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 loop_src  = 0x7F000002U;  /* 127.0.0.2 as source */

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = IPADDR_ANY;

    inject_udp_datagram(&s, TEST_PRIMARY_IF, loop_src, local_ip,
                        9999, 1234, NULL, 0);

    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

/* =========================================================================
 * ip_recv: TTL=2 forwarding (normal forward, no TTL exceeded)
 * =========================================================================
 * Branch: ip->ttl > 1 → ttl-- and forward, not TTL exceeded
 */
START_TEST(test_ip_recv_forward_ttl_normal_decremented)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip      = 0xC0A80155U;
    ip4 src_ip       = 0x0A000002U;
    static const uint8_t dest_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t *sent_ip_ttl;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);

    arp_store_neighbor(&s, TEST_SECOND_IF, dest_ip, dest_mac);
    last_frame_sent_size = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x45;
    ip->ttl      = 64;  /* TTL > 1: normal forward path */
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    ip->src      = ee32(src_ip);
    ip->dst      = ee32(dest_ip);
    fix_ip_checksum(ip);
    {
        uint16_t *udp = (uint16_t *)(frame + ETH_HEADER_LEN + IP_HEADER_LEN);
        udp[0] = ee16(9999); udp[1] = ee16(53);
        udp[2] = ee16(UDP_HEADER_LEN); udp[3] = 0;
    }

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    ck_assert_uint_gt(last_frame_sent_size, 0);
    /* TTL in forwarded frame must be decremented to 63 */
    sent_ip_ttl = last_frame_sent + ETH_HEADER_LEN + 8;  /* IP TTL offset */
    ck_assert_uint_eq(*sent_ip_ttl, 63);
}
END_TEST

/* =========================================================================
 * ip_recv: TTL=1 short-frame — dropped before TTL-exceeded sent
 * =========================================================================
 * Branch: ip->ttl <= 1 && len < ETH_HEADER_LEN + ip_hlen + 8 → return
 */
START_TEST(test_ip_recv_forward_ttl1_short_frame_dropped)
{
    struct wolfIP s;
    /* Frame too short: ETH + IP only, missing the required 8 transport bytes */
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip      = 0xC0A80155U;
    ip4 src_ip       = 0x0A000002U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x45;
    ip->ttl      = 1;  /* TTL == 1 → would send TTL exceeded if frame ok */
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN);
    ip->src      = ee32(src_ip);
    ip->dst      = ee32(dest_ip);
    fix_ip_checksum(ip);

    /* Pass only ETH+IP — total 34 bytes, missing the 8 transport bytes
     * required by wolfIP_send_ttl_exceeded */
    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Short frame: TTL-exceeded must NOT have been sent */
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

/* =========================================================================
 * ip_recv: dest matches own IP on secondary interface → is_local=1, no fwd
 * =========================================================================
 * Branch: conf->ip == dest (in the loop) → is_local = 1
 */
START_TEST(test_ip_recv_dest_matches_secondary_iface_ip_is_local)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 remote_src   = 0x0A000002U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = secondary_ip;  /* listening on secondary IP */

    /* Inject on primary iface, dst=secondary IP → local, not forwarded */
    inject_udp_datagram(&s, TEST_PRIMARY_IF, remote_src, secondary_ip,
                        9999, 1234, NULL, 0);

    /* Must be delivered locally */
    ck_assert_int_ne(ts->events & CB_EVENT_READABLE, 0);
}
END_TEST

/* =========================================================================
 * ip_recv: multicast destination (not broadcast, not own IP) — no forwarding
 * =========================================================================
 * Branch (under WOLFIP_ENABLE_FORWARDING): dest is multicast → not in is_local
 * loop, not broadcast, forwarding check runs but forward_interface returns -1.
 * Packet is not forwarded; without IP_MULTICAST it is also not delivered.
 */
START_TEST(test_ip_recv_multicast_dst_not_forwarded)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 primary_ip   = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 mcast_dst    = 0xE0000001U;  /* 224.0.0.1 — not joined */
    ip4 src_ip       = 0x0A000002U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x45;
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    ip->src      = ee32(src_ip);
    ip->dst      = ee32(mcast_dst);
    fix_ip_checksum(ip);
    {
        uint16_t *udp = (uint16_t *)(frame + ETH_HEADER_LEN + IP_HEADER_LEN);
        udp[0] = ee16(9999); udp[1] = ee16(1234);
        udp[2] = ee16(UDP_HEADER_LEN); udp[3] = 0;
    }

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Multicast not joined and not a broadcast subnet; nothing forwarded */
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

/* =========================================================================
 * arp_recv: htype != 1 — ARP packet silently dropped
 * =========================================================================
 * Branch: arp->htype != ee16(1) → return (at the compound validation check)
 */
START_TEST(test_arp_recv_htype_not_ethernet_dropped)
{
    struct wolfIP s;
    struct arp_packet arp;
    struct wolfIP_ll_dev *ll;
    struct ipconf *conf;
    ip4 sender_ip = 0x0A000099U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ll   = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    conf = wolfIP_ipconf_at(&s, TEST_PRIMARY_IF);

    build_valid_arp_request(&arp, ll, conf->ip, sender_ip);
    /* Corrupt htype: 6 = IEEE 802 hardware type (not Ethernet) */
    arp.htype = ee16(6);

    last_frame_sent_size = 0;
    arp_recv(&s, TEST_PRIMARY_IF, &arp, sizeof(arp));

    /* No reply, no neighbor cached */
    ck_assert_uint_eq(last_frame_sent_size, 0);
    ck_assert_int_lt(arp_neighbor_index(&s, TEST_PRIMARY_IF, sender_ip), 0);
}
END_TEST

/* =========================================================================
 * arp_recv: ptype != 0x0800 — not IPv4, dropped
 * =========================================================================
 * Branch: arp->ptype != ee16(0x0800) → return
 */
START_TEST(test_arp_recv_ptype_not_ipv4_dropped)
{
    struct wolfIP s;
    struct arp_packet arp;
    struct wolfIP_ll_dev *ll;
    struct ipconf *conf;
    ip4 sender_ip = 0x0A000098U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ll   = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    conf = wolfIP_ipconf_at(&s, TEST_PRIMARY_IF);

    build_valid_arp_request(&arp, ll, conf->ip, sender_ip);
    /* ptype = 0x0806 = ARP protocol type (wrong, we want IPv4 = 0x0800) */
    arp.ptype = ee16(0x86DD);  /* IPv6 — not accepted */

    last_frame_sent_size = 0;
    arp_recv(&s, TEST_PRIMARY_IF, &arp, sizeof(arp));

    ck_assert_uint_eq(last_frame_sent_size, 0);
    ck_assert_int_lt(arp_neighbor_index(&s, TEST_PRIMARY_IF, sender_ip), 0);
}
END_TEST

/* =========================================================================
 * arp_recv: hlen != 6 — hardware address length mismatch, dropped
 * =========================================================================
 * Branch: arp->hlen != 6 → return
 */
START_TEST(test_arp_recv_hlen_not_6_dropped)
{
    struct wolfIP s;
    struct arp_packet arp;
    struct wolfIP_ll_dev *ll;
    struct ipconf *conf;
    ip4 sender_ip = 0x0A000097U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ll   = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    conf = wolfIP_ipconf_at(&s, TEST_PRIMARY_IF);

    build_valid_arp_request(&arp, ll, conf->ip, sender_ip);
    arp.hlen = 8;  /* 8 bytes — not standard Ethernet (6) */

    last_frame_sent_size = 0;
    arp_recv(&s, TEST_PRIMARY_IF, &arp, sizeof(arp));

    ck_assert_uint_eq(last_frame_sent_size, 0);
    ck_assert_int_lt(arp_neighbor_index(&s, TEST_PRIMARY_IF, sender_ip), 0);
}
END_TEST

/* =========================================================================
 * arp_recv: plen != 4 — protocol address length mismatch, dropped
 * =========================================================================
 * Branch: arp->plen != 4 → return
 */
START_TEST(test_arp_recv_plen_not_4_dropped)
{
    struct wolfIP s;
    struct arp_packet arp;
    struct wolfIP_ll_dev *ll;
    struct ipconf *conf;
    ip4 sender_ip = 0x0A000096U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ll   = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    conf = wolfIP_ipconf_at(&s, TEST_PRIMARY_IF);

    build_valid_arp_request(&arp, ll, conf->ip, sender_ip);
    arp.plen = 6;  /* 6 bytes — not standard IPv4 (4) */

    last_frame_sent_size = 0;
    arp_recv(&s, TEST_PRIMARY_IF, &arp, sizeof(arp));

    ck_assert_uint_eq(last_frame_sent_size, 0);
    ck_assert_int_lt(arp_neighbor_index(&s, TEST_PRIMARY_IF, sender_ip), 0);
}
END_TEST

/* =========================================================================
 * arp_recv: sender IP == our configured IP — rejected (own-address poisoning)
 * =========================================================================
 * Branch: sip == conf->ip → skip cache update (in ARP REQUEST handler)
 * Without this check an attacker can poison our own ARP entry.
 */
START_TEST(test_arp_recv_sender_own_ip_rejected)
{
    struct wolfIP s;
    struct arp_packet arp;
    struct wolfIP_ll_dev *ll;
    struct ipconf *conf;
    ip4 own_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, own_ip, 0xFFFFFF00U, 0);

    ll   = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    conf = wolfIP_ipconf_at(&s, TEST_PRIMARY_IF);

    /* ARP request targeting our IP, but sender claims to also own our IP */
    build_valid_arp_request(&arp, ll, conf->ip, own_ip);

    arp_recv(&s, TEST_PRIMARY_IF, &arp, sizeof(arp));

    /* Our own IP must never be cached as a neighbor */
    ck_assert_int_lt(arp_neighbor_index(&s, TEST_PRIMARY_IF, own_ip), 0);
}
END_TEST

/* =========================================================================
 * arp_recv: sender IP == IPADDR_ANY (0.0.0.0) — rejected (probe-like)
 * =========================================================================
 * Branch: sip == IPADDR_ANY → skip cache update in REQUEST handler
 * ARP probes (RFC 5227) use 0.0.0.0 as sender and must not be cached.
 */
START_TEST(test_arp_recv_sender_ipaddr_any_rejected)
{
    struct wolfIP s;
    struct arp_packet arp;
    struct wolfIP_ll_dev *ll;
    struct ipconf *conf;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ll   = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    conf = wolfIP_ipconf_at(&s, TEST_PRIMARY_IF);

    build_valid_arp_request(&arp, ll, conf->ip, IPADDR_ANY);

    arp_recv(&s, TEST_PRIMARY_IF, &arp, sizeof(arp));

    /* 0.0.0.0 must not appear in the neighbor cache */
    ck_assert_int_lt(arp_neighbor_index(&s, TEST_PRIMARY_IF, IPADDR_ANY), 0);
}
END_TEST

/* =========================================================================
 * arp_recv: sender IP == limited broadcast (255.255.255.255) — rejected
 * =========================================================================
 * Branch: wolfIP_ip_is_broadcast(s, sip) → skip cache update
 * Checked in ARP REPLY path (sender is broadcast → return early).
 */
START_TEST(test_arp_recv_reply_sender_broadcast_rejected)
{
    struct wolfIP s;
    struct arp_packet arp;
    struct wolfIP_ll_dev *ll;
    static const uint8_t bcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);

    memset(&arp, 0, sizeof(arp));
    memcpy(arp.eth.dst, ll->mac, 6);
    memcpy(arp.eth.src, bcast_mac, 6);
    arp.eth.type = ee16(ETH_TYPE_ARP);
    arp.htype    = ee16(1);
    arp.ptype    = ee16(0x0800);
    arp.hlen     = 6;
    arp.plen     = 4;
    arp.opcode   = ee16(ARP_REPLY);
    memcpy(arp.sma, bcast_mac, 6);
    arp.sip      = ee32(0xFFFFFFFFU);  /* broadcast sender IP in REPLY */
    memset(arp.tma, 0, 6);
    arp.tip      = ee32(0x0A000001U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp, sizeof(arp));

    /* 255.255.255.255 must not be cached */
    ck_assert_int_lt(arp_neighbor_index(&s, TEST_PRIMARY_IF, 0xFFFFFFFFU), 0);
}
END_TEST

/* =========================================================================
 * arp_recv: sender IP == multicast address — rejected in ARP REPLY
 * =========================================================================
 * Branch: wolfIP_ip_is_multicast(sip) → return in REPLY handler
 */
START_TEST(test_arp_recv_reply_sender_multicast_rejected)
{
    struct wolfIP s;
    struct arp_packet arp;
    struct wolfIP_ll_dev *ll;
    ip4 mcast_ip = 0xE0000001U;  /* 224.0.0.1 */
    static const uint8_t mcast_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);

    memset(&arp, 0, sizeof(arp));
    memcpy(arp.eth.dst, ll->mac, 6);
    memcpy(arp.eth.src, mcast_mac, 6);
    arp.eth.type = ee16(ETH_TYPE_ARP);
    arp.htype    = ee16(1);
    arp.ptype    = ee16(0x0800);
    arp.hlen     = 6;
    arp.plen     = 4;
    arp.opcode   = ee16(ARP_REPLY);
    memcpy(arp.sma, mcast_mac, 6);
    arp.sip      = ee32(mcast_ip);
    memset(arp.tma, 0, 6);
    arp.tip      = ee32(0x0A000001U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp, sizeof(arp));

    /* Multicast source IP in a reply must not be cached */
    ck_assert_int_lt(arp_neighbor_index(&s, TEST_PRIMARY_IF, mcast_ip), 0);
}
END_TEST

/* =========================================================================
 * arp_recv: sender IP == own IP in ARP REPLY — rejected (Gratuitous ARP
 * from attacker claiming they own our IP via REPLY).
 * =========================================================================
 * Branch: sip == conf->ip → return in REPLY handler
 */
START_TEST(test_arp_recv_reply_sender_own_ip_rejected)
{
    struct wolfIP s;
    struct arp_packet arp;
    struct wolfIP_ll_dev *ll;
    ip4 own_ip = 0x0A000001U;
    static const uint8_t attacker_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, own_ip, 0xFFFFFF00U, 0);

    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);

    memset(&arp, 0, sizeof(arp));
    memcpy(arp.eth.dst, ll->mac, 6);
    memcpy(arp.eth.src, attacker_mac, 6);
    arp.eth.type = ee16(ETH_TYPE_ARP);
    arp.htype    = ee16(1);
    arp.ptype    = ee16(0x0800);
    arp.hlen     = 6;
    arp.plen     = 4;
    arp.opcode   = ee16(ARP_REPLY);
    memcpy(arp.sma, attacker_mac, 6);
    arp.sip      = ee32(own_ip);  /* attacker claims to own our IP */
    memset(arp.tma, 0, 6);
    arp.tip      = ee32(own_ip);

    arp_recv(&s, TEST_PRIMARY_IF, &arp, sizeof(arp));

    /* Own IP must not appear as a neighbor in the cache */
    ck_assert_int_lt(arp_neighbor_index(&s, TEST_PRIMARY_IF, own_ip), 0);
}
END_TEST

/* =========================================================================
 * arp_recv: reply with IPADDR_ANY sender — rejected
 * =========================================================================
 * Branch: sip == IPADDR_ANY → return in REPLY handler
 */
START_TEST(test_arp_recv_reply_sender_zero_ip_rejected)
{
    struct wolfIP s;
    struct arp_packet arp;
    struct wolfIP_ll_dev *ll;
    static const uint8_t sender_mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);

    memset(&arp, 0, sizeof(arp));
    memcpy(arp.eth.dst, ll->mac, 6);
    memcpy(arp.eth.src, sender_mac, 6);
    arp.eth.type = ee16(ETH_TYPE_ARP);
    arp.htype    = ee16(1);
    arp.ptype    = ee16(0x0800);
    arp.hlen     = 6;
    arp.plen     = 4;
    arp.opcode   = ee16(ARP_REPLY);
    memcpy(arp.sma, sender_mac, 6);
    arp.sip      = ee32(IPADDR_ANY);  /* 0.0.0.0 sender in reply */
    memset(arp.tma, 0, 6);
    arp.tip      = ee32(0x0A000001U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp, sizeof(arp));

    /* 0.0.0.0 must not be cached */
    ck_assert_int_lt(arp_neighbor_index(&s, TEST_PRIMARY_IF, IPADDR_ANY), 0);
}
END_TEST

/* =========================================================================
 * arp_recv: valid ARP request IS cached when sender IP is legitimate
 * =========================================================================
 * Positive test: confirms the happy path around the sender validation
 * runs (sip valid → arp_store_neighbor called when pending match exists).
 * We use arp_pending_record directly to bypass the arp_request rate-limit.
 */
START_TEST(test_arp_recv_valid_request_caches_neighbor_when_pending)
{
    struct wolfIP s;
    struct arp_packet arp;
    struct wolfIP_ll_dev *ll;
    struct ipconf *conf;
    ip4 sender_ip = 0x0A000020U;
    static const uint8_t sender_mac[6] = {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    s.last_tick = 5000;  /* advance tick so arp_request rate-limit does not fire */

    ll   = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    conf = wolfIP_ipconf_at(&s, TEST_PRIMARY_IF);

    /* Pre-register a pending ARP request so learn path is triggered.
     * arp_pending_record is the low-level helper; we use it directly. */
    arp_pending_record(&s, TEST_PRIMARY_IF, sender_ip);

    build_valid_arp_request(&arp, ll, conf->ip, sender_ip);
    memcpy(arp.sma, sender_mac, 6);

    last_frame_sent_size = 0;
    arp_recv(&s, TEST_PRIMARY_IF, &arp, sizeof(arp));

    /* A reply should have been sent */
    ck_assert_uint_gt(last_frame_sent_size, 0);
    /* Neighbor must now be in the cache */
    ck_assert_int_ge(arp_neighbor_index(&s, TEST_PRIMARY_IF, sender_ip), 0);
}
END_TEST

/* =========================================================================
 * arp_recv: runt packet (too short) — dropped
 * =========================================================================
 * Branch: len < sizeof(struct arp_packet) → return
 */
START_TEST(test_arp_recv_runt_packet_dropped)
{
    struct wolfIP s;
    struct arp_packet arp;
    struct wolfIP_ll_dev *ll;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);

    memset(&arp, 0, sizeof(arp));
    memcpy(arp.eth.dst, ll->mac, 6);

    last_frame_sent_size = 0;
    /* Pass only 10 bytes — much less than sizeof(arp_packet) */
    arp_recv(&s, TEST_PRIMARY_IF, &arp, 10);

    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

/* =========================================================================
 * ip_recv: IP version != 4 — dropped
 * =========================================================================
 * Branch: version != 4 → return
 */
START_TEST(test_ip_recv_wrong_version_dropped_v6)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x65;   /* version=6 (IPv6!), IHL=5 */
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    ip->src      = ee32(remote_ip);
    ip->dst      = ee32(local_ip);
    ip->csum     = 0;
    /* do NOT fix checksum — we want version check to fire first */

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    /* Version != 4 must be dropped */
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

/* =========================================================================
 * ip_recv: IP header length < 20 — dropped
 * =========================================================================
 * Branch: ip_hlen < IP_HEADER_LEN (i.e. IHL < 5) → return
 */
START_TEST(test_ip_recv_ihl_too_small_dropped)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x44;   /* version=4, IHL=4 → 16 bytes < 20 */
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(IP_HEADER_LEN);
    ip->src      = ee32(remote_ip);
    ip->dst      = ee32(local_ip);
    ip->csum     = 0;

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

/* =========================================================================
 * ip_recv: ip->len < ip_hlen — dropped (ip length shorter than header)
 * =========================================================================
 * Branch: ee16(ip->len) < ip_hlen → return
 */
START_TEST(test_ip_recv_ip_len_less_than_hlen_dropped)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(frame, 0, sizeof(frame));
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl  = 0x45;  /* IHL=5, header=20 */
    ip->ttl      = 64;
    ip->proto    = WI_IPPROTO_UDP;
    ip->len      = ee16(10);  /* ip->len=10 < ip_hlen=20 → drop */
    ip->src      = ee32(remote_ip);
    ip->dst      = ee32(local_ip);
    ip->csum     = 0;
    iphdr_set_checksum(ip);

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

/* =========================================================================
 * ip_recv: bad IP checksum — dropped
 * =========================================================================
 * Branch: iphdr_verify_checksum(ip) != 0 → return
 */
START_TEST(test_ip_recv_bad_ip_checksum_dropped)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    {
        uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN];
        struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;

        memset(frame, 0, sizeof(frame));
        memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
        memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
        ip->eth.type = ee16(ETH_TYPE_IP);
        ip->ver_ihl  = 0x45;
        ip->ttl      = 64;
        ip->proto    = WI_IPPROTO_UDP;
        ip->len      = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
        ip->src      = ee32(remote_ip);
        ip->dst      = ee32(local_ip);
        ip->csum     = ee16(0xDEAD);  /* deliberately wrong */

        ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));
    }

    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

#ifdef IP_MULTICAST
/* =========================================================================
 * ip_recv (MULTICAST): dst is multicast not joined on ingress iface — dropped
 * =========================================================================
 * Branch (wolfIP_recv_on): !mcast_is_joined && dst != IGMPV3_REPORT_DST &&
 *                           dst != IGMP_ALL_HOSTS → return (not for us)
 * This covers the multicast Ethernet demux gate in wolfIP_recv_on.
 */
START_TEST(test_ip_recv_multicast_not_joined_dropped)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)frame;
    ip4 local_ip   = 0x0A000001U;
    ip4 src_ip     = 0x0A000002U;
    ip4 mcast_grp  = 0xEF010203U;  /* 239.1.2.3 — not joined */
    uint8_t mcast_eth[6];

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    /* No IGMP join for mcast_grp */

    /* Build Ethernet frame with multicast dst MAC */
    mcast_ip_to_eth(mcast_grp, mcast_eth);
    memset(frame, 0, sizeof(frame));
    memcpy(udp->ip.eth.dst, mcast_eth, 6);
    memcpy(udp->ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    udp->ip.eth.type = ee16(ETH_TYPE_IP);
    udp->ip.ver_ihl  = 0x45;
    udp->ip.ttl      = 64;
    udp->ip.proto    = WI_IPPROTO_UDP;
    udp->ip.len      = ee16(IP_HEADER_LEN + UDP_HEADER_LEN + 4);
    udp->ip.src      = ee32(src_ip);
    udp->ip.dst      = ee32(mcast_grp);
    udp->src_port    = ee16(9999);
    udp->dst_port    = ee16(1234);
    udp->len         = ee16(UDP_HEADER_LEN + 4);
    memcpy(udp->data, "test", 4);
    fix_udp_checksums(udp);

    last_frame_sent_size = 0;
    wolfIP_recv_on(&s, TEST_PRIMARY_IF, frame, (uint32_t)sizeof(frame));

    /* Not joined → must be silently dropped at ETH demux */
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST
#endif /* IP_MULTICAST */

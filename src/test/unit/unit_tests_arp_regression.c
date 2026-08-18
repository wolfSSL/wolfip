/* unit_tests_arp_regression.c
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
/* =========================================================================
 * ARP neighbor-table regression fixtures
 *
 * Derived from the wire-level PoCs of security-scan candidate
 * candidate-3d6f7442d4b3ac81 (F-9805: unsolicited ARP reply pre-poison),
 * inverted to assert the fixed behavior: a neighbor entry is installed or
 * updated only in answer to a request the stack itself sent (a pending
 * match in arp_recv). Unsolicited frames never touch the table.
 * ========================================================================= */

/* Attacker-chosen L2 address (unicast, group bit 0). */
static const uint8_t arp_regr_att_mac[6] = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
/* "Real owner" L2 address for the victim IP. */
static const uint8_t arp_regr_own_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x50};

/* Find neighbor table index for (if_idx, ip); -1 if absent. */
static int arp_regr_neighbor_find(struct wolfIP *s, unsigned int if_idx, ip4 ip)
{
    int i;
    for (i = 0; i < MAX_NEIGHBORS; i++) {
        if (s->arp.neighbors[i].ip == ip &&
                s->arp.neighbors[i].if_idx == (uint8_t)if_idx)
            return i;
    }
    return -1;
}

static int arp_regr_pending_empty(struct wolfIP *s)
{
    int i;
    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++)
        if (s->arp.pending[i].ip != IPADDR_ANY)
            return 0;
    return 1;
}

/* Standard single-interface setup, 10.0.0.1/24 on the primary link. */
static void arp_regr_setup(struct wolfIP *s)
{
    wolfIP_init(s);
    mock_link_init(s);
    wolfIP_ipconfig_set(s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
    wolfIP_filter_set_tcp_mask(0);
}

/* Build a complete wire frame: Ethernet + ARP REPLY, with attacker-chosen
 * sender IP/MAC and a chosen target IP. Returns frame length. */
static uint32_t arp_regr_build_reply_frame(uint8_t *frame, const uint8_t *dst_mac,
        const uint8_t *src_mac, ip4 sender_ip, const uint8_t *sender_mac,
        ip4 target_ip)
{
    struct arp_packet *arp = (struct arp_packet *)frame;

    memset(frame, 0, sizeof(struct arp_packet));
    memcpy(arp->eth.dst, dst_mac, 6);
    memcpy(arp->eth.src, src_mac, 6);
    arp->eth.type = ee16(ETH_TYPE_ARP);
    arp->htype  = ee16(1);
    arp->ptype  = ee16(0x0800);
    arp->hlen   = 6;
    arp->plen   = 4;
    arp->opcode = ee16(ARP_REPLY);
    memcpy(arp->sma, sender_mac, 6);
    arp->sip = ee32(sender_ip);
    memcpy(arp->tma, dst_mac, 6);
    arp->tip = ee32(target_ip);
    return sizeof(struct arp_packet);
}

/* =========================================================================
 * Regression (F-9805): unsolicited ARP reply with no prior request and no
 * existing entry must NOT install a neighbor entry. (PoC 2a, inverted.)
 * ========================================================================= */
START_TEST(test_regression_unsolicited_reply_first_install_dropped)
{
    struct wolfIP s;
    uint8_t frame[sizeof(struct arp_packet)];
    struct wolfIP_ll_dev *ll;
    ip4 victim_ip = 0xC0A84D09U; /* 192.168.77.9 — arbitrary unicast */
    uint32_t len;

    arp_regr_setup(&s);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    /* Precondition: empty neighbor table AND no outstanding ARP request —
     * the stack never asked for this IP. */
    ck_assert_int_eq(arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, victim_ip), -1);
    ck_assert_int_eq(arp_regr_pending_empty(&s), 1);

    /* Attacker broadcasts an unsolicited ARP REPLY claiming victim_ip. */
    len = arp_regr_build_reply_frame(frame, ll->mac, arp_regr_att_mac,
                                     victim_ip, arp_regr_att_mac, 0x0A000001U);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);

    /* FIXED BEHAVIOR: no install without a request we sent. */
    ck_assert_int_eq(arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, victim_ip), -1);
}
END_TEST

/* =========================================================================
 * Regression (F-9805): gratuitous-form reply (tip = 0) is dropped too —
 * no pending request, no install. (PoC 2b, inverted.)
 * ========================================================================= */
START_TEST(test_regression_gratuitous_reply_zero_tip_dropped)
{
    struct wolfIP s;
    uint8_t frame[sizeof(struct arp_packet)];
    struct wolfIP_ll_dev *ll;
    ip4 victim_ip = 0xC0A84D0AU; /* 192.168.77.10 */
    uint32_t len;

    arp_regr_setup(&s);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    ck_assert_int_eq(arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, victim_ip), -1);

    len = arp_regr_build_reply_frame(frame, ll->mac, arp_regr_att_mac,
                                     victim_ip, arp_regr_att_mac, 0x00000000U);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);

    ck_assert_int_eq(arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, victim_ip), -1);
}
END_TEST

/* =========================================================================
 * Regression (F-9805): unsolicited reply must not pre-poison the gateway
 * TX path — resolution of the gateway IP finds no entry. (PoC 2c, inverted.)
 * ========================================================================= */
START_TEST(test_regression_unsolicited_reply_gateway_not_poisoned)
{
    struct wolfIP s;
    uint8_t frame[sizeof(struct arp_packet)];
    struct wolfIP_ll_dev *ll;
    ip4 gw_ip = 0x0A00000AU; /* 10.0.0.10 — default gateway on the /24 */
    uint8_t mac[6];
    uint32_t len;

    arp_regr_setup(&s);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    ck_assert_int_eq(arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, gw_ip), -1);
    ck_assert_int_eq(arp_regr_pending_empty(&s), 1);

    len = arp_regr_build_reply_frame(frame, ll->mac, arp_regr_att_mac,
                                     gw_ip, arp_regr_att_mac, 0x0A000001U);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);

    /* No entry: routed sends must ARP for the gateway, not follow the
     * attacker's MAC. */
    memset(mac, 0, sizeof(mac));
    ck_assert_int_eq(wolfIP_arp_lookup_ex(&s, TEST_PRIMARY_IF, gw_ip, mac), -1);
}
END_TEST

/* =========================================================================
 * Regression (F-9805): the only correction path for a wrong entry is a
 * reply to a request we ourselves sent — an unsolicited owner reply
 * installs nothing, and the solicited exchange that follows installs the
 * owner's MAC. (PoC 2d, restructured for the fixed policy.)
 * ========================================================================= */
START_TEST(test_regression_owner_correction_requires_our_request)
{
    struct wolfIP s;
    uint8_t frame[sizeof(struct arp_packet)];
    struct wolfIP_ll_dev *ll;
    ip4 victim_ip = 0xC0A84D09U; /* 192.168.77.9 */
    uint32_t len;
    int idx;

    arp_regr_setup(&s);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    /* Attacker's unsolicited reply: nothing installed. */
    len = arp_regr_build_reply_frame(frame, ll->mac, arp_regr_att_mac,
                                     victim_ip, arp_regr_att_mac, 0x0A000001U);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);
    ck_assert_int_eq(arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, victim_ip), -1);

    /* True owner's unsolicited reply: still nothing installed. */
    len = arp_regr_build_reply_frame(frame, ll->mac, arp_regr_own_mac,
                                     victim_ip, arp_regr_own_mac, 0x0A000001U);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);
    ck_assert_int_eq(arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, victim_ip), -1);

    /* We request the IP (pending recorded, bypassing the rate limit) and
     * the owner answers: the solicited reply installs the owner's MAC. */
    s.last_tick = 1000;
    arp_pending_record(&s, TEST_PRIMARY_IF, victim_ip);
    len = arp_regr_build_reply_frame(frame, ll->mac, arp_regr_own_mac,
                                     victim_ip, arp_regr_own_mac, 0x0A000001U);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);

    idx = arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, victim_ip);
    ck_assert_int_gt(idx, -1);
    ck_assert_mem_eq(s.arp.neighbors[idx].mac, arp_regr_own_mac, 6);
}
END_TEST

/* =========================================================================
 * SYN-driven learning regression fixtures
 *
 * Derived from the wire-level PoCs of security-scan candidate
 * candidate-3b4b443e774d63e8 (F-6035: unauthenticated neighbor learning
 * from a TCP SYN's source / F-6036: gateway nexthop variant / F-9804 dup),
 * inverted to assert the fixed behavior: a SYN installs nothing. The
 * stack resolves the peer through the normal ARP exchange (request
 * we sent, reply to it) when it transmits.
 * ========================================================================= */

/* Build a complete wire frame: Ethernet + IPv4 + TCP SYN, with valid IP
 * and TCP checksums. Returns total frame length. */
static uint32_t arp_regr_build_syn_frame(uint8_t *frame, const uint8_t *dst_mac,
        const uint8_t *src_mac, ip4 src_ip, ip4 dst_ip, uint16_t dst_port)
{
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)frame;
    union transport_pseudo_header ph;

    memset(frame, 0, ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN);
    memcpy(tcp->ip.eth.dst, dst_mac, 6);
    memcpy(tcp->ip.eth.src, src_mac, 6);
    tcp->ip.eth.type = ee16(ETH_TYPE_IP);
    tcp->ip.ver_ihl = 0x45;
    tcp->ip.ttl = 64;
    tcp->ip.proto = WI_IPPROTO_TCP;
    tcp->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    tcp->ip.src = ee32(src_ip);
    tcp->ip.dst = ee32(dst_ip);
    tcp->ip.csum = 0;
    iphdr_set_checksum(&tcp->ip);

    tcp->src_port = ee16(40000);
    tcp->dst_port = ee16(dst_port);
    tcp->seq = ee32(1);
    tcp->ack = 0;
    tcp->hlen = TCP_HEADER_LEN << 2; /* data offset 5, wire byte 0x50 */
    tcp->flags = TCP_FLAG_SYN;
    tcp->win = ee16(65535);
    tcp->urg = 0;
    tcp->csum = 0;

    memset(&ph, 0, sizeof(ph));
    ph.ph.src = tcp->ip.src;
    ph.ph.dst = tcp->ip.dst;
    ph.ph.proto = WI_IPPROTO_TCP;
    ph.ph.len = ee16(TCP_HEADER_LEN);
    tcp->csum = ee16(transport_checksum(&ph, &tcp->src_port));

    return ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN;
}

/* Single-interface setup with a TCP listener on 10.0.0.1:1234.
 * Returns the listener socket descriptor; ts points at its tsocket. */
static int arp_regr_setup_listener(struct wolfIP *s, struct tsocket **ts)
{
    int listen_sd;
    struct wolfIP_sockaddr_in sin;

    arp_regr_setup(s);

    listen_sd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(s, listen_sd,
        (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(s, listen_sd, 1), 0);
    *ts = &s->tcpsockets[SOCKET_UNMARK(listen_sd)];
    return listen_sd;
}

/* =========================================================================
 * Regression (F-6035): a forged SYN from a directly-connected source IP
 * is accepted but installs no neighbor entry. (PoC 1a, inverted.)
 * ========================================================================= */
START_TEST(test_regression_syn_source_does_not_install_neighbor)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN];
    struct wolfIP_ll_dev *ll;
    ip4 victim_ip = 0x0A000050U; /* 10.0.0.80, on the /24 */
    uint32_t len;
    int i;

    (void)arp_regr_setup_listener(&s, &ts);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    /* Precondition: neighbor table and pending-ARP table are empty —
     * no prior ARP exchange of any kind. */
    ck_assert_int_eq(arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, victim_ip), -1);
    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++)
        ck_assert_uint_eq(s.arp.pending[i].ip, IPADDR_ANY);

    /* Attacker sends one forged SYN: src IP = victim IP, src MAC =
     * attacker MAC, dst = our listener. Valid checksums. */
    len = arp_regr_build_syn_frame(frame, ll->mac, arp_regr_att_mac,
                                   victim_ip, 0x0A000001U, 1234);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);

    /* The SYN was accepted (no handshake completion required) ... */
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);

    /* ... but the unauthenticated source did not learn anything. */
    ck_assert_int_eq(arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, victim_ip), -1);
}
END_TEST

/* =========================================================================
 * Regression (F-6036): a forged SYN from an off-subnet source must not
 * poison the GATEWAY entry (the old code stored the route's nexthop,
 * not the source). (PoC 1b, inverted.)
 * ========================================================================= */
START_TEST(test_regression_syn_source_does_not_poison_gateway)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN];
    struct wolfIP_ll_dev *ll;
    ip4 gw_ip = 0x0A00000AU;      /* 10.0.0.10, default gateway */
    ip4 remote_ip = 0xC0A80909U;  /* 192.168.9.9, off-subnet */
    uint32_t len;

    (void)arp_regr_setup_listener(&s, &ts);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);
    ck_assert_int_eq(wolfIP_route_add(&s, TEST_PRIMARY_IF, 0, 0, gw_ip), 0);

    ck_assert_int_eq(arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, gw_ip), -1);

    /* One forged SYN from an off-subnet source with the attacker's MAC. */
    len = arp_regr_build_syn_frame(frame, ll->mac, arp_regr_att_mac,
                                   remote_ip, 0x0A000001U, 1234);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);

    /* The gateway entry stays absent: routed traffic must ARP for it. */
    ck_assert_int_eq(arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, gw_ip), -1);
}
END_TEST

/* =========================================================================
 * Regression (F-6035): downstream effect — after a forged SYN, TX
 * resolution of the claimed IP finds no entry. (PoC 1c, inverted.)
 * ========================================================================= */
START_TEST(test_regression_syn_source_not_resolved_for_tx)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN];
    struct wolfIP_ll_dev *ll;
    ip4 victim_ip = 0x0A000050U;
    uint8_t mac[6];
    uint32_t len;

    (void)arp_regr_setup_listener(&s, &ts);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    len = arp_regr_build_syn_frame(frame, ll->mac, arp_regr_att_mac,
                                   victim_ip, 0x0A000001U, 1234);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);

    /* No entry: unicast sends to 10.0.0.80 must ARP, not follow the
     * attacker's MAC. */
    memset(mac, 0, sizeof(mac));
    ck_assert_int_eq(wolfIP_arp_lookup_ex(&s, TEST_PRIMARY_IF, victim_ip, mac), -1);
}
END_TEST

/* =========================================================================
 * Regression (F-6035): the only way the owner's MAC gets in is the normal
 * ARP exchange — a forged SYN and an unsolicited owner reply both install
 * nothing; the solicited exchange that follows installs the owner's MAC.
 * (PoC 1d, restructured for the fixed policy.)
 * ========================================================================= */
START_TEST(test_regression_syn_learned_only_via_arp_exchange)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN];
    struct arp_packet arp;
    struct wolfIP_ll_dev *ll;
    ip4 victim_ip = 0x0A000050U;
    uint32_t len;
    int idx;

    (void)arp_regr_setup_listener(&s, &ts);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    s.last_tick = 1000;

    /* Forged SYN: nothing installed. */
    len = arp_regr_build_syn_frame(frame, ll->mac, arp_regr_att_mac,
                                   victim_ip, 0x0A000001U, 1234);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);
    ck_assert_int_eq(arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, victim_ip), -1);

    /* True owner's unsolicited reply: still nothing installed. */
    memset(&arp, 0, sizeof(arp));
    memcpy(arp.eth.dst, ll->mac, 6);
    memcpy(arp.eth.src, arp_regr_own_mac, 6);
    arp.eth.type = ee16(ETH_TYPE_ARP);
    arp.htype  = ee16(1);
    arp.ptype  = ee16(0x0800);
    arp.hlen   = 6;
    arp.plen   = 4;
    arp.opcode = ee16(ARP_REPLY);
    memcpy(arp.sma, arp_regr_own_mac, 6);
    arp.sip = ee32(victim_ip);
    arp.tip = ee32(0); /* gratuitous form */
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, &arp, sizeof(arp));
    ck_assert_int_eq(arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, victim_ip), -1);

    /* The solicited exchange installs the owner's MAC. */
    arp_pending_record(&s, TEST_PRIMARY_IF, victim_ip);
    memset(&arp, 0, sizeof(arp));
    memcpy(arp.eth.dst, ll->mac, 6);
    memcpy(arp.eth.src, arp_regr_own_mac, 6);
    arp.eth.type = ee16(ETH_TYPE_ARP);
    arp.htype  = ee16(1);
    arp.ptype  = ee16(0x0800);
    arp.hlen   = 6;
    arp.plen   = 4;
    arp.opcode = ee16(ARP_REPLY);
    memcpy(arp.sma, arp_regr_own_mac, 6);
    arp.sip = ee32(victim_ip);
    arp.tip = ee32(0x0A000001U);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, &arp, sizeof(arp));

    idx = arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, victim_ip);
    ck_assert_int_gt(idx, -1);
    ck_assert_mem_eq(s.arp.neighbors[idx].mac, arp_regr_own_mac, 6);
}
END_TEST

/* =========================================================================
 * Control (F-9805): an EXISTING entry is not overwritten by an unsolicited
 * reply — the behavior the pending-only gate preserves. (PoC 2e, kept.)
 * ========================================================================= */
START_TEST(test_regression_unsolicited_reply_overwrite_still_blocked)
{
    struct wolfIP s;
    uint8_t frame[sizeof(struct arp_packet)];
    struct wolfIP_ll_dev *ll;
    ip4 victim_ip = 0xC0A84D0BU; /* 192.168.77.11 */
    uint32_t len;
    int idx;

    arp_regr_setup(&s);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    /* Legitimate pre-existing entry (learned via a real reply to a request
     * we sent). */
    s.arp.neighbors[0].ip = victim_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, arp_regr_own_mac, 6);
    s.arp.neighbors[0].ts = s.last_tick;

    /* Attacker's unsolicited reply for the same IP. */
    len = arp_regr_build_reply_frame(frame, ll->mac, arp_regr_att_mac,
                                     victim_ip, arp_regr_att_mac, 0x0A000001U);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);

    /* Entry keeps the real MAC. */
    idx = arp_regr_neighbor_find(&s, TEST_PRIMARY_IF, victim_ip);
    ck_assert_int_gt(idx, -1);
    ck_assert_mem_eq(s.arp.neighbors[idx].mac, arp_regr_own_mac, 6);
}
END_TEST

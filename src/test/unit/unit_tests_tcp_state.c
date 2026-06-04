/* unit_tests_tcp_state.c
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
/* -----------------------------------------------------------------------
 * Helper: build and feed a TCP segment with options + optional payload.
 * ----------------------------------------------------------------------- */
static void inject_tcp_segment_with_opts(struct wolfIP *s, unsigned int if_idx,
        ip4 src_ip, ip4 dst_ip,
        uint16_t src_port, uint16_t dst_port,
        uint32_t seq, uint32_t ack_val, uint8_t flags,
        const uint8_t *opts, uint8_t opts_len,
        const uint8_t *payload, uint16_t payload_len)
{
    uint8_t buf[LINK_MTU];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    struct wolfIP_ll_dev *ll = wolfIP_getdev_ex(s, if_idx);
    union transport_pseudo_header ph;
    static const uint8_t src_mac[6] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35};
    uint8_t hdr_len_bytes;
    uint16_t total_tcp_len;
    uint16_t ip_len;
    uint32_t frame_len;
    uint8_t *opt_dst;

    ck_assert_ptr_nonnull(ll);
    hdr_len_bytes = (uint8_t)(TCP_HEADER_LEN + ((opts_len + 3) & ~3));
    total_tcp_len = (uint16_t)(hdr_len_bytes + payload_len);
    ip_len = (uint16_t)(IP_HEADER_LEN + total_tcp_len);
    frame_len = (uint32_t)(ETH_HEADER_LEN + ip_len);

    ck_assert_uint_le(frame_len, sizeof(buf));
    memset(buf, 0, frame_len);

    memcpy(seg->ip.eth.dst, ll->mac, 6);
    memcpy(seg->ip.eth.src, src_mac, 6);
    seg->ip.eth.type = ee16(ETH_TYPE_IP);
    seg->ip.ver_ihl = 0x45;
    seg->ip.ttl = 64;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.len = ee16(ip_len);
    seg->ip.src = ee32(src_ip);
    seg->ip.dst = ee32(dst_ip);
    iphdr_set_checksum(&seg->ip);

    seg->src_port = ee16(src_port);
    seg->dst_port = ee16(dst_port);
    seg->seq = ee32(seq);
    seg->ack = ee32(ack_val);
    seg->hlen = (uint8_t)((hdr_len_bytes >> 2) << 4);
    seg->flags = flags;
    seg->win = ee16(32768);
    seg->csum = 0;
    seg->urg = 0;

    opt_dst = (uint8_t *)buf + sizeof(struct wolfIP_tcp_seg);
    if (opts && opts_len > 0)
        memcpy(opt_dst, opts, opts_len);

    if (payload && payload_len > 0)
        memcpy(opt_dst + hdr_len_bytes - TCP_HEADER_LEN, payload, payload_len);

    memset(&ph, 0, sizeof(ph));
    ph.ph.src = seg->ip.src;
    ph.ph.dst = seg->ip.dst;
    ph.ph.proto = WI_IPPROTO_TCP;
    ph.ph.len = ee16(total_tcp_len);
    seg->csum = ee16(transport_checksum(&ph, &seg->src_port));

    tcp_input(s, if_idx, seg, frame_len);
}

/* ------------------------------------------------------------------
 * Helper: set up a connected ESTABLISHED socket in tcpsockets[0].
 * ------------------------------------------------------------------ */
static const uint8_t setup_peer_mac[6] = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77};

static struct tsocket *setup_established_socket(struct wolfIP *s,
        ip4 local_ip, ip4 remote_ip,
        uint16_t local_port, uint16_t remote_port)
{
    struct tsocket *ts = &s->tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack   = 100;
    ts->sock.tcp.seq   = 200;
    ts->sock.tcp.snd_una = 200;
    ts->sock.tcp.last    = 200;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    ts->sock.tcp.cwnd      = TCP_MSS * 4;
    ts->sock.tcp.ssthresh  = TCP_MSS * 8;
    ts->local_ip   = local_ip;
    ts->remote_ip  = remote_ip;
    ts->src_port   = local_port;
    ts->dst_port   = remote_port;
    ts->if_idx     = TEST_PRIMARY_IF;
    ts->sock.tcp.tmr_rto = NO_TIMER;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    /* Initialize rxbuf so queue_space() > 0 (needed for tcp_segment_acceptable) */
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    /* Pre-populate ARP so tcp_send_ack() can send a frame */
    arp_store_neighbor(s, TEST_PRIMARY_IF, remote_ip, (uint8_t *)setup_peer_mac);
    return ts;
}

/* ===================================================================
 * tcp_send_reset_reply — 8 missing branches
 * =================================================================== */

/* RST bit set in incoming segment: reset-reply is suppressed */
START_TEST(test_tcp_send_reset_reply_ignores_rst_input)
{
    struct wolfIP s;
    struct wolfIP_tcp_seg in;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    last_frame_sent_size = 0;

    memset(&in, 0, sizeof(in));
    in.ip.ver_ihl = 0x45;
    in.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    in.ip.src = ee32(0x0A000002U);
    in.ip.dst = ee32(0x0A000001U);
    in.ip.proto = WI_IPPROTO_TCP;
    in.hlen = TCP_HEADER_LEN << 2;
    /* RST flag set: the reply must be suppressed (RFC 793 §3.4) */
    in.flags = TCP_FLAG_RST;
    in.src_port = ee16(4000);
    in.dst_port = ee16(8080);
    iphdr_set_checksum(&in.ip);

    tcp_send_reset_reply(&s, TEST_PRIMARY_IF, &in);
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

/* Incoming has ACK: outgoing RST copies seq from in->ack, no ACK flag */
START_TEST(test_tcp_send_reset_reply_ack_in_uses_ack_seq)
{
    static const uint8_t peer_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    struct wolfIP s;
    struct wolfIP_tcp_seg in;
    struct wolfIP_tcp_seg *out;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    memset(&in, 0, sizeof(in));
    in.ip.ver_ihl = 0x45;
    in.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    in.ip.src = ee32(0x0A000002U);
    in.ip.dst = ee32(0x0A000001U);
    in.ip.proto = WI_IPPROTO_TCP;
    in.hlen = TCP_HEADER_LEN << 2;
    in.flags = TCP_FLAG_ACK;   /* ACK branch */
    in.ack   = ee32(0x12345678U);
    in.src_port = ee16(4000);
    in.dst_port = ee16(8080);
    memcpy(in.ip.eth.src, peer_mac, 6);
    iphdr_set_checksum(&in.ip);

    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A000002U, (uint8_t *)peer_mac);

    last_frame_sent_size = 0;
    tcp_send_reset_reply(&s, TEST_PRIMARY_IF, &in);

    ck_assert_uint_gt(last_frame_sent_size, 0U);
    out = (struct wolfIP_tcp_seg *)last_frame_sent;
    ck_assert_uint_eq(ee32(out->seq), 0x12345678U);
    ck_assert_uint_eq(out->flags & (TCP_FLAG_RST | TCP_FLAG_ACK), TCP_FLAG_RST);
}
END_TEST

/* No ACK in incoming SYN: reply carries RST|ACK with ack = seq+1 */
START_TEST(test_tcp_send_reset_reply_syn_no_ack_sets_rst_ack)
{
    static const uint8_t peer_mac2[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    struct wolfIP s;
    struct wolfIP_tcp_seg in;
    struct wolfIP_tcp_seg *out;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    memset(&in, 0, sizeof(in));
    in.ip.ver_ihl = 0x45;
    in.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    in.ip.src = ee32(0x0A000002U);
    in.ip.dst = ee32(0x0A000001U);
    in.ip.proto = WI_IPPROTO_TCP;
    in.hlen = TCP_HEADER_LEN << 2;
    in.flags = TCP_FLAG_SYN;   /* SYN, no ACK: reply must be RST|ACK */
    in.seq   = ee32(1000);
    in.src_port = ee16(5000);
    in.dst_port = ee16(8080);
    memcpy(in.ip.eth.src, peer_mac2, 6);
    iphdr_set_checksum(&in.ip);

    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A000002U, (uint8_t *)peer_mac2);

    last_frame_sent_size = 0;
    tcp_send_reset_reply(&s, TEST_PRIMARY_IF, &in);

    ck_assert_uint_gt(last_frame_sent_size, 0U);
    out = (struct wolfIP_tcp_seg *)last_frame_sent;
    /* ack = seq + 1 (SYN consumes one sequence number) */
    ck_assert_uint_eq(ee32(out->ack), 1001U);
    ck_assert_uint_eq(out->flags & (TCP_FLAG_RST | TCP_FLAG_ACK),
                      TCP_FLAG_RST | TCP_FLAG_ACK);
}
END_TEST

/* ===================================================================
 * tcp_parse_options — 8 missing branches
 * =================================================================== */

/* WS option with shift > 14 is clamped to 14 */
START_TEST(test_tcp_parse_options_ws_clamped_to_14)
{
    /* SYN with WS option shift = 15 (must be clamped to 14) */
    uint8_t opts[] = {
        TCP_OPTION_WS, 3, 15, /* kind=WS len=3 shift=15 */
        TCP_OPTION_EOO
    };
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LISTEN;
    ts->src_port = 8080;

    inject_tcp_segment_with_opts(&s, TEST_PRIMARY_IF,
        0x0A0000A1U, 0x0A000001U, 40000, 8080,
        1, 0, TCP_FLAG_SYN,
        opts, (uint8_t)sizeof(opts), NULL, 0);

    ck_assert_int_eq(ts->sock.tcp.ws_enabled, 1);
    ck_assert_uint_eq(ts->sock.tcp.snd_wscale, 14);
}
END_TEST

/* SACK option with invalid olen (not >=10 or not %8==0) is ignored */
START_TEST(test_tcp_parse_options_sack_bad_olen_ignored)
{
    /* SACK with olen=4 is invalid (min valid is 10); must be skipped */
    uint8_t opts[] = {
        TCP_OPTION_SACK, 4, 0, 0,  /* invalid SACK block, olen=4 */
        TCP_OPTION_EOO
    };
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LISTEN;
    ts->src_port = 8080;

    inject_tcp_segment_with_opts(&s, TEST_PRIMARY_IF,
        0x0A0000A1U, 0x0A000001U, 40000, 8080,
        1, 0, TCP_FLAG_SYN,
        opts, (uint8_t)sizeof(opts), NULL, 0);

    ck_assert_uint_eq(ts->sock.tcp.sack_permitted, 0);
}
END_TEST

/* NOP option advances the pointer by one */
START_TEST(test_tcp_parse_options_nop_advances)
{
    /* NOP padding before MSS */
    uint8_t opts[] = {
        TCP_OPTION_NOP, TCP_OPTION_NOP,
        TCP_OPTION_MSS, 4, 0x05, 0xB4, /* MSS=1460 */
        TCP_OPTION_EOO
    };
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LISTEN;
    ts->src_port = 8080;

    inject_tcp_segment_with_opts(&s, TEST_PRIMARY_IF,
        0x0A0000A1U, 0x0A000001U, 40000, 8080,
        1, 0, TCP_FLAG_SYN,
        opts, (uint8_t)sizeof(opts), NULL, 0);

    ck_assert_uint_eq(ts->sock.tcp.peer_mss, 1460);
}
END_TEST

/* Option olen=0: parser must break (loop termination guard) */
START_TEST(test_tcp_parse_options_zero_olen_breaks)
{
    /* Unknown option with olen=0: would infinite-loop without the guard */
    uint8_t opts[] = {
        0xFF, 0, /* unknown kind, olen=0 */
        TCP_OPTION_EOO
    };
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LISTEN;
    ts->src_port = 8080;

    /* Must complete without hanging */
    inject_tcp_segment_with_opts(&s, TEST_PRIMARY_IF,
        0x0A0000A1U, 0x0A000001U, 40000, 8080,
        1, 0, TCP_FLAG_SYN,
        opts, (uint8_t)sizeof(opts), NULL, 0);
}
END_TEST

/* Timestamp option correctly parsed from SYN */
START_TEST(test_tcp_parse_options_timestamp_parsed)
{
    /* TS option: kind=8, len=10, TSval=0x0102, TSEcr=0 */
    uint8_t opts[] = {
        TCP_OPTION_NOP, TCP_OPTION_NOP,
        TCP_OPTION_TS, 10,
        0x00, 0x00, 0x01, 0x02, /* TSval = 0x0102 */
        0x00, 0x00, 0x00, 0x00, /* TSEcr = 0 */
        TCP_OPTION_EOO
    };
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LISTEN;
    ts->src_port = 8080;
    ts->sock.tcp.sack_offer = 1;

    inject_tcp_segment_with_opts(&s, TEST_PRIMARY_IF,
        0x0A0000A1U, 0x0A000001U, 40000, 8080,
        1, 0, TCP_FLAG_SYN,
        opts, (uint8_t)sizeof(opts), NULL, 0);

    ck_assert_int_eq(ts->sock.tcp.ts_enabled, 1);
}
END_TEST

/* Overlong Timestamp option (olen > canonical 10) must be rejected.
 * RFC 7323 fixes the TS option at length 10; only canonical lengths
 * should roundtrip. An olen=11 TS must not negotiate ts_enabled. */
START_TEST(test_tcp_parse_options_timestamp_overlong_ignored)
{
    /* TS option with olen=11 (one byte longer than canonical). The 9
     * trailing bytes still carry a well-formed TSval/TSEcr; only the
     * length is wrong. */
    uint8_t opts[] = {
        TCP_OPTION_TS, 11,
        0x00, 0x00, 0x01, 0x02, /* TSval = 0x0102 */
        0x00, 0x00, 0x00, 0x00, /* TSEcr = 0 */
        0x00,                   /* extra byte: olen=11, not 10 */
        TCP_OPTION_EOO
    };
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LISTEN;
    ts->src_port = 8080;
    ts->sock.tcp.sack_offer = 1;

    inject_tcp_segment_with_opts(&s, TEST_PRIMARY_IF,
        0x0A0000A1U, 0x0A000001U, 40000, 8080,
        1, 0, TCP_FLAG_SYN,
        opts, (uint8_t)sizeof(opts), NULL, 0);

    ck_assert_int_eq(ts->sock.tcp.ts_enabled, 0);
}
END_TEST

/* MSS option value 0 is ignored (falls back to default) */
START_TEST(test_tcp_parse_options_mss_zero_ignored)
{
    uint8_t opts[] = {
        TCP_OPTION_MSS, 4, 0x00, 0x00,  /* MSS=0 must be ignored */
        TCP_OPTION_EOO
    };
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LISTEN;
    ts->src_port = 8080;

    inject_tcp_segment_with_opts(&s, TEST_PRIMARY_IF,
        0x0A0000A1U, 0x0A000001U, 40000, 8080,
        1, 0, TCP_FLAG_SYN,
        opts, (uint8_t)sizeof(opts), NULL, 0);

    /* When mss_found=0, tcp_input falls back to TCP_DEFAULT_MSS */
    ck_assert_uint_eq(ts->sock.tcp.peer_mss, TCP_DEFAULT_MSS);
}
END_TEST

/* SACK-permitted option is parsed */
START_TEST(test_tcp_parse_options_sack_permitted_parsed)
{
    uint8_t opts[] = {
        TCP_OPTION_SACK_PERMITTED, 2,  /* kind=4, len=2 */
        TCP_OPTION_EOO
    };
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LISTEN;
    ts->src_port = 8080;
    ts->sock.tcp.sack_offer = 1;  /* we also offer SACK */

    inject_tcp_segment_with_opts(&s, TEST_PRIMARY_IF,
        0x0A0000A1U, 0x0A000001U, 40000, 8080,
        1, 0, TCP_FLAG_SYN,
        opts, (uint8_t)sizeof(opts), NULL, 0);

    ck_assert_int_eq(ts->sock.tcp.sack_permitted, 1);
}
END_TEST

/* ===================================================================
 * tcp_input — state machine transitions
 * =================================================================== */

/* RST in SYN_RCVD without matching seq is ignored (stays SYN_RCVD) */
START_TEST(test_tcp_input_syn_rcvd_rst_bad_seq_ignored)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip   = 0x0A000001U;
    ip4 remote_ip  = 0x0A0000A1U;
    uint16_t lport = 8080, rport = 40000;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_RCVD;
    ts->sock.tcp.ack = 2;   /* rcv_nxt = 2 */
    ts->local_ip  = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port  = lport;
    ts->dst_port  = rport;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* RST with wrong seq: must be silently dropped, socket stays SYN_RCVD */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 999, 0, TCP_FLAG_RST);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_int_ne(ts->proto, 0);
}
END_TEST

/* RST in SYN_RCVD with matching seq on a listener → revert to LISTEN */
START_TEST(test_tcp_input_syn_rcvd_rst_good_seq_reverts_to_listen)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip   = 0x0A000001U;
    ip4 remote_ip  = 0x0A0000A1U;
    uint16_t lport = 8080, rport = 40000;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_RCVD;
    ts->sock.tcp.is_listener = 1;  /* listening socket: must revert, not close */
    ts->sock.tcp.ack = 2;   /* rcv_nxt = 2 */
    ts->local_ip  = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port  = lport;
    ts->dst_port  = rport;
    ts->sock.tcp.tmr_rto = NO_TIMER;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* RST with seq == rcv_nxt: should revert to LISTEN */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 2, 0, TCP_FLAG_RST);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
    ck_assert_int_ne(ts->proto, 0);  /* socket not destroyed */
}
END_TEST

/* RST in SYN_RCVD with matching seq on an accepted (non-listener) socket →
 * the half-open connection is torn down and CB_EVENT_CLOSED is delivered, so a
 * blocked consumer wakes instead of waiting on a phantom LISTEN socket. */
START_TEST(test_tcp_input_syn_rcvd_rst_good_seq_nonlistener_closes)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip   = 0x0A000001U;
    ip4 remote_ip  = 0x0A0000A1U;
    uint16_t lport = 8080, rport = 40000;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_RCVD;
    ts->sock.tcp.is_listener = 0;  /* accepted clone: must close, not revert */
    ts->sock.tcp.ack = 2;   /* rcv_nxt = 2 */
    ts->local_ip  = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port  = lport;
    ts->dst_port  = rport;
    ts->sock.tcp.tmr_rto = NO_TIMER;
    ts->callback = test_socket_cb;
    ts->callback_arg = NULL;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    socket_cb_calls = 0;
    socket_cb_last_events = 0;

    /* RST with seq == rcv_nxt: socket must be destroyed, not reverted. The
     * teardown + CB_EVENT_CLOSED are deferred from the RX path to poll Step 3
     * so the callback runs on a shallow stack. */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 2, 0, TCP_FLAG_RST);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSED);
    ck_assert_int_ne(ts->proto, 0);  /* not reverted to LISTEN, not yet reaped */
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, CB_EVENT_CLOSED);
    ck_assert_int_eq(socket_cb_calls, 0);

    (void)wolfIP_poll(&s, 1);

    ck_assert_int_eq(ts->proto, 0);  /* socket destroyed after event delivered */
    ck_assert_int_eq(socket_cb_calls, 1);
    ck_assert_uint_ne(socket_cb_last_events & CB_EVENT_CLOSED, 0);
}
END_TEST

/* Time-wait state re-ACKs any incoming segment */
START_TEST(test_tcp_input_time_wait_sends_ack_on_any_segment)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip   = 0x0A000001U;
    ip4 remote_ip  = 0x0A0000A1U;
    uint16_t lport = 9000, rport = 40001;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_TIME_WAIT;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.seq = 200;
    ts->local_ip  = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port  = lport;
    ts->dst_port  = rport;
    ts->if_idx    = TEST_PRIMARY_IF;
    ts->sock.tcp.peer_rwnd = 32768;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    arp_store_neighbor(&s, TEST_PRIMARY_IF, remote_ip, (uint8_t *)setup_peer_mac);

    last_frame_sent_size = 0;
    /* Any ACK arriving in TIME_WAIT should cause us to re-send an ACK */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 99, 200, TCP_FLAG_ACK | TCP_FLAG_FIN);

    /* ACK is queued in txbuf (tcp_send_ack uses fifo_push, not immediate tx) */
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.tcp.txbuf));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_TIME_WAIT);
}
END_TEST

/* LAST_ACK: unacceptable segment causes challenge ACK */
START_TEST(test_tcp_input_last_ack_unacceptable_sends_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip   = 0x0A000001U;
    ip4 remote_ip  = 0x0A0000A1U;
    uint16_t lport = 9001, rport = 40002;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LAST_ACK;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.seq = 200;
    ts->sock.tcp.last = 200;
    ts->local_ip  = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port  = lport;
    ts->dst_port  = rport;
    ts->if_idx    = TEST_PRIMARY_IF;
    ts->sock.tcp.peer_rwnd = 0;     /* zero window */
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    /* rxbuf size=0 → queue_space=0 → rcv_wnd=0 → segment not acceptable */
    arp_store_neighbor(&s, TEST_PRIMARY_IF, remote_ip, (uint8_t *)setup_peer_mac);

    last_frame_sent_size = 0;
    /* Segment with wrong seq (outside window) → challenge ACK */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 999, 201, TCP_FLAG_ACK);

    /* ACK is queued in txbuf (tcp_send_ack uses fifo_push, not immediate tx) */
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.tcp.txbuf));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LAST_ACK);
}
END_TEST

/* SYN on LAST_ACK synchronized connection → challenge ACK (RFC 5961) */
START_TEST(test_tcp_input_last_ack_syn_sends_challenge_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip   = 0x0A000001U;
    ip4 remote_ip  = 0x0A0000A1U;
    uint16_t lport = 9002, rport = 40003;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LAST_ACK;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.seq = 200;
    ts->sock.tcp.last = 200;
    ts->local_ip  = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port  = lport;
    ts->dst_port  = rport;
    ts->if_idx    = TEST_PRIMARY_IF;
    ts->sock.tcp.peer_rwnd = 32768;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    arp_store_neighbor(&s, TEST_PRIMARY_IF, remote_ip, (uint8_t *)setup_peer_mac);

    last_frame_sent_size = 0;
    /* SYN within window → challenge ACK, not close */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 100, 200, TCP_FLAG_SYN | TCP_FLAG_ACK);

    /* ACK is queued in txbuf (tcp_send_ack uses fifo_push, not immediate tx) */
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.tcp.txbuf));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LAST_ACK);
}
END_TEST

/* SYN in ESTABLISHED (synchronized) → challenge ACK per RFC 5961 */
START_TEST(test_tcp_input_established_syn_sends_challenge_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip   = 0x0A000001U;
    ip4 remote_ip  = 0x0A0000A1U;
    uint16_t lport = 9003, rport = 40004;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = setup_established_socket(&s, local_ip, remote_ip, lport, rport);

    last_frame_sent_size = 0;
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 100, 200, TCP_FLAG_SYN);

    /* ACK is queued in txbuf (tcp_send_ack uses fifo_push, not immediate tx) */
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.tcp.txbuf));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

/* Unacceptable out-of-window segment in ESTABLISHED sends challenge ACK */
START_TEST(test_tcp_input_established_out_of_window_sends_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip   = 0x0A000001U;
    ip4 remote_ip  = 0x0A0000A1U;
    uint16_t lport = 9004, rport = 40005;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = setup_established_socket(&s, local_ip, remote_ip, lport, rport);
    ts->sock.tcp.peer_rwnd = 32768;

    last_frame_sent_size = 0;
    /* seq far in the past → out of window */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 1, 200, TCP_FLAG_ACK);

    /* ACK is queued in txbuf (tcp_send_ack uses fifo_push, not immediate tx) */
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.tcp.txbuf));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

/* No ACK bit in ESTABLISHED → segment dropped without reply */
START_TEST(test_tcp_input_established_no_ack_dropped)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip   = 0x0A000001U;
    ip4 remote_ip  = 0x0A0000A1U;
    uint16_t lport = 9005, rport = 40006;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = setup_established_socket(&s, local_ip, remote_ip, lport, rport);

    last_frame_sent_size = 0;
    /* No ACK flag: must be silently dropped */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 100, 0, TCP_FLAG_PSH);

    ck_assert_uint_eq(last_frame_sent_size, 0U);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

/* ESTABLISHED FIN with non-matching seq (out-of-order) does not advance state */
START_TEST(test_tcp_input_established_fin_ooo_no_close_wait)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip   = 0x0A000001U;
    ip4 remote_ip  = 0x0A0000A1U;
    uint16_t lport = 9006, rport = 40007;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = setup_established_socket(&s, local_ip, remote_ip, lport, rport);
    ts->sock.tcp.ack = 100;  /* expect seq=100 for in-order FIN */

    /* FIN at seq=200 (not rcv_nxt=100) → out-of-order, no state transition */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 200, 200, TCP_FLAG_ACK | TCP_FLAG_FIN);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

/* SYN_RCVD ACK with FIN in same segment → transitions directly to CLOSE_WAIT */
START_TEST(test_tcp_input_syn_rcvd_ack_with_fin_enters_close_wait)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip   = 0x0A000001U;
    ip4 remote_ip  = 0x0A0000A1U;
    uint16_t lport = 9007, rport = 40008;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_RCVD;
    ts->sock.tcp.ack = 2;      /* rcv_nxt = 2 */
    ts->sock.tcp.seq = 1;
    ts->sock.tcp.snd_una = 1;  /* SYN-ACK not yet acked */
    ts->sock.tcp.last = 1;
    ts->local_ip  = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port  = lport;
    ts->dst_port  = rport;
    ts->if_idx    = TEST_PRIMARY_IF;
    ts->sock.tcp.peer_rwnd = 32768;
    ts->sock.tcp.tmr_rto = NO_TIMER;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* ACK + FIN completing the handshake: expected_ack = snd_una+1 = 2 */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 2, 2, TCP_FLAG_ACK | TCP_FLAG_FIN);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSE_WAIT);
}
END_TEST

/* Peer window growth from 0 → non-zero stops persist timer */
START_TEST(test_tcp_input_window_grows_from_zero_stops_persist)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip   = 0x0A000001U;
    ip4 remote_ip  = 0x0A0000A1U;
    uint16_t lport = 9008, rport = 40009;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = setup_established_socket(&s, local_ip, remote_ip, lport, rport);
    ts->sock.tcp.peer_rwnd = 0;
    ts->sock.tcp.persist_active = 1;

    /* Peer sends ACK reopening the window */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 100, 200, TCP_FLAG_ACK);

    ck_assert_int_eq(ts->sock.tcp.persist_active, 0);
}
END_TEST

/* ===================================================================
 * tcp_rto_cb — additional missing branches
 * =================================================================== */

/* fin_wait_2_timeout fires and closes the socket */
START_TEST(test_tcp_rto_cb_fin_wait_2_timeout_closes_socket)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_2;
    ts->sock.tcp.tmr_rto = NO_TIMER;
    ts->sock.tcp.fin_wait_2_timeout_active = 1;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    tcp_rto_cb(ts);

    ck_assert_int_eq(ts->proto, 0);
}
END_TEST

/* fin_wait_2_timeout fires but socket is no longer in FIN_WAIT_2 → just stop */
START_TEST(test_tcp_rto_cb_fin_wait_2_wrong_state_stops_timer)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_CLOSING; /* not FIN_WAIT_2 */
    ts->sock.tcp.tmr_rto = NO_TIMER;
    ts->sock.tcp.fin_wait_2_timeout_active = 1;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    tcp_rto_cb(ts);

    ck_assert_int_ne(ts->proto, 0);
    ck_assert_int_eq(ts->sock.tcp.fin_wait_2_timeout_active, 0);
}
END_TEST

/* ctrl_rto fires when not needed (e.g. already in ESTABLISHED): stops */
START_TEST(test_tcp_rto_cb_ctrl_not_needed_stops)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED; /* does NOT need ctrl RTO */
    ts->sock.tcp.ctrl_rto_active = 1;     /* but timer thinks it is active */
    ts->sock.tcp.tmr_rto = NO_TIMER;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    tcp_rto_cb(ts);

    ck_assert_int_eq(ts->sock.tcp.ctrl_rto_active, 0);
}
END_TEST

/* ctrl_rto max retries for a non-listener SYN_RCVD closes the socket */
START_TEST(test_tcp_rto_cb_ctrl_maxretries_nonlistener_closes)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_RCVD;
    ts->sock.tcp.ctrl_rto_active = 1;
    ts->sock.tcp.ctrl_rto_retries = TCP_CTRL_RTO_MAXRTX; /* exhausted */
    ts->sock.tcp.is_listener = 0;  /* not a listener: must close */
    ts->sock.tcp.tmr_rto = NO_TIMER;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    tcp_rto_cb(ts);

    ck_assert_int_eq(ts->proto, 0);
}
END_TEST

/* ===================================================================
 * tcp_ack — additional missing branches
 * =================================================================== */

/* ack == snd_una (duplicate) with zero inflight: returns early */
START_TEST(test_tcp_ack_duplicate_zero_inflight_early_return)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg ackseg;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 200;
    ts->sock.tcp.bytes_in_flight = 0;  /* zero inflight → early return */
    ts->sock.tcp.peer_rwnd = 32768;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack   = ee32(100);   /* duplicate: same as snd_una */
    ackseg.hlen  = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);

    tcp_ack(ts, &ackseg);
    /* dup_acks should not have been incremented */
    ck_assert_uint_eq(ts->sock.tcp.dup_acks, 0);
}
END_TEST

/* Duplicate ACK where ack != snd_una: returns immediately */
START_TEST(test_tcp_ack_duplicate_ack_ne_snd_una_returns)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg ackseg;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 300;
    ts->sock.tcp.bytes_in_flight = 50;
    ts->sock.tcp.peer_rwnd = 32768;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&ackseg, 0, sizeof(ackseg));
    /* ack=50 is below snd_una=100: neither new progress nor dup-ack of snd_una */
    ackseg.ack   = ee32(50);
    ackseg.hlen  = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.dup_acks, 0);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, 100);
}
END_TEST

/* Fast recovery inflation on 4th duplicate ACK */
START_TEST(test_tcp_ack_fourth_dupack_inflates_cwnd)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg ackseg;
    uint32_t cwnd_before;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 600;
    ts->sock.tcp.bytes_in_flight = 500;
    ts->sock.tcp.peer_rwnd = 32768;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.ssthresh = TCP_MSS * 2;
    ts->sock.tcp.fast_recovery = 1;
    ts->sock.tcp.dup_acks = 3;   /* already 3 → 4th dup-ack inflates cwnd */
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    cwnd_before = ts->sock.tcp.cwnd;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack   = ee32(100);   /* duplicate ACK */
    ackseg.hlen  = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);

    tcp_ack(ts, &ackseg);
    /* cwnd should be inflated by one SMSS */
    ck_assert_uint_gt(ts->sock.tcp.cwnd, cwnd_before);
}
END_TEST

/* CLOSE_WAIT state processes ACK normally */
START_TEST(test_tcp_ack_close_wait_processes_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg ackseg;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 120;
    ts->sock.tcp.last = 120;
    ts->sock.tcp.bytes_in_flight = 20;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    ts->sock.tcp.ssthresh = TCP_MSS * 8;
    ts->sock.tcp.tmr_rto = NO_TIMER;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* Push a sent segment */
    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 20);
    seg->hlen   = TCP_HEADER_LEN << 2;
    seg->seq    = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack   = ee32(120);
    ackseg.hlen  = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, 120);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSE_WAIT);
}
END_TEST

/* ===================================================================
 * tcp_mark_unsacked_for_retransmit — additional missing branches
 * =================================================================== */

/* cover_found=0, peer_sack_count=0: returns 0 without rescan */
START_TEST(test_tcp_mark_unsacked_no_cover_no_sack_returns_zero)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct pkt_desc *desc;
    int ret;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.peer_sack_count = 0; /* no sack → no rescan */
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* Push an unsent segment ahead of snd_una */
    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq  = ee32(200);  /* above ack=100, no cover → returns 0 */
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags &= ~PKT_FLAG_SENT;

    ret = tcp_mark_unsacked_for_retransmit(ts, 100);
    ck_assert_int_eq(ret, 0);
}
END_TEST

/* ===================================================================
 * tcp_resync_inflight — 9 missing branches
 * =================================================================== */

/* Null stack or null ts → noop */
START_TEST(test_tcp_resync_inflight_null_args)
{
    struct wolfIP s;
    struct tsocket ts;

    wolfIP_init(&s);

    tcp_resync_inflight(NULL, &ts, 0);
    tcp_resync_inflight(&s, NULL, 0);
}
END_TEST

/* ctrl_rto_active: resync is skipped entirely */
START_TEST(test_tcp_resync_inflight_skips_when_ctrl_rto_active)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_RCVD;   /* ctrl state */
    ts->sock.tcp.ctrl_rto_active = 1;
    ts->sock.tcp.bytes_in_flight = 42;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    tcp_resync_inflight(&s, ts, 0);

    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, 42);
}
END_TEST

/* Sent payload present → timer is armed */
START_TEST(test_tcp_resync_inflight_arms_timer_on_sent_payload)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.tmr_rto = NO_TIMER;
    ts->sock.tcp.rto = 1000;
    ts->sock.tcp.rto_backoff = 0;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    tcp_resync_inflight(&s, ts, 0);

    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, 10);
    ck_assert_int_ne((int)ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

/* No sent payload but timer armed → cancel timer */
START_TEST(test_tcp_resync_inflight_cancels_timer_when_no_payload)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct pkt_desc *desc;
    struct wolfIP_timer tmr;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;

    /* Insert a dummy timer so tmr_rto != NO_TIMER */
    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = tcp_rto_cb;
    tmr.expires = 9999;
    tmr.arg = ts;
    ts->sock.tcp.tmr_rto = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne((int)ts->sock.tcp.tmr_rto, NO_TIMER);

    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* Unsent (not PKT_FLAG_SENT) zero-len ACK segment in the queue */
    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);  /* zero payload */
    seg->hlen = TCP_HEADER_LEN << 2;
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    /* Not flagged as SENT → no payload in flight */

    tcp_resync_inflight(&s, ts, 0);

    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, 0);
    ck_assert_int_eq((int)ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

/* ===================================================================
 * tcp_find_pending_retrans — 12 missing branches
 * =================================================================== */

/* NULL ts or NULL start: returns NULL */
START_TEST(test_tcp_find_pending_retrans_null_args)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc dummy;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_ptr_null(tcp_find_pending_retrans(NULL, &dummy));
    ck_assert_ptr_null(tcp_find_pending_retrans(ts, NULL));
}
END_TEST

/* Segment with RETRANS flag but already SENT → not returned */
START_TEST(test_tcp_find_pending_retrans_already_sent_skipped)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct pkt_desc *desc;
    struct pkt_desc *result;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    /* RETRANS set but also SENT → must NOT be returned */
    desc->flags = PKT_FLAG_RETRANS | PKT_FLAG_SENT;

    result = tcp_find_pending_retrans(ts, desc);
    ck_assert_ptr_null(result);
}
END_TEST

/* Segment with RETRANS and NOT SENT and payload → returned */
START_TEST(test_tcp_find_pending_retrans_unsent_retrans_returned)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct pkt_desc *desc;
    struct pkt_desc *result;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags = PKT_FLAG_RETRANS;  /* RETRANS + not SENT */

    result = tcp_find_pending_retrans(ts, desc);
    ck_assert_ptr_nonnull(result);
    ck_assert_ptr_eq(result, desc);
}
END_TEST

/* ===================================================================
 * tcp_send_empty_immediate — 10 missing branches
 * =================================================================== */

/* NULL tsocket → returns -1 */
START_TEST(test_tcp_send_empty_immediate_null_tsocket)
{
    struct wolfIP_tcp_seg seg;
    int ret;
    memset(&seg, 0, sizeof(seg));
    ret = tcp_send_empty_immediate(NULL, &seg,
                ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* NULL tcp segment → returns -1 */
START_TEST(test_tcp_send_empty_immediate_null_seg)
{
    struct wolfIP s;
    struct tsocket *ts;
    int ret;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->if_idx = TEST_PRIMARY_IF;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ret = tcp_send_empty_immediate(ts, NULL,
                ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* frame_len too small → returns -1 */
START_TEST(test_tcp_send_empty_immediate_short_frame_len)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->if_idx = TEST_PRIMARY_IF;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    memset(&seg, 0, sizeof(seg));

    /* Deliberately short */
    ret = tcp_send_empty_immediate(ts, &seg, ETH_HEADER_LEN);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* Happy path: ARP hit → frame sent */
START_TEST(test_tcp_send_empty_immediate_arp_hit_sends)
{
    static const uint8_t peer_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->local_ip  = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->src_port  = 9009;
    ts->dst_port  = 40010;
    ts->if_idx    = TEST_PRIMARY_IF;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.peer_rwnd = 32768;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A000002U, (uint8_t *)peer_mac);

    memset(&seg, 0, sizeof(seg));
    seg.src_port = ee16(ts->src_port);
    seg.dst_port = ee16(ts->dst_port);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_ACK;

    last_frame_sent_size = 0;
    ret = tcp_send_empty_immediate(ts, &seg,
                ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN);

    ck_assert_int_eq(ret, 0);
    ck_assert_uint_gt(last_frame_sent_size, 0U);
}
END_TEST

/* ===================================================================
 * tcp_send_zero_wnd_probe — 11 missing branches
 * =================================================================== */

/* NULL tsocket → -1 */
START_TEST(test_tcp_send_zero_wnd_probe_null_ts)
{
    int ret = tcp_send_zero_wnd_probe(NULL);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* Non-TCP proto → -1 */
START_TEST(test_tcp_send_zero_wnd_probe_non_tcp_proto)
{
    struct wolfIP s;
    struct tsocket *ts;
    int ret;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_UDP;  /* not TCP */
    ts->S = &s;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ret = tcp_send_zero_wnd_probe(ts);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* Empty txbuf (no desc) → -1 */
START_TEST(test_tcp_send_zero_wnd_probe_empty_txbuf)
{
    struct wolfIP s;
    struct tsocket *ts;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.snd_una = 100;
    ts->if_idx = TEST_PRIMARY_IF;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ret = tcp_send_zero_wnd_probe(ts);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* Probe sent successfully when payload exists and ARP hit */
START_TEST(test_tcp_send_zero_wnd_probe_sends_probe)
{
    static const uint8_t peer_mac[6] = {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01};
    static const uint8_t payload[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->local_ip  = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->src_port  = 9010;
    ts->dst_port  = 40011;
    ts->if_idx    = TEST_PRIMARY_IF;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.snd_una = 200;
    ts->sock.tcp.peer_rwnd = 0;  /* zero window */
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* Push a sent segment that overlaps snd_una */
    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + (uint16_t)sizeof(payload));
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(200);  /* starts at snd_una */
    memcpy((uint8_t *)seg->ip.data + TCP_HEADER_LEN, payload, sizeof(payload));
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);

    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A000002U, (uint8_t *)peer_mac);

    last_frame_sent_size = 0;
    ret = tcp_send_zero_wnd_probe(ts);
    ck_assert_int_eq(ret, 0);
    ck_assert_uint_gt(last_frame_sent_size, 0U);
}
END_TEST

/* ===================================================================
 * icmp_try_deliver_tcp_error — 17 missing branches
 * =================================================================== */

/* Null pointer args: noop */
START_TEST(test_icmp_try_deliver_tcp_error_null_args)
{
    struct wolfIP s;
    wolfIP_init(&s);
    icmp_try_deliver_tcp_error(NULL, NULL);
    icmp_try_deliver_tcp_error(&s, NULL);
}
END_TEST

/* Wrong ICMP type (echo request) is ignored */
START_TEST(test_icmp_try_deliver_tcp_error_wrong_type_ignored)
{
    struct wolfIP s;
    struct wolfIP_icmp_dest_unreachable_packet pkt;

    wolfIP_init(&s);
    memset(&pkt, 0, sizeof(pkt));
    pkt.ip.len = ee16(IP_HEADER_LEN + sizeof(pkt) - sizeof(pkt.ip));
    pkt.type = 8;  /* echo request: must be ignored */
    pkt.code = 0;

    icmp_try_deliver_tcp_error(&s, (const struct wolfIP_icmp_packet *)&pkt);
}
END_TEST

/* ICMP TTL-exceeded matching socket in SYN_SENT: state unchanged (only DEST_UNREACH closes) */
START_TEST(test_icmp_try_deliver_tcp_error_ttl_exceeded_syn_sent)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_icmp_packet) + IP_HEADER_LEN + 8];
    struct wolfIP_icmp_packet *icmp = (struct wolfIP_icmp_packet *)buf;
    struct wolfIP_ip_wire *orig_ip;
    uint8_t *orig_tcp_hdr;
    uint16_t sp, dp;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->local_ip  = 0x0A000001U;
    ts->remote_ip = 0x0A000064U;
    ts->src_port  = 12345;
    ts->dst_port  = 80;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(buf, 0, sizeof(buf));
    icmp->ip.len = ee16((uint16_t)(sizeof(buf) - ETH_HEADER_LEN));
    icmp->type   = ICMP_TTL_EXCEEDED;
    icmp->code   = 0;

    orig_ip = (struct wolfIP_ip_wire *)(buf + sizeof(struct wolfIP_icmp_packet));
    orig_ip->ver_ihl = 0x45;
    orig_ip->proto   = WI_IPPROTO_TCP;
    orig_ip->src     = ee32(ts->local_ip);
    orig_ip->dst     = ee32(ts->remote_ip);

    orig_tcp_hdr = (uint8_t *)orig_ip + IP_HEADER_LEN;
    sp = ee16(ts->src_port);
    dp = ee16(ts->dst_port);
    memcpy(orig_tcp_hdr,     &sp, 2);
    memcpy(orig_tcp_hdr + 2, &dp, 2);

    icmp_try_deliver_tcp_error(&s, icmp);

    /* TTL-exceeded does not close SYN_SENT */
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);
}
END_TEST

/* ICMP DEST_UNREACH PORT_UNREACH matching SYN_SENT closes socket */
START_TEST(test_icmp_try_deliver_tcp_error_port_unreach_syn_sent_closes)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_icmp_packet) + IP_HEADER_LEN + 8];
    struct wolfIP_icmp_packet *icmp = (struct wolfIP_icmp_packet *)buf;
    struct wolfIP_ip_wire *orig_ip;
    uint8_t *orig_tcp_hdr;
    uint16_t sp, dp;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state   = TCP_SYN_SENT;
    ts->sock.tcp.seq     = 0xDEADBEEFU;   /* ISS */
    ts->sock.tcp.snd_una = 0xDEADBEEFU;
    ts->local_ip  = 0x0A000001U;
    ts->remote_ip = 0x0A000064U;
    ts->src_port  = 54321;
    ts->dst_port  = 443;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(buf, 0, sizeof(buf));
    icmp->ip.len = ee16((uint16_t)(sizeof(buf) - ETH_HEADER_LEN));
    icmp->type   = ICMP_DEST_UNREACH;
    icmp->code   = ICMP_PORT_UNREACH;

    orig_ip = (struct wolfIP_ip_wire *)(buf + sizeof(struct wolfIP_icmp_packet));
    orig_ip->ver_ihl = 0x45;
    orig_ip->proto   = WI_IPPROTO_TCP;
    orig_ip->src     = ee32(ts->local_ip);
    orig_ip->dst     = ee32(ts->remote_ip);

    orig_tcp_hdr = (uint8_t *)orig_ip + IP_HEADER_LEN;
    sp = ee16(ts->src_port);
    dp = ee16(ts->dst_port);
    memcpy(orig_tcp_hdr,     &sp, 2);
    memcpy(orig_tcp_hdr + 2, &dp, 2);
    /* RFC 5927 4.1: embedded SEG.SEQ is the in-flight SYN (== ISS == snd_una),
     * so it falls inside the [snd_una, snd_una+1) send window. */
    {
        uint32_t emb_seq = ee32(ts->sock.tcp.seq);
        memcpy(orig_tcp_hdr + 4, &emb_seq, 4);
    }

    icmp_try_deliver_tcp_error(&s, icmp);

    /* PORT_UNREACH on SYN_SENT with an in-window seq must close the socket */
    ck_assert_int_eq(ts->proto, 0);
}
END_TEST

START_TEST(test_icmp_try_deliver_tcp_error_port_unreach_bad_seq_ignored)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_icmp_packet) + IP_HEADER_LEN + 8];
    struct wolfIP_icmp_packet *icmp = (struct wolfIP_icmp_packet *)buf;
    struct wolfIP_ip_wire *orig_ip;
    uint8_t *orig_tcp_hdr;
    uint16_t sp, dp;
    uint32_t bad_seq;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state   = TCP_SYN_SENT;
    ts->sock.tcp.seq     = 0xDEADBEEFU;   /* ISS */
    ts->sock.tcp.snd_una = 0xDEADBEEFU;
    ts->local_ip  = 0x0A000001U;
    ts->remote_ip = 0x0A000064U;
    ts->src_port  = 54321;
    ts->dst_port  = 443;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(buf, 0, sizeof(buf));
    icmp->ip.len = ee16((uint16_t)(sizeof(buf) - ETH_HEADER_LEN));
    icmp->type   = ICMP_DEST_UNREACH;
    icmp->code   = ICMP_PORT_UNREACH;

    orig_ip = (struct wolfIP_ip_wire *)(buf + sizeof(struct wolfIP_icmp_packet));
    orig_ip->ver_ihl = 0x45;
    orig_ip->proto   = WI_IPPROTO_TCP;
    orig_ip->src     = ee32(ts->local_ip);
    orig_ip->dst     = ee32(ts->remote_ip);

    orig_tcp_hdr = (uint8_t *)orig_ip + IP_HEADER_LEN;
    sp = ee16(ts->src_port);
    dp = ee16(ts->dst_port);
    memcpy(orig_tcp_hdr,     &sp, 2);
    memcpy(orig_tcp_hdr + 2, &dp, 2);

    /* seq far outside [snd_una, snd_una+1) */
    bad_seq = ee32(0x41414141U);
    memcpy(orig_tcp_hdr + 4, &bad_seq, 4);

    icmp_try_deliver_tcp_error(&s, icmp);

    /* Out-of-window seq: socket must NOT be closed */
    ck_assert_int_ne(ts->proto, 0);
}
END_TEST

/* ICMP DEST_UNREACH with mismatched src_ip: socket not closed */
START_TEST(test_icmp_try_deliver_tcp_error_src_ip_mismatch_not_closed)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_icmp_packet) + IP_HEADER_LEN + 8];
    struct wolfIP_icmp_packet *icmp = (struct wolfIP_icmp_packet *)buf;
    struct wolfIP_ip_wire *orig_ip;
    uint8_t *orig_tcp_hdr;
    uint16_t sp, dp;

    wolfIP_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->local_ip  = 0x0A000001U;
    ts->remote_ip = 0x0A000064U;
    ts->src_port  = 11111;
    ts->dst_port  = 80;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(buf, 0, sizeof(buf));
    icmp->ip.len = ee16((uint16_t)(sizeof(buf) - ETH_HEADER_LEN));
    icmp->type   = ICMP_DEST_UNREACH;
    icmp->code   = ICMP_PORT_UNREACH;

    orig_ip = (struct wolfIP_ip_wire *)(buf + sizeof(struct wolfIP_icmp_packet));
    orig_ip->ver_ihl = 0x45;
    orig_ip->proto   = WI_IPPROTO_TCP;
    /* Different source IP from what the socket has */
    orig_ip->src     = ee32(0x0A000099U);  /* mismatch */
    orig_ip->dst     = ee32(ts->remote_ip);

    orig_tcp_hdr = (uint8_t *)orig_ip + IP_HEADER_LEN;
    sp = ee16(ts->src_port);
    dp = ee16(ts->dst_port);
    memcpy(orig_tcp_hdr,     &sp, 2);
    memcpy(orig_tcp_hdr + 2, &dp, 2);

    icmp_try_deliver_tcp_error(&s, icmp);

    /* Mismatch: socket must not be closed */
    ck_assert_int_ne(ts->proto, 0);
}
END_TEST

/* ICMP DEST_UNREACH FRAG_NEEDED reduces peer MSS */
START_TEST(test_icmp_try_deliver_tcp_error_frag_needed_reduces_mss)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_icmp_packet) + IP_HEADER_LEN + 8];
    struct wolfIP_icmp_packet *icmp = (struct wolfIP_icmp_packet *)buf;
    struct wolfIP_ip_wire *orig_ip;
    uint8_t *orig_tcp_hdr;
    uint16_t sp, dp, next_hop_mtu;

    wolfIP_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip  = 0x0A000001U;
    ts->remote_ip = 0x0A000064U;
    ts->src_port  = 22222;
    ts->dst_port  = 80;
    ts->sock.tcp.peer_mss = 1460;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(buf, 0, sizeof(buf));
    icmp->ip.len = ee16((uint16_t)(sizeof(buf) - ETH_HEADER_LEN));
    icmp->type   = ICMP_DEST_UNREACH;
    icmp->code   = ICMP_FRAG_NEEDED;

    /* next-hop MTU = 700 → new_mss = 700 - 40 = 660 */
    next_hop_mtu = ee16(700);
    memcpy(&icmp->unused[2], &next_hop_mtu, sizeof(next_hop_mtu));

    orig_ip = (struct wolfIP_ip_wire *)(buf + sizeof(struct wolfIP_icmp_packet));
    orig_ip->ver_ihl = 0x45;
    orig_ip->proto   = WI_IPPROTO_TCP;
    orig_ip->src     = ee32(ts->local_ip);
    orig_ip->dst     = ee32(ts->remote_ip);

    orig_tcp_hdr = (uint8_t *)orig_ip + IP_HEADER_LEN;
    sp = ee16(ts->src_port);
    dp = ee16(ts->dst_port);
    memcpy(orig_tcp_hdr,     &sp, 2);
    memcpy(orig_tcp_hdr + 2, &dp, 2);

    icmp_try_deliver_tcp_error(&s, icmp);

    /* peer_mss must be reduced */
    ck_assert_uint_lt(ts->sock.tcp.peer_mss, 1460);
}
END_TEST

/* icmp avail < IP_HEADER_LEN: returns without touching any socket */
START_TEST(test_icmp_try_deliver_tcp_error_avail_too_small)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;

    wolfIP_init(&s);

    memset(&icmp, 0, sizeof(icmp));
    icmp.type = ICMP_DEST_UNREACH;
    icmp.code = ICMP_PORT_UNREACH;
    /* ip.len just barely covers ICMP header but not enough for orig IP header */
    icmp.ip.len = ee16((uint16_t)(IP_HEADER_LEN + sizeof(uint8_t) * 8 + 3));

    icmp_try_deliver_tcp_error(&s, &icmp);
}
END_TEST

/* ===================================================================
 * raw_route_for_ip — 14 missing branches
 * =================================================================== */

#if WOLFIP_RAWSOCKETS

/* NULL stack → returns 0 */
START_TEST(test_raw_route_for_ip_null_stack)
{
    unsigned int ret = raw_route_for_ip(NULL, NULL, 0x0A000001U, 0);
    ck_assert_uint_eq(ret, 0);
}
END_TEST

/* rs=NULL, dontroute=0 → falls through to wolfIP_route_for_ip */
START_TEST(test_raw_route_for_ip_null_rs_uses_route)
{
    struct wolfIP s;
    unsigned int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ret = raw_route_for_ip(&s, NULL, 0x0A000002U, 0);
    ck_assert_uint_lt(ret, s.if_count);
}
END_TEST

/* rs has bound_local_ip that matches an interface */
START_TEST(test_raw_route_for_ip_bound_local_ip_match)
{
    struct wolfIP s;
    struct rawsocket rs;
    unsigned int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    memset(&rs, 0, sizeof(rs));
    rs.bound_local_ip = 0x0A000001U;  /* matches primary interface */

    ret = raw_route_for_ip(&s, &rs, 0x0A000002U, 0);
    ck_assert_uint_eq(ret, TEST_PRIMARY_IF);
}
END_TEST

/* rs has bound_local_ip that doesn't match any interface → falls through */
START_TEST(test_raw_route_for_ip_bound_local_ip_no_match)
{
    struct wolfIP s;
    struct rawsocket rs;
    unsigned int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    memset(&rs, 0, sizeof(rs));
    rs.bound_local_ip = 0x01020304U;  /* no interface has this IP */

    ret = raw_route_for_ip(&s, &rs, 0x0A000002U, 0);
    ck_assert_uint_lt(ret, s.if_count);
}
END_TEST

/* dontroute=1 with dest on local subnet → returns matching if */
START_TEST(test_raw_route_for_ip_dontroute_local_match)
{
    struct wolfIP s;
    unsigned int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    /* 0x0A000002 is on the same /24 subnet as 0x0A000001 */
    ret = raw_route_for_ip(&s, NULL, 0x0A000002U, 1 /* dontroute */);
    ck_assert_uint_eq(ret, TEST_PRIMARY_IF);
}
END_TEST

/* dontroute=1 with non-local dest → falls through to route lookup */
START_TEST(test_raw_route_for_ip_dontroute_no_local_match)
{
    struct wolfIP s;
    unsigned int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    /* 0xC0A80001 (192.168.0.1) is not on the 10.0.0.0/24 subnet */
    ret = raw_route_for_ip(&s, NULL, 0xC0A80001U, 1 /* dontroute */);
    ck_assert_uint_lt(ret, s.if_count);
}
END_TEST

#endif /* WOLFIP_RAWSOCKETS */

/* ===================================================================
 * Additional tcp_input branches
 * =================================================================== */

/* LISTEN state: RST is silently ignored (server stays open) */
START_TEST(test_tcp_input_listen_rst_ignored)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    uint16_t lport = 7070;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LISTEN;
    ts->src_port = lport;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, local_ip,
        40000, lport, 1, 0, TCP_FLAG_RST);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
    ck_assert_int_ne(ts->proto, 0);
}
END_TEST

/* FIN_WAIT_1 receiving a FIN → CLOSING state */
START_TEST(test_tcp_input_fin_wait_1_fin_enters_closing)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A0000A1U;
    uint16_t lport = 8181, rport = 40020;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.seq = 300;
    ts->sock.tcp.last = 300;
    ts->sock.tcp.snd_una = 300;
    ts->local_ip  = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port  = lport;
    ts->dst_port  = rport;
    ts->if_idx    = TEST_PRIMARY_IF;
    ts->sock.tcp.peer_rwnd = 32768;
    ts->sock.tcp.tmr_rto = NO_TIMER;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    arp_store_neighbor(&s, TEST_PRIMARY_IF, remote_ip, (uint8_t *)setup_peer_mac);

    /* Peer sends FIN at rcv_nxt=100, ack=300 doesn't ack our FIN (needs 301) */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 100, 300, TCP_FLAG_ACK | TCP_FLAG_FIN);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSING);
}
END_TEST

/* FIN_WAIT_2 receiving a FIN → TIME_WAIT */
START_TEST(test_tcp_input_fin_wait_2_fin_enters_time_wait)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A0000A1U;
    uint16_t lport = 8282, rport = 40021;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_2;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.seq = 300;
    ts->sock.tcp.snd_una = 300;
    ts->sock.tcp.last = 300;
    ts->local_ip  = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port  = lport;
    ts->dst_port  = rport;
    ts->if_idx    = TEST_PRIMARY_IF;
    ts->sock.tcp.peer_rwnd = 32768;
    ts->sock.tcp.tmr_rto = NO_TIMER;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    arp_store_neighbor(&s, TEST_PRIMARY_IF, remote_ip, (uint8_t *)setup_peer_mac);

    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 100, 300, TCP_FLAG_ACK | TCP_FLAG_FIN);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_TIME_WAIT);
}
END_TEST

/* RST in ESTABLISHED with seq inside window but != rcv_nxt → sends ACK */
START_TEST(test_tcp_input_rst_in_window_not_exact_sends_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A0000A1U;
    uint16_t lport = 8383, rport = 40022;
    static uint8_t rxmem[RXBUF_SIZE];

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;   /* rcv_nxt = 100 */
    ts->sock.tcp.seq = 200;
    ts->sock.tcp.peer_rwnd = 32768;
    ts->local_ip  = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port  = lport;
    ts->dst_port  = rport;
    ts->if_idx    = TEST_PRIMARY_IF;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    queue_init(&ts->sock.tcp.rxbuf, rxmem, RXBUF_SIZE, 0);
    arp_store_neighbor(&s, TEST_PRIMARY_IF, remote_ip, (uint8_t *)setup_peer_mac);

    last_frame_sent_size = 0;
    /* seq=105 is inside window but != rcv_nxt=100 → ACK, no close */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 105, 200, TCP_FLAG_RST);

    /* ACK is queued in txbuf (tcp_send_ack uses fifo_push, not immediate tx) */
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.tcp.txbuf));
    ck_assert_int_ne(ts->proto, 0);
}
END_TEST

/*
 * wolfIP_sock_close() must disarm the callback on EAGAIN teardown paths.
 * this is the transition ESTABLISHED -> FIN_WAIT_1.
 * */
START_TEST(test_sock_close_established_disarms_callback)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A0000A1U;
    uint16_t lport = 9100, rport = 41000;
    int sd = MARK_TCP_SOCKET;        /* tcpsockets[0] */
    int callback_arg = 0;            /* stand-in for the app's heap context */

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = setup_established_socket(&s, local_ip, remote_ip, lport, rport);
    wolfIP_register_callback(&s, sd, test_socket_cb, &callback_arg);

    /* Active close: FIN sent, FIN_WAIT_1, EAGAIN, callback disarmed. */
    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_1);
    ck_assert_ptr_null(ts->callback);
    ck_assert_ptr_null(ts->callback_arg);

    /* The app is now free to release callback_arg. Drive the remote FIN the
     * report relies on: seq == rcv_nxt, ack == snd_una (does not ack our FIN)
     * -> FIN_WAIT_1 transitions to CLOSING and raises the close events. */
    socket_cb_calls = 0;
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 100, 200, TCP_FLAG_ACK | TCP_FLAG_FIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSING);
    ck_assert_uint_ne(ts->events & (CB_EVENT_CLOSED | CB_EVENT_READABLE), 0);

    /* wolfIP_poll() Step 3 must not dispatch the disarmed callback. */
    (void)wolfIP_poll(&s, 1);
    ck_assert_int_eq(socket_cb_calls, 0);
}
END_TEST

/*
 * wolfIP_sock_close() must disarm the callback on EAGAIN teardown paths.
 * this is the transition CLOSE_WAIT -> LAST_ACK.
 * */
START_TEST(test_sock_close_close_wait_disarms_callback)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct pkt_desc *desc;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A0000A1U;
    uint16_t lport = 9101, rport = 41001;
    int sd = MARK_TCP_SOCKET;        /* tcpsockets[0] */
    int callback_arg = 0;            /* stand-in for the app's heap context */

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_CLOSE_WAIT;   /* remote FIN already received */
    ts->sock.tcp.ack = 100;                /* rcv_nxt */
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 120;                /* 20 bytes sent, unacked */
    ts->sock.tcp.last = 120;
    ts->sock.tcp.bytes_in_flight = 20;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    ts->sock.tcp.ssthresh = TCP_MSS * 8;
    ts->local_ip  = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port  = lport;
    ts->dst_port  = rport;
    ts->if_idx    = TEST_PRIMARY_IF;
    ts->sock.tcp.tmr_rto = NO_TIMER;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    arp_store_neighbor(&s, TEST_PRIMARY_IF, remote_ip, (uint8_t *)setup_peer_mac);

    /* Stage the 20 bytes of sent-but-unacked data (seq 100..119). */
    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 20);
    seg->hlen   = TCP_HEADER_LEN << 2;
    seg->seq    = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    wolfIP_register_callback(&s, sd, test_socket_cb, &callback_arg);

    /* Active close from CLOSE_WAIT: FIN sent (seq 120), LAST_ACK, EAGAIN,
     * callback disarmed. */
    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LAST_ACK);
    ck_assert_ptr_null(ts->callback);
    ck_assert_ptr_null(ts->callback_arg);

    /* Remote ACKs the data (ack=120) but not our FIN (would need 121): the
     * socket stays in LAST_ACK and tcp_ack raises CB_EVENT_WRITABLE. */
    socket_cb_calls = 0;
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip,
        rport, lport, 100, 120, TCP_FLAG_ACK);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LAST_ACK);
    ck_assert_uint_ne(ts->events & CB_EVENT_WRITABLE, 0);

    /* wolfIP_poll() Step 3 must not dispatch the disarmed callback. */
    (void)wolfIP_poll(&s, 1);
    ck_assert_int_eq(socket_cb_calls, 0);
}
END_TEST

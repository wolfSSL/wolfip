/* unit_tests_tcp_flow.c
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

START_TEST(test_tcp_ack_wraparound_delta_reduces_inflight)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg ackseg;
    uint32_t snd_una = 0xFFFFFFF0U;
    uint32_t ack = 0x00000010U;
    uint32_t pre_flight = 0x40U;
    uint32_t delta = 0x20U;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.snd_una = snd_una;
    ts->sock.tcp.seq = 0x00000020U;
    ts->sock.tcp.bytes_in_flight = pre_flight;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(ack);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, ack);
    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, pre_flight - delta);
}
END_TEST

START_TEST(test_tcp_ack_wraparound_delta_saturates_inflight)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg ackseg;
    uint32_t snd_una = 0xFFFFFFF0U;
    uint32_t ack = 0x00000010U;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.snd_una = snd_una;
    ts->sock.tcp.seq = 0x00000020U;
    ts->sock.tcp.bytes_in_flight = 8;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(ack);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, ack);
    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, 0);
}
END_TEST

START_TEST(test_tcp_mark_unsacked_for_retransmit_wrap_seg_end)
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
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 32);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(0xFFFFFFF0U);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    /* seg_end wraps to 0x10. With ack=0x10, segment should be treated as
     * fully acknowledged and thus not selected for retransmit. */
    ret = tcp_mark_unsacked_for_retransmit(ts, 0x00000010U);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_tcp_mark_unsacked_retransmits_partially_acked_segment)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf1;
    struct tcp_seg_buf segbuf2;
    struct wolfIP_tcp_seg *seg1;
    struct wolfIP_tcp_seg *seg2;
    struct pkt_desc *desc1, *desc2;
    int ret;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf1, 0, sizeof(segbuf1));
    seg1 = &segbuf1.seg;
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    seg1->hlen = TCP_HEADER_LEN << 2;
    seg1->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf1, sizeof(segbuf1)), 0);
    desc1 = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc1);
    desc1->flags |= PKT_FLAG_SENT;

    memset(&segbuf2, 0, sizeof(segbuf2));
    seg2 = &segbuf2.seg;
    seg2->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    seg2->hlen = TCP_HEADER_LEN << 2;
    seg2->seq = ee32(110);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf2, sizeof(segbuf2)), 0);
    desc2 = fifo_next(&ts->sock.tcp.txbuf, desc1);
    ck_assert_ptr_nonnull(desc2);
    desc2->flags |= PKT_FLAG_SENT;

    ret = tcp_mark_unsacked_for_retransmit(ts, 105);
    ck_assert_int_eq(ret, 1);
    ck_assert_int_eq(desc1->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc1->flags & PKT_FLAG_RETRANS, 0);
    ck_assert_int_ne(desc2->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_eq(desc2->flags & PKT_FLAG_RETRANS, 0);
}
END_TEST

START_TEST(test_tcp_mark_unsacked_rescans_after_clearing_stale_sack)
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
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.bytes_in_flight = 1;
    ts->sock.tcp.peer_sack_count = 1;
    ts->sock.tcp.peer_sack[0].left = 100;
    ts->sock.tcp.peer_sack[0].right = 101;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    /* First pass sees stale peer SACK covering the only hole and would skip it.
     * Function must clear SACK once and rescan, then mark the segment. */
    ret = tcp_mark_unsacked_for_retransmit(ts, 100);
    ck_assert_int_eq(ret, 1);
    ck_assert_uint_eq(ts->sock.tcp.peer_sack_count, 0);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc->flags & PKT_FLAG_RETRANS, 0);
}
END_TEST

START_TEST(test_tcp_mark_unsacked_ignores_zero_ip_len_unsent_ack_only_desc)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc1;
    struct pkt_desc *desc2;
    struct wolfIP_tcp_seg *seg1;
    int ret;
    uint8_t payload[4] = {0x21, 0x22, 0x23, 0x24};

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 100;
    ts->sock.tcp.bytes_in_flight = sizeof(payload);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 0, TCP_FLAG_ACK), 0);
    ck_assert_int_eq(enqueue_tcp_tx_with_payload(ts, payload, sizeof(payload),
            (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);

    desc1 = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc1);
    seg1 = (struct wolfIP_tcp_seg *)(ts->txmem + desc1->pos + sizeof(*desc1));
    seg1->ip.len = 0;
    seg1->seq = ee32(100);

    desc2 = fifo_next(&ts->sock.tcp.txbuf, desc1);
    ck_assert_ptr_nonnull(desc2);
    desc2->flags |= PKT_FLAG_SENT;

    ret = tcp_mark_unsacked_for_retransmit(ts, 100);
    ck_assert_int_eq(ret, 1);
    ck_assert_int_eq(desc2->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc2->flags & PKT_FLAG_RETRANS, 0);
}
END_TEST
START_TEST(test_tcp_ack_sack_blocks_clamped_and_dropped)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t ackbuf[sizeof(struct wolfIP_tcp_seg) + 12];
    struct wolfIP_tcp_seg *ackseg = (struct wolfIP_tcp_seg *)ackbuf;
    uint32_t left, right;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 1;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 200;

    memset(ackbuf, 0, sizeof(ackbuf));
    ackseg->ack = ee32(100);
    ackseg->hlen = (TCP_HEADER_LEN + 12) << 2;
    ackseg->flags = TCP_FLAG_ACK;
    ackseg->data[0] = TCP_OPTION_NOP;
    ackseg->data[1] = TCP_OPTION_NOP;
    ackseg->data[2] = TCP_OPTION_SACK;
    ackseg->data[3] = 10;
    left = ee32(50);
    right = ee32(250);
    memcpy(&ackseg->data[4], &left, sizeof(left));
    memcpy(&ackseg->data[8], &right, sizeof(right));
    tcp_ack(ts, ackseg);
    ck_assert_uint_eq(ts->sock.tcp.peer_sack_count, 1);
    ck_assert_uint_eq(ts->sock.tcp.peer_sack[0].left, 100);
    ck_assert_uint_eq(ts->sock.tcp.peer_sack[0].right, 200);

    left = ee32(10);
    right = ee32(90);
    memcpy(&ackseg->data[4], &left, sizeof(left));
    memcpy(&ackseg->data[8], &right, sizeof(right));
    tcp_ack(ts, ackseg);
    ck_assert_uint_eq(ts->sock.tcp.peer_sack_count, 0);
}
END_TEST

START_TEST(test_tcp_recv_ooo_capacity_limit)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t segbuf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)segbuf;
    uint8_t inbuf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *in = (struct wolfIP_tcp_seg *)inbuf;
    int i;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 1;
    ts->sock.tcp.ack = 100;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 100);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    for (i = 0; i < 5; i++) {
        memset(seg, 0, sizeof(segbuf));
        seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
        seg->hlen = TCP_HEADER_LEN << 2;
        seg->seq = ee32(101 + i);
        seg->data[0] = (uint8_t)('b' + i);
        tcp_recv(ts, seg);
    }
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 1);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].left, 101);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].right, 105);

    memset(in, 0, sizeof(inbuf));
    in->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    in->hlen = TCP_HEADER_LEN << 2;
    in->seq = ee32(100);
    in->data[0] = 'a';
    tcp_recv(ts, in);
    ck_assert_uint_eq(ts->sock.tcp.ack, 105);
}
END_TEST

START_TEST(test_tcp_recv_overlapping_ooo_segments_coalesce_on_consume)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg1buf[sizeof(struct wolfIP_tcp_seg) + 10];
    uint8_t seg2buf[sizeof(struct wolfIP_tcp_seg) + 10];
    uint8_t inbuf[sizeof(struct wolfIP_tcp_seg) + 10];
    struct wolfIP_tcp_seg *seg1 = (struct wolfIP_tcp_seg *)seg1buf;
    struct wolfIP_tcp_seg *seg2 = (struct wolfIP_tcp_seg *)seg2buf;
    struct wolfIP_tcp_seg *in = (struct wolfIP_tcp_seg *)inbuf;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 1;
    ts->sock.tcp.ack = 100;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 100);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(seg1, 0, sizeof(seg1buf));
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    seg1->hlen = TCP_HEADER_LEN << 2;
    seg1->seq = ee32(110);
    memcpy(seg1->data, "KLMNOPQRST", 10);
    tcp_recv(ts, seg1);

    memset(seg2, 0, sizeof(seg2buf));
    seg2->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    seg2->hlen = TCP_HEADER_LEN << 2;
    seg2->seq = ee32(115);
    memcpy(seg2->data, "PQRSTUVWXY", 10);
    tcp_recv(ts, seg2);

    memset(in, 0, sizeof(inbuf));
    in->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    in->hlen = TCP_HEADER_LEN << 2;
    in->seq = ee32(100);
    memcpy(in->data, "ABCDEFGHIJ", 10);
    tcp_recv(ts, in);
    ck_assert_uint_eq(ts->sock.tcp.ack, 125);
}
END_TEST

START_TEST(test_tcp_input_syn_with_sack_option_enables_sack)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct {
        uint8_t frame[sizeof(struct wolfIP_tcp_seg) + 4];
        uint8_t canary[8];
    } pkt;
    struct wolfIP_tcp_seg *syn = (struct wolfIP_tcp_seg *)pkt.frame;
    struct wolfIP_ll_dev *ll;
    union transport_pseudo_header ph;
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    memset(&pkt, 0, sizeof(pkt));
    memset(pkt.canary, 0xA5, sizeof(pkt.canary));
    memcpy(syn->ip.eth.dst, ll->mac, 6);
    syn->ip.eth.type = ee16(ETH_TYPE_IP);
    syn->ip.ver_ihl = 0x45;
    syn->ip.ttl = 64;
    syn->ip.proto = WI_IPPROTO_TCP;
    syn->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    syn->ip.src = ee32(0x0A0000A1U);
    syn->ip.dst = ee32(0x0A000001U);
    iphdr_set_checksum(&syn->ip);
    syn->src_port = ee16(40000);
    syn->dst_port = ee16(1234);
    syn->seq = ee32(1);
    syn->hlen = (TCP_HEADER_LEN + 4) << 2;
    syn->flags = TCP_FLAG_SYN;
    syn->win = ee16(65535);
    syn->data[0] = TCP_OPTION_SACK_PERMITTED;
    syn->data[1] = TCP_OPTION_SACK_PERMITTED_LEN;
    syn->data[2] = TCP_OPTION_NOP;
    syn->data[3] = TCP_OPTION_NOP;
    for (i = 0; i < (int)sizeof(pkt.canary); i++)
        ck_assert_uint_eq(pkt.canary[i], 0xA5);

    memset(&ph, 0, sizeof(ph));
    ph.ph.src = syn->ip.src;
    ph.ph.dst = syn->ip.dst;
    ph.ph.proto = WI_IPPROTO_TCP;
    ph.ph.len = ee16(TCP_HEADER_LEN + 4);
    syn->csum = ee16(transport_checksum(&ph, &syn->src_port));

    tcp_input(&s, TEST_PRIMARY_IF, syn,
            sizeof(struct wolfIP_eth_frame) + IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    ck_assert_uint_eq(ts->sock.tcp.sack_permitted, 1);
}
END_TEST

START_TEST(test_tcp_input_ignores_reserved_bits_in_hlen)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct {
        uint8_t frame[sizeof(struct wolfIP_tcp_seg) + 4];
    } pkt;
    struct wolfIP_tcp_seg *syn = (struct wolfIP_tcp_seg *)pkt.frame;
    struct wolfIP_ll_dev *ll;
    union transport_pseudo_header ph;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    memset(&pkt, 0, sizeof(pkt));
    memcpy(syn->ip.eth.dst, ll->mac, 6);
    syn->ip.eth.type = ee16(ETH_TYPE_IP);
    syn->ip.ver_ihl = 0x45;
    syn->ip.ttl = 64;
    syn->ip.proto = WI_IPPROTO_TCP;
    syn->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    syn->ip.src = ee32(0x0A0000A1U);
    syn->ip.dst = ee32(0x0A000001U);
    iphdr_set_checksum(&syn->ip);
    syn->src_port = ee16(40000);
    syn->dst_port = ee16(1234);
    syn->seq = ee32(1);
    syn->hlen = (uint8_t)(((TCP_HEADER_LEN + 4) << 2) | 0x0C);
    syn->flags = TCP_FLAG_SYN;
    syn->win = ee16(65535);
    syn->data[0] = TCP_OPTION_SACK_PERMITTED;
    syn->data[1] = TCP_OPTION_SACK_PERMITTED_LEN;
    syn->data[2] = TCP_OPTION_NOP;
    syn->data[3] = TCP_OPTION_NOP;

    memset(&ph, 0, sizeof(ph));
    ph.ph.src = syn->ip.src;
    ph.ph.dst = syn->ip.dst;
    ph.ph.proto = WI_IPPROTO_TCP;
    ph.ph.len = ee16(TCP_HEADER_LEN + 4);
    syn->csum = ee16(transport_checksum(&ph, &syn->src_port));

    tcp_input(&s, TEST_PRIMARY_IF, syn,
            sizeof(struct wolfIP_eth_frame) + IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    ck_assert_uint_eq(ts->sock.tcp.sack_permitted, 1);
}
END_TEST

START_TEST(test_tcp_input_syn_with_sack_option_respects_local_sack_offer)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct {
        uint8_t frame[sizeof(struct wolfIP_tcp_seg) + 4];
    } pkt;
    struct wolfIP_tcp_seg *syn = (struct wolfIP_tcp_seg *)pkt.frame;
    struct wolfIP_ll_dev *ll;
    union transport_pseudo_header ph;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ts->sock.tcp.sack_offer = 0;
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    memset(&pkt, 0, sizeof(pkt));
    memcpy(syn->ip.eth.dst, ll->mac, 6);
    syn->ip.eth.type = ee16(ETH_TYPE_IP);
    syn->ip.ver_ihl = 0x45;
    syn->ip.ttl = 64;
    syn->ip.proto = WI_IPPROTO_TCP;
    syn->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    syn->ip.src = ee32(0x0A0000A1U);
    syn->ip.dst = ee32(0x0A000001U);
    iphdr_set_checksum(&syn->ip);
    syn->src_port = ee16(40000);
    syn->dst_port = ee16(1234);
    syn->seq = ee32(1);
    syn->hlen = (TCP_HEADER_LEN + 4) << 2;
    syn->flags = TCP_FLAG_SYN;
    syn->win = ee16(65535);
    syn->data[0] = TCP_OPTION_SACK_PERMITTED;
    syn->data[1] = TCP_OPTION_SACK_PERMITTED_LEN;
    syn->data[2] = TCP_OPTION_NOP;
    syn->data[3] = TCP_OPTION_NOP;

    memset(&ph, 0, sizeof(ph));
    ph.ph.src = syn->ip.src;
    ph.ph.dst = syn->ip.dst;
    ph.ph.proto = WI_IPPROTO_TCP;
    ph.ph.len = ee16(TCP_HEADER_LEN + 4);
    syn->csum = ee16(transport_checksum(&ph, &syn->src_port));

    tcp_input(&s, TEST_PRIMARY_IF, syn,
            sizeof(struct wolfIP_eth_frame) + IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    ck_assert_uint_eq(ts->sock.tcp.sack_permitted, 0);
}
END_TEST

START_TEST(test_tcp_input_syn_listen_mismatch)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ts->bound_local_ip = 0x0A000001U;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A0000A1U, IPADDR_ANY, 40000, 1234, 1, 0, TCP_FLAG_SYN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
}
END_TEST

START_TEST(test_tcp_input_syn_sent_unexpected_flags)
{
    struct wolfIP s;
    struct tsocket *ts;
    int tcp_sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
    wolfIP_filter_set_tcp_mask(0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U, 4321, 1234, 10, 0, TCP_FLAG_SYN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);
}
END_TEST

START_TEST(test_tcp_input_syn_sent_synack_transitions)
{
    struct wolfIP s;
    struct tsocket *ts;
    int tcp_sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
    wolfIP_filter_set_tcp_mask(0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->sock.tcp.seq = 100;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U, 4321, 1234, 10, 101, (TCP_FLAG_SYN | TCP_FLAG_ACK));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.ack, 11);
}
END_TEST

START_TEST(test_tcp_input_syn_sent_synack_invalid_ack_rejected)
{
    struct wolfIP s;
    struct tsocket *ts;
    int tcp_sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
    wolfIP_filter_set_tcp_mask(0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->sock.tcp.seq = 100;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U,
            4321, 1234, 10, 999, (TCP_FLAG_SYN | TCP_FLAG_ACK));

    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);
}
END_TEST

START_TEST(test_tcp_input_syn_listen_does_not_scale_syn_window)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct {
        struct wolfIP_tcp_seg seg;
        uint8_t ws_opt[4];
    } syn;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];

    memset(&syn, 0, sizeof(syn));
    syn.seg.ip.ver_ihl = 0x45;
    syn.seg.ip.proto = WI_IPPROTO_TCP;
    syn.seg.ip.ttl = 64;
    syn.seg.ip.src = ee32(0x0A0000A1U);
    syn.seg.ip.dst = ee32(0x0A000001U);
    syn.seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    syn.seg.src_port = ee16(40000);
    syn.seg.dst_port = ee16(1234);
    syn.seg.seq = ee32(1);
    syn.seg.hlen = (TCP_HEADER_LEN + 4) << 2;
    syn.seg.flags = TCP_FLAG_SYN;
    syn.seg.win = ee16(29200);
    syn.ws_opt[0] = TCP_OPTION_WS;
    syn.ws_opt[1] = TCP_OPTION_WS_LEN;
    syn.ws_opt[2] = 7;
    syn.ws_opt[3] = TCP_OPTION_NOP;
    fix_tcp_checksums(&syn.seg);

    tcp_input(&s, TEST_PRIMARY_IF, &syn.seg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 4));

    ck_assert_uint_eq(ts->sock.tcp.ws_enabled, 1);
    ck_assert_uint_eq(ts->sock.tcp.snd_wscale, 7);
    ck_assert_uint_eq(ts->sock.tcp.peer_rwnd, 29200U);
}
END_TEST

START_TEST(test_tcp_input_syn_sent_does_not_scale_synack_window)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct {
        struct wolfIP_tcp_seg seg;
        uint8_t ws_opt[4];
    } synack;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->src_port = 23456;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5001);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);

    memset(&synack, 0, sizeof(synack));
    synack.seg.ip.ver_ihl = 0x45;
    synack.seg.ip.proto = WI_IPPROTO_TCP;
    synack.seg.ip.ttl = 64;
    synack.seg.ip.src = ee32(0x0A000002U);
    synack.seg.ip.dst = ee32(0x0A000001U);
    synack.seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    synack.seg.src_port = ee16(5001);
    synack.seg.dst_port = ee16(ts->src_port);
    synack.seg.seq = ee32(100);
    synack.seg.ack = ee32(ts->sock.tcp.seq + 1);
    synack.seg.hlen = (TCP_HEADER_LEN + 4) << 2;
    synack.seg.flags = (TCP_FLAG_SYN | TCP_FLAG_ACK);
    synack.seg.win = ee16(29200);
    synack.ws_opt[0] = TCP_OPTION_WS;
    synack.ws_opt[1] = TCP_OPTION_WS_LEN;
    synack.ws_opt[2] = 7;
    synack.ws_opt[3] = TCP_OPTION_NOP;
    fix_tcp_checksums(&synack.seg);

    tcp_input(&s, TEST_PRIMARY_IF, &synack.seg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 4));

    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.ws_enabled, 1);
    ck_assert_uint_eq(ts->sock.tcp.snd_wscale, 7);
    ck_assert_uint_eq(ts->sock.tcp.peer_rwnd, 29200U);
}
END_TEST

START_TEST(test_tcp_parse_sack_wraparound_block_accepted)
{
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 12];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct tcp_parsed_opts po;
    uint32_t left = 0xFFFFFFF0U;
    uint32_t right = 0x00000010U;
    uint8_t *opt;
    uint32_t frame_len;

    memset(seg_buf, 0, sizeof(seg_buf));
    seg->hlen = (uint8_t)((TCP_HEADER_LEN + 12) << 2);
    opt = seg->data;
    opt[0] = TCP_OPTION_SACK;
    opt[1] = 10;
    {
        uint32_t left_be = ee32(left);
        uint32_t right_be = ee32(right);
        memcpy(opt + 2, &left_be, sizeof(left_be));
        memcpy(opt + 6, &right_be, sizeof(right_be));
    }
    opt[10] = TCP_OPTION_NOP;
    opt[11] = TCP_OPTION_NOP;

    frame_len = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 12;
    tcp_parse_options(seg, frame_len, &po);

    ck_assert_int_eq(po.sack_count, 1);
    ck_assert_uint_eq(po.sack[0].left, left);
    ck_assert_uint_eq(po.sack[0].right, right);
}
END_TEST

START_TEST(test_tcp_parse_options_stops_on_truncated_or_invalid_option_length)
{
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct tcp_parsed_opts po;
    uint32_t frame_len;

    memset(seg_buf, 0, sizeof(seg_buf));
    seg->hlen = (uint8_t)((TCP_HEADER_LEN + 1) << 2);
    seg->data[0] = TCP_OPTION_WS;
    frame_len = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 1;
    tcp_parse_options(seg, frame_len, &po);
    ck_assert_int_eq(po.ws_found, 0);
    ck_assert_int_eq(po.mss_found, 0);

    memset(seg_buf, 0, sizeof(seg_buf));
    seg->hlen = (uint8_t)((TCP_HEADER_LEN + 2) << 2);
    seg->data[0] = TCP_OPTION_WS;
    seg->data[1] = 1;
    frame_len = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 2;
    tcp_parse_options(seg, frame_len, &po);
    ck_assert_int_eq(po.ws_found, 0);
    ck_assert_int_eq(po.mss_found, 0);
}
END_TEST

START_TEST(test_tcp_parse_options_returns_when_frame_has_no_option_bytes)
{
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct tcp_parsed_opts po;

    memset(seg_buf, 0, sizeof(seg_buf));
    seg->hlen = (uint8_t)((TCP_HEADER_LEN + 4) << 2);
    seg->data[0] = TCP_OPTION_WS;
    seg->data[1] = TCP_OPTION_WS_LEN;
    seg->data[2] = 4;

    tcp_parse_options(seg, sizeof(struct wolfIP_tcp_seg), &po);

    ck_assert_int_eq(po.ws_found, 0);
    ck_assert_int_eq(po.ts_found, 0);
    ck_assert_int_eq(po.sack_count, 0);
}
END_TEST

START_TEST(test_tcp_parse_options_parses_and_clamps_mixed_options)
{
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 32];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct tcp_parsed_opts po;
    uint8_t *opt;
    uint32_t ts_val = 0x01020304U;
    uint32_t ts_ecr = 0x05060708U;
    uint32_t frame_len;

    memset(seg_buf, 0, sizeof(seg_buf));
    seg->hlen = (uint8_t)((TCP_HEADER_LEN + 32) << 2);
    opt = seg->data;
    opt[0] = TCP_OPTION_WS;
    opt[1] = TCP_OPTION_WS_LEN;
    opt[2] = 20;
    opt += 3;
    opt[0] = TCP_OPTION_MSS;
    opt[1] = TCP_OPTION_MSS_LEN;
    opt[2] = 0;
    opt[3] = 0;
    opt += 4;
    opt[0] = TCP_OPTION_SACK_PERMITTED;
    opt[1] = TCP_OPTION_SACK_PERMITTED_LEN;
    opt += 2;
    opt[0] = TCP_OPTION_TS;
    opt[1] = TCP_OPTION_TS_LEN;
    {
        uint32_t be = ee32(ts_val);
        memcpy(opt + 2, &be, sizeof(be));
        be = ee32(ts_ecr);
        memcpy(opt + 6, &be, sizeof(be));
    }
    opt += 10;
    opt[0] = TCP_OPTION_SACK;
    opt[1] = 10;
    {
        uint32_t left = ee32(100U);
        uint32_t right = ee32(120U);
        memcpy(opt + 2, &left, sizeof(left));
        memcpy(opt + 6, &right, sizeof(right));
    }
    opt += 10;
    opt[0] = TCP_OPTION_NOP;
    opt[1] = TCP_OPTION_NOP;
    opt[2] = TCP_OPTION_EOO;
    frame_len = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 32;

    tcp_parse_options(seg, frame_len, &po);

    ck_assert_int_eq(po.ws_found, 1);
    ck_assert_uint_eq(po.ws_shift, 14);
    ck_assert_int_eq(po.mss_found, 0);
    ck_assert_int_eq(po.sack_permitted, 1);
    ck_assert_int_eq(po.ts_found, 1);
    ck_assert_uint_eq(po.ts_val, ts_val);
    ck_assert_uint_eq(po.ts_ecr, ts_ecr);
    ck_assert_int_eq(po.sack_count, 1);
    ck_assert_uint_eq(po.sack[0].left, 100U);
    ck_assert_uint_eq(po.sack[0].right, 120U);
}
END_TEST

START_TEST(test_tcp_parse_options_parses_mss_sack_permitted_timestamp_and_two_sack_blocks)
{
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 40];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct tcp_parsed_opts po;
    uint8_t *opt;
    uint32_t frame_len;

    memset(seg_buf, 0, sizeof(seg_buf));
    seg->hlen = (uint8_t)((TCP_HEADER_LEN + 36) << 2);
    opt = seg->data;
    opt[0] = TCP_OPTION_MSS;
    opt[1] = TCP_OPTION_MSS_LEN;
    opt[2] = 0x05;
    opt[3] = 0xB4;
    opt += 4;
    opt[0] = TCP_OPTION_SACK_PERMITTED;
    opt[1] = TCP_OPTION_SACK_PERMITTED_LEN;
    opt += 2;
    opt[0] = TCP_OPTION_TS;
    opt[1] = TCP_OPTION_TS_LEN;
    {
        uint32_t be = ee32(0x11121314U);
        memcpy(opt + 2, &be, sizeof(be));
        be = ee32(0x21222324U);
        memcpy(opt + 6, &be, sizeof(be));
    }
    opt += 10;
    opt[0] = TCP_OPTION_SACK;
    opt[1] = 18;
    {
        uint32_t left = ee32(100U), right = ee32(120U);
        memcpy(opt + 2, &left, sizeof(left));
        memcpy(opt + 6, &right, sizeof(right));
        left = ee32(140U);
        right = ee32(160U);
        memcpy(opt + 10, &left, sizeof(left));
        memcpy(opt + 14, &right, sizeof(right));
    }
    opt += 18;
    opt[0] = TCP_OPTION_NOP;
    opt[1] = TCP_OPTION_NOP;
    frame_len = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 36;

    tcp_parse_options(seg, frame_len, &po);

    ck_assert_int_eq(po.mss_found, 1);
    ck_assert_uint_eq(po.mss, 1460U);
    ck_assert_int_eq(po.sack_permitted, 1);
    ck_assert_int_eq(po.ts_found, 1);
    ck_assert_uint_eq(po.ts_val, 0x11121314U);
    ck_assert_uint_eq(po.ts_ecr, 0x21222324U);
    ck_assert_int_eq(po.sack_count, 2);
    ck_assert_uint_eq(po.sack[0].left, 100U);
    ck_assert_uint_eq(po.sack[0].right, 120U);
    ck_assert_uint_eq(po.sack[1].left, 140U);
    ck_assert_uint_eq(po.sack[1].right, 160U);
}
END_TEST

/* An explicitly advertised MSS is the peer's commitment about what it will
 * receive; the 536 default applies only when no MSS option is present. */
START_TEST(test_tcp_parse_options_keeps_sub_default_advertised_mss)
{
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct tcp_parsed_opts po;
    uint32_t frame_len;

    memset(seg_buf, 0, sizeof(seg_buf));
    seg->hlen = (uint8_t)((TCP_HEADER_LEN + 4) << 2);
    seg->data[0] = TCP_OPTION_MSS;
    seg->data[1] = TCP_OPTION_MSS_LEN;
    seg->data[2] = 0x01;
    seg->data[3] = 0x2C; /* 300 */
    frame_len = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 4;

    memset(&po, 0, sizeof(po));
    tcp_parse_options(seg, frame_len, &po);

    ck_assert_int_eq(po.mss_found, 1);
    ck_assert_uint_eq(po.mss, 300U);
}
END_TEST

START_TEST(test_tcp_parse_options_ignores_unknown_option_kinds)
{
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 8];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct tcp_parsed_opts po;
    uint32_t frame_len;

    memset(seg_buf, 0, sizeof(seg_buf));
    seg->hlen = (uint8_t)((TCP_HEADER_LEN + 4) << 2);
    seg->data[0] = 99;
    seg->data[1] = 4;
    seg->data[2] = 0xAA;
    seg->data[3] = 0xBB;
    frame_len = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 4;

    tcp_parse_options(seg, frame_len, &po);

    ck_assert_int_eq(po.ws_found, 0);
    ck_assert_int_eq(po.mss_found, 0);
    ck_assert_int_eq(po.sack_permitted, 0);
    ck_assert_int_eq(po.ts_found, 0);
    ck_assert_int_eq(po.sack_count, 0);
}
END_TEST

START_TEST(test_tcp_parse_options_caps_sack_block_count)
{
    /* TCP_SACK_MAX_BLOCKS equals the natural ceiling of SACK blocks that fit
     * in the 40-byte legal options budget (2-byte option header + 4*8 block
     * bytes = 34 bytes), so we exercise the MAX path with a compliant SACK
     * option carrying exactly TCP_SACK_MAX_BLOCKS blocks. */
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 36];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct tcp_parsed_opts po;
    uint8_t *opt;
    uint32_t frame_len;
    int i;

    memset(seg_buf, 0, sizeof(seg_buf));
    seg->hlen = (uint8_t)((TCP_HEADER_LEN + 36) << 2);
    opt = seg->data;
    opt[0] = TCP_OPTION_SACK;
    opt[1] = (uint8_t)(2 + (TCP_SACK_MAX_BLOCKS * 8));
    for (i = 0; i < TCP_SACK_MAX_BLOCKS; i++) {
        uint32_t left = ee32((uint32_t)(100 + (i * 20)));
        uint32_t right = ee32((uint32_t)(110 + (i * 20)));
        memcpy(opt + 2 + (i * 8), &left, sizeof(left));
        memcpy(opt + 2 + (i * 8) + 4, &right, sizeof(right));
    }
    opt[2 + (TCP_SACK_MAX_BLOCKS * 8)] = TCP_OPTION_NOP;
    opt[3 + (TCP_SACK_MAX_BLOCKS * 8)] = TCP_OPTION_NOP;
    frame_len = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 36;

    tcp_parse_options(seg, frame_len, &po);

    ck_assert_int_eq(po.sack_count, TCP_SACK_MAX_BLOCKS);
    ck_assert_uint_eq(po.sack[0].left, 100U);
    ck_assert_uint_eq(po.sack[TCP_SACK_MAX_BLOCKS - 1].right, 170U);
}
END_TEST

START_TEST(test_tcp_parse_options_ignores_known_kinds_with_wrong_lengths)
{
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 20];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct tcp_parsed_opts po;
    uint8_t *opt;
    uint32_t frame_len;

    memset(seg_buf, 0, sizeof(seg_buf));
    seg->hlen = (uint8_t)((TCP_HEADER_LEN + 14) << 2);
    opt = seg->data;
    opt[0] = TCP_OPTION_MSS;
    opt[1] = 3;
    opt[2] = 0x05;
    opt += 3;
    opt[0] = TCP_OPTION_SACK_PERMITTED;
    opt[1] = 3;
    opt[2] = 0x00;
    opt += 3;
    opt[0] = TCP_OPTION_TS;
    opt[1] = 8;
    memset(opt + 2, 0, 6);
    frame_len = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 14;

    tcp_parse_options(seg, frame_len, &po);

    ck_assert_int_eq(po.mss_found, 0);
    ck_assert_int_eq(po.sack_permitted, 0);
    ck_assert_int_eq(po.ts_found, 0);
    ck_assert_int_eq(po.sack_count, 0);
}
END_TEST

START_TEST(test_tcp_input_rst_bad_seq_ignored)
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
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    last_frame_sent_size = 0;
    memset(last_frame_sent, 0, sizeof(last_frame_sent));

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U,
            4321, 1234, 50, 0, TCP_FLAG_RST);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_int_eq(ts->proto, WI_IPPROTO_TCP);
    ck_assert_uint_eq(last_frame_sent_size, 0U);
    ck_assert_uint_eq(fifo_len(&ts->sock.tcp.txbuf), 0U);
}
END_TEST

START_TEST(test_tcp_input_rst_seq_in_window_sends_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg *sent;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    last_frame_sent_size = 0;
    memset(last_frame_sent, 0, sizeof(last_frame_sent));

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U,
            4321, 1234, 101, 0, TCP_FLAG_RST);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_gt(fifo_len(&ts->sock.tcp.txbuf), 0U);
    {
        struct pkt_desc *desc = fifo_peek(&ts->sock.tcp.txbuf);
        ck_assert_ptr_nonnull(desc);
        sent = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
        ck_assert_uint_eq(sent->flags & TCP_FLAG_ACK, TCP_FLAG_ACK);
    }
}
END_TEST

START_TEST(test_tcp_input_rst_seq_in_scaled_window_sends_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg *sent;
    uint32_t seg_seq;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.ws_enabled = 1;
    ts->sock.tcp.rcv_wscale = 2;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    last_frame_sent_size = 0;
    memset(last_frame_sent, 0, sizeof(last_frame_sent));

    seg_seq = ts->sock.tcp.ack + (RXBUF_SIZE >> 1);
    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U,
            4321, 1234, seg_seq, 0, TCP_FLAG_RST);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_gt(fifo_len(&ts->sock.tcp.txbuf), 0U);
    {
        struct pkt_desc *desc = fifo_peek(&ts->sock.tcp.txbuf);
        ck_assert_ptr_nonnull(desc);
        sent = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
        ck_assert_uint_eq(sent->flags & TCP_FLAG_ACK, TCP_FLAG_ACK);
    }
}
END_TEST

START_TEST(test_tcp_input_rst_out_of_window_does_not_update_peer_rwnd)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    union transport_pseudo_header ph;
    uint32_t initial_rwnd = 8000;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.ws_enabled = 1;
    ts->sock.tcp.snd_wscale = 2;
    ts->sock.tcp.peer_rwnd = initial_rwnd;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    memset(&seg, 0, sizeof(seg));
    seg.ip.ver_ihl = 0x45;
    seg.ip.ttl = 64;
    seg.ip.proto = WI_IPPROTO_TCP;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(ts->remote_ip);
    seg.ip.dst = ee32(ts->local_ip);
    seg.src_port = ee16(ts->dst_port);
    seg.dst_port = ee16(ts->src_port);
    seg.seq = ee32(50);
    seg.ack = 0;
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_RST;
    seg.win = ee16(1);
    fix_ip_checksum(&seg.ip);

    memset(&ph, 0, sizeof(ph));
    ph.ph.src = seg.ip.src;
    ph.ph.dst = seg.ip.dst;
    ph.ph.proto = WI_IPPROTO_TCP;
    ph.ph.len = ee16(TCP_HEADER_LEN);
    seg.csum = ee16(transport_checksum(&ph, &seg.src_port));

    tcp_input(&s, TEST_PRIMARY_IF, &seg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    ck_assert_uint_eq(ts->sock.tcp.peer_rwnd, initial_rwnd);
}
END_TEST

START_TEST(test_tcp_input_out_of_window_payload_not_cached)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    union transport_pseudo_header ph;
    uint32_t seq;
    uint8_t i;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    seq = ts->sock.tcp.ack + queue_space(&ts->sock.tcp.rxbuf);

    memset(seg_buf, 0, sizeof(seg_buf));
    memcpy(seg->ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(seg->ip.eth.src, "\x20\x21\x22\x23\x24\x25", 6);
    seg->ip.eth.type = ee16(ETH_TYPE_IP);
    seg->ip.ver_ihl = 0x45;
    seg->ip.ttl = 64;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->ip.src = ee32(ts->remote_ip);
    seg->ip.dst = ee32(ts->local_ip);
    fix_ip_checksum(&seg->ip);

    seg->src_port = ee16(ts->dst_port);
    seg->dst_port = ee16(ts->src_port);
    seg->seq = ee32(seq);
    seg->ack = 0;
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = TCP_FLAG_PSH;
    seg->win = ee16(65535);
    seg->data[0] = 0x5a;

    memset(&ph, 0, sizeof(ph));
    ph.ph.src = seg->ip.src;
    ph.ph.dst = seg->ip.dst;
    ph.ph.proto = WI_IPPROTO_TCP;
    ph.ph.len = ee16(TCP_HEADER_LEN + 1);
    seg->csum = ee16(transport_checksum(&ph, &seg->src_port));

    tcp_input(&s, TEST_PRIMARY_IF, seg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 1));

    ck_assert_uint_eq(queue_len(&ts->sock.tcp.rxbuf), 0U);
    for (i = 0; i < TCP_OOO_MAX_SEGS; i++) {
        ck_assert_uint_eq(ts->sock.tcp.ooo[i].used, 0);
    }
}
END_TEST

START_TEST(test_tcp_input_rst_exact_seq_closes)
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
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U,
            4321, 1234, 100, 0, TCP_FLAG_RST);

    ck_assert_int_eq(ts->proto, 0);
}
END_TEST

START_TEST(test_tcp_input_iplen_too_big)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;

    memset(&seg, 0, sizeof(seg));
    seg.ip.len = ee16(2000);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(ts->dst_port);
    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

/* Checksum validation tests */
START_TEST(test_tcp_checksum_valid_passes)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    /* Construct valid packet with correct checksums */
    memset(&seg, 0, sizeof(seg));
    seg.ip.ver_ihl = 0x45;
    seg.ip.ttl = 64;
    seg.ip.proto = WI_IPPROTO_TCP;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(ts->remote_ip);
    seg.ip.dst = ee32(ts->local_ip);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(ts->dst_port);
    seg.seq = ee32(100);
    seg.ack = ee32(50);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_ACK;
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    /* Valid checksum should update ack (packet accepted) */
    ck_assert_uint_eq(ts->sock.tcp.ack, 100);
}
END_TEST

START_TEST(test_tcp_checksum_invalid_rejected)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    /* Construct packet with correct structure but wrong checksum */
    memset(&seg, 0, sizeof(seg));
    seg.ip.ver_ihl = 0x45;
    seg.ip.ttl = 64;
    seg.ip.proto = WI_IPPROTO_TCP;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(ts->remote_ip);
    seg.ip.dst = ee32(ts->local_ip);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(ts->dst_port);
    seg.seq = ee32(100);
    seg.ack = ee32(50);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_ACK;
    fix_tcp_checksums(&seg);
    /* Corrupt the TCP checksum */
    seg.csum ^= 0x1234;

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    /* Invalid checksum should be rejected (ack unchanged) */
    ck_assert_uint_eq(ts->sock.tcp.ack, 100);
}
END_TEST

START_TEST(test_udp_checksum_valid_passes)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_udp_datagram udp;
    struct wolfIP_ll_dev *ll;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    /* Create and bind UDP socket */
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    /* Construct valid UDP packet with correct checksums */
    memset(&udp, 0, sizeof(udp));
    memcpy(udp.ip.eth.dst, ll->mac, 6);
    udp.ip.eth.type = ee16(ETH_TYPE_IP);
    udp.ip.ver_ihl = 0x45;
    udp.ip.ttl = 64;
    udp.ip.proto = WI_IPPROTO_UDP;
    udp.ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    udp.ip.src = ee32(0x0A000002U);
    udp.ip.dst = ee32(0x0A000001U);
    udp.src_port = ee16(5678);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN);
    fix_udp_checksums(&udp);

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN));
    /* Valid checksum should accept packet */
    ck_assert_uint_gt(fifo_len(&ts->sock.udp.rxbuf), 0U);
}
END_TEST

START_TEST(test_udp_checksum_invalid_rejected)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_udp_datagram udp;
    struct wolfIP_ll_dev *ll;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    /* Create and bind UDP socket */
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    /* Construct UDP packet with wrong checksum */
    memset(&udp, 0, sizeof(udp));
    memcpy(udp.ip.eth.dst, ll->mac, 6);
    udp.ip.eth.type = ee16(ETH_TYPE_IP);
    udp.ip.ver_ihl = 0x45;
    udp.ip.ttl = 64;
    udp.ip.proto = WI_IPPROTO_UDP;
    udp.ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    udp.ip.src = ee32(0x0A000002U);
    udp.ip.dst = ee32(0x0A000001U);
    udp.src_port = ee16(5678);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN);
    fix_udp_checksums(&udp);
    /* Corrupt the UDP checksum */
    udp.csum ^= 0x5678;

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN));
    /* Invalid checksum should be rejected */
    ck_assert_uint_eq(fifo_len(&ts->sock.udp.rxbuf), 0U);
}
END_TEST

START_TEST(test_udp_checksum_zero_accepted)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_udp_datagram udp;
    struct wolfIP_ll_dev *ll;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    /* Create and bind UDP socket */
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    /* Construct UDP packet with zero checksum (disabled per RFC) */
    memset(&udp, 0, sizeof(udp));
    memcpy(udp.ip.eth.dst, ll->mac, 6);
    udp.ip.eth.type = ee16(ETH_TYPE_IP);
    udp.ip.ver_ihl = 0x45;
    udp.ip.ttl = 64;
    udp.ip.proto = WI_IPPROTO_UDP;
    udp.ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    udp.ip.src = ee32(0x0A000002U);
    udp.ip.dst = ee32(0x0A000001U);
    iphdr_set_checksum(&udp.ip);
    udp.src_port = ee16(5678);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN);
    udp.csum = 0;  /* Zero checksum means "not computed" per RFC 768 */

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN));
    /* Zero checksum should be accepted (validation skipped) */
    ck_assert_uint_gt(fifo_len(&ts->sock.udp.rxbuf), 0U);
}
END_TEST

START_TEST(test_regression_udp_recv_sets_last_pkt_ttl)
{
    struct wolfIP s;
    int udp_sd;
    int enable = 1;
    int recv_ttl = 0;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_udp_datagram udp;
    struct wolfIP_ll_dev *ll;
    static const uint8_t test_ttl = 42;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_RECVTTL, &enable, sizeof(enable)), 0);

    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    memset(&udp, 0, sizeof(udp));
    memcpy(udp.ip.eth.dst, ll->mac, 6);
    udp.ip.eth.type = ee16(ETH_TYPE_IP);
    udp.ip.ver_ihl = 0x45;
    udp.ip.ttl = test_ttl;
    udp.ip.proto = WI_IPPROTO_UDP;
    udp.ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    udp.ip.src = ee32(0x0A000002U);
    udp.ip.dst = ee32(0x0A000001U);
    udp.src_port = ee16(5678);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN);
    fix_udp_checksums(&udp);

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, &udp,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN));

    ck_assert_uint_gt(fifo_len(&s.udpsockets[SOCKET_UNMARK(udp_sd)].sock.udp.rxbuf),
            0U);
    ck_assert_int_eq(wolfIP_sock_get_recv_ttl(&s, udp_sd, &recv_ttl), 1);
    ck_assert_int_eq(recv_ttl, (int)test_ttl);
}
END_TEST

START_TEST(test_regression_tcp_input_sets_last_pkt_ttl)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    int recv_ttl = 0;
    int sd;
    static const uint8_t test_ttl = 33;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->recv_ttl = 1;

    memset(&seg, 0, sizeof(seg));
    seg.ip.ver_ihl = 0x45;
    seg.ip.ttl = test_ttl;
    seg.ip.proto = WI_IPPROTO_TCP;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(ts->remote_ip);
    seg.ip.dst = ee32(ts->local_ip);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(ts->dst_port);
    seg.seq = ee32(100);
    seg.ack = ee32(50);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_ACK;
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    ck_assert_uint_eq(ts->last_pkt_ttl, test_ttl);

    sd = (int)((ts - s.tcpsockets) | MARK_TCP_SOCKET);
    ck_assert_int_eq(wolfIP_sock_get_recv_ttl(&s, sd, &recv_ttl), 1);
    ck_assert_int_eq(recv_ttl, (int)test_ttl);
}
END_TEST

START_TEST(test_udp_connected_rejects_wrong_source_ip)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {1, 2, 3, 4};
    uint8_t rxbuf[8];
    ip4 local_ip = 0x0A000001U;
    ip4 connected_ip = 0x0A000002U;
    ip4 other_ip = 0x0A000099U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(local_ip);
    ck_assert_int_eq(wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5678);
    sin.sin_addr.s_addr = ee32(connected_ip);
    ck_assert_int_eq(wolfIP_sock_connect(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    inject_udp_datagram(&s, TEST_PRIMARY_IF, other_ip, local_ip, 5678, 1234,
            payload, (uint16_t)sizeof(payload));

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL),
            -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_ip_checksum_invalid_rejected)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_udp_datagram udp;
    struct wolfIP_ll_dev *ll;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    /* Create and bind UDP socket */
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    /* Construct UDP packet with invalid IP checksum */
    memset(&udp, 0, sizeof(udp));
    memcpy(udp.ip.eth.dst, ll->mac, 6);
    udp.ip.eth.type = ee16(ETH_TYPE_IP);
    udp.ip.ver_ihl = 0x45;
    udp.ip.ttl = 64;
    udp.ip.proto = WI_IPPROTO_UDP;
    udp.ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    udp.ip.src = ee32(0x0A000002U);
    udp.ip.dst = ee32(0x0A000001U);
    iphdr_set_checksum(&udp.ip);
    /* Corrupt the IP checksum */
    udp.ip.csum ^= 0xABCD;
    udp.src_port = ee16(5678);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN);
    udp.csum = 0;

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN));
    /* Invalid IP checksum should be rejected */
    ck_assert_uint_eq(fifo_len(&ts->sock.udp.rxbuf), 0U);
}
END_TEST

START_TEST(test_ip_checksum_valid_passes)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_udp_datagram udp;
    struct wolfIP_ll_dev *ll;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    /* Create and bind UDP socket */
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    /* Construct UDP packet with valid IP checksum */
    memset(&udp, 0, sizeof(udp));
    memcpy(udp.ip.eth.dst, ll->mac, 6);
    udp.ip.eth.type = ee16(ETH_TYPE_IP);
    udp.ip.ver_ihl = 0x45;
    udp.ip.ttl = 64;
    udp.ip.proto = WI_IPPROTO_UDP;
    udp.ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    udp.ip.src = ee32(0x0A000002U);
    udp.ip.dst = ee32(0x0A000001U);
    iphdr_set_checksum(&udp.ip);
    udp.src_port = ee16(5678);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN);
    udp.csum = 0;  /* Zero checksum is valid per RFC 768 */

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN));
    /* Valid IP checksum should accept packet */
    ck_assert_uint_gt(fifo_len(&ts->sock.udp.rxbuf), 0U);
}
END_TEST

START_TEST(test_tcp_ack_acks_data_and_sets_writable)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint8_t payload[1] = { TCP_OPTION_EOO };
    uint32_t seq = 100;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.ssthresh = TCP_MSS * 4;
    /* Ensure cwnd growth is gated by bytes_in_flight and not rwnd-capped. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(seg, 0, sizeof(seg_buf));
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    seg->flags = TCP_FLAG_ACK;
    memcpy(seg->data, payload, sizeof(payload));
    fifo_push(&ts->sock.tcp.txbuf, seg, sizeof(seg_buf));
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    desc->time_sent = 10;
    /* Simulate cwnd-limited flight and initialize snd_una. */
    ts->sock.tcp.bytes_in_flight = TCP_MSS;
    ts->sock.tcp.snd_una = seq;
    ts->sock.tcp.seq = seq + TCP_MSS;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq + sizeof(payload));
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    /* FIFO should be empty after acked data is removed. */
    ck_assert_ptr_eq(fifo_peek(&ts->sock.tcp.txbuf), NULL);
    ck_assert_uint_eq(ts->events & CB_EVENT_WRITABLE, CB_EVENT_WRITABLE);
    ck_assert_uint_gt(ts->sock.tcp.cwnd, TCP_MSS);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_resend_clears_sent)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq = 200;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.ssthresh = TCP_MSS * 4;
    /* Allow duplicate-ACK path without rwnd cap. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(seg, 0, sizeof(seg_buf));
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    seg->flags = TCP_FLAG_ACK;
    seg->data[0] = TCP_OPTION_EOO;
    fifo_push(&ts->sock.tcp.txbuf, seg, sizeof(seg_buf));
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq + 1000);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_tcp_ack_discards_zero_len_segment)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(100);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.tcp.txbuf), NULL);
}
END_TEST

START_TEST(test_tcp_ack_closes_last_ack_socket)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq = 100;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LAST_ACK;
    ts->sock.tcp.last = seq;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq + 1);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_int_eq(ts->proto, 0);
}
END_TEST

START_TEST(test_tcp_ack_last_seq_match_no_close)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq = 200;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.last = seq;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_int_eq(ts->proto, WI_IPPROTO_TCP);
}
END_TEST

START_TEST(test_tcp_ack_fresh_desc_updates_rtt_existing)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq = 300;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.ssthresh = TCP_MSS * 4;
    ts->sock.tcp.rtt = 50;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    s.last_tick = 1000;

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    seg->data[0] = TCP_OPTION_EOO;
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    desc->time_sent = 900;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq + 1);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_gt(ts->sock.tcp.rtt, 0);
    ck_assert_uint_eq(ts->events & CB_EVENT_WRITABLE, CB_EVENT_WRITABLE);
}
END_TEST

START_TEST(test_tcp_ack_retransmitted_desc_skips_rtt_update)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq = 300;
    uint32_t old_rtt;
    uint32_t old_rto;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    s.last_tick = 1000;

    tcp_rto_update_from_sample(ts, 200);
    old_rtt = ts->sock.tcp.rtt;
    old_rto = ts->sock.tcp.rto;

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    seg->data[0] = TCP_OPTION_EOO;
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    desc->flags |= PKT_FLAG_WAS_RETRANS;
    desc->time_sent = 800;
    ts->sock.tcp.bytes_in_flight = 1;
    ts->sock.tcp.snd_una = seq;
    ts->sock.tcp.seq = seq + 1;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq + 1);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.rtt, old_rtt);
    ck_assert_uint_eq(ts->sock.tcp.rto, old_rto);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_zero_len_segment_large_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf1;
    struct tcp_seg_buf segbuf2;
    struct wolfIP_tcp_seg *seg1;
    struct wolfIP_tcp_seg *seg2;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.ssthresh = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf1, 0, sizeof(segbuf1));
    seg1 = &segbuf1.seg;
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 2000);
    seg1->hlen = TCP_HEADER_LEN << 2;
    seg1->seq = ee32(400);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf1, sizeof(segbuf1)), 0);

    memset(&segbuf2, 0, sizeof(segbuf2));
    seg2 = &segbuf2.seg;
    seg2->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg2->hlen = TCP_HEADER_LEN << 2;
    seg2->seq = ee32(500);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf2, sizeof(segbuf2)), 0);

    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    desc = fifo_next(&ts->sock.tcp.txbuf, desc);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    /* Force duplicate ACK handling with outstanding bytes. */
    ts->sock.tcp.bytes_in_flight = TCP_MSS * 2;
    /* Treat this ACK as a duplicate (snd_una == ack). */
    ts->sock.tcp.snd_una = 0xF0000000U;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(0xF0000000U);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    /* Prime dup-ack counter so a single ACK triggers fast retransmit. */
    ts->sock.tcp.dup_acks = 2;
    tcp_ack(ts, &ackseg);
    ck_assert_uint_le(fifo_len(&ts->sock.tcp.txbuf), TXBUF_SIZE);
    ck_assert_uint_eq(ts->sock.tcp.ssthresh, TCP_MSS * 2);
    /* RFC 5681 §3.2: cwnd = ssthresh + 3*SMSS on entering fast recovery */
    ck_assert_uint_eq(ts->sock.tcp.cwnd, TCP_MSS * 5);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_seq_match_large_seg_len)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq = 500;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    /* Allow duplicate-ACK path without rwnd cap. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 2000);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    /* Force duplicate ACK handling with outstanding bytes. */
    ts->sock.tcp.bytes_in_flight = TCP_MSS * 2;
    ts->sock.tcp.snd_una = seq;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    /* Trigger fast retransmit by delivering three duplicate ACKs. */
    tcp_ack(ts, &ackseg);
    tcp_ack(ts, &ackseg);
    tcp_ack(ts, &ackseg);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, PKT_FLAG_SENT);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_clears_sent_flag)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf1;
    struct tcp_seg_buf segbuf2;
    struct wolfIP_tcp_seg *seg1;
    struct wolfIP_tcp_seg *seg2;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq1 = 100;
    uint32_t seq2 = 200;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf1, 0, sizeof(segbuf1));
    seg1 = &segbuf1.seg;
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg1->hlen = TCP_HEADER_LEN << 2;
    seg1->seq = ee32(seq1);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf1, sizeof(segbuf1)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&segbuf2, 0, sizeof(segbuf2));
    seg2 = &segbuf2.seg;
    seg2->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg2->hlen = TCP_HEADER_LEN << 2;
    seg2->seq = ee32(seq2);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf2, sizeof(segbuf2)), 0);

    /* Force duplicate ACK handling with outstanding bytes. */
    ts->sock.tcp.bytes_in_flight = TCP_MSS * 2;
    ts->sock.tcp.snd_una = seq1;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq1);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    /* Prime dup-ack counter so a single ACK triggers fast retransmit. */
    ts->sock.tcp.dup_acks = 2;
    tcp_ack(ts, &ackseg);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_discards_zero_len_segment)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf1;
    struct tcp_seg_buf segbuf2;
    struct wolfIP_tcp_seg *seg1;
    struct wolfIP_tcp_seg *seg2;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf1, 0, sizeof(segbuf1));
    seg1 = &segbuf1.seg;
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg1->hlen = TCP_HEADER_LEN << 2;
    seg1->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf1, sizeof(segbuf1)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&segbuf2, 0, sizeof(segbuf2));
    seg2 = &segbuf2.seg;
    seg2->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg2->hlen = TCP_HEADER_LEN << 2;
    seg2->seq = ee32(200);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf2, sizeof(segbuf2)), 0);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(50);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    {
        struct wolfIP_tcp_seg *cur = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
        ck_assert_uint_eq(ee32(cur->seq), 200U);
    }
}
END_TEST

START_TEST(test_tcp_ack_progress_resets_rto_recovery_state)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    struct wolfIP_timer tmr;
    uint32_t seq = 100;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.ssthresh = 2 * TCP_MSS;
    ts->sock.tcp.seq = seq + 64;
    ts->sock.tcp.snd_una = seq;
    ts->sock.tcp.bytes_in_flight = TCP_MSS;
    ts->sock.tcp.rto_backoff = 4;
    ts->sock.tcp.dup_acks = 2;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    seg->data[0] = TCP_OPTION_EOO;
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    desc->time_sent = 10;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 1000;
    ts->sock.tcp.tmr_rto = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq + 1);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);

    ck_assert_uint_eq(ts->sock.tcp.snd_una, seq + 1);
    ck_assert_uint_eq(ts->sock.tcp.rto_backoff, 0);
    ck_assert_uint_eq(ts->sock.tcp.dup_acks, 0);
    /* Forward ACK clears recovery backoff, but if data is still in-flight
     * the sender must keep an RTO armed so loss recovery can continue. */
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_gt(ts->sock.tcp.cwnd, TCP_MSS);
}
END_TEST

START_TEST(test_tcp_ack_cwnd_grows_when_payload_acked_is_mss_minus_options)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t payload = TCP_MSS - TCP_OPTIONS_LEN;
    uint32_t seq = 100;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.ssthresh = TCP_MSS * 8;
    ts->sock.tcp.snd_una = seq;
    ts->sock.tcp.seq = seq + payload;
    ts->sock.tcp.bytes_in_flight = payload;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + payload);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq + payload);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.cwnd, TCP_MSS * 2);
}
END_TEST

/* RFC 5681: a duplicate ACK carries no data and repeats the previously
 * advertised receive window. Peer data segments that do not advance our
 * snd_una (normal in bidirectional transfer) must not inflate the dup
 * count into a spurious fast retransmit. */
START_TEST(test_tcp_ack_data_segments_not_counted_as_dup_acks)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct pkt_desc *desc;
    uint8_t pbuf[sizeof(struct wolfIP_tcp_seg) + 8];
    struct wolfIP_tcp_seg *pseg = (struct wolfIP_tcp_seg *)pbuf;
    uint32_t seq = 1000;
    int i;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.ssthresh = TCP_MSS * 8;
    ts->sock.tcp.snd_una = seq;
    ts->sock.tcp.seq = seq + TCP_MSS;
    ts->sock.tcp.bytes_in_flight = TCP_MSS;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* One in-flight segment so the dup-ACK branch is reachable. */
    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + TCP_MSS);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    /* Three peer data segments, none acknowledging the in-flight one. */
    memset(pbuf, 0, sizeof(pbuf));
    pseg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 8);
    pseg->hlen = TCP_HEADER_LEN << 2;
    pseg->flags = TCP_FLAG_ACK;
    pseg->win = ee16(65535);
    pseg->ack = ee32(seq);
    memset(pseg->data, 0x5A, 8);
    for (i = 0; i < 3; i++) {
        pseg->seq = ee32(500 + i * 8);
        tcp_ack(ts, pseg);
    }

    ck_assert_uint_eq(ts->sock.tcp.dup_acks, 0);
    ck_assert_int_eq(ts->sock.tcp.fast_recovery, 0);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, seq);
    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, TCP_MSS);
}
END_TEST

/* RFC 6298 §5.5: on a retransmission timeout the new RTO is min(2*RTO, G)
 * with G the maximum timer value, 64 s. With a 2 s base RTO and six
 * backoff doublings the uncapped interval would be 128 s; the re-armed
 * timer must land at 64 s. */
START_TEST(test_tcp_rto_backoff_capped_at_64s)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct pkt_desc *desc;
    uint64_t now = 100000;
    uint32_t seq = 1000;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.snd_una = seq;
    ts->sock.tcp.seq = seq + TCP_MSS;
    ts->sock.tcp.bytes_in_flight = TCP_MSS;
    ts->sock.tcp.rto = 2000;
    ts->sock.tcp.rto_backoff = 6;
    ts->sock.tcp.tmr_rto = NO_TIMER;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* In-flight segment covering snd_una so the timeout retransmits and
     * re-arms the RTO timer. */
    memset(&segbuf, 0, sizeof(segbuf));
    segbuf.seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + TCP_MSS);
    segbuf.seg.hlen = TCP_HEADER_LEN << 2;
    segbuf.seg.seq = ee32(seq);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    s.last_tick = now;
    tcp_rto_cb(ts);

    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
    {
        uint32_t armed_expires = 0;
        int found = 0;
        int i;
        for (i = 0; i < (int)s.timers.size; i++) {
            if (s.timers.timers[i].id == ts->sock.tcp.tmr_rto) {
                armed_expires = s.timers.timers[i].expires;
                found = 1;
                break;
            }
        }
        ck_assert_int_eq(found, 1);
        ck_assert_uint_eq(armed_expires, now + TCP_RTO_BACKOFF_MAX_MS);
    }
}
END_TEST

START_TEST(test_tcp_ack_inflight_deflate_sets_writable_without_acked_desc)
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
    ts->sock.tcp.bytes_in_flight = 64;
    ts->events = 0;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(120);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, 120U);
    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, 44U);
    ck_assert_uint_eq(ts->events & CB_EVENT_WRITABLE, CB_EVENT_WRITABLE);
}
END_TEST

START_TEST(test_tcp_input_peer_rwnd_growth_sets_writable)
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
    ts->src_port = 5001;
    ts->dst_port = 40000;
    ts->local_ip = 0xC0A80102U;
    ts->remote_ip = 0xC0A80104U;
    ts->sock.tcp.seq = 200;
    ts->sock.tcp.snd_una = 150;
    ts->sock.tcp.ack = 1234;
    ts->sock.tcp.peer_rwnd = 0;
    ts->events = 0;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ip.ver_ihl = 0x45;
    ackseg.ip.proto = WI_IPPROTO_TCP;
    ackseg.ip.src = ee32(ts->remote_ip);
    ackseg.ip.dst = ee32(ts->local_ip);
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ackseg.ip.ttl = 64;
    ackseg.src_port = ee16(ts->dst_port);
    ackseg.dst_port = ee16(ts->src_port);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    ackseg.ack = ee32(ts->sock.tcp.snd_una);
    ackseg.win = ee16(8);
    fix_tcp_checksums(&ackseg);

    tcp_input(&s, TEST_PRIMARY_IF, &ackseg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    ck_assert_uint_eq(ts->sock.tcp.peer_rwnd, 8U);
    ck_assert_uint_eq(ts->events & CB_EVENT_WRITABLE, CB_EVENT_WRITABLE);
}
END_TEST

START_TEST(test_tcp_input_synack_negotiates_peer_mss)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct {
        struct wolfIP_tcp_seg seg;
        uint8_t mss_opt[4];
    } synack;
    uint16_t mss_be;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->src_port = 23456;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5001);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);

    memset(&synack, 0, sizeof(synack));
    synack.seg.ip.ver_ihl = 0x45;
    synack.seg.ip.proto = WI_IPPROTO_TCP;
    synack.seg.ip.ttl = 64;
    synack.seg.ip.src = ee32(0x0A000002U);
    synack.seg.ip.dst = ee32(0x0A000001U);
    synack.seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    synack.seg.src_port = ee16(5001);
    synack.seg.dst_port = ee16(ts->src_port);
    synack.seg.seq = ee32(100);
    synack.seg.ack = ee32(ts->sock.tcp.seq + 1);
    synack.seg.hlen = (TCP_HEADER_LEN + 4) << 2;
    synack.seg.flags = (TCP_FLAG_SYN | TCP_FLAG_ACK);
    synack.seg.win = ee16(65535);
    synack.mss_opt[0] = TCP_OPTION_MSS;
    synack.mss_opt[1] = TCP_OPTION_MSS_LEN;
    /* Above the RFC 9293 §3.7.1 floor (536), so it is recorded verbatim. */
    mss_be = ee16(1000);
    memcpy(&synack.mss_opt[2], &mss_be, sizeof(mss_be));
    fix_tcp_checksums(&synack.seg);

    tcp_input(&s, TEST_PRIMARY_IF, &synack.seg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 4));

    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.peer_mss, 1000U);
}
END_TEST

START_TEST(test_tcp_connect_syn_advertises_interface_mss)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg *syn;
    struct tcp_parsed_opts po;
    uint16_t expected_mss;

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF, 640U), 0);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5004);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);

    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    syn = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
    ck_assert_uint_eq((uint32_t)(syn->flags & TCP_FLAG_SYN), TCP_FLAG_SYN);

    memset(&po, 0, sizeof(po));
    tcp_parse_options(syn, desc->len, &po);
    expected_mss = (uint16_t)(640U - ETH_HEADER_LEN - IP_HEADER_LEN - TCP_HEADER_LEN);
    ck_assert_int_eq(po.mss_found, 1);
    ck_assert_uint_eq(po.mss, expected_mss);
}
END_TEST

/* A TCP active OPEN has no defined destination semantics for broadcast or
 * multicast addresses (multiple hosts would answer one SYN; there is no
 * single peer for a group). connect() must reject them before mutating the
 * socket, the same way the inbound SYN path rejects such sources. */
START_TEST(test_tcp_connect_rejects_broadcast_multicast_dest)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5004);

    /* Limited broadcast. */
    sin.sin_addr.s_addr = ee32(0xFFFFFFFFU);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSED);
    ck_assert_uint_eq(ts->remote_ip, 0U);

    /* All-hosts multicast group. */
    sin.sin_addr.s_addr = ee32(0xE0000001U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSED);
    ck_assert_uint_eq(ts->remote_ip, 0U);

    /* The socket is reusable: a unicast destination still proceeds. */
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);
}
END_TEST

START_TEST(test_tcp_connect_syn_limits_options_to_small_mtu)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg *syn;
    struct tcp_parsed_opts po;
    uint32_t mtu = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF, 64U), 0);
    ck_assert_int_eq(wolfIP_mtu_get(&s, TEST_PRIMARY_IF, &mtu), 0);
    ck_assert_uint_eq(mtu, 64U);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5006);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);

    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_le(desc->len, mtu);
    syn = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));

    memset(&po, 0, sizeof(po));
    tcp_parse_options(syn, desc->len, &po);
    ck_assert_int_eq(po.mss_found, 1);
    ck_assert_int_eq(po.ws_found, 1);
    ck_assert_int_eq(po.sack_permitted, 0);
    ck_assert_int_eq(po.ts_found, 0);
}
END_TEST

START_TEST(test_sock_sendto_tcp_respects_negotiated_peer_mss)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct {
        struct wolfIP_tcp_seg seg;
        uint8_t mss_opt[4];
    } synack;
    uint16_t mss_be;
    uint8_t payload[1200];
    int ret;
    struct pkt_desc *desc;
    int seg_count = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->src_port = 23457;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5002);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);

    memset(&synack, 0, sizeof(synack));
    synack.seg.ip.ver_ihl = 0x45;
    synack.seg.ip.proto = WI_IPPROTO_TCP;
    synack.seg.ip.ttl = 64;
    synack.seg.ip.src = ee32(0x0A000002U);
    synack.seg.ip.dst = ee32(0x0A000001U);
    synack.seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    synack.seg.src_port = ee16(5002);
    synack.seg.dst_port = ee16(ts->src_port);
    synack.seg.seq = ee32(100);
    synack.seg.ack = ee32(ts->sock.tcp.seq + 1);
    synack.seg.hlen = (TCP_HEADER_LEN + 4) << 2;
    synack.seg.flags = (TCP_FLAG_SYN | TCP_FLAG_ACK);
    synack.seg.win = ee16(65535);
    synack.mss_opt[0] = TCP_OPTION_MSS;
    synack.mss_opt[1] = TCP_OPTION_MSS_LEN;
    /* Above the RFC 9293 §3.7.1 floor (536) so it is recorded verbatim, yet
     * below our own interface MSS so it still binds tcp_tx_payload_cap(); a
     * 1200-byte payload then splits into >=3 segments (ceil(1200/560)=3). */
    mss_be = ee16(560);
    memcpy(&synack.mss_opt[2], &mss_be, sizeof(mss_be));
    fix_tcp_checksums(&synack.seg);

    tcp_input(&s, TEST_PRIMARY_IF, &synack.seg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 4));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);

    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    memset(payload, 0xA5, sizeof(payload));
    ret = wolfIP_sock_sendto(&s, tcp_sd, payload, sizeof(payload), 0, NULL, 0);
    ck_assert_int_eq(ret, (int)sizeof(payload));

    desc = fifo_peek(&ts->sock.tcp.txbuf);
    while (desc != NULL) {
        struct wolfIP_tcp_seg *seg;
        uint32_t seg_payload;
        uint32_t hdr_len;
        uint32_t opt_len;
        uint32_t base_len;

        seg = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
        hdr_len = (uint32_t)(seg->hlen >> 2);
        ck_assert_uint_ge(hdr_len, TCP_HEADER_LEN);
        opt_len = hdr_len - TCP_HEADER_LEN;
        base_len = (uint32_t)(sizeof(struct wolfIP_tcp_seg) + opt_len);
        ck_assert_uint_ge(desc->len, base_len);
        seg_payload = desc->len - base_len;
        ck_assert_uint_le(seg_payload, 560U);

        seg_count++;
        desc = fifo_next(&ts->sock.tcp.txbuf, desc);
    }
    ck_assert_int_ge(seg_count, 3);
}
END_TEST

START_TEST(test_sock_sendto_tcp_defaults_to_rfc_mss_when_unset_by_peer)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_tcp_seg synack;
    uint8_t payload[1200];
    int ret;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->src_port = 23458;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5003);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);

    memset(&synack, 0, sizeof(synack));
    synack.ip.ver_ihl = 0x45;
    synack.ip.proto = WI_IPPROTO_TCP;
    synack.ip.ttl = 64;
    synack.ip.src = ee32(0x0A000002U);
    synack.ip.dst = ee32(0x0A000001U);
    synack.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    synack.src_port = ee16(5003);
    synack.dst_port = ee16(ts->src_port);
    synack.seq = ee32(100);
    synack.ack = ee32(ts->sock.tcp.seq + 1);
    synack.hlen = TCP_HEADER_LEN << 2;
    synack.flags = (TCP_FLAG_SYN | TCP_FLAG_ACK);
    synack.win = ee16(65535);
    fix_tcp_checksums(&synack);

    tcp_input(&s, TEST_PRIMARY_IF, &synack,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);

    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    memset(payload, 0x5A, sizeof(payload));
    ret = wolfIP_sock_sendto(&s, tcp_sd, payload, sizeof(payload), 0, NULL, 0);
    ck_assert_int_eq(ret, (int)sizeof(payload));

    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    while (desc != NULL) {
        struct wolfIP_tcp_seg *seg;
        uint32_t seg_payload;
        uint32_t hdr_len;
        uint32_t opt_len;
        uint32_t base_len;

        seg = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
        hdr_len = (uint32_t)(seg->hlen >> 2);
        ck_assert_uint_ge(hdr_len, TCP_HEADER_LEN);
        opt_len = hdr_len - TCP_HEADER_LEN;
        base_len = (uint32_t)(sizeof(struct wolfIP_tcp_seg) + opt_len);
        ck_assert_uint_ge(desc->len, base_len);
        seg_payload = desc->len - base_len;
        ck_assert_uint_le(seg_payload, TCP_DEFAULT_MSS);

        desc = fifo_next(&ts->sock.tcp.txbuf, desc);
    }
}
END_TEST

START_TEST(test_sock_sendto_tcp_respects_interface_mtu)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_tcp_seg synack;
    uint8_t payload[700];
    int ret;
    struct pkt_desc *desc;
    uint32_t max_payload;
    int seg_count = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF, 320U), 0);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->src_port = 23459;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5005);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);

    memset(&synack, 0, sizeof(synack));
    synack.ip.ver_ihl = 0x45;
    synack.ip.proto = WI_IPPROTO_TCP;
    synack.ip.ttl = 64;
    synack.ip.src = ee32(0x0A000002U);
    synack.ip.dst = ee32(0x0A000001U);
    synack.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    synack.src_port = ee16(5005);
    synack.dst_port = ee16(ts->src_port);
    synack.seq = ee32(100);
    synack.ack = ee32(ts->sock.tcp.seq + 1);
    synack.hlen = TCP_HEADER_LEN << 2;
    synack.flags = (TCP_FLAG_SYN | TCP_FLAG_ACK);
    synack.win = ee16(65535);
    fix_tcp_checksums(&synack);

    tcp_input(&s, TEST_PRIMARY_IF, &synack,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);

    max_payload = wolfIP_socket_tcp_mss(ts);
    ck_assert_uint_gt(max_payload, TCP_OPTIONS_LEN);
    max_payload -= TCP_OPTIONS_LEN;

    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    memset(payload, 0x3C, sizeof(payload));
    ret = wolfIP_sock_sendto(&s, tcp_sd, payload, sizeof(payload), 0, NULL, 0);
    ck_assert_int_eq(ret, (int)sizeof(payload));

    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    while (desc != NULL) {
        struct wolfIP_tcp_seg *seg;
        uint32_t seg_payload;
        uint32_t hdr_len;
        uint32_t base_len;

        seg = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
        hdr_len = (uint32_t)(seg->hlen >> 2);
        base_len = (uint32_t)(sizeof(struct wolfIP_tcp_seg) + (hdr_len - TCP_HEADER_LEN));
        ck_assert_uint_ge(desc->len, base_len);
        seg_payload = desc->len - base_len;
        ck_assert_uint_le(seg_payload, max_payload);

        seg_count++;
        desc = fifo_next(&ts->sock.tcp.txbuf, desc);
    }
    ck_assert_int_ge(seg_count, 3);
}
END_TEST

START_TEST(test_tcp_input_syn_rcvd_ack_established)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_tcp_seg ackseg;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ip.ver_ihl = 0x45;
    ackseg.ip.proto = WI_IPPROTO_TCP;
    ackseg.ip.ttl = 64;
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ackseg.ip.src = ee32(ts->remote_ip);
    ackseg.ip.dst = ee32(ts->local_ip);
    ackseg.dst_port = ee16(ts->src_port);
    ackseg.src_port = ee16(ts->dst_port);
    ackseg.seq = ee32(ts->sock.tcp.ack);
    ackseg.ack = ee32(ts->sock.tcp.seq + 1);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    fix_tcp_checksums(&ackseg);
    tcp_input(&s, TEST_PRIMARY_IF, &ackseg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

START_TEST(test_tcp_input_syn_rcvd_ack_invalid_ack_rejected)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_tcp_seg ackseg;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ip.ver_ihl = 0x45;
    ackseg.ip.proto = WI_IPPROTO_TCP;
    ackseg.ip.ttl = 64;
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ackseg.ip.src = ee32(ts->remote_ip);
    ackseg.ip.dst = ee32(ts->local_ip);
    ackseg.dst_port = ee16(ts->src_port);
    ackseg.src_port = ee16(ts->dst_port);
    ackseg.seq = ee32(ts->sock.tcp.ack);
    ackseg.ack = ee32(ts->sock.tcp.seq + 2);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    fix_tcp_checksums(&ackseg);
    tcp_input(&s, TEST_PRIMARY_IF, &ackseg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
}
END_TEST

START_TEST(test_tcp_input_syn_rcvd_high_seq_valid_ack_establishes)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_tcp_seg ackseg;
    uint32_t rcv_nxt;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
    rcv_nxt = ts->sock.tcp.ack;

    /* ACK with a valid acknowledgment number and a sequence one above
     * RCV.NXT (inside the receive window): per RFC 9293 this completes
     * the handshake and the segment is held for later processing - the
     * old exact-match check reset the connection here. */
    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ip.ver_ihl = 0x45;
    ackseg.ip.proto = WI_IPPROTO_TCP;
    ackseg.ip.ttl = 64;
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ackseg.ip.src = ee32(ts->remote_ip);
    ackseg.ip.dst = ee32(ts->local_ip);
    ackseg.dst_port = ee16(ts->src_port);
    ackseg.src_port = ee16(ts->dst_port);
    ackseg.seq = ee32(rcv_nxt + 1);
    ackseg.ack = ee32(ts->sock.tcp.seq + 1);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    fix_tcp_checksums(&ackseg);
    tcp_input(&s, TEST_PRIMARY_IF, &ackseg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    /* Nothing contiguous arrived: RCV.NXT must not skip the hole. */
    ck_assert_uint_eq(ts->sock.tcp.ack, rcv_nxt);
}
END_TEST

START_TEST(test_tcp_input_syn_rcvd_high_seq_data_held_ooo)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 10];
    struct wolfIP_tcp_seg *dataseg = (struct wolfIP_tcp_seg *)seg_buf;
    uint32_t rcv_nxt;
    uint8_t out[32];

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
    rcv_nxt = ts->sock.tcp.ack;

    /* The peer's first data segment (8 bytes) reorders ahead of the final
     * ACK: seq = RCV.NXT + 10, valid acknowledgment number. */
    memset(seg_buf, 0, sizeof(seg_buf));
    dataseg->ip.ver_ihl = 0x45;
    dataseg->ip.proto = WI_IPPROTO_TCP;
    dataseg->ip.ttl = 64;
    dataseg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 8);
    dataseg->ip.src = ee32(ts->remote_ip);
    dataseg->ip.dst = ee32(ts->local_ip);
    dataseg->dst_port = ee16(ts->src_port);
    dataseg->src_port = ee16(ts->dst_port);
    dataseg->seq = ee32(rcv_nxt + 10);
    dataseg->ack = ee32(tcp_seq_inc(ts->sock.tcp.snd_una, 1));
    dataseg->hlen = TCP_HEADER_LEN << 2;
    dataseg->flags = TCP_FLAG_ACK;
    memcpy(dataseg->data, "ABCDEFGH", 8);
    fix_tcp_checksums(dataseg);
    tcp_input(&s, TEST_PRIMARY_IF, dataseg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 8));
    /* Handshake completes on the valid ACK; the data is OOO-cached and
     * RCV.NXT must not skip the 10-byte hole. */
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.ack, rcv_nxt);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 1);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].left, rcv_nxt + 10);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].right, rcv_nxt + 18);

    /* The missing 10 bytes arrive in order and pull in the cached tail. */
    memset(seg_buf, 0, sizeof(seg_buf));
    dataseg->ip.ver_ihl = 0x45;
    dataseg->ip.proto = WI_IPPROTO_TCP;
    dataseg->ip.ttl = 64;
    dataseg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    dataseg->ip.src = ee32(ts->remote_ip);
    dataseg->ip.dst = ee32(ts->local_ip);
    dataseg->dst_port = ee16(ts->src_port);
    dataseg->src_port = ee16(ts->dst_port);
    dataseg->seq = ee32(rcv_nxt);
    dataseg->ack = ee32(tcp_seq_inc(ts->sock.tcp.snd_una, 1));
    dataseg->hlen = TCP_HEADER_LEN << 2;
    dataseg->flags = TCP_FLAG_ACK;
    memcpy(dataseg->data, "0123456789", 10);
    fix_tcp_checksums(dataseg);
    tcp_input(&s, TEST_PRIMARY_IF, dataseg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 10));
    ck_assert_uint_eq(ts->sock.tcp.ack, rcv_nxt + 18);
    ck_assert_int_eq(queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out)), 18);
    ck_assert_mem_eq(out, "0123456789ABCDEFGH", 18);
}
END_TEST

/* A data+FIN segment that reorders ahead of the final ACK completes the
 * handshake but must NOT enter CLOSE_WAIT: the FIN sits above the receive
 * hole, so it is deferred (ACK only). When the hole fills, RCV.NXT reaches
 * the FIN's sequence number and the cumulative ACK makes the peer
 * retransmit the segment; the retransmit is then accepted and the socket
 * moves to CLOSE_WAIT. */
START_TEST(test_tcp_input_syn_rcvd_fin_above_hole_deferred)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 10];
    struct wolfIP_tcp_seg *dataseg = (struct wolfIP_tcp_seg *)seg_buf;
    uint32_t rcv_nxt;
    uint8_t out[32];

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
    rcv_nxt = ts->sock.tcp.ack;

    /* data+FIN (8 bytes) reorders ahead of the final ACK: seq = RCV.NXT + 10,
     * valid acknowledgment number. */
    memset(seg_buf, 0, sizeof(seg_buf));
    dataseg->ip.ver_ihl = 0x45;
    dataseg->ip.proto = WI_IPPROTO_TCP;
    dataseg->ip.ttl = 64;
    dataseg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 8);
    dataseg->ip.src = ee32(ts->remote_ip);
    dataseg->ip.dst = ee32(ts->local_ip);
    dataseg->dst_port = ee16(ts->src_port);
    dataseg->src_port = ee16(ts->dst_port);
    dataseg->seq = ee32(rcv_nxt + 10);
    dataseg->ack = ee32(tcp_seq_inc(ts->sock.tcp.snd_una, 1));
    dataseg->hlen = TCP_HEADER_LEN << 2;
    dataseg->flags = TCP_FLAG_ACK | TCP_FLAG_FIN;
    memcpy(dataseg->data, "ABCDEFGH", 8);
    fix_tcp_checksums(dataseg);
    tcp_input(&s, TEST_PRIMARY_IF, dataseg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 8));
    /* Handshake completes on the valid ACK; the data is OOO-cached and the
     * FIN above the hole must be deferred: ESTABLISHED, not CLOSE_WAIT. */
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.ack, rcv_nxt);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 1);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].left, rcv_nxt + 10);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].right, rcv_nxt + 18);

    /* The missing 10 bytes arrive in order and pull in the cached tail.
     * RCV.NXT reaches the FIN's sequence number, but the FIN bit was not
     * recorded: the socket must stay ESTABLISHED. */
    memset(seg_buf, 0, sizeof(seg_buf));
    dataseg->ip.ver_ihl = 0x45;
    dataseg->ip.proto = WI_IPPROTO_TCP;
    dataseg->ip.ttl = 64;
    dataseg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    dataseg->ip.src = ee32(ts->remote_ip);
    dataseg->ip.dst = ee32(ts->local_ip);
    dataseg->dst_port = ee16(ts->src_port);
    dataseg->src_port = ee16(ts->dst_port);
    dataseg->seq = ee32(rcv_nxt);
    dataseg->ack = ee32(tcp_seq_inc(ts->sock.tcp.snd_una, 1));
    dataseg->hlen = TCP_HEADER_LEN << 2;
    dataseg->flags = TCP_FLAG_ACK;
    memcpy(dataseg->data, "0123456789", 10);
    fix_tcp_checksums(dataseg);
    tcp_input(&s, TEST_PRIMARY_IF, dataseg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 10));
    ck_assert_uint_eq(ts->sock.tcp.ack, rcv_nxt + 18);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 0);
    ck_assert_int_eq(queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out)), 18);
    ck_assert_mem_eq(out, "0123456789ABCDEFGH", 18);

    /* The peer retransmits the data+FIN (its cumulative ACK shows the FIN
     * unacknowledged). The payload is a pure duplicate; the FIN now sits
     * exactly at RCV.NXT and completes the close. */
    memset(seg_buf, 0, sizeof(seg_buf));
    dataseg->ip.ver_ihl = 0x45;
    dataseg->ip.proto = WI_IPPROTO_TCP;
    dataseg->ip.ttl = 64;
    dataseg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 8);
    dataseg->ip.src = ee32(ts->remote_ip);
    dataseg->ip.dst = ee32(ts->local_ip);
    dataseg->dst_port = ee16(ts->src_port);
    dataseg->src_port = ee16(ts->dst_port);
    dataseg->seq = ee32(rcv_nxt + 10);
    dataseg->ack = ee32(tcp_seq_inc(ts->sock.tcp.snd_una, 1));
    dataseg->hlen = TCP_HEADER_LEN << 2;
    dataseg->flags = TCP_FLAG_ACK | TCP_FLAG_FIN;
    memcpy(dataseg->data, "ABCDEFGH", 8);
    fix_tcp_checksums(dataseg);
    tcp_input(&s, TEST_PRIMARY_IF, dataseg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 8));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSE_WAIT);
    ck_assert_uint_eq(ts->sock.tcp.ack, rcv_nxt + 19);
}
END_TEST

START_TEST(test_tcp_input_syn_rcvd_out_of_window_ack_drop)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_tcp_seg ackseg;
    uint32_t rcv_nxt;
    uint32_t rcv_wnd;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
    rcv_nxt = ts->sock.tcp.ack;
    rcv_wnd = queue_space((struct queue *)&ts->sock.tcp.rxbuf);

    /* ACK-only segment whose sequence is beyond the receive window:
     * RFC 9293 says acknowledge and drop, do not reset. */
    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ip.ver_ihl = 0x45;
    ackseg.ip.proto = WI_IPPROTO_TCP;
    ackseg.ip.ttl = 64;
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ackseg.ip.src = ee32(ts->remote_ip);
    ackseg.ip.dst = ee32(ts->local_ip);
    ackseg.dst_port = ee16(ts->src_port);
    ackseg.src_port = ee16(ts->dst_port);
    ackseg.seq = ee32(rcv_nxt + rcv_wnd + 100);
    ackseg.ack = ee32(ts->sock.tcp.seq + 1);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    fix_tcp_checksums(&ackseg);
    last_frame_sent_size = 0;
    tcp_input(&s, TEST_PRIMARY_IF, &ackseg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    /* Out of window: ACK and drop, no state change. RSTs are sent
     * immediately (they bypass the TX queue), so a clean wire right after
     * tcp_input proves no reset was generated. */
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(ts->sock.tcp.ack, rcv_nxt);
    ck_assert_uint_eq(last_frame_sent_size, 0U);
    /* The acknowledgment is queued for the TX flush, behind the parked
     * SYN-ACK: verify the second entry is an ACK, not a RST. */
    {
        struct pkt_desc *pd = fifo_peek(&ts->sock.tcp.txbuf);
        struct pkt_desc *pd2 = fifo_next(&ts->sock.tcp.txbuf, pd);
        const struct wolfIP_tcp_seg *f;
        ck_assert_ptr_nonnull(pd);
        ck_assert_ptr_nonnull(pd2);
        f = (const struct wolfIP_tcp_seg *)(pd2 + 1);
        ck_assert_uint_eq(f->flags & (TCP_FLAG_ACK | TCP_FLAG_RST),
                          TCP_FLAG_ACK);
    }
}
END_TEST

/* Regression (F-6473 follow-up): the first peer timestamp must seed
 * TS.Recent unconditionally. last_ts starts zeroed, which is not a
 * timestamp: the RFC 7323 4.3 update gate compares the SYN's TSval
 * against it, and a TSval in the upper half of the 32-bit space (the
 * common case for real kernel clocks) compares as "older" than zero,
 * so TS.Recent never got seeded. Every later segment then failed
 * tcp_paws_check as an old duplicate and was dropped with a bare ACK -
 * the handshake completed but no data ever flowed (dup-ACK loop).
 * Values mirror a captured failure: SYN TSval 0xE0600D2C. */
START_TEST(test_tcp_input_paws_upper_half_tsval_flows)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN + 10];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct tcp_opt_ts *opt = (struct tcp_opt_ts *)seg->data;
    uint32_t rcv_nxt;
    uint8_t out[32];

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    /* SYN with a Timestamps option in the upper half of the 32-bit
     * space - compares as "older" than the zeroed last_ts. */
    memset(seg_buf, 0, sizeof(seg_buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.ttl = 64;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + TCP_OPTIONS_LEN);
    seg->ip.src = ee32(0x0A000002U);
    seg->ip.dst = ee32(0x0A000001U);
    seg->src_port = ee16(52798);
    seg->dst_port = ee16(1234);
    seg->seq = ee32(0);
    seg->hlen = (TCP_HEADER_LEN + TCP_OPTIONS_LEN) << 2;
    seg->flags = TCP_FLAG_SYN;
    opt->opt = TCP_OPTION_TS;
    opt->len = TCP_OPTION_TS_LEN;
    opt->val = ee32(0xE0600D2CU);
    opt->ecr = 0;
    opt->pad = TCP_OPTION_NOP;
    opt->eoo = TCP_OPTION_EOO;
    fix_tcp_checksums(seg);
    tcp_input(&s, TEST_PRIMARY_IF, seg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN +
                       TCP_HEADER_LEN + TCP_OPTIONS_LEN));
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
    /* The SYN must have seeded TS.Recent despite the upper-half value. */
    ck_assert_uint_eq(ts->sock.tcp.ts_recent_valid, 1);
    ck_assert_uint_eq(ts->sock.tcp.last_ts, ee32(0xE0600D2CU));
    rcv_nxt = ts->sock.tcp.ack;

    /* Final ACK, same clock (still upper half). */
    memset(seg_buf, 0, sizeof(seg_buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.ttl = 64;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + TCP_OPTIONS_LEN);
    seg->ip.src = ee32(0x0A000002U);
    seg->ip.dst = ee32(0x0A000001U);
    seg->src_port = ee16(52798);
    seg->dst_port = ee16(1234);
    seg->seq = ee32(rcv_nxt);
    seg->ack = ee32(tcp_seq_inc(ts->sock.tcp.snd_una, 1));
    seg->hlen = (TCP_HEADER_LEN + TCP_OPTIONS_LEN) << 2;
    seg->flags = TCP_FLAG_ACK;
    opt->opt = TCP_OPTION_TS;
    opt->len = TCP_OPTION_TS_LEN;
    opt->val = ee32(0xE0600D2EU);
    opt->ecr = 0;
    opt->pad = TCP_OPTION_NOP;
    opt->eoo = TCP_OPTION_EOO;
    fix_tcp_checksums(seg);
    tcp_input(&s, TEST_PRIMARY_IF, seg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN +
                       TCP_HEADER_LEN + TCP_OPTIONS_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);

    /* First data segment: pre-fix this was dropped by tcp_paws_check as
     * "older than TS.Recent" (zeroed) and the connection stalled in a
     * dup-ACK loop. */
    memset(seg_buf, 0, sizeof(seg_buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.ttl = 64;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + TCP_OPTIONS_LEN + 10);
    seg->ip.src = ee32(0x0A000002U);
    seg->ip.dst = ee32(0x0A000001U);
    seg->src_port = ee16(52798);
    seg->dst_port = ee16(1234);
    seg->seq = ee32(rcv_nxt);
    seg->ack = ee32(tcp_seq_inc(ts->sock.tcp.snd_una, 1));
    seg->hlen = (TCP_HEADER_LEN + TCP_OPTIONS_LEN) << 2;
    seg->flags = TCP_FLAG_ACK;
    opt->opt = TCP_OPTION_TS;
    opt->len = TCP_OPTION_TS_LEN;
    opt->val = ee32(0xE0600D32U);
    opt->ecr = 0;
    opt->pad = TCP_OPTION_NOP;
    opt->eoo = TCP_OPTION_EOO;
    memcpy(seg->data + TCP_OPTIONS_LEN, "0123456789", 10);
    fix_tcp_checksums(seg);
    tcp_input(&s, TEST_PRIMARY_IF, seg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN +
                       TCP_HEADER_LEN + TCP_OPTIONS_LEN + 10));
    ck_assert_uint_eq(ts->sock.tcp.ack, rcv_nxt + 10);
    ck_assert_int_eq(queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out)), 10);
    ck_assert_mem_eq(out, "0123456789", 10);
}
END_TEST

/* Regression: an ACK+FIN segment in SYN_RCVD must not be silently discarded.
 * The ACK should complete the handshake (to ESTABLISHED) and the FIN should
 * be processed in the same pass (to CLOSE_WAIT).  Per RFC 9293 section 3.10.7.4
 * the ACK field must be processed regardless of other control flags. */
START_TEST(test_tcp_input_syn_rcvd_ack_fin_transitions_to_close_wait)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_tcp_seg seg;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);

    /* Send ACK+FIN with valid seq/ack */
    memset(&seg, 0, sizeof(seg));
    seg.ip.ver_ihl = 0x45;
    seg.ip.proto = WI_IPPROTO_TCP;
    seg.ip.ttl = 64;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(ts->remote_ip);
    seg.ip.dst = ee32(ts->local_ip);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(ts->dst_port);
    seg.seq = ee32(ts->sock.tcp.ack);
    seg.ack = ee32(ts->sock.tcp.seq + 1);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_ACK | TCP_FLAG_FIN;
    fix_tcp_checksums(&seg);
    tcp_input(&s, TEST_PRIMARY_IF, &seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    /* The ACK must have completed the handshake and the FIN must have
     * been processed, landing in CLOSE_WAIT. */
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSE_WAIT);
}
END_TEST

START_TEST(test_tcp_recv_queues_payload_and_advances_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_timer tmr;
    uint8_t payload[3] = { 'a', 'b', 'c' };
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + sizeof(payload)];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    uint32_t seq = 50;
    int ret;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = seq;
    ts->sock.tcp.bytes_in_flight = 1;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, seq);

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 100;
    ts->sock.tcp.tmr_rto = timers_binheap_insert(&s.timers, tmr);

    memset(seg, 0, sizeof(seg_buf));
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    seg->flags = (TCP_FLAG_ACK | TCP_FLAG_PSH);
    memcpy(seg->data, payload, sizeof(payload));

    tcp_recv(ts, seg);
    ck_assert_uint_eq(ts->sock.tcp.ack, seq + sizeof(payload));
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, CB_EVENT_READABLE);
    /* RFC 6298: RTO is sender-side; receiving data must not cancel it. */
    ck_assert_uint_ne(ts->sock.tcp.tmr_rto, NO_TIMER);

    {
        uint8_t out[4] = {0};
        ret = queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out));
        ck_assert_int_eq(ret, (int)sizeof(payload));
        ck_assert_mem_eq(out, payload, sizeof(payload));
    }
}
END_TEST

START_TEST(test_tcp_recv_ignores_reserved_bits_in_hlen)
{
    /* RFC 9293 3.1: the low nibble of the Data Offset byte is Rsrvd and MUST
     * be ignored. tcp_recv must therefore base its payload pointer and length
     * on the masked (high-nibble) header length, otherwise a peer that sets
     * reserved bits would have its delivered bytes shifted by 4*Rsrvd octets. */
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t payload[8] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' };
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + sizeof(payload)];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    uint32_t seq = 50;
    uint8_t out[sizeof(payload) + 4];
    int ret;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = seq;
    ts->sock.tcp.bytes_in_flight = 1;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, seq);

    memset(seg, 0, sizeof(seg_buf));
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    /* No options (hdr is the bare 20 bytes), but flip every reserved bit on. */
    seg->hlen = (uint8_t)((TCP_HEADER_LEN << 2) | 0x0F);
    seg->seq = ee32(seq);
    seg->flags = (TCP_FLAG_ACK | TCP_FLAG_PSH);
    memcpy(seg->data, payload, sizeof(payload));

    tcp_recv(ts, seg);

    ck_assert_uint_eq(ts->sock.tcp.ack, seq + sizeof(payload));
    memset(out, 0, sizeof(out));
    ret = queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out));
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(out, payload, sizeof(payload));
}
END_TEST

START_TEST(test_tcp_recv_wrong_state_does_nothing)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->sock.tcp.ack = 10;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);

    memset(&seg, 0, sizeof(seg));
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.seq = ee32(10);

    tcp_recv(ts, &seg);
    ck_assert_uint_eq(queue_len(&ts->sock.tcp.rxbuf), 0);
    ck_assert_uint_eq(ts->sock.tcp.ack, 10);
}
END_TEST

START_TEST(test_tcp_recv_ack_mismatch_does_nothing)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 10;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);

    memset(seg_buf, 0, sizeof(seg_buf));
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(11);

    tcp_recv(ts, seg);
    ck_assert_uint_eq(queue_len(&ts->sock.tcp.rxbuf), 0U);
}
END_TEST

START_TEST(test_tcp_recv_wrap_seq_ahead_not_trimmed)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 0xFFFFFFF0U;
    ts->sock.tcp.sack_permitted = 1;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(seg, 0, sizeof(seg_buf));
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(0x00000010U); /* numerically lower, but ahead across wrap */
    seg->data[0] = 0x5A;

    tcp_recv(ts, seg);
    ck_assert_uint_eq(ts->sock.tcp.ack, 0xFFFFFFF0U);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 1);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].left, 0x00000010U);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].right, 0x00000011U);
}
END_TEST

START_TEST(test_tcp_recv_close_wait_ack_match)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;

    wolfIP_init(&s);
    ts = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    ts->sock.tcp.ack = 100;

    memset(buf, 0, sizeof(buf));
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    seg->data[0] = 0x5a;

    tcp_recv(ts, seg);
    ck_assert_uint_eq(ts->sock.tcp.ack, 101);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, CB_EVENT_READABLE);
}
END_TEST

START_TEST(test_tcp_recv_fin_wait_1_ack_match)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;

    wolfIP_init(&s);
    ts = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ts->sock.tcp.ack = 100;

    memset(buf, 0, sizeof(buf));
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    seg->data[0] = 0x5a;

    tcp_recv(ts, seg);
    ck_assert_uint_eq(ts->sock.tcp.ack, 101);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, CB_EVENT_READABLE);
}
END_TEST

START_TEST(test_tcp_recv_fin_wait_2_ack_match)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;

    wolfIP_init(&s);
    ts = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->sock.tcp.state = TCP_FIN_WAIT_2;
    ts->sock.tcp.ack = 100;

    memset(buf, 0, sizeof(buf));
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    seg->data[0] = 0x5a;

    tcp_recv(ts, seg);
    ck_assert_uint_eq(ts->sock.tcp.ack, 101);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, CB_EVENT_READABLE);
}
END_TEST

START_TEST(test_tcp_recv_queue_full_sends_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    uint8_t tiny[4];

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 10;
    queue_init(&ts->sock.tcp.rxbuf, tiny, sizeof(tiny), 0);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&seg, 0, sizeof(seg));
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 8);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.seq = ee32(10);

    tcp_recv(ts, &seg);
    ck_assert_uint_eq(ts->sock.tcp.ack, 10);
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.tcp.txbuf));
}
END_TEST

START_TEST(test_tcp_ack_cwnd_count_wrap)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.ssthresh = TCP_MSS;
    ts->sock.tcp.cwnd_count = ts->sock.tcp.cwnd - 1;
    /* Ensure cwnd growth path is taken and not rwnd-capped. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    /* Simulate cwnd-limited flight and initialize snd_una. */
    ts->sock.tcp.bytes_in_flight = ts->sock.tcp.cwnd;
    /* Advance ACK by 1 byte to exercise cwnd_count wrap. */
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 100 + TCP_MSS;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(101);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    /* Expect cwnd_count to wrap to (cwnd_count + MSS - cwnd). */
    ck_assert_uint_eq(ts->sock.tcp.cwnd_count, (TCP_MSS - 1));
    ck_assert_uint_eq(ts->sock.tcp.cwnd, (TCP_MSS * 5));
}
END_TEST

START_TEST(test_tcp_ack_updates_rtt_and_cwnd)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTION_TS_LEN + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *tsopt;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.ssthresh = TCP_MSS * 4;
    /* Ensure cwnd growth path is taken and not rwnd-capped. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    s.last_tick = 1000;

    memset(buf, 0, sizeof(buf));
    seg->ip.len = ee16(IP_HEADER_LEN + (TCP_HEADER_LEN + TCP_OPTION_TS_LEN) + 1);
    seg->hlen = (TCP_HEADER_LEN + TCP_OPTION_TS_LEN) << 2;
    seg->seq = ee32(100);
    tsopt = (struct tcp_opt_ts *)seg->data;
    tsopt->opt = TCP_OPTION_TS;
    tsopt->len = TCP_OPTION_TS_LEN;
    tsopt->val = ee32(123);
    tsopt->ecr = ee32(990);

    fifo_push(&ts->sock.tcp.txbuf, seg, sizeof(buf));
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    /* Simulate cwnd-limited flight and initialize snd_una. */
    ts->sock.tcp.bytes_in_flight = ts->sock.tcp.cwnd;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 100 + TCP_MSS;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(101);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_gt(ts->sock.tcp.rtt, 0);
    ck_assert_uint_eq(ts->sock.tcp.cwnd, TCP_MSS * 2);
    ck_assert_uint_eq(ts->events & CB_EVENT_WRITABLE, CB_EVENT_WRITABLE);
}
END_TEST

START_TEST(test_tcp_ack_uses_interface_mss_for_cwnd_growth)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTION_TS_LEN + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *tsopt;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t smss;

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF, 320U), 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    smss = tcp_cc_mss(ts);
    ts->sock.tcp.cwnd = smss;
    ts->sock.tcp.ssthresh = smss * 4;
    ts->sock.tcp.peer_rwnd = smss * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    s.last_tick = 1000;

    memset(buf, 0, sizeof(buf));
    seg->ip.len = ee16(IP_HEADER_LEN + (TCP_HEADER_LEN + TCP_OPTION_TS_LEN) + 1);
    seg->hlen = (TCP_HEADER_LEN + TCP_OPTION_TS_LEN) << 2;
    seg->seq = ee32(100);
    tsopt = (struct tcp_opt_ts *)seg->data;
    tsopt->opt = TCP_OPTION_TS;
    tsopt->len = TCP_OPTION_TS_LEN;
    tsopt->val = ee32(123);
    tsopt->ecr = ee32(990);

    fifo_push(&ts->sock.tcp.txbuf, seg, sizeof(buf));
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    ts->sock.tcp.bytes_in_flight = ts->sock.tcp.cwnd;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 100 + smss;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(101);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.cwnd, smss * 2);
}
END_TEST

START_TEST(test_tcp_ack_last_seq_not_last_ack_state)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.last = 100;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(100);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

START_TEST(test_tcp_ack_no_progress_when_ack_far_ahead)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq = 100;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    /* Allow duplicate-ACK path without rwnd cap. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    /* Force duplicate ACK handling with outstanding bytes. */
    ts->sock.tcp.bytes_in_flight = TCP_MSS * 2;
    ts->sock.tcp.snd_una = 500;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq + 0x100000U);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.tcp.txbuf), NULL);
}
END_TEST

START_TEST(test_tcp_ack_coarse_rtt_sets_writable)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.ssthresh = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    s.last_tick = 1000;

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    desc->time_sent = 900;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(101);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.rtt, 100U);
    ck_assert_uint_eq(ts->events & CB_EVENT_WRITABLE, CB_EVENT_WRITABLE);
}
END_TEST

START_TEST(test_tcp_ack_coarse_rtt_across_low32_wrap)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.ssthresh = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    s.last_tick = (1ULL << 32) + 100U;

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    desc->time_sent = 0xFFFFFFF0U;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(101);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.rtt, 116U);
    ck_assert_uint_eq(ts->events & CB_EVENT_WRITABLE, CB_EVENT_WRITABLE);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_clears_sent_large_seg_len)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    /* Allow duplicate-ACK path without rwnd cap. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 2000);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(500);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    /* Force duplicate ACK handling with outstanding bytes. */
    ts->sock.tcp.bytes_in_flight = TCP_MSS * 2;
    ts->sock.tcp.snd_una = 500;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(500);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    /* Trigger fast retransmit by delivering three duplicate ACKs. */
    tcp_ack(ts, &ackseg);
    tcp_ack(ts, &ackseg);
    tcp_ack(ts, &ackseg);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_discards_zero_len_segment_far_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(1000);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.tcp.txbuf), NULL);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_ssthresh_min)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    /* Allow duplicate-ACK path without rwnd cap. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    /* Force duplicate ACK handling with outstanding bytes. */
    ts->sock.tcp.bytes_in_flight = TCP_MSS;
    ts->sock.tcp.snd_una = 50;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(50);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_ge(ts->sock.tcp.cwnd, TCP_MSS);
}
END_TEST

START_TEST(test_tcp_input_filter_drop)
{
    struct wolfIP s;
    struct wolfIP_tcp_seg seg;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_tcp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));
    filter_block_reason = WOLFIP_FILT_RECEIVING;

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    memset(&seg, 0, sizeof(seg));
    seg.ip.ver_ihl = 0x45;
    seg.ip.ttl = 64;
    seg.ip.proto = WI_IPPROTO_TCP;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(ts->remote_ip);
    seg.ip.dst = ee32(ts->local_ip);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(ts->dst_port);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_ACK;
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_tcp_mask(0);
}
END_TEST

START_TEST(test_tcp_input_port_mismatch_skips_socket)
{
    struct wolfIP s;
    struct wolfIP_tcp_seg seg;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    memset(&seg, 0, sizeof(seg));
    seg.ip.ver_ihl = 0x45;
    seg.ip.ttl = 64;
    seg.ip.proto = WI_IPPROTO_TCP;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(ts->remote_ip);
    seg.ip.dst = ee32(ts->local_ip);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(9999);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_ACK;
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

START_TEST(test_tcp_input_remote_ip_mismatch_skips_socket)
{
    struct wolfIP s;
    struct wolfIP_tcp_seg seg;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->if_idx = TEST_SECOND_IF;
    ts->sock.tcp.peer_rwnd = 100;

    memset(&seg, 0, sizeof(seg));
    seg.ip.ver_ihl = 0x45;
    seg.ip.ttl = 64;
    seg.ip.proto = WI_IPPROTO_TCP;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(0x0A000003U);
    seg.ip.dst = ee32(ts->local_ip);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(ts->dst_port);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_ACK;
    seg.win = ee16(777);
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.peer_rwnd, 100);
    ck_assert_uint_eq(ts->if_idx, TEST_SECOND_IF);
}
END_TEST

START_TEST(test_tcp_input_local_ip_mismatch_preserves_if_idx)
{
    struct wolfIP s;
    struct wolfIP_tcp_seg seg;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->if_idx = TEST_SECOND_IF;
    ts->sock.tcp.peer_rwnd = 100;

    memset(&seg, 0, sizeof(seg));
    seg.ip.ver_ihl = 0x45;
    seg.ip.ttl = 64;
    seg.ip.proto = WI_IPPROTO_TCP;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(ts->remote_ip);
    seg.ip.dst = ee32(0x0A000003U);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(ts->dst_port);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_ACK;
    seg.win = ee16(777);
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.peer_rwnd, 100);
    ck_assert_uint_eq(ts->if_idx, TEST_SECOND_IF);
}
END_TEST

START_TEST(test_tcp_input_unmatched_ack_sends_rst)
{
    struct wolfIP s;
    struct wolfIP_tcp_seg *rst;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    last_frame_sent_size = 0;
    memset(last_frame_sent, 0, sizeof(last_frame_sent));

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U,
            4321, 1234, 77, 101, TCP_FLAG_ACK);

    ck_assert_uint_eq(last_frame_sent_size, (uint32_t)sizeof(struct wolfIP_tcp_seg));
    rst = (struct wolfIP_tcp_seg *)last_frame_sent;
    ck_assert_uint_eq(ee32(rst->ip.src), 0x0A000001U);
    ck_assert_uint_eq(ee32(rst->ip.dst), 0x0A000002U);
    ck_assert_uint_eq(ee16(rst->src_port), 1234);
    ck_assert_uint_eq(ee16(rst->dst_port), 4321);
    ck_assert_uint_eq(rst->flags, TCP_FLAG_RST);
    ck_assert_uint_eq(ee32(rst->seq), 101U);
    ck_assert_uint_eq(ee32(rst->ack), 0U);
}
END_TEST

START_TEST(test_tcp_input_unmatched_ack_nonlocal_dst_does_not_send_rst)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    last_frame_sent_size = 0;
    memset(last_frame_sent, 0, sizeof(last_frame_sent));

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A0000FEU,
            4321, 1234, 77, 101, TCP_FLAG_ACK);

    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_tcp_input_unmatched_syn_sends_rst_ack)
{
    struct wolfIP s;
    struct wolfIP_tcp_seg *rst;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    last_frame_sent_size = 0;
    memset(last_frame_sent, 0, sizeof(last_frame_sent));

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U,
            4321, 1234, 77, 0, TCP_FLAG_SYN);

    ck_assert_uint_eq(last_frame_sent_size, (uint32_t)sizeof(struct wolfIP_tcp_seg));
    rst = (struct wolfIP_tcp_seg *)last_frame_sent;
    ck_assert_uint_eq(ee32(rst->ip.src), 0x0A000001U);
    ck_assert_uint_eq(ee32(rst->ip.dst), 0x0A000002U);
    ck_assert_uint_eq(ee16(rst->src_port), 1234);
    ck_assert_uint_eq(ee16(rst->dst_port), 4321);
    ck_assert_uint_eq(rst->flags, (uint8_t)(TCP_FLAG_RST | TCP_FLAG_ACK));
    ck_assert_uint_eq(ee32(rst->seq), 0U);
    ck_assert_uint_eq(ee32(rst->ack), 78U);
}
END_TEST

START_TEST(test_tcp_input_unmatched_rst_is_discarded)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    last_frame_sent_size = 0;
    memset(last_frame_sent, 0, sizeof(last_frame_sent));

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U,
            4321, 1234, 77, 0, TCP_FLAG_RST);

    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_tcp_input_listen_synack_sends_rst_and_stays_listen)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_tcp_seg *rst;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd,
        (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    last_frame_sent_size = 0;
    memset(last_frame_sent, 0, sizeof(last_frame_sent));

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U,
            4321, 1234, 77, 101, (uint8_t)(TCP_FLAG_SYN | TCP_FLAG_ACK));

    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
    ck_assert_uint_eq(last_frame_sent_size, (uint32_t)sizeof(struct wolfIP_tcp_seg));
    rst = (struct wolfIP_tcp_seg *)last_frame_sent;
    ck_assert_uint_eq(ee32(rst->ip.src), 0x0A000001U);
    ck_assert_uint_eq(ee32(rst->ip.dst), 0x0A000002U);
    ck_assert_uint_eq(ee16(rst->src_port), 1234);
    ck_assert_uint_eq(ee16(rst->dst_port), 4321);
    ck_assert_uint_eq(rst->flags, TCP_FLAG_RST);
    ck_assert_uint_eq(ee32(rst->seq), 101U);
    ck_assert_uint_eq(ee32(rst->ack), 0U);
}
END_TEST

START_TEST(test_tcp_input_listen_accept_final_ack_does_not_send_rst)
{
    struct wolfIP s;
    int listen_sd;
    int client_sd;
    struct tsocket *listen_ts;
    struct tsocket *client_ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd,
        (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U,
            4321, 1234, 77, 0, TCP_FLAG_SYN);

    listen_ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(listen_ts->sock.tcp.state, TCP_SYN_RCVD);

    client_sd = wolfIP_sock_accept(&s, listen_sd, NULL, NULL);
    ck_assert_int_gt(client_sd, 0);

    client_ts = &s.tcpsockets[SOCKET_UNMARK(client_sd)];
    ck_assert_int_eq(listen_ts->sock.tcp.state, TCP_LISTEN);
    ck_assert_int_eq(client_ts->sock.tcp.state, TCP_SYN_RCVD);

    last_frame_sent_size = 0;
    memset(last_frame_sent, 0, sizeof(last_frame_sent));

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U,
            4321, 1234, client_ts->sock.tcp.ack,
            tcp_seq_inc(client_ts->sock.tcp.snd_una, 1), TCP_FLAG_ACK);

    ck_assert_uint_eq(last_frame_sent_size, 0U);
    ck_assert_int_eq(listen_ts->sock.tcp.state, TCP_LISTEN);
    ck_assert_int_eq(client_ts->sock.tcp.state, TCP_ESTABLISHED);

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U,
            4321, 1234, client_ts->sock.tcp.ack, client_ts->sock.tcp.seq, TCP_FLAG_ACK);

    ck_assert_uint_eq(last_frame_sent_size, 0U);
    ck_assert_int_eq(listen_ts->sock.tcp.state, TCP_LISTEN);
    ck_assert_int_eq(client_ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

START_TEST(test_tcp_input_syn_bound_ip_mismatch)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ts->bound_local_ip = 0x0A000001U;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A0000A1U, 0x0A000002U, 40000, 1234, 1, 0, TCP_FLAG_SYN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
}
END_TEST

START_TEST(test_tcp_input_syn_dst_not_local)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A0000A1U, 0x0A000002U, 40000, 1234, 1, 0, TCP_FLAG_SYN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
}
END_TEST

START_TEST(test_tcp_input_syn_dst_outside_subnet)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A0000A1U, 0x0B000001U, 40000, 1234, 1, 0, TCP_FLAG_SYN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
}
END_TEST

START_TEST(test_tcp_input_listen_dst_match_false)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_tcp_seg seg;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
    wolfIP_filter_set_tcp_mask(0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ts->bound_local_ip = IPADDR_ANY;
    memset(&seg, 0, sizeof(seg));
    seg.ip.ver_ihl = 0x45;
    seg.ip.ttl = 64;
    seg.ip.proto = WI_IPPROTO_TCP;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(0x0A000002U);
    seg.ip.dst = ee32(0x0B000001U);
    seg.src_port = ee16(40000);
    seg.dst_port = ee16(ts->src_port);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_SYN;
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
}
END_TEST

START_TEST(test_tcp_input_established_fin_sets_close_wait)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000B1U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 10;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);

    memset(&seg, 0, sizeof(seg));
    seg.ip.ver_ihl = 0x45;
    seg.ip.proto = WI_IPPROTO_TCP;
    seg.ip.ttl = 64;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(remote_ip);
    seg.ip.dst = ee32(local_ip);
    seg.src_port = ee16(ts->dst_port);
    seg.dst_port = ee16(ts->src_port);
    seg.seq = ee32(10);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_FIN | TCP_FLAG_ACK;
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSE_WAIT);
    ck_assert_uint_eq(ts->sock.tcp.ack, 11);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, CB_EVENT_CLOSED);
}
END_TEST

START_TEST(test_tcp_input_established_fin_with_payload_queues)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    uint8_t payload[4] = {1, 2, 3, 4};
    uint8_t out[4] = {0};
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000B1U;
    uint32_t seq = 100;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = seq;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port = 1234;
    ts->dst_port = 4321;

    memset(buf, 0, sizeof(buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.ttl = 64;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->ip.src = ee32(remote_ip);
    seg->ip.dst = ee32(local_ip);
    seg->src_port = ee16(ts->dst_port);
    seg->dst_port = ee16(ts->src_port);
    seg->seq = ee32(seq);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = (TCP_FLAG_FIN | TCP_FLAG_ACK);
    memcpy(seg->data, payload, sizeof(payload));
    fix_tcp_checksums(seg);

    tcp_input(&s, TEST_PRIMARY_IF, seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload)));

    ck_assert_int_eq(queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out)), (int)sizeof(out));
    ck_assert_mem_eq(out, payload, sizeof(payload));
    ck_assert_uint_eq(ts->sock.tcp.ack, seq + sizeof(payload) + 1);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSE_WAIT);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, CB_EVENT_CLOSED);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, CB_EVENT_READABLE);
}
END_TEST

START_TEST(test_tcp_input_established_fin_payload_out_of_order_no_transition)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    uint8_t payload[4] = {5, 6, 7, 8};
    uint8_t out[4] = {0};
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000B1U;
    uint32_t ack = 100;
    uint32_t seq = 200;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = ack;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port = 1234;
    ts->dst_port = 4321;

    memset(buf, 0, sizeof(buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.ttl = 64;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->ip.src = ee32(remote_ip);
    seg->ip.dst = ee32(local_ip);
    seg->src_port = ee16(ts->dst_port);
    seg->dst_port = ee16(ts->src_port);
    seg->seq = ee32(seq);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = (TCP_FLAG_FIN | TCP_FLAG_ACK);
    memcpy(seg->data, payload, sizeof(payload));
    fix_tcp_checksums(seg);

    tcp_input(&s, TEST_PRIMARY_IF, seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload)));

    ck_assert_int_eq(queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out)), -WOLFIP_EAGAIN);
    ck_assert_uint_eq(ts->sock.tcp.ack, ack);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, 0);
}
END_TEST

START_TEST(test_tcp_input_established_fin_out_of_order_no_transition)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000B1U;
    uint32_t ack = 100;
    uint32_t seq = 200;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = ack;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port = 1234;
    ts->dst_port = 4321;

    memset(&seg, 0, sizeof(seg));
    seg.ip.ver_ihl = 0x45;
    seg.ip.ttl = 64;
    seg.ip.proto = WI_IPPROTO_TCP;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(remote_ip);
    seg.ip.dst = ee32(local_ip);
    seg.src_port = ee16(ts->dst_port);
    seg.dst_port = ee16(ts->src_port);
    seg.seq = ee32(seq);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_FIN;
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    ck_assert_uint_eq(ts->sock.tcp.ack, ack);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, 0);
}
END_TEST

/* An application-selected Diffserv value must be carried in the IPv4 TOS
 * field of every outgoing segment; validated via setsockopt. */
START_TEST(test_tcp_setsockopt_ip_tos_applied_to_outbound_syn)
{
    struct wolfIP s;
    int tcp_sd;
    struct wolfIP_tcp_seg *syn;
    struct wolfIP_sockaddr_in sin;
    int tos = 0xA0;
    int bad = 256;
    int neg = -1;
    socklen_t len;
    static const uint8_t tos_peer_mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);

    /* Range and argument validation. */
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, tcp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_TOS, &bad, sizeof(bad)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, tcp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_TOS, &neg, sizeof(neg)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, tcp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_TOS, NULL, sizeof(tos)), -WOLFIP_EINVAL);

    /* A valid value is accepted and readable via getsockopt. */
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, tcp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_TOS, &tos, sizeof(tos)), 0);
    len = sizeof(tos);
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, tcp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_TOS, &tos, &len), 0);
    ck_assert_int_eq(tos, 0xA0);

    /* The connect SYN must carry the selected TOS in its IPv4 header.
     * Seed the ARP entry so the SYN is transmitted, not queued. */
    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A000002U, (uint8_t *)tos_peer_mac);
    last_frame_sent_size = 0;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5002);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);

    /* The SYN is queued in the tx fifo; the poll loop transmits it. */
    wolfIP_poll(&s, 1000);
    ck_assert_uint_gt(last_frame_sent_size, 0);
    syn = (struct wolfIP_tcp_seg *)last_frame_sent;
    ck_assert_uint_eq(syn->flags, TCP_FLAG_SYN);
    ck_assert_uint_eq(syn->ip.tos, (uint8_t)0xA0);
}
END_TEST

/* ------------------------------------------------------------------
 * TCP listener lock (F-9807): a single wire SYN moves the listener
 * socket itself into TCP_SYN_RCVD (wolfIP has no SYN backlog); while
 * locked, other clients are RST'd. Recovery paths covered here:
 * control-RTO expiry, RST from the holding 4-tuple, re-SYN
 * retransmission (re-arms the control RTO), and the pre-accept
 * fast-fail that reclaims a port whose handshake completed before
 * accept() (which would otherwise pin it in ESTABLISHED forever).
 * ------------------------------------------------------------------ */

#define LLK_LISTEN_PORT 4000U
#define LLK_LOCAL_IP    0x0A000001U
#define LLK_NET_MASK    0xFFFFFF00U
#define LLK_ATT_IP      0x0A000099U
#define LLK_VICTIM_IP   0x0A000050U

static const struct wolfIP_tcp_seg *llk_last_tcp(void)
{
    const struct wolfIP_tcp_seg *seg;

    if (last_frame_sent_count == 0)
        return NULL;
    if (last_frame_sent_size <
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN))
        return NULL;
    seg = (const struct wolfIP_tcp_seg *)last_frame_sent;
    if (ee16(seg->ip.eth.type) != ETH_TYPE_IP)
        return NULL;
    if (seg->ip.proto != WI_IPPROTO_TCP)
        return NULL;
    return seg;
}

/* tmr_rto stores a timer id (not a heap index): scan by id. */
static uint32_t llk_timer_expires(struct wolfIP *s, uint32_t id)
{
    uint32_t i;

    if (id == NO_TIMER)
        return 0;
    for (i = 0; i < s->timers.size; i++) {
        if (s->timers.timers[i].id == id)
            return (uint32_t)s->timers.timers[i].expires;
    }
    return 0;
}

/* Keep the attacker's learned ARP entry fresh past ARP_AGING_TIMEOUT_MS
 * (a live network would re-answer the ARP request). */
static void llk_keep_arp_fresh(struct wolfIP *s, ip4 ip)
{
    uint8_t mac[6] = { 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01 };

    arp_store_neighbor(s, TEST_PRIMARY_IF, ip, mac);
}

static int llk_open_listener(struct wolfIP *s)
{
    int fd;
    struct wolfIP_sockaddr_in sin;

    fd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(fd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16((uint16_t)LLK_LISTEN_PORT);
    sin.sin_addr.s_addr = ee32(LLK_LOCAL_IP);
    ck_assert_int_eq(wolfIP_sock_bind(s, fd, (struct wolfIP_sockaddr *)&sin,
            sizeof(sin)), 0);
    /* The backlog argument is discarded by the stack (no SYN backlog). */
    ck_assert_int_eq(wolfIP_sock_listen(s, fd, 16), 0);
    return fd;
}

static void llk_attacker_syn(struct wolfIP *s, ip4 src_ip, uint16_t src_port,
        uint32_t seq, uint64_t now)
{
    inject_tcp_segment(s, TEST_PRIMARY_IF, src_ip, LLK_LOCAL_IP,
                       src_port, (uint16_t)LLK_LISTEN_PORT, seq, 0,
                       TCP_FLAG_SYN);
    (void)wolfIP_poll(s, now);
}

/* Complete the handshake from the peer side using the ISN read from the
 * wire (internal seq is host-order, so no ee32()). */
static void llk_complete_handshake(struct wolfIP *s, struct tsocket *lsn,
        ip4 src_ip, uint16_t src_port, uint64_t now)
{
    inject_tcp_segment(s, TEST_PRIMARY_IF, src_ip, LLK_LOCAL_IP,
                       src_port, (uint16_t)LLK_LISTEN_PORT, 2,
                       lsn->sock.tcp.seq + 1, TCP_FLAG_ACK);
    (void)wolfIP_poll(s, now);
}

/* One SYN puts the listener in SYN_RCVD; other clients are RST'd; a
 * re-SYN from the holding 4-tuple retransmits the SYN-ACK instead of
 * being dropped, without touching the control-RTO retry budget (a
 * re-SYN must not extend the lock past the retry cap). */
START_TEST(test_tcp_listener_syn_lock_others_rst_resyn_retransmits_synack)
{
    struct wolfIP s;
    int fd;
    struct tsocket *lsn;
    const struct wolfIP_tcp_seg *out;
    uint32_t armed_expires;
    uint32_t frames_before;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, LLK_LOCAL_IP, LLK_NET_MASK, 0);
    fd = llk_open_listener(&s);
    lsn = &s.tcpsockets[SOCKET_UNMARK(fd)];
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_LISTEN);
    ck_assert_int_eq(lsn->sock.tcp.is_listener, 1);

    /* Pending-only ARP policy: the peers are known neighbors, so the
     * SYN-ACK/RST replies actually reach the wire. */
    llk_keep_arp_fresh(&s, LLK_ATT_IP);
    llk_keep_arp_fresh(&s, LLK_VICTIM_IP);

    /* Attacker A: one SYN, then silence. */
    llk_attacker_syn(&s, LLK_ATT_IP, 41000, 1, 0);

    /* The listener socket itself is the half-open connection. */
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_int_eq(lsn->sock.tcp.is_listener, 1);
    ck_assert_int_eq(lsn->sock.tcp.ctrl_rto_retries, 0);
    ck_assert_uint_eq(lsn->sock.tcp.rto, TCP_RTO_MIN_MS);
    ck_assert_uint_ne(lsn->sock.tcp.tmr_rto, NO_TIMER);
    out = llk_last_tcp();
    ck_assert_ptr_nonnull(out);
    ck_assert(out->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK));

    /* Victim B: fresh SYN to the same port while the listener is locked.
     * No backlog, so B is refused with RST. */
    frames_before = last_frame_sent_count;
    inject_tcp_segment(&s, TEST_PRIMARY_IF, LLK_VICTIM_IP, LLK_LOCAL_IP,
                       42000, (uint16_t)LLK_LISTEN_PORT, 5, 0, TCP_FLAG_SYN);
    (void)wolfIP_poll(&s, 1);

    ck_assert_int_eq(lsn->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(last_frame_sent_count, frames_before + 1);
    out = llk_last_tcp();
    ck_assert_ptr_nonnull(out);
    ck_assert(out->flags & TCP_FLAG_RST);
    ck_assert_uint_eq(ee16(out->src_port), LLK_LISTEN_PORT);
    ck_assert_uint_eq(ee16(out->dst_port), 42000);

    /* Victim B sends a confused SYN-ACK: unacceptable ACK in SYN_RCVD
     * -> RST again, listener still locked. */
    frames_before = last_frame_sent_count;
    inject_tcp_segment(&s, TEST_PRIMARY_IF, LLK_VICTIM_IP, LLK_LOCAL_IP,
                       42000, (uint16_t)LLK_LISTEN_PORT, 6, 0xDEADBEEFU,
                       TCP_FLAG_SYN | TCP_FLAG_ACK);
    (void)wolfIP_poll(&s, 2);

    ck_assert_int_eq(lsn->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(last_frame_sent_count, frames_before + 1);
    out = llk_last_tcp();
    ck_assert_ptr_nonnull(out);
    ck_assert(out->flags & TCP_FLAG_RST);
    ck_assert_uint_eq(ee16(out->dst_port), 42000);

    /* Attacker A retransmits the original SYN: the stack retransmits
     * the SYN-ACK, but the control RTO keeps its own schedule (no
     * re-arm), so the retry cap still bounds the lock. */
    armed_expires = llk_timer_expires(&s, lsn->sock.tcp.tmr_rto);
    frames_before = last_frame_sent_count;
    inject_tcp_segment(&s, TEST_PRIMARY_IF, LLK_ATT_IP, LLK_LOCAL_IP,
                       41000, (uint16_t)LLK_LISTEN_PORT, 1, 0, TCP_FLAG_SYN);
    (void)wolfIP_poll(&s, 3);

    ck_assert_int_eq(lsn->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_int_eq(lsn->sock.tcp.ctrl_rto_retries, 0);
    ck_assert_uint_eq(last_frame_sent_count, frames_before + 1);
    out = llk_last_tcp();
    ck_assert_ptr_nonnull(out);
    ck_assert(out->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK));
    ck_assert_uint_eq(ee16(out->dst_port), 41000);
    ck_assert_uint_eq(llk_timer_expires(&s, lsn->sock.tcp.tmr_rto),
                      armed_expires);
}
END_TEST

/* Silence: the listener is reclaimed by the control-RTO backoff
 * (1,2,4,8,16,32,64,64 s arms = 8 retransmissions, revert at t = 255 s)
 * and the port accepts new clients again. */
START_TEST(test_tcp_listener_lock_reclaimed_at_255s_via_ctrl_rto)
{
    struct wolfIP s;
    int fd;
    struct tsocket *lsn;
    uint64_t t;
    uint32_t retrans_at[8];
    int retrans = 0;
    uint32_t last_count;
    uint64_t reclaimed_at = 0;
    const struct wolfIP_tcp_seg *out;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, LLK_LOCAL_IP, LLK_NET_MASK, 0);
    fd = llk_open_listener(&s);
    lsn = &s.tcpsockets[SOCKET_UNMARK(fd)];

    /* Pending-only ARP policy: the peers are known neighbors, so the
     * initial SYN-ACK and every retransmit reach the wire. */
    llk_keep_arp_fresh(&s, LLK_ATT_IP);
    llk_keep_arp_fresh(&s, 0x0A000077U);

    llk_attacker_syn(&s, LLK_ATT_IP, 41000, 1, 0);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_SYN_RCVD);
    last_count = last_frame_sent_count; /* initial SYN-ACK already sent */

    for (t = 1000; t <= 260000; t += 1000) {
        (void)wolfIP_poll(&s, t);
        if (t % 60000 == 0)
            llk_keep_arp_fresh(&s, LLK_ATT_IP);
        if (last_frame_sent_count != last_count) {
            last_count = last_frame_sent_count;
            if (lsn->sock.tcp.state == TCP_SYN_RCVD && retrans < 8)
                retrans_at[retrans++] = (uint32_t)t;
        }
        if (reclaimed_at == 0 && lsn->sock.tcp.state == TCP_LISTEN)
            reclaimed_at = t;
    }

    ck_assert_int_eq(retrans, 8);
    ck_assert_uint_eq(retrans_at[0], 1000);
    ck_assert_uint_eq(retrans_at[1], 3000);
    ck_assert_uint_eq(retrans_at[2], 7000);
    ck_assert_uint_eq(retrans_at[3], 15000);
    ck_assert_uint_eq(retrans_at[4], 31000);
    ck_assert_uint_eq(retrans_at[5], 63000);
    ck_assert_uint_eq(retrans_at[6], 127000);
    ck_assert_uint_eq(retrans_at[7], 191000);

    ck_assert_uint_eq(reclaimed_at, 255000);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_LISTEN);
    ck_assert_uint_eq(lsn->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_eq(lsn->remote_ip, 0);
    ck_assert_uint_eq(lsn->dst_port, 0);

    /* The port is alive again: a new client C gets a SYN-ACK (its ARP
     * entry aged out during the 255 s lock: refresh it). */
    llk_keep_arp_fresh(&s, 0x0A000077U);
    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000077U, LLK_LOCAL_IP,
                       43000, (uint16_t)LLK_LISTEN_PORT, 9, 0, TCP_FLAG_SYN);
    (void)wolfIP_poll(&s, t + 1);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_SYN_RCVD);
    out = llk_last_tcp();
    ck_assert_ptr_nonnull(out);
    ck_assert(out->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK));
    ck_assert_uint_eq(ee16(out->dst_port), 43000);
}
END_TEST

/* One SYN per full backoff window keeps the port dead window after
 * window: two consecutive 255 s lock windows, victim refused in both.
 * (Documents the remaining exposure: a real SYN backlog is the full
 * fix; this test pins the current single-listener behavior.) */
START_TEST(test_tcp_listener_sustained_lock_one_syn_per_window)
{
    struct wolfIP s;
    int fd;
    struct tsocket *lsn;
    uint64_t t;
    uint32_t frames_before;
    const struct wolfIP_tcp_seg *out;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, LLK_LOCAL_IP, LLK_NET_MASK, 0);
    fd = llk_open_listener(&s);
    lsn = &s.tcpsockets[SOCKET_UNMARK(fd)];

    /* Pending-only ARP policy: the peers are known neighbors. */
    llk_keep_arp_fresh(&s, LLK_ATT_IP);
    llk_keep_arp_fresh(&s, LLK_VICTIM_IP);
    llk_keep_arp_fresh(&s, 0x0A00009AU);

    /* Window 1: lock at t=0, reclaim at t=255 s. */
    llk_attacker_syn(&s, LLK_ATT_IP, 41000, 1, 0);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_SYN_RCVD);
    for (t = 1000; t <= 255000; t += 1000) {
        (void)wolfIP_poll(&s, t);
        if (t % 60000 == 0)
            llk_keep_arp_fresh(&s, LLK_ATT_IP);
    }
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_LISTEN);

    /* Attacker re-locks the port right after reclamation. */
    llk_attacker_syn(&s, 0x0A00009AU, 41001, 2, 256000);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_SYN_RCVD);

    /* Window 2: victim B is refused again. */
    frames_before = last_frame_sent_count;
    inject_tcp_segment(&s, TEST_PRIMARY_IF, LLK_VICTIM_IP, LLK_LOCAL_IP,
                       42000, (uint16_t)LLK_LISTEN_PORT, 5, 0, TCP_FLAG_SYN);
    (void)wolfIP_poll(&s, 256001);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(last_frame_sent_count, frames_before + 1);
    out = llk_last_tcp();
    ck_assert_ptr_nonnull(out);
    ck_assert(out->flags & TCP_FLAG_RST);
    ck_assert_uint_eq(ee16(out->dst_port), 42000);

    /* Hold through the second full window. */
    for (t = 257000; t <= 511000; t += 1000) {
        (void)wolfIP_poll(&s, t);
        if (t % 60000 == 0)
            llk_keep_arp_fresh(&s, 0x0A00009AU);
    }
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_LISTEN);
}
END_TEST

/* A RST from the holding 4-tuple with seq == rcv_nxt reverts the
 * listener to LISTEN immediately; a RST with the wrong seq is ignored. */
START_TEST(test_tcp_listener_rst_from_holding_4tuple_releases_lock)
{
    struct wolfIP s;
    int fd;
    struct tsocket *lsn;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, LLK_LOCAL_IP, LLK_NET_MASK, 0);
    fd = llk_open_listener(&s);
    lsn = &s.tcpsockets[SOCKET_UNMARK(fd)];

    llk_attacker_syn(&s, LLK_ATT_IP, 41000, 1, 0);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_SYN_RCVD);

    /* RST with wrong seq: ignored, lock persists. */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, LLK_ATT_IP, LLK_LOCAL_IP,
                       41000, (uint16_t)LLK_LISTEN_PORT, 777, 0,
                       TCP_FLAG_RST);
    (void)wolfIP_poll(&s, 1);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_SYN_RCVD);

    /* RST with seq == rcv_nxt (attacker ISN 1 + 1 = 2): immediate
     * revert to LISTEN. */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, LLK_ATT_IP, LLK_LOCAL_IP,
                       41000, (uint16_t)LLK_LISTEN_PORT, 2, 0,
                       TCP_FLAG_RST);
    (void)wolfIP_poll(&s, 2);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_LISTEN);
    ck_assert_uint_eq(lsn->remote_ip, 0);
    ck_assert_uint_eq(lsn->dst_port, 0);
}
END_TEST

/* The handshake completes before accept(): the listener is ESTABLISHED
 * with the pre-accept fast-fail timer armed. accept() can no longer
 * clone the connection, but it reverts the port to LISTEN so it is not
 * pinned, and new clients are served again. */
START_TEST(test_tcp_listener_preaccept_accept_reverts_port)
{
    struct wolfIP s;
    int fd;
    struct tsocket *lsn;
    struct wolfIP_sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    const struct wolfIP_tcp_seg *out;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, LLK_LOCAL_IP, LLK_NET_MASK, 0);
    fd = llk_open_listener(&s);
    lsn = &s.tcpsockets[SOCKET_UNMARK(fd)];

    /* Pending-only ARP policy: the peers are known neighbors. */
    llk_keep_arp_fresh(&s, LLK_ATT_IP);
    llk_keep_arp_fresh(&s, LLK_VICTIM_IP);

    llk_attacker_syn(&s, LLK_ATT_IP, 41000, 1, 0);
    llk_complete_handshake(&s, lsn, LLK_ATT_IP, 41000, 1);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_ESTABLISHED);
    /* The un-accepted established listener is time-boxed. */
    ck_assert_int_eq(lsn->sock.tcp.preaccept_timeout_active, 1);
    ck_assert_uint_ne(lsn->sock.tcp.tmr_rto, NO_TIMER);

    /* accept() cannot clone an ESTABLISHED connection: it fails, but it
     * reverts the port to LISTEN instead of leaving it pinned. */
    memset(&peer, 0, sizeof(peer));
    ck_assert_int_eq(wolfIP_sock_accept(&s, fd,
            (struct wolfIP_sockaddr *)&peer, &peer_len), -1);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_LISTEN);
    ck_assert_int_eq(lsn->sock.tcp.preaccept_timeout_active, 0);
    ck_assert_uint_eq(lsn->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_eq(lsn->remote_ip, 0);
    ck_assert_uint_eq(lsn->dst_port, 0);

    /* A new client is served again. */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, LLK_VICTIM_IP, LLK_LOCAL_IP,
                       42000, (uint16_t)LLK_LISTEN_PORT, 5, 0, TCP_FLAG_SYN);
    (void)wolfIP_poll(&s, 2);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_SYN_RCVD);
    out = llk_last_tcp();
    ck_assert_ptr_nonnull(out);
    ck_assert(out->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK));
    ck_assert_uint_eq(ee16(out->dst_port), 42000);
}
END_TEST

/* Same pre-accept condition, no accept() call: the fast-fail timer
 * reverts the port to LISTEN after TCP_PREACCEPT_TIMEOUT_MS, so the pin
 * is bounded even if the application never touches the socket again. */
START_TEST(test_tcp_listener_preaccept_timeout_reverts_port)
{
    struct wolfIP s;
    int fd;
    struct tsocket *lsn;
    uint64_t t;
    uint64_t reverted_at = 0;
    const struct wolfIP_tcp_seg *out;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, LLK_LOCAL_IP, LLK_NET_MASK, 0);
    fd = llk_open_listener(&s);
    lsn = &s.tcpsockets[SOCKET_UNMARK(fd)];

    /* Pending-only ARP policy: the peers are known neighbors. */
    llk_keep_arp_fresh(&s, LLK_ATT_IP);
    llk_keep_arp_fresh(&s, LLK_VICTIM_IP);

    llk_attacker_syn(&s, LLK_ATT_IP, 41000, 1, 0);
    llk_complete_handshake(&s, lsn, LLK_ATT_IP, 41000, 1);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_int_eq(lsn->sock.tcp.preaccept_timeout_active, 1);

    /* No accept() call: the timer alone reclaims the port. */
    for (t = 1000; t <= 10000; t += 1000) {
        (void)wolfIP_poll(&s, t);
        if (reverted_at == 0 && lsn->sock.tcp.state == TCP_LISTEN)
            reverted_at = t;
    }

    ck_assert_uint_eq(reverted_at, TCP_PREACCEPT_TIMEOUT_MS);
    ck_assert_int_eq(lsn->sock.tcp.preaccept_timeout_active, 0);
    ck_assert_uint_eq(lsn->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_eq(lsn->remote_ip, 0);
    ck_assert_uint_eq(lsn->dst_port, 0);

    /* A new client is served again. */
    inject_tcp_segment(&s, TEST_PRIMARY_IF, LLK_VICTIM_IP, LLK_LOCAL_IP,
                       42000, (uint16_t)LLK_LISTEN_PORT, 5, 0, TCP_FLAG_SYN);
    (void)wolfIP_poll(&s, t + 1);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_SYN_RCVD);
    out = llk_last_tcp();
    ck_assert_ptr_nonnull(out);
    ck_assert(out->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK));
    ck_assert_uint_eq(ee16(out->dst_port), 42000);
}
END_TEST

/* The accept() recovery path must also drain the dead connection's
 * transport state: segments parked on the listener socket during the
 * pre-accept window must not leak into the next connection (stale
 * descriptors would carry dead seqs into the new ACK window). */
START_TEST(test_tcp_listener_preaccept_revert_drains_connection_state)
{
    struct wolfIP s;
    int fd;
    struct tsocket *lsn;
    struct wolfIP_sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    int i;
    const struct wolfIP_tcp_seg *out;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, LLK_LOCAL_IP, LLK_NET_MASK, 0);
    fd = llk_open_listener(&s);
    lsn = &s.tcpsockets[SOCKET_UNMARK(fd)];

    llk_attacker_syn(&s, LLK_ATT_IP, 41000, 1, 0);
    llk_complete_handshake(&s, lsn, LLK_ATT_IP, 41000, 1);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_ESTABLISHED);

    /* Under the pending-only ARP policy the listener's SYN-ACK is parked
     * in the tx fifo (the neighbor never resolved): live state a revert
     * must drop, or the next connection inherits a stale segment. */
    ck_assert_int_eq(fifo_is_empty(&lsn->sock.tcp.txbuf), 0);

    /* accept() fails (ESTABLISHED) and reverts the port to LISTEN. */
    memset(&peer, 0, sizeof(peer));
    ck_assert_int_eq(wolfIP_sock_accept(&s, fd,
            (struct wolfIP_sockaddr *)&peer, &peer_len), -1);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_LISTEN);

    /* The dead connection's transport state is gone. */
    ck_assert_uint_eq(lsn->sock.tcp.bytes_in_flight, 0);
    ck_assert_ptr_null(fifo_peek(&lsn->sock.tcp.txbuf));
    /* An empty ring queue always holds back one slot. */
    ck_assert_uint_eq(queue_space((struct queue *)&lsn->sock.tcp.rxbuf),
                      RXBUF_SIZE - 1);
    for (i = 0; i < TCP_OOO_MAX_SEGS; i++)
        ck_assert_int_eq(lsn->sock.tcp.ooo[i].used, 0);
    ck_assert_uint_eq(lsn->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_int_eq(lsn->sock.tcp.preaccept_timeout_active, 0);

    /* A new client gets a clean connection and completes the handshake
     * (the victim is a known neighbor so its SYN-ACK reaches the wire;
     * the attacker's stays unresolved, keeping the parked-SYN-ACK premise
     * above intact). */
    llk_keep_arp_fresh(&s, LLK_VICTIM_IP);
    inject_tcp_segment(&s, TEST_PRIMARY_IF, LLK_VICTIM_IP, LLK_LOCAL_IP,
                       42000, (uint16_t)LLK_LISTEN_PORT, 5, 0, TCP_FLAG_SYN);
    (void)wolfIP_poll(&s, 3);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_SYN_RCVD);
    out = llk_last_tcp();
    ck_assert_ptr_nonnull(out);
    ck_assert(out->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK));
    ck_assert_uint_eq(ee16(out->dst_port), 42000);

    inject_tcp_segment(&s, TEST_PRIMARY_IF, LLK_VICTIM_IP, LLK_LOCAL_IP,
                       42000, (uint16_t)LLK_LISTEN_PORT, 6,
                       lsn->sock.tcp.seq + 1, TCP_FLAG_ACK);
    (void)wolfIP_poll(&s, 4);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_int_eq(lsn->sock.tcp.preaccept_timeout_active, 1);
}
END_TEST

/* The revert must leave the listener on the same option baseline as a
 * freshly allocated socket: the receive-window scale we advertise is a
 * property of RXBUF_SIZE, not of the dead connection. A revert that left
 * it zeroed would make the next connection on the port advertise WS shift
 * 0 (receive window capped at 64KB when RXBUF_SIZE > 0xFFFF) and drop the
 * WS/TS offers that accept() copies into new connections. */
START_TEST(test_tcp_listener_revert_restores_option_baseline)
{
    struct wolfIP s;
    int fd;
    struct tsocket *lsn;
    struct tsocket *fresh;
    struct wolfIP_sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, LLK_LOCAL_IP, LLK_NET_MASK, 0);
    fd = llk_open_listener(&s);
    lsn = &s.tcpsockets[SOCKET_UNMARK(fd)];

    llk_attacker_syn(&s, LLK_ATT_IP, 41000, 1, 0);
    llk_complete_handshake(&s, lsn, LLK_ATT_IP, 41000, 1);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_ESTABLISHED);

    /* accept() fails (ESTABLISHED) and reverts the port to LISTEN. */
    memset(&peer, 0, sizeof(peer));
    ck_assert_int_eq(wolfIP_sock_accept(&s, fd,
            (struct wolfIP_sockaddr *)&peer, &peer_len), -1);
    ck_assert_int_eq(lsn->sock.tcp.state, TCP_LISTEN);

    /* The option baseline matches a freshly allocated socket. */
    fresh = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(fresh);
    ck_assert_uint_eq(lsn->sock.tcp.rcv_wscale, fresh->sock.tcp.rcv_wscale);
    ck_assert_uint_eq(lsn->sock.tcp.ws_offer, fresh->sock.tcp.ws_offer);
    ck_assert_uint_eq(lsn->sock.tcp.ts_offer, fresh->sock.tcp.ts_offer);
}
END_TEST

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
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 10];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct tcp_parsed_opts po;
    uint32_t left = 0xFFFFFFF0U;
    uint32_t right = 0x00000010U;
    uint8_t *opt;
    uint32_t frame_len;

    memset(seg_buf, 0, sizeof(seg_buf));
    seg->hlen = (uint8_t)((TCP_HEADER_LEN + 10) << 2);
    opt = seg->data;
    opt[0] = TCP_OPTION_SACK;
    opt[1] = 10;
    {
        uint32_t left_be = ee32(left);
        uint32_t right_be = ee32(right);
        memcpy(opt + 2, &left_be, sizeof(left_be));
        memcpy(opt + 6, &right_be, sizeof(right_be));
    }

    frame_len = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 10;
    tcp_parse_options(seg, frame_len, &po);

    ck_assert_int_eq(po.sack_count, 1);
    ck_assert_uint_eq(po.sack[0].left, left);
    ck_assert_uint_eq(po.sack[0].right, right);
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
    ck_assert_uint_eq(ts->sock.tcp.cwnd, TCP_MSS * 3);
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
    mss_be = ee16(512);
    memcpy(&synack.mss_opt[2], &mss_be, sizeof(mss_be));
    fix_tcp_checksums(&synack.seg);

    tcp_input(&s, TEST_PRIMARY_IF, &synack.seg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 4));

    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.peer_mss, 512U);
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
    mss_be = ee16(512);
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
        ck_assert_uint_le(seg_payload, 512U);

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

START_TEST(test_tcp_input_syn_rcvd_ack_invalid_seq_rejected)
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
    ackseg.seq = ee32(ts->sock.tcp.ack + 1);
    ackseg.ack = ee32(ts->sock.tcp.seq + 1);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    fix_tcp_checksums(&ackseg);
    tcp_input(&s, TEST_PRIMARY_IF, &ackseg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
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
    seg.flags = TCP_FLAG_FIN;
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

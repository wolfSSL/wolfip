START_TEST(test_tcp_input_fin_wait_1_fin_with_payload_returns)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    uint8_t payload[4] = {1,2,3,4};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ts->sock.tcp.ack = 104;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);

    memset(buf, 0, sizeof(buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.ttl = 64;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->ip.src = ee32(ts->remote_ip);
    seg->ip.dst = ee32(ts->local_ip);
    seg->dst_port = ee16(ts->src_port);
    seg->src_port = ee16(ts->dst_port);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = (TCP_FLAG_FIN | TCP_FLAG_ACK);
    seg->seq = ee32(100);
    memcpy(seg->data, payload, sizeof(payload));
    fix_tcp_checksums(seg);

    tcp_input(&s, TEST_PRIMARY_IF, seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload)));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSING);
}
END_TEST

START_TEST(test_tcp_input_fin_wait_1_fin_out_of_order_no_transition)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    uint32_t ack = 100;
    uint32_t seq = 111;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ts->sock.tcp.ack = ack;
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
    seg.flags = TCP_FLAG_FIN;
    seg.seq = ee32(seq);
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_1);
    ck_assert_uint_eq(ts->sock.tcp.ack, ack);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, 0);
}
END_TEST

START_TEST(test_tcp_input_fin_wait_1_fin_payload_out_of_order_no_transition)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    uint8_t payload[4] = {1, 2, 3, 4};
    uint32_t ack = 100;
    uint32_t seq = 200;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ts->sock.tcp.ack = ack;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    memset(buf, 0, sizeof(buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.ttl = 64;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->ip.src = ee32(ts->remote_ip);
    seg->ip.dst = ee32(ts->local_ip);
    seg->dst_port = ee16(ts->src_port);
    seg->src_port = ee16(ts->dst_port);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = (TCP_FLAG_FIN | TCP_FLAG_ACK);
    seg->seq = ee32(seq);
    memcpy(seg->data, payload, sizeof(payload));
    fix_tcp_checksums(seg);

    tcp_input(&s, TEST_PRIMARY_IF, seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload)));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_1);
    ck_assert_uint_eq(ts->sock.tcp.ack, ack);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, 0);
    ck_assert_uint_eq(queue_len(&ts->sock.tcp.rxbuf), 0U);
}
END_TEST

START_TEST(test_tcp_input_fin_wait_1_fin_payload_ack_mismatch_no_transition)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    uint8_t payload[4] = {1, 2, 3, 4};
    uint32_t ack = 100;
    uint32_t seq = 100;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ts->sock.tcp.ack = ack;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    memset(buf, 0, sizeof(buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.ttl = 64;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->ip.src = ee32(ts->remote_ip);
    seg->ip.dst = ee32(ts->local_ip);
    seg->dst_port = ee16(ts->src_port);
    seg->src_port = ee16(ts->dst_port);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = (TCP_FLAG_FIN | TCP_FLAG_ACK);
    seg->seq = ee32(seq);
    memcpy(seg->data, payload, sizeof(payload));
    fix_tcp_checksums(seg);

    tcp_input(&s, TEST_PRIMARY_IF, seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload)));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_1);
    ck_assert_uint_eq(ts->sock.tcp.ack, ack);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, 0);
    ck_assert_uint_eq(queue_len(&ts->sock.tcp.rxbuf), 0U);
}
END_TEST

START_TEST(test_tcp_input_header_len_below_min_dropped)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    uint8_t payload[4] = {1, 2, 3, 4};
    uint32_t ack = 100;
    uint32_t seq = 100;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = ack;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);

    memset(buf, 0, sizeof(buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.ttl = 64;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->ip.src = ee32(ts->remote_ip);
    seg->ip.dst = ee32(ts->local_ip);
    seg->dst_port = ee16(ts->src_port);
    seg->src_port = ee16(ts->dst_port);
    seg->seq = ee32(seq);
    seg->ack = ee32(ack);
    seg->flags = TCP_FLAG_ACK;
    seg->hlen = 0; /* invalid: data offset below minimum */
    memcpy(seg->data, payload, sizeof(payload));
    fix_tcp_checksums(seg);

    tcp_input(&s, TEST_PRIMARY_IF, seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload)));

    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.ack, ack);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, 0);
    ck_assert_uint_eq(queue_len(&ts->sock.tcp.rxbuf), 0U);
}
END_TEST

START_TEST(test_tcp_input_fin_wait_2_fin_with_payload_queues)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    uint8_t payload[4] = {9, 8, 7, 6};
    uint8_t out[4] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->sock.tcp.state = TCP_FIN_WAIT_2;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->sock.tcp.ack = 100;

    memset(buf, 0, sizeof(buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.ttl = 64;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->ip.src = ee32(ts->remote_ip);
    seg->ip.dst = ee32(ts->local_ip);
    seg->dst_port = ee16(ts->src_port);
    seg->src_port = ee16(ts->dst_port);
    seg->seq = ee32(100);
    seg->ack = ee32(100);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = TCP_FLAG_FIN | TCP_FLAG_ACK;
    memcpy(seg->data, payload, sizeof(payload));
    fix_tcp_checksums(seg);

    tcp_input(&s, TEST_PRIMARY_IF, seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload)));
    ck_assert_int_eq(queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out)), (int)sizeof(payload));
    ck_assert_mem_eq(out, payload, sizeof(payload));
    ck_assert_uint_eq(ts->sock.tcp.ack, 105);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_TIME_WAIT);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, CB_EVENT_CLOSED);
}
END_TEST

START_TEST(test_tcp_input_fin_wait_2_fin_payload_ack_mismatch_no_transition)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    uint8_t payload[4] = {9, 8, 7, 6};
    uint32_t ack = 100;
    uint32_t seq = 101;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->sock.tcp.state = TCP_FIN_WAIT_2;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->sock.tcp.ack = ack;

    memset(buf, 0, sizeof(buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.ttl = 64;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->ip.src = ee32(ts->remote_ip);
    seg->ip.dst = ee32(ts->local_ip);
    seg->dst_port = ee16(ts->src_port);
    seg->src_port = ee16(ts->dst_port);
    seg->seq = ee32(seq);
    seg->ack = ee32(ack);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = TCP_FLAG_FIN;
    memcpy(seg->data, payload, sizeof(payload));
    fix_tcp_checksums(seg);

    tcp_input(&s, TEST_PRIMARY_IF, seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload)));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_2);
    ck_assert_uint_eq(ts->sock.tcp.ack, ack);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, 0);
    ck_assert_uint_eq(queue_len(&ts->sock.tcp.rxbuf), 0U);
}
END_TEST

START_TEST(test_socket_from_fd_invalid)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_ptr_eq(wolfIP_socket_from_fd(NULL, 1), NULL);
    ck_assert_ptr_eq(wolfIP_socket_from_fd(&s, -1), NULL);
    ck_assert_ptr_eq(wolfIP_socket_from_fd(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS), NULL);
    ck_assert_ptr_eq(wolfIP_socket_from_fd(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS), NULL);
    ck_assert_ptr_eq(wolfIP_socket_from_fd(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS), NULL);
}
END_TEST

START_TEST(test_socket_from_fd_valid)
{
    struct wolfIP s;
    int tcp_sd;
    int udp_sd;
    int icmp_sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(tcp_sd, 0);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_gt(icmp_sd, 0);

    ts = wolfIP_socket_from_fd(&s, tcp_sd);
    ck_assert_ptr_eq(ts, &s.tcpsockets[SOCKET_UNMARK(tcp_sd)]);
    ts = wolfIP_socket_from_fd(&s, udp_sd);
    ck_assert_ptr_eq(ts, &s.udpsockets[SOCKET_UNMARK(udp_sd)]);
    ts = wolfIP_socket_from_fd(&s, icmp_sd);
    ck_assert_ptr_eq(ts, &s.icmpsockets[SOCKET_UNMARK(icmp_sd)]);
}
END_TEST

START_TEST(test_tcp_input_syn_rcvd_ack_wrong_flags)
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
    ackseg.ip.ttl = 64;
    ackseg.ip.proto = WI_IPPROTO_TCP;
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ackseg.ip.src = ee32(ts->remote_ip);
    ackseg.ip.dst = ee32(ts->local_ip);
    ackseg.dst_port = ee16(ts->src_port);
    ackseg.src_port = ee16(ts->dst_port);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = (TCP_FLAG_ACK | TCP_FLAG_PSH);
    fix_tcp_checksums(&ackseg);
    tcp_input(&s, TEST_PRIMARY_IF, &ackseg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
}
END_TEST

START_TEST(test_tcp_input_established_ack_only_returns)
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
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

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
}
END_TEST

START_TEST(test_tcp_input_close_wait_processes_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *queued;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.bytes_in_flight = 1;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    queued = &segbuf.seg;
    queued->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    queued->hlen = TCP_HEADER_LEN << 2;
    queued->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ip.ver_ihl = 0x45;
    ackseg.ip.ttl = 64;
    ackseg.ip.proto = WI_IPPROTO_TCP;
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ackseg.ip.src = ee32(ts->remote_ip);
    ackseg.ip.dst = ee32(ts->local_ip);
    ackseg.src_port = ee16(ts->dst_port);
    ackseg.dst_port = ee16(ts->src_port);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    ackseg.ack = ee32(101);
    ackseg.win = ee16(32);
    fix_tcp_checksums(&ackseg);

    tcp_input(&s, TEST_PRIMARY_IF, &ackseg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSE_WAIT);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, 101U);
    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, 0U);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.tcp.txbuf), NULL);
}
END_TEST

START_TEST(test_tcp_input_closing_processes_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *queued;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    struct wolfIP_timer tmr;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_CLOSING;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->sock.tcp.last = 100;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.bytes_in_flight = 1;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.ctrl_rto_active = 1;
    ts->sock.tcp.ctrl_rto_retries = 2;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    queued = &segbuf.seg;
    queued->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    queued->hlen = TCP_HEADER_LEN << 2;
    queued->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 200;
    tmr.arg = ts;
    ts->sock.tcp.tmr_rto = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ip.ver_ihl = 0x45;
    ackseg.ip.ttl = 64;
    ackseg.ip.proto = WI_IPPROTO_TCP;
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ackseg.ip.src = ee32(ts->remote_ip);
    ackseg.ip.dst = ee32(ts->local_ip);
    ackseg.src_port = ee16(ts->dst_port);
    ackseg.dst_port = ee16(ts->src_port);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    ackseg.ack = ee32(101);
    ackseg.win = ee16(32);
    fix_tcp_checksums(&ackseg);

    tcp_input(&s, TEST_PRIMARY_IF, &ackseg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    ck_assert_int_eq(ts->sock.tcp.state, TCP_TIME_WAIT);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, 101U);
    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, 0U);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.tcp.txbuf), NULL);
    ck_assert_int_eq(ts->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_active, 0U);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_retries, 0U);
}
END_TEST

START_TEST(test_tcp_sock_close_state_transitions)
{
    struct wolfIP s;
    struct tsocket *ts;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_1);

    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LAST_ACK);

    ts->sock.tcp.state = TCP_FIN_WAIT_2;
    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_2);

    ts->sock.tcp.state = TCP_CLOSING;
    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSING);

    ts->sock.tcp.state = TCP_LISTEN;
    ck_assert_int_eq(wolfIP_sock_close(&s, sd), 0);
    ck_assert_int_eq(ts->proto, 0);
}
END_TEST
START_TEST(test_fifo_push_wrap) {
    struct fifo f;
    uint8_t buffer[100];
    uint8_t data[] = {1, 2, 3, 4};
    int ret;
    struct pkt_desc *desc;
    fifo_init(&f, buffer, sizeof(buffer));
    fifo_push(&f, data, sizeof(data)); // Add data to FIFO

    // Pop the data to make space
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);

    // Push data to wrap around the buffer
    ret = fifo_push(&f, data, sizeof(data));
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(desc->len, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data));
}
END_TEST

START_TEST(test_fifo_push_wrap_multiple) {
    struct fifo f;
    uint8_t data[] = {1, 2, 3, 4};
    uint8_t data2[] = {5, 6, 7, 8, 9};
    int ret;
    struct pkt_desc *desc;
    fifo_init(&f, mem, memsz);
    fifo_push(&f, data, sizeof(data)); // Add data to FIFO

    // Pop the data to make space
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);

    // Push data to wrap around the buffer
    ret = fifo_push(&f, data, sizeof(data));
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(desc->len, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data));

    // Push more data to wrap around the buffer
    ret = fifo_push(&f, data2, sizeof(data2));
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(fifo_len(&f), sizeof(data2) + sizeof(data) + 2 * sizeof(struct pkt_desc));
}
END_TEST

START_TEST(test_fifo_push_wrap_tail_equals_needed)
{
    struct fifo f;
    uint8_t buffer[64];
    uint8_t payload[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44};
    uint32_t needed = (uint32_t)(sizeof(struct pkt_desc) + sizeof(payload));
    struct pkt_desc *desc;

    fifo_init(&f, buffer, sizeof(buffer));
    f.head = 60;
    f.tail = needed;
    f.h_wrap = 0;

    ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    ck_assert_uint_eq(f.h_wrap, 60U);
    ck_assert_uint_eq(f.head, needed);

    desc = (struct pkt_desc *)buffer;
    ck_assert_uint_eq(desc->pos, 0U);
    ck_assert_uint_eq(desc->len, sizeof(payload));
}
END_TEST

START_TEST(test_fifo_can_push_len_wrap_tail_equals_needed)
{
    struct fifo f;
    uint8_t buffer[64];
    uint32_t len = 8U;
    uint32_t needed = (uint32_t)(sizeof(struct pkt_desc) + len);

    fifo_init(&f, buffer, sizeof(buffer));
    f.head = 60;
    f.tail = needed;
    f.h_wrap = 0;

    ck_assert_int_eq(fifo_can_push_len(&f, len), 1);
}
END_TEST

START_TEST(test_fifo_space_wrap_sets_hwrap)
{
    struct fifo f;
    size_t total = sizeof(struct pkt_desc) + LINK_MTU + 64;
    uint8_t *buf = malloc(total);
    uint32_t space;
    uint32_t expected;

    ck_assert_ptr_nonnull(buf);
    fifo_init(&f, buf, (uint32_t)total);
    f.head = (uint32_t)(total - 8);
    f.tail = (uint32_t)(sizeof(struct pkt_desc) + LINK_MTU + 8);
    f.h_wrap = 0;

    space = fifo_space(&f);
    expected = (uint32_t)total - (f.head - f.tail);
    ck_assert_uint_eq(f.h_wrap, 0);
    ck_assert_uint_eq(space, expected);

    free(buf);
}
END_TEST

START_TEST(test_fifo_space_wrap_returns_zero)
{
    struct fifo f;
    size_t total = sizeof(struct pkt_desc) + LINK_MTU + 32;
    uint8_t *buf = malloc(total);
    uint32_t space;

    ck_assert_ptr_nonnull(buf);
    fifo_init(&f, buf, (uint32_t)total);
    f.head = (uint32_t)(total - 8);
    f.tail = 8;
    f.h_wrap = 0;

    space = fifo_space(&f);
    ck_assert_uint_eq(space, (uint32_t)total - (f.head - f.tail));
    ck_assert_uint_eq(f.h_wrap, 0);

    free(buf);
}
END_TEST

START_TEST(test_fifo_peek_wrap_to_start)
{
    struct fifo f;
    size_t total = sizeof(struct pkt_desc) + LINK_MTU + 8;
    uint8_t *buf = malloc(total);
    struct pkt_desc *desc;
    struct pkt_desc *peeked;

    ck_assert_ptr_nonnull(buf);
    fifo_init(&f, buf, (uint32_t)total);
    f.head = 8;
    f.tail = 4;
    f.h_wrap = 8;

    desc = (struct pkt_desc *)buf;
    memset(desc, 0, sizeof(*desc));
    desc->len = 1;
    desc->pos = 0;

    /* When tail crosses h_wrap, peek should wrap to the start and return
     * the first descriptor at offset 0. */
    peeked = fifo_peek(&f);
    ck_assert_ptr_eq(peeked, desc);

    free(buf);
}
END_TEST

START_TEST(test_fifo_len_with_hwrap)
{
    struct fifo f;
    uint8_t buf[256];

    fifo_init(&f, buf, sizeof(buf));
    f.head = 64;
    f.tail = 128;
    f.h_wrap = 200;

    ck_assert_uint_eq(fifo_len(&f), f.h_wrap - f.tail + f.head);
}
END_TEST

START_TEST(test_fifo_peek_aligns_tail)
{
    struct fifo f;
    uint8_t buf[64];
    struct pkt_desc *desc;
    struct pkt_desc *peeked;

    fifo_init(&f, buf, sizeof(buf));
    f.tail = 2;
    f.head = 16;
    desc = (struct pkt_desc *)(buf + 4);
    memset(desc, 0, sizeof(*desc));
    desc->len = 1;
    desc->pos = 4;

    /* Peek aligns tail to 4-byte boundary before reading the descriptor. */
    peeked = fifo_peek(&f);
    ck_assert_ptr_eq(peeked, desc);
    ck_assert_uint_eq(f.tail, 4);
}
END_TEST

START_TEST(test_fifo_next_wraps_to_start)
{
    struct fifo f;
    size_t total = sizeof(struct pkt_desc) + LINK_MTU + 8;
    uint8_t *buf = malloc(total);
    struct pkt_desc *desc;
    struct pkt_desc *next;
    uint32_t h_wrap = 64;
    uint32_t len;

    ck_assert_ptr_nonnull(buf);
    fifo_init(&f, buf, (uint32_t)total);
    desc = (struct pkt_desc *)buf;
    memset(desc, 0, sizeof(*desc));
    desc->pos = 0;
    len = h_wrap - desc->pos;
    desc->len = len - sizeof(struct pkt_desc);
    f.head = 128;
    f.h_wrap = h_wrap;

    next = fifo_next(&f, desc);
    ck_assert_ptr_eq(next, (struct pkt_desc *)buf);

    free(buf);
}
END_TEST

START_TEST(test_fifo_space_head_lt_tail)
{
    struct fifo f;
    size_t total = sizeof(struct pkt_desc) + LINK_MTU + 128;
    uint8_t *buf = malloc(total);
    uint32_t space;

    ck_assert_ptr_nonnull(buf);
    fifo_init(&f, buf, (uint32_t)total);
    f.head = 50;
    f.tail = 200;
    f.h_wrap = 0;

    space = fifo_space(&f);
    ck_assert_uint_eq(space, f.tail - f.head);

    free(buf);
}
END_TEST

START_TEST(test_fifo_space_with_hwrap)
{
    struct fifo f;
    uint8_t buf[512];
    uint32_t space;

    fifo_init(&f, buf, sizeof(buf));
    f.head = 50;
    f.tail = 200;
    f.h_wrap = 300;

    space = fifo_space(&f);
    ck_assert_uint_eq(space, f.tail - f.head);
}
END_TEST

START_TEST(test_fifo_space_hwrap_head_hits_wrap)
{
    struct fifo f;
    uint8_t buf[512];
    uint32_t space;

    fifo_init(&f, buf, sizeof(buf));
    f.head = 300;
    f.tail = 200;
    f.h_wrap = 300;

    space = fifo_space(&f);
    ck_assert_uint_eq(space, 0);
}
END_TEST

START_TEST(test_fifo_space_hwrap_head_ge_tail_returns_zero)
{
    struct fifo f;
    uint8_t buf[512];
    uint32_t space;

    fifo_init(&f, buf, sizeof(buf));
    f.head = 220;
    f.tail = 200;
    f.h_wrap = 300;

    space = fifo_space(&f);
    ck_assert_uint_eq(space, 0);
}
END_TEST

START_TEST(test_fifo_push_no_contiguous_space_even_with_space)
{
    struct fifo f;
    uint8_t buf[4096];
    uint8_t payload[1592];
    int ret;

    fifo_init(&f, buf, sizeof(buf));
    f.head = 2506;
    f.tail = 1500;
    f.h_wrap = 0;

    memset(payload, 0xCD, sizeof(payload));
    ret = fifo_push(&f, payload, sizeof(payload));
    ck_assert_int_eq(ret, -1);
    ck_assert_uint_eq(f.h_wrap, 0);
}
END_TEST

START_TEST(test_fifo_next_hits_hwrap)
{
    struct fifo f;
    uint8_t buf[256];
    struct pkt_desc *desc;
    struct pkt_desc *next;
    uint32_t pos = 20;
    uint32_t h_wrap = 64;
    uint32_t len;

    fifo_init(&f, buf, sizeof(buf));
    f.head = 120;
    f.h_wrap = h_wrap;

    desc = (struct pkt_desc *)(buf + pos);
    memset(desc, 0, sizeof(*desc));
    len = h_wrap - pos;
    if (len < sizeof(struct pkt_desc))
        len = sizeof(struct pkt_desc);
    desc->len = len - sizeof(struct pkt_desc);
    while ((desc->pos + sizeof(struct pkt_desc) + desc->len) % 4)
        desc->len++;
    desc->pos = pos;

    next = fifo_next(&f, desc);
    ck_assert_ptr_eq(next, (struct pkt_desc *)buf);
}
END_TEST

START_TEST(test_fifo_next_aligned_len_exceeds_size_returns_null)
{
    struct fifo f;
    uint8_t buf[128];
    struct pkt_desc *desc;
    struct pkt_desc *next;
    uint32_t sz = (uint32_t)(sizeof(struct pkt_desc) + 1U);
    uint32_t pos = 1U;
    uint32_t adv;

    fifo_init(&f, buf, sz);
    f.head = 8;
    f.h_wrap = 0;

    desc = (struct pkt_desc *)(buf + pos);
    memset(desc, 0, sizeof(*desc));
    desc->pos = pos;
    desc->len = 1U; /* accepted by precheck: <= f.size - sizeof(pkt_desc). */

    adv = (uint32_t)(sizeof(struct pkt_desc) + desc->len);
    while ((pos + adv) % 4U)
        adv++;
    ck_assert_uint_gt(adv, (f.size - pos));

    /* Alignment padding would make traversal exceed queue bounds. */
    next = fifo_next(&f, desc);
    ck_assert_ptr_null(next);
}
END_TEST

START_TEST(test_fifo_len_tail_gt_head_no_hwrap)
{
    struct fifo f;
    uint8_t buf[256];

    fifo_init(&f, buf, sizeof(buf));
    f.head = 20;
    f.tail = 100;
    f.h_wrap = 0;

    ck_assert_uint_eq(fifo_len(&f), f.size - (f.tail - f.head));
}
END_TEST

START_TEST(test_fifo_pop_wrap_to_start)
{
    struct fifo f;
    size_t total = sizeof(struct pkt_desc) + LINK_MTU + 8;
    uint8_t *buf = malloc(total);
    struct pkt_desc *desc;
    struct pkt_desc *popped;

    ck_assert_ptr_nonnull(buf);
    fifo_init(&f, buf, (uint32_t)total);
    f.head = 8;
    f.tail = 4;
    f.h_wrap = 8;

    desc = (struct pkt_desc *)buf;
    memset(desc, 0, sizeof(*desc));
    desc->len = 1;
    desc->pos = 0;

    /* Pop should wrap to start and return the descriptor at offset 0. */
    popped = fifo_pop(&f);
    ck_assert_ptr_eq(popped, desc);

    free(buf);
}
END_TEST

START_TEST(test_fifo_next_success) {
    struct fifo f;
    uint8_t data1[] = {1, 2, 3, 4};
    uint8_t data2[] = {5, 6, 7, 8, 9};
    struct pkt_desc *desc;
    struct pkt_desc *next_desc;

    fifo_init(&f, mem, memsz);

    // Add two packets to the FIFO
    fifo_push(&f, data1, sizeof(data1));
    fifo_push(&f, data2, sizeof(data2));
    ck_assert_int_eq(fifo_len(&f), sizeof(data1) + sizeof(data2) + 2 * sizeof(struct pkt_desc));

    // Get the first packet descriptor
    desc = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc);

    // Get the next packet descriptor using fifo_next
    next_desc = fifo_next(&f, desc);
    ck_assert_ptr_nonnull(next_desc); // Ensure next descriptor is valid
    ck_assert_int_eq(next_desc->len, sizeof(data2)); // Check length of next packet
}

START_TEST(test_fifo_next_empty_fifo) {
    struct fifo f;
    struct pkt_desc *desc;
    struct pkt_desc *next_desc;
    fifo_init(&f, mem, memsz);

    // Start with an empty FIFO
    desc = NULL;
    next_desc = fifo_next(&f, desc);
    ck_assert_ptr_eq(next_desc, NULL); // Ensure next returns NULL on empty FIFO
}

START_TEST(test_fifo_next_end_of_fifo) {
    struct fifo f;
    uint8_t data[] = {1, 2, 3, 4};
    struct pkt_desc *desc;
    struct pkt_desc *next_desc;

    fifo_init(&f, mem, memsz);
    fifo_push(&f, data, sizeof(data));

    desc = fifo_peek(&f); // Get first packet
    fifo_pop(&f); // Simulate removing the packet
    next_desc = fifo_next(&f, desc);
    ck_assert_ptr_eq(next_desc, NULL); // Should return NULL as there are no more packets
}
END_TEST
START_TEST(test_queue_init) {
    struct queue q;
    queue_init(&q, mem, memsz, 0x12345678);
    ck_assert_int_eq(q.size, memsz);
    ck_assert_ptr_eq(q.data, mem);
    ck_assert_int_eq(q.head, 0);
    ck_assert_int_eq(q.tail, 0);
    ck_assert_int_eq(q.seq_base, 0x12345678);

}
END_TEST

START_TEST(test_queue_space_empty) {
    struct queue q;

    queue_init(&q, mem, memsz, 0x12345678);
    ck_assert_int_eq(queue_space(&q), memsz - 1);  // Reserve one byte to disambiguate full/empty

}
END_TEST

START_TEST(test_queue_len_empty) {
    struct queue q;

    queue_init(&q, mem, memsz, 0x12345678);
    ck_assert_int_eq(queue_len(&q), 0);  // No bytes should be in use

}
END_TEST

START_TEST(test_queue_partial_fill) {
    struct queue q;
    queue_init(&q, mem, memsz, 0x12345678);
    q.head = 256;  // Simulate adding 256 bytes of data
    ck_assert_int_eq(queue_space(&q), memsz - 257);
    ck_assert_int_eq(queue_len(&q), 256);

}
END_TEST

START_TEST(test_queue_wrap_around) {
    struct queue q;
    queue_init(&q, mem, memsz, 0x12345678);
    q.head = 800;
    q.tail = 200;  // Head has wrapped around, so 600 bytes are filled
    ck_assert_int_eq(queue_space(&q), q.size - 601);
    ck_assert_int_eq(queue_len(&q), 600);  // 600 bytes filled
}
END_TEST

START_TEST(test_queue_insert_empty) {
    struct queue q;
    uint8_t data[] = {1, 2, 3, 4};
    int res;
    queue_init(&q, mem, memsz, 0x12345678);

    res = queue_insert(&q, data, 0, sizeof(data));
    ck_assert_int_eq(res, 0);
    ck_assert_int_eq(queue_len(&q), sizeof(data));
    ck_assert_int_eq(q.head, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)q.data, data, sizeof(data));
}
END_TEST

START_TEST(test_queue_insert_sequential) {
    struct queue q;
    uint8_t data1[] = {1, 2};
    uint8_t data2[] = {3, 4};
    int res1;
    int res2;
    queue_init(&q, mem, memsz, 0x12345678);

    res1 = queue_insert(&q, data1, 0, sizeof(data1));
    res2 = queue_insert(&q, data2, 2, sizeof(data2));
    ck_assert_int_eq(res1, 0);
    ck_assert_int_eq(res2, 0);
    ck_assert_int_eq(queue_len(&q), sizeof(data1) + sizeof(data2));
    ck_assert_mem_eq((const uint8_t *)q.data, data1, sizeof(data1));
    ck_assert_mem_eq((uint8_t *)q.data + 2, data2, sizeof(data2));
}
END_TEST

START_TEST(test_queue_insert_negative_diff)
{
    struct queue q;
    uint8_t mem[32];
    uint8_t data[4] = {1, 2, 3, 4};

    queue_init(&q, mem, sizeof(mem), 100);
    ck_assert_int_eq(queue_insert(&q, data, 100, sizeof(data)), 0);
    ck_assert_int_eq(queue_insert(&q, data, 90, sizeof(data)), -1);
}
END_TEST

START_TEST(test_queue_insert_wraparound_contiguous_and_old_rejected)
{
    struct queue q;
    uint8_t mem[64];
    uint8_t data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t out[32];
    uint32_t next_seq;

    queue_init(&q, mem, sizeof(mem), 0xFFFFFFFCU);
    ck_assert_int_eq(queue_insert(&q, data, 0xFFFFFFFCU, sizeof(data)), 0);
    next_seq = 0xFFFFFFFCU + (uint32_t)sizeof(data);
    ck_assert_int_eq(queue_insert(&q, data, next_seq, sizeof(data)), 0);
    ck_assert_int_eq(queue_len(&q), (int)(sizeof(data) * 2));

    /* A sequence behind base after wrap must not be accepted. */
    ck_assert_int_eq(queue_insert(&q, data, 0xFFFFFFF0U, sizeof(data)), -1);
    ck_assert_int_eq(queue_pop(&q, out, sizeof(out)), (int)(sizeof(data) * 2));
}
END_TEST

START_TEST(test_queue_insert_pos_gt_size)
{
    struct queue q;
    uint8_t mem[16];
    uint8_t data[4] = {1, 2, 3, 4};

    queue_init(&q, mem, sizeof(mem), 0);
    ck_assert_int_eq(queue_insert(&q, data, 0, sizeof(data)), 0);
    ck_assert_int_eq(queue_insert(&q, data, 32, sizeof(data)), -1);
}
END_TEST

START_TEST(test_queue_insert_ancient_data)
{
    struct queue q;
    uint8_t mem[32];
    uint8_t data[8] = {0};
    uint8_t out[4];

    queue_init(&q, mem, sizeof(mem), 0);
    ck_assert_int_eq(queue_insert(&q, data, 0, sizeof(data)), 0);
    ck_assert_int_eq(queue_pop(&q, out, sizeof(out)), (int)sizeof(out));
    ck_assert_int_eq(queue_insert(&q, data, 5, sizeof(data)), 0);
}
END_TEST

START_TEST(test_queue_insert_wrap)
{
    struct queue q;
    uint8_t mem[16];
    uint8_t first[12];
    uint8_t second[3];
    uint8_t out[16];

    memset(first, 0xAB, sizeof(first));
    memset(second, 0xCD, sizeof(second));
    queue_init(&q, mem, sizeof(mem), 0);
    ck_assert_int_eq(queue_insert(&q, first, 0, sizeof(first)), 0);
    ck_assert_int_eq(queue_pop(&q, out, 10), 10);
    ck_assert_int_eq(queue_insert(&q, second, 12, sizeof(second)), 0);
    ck_assert_uint_eq(queue_len(&q), 5);
    ck_assert_int_eq(queue_pop(&q, out, 2), 2);
    ck_assert_mem_eq(out, first + 10, 2);
    ck_assert_int_eq(queue_pop(&q, out, 3), 3);
    ck_assert_mem_eq(out, second, 3);
}
END_TEST

START_TEST(test_queue_space_wrap)
{
    struct queue q;
    uint8_t mem[16];

    queue_init(&q, mem, sizeof(mem), 0);
    q.head = 4;
    q.tail = 12;
    ck_assert_uint_eq(queue_space(&q), (q.tail - q.head) - 1);
}
END_TEST

START_TEST(test_queue_full_state_not_empty_and_drains_data)
{
    struct queue q;
    uint8_t mem[16];
    uint8_t data[15];
    uint8_t out[15];
    int i;

    for (i = 0; i < (int)sizeof(data); i++)
        data[i] = (uint8_t)(i + 1);
    queue_init(&q, mem, sizeof(mem), 1000);
    ck_assert_int_eq(queue_insert(&q, data, 1000, sizeof(data)), 0);
    ck_assert_uint_eq(queue_len(&q), sizeof(data));
    ck_assert_uint_eq(queue_space(&q), 0);
    ck_assert_int_eq(queue_pop(&q, out, sizeof(out)), (int)sizeof(out));
    ck_assert_mem_eq(out, data, sizeof(data));
    ck_assert_uint_eq(queue_len(&q), 0);
    ck_assert_uint_eq(queue_space(&q), sizeof(mem) - 1);
}
END_TEST

START_TEST(test_poll_tcp_residual_window_gates_data_segment)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xef};
    struct pkt_desc *desc;
    struct pkt_desc *sent_desc;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.ack = 20;
    ts->sock.tcp.last_ack = 0;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.cwnd = 32;
    ts->sock.tcp.peer_rwnd = 20;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* Keep 12 bytes in-flight, then queue 16 new bytes. Residual window is 8. */
    ck_assert_int_eq(enqueue_tcp_tx(ts, 12, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    sent_desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(sent_desc);
    sent_desc->flags |= PKT_FLAG_SENT;
    ts->sock.tcp.bytes_in_flight = 12;

    ts->sock.tcp.seq = 12;
    ck_assert_int_eq(enqueue_tcp_tx(ts, 16, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    desc = fifo_next(&ts->sock.tcp.txbuf, sent_desc);
    ck_assert_ptr_nonnull(desc);

    (void)wolfIP_poll(&s, 200);

    ck_assert_uint_eq(last_frame_sent_size, 0);
    ck_assert_ptr_eq(fifo_next(&ts->sock.tcp.txbuf, sent_desc), desc);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_poll_tcp_residual_window_allows_exact_fit)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *sent_desc;
    struct pkt_desc *data_desc;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xf0};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.ack = 20;
    ts->sock.tcp.last_ack = 0;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.cwnd = 32;
    ts->sock.tcp.peer_rwnd = 20;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* Keep 4 bytes in-flight, then queue 16 bytes: exact residual-window fit. */
    ck_assert_int_eq(enqueue_tcp_tx(ts, 4, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    sent_desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(sent_desc);
    sent_desc->flags |= PKT_FLAG_SENT;
    ts->sock.tcp.bytes_in_flight = 4;

    ts->sock.tcp.seq = 4;
    ck_assert_int_eq(enqueue_tcp_tx(ts, 16, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    data_desc = fifo_next(&ts->sock.tcp.txbuf, sent_desc);
    ck_assert_ptr_nonnull(data_desc);

    (void)wolfIP_poll(&s, 200);

    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_int_ne(data_desc->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_poll_tcp_zero_window_arms_persist)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xf1};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.ack = 20;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = 0;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 8, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    (void)wolfIP_poll(&s, 200);

    ck_assert_uint_eq(last_frame_sent_size, 0);
    ck_assert_uint_eq(ts->sock.tcp.persist_active, 1);
    ck_assert_int_ne(ts->sock.tcp.tmr_persist, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_persist_start_stops_when_window_reopens_or_no_unsent_payload)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.peer_rwnd = 0;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 8, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);

    /* Baseline: zero peer window plus unsent payload arms persist probing. */
    tcp_persist_start(ts, 1000);
    ck_assert_uint_eq(ts->sock.tcp.persist_active, 1);
    ck_assert_int_ne(ts->sock.tcp.tmr_persist, NO_TIMER);

    /* Reopening the advertised window should tear persist state back down. */
    ts->sock.tcp.persist_backoff = 3;
    ts->sock.tcp.peer_rwnd = 32;
    tcp_persist_start(ts, 1100);
    ck_assert_uint_eq(ts->sock.tcp.persist_active, 0);
    ck_assert_uint_eq(ts->sock.tcp.persist_backoff, 0);
    ck_assert_int_eq(ts->sock.tcp.tmr_persist, NO_TIMER);

    /* Closing the window again with the same queued data should re-arm persist. */
    ts->sock.tcp.peer_rwnd = 0;
    tcp_persist_start(ts, 1200);
    ck_assert_uint_eq(ts->sock.tcp.persist_active, 1);
    ck_assert_int_ne(ts->sock.tcp.tmr_persist, NO_TIMER);

    /* Once the queued segment is no longer unsent payload, the guard must stop probing. */
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    ts->sock.tcp.persist_backoff = 5;
    tcp_persist_start(ts, 1300);
    ck_assert_uint_eq(ts->sock.tcp.persist_active, 0);
    ck_assert_uint_eq(ts->sock.tcp.persist_backoff, 0);
    ck_assert_int_eq(ts->sock.tcp.tmr_persist, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_persist_helpers_ignore_non_tcp_and_null_inputs)
{
    struct wolfIP s;
    struct tsocket ts;

    wolfIP_init(&s);
    memset(&ts, 0, sizeof(ts));
    ts.S = &s;
    ts.proto = WI_IPPROTO_UDP;
    ts.sock.tcp.persist_active = 1;
    ts.sock.tcp.persist_backoff = 3;
    ts.sock.tcp.tmr_persist = 77;

    ck_assert_int_eq(tcp_has_pending_unsent_payload(NULL), 0);
    tcp_persist_stop(NULL);
    tcp_persist_start(NULL, 1);
    tcp_persist_stop(&ts);
    ck_assert_uint_eq(ts.sock.tcp.persist_active, 1);
    ck_assert_uint_eq(ts.sock.tcp.persist_backoff, 3);
    ck_assert_int_eq(ts.sock.tcp.tmr_persist, 77);
    tcp_persist_start(&ts, 100);
    ck_assert_uint_eq(ts.sock.tcp.persist_active, 1);
    ck_assert_uint_eq(ts.sock.tcp.persist_backoff, 3);
    ck_assert_int_eq(ts.sock.tcp.tmr_persist, 77);
}
END_TEST

START_TEST(test_tcp_has_pending_unsent_payload_ignores_zero_ip_len_ack_only_desc)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg *seg;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 0, TCP_FLAG_ACK), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    seg = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
    seg->ip.len = 0;

    ck_assert_int_eq(tcp_has_pending_unsent_payload(ts), 0);
}
END_TEST

START_TEST(test_tcp_zero_wnd_probe_rejects_invalid_inputs_and_empty_payload)
{
    struct wolfIP s;
    struct tsocket ts;

    wolfIP_init(&s);
    memset(&ts, 0, sizeof(ts));
    ts.S = &s;
    ts.proto = WI_IPPROTO_UDP;
    fifo_init(&ts.sock.tcp.txbuf, ts.txmem, TXBUF_SIZE);

    ck_assert_int_eq(tcp_send_zero_wnd_probe(NULL), -1);
    ck_assert_int_eq(tcp_send_zero_wnd_probe(&ts), -1);

    ts.proto = WI_IPPROTO_TCP;
    ck_assert_int_eq(tcp_send_zero_wnd_probe(&ts), -1);
}
END_TEST

START_TEST(test_tcp_zero_wnd_probe_skips_ack_only_segment)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *ack_desc;
    struct pkt_desc *data_desc;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x46};
    uint8_t payload[4] = {0x51, 0x52, 0x53, 0x54};
    struct wolfIP_tcp_seg *tcp;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.seq = 20;
    ts->sock.tcp.snd_una = 20;
    ts->sock.tcp.ack = 30;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 0, TCP_FLAG_ACK), 0);
    ck_assert_int_eq(enqueue_tcp_tx_with_payload(ts, payload, sizeof(payload),
            (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    ack_desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(ack_desc);
    ((struct wolfIP_tcp_seg *)(ts->txmem + ack_desc->pos + sizeof(*ack_desc)))->ip.len = 0;
    data_desc = fifo_next(&ts->sock.tcp.txbuf, ack_desc);
    ck_assert_ptr_nonnull(data_desc);
    ((struct wolfIP_tcp_seg *)(ts->txmem + data_desc->pos + sizeof(*data_desc)))->ip.len = 0;
    ck_assert_int_eq(tcp_send_zero_wnd_probe(ts), 0);

    ck_assert_uint_gt(last_frame_sent_size, 0);
    tcp = (struct wolfIP_tcp_seg *)last_frame_sent;
    ck_assert_uint_eq(ee32(tcp->seq), 20U);
    ck_assert_uint_eq(tcp->data[0], payload[0]);
}
END_TEST

START_TEST(test_tcp_persist_cb_sends_one_byte_probe)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xf2};
    struct wolfIP_ip_packet *ip;
    struct wolfIP_tcp_seg *tcp;
    uint32_t ip_len;
    uint32_t tcp_hlen;
    uint8_t payload[8] = {0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.seq = 10;
    ts->sock.tcp.ack = 20;
    ts->sock.tcp.snd_una = 13;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = 0;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx_with_payload(ts, payload, sizeof(payload), (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    s.last_tick = 500;
    tcp_persist_cb(ts);

    ck_assert_uint_gt(last_frame_sent_size, 0);
    ip = (struct wolfIP_ip_packet *)last_frame_sent;
    tcp = (struct wolfIP_tcp_seg *)last_frame_sent;
    ip_len = ee16(ip->len);
    tcp_hlen = (uint32_t)(tcp->hlen >> 2);
    ck_assert_uint_eq(ip_len - (IP_HEADER_LEN + tcp_hlen), 1U);
    ck_assert_uint_eq(ee32(tcp->seq), ts->sock.tcp.snd_una);
    ck_assert_uint_eq(tcp->data[0], 0x18U);
    ck_assert_uint_eq(tcp->flags & TCP_FLAG_ACK, TCP_FLAG_ACK);
    ck_assert_uint_eq(ts->sock.tcp.persist_active, 1);
    ck_assert_int_ne(ts->sock.tcp.tmr_persist, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_zero_wnd_probe_selects_middle_byte_at_snd_una)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x45};
    uint8_t payload[8] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    struct wolfIP_tcp_seg *tcp;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.seq = 100;
    ts->sock.tcp.snd_una = 103;
    ts->sock.tcp.ack = 20;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* snd_una points into the middle of this payload, so the probe must reuse that byte. */
    ck_assert_int_eq(enqueue_tcp_tx_with_payload(ts, payload, sizeof(payload),
            (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    ck_assert_int_eq(tcp_send_zero_wnd_probe(ts), 0);

    ck_assert_uint_gt(last_frame_sent_size, 0);
    tcp = (struct wolfIP_tcp_seg *)last_frame_sent;
    ck_assert_uint_eq(ee32(tcp->seq), 103U);
    ck_assert_uint_eq(tcp->data[0], payload[3]);
}
END_TEST

START_TEST(test_tcp_initial_cwnd_caps_to_iw10_and_half_rwnd)
{
    ck_assert_uint_eq(tcp_initial_cwnd(65535U, 1460U), 14600U);
    ck_assert_uint_eq(tcp_initial_cwnd(4000U, 1460U), 2920U);
    ck_assert_uint_eq(tcp_initial_cwnd(0U, 1460U), 2920U);
}
END_TEST

START_TEST(test_tcp_persist_probe_byte_matches_snd_una_offset)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x44};
    uint8_t payload[8] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    struct wolfIP_tcp_seg *tcp;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.seq = 100;
    ts->sock.tcp.snd_una = 103;
    ts->sock.tcp.ack = 20;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = 0;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx_with_payload(ts, payload, sizeof(payload), (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    s.last_tick = 1000;
    tcp_persist_cb(ts);

    ck_assert_uint_gt(last_frame_sent_size, 0);
    tcp = (struct wolfIP_tcp_seg *)last_frame_sent;
    ck_assert_uint_eq(ee32(tcp->seq), 103U);
    ck_assert_uint_eq(tcp->data[0], payload[3]);
}
END_TEST

START_TEST(test_tcp_zero_wnd_probe_arp_miss_requests_resolution)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct arp_packet *arp;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t payload[4] = {0x21, 0x22, 0x23, 0x24};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    s.last_tick = 1000;
    last_frame_sent_size = 0;

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.seq = 10;
    ts->sock.tcp.snd_una = 10;
    ts->sock.tcp.ack = 20;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* With no ARP cache entry for the peer, probing should trigger resolution instead of send. */
    ck_assert_int_eq(enqueue_tcp_tx_with_payload(ts, payload, sizeof(payload),
            (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    ck_assert_int_eq(tcp_send_zero_wnd_probe(ts), -1);

    ck_assert_uint_eq(last_frame_sent_size, sizeof(struct arp_packet));
    arp = (struct arp_packet *)last_frame_sent;
    ck_assert_int_eq(arp->opcode, ee16(ARP_REQUEST));
    ck_assert_int_eq(arp->tip, ee32(remote_ip));
}
END_TEST

START_TEST(test_tcp_rto_cb_marks_snd_una_payload_for_retransmit)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;
    struct wolfIP_timer tmr;
    uint32_t smss;
    uint8_t payload[4] = {0x31, 0x32, 0x33, 0x34};

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.seq = 100;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.rto_backoff = 1;
    ts->sock.tcp.bytes_in_flight = sizeof(payload);
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.ssthresh = TCP_MSS * 8;
    ts->sock.tcp.peer_sack_count = 2;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* Seed one sent payload segment so data-RTO has a retransmission candidate. */
    ck_assert_int_eq(enqueue_tcp_tx_with_payload(ts, payload, sizeof(payload),
            (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 100;
    ts->sock.tcp.tmr_rto = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);

    /* This callback should discard stale SACK state and retransmit from snd_una. */
    s.last_tick = 500;
    tcp_rto_cb(ts);

    smss = tcp_cc_mss(ts);
    /* RTO recovery should restart from one MSS and leave the segment pending retransmit. */
    ck_assert_uint_eq(ts->sock.tcp.peer_sack_count, 0);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc->flags & PKT_FLAG_RETRANS, 0);
    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, 0);
    ck_assert_uint_eq(ts->sock.tcp.rto_backoff, 2);
    ck_assert_uint_eq(ts->sock.tcp.cwnd, smss);
    ck_assert_uint_eq(ts->sock.tcp.ssthresh, 2 * smss);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_rto_cb_clears_bookkeeping_when_no_payload_pending)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_timer tmr;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.rto_backoff = 3;
    ts->sock.tcp.bytes_in_flight = 64;
    ts->sock.tcp.peer_sack_count = 1;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 100;
    ts->sock.tcp.tmr_rto = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);

    /* If bookkeeping says bytes are in flight but no payload is queued, recover by clearing state. */
    tcp_rto_cb(ts);

    /* No retransmission should be armed in this recovery-only path. */
    ck_assert_uint_eq(ts->sock.tcp.peer_sack_count, 0);
    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, 0);
    ck_assert_uint_eq(ts->sock.tcp.rto_backoff, 0);
    ck_assert_int_eq(ts->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_int_ne(ts->events & CB_EVENT_WRITABLE, 0);
}
END_TEST

START_TEST(test_tcp_rto_cb_does_not_signal_writable_for_zero_ip_len_ack_only_desc)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg *seg;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 100;
    ts->sock.tcp.rto_backoff = 3;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 0, TCP_FLAG_ACK), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    seg = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
    seg->ip.len = 0;
    seg->seq = ee32(100);

    tcp_rto_cb(ts);
    ck_assert_uint_eq(ts->sock.tcp.rto_backoff, 0);
    ck_assert_int_eq(ts->events & CB_EVENT_WRITABLE, 0);
}
END_TEST
START_TEST(test_tcp_rto_cb_closes_socket_when_backoff_exhausted)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;
    struct wolfIP_timer tmr;
    uint8_t payload[4] = {0x41, 0x42, 0x43, 0x44};

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.seq = 200;
    ts->sock.tcp.snd_una = 200;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.rto_backoff = TCP_RTO_MAX_BACKOFF;
    ts->sock.tcp.bytes_in_flight = sizeof(payload);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* Present one outstanding payload so the callback takes the data-RTO close path. */
    ck_assert_int_eq(enqueue_tcp_tx_with_payload(ts, payload, sizeof(payload),
            (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 100;
    ts->sock.tcp.tmr_rto = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);

    /* Once data-RTO backoff is exhausted, the callback should abandon the TCP socket. */
    tcp_rto_cb(ts);

    /* close_socket() zeros the descriptor, so the original TCP identity should be gone. */
    ck_assert_int_eq(ts->proto, 0);
    ck_assert_int_eq(ts->sock.tcp.state, 0);
    ck_assert_ptr_eq(ts->S, NULL);
}
END_TEST

START_TEST(test_tcp_input_window_reopen_stops_persist)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    struct wolfIP_timer tmr;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.peer_rwnd = 0;
    ts->sock.tcp.persist_active = 1;
    ts->src_port = 2222;
    ts->dst_port = 3333;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 100;
    ts->sock.tcp.tmr_persist = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ts->sock.tcp.tmr_persist, NO_TIMER);

    memset(&seg, 0, sizeof(seg));
    seg.ip.ver_ihl = 0x45;
    seg.ip.proto = WI_IPPROTO_TCP;
    seg.ip.ttl = 64;
    seg.ip.src = ee32(remote_ip);
    seg.ip.dst = ee32(local_ip);
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.src_port = ee16(ts->dst_port);
    seg.dst_port = ee16(ts->src_port);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_ACK;
    seg.win = ee16(16);
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    ck_assert_uint_gt(ts->sock.tcp.peer_rwnd, 0);
    ck_assert_uint_eq(ts->sock.tcp.persist_active, 0);
    ck_assert_int_eq(ts->sock.tcp.tmr_persist, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_persist_cb_stops_when_state_invalid)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_timer tmr;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->sock.tcp.persist_active = 1;
    ts->sock.tcp.persist_backoff = 4;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 100;
    ts->sock.tcp.tmr_persist = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ts->sock.tcp.tmr_persist, NO_TIMER);

    tcp_persist_cb(ts);

    ck_assert_uint_eq(ts->sock.tcp.persist_active, 0);
    ck_assert_uint_eq(ts->sock.tcp.persist_backoff, 0);
    ck_assert_int_eq(ts->sock.tcp.tmr_persist, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_persist_cb_stops_when_window_reopens)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_timer tmr;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.peer_rwnd = 64;
    ts->sock.tcp.persist_active = 1;
    ts->sock.tcp.persist_backoff = 2;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 100;
    ts->sock.tcp.tmr_persist = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ts->sock.tcp.tmr_persist, NO_TIMER);

    tcp_persist_cb(ts);

    ck_assert_uint_eq(ts->sock.tcp.persist_active, 0);
    ck_assert_uint_eq(ts->sock.tcp.persist_backoff, 0);
    ck_assert_int_eq(ts->sock.tcp.tmr_persist, NO_TIMER);
}
END_TEST

START_TEST(test_queue_insert_len_gt_size)
{
    struct queue q;
    uint8_t mem[8];
    uint8_t data[16] = {0};

    queue_init(&q, mem, sizeof(mem), 0);
    ck_assert_int_eq(queue_insert(&q, data, 0, sizeof(data)), -1);
}
END_TEST

START_TEST(test_queue_pop) {
    struct queue q;
    uint8_t data[] = {5, 6, 7, 8};
    uint8_t out[4];
    int len;
    queue_init(&q, mem, memsz, 0x12345678);

    queue_insert(&q, data, 0, sizeof(data));
    len = queue_pop(&q, out, sizeof(out));
    ck_assert_int_eq(len, sizeof(out));
    ck_assert_mem_eq(out, data, sizeof(data));
    ck_assert_int_eq(queue_len(&q), 0);
    ck_assert_int_eq(q.tail, 4);
}
END_TEST

START_TEST(test_queue_pop_wraparound) {
    struct queue q;
    struct {
        uint8_t buf[8];
        uint8_t guard[4];
    } storage;
    uint8_t data[] = {9, 10, 11, 12};
    uint8_t expected_guard[] = {0xEE, 0xEE, 0xEE, 0xEE};
    uint8_t out[4];
    int len;
    memset(&storage, 0, sizeof(storage));
    memset(storage.guard, 0xEE, sizeof(storage.guard));
    queue_init(&q, storage.buf, sizeof(storage.buf), 0x12345678);

    /* Manually set a wrapped queue state: tail near end, head near start. */
    q.tail = 6;
    q.head = 2;
    storage.buf[6] = data[0];
    storage.buf[7] = data[1];
    storage.buf[0] = data[2];
    storage.buf[1] = data[3];
    len = queue_pop(&q, out, sizeof(out));
    ck_assert_int_eq(len, sizeof(out));
    ck_assert_mem_eq(out, data, sizeof(data));
    ck_assert_int_eq(queue_len(&q), 0);
    ck_assert_mem_eq(storage.guard, expected_guard, sizeof(expected_guard));
}
END_TEST


/* Utils */
START_TEST(test_insert_timer) {
    struct wolfIP_timer tmr1 = { .expires = 100 };
    struct wolfIP_timer tmr2 = { .expires = 50 };
    struct wolfIP_timer tmr3 = { .expires = 200 };
    int id1;
    int id2;
    int id3;

    reset_heap();

    id1 = timers_binheap_insert(&heap, tmr1);
    id2 = timers_binheap_insert(&heap, tmr2);
    id3 = timers_binheap_insert(&heap, tmr3);

    ck_assert_int_eq(heap.size, 3);
    ck_assert_int_lt(heap.timers[0].expires, heap.timers[1].expires);
    ck_assert_int_lt(heap.timers[0].expires, heap.timers[2].expires);
    ck_assert_int_ne(id1, id2);
    ck_assert_int_ne(id2, id3);
}
END_TEST

START_TEST(test_timer_insert_skips_zero_head)
{
    struct timers_binheap local = {0};
    struct wolfIP_timer tmr = {0};

    local.size = 1;
    local.timers[0].expires = 0;
    local.timers[0].id = 99;

    tmr.expires = 10;
    tmr.cb = test_timer_cb;

    timers_binheap_insert(&local, tmr);
    ck_assert_uint_eq(local.size, 1);
    ck_assert_uint_eq(local.timers[0].expires, 10);
}
END_TEST

START_TEST(test_timer_cancel_existing_and_missing)
{
    struct timers_binheap local = {0};
    struct wolfIP_timer tmr = {0};
    uint32_t id;

    tmr.expires = 5;
    tmr.cb = test_timer_cb;
    id = timers_binheap_insert(&local, tmr);
    ck_assert_uint_eq(local.timers[0].expires, 5);

    timer_binheap_cancel(&local, id);
    ck_assert_uint_eq(local.timers[0].expires, 0);

    timer_binheap_cancel(&local, id + 1);
}
END_TEST

START_TEST(test_pop_timer) {
    struct wolfIP_timer tmr1 = { .expires = 300 };
    struct wolfIP_timer tmr2 = { .expires = 100 };
    struct wolfIP_timer tmr3 = { .expires = 200 };
    struct wolfIP_timer popped;

    reset_heap();

    timers_binheap_insert(&heap, tmr1);
    timers_binheap_insert(&heap, tmr2);
    timers_binheap_insert(&heap, tmr3);

    popped = timers_binheap_pop(&heap);
    ck_assert_int_eq(popped.expires, 100);
    ck_assert_int_eq(heap.size, 2);
    ck_assert_int_lt(heap.timers[0].expires, heap.timers[1].expires);
}
END_TEST

START_TEST(test_is_timer_expired) {
    struct wolfIP_timer tmr = { .expires = 150 };

    reset_heap();
    timers_binheap_insert(&heap, tmr);

    ck_assert_int_eq(is_timer_expired(&heap, 100), 0);
    ck_assert_int_eq(is_timer_expired(&heap, 150), 1);
    ck_assert_int_eq(is_timer_expired(&heap, 200), 1);
}
END_TEST

START_TEST(test_cancel_timer) {
    struct wolfIP_timer tmr1 = { .expires = 100 };
    struct wolfIP_timer tmr2 = { .expires = 200 };
    int id1;
    int id2;
    struct wolfIP_timer popped;

    reset_heap();

    id1 = timers_binheap_insert(&heap, tmr1);
    id2 = timers_binheap_insert(&heap, tmr2);
    (void)id2;

    timer_binheap_cancel(&heap, id1);
    ck_assert_int_eq(heap.timers[0].expires, 0);  // tmr1 canceled

    popped = timers_binheap_pop(&heap);
    ck_assert_int_eq(popped.expires, 200);  // Only tmr2 should remain
    ck_assert_int_eq(heap.size, 0);
}
END_TEST

START_TEST(test_timer_pop_skips_zero_expires)
{
    struct timers_binheap h;
    struct wolfIP_timer tmr1 = { .expires = 50 };
    struct wolfIP_timer tmr2 = { .expires = 10 };
    struct wolfIP_timer popped;

    memset(&h, 0, sizeof(h));
    tmr1.id = timers_binheap_insert(&h, tmr1);
    tmr2.id = timers_binheap_insert(&h, tmr2);
    timer_binheap_cancel(&h, tmr2.id);

    popped = timers_binheap_pop(&h);
    ck_assert_uint_ne(popped.expires, 0);
}
END_TEST

START_TEST(test_timer_pop_reorders_heap)
{
    struct timers_binheap h;
    struct wolfIP_timer t1 = { .expires = 30 };
    struct wolfIP_timer t2 = { .expires = 20 };
    struct wolfIP_timer t3 = { .expires = 10 };
    struct wolfIP_timer popped;

    memset(&h, 0, sizeof(h));
    timers_binheap_insert(&h, t1);
    timers_binheap_insert(&h, t2);
    timers_binheap_insert(&h, t3);

    popped = timers_binheap_pop(&h);
    ck_assert_uint_eq(popped.expires, 10);
}
END_TEST

START_TEST(test_timer_pop_right_child_swap)
{
    struct timers_binheap h;
    struct wolfIP_timer popped;

    memset(&h, 0, sizeof(h));
    h.size = 4;
    h.timers[0].expires = 10;
    h.timers[1].expires = 40;
    h.timers[2].expires = 20;
    h.timers[3].expires = 30;

    popped = timers_binheap_pop(&h);
    ck_assert_uint_eq(popped.expires, 10);
    ck_assert_uint_eq(h.size, 3);
    ck_assert_uint_eq(h.timers[0].expires, 20);
}
END_TEST

START_TEST(test_timer_pop_break_when_root_small)
{
    struct timers_binheap h;
    struct wolfIP_timer popped;

    memset(&h, 0, sizeof(h));
    h.size = 4;
    h.timers[0].expires = 10;
    h.timers[1].expires = 20;
    h.timers[2].expires = 30;
    h.timers[3].expires = 15;

    popped = timers_binheap_pop(&h);
    ck_assert_uint_eq(popped.expires, 10);
    ck_assert_uint_eq(h.size, 3);
    ck_assert_uint_eq(h.timers[0].expires, 15);
}
END_TEST

START_TEST(test_is_timer_expired_skips_zero_head)
{
    struct timers_binheap h;

    memset(&h, 0, sizeof(h));
    h.size = 2;
    h.timers[0].expires = 0;
    h.timers[1].expires = 50;

    ck_assert_int_eq(is_timer_expired(&h, 10), 0);
    ck_assert_uint_eq(h.size, 0);
}
END_TEST


/* Arp suite */
START_TEST(test_arp_request_basic)
{
    struct wolfIP s;
    struct arp_packet *arp;
    uint32_t target_ip = 0xC0A80002; /* 192.168.0.2 */

    wolfIP_init(&s);
    mock_link_init(&s);
    s.last_tick = 1000;
    arp_request(&s, TEST_PRIMARY_IF, target_ip);
    ck_assert_int_eq(last_frame_sent_size, sizeof(struct arp_packet));
    arp = (struct arp_packet *)last_frame_sent;
    ck_assert_mem_eq(arp->eth.dst, "\xff\xff\xff\xff\xff\xff", 6);
    ck_assert_mem_eq(arp->eth.src, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    ck_assert_int_eq(arp->eth.type, ee16(0x0806));
    ck_assert_int_eq(arp->htype, ee16(1));
    ck_assert_int_eq(arp->ptype, ee16(0x0800));
    ck_assert_int_eq(arp->hlen, 6);
    ck_assert_int_eq(arp->plen, 4);
    ck_assert_int_eq(arp->opcode, ee16(ARP_REQUEST));
    ck_assert_mem_eq(arp->sma, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    ck_assert_int_eq(arp->sip, ee32(s.ipconf[TEST_PRIMARY_IF].ip));
    ck_assert_mem_eq(arp->tma, "\x00\x00\x00\x00\x00\x00", 6);
    ck_assert_int_eq(arp->tip, ee32(target_ip));
}
END_TEST

START_TEST(test_arp_request_throttle)
{
    struct wolfIP s;
    uint32_t target_ip = 0xC0A80002; /*192.168.0.2*/

    wolfIP_init(&s);
    mock_link_init(&s);
    s.last_tick = 1000;
    s.arp.last_arp[TEST_PRIMARY_IF] = 880;
    last_frame_sent_size = 0;
    arp_request(&s, TEST_PRIMARY_IF, target_ip);
    ck_assert_int_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_request_target_ip) {
    struct wolfIP s;
    uint32_t target_ip = 0xC0A80002;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.last_tick = 1000;
    arp_request(&s, TEST_PRIMARY_IF, target_ip);
    ck_assert_int_eq(((struct arp_packet *)(last_frame_sent))->tip, ee32(target_ip));
}
END_TEST

START_TEST(test_arp_request_handling) {
    struct arp_packet arp_req;
    struct arp_packet *arp_reply;
    uint32_t req_ip = 0xC0A80002; // 192.168.0.2
    uint32_t device_ip = 0xC0A80001; // 192.168.0.1
    uint8_t req_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t mac[6] = {0};
    struct wolfIP s;

    memset(&arp_req, 0, sizeof(arp_req));
    wolfIP_init(&s);
    mock_link_init(&s);
    s.ipconf[TEST_PRIMARY_IF].ip = device_ip;

    /* Prepare ARP request */
    arp_req.htype = ee16(1);
    arp_req.ptype = ee16(0x0800);
    arp_req.hlen = 6;
    arp_req.plen = 4;
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(req_ip);
    memcpy(arp_req.sma, req_mac, 6);
    arp_req.tip = ee32(device_ip);

    /* Call arp_recv with the ARP request */
    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
    wolfIP_poll(&s, 1000);
    wolfIP_poll(&s, 1001);
    wolfIP_poll(&s, 1002);

    /* Check if ARP table updated with requester's MAC and IP */
    ck_assert_int_eq(arp_lookup(&s, TEST_PRIMARY_IF, req_ip, mac), 0);
    ck_assert_mem_eq(mac, req_mac, 6);

    /* Check if an ARP reply was generated */
    arp_reply = (struct arp_packet *)last_frame_sent;
    ck_assert_int_eq(last_frame_sent_size, sizeof(struct arp_packet));
    ck_assert_int_eq(arp_reply->opcode, ee16(ARP_REPLY));
    ck_assert_mem_eq(arp_reply->sma, s.ll_dev[TEST_PRIMARY_IF].mac, 6);     // source MAC
    ck_assert_int_eq(arp_reply->sip, ee32(device_ip));     // source IP
    ck_assert_mem_eq(arp_reply->tma, req_mac, 6);          // target MAC
    ck_assert_int_eq(arp_reply->tip, ee32(req_ip));        // target IP
}
END_TEST

START_TEST(test_arp_reply_handling) {
    struct arp_packet arp_reply;
    uint32_t reply_ip = 0xC0A80003; // 192.168.0.3
    uint8_t reply_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    struct wolfIP s;

    memset(&arp_reply, 0, sizeof(arp_reply));
    wolfIP_init(&s);
    mock_link_init(&s);

    /* Prepare ARP reply */
    arp_reply.htype = ee16(1);
    arp_reply.ptype = ee16(0x0800);
    arp_reply.hlen = 6;
    arp_reply.plen = 4;
    arp_reply.opcode = ee16(ARP_REPLY);
    arp_reply.sip = ee32(reply_ip);
    memcpy(arp_reply.sma, reply_mac, 6);

    /* Call arp_recv with the ARP reply */
    arp_recv(&s, TEST_PRIMARY_IF, &arp_reply, sizeof(arp_reply));

    /* Check if ARP table updated with reply IP and MAC */
    ck_assert_int_eq(s.arp.neighbors[0].ip, reply_ip);
    ck_assert_mem_eq(s.arp.neighbors[0].mac, reply_mac, 6);
}
END_TEST

START_TEST(test_arp_reply_unsolicited_does_not_overwrite_existing)
{
    struct arp_packet arp_reply;
    uint32_t reply_ip = 0xC0A80003; /* 192.168.0.3 */
    uint8_t reply_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    uint8_t existing_mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    struct wolfIP s;

    memset(&arp_reply, 0, sizeof(arp_reply));
    wolfIP_init(&s);
    mock_link_init(&s);

    s.arp.neighbors[0].ip = reply_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, existing_mac, 6);

    arp_reply.htype = ee16(1);
    arp_reply.ptype = ee16(0x0800);
    arp_reply.hlen = 6;
    arp_reply.plen = 4;
    arp_reply.opcode = ee16(ARP_REPLY);
    arp_reply.sip = ee32(reply_ip);
    memcpy(arp_reply.sma, reply_mac, 6);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_reply, sizeof(arp_reply));

    ck_assert_mem_eq(s.arp.neighbors[0].mac, existing_mac, 6);
}
END_TEST

START_TEST(test_arp_reply_with_pending_request_updates)
{
    struct arp_packet arp_reply;
    uint32_t reply_ip = 0xC0A80003; /* 192.168.0.3 */
    uint8_t old_mac[6] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
    uint8_t new_mac[6] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26};
    struct wolfIP s;

    memset(&arp_reply, 0, sizeof(arp_reply));
    wolfIP_init(&s);
    mock_link_init(&s);

    s.arp.neighbors[0].ip = reply_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, old_mac, 6);

    s.last_tick = 1000;
    s.arp.last_arp[TEST_PRIMARY_IF] = 0;
    arp_request(&s, TEST_PRIMARY_IF, reply_ip);

    arp_reply.htype = ee16(1);
    arp_reply.ptype = ee16(0x0800);
    arp_reply.hlen = 6;
    arp_reply.plen = 4;
    arp_reply.opcode = ee16(ARP_REPLY);
    arp_reply.sip = ee32(reply_ip);
    memcpy(arp_reply.sma, new_mac, 6);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_reply, sizeof(arp_reply));

    ck_assert_mem_eq(s.arp.neighbors[0].mac, new_mac, 6);
}
END_TEST

START_TEST(test_arp_request_refreshes_existing_entry)
{
    struct arp_packet arp_req;
    uint32_t req_ip = 0xC0A80002; /* 192.168.0.2 */
    uint32_t device_ip = 0xC0A80001; /* 192.168.0.1 */
    uint8_t existing_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t req_mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    struct wolfIP s;

    memset(&arp_req, 0, sizeof(arp_req));
    wolfIP_init(&s);
    mock_link_init(&s);
    s.ipconf[TEST_PRIMARY_IF].ip = device_ip;
    s.last_tick = 42;

    s.arp.neighbors[0].ip = req_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, existing_mac, 6);
    s.arp.neighbors[0].ts = 10;

    arp_req.htype = ee16(1);
    arp_req.ptype = ee16(0x0800);
    arp_req.hlen = 6;
    arp_req.plen = 4;
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(req_ip);
    memcpy(arp_req.sma, req_mac, 6);
    arp_req.tip = ee32(device_ip);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));

    ck_assert_mem_eq(s.arp.neighbors[0].mac, existing_mac, 6);
    ck_assert_uint_eq(s.arp.neighbors[0].ts, 10);
}
END_TEST

START_TEST(test_arp_request_refreshes_timestamp_on_same_mac)
{
    struct arp_packet arp_req;
    uint32_t req_ip = 0xC0A80002; /* 192.168.0.2 */
    uint32_t device_ip = 0xC0A80001; /* 192.168.0.1 */
    uint8_t mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    struct wolfIP s;

    memset(&arp_req, 0, sizeof(arp_req));
    wolfIP_init(&s);
    mock_link_init(&s);
    s.ipconf[TEST_PRIMARY_IF].ip = device_ip;

    s.arp.neighbors[0].ip = req_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, mac, 6);
    s.arp.neighbors[0].ts = 10;
    s.last_tick = 42;

    arp_req.htype = ee16(1);
    arp_req.ptype = ee16(0x0800);
    arp_req.hlen = 6;
    arp_req.plen = 4;
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(req_ip);
    memcpy(arp_req.sma, mac, 6);
    arp_req.tip = ee32(device_ip);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));

    ck_assert_mem_eq(s.arp.neighbors[0].mac, mac, 6);
    ck_assert_uint_eq(s.arp.neighbors[0].ts, s.last_tick);
}
END_TEST

START_TEST(test_arp_lookup_success) {
    uint8_t found_mac[6];
    uint32_t ip = 0xC0A80002;
    const uint8_t mock_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    struct wolfIP s;
    int result;

    wolfIP_init(&s);
    mock_link_init(&s);

    /* Add a known IP-MAC pair */
    s.arp.neighbors[0].ip = ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, mock_mac, 6);

    /* Test arp_lookup */
    result = arp_lookup(&s, TEST_PRIMARY_IF, ip, found_mac);
    ck_assert_int_eq(result, 0);
    ck_assert_mem_eq(found_mac, mock_mac, 6);
}
END_TEST

START_TEST(test_arp_lookup_failure) {
    uint8_t found_mac[6];
    uint32_t ip = 0xC0A80004;
    struct wolfIP s;
    int result;
    uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};

    wolfIP_init(&s);
    mock_link_init(&s);

    /* Ensure arp_lookup fails for unknown IP */
    result = arp_lookup(&s, TEST_PRIMARY_IF, ip, found_mac);
    ck_assert_int_eq(result, -1);
    ck_assert_mem_eq(found_mac, zero_mac, 6);
}
END_TEST

START_TEST(test_arp_lookup_expired_entry_rejected)
{
    uint8_t found_mac[6];
    uint32_t ip = 0xC0A80002;
    const uint8_t mock_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    struct wolfIP s;
    int result;

    wolfIP_init(&s);
    mock_link_init(&s);

    s.last_tick = 200000U;
    s.arp.neighbors[0].ip = ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    s.arp.neighbors[0].ts = 0;
    memcpy(s.arp.neighbors[0].mac, mock_mac, 6);

    result = arp_lookup(&s, TEST_PRIMARY_IF, ip, found_mac);
    ck_assert_int_eq(result, -1);
    ck_assert_uint_eq(s.arp.neighbors[0].ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_reply_updates_expired_entry)
{
    struct arp_packet arp_reply;
    uint32_t reply_ip = 0xC0A80003; /* 192.168.0.3 */
    uint8_t old_mac[6] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
    uint8_t new_mac[6] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26};
    struct wolfIP s;

    memset(&arp_reply, 0, sizeof(arp_reply));
    wolfIP_init(&s);
    mock_link_init(&s);

    s.last_tick = 200000U;
    s.arp.neighbors[0].ip = reply_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    s.arp.neighbors[0].ts = 0;
    memcpy(s.arp.neighbors[0].mac, old_mac, 6);

    arp_reply.htype = ee16(1);
    arp_reply.ptype = ee16(0x0800);
    arp_reply.hlen = 6;
    arp_reply.plen = 4;
    arp_reply.opcode = ee16(ARP_REPLY);
    arp_reply.sip = ee32(reply_ip);
    memcpy(arp_reply.sma, new_mac, 6);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_reply, sizeof(arp_reply));

    ck_assert_mem_eq(s.arp.neighbors[0].mac, new_mac, 6);
}
END_TEST

START_TEST(test_wolfip_getdev_ex_api)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *ll_def;
    wolfIP_init(&s);
    ll_def = wolfIP_getdev(&s);
    ck_assert_ptr_nonnull(ll_def);
    ck_assert_uint_eq(ll_def->mtu, LINK_MTU);
    ck_assert_ptr_eq(ll_def, wolfIP_getdev_ex(&s, TEST_PRIMARY_IF));
#if WOLFIP_ENABLE_LOOPBACK
    ck_assert_ptr_ne(ll_def, wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF));
    ck_assert_uint_eq(wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF)->mtu, LINK_MTU);
#endif
    ck_assert_ptr_null(wolfIP_getdev_ex(&s, WOLFIP_MAX_INTERFACES));
}
END_TEST

START_TEST(test_wolfip_ll_at_and_ipconf_at_invalid)
{
    struct wolfIP s;

    wolfIP_init(&s);

    ck_assert_ptr_eq(wolfIP_ll_at(NULL, 0), NULL);
    ck_assert_ptr_eq(wolfIP_ll_at(&s, s.if_count), NULL);
    ck_assert_ptr_eq(wolfIP_ipconf_at(NULL, 0), NULL);
    ck_assert_ptr_eq(wolfIP_ipconf_at(&s, s.if_count), NULL);
}
END_TEST

START_TEST(test_wolfip_ll_frame_mtu_enforces_minimum)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *ll;

    wolfIP_init(&s);
    mock_link_init(&s);
    ll = wolfIP_getdev(&s);
    ck_assert_ptr_nonnull(ll);

    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF, LINK_MTU_MIN - 1U), 0);
    ck_assert_uint_eq(wolfIP_ll_frame_mtu(ll), LINK_MTU_MIN);
}
END_TEST

START_TEST(test_transport_capacity_helpers_cover_guard_paths)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *ll;
    struct tsocket ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    ck_assert_int_eq(tx_has_writable_space(NULL), 0);

    memset(&ts, 0, sizeof(ts));
    ts.proto = WI_IPPROTO_ICMP;
    fifo_init(&ts.sock.udp.txbuf, ts.txmem, TXBUF_SIZE);
    ck_assert_int_ne(tx_has_writable_space(&ts), 0);
    ts.proto = 0;
    ck_assert_int_eq(tx_has_writable_space(&ts), 0);

    ck_assert_uint_eq(wolfIP_ll_frame_mtu(NULL), LINK_MTU);
    ll->mtu = 0;
    ck_assert_uint_eq(wolfIP_ll_frame_mtu(ll), LINK_MTU);
    ll->mtu = LINK_MTU + 128U;
    ck_assert_uint_eq(wolfIP_ll_frame_mtu(ll), LINK_MTU);
    ll->mtu = 1U;
    ck_assert_uint_eq(wolfIP_ll_frame_mtu(ll), LINK_MTU_MIN);

    ck_assert_uint_eq(wolfIP_socket_ip_mtu(NULL), 0U);
    ck_assert_uint_eq(wolfIP_socket_tcp_mss(NULL), 0U);
    ck_assert_uint_eq(tcp_cc_mss(NULL), TCP_MSS_MAX);
    ck_assert_uint_eq(tcp_tx_payload_cap(NULL), 0U);

    memset(&ts, 0, sizeof(ts));
    ts.proto = WI_IPPROTO_TCP;
    ck_assert_uint_eq(wolfIP_socket_ip_mtu(&ts), 0U);
    ck_assert_uint_eq(wolfIP_socket_tcp_mss(&ts), 0U);
    ck_assert_uint_eq(tcp_cc_mss(&ts), TCP_MSS_MAX);
    ck_assert_uint_eq(tcp_tx_payload_cap(&ts), 0U);

    ts.S = &s;
    ts.if_idx = TEST_PRIMARY_IF;
    ll->mtu = LINK_MTU;
    ts.sock.tcp.peer_mss = 1000U;
    ck_assert_uint_eq(tcp_tx_payload_cap(&ts), 1000U);
    ts.proto = WI_IPPROTO_UDP;
    ck_assert_uint_eq(tcp_tx_payload_cap(&ts), wolfIP_socket_tcp_mss(&ts) - TCP_OPTIONS_LEN);
    ts.proto = WI_IPPROTO_TCP;
    ts.sock.tcp.peer_mss = 0U;
    ck_assert_uint_eq(tcp_tx_payload_cap(&ts), wolfIP_socket_tcp_mss(&ts) - TCP_OPTIONS_LEN);
    ll->mtu = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + TCP_OPTIONS_LEN;
    ck_assert_uint_eq(tcp_tx_payload_cap(&ts), 0U);
}
END_TEST

START_TEST(test_tx_has_writable_space_icmp_accepts_minimal_packet)
{
    struct tsocket ts;

    memset(&ts, 0, sizeof(ts));
    ts.proto = WI_IPPROTO_ICMP;
    fifo_init(&ts.sock.udp.txbuf, ts.txmem, TXBUF_SIZE);

    /* Exact room for one descriptor plus the minimal queued ICMP frame. */
    ts.sock.udp.txbuf.size =
        (uint32_t)(sizeof(struct pkt_desc) + sizeof(struct wolfIP_icmp_packet));

    ck_assert_int_ne(tx_has_writable_space(&ts), 0);
}
END_TEST

START_TEST(test_wolfip_if_for_local_ip_single_interface_falls_back_to_zero)
{
    struct wolfIP s;
    int found = 7;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 1;

    ck_assert_uint_eq(wolfIP_if_for_local_ip(&s, IPADDR_ANY, &found), 0U);
    ck_assert_int_eq(found, 0);
}
END_TEST

START_TEST(test_wolfip_mtu_set_get_api)
{
    struct wolfIP s;
    uint32_t mtu = 0;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_mtu_set(NULL, TEST_PRIMARY_IF, 128U), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_mtu_set(&s, WOLFIP_MAX_INTERFACES, 128U), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_mtu_get(NULL, TEST_PRIMARY_IF, &mtu), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_mtu_get(&s, WOLFIP_MAX_INTERFACES, &mtu), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_mtu_get(&s, TEST_PRIMARY_IF, NULL), -WOLFIP_EINVAL);

    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF, 256U), 0);
    ck_assert_int_eq(wolfIP_mtu_get(&s, TEST_PRIMARY_IF, &mtu), 0);
    ck_assert_uint_eq(mtu, 256U);

    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF, LINK_MTU_MIN - 1U), 0);
    ck_assert_int_eq(wolfIP_mtu_get(&s, TEST_PRIMARY_IF, &mtu), 0);
    ck_assert_uint_eq(mtu, LINK_MTU_MIN);

    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF, LINK_MTU + 1U), 0);
    ck_assert_int_eq(wolfIP_mtu_get(&s, TEST_PRIMARY_IF, &mtu), 0);
    ck_assert_uint_eq(mtu, LINK_MTU);

    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF, 0), 0);
    ck_assert_int_eq(wolfIP_mtu_get(&s, TEST_PRIMARY_IF, &mtu), 0);
    ck_assert_uint_eq(mtu, LINK_MTU);
}
END_TEST

START_TEST(test_ip_is_local_conf_variants)
{
    struct ipconf conf;
    ip4 addr = 0x0A000001U;

    ck_assert_int_eq(ip_is_local_conf(NULL, addr), 0);

    memset(&conf, 0, sizeof(conf));
    conf.ip = addr;
    conf.mask = 0;
    ck_assert_int_eq(ip_is_local_conf(&conf, addr), 1);
}
END_TEST

START_TEST(test_wolfip_ip_is_multicast_variants)
{
    ck_assert_int_eq(wolfIP_ip_is_multicast(0xE0000001U), 1);
    ck_assert_int_eq(wolfIP_ip_is_multicast(0x0A000001U), 0);
}
END_TEST

START_TEST(test_wolfip_ip_is_broadcast_variants)
{
    struct wolfIP s;

    ck_assert_int_eq(wolfIP_ip_is_broadcast(NULL, 0xFFFFFFFFU), 1);
    ck_assert_int_eq(wolfIP_ip_is_broadcast(NULL, 0x0A000001U), 0);

    setup_stack_with_two_ifaces(&s, 0x0A000001U, 0xC0A80101U);
    ck_assert_int_eq(wolfIP_ip_is_broadcast(&s, 0x0A0000FFU), 1);
    ck_assert_int_eq(wolfIP_ip_is_broadcast(&s, 0xC0A801FFU), 1);
    ck_assert_int_eq(wolfIP_ip_is_broadcast(&s, 0x0A000001U), 0);
}
END_TEST

START_TEST(test_wolfip_ip_is_broadcast_skips_unsuitable_configs)
{
    struct wolfIP s;

    wolfIP_init(&s);
    s.if_count = 2;
    s.ipconf[0].ip = 0x0A000001U;
    s.ipconf[0].mask = 0xFFFFFFFFU;
    s.ipconf[1].ip = IPADDR_ANY;
    s.ipconf[1].mask = 0xFFFFFF00U;

    ck_assert_int_eq(wolfIP_ip_is_broadcast(&s, 0x0A0000FFU), 0);
}
END_TEST

START_TEST(test_wolfip_ip_is_broadcast_skips_zero_mask)
{
    struct wolfIP s;

    wolfIP_init(&s);
    s.if_count = 1;
    s.ipconf[0].ip = 0x0A000001U;
    s.ipconf[0].mask = 0U;

    ck_assert_int_eq(wolfIP_ip_is_broadcast(&s, 0xFFFFFFFFU), 1);
    ck_assert_int_eq(wolfIP_ip_is_broadcast(&s, 0x0A0000FFU), 0);
}
END_TEST

#if WOLFIP_ENABLE_LOOPBACK
START_TEST(test_wolfip_loopback_defaults)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *loop;
    struct wolfIP_ll_dev *hw;
    ip4 ip = 0, mask = 0, gw = 0;

    wolfIP_init(&s);

    loop = wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF);
    ck_assert_ptr_nonnull(loop);
    ck_assert_ptr_nonnull(loop->send);
    ck_assert_ptr_eq(loop->poll, wolfIP_loopback_poll);
    ck_assert_uint_eq(loop->mac[0], 0x02);

    wolfIP_ipconfig_get_ex(&s, TEST_LOOPBACK_IF, &ip, &mask, &gw);
    ck_assert_uint_eq(ip, 0x7F000001U);
    ck_assert_uint_eq(mask, 0xFF000000U);
    ck_assert_uint_eq(gw, 0U);

    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0x0A0000FEU);
    wolfIP_ipconfig_get_ex(&s, TEST_PRIMARY_IF, &ip, &mask, &gw);
    ck_assert_uint_eq(ip, 0x0A000001U);
    ck_assert_uint_eq(mask, 0xFFFFFF00U);
    ck_assert_uint_eq(gw, 0x0A0000FEU);

    hw = wolfIP_getdev(&s);
    ck_assert_ptr_eq(hw, wolfIP_getdev_ex(&s, TEST_PRIMARY_IF));
}
END_TEST

START_TEST(test_wolfip_loopback_send_paths)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *loop;
    uint8_t frame[16] = {0};

    wolfIP_init(&s);
    loop = wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF);
    ck_assert_ptr_nonnull(loop);

    ck_assert_int_eq(wolfIP_loopback_send(NULL, frame, sizeof(frame)), -1);
    ck_assert_int_eq(wolfIP_loopback_send(loop, NULL, sizeof(frame)), -1);
    /* Fill the queue, each slot enqueue returns the byte count. */
    for (unsigned int i = 0; i < WOLFIP_LOOPBACK_QUEUE_DEPTH; i++) {
        ck_assert_int_eq(wolfIP_loopback_send(loop, frame, sizeof(frame)),
                         (int)sizeof(frame));
    }
    /* Next send must return -WOLFIP_EAGAIN because the queue is full. */
    ck_assert_int_eq(wolfIP_loopback_send(loop, frame, sizeof(frame)),
                     -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_wolfip_loopback_poll_paths)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *loop;
    uint8_t tx[16];
    uint8_t rx[16];

    wolfIP_init(&s);
    loop = wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF);
    ck_assert_ptr_nonnull(loop);

    memset(tx, 0x5A, sizeof(tx));
    memset(rx, 0, sizeof(rx));

    ck_assert_int_eq(wolfIP_loopback_poll(NULL, rx, sizeof(rx)), 0);
    ck_assert_int_eq(wolfIP_loopback_poll(loop, NULL, sizeof(rx)), 0);
    ck_assert_int_eq(wolfIP_loopback_poll(loop, rx, sizeof(rx)), 0);

    ck_assert_int_eq(wolfIP_loopback_send(loop, tx, sizeof(tx)), (int)sizeof(tx));
    ck_assert_int_eq(wolfIP_loopback_poll(loop, rx, sizeof(rx)), (int)sizeof(rx));
    ck_assert_mem_eq(rx, tx, sizeof(tx));
    ck_assert_int_eq(wolfIP_loopback_poll(loop, rx, sizeof(rx)), 0);
}
END_TEST

START_TEST(test_wolfip_loopback_poll_keeps_pending_on_short_buffer)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *loop;
    uint8_t tx[16];
    uint8_t rx[16];

    wolfIP_init(&s);
    loop = wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF);
    ck_assert_ptr_nonnull(loop);

    memset(tx, 0xC3, sizeof(tx));
    memset(rx, 0, sizeof(rx));

    ck_assert_int_eq(wolfIP_loopback_send(loop, tx, sizeof(tx)), (int)sizeof(tx));
    ck_assert_int_eq(wolfIP_loopback_poll(loop, rx, sizeof(rx) - 1U), 0);
    ck_assert_int_eq(wolfIP_loopback_poll(loop, rx, sizeof(rx)), (int)sizeof(rx));
    ck_assert_mem_eq(rx, tx, sizeof(tx));
}
END_TEST

START_TEST(test_wolfip_loopback_send_drops_oversize)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *loop;
    uint8_t frame[LINK_MTU + 8];

    wolfIP_init(&s);
    loop = wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF);
    ck_assert_ptr_nonnull(loop);

    memset(frame, 0xAB, sizeof(frame));
    ck_assert_int_eq(wolfIP_loopback_send(loop, frame, (uint32_t)sizeof(frame)), 0);

    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_LOOPBACK_IF, LINK_MTU_MIN - 1U), 0);
    ck_assert_int_eq(wolfIP_loopback_send(loop, frame, (uint32_t)sizeof(frame)), 0);
}
END_TEST

START_TEST(test_wolfip_loopback_send_queue_full_returns_eagain)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *loop;
    uint8_t frame[16] = {0};
    uint8_t rx[IP_MTU_MAX];

    wolfIP_init(&s);
    loop = wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF);
    ck_assert_ptr_nonnull(loop);

    /* Fill the queue completely. */
    for (unsigned int i = 0; i < WOLFIP_LOOPBACK_QUEUE_DEPTH; i++) {
        frame[0] = (uint8_t)i;
        ck_assert_int_eq(wolfIP_loopback_send(loop, frame, sizeof(frame)),
                         (int)sizeof(frame));
    }

    /* Queue-full must return -WOLFIP_EAGAIN, not 0. */
    ck_assert_int_eq(wolfIP_loopback_send(loop, frame, sizeof(frame)),
                     -WOLFIP_EAGAIN);

    /* Drain one slot and verify we can enqueue again. */
    ck_assert_int_gt(wolfIP_loopback_poll(loop, rx, sizeof(rx)), 0);
    frame[0] = 0xFF;
    ck_assert_int_eq(wolfIP_loopback_send(loop, frame, sizeof(frame)),
                     (int)sizeof(frame));

    /* Queue is full again — must get -WOLFIP_EAGAIN once more. */
    ck_assert_int_eq(wolfIP_loopback_send(loop, frame, sizeof(frame)),
                     -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_wolfip_loopback_send_rejects_null_args)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *loop;
    uint8_t frame[4] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    loop = wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF);
    ck_assert_ptr_nonnull(loop);

    ck_assert_int_eq(wolfIP_loopback_send(NULL, frame, sizeof(frame)), -1);
    ck_assert_int_eq(wolfIP_loopback_send(loop, NULL, sizeof(frame)), -1);
}
END_TEST
#endif

START_TEST(test_wolfip_send_port_unreachable_ignores_missing_link_sender)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *ll;
    struct wolfIP_ip_packet orig;

    wolfIP_init(&s);
    mock_link_init(&s);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);
    memset(&orig, 0, sizeof(orig));
    last_frame_sent_size = 0;

    wolfIP_send_port_unreachable(&s, WOLFIP_MAX_INTERFACES, &orig);
    ck_assert_uint_eq(last_frame_sent_size, 0U);

    ll->send = NULL;
    wolfIP_send_port_unreachable(&s, TEST_PRIMARY_IF, &orig);
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_wolfip_send_port_unreachable_non_ethernet_skips_eth_filter)
{
    struct wolfIP s;
    uint8_t orig_buf[ETH_HEADER_LEN + TTL_EXCEEDED_ORIG_PACKET_SIZE];
    struct wolfIP_ip_packet *orig = (struct wolfIP_ip_packet *)orig_buf;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    s.ll_dev[TEST_PRIMARY_IF].non_ethernet = 1;
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    wolfIP_filter_set_icmp_mask(0);
    wolfIP_filter_set_ip_mask(0);
    last_frame_sent_size = 0;

    memset(orig_buf, 0, sizeof(orig_buf));
    orig->src = ee32(0x0A000002U);

    wolfIP_send_port_unreachable(&s, TEST_PRIMARY_IF, orig);
    ck_assert_uint_eq(last_frame_sent_size,
            sizeof(struct wolfIP_icmp_dest_unreachable_packet) - ETH_HEADER_LEN);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

START_TEST(test_tcp_adv_win_clamps_and_applies_window_scale)
{
    struct tsocket ts;
    uint32_t space;

    memset(&ts, 0, sizeof(ts));
    queue_init(&ts.sock.tcp.rxbuf, ts.rxmem, RXBUF_SIZE, 0);
    ts.sock.tcp.rxbuf.size = 70000U;
    ts.sock.tcp.ws_enabled = 1;
    ts.sock.tcp.rcv_wscale = 1;
    space = queue_space((struct queue *)&ts.sock.tcp.rxbuf);

    ck_assert_uint_eq(tcp_adv_win(&ts, 0), 0xFFFFU);
    ck_assert_uint_eq(tcp_adv_win(&ts, 1), (uint16_t)(space >> 1));
}
END_TEST

START_TEST(test_tcp_segment_acceptable_zero_window_and_overlap_cases)
{
    struct tsocket ts;
    struct wolfIP_tcp_seg seg;
    uint32_t wnd;

    memset(&ts, 0, sizeof(ts));
    memset(&seg, 0, sizeof(seg));
    queue_init(&ts.sock.tcp.rxbuf, ts.rxmem, RXBUF_SIZE, 100U);
    ts.sock.tcp.ack = 100U;

    ts.sock.tcp.rxbuf.size = 0U;
    seg.seq = ee32(100U);
    ck_assert_int_eq(tcp_segment_acceptable(&ts, &seg, 0U), 1);
    seg.seq = ee32(101U);
    ck_assert_int_eq(tcp_segment_acceptable(&ts, &seg, 0U), 0);
    seg.seq = ee32(100U);
    ck_assert_int_eq(tcp_segment_acceptable(&ts, &seg, 1U), 0);

    ts.sock.tcp.rxbuf.size = RXBUF_SIZE;
    wnd = queue_space((struct queue *)&ts.sock.tcp.rxbuf);
    ts.sock.tcp.ack = 100U;
    seg.seq = ee32(100U + wnd - 1U);
    ck_assert_int_eq(tcp_segment_acceptable(&ts, &seg, 2U), 1);
    seg.seq = ee32(99U);
    ck_assert_int_eq(tcp_segment_acceptable(&ts, &seg, 2U), 1);
    seg.seq = ee32(100U + wnd);
    ck_assert_int_eq(tcp_segment_acceptable(&ts, &seg, 2U), 0);
}
END_TEST

START_TEST(test_tcp_segment_acceptable_counts_syn_in_segment_length)
{
    struct tsocket ts;
    struct wolfIP_tcp_seg seg;

    memset(&ts, 0, sizeof(ts));
    memset(&seg, 0, sizeof(seg));
    queue_init(&ts.sock.tcp.rxbuf, ts.rxmem, RXBUF_SIZE, 100U);
    ts.sock.tcp.ack = 100U;

    ts.sock.tcp.rxbuf.size = RXBUF_SIZE;
    seg.seq = ee32(99U);
    seg.flags = TCP_FLAG_SYN | TCP_FLAG_FIN;

    ck_assert_int_eq(tcp_segment_acceptable(&ts, &seg, 0U), 1);
}
END_TEST

START_TEST(test_wolfip_ipconfig_ex_per_interface)
{
    struct wolfIP s;
    ip4 base_ip = 0x0A000001;
    ip4 base_mask = 0xFFFFFF00;
    ip4 base_gw = 0x0A0000FE;
    ip4 iface_ip = 0x0A000201;
    ip4 iface_mask = 0xFFFF0000;
    ip4 iface_gw = 0x0A0002FE;
    ip4 out_ip = 0, out_mask = 0, out_gw = 0;
    ip4 def_ip = 0, def_mask = 0, def_gw = 0;

    wolfIP_init(&s);
    wolfIP_ipconfig_set(&s, base_ip, base_mask, base_gw);

    wolfIP_ipconfig_set_ex(&s, TEST_SECOND_IF, iface_ip, iface_mask, iface_gw);
    wolfIP_ipconfig_get_ex(&s, TEST_SECOND_IF, &out_ip, &out_mask, &out_gw);

    ck_assert_uint_eq(out_ip, iface_ip);
    ck_assert_uint_eq(out_mask, iface_mask);
    ck_assert_uint_eq(out_gw, iface_gw);

    wolfIP_ipconfig_get(&s, &def_ip, &def_mask, &def_gw);
    ck_assert_uint_eq(def_ip, base_ip);
    ck_assert_uint_eq(def_mask, base_mask);
    ck_assert_uint_eq(def_gw, base_gw);

    wolfIP_ipconfig_set_ex(&s, WOLFIP_MAX_INTERFACES, 0xDEADBEEF, 0xFFFFFFFF, 0x01010101);
    ck_assert_uint_eq(s.ipconf[TEST_SECOND_IF].ip, iface_ip);
    ck_assert_uint_eq(s.ipconf[TEST_SECOND_IF].mask, iface_mask);
    ck_assert_uint_eq(s.ipconf[TEST_SECOND_IF].gw, iface_gw);

    wolfIP_ipconfig_get_ex(&s, TEST_SECOND_IF, NULL, NULL, NULL);
}
END_TEST

START_TEST(test_wolfip_recv_ex_multi_interface_arp_reply)
{
    struct wolfIP s;
    struct arp_packet arp_req;
    struct arp_packet *arp_reply;
    uint8_t requester_mac[6] = {0x10, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t iface1_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};

    wolfIP_init(&s);
    mock_link_init(&s);
    mock_link_init_idx(&s, TEST_SECOND_IF, iface1_mac);
    wolfIP_ipconfig_set(&s, 0xC0A80001, 0xFFFFFF00, 0);
    wolfIP_ipconfig_set_ex(&s, TEST_SECOND_IF, 0xC0A80101, 0xFFFFFF00, 0);

    memset(&arp_req, 0, sizeof(arp_req));
    memset(last_frame_sent, 0, sizeof(last_frame_sent));
    last_frame_sent_size = 0;

    memset(arp_req.eth.dst, 0xFF, sizeof(arp_req.eth.dst));
    memcpy(arp_req.eth.src, requester_mac, 6);
    arp_req.eth.type = ee16(ETH_TYPE_ARP);
    arp_req.htype = ee16(1);
    arp_req.ptype = ee16(ETH_TYPE_IP);
    arp_req.hlen = 6;
    arp_req.plen = 4;
    arp_req.htype = ee16(1);
    arp_req.ptype = ee16(0x0800);
    arp_req.hlen = 6;
    arp_req.plen = 4;
    arp_req.opcode = ee16(ARP_REQUEST);
    memcpy(arp_req.sma, requester_mac, 6);
    arp_req.sip = ee32(0xC0A80164);
    memset(arp_req.tma, 0, sizeof(arp_req.tma));
    arp_req.tip = ee32(0xC0A80101);

    wolfIP_recv_ex(&s, TEST_SECOND_IF, &arp_req, sizeof(arp_req));

    ck_assert_uint_eq(last_frame_sent_size, sizeof(struct arp_packet));
    arp_reply = (struct arp_packet *)last_frame_sent;
    ck_assert_uint_eq(arp_reply->opcode, ee16(ARP_REPLY));
    ck_assert_mem_eq(arp_reply->eth.src, iface1_mac, 6);
    ck_assert_mem_eq(arp_reply->sma, iface1_mac, 6);
    ck_assert_uint_eq(arp_reply->sip, ee32(s.ipconf[TEST_SECOND_IF].ip));
}
END_TEST

START_TEST(test_wolfip_forwarding_basic)
{
    struct wolfIP s;
    uint8_t frame_buf[64];
    struct wolfIP_ip_packet *frame = (struct wolfIP_ip_packet *)frame_buf;
    struct wolfIP_ip_packet *fwd;
    uint8_t src_mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    uint8_t iface1_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    uint8_t next_hop_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    uint32_t dest_ip = 0xC0A80164; /* 192.168.1.100 */
    uint8_t initial_ttl = 2;
    uint16_t orig_csum;
    uint16_t expected_csum;

    wolfIP_init(&s);
    mock_link_init(&s);
    mock_link_init_idx(&s, TEST_SECOND_IF, iface1_mac);
    wolfIP_ipconfig_set(&s, 0xC0A80001, 0xFFFFFF00, 0);
    wolfIP_ipconfig_set_ex(&s, TEST_SECOND_IF, 0xC0A80101, 0xFFFFFF00, 0);
    s.arp.neighbors[0].ip = dest_ip;
    s.arp.neighbors[0].if_idx = TEST_SECOND_IF;
    memcpy(s.arp.neighbors[0].mac, next_hop_mac, 6);

    memset(frame_buf, 0, sizeof(frame_buf));
    memcpy(frame->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(frame->eth.src, src_mac, 6);
    frame->eth.type = ee16(ETH_TYPE_IP);
    frame->ver_ihl = 0x45;
    frame->ttl = initial_ttl;
    frame->proto = WI_IPPROTO_UDP;
    frame->len = ee16(IP_HEADER_LEN);
    frame->src = ee32(0xC0A800AA);
    frame->dst = ee32(dest_ip);
    frame->csum = 0;
    iphdr_set_checksum(frame);
    orig_csum = ee16(frame->csum);

    memset(last_frame_sent, 0, sizeof(last_frame_sent));
    last_frame_sent_size = 0;

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, ETH_HEADER_LEN + IP_HEADER_LEN);

    ck_assert_uint_eq(last_frame_sent_size, sizeof(struct wolfIP_ip_packet));
    fwd = (struct wolfIP_ip_packet *)last_frame_sent;
    ck_assert_mem_eq(fwd->eth.dst, next_hop_mac, 6);
    ck_assert_mem_eq(fwd->eth.src, s.ll_dev[TEST_SECOND_IF].mac, 6);
    ck_assert_uint_eq(fwd->ttl, (uint8_t)(initial_ttl - 1));
    {
        uint32_t sum = orig_csum + 0x0100;
        sum = (sum & 0xFFFF) + (sum >> 16);
        expected_csum = (uint16_t)sum;
        if (expected_csum == 0)
            expected_csum = 0xFFFF;
    }
    ck_assert_uint_eq(ee16(fwd->csum), expected_csum);
}
END_TEST

START_TEST(test_wolfip_forwarding_ttl_expired)
{
    struct wolfIP s;
    uint8_t frame_buf[64];
    struct wolfIP_ip_packet *frame = (struct wolfIP_ip_packet *)frame_buf;
    struct wolfIP_icmp_ttl_exceeded_packet *icmp;
    uint8_t src_mac[6] = {0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC};
    uint8_t iface1_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};
    uint32_t dest_ip = 0xC0A80110;

    wolfIP_init(&s);
    mock_link_init(&s);
    mock_link_init_idx(&s, TEST_SECOND_IF, iface1_mac);
    wolfIP_ipconfig_set(&s, 0xC0A80001, 0xFFFFFF00, 0);
    wolfIP_ipconfig_set_ex(&s, TEST_SECOND_IF, 0xC0A80101, 0xFFFFFF00, 0);

    memset(frame_buf, 0, sizeof(frame_buf));
    memcpy(frame->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(frame->eth.src, src_mac, 6);
    frame->eth.type = ee16(ETH_TYPE_IP);
    frame->ver_ihl = 0x45;
    frame->ttl = 1;
    frame->proto = WI_IPPROTO_UDP;
    frame->len = ee16(IP_HEADER_LEN);
    frame->src = ee32(0xC0A800AA);
    frame->dst = ee32(dest_ip);
    frame->csum = 0;
    iphdr_set_checksum(frame);

    memset(last_frame_sent, 0, sizeof(last_frame_sent));
    last_frame_sent_size = 0;

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, ETH_HEADER_LEN + IP_HEADER_LEN + 8);

    ck_assert_uint_eq(last_frame_sent_size,
            sizeof(struct wolfIP_icmp_ttl_exceeded_packet));
    icmp = (struct wolfIP_icmp_ttl_exceeded_packet *)last_frame_sent;
    ck_assert_uint_eq(icmp->type, ICMP_TTL_EXCEEDED);
    ck_assert_uint_eq(icmp->code, 0);
    ck_assert_mem_eq(icmp->unused, "\x00\x00\x00\x00", sizeof(icmp->unused));
    ck_assert_mem_eq(icmp->ip.eth.dst, src_mac, 6);
    ck_assert_mem_eq(icmp->ip.eth.src, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    ck_assert_uint_eq(icmp->ip.ttl, 64);
    ck_assert_uint_eq(ee16(icmp->ip.len),
            (uint16_t)(IP_HEADER_LEN + ICMP_TTL_EXCEEDED_SIZE));
    ck_assert_uint_eq(ee32(icmp->ip.src), s.ipconf[TEST_PRIMARY_IF].ip);
    ck_assert_uint_eq(ee32(icmp->ip.dst), ee32(frame->src));
    ck_assert_mem_eq(icmp->orig_packet,
            ((uint8_t *)frame) + ETH_HEADER_LEN,
            ee16(frame->len) < TTL_EXCEEDED_ORIG_PACKET_SIZE ?
            ee16(frame->len) : TTL_EXCEEDED_ORIG_PACKET_SIZE);
    ck_assert_uint_eq(frame->ttl, 1); /* original packet should remain unchanged */
}
END_TEST

START_TEST(test_loopback_dest_not_forwarded)
{
    struct wolfIP s;
    struct wolfIP_ip_packet frame;
    uint8_t src_mac[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};

    wolfIP_init(&s);
    mock_link_init(&s);
    mock_link_init_idx(&s, TEST_SECOND_IF, NULL);
    wolfIP_ipconfig_set(&s, 0xC0A80001, 0xFFFFFF00, 0);

    memset(&frame, 0, sizeof(frame));
    memcpy(frame.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(frame.eth.src, src_mac, 6);
    frame.eth.type = ee16(ETH_TYPE_IP);
    frame.ver_ihl = 0x45;
    frame.ttl = 64;
    frame.proto = WI_IPPROTO_UDP;
    frame.len = ee16(IP_HEADER_LEN);
    frame.src = ee32(0x0A000002U);
    frame.dst = ee32(0x7F000001U);
    frame.csum = 0;
    iphdr_set_checksum(&frame);

    memset(last_frame_sent, 0, sizeof(last_frame_sent));
    last_frame_sent_size = 0;

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, &frame, sizeof(frame));

    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

/* wolfSSL IO glue tests */
START_TEST(test_wolfssl_io_ctx_registers_callbacks)
{
    struct wolfIP s;
    WOLFSSL_CTX ctx;

    memset(&ctx, 0, sizeof(ctx));
    reset_wolfssl_io_state();
    wolfSSL_SetIO_wolfIP_CTX(&ctx, &s);

    ck_assert_ptr_eq(g_ctx_recv_cb, wolfIP_io_recv);
    ck_assert_ptr_eq(g_ctx_send_cb, wolfIP_io_send);
    ck_assert_ptr_eq(g_last_ctx, &ctx);
    ck_assert_ptr_eq(wolfIP_lookup_stack(&ctx), &s);
}
END_TEST

START_TEST(test_wolfssl_io_setio_success)
{
    struct wolfIP s;
    WOLFSSL_CTX ctx;
    WOLFSSL ssl;
    int ret;
    struct wolfip_io_desc *desc;

    memset(&ctx, 0, sizeof(ctx));
    memset(&ssl, 0, sizeof(ssl));
    ssl.ctx = &ctx;

    reset_wolfssl_io_state();
    wolfSSL_SetIO_wolfIP_CTX(&ctx, &s);
    ret = wolfSSL_SetIO_wolfIP(&ssl, 7);
    ck_assert_int_eq(ret, 0);
    ck_assert_ptr_nonnull(ssl.rctx);
    ck_assert_ptr_eq(ssl.rctx, ssl.wctx);
    ck_assert_ptr_eq(g_last_read_ctx, ssl.rctx);
    ck_assert_ptr_eq(g_last_write_ctx, ssl.wctx);
    desc = (struct wolfip_io_desc *)ssl.rctx;
    ck_assert_int_eq(desc->fd, 7);
    ck_assert_ptr_eq(desc->stack, &s);
}
END_TEST

START_TEST(test_wolfssl_io_setio_invalid_ssl)
{
    reset_wolfssl_io_state();
    ck_assert_int_eq(wolfSSL_SetIO_wolfIP(NULL, 1), -1);
}
END_TEST

START_TEST(test_wolfssl_io_setio_invalid_ctx)
{
    WOLFSSL ssl;
    memset(&ssl, 0, sizeof(ssl));
    reset_wolfssl_io_state();
    ck_assert_int_eq(wolfSSL_SetIO_wolfIP(&ssl, 1), -1);
}
END_TEST

START_TEST(test_wolfssl_io_setio_invalid_fd)
{
    struct wolfIP s;
    WOLFSSL_CTX ctx;
    WOLFSSL ssl;

    memset(&ctx, 0, sizeof(ctx));
    memset(&ssl, 0, sizeof(ssl));
    ssl.ctx = &ctx;
    reset_wolfssl_io_state();
    wolfSSL_SetIO_wolfIP_CTX(&ctx, &s);
    ck_assert_int_eq(wolfSSL_SetIO_wolfIP(&ssl, -1), -1);
}
END_TEST

START_TEST(test_wolfssl_io_setio_no_stack)
{
    WOLFSSL_CTX ctx;
    WOLFSSL ssl;

    memset(&ctx, 0, sizeof(ctx));
    memset(&ssl, 0, sizeof(ssl));
    ssl.ctx = &ctx;
    reset_wolfssl_io_state();
    ck_assert_int_eq(wolfSSL_SetIO_wolfIP(&ssl, 4), WOLFSSL_CBIO_ERR_GENERAL);
}
END_TEST

START_TEST(test_wolfssl_io_recv_behaviors)
{
    struct wolfIP s;
    struct wolfip_io_desc desc;
    char buf[8];
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.stack = &s;

    reset_wolfssl_io_state();
    test_recv_ret = -WOLFIP_EAGAIN;
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_READ);

    test_recv_ret = -1;
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_READ);

    test_recv_ret = 0;
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_CONN_CLOSE);

    memset(test_recv_fill, 0, sizeof(test_recv_fill));
    test_recv_fill[0] = 0xA1;
    test_recv_fill[1] = 0xB2;
    test_recv_fill_len = 2;
    test_recv_ret = 2;
    memset(buf, 0, sizeof(buf));
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, 2);
    ck_assert_int_eq((unsigned char)buf[0], 0xA1);
    ck_assert_int_eq((unsigned char)buf[1], 0xB2);
}
END_TEST

START_TEST(test_wolfssl_io_recv_invalid_desc)
{
    char buf[4];
    int ret;

    reset_wolfssl_io_state();
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), NULL);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_GENERAL);
}
END_TEST

START_TEST(test_wolfssl_io_recv_fragmented_sequence)
{
    struct wolfIP s;
    struct wolfip_io_desc desc;
    char buf[4];
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.stack = &s;
    reset_wolfssl_io_state();

    test_recv_fill[0] = 0xAA;
    test_recv_fill_len = 1;
    test_recv_ret = 1;
    memset(buf, 0, sizeof(buf));
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, 1);
    ck_assert_int_eq((unsigned char)buf[0], 0xAA);

    test_recv_fill[0] = 0xBB;
    test_recv_fill_len = 1;
    test_recv_ret = 1;
    ret = wolfIP_io_recv(NULL, buf + 1, (int)(sizeof(buf) - 1), &desc);
    ck_assert_int_eq(ret, 1);
    ck_assert_int_eq((unsigned char)buf[1], 0xBB);
}
END_TEST

START_TEST(test_wolfssl_io_recv_respects_buffer_size)
{
    struct wolfIP s;
    struct wolfip_io_desc desc;
    char buf[2];
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.stack = &s;
    reset_wolfssl_io_state();

    test_recv_fill[0] = 0x11;
    test_recv_fill[1] = 0x22;
    test_recv_fill[2] = 0x33;
    test_recv_fill_len = 3;
    test_recv_ret = 2;
    memset(buf, 0, sizeof(buf));
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, 2);
    ck_assert_int_eq((unsigned char)buf[0], 0x11);
    ck_assert_int_eq((unsigned char)buf[1], 0x22);
}
END_TEST

START_TEST(test_wolfssl_io_recv_want_read_keeps_buffer)
{
    struct wolfIP s;
    struct wolfip_io_desc desc;
    char buf[3] = {0x5A, 0x5A, 0x5A};
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.stack = &s;
    reset_wolfssl_io_state();

    test_recv_ret = -WOLFIP_EAGAIN;
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_READ);
    ck_assert_mem_eq(buf, "\x5A\x5A\x5A", 3);
}
END_TEST

START_TEST(test_wolfssl_io_recv_alternating_eagain_short_reads)
{
    struct wolfIP s;
    struct wolfip_io_desc desc;
    char buf[6];
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.stack = &s;
    reset_wolfssl_io_state();

    test_recv_fill[0] = 0x01;
    test_recv_fill[1] = 0x02;
    test_recv_fill[2] = 0x03;
    test_recv_fill[3] = 0x04;
    test_recv_fill[4] = 0x05;
    test_recv_fill[5] = 0x06;
    test_recv_steps_len = 5;
    test_recv_steps[0] = -WOLFIP_EAGAIN;
    test_recv_steps[1] = 2;
    test_recv_steps[2] = -WOLFIP_EAGAIN;
    test_recv_steps[3] = 2;
    test_recv_steps[4] = 2;

    memset(buf, 0, sizeof(buf));
    ret = wolfIP_io_recv(NULL, buf, 2, &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_READ);

    ret = wolfIP_io_recv(NULL, buf, 2, &desc);
    ck_assert_int_eq(ret, 2);
    ck_assert_int_eq((unsigned char)buf[0], 0x01);
    ck_assert_int_eq((unsigned char)buf[1], 0x02);

    ret = wolfIP_io_recv(NULL, buf + 2, 2, &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_READ);

    ret = wolfIP_io_recv(NULL, buf + 2, 2, &desc);
    ck_assert_int_eq(ret, 2);
    ck_assert_int_eq((unsigned char)buf[2], 0x03);
    ck_assert_int_eq((unsigned char)buf[3], 0x04);

    ret = wolfIP_io_recv(NULL, buf + 4, 2, &desc);
    ck_assert_int_eq(ret, 2);
    ck_assert_int_eq((unsigned char)buf[4], 0x05);
    ck_assert_int_eq((unsigned char)buf[5], 0x06);
}
END_TEST

START_TEST(test_wolfssl_io_send_behaviors)
{
    struct wolfIP s;
    struct wolfip_io_desc desc;
    char buf[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.stack = &s;

    reset_wolfssl_io_state();
    test_send_ret = -WOLFIP_EAGAIN;
    ret = wolfIP_io_send(NULL, buf, 4, &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_WRITE);

    test_send_ret = -1;
    ret = wolfIP_io_send(NULL, buf, 4, &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_WRITE);

    test_send_ret = 0;
    ret = wolfIP_io_send(NULL, buf, 4, &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_CONN_CLOSE);

    test_send_capture_len = 4;
    test_send_ret = 4;
    memset(test_send_capture, 0, sizeof(test_send_capture));
    ret = wolfIP_io_send(NULL, buf, 4, &desc);
    ck_assert_int_eq(ret, 4);
    ck_assert_int_eq(test_send_last_len, 4);
    ck_assert_mem_eq(test_send_capture, buf, 4);
}
END_TEST

START_TEST(test_wolfssl_io_send_want_write_keeps_buffer)
{
    struct wolfIP s;
    struct wolfip_io_desc desc;
    char buf[3] = {0x6B, 0x6B, 0x6B};
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.stack = &s;
    reset_wolfssl_io_state();

    test_send_ret = -WOLFIP_EAGAIN;
    ret = wolfIP_io_send(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_WRITE);
    ck_assert_mem_eq(buf, "\x6B\x6B\x6B", 3);
}
END_TEST

START_TEST(test_wolfssl_io_send_invalid_desc)
{
    char buf[4] = {0};
    int ret;

    reset_wolfssl_io_state();
    ret = wolfIP_io_send(NULL, buf, sizeof(buf), NULL);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_GENERAL);
}
END_TEST

START_TEST(test_tcp_listen_rejects_wrong_interface)
{
    struct wolfIP s;
    const ip4 primary_ip = 0xC0A80001U;
    const ip4 secondary_ip = 0xC0A80101U;
    const uint16_t listen_port = 12345;
    int listen_fd;
    struct wolfIP_sockaddr_in addr;
    struct tsocket *listener;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);

    listen_fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(listen_fd, 0);
    listener = &s.tcpsockets[SOCKET_UNMARK(listen_fd)];

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(listen_port);
    addr.sin_addr.s_addr = ee32(primary_ip);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_fd, (struct wolfIP_sockaddr *)&addr, sizeof(addr)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_fd, 1), 0);

    inject_tcp_syn(&s, TEST_SECOND_IF, secondary_ip, listen_port);

    ck_assert_int_eq(listener->sock.tcp.state, TCP_LISTEN);
    ck_assert_int_eq(listener->events & CB_EVENT_READABLE, 0);
}
END_TEST

START_TEST(test_tcp_listen_accepts_bound_interface)
{
    struct wolfIP s;
    const ip4 primary_ip = 0xC0A80002U;
    const ip4 secondary_ip = 0xC0A80101U;
    const uint16_t listen_port = 23456;
    int listen_fd;
    int client_fd;
    struct wolfIP_sockaddr_in addr;
    struct tsocket *listener;
    struct tsocket *client;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);

    listen_fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(listen_fd, 0);
    listener = &s.tcpsockets[SOCKET_UNMARK(listen_fd)];

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(listen_port);
    addr.sin_addr.s_addr = ee32(secondary_ip);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_fd, (struct wolfIP_sockaddr *)&addr, sizeof(addr)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_fd, 1), 0);

    inject_tcp_syn(&s, TEST_SECOND_IF, secondary_ip, listen_port);

    ck_assert_int_eq(listener->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(listener->local_ip, secondary_ip);
    ck_assert_uint_eq(listener->if_idx, TEST_SECOND_IF);

    client_fd = wolfIP_sock_accept(&s, listen_fd, NULL, NULL);
    ck_assert_int_ge(client_fd, 0);
    client = &s.tcpsockets[SOCKET_UNMARK(client_fd)];
    ck_assert_uint_eq(client->local_ip, secondary_ip);
    ck_assert_uint_eq(client->bound_local_ip, secondary_ip);
    /* After accept(), socket stays in SYN_RCVD until final ACK. */
    ck_assert_int_eq(client->sock.tcp.state, TCP_SYN_RCVD);
}
END_TEST

START_TEST(test_tcp_listen_accepts_any_interface)
{
    struct wolfIP s;
    const ip4 primary_ip = 0xC0A80005U;
    const ip4 secondary_ip = 0xC0A80105U;
    const uint16_t listen_port = 34567;
    int listen_fd;
    int client_fd;
    struct wolfIP_sockaddr_in addr;
    struct tsocket *listener;
    struct tsocket *client;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);

    listen_fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(listen_fd, 0);
    listener = &s.tcpsockets[SOCKET_UNMARK(listen_fd)];

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(listen_port);
    addr.sin_addr.s_addr = ee32(IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_fd, (struct wolfIP_sockaddr *)&addr, sizeof(addr)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_fd, 1), 0);

    inject_tcp_syn(&s, TEST_SECOND_IF, secondary_ip, listen_port);

    ck_assert_int_eq(listener->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(listener->local_ip, secondary_ip);
    ck_assert_uint_eq(listener->if_idx, TEST_SECOND_IF);

    client_fd = wolfIP_sock_accept(&s, listen_fd, NULL, NULL);
    ck_assert_int_ge(client_fd, 0);
    client = &s.tcpsockets[SOCKET_UNMARK(client_fd)];
    ck_assert_uint_eq(client->local_ip, secondary_ip);
    /* After accept(), socket stays in SYN_RCVD until final ACK. */
    ck_assert_int_eq(client->sock.tcp.state, TCP_SYN_RCVD);
}
END_TEST

START_TEST(test_sock_connect_selects_local_ip_multi_if)
{
    struct wolfIP s;
    const ip4 primary_ip = 0xC0A80009U;
    const ip4 secondary_ip = 0xC0A80109U;
    const ip4 remote_primary = 0xC0A800AAU;
    const ip4 remote_secondary = 0xC0A801A1U;
    int udp_fd;
    int tcp_fd;
    struct wolfIP_sockaddr_in dst;
    struct tsocket *ts;
    int ret;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);

    udp_fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(udp_fd, 0);
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = ee16(5555);
    dst.sin_addr.s_addr = ee32(remote_secondary);
    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_fd, (struct wolfIP_sockaddr *)&dst, sizeof(dst)), 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_fd)];
    ck_assert_uint_eq(ts->local_ip, secondary_ip);
    ck_assert_uint_eq(ts->if_idx, TEST_SECOND_IF);

    tcp_fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(tcp_fd, 0);
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = ee16(8080);
    dst.sin_addr.s_addr = ee32(remote_primary);
    ret = wolfIP_sock_connect(&s, tcp_fd, (struct wolfIP_sockaddr *)&dst, sizeof(dst));
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_fd)];
    ck_assert_uint_eq(ts->local_ip, primary_ip);
    ck_assert_uint_eq(ts->if_idx, TEST_PRIMARY_IF);
}
END_TEST


// Test for `transport_checksum` calculation
START_TEST(test_transport_checksum) {
    union transport_pseudo_header ph;
    struct wolfIP_tcp_seg tcp_data;
    uint16_t checksum;
    memset(&ph, 0, sizeof(ph));
    memset(&tcp_data, 0, sizeof(tcp_data));

    // Set up pseudo-header values for test
    ph.ph.src = 0xc0a80101; // 192.168.1.1
    ph.ph.dst = 0xc0a80102; // 192.168.1.2
    ph.ph.proto = WI_IPPROTO_TCP;
    ph.ph.len = ee16(20); // TCP header length (without options)

    // Test with a simple TCP header with src/dst ports and no data
    tcp_data.src_port = ee16(12345);
    tcp_data.dst_port = ee16(80);
    tcp_data.seq = ee32(1);
    tcp_data.ack = ee32(0);
    tcp_data.hlen = 5; // offset=5 (20 bytes)
    tcp_data.flags = TCP_FLAG_SYN; // SYN
    tcp_data.win = ee16(65535);

    checksum = transport_checksum(&ph, &tcp_data.src_port);
    ck_assert_msg(checksum != 0, "Transport checksum should not be zero");
}
END_TEST

// Test for `iphdr_set_checksum` calculation
START_TEST(test_iphdr_set_checksum) {
    struct wolfIP_ip_packet ip;
    memset(&ip, 0, sizeof(ip));

    ip.ver_ihl = 0x45;
    ip.tos = 0;
    ip.len = ee16(20);
    ip.id = ee16(1);
    ip.flags_fo = 0;
    ip.ttl = 64;
    ip.proto = WI_IPPROTO_TCP;
    ip.src = ee32(0xc0a80101); // 192.168.1.1
    ip.dst = ee32(0xc0a80102); // 192.168.1.2

    iphdr_set_checksum(&ip);
    ck_assert_msg(ip.csum != 0, "IP header checksum should not be zero");
}
END_TEST

// Test for `eth_output_add_header` to add Ethernet headers
START_TEST(test_eth_output_add_header) {
    struct wolfIP_eth_frame eth_frame;
    struct wolfIP S;
    uint8_t test_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    struct wolfIP_ll_dev *ll;

    wolfIP_init(&S);
    memset(&eth_frame, 0, sizeof(eth_frame));

    ll = wolfIP_getdev_ex(&S, TEST_PRIMARY_IF);
    memcpy(ll->mac, test_mac, 6);

    eth_output_add_header(&S, TEST_PRIMARY_IF, NULL, &eth_frame, ETH_TYPE_IP);

    ck_assert_mem_eq(eth_frame.dst, "\xff\xff\xff\xff\xff\xff", 6);  // Broadcast
    ck_assert_mem_eq(eth_frame.src, test_mac, 6);
    ck_assert_uint_eq(eth_frame.type, ee16(ETH_TYPE_IP));
}
END_TEST

START_TEST(test_eth_output_add_header_invalid_if)
{
    struct wolfIP_eth_frame eth_frame;
    struct wolfIP S;
    int ret;

    wolfIP_init(&S);
    memset(&eth_frame, 0, sizeof(eth_frame));

    ret = eth_output_add_header(&S, WOLFIP_MAX_INTERFACES, NULL, &eth_frame, ETH_TYPE_IP);
    ck_assert_int_eq(ret, -1);
}
END_TEST

// Test for `ip_output_add_header` to set up IP headers and calculate checksums
START_TEST(test_ip_output_add_header) {
    struct tsocket t;
    uint8_t ip_buf[ETH_HEADER_LEN + IP_HEADER_LEN + 40];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)ip_buf;
    struct wolfIP S;
    int result;
    struct wolfIP_tcp_seg *tcp;

    memset(&t, 0, sizeof(t));
    memset(ip_buf, 0, sizeof(ip_buf));
    wolfIP_init(&S);

    // Setup socket and IP stack parameters
    t.local_ip = 0xc0a80101;   // 192.168.1.1
    t.remote_ip = 0xc0a80102;  // 192.168.1.2
    t.S = &S;

    // Run the function for a TCP packet
    result = ip_output_add_header(&t, ip, WI_IPPROTO_TCP, 40);
    ck_assert_int_eq(result, 0);

    // Validate IP header fields
    ck_assert_uint_eq(ip->ver_ihl, 0x45);
    ck_assert_uint_eq(ip->ttl, 64);
    ck_assert_uint_eq(ip->proto, WI_IPPROTO_TCP);
    ck_assert_uint_eq(ip->src, ee32(t.local_ip));
    ck_assert_uint_eq(ip->dst, ee32(t.remote_ip));
    ck_assert_uint_eq(ip->flags_fo, ee16(0x4000));
    ck_assert_msg(ip->csum != 0, "IP header checksum should not be zero");

    // Check the pseudo-header checksum calculation for TCP segment
    tcp = (struct wolfIP_tcp_seg *)ip;
    ck_assert_msg(tcp->csum != 0, "TCP checksum should not be zero");
}
END_TEST

START_TEST(test_ip_output_add_header_icmp)
{
    struct tsocket t;
    uint8_t ip_buf[ETH_HEADER_LEN + IP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)ip_buf;
    struct wolfIP S;
    int result;
    struct wolfIP_icmp_packet *icmp;

    memset(&t, 0, sizeof(t));
    memset(ip_buf, 0, sizeof(ip_buf));
    wolfIP_init(&S);

    t.local_ip = 0xc0a80101;
    t.remote_ip = 0xc0a80102;
    t.S = &S;
    t.if_idx = TEST_PRIMARY_IF;
    mock_link_init(&S);

    result = ip_output_add_header(&t, ip, WI_IPPROTO_ICMP, IP_HEADER_LEN + ICMP_HEADER_LEN);
    ck_assert_int_eq(result, 0);

    icmp = (struct wolfIP_icmp_packet *)ip;
    ck_assert_msg(icmp->csum != 0, "ICMP checksum should not be zero");
}
END_TEST

START_TEST(test_icmp_socket_send_recv)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN + 4];
    uint32_t local_ip = 0x0A000001U;
    uint32_t remote_ip = 0x0A000002U;
    struct tsocket *ts;
    struct wolfIP_icmp_packet *sent_pkt;
    uint8_t reply_buf[sizeof(struct wolfIP_icmp_packet) + sizeof(payload)];
    struct wolfIP_icmp_packet *reply = (struct wolfIP_icmp_packet *)reply_buf;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x01};
    uint8_t rxbuf[sizeof(payload)];
    struct wolfIP_sockaddr_in from;
    socklen_t from_len = sizeof(from);
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(sd)];
    ck_assert_uint_gt(fifo_space(&ts->sock.udp.txbuf), (uint32_t)sizeof(payload));
    fifo_init(&ts->sock.udp.txbuf, ts->txmem, TXBUF_SIZE);
    fifo_init(&ts->sock.udp.rxbuf, ts->rxmem, RXBUF_SIZE);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(remote_ip);

    memset(payload, 0, sizeof(payload));
    payload[0] = ICMP_ECHO_REQUEST;
    payload[1] = 0;
    payload[ICMP_HEADER_LEN] = 'P';
    payload[ICMP_HEADER_LEN + 1] = 'I';
    payload[ICMP_HEADER_LEN + 2] = 'N';
    payload[ICMP_HEADER_LEN + 3] = 'G';

    ret = wolfIP_sock_sendto(&s, sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ts = &s.icmpsockets[SOCKET_UNMARK(sd)];
    ck_assert_uint_eq(ts->if_idx, TEST_PRIMARY_IF);

    {
        struct pkt_desc *desc = fifo_peek(&ts->sock.udp.txbuf);
        ck_assert_ptr_nonnull(desc);
        sent_pkt = (struct wolfIP_icmp_packet *)(ts->txmem + desc->pos + sizeof(*desc));
        ck_assert_uint_eq(sent_pkt->type, ICMP_ECHO_REQUEST);
        ck_assert_uint_eq(icmp_echo_id(sent_pkt), ts->src_port);
        fifo_pop(&ts->sock.udp.txbuf);
    }

    memset(reply, 0, sizeof(reply_buf));
    memcpy(reply->ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(reply->ip.eth.src, peer_mac, 6);
    reply->ip.eth.type = ee16(ETH_TYPE_IP);
    reply->ip.ver_ihl = 0x45;
    reply->ip.ttl = 64;
    reply->ip.proto = WI_IPPROTO_ICMP;
    reply->ip.len = ee16(IP_HEADER_LEN + sizeof(payload));
    reply->ip.src = ee32(remote_ip);
    reply->ip.dst = ee32(local_ip);
    reply->type = ICMP_ECHO_REPLY;
    reply->code = 0;
    icmp_set_echo_id(reply, ts->src_port);
    {
        uint16_t seq = ee16(1);
        memcpy(reply->unused + sizeof(uint16_t), &seq, sizeof(seq));
    }
    memcpy(((uint8_t *)&reply->type) + ICMP_HEADER_LEN,
            payload + ICMP_HEADER_LEN,
            sizeof(payload) - ICMP_HEADER_LEN);
    reply->csum = 0;
    reply->csum = ee16(icmp_checksum(reply, sizeof(payload)));
    reply->ip.csum = 0;
    iphdr_set_checksum(&reply->ip);

    wolfIP_recv(&s, reply, ETH_HEADER_LEN + IP_HEADER_LEN + sizeof(payload));

    memset(&from, 0, sizeof(from));
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len);
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(rxbuf, &reply->type, sizeof(payload));
    ck_assert_uint_eq(from.sin_addr.s_addr, ee32(remote_ip));
    ck_assert_uint_eq(from_len, sizeof(from));

    /* Ensure the packet was removed from the queue */
    memset(rxbuf, 0, sizeof(rxbuf));
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
            NULL, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_icmp_sendto_respects_bound_local_ip_interface)
{
    struct wolfIP s;
    const ip4 primary_ip = 0xC0A80009U;
    const ip4 secondary_ip = 0xC0A80109U;
    const ip4 remote_secondary = 0xC0A801A1U;
    int sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(sd)];
    fifo_init(&ts->sock.udp.txbuf, ts->txmem, TXBUF_SIZE);
    ts->bound_local_ip = primary_ip;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(remote_secondary);

    payload[0] = ICMP_ECHO_REQUEST;

    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    ck_assert_uint_eq(ts->local_ip, primary_ip);
    ck_assert_uint_eq(ts->if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_icmp_sendto_respects_mtu_api)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t small_payload[30] = {0};
    uint8_t large_payload[31] = {0};
    struct tsocket *ts;
    uint32_t mtu = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF, 64U), 0);
    ck_assert_int_eq(wolfIP_mtu_get(&s, TEST_PRIMARY_IF, &mtu), 0);
    ck_assert_uint_eq(mtu, 64U);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(sd)];
    fifo_init(&ts->sock.udp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    small_payload[0] = ICMP_ECHO_REQUEST;
    large_payload[0] = ICMP_ECHO_REQUEST;

    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, small_payload, sizeof(small_payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(small_payload));
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.txbuf));

    fifo_init(&ts->sock.udp.txbuf, ts->txmem, TXBUF_SIZE);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, large_payload, sizeof(large_payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
    ck_assert_ptr_null(fifo_peek(&ts->sock.udp.txbuf));
}
END_TEST

START_TEST(test_regression_snd_una_initialized_on_syn_rcvd)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    uint16_t local_port = 8080;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port   = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    wolfIP_sock_listen(&s, sd, 1);

    /* inject_tcp_syn uses a deterministic PRNG seed so seq is reproducible */
    inject_tcp_syn(&s, TEST_PRIMARY_IF, local_ip, local_port);

    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);

    /* snd_una must equal the ISN that was placed in seq, not 0 */
    ck_assert_uint_eq(ts->sock.tcp.snd_una, ts->sock.tcp.seq);

    /* The wrap-aware ordering invariant: snd_una <= seq */
    ck_assert_int_eq(tcp_seq_leq(ts->sock.tcp.snd_una, ts->sock.tcp.seq), 1);
}
END_TEST

START_TEST(test_regression_duplicate_syn_rejected_on_established)
{
    struct wolfIP s;
    int sd, sd2;
    struct wolfIP_sockaddr_in sin;
    struct tsocket *listener, *established;
    ip4 local_ip   = 0x0A000001U;
    ip4 remote_ip  = 0x0A0000A1U; /* hardcoded in inject_tcp_syn */
    uint16_t local_port  = 8080;
    uint16_t remote_port = 40000; /* hardcoded in inject_tcp_syn */

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    /* Create a listening socket that must stay in LISTEN throughout */
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port   = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    wolfIP_sock_listen(&s, sd, 4);
    listener = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ck_assert_int_eq(listener->sock.tcp.state, TCP_LISTEN);

    /* Allocate a second socket slot and wire it as ESTABLISHED with the
     * same 4-tuple that inject_tcp_syn will use.  This simulates a live
     * connection that was established by a previous handshake. */
    sd2 = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd2, 0);
    established = &s.tcpsockets[SOCKET_UNMARK(sd2)];
    established->sock.tcp.state   = TCP_ESTABLISHED;
    established->local_ip         = local_ip;
    established->remote_ip        = remote_ip;
    established->if_idx           = TEST_PRIMARY_IF;
    established->src_port         = local_port;
    established->dst_port         = remote_port;
    established->sock.tcp.seq     = 1000;
    established->sock.tcp.snd_una = 1000;
    established->sock.tcp.ack     = 2;
    established->sock.tcp.cwnd    = TCP_MSS;
    established->sock.tcp.peer_rwnd = TCP_MSS;
    queue_init(&established->sock.tcp.rxbuf, established->rxmem, RXBUF_SIZE, 0);
    fifo_init(&established->sock.tcp.txbuf, established->txmem, TXBUF_SIZE);

    /* Send a SYN whose tuple matches the established connection above.
     * Without the fix (da5c792): listener → TCP_SYN_RCVD.
     * With the fix:              listener stays in TCP_LISTEN. */
    inject_tcp_syn(&s, TEST_PRIMARY_IF, local_ip, local_port);

    ck_assert_int_eq(listener->sock.tcp.state, TCP_LISTEN);
}
END_TEST


START_TEST(test_regression_timer_heap_insert_bounded_by_max_timers)
{
    struct timers_binheap h;
    struct wolfIP_timer anchor, tmr;
    int id;
    int i;

    memset(&h, 0, sizeof(h));

    memset(&anchor, 0, sizeof(anchor));
    anchor.expires = 50;
    anchor.cb      = test_timer_cb;
    anchor.arg     = NULL;
    timers_binheap_insert(&h, anchor);
    ck_assert_uint_eq(h.size, 1);

    for (i = 0; i < MAX_TIMERS + 4; i++) {
        memset(&tmr, 0, sizeof(tmr));
        tmr.expires = 1000;
        tmr.cb      = test_timer_cb;
        tmr.arg     = NULL;
        id = timers_binheap_insert(&h, tmr);

        ck_assert_uint_le(h.size, (uint32_t)MAX_TIMERS);

        timer_binheap_cancel(&h, id);
    }

    timers_binheap_pop(&h);
    memset(&tmr, 0, sizeof(tmr));
    tmr.expires = 300;
    tmr.cb      = test_timer_cb;
    tmr.arg     = NULL;
    id = timers_binheap_insert(&h, tmr);
    ck_assert_int_ne(id, 0);
    ck_assert_uint_le(h.size, (uint32_t)MAX_TIMERS);
}
END_TEST

START_TEST(test_regression_icmp_inflated_ip_len)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_OFF;
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.ttl = 64;
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN + 256);
    icmp.type   = ICMP_ECHO_REQUEST;
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_regression_udp_inflated_udp_len)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_udp_datagram) + 4];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)buf;
    uint32_t local_ip = 0x0A000001U;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(buf, 0, sizeof(buf));
    udp->ip.dst     = ee32(local_ip);
    udp->ip.ver_ihl = 0x45;
    udp->ip.proto   = WI_IPPROTO_UDP;
    udp->ip.len  = ee16(IP_HEADER_LEN + UDP_HEADER_LEN + 4);
    udp->dst_port = ee16(1234);
    udp->len = ee16(UDP_HEADER_LEN + 4096);
    udp->csum = 0xFFFFU;
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4);

    udp_try_recv(&s, TEST_PRIMARY_IF, udp, frame_len);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_regression_udp_len_below_header_discards_and_unblocks)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_udp_datagram) + 64];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)buf;
    uint8_t rxbuf[64];
    int sd, ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = 0x0A000001U;

    /* Compute the socket descriptor from the slot index */
    sd = (int)(MARK_UDP_SOCKET | (uint32_t)(ts - s.udpsockets));

    /* Inject a malformed UDP packet with udp->len < UDP_HEADER_LEN (8).
     * Push directly into the socket rxbuf to bypass ingress filtering,
     * simulating a crafted packet that reaches recvfrom. */
    memset(buf, 0, sizeof(buf));
    udp->src_port = ee16(9999);
    udp->dst_port = ee16(1234);
    udp->len = ee16(4); /* invalid length: 4 < UDP_HEADER_LEN(8) */
    ret = fifo_push(&ts->sock.udp.rxbuf, udp, sizeof(struct wolfIP_udp_datagram));
    ck_assert_int_eq(ret, 0);

    /* recvfrom must return EINVAL and discard the malformed packet */
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    /* FIFO must be empty: the malformed packet was popped, not left behind */
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);

    /* A subsequent recvfrom must return EAGAIN, not the same error again */
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_regression_udp_payload_exceeds_buffer_discards_and_unblocks)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t payload[32];
    uint8_t rxbuf[8]; /* smaller than payload */
    int sd, ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = 0x0A000001U;

    sd = (int)(MARK_UDP_SOCKET | (uint32_t)(ts - s.udpsockets));

    /* Inject a valid UDP packet whose payload exceeds the caller's buffer. */
    memset(payload, 0xAB, sizeof(payload));
    enqueue_udp_rx(ts, payload, sizeof(payload), 9999);

    /* recvfrom with a too-small buffer must discard the packet and return EINVAL */
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    /* FIFO must be empty: packet was popped, not left to block subsequent reads */
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);

    /* A subsequent recvfrom must return EAGAIN, not the same error again */
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_regression_icmp_payload_exceeds_buffer_discards_and_unblocks)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_icmp_packet) + 32];
    struct wolfIP_icmp_packet *icmp = (struct wolfIP_icmp_packet *)buf;
    uint8_t rxbuf[8];
    int sd, ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = icmp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = 0x0A000001U;

    sd = (int)(MARK_ICMP_SOCKET | (uint32_t)(ts - s.icmpsockets));

    memset(buf, 0, sizeof(buf));
    icmp->ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN + 32);
    icmp->type = ICMP_ECHO_REPLY;
    ret = fifo_push(&ts->sock.udp.rxbuf, icmp,
            sizeof(struct wolfIP_icmp_packet) + 32);
    ck_assert_int_eq(ret, 0);
    ts->events |= CB_EVENT_READABLE;

    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, -1);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, 0U);

    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_regression_icmp_ip_len_below_header)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_OFF;
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.ttl = 64;
    icmp.ip.len = 0;
    icmp.type   = ICMP_ECHO_REQUEST;
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST


START_TEST(test_regression_tcp_ip_len_below_ip_header)
{
    struct wolfIP s;
    struct wolfIP_tcp_seg seg;
    struct wolfIP_ll_dev *ll;
    static const uint8_t src_mac[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    memset(&seg, 0, sizeof(seg));
    memcpy(seg.ip.eth.dst, ll->mac, 6);
    memcpy(seg.ip.eth.src, src_mac, 6);
    seg.ip.eth.type = ee16(ETH_TYPE_IP);
    seg.ip.ver_ihl  = 0x45;
    seg.ip.ttl      = 64;
    seg.ip.proto    = WI_IPPROTO_TCP;
    seg.ip.src      = ee32(0x0A0000A1U);
    seg.ip.dst      = ee32(0x0A000001U);
    seg.ip.len      = ee16(2);
    seg.src_port    = ee16(40000);
    seg.dst_port    = ee16(80);
    seg.flags       = TCP_FLAG_SYN;
    seg.hlen        = TCP_HEADER_LEN << 2;
    seg.win         = ee16(65535);
    frame_len = (uint32_t)sizeof(struct wolfIP_tcp_seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST


/* RFC 9293 §3.10.7.4: SYN on synchronized connection must not be silently
 * processed.  The implementation must either send a challenge ACK and drop
 * (RFC 5961) or send RST and abort (original RFC 793).  The current code
 * silently processes an in-window SYN as normal data on ESTABLISHED
 * connections, potentially corrupting connection state. */
START_TEST(test_regression_syn_on_established_not_silently_processed)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    uint32_t original_ack;
    uint32_t original_seq;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    last_frame_sent_size = 0;

    /* Set up an ARP entry so the stack can send a reply frame */
    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac,
           (uint8_t[]){0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, 6);

    /* Wire up socket slot 0 as an ESTABLISHED connection */
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.seq = 1000;
    ts->sock.tcp.snd_una = 1000;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.peer_rwnd = TCP_MSS;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->if_idx = TEST_PRIMARY_IF;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    original_ack = ts->sock.tcp.ack;
    original_seq = ts->sock.tcp.seq;

    /* Craft an in-window SYN segment (seq == rcv_nxt so it passes the
     * acceptability test and reaches the established-state handler). */
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
    seg.flags = TCP_FLAG_SYN;
    seg.seq = ee32(100); /* == ts->sock.tcp.ack, i.e. in-window */
    seg.win = ee16(65535);
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    /* tcp_send_ack enqueues into txbuf; flush it via wolfIP_poll */
    (void)wolfIP_poll(&s, 200);

    /* The SYN must NOT be silently accepted.  The connection state must not
     * have been corrupted by processing the SYN as data. Verify:
     * 1) The connection did not stay silently in ESTABLISHED with no reply
     *    (last_frame_sent_size > 0 means a challenge ACK or RST was sent).
     * 2) The ack/seq values were not altered by data processing. */
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(ts->sock.tcp.ack, original_ack);
    ck_assert_uint_eq(ts->sock.tcp.seq, original_seq);
}
END_TEST

/* RFC 9293 §3.10.7.4: LAST-ACK is a synchronized state.  A SYN arriving
 * on a LAST_ACK socket must trigger a challenge ACK and be dropped, not
 * silently ignored or processed as a normal ACK. */
START_TEST(test_regression_syn_on_last_ack_not_silently_processed)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    uint32_t original_ack;
    uint32_t original_seq;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac,
           (uint8_t[]){0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, 6);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LAST_ACK;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.seq = 1000;
    ts->sock.tcp.snd_una = 1000;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.peer_rwnd = TCP_MSS;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->if_idx = TEST_PRIMARY_IF;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    original_ack = ts->sock.tcp.ack;
    original_seq = ts->sock.tcp.seq;

    /* In-window SYN+ACK: without the fix tcp_ack() would process this
     * as a normal acknowledgment in LAST_ACK. */
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
    seg.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    seg.seq = ee32(100);
    seg.ack = ee32(ts->sock.tcp.seq);
    seg.win = ee16(65535);
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    (void)wolfIP_poll(&s, 200);

    /* The SYN must not be silently processed.  A challenge ACK must be
     * sent and the segment dropped without altering connection state. */
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(ts->sock.tcp.state, TCP_LAST_ACK);
    ck_assert_uint_eq(ts->sock.tcp.ack, original_ack);
    ck_assert_uint_eq(ts->sock.tcp.seq, original_seq);
}
END_TEST

/* F/1774: even if the shared TCP TX FIFO is full of sent payload waiting for
 * ACK, the stack still needs to emit a pure ACK for newly received data. */
START_TEST(test_regression_full_txbuf_still_sends_pure_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    struct pkt_desc *desc;
    uint32_t original_ack;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac,
           (uint8_t[]){0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, 6);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.seq = 1000;
    ts->sock.tcp.snd_una = 900;
    ts->sock.tcp.cwnd = TXBUF_SIZE;
    ts->sock.tcp.peer_rwnd = TXBUF_SIZE;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    while (enqueue_tcp_tx(ts, 16, (TCP_FLAG_ACK | TCP_FLAG_PSH)) == 0) {
    }
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    while (desc) {
        desc->flags |= PKT_FLAG_SENT;
        desc = fifo_next(&ts->sock.tcp.txbuf, desc);
    }

    original_ack = ts->sock.tcp.ack;

    memset(buf, 0, sizeof(buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.ttl = 64;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    seg->ip.src = ee32(ts->remote_ip);
    seg->ip.dst = ee32(ts->local_ip);
    seg->dst_port = ee16(ts->src_port);
    seg->src_port = ee16(ts->dst_port);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = TCP_FLAG_ACK;
    seg->seq = ee32(original_ack);
    seg->ack = ee32(ts->sock.tcp.seq);
    seg->win = ee16(65535);
    memcpy(seg->data, (uint8_t[]){0xDE, 0xAD, 0xBE, 0xEF}, 4);
    fix_tcp_checksums(seg);

    tcp_input(&s, TEST_PRIMARY_IF, seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 4));

    ck_assert_uint_eq(ts->sock.tcp.ack, original_ack + 4);

    (void)wolfIP_poll(&s, 200);

    ck_assert_uint_gt(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_regression_loopback_pure_ack_uses_deferred_buffer_until_poll)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_ll_dev *loop;
    struct wolfIP_tcp_seg seg;
    uint32_t expected_pending_len;

    wolfIP_init(&s);
    loop = wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF);
    ck_assert_ptr_nonnull(loop);
    ck_assert_ptr_eq(loop->send, wolfIP_loopback_send);
    last_frame_sent_size = 0;
    memset(last_frame_sent, 0, sizeof(last_frame_sent));

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->if_idx = TEST_LOOPBACK_IF;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.seq = 1000;
    ts->sock.tcp.snd_una = 900;
    ts->sock.tcp.cwnd = TXBUF_SIZE;
    ts->sock.tcp.peer_rwnd = TXBUF_SIZE;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x7F000001U;
    ts->remote_ip = 0x7F000001U;
    memset(&seg, 0, sizeof(seg));
    seg.src_port = ee16(ts->src_port);
    seg.dst_port = ee16(ts->dst_port);
    seg.seq = ee32(ts->sock.tcp.seq);
    seg.ack = ee32(ts->sock.tcp.ack);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_ACK;
    expected_pending_len = (uint32_t)sizeof(seg) - ETH_HEADER_LEN;

    ck_assert_int_eq(tcp_send_empty_immediate(ts, &seg,
            (uint32_t)sizeof(seg)), 0);
    ck_assert_uint_eq(ts->sock.tcp.last_ack, ts->sock.tcp.ack);
    ck_assert_uint_eq(last_frame_sent_size, 0U);
    ck_assert_uint_eq(s.loopback_count, 1U);
    ck_assert_uint_eq(s.loopback_pending_len[s.loopback_head],
                      expected_pending_len);

    (void)wolfIP_poll(&s, 200);
    ck_assert_uint_eq(s.loopback_count, 0U);
}
END_TEST

START_TEST(test_regression_loopback_pure_ack_drain_allows_next_send_cycle)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_ll_dev *loop;
    struct wolfIP_tcp_seg seg;
    uint8_t rx[IP_MTU_MAX];
    uint32_t expected_pending_len = (uint32_t)sizeof(seg) - ETH_HEADER_LEN;

    wolfIP_init(&s);
    loop = wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF);
    ck_assert_ptr_nonnull(loop);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->if_idx = TEST_LOOPBACK_IF;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.seq = 1000;
    ts->sock.tcp.snd_una = 900;
    ts->sock.tcp.cwnd = TXBUF_SIZE;
    ts->sock.tcp.peer_rwnd = TXBUF_SIZE;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x7F000001U;
    ts->remote_ip = 0x7F000001U;
    memset(&seg, 0, sizeof(seg));
    seg.src_port = ee16(ts->src_port);
    seg.dst_port = ee16(ts->dst_port);
    seg.seq = ee32(ts->sock.tcp.seq);
    seg.ack = ee32(ts->sock.tcp.ack);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = TCP_FLAG_ACK;

    ck_assert_int_eq(tcp_send_empty_immediate(ts, &seg, (uint32_t)sizeof(seg)), 0);
    ck_assert_uint_eq(s.loopback_count, 1U);
    ck_assert_uint_eq(s.loopback_pending_len[s.loopback_head],
                      expected_pending_len);

    ck_assert_int_eq(loop->poll(loop, rx, sizeof(rx)), (int)expected_pending_len);
    ck_assert_uint_eq(s.loopback_count, 0U);

    ck_assert_int_eq(tcp_send_empty_immediate(ts, &seg, (uint32_t)sizeof(seg)), 0);
    ck_assert_uint_eq(s.loopback_count, 1U);
    ck_assert_uint_eq(s.loopback_pending_len[s.loopback_head],
                      expected_pending_len);
}
END_TEST

START_TEST(test_regression_tcp_tx_desc_payload_len_keeps_descriptor_layout_sanity)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc desc;
    struct wolfIP_tcp_seg seg;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->if_idx = TEST_PRIMARY_IF;

    memset(&desc, 0, sizeof(desc));
    memset(&seg, 0, sizeof(seg));
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.ip.len = 0;

    /* Short Ethernet-backed descriptors must not be treated as if desc->len
     * were already an IP length. */
    desc.len = IP_HEADER_LEN + TCP_HEADER_LEN + 4;
    ck_assert_uint_eq(tcp_tx_desc_ip_len(ts, &desc, &seg), 0U);
    ck_assert_uint_eq(tcp_tx_desc_payload_len(ts, &desc, &seg), 0U);

    /* Non-Ethernet links still use the same queued descriptor layout. */
    s.ll_dev[TEST_PRIMARY_IF].non_ethernet = 1;
    ck_assert_uint_eq(tcp_tx_desc_ip_len(ts, &desc, &seg), 0U);
    ck_assert_uint_eq(tcp_tx_desc_payload_len(ts, &desc, &seg), 0U);

    /* Once the descriptor includes stored link headroom, both paths decode
     * the same IP and payload lengths. */
    desc.len = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 4;
    s.ll_dev[TEST_PRIMARY_IF].non_ethernet = 0;
    ck_assert_uint_eq(tcp_tx_desc_ip_len(ts, &desc, &seg),
            IP_HEADER_LEN + TCP_HEADER_LEN + 4U);
    ck_assert_uint_eq(tcp_tx_desc_payload_len(ts, &desc, &seg), 4U);

    s.ll_dev[TEST_PRIMARY_IF].non_ethernet = 1;
    ck_assert_uint_eq(tcp_tx_desc_ip_len(ts, &desc, &seg),
            IP_HEADER_LEN + TCP_HEADER_LEN + 4U);
    ck_assert_uint_eq(tcp_tx_desc_payload_len(ts, &desc, &seg), 4U);
}
END_TEST


/* RFC 5681 §3.2: fast recovery deviates in multiple ways.
 * (a) ssthresh uses cwnd/2 instead of max(FlightSize/2, 2*SMSS)
 * (b) cwnd set to ssthresh + 1*SMSS instead of ssthresh + 3*SMSS
 * (c) no cwnd inflation by SMSS for each dup ACK beyond the 3rd
 * (d) no cwnd deflation to ssthresh on new-data ACK exiting recovery */
START_TEST(test_regression_fast_recovery_cwnd_ssthresh_rfc5681)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    struct pkt_desc *desc;
    uint32_t smss;
    uint32_t flight_size;
    uint32_t expected_ssthresh;
    uint32_t expected_cwnd;
    uint32_t cwnd_after_3rd;
    uint8_t txbuf[ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + TCP_MSS];
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    smss = tcp_cc_mss(ts);
    ck_assert_uint_gt(smss, 0);

    flight_size = 4 * smss;

    ts->sock.tcp.snd_una = 1000;
    ts->sock.tcp.ack = 500;
    ts->sock.tcp.cwnd = 10 * smss;     /* App-limited: cwnd >> FlightSize */
    ts->sock.tcp.ssthresh = 20 * smss;
    ts->sock.tcp.peer_rwnd = 20 * smss;
    ts->sock.tcp.bytes_in_flight = flight_size;

    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* Enqueue four full-sized sent segments so partial ACK handling can
     * advance cumulatively while still leaving data outstanding. */
    memset(txbuf, 0xAB, sizeof(txbuf));
    for (i = 0; i < 4; i++) {
        struct wolfIP_tcp_seg *out = (struct wolfIP_tcp_seg *)txbuf;
        uint32_t total_len = IP_HEADER_LEN + TCP_HEADER_LEN + smss;
        uint32_t frame_len = ETH_HEADER_LEN + total_len;
        memset(txbuf, 0, ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN);
        out->ip.len = ee16((uint16_t)total_len);
        out->hlen = TCP_HEADER_LEN << 2;
        out->flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
        out->seq = ee32(ts->sock.tcp.snd_una + (i * smss));
        out->ack = ee32(ts->sock.tcp.ack);
        out->src_port = ee16(ts->src_port);
        out->dst_port = ee16(ts->dst_port);
        memset((uint8_t *)out->ip.data + TCP_HEADER_LEN, 0xAB, smss);
        ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, out, frame_len), 0);
    }
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    while (desc) {
        desc->flags |= PKT_FLAG_SENT;
        desc = fifo_next(&ts->sock.tcp.txbuf, desc);
        if (desc == fifo_peek(&ts->sock.tcp.txbuf))
            break;
    }
    ts->sock.tcp.seq = 1000 + flight_size;

    /* --- Phase 1: send 3 duplicate ACKs to enter fast recovery --- */
    for (i = 0; i < 3; i++) {
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
        seg.seq = ee32(ts->sock.tcp.ack);
        seg.ack = ee32(1000);  /* == snd_una, no advance */
        seg.win = ee16(65535);
        fix_tcp_checksums(&seg);

        tcp_input(&s, TEST_PRIMARY_IF, &seg,
                  (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    }

    /* (a) ssthresh = max(FlightSize/2, 2*SMSS) = max(2*SMSS, 2*SMSS) = 2*SMSS
     *     Bug: max(cwnd/2, 2*SMSS) = max(5*SMSS, 2*SMSS) = 5*SMSS
     * (b) cwnd = ssthresh + 3*SMSS = 5*SMSS
     *     Bug: ssthresh + 1*SMSS = 6*SMSS */
    expected_ssthresh = 2 * smss;
    expected_cwnd = expected_ssthresh + 3 * smss;
    ck_assert_uint_eq(ts->sock.tcp.ssthresh, expected_ssthresh);
    ck_assert_uint_eq(ts->sock.tcp.cwnd, expected_cwnd);

    /* --- Phase 2: 4th dup ACK should inflate cwnd by SMSS (c) --- */
    cwnd_after_3rd = ts->sock.tcp.cwnd;

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
    seg.seq = ee32(ts->sock.tcp.ack);
    seg.ack = ee32(1000);
    seg.win = ee16(65535);
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    /* (c) cwnd should be inflated by exactly SMSS, not recomputed */
    ck_assert_uint_eq(ts->sock.tcp.cwnd, cwnd_after_3rd + smss);

    /* Simulate the fast retransmit having been sent so a partial ACK can
     * acknowledge it and expose the next hole. */
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_ne(desc->flags & PKT_FLAG_RETRANS, 0);
    desc->flags |= PKT_FLAG_SENT;
    desc->flags &= ~PKT_FLAG_RETRANS;
    desc->flags |= PKT_FLAG_WAS_RETRANS;

    /* --- Phase 3: a partial ACK should stay in recovery and mark the next
     * missing segment for retransmission. */
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
    seg.seq = ee32(ts->sock.tcp.ack);
    seg.ack = ee32(1000 + smss);
    seg.win = ee16(65535);
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    ck_assert_uint_eq(ts->sock.tcp.snd_una, 1000 + smss);
    ck_assert_uint_eq(ts->sock.tcp.cwnd, cwnd_after_3rd + smss);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(ee32(((struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc)))->seq),
            1000 + smss);
    ck_assert_int_ne(desc->flags & PKT_FLAG_RETRANS, 0);

    /* Simulate the second retransmission being sent, then ACK all data that
     * was outstanding when recovery began. */
    desc->flags |= PKT_FLAG_SENT;
    desc->flags &= ~PKT_FLAG_RETRANS;
    desc->flags |= PKT_FLAG_WAS_RETRANS;

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
    seg.seq = ee32(ts->sock.tcp.ack);
    seg.ack = ee32(1000 + flight_size);
    seg.win = ee16(65535);
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    ck_assert_uint_eq(ts->sock.tcp.cwnd, ts->sock.tcp.ssthresh);
}
END_TEST


/* RFC 7323 §3.2: when timestamps are negotiated, segments with
 * SEG.TSval < TS.Recent (stale timestamp) must be rejected (send ACK
 * and discard) to protect against wrapped sequence numbers (PAWS).
 * The current code accepts such segments, risking data corruption on
 * long-lived high-throughput connections. */
START_TEST(test_regression_paws_rejects_stale_timestamp)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *tsopt;
    uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint32_t original_ack;
    uint32_t tcp_hlen = TCP_HEADER_LEN + TCP_OPTIONS_LEN;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac,
           (uint8_t[]){0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, 6);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.seq = 1000;
    ts->sock.tcp.snd_una = 1000;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.peer_rwnd = TCP_MSS;
    ts->sock.tcp.ts_enabled = 1;
    ts->sock.tcp.last_ts = ee32(5000);  /* TS.Recent = 5000 */
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    original_ack = ts->sock.tcp.ack;

    /* Craft an in-window data segment with a stale timestamp (TSval=1000,
     * which is less than TS.Recent=5000).  This simulates an old duplicate
     * with a wrapped sequence number. */
    memset(buf, 0, sizeof(buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.ttl = 64;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.len = ee16(IP_HEADER_LEN + tcp_hlen + sizeof(payload));
    seg->ip.src = ee32(ts->remote_ip);
    seg->ip.dst = ee32(ts->local_ip);
    seg->dst_port = ee16(ts->src_port);
    seg->src_port = ee16(ts->dst_port);
    seg->hlen = (uint8_t)(tcp_hlen << 2);
    seg->flags = TCP_FLAG_ACK;
    seg->seq = ee32(100);  /* == rcv_nxt, in-window */
    seg->ack = ee32(ts->sock.tcp.seq);
    seg->win = ee16(65535);

    /* Append timestamp option with stale TSval */
    tsopt = (struct tcp_opt_ts *)seg->data;
    tsopt->opt = TCP_OPTION_TS;
    tsopt->len = TCP_OPTION_TS_LEN;
    tsopt->val = ee32(1000);   /* SEG.TSval = 1000 < TS.Recent = 5000 */
    tsopt->ecr = ee32(500);
    tsopt->pad = TCP_OPTION_NOP;
    tsopt->eoo = TCP_OPTION_NOP;

    memcpy(seg->data + TCP_OPTIONS_LEN, payload, sizeof(payload));
    fix_tcp_checksums(seg);

    tcp_input(&s, TEST_PRIMARY_IF, seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + tcp_hlen + sizeof(payload)));

    (void)wolfIP_poll(&s, 200);

    /* PAWS: the stale-timestamp segment must be discarded without
     * advancing rcv_nxt (no data accepted into rxbuf). An ACK should
     * be sent in response. */
    ck_assert_uint_eq(ts->sock.tcp.ack, original_ack);
    ck_assert_uint_gt(last_frame_sent_size, 0);
}
END_TEST

/* RFC 7323 §5.2: TSval ordering is modulo 2^32, so after wrap a low
 * TSval can still be newer than TS.Recent. PAWS must not reject such
 * segments just because the raw unsigned value is smaller. */
START_TEST(test_regression_paws_accepts_wrapped_newer_timestamp)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *tsopt;
    uint8_t payload[4] = {0xCA, 0xFE, 0xBA, 0xBE};
    uint8_t out[sizeof(payload)] = {0};
    uint32_t original_ack;
    uint32_t tcp_hlen = TCP_HEADER_LEN + TCP_OPTIONS_LEN;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac,
           (uint8_t[]){0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, 6);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.seq = 1000;
    ts->sock.tcp.snd_una = 1000;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.peer_rwnd = TCP_MSS;
    ts->sock.tcp.ts_enabled = 1;
    ts->sock.tcp.last_ts = ee32(0xFFFFFFF0U);  /* TS.Recent just before wrap */
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    original_ack = ts->sock.tcp.ack;

    memset(buf, 0, sizeof(buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.ttl = 64;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.len = ee16(IP_HEADER_LEN + tcp_hlen + sizeof(payload));
    seg->ip.src = ee32(ts->remote_ip);
    seg->ip.dst = ee32(ts->local_ip);
    seg->dst_port = ee16(ts->src_port);
    seg->src_port = ee16(ts->dst_port);
    seg->hlen = (uint8_t)(tcp_hlen << 2);
    seg->flags = TCP_FLAG_ACK;
    seg->seq = ee32(100);  /* == rcv_nxt, in-window */
    seg->ack = ee32(ts->sock.tcp.seq);
    seg->win = ee16(65535);

    tsopt = (struct tcp_opt_ts *)seg->data;
    tsopt->opt = TCP_OPTION_TS;
    tsopt->len = TCP_OPTION_TS_LEN;
    tsopt->val = ee32(0x00000010U);   /* Newer than 0xFFFFFFF0 modulo 2^32 */
    tsopt->ecr = ee32(500);
    tsopt->pad = TCP_OPTION_NOP;
    tsopt->eoo = TCP_OPTION_NOP;

    memcpy(seg->data + TCP_OPTIONS_LEN, payload, sizeof(payload));
    fix_tcp_checksums(seg);

    tcp_input(&s, TEST_PRIMARY_IF, seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + tcp_hlen + sizeof(payload)));

    (void)wolfIP_poll(&s, 200);

    ck_assert_uint_eq(ts->sock.tcp.ack, original_ack + (uint32_t)sizeof(payload));
    ck_assert_uint_eq(queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out)),
                      (uint32_t)sizeof(payload));
    ck_assert_mem_eq(out, payload, sizeof(payload));
    ck_assert_uint_eq(ee32(ts->sock.tcp.last_ts), 0x00000010U);
}
END_TEST


/* RFC 2131 s4.4.1: if the client receives a DHCPNAK, it must restart
 * the configuration process.  The current code silently ignores NAKs
 * during RENEWING/REBINDING because dhcp_parse_ack returns -1 and
 * dhcp_poll treats that as a no-op. */
START_TEST(test_regression_dhcp_nak_restarts_configuration)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct tsocket *ts;
    struct ipconf *primary;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000064U, 0xFFFFFF00U, 0);

    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dhcp_udp_sd)];

    /* Simulate a RENEWING client that receives a DHCPNAK */
    s.dhcp_state = DHCP_RENEWING;
    s.dhcp_xid = 0x12345678U;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    /* Build a minimal DHCPNAK message (type 6) */
    memset(&msg, 0, sizeof(msg));
    msg.op = 2; /* BOOT_REPLY */
    msg.magic = ee32(DHCP_MAGIC);
    msg.xid = ee32(0x12345678U);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = 6; /* DHCPNAK */
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_END;

    enqueue_udp_rx(ts, &msg, sizeof(msg), DHCP_SERVER_PORT);
    (void)dhcp_poll(&s);

    /* After receiving NAK, the client must not remain in RENEWING.
     * It should restart discovery (transition to DHCP_OFF or
     * DHCP_DISCOVER_SENT). */
    ck_assert_int_ne(s.dhcp_state, DHCP_RENEWING);
    ck_assert_int_ne(s.dhcp_state, DHCP_BOUND);
}
END_TEST

/* RFC 2131 s2: server-to-client DHCP messages use BOOT_REPLY.
 * A reflected or malformed BOOT_REQUEST must not be treated as a DHCPNAK. */
START_TEST(test_regression_dhcp_boot_request_nak_ignored)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct tsocket *ts;
    struct ipconf *primary;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000064U, 0xFFFFFF00U, 0);

    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dhcp_udp_sd)];

    s.dhcp_state = DHCP_RENEWING;
    s.dhcp_xid = 0x12345678U;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REQUEST;
    msg.magic = ee32(DHCP_MAGIC);
    msg.xid = ee32(0x12345678U);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_NAK;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_END;

    enqueue_udp_rx(ts, &msg, sizeof(msg), DHCP_SERVER_PORT);
    (void)dhcp_poll(&s);

    ck_assert_int_eq(s.dhcp_state, DHCP_RENEWING);
    ck_assert_uint_eq(primary->ip, 0x0A000064U);
}
END_TEST

/* DNS response parser does not check the RCODE field.  An error response
 * such as NXDOMAIN (RCODE=3) passes the QR+RD check, the empty answer
 * section is silently skipped, and the query stays active until the
 * retry timer fires.  RFC 1035 s4.1.1: RCODE != 0 is an error. */
START_TEST(test_regression_dns_rcode_error_aborts_query)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t response[64];
    struct dns_header *hdr = (struct dns_header *)response;
    struct dns_question *q;
    int pos;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x08080808U;

    /* Set up an active DNS query */
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)];
    s.dns_id = 0xABCD;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_lookup_cb = test_dns_lookup_cb;

    /* Build a DNS response with RCODE=3 (NXDOMAIN).
     * flags = 0x8183: QR=1, RD=1, RA=1, RCODE=3
     * ancount=0 (no answers, as expected for NXDOMAIN). */
    memset(response, 0, sizeof(response));
    hdr->id = ee16(0xABCD);
    hdr->flags = ee16(0x8183);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(0);
    pos = sizeof(struct dns_header);
    response[pos++] = 3; memcpy(&response[pos], "foo", 3); pos += 3;
    response[pos++] = 3; memcpy(&response[pos], "com", 3); pos += 3;
    response[pos++] = 0;
    q = (struct dns_question *)(response + pos);
    q->qtype = ee16(DNS_A);
    q->qclass = ee16(1);
    pos += sizeof(struct dns_question);

    enqueue_udp_rx(ts, response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);

    /* The query must be aborted after receiving an authoritative error,
     * not left active for the retry timer to fire. */
    ck_assert_uint_eq(s.dns_id, 0);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
}
END_TEST


/* RFC 768: if the computed UDP checksum is zero, it must be transmitted
 * as 0xFFFF.  A zero checksum means "no checksum computed" and the
 * receiver would skip verification.  The current code stores the raw
 * transport_checksum result without zero-substitution. */
START_TEST(test_regression_udp_checksum_zero_substituted_with_ffff)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_udp_datagram udp;

    /* Craft a UDP datagram whose pseudo-header + data sums to 0xFFFF
     * in one's complement, causing transport_checksum to return 0.
     *
     * Pseudo-header: src=0, dst=0, proto=0x11, len=8
     *   sum = 0x0011 + 0x0008 = 0x0019
     * UDP header: src_port=0xFFDE, dst_port=0, udp_len=8, csum=0
     *   sum += 0xFFDE + 0 + 0x0008 = 0xFFE6
     * Total = 0x0019 + 0xFFE6 = 0xFFFF -> ~0xFFFF = 0 */

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0, 0, 0);

    /* Set up a UDP socket so ip_output_add_header can be called */
    ts = &s.udpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_UDP;
    ts->S = &s;
    ts->local_ip = 0;
    ts->remote_ip = 0;
    ts->if_idx = TEST_PRIMARY_IF;

    memset(&udp, 0, sizeof(udp));
    udp.src_port = ee16(0xFFDE);
    udp.dst_port = 0;
    udp.len = ee16(8);
    udp.csum = 0;

    ip_output_add_header(ts, (struct wolfIP_ip_packet *)&udp,
                         WI_IPPROTO_UDP, IP_HEADER_LEN + 8);

    /* The stored checksum must be 0xFFFF, not 0. */
    ck_assert_uint_ne(udp.csum, 0);
    ck_assert_uint_eq(ee16(udp.csum), 0xFFFF);
}
END_TEST


/* RFC 9293 s3.10.7.2: segment acceptability applies to all synchronized
 * states including LAST_ACK.  The current LAST_ACK handler processes ACKs
 * without checking tcp_segment_acceptable, so an out-of-window ACK could
 * close the connection. */
START_TEST(test_regression_last_ack_rejects_out_of_window_segment)
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
    ts->if_idx = TEST_PRIMARY_IF;
    ts->sock.tcp.state = TCP_LAST_ACK;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.seq = 1000;
    ts->sock.tcp.snd_una = 1000;
    ts->sock.tcp.last = 999; /* FIN was at seq 999 */
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.peer_rwnd = TCP_MSS;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* Send an ACK with an out-of-window sequence number.
     * rcv_nxt = 100, window = RXBUF_SIZE (20480), so seq = 99999
     * is far outside the window. */
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
    seg.seq = ee32(99999);
    seg.ack = ee32(1001); /* ACKs the FIN */
    seg.win = ee16(65535);
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    /* The out-of-window segment must be rejected; connection must
     * remain in LAST_ACK, not transition to CLOSED. */
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LAST_ACK);
}
END_TEST

/* dns_id is assigned from wolfIP_getrandom() which can truncate to 0.
 * Zero is the sentinel for "no query active," so a zero dns_id breaks
 * the re-entry guard, disables retransmission, and puts a predictable
 * transaction ID on the wire. */
START_TEST(test_regression_dns_id_never_zero)
{
    struct wolfIP s;
    uint16_t id = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x08080808U;

    /* Force wolfIP_getrandom to return 0 */
    test_rand_override_enabled = 1;
    test_rand_override_value = 0;

    ck_assert_int_eq(dns_send_query(&s, "example.com", &id, DNS_A), 0);

    /* dns_id must never be zero even when the RNG returns zero */
    ck_assert_uint_ne(s.dns_id, 0);
    ck_assert_uint_ne(id, 0);

    test_rand_override_enabled = 0;
}
END_TEST


/* ----------------------------------------------------------------------- */

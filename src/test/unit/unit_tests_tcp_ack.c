START_TEST(test_dns_abort_query_null_noop)
{
    dns_abort_query(NULL);
}
END_TEST


START_TEST(test_tcp_input_ttl_zero_local_ack_still_processes)
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
    last_frame_sent_size = 0;

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 5678;
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
    ackseg.ip.ttl = 0;
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

    ck_assert_uint_eq(last_frame_sent_size, 0U);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, 101U);
    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, 0U);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.tcp.txbuf), NULL);
}
END_TEST

START_TEST(test_tcp_rst_closes_socket)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000C1U;
    uint16_t local_port = 2222;
    uint16_t remote_port = 3333;

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
    ts->src_port = local_port;
    ts->dst_port = remote_port;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            ts->sock.tcp.ack, 0, TCP_FLAG_RST);
    ck_assert_int_eq(ts->proto, 0);
}
END_TEST

START_TEST(test_tcp_rst_ignored_in_listen)
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
    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A0000A1U, 0x0A000001U, 40000, 1234, 1, 0, TCP_FLAG_RST);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
    ck_assert_int_eq(ts->proto, WI_IPPROTO_TCP);
}
END_TEST

START_TEST(test_tcp_rst_syn_rcvd_returns_to_listen)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000A1U;
    uint16_t local_port = 1234;
    uint16_t remote_port = 40000;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, local_ip, local_port);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);

    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port, ts->sock.tcp.ack, 0, TCP_FLAG_RST);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
    ck_assert_uint_eq(ts->remote_ip, IPADDR_ANY);
    ck_assert_uint_eq(ts->dst_port, 0);
}
END_TEST

START_TEST(test_tcp_input_fin_wait_2_fin_sets_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    uint32_t seq = 111;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_2;
    ts->src_port = 1234;
    ts->dst_port = 2222;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->sock.tcp.ack = seq;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);

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
    seg.flags = TCP_FLAG_FIN | TCP_FLAG_ACK;
    seg.seq = ee32(seq);
    fix_tcp_checksums(&seg);

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_TIME_WAIT);
    ck_assert_uint_eq(ts->sock.tcp.ack, seq + 1);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, CB_EVENT_CLOSED);
}
END_TEST

START_TEST(test_tcp_input_fin_wait_2_fin_out_of_order_no_transition)
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
    ts->sock.tcp.state = TCP_FIN_WAIT_2;
    ts->sock.tcp.ack = ack;
    ts->src_port = 1234;
    ts->dst_port = 2222;
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

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_2);
    ck_assert_uint_eq(ts->sock.tcp.ack, ack);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, 0);
}
END_TEST

START_TEST(test_tcp_input_fin_wait_2_ack_with_payload_receives)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    uint8_t out = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->sock.tcp.state = TCP_FIN_WAIT_2;
    ts->sock.tcp.ack = 50;
    ts->src_port = 1234;
    ts->dst_port = 2222;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    memset(buf, 0, sizeof(buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.ttl = 64;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->ip.src = ee32(ts->remote_ip);
    seg->ip.dst = ee32(ts->local_ip);
    seg->dst_port = ee16(ts->src_port);
    seg->src_port = ee16(ts->dst_port);
    seg->seq = ee32(50);
    seg->ack = ee32(10);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = TCP_FLAG_ACK;
    seg->data[0] = TCP_OPTION_EOO;
    fix_tcp_checksums(seg);

    tcp_input(&s, TEST_PRIMARY_IF, seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 1));
    ck_assert_uint_eq(ts->sock.tcp.ack, 51);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, CB_EVENT_READABLE);
    ck_assert_int_eq(queue_pop(&ts->sock.tcp.rxbuf, &out, sizeof(out)), 1);
    ck_assert_uint_eq(out, TCP_OPTION_EOO);
}
END_TEST

START_TEST(test_dns_callback_bad_rr_rdlen)
{
    struct wolfIP s;
    uint8_t response[128];
    int pos;
    struct dns_header *hdr = (struct dns_header *)response;
    struct dns_question *q;
    struct dns_rr *rr;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_id = 0x1234;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    memset(response, 0, sizeof(response));
    hdr->id = ee16(s.dns_id);
    hdr->flags = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(1);
    pos = sizeof(struct dns_header);
    response[pos++] = 1; response[pos++] = 'a';
    response[pos++] = 0;
    q = (struct dns_question *)(response + pos);
    q->qtype = ee16(DNS_A);
    q->qclass = ee16(1);
    pos += sizeof(struct dns_question);
    response[pos++] = 0xC0;
    response[pos++] = (uint8_t)sizeof(struct dns_header);
    rr = (struct dns_rr *)(response + pos);
    rr->type = ee16(DNS_A);
    rr->class = ee16(1);
    rr->ttl = ee32(60);
    rr->rdlength = ee16(64);
    pos += sizeof(struct dns_rr);

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)], response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_uint_eq(s.dns_id, 0);
}
END_TEST

START_TEST(test_dhcp_parse_offer_no_match)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_REQUEST;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_invalid)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_offer_short_len_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_OFFER;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, DHCP_HEADER_LEN - 1), -1);
}
END_TEST

START_TEST(test_dhcp_parse_offer_truncated_option_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 4;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, DHCP_HEADER_LEN + 2), -1);
}
END_TEST

START_TEST(test_dhcp_parse_offer_len_lt_four_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_OFFER;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_SERVER_ID;
    opt->len = 2;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, DHCP_HEADER_LEN + 5), -1);
}
END_TEST

START_TEST(test_dhcp_parse_offer_ignores_short_unknown_option)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct ipconf *primary;
    uint32_t offer_ip = 0x0A000064U;
    uint32_t server_ip = 0x0A000001U;

    wolfIP_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.yiaddr = ee32(offer_ip);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_OFFER;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = 61; /* Client identifier (unused by parser) */
    opt->len = 1;
    opt->data[0] = 0x01;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_SERVER_ID;
    opt->len = 4;
    opt->data[0] = (server_ip >> 24) & 0xFF;
    opt->data[1] = (server_ip >> 16) & 0xFF;
    opt->data[2] = (server_ip >> 8) & 0xFF;
    opt->data[3] = (server_ip >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, DHCP_HEADER_LEN + 14), 0);
    ck_assert_uint_eq(s.dhcp_ip, offer_ip);
    ck_assert_uint_eq(s.dhcp_server_ip, server_ip);
    ck_assert_int_eq(s.dhcp_state, DHCP_REQUEST_SENT);
}
END_TEST

START_TEST(test_dhcp_parse_offer_ignores_zero_len_unknown_option)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct ipconf *primary;
    uint32_t offer_ip = 0x0A000064U;
    uint32_t server_ip = 0x0A000001U;

    wolfIP_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.yiaddr = ee32(offer_ip);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_OFFER;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = 61; /* Client identifier (unused by parser) */
    opt->len = 0;
    opt = (struct dhcp_option *)((uint8_t *)opt + 2);
    opt->code = DHCP_OPTION_SERVER_ID;
    opt->len = 4;
    opt->data[0] = (server_ip >> 24) & 0xFF;
    opt->data[1] = (server_ip >> 16) & 0xFF;
    opt->data[2] = (server_ip >> 8) & 0xFF;
    opt->data[3] = (server_ip >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, DHCP_HEADER_LEN + 13), 0);
    ck_assert_uint_eq(s.dhcp_ip, offer_ip);
    ck_assert_uint_eq(s.dhcp_server_ip, server_ip);
    ck_assert_int_eq(s.dhcp_state, DHCP_REQUEST_SENT);
}
END_TEST

START_TEST(test_dhcp_parse_offer_missing_server_id_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct ipconf *primary;
    uint32_t offer_ip = 0x0A000064U;

    wolfIP_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    s.dhcp_server_ip = 0x0A000001U;

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.yiaddr = ee32(offer_ip);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_OFFER;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, DHCP_HEADER_LEN + 4), -1);
    ck_assert_uint_eq(s.dhcp_server_ip, 0x0A000001U);
    ck_assert_uint_eq(s.dhcp_ip, 0U);
    ck_assert_int_ne(s.dhcp_state, DHCP_REQUEST_SENT);
}
END_TEST

START_TEST(test_dhcp_parse_offer_missing_end_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_OFFER;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, DHCP_HEADER_LEN + 3), -1);
}
END_TEST

START_TEST(test_dhcp_parse_offer_msg_type_len_ne_1_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 2;
    opt->data[0] = DHCP_OFFER;
    opt->data[1] = 0;
    opt = (struct dhcp_option *)((uint8_t *)opt + 4);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, DHCP_HEADER_LEN + 5), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_truncated_option_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, DHCP_HEADER_LEN + 2), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_msg_type_len_ne_1_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 2;
    opt->data[0] = DHCP_ACK;
    opt->data[1] = 0;
    opt = (struct dhcp_option *)((uint8_t *)opt + 4);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, DHCP_HEADER_LEN + 5), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_len_lt_four_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_SUBNET_MASK;
    opt->len = 2;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, DHCP_HEADER_LEN + 5), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_ignores_short_unknown_option)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct ipconf *primary;
    uint32_t offer_ip = 0x0A000064U;
    uint32_t server_ip = 0x0A000001U;
    uint32_t mask = 0xFFFFFF00U;

    wolfIP_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = 61; /* Client identifier (unused by parser) */
    opt->len = 1;
    opt->data[0] = 0x01;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_SERVER_ID;
    opt->len = 4;
    opt->data[0] = (server_ip >> 24) & 0xFF;
    opt->data[1] = (server_ip >> 16) & 0xFF;
    opt->data[2] = (server_ip >> 8) & 0xFF;
    opt->data[3] = (server_ip >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_SUBNET_MASK;
    opt->len = 4;
    opt->data[0] = (mask >> 24) & 0xFF;
    opt->data[1] = (mask >> 16) & 0xFF;
    opt->data[2] = (mask >> 8) & 0xFF;
    opt->data[3] = (mask >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_OFFER_IP;
    opt->len = 4;
    opt->data[0] = (offer_ip >> 24) & 0xFF;
    opt->data[1] = (offer_ip >> 16) & 0xFF;
    opt->data[2] = (offer_ip >> 8) & 0xFF;
    opt->data[3] = (offer_ip >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, DHCP_HEADER_LEN + 26), 0);
    ck_assert_uint_eq(primary->ip, offer_ip);
    ck_assert_uint_eq(primary->mask, mask);
    ck_assert_uint_eq(s.dhcp_server_ip, server_ip);
}
END_TEST

START_TEST(test_dhcp_parse_ack_ignores_zero_len_unknown_option)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct ipconf *primary;
    uint32_t offer_ip = 0x0A000064U;
    uint32_t server_ip = 0x0A000001U;
    uint32_t mask = 0xFFFFFF00U;

    wolfIP_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = 61; /* Client identifier (unused by parser) */
    opt->len = 0;
    opt = (struct dhcp_option *)((uint8_t *)opt + 2);
    opt->code = DHCP_OPTION_SERVER_ID;
    opt->len = 4;
    opt->data[0] = (server_ip >> 24) & 0xFF;
    opt->data[1] = (server_ip >> 16) & 0xFF;
    opt->data[2] = (server_ip >> 8) & 0xFF;
    opt->data[3] = (server_ip >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_SUBNET_MASK;
    opt->len = 4;
    opt->data[0] = (mask >> 24) & 0xFF;
    opt->data[1] = (mask >> 16) & 0xFF;
    opt->data[2] = (mask >> 8) & 0xFF;
    opt->data[3] = (mask >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_OFFER_IP;
    opt->len = 4;
    opt->data[0] = (offer_ip >> 24) & 0xFF;
    opt->data[1] = (offer_ip >> 16) & 0xFF;
    opt->data[2] = (offer_ip >> 8) & 0xFF;
    opt->data[3] = (offer_ip >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, DHCP_HEADER_LEN + 25), 0);
    ck_assert_uint_eq(primary->ip, offer_ip);
    ck_assert_uint_eq(primary->mask, mask);
    ck_assert_uint_eq(s.dhcp_server_ip, server_ip);
}
END_TEST

START_TEST(test_dhcp_parse_ack_missing_server_id_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct ipconf *primary;
    uint32_t offer_ip = 0x0A000064U;
    uint32_t mask = 0xFFFFFF00U;

    wolfIP_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    s.dhcp_server_ip = 0x0A000001U;

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_SUBNET_MASK;
    opt->len = 4;
    opt->data[0] = (mask >> 24) & 0xFF;
    opt->data[1] = (mask >> 16) & 0xFF;
    opt->data[2] = (mask >> 8) & 0xFF;
    opt->data[3] = (mask >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_OFFER_IP;
    opt->len = 4;
    opt->data[0] = (offer_ip >> 24) & 0xFF;
    opt->data[1] = (offer_ip >> 16) & 0xFF;
    opt->data[2] = (offer_ip >> 8) & 0xFF;
    opt->data[3] = (offer_ip >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, DHCP_HEADER_LEN + 16), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_missing_end_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, DHCP_HEADER_LEN + 3), -1);
}
END_TEST

START_TEST(test_dhcp_parse_offer_rejects_mismatched_xid)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct ipconf *primary;

    wolfIP_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    s.dhcp_xid = 0x12345678U;

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.xid = ee32(0x87654321U);
    msg.yiaddr = ee32(0x0A000064U);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_OFFER;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, sizeof(msg)), -1);
    ck_assert_uint_eq(s.dhcp_ip, 0U);
    ck_assert_uint_eq(primary->ip, 0U);
    ck_assert_int_eq(s.dhcp_state, DHCP_OFF);
}
END_TEST

START_TEST(test_dhcp_parse_ack_rejects_mismatched_xid)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct ipconf *primary;

    wolfIP_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    s.dhcp_xid = 0x12345678U;
    s.dhcp_ip = 0x0A000064U;
    s.dhcp_server_ip = 0x0A000001U;
    s.dhcp_state = DHCP_REQUEST_SENT;

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.xid = ee32(0x87654321U);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
    ck_assert_int_eq(s.dhcp_state, DHCP_REQUEST_SENT);
    ck_assert_uint_eq(primary->ip, 0U);
}
END_TEST

START_TEST(test_dhcp_parse_offer_rejects_boot_request_op)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct ipconf *primary;

    wolfIP_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REQUEST;
    msg.magic = ee32(DHCP_MAGIC);
    msg.yiaddr = ee32(0x0A000064U);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_OFFER;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, sizeof(msg)), -1);
    ck_assert_uint_eq(s.dhcp_ip, 0U);
    ck_assert_uint_eq(primary->ip, 0U);
    ck_assert_int_eq(s.dhcp_state, DHCP_OFF);
}
END_TEST

START_TEST(test_dhcp_parse_ack_rejects_boot_request_op)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;

    wolfIP_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    s.dhcp_ip = 0x0A000064U;
    s.dhcp_server_ip = 0x0A000001U;
    s.dhcp_state = DHCP_REQUEST_SENT;

    build_dhcp_ack_msg(&msg, 0x0A000001U, 0xFFFFFF00U, 0x0A000002U, 0x08080808U);
    msg.op = BOOT_REQUEST;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
    ck_assert_int_eq(s.dhcp_state, DHCP_REQUEST_SENT);
    ck_assert_uint_eq(primary->ip, 0U);
}
END_TEST

START_TEST(test_dhcp_parse_offer_bad_magic_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = 0;
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_OFFER;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_bad_magic_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = 0;
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_offer_zero_len_option_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_OFFER;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_SERVER_ID;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, DHCP_HEADER_LEN + 5), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_zero_len_option_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_SUBNET_MASK;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, DHCP_HEADER_LEN + 5), -1);
}
END_TEST

START_TEST(test_dhcp_poll_no_data_and_wrong_state)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);

    s.dhcp_state = DHCP_OFF;
    ck_assert_int_eq(dhcp_poll(&s), -1);
}
END_TEST
START_TEST(test_tcp_fin_wait_1_to_closing)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000D1U;
    uint16_t local_port = 4444;
    uint16_t remote_port = 5555;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ts->sock.tcp.ack = 9;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port = local_port;
    ts->dst_port = remote_port;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);

    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            9, 0, TCP_FLAG_FIN | TCP_FLAG_ACK);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSING);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, CB_EVENT_CLOSED);
}
END_TEST

START_TEST(test_dhcp_callback_null_and_off_state)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);

    dhcp_callback(0, 0, NULL);

    s.dhcp_state = DHCP_OFF;
    s.dhcp_udp_sd = 0;
    dhcp_callback(0, 0, &s);
    ck_assert_int_eq(s.dhcp_state, DHCP_OFF);
}
END_TEST

#if WOLFIP_ENABLE_FORWARDING
START_TEST(test_forward_prepare_paths)
{
    struct wolfIP s;
    uint8_t mac[6] = {0};
    int broadcast = 0;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    ret = wolfIP_forward_prepare(&s, TEST_LOOPBACK_IF, 0x0A000002U, mac, &broadcast);
    ck_assert_int_eq(ret, 1);
    ck_assert_int_eq(broadcast, 0);

    ret = wolfIP_forward_prepare(&s, TEST_PRIMARY_IF, 0xFFFFFFFFU, mac, &broadcast);
    ck_assert_int_eq(ret, 1);
    ck_assert_int_eq(broadcast, 1);

    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    ret = wolfIP_forward_prepare(&s, TEST_PRIMARY_IF, 0x0A0000FFU, mac, &broadcast);
    ck_assert_int_eq(ret, 1);
    ck_assert_int_eq(broadcast, 1);

    last_frame_sent_size = 0;
    s.last_tick = 2000;
    ret = wolfIP_forward_prepare(&s, TEST_PRIMARY_IF, 0x0A000002U, mac, &broadcast);
    ck_assert_int_eq(ret, 0);
    ck_assert_uint_gt(last_frame_sent_size, 0);

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);
    ret = wolfIP_forward_prepare(&s, TEST_PRIMARY_IF, 0x0A000002U, mac, &broadcast);
    ck_assert_int_eq(ret, 1);
    ck_assert_int_eq(broadcast, 0);
    ck_assert_mem_eq(mac, "\x01\x02\x03\x04\x05\x06", 6);
}
END_TEST

START_TEST(test_forward_prepare_null_args)
{
    struct wolfIP s;
    uint8_t mac[6];
    int broadcast = 0;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    ret = wolfIP_forward_prepare(&s, TEST_PRIMARY_IF, 0x0A000002U, NULL, &broadcast);
    ck_assert_int_eq(ret, 0);
    ret = wolfIP_forward_prepare(&s, TEST_PRIMARY_IF, 0x0A000002U, mac, NULL);
    ck_assert_int_eq(ret, 0);
    ret = wolfIP_forward_prepare(&s, TEST_PRIMARY_IF, 0x0A000002U, NULL, NULL);
    ck_assert_int_eq(ret, 0);
}
END_TEST

START_TEST(test_forward_prepare_loopback_no_ll)
{
    struct wolfIP s;
    uint8_t mac[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    int broadcast = 1;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;

    ck_assert_int_eq(wolfIP_forward_prepare(&s, TEST_LOOPBACK_IF, 0x0A000002U, mac, &broadcast), 1);
    ck_assert_int_eq(broadcast, 0);
    ck_assert_mem_eq(mac, "\xaa\xbb\xcc\xdd\xee\xff", 6);
}
END_TEST

START_TEST(test_forward_packet_invalid_if)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN];
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)buf;
    struct wolfIP_ip_packet *ip = &tcp->ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    last_frame_sent_size = 0;

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_TCP;
    ip->len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);

    wolfIP_forward_packet(&s, s.if_count + 1, ip, (uint32_t)sizeof(buf), NULL, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_select_nexthop_variants)
{
    struct ipconf conf;
    ip4 dest = 0x0A0000A1U;

    memset(&conf, 0, sizeof(conf));
    ck_assert_uint_eq(wolfIP_select_nexthop(NULL, dest), dest);
    ck_assert_uint_eq(wolfIP_select_nexthop(&conf, 0xFFFFFFFFU), 0xFFFFFFFFU);

    conf.ip = 0x0A000001U;
    conf.mask = 0xFFFFFF00U;
    conf.gw = 0x0A0000FEU;
    ck_assert_uint_eq(wolfIP_select_nexthop(&conf, 0x0A000099U), 0x0A000099U);
    ck_assert_uint_eq(wolfIP_select_nexthop(&conf, 0x0A010101U), conf.gw);

    conf.gw = IPADDR_ANY;
    ck_assert_uint_eq(wolfIP_select_nexthop(&conf, 0x0A010101U), 0x0A010101U);
}
END_TEST

START_TEST(test_route_for_ip_variants)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    s.ipconf[TEST_PRIMARY_IF].gw = 0x0A0000FEU;
    s.ipconf[TEST_SECOND_IF].gw = 0;

    ck_assert_uint_eq(wolfIP_route_for_ip(&s, IPADDR_ANY), TEST_PRIMARY_IF);
    ck_assert_uint_eq(wolfIP_route_for_ip(&s, 0xFFFFFFFFU), TEST_PRIMARY_IF);
    ck_assert_uint_eq(wolfIP_route_for_ip(&s, 0x0A000055U), TEST_PRIMARY_IF);
    ck_assert_uint_eq(wolfIP_route_for_ip(&s, 0xC0A80122U), TEST_SECOND_IF);
    ck_assert_uint_eq(wolfIP_route_for_ip(&s, 0x0B000001U), TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_route_for_ip_dest_matches_iface_ip)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);

    ck_assert_uint_eq(wolfIP_route_for_ip(&s, primary_ip), TEST_PRIMARY_IF);
    ck_assert_uint_eq(wolfIP_route_for_ip(&s, secondary_ip), TEST_SECOND_IF);
}
END_TEST

START_TEST(test_route_for_ip_matches_exact_ip_when_mask_is_zero)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    s.ipconf[TEST_SECOND_IF].mask = 0U;

    ck_assert_uint_eq(wolfIP_route_for_ip(&s, secondary_ip), TEST_SECOND_IF);
}
END_TEST

START_TEST(test_route_for_ip_gw_and_nonloop_fallback)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    s.ipconf[TEST_PRIMARY_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_PRIMARY_IF].gw = 0;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    ck_assert_uint_eq(wolfIP_route_for_ip(&s, 0x0B000001U), TEST_SECOND_IF);

    s.ipconf[TEST_SECOND_IF].gw = IPADDR_ANY;
    ck_assert_uint_eq(wolfIP_route_for_ip(&s, 0x0B000001U), TEST_SECOND_IF);
}
END_TEST

START_TEST(test_route_for_ip_no_primary_index)
{
    struct wolfIP s;

    wolfIP_init(&s);
    s.if_count = 1;
    s.ipconf[0].ip = 0x0A000001U;
    s.ipconf[0].mask = 0xFFFFFF00U;

    ck_assert_uint_eq(wolfIP_route_for_ip(&s, 0x0A000055U), 0U);
}
END_TEST

START_TEST(test_route_for_ip_null_stack)
{
    ck_assert_uint_eq(wolfIP_route_for_ip(NULL, 0x0A000001U), 0U);
}
END_TEST

START_TEST(test_inline_ip_helpers)
{
    char buf[20];

    ck_assert_uint_eq(atou("1234"), 1234U);
    ck_assert_uint_eq(atou("12x"), 12U);
    ck_assert_uint_eq(atou(""), 0U);

    ck_assert_uint_eq(atoip4("10.0.1.2"), 0x0A000102U);
    ck_assert_uint_eq(atoip4("192.168"), 0xC0A80000U);

    iptoa(0x010C7B00U, buf);
    ck_assert_str_eq(buf, "1.12.123.0");
}
END_TEST

START_TEST(test_forward_interface_variants)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    unsigned int out_if;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    out_if = wolfIP_forward_interface(&s, TEST_PRIMARY_IF, 0xC0A80199U);
    ck_assert_uint_eq(out_if, TEST_SECOND_IF);

    out_if = wolfIP_forward_interface(&s, TEST_PRIMARY_IF, secondary_ip);
    ck_assert_int_eq((int)out_if, -1);

    s.if_count = 1;
    ck_assert_int_eq(wolfIP_forward_interface(&s, TEST_PRIMARY_IF, 0x0A000099U), -1);
}
END_TEST

START_TEST(test_forward_interface_skips_ipaddr_any)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].mask = 0xFFFFFF00U;

    ck_assert_int_eq((int)wolfIP_forward_interface(&s, TEST_PRIMARY_IF, 0xC0A80199U), -1);
}
END_TEST

START_TEST(test_forward_interface_dest_is_local_ip)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    unsigned int out_if;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    out_if = wolfIP_forward_interface(&s, TEST_PRIMARY_IF, secondary_ip);
    ck_assert_int_eq((int)out_if, -1);
}
END_TEST

START_TEST(test_forward_interface_short_circuit_cases)
{
    struct wolfIP s;

    ck_assert_int_eq(wolfIP_forward_interface(NULL, 0, 0x0A000001U), -1);

    wolfIP_init(&s);
    s.if_count = 1;
    ck_assert_int_eq(wolfIP_forward_interface(&s, 0, 0x0A000001U), -1);
}
END_TEST

START_TEST(test_ip_recv_forward_ttl_exceeded)
{
    struct wolfIP s;
    uint8_t ip_buf[ETH_HEADER_LEN + TTL_EXCEEDED_ORIG_PACKET_SIZE_DEFAULT];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)ip_buf;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(ip_buf, 0, sizeof(ip_buf));
    ip->eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->ver_ihl = 0x45;
    ip->ttl = 1;
    ip->proto = WI_IPPROTO_UDP;
    ip->len = ee16(IP_HEADER_LEN + 8);
    ip->src = ee32(primary_ip);
    ip->dst = ee32(0xC0A80155U);
    fix_ip_checksum(ip);

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + 8));
    ck_assert_uint_gt(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_ip_recv_udp_with_ip_options_delivers_payload)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + 4 + UDP_HEADER_LEN + 4];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    uint8_t *udp_hdr = frame + ETH_HEADER_LEN + IP_HEADER_LEN + 4;
    uint16_t udp_len = UDP_HEADER_LEN + 4;
    uint32_t local_ip = 0x0A000001U;
    uint32_t remote_ip = 0x0A000002U;

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
    ip->ver_ihl = 0x46;
    ip->ttl = 64;
    ip->proto = WI_IPPROTO_UDP;
    ip->len = ee16(IP_HEADER_LEN + 4 + udp_len);
    ip->src = ee32(remote_ip);
    ip->dst = ee32(local_ip);
    ip->data[0] = 1;
    ip->data[1] = 1;
    ip->data[2] = 1;
    ip->data[3] = 0;

    ((uint16_t *)udp_hdr)[0] = ee16(4321);
    ((uint16_t *)udp_hdr)[1] = ee16(1234);
    ((uint16_t *)udp_hdr)[2] = ee16(udp_len);
    memcpy(udp_hdr + UDP_HEADER_LEN, "opt!", 4);

    fix_udp_checksum_raw(ip, udp_hdr, udp_len);
    fix_ip_checksum_with_hlen(ip, (uint16_t)(IP_HEADER_LEN + 4));

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.rxbuf));
    ck_assert_int_ne((ts->events & CB_EVENT_READABLE), 0);
}
END_TEST

START_TEST(test_ip_recv_fragmented_udp_dropped)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    uint8_t *udp_hdr = frame + ETH_HEADER_LEN + IP_HEADER_LEN;
    uint16_t udp_len = UDP_HEADER_LEN + 4;
    uint32_t local_ip = 0x0A000001U;
    uint32_t remote_ip = 0x0A000002U;

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
    ip->ver_ihl = 0x45;
    ip->ttl = 64;
    ip->proto = WI_IPPROTO_UDP;
    ip->len = ee16(IP_HEADER_LEN + udp_len);
    ip->flags_fo = ee16(0x2000U); /* MF=1, offset=0 */
    ip->src = ee32(remote_ip);
    ip->dst = ee32(local_ip);

    ((uint16_t *)udp_hdr)[0] = ee16(4321);
    ((uint16_t *)udp_hdr)[1] = ee16(1234);
    ((uint16_t *)udp_hdr)[2] = ee16(udp_len);
    memcpy(udp_hdr + UDP_HEADER_LEN, "frag", 4);

    fix_udp_checksum_raw(ip, udp_hdr, udp_len);
    fix_ip_checksum(ip);

    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(frame));

    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, 0);
}
END_TEST

START_TEST(test_ip_recv_forward_arp_queue_and_flush)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    struct arp_packet arp_reply;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip = 0xC0A80155U;
    uint8_t dest_mac[6] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15};

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    s.last_tick = 2000;
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    ip.eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.ver_ihl = 0x45;
    ip.ttl = 2;
    ip.proto = WI_IPPROTO_TCP;
    ip.len = ee16(IP_HEADER_LEN);
    ip.src = ee32(primary_ip);
    ip.dst = ee32(dest_ip);
    fix_ip_checksum(&ip);

    ip_recv(&s, TEST_PRIMARY_IF, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(s.arp_pending[0].dest, dest_ip);
    ck_assert_uint_eq(s.arp_pending[0].if_idx, TEST_SECOND_IF);
    ck_assert_uint_gt(s.arp_pending[0].len, 0);

    memset(&arp_reply, 0, sizeof(arp_reply));
    arp_reply.htype = ee16(1);
    arp_reply.ptype = ee16(0x0800);
    arp_reply.hlen = 6;
    arp_reply.plen = 4;
    arp_reply.opcode = ee16(ARP_REPLY);
    arp_reply.sip = ee32(dest_ip);
    memcpy(arp_reply.sma, dest_mac, 6);
    arp_recv(&s, TEST_SECOND_IF, &arp_reply, sizeof(arp_reply));
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_flush_pending_ttl_expired)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    struct arp_packet arp_reply;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip = 0xC0A80166U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    s.last_tick = 2000;
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    ip.ver_ihl = 0x45;
    ip.ttl = 1;
    ip.proto = WI_IPPROTO_TCP;
    ip.len = ee16(IP_HEADER_LEN);
    ip.src = ee32(primary_ip);
    ip.dst = ee32(dest_ip);

    arp_queue_packet(&s, TEST_SECOND_IF, dest_ip, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(s.arp_pending[0].dest, dest_ip);

    memset(&arp_reply, 0, sizeof(arp_reply));
    arp_reply.htype = ee16(1);
    arp_reply.ptype = ee16(0x0800);
    arp_reply.hlen = 6;
    arp_reply.plen = 4;
    arp_reply.opcode = ee16(ARP_REPLY);
    arp_reply.sip = ee32(dest_ip);
    memcpy(arp_reply.sma, "\x01\x02\x03\x04\x05\x06", 6);
    arp_recv(&s, TEST_SECOND_IF, &arp_reply, sizeof(arp_reply));
    ck_assert_uint_eq(last_frame_sent_size, 0);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_queue_packet_invalid_args)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    s.arp_pending[0].dest = 0x0A000002U;
    arp_queue_packet(NULL, TEST_PRIMARY_IF, 0x0A000002U, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(s.arp_pending[0].dest, 0x0A000002U);

    arp_queue_packet(&s, TEST_PRIMARY_IF, 0x0A000003U, &ip, 0);
    ck_assert_uint_eq(s.arp_pending[0].dest, 0x0A000002U);
}
END_TEST

START_TEST(test_arp_queue_packet_reuses_existing_slot)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    const ip4 dest_ip = 0x0A0000A1U;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    s.arp_pending[0].dest = dest_ip;
    s.arp_pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp_pending[0].len = 4;

    arp_queue_packet(&s, TEST_PRIMARY_IF, dest_ip, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(s.arp_pending[0].dest, dest_ip);
    ck_assert_uint_eq(s.arp_pending[0].if_idx, TEST_PRIMARY_IF);
    ck_assert_uint_gt(s.arp_pending[0].len, 0U);
}
END_TEST

START_TEST(test_arp_queue_packet_same_dest_different_if)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    const ip4 dest_ip = 0x0A0000A1U;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    s.arp_pending[0].dest = dest_ip;
    s.arp_pending[0].if_idx = TEST_SECOND_IF;

    arp_queue_packet(&s, TEST_PRIMARY_IF, dest_ip, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(s.arp_pending[1].dest, dest_ip);
    ck_assert_uint_eq(s.arp_pending[1].if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_arp_queue_packet_uses_empty_slot)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    const ip4 dest_ip = 0x0A0000A2U;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    s.arp_pending[0].dest = 0x0A0000B1U;
    s.arp_pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp_pending[1].dest = IPADDR_ANY;

    arp_queue_packet(&s, TEST_PRIMARY_IF, dest_ip, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(s.arp_pending[1].dest, dest_ip);
}
END_TEST

START_TEST(test_arp_queue_packet_drops_oversize_len)
{
    struct wolfIP s;
    uint8_t ip_buf[LINK_MTU];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)ip_buf;
    uint32_t len = LINK_MTU + 16;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(ip_buf, 0, sizeof(ip_buf));

    arp_queue_packet(&s, TEST_PRIMARY_IF, 0x0A0000A3U, ip, len);
    ck_assert_uint_eq(s.arp_pending[0].len, 0U);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_queue_packet_slot_fallback_zero)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++) {
        s.arp_pending[i].dest = (ip4)(0x0A000100U + (uint32_t)i);
        s.arp_pending[i].if_idx = TEST_PRIMARY_IF;
        s.arp_pending[i].len = 1;
    }

    arp_queue_packet(&s, TEST_PRIMARY_IF, 0x0A0000C1U, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(s.arp_pending[0].dest, 0x0A0000C1U);
}
END_TEST

START_TEST(test_arp_flush_pending_no_neighbor)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    s.arp_pending[0].dest = 0x0A0000A1U;
    s.arp_pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp_pending[0].len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN);
    memcpy(s.arp_pending[0].frame, &ip, sizeof(ip));

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp_pending[0].dest, 0x0A0000A1U);
}
END_TEST

START_TEST(test_arp_flush_pending_len_zero_clears)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    s.arp_pending[0].dest = 0x0A0000A1U;
    s.arp_pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp_pending[0].len = 0;

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_flush_pending_null_stack)
{
    arp_flush_pending(NULL, TEST_PRIMARY_IF, 0x0A0000A1U);
}
END_TEST

START_TEST(test_arp_flush_pending_skips_non_matching)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    s.arp_pending[0].dest = 0x0A0000A2U;
    s.arp_pending[0].if_idx = TEST_SECOND_IF;
    s.arp_pending[0].len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN);
    memcpy(s.arp_pending[0].frame, &ip, sizeof(ip));

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp_pending[0].dest, 0x0A0000A2U);
}
END_TEST

START_TEST(test_arp_flush_pending_same_dest_if_idx_mismatch)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));
    ip.ttl = 64;

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    s.arp_pending[0].dest = 0x0A0000A1U;
    s.arp_pending[0].if_idx = TEST_SECOND_IF;
    s.arp_pending[0].len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN);
    memcpy(s.arp_pending[0].frame, &ip, sizeof(ip));

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp_pending[0].dest, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp_pending[0].if_idx, TEST_SECOND_IF);
    ck_assert_uint_eq(s.arp_pending[0].len, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
}
END_TEST

START_TEST(test_arp_flush_pending_truncates_len)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));
    ip.ttl = 64;

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    s.arp_pending[0].dest = 0x0A0000A1U;
    s.arp_pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp_pending[0].len = LINK_MTU + 8;
    memcpy(s.arp_pending[0].frame, &ip, sizeof(ip));

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_flush_pending_processes_matching_entry)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));
    ip.ttl = 64;

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    s.arp_pending[0].dest = 0x0A0000A1U;
    s.arp_pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp_pending[0].len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN);
    memcpy(s.arp_pending[0].frame, &ip, sizeof(ip));
    last_frame_sent_size = 0;

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_flush_pending_match_condition_false)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));
    ip.ttl = 64;

    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++) {
        s.arp_pending[i].dest = IPADDR_ANY;
        s.arp_pending[i].if_idx = 0;
        s.arp_pending[i].len = 0;
    }

    s.arp.neighbors[0].ip = 0x0A0000A2U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    s.arp_pending[0].dest = 0x0A0000A2U;
    s.arp_pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp_pending[0].len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN);
    memcpy(s.arp_pending[0].frame, &ip, sizeof(ip));

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000A2U);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_queue_and_flush_matching_entry)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));
    ip.ttl = 64;

    arp_queue_packet(&s, TEST_PRIMARY_IF, 0x0A0000B1U, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));

    s.arp.neighbors[0].ip = 0x0A0000B1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000B1U);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_flush_pending_loopback_match)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);

    s.arp.neighbors[0].ip = 0x7F000001U;
    s.arp.neighbors[0].if_idx = TEST_LOOPBACK_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    s.arp_pending[0].dest = 0x7F000001U;
    s.arp_pending[0].if_idx = TEST_LOOPBACK_IF;
    s.arp_pending[0].len = 0;

    arp_flush_pending(&s, TEST_LOOPBACK_IF, 0x7F000001U);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_store_neighbor_updates_existing)
{
    struct wolfIP s;
    uint8_t old_mac[6] = {0, 1, 2, 3, 4, 5};
    uint8_t new_mac[6] = {6, 7, 8, 9, 10, 11};

    wolfIP_init(&s);
    mock_link_init(&s);

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, old_mac, 6);

    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A0000A1U, new_mac);
    ck_assert_mem_eq(s.arp.neighbors[0].mac, new_mac, 6);
}
END_TEST

START_TEST(test_arp_recv_reply_updates_existing_no_duplicate)
{
    struct wolfIP s;
    struct arp_packet pkt;
    uint8_t old_mac[6] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t new_mac[6] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
    ip4 ip = 0x0A0000A1U;
    int i;
    int count = 0;

    wolfIP_init(&s);
    mock_link_init(&s);

    s.arp.neighbors[0].ip = ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, old_mac, 6);
    s.arp.neighbors[0].ts = 10;

    s.arp.pending[0].ip = ip;
    s.arp.pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp.pending[0].ts = 50;

    s.last_tick = 100;

    memset(&pkt, 0, sizeof(pkt));
    pkt.htype = ee16(1);
    pkt.ptype = ee16(0x0800);
    pkt.hlen = 6;
    pkt.plen = 4;
    pkt.opcode = ee16(ARP_REPLY);
    pkt.sip = ee32(ip);
    memcpy(pkt.sma, new_mac, 6);

    arp_recv(&s, TEST_PRIMARY_IF, &pkt, (int)sizeof(pkt));

    for (i = 0; i < MAX_NEIGHBORS; i++) {
        if (s.arp.neighbors[i].ip == ip &&
            s.arp.neighbors[i].if_idx == TEST_PRIMARY_IF)
            count++;
    }
    ck_assert_int_eq(count, 1);
    ck_assert_mem_eq(s.arp.neighbors[0].mac, new_mac, 6);
    ck_assert_uint_eq(s.arp.neighbors[0].ts, s.last_tick);
}
END_TEST

START_TEST(test_arp_store_neighbor_empty_slot)
{
    struct wolfIP s;
    uint8_t mac[6] = {1, 2, 3, 4, 5, 6};

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(s.arp.neighbors, 0, sizeof(s.arp.neighbors));

    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A0000A1U, mac);
    ck_assert_uint_eq(s.arp.neighbors[0].ip, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp.neighbors[0].if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_arp_store_neighbor_same_ip_diff_if)
{
    struct wolfIP s;
    uint8_t mac0[6] = {1, 2, 3, 4, 5, 6};
    uint8_t mac1[6] = {6, 7, 8, 9, 10, 11};

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(s.arp.neighbors, 0, sizeof(s.arp.neighbors));

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_SECOND_IF;
    memcpy(s.arp.neighbors[0].mac, mac0, 6);

    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A0000A1U, mac1);
    ck_assert_mem_eq(s.arp.neighbors[0].mac, mac0, 6);
    ck_assert_uint_eq(s.arp.neighbors[1].ip, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp.neighbors[1].if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_arp_pending_record_prefers_empty_slot)
{
    struct wolfIP s;
    ip4 ip1 = 0x0A000001U;
    ip4 ip2 = 0x0A000002U;
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.last_tick = 1000;

    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++) {
        s.arp.pending[i].ip = IPADDR_ANY;
        s.arp.pending[i].if_idx = 0;
        s.arp.pending[i].ts = 0;
    }

    s.arp.pending[0].ip = ip1;
    s.arp.pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp.pending[0].ts = 900;

    arp_pending_record(&s, TEST_PRIMARY_IF, ip2);

    ck_assert_uint_eq(s.arp.pending[0].ip, ip1);
    ck_assert_uint_eq(s.arp.pending[1].ip, ip2);
    ck_assert_uint_eq(s.arp.pending[1].if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_arp_pending_match_and_clear_time_goes_back)
{
    struct wolfIP s;
    ip4 ip = 0x0A000001U;
    int matched;

    wolfIP_init(&s);
    mock_link_init(&s);

    s.last_tick = 1000;
    s.arp.pending[0].ip = ip;
    s.arp.pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp.pending[0].ts = 2000;

    matched = arp_pending_match_and_clear(&s, TEST_PRIMARY_IF, ip);
    ck_assert_int_eq(matched, 1);
    ck_assert_uint_eq(s.arp.pending[0].ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_store_neighbor_no_space)
{
    struct wolfIP s;
    uint8_t mac[6] = {1, 2, 3, 4, 5, 6};
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);

    for (i = 0; i < MAX_NEIGHBORS; i++) {
        s.arp.neighbors[i].ip = (ip4)(0x0A000100U + (uint32_t)i);
        s.arp.neighbors[i].if_idx = TEST_PRIMARY_IF;
        memcpy(s.arp.neighbors[i].mac, "\x00\x00\x00\x00\x00\x00", 6);
    }

    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A0000A1U, mac);
    ck_assert_uint_ne(s.arp.neighbors[0].ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_store_neighbor_null_stack)
{
    uint8_t mac[6] = {1, 2, 3, 4, 5, 6};
    arp_store_neighbor(NULL, TEST_PRIMARY_IF, 0x0A0000A1U, mac);
}
END_TEST

START_TEST(test_arp_lookup_if_idx_mismatch)
{
    struct wolfIP s;
    uint8_t mac[6] = {0};
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    ret = arp_lookup(&s, TEST_SECOND_IF, 0x0A0000A1U, mac);
    ck_assert_int_eq(ret, -1);
}
END_TEST

START_TEST(test_arp_request_missing_conf)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;
    last_frame_sent_size = 0;

    arp_request(&s, TEST_PRIMARY_IF, 0x0A000002U);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_request_null_stack)
{
    arp_request(NULL, TEST_PRIMARY_IF, 0x0A000002U);
}
END_TEST

START_TEST(test_arp_recv_request_other_ip_no_reply)
{
    struct wolfIP s;
    struct arp_packet arp_req;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    last_frame_sent_size = 0;

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.htype = ee16(1);
    arp_req.ptype = ee16(0x0800);
    arp_req.hlen = 6;
    arp_req.plen = 4;
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(0x0A000002U);
    memcpy(arp_req.sma, "\x01\x02\x03\x04\x05\x06", 6);
    arp_req.tip = ee32(0x0A000099U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_recv_null_stack)
{
    struct arp_packet arp_req;

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.htype = ee16(1);
    arp_req.ptype = ee16(0x0800);
    arp_req.hlen = 6;
    arp_req.plen = 4;
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.tip = ee32(0x0A000001U);

    arp_recv(NULL, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
}
END_TEST

START_TEST(test_arp_recv_request_no_send_fn)
{
    struct wolfIP s;
    struct arp_packet arp_req;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    s.ll_dev[TEST_PRIMARY_IF].send = NULL;
    last_frame_sent_size = 0;

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.htype = ee16(1);
    arp_req.ptype = ee16(0x0800);
    arp_req.hlen = 6;
    arp_req.plen = 4;
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(0x0A000002U);
    memcpy(arp_req.sma, "\x01\x02\x03\x04\x05\x06", 6);
    arp_req.tip = ee32(0x0A000001U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_recv_request_sends_reply)
{
    struct wolfIP s;
    struct arp_packet arp_req;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
    last_frame_sent_size = 0;

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.htype = ee16(1);
    arp_req.ptype = ee16(0x0800);
    arp_req.hlen = 6;
    arp_req.plen = 4;
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(0x0A000002U);
    memcpy(arp_req.sma, "\x01\x02\x03\x04\x05\x06", 6);
    arp_req.tip = ee32(0x0A000001U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
    ck_assert_uint_eq(last_frame_sent_size, sizeof(struct arp_packet));
}
END_TEST

START_TEST(test_arp_recv_request_does_not_store_self_neighbor)
{
    struct wolfIP s;
    struct arp_packet arp_req;
    const ip4 local_ip = 0x0A000001U;
    const ip4 sender_ip = 0x0A000002U;
    const uint8_t sender_mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    int i;
    int sender_count = 0;
    int self_count = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.htype = ee16(1);
    arp_req.ptype = ee16(0x0800);
    arp_req.hlen = 6;
    arp_req.plen = 4;
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(sender_ip);
    memcpy(arp_req.sma, sender_mac, sizeof(sender_mac));
    arp_req.tip = ee32(local_ip);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));

    for (i = 0; i < MAX_NEIGHBORS; i++) {
        if (s.arp.neighbors[i].if_idx != TEST_PRIMARY_IF)
            continue;
        if (s.arp.neighbors[i].ip == sender_ip) {
            sender_count++;
            ck_assert_mem_eq(s.arp.neighbors[i].mac, sender_mac,
                             sizeof(sender_mac));
        }
        if (s.arp.neighbors[i].ip == local_ip)
            self_count++;
    }

    ck_assert_int_eq(sender_count, 1);
    ck_assert_int_eq(self_count, 0);
}
END_TEST

START_TEST(test_send_ttl_exceeded_filter_drop)
{
    struct wolfIP s;
    uint8_t ip_buf[ETH_HEADER_LEN + TTL_EXCEEDED_ORIG_PACKET_SIZE_DEFAULT];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)ip_buf;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_icmp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;

    memset(ip_buf, 0, sizeof(ip_buf));
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->src = ee32(0x0A000002U);
    ip->dst = ee32(0x0A000001U);

    wolfIP_send_ttl_exceeded(&s, TEST_PRIMARY_IF, ip);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_icmp_mask(0);
}
END_TEST

START_TEST(test_send_ttl_exceeded_ip_filter_drop)
{
    struct wolfIP s;
    uint8_t ip_buf[ETH_HEADER_LEN + IP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)ip_buf;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_ip_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    wolfIP_filter_set_icmp_mask(0);
    last_frame_sent_size = 0;

    memset(ip_buf, 0, sizeof(ip_buf));
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->src = ee32(0x0A000002U);
    ip->dst = ee32(0x0A000001U);

    wolfIP_send_ttl_exceeded(&s, TEST_PRIMARY_IF, ip);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_ip_mask(0);
}
END_TEST

START_TEST(test_send_ttl_exceeded_eth_filter_drop)
{
    struct wolfIP s;
    uint8_t ip_buf[ETH_HEADER_LEN + IP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)ip_buf;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    wolfIP_filter_set_icmp_mask(0);
    wolfIP_filter_set_ip_mask(0);
    last_frame_sent_size = 0;

    memset(ip_buf, 0, sizeof(ip_buf));
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->src = ee32(0x0A000002U);
    ip->dst = ee32(0x0A000001U);

    wolfIP_send_ttl_exceeded(&s, TEST_PRIMARY_IF, ip);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

/* Regression: wolfIP_send_ttl_exceeded must include the full original IP
 * header (including options) plus 8 bytes of transport data per RFC 792.
 * With IHL=6 (24-byte header), 24+8=32 bytes must be copied, not 28. */
START_TEST(test_send_ttl_exceeded_includes_full_ip_header_with_options)
{
    struct wolfIP s;
    /* Original packet: IHL=6 (24-byte IP header) + 8 bytes of UDP ports */
    uint8_t orig_buf[ETH_HEADER_LEN + 24 + 8];
    struct wolfIP_ip_packet *orig = (struct wolfIP_ip_packet *)orig_buf;
    struct wolfIP_icmp_ttl_exceeded_packet *icmp_out;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(orig_buf, 0, sizeof(orig_buf));
    memcpy(orig->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    orig->ver_ihl = 0x46;  /* IHL=6, 24-byte header */
    orig->len = ee16(24 + 8);
    orig->ttl = 1;
    orig->proto = WI_IPPROTO_UDP;
    orig->src = ee32(0x0A000002U);
    orig->dst = ee32(0x0A000003U);
    /* Fill IP option area with a recognizable pattern */
    ((uint8_t *)orig)[ETH_HEADER_LEN + IP_HEADER_LEN] = 0x01;  /* NOP */
    ((uint8_t *)orig)[ETH_HEADER_LEN + IP_HEADER_LEN + 1] = 0x01;
    ((uint8_t *)orig)[ETH_HEADER_LEN + IP_HEADER_LEN + 2] = 0x01;
    ((uint8_t *)orig)[ETH_HEADER_LEN + IP_HEADER_LEN + 3] = 0x00;  /* EOO */
    /* Fill transport data (UDP src/dst ports) with recognizable bytes */
    ((uint8_t *)orig)[ETH_HEADER_LEN + 24 + 0] = 0xAA;
    ((uint8_t *)orig)[ETH_HEADER_LEN + 24 + 1] = 0xBB;
    ((uint8_t *)orig)[ETH_HEADER_LEN + 24 + 2] = 0xCC;
    ((uint8_t *)orig)[ETH_HEADER_LEN + 24 + 3] = 0xDD;
    ((uint8_t *)orig)[ETH_HEADER_LEN + 24 + 4] = 0x11;
    ((uint8_t *)orig)[ETH_HEADER_LEN + 24 + 5] = 0x22;
    ((uint8_t *)orig)[ETH_HEADER_LEN + 24 + 6] = 0x33;
    ((uint8_t *)orig)[ETH_HEADER_LEN + 24 + 7] = 0x44;

    wolfIP_send_ttl_exceeded(&s, TEST_PRIMARY_IF, orig);

    ck_assert_uint_gt(last_frame_sent_size, 0);
    icmp_out = (struct wolfIP_icmp_ttl_exceeded_packet *)last_frame_sent;

    /* Verify all 8 bytes of transport data are present (bytes 24-31) */
    ck_assert_uint_eq(icmp_out->orig_packet[24], 0xAA);
    ck_assert_uint_eq(icmp_out->orig_packet[25], 0xBB);
    ck_assert_uint_eq(icmp_out->orig_packet[26], 0xCC);
    ck_assert_uint_eq(icmp_out->orig_packet[27], 0xDD);
    ck_assert_uint_eq(icmp_out->orig_packet[28], 0x11);
    ck_assert_uint_eq(icmp_out->orig_packet[29], 0x22);
    ck_assert_uint_eq(icmp_out->orig_packet[30], 0x33);
    ck_assert_uint_eq(icmp_out->orig_packet[31], 0x44);
}
END_TEST

START_TEST(test_send_ttl_exceeded_no_send)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    s.ll_dev[TEST_PRIMARY_IF].send = NULL;
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.src = ee32(0x0A000002U);
    ip.dst = ee32(0x0A000001U);

    wolfIP_send_ttl_exceeded(&s, TEST_PRIMARY_IF, &ip);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_send_ttl_exceeded_non_ethernet_skips_eth_filter)
{
    struct wolfIP s;
    uint8_t ip_buf[ETH_HEADER_LEN + TTL_EXCEEDED_ORIG_PACKET_SIZE_DEFAULT];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)ip_buf;

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

    memset(ip_buf, 0, sizeof(ip_buf));
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->src = ee32(0x0A000002U);
    ip->dst = ee32(0x0A000001U);

    wolfIP_send_ttl_exceeded(&s, TEST_PRIMARY_IF, ip);
    ck_assert_uint_eq(last_frame_sent_size,
            (uint32_t)(IP_HEADER_LEN + ICMP_TTL_EXCEEDED_SIZE));

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

#if WOLFIP_ENABLE_FORWARDING
START_TEST(test_wolfip_forward_ttl_exceeded_short_len_does_not_send)
{
    struct wolfIP s;
    uint8_t ip_buf[ETH_HEADER_LEN + IP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)ip_buf;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    mock_link_init(&s);
    last_frame_sent_size = 0;

    memset(ip_buf, 0, sizeof(ip_buf));
    ip->eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->ver_ihl = 0x45;
    ip->ttl = 1;
    ip->proto = WI_IPPROTO_UDP;
    ip->len = ee16(IP_HEADER_LEN);
    ip->src = ee32(0x0A000099U);
    ip->dst = ee32(0xC0A80199U);
    fix_ip_checksum(ip);

    wolfIP_recv_on(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(ip_buf));
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST
#endif

START_TEST(test_arp_request_filter_drop)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    s.last_tick = 2000;
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;

    arp_request(&s, TEST_PRIMARY_IF, 0x0A000002U);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

START_TEST(test_arp_request_invalid_interface)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    last_frame_sent_size = 0;

    arp_request(&s, WOLFIP_MAX_INTERFACES, 0x0A000002U);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

/* Regression: ARP reply handler must reject sender IPs that are broadcast,
 * multicast, zero, or the device's own address -- same validation the request
 * handler already applies.  Without the check, an attacker can poison the
 * cache by sending a reply with sip set to the victim's own IP. */
START_TEST(test_arp_reply_rejects_invalid_sender_ip)
{
    struct wolfIP s;
    struct arp_packet arp_rep;
    struct wolfIP_ll_dev *ll;
    const ip4 local_ip = 0x0A000001U;
    static const uint8_t attacker_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    /* IPs that must never be cached */
    const ip4 bad_ips[] = {
        IPADDR_ANY,         /* 0.0.0.0 */
        local_ip,           /* own IP */
        0xFFFFFFFFU,        /* broadcast */
        0xE0000001U,        /* multicast 224.0.0.1 */
    };
    int k;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);

    for (k = 0; k < (int)(sizeof(bad_ips)/sizeof(bad_ips[0])); k++) {
        memset(&arp_rep, 0, sizeof(arp_rep));
        memcpy(arp_rep.eth.dst, ll->mac, 6);
        memcpy(arp_rep.eth.src, attacker_mac, 6);
        arp_rep.eth.type = ee16(ETH_TYPE_ARP);
        arp_rep.htype = ee16(1);
        arp_rep.ptype = ee16(0x0800);
        arp_rep.hlen = 6;
        arp_rep.plen = 4;
        arp_rep.opcode = ee16(ARP_REPLY);
        memcpy(arp_rep.sma, attacker_mac, 6);
        arp_rep.sip = ee32(bad_ips[k]);
        memcpy(arp_rep.tma, ll->mac, 6);
        arp_rep.tip = ee32(local_ip);

        arp_recv(&s, TEST_PRIMARY_IF, &arp_rep, sizeof(arp_rep));

        ck_assert_int_lt(arp_neighbor_index(&s, TEST_PRIMARY_IF, bad_ips[k]), 0);
    }
}
END_TEST

START_TEST(test_arp_reply_filter_drop)
{
    struct wolfIP s;
    struct arp_packet arp_req;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.htype = ee16(1);
    arp_req.ptype = ee16(0x0800);
    arp_req.hlen = 6;
    arp_req.plen = 4;
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(0x0A000002U);
    memcpy(arp_req.sma, "\x01\x02\x03\x04\x05\x06", 6);
    arp_req.tip = ee32(0x0A000001U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

START_TEST(test_arp_request_no_send_fn)
{
    struct wolfIP s;
    ip4 target_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.last_tick = 2000;
    s.ll_dev[TEST_PRIMARY_IF].send = NULL;
    last_frame_sent_size = 0;

    arp_request(&s, TEST_PRIMARY_IF, target_ip);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_recv_invalid_iface)
{
    struct wolfIP s;
    struct arp_packet arp_req;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;
    last_frame_sent_size = 0;

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.htype = ee16(1);
    arp_req.ptype = ee16(0x0800);
    arp_req.hlen = 6;
    arp_req.plen = 4;
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.tip = ee32(0x0A000001U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_recv_filter_drop)
{
    struct wolfIP s;
    struct arp_packet arp_req;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.htype = ee16(1);
    arp_req.ptype = ee16(0x0800);
    arp_req.hlen = 6;
    arp_req.plen = 4;
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(0x0A000002U);
    memcpy(arp_req.sma, "\x01\x02\x03\x04\x05\x06", 6);
    arp_req.tip = ee32(0x0A000001U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
    ck_assert_uint_eq(last_frame_sent_size, 0);
    ck_assert_int_ne(s.arp.neighbors[0].ip, IPADDR_ANY);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

START_TEST(test_wolfip_if_for_local_ip_paths)
{
    struct wolfIP s;
    int found = 1;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    ck_assert_uint_eq(wolfIP_if_for_local_ip(NULL, primary_ip, &found), 0U);
    ck_assert_int_eq(found, 0);

    wolfIP_init(&s);
    s.if_count = 0;
    found = 1;
    ck_assert_uint_eq(wolfIP_if_for_local_ip(&s, primary_ip, &found), 0U);
    ck_assert_int_eq(found, 0);

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    found = 0;
    ck_assert_uint_eq(wolfIP_if_for_local_ip(&s, IPADDR_ANY, &found), TEST_PRIMARY_IF);

    found = 0;
    ck_assert_uint_eq(wolfIP_if_for_local_ip(&s, secondary_ip, &found), TEST_SECOND_IF);
    ck_assert_int_eq(found, 1);

    found = 1;
    ck_assert_uint_eq(wolfIP_if_for_local_ip(&s, 0x0B000001U, &found), TEST_PRIMARY_IF);
    ck_assert_int_eq(found, 0);
}
END_TEST

START_TEST(test_wolfip_if_for_local_ip_null_found)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    ck_assert_uint_eq(wolfIP_if_for_local_ip(&s, secondary_ip, NULL), TEST_SECOND_IF);
}
END_TEST

START_TEST(test_wolfip_socket_if_idx_invalid)
{
    struct tsocket t;
    struct wolfIP s;

    ck_assert_uint_eq(wolfIP_socket_if_idx(NULL), 0U);

    memset(&t, 0, sizeof(t));
    ck_assert_uint_eq(wolfIP_socket_if_idx(&t), 0U);

    wolfIP_init(&s);
    memset(&t, 0, sizeof(t));
    t.S = &s;
    t.if_idx = (uint8_t)(s.if_count + 1);
    ck_assert_uint_eq(wolfIP_socket_if_idx(&t), 0U);
}
END_TEST

START_TEST(test_icmp_try_recv_mismatch_paths)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->src_port = ee16(0x1234);

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.ip.src = ee32(ts->remote_ip);
    icmp.ip.dst = ee32(0x0A000003U);
    icmp_set_echo_id(&icmp, ts->src_port);
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);

    icmp.ip.dst = ee32(ts->local_ip);
    icmp_set_echo_id(&icmp, ee16(0x9999));
    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);

    icmp_set_echo_id(&icmp, ts->src_port);
    icmp.ip.src = ee32(0x0A000099U);
    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);

    icmp.ip.src = ee32(ts->remote_ip);
    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len - 1);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_icmp_try_recv_mismatch_local_ip)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = icmp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->local_ip = 0x0A000001U;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000099U);
    icmp_set_echo_id(&icmp, 0);
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_icmp_try_recv_mismatch_src_port)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = icmp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->local_ip = 0;
    ts->src_port = 1234;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp_set_echo_id(&icmp, ee16(4321));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_icmp_try_recv_mismatch_remote_ip)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = icmp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->remote_ip = 0x0A000002U;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.ip.src = ee32(0x0A000099U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp_set_echo_id(&icmp, 0);
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_icmp_try_recv_full_fifo_does_not_signal_readable)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;
    uint32_t fifo_used;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = icmp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->src_port = 0x1234U;
    ts->last_pkt_ttl = 77U;
    ts->events = 0U;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.ip.src = ee32(ts->remote_ip);
    icmp.ip.dst = ee32(ts->local_ip);
    icmp.ip.ttl = 29U;
    icmp.type = ICMP_ECHO_REPLY;
    icmp_set_echo_id(&icmp, ts->src_port);
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    while (fifo_can_push_len(&ts->sock.udp.rxbuf, frame_len)) {
        ret = fifo_push(&ts->sock.udp.rxbuf, &icmp, frame_len);
        ck_assert_int_eq(ret, 0);
    }

    fifo_used = fifo_len(&ts->sock.udp.rxbuf);
    ck_assert_uint_gt(fifo_used, 0U);
    ck_assert_int_eq(fifo_can_push_len(&ts->sock.udp.rxbuf, frame_len), 0);

    icmp.ip.ttl = 42U;
    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len);

    ck_assert_uint_eq(fifo_len(&ts->sock.udp.rxbuf), fifo_used);
    ck_assert_uint_eq(ts->last_pkt_ttl, 77U);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, 0U);
}
END_TEST

START_TEST(test_wolfip_recv_on_not_for_us)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    uint8_t other_mac[6] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15};

    wolfIP_init(&s);
    mock_link_init(&s);
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    ip.eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip.eth.dst, other_mac, 6);
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.ver_ihl = 0x45;

    wolfIP_recv_on(&s, TEST_PRIMARY_IF, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_wolfip_recv_on_filter_drop_eth)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    filter_block_reason = WOLFIP_FILT_RECEIVING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    ip.eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.ver_ihl = 0x45;

    wolfIP_recv_on(&s, TEST_PRIMARY_IF, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

#if WOLFIP_ENABLE_FORWARDING
START_TEST(test_wolfip_recv_on_forward_ttl_exceeded)
{
    struct wolfIP s;
    uint8_t ip_buf[ETH_HEADER_LEN + IP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)ip_buf;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    mock_link_init(&s);
    last_frame_sent_size = 0;

    memset(ip_buf, 0, sizeof(ip_buf));
    ip->eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->ver_ihl = 0x45;
    ip->ttl = 1;
    ip->proto = WI_IPPROTO_UDP;
    ip->len = ee16(IP_HEADER_LEN);
    ip->src = ee32(0x0A000099U);
    ip->dst = ee32(0xC0A80199U);
    fix_ip_checksum(ip);

    wolfIP_recv_on(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(ip_buf));
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(((struct wolfIP_icmp_ttl_exceeded_packet *)last_frame_sent)->type, ICMP_TTL_EXCEEDED);
}
END_TEST

START_TEST(test_wolfip_recv_on_forward_arp_queue)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    int found = 0;
    int i;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    mock_link_init(&s);
    s.last_tick = 2000;
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    ip.eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.ver_ihl = 0x45;
    ip.ttl = 4;
    ip.proto = WI_IPPROTO_UDP;
    ip.len = ee16(IP_HEADER_LEN);
    ip.src = ee32(0x0A000099U);
    ip.dst = ee32(0xC0A80199U);
    fix_ip_checksum(&ip);

    wolfIP_recv_on(&s, TEST_PRIMARY_IF, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_gt(last_frame_sent_size, 0);
    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++) {
        if (s.arp_pending[i].dest == ee32(ip.dst)) {
            found = 1;
            ck_assert_uint_eq(s.arp_pending[i].if_idx, TEST_SECOND_IF);
            break;
        }
    }
    ck_assert_int_eq(found, 1);
}
END_TEST

START_TEST(test_wolfip_recv_on_forward_arp_hit_sends)
{
    struct wolfIP s;
    uint8_t ip_buf[ETH_HEADER_LEN + IP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)ip_buf;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    uint8_t mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    mock_link_init(&s);
    arp_store_neighbor(&s, TEST_SECOND_IF, 0xC0A80199U, mac);
    last_frame_sent_size = 0;

    memset(ip_buf, 0, sizeof(ip_buf));
    ip->eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->ver_ihl = 0x45;
    ip->ttl = 4;
    ip->proto = WI_IPPROTO_UDP;
    ip->len = ee16(IP_HEADER_LEN);
    ip->src = ee32(0x0A000099U);
    ip->dst = ee32(0xC0A80199U);
    fix_ip_checksum(ip);

    wolfIP_recv_on(&s, TEST_PRIMARY_IF, ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(((struct wolfIP_ip_packet *)last_frame_sent)->ttl, 3);
}
END_TEST

START_TEST(test_wolfip_forward_non_ethernet_in_to_ethernet_out)
{
    struct wolfIP s;
    uint8_t ip_buf[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)ip_buf;
    struct wolfIP_ip_packet *ip = &udp->ip;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    uint8_t mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    mock_link_init(&s);
    s.ll_dev[TEST_PRIMARY_IF].non_ethernet = 1;
    arp_store_neighbor(&s, TEST_SECOND_IF, 0xC0A80199U, mac);
    last_frame_sent_size = 0;

    memset(ip_buf, 0, sizeof(ip_buf));
    ip->ver_ihl = 0x45;
    ip->ttl = 4;
    ip->proto = WI_IPPROTO_UDP;
    ip->len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    ip->src = ee32(0x0A000099U);
    ip->dst = ee32(0xC0A80199U);
    udp->src_port = ee16(1234);
    udp->dst_port = ee16(5678);
    udp->len = ee16(UDP_HEADER_LEN);
    fix_ip_checksum(ip);

    wolfIP_recv_on(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(ip_buf));
    ck_assert_uint_eq(last_frame_sent_size, (uint32_t)sizeof(ip_buf));
    ck_assert_uint_eq(((struct wolfIP_eth_frame *)last_frame_sent)->type, ee16(ETH_TYPE_IP));
    ck_assert_mem_eq(((struct wolfIP_eth_frame *)last_frame_sent)->src,
                     s.ll_dev[TEST_SECOND_IF].mac, 6);
    ck_assert_uint_eq(((struct wolfIP_ip_packet *)last_frame_sent)->ttl, 3);
}
END_TEST

START_TEST(test_wolfip_forward_ethernet_in_to_non_ethernet_out)
{
    struct wolfIP s;
    uint8_t ip_buf[ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)ip_buf;
    struct wolfIP_ip_packet *ip = &udp->ip;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    mock_link_init(&s);
    s.ll_dev[TEST_SECOND_IF].non_ethernet = 1;
    last_frame_sent_size = 0;

    memset(ip_buf, 0, sizeof(ip_buf));
    ip->eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip->eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip->ver_ihl = 0x45;
    ip->ttl = 4;
    ip->proto = WI_IPPROTO_UDP;
    ip->len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    ip->src = ee32(0x0A000099U);
    ip->dst = ee32(0xC0A80199U);
    udp->src_port = ee16(1234);
    udp->dst_port = ee16(5678);
    udp->len = ee16(UDP_HEADER_LEN);
    fix_ip_checksum(ip);

    wolfIP_recv_on(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(ip_buf));
    ck_assert_uint_eq(last_frame_sent_size, (uint32_t)(sizeof(ip_buf) - ETH_HEADER_LEN));
    ck_assert_uint_eq(last_frame_sent[0], 0x45);
    ck_assert_uint_eq(last_frame_sent[8], 3);
}
END_TEST
#endif

START_TEST(test_forward_packet_no_send)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN];
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)buf;
    struct wolfIP_ip_packet *ip = &tcp->ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.ll_dev[TEST_PRIMARY_IF].send = NULL;

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_TCP;
    ip->len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), NULL, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_forward_packet_filter_drop)
{
    struct wolfIP s;
    uint8_t buf[64];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    filter_block_reason = WOLFIP_FILT_SENDING;

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_TCP;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), NULL, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_forward_packet_send_paths)
{
    struct wolfIP s;
    uint8_t buf[64];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    uint8_t mac[6] = {0x01,0x02,0x03,0x04,0x05,0x06};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_filter_set_callback(NULL, NULL);

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_TCP;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), mac, 0);
    ck_assert_uint_gt(last_frame_sent_size, 0);

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_UDP;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), mac, 1);
    ck_assert_uint_gt(last_frame_sent_size, 0);

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_ICMP;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), mac, 0);
    ck_assert_uint_gt(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_ll_send_frame_non_ethernet_strips)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN];

    wolfIP_init(&s);
    mock_link_init(&s);
    s.ll_dev[TEST_PRIMARY_IF].non_ethernet = 1;

    memset(buf, 0, sizeof(buf));
    buf[ETH_HEADER_LEN] = 0x45;
    last_frame_sent_size = 0;

    wolfIP_ll_send_frame(&s, TEST_PRIMARY_IF, buf, (uint32_t)sizeof(buf));
    ck_assert_uint_eq(last_frame_sent_size, (uint32_t)(sizeof(buf) - ETH_HEADER_LEN));
    ck_assert_mem_eq(last_frame_sent, buf + ETH_HEADER_LEN, sizeof(buf) - ETH_HEADER_LEN);
}
END_TEST

START_TEST(test_ll_send_frame_non_ethernet_short_len)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN];

    wolfIP_init(&s);
    mock_link_init(&s);
    s.ll_dev[TEST_PRIMARY_IF].non_ethernet = 1;

    last_frame_sent_size = 0;
    wolfIP_ll_send_frame(&s, TEST_PRIMARY_IF, buf, (uint32_t)sizeof(buf));
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_ll_send_frame_drops_oversize)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN + 32];

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF,
            (uint32_t)(sizeof(buf) - 1U)), 0);

    memset(buf, 0, sizeof(buf));
    last_frame_sent_size = 0;

    wolfIP_ll_send_frame(&s, TEST_PRIMARY_IF, buf, (uint32_t)sizeof(buf));
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_ll_helpers_invalid_inputs)
{
    struct wolfIP s;
    uint8_t buf[4] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    last_frame_sent_size = 0;

    ck_assert_int_eq(wolfIP_ll_is_non_ethernet(NULL, 0), 0);
    ck_assert_int_eq(wolfIP_ll_is_non_ethernet(&s, s.if_count), 0);

    wolfIP_ll_send_frame(NULL, 0, buf, (uint32_t)sizeof(buf));
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_ll_send_frame(&s, s.if_count, buf, (uint32_t)sizeof(buf));
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_non_ethernet_recv_oversize_dropped)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_ll_dev *ll;
    struct wolfIP_ip_packet tmp;
    uint8_t *ip_hdr;
    uint8_t buf[LINK_MTU];
    uint32_t local_ip = 0x0A000001U;
    uint32_t src_ip = 0x0A0000A1U;
    uint32_t dst_ip = local_ip;
    struct {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t len;
        uint16_t csum;
    } PACKED udp_hdr;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);
    ll->non_ethernet = 1;

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(buf, 0, sizeof(buf));
    memset(&tmp, 0, sizeof(tmp));
    tmp.ver_ihl = 0x45;
    tmp.ttl = 64;
    tmp.proto = WI_IPPROTO_UDP;
    tmp.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    tmp.src = ee32(src_ip);
    tmp.dst = ee32(dst_ip);
    iphdr_set_checksum(&tmp);
    ip_hdr = ((uint8_t *)&tmp) + ETH_HEADER_LEN;
    memcpy(buf, ip_hdr, IP_HEADER_LEN);
    udp_hdr.src_port = ee16(1111);
    udp_hdr.dst_port = ee16(1234);
    udp_hdr.len = ee16(UDP_HEADER_LEN);
    udp_hdr.csum = 0;
    memcpy(buf + IP_HEADER_LEN, &udp_hdr, sizeof(udp_hdr));

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, buf, (uint32_t)(LINK_MTU - ETH_HEADER_LEN + 1));
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_non_ethernet_recv_wrapper_delivers_udp_and_skips_eth_filter)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_ll_dev *ll;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_sockaddr_in from;
    uint8_t raw[IP_HEADER_LEN + UDP_HEADER_LEN + 4];
    uint8_t payload[4] = {1, 2, 3, 4};
    uint8_t udp_buf[sizeof(struct wolfIP_udp_datagram) + sizeof(payload)];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)udp_buf;
    uint8_t rxbuf[sizeof(payload)];
    socklen_t from_len = sizeof(from);
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);
    ll->non_ethernet = 1;

    filter_block_reason = WOLFIP_FILT_RECEIVING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];

    memset(udp_buf, 0, sizeof(udp_buf));
    udp->ip.ver_ihl = 0x45;
    udp->ip.ttl = 64;
    udp->ip.proto = WI_IPPROTO_UDP;
    udp->ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN + sizeof(payload));
    udp->ip.src = ee32(0x0A000002U);
    udp->ip.dst = ee32(0x0A000001U);
    udp->src_port = ee16(5678);
    udp->dst_port = ee16(1234);
    udp->len = ee16(UDP_HEADER_LEN + sizeof(payload));
    memcpy(udp->data, payload, sizeof(payload));
    fix_udp_checksums(udp);
    memcpy(raw, udp_buf + ETH_HEADER_LEN, sizeof(raw));

    wolfIP_recv(&s, raw, (uint32_t)sizeof(raw));

    memset(&from, 0, sizeof(from));
    ret = wolfIP_sock_recvfrom(&s, udp_sd, rxbuf, sizeof(rxbuf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len);
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(rxbuf, payload, sizeof(payload));
    ck_assert_uint_eq(from.sin_addr.s_addr, ee32(0x0A000002U));
    ck_assert_uint_eq(from.sin_port, ee16(5678));
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

START_TEST(test_non_ethernet_recv_ex_wrapper_delivers_udp_on_second_if)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_ll_dev *ll;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_sockaddr_in from;
    uint8_t raw[IP_HEADER_LEN + UDP_HEADER_LEN + 4];
    uint8_t payload[4] = {9, 8, 7, 6};
    uint8_t udp_buf[sizeof(struct wolfIP_udp_datagram) + sizeof(payload)];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)udp_buf;
    uint8_t rxbuf[sizeof(payload)];
    socklen_t from_len = sizeof(from);
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    mock_link_init_idx(&s, TEST_SECOND_IF, NULL);
    s.ipconf[TEST_SECOND_IF].ip = 0x0A000101U;
    s.ipconf[TEST_SECOND_IF].mask = 0xFFFFFF00U;

    ll = wolfIP_getdev_ex(&s, TEST_SECOND_IF);
    ck_assert_ptr_nonnull(ll);
    ll->non_ethernet = 1;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(2345);
    sin.sin_addr.s_addr = ee32(0x0A000101U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    memset(udp_buf, 0, sizeof(udp_buf));
    udp->ip.ver_ihl = 0x45;
    udp->ip.ttl = 64;
    udp->ip.proto = WI_IPPROTO_UDP;
    udp->ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN + sizeof(payload));
    udp->ip.src = ee32(0x0A000102U);
    udp->ip.dst = ee32(0x0A000101U);
    udp->src_port = ee16(6789);
    udp->dst_port = ee16(2345);
    udp->len = ee16(UDP_HEADER_LEN + sizeof(payload));
    memcpy(udp->data, payload, sizeof(payload));
    fix_udp_checksums(udp);
    memcpy(raw, udp_buf + ETH_HEADER_LEN, sizeof(raw));

    wolfIP_recv_ex(&s, TEST_SECOND_IF, raw, (uint32_t)sizeof(raw));

    memset(&from, 0, sizeof(from));
    ret = wolfIP_sock_recvfrom(&s, udp_sd, rxbuf, sizeof(rxbuf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len);
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(rxbuf, payload, sizeof(payload));
    ck_assert_uint_eq(from.sin_addr.s_addr, ee32(0x0A000102U));
    ck_assert_uint_eq(from.sin_port, ee16(6789));
}
END_TEST

START_TEST(test_forward_packet_filter_drop_udp_icmp)
{
    struct wolfIP s;
    uint8_t buf[64];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    filter_block_reason = WOLFIP_FILT_SENDING;

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_UDP;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), NULL, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_ICMP;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), NULL, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST
#endif

START_TEST(test_forward_packet_ip_filter_drop)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    uint8_t mac[6] = {0x01,0x02,0x03,0x04,0x05,0x06};

    wolfIP_init(&s);
    mock_link_init(&s);
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_ip_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));

    memset(ip, 0, sizeof(buf));
    ip->proto = 0x00;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), mac, 0);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_ip_mask(0);
}
END_TEST

START_TEST(test_forward_packet_eth_filter_drop)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    uint8_t mac[6] = {0x01,0x02,0x03,0x04,0x05,0x06};

    wolfIP_init(&s);
    mock_link_init(&s);
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));

    memset(ip, 0, sizeof(buf));
    ip->proto = 0x00;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), mac, 0);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST
START_TEST(test_tcp_last_ack_closes_socket)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_timer tmr;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000E1U;
    uint16_t local_port = 6666;
    uint16_t remote_port = 7777;
    uint32_t ctrl_rto_id;
    uint32_t i;
    int found_canceled = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LAST_ACK;
    ts->sock.tcp.last = 9;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port = local_port;
    ts->dst_port = remote_port;
    ts->sock.tcp.ack = 10;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    ts->sock.tcp.ctrl_rto_active = 1;
    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 12345;
    ctrl_rto_id = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ctrl_rto_id, NO_TIMER);
    ts->sock.tcp.tmr_rto = ctrl_rto_id;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            10, 10, TCP_FLAG_ACK);
    ck_assert_int_eq(ts->proto, 0);
    for (i = 0; i < s.timers.size; i++) {
        if (s.timers.timers[i].id == ctrl_rto_id) {
            found_canceled = 1;
            ck_assert_uint_eq(s.timers.timers[i].expires, 0);
            break;
        }
    }
    ck_assert_int_eq(found_canceled, 1);
}
END_TEST

START_TEST(test_tcp_last_ack_partial_ack_keeps_socket_and_timer)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_timer tmr;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000E2U;
    uint16_t local_port = 6667;
    uint16_t remote_port = 7778;
    uint32_t ctrl_rto_id;
    uint32_t i;
    int found_active = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LAST_ACK;
    ts->sock.tcp.last = 9;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port = local_port;
    ts->dst_port = remote_port;
    ts->sock.tcp.ack = 10;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    ts->sock.tcp.ctrl_rto_active = 1;
    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 12345;
    ctrl_rto_id = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ctrl_rto_id, NO_TIMER);
    ts->sock.tcp.tmr_rto = ctrl_rto_id;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            10, 9, TCP_FLAG_ACK);

    ck_assert_int_eq(ts->proto, WI_IPPROTO_TCP);
    ck_assert_uint_eq(ts->sock.tcp.state, TCP_LAST_ACK);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_active, 1);
    ck_assert_uint_eq(ts->sock.tcp.tmr_rto, ctrl_rto_id);
    for (i = 0; i < s.timers.size; i++) {
        if (s.timers.timers[i].id == ctrl_rto_id) {
            found_active = 1;
            ck_assert_uint_eq(s.timers.timers[i].expires, 12345);
            break;
        }
    }
    ck_assert_int_eq(found_active, 1);
}
END_TEST
START_TEST(test_fifo_pop_success) {
    struct fifo f;
    uint8_t data[] = {1, 2, 3, 4};
    struct pkt_desc *desc;
    fifo_init(&f, mem, memsz);
    fifo_push(&f, data, sizeof(data)); // Add data to FIFO

    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc); // Ensure we got a valid descriptor
    ck_assert_int_eq(desc->len, sizeof(data)); // Check length
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data)); // Check data
}

START_TEST(test_fifo_pop_empty) {
    struct fifo f;
    struct pkt_desc *desc;
    fifo_init(&f, mem, memsz);

    desc = fifo_pop(&f);
    ck_assert_ptr_eq(desc, NULL); // Ensure pop returns NULL on empty FIFO
}

START_TEST(test_fifo_push_full) {
    struct fifo f;
    uint8_t data[8 * 1024] = {1, 2, 3, 4};
    int ret;
    fifo_init(&f, mem, memsz);
    fifo_push(&f, data, sizeof(data)); // Add data to FIFO

    ret = fifo_push(&f, data, sizeof(data));
    ck_assert_int_eq(ret, -1); // Ensure push returns -1 when FIFO is full
}
END_TEST

START_TEST(test_fifo_can_push_len_null_and_oversized)
{
    struct fifo f;
    uint8_t data[64];

    ck_assert_int_eq(fifo_can_push_len(NULL, 1), 0);
    fifo_init(&f, data, sizeof(data));
    ck_assert_int_eq(fifo_can_push_len(&f, (uint32_t)(sizeof(data) - sizeof(struct pkt_desc) + 1)), 0);
}
END_TEST

START_TEST(test_fifo_can_push_len_head_tail_equal_with_wrap)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    f.head = 8;
    f.tail = 8;
    f.h_wrap = 32;

    ck_assert_int_eq(fifo_can_push_len(&f, 1), 0);
}
END_TEST

START_TEST(test_fifo_can_push_len_wrap_tail_too_small_rejects)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    f.head = 60;
    f.tail = 8;
    f.h_wrap = 0;

    ck_assert_int_eq(fifo_can_push_len(&f, 1), 0);
}
END_TEST

START_TEST(test_fifo_can_push_len_wrap_to_zero_then_accepts)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    f.head = 60;
    f.tail = 40;
    f.h_wrap = 0;

    ck_assert_int_eq(fifo_can_push_len(&f, 1), 1);
}
END_TEST

START_TEST(test_fifo_can_push_len_head_at_wrap_boundary)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    f.head = 32;
    f.tail = 48;
    f.h_wrap = 32;
    ck_assert_int_eq(fifo_can_push_len(&f, 0), 1);

    f.tail = 12;
    ck_assert_int_eq(fifo_can_push_len(&f, 1), 0);
}
END_TEST

START_TEST(test_tcp_process_ts_uses_ecr)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN];
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *opt = (struct tcp_opt_ts *)tcp->data;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;

    memset(tcp, 0, sizeof(buf));
    tcp->hlen = (TCP_HEADER_LEN + TCP_OPTIONS_LEN) << 2;
    opt->opt = TCP_OPTION_TS;
    opt->len = TCP_OPTION_TS_LEN;
    opt->val = ee32(1000);
    opt->ecr = ee32(900);
    opt->pad = TCP_OPTION_NOP;
    opt->eoo = TCP_OPTION_EOO;

    s.last_tick = 1000;
    ck_assert_int_eq(tcp_process_ts(ts, tcp, sizeof(buf)), 0);
    ck_assert_uint_eq(ts->sock.tcp.rtt, 100);
    ck_assert_uint_eq(ts->sock.tcp.rto, TCP_RTO_MIN_MS);
    ck_assert_uint_eq(ts->sock.tcp.rto_initialized, 1);
}
END_TEST

START_TEST(test_tcp_rto_update_second_sample_rfc6298)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;

    tcp_rto_update_from_sample(ts, 2000);
    ck_assert_uint_eq(ts->sock.tcp.rtt, 2000);
    ck_assert_uint_eq(ts->sock.tcp.rto, 6000);

    tcp_rto_update_from_sample(ts, 1000);
    ck_assert_uint_eq(ts->sock.tcp.rtt, 1875);
    ck_assert_uint_eq(ts->sock.tcp.rto, 5875);
}
END_TEST

START_TEST(test_tcp_process_ts_nop_then_ts)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN + 1];
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *opt;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;

    memset(tcp, 0, sizeof(buf));
    tcp->hlen = (TCP_HEADER_LEN + TCP_OPTIONS_LEN + 1) << 2;
    tcp->data[0] = TCP_OPTION_NOP;
    opt = (struct tcp_opt_ts *)&tcp->data[1];
    opt->opt = TCP_OPTION_TS;
    opt->len = TCP_OPTION_TS_LEN;
    opt->val = ee32(100);
    opt->ecr = ee32(50);
    opt->pad = TCP_OPTION_NOP;
    opt->eoo = TCP_OPTION_EOO;

    s.last_tick = 120;
    ck_assert_int_eq(tcp_process_ts(ts, tcp, sizeof(buf)), 0);
}
END_TEST

START_TEST(test_tcp_process_ts_skips_unknown_option)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN + 4];
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *opt;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;

    memset(tcp, 0, sizeof(buf));
    tcp->hlen = (TCP_HEADER_LEN + TCP_OPTIONS_LEN + 4) << 2;
    tcp->data[0] = 0x22;
    tcp->data[1] = 4;
    tcp->data[2] = 0;
    tcp->data[3] = 0;
    opt = (struct tcp_opt_ts *)&tcp->data[4];
    opt->opt = TCP_OPTION_TS;
    opt->len = TCP_OPTION_TS_LEN;
    opt->val = ee32(200);
    opt->ecr = ee32(100);
    opt->pad = TCP_OPTION_NOP;
    opt->eoo = TCP_OPTION_EOO;

    s.last_tick = 250;
    ck_assert_int_eq(tcp_process_ts(ts, tcp, sizeof(buf)), 0);
}
END_TEST

START_TEST(test_tcp_process_ts_no_ecr)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN];
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *opt = (struct tcp_opt_ts *)tcp->data;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;

    memset(tcp, 0, sizeof(buf));
    tcp->hlen = (TCP_HEADER_LEN + TCP_OPTIONS_LEN) << 2;
    opt->opt = TCP_OPTION_TS;
    opt->len = TCP_OPTION_TS_LEN;
    opt->val = ee32(100);
    opt->ecr = 0;
    opt->pad = TCP_OPTION_NOP;
    opt->eoo = TCP_OPTION_EOO;

    ck_assert_int_eq(tcp_process_ts(ts, tcp, sizeof(buf)), -1);
}
END_TEST

START_TEST(test_tcp_process_ts_updates_rtt_when_set)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN];
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *opt = (struct tcp_opt_ts *)tcp->data;
    uint32_t old_rtt;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.rtt = 10;
    old_rtt = ts->sock.tcp.rtt;

    memset(tcp, 0, sizeof(buf));
    tcp->hlen = (TCP_HEADER_LEN + TCP_OPTIONS_LEN) << 2;
    opt->opt = TCP_OPTION_TS;
    opt->len = TCP_OPTION_TS_LEN;
    opt->val = ee32(100);
    opt->ecr = ee32(90);
    opt->pad = TCP_OPTION_NOP;
    opt->eoo = TCP_OPTION_EOO;

    s.last_tick = 120;
    ck_assert_int_eq(tcp_process_ts(ts, tcp, sizeof(buf)), 0);
    ck_assert_uint_ne(ts->sock.tcp.rtt, old_rtt);
}
END_TEST

START_TEST(test_tcp_send_syn_advertises_sack_permitted)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg *syn;
    int off;

    wolfIP_init(&s);
    ts = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->dst_port = 4321;

    tcp_send_syn(ts, TCP_FLAG_SYN);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    syn = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
    off = tcp_option_find(syn, TCP_OPTION_SACK_PERMITTED);
    ck_assert_int_ge(off, 0);
    ck_assert_uint_eq(syn->data[off + 1], TCP_OPTION_SACK_PERMITTED_LEN);
}
END_TEST

START_TEST(test_tcp_build_ack_options_does_not_write_past_returned_len)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t opts[TCP_MAX_OPTIONS_LEN];
    uint8_t len;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.ts_enabled = 1;
    ts->sock.tcp.sack_permitted = 0;
    ts->sock.tcp.rx_sack_count = 0;

    memset(opts, 0xCC, sizeof(opts));
    len = tcp_build_ack_options(ts, opts, sizeof(opts));
    ck_assert_uint_eq(len, TCP_OPTION_TS_LEN + 2); /* TS + 2-byte NOP pad */
    ck_assert_uint_eq((uint8_t)(len % 4), 0);
    ck_assert_uint_eq(opts[len], 0xCC);
}
END_TEST

START_TEST(test_tcp_build_ack_options_omits_ts_when_not_negotiated)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t opts[TCP_MAX_OPTIONS_LEN];
    uint8_t len;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.ts_enabled = 0;
    ts->sock.tcp.sack_permitted = 0;
    ts->sock.tcp.rx_sack_count = 0;

    memset(opts, 0xCC, sizeof(opts));
    len = tcp_build_ack_options(ts, opts, sizeof(opts));
    ck_assert_uint_eq(len, 0);
    ck_assert_uint_eq(opts[0], 0xCC);
}
END_TEST

START_TEST(test_tcp_sort_sack_blocks_swaps_out_of_order)
{
    struct tcp_sack_block blocks[3];

    blocks[0].left = 30; blocks[0].right = 40;
    blocks[1].left = 10; blocks[1].right = 20;
    blocks[2].left = 25; blocks[2].right = 26;

    tcp_sort_sack_blocks(blocks, 3);
    ck_assert_uint_eq(blocks[0].left, 10);
    ck_assert_uint_eq(blocks[1].left, 25);
    ck_assert_uint_eq(blocks[2].left, 30);
}
END_TEST

START_TEST(test_tcp_sort_sack_blocks_wrap_order)
{
    struct tcp_sack_block blocks[2];

    blocks[0].left = 0x00000010U;
    blocks[0].right = 0x00000020U;
    blocks[1].left = 0xFFFFFFF0U;
    blocks[1].right = 0xFFFFFFF8U;

    tcp_sort_sack_blocks(blocks, 2);
    ck_assert_uint_eq(blocks[0].left, 0xFFFFFFF0U);
    ck_assert_uint_eq(blocks[1].left, 0x00000010U);
}
END_TEST

START_TEST(test_tcp_merge_sack_blocks_adjacent_and_disjoint)
{
    struct tcp_sack_block blocks[3];
    uint8_t merged;

    blocks[0].left = 30; blocks[0].right = 35;
    blocks[1].left = 20; blocks[1].right = 30;
    blocks[2].left = 40; blocks[2].right = 45;

    merged = tcp_merge_sack_blocks(blocks, 3);
    ck_assert_uint_eq(merged, 2);
    ck_assert_uint_eq(blocks[0].left, 20);
    ck_assert_uint_eq(blocks[0].right, 35);
    ck_assert_uint_eq(blocks[1].left, 40);
    ck_assert_uint_eq(blocks[1].right, 45);
}
END_TEST

START_TEST(test_tcp_merge_sack_blocks_wrap_order)
{
    struct tcp_sack_block blocks[2];
    uint8_t merged;

    blocks[0].left = 0x00000010U;
    blocks[0].right = 0x00000020U;
    blocks[1].left = 0xFFFFFFF0U;
    blocks[1].right = 0xFFFFFFF8U;

    merged = tcp_merge_sack_blocks(blocks, 2);
    ck_assert_uint_eq(merged, 2U);
    ck_assert_uint_eq(blocks[0].left, 0xFFFFFFF0U);
    ck_assert_uint_eq(blocks[1].left, 0x00000010U);
}
END_TEST

START_TEST(test_tcp_recv_tracks_holes_and_sack_blocks)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg_buf_ooo[sizeof(struct wolfIP_tcp_seg) + 1];
    uint8_t seg_buf_in[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg_ooo = (struct wolfIP_tcp_seg *)seg_buf_ooo;
    struct wolfIP_tcp_seg *seg_in = (struct wolfIP_tcp_seg *)seg_buf_in;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg *ackseg;
    uint8_t out[2];

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

    memset(seg_ooo, 0, sizeof(seg_buf_ooo));
    seg_ooo->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg_ooo->hlen = TCP_HEADER_LEN << 2;
    seg_ooo->seq = ee32(101);
    seg_ooo->data[0] = 'b';
    tcp_recv(ts, seg_ooo);
    ck_assert_uint_eq(ts->sock.tcp.ack, 100);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 1);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].left, 101);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].right, 102);

    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ackseg = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
    ck_assert_int_ge(tcp_option_find(ackseg, TCP_OPTION_SACK), 0);

    (void)fifo_pop(&ts->sock.tcp.txbuf);

    memset(seg_in, 0, sizeof(seg_buf_in));
    seg_in->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg_in->hlen = TCP_HEADER_LEN << 2;
    seg_in->seq = ee32(100);
    seg_in->data[0] = 'a';
    tcp_recv(ts, seg_in);
    ck_assert_uint_eq(ts->sock.tcp.ack, 102);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 0);

    ck_assert_int_eq(queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out)), 2);
    ck_assert_mem_eq(out, "ab", 2);
}
END_TEST

START_TEST(test_tcp_rebuild_rx_sack_right_edge_wraps)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t payload[8] = {0};

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;

    ck_assert_int_eq(tcp_store_ooo_segment(ts, payload, 0xFFFFFFFCU, 8), 0);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 1);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].left, 0xFFFFFFFCU);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].right, 4U);
}
END_TEST

START_TEST(test_tcp_consume_ooo_wrap_trim_and_promote)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t out[8];
    uint8_t payload[8] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' };

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 2;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 2);

    ts->sock.tcp.ooo[0].used = 1;
    ts->sock.tcp.ooo[0].seq = 0xFFFFFFFCU;
    ts->sock.tcp.ooo[0].len = 8;
    memcpy(ts->sock.tcp.ooo[0].data, payload, sizeof(payload));

    tcp_consume_ooo(ts);
    ck_assert_uint_eq(ts->sock.tcp.ack, 4U);
    ck_assert_int_eq(ts->sock.tcp.ooo[0].used, 0);
    ck_assert_int_eq(queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out)), 2);
    ck_assert_mem_eq(out, payload + 6, 2);
}
END_TEST

START_TEST(test_tcp_consume_ooo_wrap_drop_fully_acked)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t payload[8] = {0};

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 4;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 4);

    ts->sock.tcp.ooo[0].used = 1;
    ts->sock.tcp.ooo[0].seq = 0xFFFFFFFCU;
    ts->sock.tcp.ooo[0].len = 8;
    memcpy(ts->sock.tcp.ooo[0].data, payload, sizeof(payload));

    tcp_consume_ooo(ts);
    ck_assert_uint_eq(ts->sock.tcp.ack, 4U);
    ck_assert_int_eq(ts->sock.tcp.ooo[0].used, 0);
    ck_assert_int_eq(ts->sock.tcp.ooo[0].len, 0);
}
END_TEST

START_TEST(test_tcp_ack_sack_early_retransmit_before_three_dupack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf1;
    struct tcp_seg_buf segbuf2;
    struct wolfIP_tcp_seg *seg1;
    struct wolfIP_tcp_seg *seg2;
    uint8_t ackbuf[sizeof(struct wolfIP_tcp_seg) + 12];
    struct wolfIP_tcp_seg *ackseg = (struct wolfIP_tcp_seg *)ackbuf;
    struct pkt_desc *desc;
    uint32_t left, right;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 1;
    ts->sock.tcp.seq = 102;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.bytes_in_flight = 2;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf1, 0, sizeof(segbuf1));
    seg1 = &segbuf1.seg;
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
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
    seg2->seq = ee32(101);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf2, sizeof(segbuf2)), 0);
    desc = fifo_next(&ts->sock.tcp.txbuf, desc);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(ackbuf, 0, sizeof(ackbuf));
    ackseg->ack = ee32(100);
    ackseg->hlen = (TCP_HEADER_LEN + 12) << 2;
    ackseg->flags = TCP_FLAG_ACK;
    ackseg->data[0] = TCP_OPTION_NOP;
    ackseg->data[1] = TCP_OPTION_NOP;
    ackseg->data[2] = TCP_OPTION_SACK;
    ackseg->data[3] = 10;
    left = ee32(101);
    right = ee32(102);
    memcpy(&ackseg->data[4], &left, sizeof(left));
    memcpy(&ackseg->data[8], &right, sizeof(right));

    tcp_ack(ts, ackseg);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_uint_eq(ts->sock.tcp.dup_acks, 1);

    tcp_ack(ts, ackseg);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_uint_eq(ts->sock.tcp.dup_acks, 2);
}
END_TEST

START_TEST(test_tcp_input_listen_syn_without_sack_disables_sack)
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
    ts->sock.tcp.sack_permitted = 1;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A0000A1U, 0x0A000001U, 40000, 1234, 1, 0, TCP_FLAG_SYN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(ts->sock.tcp.sack_permitted, 0);
}
END_TEST

START_TEST(test_tcp_input_listen_syn_arms_control_rto)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    s.last_tick = 777;

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_active, 0);

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A0000A1U, 0x0A000001U, 40000, 1234, 1, 0, TCP_FLAG_SYN);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_active, 1);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_retries, 0);
}
END_TEST

/* Regression: when a SYN arrives at a LISTEN socket, the SYN-ACK must be
 * sent immediately as part of the LISTEN->SYN_RCVD transition, not deferred
 * until accept() or the ctrl_rto timer fires (up to 1 second later). */
START_TEST(test_tcp_input_listen_syn_sends_synack_immediately)
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

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A0000A1U, 0x0A000001U,
                       40000, 1234, 1, 0, TCP_FLAG_SYN);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);

    /* A SYN-ACK must have been queued in the TX FIFO immediately */
    ck_assert(!fifo_is_empty(&ts->sock.tcp.txbuf));
    {
        struct pkt_desc *desc = fifo_peek(&ts->sock.tcp.txbuf);
        struct wolfIP_tcp_seg *seg;
        ck_assert_ptr_nonnull(desc);
        seg = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
        ck_assert_uint_eq(seg->flags, (TCP_FLAG_SYN | TCP_FLAG_ACK));
    }
}
END_TEST

START_TEST(test_tcp_input_syn_sent_synack_without_sack_disables_sack)
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
    ts->sock.tcp.sack_offer = 1;
    ts->sock.tcp.sack_permitted = 1;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U, 4321, 1234, 10, 101, (TCP_FLAG_SYN | TCP_FLAG_ACK));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.sack_permitted, 0);
}
END_TEST

START_TEST(test_tcp_recv_partial_hole_fill_consumes_stored_ooo)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg_ooo_buf[sizeof(struct wolfIP_tcp_seg) + 10];
    uint8_t seg_in_buf[sizeof(struct wolfIP_tcp_seg) + 5];
    struct wolfIP_tcp_seg *seg_ooo = (struct wolfIP_tcp_seg *)seg_ooo_buf;
    struct wolfIP_tcp_seg *seg_in = (struct wolfIP_tcp_seg *)seg_in_buf;
    uint8_t out[16];

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

    memset(seg_ooo, 0, sizeof(seg_ooo_buf));
    seg_ooo->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    seg_ooo->hlen = TCP_HEADER_LEN << 2;
    seg_ooo->seq = ee32(105);
    memcpy(seg_ooo->data, "FGHIJKLMNO", 10);
    tcp_recv(ts, seg_ooo);
    ck_assert_uint_eq(ts->sock.tcp.ack, 100);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 1);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].left, 105);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].right, 115);

    memset(seg_in, 0, sizeof(seg_in_buf));
    seg_in->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 5);
    seg_in->hlen = TCP_HEADER_LEN << 2;
    seg_in->seq = ee32(100);
    memcpy(seg_in->data, "ABCDE", 5);
    tcp_recv(ts, seg_in);
    ck_assert_uint_eq(ts->sock.tcp.ack, 115);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 0);

    ck_assert_int_eq(queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out)), 15);
    ck_assert_mem_eq(out, "ABCDEFGHIJKLMNO", 15);
}
END_TEST

START_TEST(test_tcp_ack_ignores_sack_when_not_negotiated)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf1;
    struct tcp_seg_buf segbuf2;
    struct wolfIP_tcp_seg *seg1;
    struct wolfIP_tcp_seg *seg2;
    uint8_t ackbuf[sizeof(struct wolfIP_tcp_seg) + 12];
    struct wolfIP_tcp_seg *ackseg = (struct wolfIP_tcp_seg *)ackbuf;
    struct pkt_desc *desc;
    uint32_t left, right;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 0;
    ts->sock.tcp.seq = 102;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.bytes_in_flight = 2;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf1, 0, sizeof(segbuf1));
    seg1 = &segbuf1.seg;
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
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
    seg2->seq = ee32(101);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf2, sizeof(segbuf2)), 0);
    desc = fifo_next(&ts->sock.tcp.txbuf, desc);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(ackbuf, 0, sizeof(ackbuf));
    ackseg->ack = ee32(100);
    ackseg->hlen = (TCP_HEADER_LEN + 12) << 2;
    ackseg->flags = TCP_FLAG_ACK;
    ackseg->data[0] = TCP_OPTION_NOP;
    ackseg->data[1] = TCP_OPTION_NOP;
    ackseg->data[2] = TCP_OPTION_SACK;
    ackseg->data[3] = 10;
    left = ee32(101);
    right = ee32(102);
    memcpy(&ackseg->data[4], &left, sizeof(left));
    memcpy(&ackseg->data[8], &right, sizeof(right));

    tcp_ack(ts, ackseg);
    ck_assert_uint_eq(ts->sock.tcp.peer_sack_count, 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_uint_eq(ts->sock.tcp.dup_acks, 1);
}
END_TEST

START_TEST(test_tcp_ack_malformed_sack_does_not_early_retransmit)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    uint8_t ackbuf[sizeof(struct wolfIP_tcp_seg) + 12];
    struct wolfIP_tcp_seg *ackseg = (struct wolfIP_tcp_seg *)ackbuf;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 1;
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.bytes_in_flight = 1;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
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

    memset(ackbuf, 0, sizeof(ackbuf));
    ackseg->ack = ee32(100);
    ackseg->hlen = (TCP_HEADER_LEN + 12) << 2;
    ackseg->flags = TCP_FLAG_ACK;
    ackseg->data[0] = TCP_OPTION_NOP;
    ackseg->data[1] = TCP_OPTION_NOP;
    ackseg->data[2] = TCP_OPTION_SACK;
    ackseg->data[3] = 11; /* malformed length */
    ackseg->data[4] = 0;

    tcp_ack(ts, ackseg);
    ck_assert_uint_eq(ts->sock.tcp.peer_sack_count, 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_uint_eq(ts->sock.tcp.dup_acks, 1);
}
END_TEST

START_TEST(test_tcp_ack_early_retransmit_once_per_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf1;
    struct tcp_seg_buf segbuf2;
    struct wolfIP_tcp_seg *seg1;
    struct wolfIP_tcp_seg *seg2;
    uint8_t ackbuf[sizeof(struct wolfIP_tcp_seg) + 12];
    struct wolfIP_tcp_seg *ackseg = (struct wolfIP_tcp_seg *)ackbuf;
    struct pkt_desc *desc1, *desc2;
    uint32_t left, right;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 1;
    ts->sock.tcp.seq = 102;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.bytes_in_flight = 2;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf1, 0, sizeof(segbuf1));
    seg1 = &segbuf1.seg;
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg1->hlen = TCP_HEADER_LEN << 2;
    seg1->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf1, sizeof(segbuf1)), 0);
    desc1 = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc1);
    desc1->flags |= PKT_FLAG_SENT;

    memset(&segbuf2, 0, sizeof(segbuf2));
    seg2 = &segbuf2.seg;
    seg2->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg2->hlen = TCP_HEADER_LEN << 2;
    seg2->seq = ee32(101);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf2, sizeof(segbuf2)), 0);
    desc2 = fifo_next(&ts->sock.tcp.txbuf, desc1);
    ck_assert_ptr_nonnull(desc2);
    desc2->flags |= PKT_FLAG_SENT;

    memset(ackbuf, 0, sizeof(ackbuf));
    ackseg->ack = ee32(100);
    ackseg->hlen = (TCP_HEADER_LEN + 12) << 2;
    ackseg->flags = TCP_FLAG_ACK;
    ackseg->data[0] = TCP_OPTION_NOP;
    ackseg->data[1] = TCP_OPTION_NOP;
    ackseg->data[2] = TCP_OPTION_SACK;
    ackseg->data[3] = 10;
    left = ee32(101);
    right = ee32(102);
    memcpy(&ackseg->data[4], &left, sizeof(left));
    memcpy(&ackseg->data[8], &right, sizeof(right));

    tcp_ack(ts, ackseg);
    ck_assert_int_ne(desc1->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc2->flags & PKT_FLAG_SENT, 0);

    tcp_ack(ts, ackseg);
    ck_assert_int_eq(desc1->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc2->flags & PKT_FLAG_SENT, 0);

    desc1->flags |= PKT_FLAG_SENT; /* emulate transmit loop sending it again */
    tcp_ack(ts, ackseg);
    ck_assert_int_eq(desc1->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc2->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_tcp_ack_no_sack_requires_three_dupacks)
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
    ts->sock.tcp.sack_permitted = 0;
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.bytes_in_flight = 1;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
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
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
    tcp_ack(ts, &ackseg);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
    tcp_ack(ts, &ackseg);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_tcp_ack_no_sack_three_dupacks_with_zero_rwnd_triggers_retransmit)
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
    ts->sock.tcp.sack_permitted = 0;
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.bytes_in_flight = 1;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = 0;
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
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
    tcp_ack(ts, &ackseg);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
    tcp_ack(ts, &ackseg);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc->flags & PKT_FLAG_RETRANS, 0);
}
END_TEST

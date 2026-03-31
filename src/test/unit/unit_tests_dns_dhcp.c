static uint64_t find_timer_expiry(const struct wolfIP *s, uint32_t timer_id)
{
    uint32_t i;

    for (i = 0; i < s->timers.size; i++) {
        if (s->timers.timers[i].id == timer_id)
            return s->timers.timers[i].expires;
    }
    return 0;
}

static void build_dhcp_ack_msg(struct dhcp_msg *msg, uint32_t server_ip, uint32_t mask,
        uint32_t router_ip, uint32_t dns_ip)
{
    struct dhcp_option *opt;

    memset(msg, 0, sizeof(*msg));
    msg->op = BOOT_REPLY;
    msg->magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg->options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;
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
    opt->code = DHCP_OPTION_ROUTER;
    opt->len = 4;
    opt->data[0] = (router_ip >> 24) & 0xFF;
    opt->data[1] = (router_ip >> 16) & 0xFF;
    opt->data[2] = (router_ip >> 8) & 0xFF;
    opt->data[3] = (router_ip >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_DNS;
    opt->len = 4;
    opt->data[0] = (dns_ip >> 24) & 0xFF;
    opt->data[1] = (dns_ip >> 16) & 0xFF;
    opt->data[2] = (dns_ip >> 8) & 0xFF;
    opt->data[3] = (dns_ip >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;
}

START_TEST(test_dhcp_option_u32_macros_round_trip_wire_order)
{
    struct PACKED {
        struct dhcp_option opt;
        uint8_t data[4];
    } opt_buf;
    struct dhcp_option *opt = &opt_buf.opt;
    uint32_t value = 0x0A000001U;

    memset(&opt_buf, 0, sizeof(opt_buf));
    opt->len = 4;

    DHCP_OPT_u32_to_data(opt, value);

    ck_assert_uint_eq(opt->data[0], 0x0AU);
    ck_assert_uint_eq(opt->data[1], 0x00U);
    ck_assert_uint_eq(opt->data[2], 0x00U);
    ck_assert_uint_eq(opt->data[3], 0x01U);
    ck_assert_uint_eq(DHCP_OPT_data_to_u32(opt), value);
}
END_TEST

START_TEST(test_wolfip_static_instance_apis)
{
    struct wolfIP *s = NULL;

    wolfIP_init_static(NULL);
    wolfIP_init_static(&s);
    ck_assert_ptr_nonnull(s);
    ck_assert_uint_gt(wolfIP_instance_size(), 0U);
}
END_TEST
START_TEST(test_dhcp_parse_offer_and_ack)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct ipconf *primary;
    uint32_t offer_ip = 0x0A000064U;
    uint32_t server_ip = 0x0A000001U;
    uint32_t router_ip = 0x0A000002U;
    uint32_t dns_ip = 0x08080808U;
    uint32_t mask = 0xFFFFFF00U;
    uint32_t lease_s = 120U;

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
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, sizeof(msg)), 0);
    ck_assert_uint_eq(s.dhcp_ip, offer_ip);
    ck_assert_uint_eq(s.dhcp_server_ip, server_ip);
    ck_assert_uint_eq(primary->mask, mask);
    ck_assert_int_eq(s.dhcp_state, DHCP_REQUEST_SENT);
    s.last_tick = 1000U;

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;
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
    opt->code = DHCP_OPTION_DNS;
    opt->len = 4;
    opt->data[0] = (dns_ip >> 24) & 0xFF;
    opt->data[1] = (dns_ip >> 16) & 0xFF;
    opt->data[2] = (dns_ip >> 8) & 0xFF;
    opt->data[3] = (dns_ip >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_ROUTER;
    opt->len = 4;
    opt->data[0] = (router_ip >> 24) & 0xFF;
    opt->data[1] = (router_ip >> 16) & 0xFF;
    opt->data[2] = (router_ip >> 8) & 0xFF;
    opt->data[3] = (router_ip >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_LEASE_TIME;
    opt->len = 4;
    opt->data[0] = (lease_s >> 24) & 0xFF;
    opt->data[1] = (lease_s >> 16) & 0xFF;
    opt->data[2] = (lease_s >> 8) & 0xFF;
    opt->data[3] = (lease_s >> 0) & 0xFF;
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

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_BOUND);
    ck_assert_uint_eq(primary->ip, offer_ip);
    ck_assert_uint_eq(primary->mask, mask);
    ck_assert_uint_eq(primary->gw, router_ip);
    ck_assert_uint_eq(s.dns_server, dns_ip);
    ck_assert_int_ne(s.dhcp_timer, NO_TIMER);
    ck_assert_uint_eq(find_timer_expiry(&s, s.dhcp_timer), 61000U);
}
END_TEST

START_TEST(test_dhcp_schedule_lease_timer_defaults_t1_t2)
{
    struct wolfIP s;

    wolfIP_init(&s);
    s.last_tick = 1000U;

    dhcp_schedule_lease_timer(&s, 120U, 0, 0);

    ck_assert_int_ne(s.dhcp_timer, NO_TIMER);
    ck_assert_uint_eq(s.dhcp_renew_at, 61000U);
    ck_assert_uint_eq(s.dhcp_rebind_at, 106000U);
    ck_assert_uint_eq(s.dhcp_lease_expires, 121000U);
    ck_assert_uint_eq(find_timer_expiry(&s, s.dhcp_timer), s.dhcp_renew_at);
}
END_TEST

START_TEST(test_dhcp_schedule_lease_timer_small_lease_clamps_t1_t2)
{
    struct wolfIP s;

    wolfIP_init(&s);
    s.last_tick = 1000U;

    dhcp_schedule_lease_timer(&s, 1U, 0, 0);

    ck_assert_int_ne(s.dhcp_timer, NO_TIMER);
    ck_assert_uint_eq(s.dhcp_renew_at, 2000U);
    ck_assert_uint_eq(s.dhcp_rebind_at, 2000U);
    ck_assert_uint_eq(s.dhcp_lease_expires, 2000U);
    ck_assert_uint_eq(find_timer_expiry(&s, s.dhcp_timer), s.dhcp_renew_at);
}
END_TEST

START_TEST(test_dhcp_parse_offer_defaults_mask_when_missing)
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
    msg.yiaddr = ee32(offer_ip);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_OFFER;
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

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, sizeof(msg)), 0);
    ck_assert_uint_eq(s.dhcp_ip, offer_ip);
    ck_assert_uint_eq(s.dhcp_server_ip, server_ip);
    ck_assert_uint_eq(primary->mask, mask);
    ck_assert_int_eq(s.dhcp_state, DHCP_REQUEST_SENT);
}
END_TEST

START_TEST(test_sock_recvfrom_tcp_states)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t payload[4] = {1, 2, 3, 4};
    uint8_t buf[4];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];

    ts->sock.tcp.state = TCP_SYN_SENT;
    ret = wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, -1);

    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    ret = wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, 0);

    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->events = 0;
    ret = wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);

    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    ck_assert_int_eq(queue_insert(&ts->sock.tcp.rxbuf, payload, 0, sizeof(payload)), 0);
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ret = wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, sizeof(payload));
    ck_assert_mem_eq(buf, payload, sizeof(payload));

    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    ck_assert_int_eq(queue_insert(&ts->sock.tcp.rxbuf, payload, 0, sizeof(payload)), 0);
    ts->sock.tcp.state = TCP_FIN_WAIT_2;
    ret = wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, sizeof(payload));
    ck_assert_mem_eq(buf, payload, sizeof(payload));
}
END_TEST

START_TEST(test_sock_opts_unknown_level)
{
    struct wolfIP s;
    int udp_sd;
    int value = 1;
    socklen_t len = sizeof(value);

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, 0xFFFF, 0, &value, len), 0);
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, 0xFFFF, 0, &value, &len), 0);
}
END_TEST

START_TEST(test_sock_opts_sol_ip_unknown_optname)
{
    struct wolfIP s;
    int udp_sd;
    int value = 1;
    socklen_t len = sizeof(value);

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP, 0xFFFF, &value, len), 0);
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, 0xFFFF, &value, &len), 0);
}
END_TEST

START_TEST(test_sock_accept_wrong_state)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;

    ck_assert_int_eq(wolfIP_sock_accept(&s, tcp_sd, NULL, NULL), -1);
}
END_TEST
START_TEST(test_sock_opts_and_names)
{
    struct wolfIP s;
    int udp_sd;
    int tcp_sd;
    int enable = 1;
    int ttl = 0;
    socklen_t optlen;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_sockaddr_in peer;
    socklen_t sin_len = sizeof(sin);
    socklen_t peer_len = sizeof(peer);
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL,
            &enable, sizeof(enable)), 0);
    s.udpsockets[SOCKET_UNMARK(udp_sd)].last_pkt_ttl = 42;
    ck_assert_int_eq(wolfIP_sock_get_recv_ttl(&s, udp_sd, &ttl), 1);
    ck_assert_int_eq(ttl, 42);

    optlen = sizeof(ttl);
    ttl = 0;
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL,
            &ttl, &optlen), 0);
    ck_assert_int_eq(ttl, 1);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(local_ip);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    memset(&sin, 0, sizeof(sin));
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, &sin_len), 0);
    ck_assert_uint_eq(sin.sin_port, ee16(1234));
    ck_assert_uint_eq(sin.sin_addr.s_addr, ee32(local_ip));

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->src_port = 4321;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->dst_port = 2222;

    memset(&sin, 0, sizeof(sin));
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, &sin_len), 0);
    ck_assert_uint_eq(sin.sin_port, ee16(4321));
    ck_assert_uint_eq(sin.sin_addr.s_addr, ee32(local_ip));

    memset(&peer, 0, sizeof(peer));
    ck_assert_int_eq(wolfIP_sock_getpeername(&s, tcp_sd, (struct wolfIP_sockaddr *)&peer, &peer_len), 0);
    ck_assert_uint_eq(peer.sin_port, ee16(2222));
    ck_assert_uint_eq(peer.sin_addr.s_addr, ee32(remote_ip));
}
END_TEST

START_TEST(test_sock_get_recv_ttl_disabled)
{
    struct wolfIP s;
    int udp_sd;
    int ttl = 123;
    socklen_t len = sizeof(ttl);

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_get_recv_ttl(&s, udp_sd, &ttl), 0);
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &ttl, &len), 0);
    ck_assert_int_eq(ttl, 0);
}
END_TEST

START_TEST(test_sock_get_recv_ttl_null)
{
    struct wolfIP s;
    int udp_sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    s.udpsockets[SOCKET_UNMARK(udp_sd)].recv_ttl = 1;
    s.udpsockets[SOCKET_UNMARK(udp_sd)].last_pkt_ttl = 99;

    ck_assert_int_eq(wolfIP_sock_get_recv_ttl(&s, udp_sd, NULL), 1);
}
END_TEST

START_TEST(test_sock_connect_tcp_states)
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
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ts->sock.tcp.state = TCP_SYN_SENT;
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);

    ts->sock.tcp.state = TCP_ESTABLISHED;
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
}
END_TEST

START_TEST(test_sock_listen_errors)
{
    struct wolfIP s;
    int udp_sd;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, udp_sd, 1), -1);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ck_assert_int_eq(wolfIP_sock_listen(&s, tcp_sd, 1), -1);

    ts->sock.tcp.state = TCP_CLOSED;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    filter_block_reason = WOLFIP_FILT_LISTENING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_LISTENING));
    ck_assert_int_eq(wolfIP_sock_listen(&s, tcp_sd, 1), -1);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSED);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
}
END_TEST

START_TEST(test_sock_getpeername_errors)
{
    struct wolfIP s;
    int tcp_sd;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t len = 1;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_getpeername(&s, -1, (struct wolfIP_sockaddr *)&sin, &len), -WOLFIP_EINVAL);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_getpeername(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, &len), -1);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_getpeername(&s, tcp_sd, NULL, &len), -1);
    ck_assert_int_eq(wolfIP_sock_getpeername(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, &len), -1);
    ck_assert_int_eq(wolfIP_sock_getpeername(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, NULL), -1);
}
END_TEST

START_TEST(test_sock_getsockname_errors)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t len = 1;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_getsockname(&s, -1, (struct wolfIP_sockaddr *)&sin, &len), -WOLFIP_EINVAL);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, &len), -1);
}
END_TEST

START_TEST(test_sock_getsockname_null_addr)
{
    struct wolfIP s;
    int tcp_sd;
    socklen_t len = sizeof(struct wolfIP_sockaddr_in);

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, tcp_sd, NULL, &len), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_getsockname_invalid_socket_ids)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    socklen_t len = sizeof(sin);

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_getsockname(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, &len), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, &len), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, &len), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_getsockname_icmp_success)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t len = sizeof(sin);
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->src_port = 7;
    ts->local_ip = 0x0A000001U;

    ck_assert_int_eq(wolfIP_sock_getsockname(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, &len), 0);
    ck_assert_uint_eq(sin.sin_family, AF_INET);
    ck_assert_uint_eq(sin.sin_port, ee16(7));
    ck_assert_uint_eq(sin.sin_addr.s_addr, ee32(0x0A000001U));
}
END_TEST

START_TEST(test_sock_socket_udp_protocol_zero)
{
    struct wolfIP s;
    int udp_sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_gt(udp_sd, 0);
}
END_TEST

START_TEST(test_sock_socket_full_tables)
{
    struct wolfIP s;
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);

    for (i = 0; i < MAX_TCPSOCKETS; i++)
        s.tcpsockets[i].proto = WI_IPPROTO_TCP;
    ck_assert_int_eq(wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP), -1);

    for (i = 0; i < MAX_UDPSOCKETS; i++)
        s.udpsockets[i].proto = WI_IPPROTO_UDP;
    ck_assert_int_eq(wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP), -1);

    for (i = 0; i < MAX_ICMPSOCKETS; i++)
        s.icmpsockets[i].proto = WI_IPPROTO_ICMP;
    ck_assert_int_eq(wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP), -1);
}
END_TEST

START_TEST(test_register_callback_variants)
{
    struct wolfIP s;
    int tcp_sd;
    int udp_sd;
    int icmp_sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);

    wolfIP_register_callback(&s, -1, test_socket_cb, NULL);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    wolfIP_register_callback(&s, tcp_sd, test_socket_cb, NULL);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ck_assert_ptr_eq(ts->callback, test_socket_cb);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    wolfIP_register_callback(&s, udp_sd, test_socket_cb, NULL);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ck_assert_ptr_eq(ts->callback, test_socket_cb);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    wolfIP_register_callback(&s, icmp_sd, test_socket_cb, NULL);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ck_assert_ptr_eq(ts->callback, test_socket_cb);

    wolfIP_register_callback(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS, test_socket_cb, NULL);
    wolfIP_register_callback(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS, test_socket_cb, NULL);
    wolfIP_register_callback(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS, test_socket_cb, NULL);
}
END_TEST

START_TEST(test_sock_connect_udp_bound_ip_not_local)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->bound_local_ip = 0x0A0000FEU;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5555);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)),
            -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_udp_bound_ip_success)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->bound_local_ip = local_ip;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5555);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, local_ip);
    ck_assert_uint_eq(ts->if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_sock_connect_udp_primary_fallback)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5555);
    sin.sin_addr.s_addr = ee32(0xC0A80199U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST

START_TEST(test_sock_connect_icmp_primary_fallback)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = ee32(0xC0A80199U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST

START_TEST(test_sock_connect_tcp_filter_drop)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    filter_block_reason = WOLFIP_FILT_CONNECTING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_CONNECTING));

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5555);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSED);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
}
END_TEST

START_TEST(test_dhcp_send_request_renewing_sets_ciaddr_and_rebind_deadline)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct ipconf *primary;
    struct pkt_desc *desc;
    struct wolfIP_udp_datagram *udp;
    struct dhcp_msg *req;

    wolfIP_init(&s);
    mock_link_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    primary->ip = 0x0A000064U;
    primary->mask = 0xFFFFFF00U;
    s.dhcp_server_ip = 0x0A000001U;
    s.dhcp_ip = primary->ip;
    s.dhcp_state = DHCP_RENEWING;
    s.dhcp_rebind_at = 1500U;
    s.last_tick = 1000U;

    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dhcp_udp_sd)];

    ck_assert_int_eq(dhcp_send_request(&s), 0);
    ck_assert_uint_eq(ts->remote_ip, s.dhcp_server_ip);
    ck_assert_uint_eq(find_timer_expiry(&s, s.dhcp_timer), s.dhcp_rebind_at);

    desc = fifo_peek(&ts->sock.udp.txbuf);
    ck_assert_ptr_nonnull(desc);
    udp = (struct wolfIP_udp_datagram *)(ts->txmem + desc->pos + sizeof(*desc));
    req = (struct dhcp_msg *)udp->data;
    ck_assert_uint_eq(req->ciaddr, ee32(primary->ip));
}
END_TEST

START_TEST(test_dhcp_send_request_rebinding_broadcasts_to_lease_expiry)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct ipconf *primary;
    struct pkt_desc *desc;
    struct wolfIP_udp_datagram *udp;
    struct dhcp_msg *req;

    wolfIP_init(&s);
    mock_link_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    primary->ip = 0x0A000064U;
    primary->mask = 0xFFFFFF00U;
    s.dhcp_server_ip = 0x0A000001U;
    s.dhcp_ip = primary->ip;
    s.dhcp_state = DHCP_REBINDING;
    s.dhcp_lease_expires = 1300U;
    s.last_tick = 1000U;

    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dhcp_udp_sd)];

    ck_assert_int_eq(dhcp_send_request(&s), 0);
    ck_assert_uint_eq(ts->remote_ip, 0xFFFFFFFFU);
    ck_assert_uint_eq(find_timer_expiry(&s, s.dhcp_timer), s.dhcp_lease_expires);

    desc = fifo_peek(&ts->sock.udp.txbuf);
    ck_assert_ptr_nonnull(desc);
    udp = (struct wolfIP_udp_datagram *)(ts->txmem + desc->pos + sizeof(*desc));
    req = (struct dhcp_msg *)udp->data;
    ck_assert_uint_eq(req->ciaddr, ee32(primary->ip));
}
END_TEST

START_TEST(test_dhcp_send_request_send_failure_retries_next_tick)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct ipconf *primary;
    uint8_t tiny[2];

    wolfIP_init(&s);
    mock_link_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    primary->ip = 0x0A000064U;
    primary->mask = 0xFFFFFF00U;
    s.dhcp_server_ip = 0x0A000001U;
    s.dhcp_ip = primary->ip;
    s.dhcp_xid = 1U;
    s.dhcp_state = DHCP_REQUEST_SENT;
    s.last_tick = 1000U;

    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dhcp_udp_sd)];
    fifo_init(&ts->sock.udp.txbuf, tiny, sizeof(tiny));

    ck_assert_int_eq(dhcp_send_request(&s), -WOLFIP_EAGAIN);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.txbuf), NULL);
    ck_assert_uint_eq(ts->local_ip, 0U);
    ck_assert_uint_eq(find_timer_expiry(&s, s.dhcp_timer), s.last_tick + 1U);
}
END_TEST

START_TEST(test_dhcp_send_discover_send_failure_retries_next_tick)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t tiny[2];

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_xid = 1U;
    s.last_tick = 1000U;

    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dhcp_udp_sd)];
    fifo_init(&ts->sock.udp.txbuf, tiny, sizeof(tiny));

    ck_assert_int_eq(dhcp_send_discover(&s), -WOLFIP_EAGAIN);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.txbuf), NULL);
    ck_assert_int_eq(s.dhcp_state, DHCP_DISCOVER_SENT);
    ck_assert_uint_eq(find_timer_expiry(&s, s.dhcp_timer), s.last_tick + 1U);
}
END_TEST

START_TEST(test_dhcp_messages_set_secs_from_process_start)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;
    struct wolfIP_udp_datagram *udp;
    struct dhcp_msg *msg;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_xid = 1U;
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dhcp_udp_sd)];

    s.dhcp_state = DHCP_DISCOVER_SENT;
    s.dhcp_start_tick = 1000U;
    s.last_tick = 3500U;
    ck_assert_int_eq(dhcp_send_discover(&s), 0);

    desc = fifo_peek(&ts->sock.udp.txbuf);
    ck_assert_ptr_nonnull(desc);
    udp = (struct wolfIP_udp_datagram *)(ts->txmem + desc->pos + sizeof(*desc));
    msg = (struct dhcp_msg *)udp->data;
    ck_assert_uint_eq(ee16(msg->secs), 2U);

    ck_assert_ptr_nonnull(fifo_pop(&ts->sock.udp.txbuf));
    s.dhcp_state = DHCP_REQUEST_SENT;
    s.last_tick = 4200U;
    ck_assert_int_eq(dhcp_send_request(&s), 0);

    desc = fifo_peek(&ts->sock.udp.txbuf);
    ck_assert_ptr_nonnull(desc);
    udp = (struct wolfIP_udp_datagram *)(ts->txmem + desc->pos + sizeof(*desc));
    msg = (struct dhcp_msg *)udp->data;
    ck_assert_uint_eq(ee16(msg->secs), 3U);
}
END_TEST

START_TEST(test_sock_connect_tcp_src_port_low)
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
    ts->sock.tcp.state = TCP_CLOSED;
    ts->src_port = 1;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5555);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_uint_eq(ts->src_port, 1025);
}
END_TEST

START_TEST(test_sock_connect_tcp_initial_seq_randomized)
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
    ts->sock.tcp.state = TCP_CLOSED;
    ts->src_port = 23456;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5555);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)),
            -WOLFIP_EAGAIN);
    ck_assert_uint_ne(ts->sock.tcp.seq, 0U);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, ts->sock.tcp.seq);
}
END_TEST

START_TEST(test_sock_sendto_more_error_paths)
{
    struct wolfIP s;
    int tcp_sd;
    int udp_sd;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[64];
    uint8_t tiny[128];
    uint8_t tiny_udp[32];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    fifo_init(&ts->sock.tcp.txbuf, tiny, sizeof(tiny));
    ret = wolfIP_sock_sendto(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, -1);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    fifo_init(&ts->sock.udp.txbuf, tiny_udp, sizeof(tiny_udp));
    ret = wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, -1);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ret = wolfIP_sock_sendto(&s, icmp_sd, NULL, 0, 0, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_no_dest)
{
    struct wolfIP s;
    int udp_sd;
    uint8_t buf[4] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0, NULL, 0), -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_addrlen_short)
{
    struct wolfIP s;
    int udp_sd;
    uint8_t buf[4] = {0};
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, 1), -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_len_too_large)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[WI_IP_MTU] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf,
            (size_t)(WI_IP_MTU - IP_HEADER_LEN - UDP_HEADER_LEN + 1), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_fifo_full)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t tiny[2];
    uint8_t buf[4] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    fifo_init(&ts->sock.udp.txbuf, tiny, sizeof(tiny));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_sendto_icmp_len_invalid)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[ICMP_HEADER_LEN - 1] = {0};
    uint8_t bigbuf[WI_IP_MTU] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, bigbuf,
            (size_t)(WI_IP_MTU - IP_HEADER_LEN + 1), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_sendto_icmp_fifo_full)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t tiny[2];
    uint8_t buf[ICMP_HEADER_LEN] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    fifo_init(&ts->sock.udp.txbuf, tiny, sizeof(tiny));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_sendto_icmp_addrlen_short)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[ICMP_HEADER_LEN] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, 1), -1);
}
END_TEST

START_TEST(test_sock_sendto_icmp_remote_zero)
{
    struct wolfIP s;
    int icmp_sd;
    uint8_t buf[ICMP_HEADER_LEN] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, buf, sizeof(buf), 0, NULL, 0), -1);
}
END_TEST

START_TEST(test_sock_sendto_tcp_txbuf_full)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t buf[8] = {0};
    uint8_t tiny[16];

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    fifo_init(&ts->sock.tcp.txbuf, tiny, sizeof(tiny));

    ck_assert_int_eq(wolfIP_sock_sendto(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_sendto_tcp_partial_send_only)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    size_t seg_payload = TCP_MSS - TCP_OPTIONS_LEN;
    size_t payload_len = seg_payload;
    uint8_t buf[seg_payload * 2];
    size_t required = sizeof(struct pkt_desc) + sizeof(struct wolfIP_tcp_seg) +
        TCP_OPTIONS_LEN + payload_len;
    /* Provide a small alignment cushion so one segment fits but two do not. */
    uint8_t txbuf[required + 8];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    fifo_init(&ts->sock.tcp.txbuf, txbuf, sizeof(txbuf));

    memset(buf, 0xAB, sizeof(buf));
    /* Expect a partial send because the tx buffer fits only one segment
     * (includes full TCP/IP header size and alignment padding). */
    ret = wolfIP_sock_sendto(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_msg(ret > 0, "expected partial send, got %d", ret);
}
END_TEST

START_TEST(test_sock_sendto_udp_fifo_push_fails_returns_eagain)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    uint8_t txbuf[4096];
    enum { UDP_PAYLOAD_LEN =
        (WI_IP_MTU - IP_HEADER_LEN - UDP_HEADER_LEN) > 1000
            ? 1000
            : (WI_IP_MTU - IP_HEADER_LEN - UDP_HEADER_LEN)
    };
    uint8_t payload[UDP_PAYLOAD_LEN];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->dst_port = 4321;
    ts->remote_ip = 0x0A000002U;
    ts->local_ip = 0x0A000001U;

    fifo_init(&ts->sock.udp.txbuf, txbuf, sizeof(txbuf));
    ts->sock.udp.txbuf.head = 100;
    ts->sock.udp.txbuf.tail = 100 + UDP_PAYLOAD_LEN;
    ts->sock.udp.txbuf.h_wrap = 3000;

    memset(payload, 0xEE, sizeof(payload));
    ret = wolfIP_sock_sendto(&s, udp_sd, payload, sizeof(payload), 0, NULL, 0);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_sendto_icmp_fifo_push_fails_returns_eagain)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    uint8_t txbuf[4096];
    enum { ICMP_PAYLOAD_LEN =
        (WI_IP_MTU - IP_HEADER_LEN) > 1000
            ? 1000
            : (WI_IP_MTU - IP_HEADER_LEN)
    };
    uint8_t payload[ICMP_PAYLOAD_LEN];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->remote_ip = 0x0A000002U;

    fifo_init(&ts->sock.udp.txbuf, txbuf, sizeof(txbuf));
    ts->sock.udp.txbuf.head = 100;
    ts->sock.udp.txbuf.tail = 100 + ICMP_PAYLOAD_LEN;
    ts->sock.udp.txbuf.h_wrap = 3000;

    memset(payload, 0xEE, sizeof(payload));
    payload[0] = ICMP_ECHO_REQUEST;
    ret = wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0, NULL, 0);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_recvfrom_icmp_paths)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct {
        struct wolfIP_icmp_packet icmp;
        uint8_t payload[2];
    } icmp_frame;
    struct pkt_desc *desc;
    uint8_t rxbuf[ICMP_HEADER_LEN + 2];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    fifo_init(&ts->sock.udp.rxbuf, ts->rxmem, RXBUF_SIZE);

    ret = wolfIP_sock_recvfrom(&s, icmp_sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);

    memset(&icmp_frame, 0, sizeof(icmp_frame));
    icmp_frame.icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN + sizeof(icmp_frame.payload));
    icmp_frame.icmp.type = ICMP_ECHO_REPLY;
    icmp_frame.icmp.code = 0;
    {
        uint8_t *payload = ((uint8_t *)&icmp_frame.icmp.type) + ICMP_HEADER_LEN;
        payload[0] = 0xAA;
        payload[1] = 0xBB;
    }
    ck_assert_int_eq(fifo_push(&ts->sock.udp.rxbuf, &icmp_frame, sizeof(icmp_frame)), 0);
    desc = fifo_peek(&ts->sock.udp.rxbuf);
    ck_assert_ptr_nonnull(desc);

    ret = wolfIP_sock_recvfrom(&s, icmp_sd, rxbuf, (size_t)(ICMP_HEADER_LEN - 1), 0, NULL, NULL);
    ck_assert_int_eq(ret, -1);

    ret = wolfIP_sock_recvfrom(&s, icmp_sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

#ifdef DEBUG_UDP
START_TEST(test_wolfip_print_udp_short_len_no_oob)
{
    struct wolfIP_udp_datagram udp;

    memset(&udp, 0, sizeof(udp));
    udp.len = ee16(4); /* Invalid: shorter than UDP header. */
    wolfIP_print_udp(&udp);
}
END_TEST
#endif

START_TEST(test_sock_recvfrom_icmp_readable_stays_when_queue_nonempty)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct {
        struct wolfIP_icmp_packet icmp;
        uint8_t payload[2];
    } icmp_frame;
    uint8_t rxbuf[ICMP_HEADER_LEN + 2];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    fifo_init(&ts->sock.udp.rxbuf, ts->rxmem, RXBUF_SIZE);

    memset(&icmp_frame, 0, sizeof(icmp_frame));
    icmp_frame.icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN + sizeof(icmp_frame.payload));
    icmp_frame.icmp.type = ICMP_ECHO_REPLY;
    icmp_frame.icmp.code = 0;
    icmp_frame.payload[0] = 0xAA;
    icmp_frame.payload[1] = 0xBB;
    ck_assert_int_eq(fifo_push(&ts->sock.udp.rxbuf, &icmp_frame, sizeof(icmp_frame)), 0);
    ck_assert_int_eq(fifo_push(&ts->sock.udp.rxbuf, &icmp_frame, sizeof(icmp_frame)), 0);

    ts->events |= CB_EVENT_READABLE;
    ret = wolfIP_sock_recvfrom(&s, icmp_sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, ICMP_HEADER_LEN + 2);
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.rxbuf));
    ck_assert_uint_ne(ts->events & CB_EVENT_READABLE, 0U);
}
END_TEST

START_TEST(test_sock_recvfrom_udp_short_addrlen)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = 1;
    uint8_t buf[8];

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, &alen), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_recvfrom_icmp_short_addrlen)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = 1;
    uint8_t buf[8];

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, icmp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, &alen), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_recvfrom_udp_fifo_alignment)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in from;
    socklen_t from_len;
    uint8_t buf[16];
    uint8_t payload1[3] = {0xA1, 0xA2, 0xA3};
    uint8_t payload2[5] = {0xB1, 0xB2, 0xB3, 0xB4, 0xB5};
    uint8_t payload3[7] = {0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7};
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 1234;

    enqueue_udp_rx(ts, payload1, sizeof(payload1), 1111);
    enqueue_udp_rx(ts, payload2, sizeof(payload2), 2222);
    enqueue_udp_rx(ts, payload3, sizeof(payload3), 3333);

    memset(buf, 0, sizeof(buf));
    ret = wolfIP_sock_recv(&s, udp_sd, buf, sizeof(buf), 0);
    ck_assert_int_eq(ret, (int)sizeof(payload1));
    ck_assert_mem_eq(buf, payload1, sizeof(payload1));

    memset(&from, 0, sizeof(from));
    from_len = sizeof(from);
    memset(buf, 0, sizeof(buf));
    ret = wolfIP_sock_recvfrom(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len);
    ck_assert_int_eq(ret, (int)sizeof(payload2));
    ck_assert_mem_eq(buf, payload2, sizeof(payload2));
    ck_assert_uint_eq(from.sin_port, ee16(2222));
    ck_assert_uint_eq(from_len, sizeof(from));

    memset(buf, 0, sizeof(buf));
    ret = wolfIP_sock_recv(&s, udp_sd, buf, sizeof(buf), 0);
    ck_assert_int_eq(ret, (int)sizeof(payload3));
    ck_assert_mem_eq(buf, payload3, sizeof(payload3));

    ret = wolfIP_sock_recv(&s, udp_sd, buf, sizeof(buf), 0);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_recvfrom_udp_payload_too_long)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[16] = {0};
    uint8_t rxbuf[4];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    inject_udp_datagram(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U, 4321, 1234,
            payload, sizeof(payload));

    ret = wolfIP_sock_recvfrom(&s, udp_sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
    ck_assert_ptr_eq(fifo_peek(&s.udpsockets[SOCKET_UNMARK(udp_sd)].sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_sock_recvfrom_udp_readable_stays_when_queue_nonempty)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    uint8_t payload1[2] = {0xAA, 0xBB};
    uint8_t payload2[2] = {0xCC, 0xDD};
    uint8_t buf[4];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 1234;

    enqueue_udp_rx(ts, payload1, sizeof(payload1), 1111);
    enqueue_udp_rx(ts, payload2, sizeof(payload2), 2222);
    ts->events |= CB_EVENT_READABLE;

    memset(buf, 0, sizeof(buf));
    ret = wolfIP_sock_recvfrom(&s, udp_sd, buf, sizeof(buf), 0, NULL, NULL);
    ck_assert_int_eq(ret, (int)sizeof(payload1));
    ck_assert_mem_eq(buf, payload1, sizeof(payload1));
    ck_assert_uint_ne(ts->events & CB_EVENT_READABLE, 0U);
}
END_TEST

START_TEST(test_sock_recvfrom_icmp_payload_too_long)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_icmp_packet icmp;
    uint8_t rxbuf[4];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN + 8);
    fifo_push(&ts->sock.udp.rxbuf, &icmp, sizeof(icmp));

    ret = wolfIP_sock_recvfrom(&s, icmp_sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, -1);
}
END_TEST

START_TEST(test_icmp_input_echo_reply_queues)
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
    icmp.ip.src = ee32(ts->remote_ip);
    icmp.ip.dst = ee32(ts->local_ip);
    icmp.ip.ttl = 55;
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REPLY;
    icmp_set_echo_id(&icmp, ts->src_port);
    icmp.csum = ee16(icmp_checksum(&icmp, ICMP_HEADER_LEN));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.rxbuf));
    ck_assert_uint_eq(ts->last_pkt_ttl, 55);
}
END_TEST

START_TEST(test_icmp_input_echo_request_reply_sent)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    struct wolfIP_icmp_packet *reply;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_OFF;
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.ttl = 1;
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    icmp.csum = ee16(icmp_checksum(&icmp, ICMP_HEADER_LEN));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_gt(last_frame_sent_size, 0);
    reply = (struct wolfIP_icmp_packet *)last_frame_sent;
    ck_assert_uint_eq(reply->type, ICMP_ECHO_REPLY);
    ck_assert_uint_eq(reply->ip.ttl, 64);
}
END_TEST

START_TEST(test_icmp_input_echo_request_bad_checksum_dropped)
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
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    icmp.csum = ee16(icmp_checksum(&icmp, ICMP_HEADER_LEN));
    icmp.csum ^= ee16(0x0001);
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);

    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_icmp_input_echo_request_odd_len_reply_checksum)
{
    struct wolfIP s;
    uint8_t frame[sizeof(struct wolfIP_icmp_packet) + 1];
    struct wolfIP_ip_packet *ip;
    struct wolfIP_icmp_packet *icmp;
    struct wolfIP_icmp_packet *reply;
    uint32_t frame_len;
    uint16_t icmp_len;
    uint32_t sum;
    uint16_t word;
    uint32_t i;
    const uint8_t *ptr;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_OFF;
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(frame, 0, sizeof(frame));
    ip   = (struct wolfIP_ip_packet  *)frame;
    icmp = (struct wolfIP_icmp_packet *)frame;

    icmp_len = ICMP_HEADER_LEN + 1;

    ip->src     = ee32(0x0A000002U);
    ip->dst     = ee32(0x0A000001U);
    ip->ttl     = 64;
    ip->len     = ee16(IP_HEADER_LEN + icmp_len);
    icmp->type  = ICMP_ECHO_REQUEST;
    icmp->code  = 0;
    icmp->csum  = 0;
    ((uint8_t *)&icmp->type)[ICMP_HEADER_LEN] = 0xAB;
    icmp->csum  = ee16(icmp_checksum(icmp, icmp_len));

    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + icmp_len);
    icmp_input(&s, TEST_PRIMARY_IF, ip, frame_len);

    ck_assert_uint_gt(last_frame_sent_size, 0);
    reply = (struct wolfIP_icmp_packet *)last_frame_sent;
    ck_assert_uint_eq(reply->type, ICMP_ECHO_REPLY);

    ptr = (const uint8_t *)(&reply->type);
    sum = 0;
    for (i = 0; i < (uint32_t)(icmp_len & ~1u); i += 2) {
        memcpy(&word, ptr + i, sizeof(word));
        sum += ee16(word);
    }
    if (icmp_len & 0x01) {
        uint16_t spare = 0;
        spare |= ptr[icmp_len - 1] << 8;
        sum += spare;
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    ck_assert_uint_eq(sum, 0xFFFFU);
}
END_TEST

START_TEST(test_icmp_input_echo_request_dhcp_running_no_reply)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_DISCOVER_SENT;
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    icmp.csum = ee16(icmp_checksum(&icmp, ICMP_HEADER_LEN));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_icmp_input_echo_request_broadcast_no_reply)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_OFF;
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0xFFFFFFFFU);
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    icmp.csum = ee16(icmp_checksum(&icmp, ICMP_HEADER_LEN));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_icmp_input_echo_request_directed_broadcast_no_reply)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    s.dhcp_state = DHCP_OFF;
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A0000FFU);
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    icmp.csum = ee16(icmp_checksum(&icmp, ICMP_HEADER_LEN));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_icmp_input_echo_request_filter_drop)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_OFF;
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_icmp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    icmp.csum = ee16(icmp_checksum(&icmp, ICMP_HEADER_LEN));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_icmp_mask(0);
}
END_TEST

START_TEST(test_icmp_input_echo_request_ip_filter_drop)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_OFF;
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_ip_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    icmp.csum = ee16(icmp_checksum(&icmp, ICMP_HEADER_LEN));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_ip_mask(0);
}
END_TEST

START_TEST(test_icmp_input_echo_request_eth_filter_drop)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_OFF;
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    icmp.csum = ee16(icmp_checksum(&icmp, ICMP_HEADER_LEN));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

START_TEST(test_icmp_input_filter_drop_receiving)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    filter_block_reason = WOLFIP_FILT_RECEIVING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_icmp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    icmp.csum = ee16(icmp_checksum(&icmp, ICMP_HEADER_LEN));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_icmp_mask(0);
}
END_TEST

START_TEST(test_icmp_input_dest_unreach_port_unreachable_keeps_established_tcp_socket)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_icmp_dest_unreachable_packet icmp;
    struct wolfIP_tcp_wire_prefix *orig;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->src_port = 1234;
    ts->dst_port = 4321;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A0000FEU);
    icmp.ip.dst = ee32(ts->local_ip);
    icmp.ip.ttl = 64;
    icmp.ip.proto = WI_IPPROTO_ICMP;
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_DEST_UNREACH_SIZE);
    icmp.type = ICMP_DEST_UNREACH;
    icmp.code = ICMP_PORT_UNREACH;

    orig = (struct wolfIP_tcp_wire_prefix *)icmp.orig_packet;
    orig->ip.ver_ihl = 0x45;
    orig->ip.proto = WI_IPPROTO_TCP;
    orig->ip.src = ee32(ts->local_ip);
    orig->ip.dst = ee32(ts->remote_ip);
    orig->ip.len = ee16(IP_HEADER_LEN + 8U);
    orig->src_port = ee16(ts->src_port);
    orig->dst_port = ee16(ts->dst_port);

    icmp.csum = ee16(icmp_checksum((struct wolfIP_icmp_packet *)&icmp,
                ICMP_DEST_UNREACH_SIZE));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_DEST_UNREACH_SIZE);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);

    ck_assert_uint_eq(ts->proto, WI_IPPROTO_TCP);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

START_TEST(test_icmp_input_dest_unreach_frag_needed_reduces_tcp_peer_mss)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_icmp_dest_unreachable_packet icmp;
    struct wolfIP_tcp_wire_prefix *orig;
    uint32_t frame_len;
    uint16_t next_hop_mtu;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->sock.tcp.peer_mss = 1200U;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A0000FEU);
    icmp.ip.dst = ee32(ts->local_ip);
    icmp.ip.ttl = 64;
    icmp.ip.proto = WI_IPPROTO_ICMP;
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_DEST_UNREACH_SIZE);
    icmp.type = ICMP_DEST_UNREACH;
    icmp.code = ICMP_FRAG_NEEDED;
    next_hop_mtu = ee16(576U);
    memcpy(&icmp.unused[2], &next_hop_mtu, sizeof(next_hop_mtu));

    orig = (struct wolfIP_tcp_wire_prefix *)icmp.orig_packet;
    orig->ip.ver_ihl = 0x45;
    orig->ip.proto = WI_IPPROTO_TCP;
    orig->ip.src = ee32(ts->local_ip);
    orig->ip.dst = ee32(ts->remote_ip);
    orig->ip.len = ee16(IP_HEADER_LEN + 8U);
    orig->src_port = ee16(ts->src_port);
    orig->dst_port = ee16(ts->dst_port);

    icmp.csum = ee16(icmp_checksum((struct wolfIP_icmp_packet *)&icmp,
                ICMP_DEST_UNREACH_SIZE));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_DEST_UNREACH_SIZE);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);

    ck_assert_uint_eq(ts->sock.tcp.peer_mss, 536U);
}
END_TEST

START_TEST(test_icmp_input_dest_unreach_port_unreachable_closes_syn_sent_tcp_socket)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_icmp_dest_unreachable_packet icmp;
    struct wolfIP_tcp_wire_prefix *orig;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->src_port = 1234;
    ts->dst_port = 4321;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A0000FEU);
    icmp.ip.dst = ee32(ts->local_ip);
    icmp.ip.ttl = 64;
    icmp.ip.proto = WI_IPPROTO_ICMP;
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_DEST_UNREACH_SIZE);
    icmp.type = ICMP_DEST_UNREACH;
    icmp.code = ICMP_PORT_UNREACH;

    orig = (struct wolfIP_tcp_wire_prefix *)icmp.orig_packet;
    orig->ip.ver_ihl = 0x45;
    orig->ip.proto = WI_IPPROTO_TCP;
    orig->ip.src = ee32(ts->local_ip);
    orig->ip.dst = ee32(ts->remote_ip);
    orig->ip.len = ee16(IP_HEADER_LEN + 8U);
    orig->src_port = ee16(ts->src_port);
    orig->dst_port = ee16(ts->dst_port);

    icmp.csum = ee16(icmp_checksum((struct wolfIP_icmp_packet *)&icmp,
                ICMP_DEST_UNREACH_SIZE));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_DEST_UNREACH_SIZE);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);

    ck_assert_uint_eq(ts->proto, 0U);
}
END_TEST

START_TEST(test_icmp_input_dest_unreach_port_unreachable_quoted_ip_options_keep_established_tcp_socket)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t packet[sizeof(struct wolfIP_icmp_dest_unreachable_packet) + 4];
    struct wolfIP_icmp_packet *icmp = (struct wolfIP_icmp_packet *)packet;
    struct wolfIP_ip_wire *orig_ip;
    uint8_t *orig_tcp;
    uint16_t port;
    uint32_t icmp_body_len;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->src_port = 1234;
    ts->dst_port = 4321;

    memset(packet, 0, sizeof(packet));
    icmp_body_len = ICMP_HEADER_LEN + 24U + 8U;
    icmp->ip.src = ee32(0x0A0000FEU);
    icmp->ip.dst = ee32(ts->local_ip);
    icmp->ip.ttl = 64;
    icmp->ip.proto = WI_IPPROTO_ICMP;
    icmp->ip.len = ee16(IP_HEADER_LEN + icmp_body_len);
    icmp->type = ICMP_DEST_UNREACH;
    icmp->code = ICMP_PORT_UNREACH;

    orig_ip = (struct wolfIP_ip_wire *)(packet + sizeof(struct wolfIP_icmp_packet));
    orig_ip->ver_ihl = 0x46;
    orig_ip->proto = WI_IPPROTO_TCP;
    orig_ip->src = ee32(ts->local_ip);
    orig_ip->dst = ee32(ts->remote_ip);
    orig_ip->len = ee16(24U + 8U);
    memset(orig_ip->data, 0xAB, 4);

    orig_tcp = ((uint8_t *)orig_ip) + 24U;
    port = ee16(ts->src_port);
    memcpy(orig_tcp, &port, sizeof(port));
    port = ee16(ts->dst_port);
    memcpy(orig_tcp + sizeof(port), &port, sizeof(port));

    icmp->csum = ee16(icmp_checksum(icmp, icmp_body_len));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + icmp_body_len);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)icmp, frame_len);

    ck_assert_uint_eq(ts->proto, WI_IPPROTO_TCP);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

START_TEST(test_dns_send_query_errors)
{
    struct wolfIP s;
    uint16_t id = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0;
    ck_assert_int_eq(dns_send_query(&s, "example.com", &id, DNS_A), -101);

    s.dns_server = 0x08080808U;
    s.dns_id = 123;
    ck_assert_int_eq(dns_send_query(&s, "example.com", &id, DNS_A), -16);
}
END_TEST

START_TEST(test_dns_schedule_timer_initial_jitter_and_cancel)
{
    struct wolfIP s;
    uint32_t timer_id;

    wolfIP_init(&s);
    s.last_tick = 100U;
    s.dns_retry_count = 0;
    test_rand_override_enabled = 1;
    test_rand_override_value = 390U;

    dns_schedule_timer(&s);
    ck_assert_int_ne(s.dns_timer, NO_TIMER);
    ck_assert_uint_eq(find_timer_expiry(&s, s.dns_timer), 2290U);

    timer_id = s.dns_timer;
    dns_cancel_timer(&s);
    ck_assert_int_eq(s.dns_timer, NO_TIMER);
    ck_assert_uint_eq(find_timer_expiry(&s, timer_id), 0U);

    s.dns_retry_count = 1;
    dns_schedule_timer(&s);
    ck_assert_int_ne(s.dns_timer, NO_TIMER);
    ck_assert_uint_eq(find_timer_expiry(&s, s.dns_timer), 4100U);

    test_rand_override_enabled = 0;
}
END_TEST

START_TEST(test_dns_schedule_timer_caps_large_retry_shift)
{
    struct wolfIP s;

    wolfIP_init(&s);
    s.last_tick = 100U;
    s.dns_retry_count = 64U;

    dns_schedule_timer(&s);
    ck_assert_int_ne(s.dns_timer, NO_TIMER);
    ck_assert_uint_eq(find_timer_expiry(&s, s.dns_timer), UINT64_MAX);
}
END_TEST

START_TEST(test_dns_send_query_schedules_timeout)
{
    struct wolfIP s;
    uint16_t id = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x08080808U;
    s.last_tick = 100U;
    test_rand_override_enabled = 1;
    test_rand_override_value = 390U;

    ck_assert_int_eq(dns_send_query(&s, "example.com", &id, DNS_A), 0);
    ck_assert_uint_ne(id, 0U);
    ck_assert_uint_eq(s.dns_id, id);
    ck_assert_int_ne(s.dns_timer, NO_TIMER);
    ck_assert_uint_eq(find_timer_expiry(&s, s.dns_timer), 2290U);
    test_rand_override_enabled = 0;
}
END_TEST

START_TEST(test_dns_send_query_send_failure_clears_outstanding_state)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint16_t id = 0;
    uint8_t tiny[2];

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x08080808U;
    s.last_tick = 100U;

    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)];
    fifo_init(&ts->sock.udp.txbuf, tiny, sizeof(tiny));

    ck_assert_int_eq(dns_send_query(&s, "example.com", &id, DNS_A), -WOLFIP_EAGAIN);
    ck_assert_uint_eq(id, 0U);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.txbuf), NULL);
    ck_assert_int_eq(s.dns_timer, NO_TIMER);
    ck_assert_uint_eq(s.dns_id, 0U);
    ck_assert_uint_eq(s.dns_retry_count, 0U);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
    ck_assert_uint_eq(s.dns_query_len, 0U);
}
END_TEST

START_TEST(test_dns_resend_query_uses_stored_query_buffer)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint16_t id = 0;
    uint32_t tx_before;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x08080808U;
    s.last_tick = 100U;
    test_rand_override_enabled = 1;
    test_rand_override_value = 1U;

    ck_assert_int_eq(dns_send_query(&s, "example.com", &id, DNS_A), 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)];
    tx_before = fifo_len(&ts->sock.udp.txbuf);
    ck_assert_uint_gt(s.dns_query_len, 0U);
    ck_assert_int_gt(dns_resend_query(&s), 0);
    ck_assert_uint_gt(fifo_len(&ts->sock.udp.txbuf), tx_before);

    test_rand_override_enabled = 0;
}
END_TEST

START_TEST(test_dns_resend_query_fails_without_valid_socket)
{
    struct wolfIP s;
    uint16_t id = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x08080808U;
    s.last_tick = 100U;
    test_rand_override_enabled = 1;
    test_rand_override_value = 2U;

    /* Seed a cached query, then invalidate the socket so resend must reject it. */
    ck_assert_int_eq(dns_send_query(&s, "example.com", &id, DNS_A), 0);
    ck_assert_uint_gt(s.dns_query_len, 0U);
    s.dns_udp_sd = 0;
    ck_assert_int_eq(dns_resend_query(&s), -1);

    test_rand_override_enabled = 0;
}
END_TEST

START_TEST(test_dns_resend_query_fails_without_cached_query_buffer)
{
    struct wolfIP s;
    uint16_t id = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x08080808U;
    s.last_tick = 100U;
    test_rand_override_enabled = 1;
    test_rand_override_value = 3U;

    /* A live DNS socket alone is not enough; resend needs a cached query payload as well. */
    ck_assert_int_eq(dns_send_query(&s, "example.com", &id, DNS_A), 0);
    ck_assert_int_gt(s.dns_udp_sd, 0);
    s.dns_query_len = 0U;
    ck_assert_int_eq(dns_resend_query(&s), -1);

    test_rand_override_enabled = 0;
}
END_TEST

START_TEST(test_dns_resend_query_fails_with_null_stack)
{
    ck_assert_int_eq(dns_resend_query(NULL), -1);
}
END_TEST

START_TEST(test_dns_abort_query_clears_timer_and_query_state)
{
    struct wolfIP s;
    uint32_t timer_id;

    wolfIP_init(&s);
    s.last_tick = 100U;
    s.dns_id = 0x1234U;
    s.dns_retry_count = 2U;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_query_len = 32U;
    s.dns_lookup_cb = test_dns_lookup_cb;
    s.dns_ptr_cb = test_dns_ptr_cb;
    test_rand_override_enabled = 1;
    test_rand_override_value = 0U;

    dns_schedule_timer(&s);
    timer_id = s.dns_timer;
    ck_assert_int_ne(timer_id, NO_TIMER);

    dns_abort_query(&s);
    ck_assert_int_eq(s.dns_timer, NO_TIMER);
    ck_assert_uint_eq(find_timer_expiry(&s, timer_id), 0U);
    ck_assert_uint_eq(s.dns_id, 0U);
    ck_assert_uint_eq(s.dns_retry_count, 0U);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
    ck_assert_uint_eq(s.dns_query_len, 0U);
    ck_assert_ptr_eq(s.dns_lookup_cb, NULL);
    ck_assert_ptr_eq(s.dns_ptr_cb, NULL);

    test_rand_override_enabled = 0;
}
END_TEST

START_TEST(test_dns_timeout_retries_then_aborts_and_allows_new_query)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint16_t id1 = 0;
    uint16_t id2 = 0;
    uint32_t tx_before;
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x08080808U;
    s.last_tick = 100U;
    test_rand_override_enabled = 1;
    test_rand_override_value = 1U;

    ck_assert_int_eq(dns_send_query(&s, "example.com", &id1, DNS_A), 0);
    ck_assert_uint_ne(id1, 0U);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)];
    tx_before = fifo_len(&ts->sock.udp.txbuf);

    ck_assert_int_eq(dns_send_query(&s, "example.net", &id2, DNS_A), -16);

    for (i = 0; i < DNS_QUERY_RETRIES; i++) {
        dns_timeout_cb(&s);
        ck_assert_uint_gt(fifo_len(&ts->sock.udp.txbuf), tx_before);
        tx_before = fifo_len(&ts->sock.udp.txbuf);
    }

    dns_timeout_cb(&s);
    ck_assert_uint_eq(s.dns_id, 0U);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
    ck_assert_ptr_eq(s.dns_lookup_cb, NULL);

    ck_assert_int_eq(dns_send_query(&s, "example.net", &id2, DNS_A), 0);
    ck_assert_uint_ne(id2, 0U);
    test_rand_override_enabled = 0;
}
END_TEST

START_TEST(test_dns_send_query_invalid_name)
{
    struct wolfIP s;
    uint16_t id = 0;
    char name[260];
    size_t pos = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x08080808U;
    s.dns_id = 0;

    memset(name, 'a', 64);
    name[64] = '.';
    memcpy(name + 65, "com", 3);
    name[68] = 0;
    ck_assert_int_eq(dns_send_query(&s, name, &id, DNS_A), -22);

    s.dns_id = 0;
    memset(name, 'a', sizeof(name));
    pos = 0;
    memset(name + pos, 'a', 63);
    pos += 63;
    name[pos++] = '.';
    memset(name + pos, 'b', 63);
    pos += 63;
    name[pos++] = '.';
    memset(name + pos, 'c', 63);
    pos += 63;
    name[pos++] = '.';
    memset(name + pos, 'd', 63);
    pos += 63;
    name[pos] = 0;
    ck_assert_int_eq(dns_send_query(&s, name, &id, DNS_A), -22);
}
END_TEST
START_TEST(test_fifo_push_and_pop) {
    struct fifo f;
    struct pkt_desc *desc, *desc2;
    uint8_t data[] = {1, 2, 3, 4, 5};

    fifo_init(&f, mem, memsz);

    ck_assert_int_eq(fifo_space(&f), memsz);
    /* Push one payload and verify descriptors reflect its size. */
    ck_assert_int_eq(fifo_push(&f, data, sizeof(data)), 0);

    /* Peek should return the current head descriptor without consuming data. */
    desc = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->len, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data));
    desc2 = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc2);
    ck_assert_ptr_eq(desc, desc2);
    ck_assert_int_eq(fifo_len(&f), desc->len + sizeof(struct pkt_desc));


    /* Pop should consume the packet and restore full space. */
    desc = fifo_pop(&f);
    ck_assert_int_eq(fifo_space(&f), memsz);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->len, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data));
    ck_assert_ptr_eq(fifo_peek(&f), NULL);
}
END_TEST

START_TEST(test_sock_accept_success)
{
    struct wolfIP s;
    int listen_sd;
    int new_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = sizeof(sin);
    struct tsocket *listen_ts;
    struct tsocket *new_ts;

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

    new_sd = wolfIP_sock_accept(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, &alen);
    ck_assert_int_gt(new_sd, 0);
    new_ts = &s.tcpsockets[SOCKET_UNMARK(new_sd)];
    /* After accept(), socket stays in SYN_RCVD until final ACK completes
     * the three-way handshake (SYN-ACK retransmission fix). */
    ck_assert_int_eq(new_ts->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(sin.sin_port, ee16(new_ts->dst_port));

    listen_ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(listen_ts->sock.tcp.state, TCP_LISTEN);
}
END_TEST

START_TEST(test_sock_accept_ack_with_payload_completes_handshake)
{
    struct wolfIP s;
    int listen_sd;
    int new_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = sizeof(sin);
    struct tsocket *new_ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    uint8_t payload[4] = {1, 2, 3, 4};
    uint8_t out[4] = {0};
    uint32_t base_seq;
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

    new_sd = wolfIP_sock_accept(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, &alen);
    ck_assert_int_gt(new_sd, 0);
    new_ts = &s.tcpsockets[SOCKET_UNMARK(new_sd)];
    ck_assert_int_eq(new_ts->sock.tcp.state, TCP_SYN_RCVD);

    memset(buf, 0, sizeof(buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.ttl = 64;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->ip.src = ee32(remote_ip);
    seg->ip.dst = ee32(local_ip);
    seg->src_port = ee16(remote_port);
    seg->dst_port = ee16(local_port);
    base_seq = new_ts->sock.tcp.ack;
    seg->seq = ee32(base_seq);
    seg->ack = ee32(new_ts->sock.tcp.seq);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = TCP_FLAG_ACK;
    memcpy(seg->data, payload, sizeof(payload));
    fix_tcp_checksums(seg);

    tcp_input(&s, TEST_PRIMARY_IF, seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload)));

    ck_assert_int_eq(new_ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(queue_pop(&new_ts->sock.tcp.rxbuf, out, sizeof(out)), (int)sizeof(out));
    ck_assert_mem_eq(out, payload, sizeof(payload));
    ck_assert_uint_eq(new_ts->sock.tcp.ack, tcp_seq_inc(base_seq, sizeof(payload)));
}
END_TEST

START_TEST(test_sock_accept_ack_at_snd_nxt_completes_handshake)
{
    struct wolfIP s;
    int listen_sd;
    int new_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = sizeof(sin);
    struct tsocket *new_ts;
    struct wolfIP_tcp_seg ackseg;
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

    new_sd = wolfIP_sock_accept(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, &alen);
    ck_assert_int_gt(new_sd, 0);
    new_ts = &s.tcpsockets[SOCKET_UNMARK(new_sd)];
    ck_assert_int_eq(new_ts->sock.tcp.state, TCP_SYN_RCVD);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ip.ver_ihl = 0x45;
    ackseg.ip.ttl = 64;
    ackseg.ip.proto = WI_IPPROTO_TCP;
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ackseg.ip.src = ee32(remote_ip);
    ackseg.ip.dst = ee32(local_ip);
    ackseg.src_port = ee16(remote_port);
    ackseg.dst_port = ee16(local_port);
    ackseg.seq = ee32(new_ts->sock.tcp.ack);
    ackseg.ack = ee32(new_ts->sock.tcp.seq);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    fix_tcp_checksums(&ackseg);

    tcp_input(&s, TEST_PRIMARY_IF, &ackseg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    ck_assert_int_eq(new_ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

START_TEST(test_sock_accept_ack_psh_with_payload_completes_handshake)
{
    struct wolfIP s;
    int listen_sd;
    int new_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = sizeof(sin);
    struct tsocket *new_ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    uint8_t payload[4] = {9, 8, 7, 6};
    uint8_t out[4] = {0};
    uint32_t base_seq;
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

    new_sd = wolfIP_sock_accept(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, &alen);
    ck_assert_int_gt(new_sd, 0);
    new_ts = &s.tcpsockets[SOCKET_UNMARK(new_sd)];
    ck_assert_int_eq(new_ts->sock.tcp.state, TCP_SYN_RCVD);

    memset(buf, 0, sizeof(buf));
    seg->ip.ver_ihl = 0x45;
    seg->ip.ttl = 64;
    seg->ip.proto = WI_IPPROTO_TCP;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->ip.src = ee32(remote_ip);
    seg->ip.dst = ee32(local_ip);
    seg->src_port = ee16(remote_port);
    seg->dst_port = ee16(local_port);
    base_seq = new_ts->sock.tcp.ack;
    seg->seq = ee32(base_seq);
    seg->ack = ee32(new_ts->sock.tcp.seq);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = (TCP_FLAG_ACK | TCP_FLAG_PSH);
    memcpy(seg->data, payload, sizeof(payload));
    fix_tcp_checksums(seg);

    tcp_input(&s, TEST_PRIMARY_IF, seg,
              (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload)));

    ck_assert_int_eq(new_ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(queue_pop(&new_ts->sock.tcp.rxbuf, out, sizeof(out)), (int)sizeof(out));
    ck_assert_mem_eq(out, payload, sizeof(payload));
    ck_assert_uint_eq(new_ts->sock.tcp.ack, tcp_seq_inc(base_seq, sizeof(payload)));
}
END_TEST

START_TEST(test_sock_accept_filtered_out)
{
    struct wolfIP s;
    int listen_sd;
    int new_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = sizeof(sin);
    struct tsocket *listen_ts;

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

    filter_block_reason = WOLFIP_FILT_ACCEPTING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_ACCEPTING));

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    new_sd = wolfIP_sock_accept(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, &alen);
    ck_assert_int_eq(new_sd, -1);
    ck_assert_int_gt(filter_block_calls, 0);

    listen_ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(listen_ts->sock.tcp.state, TCP_LISTEN);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST
START_TEST(test_tcp_handshake_and_fin_close_wait)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000A1U;
    uint16_t local_port = 8080;
    uint16_t remote_port = 40000;
    uint32_t server_seq;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ck_assert_int_eq(wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, local_ip, local_port);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(ts->remote_ip, remote_ip);
    ck_assert_uint_eq(ts->dst_port, remote_port);

    server_seq = ts->sock.tcp.seq;
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port, 2, server_seq + 1, TCP_FLAG_ACK);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);

    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port, 2, server_seq + 1, TCP_FLAG_FIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSE_WAIT);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, CB_EVENT_CLOSED);
}
END_TEST

START_TEST(test_poll_tcp_ack_only_skips_send)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};

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
    ts->sock.tcp.ack = 10;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.ack = 10;
    ts->sock.tcp.last_ack = 10;
    ts->sock.tcp.rto = 100;
    /* Ensure send window allows processing of the queued ACK-only segment. */
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.peer_rwnd = TCP_MSS;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 0, TCP_FLAG_ACK), 0);
    (void)wolfIP_poll(&s, 2000);

    ck_assert_ptr_eq(fifo_peek(&ts->sock.tcp.txbuf), NULL);
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x00);
    ck_assert_int_eq(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_poll_tcp_send_on_arp_hit)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xef};

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
    ts->sock.tcp.ack = 10;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.ack = 20;
    ts->sock.tcp.last_ack = 0;
    ts->sock.tcp.rto = 100;
    /* Ensure send window allows emitting the queued data segment. */
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    (void)wolfIP_poll(&s, 200);

    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x00);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_poll_tcp_arp_request_on_miss)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 10;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.rto = 100;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    (void)wolfIP_poll(&s, 2000);

    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x06);
}
END_TEST
START_TEST(test_tcp_rto_cb_resets_flags_and_arms_timer)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.rto_backoff = 0;
    ts->sock.tcp.cwnd = TCP_MSS * 2;
    ts->sock.tcp.snd_una = 101;
    ts->sock.tcp.seq = 101;

    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    s.last_tick = 1000;
    tcp_rto_cb(ts);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, PKT_FLAG_SENT);
    ck_assert_uint_gt(ts->sock.tcp.rto_backoff, 0);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_rto_cb_no_pending_resets_backoff)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto_backoff = 3;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    tcp_rto_cb(ts);
    ck_assert_uint_eq(ts->sock.tcp.rto_backoff, 0);
}
END_TEST

START_TEST(test_tcp_rto_cb_skips_unsent_desc)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg tcp;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto_backoff = 7;

    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    memset(&tcp, 0, sizeof(tcp));
    fifo_push(&ts->sock.tcp.txbuf, &tcp, sizeof(tcp));
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);

    tcp_rto_cb(ts);
    ck_assert_uint_eq(ts->sock.tcp.rto_backoff, 0);
}
END_TEST

START_TEST(test_tcp_rto_cb_non_tcp_noop)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_UDP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto_backoff = 5;

    tcp_rto_cb(ts);
    ck_assert_uint_eq(ts->sock.tcp.rto_backoff, 5);
}
END_TEST

START_TEST(test_tcp_rto_cb_non_established_noop)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_CLOSED;
    ts->sock.tcp.rto_backoff = 2;

    tcp_rto_cb(ts);
    ck_assert_uint_eq(ts->sock.tcp.rto_backoff, 2);
}
END_TEST

START_TEST(test_tcp_rto_cb_syn_sent_requeues_syn_and_arms_timer)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg *seg;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->sock.tcp.rto = 100;
    ts->src_port = 12345;
    ts->dst_port = 5001;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    s.last_tick = 1000;
    tcp_rto_cb(ts);

    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    seg = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
    ck_assert_uint_eq(seg->flags, TCP_FLAG_SYN);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_retries, 1);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_input_synack_cancels_control_rto)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg synack;
    struct wolfIP_timer tmr;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.ctrl_rto_retries = 3;
    ts->sock.tcp.ctrl_rto_active = 1;
    ts->src_port = 2222;
    ts->dst_port = 5001;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 100;
    tmr.arg = ts;
    ts->sock.tcp.tmr_rto = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);

    memset(&synack, 0, sizeof(synack));
    synack.ip.ttl = 64;
    synack.ip.src = ee32(0x0A000002U);
    synack.ip.dst = ee32(0x0A000001U);
    synack.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    synack.src_port = ee16(5001);
    synack.dst_port = ee16(ts->src_port);
    synack.seq = ee32(1000);
    synack.ack = ee32(ts->sock.tcp.seq + 1);
    synack.hlen = TCP_HEADER_LEN << 2;
    synack.flags = (TCP_FLAG_SYN | TCP_FLAG_ACK);
    synack.win = ee16(65535);
    fix_tcp_checksums(&synack);

    tcp_input(&s, TEST_PRIMARY_IF, &synack,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    /* Handshake RTO is control-plane; stop it once established. */
    ck_assert_uint_eq(ts->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_retries, 0);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_active, 0);
}
END_TEST

START_TEST(test_tcp_rto_cb_last_ack_requeues_finack_and_arms_timer)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg *seg;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LAST_ACK;
    ts->sock.tcp.rto = 100;
    ts->src_port = 12345;
    ts->dst_port = 5001;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    s.last_tick = 1000;
    tcp_rto_cb(ts);

    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    seg = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
    ck_assert_uint_eq(seg->flags, (TCP_FLAG_FIN | TCP_FLAG_ACK));
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_retries, 1);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_rto_cb_last_ack_full_txbuf_keeps_retry_budget)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LAST_ACK;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.ctrl_rto_retries = 2;
    ts->src_port = 12345;
    ts->dst_port = 5001;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    ts->sock.tcp.txbuf.head = 0;
    ts->sock.tcp.txbuf.tail = 0;
    ts->sock.tcp.txbuf.h_wrap = ts->sock.tcp.txbuf.size;

    s.last_tick = 1000;
    tcp_rto_cb(ts);

    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_retries, 2);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_active, 1);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_eq(find_timer_expiry(&s, ts->sock.tcp.tmr_rto), 1400U);
}
END_TEST

START_TEST(test_tcp_ctrl_state_needs_rto_fin_wait_1_waits_for_payload_drain)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ts->sock.tcp.bytes_in_flight = 1;
    ck_assert_int_eq(tcp_ctrl_state_needs_rto(ts), 0);

    ts->sock.tcp.bytes_in_flight = 0;
    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    ck_assert_int_eq(tcp_ctrl_state_needs_rto(ts), 0);

    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    ck_assert_int_eq(tcp_ctrl_state_needs_rto(ts), 1);
}
END_TEST

START_TEST(test_tcp_rto_cb_fin_wait_1_with_data_uses_data_recovery)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.rto_backoff = 0;
    ts->sock.tcp.snd_una = 101;
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.bytes_in_flight = 1;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    s.last_tick = 1000;
    tcp_rto_cb(ts);

    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc->flags & PKT_FLAG_RETRANS, 0);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_retries, 0);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_rto_cb_fin_wait_1_no_data_requeues_finack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg *seg;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ts->sock.tcp.rto = 100;
    ts->src_port = 12345;
    ts->dst_port = 5001;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->sock.tcp.bytes_in_flight = 0;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    s.last_tick = 1000;
    tcp_rto_cb(ts);

    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    seg = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
    ck_assert_uint_eq(seg->flags, (TCP_FLAG_FIN | TCP_FLAG_ACK));
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_retries, 1);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_rto_cb_fin_wait_1_no_data_full_txbuf_keeps_retry_budget)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.ctrl_rto_retries = 2;
    ts->src_port = 12345;
    ts->dst_port = 5001;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->sock.tcp.bytes_in_flight = 0;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    ts->sock.tcp.txbuf.head = 0;
    ts->sock.tcp.txbuf.tail = 0;
    ts->sock.tcp.txbuf.h_wrap = ts->sock.tcp.txbuf.size;

    s.last_tick = 1000;
    tcp_rto_cb(ts);

    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_retries, 2);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_active, 1);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_eq(find_timer_expiry(&s, ts->sock.tcp.tmr_rto), 1400U);
}
END_TEST

START_TEST(test_tcp_ack_fin_wait_1_ack_of_fin_moves_to_fin_wait_2_and_arms_timeout)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg ackseg;
    struct wolfIP_timer tmr;
    uint64_t timeout_at;

    wolfIP_init(&s);
    s.last_tick = 1000U;
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ts->sock.tcp.last = 100;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 1000;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.ctrl_rto_active = 1;
    ts->sock.tcp.ctrl_rto_retries = 2;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 200;
    tmr.arg = ts;
    ts->sock.tcp.tmr_rto = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    ackseg.ack = ee32(101);
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);

    tcp_ack(ts, &ackseg);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_2);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_active, 0);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_retries, 0);
    ck_assert_uint_eq(ts->sock.tcp.fin_wait_2_timeout_active, 1);
    timeout_at = find_timer_expiry(&s, ts->sock.tcp.tmr_rto);
    ck_assert_uint_eq(timeout_at, s.last_tick + TCP_FIN_WAIT_2_TIMEOUT_MS);

    (void)wolfIP_poll(&s, timeout_at);

    ck_assert_int_eq(ts->proto, 0);
    ck_assert_int_eq(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_ack_closing_ack_of_fin_moves_to_time_wait_and_stops_timer)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg ackseg;
    struct wolfIP_timer tmr;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    /* Simultaneous close: we sent FIN (last=100), peer sent FIN too,
     * tcp_input moved us to CLOSING. Now peer's ACK of our FIN arrives. */
    ts->sock.tcp.state = TCP_CLOSING;
    ts->sock.tcp.last = 100;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 1000;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.ctrl_rto_active = 1;
    ts->sock.tcp.ctrl_rto_retries = 2;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 200;
    tmr.arg = ts;
    ts->sock.tcp.tmr_rto = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    ackseg.ack = ee32(101); /* acknowledges our FIN at seq 100 */
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);

    tcp_ack(ts, &ackseg);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_TIME_WAIT);
    ck_assert_int_eq(ts->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_active, 0);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_retries, 0);
}
END_TEST

START_TEST(test_tcp_rto_cb_control_retry_cap_closes_socket)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.ctrl_rto_active = 1;
    ts->sock.tcp.ctrl_rto_retries = TCP_CTRL_RTO_MAXRTX;

    tcp_rto_cb(ts);
    ck_assert_int_eq(ts->proto, 0);
}
END_TEST

START_TEST(test_tcp_rto_cb_cancels_existing_timer)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.tmr_rto = 1;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    tcp_rto_cb(ts);
    ck_assert_int_eq(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_rto_cb_clears_sack_and_marks_lowest_only)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc1;
    struct pkt_desc *desc2;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.cwnd = TCP_MSS * 8;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 100;
    ts->sock.tcp.bytes_in_flight = 2;
    ts->sock.tcp.peer_sack_count = 1;
    ts->sock.tcp.peer_sack[0].left = 101;
    ts->sock.tcp.peer_sack[0].right = 102;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    ts->sock.tcp.seq = 101;
    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    desc1 = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc1);
    desc2 = fifo_next(&ts->sock.tcp.txbuf, desc1);
    ck_assert_ptr_nonnull(desc2);
    ck_assert_ptr_ne(desc2, desc1);

    desc1->flags |= PKT_FLAG_SENT;
    desc2->flags |= PKT_FLAG_SENT;

    s.last_tick = 1000;
    tcp_rto_cb(ts);

    ck_assert_uint_eq(ts->sock.tcp.peer_sack_count, 0);
    ck_assert_int_eq(desc1->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc1->flags & PKT_FLAG_RETRANS, 0);
    ck_assert_int_ne(desc2->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_eq(desc2->flags & PKT_FLAG_RETRANS, 0);
    ck_assert_uint_eq(ts->sock.tcp.cwnd, TCP_MSS);
    ck_assert_uint_eq(ts->sock.tcp.ssthresh, TCP_MSS * 2);
}
END_TEST

START_TEST(test_tcp_rto_cb_ssthresh_uses_inflight_not_cwnd)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.snd_una = 101;
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.bytes_in_flight = TCP_MSS * 10;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    s.last_tick = 1000;
    tcp_rto_cb(ts);

    ck_assert_uint_eq(ts->sock.tcp.cwnd, TCP_MSS);
    ck_assert_uint_eq(ts->sock.tcp.ssthresh, TCP_MSS * 5);
}
END_TEST

START_TEST(test_tcp_rto_cb_ssthresh_floor_two_mss)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.snd_una = 101;
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.bytes_in_flight = 1;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    s.last_tick = 1000;
    tcp_rto_cb(ts);

    ck_assert_uint_eq(ts->sock.tcp.cwnd, TCP_MSS);
    ck_assert_uint_eq(ts->sock.tcp.ssthresh, TCP_MSS * 2);
}
END_TEST

START_TEST(test_tcp_rto_cb_fallback_marks_lowest_sent_when_no_snd_una_cover)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.snd_una = 50;
    ts->sock.tcp.seq = 100;
    ts->sock.tcp.bytes_in_flight = 1;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, (TCP_FLAG_ACK | TCP_FLAG_PSH)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    s.last_tick = 1000;
    tcp_rto_cb(ts);

    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc->flags & PKT_FLAG_RETRANS, 0);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, 50U);
    ck_assert_uint_eq(ts->sock.tcp.cwnd, TCP_MSS);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_poll_udp_send_on_arp_hit)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {1, 2, 3, 4};
    uint8_t peer_mac[6] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ret = wolfIP_sock_sendto(&s, udp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, (int)sizeof(payload));

    (void)wolfIP_poll(&s, 2000);
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x00);
}
END_TEST

START_TEST(test_poll_udp_send_on_arp_miss_requests_arp_and_retains_queue)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {1, 2, 3, 4};
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ret = wolfIP_sock_sendto(&s, udp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ts->if_idx = TEST_PRIMARY_IF;
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.txbuf));

    (void)wolfIP_poll(&s, 2000);
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x06);
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.txbuf));
}
END_TEST

START_TEST(test_poll_icmp_send_on_arp_hit)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN + 1];
    uint8_t peer_mac[6] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x06};
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    memset(payload, 0, sizeof(payload));
    payload[0] = ICMP_ECHO_REQUEST;
    ret = wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, (int)sizeof(payload));

    (void)wolfIP_poll(&s, 100);
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x00);
}
END_TEST

START_TEST(test_poll_icmp_send_on_arp_miss_requests_arp_and_retains_queue)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN + 1];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    memset(payload, 0, sizeof(payload));
    payload[0] = ICMP_ECHO_REQUEST;
    ret = wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ts->if_idx = TEST_PRIMARY_IF;
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.txbuf));

    (void)wolfIP_poll(&s, 2000);
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x06);
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.txbuf));
}
END_TEST

START_TEST(test_dhcp_timer_cb_paths)
{
    struct wolfIP s;
    struct ipconf *primary;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    s.dhcp_xid = 1;

    s.dhcp_state = DHCP_DISCOVER_SENT;
    s.dhcp_timeout_count = 0;
    ret = dhcp_send_discover(&s);
    ck_assert_int_eq(ret, 0);
    dhcp_timer_cb(&s);
    ck_assert_int_eq(s.dhcp_timeout_count, 1);

    s.dhcp_timeout_count = DHCP_DISCOVER_RETRIES;
    dhcp_timer_cb(&s);
    ck_assert_int_eq(s.dhcp_state, DHCP_OFF);

    s.dhcp_state = DHCP_REQUEST_SENT;
    s.dhcp_timeout_count = 0;
    ret = dhcp_send_request(&s);
    ck_assert_int_eq(ret, 0);
    dhcp_timer_cb(&s);
    ck_assert_int_eq(s.dhcp_timeout_count, 1);

    primary->ip = 0x0A000064U;
    primary->mask = 0xFFFFFF00U;
    s.dhcp_ip = primary->ip;
    s.dhcp_server_ip = 0x0A000001U;
    s.last_tick = 1000U;
    s.dhcp_state = DHCP_BOUND;
    last_frame_sent_size = 0;
    dhcp_timer_cb(&s);
    (void)wolfIP_poll(&s, s.last_tick);
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    ck_assert_int_eq(s.dhcp_state, DHCP_RENEWING);
}
END_TEST

START_TEST(test_regression_dhcp_lease_expiry_deconfigures_address)
{
    struct wolfIP s;
    struct ipconf *primary;
    uint32_t stale_timeout_count;

    wolfIP_init(&s);
    mock_link_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    s.dhcp_xid = 1U;

    wolfIP_ipconfig_set(&s, 0x0A000064U, 0xFFFFFF00U, 0x0A000001U);
    s.dhcp_ip = primary->ip;
    s.dhcp_server_ip = 0x0A000001U;
    s.last_tick = 1000U;
    s.dhcp_lease_expires = s.last_tick;
    s.dhcp_timeout_count = 3U;
    stale_timeout_count = s.dhcp_timeout_count;

    s.dhcp_state = DHCP_BOUND;
    dhcp_timer_cb(&s);
    ck_assert_int_eq(s.dhcp_state, DHCP_DISCOVER_SENT);
    ck_assert_uint_eq(primary->ip, 0U);
    ck_assert_uint_eq(primary->mask, 0U);
    ck_assert_uint_eq(primary->gw, 0U);
    ck_assert_uint_eq(s.dhcp_ip, 0U);
    ck_assert_uint_eq(s.dhcp_server_ip, 0U);
    ck_assert_uint_ne(stale_timeout_count, 0U);
    ck_assert_uint_eq(s.dhcp_timeout_count, 0U);
    ck_assert_uint_ne(s.dhcp_timer, NO_TIMER);

    wolfIP_ipconfig_set(&s, 0x0A000064U, 0xFFFFFF00U, 0x0A000001U);
    s.dhcp_ip = primary->ip;
    s.dhcp_server_ip = 0x0A000001U;
    s.last_tick = 2000U;
    s.dhcp_lease_expires = s.last_tick;
    s.dhcp_timeout_count = 2U;

    s.dhcp_state = DHCP_REBINDING;
    dhcp_timer_cb(&s);
    ck_assert_int_eq(s.dhcp_state, DHCP_DISCOVER_SENT);
    ck_assert_uint_eq(primary->ip, 0U);
    ck_assert_uint_eq(primary->mask, 0U);
    ck_assert_uint_eq(primary->gw, 0U);
    ck_assert_uint_eq(s.dhcp_ip, 0U);
    ck_assert_uint_eq(s.dhcp_server_ip, 0U);
    ck_assert_uint_eq(s.dhcp_timeout_count, 0U);
    ck_assert_uint_ne(s.dhcp_timer, NO_TIMER);
}
END_TEST

START_TEST(test_dhcp_timer_cb_send_failure_does_not_consume_retry_budget)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t tiny[2];

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_xid = 1U;
    s.last_tick = 1000U;

    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dhcp_udp_sd)];
    fifo_init(&ts->sock.udp.txbuf, tiny, sizeof(tiny));

    s.dhcp_state = DHCP_DISCOVER_SENT;
    s.dhcp_timeout_count = 0;
    dhcp_timer_cb(&s);
    ck_assert_int_eq(s.dhcp_timeout_count, 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_DISCOVER_SENT);
    ck_assert_uint_eq(find_timer_expiry(&s, s.dhcp_timer), s.last_tick + 1U);

    s.dhcp_state = DHCP_REQUEST_SENT;
    s.dhcp_timeout_count = 0;
    dhcp_timer_cb(&s);
    ck_assert_int_eq(s.dhcp_timeout_count, 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_REQUEST_SENT);
    ck_assert_uint_eq(find_timer_expiry(&s, s.dhcp_timer), s.last_tick + 1U);
}
END_TEST

START_TEST(test_dhcp_client_init_and_bound)
{
    struct wolfIP s;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_BOUND;
    ret = dhcp_client_init(&s);
    ck_assert_int_eq(ret, -1);

    s.dhcp_state = DHCP_OFF;
    ret = dhcp_client_init(&s);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(dhcp_bound(&s), 0);
    ck_assert_int_eq(dhcp_client_is_running(&s), 1);
}
END_TEST

START_TEST(test_dhcp_client_init_bind_failure_closes_socket)
{
    struct wolfIP s;
    unsigned int i;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    filter_block_reason = WOLFIP_FILT_BINDING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_BINDING));

    ret = dhcp_client_init(&s);
    ck_assert_int_eq(ret, -1);
    ck_assert_int_eq(s.dhcp_udp_sd, 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_OFF);
    ck_assert_int_gt(filter_block_calls, 0);
    for (i = 0; i < MAX_UDPSOCKETS; i++) {
        ck_assert_int_eq(s.udpsockets[i].proto, 0);
        ck_assert_uint_eq(s.udpsockets[i].src_port, 0U);
    }

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
}
END_TEST

START_TEST(test_sock_close_udp_icmp)
{
    struct wolfIP s;
    int udp_sd;
    int icmp_sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 1234;
    ck_assert_int_eq(wolfIP_sock_close(&s, udp_sd), 0);
    ck_assert_int_eq(ts->proto, 0);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->src_port = 1;
    ck_assert_int_eq(wolfIP_sock_close(&s, icmp_sd), 0);
    ck_assert_int_eq(ts->proto, 0);
}
END_TEST

START_TEST(test_sock_close_invalid_fds)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_close(&s, -1), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_close(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_close(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_close(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_close(&s, 1), -1);
}
END_TEST

START_TEST(test_sock_close_tcp_fin_wait_1)
{
    struct wolfIP s;
    struct tsocket *ts;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_FIN_WAIT_1;

    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_1);
}
END_TEST

START_TEST(test_sock_close_tcp_established_full_txbuf_preserves_state)
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
    ts->src_port = 12345;
    ts->dst_port = 5001;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    ts->sock.tcp.txbuf.head = 0;
    ts->sock.tcp.txbuf.tail = 0;
    ts->sock.tcp.txbuf.h_wrap = ts->sock.tcp.txbuf.size;

    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_active, 0);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_retries, 0);
    ck_assert_uint_eq(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_sock_close_tcp_close_wait_full_txbuf_preserves_state)
{
    struct wolfIP s;
    struct tsocket *ts;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    ts->src_port = 12345;
    ts->dst_port = 5001;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    ts->sock.tcp.txbuf.head = 0;
    ts->sock.tcp.txbuf.tail = 0;
    ts->sock.tcp.txbuf.h_wrap = ts->sock.tcp.txbuf.size;

    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSE_WAIT);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_active, 0);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_retries, 0);
    ck_assert_uint_eq(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_sock_close_tcp_fin_wait_1_repeated_close_keeps_fin_wait_2_path)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg ackseg;
    struct wolfIP_timer tmr;
    int sd;
    uint64_t timeout_at;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.last_tick = 1000U;

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ts->sock.tcp.last = 100;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 1000;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.ctrl_rto_active = 1;
    ts->sock.tcp.ctrl_rto_retries = 2;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 200;
    tmr.arg = ts;
    ts->sock.tcp.tmr_rto = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);

    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_1);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = TCP_FLAG_ACK;
    ackseg.ack = ee32(101);
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);

    tcp_ack(ts, &ackseg);

    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_2);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_active, 0);
    ck_assert_uint_eq(ts->sock.tcp.ctrl_rto_retries, 0);
    ck_assert_uint_eq(ts->sock.tcp.fin_wait_2_timeout_active, 1);
    timeout_at = find_timer_expiry(&s, ts->sock.tcp.tmr_rto);
    ck_assert_uint_eq(timeout_at, s.last_tick + TCP_FIN_WAIT_2_TIMEOUT_MS);

    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_2);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_eq(ts->sock.tcp.fin_wait_2_timeout_active, 1);
    ck_assert_uint_eq(find_timer_expiry(&s, ts->sock.tcp.tmr_rto), timeout_at);
}
END_TEST

START_TEST(test_sock_close_tcp_other_state_closes)
{
    struct wolfIP s;
    struct tsocket *ts;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;

    ck_assert_int_eq(wolfIP_sock_close(&s, sd), 0);
    ck_assert_int_eq(ts->proto, 0);
}
END_TEST

START_TEST(test_sock_close_tcp_cancels_rto_timer)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_timer tmr;
    int sd;
    uint32_t rto_id;
    uint32_t i;
    int found_canceled = 0;

    wolfIP_init(&s);
    mock_link_init(&s);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->sock.tcp.ctrl_rto_active = 1;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 1234;
    rto_id = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(rto_id, NO_TIMER);
    ts->sock.tcp.tmr_rto = rto_id;

    ck_assert_int_eq(wolfIP_sock_close(&s, sd), 0);
    ck_assert_int_eq(ts->proto, 0);
    for (i = 0; i < s.timers.size; i++) {
        if (s.timers.timers[i].id == rto_id) {
            found_canceled = 1;
            ck_assert_uint_eq(s.timers.timers[i].expires, 0);
            break;
        }
    }
    ck_assert_int_eq(found_canceled, 1);
}
END_TEST

START_TEST(test_sock_close_tcp_closed_returns_minus_one)
{
    struct wolfIP s;
    struct tsocket *ts;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_CLOSED;

    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -1);
}
END_TEST
START_TEST(test_fifo_push_and_pop_multiple) {
    struct fifo f;
    uint8_t data[] = {1, 2, 3, 4, 5};
    uint8_t data2[] = {6, 7, 8, 9, 10};
    struct pkt_desc *desc;

    fifo_init(&f, mem, memsz);
    ck_assert_int_eq(fifo_space(&f), memsz);

    // Test push
    ck_assert_int_eq(fifo_push(&f, data, sizeof(data)), 0);
    ck_assert_int_eq(fifo_len(&f), sizeof(data) + sizeof(struct pkt_desc));
    ck_assert_int_eq(fifo_space(&f), f.size - (sizeof(data) + sizeof(struct pkt_desc)));
    ck_assert_int_eq(fifo_push(&f, data2, sizeof(data2)), 0);

    // Test pop
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->len, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data));

    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->len, sizeof(data2));
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data2, sizeof(data2));
}
END_TEST

START_TEST(test_dhcp_poll_offer_and_ack)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct tsocket *ts;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dhcp_udp_sd)];

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.yiaddr = ee32(0x0A000064U);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_OFFER;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_SERVER_ID;
    opt->len = 4;
    opt->data[0] = 0x0A;
    opt->data[1] = 0x00;
    opt->data[2] = 0x00;
    opt->data[3] = 0x01;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_SUBNET_MASK;
    opt->len = 4;
    opt->data[0] = 0xFF;
    opt->data[1] = 0xFF;
    opt->data[2] = 0xFF;
    opt->data[3] = 0x00;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    s.dhcp_state = DHCP_DISCOVER_SENT;
    enqueue_udp_rx(ts, &msg, sizeof(msg), DHCP_SERVER_PORT);
    ret = dhcp_poll(&s);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_REQUEST_SENT);

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_SERVER_ID;
    opt->len = 4;
    opt->data[0] = 0x0A;
    opt->data[1] = 0x00;
    opt->data[2] = 0x00;
    opt->data[3] = 0x01;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_SUBNET_MASK;
    opt->len = 4;
    opt->data[0] = 0xFF;
    opt->data[1] = 0xFF;
    opt->data[2] = 0xFF;
    opt->data[3] = 0x00;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_ROUTER;
    opt->len = 4;
    opt->data[0] = 0x0A;
    opt->data[1] = 0x00;
    opt->data[2] = 0x00;
    opt->data[3] = 0x01;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_DNS;
    opt->len = 4;
    opt->data[0] = 0x08;
    opt->data[1] = 0x08;
    opt->data[2] = 0x08;
    opt->data[3] = 0x08;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    s.dhcp_state = DHCP_REQUEST_SENT;
    enqueue_udp_rx(ts, &msg, sizeof(msg), DHCP_SERVER_PORT);
    ret = dhcp_poll(&s);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_BOUND);
}
END_TEST

START_TEST(test_dhcp_poll_renewing_ack_binds_client)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct tsocket *ts;
    struct ipconf *primary;
    uint32_t server_ip = 0x0A000001U;
    uint32_t client_ip = 0x0A000064U;
    uint32_t router_ip = 0x0A000002U;
    uint32_t dns_ip = 0x08080808U;
    uint32_t mask = 0xFFFFFF00U;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dhcp_udp_sd)];

    /* Simulate a renewing client that already owns an address and receives a valid ACK. */
    s.last_tick = 1000U;
    s.dhcp_state = DHCP_RENEWING;
    s.dhcp_xid = 0x12345678U;
    s.dhcp_server_ip = server_ip;
    primary->ip = client_ip;
    build_dhcp_ack_msg(&msg, server_ip, mask, router_ip, dns_ip);
    msg.xid = ee32(s.dhcp_xid);

    enqueue_udp_rx(ts, &msg, sizeof(msg), DHCP_SERVER_PORT);
    ret = dhcp_poll(&s);

    /* The poll dispatcher should route renewing traffic through ACK parsing to BOUND. */
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_BOUND);
    ck_assert_uint_eq(primary->ip, client_ip);
    ck_assert_uint_eq(primary->mask, mask);
    ck_assert_uint_eq(primary->gw, router_ip);
    ck_assert_uint_eq(s.dns_server, dns_ip);
}
END_TEST

START_TEST(test_dhcp_poll_rebinding_ack_binds_client)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct tsocket *ts;
    struct ipconf *primary;
    uint32_t server_ip = 0x0A000001U;
    uint32_t client_ip = 0x0A000064U;
    uint32_t router_ip = 0x0A000002U;
    uint32_t dns_ip = 0x08080808U;
    uint32_t mask = 0xFFFFFF00U;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dhcp_udp_sd)];

    /* Rebinding uses the same ACK branch, but arrives after the server-specific renew phase. */
    s.last_tick = 1000U;
    s.dhcp_state = DHCP_REBINDING;
    s.dhcp_xid = 0xABCDEF01U;
    s.dhcp_server_ip = server_ip;
    primary->ip = client_ip;
    build_dhcp_ack_msg(&msg, server_ip, mask, router_ip, dns_ip);
    msg.xid = ee32(s.dhcp_xid);

    enqueue_udp_rx(ts, &msg, sizeof(msg), DHCP_SERVER_PORT);
    ret = dhcp_poll(&s);

    /* Rebinding ACKs should also drive the client back to BOUND with refreshed config. */
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_BOUND);
    ck_assert_uint_eq(primary->ip, client_ip);
    ck_assert_uint_eq(primary->mask, mask);
    ck_assert_uint_eq(primary->gw, router_ip);
    ck_assert_uint_eq(s.dns_server, dns_ip);
}
END_TEST

START_TEST(test_regression_dhcp_nak_deconfigures_address_during_renew_and_rebind)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct tsocket *ts;
    struct ipconf *primary;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dhcp_udp_sd)];
    s.dhcp_xid = 0x12345678U;

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.xid = ee32(s.dhcp_xid);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_NAK;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_END;

    wolfIP_ipconfig_set(&s, 0x0A000064U, 0xFFFFFF00U, 0x0A000001U);
    s.dhcp_state = DHCP_RENEWING;
    enqueue_udp_rx(ts, &msg, sizeof(msg), DHCP_SERVER_PORT);
    ret = dhcp_poll(&s);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_DISCOVER_SENT);
    ck_assert_uint_eq(primary->ip, 0U);
    ck_assert_uint_eq(primary->mask, 0U);
    ck_assert_uint_eq(primary->gw, 0U);

    wolfIP_ipconfig_set(&s, 0x0A000064U, 0xFFFFFF00U, 0x0A000001U);
    s.dhcp_state = DHCP_REBINDING;
    enqueue_udp_rx(ts, &msg, sizeof(msg), DHCP_SERVER_PORT);
    ret = dhcp_poll(&s);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_DISCOVER_SENT);
    ck_assert_uint_eq(primary->ip, 0U);
    ck_assert_uint_eq(primary->mask, 0U);
    ck_assert_uint_eq(primary->gw, 0U);
}
END_TEST

START_TEST(test_dns_callback_ptr_response)
{
    struct wolfIP s;
    uint8_t response[192];
    int pos;
    struct dns_header *hdr = (struct dns_header *)response;
    struct dns_question *q;
    struct dns_rr *rr;
    const char *ptr_name = "1.0.0.10.in-addr.arpa";
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_query_type = DNS_QUERY_TYPE_PTR;
    s.dns_id = 0x1234;
    s.dns_ptr_cb = test_dns_ptr_cb;
    s.dns_lookup_cb = NULL;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)];

    memset(response, 0, sizeof(response));
    hdr->id = ee16(s.dns_id);
    hdr->flags = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(1);
    pos = sizeof(struct dns_header);
    response[pos++] = 1; response[pos++] = 'a';
    response[pos++] = 3; memcpy(&response[pos], "com", 3); pos += 3;
    response[pos++] = 0;
    q = (struct dns_question *)(response + pos);
    q->qtype = ee16(DNS_PTR);
    q->qclass = ee16(1);
    pos += sizeof(struct dns_question);
    response[pos++] = 0xC0;
    response[pos++] = (uint8_t)sizeof(struct dns_header);
    rr = (struct dns_rr *)(response + pos);
    rr->type = ee16(DNS_PTR);
    rr->class = ee16(1);
    rr->ttl = ee32(60);
    rr->rdlength = ee16((uint16_t)(strlen(ptr_name) + 2));
    pos += sizeof(struct dns_rr);
    response[pos++] = (uint8_t)strlen(ptr_name);
    memcpy(&response[pos], ptr_name, strlen(ptr_name));
    pos += (int)strlen(ptr_name);
    response[pos++] = 0;

    enqueue_udp_rx(ts, response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
}
END_TEST
START_TEST(test_tcp_syn_sent_to_established)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000B1U;
    uint16_t remote_port = 12345;
    uint32_t client_seq;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(remote_port);
    sin.sin_addr.s_addr = ee32(remote_ip);

    ck_assert_int_eq(wolfIP_sock_connect(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);
    ck_assert_uint_eq(ts->remote_ip, remote_ip);
    ck_assert_uint_eq(ts->dst_port, remote_port);

    client_seq = ts->sock.tcp.seq;
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, ts->src_port,
            100, client_seq + 1, (TCP_FLAG_SYN | TCP_FLAG_ACK));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.ack, 101);
}
END_TEST

START_TEST(test_udp_try_recv_short_frame)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_udp_datagram udp;
    uint32_t local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(&udp, 0, sizeof(udp));
    udp.ip.dst = ee32(local_ip);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN + 4);
    udp_try_recv(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN));
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_udp_try_recv_filter_drop)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_udp_datagram udp;
    uint32_t local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    filter_block_reason = WOLFIP_FILT_RECEIVING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_udp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));

    memset(&udp, 0, sizeof(udp));
    udp.ip.dst = ee32(local_ip);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN + 4);
    udp_try_recv(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
    ck_assert_int_gt(filter_block_calls, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_udp_mask(0);
}
END_TEST

START_TEST(test_udp_try_recv_conf_null)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t udp_buf[sizeof(struct wolfIP_udp_datagram) + 4];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)udp_buf;
    uint32_t dst_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = dst_ip;
    ts->remote_ip = 0;

    memset(udp_buf, 0, sizeof(udp_buf));
    udp->ip.dst = ee32(dst_ip);
    udp->dst_port = ee16(1234);
    udp->len = ee16(UDP_HEADER_LEN + 4);
    udp_try_recv(&s, TEST_PRIMARY_IF, udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.rxbuf));
}
END_TEST

START_TEST(test_udp_try_recv_remote_ip_matches_local_ip)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_udp_datagram udp;
    uint32_t local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;
    ts->remote_ip = local_ip;

    memset(&udp, 0, sizeof(udp));
    udp.ip.dst = ee32(local_ip);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN + 4);
    udp_try_recv(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_udp_try_recv_dhcp_running_local_zero)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t udp_buf[sizeof(struct wolfIP_udp_datagram) + 4];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)udp_buf;
    uint32_t local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_DISCOVER_SENT;
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = 0;

    memset(udp_buf, 0, sizeof(udp_buf));
    udp->ip.dst = ee32(local_ip);
    udp->dst_port = ee16(1234);
    udp->len = ee16(UDP_HEADER_LEN + 4);
    udp_try_recv(&s, TEST_PRIMARY_IF, udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.rxbuf));
}
END_TEST

START_TEST(test_udp_try_recv_short_expected_len)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_udp_datagram udp;
    uint32_t local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(&udp, 0, sizeof(udp));
    udp.ip.dst = ee32(local_ip);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN + 10);
    udp_try_recv(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_udp_try_recv_len_below_header_rejected)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_udp_datagram udp;
    uint32_t local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(&udp, 0, sizeof(udp));
    udp.ip.dst = ee32(local_ip);
    udp.ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN - 1);

    udp_try_recv(&s, TEST_PRIMARY_IF, &udp,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN));

    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_udp_try_recv_unmatched_port_sends_icmp_unreachable)
{
    struct wolfIP s;
    uint8_t udp_buf[sizeof(struct wolfIP_udp_datagram) + 4];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)udp_buf;
    struct wolfIP_icmp_dest_unreachable_packet *icmp;
    uint32_t local_ip = 0x0A000001U;
    uint32_t remote_ip = 0x0A000002U;
    uint8_t src_mac[6] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    memset(udp_buf, 0, sizeof(udp_buf));
    memcpy(udp->ip.eth.src, src_mac, sizeof(src_mac));
    memcpy(udp->ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    udp->ip.eth.type = ee16(ETH_TYPE_IP);
    udp->ip.ver_ihl = 0x45;
    udp->ip.ttl = 64;
    udp->ip.proto = WI_IPPROTO_UDP;
    udp->ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN + 4);
    udp->ip.src = ee32(remote_ip);
    udp->ip.dst = ee32(local_ip);
    udp->src_port = ee16(4321);
    udp->dst_port = ee16(1234);
    udp->len = ee16(UDP_HEADER_LEN + 4);
    memcpy(udp->data, "test", 4);
    fix_udp_checksums(udp);

    memset(last_frame_sent, 0, sizeof(last_frame_sent));
    last_frame_sent_size = 0;

    udp_try_recv(&s, TEST_PRIMARY_IF, udp,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));

    ck_assert_uint_eq(last_frame_sent_size,
            sizeof(struct wolfIP_icmp_dest_unreachable_packet));
    icmp = (struct wolfIP_icmp_dest_unreachable_packet *)last_frame_sent;
    ck_assert_uint_eq(icmp->type, 3U);
    ck_assert_uint_eq(icmp->code, 3U);
    ck_assert_mem_eq(icmp->unused, "\x00\x00\x00\x00", sizeof(icmp->unused));
    ck_assert_mem_eq(icmp->ip.eth.dst, src_mac, 6);
    ck_assert_mem_eq(icmp->ip.eth.src, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    ck_assert_uint_eq(ee32(icmp->ip.src), local_ip);
    ck_assert_uint_eq(ee32(icmp->ip.dst), remote_ip);
    ck_assert_mem_eq(icmp->orig_packet, ((uint8_t *)udp) + ETH_HEADER_LEN,
            TTL_EXCEEDED_ORIG_PACKET_SIZE);
}
END_TEST

START_TEST(test_udp_try_recv_unmatched_nonlocal_dst_does_not_send_icmp)
{
    struct wolfIP s;
    uint8_t udp_buf[sizeof(struct wolfIP_udp_datagram) + 4];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)udp_buf;
    uint32_t local_ip = 0x0A000001U;
    uint32_t remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    memset(udp_buf, 0, sizeof(udp_buf));
    udp->ip.ver_ihl = 0x45;
    udp->ip.ttl = 64;
    udp->ip.proto = WI_IPPROTO_UDP;
    udp->ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN + 4);
    udp->ip.src = ee32(remote_ip);
    udp->ip.dst = ee32(0x0A0000FEU);
    udp->src_port = ee16(4321);
    udp->dst_port = ee16(1234);
    udp->len = ee16(UDP_HEADER_LEN + 4);
    memcpy(udp->data, "test", 4);
    fix_udp_checksums(udp);

    memset(last_frame_sent, 0, sizeof(last_frame_sent));
    last_frame_sent_size = 0;

    udp_try_recv(&s, TEST_PRIMARY_IF, udp,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));

    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_udp_try_recv_full_fifo_drop_does_not_set_readable_or_send_icmp)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t udp_buf[sizeof(struct wolfIP_udp_datagram) + 4];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)udp_buf;
    uint32_t local_ip = 0x0A000001U;
    uint32_t remote_ip = 0x0A000002U;
    uint8_t src_mac[6] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25};
    uint32_t frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4);
    uint32_t head_before;
    uint32_t tail_before;
    uint32_t h_wrap_before;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(udp_buf, 0, sizeof(udp_buf));
    memcpy(udp->ip.eth.src, src_mac, sizeof(src_mac));
    memcpy(udp->ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    udp->ip.eth.type = ee16(ETH_TYPE_IP);
    udp->ip.ver_ihl = 0x45;
    udp->ip.ttl = 64;
    udp->ip.proto = WI_IPPROTO_UDP;
    udp->ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN + 4);
    udp->ip.src = ee32(remote_ip);
    udp->ip.dst = ee32(local_ip);
    udp->src_port = ee16(4321);
    udp->dst_port = ee16(1234);
    udp->len = ee16(UDP_HEADER_LEN + 4);
    memcpy(udp->data, "test", 4);
    fix_udp_checksums(udp);

    /* Mirror the FIFO's canonical full state: head == tail with wrap set. */
    ts->sock.udp.rxbuf.head = 0;
    ts->sock.udp.rxbuf.tail = 0;
    ts->sock.udp.rxbuf.h_wrap = ts->sock.udp.rxbuf.size;
    ck_assert_int_eq(fifo_can_push_len(&ts->sock.udp.rxbuf, frame_len), 0);

    head_before = ts->sock.udp.rxbuf.head;
    tail_before = ts->sock.udp.rxbuf.tail;
    h_wrap_before = ts->sock.udp.rxbuf.h_wrap;
    ts->events = 0;

    memset(last_frame_sent, 0, sizeof(last_frame_sent));
    last_frame_sent_size = 0;

    udp_try_recv(&s, TEST_PRIMARY_IF, udp, frame_len);

    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, 0U);
    ck_assert_uint_eq(ts->sock.udp.rxbuf.head, head_before);
    ck_assert_uint_eq(ts->sock.udp.rxbuf.tail, tail_before);
    ck_assert_uint_eq(ts->sock.udp.rxbuf.h_wrap, h_wrap_before);
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_dns_callback_bad_flags)
{
    struct wolfIP s;
    uint8_t response[32];
    struct dns_header *hdr = (struct dns_header *)response;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_id = 0x1234;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    memset(response, 0, sizeof(response));
    hdr->id = ee16(s.dns_id);
    hdr->flags = 0;

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)], response, sizeof(response), DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_uint_eq(s.dns_id, 0x1234);
}
END_TEST

START_TEST(test_dns_callback_truncated_response_aborts_query)
{
    struct wolfIP s;
    uint8_t response[128];
    int pos;
    struct dns_header *hdr = (struct dns_header *)response;
    struct dns_question *q;
    struct dns_rr *rr;
    const uint8_t ip_bytes[4] = {0x0A, 0x00, 0x00, 0x42};

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_id = 0x1234;
    s.dns_lookup_cb = test_dns_lookup_cb;
    dns_lookup_calls = 0;
    dns_lookup_ip = 0;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    memset(response, 0, sizeof(response));
    hdr->id = ee16(s.dns_id);
    hdr->flags = ee16(0x8300);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(1);
    pos = sizeof(struct dns_header);
    response[pos++] = 7; memcpy(&response[pos], "example", 7); pos += 7;
    response[pos++] = 3; memcpy(&response[pos], "com", 3); pos += 3;
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
    rr->rdlength = ee16(4);
    pos += sizeof(struct dns_rr);
    memcpy(&response[pos], ip_bytes, sizeof(ip_bytes));
    pos += sizeof(ip_bytes);

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)], response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);

    ck_assert_int_eq(dns_lookup_calls, 0);
    ck_assert_uint_eq(dns_lookup_ip, 0U);
    ck_assert_uint_eq(s.dns_id, 0);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
    ck_assert_ptr_eq(s.dns_lookup_cb, NULL);
}
END_TEST

START_TEST(test_dns_callback_bad_name)
{
    struct wolfIP s;
    uint8_t response[64];
    int pos;
    struct dns_header *hdr = (struct dns_header *)response;

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
    hdr->ancount = ee16(0);
    pos = sizeof(struct dns_header);
    response[pos++] = 60;
    memset(&response[pos], 'a', 5);
    pos += 5;

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)], response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_uint_eq(s.dns_id, 0);
}
END_TEST

START_TEST(test_dns_callback_short_header_ignored)
{
    struct wolfIP s;
    uint8_t response[10];
    struct dns_header *hdr = (struct dns_header *)response;

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
    hdr->ancount = 0;

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)], response, sizeof(response), DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_uint_eq(s.dns_id, 0x1234);
}
END_TEST

START_TEST(test_dns_callback_wrong_id_ignored)
{
    struct wolfIP s;
    uint8_t response[128];
    int pos;
    struct dns_header *hdr = (struct dns_header *)response;
    struct dns_question *q;
    struct dns_rr *rr;
    const uint8_t ip_bytes[4] = {0x0A, 0x00, 0x00, 0x42};

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_id = 0x1234;
    s.dns_lookup_cb = test_dns_lookup_cb;
    dns_lookup_calls = 0;
    dns_lookup_ip = 0;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    memset(response, 0, sizeof(response));
    hdr->id = ee16(0x4321);
    hdr->flags = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(1);
    pos = sizeof(struct dns_header);
    response[pos++] = 7; memcpy(&response[pos], "example", 7); pos += 7;
    response[pos++] = 3; memcpy(&response[pos], "com", 3); pos += 3;
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
    rr->rdlength = ee16(4);
    pos += sizeof(struct dns_rr);
    memcpy(&response[pos], ip_bytes, sizeof(ip_bytes));
    pos += sizeof(ip_bytes);

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)], response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_int_eq(dns_lookup_calls, 0);
    ck_assert_uint_eq(dns_lookup_ip, 0U);
    ck_assert_uint_eq(s.dns_id, 0x1234);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_A);
}
END_TEST

START_TEST(test_dns_callback_non_in_a_answer_ignored)
{
    struct wolfIP s;
    uint8_t response[128];
    int pos;
    struct dns_header *hdr = (struct dns_header *)response;
    struct dns_question *q;
    struct dns_rr *rr;
    const uint8_t ip_bytes[4] = {0x0A, 0x00, 0x00, 0x42};

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_id = 0x1234;
    s.dns_lookup_cb = test_dns_lookup_cb;
    dns_lookup_calls = 0;
    dns_lookup_ip = 0;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    memset(response, 0, sizeof(response));
    hdr->id = ee16(s.dns_id);
    hdr->flags = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(1);
    pos = sizeof(struct dns_header);
    response[pos++] = 7; memcpy(&response[pos], "example", 7); pos += 7;
    response[pos++] = 3; memcpy(&response[pos], "com", 3); pos += 3;
    response[pos++] = 0;
    q = (struct dns_question *)(response + pos);
    q->qtype = ee16(DNS_A);
    q->qclass = ee16(1);
    pos += sizeof(struct dns_question);
    response[pos++] = 0xC0;
    response[pos++] = (uint8_t)sizeof(struct dns_header);
    rr = (struct dns_rr *)(response + pos);
    rr->type = ee16(DNS_A);
    rr->class = ee16(3);
    rr->ttl = ee32(60);
    rr->rdlength = ee16(4);
    pos += sizeof(struct dns_rr);
    memcpy(&response[pos], ip_bytes, sizeof(ip_bytes));
    pos += sizeof(ip_bytes);

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)], response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_int_eq(dns_lookup_calls, 0);
    ck_assert_uint_eq(dns_lookup_ip, 0U);
    ck_assert_uint_eq(s.dns_id, 0x1234);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_A);
}
END_TEST

START_TEST(test_dns_callback_non_in_ptr_answer_ignored)
{
    struct wolfIP s;
    uint8_t response[192];
    int pos;
    struct dns_header *hdr = (struct dns_header *)response;
    struct dns_question *q;
    struct dns_rr *rr;
    const char *ptr_name = "1.0.0.10.in-addr.arpa";
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_query_type = DNS_QUERY_TYPE_PTR;
    s.dns_id = 0x1234;
    s.dns_ptr_cb = test_dns_ptr_cb;
    s.dns_lookup_cb = NULL;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)];

    memset(response, 0, sizeof(response));
    hdr->id = ee16(s.dns_id);
    hdr->flags = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(1);
    pos = sizeof(struct dns_header);
    response[pos++] = 1; response[pos++] = 'a';
    response[pos++] = 3; memcpy(&response[pos], "com", 3); pos += 3;
    response[pos++] = 0;
    q = (struct dns_question *)(response + pos);
    q->qtype = ee16(DNS_PTR);
    q->qclass = ee16(1);
    pos += sizeof(struct dns_question);
    response[pos++] = 0xC0;
    response[pos++] = (uint8_t)sizeof(struct dns_header);
    rr = (struct dns_rr *)(response + pos);
    rr->type = ee16(DNS_PTR);
    rr->class = ee16(3);
    rr->ttl = ee32(60);
    rr->rdlength = ee16((uint16_t)(strlen(ptr_name) + 2));
    pos += sizeof(struct dns_rr);
    response[pos++] = (uint8_t)strlen(ptr_name);
    memcpy(&response[pos], ptr_name, strlen(ptr_name));
    pos += (int)strlen(ptr_name);
    response[pos++] = 0;

    enqueue_udp_rx(ts, response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_uint_eq(s.dns_id, 0x1234);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_PTR);
}
END_TEST

START_TEST(test_dns_callback_malformed_compressed_name_aborts_query)
{
    struct wolfIP s;
    uint8_t response[128];
    int pos;
    struct dns_header *hdr = (struct dns_header *)response;
    struct dns_question *q;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_id = 0x1234;
    s.dns_lookup_cb = test_dns_lookup_cb;
    dns_lookup_calls = 0;
    dns_lookup_ip = 0;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    memset(response, 0, sizeof(response));
    hdr->id = ee16(s.dns_id);
    hdr->flags = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(1);
    pos = sizeof(struct dns_header);
    response[pos++] = 1;
    response[pos++] = 'a';
    response[pos++] = 0;
    q = (struct dns_question *)(response + pos);
    q->qtype = ee16(DNS_A);
    q->qclass = ee16(1);
    pos += sizeof(struct dns_question);

    /* Truncate the compressed owner name so dns_skip_name() hits the abort path. */
    response[pos++] = 0xC0;

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)], response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);

    /* Malformed compressed names must abort the active query and suppress callbacks. */
    ck_assert_int_eq(dns_lookup_calls, 0);
    ck_assert_uint_eq(dns_lookup_ip, 0U);
    ck_assert_uint_eq(s.dns_id, 0);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
    ck_assert_ptr_eq(s.dns_lookup_cb, NULL);
}
END_TEST

START_TEST(test_dns_callback_abort_clears_query_state)
{
    struct wolfIP s;
    uint8_t bad_response[64];
    uint8_t good_response[128];
    int pos;
    struct dns_header *hdr = (struct dns_header *)bad_response;
    struct dns_header *good_hdr = (struct dns_header *)good_response;
    struct dns_question *q;
    struct dns_rr *rr;
    const uint8_t ip_bytes[4] = {0x0A, 0x00, 0x00, 0x42};

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_id = 0x1234;
    s.dns_lookup_cb = test_dns_lookup_cb;
    dns_lookup_calls = 0;
    dns_lookup_ip = 0;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    memset(bad_response, 0, sizeof(bad_response));
    hdr->id = ee16(s.dns_id);
    hdr->flags = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(0);
    pos = sizeof(struct dns_header);
    bad_response[pos++] = 60;
    memset(&bad_response[pos], 'a', 5);
    pos += 5;

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)], bad_response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_uint_eq(s.dns_id, 0);

    memset(good_response, 0, sizeof(good_response));
    good_hdr->id = 0;
    good_hdr->flags = ee16(0x8100);
    good_hdr->qdcount = ee16(1);
    good_hdr->ancount = ee16(1);
    pos = sizeof(struct dns_header);
    good_response[pos++] = 7; memcpy(&good_response[pos], "example", 7); pos += 7;
    good_response[pos++] = 3; memcpy(&good_response[pos], "com", 3); pos += 3;
    good_response[pos++] = 0;
    q = (struct dns_question *)(good_response + pos);
    q->qtype = ee16(DNS_A);
    q->qclass = ee16(1);
    pos += sizeof(struct dns_question);
    good_response[pos++] = 0xC0;
    good_response[pos++] = (uint8_t)sizeof(struct dns_header);
    rr = (struct dns_rr *)(good_response + pos);
    rr->type = ee16(DNS_A);
    rr->class = ee16(1);
    rr->ttl = ee32(60);
    rr->rdlength = ee16(4);
    pos += sizeof(struct dns_rr);
    memcpy(&good_response[pos], ip_bytes, sizeof(ip_bytes));
    pos += sizeof(ip_bytes);

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)], good_response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_int_eq(dns_lookup_calls, 0);
    ck_assert_uint_eq(dns_lookup_ip, 0U);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
    ck_assert_ptr_eq(s.dns_lookup_cb, NULL);
}
END_TEST

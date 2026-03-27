static struct wolfIP *poll_rearm_stack;
static int poll_rearm_cb_calls;
static int poll_rearm_recv_len;
static int poll_budget_packets_left;
static int poll_budget_poll_calls;

static int test_poll_budget_ll_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct wolfIP_eth_frame *eth = (struct wolfIP_eth_frame *)frame;

    (void)dev;
    if (len < ETH_HEADER_LEN || poll_budget_packets_left <= 0)
        return 0;
    memset(eth, 0, ETH_HEADER_LEN);
    poll_budget_packets_left--;
    poll_budget_poll_calls++;
    return ETH_HEADER_LEN;
}

static void test_poll_rearm_tcp_cb(int sock_fd, uint16_t events, void *arg)
{
    uint8_t buf[8];

    (void)arg;
    poll_rearm_cb_calls++;
    ck_assert_ptr_nonnull(poll_rearm_stack);
    ck_assert_uint_eq(events & CB_EVENT_READABLE, CB_EVENT_READABLE);
    ck_assert_int_eq(wolfIP_sock_recvfrom(poll_rearm_stack, sock_fd, buf,
            (size_t)poll_rearm_recv_len, 0, NULL, NULL), poll_rearm_recv_len);
}

START_TEST(test_wolfip_poll_executes_timers_and_callbacks)
{
    struct wolfIP s;
    struct wolfIP_timer tmr;
    int udp_sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    timer_cb_calls = 0;
    socket_cb_calls = 0;
    socket_cb_last_fd = -1;
    socket_cb_last_events = 0;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 100;
    tmr.arg = NULL;
    timers_binheap_insert(&s.timers, tmr);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    wolfIP_register_callback(&s, udp_sd, test_socket_cb, NULL);
    s.udpsockets[SOCKET_UNMARK(udp_sd)].events = CB_EVENT_READABLE;

    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(timer_cb_calls, 1);
    ck_assert_int_eq(socket_cb_calls, 1);
    ck_assert_int_eq(socket_cb_last_fd, udp_sd);
    ck_assert_int_eq(socket_cb_last_events, CB_EVENT_READABLE);
    ck_assert_int_eq(s.udpsockets[SOCKET_UNMARK(udp_sd)].events, 0);
}
END_TEST

START_TEST(test_wolfip_poll_drains_all_expired_timers_in_one_pass)
{
    struct wolfIP s;
    struct wolfIP_timer tmr;

    wolfIP_init(&s);
    mock_link_init(&s);
    timer_cb_calls = 0;

    /* Multiple expired timers should all run during the same poll iteration. */
    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 100;
    timers_binheap_insert(&s.timers, tmr);

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 90;
    timers_binheap_insert(&s.timers, tmr);

    (void)wolfIP_poll(&s, 100);

    /* The timer heap should be empty once all expired callbacks have run. */
    ck_assert_int_eq(timer_cb_calls, 2);
    ck_assert_uint_eq(s.timers.size, 0U);
}
END_TEST

START_TEST(test_wolfip_poll_preserves_tcp_events_raised_during_callback)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t payload[8] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    ck_assert_int_eq(queue_insert(&ts->sock.tcp.rxbuf, payload, 0, sizeof(payload)), 0);

    poll_rearm_stack = &s;
    poll_rearm_cb_calls = 0;
    poll_rearm_recv_len = 4;
    wolfIP_register_callback(&s, tcp_sd, test_poll_rearm_tcp_cb, NULL);
    ts->events = CB_EVENT_READABLE;

    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(poll_rearm_cb_calls, 1);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, CB_EVENT_READABLE);

    (void)wolfIP_poll(&s, 101);
    ck_assert_int_eq(poll_rearm_cb_calls, 2);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, 0U);
}
END_TEST

START_TEST(test_wolfip_poll_limits_device_drain_to_poll_budget)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *ll;

    wolfIP_init(&s);
    mock_link_init(&s);
    ll = wolfIP_ll_at(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);
    ll->poll = test_poll_budget_ll_poll;
    ll->non_ethernet = 0;

    /* Feed more frames than the scheduler budget allows in a single poll call. */
    poll_budget_packets_left = WOLFIP_POLL_BUDGET + 3;
    poll_budget_poll_calls = 0;
    (void)wolfIP_poll(&s, 100);

    /* Step 1 should stop after consuming exactly one poll budget worth of packets. */
    ck_assert_int_eq(poll_budget_poll_calls, WOLFIP_POLL_BUDGET);
    ck_assert_int_eq(poll_budget_packets_left, 3);
}
END_TEST

START_TEST(test_filter_notify_tcp_metadata)
{
    struct wolfIP s;
    struct wolfIP_tcp_seg tcp;

    memset(&s, 0, sizeof(s));
    memset(&tcp, 0, sizeof(tcp));
    tcp.ip.src = ee32(0x0A000001U);
    tcp.ip.dst = ee32(0x0A000002U);
    tcp.ip.proto = WI_IPPROTO_TCP;
    tcp.src_port = ee16(1234);
    tcp.dst_port = ee16(5678);
    tcp.flags = (TCP_FLAG_SYN | TCP_FLAG_ACK);

    filter_cb_calls = 0;
    memset(&filter_last_event, 0, sizeof(filter_last_event));
    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));

    (void)wolfIP_filter_notify_tcp(WOLFIP_FILT_SENDING, &s, 1, &tcp, sizeof(tcp));
    ck_assert_int_eq(filter_cb_calls, 1);
    ck_assert_uint_eq(filter_last_event.meta.ip_proto, WOLFIP_FILTER_PROTO_TCP);
    ck_assert_uint_eq(filter_last_event.meta.l4.tcp.src_port, tcp.src_port);
    ck_assert_uint_eq(filter_last_event.meta.l4.tcp.dst_port, tcp.dst_port);
    ck_assert_uint_eq(filter_last_event.meta.l4.tcp.flags, tcp.flags);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_filter_dispatch_no_callback)
{
    struct wolfIP s;
    struct wolfIP_filter_metadata meta;

    memset(&s, 0, sizeof(s));
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));

    wolfIP_filter_init_metadata(&meta);
    meta.ip_proto = WOLFIP_FILTER_PROTO_TCP;

    ck_assert_int_eq(wolfIP_filter_dispatch(WOLFIP_FILT_RECEIVING, &s, 0, NULL, 0, &meta), 0);
}
END_TEST

START_TEST(test_filter_dispatch_mask_not_set)
{
    struct wolfIP s;
    struct wolfIP_filter_metadata meta;

    memset(&s, 0, sizeof(s));
    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(0);

    filter_cb_calls = 0;
    wolfIP_filter_init_metadata(&meta);
    meta.ip_proto = WOLFIP_FILTER_PROTO_TCP;

    ck_assert_int_eq(wolfIP_filter_dispatch(WOLFIP_FILT_RECEIVING, &s, 0, NULL, 0, &meta), 0);
    ck_assert_int_eq(filter_cb_calls, 0);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_filter_dispatch_lock_blocks)
{
    struct wolfIP s;
    struct wolfIP_filter_metadata meta;

    memset(&s, 0, sizeof(s));
    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));

    filter_cb_calls = 0;
    wolfIP_filter_init_metadata(&meta);
    meta.ip_proto = WOLFIP_FILTER_PROTO_TCP;

    wolfip_filter_lock = 1;
    ck_assert_int_eq(wolfIP_filter_dispatch(WOLFIP_FILT_RECEIVING, &s, 0, NULL, 0, &meta), 0);
    ck_assert_int_eq(filter_cb_calls, 0);
    wolfip_filter_lock = 0;

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_filter_dispatch_meta_null_initializes)
{
    struct wolfIP s;

    memset(&s, 0, sizeof(s));
    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));
    filter_cb_calls = 0;
    memset(&filter_last_event, 0xA5, sizeof(filter_last_event));

    ck_assert_int_eq(wolfIP_filter_dispatch(WOLFIP_FILT_RECEIVING, &s, 0, NULL, 0, NULL), 0);
    ck_assert_int_eq(filter_cb_calls, 1);
    ck_assert_uint_eq(filter_last_event.meta.ip_proto, 0);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_filter_socket_event_unknown_proto)
{
    struct wolfIP s;
    struct tsocket ts;

    wolfIP_init(&s);
    memset(&ts, 0, sizeof(ts));
    ts.S = &s;
    ts.proto = 0;

    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_CONNECTING));
    filter_cb_calls = 0;

    (void)wolfIP_filter_notify_socket_event(WOLFIP_FILT_CONNECTING, &s, &ts,
            0x0A000001U, 1234, 0x0A000002U, 4321);
    ck_assert_int_eq(filter_cb_calls, 1);
    ck_assert_uint_eq(filter_last_event.meta.ip_proto, 0);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_filter_socket_event_null_socket_uses_primary_defaults)
{
    struct wolfIP s;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_CONNECTING));
    filter_cb_calls = 0;
    memset(&filter_last_event, 0xA5, sizeof(filter_last_event));

    (void)wolfIP_filter_notify_socket_event(WOLFIP_FILT_CONNECTING, &s, NULL,
            local_ip, 1234, remote_ip, 4321);

    ck_assert_int_eq(filter_cb_calls, 1);
    ck_assert_uint_eq(filter_last_event.if_idx, WOLFIP_PRIMARY_IF_IDX);
    ck_assert_uint_eq(filter_last_event.meta.ip_proto, 0);
    ck_assert_uint_eq(filter_last_event.meta.src_ip, ee32(local_ip));
    ck_assert_uint_eq(filter_last_event.meta.dst_ip, ee32(remote_ip));

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
}
END_TEST

START_TEST(test_filter_socket_event_proto_variants)
{
    struct wolfIP s;
    struct tsocket ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint16_t local_port = 1234;
    uint16_t remote_port = 4321;

    wolfIP_init(&s);
    memset(&ts, 0, sizeof(ts));
    ts.S = &s;
    ts.if_idx = TEST_PRIMARY_IF;

    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_CONNECTING));
    filter_cb_calls = 0;

    ts.proto = WI_IPPROTO_TCP;
    (void)wolfIP_filter_notify_socket_event(WOLFIP_FILT_CONNECTING, &s, &ts,
            local_ip, local_port, remote_ip, remote_port);
    ck_assert_int_eq(filter_cb_calls, 1);
    ck_assert_uint_eq(filter_last_event.meta.ip_proto, WOLFIP_FILTER_PROTO_TCP);
    ck_assert_uint_eq(filter_last_event.meta.l4.tcp.src_port, ee16(local_port));
    ck_assert_uint_eq(filter_last_event.meta.l4.tcp.dst_port, ee16(remote_port));

    ts.proto = WI_IPPROTO_UDP;
    (void)wolfIP_filter_notify_socket_event(WOLFIP_FILT_CONNECTING, &s, &ts,
            local_ip, local_port, remote_ip, remote_port);
    ck_assert_int_eq(filter_cb_calls, 2);
    ck_assert_uint_eq(filter_last_event.meta.ip_proto, WOLFIP_FILTER_PROTO_UDP);
    ck_assert_uint_eq(filter_last_event.meta.l4.udp.src_port, ee16(local_port));
    ck_assert_uint_eq(filter_last_event.meta.l4.udp.dst_port, ee16(remote_port));

    ts.proto = WI_IPPROTO_ICMP;
    (void)wolfIP_filter_notify_socket_event(WOLFIP_FILT_CONNECTING, &s, &ts,
            local_ip, local_port, remote_ip, remote_port);
    ck_assert_int_eq(filter_cb_calls, 3);
    ck_assert_uint_eq(filter_last_event.meta.ip_proto, WOLFIP_FILTER_PROTO_ICMP);
    ck_assert_uint_eq(filter_last_event.meta.l4.icmp.type, 0);
    ck_assert_uint_eq(filter_last_event.meta.l4.icmp.code, 0);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_filter_setters_and_get_mask)
{
    wolfIP_filter_set_mask(0x1234U);
    ck_assert_uint_eq(wolfIP_filter_get_mask(), 0x1234U);
    wolfIP_filter_set_eth_mask(0x10U);
    wolfIP_filter_set_ip_mask(0x20U);
    wolfIP_filter_set_tcp_mask(0x40U);
    wolfIP_filter_set_udp_mask(0x80U);
    wolfIP_filter_set_icmp_mask(0x100U);
    ck_assert_uint_eq(wolfIP_filter_get_mask(), 0x1234U);
}
END_TEST

START_TEST(test_filter_mask_for_proto_variants)
{
    wolfIP_filter_set_mask(0x1U);
    wolfIP_filter_set_eth_mask(0);
    wolfIP_filter_set_ip_mask(0);
    wolfIP_filter_set_tcp_mask(0);
    wolfIP_filter_set_udp_mask(0);
    wolfIP_filter_set_icmp_mask(0);

    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_ETH), 0x1U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_IP), 0x1U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_TCP), 0x1U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_UDP), 0x1U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_ICMP), 0x1U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(0xFFFF), 0x1U);

    wolfIP_filter_set_eth_mask(0x10U);
    wolfIP_filter_set_ip_mask(0x20U);
    wolfIP_filter_set_tcp_mask(0x40U);
    wolfIP_filter_set_udp_mask(0x80U);
    wolfIP_filter_set_icmp_mask(0x100U);

    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_ETH), 0x10U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_IP), 0x20U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_TCP), 0x40U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_UDP), 0x80U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_ICMP), 0x100U);
}
END_TEST

START_TEST(test_filter_dispatch_paths)
{
    struct wolfIP s;
    struct wolfIP_filter_metadata meta;
    int ret;

    wolfIP_init(&s);
    filter_cb_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(0);
    wolfIP_filter_set_tcp_mask(0);

    wolfip_filter_lock = 1;
    ret = wolfIP_filter_dispatch(WOLFIP_FILT_SENDING, &s, 0, NULL, 0, NULL);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(filter_cb_calls, 0);
    wolfip_filter_lock = 0;

    ret = wolfIP_filter_dispatch(WOLFIP_FILT_SENDING, &s, 0, NULL, 0, NULL);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(filter_cb_calls, 0);

    wolfIP_filter_set_tcp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    wolfIP_filter_init_metadata(&meta);
    meta.ip_proto = WOLFIP_FILTER_PROTO_TCP;
    ret = wolfIP_filter_dispatch(WOLFIP_FILT_SENDING, &s, 0, NULL, 0, &meta);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(filter_cb_calls, 1);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
    wolfIP_filter_set_tcp_mask(0);
}
END_TEST

START_TEST(test_sock_wrappers_basic)
{
    struct wolfIP s;
    int udp_sd;
    uint8_t buf[8];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ret = wolfIP_sock_send(&s, udp_sd, buf, sizeof(buf), 0);
    ck_assert_int_eq(ret, -1);

    ret = wolfIP_sock_write(&s, udp_sd, buf, sizeof(buf));
    ck_assert_int_eq(ret, -1);

    ret = wolfIP_sock_recv(&s, udp_sd, buf, sizeof(buf), 0);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);

    ret = wolfIP_sock_read(&s, udp_sd, buf, sizeof(buf));
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_socket_errors)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_socket(&s, 0, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP), -1);
    ck_assert_int_eq(wolfIP_sock_socket(&s, AF_INET, 0xFF, WI_IPPROTO_UDP), -1);
    ck_assert_int_eq(wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_TCP), -1);
}
END_TEST
START_TEST(test_udp_sendto_and_recvfrom)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    uint8_t rxbuf[8] = {0};
    struct wolfIP_sockaddr_in from;
    socklen_t from_len = sizeof(from);
    int ret;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint16_t local_port = 4000;
    uint16_t remote_port = 5000;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ret = wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(remote_port);
    sin.sin_addr.s_addr = ee32(remote_ip);
    ret = wolfIP_sock_sendto(&s, sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, (int)sizeof(payload));

    ts = &s.udpsockets[SOCKET_UNMARK(sd)];
    ck_assert_uint_gt(ts->src_port, 0);
    ck_assert_uint_eq(ts->dst_port, remote_port);
    ck_assert_uint_eq(ts->remote_ip, remote_ip);
    ck_assert_uint_gt(fifo_len(&ts->sock.udp.txbuf), 0);

    inject_udp_datagram(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            payload, sizeof(payload));

    memset(&from, 0, sizeof(from));
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len);
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(rxbuf, payload, sizeof(payload));
    ck_assert_uint_eq(from.sin_port, ee16(remote_port));
}
END_TEST

START_TEST(test_udp_sendto_respects_mtu_api)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t small_payload[38] = {0};
    uint8_t large_payload[39] = {0};
    struct tsocket *ts;
    uint32_t mtu = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF, 80U), 0);
    ck_assert_int_eq(wolfIP_mtu_get(&s, TEST_PRIMARY_IF, &mtu), 0);
    ck_assert_uint_eq(mtu, 80U);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(sd)];
    fifo_init(&ts->sock.udp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5000);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, small_payload, sizeof(small_payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(small_payload));
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.txbuf));

    fifo_init(&ts->sock.udp.txbuf, ts->txmem, TXBUF_SIZE);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, large_payload, sizeof(large_payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    ck_assert_ptr_null(fifo_peek(&ts->sock.udp.txbuf));
}
END_TEST

START_TEST(test_udp_recvfrom_sets_remote_ip)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t rxbuf[4] = {0};
    struct wolfIP_sockaddr_in from;
    socklen_t from_len = sizeof(from);
    int ret;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint16_t local_port = 4001;
    uint16_t remote_port = 5001;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ret = wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, 0);

    ts = &s.udpsockets[SOCKET_UNMARK(sd)];
    ck_assert_uint_eq(ts->remote_ip, 0);

    inject_udp_datagram(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            payload, sizeof(payload));

    memset(&from, 0, sizeof(from));
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len);
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(rxbuf, payload, sizeof(payload));
    ck_assert_uint_eq(from.sin_addr.s_addr, ee32(remote_ip));
    ck_assert_uint_eq(ts->remote_ip, remote_ip);
}
END_TEST

START_TEST(test_udp_recvfrom_null_src_addr_len)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t rxbuf[4] = {0};
    int ret;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint16_t local_port = 4002;
    uint16_t remote_port = 5002;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ret = wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, 0);

    inject_udp_datagram(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            payload, sizeof(payload));

    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(rxbuf, payload, sizeof(payload));
}
END_TEST

START_TEST(test_udp_recvfrom_preserves_remote_ip)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {0x55, 0x66, 0x77, 0x88};
    uint8_t rxbuf[4] = {0};
    struct wolfIP_sockaddr_in from;
    socklen_t from_len = sizeof(from);
    int ret;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    ip4 preset_remote_ip = 0x0A000002U;
    uint16_t local_port = 4003;
    uint16_t remote_port = 5003;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ret = wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, 0);

    ts = &s.udpsockets[SOCKET_UNMARK(sd)];
    ts->remote_ip = preset_remote_ip;

    inject_udp_datagram(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            payload, sizeof(payload));

    memset(&from, 0, sizeof(from));
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len);
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(rxbuf, payload, sizeof(payload));
    ck_assert_uint_eq(from.sin_addr.s_addr, ee32(remote_ip));
    ck_assert_uint_eq(ts->remote_ip, preset_remote_ip);
}
END_TEST

START_TEST(test_udp_recvfrom_null_addrlen)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {0x9A, 0xBC, 0xDE, 0xF0};
    uint8_t rxbuf[4] = {0};
    struct wolfIP_sockaddr_in from;
    int ret;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint16_t local_port = 4004;
    uint16_t remote_port = 5004;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ret = wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, 0);

    inject_udp_datagram(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            payload, sizeof(payload));

    memset(&from, 0, sizeof(from));
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
            (struct wolfIP_sockaddr *)&from, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_udp_recvfrom_src_equals_local_ip_does_not_persist_remote)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t rxbuf[4] = {0};
    struct wolfIP_sockaddr_in from;
    socklen_t from_len = sizeof(from);
    int ret;
    ip4 local_ip = 0x0A000001U;
    uint16_t local_port = 4005;
    uint16_t remote_port = 5005;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ret = wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, 0);

    ts = &s.udpsockets[SOCKET_UNMARK(sd)];
    ck_assert_uint_eq(ts->remote_ip, 0);

    inject_udp_datagram(&s, TEST_PRIMARY_IF, local_ip, local_ip, remote_port, local_port,
            payload, sizeof(payload));

    memset(&from, 0, sizeof(from));
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len);
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(rxbuf, payload, sizeof(payload));
    ck_assert_uint_eq(from.sin_addr.s_addr, ee32(local_ip));
    ck_assert_uint_eq(ts->remote_ip, 0);
}
END_TEST

START_TEST(test_sock_error_paths)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4];
    int ret;
    socklen_t alen;

    wolfIP_init(&s);
    mock_link_init(&s);

    ret = wolfIP_sock_sendto(&s, -1, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    ret = wolfIP_sock_recvfrom(&s, -1, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    ret = wolfIP_sock_getsockname(&s, -1, (struct wolfIP_sockaddr *)&sin, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    ret = wolfIP_sock_getpeername(&s, -1, (struct wolfIP_sockaddr *)&sin, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    alen = (socklen_t)(sizeof(sin) - 1);
    ret = wolfIP_sock_bind(&s, -1, (struct wolfIP_sockaddr *)&sin, alen);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST
START_TEST(test_dns_format_ptr_name)
{
    char out[64];
    int ret;
    ret = dns_format_ptr_name(out, sizeof(out), 0xC0A80102U);
    ck_assert_int_eq(ret, 0);
    ck_assert_str_eq(out, "2.1.168.192.in-addr.arpa");
}
END_TEST

START_TEST(test_sock_name_and_opt_errors)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen;
    int opt;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ret = wolfIP_sock_getsockname(&s, udp_sd, NULL, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    memset(&sin, 0, sizeof(sin));
    alen = (socklen_t)(sizeof(sin) - 1);
    ret = wolfIP_sock_getsockname(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, &alen);
    ck_assert_int_eq(ret, -1);

    ret = wolfIP_sock_getpeername(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, &alen);
    ck_assert_int_eq(ret, -1);

    opt = 1;
    ret = wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, NULL, sizeof(opt));
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    alen = 1;
    ret = wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &opt, &alen);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST
START_TEST(test_dns_skip_and_copy_name)
{
    uint8_t buf[64];
    int pos = 0;
    int ret;
    char out[64];

    /* www.example.com */
    buf[pos++] = 3; memcpy(&buf[pos], "www", 3); pos += 3;
    buf[pos++] = 7; memcpy(&buf[pos], "example", 7); pos += 7;
    buf[pos++] = 3; memcpy(&buf[pos], "com", 3); pos += 3;
    buf[pos++] = 0;

    ret = dns_skip_name(buf, sizeof(buf), 0);
    ck_assert_int_eq(ret, pos);

    ret = dns_copy_name(buf, sizeof(buf), 0, out, sizeof(out));
    ck_assert_int_eq(ret, 0);
    ck_assert_str_eq(out, "www.example.com");

    /* add a pointer to the name at offset 0 */
    buf[pos++] = 0xC0;
    buf[pos++] = 0x00;
    ret = dns_copy_name(buf, sizeof(buf), pos - 2, out, sizeof(out));
    ck_assert_int_eq(ret, 0);
    ck_assert_str_eq(out, "www.example.com");
}
END_TEST

START_TEST(test_inline_helpers)
{
    char buf[32];
    ck_assert_uint_eq(atou("0"), 0);
    ck_assert_uint_eq(atou("1234"), 1234);

    ck_assert_uint_eq(atoip4("10.0.0.1"), 0x0A000001U);
    ck_assert_uint_eq(atoip4("192.168.1.2"), 0xC0A80102U);

    iptoa(0xC0A80102U, buf);
    ck_assert_str_eq(buf, "192.168.1.2");
    iptoa(0x0A000001U, buf);
    ck_assert_str_eq(buf, "10.0.0.1");
}
END_TEST

START_TEST(test_sock_bind_wrong_family)
{
    struct wolfIP s;
    int udp_sd;
    int tcp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = 0;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_bind(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_bind_invalid_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    ck_assert_int_eq(wolfIP_sock_bind(&s, -1, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_bind(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    ck_assert_int_eq(wolfIP_sock_bind(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    ck_assert_int_eq(wolfIP_sock_bind(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_bind_tcp_state_not_closed)
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
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 10;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    ck_assert_int_eq(wolfIP_sock_bind(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_bind_tcp_filter_blocks)
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
    ts->local_ip = 0;
    ts->src_port = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    filter_block_reason = WOLFIP_FILT_BINDING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_BINDING));

    ck_assert_int_eq(wolfIP_sock_bind(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    ck_assert_uint_eq(ts->local_ip, 0U);
    ck_assert_uint_eq(ts->src_port, 0U);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_sock_bind_udp_src_port_nonzero)
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
    ts->src_port = 1234;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5678);
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_bind_udp_filter_blocks)
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
    ts->src_port = 0;
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(2222);
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    filter_block_reason = WOLFIP_FILT_BINDING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_BINDING));

    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    ck_assert_uint_eq(ts->local_ip, 0U);
    ck_assert_uint_eq(ts->src_port, 0U);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_sock_bind_icmp_success)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->src_port = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7);
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    ck_assert_int_eq(wolfIP_sock_bind(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->src_port, 7U);
    ck_assert_uint_eq(ts->bound_local_ip, 0x0A000001U);
}
END_TEST

START_TEST(test_sock_connect_wrong_family)
{
    struct wolfIP s;
    int tcp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = 0;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_accept_error_paths)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_LISTEN;

    alen = (socklen_t)(sizeof(sin) - 1);
    ck_assert_int_eq(wolfIP_sock_accept(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, &alen), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_accept(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, NULL), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_accept(&s, tcp_sd, NULL, NULL), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_accept_non_tcp_socket_sets_addrlen)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = sizeof(sin);

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_accept(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, &alen), -WOLFIP_EINVAL);
    ck_assert_uint_eq(alen, sizeof(sin));
}
END_TEST

START_TEST(test_sock_accept_null_addr_with_addrlen)
{
    struct wolfIP s;
    int tcp_sd;
    socklen_t alen = 123;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_accept(&s, tcp_sd, NULL, &alen), -1);
    ck_assert_uint_eq(alen, sizeof(struct wolfIP_sockaddr_in));
}
END_TEST

START_TEST(test_sock_recvfrom_short_addrlen)
{
    struct wolfIP s;
    int udp_sd;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen;
    uint8_t buf[4];

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    alen = (socklen_t)1;
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, &alen), -WOLFIP_EINVAL);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    alen = (socklen_t)1;
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, icmp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, &alen), -WOLFIP_EINVAL);
}
END_TEST
START_TEST(test_dns_query_and_callback_a)
{
    struct wolfIP s;
    uint16_t id = 0;
    uint8_t response[128];
    int pos = 0;
    struct dns_header *hdr = (struct dns_header *)response;
    struct dns_question *q;
    struct dns_rr *rr;
    const uint8_t ip_bytes[4] = {0x0A, 0x00, 0x00, 0x42};
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    s.dns_server = 0x08080808U;
    dns_lookup_calls = 0;
    dns_lookup_ip = 0;
    s.dns_lookup_cb = test_dns_lookup_cb;

    ck_assert_int_eq(dns_send_query(&s, "example.com", &id, DNS_A), 0);
    ck_assert_uint_ne(id, 0);
    ck_assert_uint_eq(s.dns_id, id);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_A);

    memset(response, 0, sizeof(response));
    hdr->id = ee16(id);
    hdr->flags = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(1);
    pos = sizeof(struct dns_header);
    /* question name */
    response[pos++] = 7; memcpy(&response[pos], "example", 7); pos += 7;
    response[pos++] = 3; memcpy(&response[pos], "com", 3); pos += 3;
    response[pos++] = 0;
    q = (struct dns_question *)(response + pos);
    q->qtype = ee16(DNS_A);
    q->qclass = ee16(1);
    pos += sizeof(struct dns_question);
    /* answer name pointer to question */
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

    ts = &s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)];
    inject_udp_datagram(&s, TEST_PRIMARY_IF, s.dns_server, local_ip, DNS_PORT, ts->src_port,
            response, (uint16_t)pos);

    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_int_eq(dns_lookup_calls, 1);
    ck_assert_uint_eq(dns_lookup_ip, 0x0A000042U);
    ck_assert_int_eq(s.dns_id, 0);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
}
END_TEST

START_TEST(test_sock_bind_non_local_ip_fails)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A0000FFU);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_connect_bad_addrlen)
{
    struct wolfIP s;
    int icmp_sd;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, (socklen_t)1), -WOLFIP_EINVAL);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, (socklen_t)1), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_tcp_bad_addrlen)
{
    struct wolfIP s;
    int tcp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, (socklen_t)1), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_invalid_args)
{
    struct wolfIP s;
    int tcp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, NULL, sizeof(sin)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_connect(&s, -1, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_invalid_tcp_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    int bad_fd = MARK_TCP_SOCKET | MAX_TCPSOCKETS;

    wolfIP_init(&s);
    mock_link_init(&s);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, bad_fd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_connect(&s, 0, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_udp_invalid_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    int bad_fd = MARK_UDP_SOCKET | MAX_UDPSOCKETS;

    wolfIP_init(&s);
    mock_link_init(&s);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, bad_fd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_udp_wrong_family)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = 0;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)),
            -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_udp_short_addrlen)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t bad_len = (socklen_t)(sizeof(struct wolfIP_sockaddr_in) - 1);

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, bad_len),
            -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_icmp_invalid_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    int bad_fd = MARK_ICMP_SOCKET | MAX_ICMPSOCKETS;

    wolfIP_init(&s);
    mock_link_init(&s);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, bad_fd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_udp_sets_local_ip_from_conf)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(remote_ip);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ck_assert_uint_eq(ts->local_ip, local_ip);
}
END_TEST

START_TEST(test_sock_connect_udp_falls_back_to_primary)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(remote_ip);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ck_assert_uint_eq(ts->local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_connect_udp_primary_missing)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ck_assert_uint_eq(ts->local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_connect_udp_bound_local_ip_no_match)
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
    ts->bound_local_ip = 0x0B000001U;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_udp_bound_local_ip_match)
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
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, local_ip);
    ck_assert_uint_eq(ts->if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_sock_connect_icmp_sets_local_ip_from_conf)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, local_ip);
}
END_TEST

START_TEST(test_sock_connect_icmp_wrong_family)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = 0;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_icmp_local_ip_pre_set)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0x0A000001U;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, 0x0A000001U);
}
END_TEST

START_TEST(test_sock_connect_icmp_conf_null)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_connect_icmp_falls_back_to_primary)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_connect_icmp_primary_ip_any)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_connect_icmp_primary_ip_fallback)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 primary_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = TEST_SECOND_IF + 1;
    s.ipconf[TEST_PRIMARY_IF].ip = primary_ip;
    s.ipconf[TEST_PRIMARY_IF].mask = 0xFFFFFF00U;
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0B000001U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST

START_TEST(test_sock_connect_icmp_bound_local_ip_match)
{
    struct wolfIP s;
    const ip4 primary_ip = 0xC0A80009U;
    const ip4 secondary_ip = 0xC0A80109U;
    const ip4 remote_secondary = 0xC0A801A1U;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->bound_local_ip = primary_ip;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(remote_secondary);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, primary_ip);
    ck_assert_uint_eq(ts->if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_sock_connect_tcp_established_returns_zero)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
}
END_TEST

START_TEST(test_sock_connect_tcp_bound_local_ip_match)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;
    ts->bound_local_ip = local_ip;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_uint_eq(ts->local_ip, local_ip);
    ck_assert_uint_eq(ts->if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_sock_connect_tcp_bound_local_ip_no_match)
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
    ts->bound_local_ip = 0x0B000001U;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_tcp_filter_blocks)
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

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    filter_block_reason = WOLFIP_FILT_CONNECTING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_CONNECTING));

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSED);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST
START_TEST(test_sock_connect_tcp_local_ip_from_conf)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_uint_eq(ts->local_ip, local_ip);
}
END_TEST

START_TEST(test_sock_connect_tcp_local_ip_from_primary)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_uint_eq(ts->local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_connect_tcp_primary_ip_fallback)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 primary_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = TEST_SECOND_IF + 1;
    s.ipconf[TEST_PRIMARY_IF].ip = primary_ip;
    s.ipconf[TEST_PRIMARY_IF].mask = 0xFFFFFF00U;
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0B000001U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST
START_TEST(test_sock_accept_negative_fd)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_accept(&s, -1, NULL, NULL), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_tcp_conf_null_primary_null)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_uint_eq(ts->local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_connect_tcp_state_not_closed)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_LISTEN;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST
START_TEST(test_sock_accept_invalid_tcp_fd)
{
    struct wolfIP s;
    int bad_fd = MARK_TCP_SOCKET | MAX_TCPSOCKETS;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_accept(&s, bad_fd, NULL, NULL), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_accept_success_sets_addr)
{
    struct wolfIP s;
    int listen_sd;
    int client_sd;
    struct tsocket *listener;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = sizeof(sin);

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
    listener = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(listener->sock.tcp.state, TCP_SYN_RCVD);

    client_sd = wolfIP_sock_accept(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, &alen);
    ck_assert_int_gt(client_sd, 0);
    ck_assert_uint_eq(alen, sizeof(sin));
    ck_assert_uint_eq(sin.sin_family, AF_INET);
}
END_TEST

START_TEST(test_sock_accept_no_available_socket)
{
    struct wolfIP s;
    int listen_sd;
    struct wolfIP_sockaddr_in sin;
    struct tsocket *ts;
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

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);

    for (i = 0; i < MAX_TCPSOCKETS; i++) {
        ts = &s.tcpsockets[i];
        ts->proto = WI_IPPROTO_TCP;
        ts->sock.tcp.state = TCP_ESTABLISHED;
    }

    ck_assert_int_eq(wolfIP_sock_accept(&s, listen_sd, NULL, NULL), -1);
}
END_TEST

START_TEST(test_sock_accept_no_free_socket_syn_rcvd)
{
    struct wolfIP s;
    int listen_sd;
    struct wolfIP_sockaddr_in sin;
    struct tsocket *ts;
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

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);

    for (i = 0; i < MAX_TCPSOCKETS; i++) {
        if (i == SOCKET_UNMARK(listen_sd)) {
            continue;
        }
        s.tcpsockets[i].proto = WI_IPPROTO_TCP;
        s.tcpsockets[i].sock.tcp.state = TCP_ESTABLISHED;
    }

    ck_assert_int_eq(wolfIP_sock_accept(&s, listen_sd, NULL, NULL), -1);
}
END_TEST

START_TEST(test_sock_accept_listen_no_connection)
{
    struct wolfIP s;
    int listen_sd;
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

    ck_assert_int_eq(wolfIP_sock_accept(&s, listen_sd, NULL, NULL), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_accept_bound_local_ip_no_match)
{
    struct wolfIP s;
    int listen_sd;
    int client_sd;
    struct tsocket *listener;
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

    listener = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    listener->bound_local_ip = 0x0A000001U;
    listener->if_idx = TEST_PRIMARY_IF;

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    s.if_count = 0;

    client_sd = wolfIP_sock_accept(&s, listen_sd, NULL, NULL);
    ck_assert_int_gt(client_sd, 0);
    ck_assert_uint_eq(listener->if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_sock_accept_starts_rto_timer)
{
    struct wolfIP s;
    int listen_sd;
    int client_sd;
    struct tsocket *listener;
    struct tsocket *accepted;
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

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    listener = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(listener->sock.tcp.state, TCP_SYN_RCVD);

    client_sd = wolfIP_sock_accept(&s, listen_sd, NULL, NULL);
    ck_assert_int_gt(client_sd, 0);

    accepted = &s.tcpsockets[SOCKET_UNMARK(client_sd)];
    /* Accepted socket should be in SYN_RCVD state with RTO timer active */
    ck_assert_int_eq(accepted->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(accepted->sock.tcp.ctrl_rto_active, 1);
    ck_assert_uint_eq(accepted->sock.tcp.ctrl_rto_retries, 0);
    ck_assert_int_ne(accepted->sock.tcp.tmr_rto, NO_TIMER);

    /* Listening socket should have returned to LISTEN with RTO stopped */
    ck_assert_int_eq(listener->sock.tcp.state, TCP_LISTEN);
    ck_assert_uint_eq(listener->sock.tcp.ctrl_rto_active, 0);
}
END_TEST

START_TEST(test_sock_accept_initializes_snd_una)
{
    struct wolfIP s;
    int listen_sd;
    int client_sd;
    struct tsocket *listener;
    struct tsocket *accepted;
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

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    listener = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(listener->sock.tcp.state, TCP_SYN_RCVD);

    /* Force a high ISN to exercise wrap-aware ordering. */
    {
        uint32_t isn = 0x80000000U;
        listener->sock.tcp.seq = isn;
        listener->sock.tcp.snd_una = isn;
    }

    client_sd = wolfIP_sock_accept(&s, listen_sd, NULL, NULL);
    ck_assert_int_gt(client_sd, 0);

    accepted = &s.tcpsockets[SOCKET_UNMARK(client_sd)];
    ck_assert_uint_eq(accepted->sock.tcp.seq, (uint32_t)(0x80000000U + 1U));
    ck_assert_uint_eq(accepted->sock.tcp.snd_una, 0x80000000U);
    ck_assert_int_eq(tcp_seq_leq(accepted->sock.tcp.snd_una, accepted->sock.tcp.seq), 1);
}
END_TEST

START_TEST(test_sock_accept_clones_half_open_state_and_queues_synack)
{
    struct wolfIP s;
    int listen_sd;
    int client_sd;
    struct tsocket *listener;
    struct tsocket *accepted;
    struct wolfIP_sockaddr_in sin;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg *seg;
    void *cb_arg = &s;
    uint32_t pre_accept_seq;
    uint32_t pre_accept_ack;
    uint32_t pre_accept_last_ts;
    uint32_t pre_accept_local_ip;
    uint32_t pre_accept_remote_ip;
    uint32_t pre_accept_peer_rwnd;
    uint16_t pre_accept_peer_mss;
    uint16_t pre_accept_src_port;
    uint16_t pre_accept_dst_port;
    uint8_t pre_accept_snd_wscale;
    uint8_t pre_accept_rcv_wscale;
    uint8_t pre_accept_ws_enabled;
    uint8_t pre_accept_ws_offer;
    uint8_t pre_accept_ts_enabled;
    uint8_t pre_accept_ts_offer;
    uint8_t pre_accept_sack_offer;
    uint8_t pre_accept_sack_permitted;

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

    listener = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    listener->callback = test_socket_cb;
    listener->callback_arg = cb_arg;

    /* Drive the listener into SYN_RCVD so accept() has half-open state to fork. */
    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    ck_assert_int_eq(listener->sock.tcp.state, TCP_SYN_RCVD);

    /* Seed half-open negotiation state so accept() must clone it into the child socket. */
    listener->sock.tcp.last_ts = 0x11223344U;
    listener->sock.tcp.peer_rwnd = 4096;
    listener->sock.tcp.peer_mss = 1200;
    listener->sock.tcp.snd_wscale = 4;
    listener->sock.tcp.rcv_wscale = 2;
    listener->sock.tcp.ws_enabled = 1;
    listener->sock.tcp.ws_offer = 1;
    listener->sock.tcp.ts_enabled = 1;
    listener->sock.tcp.ts_offer = 1;
    listener->sock.tcp.sack_offer = 1;
    listener->sock.tcp.sack_permitted = 1;

    pre_accept_seq = listener->sock.tcp.seq;
    pre_accept_ack = listener->sock.tcp.ack;
    pre_accept_last_ts = listener->sock.tcp.last_ts;
    pre_accept_local_ip = listener->local_ip;
    pre_accept_remote_ip = listener->remote_ip;
    pre_accept_peer_rwnd = listener->sock.tcp.peer_rwnd;
    pre_accept_peer_mss = listener->sock.tcp.peer_mss;
    pre_accept_src_port = listener->src_port;
    pre_accept_dst_port = listener->dst_port;
    pre_accept_snd_wscale = listener->sock.tcp.snd_wscale;
    pre_accept_rcv_wscale = listener->sock.tcp.rcv_wscale;
    pre_accept_ws_enabled = listener->sock.tcp.ws_enabled;
    pre_accept_ws_offer = listener->sock.tcp.ws_offer;
    pre_accept_ts_enabled = listener->sock.tcp.ts_enabled;
    pre_accept_ts_offer = listener->sock.tcp.ts_offer;
    pre_accept_sack_offer = listener->sock.tcp.sack_offer;
    pre_accept_sack_permitted = listener->sock.tcp.sack_permitted;

    /* Accept should fork the half-open state into a child socket and queue a SYN-ACK there. */
    client_sd = wolfIP_sock_accept(&s, listen_sd, NULL, NULL);
    ck_assert_int_gt(client_sd, 0);

    accepted = &s.tcpsockets[SOCKET_UNMARK(client_sd)];
    /* The child socket should inherit the negotiated transport parameters verbatim. */
    ck_assert_int_eq(accepted->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_ptr_eq(accepted->callback, test_socket_cb);
    ck_assert_ptr_eq(accepted->callback_arg, cb_arg);
    ck_assert_uint_eq(accepted->local_ip, pre_accept_local_ip);
    ck_assert_uint_eq(accepted->bound_local_ip, listener->bound_local_ip);
    ck_assert_uint_eq(accepted->if_idx, TEST_PRIMARY_IF);
    ck_assert_uint_eq(accepted->remote_ip, pre_accept_remote_ip);
    ck_assert_uint_eq(accepted->src_port, pre_accept_src_port);
    ck_assert_uint_eq(accepted->dst_port, pre_accept_dst_port);
    ck_assert_uint_eq(accepted->sock.tcp.ack, pre_accept_ack);
    ck_assert_uint_eq(accepted->sock.tcp.snd_una, pre_accept_seq);
    ck_assert_uint_eq(accepted->sock.tcp.last_ts, pre_accept_last_ts);
    ck_assert_uint_eq(accepted->sock.tcp.peer_rwnd, pre_accept_peer_rwnd);
    ck_assert_uint_eq(accepted->sock.tcp.peer_mss, pre_accept_peer_mss);
    ck_assert_uint_eq(accepted->sock.tcp.snd_wscale, pre_accept_snd_wscale);
    ck_assert_uint_eq(accepted->sock.tcp.rcv_wscale, pre_accept_rcv_wscale);
    ck_assert_uint_eq(accepted->sock.tcp.ws_enabled, pre_accept_ws_enabled);
    ck_assert_uint_eq(accepted->sock.tcp.ws_offer, pre_accept_ws_offer);
    ck_assert_uint_eq(accepted->sock.tcp.ts_enabled, pre_accept_ts_enabled);
    ck_assert_uint_eq(accepted->sock.tcp.ts_offer, pre_accept_ts_offer);
    ck_assert_uint_eq(accepted->sock.tcp.sack_offer, pre_accept_sack_offer);
    ck_assert_uint_eq(accepted->sock.tcp.sack_permitted, pre_accept_sack_permitted);
    ck_assert_uint_eq(accepted->sock.tcp.cwnd,
            tcp_initial_cwnd(pre_accept_peer_rwnd, tcp_cc_mss(accepted)));
    ck_assert_uint_eq(accepted->sock.tcp.ssthresh,
            tcp_initial_ssthresh(pre_accept_peer_rwnd));

    desc = fifo_peek(&accepted->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    seg = (struct wolfIP_tcp_seg *)(accepted->txmem + desc->pos + sizeof(*desc));
    /* SYN-ACK transmission must be queued on the accepted child, not the listener. */
    ck_assert_uint_eq(seg->flags, (TCP_FLAG_SYN | TCP_FLAG_ACK));
    ck_assert_uint_eq(ee32(seg->seq), pre_accept_seq);
    ck_assert_uint_eq(ee32(seg->ack), pre_accept_ack);

    /* The listener should be reset to passive-open state once the child is created. */
    ck_assert_int_eq(listener->sock.tcp.state, TCP_LISTEN);
    ck_assert_uint_eq(listener->sock.tcp.ctrl_rto_active, 0);
    ck_assert_uint_eq(listener->events & CB_EVENT_READABLE, 0);
}
END_TEST

START_TEST(test_sock_accept_synack_retransmission)
{
    struct wolfIP s;
    int listen_sd;
    int client_sd;
    struct tsocket *accepted;
    struct wolfIP_sockaddr_in sin;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg *seg;

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
    client_sd = wolfIP_sock_accept(&s, listen_sd, NULL, NULL);
    ck_assert_int_gt(client_sd, 0);

    accepted = &s.tcpsockets[SOCKET_UNMARK(client_sd)];
    ck_assert_int_eq(accepted->sock.tcp.state, TCP_SYN_RCVD);

    /* Clear tx buffer to prepare for retransmission check */
    fifo_init(&accepted->sock.tcp.txbuf, accepted->txmem, TXBUF_SIZE);
    s.last_tick = 10000;

    /* Simulate RTO timeout by calling tcp_rto_cb */
    tcp_rto_cb(accepted);

    /* Verify SYN-ACK was retransmitted */
    desc = fifo_peek(&accepted->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    seg = (struct wolfIP_tcp_seg *)(accepted->txmem + desc->pos + sizeof(*desc));
    ck_assert_uint_eq(seg->flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
    ck_assert_uint_eq(accepted->sock.tcp.ctrl_rto_retries, 1);
    ck_assert_int_ne(accepted->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_sock_accept_synack_window_not_scaled)
{
    struct wolfIP s;
    int listen_sd;
    int client_sd;
    struct tsocket *listener;
    struct tsocket *accepted;
    struct wolfIP_sockaddr_in sin;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg *seg;

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
    listener = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(listener->sock.tcp.state, TCP_SYN_RCVD);
    listener->sock.tcp.ws_enabled = 1;
    listener->sock.tcp.rcv_wscale = 3;

    client_sd = wolfIP_sock_accept(&s, listen_sd, NULL, NULL);
    ck_assert_int_gt(client_sd, 0);

    accepted = &s.tcpsockets[SOCKET_UNMARK(client_sd)];
    desc = fifo_peek(&accepted->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    seg = (struct wolfIP_tcp_seg *)(accepted->txmem + desc->pos + sizeof(*desc));

    ck_assert_uint_eq(seg->flags, (TCP_FLAG_SYN | TCP_FLAG_ACK));
    ck_assert_uint_eq(ee16(seg->win), queue_space((struct queue *)&accepted->sock.tcp.rxbuf));
}
END_TEST

START_TEST(test_sock_accept_ack_transitions_to_established)
{
    struct wolfIP s;
    int listen_sd;
    int client_sd;
    struct tsocket *accepted;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_tcp_seg ack;
    struct wolfIP_ll_dev *ll;

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
    client_sd = wolfIP_sock_accept(&s, listen_sd, NULL, NULL);
    ck_assert_int_gt(client_sd, 0);

    accepted = &s.tcpsockets[SOCKET_UNMARK(client_sd)];
    ck_assert_int_eq(accepted->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(accepted->sock.tcp.ctrl_rto_active, 1);

    /* Send pure ACK to complete the handshake */
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    memset(&ack, 0, sizeof(ack));
    memcpy(ack.ip.eth.dst, ll->mac, 6);
    ack.ip.eth.type = ee16(ETH_TYPE_IP);
    ack.ip.ver_ihl = 0x45;
    ack.ip.ttl = 64;
    ack.ip.proto = WI_IPPROTO_TCP;
    ack.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ack.ip.src = ee32(0x0A0000A1U);  /* Remote IP from inject_tcp_syn */
    ack.ip.dst = ee32(0x0A000001U);
    ack.ip.csum = 0;
    iphdr_set_checksum(&ack.ip);
    ack.src_port = ee16(40000);      /* Remote port from inject_tcp_syn */
    ack.dst_port = ee16(1234);
    ack.seq = ee32(accepted->sock.tcp.ack);
    ack.ack = ee32(accepted->sock.tcp.seq);
    ack.hlen = TCP_HEADER_LEN << 2;
    ack.flags = TCP_FLAG_ACK;
    ack.win = ee16(65535);
    fix_tcp_checksum(&ack, TCP_HEADER_LEN);

    tcp_input(&s, TEST_PRIMARY_IF, &ack,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    /* Verify socket transitioned to ESTABLISHED and RTO stopped */
    ck_assert_int_eq(accepted->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(accepted->sock.tcp.ctrl_rto_active, 0);
    ck_assert_uint_eq(accepted->sock.tcp.ctrl_rto_retries, 0);
    ck_assert_int_eq(accepted->sock.tcp.tmr_rto, NO_TIMER);
    /* Should be signaled as writable */
    ck_assert(accepted->events & CB_EVENT_WRITABLE);
}
END_TEST

START_TEST(test_sock_sendto_error_paths)
{
    struct wolfIP s;
    int tcp_sd;
    int udp_sd;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[8];

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0), -1);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, (size_t)(WI_IP_MTU), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, buf, (size_t)(ICMP_HEADER_LEN - 1), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_sendto_null_buf_or_len_zero)
{
    struct wolfIP s;
    int udp_sd;
    uint8_t buf[1] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, NULL, 1, 0, NULL, 0), -1);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, 0, 0, NULL, 0), -1);
}
END_TEST

START_TEST(test_sock_sendto_tcp_not_established)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t buf[4] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;

    ck_assert_int_eq(wolfIP_sock_sendto(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0), -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_sets_dest_and_assigns)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {1,2,3,4};
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 0;
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(9999);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(buf));
    ck_assert_uint_eq(ts->dst_port, 9999U);
    ck_assert_uint_eq(ts->remote_ip, 0x0A000002U);
    ck_assert_uint_ge(ts->src_port, 1024U);
    ck_assert_uint_eq(ts->local_ip, local_ip);
}
END_TEST

START_TEST(test_sock_sendto_icmp_assigns_src_port_and_sets_echo_id)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};
    struct pkt_desc *desc;
    struct wolfIP_icmp_packet *icmp;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->src_port = 0;
    ts->local_ip = 0;

    payload[0] = ICMP_ECHO_REQUEST;
    payload[1] = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    ck_assert_uint_ne(ts->src_port, 0);
    ck_assert_uint_eq(ts->local_ip, 0x0A000001U);

    desc = fifo_peek(&ts->sock.udp.txbuf);
    ck_assert_ptr_nonnull(desc);
    icmp = (struct wolfIP_icmp_packet *)(ts->txmem + desc->pos + sizeof(*desc));
    ck_assert_uint_eq(icmp_echo_id(icmp), ts->src_port);
}
END_TEST

START_TEST(test_sock_sendto_invalid_socket_ids)
{
    struct wolfIP s;
    uint8_t buf[1] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS, buf, sizeof(buf), 0, NULL, 0), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS, buf, sizeof(buf), 0, NULL, 0), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS, buf, sizeof(buf), 0, NULL, 0), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_sendto_non_socket_returns_minus_one)
{
    struct wolfIP s;
    uint8_t buf[1] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, 1, buf, sizeof(buf), 0, NULL, 0), -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_remote_ip_zero)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    uint8_t buf[4] = {1,2,3,4};

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->dst_port = 1234;
    ts->remote_ip = 0;

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0, NULL, 0), -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_primary_ip_fallback)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {1,2,3,4};
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 0;
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7777);
    sin.sin_addr.s_addr = ee32(0xC0A80199U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(buf));
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST

START_TEST(test_sock_sendto_udp_zero_port_in_addr)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {1,2,3,4};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 1234;
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_src_port_low_adjusts)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {1,2,3,4};
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 0;
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(9999);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    test_rand_override_enabled = 1;
    test_rand_override_value = 5;
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(buf));
    test_rand_override_enabled = 0;

    ck_assert_uint_eq(ts->src_port, 5U + 1024U);
}
END_TEST

START_TEST(test_sock_sendto_udp_local_ip_conf_null)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {1,2,3,4};

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 1234;
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7777);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(buf));
    ck_assert_uint_eq(ts->local_ip, 0U);
}
END_TEST

START_TEST(test_sock_sendto_udp_local_ip_from_primary)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {1,2,3,4};
    ip4 primary_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = TEST_SECOND_IF + 1;
    s.ipconf[TEST_PRIMARY_IF].ip = primary_ip;
    s.ipconf[TEST_PRIMARY_IF].mask = 0xFFFFFF00U;
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 1234;
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7777);
    sin.sin_addr.s_addr = ee32(0x0B000001U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(buf));
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST

START_TEST(test_sock_sendto_tcp_multiple_segments_flags)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    size_t seg_payload = TCP_MSS - TCP_OPTIONS_LEN;
    size_t payload_len = seg_payload * 2;
    uint8_t buf[TCP_MSS * 2];
    uint8_t txbuf[4096];
    struct pkt_desc *first;
    struct pkt_desc *second;
    struct wolfIP_tcp_seg *tcp1;
    struct wolfIP_tcp_seg *tcp2;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.peer_mss = TCP_MSS;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    fifo_init(&ts->sock.tcp.txbuf, txbuf, sizeof(txbuf));

    memset(buf, 0xAA, payload_len);
    ret = wolfIP_sock_sendto(&s, tcp_sd, buf, payload_len, 0, NULL, 0);
    ck_assert_int_eq(ret, (int)payload_len);

    first = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(first);
    tcp1 = (struct wolfIP_tcp_seg *)(txbuf + first->pos + sizeof(*first));
    ck_assert_uint_eq(tcp1->flags & (TCP_FLAG_ACK | TCP_FLAG_PSH), TCP_FLAG_ACK);

    second = fifo_next(&ts->sock.tcp.txbuf, first);
    ck_assert_ptr_nonnull(second);
    tcp2 = (struct wolfIP_tcp_seg *)(txbuf + second->pos + sizeof(*second));
    ck_assert_uint_eq(tcp2->flags & (TCP_FLAG_ACK | TCP_FLAG_PSH), (TCP_FLAG_ACK | TCP_FLAG_PSH));
}
END_TEST

START_TEST(test_sock_sendto_icmp_src_port_zero_random_zero_sets_one)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->src_port = 0;
    ts->local_ip = 0;

    payload[0] = ICMP_ECHO_REQUEST;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    test_rand_override_enabled = 1;
    test_rand_override_value = 0;
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    test_rand_override_enabled = 0;

    ck_assert_uint_eq(ts->src_port, 1U);
}
END_TEST

START_TEST(test_sock_sendto_icmp_non_echo_no_set_id)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};
    struct pkt_desc *desc;
    struct wolfIP_icmp_packet *icmp;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->src_port = 1234;
    ts->local_ip = 0;

    payload[0] = ICMP_ECHO_REPLY;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));

    desc = fifo_peek(&ts->sock.udp.txbuf);
    ck_assert_ptr_nonnull(desc);
    icmp = (struct wolfIP_icmp_packet *)(ts->txmem + desc->pos + sizeof(*desc));
    ck_assert_uint_eq(icmp_echo_id(icmp), 0U);
}
END_TEST

START_TEST(test_sock_sendto_icmp_local_ip_from_primary)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};
    ip4 primary_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = TEST_SECOND_IF + 1;
    s.ipconf[TEST_PRIMARY_IF].ip = primary_ip;
    s.ipconf[TEST_PRIMARY_IF].mask = 0xFFFFFF00U;
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;
    ts->src_port = 1234;

    payload[0] = ICMP_ECHO_REQUEST;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0B000001U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST

START_TEST(test_sock_sendto_icmp_local_ip_pre_set)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0x0A000001U;
    ts->src_port = 1234;

    payload[0] = ICMP_ECHO_REQUEST;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    ck_assert_uint_eq(ts->local_ip, 0x0A000001U);
}
END_TEST

START_TEST(test_sock_sendto_icmp_conf_null_primary_null)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;
    ts->src_port = 1234;

    payload[0] = ICMP_ECHO_REQUEST;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    ck_assert_uint_eq(ts->local_ip, 0U);
}
END_TEST
START_TEST(test_sock_recvfrom_tcp_close_wait_empty_returns_zero)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t buf[8];

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, NULL), 0);
}
END_TEST

START_TEST(test_sock_recvfrom_tcp_close_wait_with_data)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t buf[8];
    uint8_t payload[4] = {1,2,3,4};

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    ck_assert_int_eq(queue_insert(&ts->sock.tcp.rxbuf, payload, 0, sizeof(payload)), 0);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, NULL), (int)sizeof(payload));
}
END_TEST

START_TEST(test_sock_recvfrom_tcp_close_wait_sets_readable)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t buf[4];
    uint8_t payload[8] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);

    ck_assert_int_eq(queue_insert(&ts->sock.tcp.rxbuf, payload, 0, sizeof(payload)), 0);
    ts->events = 0;
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, NULL), (int)sizeof(buf));
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, CB_EVENT_READABLE);
}
END_TEST

START_TEST(test_sock_recvfrom_tcp_established_sets_readable)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t buf[4];
    uint8_t payload[8] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);

    ck_assert_int_eq(queue_insert(&ts->sock.tcp.rxbuf, payload, 0, sizeof(payload)), 0);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, NULL), (int)sizeof(buf));
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, CB_EVENT_READABLE);
}
END_TEST

START_TEST(test_sock_recvfrom_tcp_established_no_remaining_data)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t buf[8];
    uint8_t payload[8] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    ck_assert_int_eq(queue_insert(&ts->sock.tcp.rxbuf, payload, 0, sizeof(payload)), 0);

    ts->events = 0;
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, NULL), (int)sizeof(buf));
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, 0);
}
END_TEST

START_TEST(test_tcp_recv_does_not_cancel_rto_timer)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_timer tmr;
    uint8_t payload[1] = {0xAB};
    uint32_t rto_id;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 100;
    ts->sock.tcp.seq = 200;
    ts->sock.tcp.bytes_in_flight = 1;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&tmr, 0, sizeof(tmr));
    tmr.expires = 100;
    tmr.arg = ts;
    tmr.cb = tcp_rto_cb;
    rto_id = timers_binheap_insert(&s.timers, tmr);
    ts->sock.tcp.tmr_rto = rto_id;

    memset(seg_buf, 0, sizeof(seg_buf));
    seg = (struct wolfIP_tcp_seg *)seg_buf;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(ts->sock.tcp.ack);
    memcpy(((uint8_t *)seg->ip.data) + TCP_HEADER_LEN, payload, sizeof(payload));

    tcp_recv(ts, seg);

    ck_assert_uint_eq(ts->sock.tcp.tmr_rto, rto_id);
    ck_assert_uint_ne(s.timers.timers[0].expires, 0U);
}
END_TEST

START_TEST(test_sock_recvfrom_invalid_socket_ids)
{
    struct wolfIP s;
    uint8_t buf[4];

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS, buf, sizeof(buf), 0, NULL, NULL), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS, buf, sizeof(buf), 0, NULL, NULL), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS, buf, sizeof(buf), 0, NULL, NULL), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_recvfrom_non_socket)
{
    struct wolfIP s;
    uint8_t buf[4];

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, 1, buf, sizeof(buf), 0, NULL, NULL), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_recvfrom_icmp_success)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_icmp_packet icmp;
    struct wolfIP_sockaddr_in from;
    socklen_t from_len = sizeof(from);
    uint8_t buf[ICMP_HEADER_LEN];

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.ip.src = ee32(0x0A000002U);
    icmp.type = ICMP_ECHO_REPLY;
    fifo_push(&ts->sock.udp.rxbuf, &icmp, sizeof(icmp));

    memset(&from, 0, sizeof(from));
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, icmp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len), (int)ICMP_HEADER_LEN);
    ck_assert_uint_eq(from.sin_family, AF_INET);
    ck_assert_uint_eq(from.sin_addr.s_addr, icmp.ip.src);
}
END_TEST

START_TEST(test_sock_setsockopt_recvttl)
{
    struct wolfIP s;
    int udp_sd;
    int enable = 1;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &enable, sizeof(enable)), 0);
    ck_assert_int_eq(s.udpsockets[SOCKET_UNMARK(udp_sd)].recv_ttl, 1);
}
END_TEST

START_TEST(test_sock_setsockopt_invalid_socket)
{
    struct wolfIP s;
    int enable = 1;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS,
            WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &enable, sizeof(enable)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_getsockopt_recvttl_enabled_state)
{
    struct wolfIP s;
    int udp_sd;
    int value = 0;
    socklen_t len = sizeof(value);

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    s.udpsockets[SOCKET_UNMARK(udp_sd)].recv_ttl = 1;
    s.udpsockets[SOCKET_UNMARK(udp_sd)].last_pkt_ttl = 77;

    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &value, &len), 0);
    ck_assert_int_eq(value, 1);
}
END_TEST

START_TEST(test_sock_getsockopt_invalid_socket)
{
    struct wolfIP s;
    int value = 0;
    socklen_t len = sizeof(value);

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS,
            WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &value, &len), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_get_recv_ttl_invalid_socket)
{
    struct wolfIP s;
    int ttl = 0;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_get_recv_ttl(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS, &ttl), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_setsockopt_recvttl_invalid_params)
{
    struct wolfIP s;
    int udp_sd;
    int enable = 1;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, NULL, sizeof(enable)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &enable, (socklen_t)1), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_can_read_write_paths)
{
    struct wolfIP s;
    struct tsocket *ts;
    int tcp_sd;
    int udp_sd;
    int icmp_sd;
    uint8_t payload[4] = {1, 2, 3, 4};

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_can_read(&s, -1), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_can_write(&s, -1), -WOLFIP_EINVAL);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];

    ts->sock.tcp.state = TCP_SYN_SENT;
    ck_assert_int_eq(wolfIP_sock_can_write(&s, tcp_sd), 0);

    ts->sock.tcp.state = TCP_ESTABLISHED;
    ck_assert_int_eq(wolfIP_sock_can_read(&s, tcp_sd), 0);
    ck_assert_int_eq(wolfIP_sock_can_write(&s, tcp_sd), 1);
    ck_assert_int_eq(queue_insert(&ts->sock.tcp.rxbuf, payload, 0, sizeof(payload)), 0);
    ck_assert_int_eq(wolfIP_sock_can_read(&s, tcp_sd), 1);

    while (enqueue_tcp_tx(ts, 16, TCP_FLAG_ACK | TCP_FLAG_PSH) == 0) {
    }
    ck_assert_int_eq(wolfIP_sock_can_write(&s, tcp_sd), 0);

    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    ck_assert_int_eq(wolfIP_sock_can_read(&s, tcp_sd), 1);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ck_assert_int_eq(wolfIP_sock_can_read(&s, udp_sd), 0);
    enqueue_udp_rx(ts, payload, sizeof(payload), 4000);
    ck_assert_int_eq(wolfIP_sock_can_read(&s, udp_sd), 1);
    ck_assert_int_eq(wolfIP_sock_can_write(&s, udp_sd), 1);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_can_write(&s, icmp_sd), 1);
}
END_TEST

START_TEST(test_sock_getsockopt_recvttl_invalid_params)
{
    struct wolfIP s;
    int udp_sd;
    int value = 0;
    socklen_t len = sizeof(value);

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, NULL, &len), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &value, NULL), -WOLFIP_EINVAL);
    len = 1;
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &value, &len), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_dns_wrapper_apis)
{
    struct wolfIP s;
    uint16_t id = 0;
    int dns_sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(nslookup(NULL, "example.com", &id, test_dns_lookup_cb), -22);
    ck_assert_int_eq(nslookup(&s, NULL, &id, test_dns_lookup_cb), -22);
    ck_assert_int_eq(nslookup(&s, "example.com", NULL, test_dns_lookup_cb), -22);
    ck_assert_int_eq(nslookup(&s, "example.com", &id, NULL), -22);

    ck_assert_int_eq(wolfIP_dns_ptr_lookup(NULL, 0x01020304U, &id, test_dns_ptr_cb), -22);
    ck_assert_int_eq(wolfIP_dns_ptr_lookup(&s, 0x01020304U, NULL, test_dns_ptr_cb), -22);
    ck_assert_int_eq(wolfIP_dns_ptr_lookup(&s, 0x01020304U, &id, NULL), -22);

    s.dns_server = 0x08080808U;
    dns_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(dns_sd, 0);
    s.dns_udp_sd = dns_sd;

    ck_assert_int_eq(nslookup(&s, "example.com", &id, test_dns_lookup_cb), 0);
    ck_assert_ptr_eq(s.dns_lookup_cb, test_dns_lookup_cb);
    ck_assert_ptr_eq(s.dns_ptr_cb, NULL);
    ck_assert_uint_eq(s.dns_query_type, DNS_QUERY_TYPE_A);

    s.dns_id = 0;
    ck_assert_int_eq(wolfIP_dns_ptr_lookup(&s, 0x01020304U, &id, test_dns_ptr_cb), 0);
    ck_assert_ptr_eq(s.dns_ptr_cb, test_dns_ptr_cb);
    ck_assert_ptr_eq(s.dns_lookup_cb, NULL);
    ck_assert_uint_eq(s.dns_query_type, DNS_QUERY_TYPE_PTR);
}
END_TEST

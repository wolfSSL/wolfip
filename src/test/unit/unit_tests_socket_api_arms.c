/* unit_tests_socket_api_arms.c
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
/* ---- wolfIP_register_callback: TCP, RAW, and PACKET arms ---- */

START_TEST(test_register_callback_tcp_stores_handle)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];

    wolfIP_register_callback(&s, sd, test_socket_cb, (void *)0x42);
    ck_assert_ptr_eq(ts->callback, test_socket_cb);
    ck_assert_ptr_eq(ts->callback_arg, (void *)0x42);
}
END_TEST

START_TEST(test_register_callback_tcp_oor_ignored)
{
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);
    /* out-of-range TCP fd — must not crash */
    wolfIP_register_callback(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS,
                             test_socket_cb, NULL);
}
END_TEST

#if WOLFIP_RAWSOCKETS
START_TEST(test_register_callback_raw_stores_handle)
{
    struct wolfIP s;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    wolfIP_register_callback(&s, sd, test_socket_cb, (void *)0xBEEF);
    ck_assert_ptr_eq(s.rawsockets[SOCKET_UNMARK(sd)].callback, test_socket_cb);
    ck_assert_ptr_eq(s.rawsockets[SOCKET_UNMARK(sd)].callback_arg, (void *)0xBEEF);
}
END_TEST

START_TEST(test_register_callback_raw_oor_ignored)
{
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_register_callback(&s, MARK_RAW_SOCKET | WOLFIP_MAX_RAWSOCKETS,
                             test_socket_cb, NULL);
}
END_TEST
#endif /* WOLFIP_RAWSOCKETS */

#if WOLFIP_PACKET_SOCKETS
START_TEST(test_register_callback_packet_stores_handle)
{
    struct wolfIP s;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, 0);
    ck_assert_int_ge(sd, 0);

    wolfIP_register_callback(&s, sd, test_socket_cb, (void *)0xCAFE);
    ck_assert_ptr_eq(s.packetsockets[SOCKET_UNMARK(sd)].callback, test_socket_cb);
}
END_TEST

START_TEST(test_register_callback_packet_oor_ignored)
{
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_register_callback(&s, MARK_PACKET_SOCKET | WOLFIP_MAX_PACKETSOCKETS,
                             test_socket_cb, NULL);
}
END_TEST
#endif /* WOLFIP_PACKET_SOCKETS */

/* ---- wolfIP_sock_can_read / wolfIP_sock_can_write: TCP and RAW arms ---- */

START_TEST(test_sock_can_read_tcp_established_empty)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;

    /* empty queue and ESTABLISHED → not readable */
    ck_assert_int_eq(wolfIP_sock_can_read(&s, sd), 0);
}
END_TEST

START_TEST(test_sock_can_read_tcp_close_wait_returns_one)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_CLOSE_WAIT;

    /* CLOSE_WAIT always reports readable so caller sees EOF */
    ck_assert_int_eq(wolfIP_sock_can_read(&s, sd), 1);
}
END_TEST

START_TEST(test_sock_can_read_tcp_invalid_fd)
{
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_can_read(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS),
                     -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_can_write_tcp_syn_sent_returns_zero)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;

    ck_assert_int_eq(wolfIP_sock_can_write(&s, sd), 0);
}
END_TEST

START_TEST(test_sock_can_write_tcp_established_with_space)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;

    ck_assert_int_eq(wolfIP_sock_can_write(&s, sd), 1);
}
END_TEST

START_TEST(test_sock_can_write_tcp_closed_returns_one)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_CLOSED;

    /* not ESTABLISHED and not SYN_SENT → reports writable */
    ck_assert_int_eq(wolfIP_sock_can_write(&s, sd), 1);
}
END_TEST

START_TEST(test_sock_can_write_tcp_invalid_fd)
{
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_can_write(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS),
                     -WOLFIP_EINVAL);
}
END_TEST

#if WOLFIP_RAWSOCKETS
START_TEST(test_sock_can_read_raw_empty)
{
    struct wolfIP s;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    ck_assert_int_eq(wolfIP_sock_can_read(&s, sd), 0);
}
END_TEST

START_TEST(test_sock_can_read_raw_invalid_fd)
{
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_can_read(&s, MARK_RAW_SOCKET | WOLFIP_MAX_RAWSOCKETS),
                     -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_can_write_raw_with_space)
{
    struct wolfIP s;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    ck_assert_int_eq(wolfIP_sock_can_write(&s, sd), 1);
}
END_TEST

START_TEST(test_sock_can_write_raw_invalid_fd)
{
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_can_write(&s, MARK_RAW_SOCKET | WOLFIP_MAX_RAWSOCKETS),
                     -WOLFIP_EINVAL);
}
END_TEST
#endif /* WOLFIP_RAWSOCKETS */

#if WOLFIP_PACKET_SOCKETS
START_TEST(test_sock_can_read_packet_empty)
{
    struct wolfIP s;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, 0);
    ck_assert_int_ge(sd, 0);
    ck_assert_int_eq(wolfIP_sock_can_read(&s, sd), 0);
}
END_TEST

START_TEST(test_sock_can_write_packet_with_space)
{
    struct wolfIP s;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, 0);
    ck_assert_int_ge(sd, 0);
    ck_assert_int_eq(wolfIP_sock_can_write(&s, sd), 1);
}
END_TEST
#endif /* WOLFIP_PACKET_SOCKETS */

/* ---- wolfIP_sock_bind: TCP, RAW, and PACKET arms ---- */

START_TEST(test_sock_bind_tcp_success)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    sin.sin_port = ee16(8080);

    ck_assert_int_eq(wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), 0);
    ck_assert_uint_eq(s.tcpsockets[SOCKET_UNMARK(sd)].src_port, 8080);
    ck_assert_uint_eq(s.tcpsockets[SOCKET_UNMARK(sd)].bound_local_ip,
                      0x0A000001U);
}
END_TEST

START_TEST(test_sock_bind_tcp_any_ip_uses_primary)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = IPADDR_ANY; /* 0.0.0.0 */
    sin.sin_port = ee16(9090);

    ck_assert_int_eq(wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), 0);
    /* bound_local_ip stays IPADDR_ANY but local_ip gets primary */
    ck_assert_uint_eq(s.tcpsockets[SOCKET_UNMARK(sd)].bound_local_ip,
                      IPADDR_ANY);
    ck_assert_uint_eq(s.tcpsockets[SOCKET_UNMARK(sd)].local_ip,
                      0x0A000001U);
    ck_assert_uint_eq(s.tcpsockets[SOCKET_UNMARK(sd)].src_port, 9090);
}
END_TEST

START_TEST(test_sock_bind_tcp_oor_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    sin.sin_port = ee16(1234);

    ck_assert_int_eq(wolfIP_sock_bind(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS,
                                      (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_bind_tcp_state_closed_required)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_LISTEN;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    sin.sin_port = ee16(80);

    /* bind on non-CLOSED socket must fail */
    ck_assert_int_eq(wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), -1);
}
END_TEST

#if WOLFIP_RAWSOCKETS
START_TEST(test_sock_bind_raw_specific_interface)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    ck_assert_int_eq(wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), 0);
    ck_assert_uint_eq(s.rawsockets[SOCKET_UNMARK(sd)].local_ip, 0x0A000001U);
    ck_assert_uint_eq(s.rawsockets[SOCKET_UNMARK(sd)].bound_local_ip, 0x0A000001U);
}
END_TEST

START_TEST(test_sock_bind_raw_any_ip_uses_primary)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = IPADDR_ANY;

    ck_assert_int_eq(wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), 0);
    ck_assert_uint_eq(s.rawsockets[SOCKET_UNMARK(sd)].bound_local_ip, IPADDR_ANY);
    ck_assert_uint_eq(s.rawsockets[SOCKET_UNMARK(sd)].local_ip, 0x0A000001U);
}
END_TEST

START_TEST(test_sock_bind_raw_wrong_family)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_PACKET; /* wrong */
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    ck_assert_int_eq(wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_bind_raw_oor_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    ck_assert_int_eq(wolfIP_sock_bind(&s, MARK_RAW_SOCKET | WOLFIP_MAX_RAWSOCKETS,
                                      (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST
#endif /* WOLFIP_RAWSOCKETS */

#if WOLFIP_PACKET_SOCKETS
START_TEST(test_sock_bind_packet_success)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_ll sll;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, 0);
    ck_assert_int_ge(sd, 0);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = ee16(ETH_TYPE_IP);
    sll.sll_ifindex = (int)TEST_PRIMARY_IF;
    sll.sll_halen = 6;

    ck_assert_int_eq(wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sll,
                                      sizeof(sll)), 0);
    ck_assert_uint_eq(s.packetsockets[SOCKET_UNMARK(sd)].if_idx,
                      (uint8_t)TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_sock_bind_packet_wrong_family)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_ll sll;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, 0);
    ck_assert_int_ge(sd, 0);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_INET; /* wrong */
    sll.sll_ifindex = (int)TEST_PRIMARY_IF;

    ck_assert_int_eq(wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sll,
                                      sizeof(sll)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_bind_packet_out_of_range_ifindex)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_ll sll;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, 0);
    ck_assert_int_ge(sd, 0);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = (int)s.if_count; /* == if_count is out of range */

    ck_assert_int_eq(wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sll,
                                      sizeof(sll)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_bind_packet_oor_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_ll sll;

    wolfIP_init(&s);
    mock_link_init(&s);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = 0;

    ck_assert_int_eq(wolfIP_sock_bind(&s, MARK_PACKET_SOCKET | WOLFIP_MAX_PACKETSOCKETS,
                                      (struct wolfIP_sockaddr *)&sll,
                                      sizeof(sll)), -WOLFIP_EINVAL);
}
END_TEST
#endif /* WOLFIP_PACKET_SOCKETS */

/* ---- wolfIP_sock_connect: TCP and RAW arms ---- */

START_TEST(test_sock_connect_tcp_invalid_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    sin.sin_port = ee16(80);

    ck_assert_int_eq(wolfIP_sock_connect(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS,
                                         (struct wolfIP_sockaddr *)&sin,
                                         sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_tcp_syn_sent_returns_eagain)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    sin.sin_port = ee16(80);

    ck_assert_int_eq(wolfIP_sock_connect(&s, sd, (struct wolfIP_sockaddr *)&sin,
                                          sizeof(sin)), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_connect_tcp_established_arm_returns_zero)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    sin.sin_port = ee16(80);

    ck_assert_int_eq(wolfIP_sock_connect(&s, sd, (struct wolfIP_sockaddr *)&sin,
                                          sizeof(sin)), 0);
}
END_TEST

START_TEST(test_sock_connect_tcp_bad_state_returns_einval)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_LISTEN;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    sin.sin_port = ee16(80);

    ck_assert_int_eq(wolfIP_sock_connect(&s, sd, (struct wolfIP_sockaddr *)&sin,
                                          sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

#if WOLFIP_RAWSOCKETS
START_TEST(test_sock_connect_raw_sets_remote_ip)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, sd, (struct wolfIP_sockaddr *)&sin,
                                          sizeof(sin)), 0);
    ck_assert_uint_eq(s.rawsockets[SOCKET_UNMARK(sd)].remote_ip, 0x0A000002U);
}
END_TEST

START_TEST(test_sock_connect_raw_invalid_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, MARK_RAW_SOCKET | WOLFIP_MAX_RAWSOCKETS,
                                          (struct wolfIP_sockaddr *)&sin,
                                          sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_raw_wrong_family)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_PACKET; /* wrong */
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, sd, (struct wolfIP_sockaddr *)&sin,
                                          sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_raw_with_bound_local_ip)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    /* pre-bind so connect uses the bound IP path */
    s.rawsockets[SOCKET_UNMARK(sd)].bound_local_ip = 0x0A000001U;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, sd, (struct wolfIP_sockaddr *)&sin,
                                          sizeof(sin)), 0);
    ck_assert_uint_eq(s.rawsockets[SOCKET_UNMARK(sd)].local_ip, 0x0A000001U);
}
END_TEST
#endif /* WOLFIP_RAWSOCKETS */

/* ---- wolfIP_sock_sendto: TCP, RAW, and PACKET arms ---- */

START_TEST(test_sock_sendto_tcp_established_sends_data)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    uint8_t buf[64];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->remote_ip = 0x0A000002U;
    ts->src_port = 12345;
    ts->dst_port = 80;
    ts->sock.tcp.peer_rwnd = 65535;
    ts->sock.tcp.cwnd = 65535;

    memset(buf, 'A', sizeof(buf));
    ret = wolfIP_sock_sendto(&s, sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_gt(ret, 0);
}
END_TEST

START_TEST(test_sock_sendto_tcp_invalid_fd)
{
    struct wolfIP s;
    uint8_t buf[8] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS,
                                         buf, sizeof(buf), 0, NULL, 0),
                     -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_sendto_tcp_close_wait_sends_data)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    uint8_t buf[64];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    ts->remote_ip = 0x0A000002U;
    ts->src_port = 54321;
    ts->dst_port = 80;
    ts->sock.tcp.peer_rwnd = 65535;
    ts->sock.tcp.cwnd = 65535;

    memset(buf, 'B', sizeof(buf));
    ret = wolfIP_sock_sendto(&s, sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_gt(ret, 0);
}
END_TEST

#if WOLFIP_RAWSOCKETS
START_TEST(test_sock_sendto_raw_null_dest_uses_stored_remote_ip)
{
    struct wolfIP s;
    int sd;
    uint8_t payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t nh_mac[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, nh_mac, 6);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    /* Pre-set remote_ip so sendto with NULL dest uses it */
    s.rawsockets[SOCKET_UNMARK(sd)].remote_ip = 0x0A000002U;

    ret = wolfIP_sock_sendto(&s, sd, payload, sizeof(payload), 0, NULL, 0);
    ck_assert_int_eq(ret, (int)sizeof(payload));
}
END_TEST

START_TEST(test_sock_sendto_raw_null_dest_no_remote_ip)
{
    struct wolfIP s;
    int sd;
    uint8_t payload[8] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    /* remote_ip is 0 and no dest_addr provided */

    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, payload, sizeof(payload), 0,
                                         NULL, 0), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_sendto_raw_hdrincl_dst_from_buf)
{
    struct wolfIP s;
    int sd;
    int one = 1;
    /* struct wolfIP_ip_packet embeds an Ethernet header at offset 0; the
     * IP fields live at offset ETH_HEADER_LEN, so the backing buffer must
     * include both. */
    uint8_t ip_buf[ETH_HEADER_LEN + IP_HEADER_LEN + 4];
    struct wolfIP_ip_packet *ip;
    uint8_t nh_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, nh_mac, 6);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
                WOLFIP_IP_HDRINCL, &one, sizeof(one)), 0);

    /* Build a minimal IP packet within the buffer; the Ethernet bytes are
     * harmless filler that sendto ignores when IP_HDRINCL is set. */
    memset(ip_buf, 0, sizeof(ip_buf));
    ip = (struct wolfIP_ip_packet *)ip_buf;
    ip->ver_ihl = 0x45;
    ip->ttl = 64;
    ip->proto = WI_IPPROTO_UDP;
    ip->len = ee16(IP_HEADER_LEN + 4);
    ip->src = ee32(0x0A000001U);
    ip->dst = ee32(0x0A000002U);
    iphdr_set_checksum(ip);

    /* pass the raw IP header (after ETH offset) to sendto */
    ret = wolfIP_sock_sendto(&s, sd,
                              (uint8_t *)ip + ETH_HEADER_LEN,
                              IP_HEADER_LEN + 4,
                              0, NULL, 0);
    ck_assert_int_eq(ret, IP_HEADER_LEN + 4);
}
END_TEST

START_TEST(test_sock_sendto_raw_invalid_fd)
{
    struct wolfIP s;
    uint8_t buf[8] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, MARK_RAW_SOCKET | WOLFIP_MAX_RAWSOCKETS,
                                         buf, sizeof(buf), 0, NULL, 0),
                     -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_sendto_raw_fifo_full_returns_eagain)
{
    struct wolfIP s;
    int sd;
    uint8_t payload[8] = {0};
    struct wolfIP_sockaddr_in sin;
    struct rawsocket *rs;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    rs = &s.rawsockets[SOCKET_UNMARK(sd)];

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    /* Fill the txbuf completely by writing dummy bytes */
    rs->txbuf.tail = 0;
    rs->txbuf.head = 0;
    rs->txbuf.size = 0; /* force fifo_space to return 0 */

    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, payload, sizeof(payload), 0,
                                         (struct wolfIP_sockaddr *)&sin,
                                         sizeof(sin)), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_setsockopt_raw_hdrincl)
{
    struct wolfIP s;
    int sd;
    int enable = 1;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
                WOLFIP_IP_HDRINCL, &enable, sizeof(enable)), 0);
    ck_assert_int_eq(s.rawsockets[SOCKET_UNMARK(sd)].ipheader_include, 1);

    enable = 0;
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
                WOLFIP_IP_HDRINCL, &enable, sizeof(enable)), 0);
    ck_assert_int_eq(s.rawsockets[SOCKET_UNMARK(sd)].ipheader_include, 0);
}
END_TEST

START_TEST(test_sock_setsockopt_raw_dontroute)
{
    struct wolfIP s;
    int sd;
    int enable = 1;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_SOCKET,
                WOLFIP_SO_DONTROUTE, &enable, sizeof(enable)), 0);
    ck_assert_int_eq(s.rawsockets[SOCKET_UNMARK(sd)].dontroute, 1);
}
END_TEST

START_TEST(test_sock_setsockopt_raw_recvttl)
{
    struct wolfIP s;
    int sd;
    int enable = 1;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
                WOLFIP_IP_RECVTTL, &enable, sizeof(enable)), 0);
    ck_assert_int_eq(s.rawsockets[SOCKET_UNMARK(sd)].recv_ttl, 1);
}
END_TEST

START_TEST(test_sock_setsockopt_raw_unknown_option)
{
    struct wolfIP s;
    int sd;
    int enable = 1;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    /* unknown combination returns EINVAL for raw sockets */
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_SOCKET,
                0x7FFF, &enable, sizeof(enable)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_setsockopt_raw_null_optval)
{
    struct wolfIP s;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
                WOLFIP_IP_HDRINCL, NULL, sizeof(int)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_setsockopt_raw_invalid_fd)
{
    struct wolfIP s;
    int enable = 1;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s,
                MARK_RAW_SOCKET | WOLFIP_MAX_RAWSOCKETS,
                WOLFIP_SOL_IP, WOLFIP_IP_HDRINCL, &enable, sizeof(enable)),
                -WOLFIP_EINVAL);
}
END_TEST
#endif /* WOLFIP_RAWSOCKETS */

#if WOLFIP_PACKET_SOCKETS
START_TEST(test_sock_setsockopt_packet_returns_einval)
{
    struct wolfIP s;
    int sd;
    int enable = 1;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, 0);
    ck_assert_int_ge(sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
                WOLFIP_IP_HDRINCL, &enable, sizeof(enable)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_sendto_packet_writes_raw_frame)
{
    struct wolfIP s;
    int sd;
    uint8_t frame[ETH_HEADER_LEN + 4];
    struct wolfIP_eth_frame *eth = (struct wolfIP_eth_frame *)frame;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, 0);
    ck_assert_int_ge(sd, 0);

    memset(frame, 0, sizeof(frame));
    memset(eth->dst, 0xFF, 6); /* broadcast */
    memset(eth->src, 0x11, 6);
    eth->type = ee16(ETH_TYPE_IP);

    ret = wolfIP_sock_sendto(&s, sd, frame, sizeof(frame), 0, NULL, 0);
    ck_assert_int_eq(ret, (int)sizeof(frame));
}
END_TEST

START_TEST(test_sock_sendto_packet_with_sll_updates_dst_mac)
{
    struct wolfIP s;
    int sd;
    uint8_t frame[ETH_HEADER_LEN + 4];
    struct wolfIP_eth_frame *eth = (struct wolfIP_eth_frame *)frame;
    struct wolfIP_sockaddr_ll sll;
    int ret;
    uint8_t expected_mac[6];

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, 0);
    ck_assert_int_ge(sd, 0);

    memset(frame, 0, sizeof(frame));
    eth->type = ee16(ETH_TYPE_IP);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = (int)TEST_PRIMARY_IF;
    sll.sll_halen = 6;
    memset(sll.sll_addr, 0xAA, 6);
    memset(expected_mac, 0xAA, 6);

    ret = wolfIP_sock_sendto(&s, sd, frame, sizeof(frame), 0,
                              (struct wolfIP_sockaddr *)&sll, sizeof(sll));
    ck_assert_int_eq(ret, (int)sizeof(frame));

    /* sendto copies to internal pkt_frame and pushes to fifo; poll drains it.
     * Verify by polling and checking last_frame_sent. */
    wolfIP_poll(&s, 0);
    ck_assert_uint_ge(last_frame_sent_size, ETH_HEADER_LEN);
    ck_assert_mem_eq(last_frame_sent, expected_mac, 6);
}
END_TEST

START_TEST(test_sock_sendto_packet_too_small)
{
    struct wolfIP s;
    int sd;
    uint8_t tiny[ETH_HEADER_LEN - 1];

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, 0);
    ck_assert_int_ge(sd, 0);
    memset(tiny, 0, sizeof(tiny));

    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, tiny, sizeof(tiny), 0,
                                         NULL, 0), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_sendto_packet_invalid_fd)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + 4];
    wolfIP_init(&s);
    mock_link_init(&s);
    memset(frame, 0, sizeof(frame));
    ck_assert_int_eq(wolfIP_sock_sendto(&s,
                MARK_PACKET_SOCKET | WOLFIP_MAX_PACKETSOCKETS,
                frame, sizeof(frame), 0, NULL, 0), -WOLFIP_EINVAL);
}
END_TEST
#endif /* WOLFIP_PACKET_SOCKETS */

/* ---- wolfIP_sock_recvfrom: TCP, RAW, and PACKET arms ---- */

START_TEST(test_sock_recvfrom_tcp_not_established)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    uint8_t buf[64];

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    /* A genuinely not-established stream (mid-connect) reports an error.
     * TCP_CLOSED is intentionally NOT used here: a torn-down/closed stream now
     * reports EOF (0), covered by
     * test_tcp_input_syn_rcvd_rst_nullcb_recv_reports_eof. */
    ts->sock.tcp.state = TCP_SYN_SENT;

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, sd, buf, sizeof(buf), 0,
                                           NULL, NULL), -1);
}
END_TEST

START_TEST(test_sock_recvfrom_tcp_established_empty_queue)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    uint8_t buf[64];

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;

    /* empty queue → queue_pop returns -WOLFIP_EAGAIN which propagates */
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, sd, buf, sizeof(buf), 0,
                                           NULL, NULL), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_recvfrom_tcp_invalid_fd)
{
    struct wolfIP s;
    uint8_t buf[64];

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS,
                                           buf, sizeof(buf), 0, NULL, NULL),
                     -WOLFIP_EINVAL);
}
END_TEST

#if WOLFIP_RAWSOCKETS
START_TEST(test_sock_recvfrom_raw_empty)
{
    struct wolfIP s;
    int sd;
    uint8_t buf[64];

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, sd, buf, sizeof(buf), 0,
                                           NULL, NULL), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_recvfrom_raw_invalid_fd)
{
    struct wolfIP s;
    uint8_t buf[64];

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, MARK_RAW_SOCKET | WOLFIP_MAX_RAWSOCKETS,
                                           buf, sizeof(buf), 0, NULL, NULL),
                     -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_recvfrom_raw_with_sin)
{
    struct wolfIP s;
    int sd;
    uint8_t frame_buf[ETH_HEADER_LEN + IP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *frame = (struct wolfIP_ip_packet *)frame_buf;
    uint8_t payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    struct wolfIP_sockaddr_in sin;
    socklen_t sin_len = sizeof(sin);
    uint8_t rxbuf[64];

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    memset(frame_buf, 0, sizeof(frame_buf));
    memcpy(frame->eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    frame->eth.type = ee16(ETH_TYPE_IP);
    frame->ver_ihl = 0x45;
    frame->ttl = 64;
    frame->proto = WI_IPPROTO_UDP;
    frame->len = ee16(IP_HEADER_LEN + sizeof(payload));
    frame->src = ee32(0x0A000002U);
    frame->dst = ee32(0x0A000001U);
    memcpy(frame->data, payload, sizeof(payload));
    iphdr_set_checksum(frame);

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, sizeof(frame_buf));

    memset(&sin, 0, sizeof(sin));
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
                                           (struct wolfIP_sockaddr *)&sin,
                                           &sin_len),
                     IP_HEADER_LEN + (int)sizeof(payload));
    ck_assert_uint_eq(sin.sin_family, AF_INET);
    ck_assert_uint_eq(ee32(sin.sin_addr.s_addr), 0x0A000002U);
}
END_TEST
#endif /* WOLFIP_RAWSOCKETS */

#if WOLFIP_PACKET_SOCKETS
START_TEST(test_sock_recvfrom_packet_empty)
{
    struct wolfIP s;
    int sd;
    uint8_t buf[LINK_MTU];

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, 0);
    ck_assert_int_ge(sd, 0);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, sd, buf, sizeof(buf), 0,
                                           NULL, NULL), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_recvfrom_packet_invalid_fd)
{
    struct wolfIP s;
    uint8_t buf[64];

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s,
                MARK_PACKET_SOCKET | WOLFIP_MAX_PACKETSOCKETS,
                buf, sizeof(buf), 0, NULL, NULL), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_recvfrom_packet_null_addrlen_with_sll)
{
    struct wolfIP s;
    int sd;
    uint8_t buf[LINK_MTU];
    struct wolfIP_sockaddr_ll sll;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, 0);
    ck_assert_int_ge(sd, 0);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, sd, buf, sizeof(buf), 0,
                                           (struct wolfIP_sockaddr *)&sll,
                                           NULL), -WOLFIP_EINVAL);
}
END_TEST
#endif /* WOLFIP_PACKET_SOCKETS */

/* ---- wolfIP_sock_getsockname: TCP, RAW, and PACKET arms ---- */

START_TEST(test_sock_getsockname_tcp_success)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in out;
    socklen_t outlen = sizeof(out);

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->local_ip = 0x0A000001U;
    ts->src_port = 12345;

    ck_assert_int_eq(wolfIP_sock_getsockname(&s, sd, (struct wolfIP_sockaddr *)&out,
                                              &outlen), 0);
    ck_assert_uint_eq(out.sin_family, AF_INET);
    ck_assert_uint_eq(ee32(out.sin_addr.s_addr), 0x0A000001U);
    ck_assert_uint_eq(ee16(out.sin_port), 12345);
}
END_TEST

START_TEST(test_sock_getsockname_tcp_invalid_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in out;
    socklen_t outlen = sizeof(out);

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS,
                                              (struct wolfIP_sockaddr *)&out,
                                              &outlen), -WOLFIP_EINVAL);
}
END_TEST

#if WOLFIP_RAWSOCKETS
START_TEST(test_sock_getsockname_raw_success)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in out;
    socklen_t outlen = sizeof(out);

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    s.rawsockets[SOCKET_UNMARK(sd)].local_ip = 0x0A000001U;

    ck_assert_int_eq(wolfIP_sock_getsockname(&s, sd, (struct wolfIP_sockaddr *)&out,
                                              &outlen), 0);
    ck_assert_uint_eq(out.sin_family, AF_INET);
    ck_assert_uint_eq(ee32(out.sin_addr.s_addr), 0x0A000001U);
    ck_assert_uint_eq(ee16(out.sin_port), 0);
}
END_TEST

START_TEST(test_sock_getsockname_raw_invalid_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in out;
    socklen_t outlen = sizeof(out);

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_getsockname(&s,
                MARK_RAW_SOCKET | WOLFIP_MAX_RAWSOCKETS,
                (struct wolfIP_sockaddr *)&out, &outlen), -WOLFIP_EINVAL);
}
END_TEST
#endif /* WOLFIP_RAWSOCKETS */

#if WOLFIP_PACKET_SOCKETS
START_TEST(test_sock_getsockname_packet_success)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_ll sll_bind, sll_out;
    socklen_t outlen = sizeof(sll_out);

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, 0);
    ck_assert_int_ge(sd, 0);

    memset(&sll_bind, 0, sizeof(sll_bind));
    sll_bind.sll_family = AF_PACKET;
    sll_bind.sll_ifindex = (int)TEST_PRIMARY_IF;
    sll_bind.sll_halen = 6;
    wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sll_bind, sizeof(sll_bind));

    ck_assert_int_eq(wolfIP_sock_getsockname(&s, sd, (struct wolfIP_sockaddr *)&sll_out,
                                              &outlen), 0);
    ck_assert_uint_eq(sll_out.sll_family, AF_PACKET);
}
END_TEST
#endif /* WOLFIP_PACKET_SOCKETS */

/* ---- wolfIP_sock_getpeername: TCP and RAW arms ---- */

START_TEST(test_sock_getpeername_tcp_success)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in out;
    socklen_t outlen = sizeof(out);

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->remote_ip = 0x0A000002U;
    ts->dst_port = 80;

    ck_assert_int_eq(wolfIP_sock_getpeername(&s, sd, (struct wolfIP_sockaddr *)&out,
                                              &outlen), 0);
    ck_assert_uint_eq(out.sin_family, AF_INET);
    ck_assert_uint_eq(ee32(out.sin_addr.s_addr), 0x0A000002U);
    ck_assert_uint_eq(ee16(out.sin_port), 80);
}
END_TEST

START_TEST(test_sock_getpeername_tcp_invalid_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in out;
    socklen_t outlen = sizeof(out);

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_getpeername(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS,
                                              (struct wolfIP_sockaddr *)&out,
                                              &outlen), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_getpeername_tcp_null_addr)
{
    struct wolfIP s;
    int sd;
    socklen_t outlen = sizeof(struct wolfIP_sockaddr_in);

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);

    /* null addr pointer → -1 */
    ck_assert_int_eq(wolfIP_sock_getpeername(&s, sd, NULL, &outlen), -1);
}
END_TEST

#if WOLFIP_RAWSOCKETS
START_TEST(test_sock_getpeername_raw_success)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in out;
    socklen_t outlen = sizeof(out);

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    s.rawsockets[SOCKET_UNMARK(sd)].remote_ip = 0x0A000002U;

    ck_assert_int_eq(wolfIP_sock_getpeername(&s, sd, (struct wolfIP_sockaddr *)&out,
                                              &outlen), 0);
    ck_assert_uint_eq(out.sin_family, AF_INET);
    ck_assert_uint_eq(ee32(out.sin_addr.s_addr), 0x0A000002U);
}
END_TEST

START_TEST(test_sock_getpeername_raw_no_remote_ip)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in out;
    socklen_t outlen = sizeof(out);

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    /* remote_ip defaults to 0 → returns -1 */

    ck_assert_int_eq(wolfIP_sock_getpeername(&s, sd, (struct wolfIP_sockaddr *)&out,
                                              &outlen), -1);
}
END_TEST

START_TEST(test_sock_getpeername_raw_invalid_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in out;
    socklen_t outlen = sizeof(out);

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_getpeername(&s,
                MARK_RAW_SOCKET | WOLFIP_MAX_RAWSOCKETS,
                (struct wolfIP_sockaddr *)&out, &outlen), -WOLFIP_EINVAL);
}
END_TEST
#endif /* WOLFIP_RAWSOCKETS */

/* ---- wolfIP_sock_get_recv_ttl: RAW arm ---- */

#if WOLFIP_RAWSOCKETS
START_TEST(test_sock_get_recv_ttl_raw_disabled)
{
    struct wolfIP s;
    int sd;
    int ttl = -1;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);

    /* recv_ttl defaults to 0 → returns 0 */
    ck_assert_int_eq(wolfIP_sock_get_recv_ttl(&s, sd, &ttl), 0);
}
END_TEST

START_TEST(test_sock_get_recv_ttl_raw_enabled)
{
    struct wolfIP s;
    int sd;
    int enable = 1;
    int ttl = -1;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
                WOLFIP_IP_RECVTTL, &enable, sizeof(enable)), 0);
    s.rawsockets[SOCKET_UNMARK(sd)].last_pkt_ttl = 64;

    ck_assert_int_eq(wolfIP_sock_get_recv_ttl(&s, sd, &ttl), 1);
    ck_assert_int_eq(ttl, 64);
}
END_TEST

START_TEST(test_sock_get_recv_ttl_raw_null_ttl)
{
    struct wolfIP s;
    int sd;
    int enable = 1;

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
                WOLFIP_IP_RECVTTL, &enable, sizeof(enable)), 0);
    s.rawsockets[SOCKET_UNMARK(sd)].last_pkt_ttl = 128;

    /* NULL ttl pointer should still return 1 and not crash */
    ck_assert_int_eq(wolfIP_sock_get_recv_ttl(&s, sd, NULL), 1);
}
END_TEST

START_TEST(test_sock_get_recv_ttl_raw_invalid_fd)
{
    struct wolfIP s;
    int ttl;

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_get_recv_ttl(&s,
                MARK_RAW_SOCKET | WOLFIP_MAX_RAWSOCKETS, &ttl),
                -WOLFIP_EINVAL);
}
END_TEST
#endif /* WOLFIP_RAWSOCKETS */

/* ---- wolfIP_notify_loopback_space_available ---- */

START_TEST(test_notify_loopback_tcp_sets_writable)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, WOLFIP_LOOPBACK_IP, WOLFIP_LOOPBACK_MASK, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->proto = WI_IPPROTO_TCP;
    ts->if_idx = (uint8_t)WOLFIP_LOOPBACK_IF_IDX;
    ts->events = 0;

    /* calling the loopback notifier indirectly via wolfIP_poll triggers notify */
    wolfIP_notify_loopback_space_available(&s);

    ck_assert_int_ne(ts->events & CB_EVENT_WRITABLE, 0);
}
END_TEST

START_TEST(test_notify_loopback_tcp_non_loopback_not_notified)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->proto = WI_IPPROTO_TCP;
    ts->if_idx = (uint8_t)TEST_PRIMARY_IF; /* not loopback */
    ts->events = 0;

    wolfIP_notify_loopback_space_available(&s);

    /* not on loopback → events unchanged */
    ck_assert_int_eq(ts->events & CB_EVENT_WRITABLE, 0);
}
END_TEST

START_TEST(test_notify_loopback_null_stack_no_crash)
{
    /* must not crash */
    wolfIP_notify_loopback_space_available(NULL);
}
END_TEST

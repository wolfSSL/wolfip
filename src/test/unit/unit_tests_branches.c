/* unit_tests_branches.c
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
/* ---- wolfIP_socket_from_fd / wolfIP_sock_can_read / wolfIP_sock_can_write ---- */

START_TEST(test_socket_from_fd_invalid_inputs)
{
    struct wolfIP s;
    int udp_sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    /* can_read / can_write reject negative descriptors via socket_from_fd */
    ck_assert_int_eq(wolfIP_sock_can_read(&s, -1), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_can_write(&s, -1), -WOLFIP_EINVAL);

    /* Out-of-range UDP/ICMP descriptors */
    ck_assert_int_eq(wolfIP_sock_can_read(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS),
            -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_can_write(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS),
            -WOLFIP_EINVAL);

    /* Unmarked descriptor (neither UDP nor ICMP) is rejected */
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_can_read(&s, 0), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_can_write(&s, 0), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_can_read_write_icmp_socket)
{
    struct wolfIP s;
    struct tsocket *ts;
    int sd;
    uint8_t payload[8] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(sd)];
    ck_assert_int_eq(wolfIP_sock_can_read(&s, sd), 0);
    ck_assert_int_eq(wolfIP_sock_can_write(&s, sd), 1);
    /* enqueue a fake ICMP frame */
    {
        uint8_t buf[sizeof(struct wolfIP_icmp_packet) + sizeof(payload)];
        struct wolfIP_icmp_packet *icmp = (struct wolfIP_icmp_packet *)buf;
        memset(buf, 0, sizeof(buf));
        icmp->ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN + sizeof(payload));
        ck_assert_int_eq(fifo_push(&ts->sock.udp.rxbuf, buf, sizeof(buf)), 0);
    }
    ck_assert_int_eq(wolfIP_sock_can_read(&s, sd), 1);
}
END_TEST

/* ---- wolfIP_sock_socket ---- */

START_TEST(test_sock_socket_wrong_domain)
{
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_socket(&s, AF_INET + 1,
            IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP), -1);
}
END_TEST

START_TEST(test_sock_socket_unsupported_protocol)
{
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);
    /* SOCK_DGRAM with a protocol number outside {0, UDP, ICMP} is rejected. */
    ck_assert_int_eq(wolfIP_sock_socket(&s, AF_INET,
            IPSTACK_SOCK_DGRAM, 0x7f), -1);
}
END_TEST

START_TEST(test_sock_socket_pool_exhaustion)
{
    struct wolfIP s;
    int i;
    int sd;
    wolfIP_init(&s);
    mock_link_init(&s);
    for (i = 0; i < MAX_UDPSOCKETS; i++) {
        sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
        ck_assert_int_gt(sd, 0);
    }
    /* Pool exhausted: next allocation fails. */
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_eq(sd, -1);

    for (i = 0; i < MAX_ICMPSOCKETS; i++) {
        sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
        ck_assert_int_gt(sd, 0);
    }
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_eq(sd, -1);
}
END_TEST

/* ---- wolfIP_sock_close ---- */

START_TEST(test_sock_close_invalid_inputs)
{
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_close(&s, -1), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_close(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS),
            -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_close(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS),
            -WOLFIP_EINVAL);
    /* Unmarked descriptor */
    ck_assert_int_eq(wolfIP_sock_close(&s, 0), -1);
}
END_TEST

START_TEST(test_sock_close_udp_dispatches_filter)
{
    struct wolfIP s;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);

    filter_cb_calls = 0;
    memset(&filter_last_event, 0, sizeof(filter_last_event));
    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_DISSOCIATE));

    ck_assert_int_eq(wolfIP_sock_close(&s, sd), 0);
    ck_assert_int_eq(filter_cb_calls, 1);
    ck_assert_int_eq(filter_last_event.reason, WOLFIP_FILT_DISSOCIATE);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
}
END_TEST

START_TEST(test_sock_close_icmp_dispatches_filter)
{
    struct wolfIP s;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(sd, 0);

    filter_cb_calls = 0;
    memset(&filter_last_event, 0, sizeof(filter_last_event));
    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_DISSOCIATE));

    ck_assert_int_eq(wolfIP_sock_close(&s, sd), 0);
    ck_assert_int_eq(filter_cb_calls, 1);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
}
END_TEST

/* ---- wolfIP_sock_connect ---- */

START_TEST(test_sock_connect_invalid_args_udp_icmp)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    /* NULL addr */
    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, NULL, sizeof(sin)),
            -WOLFIP_EINVAL);
    /* sockfd<0 */
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    ck_assert_int_eq(wolfIP_sock_connect(&s, -1, (struct wolfIP_sockaddr *)&sin,
            sizeof(sin)), -WOLFIP_EINVAL);
    /* Unmarked descriptor */
    ck_assert_int_eq(wolfIP_sock_connect(&s, 0, (struct wolfIP_sockaddr *)&sin,
            sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_udp_descriptor_oor)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_connect(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_udp_short_addrlen_or_wrong_family)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, 1), -WOLFIP_EINVAL);
    sin.sin_family = AF_INET + 1;
    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_udp_uses_bound_local_ip)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    const ip4 primary_ip = 0xC0A80001U;
    const ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];

    /* Set bound_local_ip directly so connect picks if_idx from it. */
    ts->bound_local_ip = secondary_ip;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(9000);
    sin.sin_addr.s_addr = ee32(0xC0A80155U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->if_idx, TEST_SECOND_IF);
    ck_assert_uint_eq(ts->local_ip, secondary_ip);

    /* bound_local_ip that doesn't match any interface fails. */
    ts->bound_local_ip = 0xDEADBEEFU;
    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_udp_unbound_uses_route)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    const ip4 primary_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, primary_ip, 0xFFFFFF00U, 0);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(9000);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, primary_ip);
    ck_assert_uint_eq(ts->remote_ip, 0x0A000002U);
    ck_assert_uint_eq(ts->dst_port, 9000);
}
END_TEST

START_TEST(test_sock_connect_icmp_basic)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    const ip4 primary_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, primary_ip, 0xFFFFFF00U, 0);
    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->remote_ip, 0x0A000002U);
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST

START_TEST(test_sock_connect_icmp_wrong_family_or_short)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET + 1;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
    sin.sin_family = AF_INET;
    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd,
            (struct wolfIP_sockaddr *)&sin, 1), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_icmp_bound_local_mismatch)
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
    ts->bound_local_ip = 0xDEADBEEFU;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

/* ---- wolfIP_sock_bind extras ---- */

START_TEST(test_sock_bind_null_or_short)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, NULL, sizeof(sin)),
            -WOLFIP_EINVAL);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, 1), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_bind(&s, -1,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_bind_oor_and_unmarked)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_bind(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_bind(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_bind(&s, 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_bind_udp_rebind_rejected)
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
    sin.sin_addr.s_addr = ee32(IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    /* Already bound -> reject. */
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_bind_udp_wrong_family)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    wolfIP_init(&s);
    mock_link_init(&s);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET + 1;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_bind_udp_any_uses_primary)
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
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    /* bind to IPADDR_ANY should fall through to the primary interface config. */
    ck_assert_uint_eq(ts->local_ip, 0x0A000001U);
    ck_assert_uint_eq(ts->bound_local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_bind_icmp_basic_and_rebind)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, icmp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    /* Wrong family on rebind path: existing src_port != 0 takes precedence,
     * returning -1 before family check. */
    ck_assert_int_eq(wolfIP_sock_bind(&s, icmp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_bind_icmp_wrong_family)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    wolfIP_init(&s);
    mock_link_init(&s);
    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET + 1;
    sin.sin_port = ee16(7);
    sin.sin_addr.s_addr = ee32(IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_bind(&s, icmp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_bind_filter_block_rolls_back)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 prev_ip;
    uint16_t prev_port;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    prev_ip = ts->local_ip;
    prev_port = ts->src_port;

    filter_block_reason = WOLFIP_FILT_BINDING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_BINDING));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    /* State rolled back. */
    ck_assert_uint_eq(ts->local_ip, prev_ip);
    ck_assert_uint_eq(ts->src_port, prev_port);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
}
END_TEST

/* ---- wolfIP_sock_sendto extras ---- */

START_TEST(test_sendto_arg_validation)
{
    struct wolfIP s;
    int udp_sd;
    int icmp_sd;
    uint8_t buf[4] = {1, 2, 3, 4};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_gt(icmp_sd, 0);

    /* sockfd<0 */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, -1, buf, sizeof(buf), 0, NULL, 0),
            -WOLFIP_EINVAL);
    /* NULL buf */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, NULL, sizeof(buf), 0, NULL, 0),
            -1);
    /* len=0 */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, 0, 0, NULL, 0),
            -1);
    /* OOR descriptors */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS,
            buf, sizeof(buf), 0, NULL, 0), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS,
            buf, sizeof(buf), 0, NULL, 0), -WOLFIP_EINVAL);
    /* Unmarked descriptor */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, 0, buf, sizeof(buf), 0, NULL, 0),
            -1);
    /* UDP: no dest_port, no dest_addr */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0, NULL, 0),
            -1);
}
END_TEST

START_TEST(test_sendto_udp_short_addrlen_and_zero_dest)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(9000);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    /* Short addrlen with non-NULL sin */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, 1), -1);

    /* sin with zero port/addr after copy -> dst_port/remote_ip==0 path */
    sin.sin_port = 0;
    sin.sin_addr.s_addr = 0;
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sendto_udp_auto_assigns_src_port)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {0xAA, 0xBB, 0xCC, 0xDD};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ck_assert_uint_eq(ts->src_port, 0);

    /* Force low-value random to exercise the "< 1024" rollover branch. */
    test_rand_override_enabled = 1;
    test_rand_override_value = 5;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(9000);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(buf));
    ck_assert_uint_ge(ts->src_port, 1024U);
    test_rand_override_enabled = 0;
}
END_TEST

START_TEST(test_sendto_icmp_branches)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t small[ICMP_HEADER_LEN - 1] = {0};
    uint8_t payload[ICMP_HEADER_LEN] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];

    /* ICMP: no remote yet, no dest_addr -> -1 */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload),
            0, NULL, 0), -1);

    /* Short addrlen with sin -> -1 */
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload),
            0, (struct wolfIP_sockaddr *)&sin, 1), -1);

    /* payload < ICMP_HEADER_LEN -> EINVAL */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, small, sizeof(small),
            0, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
    /* Valid send: payload exactly ICMP_HEADER_LEN, dest from sin */
    payload[0] = ICMP_ECHO_REQUEST;
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload),
            0, (struct wolfIP_sockaddr *)&sin, sizeof(sin)),
            (int)sizeof(payload));
    ck_assert_uint_eq(ts->remote_ip, 0x0A000002U);

    /* bound_local_ip mismatch -> EINVAL */
    ts->bound_local_ip = 0xDEADBEEFU;
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload),
            0, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

/* ---- wolfIP_sock_recvfrom extras ---- */

START_TEST(test_recvfrom_arg_validation)
{
    struct wolfIP s;
    int udp_sd;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t slen = sizeof(sin);
    uint8_t buf[8];

    wolfIP_init(&s);
    mock_link_init(&s);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_gt(icmp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, -1, buf, sizeof(buf), 0, NULL, NULL),
            -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS,
            buf, sizeof(buf), 0, NULL, NULL), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS,
            buf, sizeof(buf), 0, NULL, NULL), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, 0, buf, sizeof(buf), 0, NULL, NULL),
            -WOLFIP_EINVAL);
    /* sin with no addrlen */
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, NULL), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, icmp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, NULL), -WOLFIP_EINVAL);
    /* sin with short addrlen */
    slen = 1;
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, &slen), -WOLFIP_EINVAL);
    slen = 1;
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, icmp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, &slen), -WOLFIP_EINVAL);
    /* Empty UDP returns EAGAIN, empty ICMP returns EAGAIN */
    slen = sizeof(sin);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, udp_sd, buf, sizeof(buf), 0,
            NULL, NULL), -WOLFIP_EAGAIN);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, icmp_sd, buf, sizeof(buf), 0,
            NULL, NULL), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_recvfrom_icmp_populates_sin)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    uint8_t out[ICMP_HEADER_LEN];
    struct wolfIP_sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    uint8_t buf[sizeof(struct wolfIP_icmp_packet)];
    struct wolfIP_icmp_packet *icmp = (struct wolfIP_icmp_packet *)buf;

    wolfIP_init(&s);
    mock_link_init(&s);
    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];

    memset(buf, 0, sizeof(buf));
    icmp->ip.src = ee32(0x0A000002U);
    icmp->ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp->type = ICMP_ECHO_REPLY;
    ck_assert_int_eq(fifo_push(&ts->sock.udp.rxbuf, buf, sizeof(buf)), 0);
    ts->events |= CB_EVENT_READABLE;

    memset(&from, 0, sizeof(from));
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, icmp_sd, out, sizeof(out), 0,
            (struct wolfIP_sockaddr *)&from, &fromlen), ICMP_HEADER_LEN);
    ck_assert_uint_eq(from.sin_family, AF_INET);
    ck_assert_uint_eq(from.sin_addr.s_addr, ee32(0x0A000002U));
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, 0U);
}
END_TEST

/* ---- wolfIP_sock_setsockopt extras ---- */

START_TEST(test_setsockopt_invalid_socket)
{
    struct wolfIP s;
    int v = 1;
    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, -1,
            WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &v, sizeof(v)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS,
            WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &v, sizeof(v)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_setsockopt_recvttl_argument_checks)
{
    struct wolfIP s;
    int udp_sd;
    int enable = 1;
    struct tsocket *ts;
    wolfIP_init(&s);
    mock_link_init(&s);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_RECVTTL, NULL, sizeof(enable)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_RECVTTL, &enable, 1), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_RECVTTL, &enable, sizeof(enable)), 0);
    ck_assert_uint_eq(ts->recv_ttl, 1);
    enable = 0;
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_RECVTTL, &enable, sizeof(enable)), 0);
    ck_assert_uint_eq(ts->recv_ttl, 0);
}
END_TEST

START_TEST(test_setsockopt_unknown_optname_returns_zero)
{
    struct wolfIP s;
    int udp_sd;
    int v = 42;
    wolfIP_init(&s);
    mock_link_init(&s);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd,
            0xFEED, 0xBEEF, &v, sizeof(v)), 0);
}
END_TEST

#ifdef IP_MULTICAST
START_TEST(test_setsockopt_multicast_short_optlen)
{
    struct wolfIP s;
    int udp_sd;
    uint8_t small[1] = {0};
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_ADD_MEMBERSHIP, small, sizeof(small)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_DROP_MEMBERSHIP, NULL, 0), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_IF, small, sizeof(small)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_TTL, NULL, sizeof(int)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_TTL, small, 0), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_LOOP, NULL, sizeof(int)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_LOOP, small, 0), -WOLFIP_EINVAL);
}
END_TEST
#endif /* IP_MULTICAST */

#ifdef IP_MULTICAST
START_TEST(test_setsockopt_multicast_ttl_out_of_range)
{
    struct wolfIP s;
    int udp_sd;
    int ttl;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ttl = -1;
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_TTL, &ttl, sizeof(ttl)), -WOLFIP_EINVAL);
    ttl = 256;
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_TTL, &ttl, sizeof(ttl)), -WOLFIP_EINVAL);
}
END_TEST
#endif /* IP_MULTICAST */

#ifdef IP_MULTICAST
START_TEST(test_setsockopt_multicast_on_icmp_is_noop)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_ip_mreq mreq;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = ee32(0xE9010210U);
    /* On ICMP socket, IP_ADD_MEMBERSHIP is ignored and returns 0 (fall-through). */
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, icmp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)), 0);
}
END_TEST
#endif /* IP_MULTICAST */

#ifdef IP_MULTICAST
START_TEST(test_setsockopt_drop_unjoined_returns_einval)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_ip_mreq mreq;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = ee32(0xE9010211U);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)), -WOLFIP_EINVAL);
}
END_TEST
#endif /* IP_MULTICAST */

/* ---- wolfIP_sock_getsockopt extras ---- */

START_TEST(test_getsockopt_invalid_inputs)
{
    struct wolfIP s;
    int udp_sd;
    int value;
    socklen_t len = sizeof(value);
    wolfIP_init(&s);
    mock_link_init(&s);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    /* Invalid socket */
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, -1, WOLFIP_SOL_IP,
            WOLFIP_IP_RECVTTL, &value, &len), -WOLFIP_EINVAL);
    /* Null optval / optlen / short len */
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_RECVTTL, NULL, &len), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_RECVTTL, &value, NULL), -WOLFIP_EINVAL);
    len = 1;
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_RECVTTL, &value, &len), -WOLFIP_EINVAL);
    /* Unknown optname returns 0 (fall-through). */
    len = sizeof(value);
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, 0xFEED, 0xBEEF,
            &value, &len), 0);
}
END_TEST

#ifdef IP_MULTICAST
START_TEST(test_getsockopt_multicast_if_short_optlen)
{
    struct wolfIP s;
    int udp_sd;
    uint8_t small[1];
    socklen_t len = sizeof(small);
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_IF, small, &len), -WOLFIP_EINVAL);
}
END_TEST
#endif /* IP_MULTICAST */

/* ---- wolfIP_poll ---- */

START_TEST(test_poll_dispatches_socket_callback)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    wolfIP_init(&s);
    mock_link_init(&s);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    wolfIP_register_callback(&s, udp_sd, test_socket_cb, NULL);
    ts->events = CB_EVENT_READABLE;
    socket_cb_calls = 0;
    socket_cb_last_fd = -1;
    ck_assert_int_eq(wolfIP_poll(&s, 1), 0);
    ck_assert_int_eq(socket_cb_calls, 1);
    ck_assert_int_eq(socket_cb_last_fd, SOCKET_UNMARK(udp_sd) | MARK_UDP_SOCKET);
}
END_TEST

START_TEST(test_poll_fires_expired_timer)
{
    struct wolfIP s;
    struct wolfIP_timer tmr;
    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&tmr, 0, sizeof(tmr));
    tmr.expires = 100;
    tmr.cb = test_timer_cb;
    timers_binheap_insert(&s.timers, tmr);
    timer_cb_calls = 0;
    ck_assert_int_eq(wolfIP_poll(&s, 200), 0);
    ck_assert_int_eq(timer_cb_calls, 1);
}
END_TEST

START_TEST(test_poll_arp_pending_when_nexthop_unresolved)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {1, 2, 3, 4};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(9000);
    sin.sin_addr.s_addr = ee32(0x0A0000FEU); /* not in ARP cache */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(buf));
    ck_assert_uint_gt(fifo_len(&ts->sock.udp.txbuf), 0U);
    last_frame_sent_size = 0;
    /* Use now > 1000 so the ARP rate-limit window has elapsed. */
    ck_assert_int_eq(wolfIP_poll(&s, 2000), 0);
    /* Poll should have emitted an ARP request and left the datagram queued. */
    ck_assert_uint_eq(last_frame_sent_size, sizeof(struct arp_packet));
    ck_assert_uint_gt(fifo_len(&ts->sock.udp.txbuf), 0U);
}
END_TEST

START_TEST(test_poll_filter_block_holds_tx)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {0};
    uint8_t neighbor_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    /* Pre-load ARP so that sendto can be flushed by poll without ARP wait. */
    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    s.arp.neighbors[0].ts = 1;
    memcpy(s.arp.neighbors[0].mac, neighbor_mac, 6);
    s.last_tick = 1;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(9000);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(buf));

    /* Block UDP sends via filter. */
    filter_block_reason = WOLFIP_FILT_SENDING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_udp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;
    ck_assert_int_eq(wolfIP_poll(&s, 2), 0);
    /* Filter blocked send: nothing transmitted, packet still in txbuf. */
    ck_assert_uint_eq(last_frame_sent_size, 0U);
    ck_assert_uint_gt(fifo_len(&ts->sock.udp.txbuf), 0U);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_udp_mask(0);
}
END_TEST

START_TEST(test_poll_drains_icmp_tx)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};
    uint8_t neighbor_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    s.arp.neighbors[0].ts = 1;
    memcpy(s.arp.neighbors[0].mac, neighbor_mac, 6);
    s.last_tick = 1;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];

    payload[0] = ICMP_ECHO_REQUEST;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    last_frame_sent_size = 0;
    ck_assert_int_eq(wolfIP_poll(&s, 2), 0);
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    ck_assert_uint_eq(fifo_len(&ts->sock.udp.txbuf), 0U);
}
END_TEST

/* ---- ARP queue eviction / replacement ---- */

START_TEST(test_arp_pending_record_replaces_oldest_slot)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    uint32_t len = sizeof(ip);
    int i;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    memset(&ip, 0, sizeof(ip));
    ip.ver_ihl = 0x45;
    ip.ttl = 64;
    ip.len = ee16(IP_HEADER_LEN);

    /* Fill the pending pool. */
    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++) {
        ip.dst = ee32(0x0A000010U + i);
        arp_queue_packet(&s, TEST_PRIMARY_IF, 0x0A000010U + i, &ip, len);
    }
    /* Same dst hits the existing slot, no new slot allocated. */
    ip.dst = ee32(0x0A000010U);
    arp_queue_packet(&s, TEST_PRIMARY_IF, 0x0A000010U, &ip, len);
    ck_assert_uint_eq(s.arp_pending[0].dest, 0x0A000010U);

    /* A new destination with no free slot falls back to slot 0. */
    ip.dst = ee32(0x0A0000A0U);
    arp_queue_packet(&s, TEST_PRIMARY_IF, 0x0A0000A0U, &ip, len);
    ck_assert_uint_eq(s.arp_pending[0].dest, 0x0A0000A0U);
}
END_TEST

START_TEST(test_arp_flush_pending_drops_ttl1)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    struct arp_packet reply;
    uint8_t mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    memset(&ip, 0, sizeof(ip));
    ip.ver_ihl = 0x45;
    ip.ttl = 1;
    ip.len = ee16(IP_HEADER_LEN);
    ip.dst = ee32(0x0A000050U);
    arp_queue_packet(&s, TEST_PRIMARY_IF, 0x0A000050U, &ip, sizeof(ip));

    memset(&reply, 0, sizeof(reply));
    reply.htype = ee16(1);
    reply.ptype = ee16(0x0800);
    reply.hlen = 6;
    reply.plen = 4;
    reply.opcode = ee16(ARP_REPLY);
    reply.sip = ee32(0x0A000050U);
    memcpy(reply.sma, mac, 6);
    last_frame_sent_size = 0;
    arp_recv(&s, TEST_PRIMARY_IF, &reply, sizeof(reply));
    /* Queue should be drained even though no frame was emitted (TTL would drop to 0). */
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
    ck_assert_uint_eq(s.arp_pending[0].len, 0U);
}
END_TEST

/* ---- icmp_input extras ---- */

START_TEST(test_icmp_input_short_frame_dropped)
{
    struct wolfIP s;
    uint8_t buf[sizeof(struct wolfIP_icmp_packet) - 1];
    wolfIP_init(&s);
    mock_link_init(&s);
    last_frame_sent_size = 0;
    memset(buf, 0, sizeof(buf));
    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)buf, sizeof(buf));
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_icmp_input_bad_checksum_dropped)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;
    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.ttl = 64;
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    icmp.csum = 0; /* wrong checksum */
    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN));
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_icmp_input_filter_blocked)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    wolfIP_init(&s);
    mock_link_init(&s);
    last_frame_sent_size = 0;
    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.ttl = 64;
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    icmp.csum = ee16(icmp_checksum(&icmp, ICMP_HEADER_LEN));

    filter_block_reason = WOLFIP_FILT_RECEIVING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_icmp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));
    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN));
    ck_assert_uint_eq(last_frame_sent_size, 0U);
    ck_assert_int_gt(filter_block_calls, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_icmp_mask(0);
}
END_TEST

/* ---- udp_try_recv extras ---- */

START_TEST(test_udp_try_recv_short_frame_dropped)
{
    struct wolfIP s;
    uint8_t buf[sizeof(struct wolfIP_udp_datagram) - 1];
    wolfIP_init(&s);
    mock_link_init(&s);
    memset(buf, 0, sizeof(buf));
    last_frame_sent_size = 0;
    udp_try_recv(&s, TEST_PRIMARY_IF, (struct wolfIP_udp_datagram *)buf,
            (uint32_t)sizeof(buf));
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_udp_try_recv_bad_udp_checksum_dropped)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_udp_datagram) + 4];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)buf;
    ip4 local_ip = 0x0A000001U;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(buf, 0, sizeof(buf));
    udp->ip.src = ee32(0x0A000002U);
    udp->ip.dst = ee32(local_ip);
    udp->ip.ver_ihl = 0x45;
    udp->ip.ttl = 64;
    udp->ip.proto = WI_IPPROTO_UDP;
    udp->ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN + 4);
    udp->src_port = ee16(9999);
    udp->dst_port = ee16(1234);
    udp->len = ee16(UDP_HEADER_LEN + 4);
    udp->csum = ee16(0xABCD); /* wrong */
    udp_try_recv(&s, TEST_PRIMARY_IF, udp,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_udp_try_recv_filter_blocked)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_udp_datagram) + 4];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)buf;
    ip4 local_ip = 0x0A000001U;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 1234;
    ts->local_ip = local_ip;

    memset(buf, 0, sizeof(buf));
    udp->ip.src = ee32(0x0A000002U);
    udp->ip.dst = ee32(local_ip);
    udp->ip.ver_ihl = 0x45;
    udp->ip.ttl = 64;
    udp->ip.proto = WI_IPPROTO_UDP;
    udp->ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN + 4);
    udp->src_port = ee16(9999);
    udp->dst_port = ee16(1234);
    udp->len = ee16(UDP_HEADER_LEN + 4);
    fix_udp_checksums(udp);

    filter_block_reason = WOLFIP_FILT_RECEIVING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_udp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));
    udp_try_recv(&s, TEST_PRIMARY_IF, udp,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
    ck_assert_int_gt(filter_block_calls, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_udp_mask(0);
}
END_TEST

/* ---- mcast_if_from_addr error edges ---- */

#ifdef IP_MULTICAST
START_TEST(test_mcast_if_from_addr_validation)
{
    struct wolfIP s;
    unsigned int if_idx = 0xFF;
    wolfIP_init(&s);
    mock_link_init(&s);
    /* Non-multicast group rejected. */
    ck_assert_int_eq(mcast_if_from_addr(&s, IPADDR_ANY, 0x0A000001U, &if_idx),
            -WOLFIP_EINVAL);
    /* NULL if_idx pointer rejected. */
    ck_assert_int_eq(mcast_if_from_addr(&s, IPADDR_ANY, 0xE9010220U, NULL),
            -WOLFIP_EINVAL);
    /* Address that doesn't match any interface fails. */
    ck_assert_int_eq(mcast_if_from_addr(&s, 0xDEADBEEFU, 0xE9010220U, &if_idx),
            -WOLFIP_EINVAL);
}
END_TEST
#endif /* IP_MULTICAST */

/* ---- ip_output_add_header / ip_recv coverage via direct unicast UDP send-and-receive ---- */

START_TEST(test_udp_send_and_receive_through_poll)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    uint8_t rxbuf[8];
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    s.arp.neighbors[0].ts = 1;
    memcpy(s.arp.neighbors[0].mac, mac, 6);
    s.last_tick = 1;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_ip & 0xFFFFU);
    sin.sin_addr.s_addr = ee32(local_ip);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    sin.sin_port = ee16(7000);
    sin.sin_addr.s_addr = ee32(remote_ip);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(buf));
    last_frame_sent_size = 0;
    ck_assert_int_eq(wolfIP_poll(&s, 2), 0);
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    ck_assert_uint_eq(fifo_len(&ts->sock.udp.txbuf), 0U);

    /* Loop the frame back as if received and verify recvfrom returns it. */
    inject_udp_datagram(&s, TEST_PRIMARY_IF, remote_ip, local_ip, 7000,
            local_ip & 0xFFFFU, buf, sizeof(buf));
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, udp_sd, rxbuf, sizeof(rxbuf),
            0, NULL, NULL), (int)sizeof(buf));
    ck_assert_mem_eq(rxbuf, buf, sizeof(buf));
}
END_TEST

/* ---- wolfIP_sock_getsockname / wolfIP_sock_getpeername extras ---- */

START_TEST(test_sock_getsockname_udp_success)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_sockaddr_in out;
    socklen_t len = sizeof(out);

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
    memset(&out, 0, sizeof(out));
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, udp_sd,
            (struct wolfIP_sockaddr *)&out, &len), 0);
    ck_assert_uint_eq(out.sin_family, AF_INET);
    ck_assert_uint_eq(out.sin_port, ee16(1234));
}
END_TEST

START_TEST(test_sock_getpeername_negative_sockfd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in out;
    socklen_t len = sizeof(out);
    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_sock_getpeername(&s, -2,
            (struct wolfIP_sockaddr *)&out, &len), -WOLFIP_EINVAL);
    /* Marked but otherwise valid: still -1 in trimmed scope. */
    ck_assert_int_eq(wolfIP_sock_getpeername(&s, MARK_UDP_SOCKET | 0,
            (struct wolfIP_sockaddr *)&out, &len), -1);
}
END_TEST

/* ---- arp_request rate-limit / arp_lookup non-existent ---- */

START_TEST(test_arp_lookup_missing_returns_neg1)
{
    struct wolfIP s;
    uint8_t out[6];
    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(arp_lookup(&s, TEST_PRIMARY_IF, 0xDEADBEEFU, out), -1);
}
END_TEST

/* ---- fifo_can_push_len wrap-state branches ---- */

START_TEST(test_fifo_can_push_len_validation)
{
    struct fifo f;
    uint8_t data[128];

    fifo_init(&f, data, sizeof(data));
    /* NULL fifo */
    ck_assert_int_eq(fifo_can_push_len(NULL, 4), 0);
    /* Length larger than the FIFO's total capacity */
    ck_assert_int_eq(fifo_can_push_len(&f, sizeof(data) + 1), 0);
    /* Valid trivial push */
    ck_assert_int_eq(fifo_can_push_len(&f, 4), 1);
}
END_TEST

START_TEST(test_fifo_can_push_len_full_no_wrap_returns_zero)
{
    struct fifo f;
    uint8_t data[64];
    uint8_t payload[4] = {0};
    /* Two pkt_desc(16)+payload(4)=20-byte slots fit 3 times in 64 bytes
     * (60 used, 4 unused). Use a smaller capacity to make full easy. */
    fifo_init(&f, data, sizeof(data));
    /* Force full: head == tail with no wrap means empty; we want the
     * "head == tail && h_wrap != 0" full-state branch. */
    f.head = 4;
    f.tail = 4;
    f.h_wrap = sizeof(data);
    ck_assert_int_eq(fifo_can_push_len(&f, sizeof(payload)), 0);
}
END_TEST

START_TEST(test_fifo_can_push_len_head_wraps_when_h_wrap_matches)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    /* Simulate state where head sits exactly at h_wrap so the function
     * wraps head to 0 before testing space. */
    f.tail = 16;
    f.head = 48;
    f.h_wrap = 48;
    /* Now head == h_wrap; head should be wrapped to 0, then needed (4+16=20)
     * compared against tail==16. 0+20 > 16 -> not enough -> 0. */
    ck_assert_int_eq(fifo_can_push_len(&f, 4), 0);
}
END_TEST

START_TEST(test_fifo_can_push_len_end_space_insufficient_then_wraps)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    f.tail = 32;
    f.head = 56;
    f.h_wrap = 0;
    /* end_space = 64 - 56 = 8 bytes; pkt_desc(16)+4 = 20 needed.
     * end_space < needed: requires wrap. tail(32) >= needed(20) so wrap path
     * succeeds and returns 1. */
    ck_assert_int_eq(fifo_can_push_len(&f, 4), 1);
}
END_TEST

START_TEST(test_fifo_can_push_len_end_space_insufficient_tail_too_close)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    f.tail = 4;
    f.head = 56;
    f.h_wrap = 0;
    /* end_space = 8 < needed=20 and tail=4 < needed=20 -> return 0. */
    ck_assert_int_eq(fifo_can_push_len(&f, 4), 0);
}
END_TEST

START_TEST(test_fifo_can_push_len_h_wrap_insufficient_space)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    /* h_wrap state with head<tail: space = tail-head. */
    f.tail = 20;
    f.head = 8;
    f.h_wrap = 48;
    /* space = 20-8 = 12 bytes; needed = 20 -> return 0. */
    ck_assert_int_eq(fifo_can_push_len(&f, 4), 0);
}
END_TEST

START_TEST(test_fifo_can_push_len_h_wrap_head_ge_tail_no_space)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    /* h_wrap set but head >= tail (degenerate state) -> space = 0 -> return 0. */
    f.tail = 8;
    f.head = 16;
    f.h_wrap = 48;
    ck_assert_int_eq(fifo_can_push_len(&f, 4), 0);
}
END_TEST

/* ---- fifo_push insufficient space ---- */

START_TEST(test_fifo_push_returns_minus_one_when_full)
{
    struct fifo f;
    uint8_t data[64];
    uint8_t payload[8];

    fifo_init(&f, data, sizeof(data));
    memset(payload, 0xAB, sizeof(payload));
    /* Fill the FIFO (2 * (16+8) = 48 bytes). */
    ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    /* Third push would exceed capacity: 48 + 24 = 72 > 64. */
    ck_assert_int_lt(fifo_push(&f, payload, sizeof(payload)), 0);
}
END_TEST

/* ---- wolfIP_route_for_ip gateway fallback ---- */

START_TEST(test_route_for_ip_gateway_fallback)
{
    struct wolfIP s;
    unsigned int if_idx;
    wolfIP_init(&s);
    mock_link_init(&s);
    /* Configure primary with a gateway so non-local destinations route there. */
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0x0A000002U);
    /* Destination outside the configured subnet -> use gw_fallback path. */
    if_idx = wolfIP_route_for_ip(&s, 0x14000001U);
    ck_assert_uint_eq(if_idx, TEST_PRIMARY_IF);
    /* Destination IPADDR_ANY -> default_if (loopback-aware). */
    if_idx = wolfIP_route_for_ip(&s, IPADDR_ANY);
    ck_assert_uint_eq(if_idx, WOLFIP_PRIMARY_IF_IDX);
}
END_TEST

START_TEST(test_route_for_ip_first_non_loop_fallback)
{
    struct wolfIP s;
    unsigned int if_idx;
    wolfIP_init(&s);
    mock_link_init(&s);
    /* Set a primary IP but no gateway and destination outside subnet:
     * has_gw_fallback false, has_non_loop true -> returns first_non_loop. */
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    if_idx = wolfIP_route_for_ip(&s, 0x14000001U);
    ck_assert_uint_eq(if_idx, TEST_PRIMARY_IF);
}
END_TEST

/* ---- wolfIP_sock_sendto: TX buf full -> EAGAIN ---- */

START_TEST(test_sendto_udp_txbuf_full_eagain)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[512];

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(9000);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    memset(buf, 0xCC, sizeof(buf));

    /* Push enough datagrams to overflow the txbuf. Each push reserves
     * sizeof(pkt_desc)+sizeof(wolfIP_udp_datagram)+len bytes. */
    while (1) {
        int r = wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin));
        if (r != (int)sizeof(buf))
            break;
    }
    /* Final attempt returns -EAGAIN because txbuf is full. */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    (void)ts;
}
END_TEST

/* ---- wolfIP_sock_sendto: bound_local_ip mismatch on ICMP ---- */

START_TEST(test_sendto_icmp_no_remote_after_addr_zero)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;  /* will set ts->remote_ip = 0 -> reject */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

/* ---- ip_recv with IP options (options-stripping path) ---- */

START_TEST(test_ip_recv_with_ip_options_strips_and_dispatches)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    uint8_t frame[ETH_HEADER_LEN + 24 /* IP+4 opts */ + UDP_HEADER_LEN + 4];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)frame;
    uint8_t *udp_hdr;
    ip4 local_ip = 0x0A000001U;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5000);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    memset(frame, 0, sizeof(frame));
    {
        struct wolfIP_ll_dev *ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
        ck_assert_ptr_nonnull(ll);
        memcpy(ip->eth.dst, ll->mac, 6);
    }
    memcpy(ip->eth.src, "\x10\x20\x30\x40\x50\x60", 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    /* IHL=6 -> 24-byte IP header (4 bytes of options) */
    ip->ver_ihl = 0x46;
    ip->ttl = 32;
    ip->proto = WI_IPPROTO_UDP;
    ip->len = ee16(24 + UDP_HEADER_LEN + 4);
    ip->src = ee32(0x0A000002U);
    ip->dst = ee32(local_ip);
    /* 4 bytes of option = NOP NOP NOP END */
    ip->data[0] = 0x01;
    ip->data[1] = 0x01;
    ip->data[2] = 0x01;
    ip->data[3] = 0x00;
    fix_ip_checksum_with_hlen(ip, 24);

    udp_hdr = frame + ETH_HEADER_LEN + 24;
    {
        uint16_t sp = ee16(4000);
        uint16_t dp = ee16(5000);
        uint16_t ulen = ee16(UDP_HEADER_LEN + 4);
        memcpy(udp_hdr + 0, &sp, 2);
        memcpy(udp_hdr + 2, &dp, 2);
        memcpy(udp_hdr + 4, &ulen, 2);
        memset(udp_hdr + 6, 0, 2); /* csum 0 = no validation */
        memcpy(udp_hdr + UDP_HEADER_LEN, "abcd", 4);
        fix_udp_checksum_raw(ip, udp_hdr, UDP_HEADER_LEN + 4);
    }

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, sizeof(frame));
    /* After options-stripping the datagram should land in the UDP queue. */
    ck_assert_uint_gt(fifo_len(&ts->sock.udp.rxbuf), 0U);
}
END_TEST

START_TEST(test_ip_recv_wrong_version_dropped)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    memset(&ip, 0, sizeof(ip));
    ip.ver_ihl = 0x65; /* version=6 */
    ip.ttl = 64;
    ip.len = ee16(IP_HEADER_LEN);
    ip.src = ee32(0x0A000002U);
    ip.dst = ee32(0x0A000001U);
    last_frame_sent_size = 0;
    ip_recv(&s, TEST_PRIMARY_IF, &ip, sizeof(ip));
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_ip_recv_short_ihl_dropped)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    memset(&ip, 0, sizeof(ip));
    ip.ver_ihl = 0x44; /* IHL=4 -> 16 bytes, below IP_HEADER_LEN (20) */
    ip.ttl = 64;
    ip.len = ee16(IP_HEADER_LEN);
    last_frame_sent_size = 0;
    ip_recv(&s, TEST_PRIMARY_IF, &ip, sizeof(ip));
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_ip_recv_fragment_dropped)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    memset(&ip, 0, sizeof(ip));
    ip.ver_ihl = 0x45;
    ip.ttl = 64;
    ip.flags_fo = ee16(0x2000); /* MF flag set */
    ip.len = ee16(IP_HEADER_LEN);
    ip.src = ee32(0x0A000002U);
    ip.dst = ee32(0x0A000001U);
    fix_ip_checksum(&ip);
    last_frame_sent_size = 0;
    ip_recv(&s, TEST_PRIMARY_IF, &ip,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_ip_recv_bad_header_checksum_dropped)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    memset(&ip, 0, sizeof(ip));
    ip.ver_ihl = 0x45;
    ip.ttl = 64;
    ip.len = ee16(IP_HEADER_LEN);
    ip.src = ee32(0x0A000002U);
    ip.dst = ee32(0x0A000001U);
    ip.csum = ee16(0x1234); /* wrong */
    last_frame_sent_size = 0;
    ip_recv(&s, TEST_PRIMARY_IF, &ip,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

/* ---- arp_recv extras ---- */

START_TEST(test_arp_recv_short_frame_dropped)
{
    struct wolfIP s;
    uint8_t buf[8] = {0};
    wolfIP_init(&s);
    mock_link_init(&s);
    /* Short ARP frame is dropped; no neighbor learned. */
    arp_recv(&s, TEST_PRIMARY_IF, buf, sizeof(buf));
    ck_assert_uint_eq(s.arp.neighbors[0].ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_recv_request_for_other_ip_ignored)
{
    struct wolfIP s;
    struct arp_packet req;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    memset(&req, 0, sizeof(req));
    req.htype = ee16(1);
    req.ptype = ee16(0x0800);
    req.hlen = 6;
    req.plen = 4;
    req.opcode = ee16(ARP_REQUEST);
    req.sip = ee32(0x0A000002U);
    req.tip = ee32(0x0A0000AAU); /* not our IP */
    memcpy(req.sma, "\x10\x20\x30\x40\x50\x60", 6);
    last_frame_sent_size = 0;
    arp_recv(&s, TEST_PRIMARY_IF, &req, sizeof(req));
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_arp_recv_request_refreshes_existing_neighbor)
{
    struct wolfIP s;
    struct arp_packet req;
    uint8_t sender_mac[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    s.arp.neighbors[0].ts = 100;
    memcpy(s.arp.neighbors[0].mac, sender_mac, 6);
    s.last_tick = 5000;

    memset(&req, 0, sizeof(req));
    req.htype = ee16(1);
    req.ptype = ee16(0x0800);
    req.hlen = 6;
    req.plen = 4;
    req.opcode = ee16(ARP_REQUEST);
    req.sip = ee32(0x0A000002U);
    req.tip = ee32(0x0A000001U);
    memcpy(req.sma, sender_mac, 6);
    arp_recv(&s, TEST_PRIMARY_IF, &req, sizeof(req));
    /* Existing neighbor with matching MAC: ts refreshed. */
    ck_assert_uint_eq(s.arp.neighbors[0].ts, 5000U);
}
END_TEST

START_TEST(test_arp_recv_reply_overwrite_blocked_when_no_pending)
{
    struct wolfIP s;
    struct arp_packet reply;
    uint8_t mac1[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    uint8_t mac2[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    s.arp.neighbors[0].ts = 100;
    memcpy(s.arp.neighbors[0].mac, mac1, 6);

    memset(&reply, 0, sizeof(reply));
    reply.htype = ee16(1);
    reply.ptype = ee16(0x0800);
    reply.hlen = 6;
    reply.plen = 4;
    reply.opcode = ee16(ARP_REPLY);
    reply.sip = ee32(0x0A000002U);
    memcpy(reply.sma, mac2, 6);
    arp_recv(&s, TEST_PRIMARY_IF, &reply, sizeof(reply));
    /* Without a pending request the existing MAC must NOT be overwritten. */
    ck_assert_mem_eq(s.arp.neighbors[0].mac, mac1, 6);
}
END_TEST

/* ---- arp_request rate-limit branch ---- */

START_TEST(test_arp_request_rate_limited)
{
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    s.last_tick = 5000;
    arp_request(&s, TEST_PRIMARY_IF, 0x0A000002U);
    last_frame_sent_size = 0;
    /* A second request within 1000 ticks is suppressed. */
    s.last_tick = 5500;
    arp_request(&s, TEST_PRIMARY_IF, 0x0A000003U);
    ck_assert_uint_eq(last_frame_sent_size, 0U);
    /* After the rate-limit window elapses, the request fires again. */
    s.last_tick = 6500;
    arp_request(&s, TEST_PRIMARY_IF, 0x0A000003U);
    ck_assert_uint_eq(last_frame_sent_size, sizeof(struct arp_packet));
}
END_TEST

/* ---- close_socket releases multicast memberships ---- */

#ifdef IP_MULTICAST
START_TEST(test_close_releases_multicast)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_ip_mreq mreq;
    ip4 group = 0xE901020FU;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = ee32(group);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
            WOLFIP_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)), 0);
    ck_assert_uint_eq(s.mcast[0].refs, 1U);
    /* Close should drop the membership and emit the leave report. */
    last_frame_sent_size = 0;
    ck_assert_int_eq(wolfIP_sock_close(&s, sd), 0);
    ck_assert_uint_eq(s.mcast[0].refs, 0U);
    ck_assert_uint_gt(last_frame_sent_size, 0U);
}
END_TEST
#endif /* IP_MULTICAST */

/* ---- wolfIP_send_ttl_exceeded / wolfIP_send_port_unreachable filter dispatch ---- */

START_TEST(test_send_port_unreachable_filter_blocked_at_eth)
{
    struct wolfIP s;
    uint8_t buf[sizeof(struct wolfIP_udp_datagram) + 4];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)buf;
    uint32_t local_ip = 0x0A000001U;
    uint32_t remote_ip = 0x0A000002U;
    uint8_t src_mac[6] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    memset(buf, 0, sizeof(buf));
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

    /* Block the outgoing ICMP-port-unreachable via the eth-level filter. */
    filter_block_reason = WOLFIP_FILT_SENDING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;
    udp_try_recv(&s, TEST_PRIMARY_IF, udp,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));
    /* Filter blocked: no port-unreachable frame transmitted. */
    ck_assert_uint_eq(last_frame_sent_size, 0U);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

START_TEST(test_send_ttl_exceeded_filter_blocked_at_icmp)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN + TTL_EXCEEDED_ORIG_PACKET_SIZE_MAX];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);

    memset(buf, 0, sizeof(buf));
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

    /* Block the outgoing ICMP-TTL-exceeded via the icmp-level filter. */
    filter_block_reason = WOLFIP_FILT_SENDING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_icmp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;
    ip_recv(&s, TEST_PRIMARY_IF, ip,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + 8));
    ck_assert_uint_eq(last_frame_sent_size, 0U);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_icmp_mask(0);
}
END_TEST

/* ---- udp_mcast_join error edges ---- */

#ifdef IP_MULTICAST
START_TEST(test_mcast_join_non_multicast_rejected_direct)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(sd)];
    /* Non-multicast group / null pointers rejected. */
    ck_assert_int_eq(udp_mcast_join(NULL, ts, 0xE9010220U, TEST_PRIMARY_IF),
            -WOLFIP_EINVAL);
    ck_assert_int_eq(udp_mcast_join(&s, NULL, 0xE9010220U, TEST_PRIMARY_IF),
            -WOLFIP_EINVAL);
    ck_assert_int_eq(udp_mcast_join(&s, ts, 0x0A000001U, TEST_PRIMARY_IF),
            -WOLFIP_EINVAL);
    /* if_idx out of range. */
    ck_assert_int_eq(udp_mcast_join(&s, ts, 0xE9010220U, WOLFIP_MAX_INTERFACES),
            -WOLFIP_EINVAL);
}
END_TEST
#endif /* IP_MULTICAST */

#ifdef IP_MULTICAST
START_TEST(test_mcast_join_exhausts_socket_slots)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    unsigned int i;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(sd)];

    /* Fill all per-socket membership slots. */
    for (i = 0; i < WOLFIP_UDP_MCAST_MEMBERSHIPS; i++) {
        ck_assert_int_eq(udp_mcast_join(&s, ts, 0xE9010300U + i, TEST_PRIMARY_IF),
                0);
    }
    /* One more should return ENOMEM (slot exhaustion). */
    ck_assert_int_eq(udp_mcast_join(&s, ts, 0xE901031FU, TEST_PRIMARY_IF),
            -WOLFIP_ENOMEM);
}
END_TEST
#endif /* IP_MULTICAST */

#ifdef IP_MULTICAST
START_TEST(test_mcast_drop_unjoined_returns_einval_direct)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(sd)];
    /* No join performed -> drop fails. */
    ck_assert_int_eq(udp_mcast_drop(&s, ts, 0xE9010221U, TEST_PRIMARY_IF),
            -WOLFIP_EINVAL);
}
END_TEST
#endif /* IP_MULTICAST */

/* ---- arp_store_neighbor: existing entry refresh / full table ---- */

START_TEST(test_arp_store_neighbor_refresh_existing)
{
    struct wolfIP s;
    uint8_t mac1[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    uint8_t mac2[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    wolfIP_init(&s);
    mock_link_init(&s);
    s.last_tick = 100;
    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A000002U, mac1);
    ck_assert_mem_eq(s.arp.neighbors[0].mac, mac1, 6);
    s.last_tick = 200;
    /* Re-store same ip/if_idx -> mac is updated in place. */
    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A000002U, mac2);
    ck_assert_mem_eq(s.arp.neighbors[0].mac, mac2, 6);
    ck_assert_uint_eq(s.arp.neighbors[0].ts, 200U);
}
END_TEST

START_TEST(test_arp_store_neighbor_full_table)
{
    struct wolfIP s;
    uint8_t mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    int i;
    wolfIP_init(&s);
    mock_link_init(&s);
    for (i = 0; i < MAX_NEIGHBORS; i++) {
        s.arp.neighbors[i].ip = 0x0A000010U + (uint32_t)i;
        s.arp.neighbors[i].if_idx = TEST_PRIMARY_IF;
        s.arp.neighbors[i].ts = 1;
        memset(s.arp.neighbors[i].mac, (uint8_t)i, 6);
    }
    /* Table is full and no slot matches: store should silently fail. */
    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A0000A1U, mac);
    /* Confirm none of the existing slots was overwritten. */
    for (i = 0; i < MAX_NEIGHBORS; i++) {
        ck_assert_uint_ne(s.arp.neighbors[i].ip, 0x0A0000A1U);
    }
}
END_TEST

/* ---- arp_pending_record validation ---- */

START_TEST(test_arp_pending_record_rejects_null_and_oversized)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    memset(&ip, 0, sizeof(ip));
    /* NULL s */
    arp_queue_packet(NULL, TEST_PRIMARY_IF, 0x0A000050U, &ip, sizeof(ip));
    /* Zero len */
    arp_queue_packet(&s, TEST_PRIMARY_IF, 0x0A000050U, &ip, 0);
    /* Length larger than MTU */
    arp_queue_packet(&s, TEST_PRIMARY_IF, 0x0A000050U, &ip, LINK_MTU * 2);
    /* None of the above should have inserted into the queue. */
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

/* ---- wolfIP_sock_bind: ICMP filter rollback ---- */

START_TEST(test_sock_bind_icmp_filter_rolls_back)
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

    filter_block_reason = WOLFIP_FILT_BINDING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_BINDING));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(9);
    sin.sin_addr.s_addr = ee32(IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_bind(&s, icmp_sd,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    ck_assert_uint_eq(ts->src_port, 0U);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
}
END_TEST

/* ---- wolfIP_sock_setsockopt: int sized multicast TTL / LOOP ---- */

#ifdef IP_MULTICAST
START_TEST(test_setsockopt_multicast_ttl_int_path)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    int ttl = 17;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(sd)];
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_TTL, &ttl, sizeof(ttl)), 0);
    ck_assert_uint_eq(ts->sock.udp.mcast_ttl, 17U);
}
END_TEST
#endif /* IP_MULTICAST */

#ifdef IP_MULTICAST
START_TEST(test_setsockopt_multicast_loop_int_and_uint8)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    int loop_i = 1;
    uint8_t loop_b = 0;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(sd)];
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_LOOP, &loop_i, sizeof(loop_i)), 0);
    ck_assert_uint_eq(ts->sock.udp.mcast_loop, 1U);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_LOOP, &loop_b, sizeof(loop_b)), 0);
    ck_assert_uint_eq(ts->sock.udp.mcast_loop, 0U);
}
END_TEST
#endif /* IP_MULTICAST */

#ifdef IP_MULTICAST
START_TEST(test_setsockopt_multicast_ttl_uint8_path)
{
    struct wolfIP s;
    int sd;
    struct tsocket *ts;
    uint8_t ttl8 = 42;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(sd)];
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_TTL, &ttl8, sizeof(ttl8)), 0);
    ck_assert_uint_eq(ts->sock.udp.mcast_ttl, 42U);
}
END_TEST
#endif /* IP_MULTICAST */

/* ---- icmp_input filter dispatch when icmp filter blocks reply send ---- */

START_TEST(test_icmp_input_echo_reply_path_filter_at_eth)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    memset(&icmp, 0, sizeof(icmp));
    memcpy(icmp.ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.ttl = 64;
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    icmp.csum = ee16(icmp_checksum(&icmp, ICMP_HEADER_LEN));

    /* Block at eth send level. */
    filter_block_reason = WOLFIP_FILT_SENDING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;
    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN));
    ck_assert_uint_eq(last_frame_sent_size, 0U);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

/* ---- ip_recv with options too large drops ---- */

START_TEST(test_ip_recv_with_options_oversize_dropped)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU + 100];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    memset(buf, 0, sizeof(buf));
    ip->ver_ihl = 0x46; /* IHL=6, 24-byte hdr (one option word) */
    ip->ttl = 64;
    ip->proto = WI_IPPROTO_UDP;
    ip->len = ee16(IP_HEADER_LEN + 4 + UDP_HEADER_LEN + 4);
    ip->src = ee32(0x0A000002U);
    ip->dst = ee32(0x0A000001U);
    /* Pretend the frame size is larger than LINK_MTU to hit the
     * "len > LINK_MTU -> return" guard in ip_recv. */
    fix_ip_checksum_with_hlen(ip, 24);
    last_frame_sent_size = 0;
    ip_recv(&s, TEST_PRIMARY_IF, ip, (uint32_t)(LINK_MTU + 50));
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

/* ---- wolfIP_recv_on short ETH header ---- */

START_TEST(test_wolfip_recv_on_null_stack_returns)
{
    /* exercises the `!s` early return */
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN];
    memset(buf, 0, sizeof(buf));
    wolfIP_recv_on(NULL, TEST_PRIMARY_IF, buf, sizeof(buf));
}
END_TEST

/* unit_tests_ipv6_sockets.c
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

#if WOLFIP_IPV6

/* =========================================================================
 * Environment note
 * =========================================================================
 * The AF_INET6 socket surface: creation, bind, the names reported back, and
 * IPV6_V6ONLY. Everything here is about how a socket is addressed and
 * described, not about moving packets - the data paths are covered
 * separately.
 *
 * The design being pinned down is RFC 3493 dual-stack. An AF_INET6 socket
 * carries two identities at once: what the application asked for, which
 * decides how addresses are rendered back to it, and what the packets will
 * be, which is decided by the address itself. A v4-mapped address
 * (::ffff:a.b.c.d) is IPv4 on the wire and is deliberately routed through
 * the existing IPv4 code, so the tests below check the reported address
 * rather than assuming the two are the same thing.
 */

#define S6_TEST_GLOBAL "2001:db8:5::1"
#define S6_TEST_OTHER  "2001:db8:5::2"

static void sock6_setup(struct wolfIP *s)
{
    ip6 a;

    wolfIP_init(s);
    mock_link_init(s);
    wolfIP_ipconfig_set_ex(s, TEST_PRIMARY_IF, atoip4("192.168.10.2"),
                           atoip4("255.255.255.0"), atoip4("192.168.10.1"));
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &a), 0);
    ck_assert_int_eq(wolfIP_ifaddr_add6(s, TEST_PRIMARY_IF, &a, 64), 0);
}

static void sock6_addr(struct wolfIP_sockaddr_in6 *sin6, const char *addr,
                       uint16_t port)
{
    ip6 a;

    memset(sin6, 0, sizeof(*sin6));
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = ee16(port);
    if (addr == NULL) {
        ip6_set_unspecified(&a);
    } else {
        ck_assert_int_eq(atoip6(addr, &a), 0);
    }
    memcpy(&sin6->sin6_addr, a.addr, 16);
}

/* =========================================================================
 * 1. Creation
 * ========================================================================= */

START_TEST(test_sock6_stream_and_dgram_are_created)
{
    struct wolfIP s;
    int tcp_fd;
    int udp_fd;

    sock6_setup(&s);
    tcp_fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(tcp_fd, 0);
    udp_fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(udp_fd, 0);
    /* Both come out of the same pools as their AF_INET counterparts, so an
     * AF_INET socket must still be creatable alongside them. */
    ck_assert_int_ge(wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0), 0);
    ck_assert_int_ge(wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, 0), 0);
}
END_TEST

/* ICMP and ICMPv6 are different protocols with different numbers. Pairing a
 * family with the other one's protocol would create a socket that could
 * never match anything on receive, so it is refused at creation. */
START_TEST(test_sock6_icmpv6_socket_requires_the_icmpv6_protocol)
{
    struct wolfIP s;

    sock6_setup(&s);
    ck_assert_int_ge(wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM,
                                        WI_IPPROTO_ICMPV6), 0);
    ck_assert_int_lt(wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM,
                                        WI_IPPROTO_ICMP), 0);
    ck_assert_int_ge(wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM,
                                        WI_IPPROTO_ICMP), 0);
    ck_assert_int_lt(wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM,
                                        WI_IPPROTO_ICMPV6), 0);
}
END_TEST

/* =========================================================================
 * 2. bind and getsockname
 * ========================================================================= */

START_TEST(test_sock6_bind_and_getsockname_roundtrip)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 sin6;
    struct wolfIP_sockaddr_in6 got;
    socklen_t len = sizeof(got);
    ip6 expect;
    int fd;

    sock6_setup(&s);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);

    sock6_addr(&sin6, S6_TEST_GLOBAL, 5000);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd, (struct wolfIP_sockaddr *)&sin6,
                                      sizeof(sin6)), 0);

    memset(&got, 0, sizeof(got));
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, fd,
                                             (struct wolfIP_sockaddr *)&got,
                                             &len), 0);
    ck_assert_uint_eq(got.sin6_family, AF_INET6);
    ck_assert_uint_eq(ee16(got.sin6_port), 5000);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &expect), 0);
    ck_assert_int_eq(memcmp(&got.sin6_addr, expect.addr, 16), 0);
}
END_TEST

/* An address that is not configured on any interface cannot be bound, the
 * same rule the IPv4 path applies. */
START_TEST(test_sock6_bind_to_a_foreign_address_is_refused)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 sin6;
    int fd;

    sock6_setup(&s);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);
    sock6_addr(&sin6, S6_TEST_OTHER, 5000);
    ck_assert_int_lt(wolfIP_sock_bind(&s, fd, (struct wolfIP_sockaddr *)&sin6,
                                      sizeof(sin6)), 0);
}
END_TEST

/* The wildcard binds without choosing a family, so the socket is still
 * dual-stack afterwards and reports :: back. */
START_TEST(test_sock6_wildcard_bind_reports_the_unspecified_address)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 sin6;
    struct wolfIP_sockaddr_in6 got;
    socklen_t len = sizeof(got);
    ip6 reported;
    int fd;

    sock6_setup(&s);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);
    sock6_addr(&sin6, NULL, 5001);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd, (struct wolfIP_sockaddr *)&sin6,
                                      sizeof(sin6)), 0);

    memset(&got, 0, sizeof(got));
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, fd,
                                             (struct wolfIP_sockaddr *)&got,
                                             &len), 0);
    ck_assert_uint_eq(got.sin6_family, AF_INET6);
    ck_assert_uint_eq(ee16(got.sin6_port), 5001);
    memcpy(reported.addr, &got.sin6_addr, 16);
    /* Either the unspecified address or the v4-mapped form of the address
     * the wildcard resolved to; what must not happen is a bare IPv4
     * address leaking out of an AF_INET6 socket. */
    ck_assert(ip6_is_unspecified(&reported) || ip6_is_v4mapped(&reported));
}
END_TEST

/* A v4-mapped bind is IPv4 on the wire, and the address comes back in the
 * mapped form the application handed in rather than as a bare IPv4
 * address (RFC 3493 section 3.7). */
START_TEST(test_sock6_v4_mapped_bind_is_reported_as_mapped)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 sin6;
    struct wolfIP_sockaddr_in6 got;
    socklen_t len = sizeof(got);
    ip6 mapped;
    ip6 reported;
    int fd;

    sock6_setup(&s);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);

    ip6_set_v4mapped(&mapped, atoip4("192.168.10.2"));
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = ee16(5002);
    memcpy(&sin6.sin6_addr, mapped.addr, 16);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd, (struct wolfIP_sockaddr *)&sin6,
                                      sizeof(sin6)), 0);

    memset(&got, 0, sizeof(got));
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, fd,
                                             (struct wolfIP_sockaddr *)&got,
                                             &len), 0);
    ck_assert_uint_eq(got.sin6_family, AF_INET6);
    memcpy(reported.addr, &got.sin6_addr, 16);
    ck_assert_int_eq(ip6_is_v4mapped(&reported), 1);
    ck_assert_uint_eq(ip6_get_v4mapped(&reported), atoip4("192.168.10.2"));
}
END_TEST

/* An AF_INET socket must be entirely unaffected: it still reports a
 * sockaddr_in, not a sockaddr_in6. */
START_TEST(test_sock6_af_inet_socket_still_reports_sockaddr_in)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_sockaddr_in got;
    socklen_t len = sizeof(got);
    int fd;

    sock6_setup(&s);
    fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5003);
    sin.sin_addr.s_addr = ee32(atoip4("192.168.10.2"));
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd, (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), 0);

    memset(&got, 0, sizeof(got));
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, fd,
                                             (struct wolfIP_sockaddr *)&got,
                                             &len), 0);
    ck_assert_uint_eq(got.sin_family, AF_INET);
    ck_assert_uint_eq(ee16(got.sin_port), 5003);
    ck_assert_uint_eq(ee32(got.sin_addr.s_addr), atoip4("192.168.10.2"));
}
END_TEST

/* An AF_INET socket and an AF_INET6 socket bound to a real IPv6 address are
 * in different address spaces and may share a port. */
START_TEST(test_sock6_ipv4_and_ipv6_sockets_coexist_on_one_port)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_sockaddr_in6 sin6;
    int fd4;
    int fd6;

    sock6_setup(&s);
    fd4 = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    fd6 = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd4, 0);
    ck_assert_int_ge(fd6, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5004);
    sin.sin_addr.s_addr = ee32(atoip4("192.168.10.2"));
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd4, (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), 0);

    sock6_addr(&sin6, S6_TEST_GLOBAL, 5004);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd6, (struct wolfIP_sockaddr *)&sin6,
                                      sizeof(sin6)), 0);
}
END_TEST

/* Two IPv6 sockets on the same address and port do still collide. */
START_TEST(test_sock6_duplicate_ipv6_bind_is_refused)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 sin6;
    int a;
    int b;

    sock6_setup(&s);
    a = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    b = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(a, 0);
    ck_assert_int_ge(b, 0);

    sock6_addr(&sin6, S6_TEST_GLOBAL, 5005);
    ck_assert_int_eq(wolfIP_sock_bind(&s, a, (struct wolfIP_sockaddr *)&sin6,
                                      sizeof(sin6)), 0);
    ck_assert_int_lt(wolfIP_sock_bind(&s, b, (struct wolfIP_sockaddr *)&sin6,
                                      sizeof(sin6)), 0);
}
END_TEST

/* =========================================================================
 * 3. IPV6_V6ONLY
 * ========================================================================= */

/* setsockopt returns 0 for options it does not implement, so an option that
 * was merely accepted would be indistinguishable from one that works. This
 * checks it is genuinely stored and reported. */
START_TEST(test_sock6_v6only_is_stored_and_reported)
{
    struct wolfIP s;
    int fd;
    int on = 1;
    int value = -1;
    socklen_t len = sizeof(value);

    sock6_setup(&s);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);

    /* Off by default: a fresh AF_INET6 socket is dual-stack. */
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, fd, WOLFIP_SOL_IPV6,
                                            WOLFIP_IPV6_V6ONLY, &value, &len), 0);
    ck_assert_int_eq(value, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, fd, WOLFIP_SOL_IPV6,
                                            WOLFIP_IPV6_V6ONLY, &on,
                                            sizeof(on)), 0);
    value = -1;
    len = sizeof(value);
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, fd, WOLFIP_SOL_IPV6,
                                            WOLFIP_IPV6_V6ONLY, &value, &len), 0);
    ck_assert_int_eq(value, 1);
}
END_TEST

/* The option belongs to AF_INET6 sockets, and only before they are bound. */
START_TEST(test_sock6_v6only_is_refused_where_it_has_no_meaning)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 sin6;
    int fd4;
    int fd6;
    int on = 1;
    int value = 0;
    socklen_t len = sizeof(value);

    sock6_setup(&s);
    fd4 = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd4, 0);
    ck_assert_int_lt(wolfIP_sock_setsockopt(&s, fd4, WOLFIP_SOL_IPV6,
                                            WOLFIP_IPV6_V6ONLY, &on,
                                            sizeof(on)), 0);
    ck_assert_int_lt(wolfIP_sock_getsockopt(&s, fd4, WOLFIP_SOL_IPV6,
                                            WOLFIP_IPV6_V6ONLY, &value, &len), 0);

    /* After a bind the socket has already committed to an address, so
     * changing the option would contradict it. */
    fd6 = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd6, 0);
    sock6_addr(&sin6, S6_TEST_GLOBAL, 5006);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd6, (struct wolfIP_sockaddr *)&sin6,
                                      sizeof(sin6)), 0);
    ck_assert_int_lt(wolfIP_sock_setsockopt(&s, fd6, WOLFIP_SOL_IPV6,
                                            WOLFIP_IPV6_V6ONLY, &on,
                                            sizeof(on)), 0);
}
END_TEST

/* With the option set, a v4-mapped address is not an acceptable local
 * address: the socket has declared it speaks IPv6 only. */
START_TEST(test_sock6_v6only_socket_rejects_a_v4_mapped_bind)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 sin6;
    ip6 mapped;
    int fd;
    int on = 1;

    sock6_setup(&s);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, fd, WOLFIP_SOL_IPV6,
                                            WOLFIP_IPV6_V6ONLY, &on,
                                            sizeof(on)), 0);

    ip6_set_v4mapped(&mapped, atoip4("192.168.10.2"));
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = ee16(5007);
    memcpy(&sin6.sin6_addr, mapped.addr, 16);
    ck_assert_int_lt(wolfIP_sock_bind(&s, fd, (struct wolfIP_sockaddr *)&sin6,
                                      sizeof(sin6)), 0);

    /* A real IPv6 address is of course still fine. */
    sock6_addr(&sin6, S6_TEST_GLOBAL, 5007);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd, (struct wolfIP_sockaddr *)&sin6,
                                      sizeof(sin6)), 0);
}
END_TEST

#endif /* WOLFIP_IPV6 */

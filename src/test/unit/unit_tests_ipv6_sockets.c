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


/* =========================================================================
 * 4. UDP over IPv6
 * ========================================================================= */

#define S6_PEER "2001:db8:5::9"

/* Bring the interface's IPv6 address out of TENTATIVE so it can be used as
 * a source, and make the peer reachable without waiting for Neighbor
 * Discovery - address resolution is exercised separately. */
static void sock6_ready(struct wolfIP *s, uint64_t *now)
{
    const uint8_t peer_mac[6] = {0x02, 0xEE, 0x00, 0x00, 0x00, 0x01};
    struct wolfIP_ifaddr_slot *slot;
    ip6 peer;
    unsigned int i;

    for (i = 0; i < WOLFIP_IFADDR_MAX; i++) {
        slot = &s->ifaddr[i];
        if (slot->used && (slot->info.family == AF_INET6))
            slot->info.state = WOLFIP_IFADDR_PREFERRED;
    }
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    ck_assert_int_eq(wolfIP_nd6_neighbor_add(s, TEST_PRIMARY_IF, &peer,
                                             peer_mac), 0);
    *now += 100;
    wolfIP_poll(s, *now);
}

/* Deliver a UDP datagram over IPv6 to the stack, built the way a peer would
 * send it: real checksum, real header, through the ingress path. */
static void sock6_deliver_udp(struct wolfIP *s, const char *src_str,
                              const ip6 *dst, uint16_t sport, uint16_t dport,
                              const void *payload, uint16_t payload_len)
{
    uint8_t frame[LINK_MTU];
    struct wolfIP_udp6_datagram *udp = (struct wolfIP_udp6_datagram *)frame;
    struct wolfIP_ll_dev *ll = wolfIP_getdev_ex(s, TEST_PRIMARY_IF);
    union transport6_pseudo_header ph;
    uint16_t udp_len = (uint16_t)(UDP_HEADER_LEN + payload_len);
    ip6 src;

    ck_assert_ptr_nonnull(ll);
    ck_assert_int_eq(atoip6(src_str, &src), 0);
    memset(frame, 0, sizeof(frame));
    memcpy(udp->ip6.eth.dst, ll->mac, 6);
    memset(udp->ip6.eth.src, 0x22, 6);
    udp->ip6.eth.type = ee16(ETH_TYPE_IPV6);
    ip6_hdr_set_vtf(&udp->ip6, 0, 0);
    udp->ip6.payload_len = ee16(udp_len);
    udp->ip6.next_hdr = IP6_NEXTHDR_UDP;
    udp->ip6.hop_limit = 64;
    ip6_hdr_set_src(&udp->ip6, &src);
    ip6_hdr_set_dst(&udp->ip6, dst);
    udp->src_port = ee16(sport);
    udp->dst_port = ee16(dport);
    udp->len = ee16(udp_len);
    udp->csum = 0;
    if (payload_len > 0)
        memcpy(udp->data, payload, payload_len);
    transport6_pseudo_header_init(&ph, &src, dst, udp_len, IP6_NEXTHDR_UDP);
    udp->csum = ee16(transport6_checksum(&ph, &udp->src_port));
    if (udp->csum == 0)
        udp->csum = 0xFFFFu;
    wolfIP_recv_ex(s, TEST_PRIMARY_IF, frame,
                   (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) + udp_len);
}

START_TEST(test_sock6_udp_sendto_emits_an_ipv6_datagram)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 dst;
    struct wolfIP_udp6_datagram *sent;
    uint8_t staged[LINK_MTU + ETH_HEADER_LEN];
    uint64_t now = 0;
    ip6 got_src;
    ip6 got_dst;
    ip6 expect_dst;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);

    sock6_addr(&dst, S6_PEER, 7777);
    mock_link_capture_reset();
    ck_assert_int_eq(wolfIP_sock_sendto(&s, fd, "hello", 5, 0,
                                        (struct wolfIP_sockaddr *)&dst,
                                        sizeof(dst)), 5);
    now += 100;
    wolfIP_poll(&s, now);

    ck_assert_uint_eq(last_frame_sent_size,
                      (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN +
                                 UDP_HEADER_LEN + 5));
    memcpy(staged, last_frame_sent, last_frame_sent_size);
    sent = (struct wolfIP_udp6_datagram *)staged;
    ck_assert_uint_eq(ee16(sent->ip6.eth.type), ETH_TYPE_IPV6);
    ck_assert_uint_eq(ip6_hdr_version(&sent->ip6), 6);
    ck_assert_uint_eq(sent->ip6.next_hdr, IP6_NEXTHDR_UDP);
    ck_assert_uint_eq(ee16(sent->dst_port), 7777);
    ck_assert_uint_eq(ee16(sent->len), UDP_HEADER_LEN + 5);
    ck_assert_int_eq(memcmp(sent->data, "hello", 5), 0);

    ip6_hdr_get_src(&sent->ip6, &got_src);
    ip6_hdr_get_dst(&sent->ip6, &got_dst);
    ck_assert_int_eq(atoip6(S6_PEER, &expect_dst), 0);
    ck_assert_int_eq(ip6_cmp(&got_dst, &expect_dst), 0);
    /* Source selection must have picked one of our own addresses. */
    ck_assert_int_eq(ip6_is_unspecified(&got_src), 0);

    /* RFC 8200 section 8.1: a zero UDP checksum is not permitted over
     * IPv6, unlike IPv4 where it means "not computed". */
    ck_assert_uint_ne(sent->csum, 0);
}
END_TEST

START_TEST(test_sock6_udp_recvfrom_reports_an_ipv6_peer)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 bind_addr;
    struct wolfIP_sockaddr_in6 from;
    socklen_t fromlen = sizeof(from);
    uint8_t buf[32];
    uint64_t now = 0;
    ip6 local;
    ip6 expect;
    ip6 got;
    int fd;
    int rc;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);
    sock6_addr(&bind_addr, S6_TEST_GLOBAL, 7000);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd,
                                      (struct wolfIP_sockaddr *)&bind_addr,
                                      sizeof(bind_addr)), 0);

    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    sock6_deliver_udp(&s, S6_PEER, &local, 6000, 7000, "abcd", 4);

    rc = wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0,
                              (struct wolfIP_sockaddr *)&from, &fromlen);
    ck_assert_int_eq(rc, 4);
    ck_assert_int_eq(memcmp(buf, "abcd", 4), 0);
    ck_assert_uint_eq(from.sin6_family, AF_INET6);
    ck_assert_uint_eq(ee16(from.sin6_port), 6000);
    memcpy(got.addr, &from.sin6_addr, 16);
    ck_assert_int_eq(atoip6(S6_PEER, &expect), 0);
    ck_assert_int_eq(ip6_cmp(&got, &expect), 0);
}
END_TEST

/* A datagram addressed to a port nobody holds, or to an address that is not
 * ours, must not be delivered. */
START_TEST(test_sock6_udp_unmatched_datagram_is_not_delivered)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 bind_addr;
    uint8_t buf[32];
    uint64_t now = 0;
    ip6 local;
    ip6 elsewhere;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);
    sock6_addr(&bind_addr, S6_TEST_GLOBAL, 7001);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd,
                                      (struct wolfIP_sockaddr *)&bind_addr,
                                      sizeof(bind_addr)), 0);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    ck_assert_int_eq(atoip6(S6_TEST_OTHER, &elsewhere), 0);

    /* Right address, wrong port. */
    sock6_deliver_udp(&s, S6_PEER, &local, 6000, 7999, "x", 1);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0, NULL,
                                          NULL), -WOLFIP_EAGAIN);
    /* Right port, an address that is not ours. */
    sock6_deliver_udp(&s, S6_PEER, &elsewhere, 6000, 7001, "x", 1);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0, NULL,
                                          NULL), -WOLFIP_EAGAIN);
}
END_TEST

/* A wildcard bind takes datagrams addressed to any of our addresses, the
 * same rule the IPv4 path applies. */
START_TEST(test_sock6_udp_wildcard_bind_receives_any_local_address)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 bind_addr;
    uint8_t buf[32];
    uint64_t now = 0;
    ip6 local;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);
    sock6_addr(&bind_addr, NULL, 7002);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd,
                                      (struct wolfIP_sockaddr *)&bind_addr,
                                      sizeof(bind_addr)), 0);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    sock6_deliver_udp(&s, S6_PEER, &local, 6000, 7002, "wild", 4);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0, NULL,
                                          NULL), 4);
}
END_TEST

/* An AF_INET socket must never be handed an IPv6 datagram: it has no way to
 * report the peer to its application. */
START_TEST(test_sock6_udp_af_inet_socket_never_receives_ipv6)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[32];
    uint64_t now = 0;
    ip6 local;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7003);
    sin.sin_addr.s_addr = ee32(IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd, (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), 0);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    sock6_deliver_udp(&s, S6_PEER, &local, 6000, 7003, "no", 2);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0, NULL,
                                          NULL), -WOLFIP_EAGAIN);
}
END_TEST

/* A connected socket filters by peer; an unconnected one takes anything. */
START_TEST(test_sock6_udp_connected_socket_filters_by_peer)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 peer;
    uint8_t buf[32];
    uint64_t now = 0;
    ip6 local;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);
    sock6_addr(&peer, S6_PEER, 6000);
    ck_assert_int_eq(wolfIP_sock_connect(&s, fd,
                                         (struct wolfIP_sockaddr *)&peer,
                                         sizeof(peer)), 0);
    /* connect() picks the source and the ephemeral port at first send. */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, fd, "q", 1, 0, NULL, 0), 1);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);

    /* From the connected peer: delivered. */
    sock6_deliver_udp(&s, S6_PEER, &local, 6000,
                      s.udpsockets[SOCKET_UNMARK(fd)].src_port, "yes", 3);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0, NULL,
                                          NULL), 3);
    /* From somebody else: refused. */
    sock6_deliver_udp(&s, S6_TEST_OTHER, &local, 6000,
                      s.udpsockets[SOCKET_UNMARK(fd)].src_port, "no", 2);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0, NULL,
                                          NULL), -WOLFIP_EAGAIN);
}
END_TEST

/* IPv6 routers do not fragment and this stack does not fragment at the
 * source, so an oversized datagram is refused at sendto rather than
 * truncated on the way out. */
START_TEST(test_sock6_udp_oversize_datagram_is_refused)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 dst;
    static uint8_t big[LINK_MTU];
    uint64_t now = 0;
    uint32_t mtu;
    uint32_t max_payload;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);
    sock6_addr(&dst, S6_PEER, 7777);

    mtu = wolfIP_ip_mtu(&s, TEST_PRIMARY_IF);
    if (mtu < IP6_MIN_MTU)
        mtu = IP6_MIN_MTU;
    max_payload = mtu - IP6_HEADER_LEN - UDP_HEADER_LEN;
    ck_assert_uint_lt(max_payload, sizeof(big));

    memset(big, 0x5A, sizeof(big));
    /* Exactly at the limit still goes. */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, fd, big, max_payload, 0,
                                        (struct wolfIP_sockaddr *)&dst,
                                        sizeof(dst)), (int)max_payload);
    /* One byte more does not. */
    ck_assert_int_lt(wolfIP_sock_sendto(&s, fd, big, max_payload + 1, 0,
                                        (struct wolfIP_sockaddr *)&dst,
                                        sizeof(dst)), 0);
}
END_TEST

/* An unresolved neighbour holds the datagram rather than dropping it, and a
 * Neighbor Solicitation goes out for it. Once the advertisement arrives the
 * queued datagram is sent. */
START_TEST(test_sock6_udp_unresolved_neighbour_holds_the_datagram)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 dst;
    const uint8_t peer_mac[6] = {0x02, 0xEE, 0x00, 0x00, 0x00, 0x02};
    struct wolfIP_ifaddr_slot *slot;
    uint64_t now = 0;
    unsigned int i;
    ip6 peer;
    int fd;

    sock6_setup(&s);
    /* Deliberately no neighbour entry this time. */
    for (i = 0; i < WOLFIP_IFADDR_MAX; i++) {
        slot = &s.ifaddr[i];
        if (slot->used && (slot->info.family == AF_INET6))
            slot->info.state = WOLFIP_IFADDR_PREFERRED;
    }
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);
    sock6_addr(&dst, S6_PEER, 7777);
    mock_link_capture_reset();
    ck_assert_int_eq(wolfIP_sock_sendto(&s, fd, "held", 4, 0,
                                        (struct wolfIP_sockaddr *)&dst,
                                        sizeof(dst)), 4);
    now += 100;
    wolfIP_poll(&s, now);

    /* What went out is a solicitation, not the datagram. */
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(last_frame_sent[ETH_HEADER_LEN + IP6_HEADER_LEN],
                      ICMP6_NEIGHBOR_SOLICIT);

    /* Answer it, and the held datagram follows. */
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    ck_assert_int_eq(wolfIP_nd6_neighbor_add(&s, TEST_PRIMARY_IF, &peer,
                                             peer_mac), 0);
    mock_link_capture_reset();
    now += 100;
    wolfIP_poll(&s, now);
    ck_assert_uint_eq(last_frame_sent_size,
                      (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN +
                                 UDP_HEADER_LEN + 4));
    ck_assert_uint_eq(last_frame_sent[ETH_HEADER_LEN + IP6_HEADER_LEN +
                                      UDP_HEADER_LEN], 'h');
}
END_TEST

/* A datagram whose checksum does not verify is dropped. RFC 8200 s8.1 also
 * forbids the zero checksum that IPv4 allows, so that is refused too. */
START_TEST(test_sock6_udp_bad_checksum_is_dropped)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 bind_addr;
    uint8_t frame[LINK_MTU];
    struct wolfIP_udp6_datagram *udp = (struct wolfIP_udp6_datagram *)frame;
    struct wolfIP_ll_dev *ll;
    uint8_t buf[32];
    uint64_t now = 0;
    ip6 local;
    ip6 src;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(fd, 0);
    sock6_addr(&bind_addr, S6_TEST_GLOBAL, 7004);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd,
                                      (struct wolfIP_sockaddr *)&bind_addr,
                                      sizeof(bind_addr)), 0);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    ck_assert_int_eq(atoip6(S6_PEER, &src), 0);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    /* Deliberately wrong checksum. */
    memset(frame, 0, sizeof(frame));
    memcpy(udp->ip6.eth.dst, ll->mac, 6);
    udp->ip6.eth.type = ee16(ETH_TYPE_IPV6);
    ip6_hdr_set_vtf(&udp->ip6, 0, 0);
    udp->ip6.payload_len = ee16(UDP_HEADER_LEN + 2);
    udp->ip6.next_hdr = IP6_NEXTHDR_UDP;
    udp->ip6.hop_limit = 64;
    ip6_hdr_set_src(&udp->ip6, &src);
    ip6_hdr_set_dst(&udp->ip6, &local);
    udp->src_port = ee16(6000);
    udp->dst_port = ee16(7004);
    udp->len = ee16(UDP_HEADER_LEN + 2);
    udp->csum = 0xDEAD;
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame,
                   (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN +
                              UDP_HEADER_LEN + 2));
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0, NULL,
                                          NULL), -WOLFIP_EAGAIN);

    /* And a zero checksum, which IPv4 would have accepted as "not
     * computed" but IPv6 does not permit at all. */
    udp->csum = 0;
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame,
                   (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN +
                              UDP_HEADER_LEN + 2));
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0, NULL,
                                          NULL), -WOLFIP_EAGAIN);
}
END_TEST

#endif /* WOLFIP_IPV6 */

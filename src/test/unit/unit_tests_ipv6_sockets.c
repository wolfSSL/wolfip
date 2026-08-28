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


/* =========================================================================
 * 5. TCP over IPv6
 * ========================================================================= */

/* The segment the stack last transmitted, re-based so the IPv6 accessors
 * line up. Returns NULL when nothing was sent. */
static struct wolfIP_tcp6_seg *sock6_last_tcp(uint8_t *staging)
{
    if (last_frame_sent_size < (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN +
                                          TCP_HEADER_LEN))
        return NULL;
    memcpy(staging, last_frame_sent, last_frame_sent_size);
    return (struct wolfIP_tcp6_seg *)staging;
}

/* Inject a TCP segment over IPv6, built the way a peer would send it. */
static void sock6_deliver_tcp(struct wolfIP *s, const ip6 *src, const ip6 *dst,
                              uint16_t sport, uint16_t dport, uint32_t seq,
                              uint32_t ack, uint8_t flags,
                              const void *payload, uint16_t payload_len)
{
    uint8_t frame[LINK_MTU];
    struct wolfIP_tcp6_seg *tcp = (struct wolfIP_tcp6_seg *)frame;
    struct wolfIP_ll_dev *ll = wolfIP_getdev_ex(s, TEST_PRIMARY_IF);
    union transport6_pseudo_header ph;
    uint16_t seg_len = (uint16_t)(TCP_HEADER_LEN + payload_len);

    ck_assert_ptr_nonnull(ll);
    memset(frame, 0, sizeof(frame));
    memcpy(tcp->ip6.eth.dst, ll->mac, 6);
    memset(tcp->ip6.eth.src, 0x22, 6);
    tcp->ip6.eth.type = ee16(ETH_TYPE_IPV6);
    ip6_hdr_set_vtf(&tcp->ip6, 0, 0);
    tcp->ip6.payload_len = ee16(seg_len);
    tcp->ip6.next_hdr = IP6_NEXTHDR_TCP;
    tcp->ip6.hop_limit = 64;
    ip6_hdr_set_src(&tcp->ip6, src);
    ip6_hdr_set_dst(&tcp->ip6, dst);
    tcp->src_port = ee16(sport);
    tcp->dst_port = ee16(dport);
    tcp->seq = ee32(seq);
    tcp->ack = ee32(ack);
    tcp->hlen = (uint8_t)(TCP_HEADER_LEN << 2);
    tcp->flags = flags;
    tcp->win = ee16(8192);
    tcp->csum = 0;
    tcp->urg = 0;
    if (payload_len > 0)
        memcpy(tcp->data, payload, payload_len);
    transport6_pseudo_header_init(&ph, src, dst, seg_len, IP6_NEXTHDR_TCP);
    tcp->csum = ee16(transport6_checksum(&ph, &tcp->src_port));
    wolfIP_recv_ex(s, TEST_PRIMARY_IF, frame,
                   (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) + seg_len);
}

/* A full active open: connect emits a SYN over IPv6, the SYN-ACK is
 * answered, and the socket reaches ESTABLISHED. */
START_TEST(test_sock6_tcp_connect_completes_the_handshake)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 dst;
    struct wolfIP_tcp6_seg *seg;
    uint8_t staging[LINK_MTU];
    uint64_t now = 0;
    ip6 peer;
    ip6 local;
    ip6 got;
    uint32_t peer_seq = 0x11223344;
    uint32_t our_isn;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(fd, 0);
    sock6_addr(&dst, S6_PEER, 80);

    mock_link_capture_reset();
    /* connect reports "in progress", as the IPv4 arm does. */
    ck_assert_int_eq(wolfIP_sock_connect(&s, fd,
                                         (struct wolfIP_sockaddr *)&dst,
                                         sizeof(dst)), -WOLFIP_EAGAIN);
    now += 100;
    wolfIP_poll(&s, now);

    seg = sock6_last_tcp(staging);
    ck_assert_ptr_nonnull(seg);
    ck_assert_uint_eq(ee16(seg->ip6.eth.type), ETH_TYPE_IPV6);
    ck_assert_uint_eq(seg->ip6.next_hdr, IP6_NEXTHDR_TCP);
    ck_assert_uint_eq(seg->flags & TCP_FLAG_SYN, TCP_FLAG_SYN);
    ck_assert_uint_eq(seg->flags & TCP_FLAG_ACK, 0);
    ck_assert_uint_eq(ee16(seg->dst_port), 80);
    ip6_hdr_get_dst(&seg->ip6, &got);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    ck_assert_int_eq(ip6_cmp(&got, &peer), 0);
    our_isn = ee32(seg->seq);

    /* Answer it. */
    ip6_hdr_get_src(&seg->ip6, &local);
    sock6_deliver_tcp(&s, &peer, &local, 80,
                      s.tcpsockets[SOCKET_UNMARK(fd)].src_port,
                      peer_seq, our_isn + 1,
                      TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);
    now += 100;
    wolfIP_poll(&s, now);

    ck_assert_int_eq(s.tcpsockets[SOCKET_UNMARK(fd)].sock.tcp.state,
                     TCP_ESTABLISHED);
    ck_assert_int_eq(wolfIP_sock_connect(&s, fd,
                                         (struct wolfIP_sockaddr *)&dst,
                                         sizeof(dst)), 0);
}
END_TEST

/* Data in both directions over an established IPv6 connection. */
START_TEST(test_sock6_tcp_carries_data_both_ways)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 dst;
    struct wolfIP_tcp6_seg *seg;
    uint8_t staging[LINK_MTU];
    uint8_t buf[64];
    uint64_t now = 0;
    ip6 peer;
    ip6 local;
    uint32_t peer_seq = 0x55667788;
    uint32_t our_isn;
    uint16_t sport;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(fd, 0);
    sock6_addr(&dst, S6_PEER, 80);
    mock_link_capture_reset();
    (void)wolfIP_sock_connect(&s, fd, (struct wolfIP_sockaddr *)&dst,
                              sizeof(dst));
    now += 100;
    wolfIP_poll(&s, now);
    seg = sock6_last_tcp(staging);
    ck_assert_ptr_nonnull(seg);
    our_isn = ee32(seg->seq);
    ip6_hdr_get_src(&seg->ip6, &local);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    sport = s.tcpsockets[SOCKET_UNMARK(fd)].src_port;
    sock6_deliver_tcp(&s, &peer, &local, 80, sport, peer_seq, our_isn + 1,
                      TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);
    now += 100;
    wolfIP_poll(&s, now);
    ck_assert_int_eq(s.tcpsockets[SOCKET_UNMARK(fd)].sock.tcp.state,
                     TCP_ESTABLISHED);

    /* Outbound. */
    mock_link_capture_reset();
    ck_assert_int_eq(wolfIP_sock_send(&s, fd, "ping6", 5, 0), 5);
    now += 100;
    wolfIP_poll(&s, now);
    seg = sock6_last_tcp(staging);
    ck_assert_ptr_nonnull(seg);
    ck_assert_uint_eq(seg->ip6.next_hdr, IP6_NEXTHDR_TCP);
    ck_assert_uint_eq(last_frame_sent_size,
                      (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN +
                                 TCP_HEADER_LEN + 5));
    ck_assert_int_eq(memcmp(seg->data, "ping6", 5), 0);

    /* Inbound. */
    sock6_deliver_tcp(&s, &peer, &local, 80, sport, peer_seq + 1,
                      our_isn + 1 + 5, TCP_FLAG_ACK, "pong6", 5);
    now += 100;
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_sock_recv(&s, fd, buf, sizeof(buf), 0), 5);
    ck_assert_int_eq(memcmp(buf, "pong6", 5), 0);
}
END_TEST

/* A listening AF_INET6 socket accepts an IPv6 connection and reports the
 * peer as a sockaddr_in6. */
START_TEST(test_sock6_tcp_listener_accepts_an_ipv6_connection)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 bind_addr;
    struct wolfIP_sockaddr_in6 from;
    socklen_t fromlen = sizeof(from);
    struct wolfIP_tcp6_seg *seg;
    uint8_t staging[LINK_MTU];
    uint64_t now = 0;
    ip6 peer;
    ip6 local;
    ip6 got;
    int listen_fd;
    int conn_fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    listen_fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(listen_fd, 0);
    sock6_addr(&bind_addr, S6_TEST_GLOBAL, 8080);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_fd,
                                      (struct wolfIP_sockaddr *)&bind_addr,
                                      sizeof(bind_addr)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_fd, 1), 0);

    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    mock_link_capture_reset();
    sock6_deliver_tcp(&s, &peer, &local, 40000, 8080, 0x99aabbcc, 0,
                      TCP_FLAG_SYN, NULL, 0);
    now += 100;
    wolfIP_poll(&s, now);

    conn_fd = wolfIP_sock_accept(&s, listen_fd,
                                 (struct wolfIP_sockaddr *)&from, &fromlen);
    ck_assert_int_ge(conn_fd, 0);
    ck_assert_uint_eq(from.sin6_family, AF_INET6);
    ck_assert_uint_eq(ee16(from.sin6_port), 40000);
    memcpy(got.addr, &from.sin6_addr, 16);
    ck_assert_int_eq(ip6_cmp(&got, &peer), 0);

    /* The SYN-ACK goes out over IPv6, from the address that was addressed. */
    now += 100;
    wolfIP_poll(&s, now);
    seg = sock6_last_tcp(staging);
    ck_assert_ptr_nonnull(seg);
    ck_assert_uint_eq(seg->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK),
                      TCP_FLAG_SYN | TCP_FLAG_ACK);
    ip6_hdr_get_src(&seg->ip6, &got);
    ck_assert_int_eq(ip6_cmp(&got, &local), 0);
}
END_TEST

/* The IPv6 header is 20 bytes larger, so the MSS derived from the same link
 * MTU must be 20 bytes smaller. */
START_TEST(test_sock6_tcp_mss_accounts_for_the_40_byte_header)
{
    struct wolfIP s;
    struct tsocket *t4;
    struct tsocket *t6;
    uint64_t now = 0;
    int fd4;
    int fd6;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    fd4 = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    fd6 = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(fd4, 0);
    ck_assert_int_ge(fd6, 0);
    t4 = &s.tcpsockets[SOCKET_UNMARK(fd4)];
    t6 = &s.tcpsockets[SOCKET_UNMARK(fd6)];
    t4->if_idx = TEST_PRIMARY_IF;
    t6->if_idx = TEST_PRIMARY_IF;
    /* peer_is_v6 is what selects the header size, and it is set once the
     * destination is known. */
    t6->peer_is_v6 = 1;

    ck_assert_uint_gt(wolfIP_socket_tcp_mss(t4), 0);
    ck_assert_uint_eq(wolfIP_socket_tcp_mss(t4) - wolfIP_socket_tcp_mss(t6),
                      IP6_HEADER_LEN - IP_HEADER_LEN);
}
END_TEST

/* A segment to a port nobody holds is answered with a reset, so the peer
 * learns at once rather than retrying. */
START_TEST(test_sock6_tcp_segment_to_a_dead_port_is_reset)
{
    struct wolfIP s;
    struct wolfIP_tcp6_seg *seg;
    uint8_t staging[LINK_MTU];
    uint64_t now = 0;
    ip6 peer;
    ip6 local;
    ip6 got;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);

    mock_link_capture_reset();
    sock6_deliver_tcp(&s, &peer, &local, 40001, 9999, 0x1000, 0,
                      TCP_FLAG_SYN, NULL, 0);
    seg = sock6_last_tcp(staging);
    ck_assert_ptr_nonnull(seg);
    ck_assert_uint_eq(seg->flags & TCP_FLAG_RST, TCP_FLAG_RST);
    ck_assert_uint_eq(ee16(seg->dst_port), 40001);
    /* Source and destination swapped: the reply comes from the address
     * that was addressed. */
    ip6_hdr_get_src(&seg->ip6, &got);
    ck_assert_int_eq(ip6_cmp(&got, &local), 0);
    ip6_hdr_get_dst(&seg->ip6, &got);
    ck_assert_int_eq(ip6_cmp(&got, &peer), 0);

    /* A reset is never answered with a reset. */
    mock_link_capture_reset();
    sock6_deliver_tcp(&s, &peer, &local, 40001, 9999, 0x1000, 0,
                      TCP_FLAG_RST, NULL, 0);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

/* A segment with a broken checksum is dropped rather than answered. */
START_TEST(test_sock6_tcp_bad_checksum_is_dropped)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    struct wolfIP_tcp6_seg *tcp = (struct wolfIP_tcp6_seg *)frame;
    struct wolfIP_ll_dev *ll;
    uint64_t now = 0;
    ip6 peer;
    ip6 local;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    memset(frame, 0, sizeof(frame));
    memcpy(tcp->ip6.eth.dst, ll->mac, 6);
    tcp->ip6.eth.type = ee16(ETH_TYPE_IPV6);
    ip6_hdr_set_vtf(&tcp->ip6, 0, 0);
    tcp->ip6.payload_len = ee16(TCP_HEADER_LEN);
    tcp->ip6.next_hdr = IP6_NEXTHDR_TCP;
    tcp->ip6.hop_limit = 64;
    ip6_hdr_set_src(&tcp->ip6, &peer);
    ip6_hdr_set_dst(&tcp->ip6, &local);
    tcp->src_port = ee16(40002);
    tcp->dst_port = ee16(9999);
    tcp->hlen = (uint8_t)(TCP_HEADER_LEN << 2);
    tcp->flags = TCP_FLAG_SYN;
    tcp->csum = 0xBEEF;

    mock_link_capture_reset();
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame,
                   (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN +
                              TCP_HEADER_LEN));
    /* No reset: a segment that fails the checksum was never received. */
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

/* An AF_INET listener must never accept an IPv6 SYN. */
START_TEST(test_sock6_tcp_af_inet_listener_ignores_ipv6)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    uint64_t now = 0;
    ip6 peer;
    ip6 local;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(fd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(8081);
    sin.sin_addr.s_addr = ee32(IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd, (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, fd, 1), 0);

    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    sock6_deliver_tcp(&s, &peer, &local, 40003, 8081, 0x2000, 0,
                      TCP_FLAG_SYN, NULL, 0);
    now += 100;
    wolfIP_poll(&s, now);
    /* Not accepted: the listener is still in LISTEN. */
    ck_assert_int_eq(s.tcpsockets[SOCKET_UNMARK(fd)].sock.tcp.state,
                     TCP_LISTEN);
}
END_TEST


/* =========================================================================
 * 6. ICMPv6: error messages (RFC 4443) and sockets
 * ========================================================================= */

/* Deliver an ICMPv6 message of a given type and code, with a correct
 * checksum, through the real ingress path. */
static void sock6_deliver_icmp6_body(struct wolfIP *s, const ip6 *src,
                                     const ip6 *dst, const uint8_t *body,
                                     uint16_t body_len)
{
    uint8_t frame[LINK_MTU];
    struct wolfIP_icmp6_packet *icmp = (struct wolfIP_icmp6_packet *)frame;
    struct wolfIP_ll_dev *ll = wolfIP_getdev_ex(s, TEST_PRIMARY_IF);
    union transport6_pseudo_header ph;

    ck_assert_ptr_nonnull(ll);
    memset(frame, 0, sizeof(frame));
    memcpy(icmp->ip6.eth.dst, ll->mac, 6);
    memset(icmp->ip6.eth.src, 0x22, 6);
    icmp->ip6.eth.type = ee16(ETH_TYPE_IPV6);
    ip6_hdr_set_vtf(&icmp->ip6, 0, 0);
    icmp->ip6.payload_len = ee16(body_len);
    icmp->ip6.next_hdr = IP6_NEXTHDR_ICMPV6;
    icmp->ip6.hop_limit = 64;
    ip6_hdr_set_src(&icmp->ip6, src);
    ip6_hdr_set_dst(&icmp->ip6, dst);
    memcpy(&icmp->type, body, body_len);
    icmp->csum = 0;
    transport6_pseudo_header_init(&ph, src, dst, body_len,
                                  IP6_NEXTHDR_ICMPV6);
    icmp->csum = ee16(transport6_checksum(&ph, &icmp->type));
    wolfIP_recv_ex(s, TEST_PRIMARY_IF, frame,
                   (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) + body_len);
}

/* A bare ICMPv6 message: type, code and an empty type-specific word. */
static void sock6_deliver_icmp6_msg(struct wolfIP *s, const ip6 *src,
                                    const ip6 *dst, uint8_t type, uint8_t code)
{
    uint8_t body[16];

    memset(body, 0, sizeof(body));
    body[0] = type;
    body[1] = code;
    sock6_deliver_icmp6_body(s, src, dst, body, sizeof(body));
}

/* An Echo Request or Reply with a chosen identifier and sequence. */
static void sock6_deliver_icmp6_echo(struct wolfIP *s, const ip6 *src,
                                     const ip6 *dst, uint8_t type,
                                     uint16_t id, uint16_t seq)
{
    uint8_t body[12];

    memset(body, 0, sizeof(body));
    body[0] = type;
    body[4] = (uint8_t)(id >> 8);
    body[5] = (uint8_t)(id & 0xFF);
    body[6] = (uint8_t)(seq >> 8);
    body[7] = (uint8_t)(seq & 0xFF);
    sock6_deliver_icmp6_body(s, src, dst, body, sizeof(body));
}

/* Deliver an arbitrary IPv6 packet with a chosen next header, for driving
 * the error paths. Returns the frame length used. */
static uint32_t sock6_deliver_raw6(struct wolfIP *s, const ip6 *src,
                                   const ip6 *dst, uint8_t next_hdr,
                                   const void *payload, uint16_t payload_len)
{
    uint8_t frame[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)frame;
    struct wolfIP_ll_dev *ll = wolfIP_getdev_ex(s, TEST_PRIMARY_IF);
    uint32_t frame_len;

    ck_assert_ptr_nonnull(ll);
    memset(frame, 0, sizeof(frame));
    if (ip6_is_multicast(dst))
        ip6_mcast_to_eth(dst, pkt->eth.dst);
    else
        memcpy(pkt->eth.dst, ll->mac, 6);
    memset(pkt->eth.src, 0x22, 6);
    pkt->eth.type = ee16(ETH_TYPE_IPV6);
    ip6_hdr_set_vtf(pkt, 0, 0);
    pkt->payload_len = ee16(payload_len);
    pkt->next_hdr = next_hdr;
    pkt->hop_limit = 64;
    ip6_hdr_set_src(pkt, src);
    ip6_hdr_set_dst(pkt, dst);
    if (payload_len > 0)
        memcpy(pkt->data, payload, payload_len);
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) + payload_len;
    wolfIP_recv_ex(s, TEST_PRIMARY_IF, frame, frame_len);
    return frame_len;
}

/* The error the stack last emitted, restaged so the accessors line up. */
static struct wolfIP_icmp6_packet *sock6_last_icmp6(uint8_t *staging)
{
    if (last_frame_sent_size < (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN + 4))
        return NULL;
    memcpy(staging, last_frame_sent, last_frame_sent_size);
    return (struct wolfIP_icmp6_packet *)staging;
}

/* A datagram to a port nobody holds draws Destination Unreachable code 4,
 * which is the error UDP actually needs (RFC 4443 section 3.1). */
START_TEST(test_icmp6_udp_port_unreachable)
{
    struct wolfIP s;
    struct wolfIP_icmp6_packet *err;
    uint8_t staging[LINK_MTU];
    uint64_t now = 0;
    ip6 local;
    ip6 peer;
    ip6 got;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);

    mock_link_capture_reset();
    sock6_deliver_udp(&s, S6_PEER, &local, 6000, 7100, "x", 1);

    err = sock6_last_icmp6(staging);
    ck_assert_ptr_nonnull(err);
    ck_assert_uint_eq(err->ip6.next_hdr, IP6_NEXTHDR_ICMPV6);
    ck_assert_uint_eq(err->type, ICMP6_DEST_UNREACH);
    ck_assert_uint_eq(err->code, ICMP6_DST_PORT_UNREACH);
    /* The four type-specific octets are unused and must be zero. */
    ck_assert_uint_eq(err->data[0], 0);
    ck_assert_uint_eq(err->data[1], 0);
    ck_assert_uint_eq(err->data[2], 0);
    ck_assert_uint_eq(err->data[3], 0);
    /* Sourced from the address that was addressed, sent to the sender. */
    ip6_hdr_get_src(&err->ip6, &got);
    ck_assert_int_eq(ip6_cmp(&got, &local), 0);
    ip6_hdr_get_dst(&err->ip6, &got);
    ck_assert_int_eq(ip6_cmp(&got, &peer), 0);
    /* The offending datagram is quoted after the 8-byte ICMPv6 header. */
    ck_assert_uint_eq(err->data[4] >> 4, 6);
}
END_TEST

/* An unrecognised Next Header draws Parameter Problem code 1, with the
 * pointer at the Next Header field - octet 6 of the IPv6 header (RFC 4443
 * section 3.4). */
START_TEST(test_icmp6_parameter_problem_points_at_the_bad_octet)
{
    struct wolfIP s;
    struct wolfIP_icmp6_packet *err;
    uint8_t staging[LINK_MTU];
    uint8_t body[8];
    uint64_t now = 0;
    uint32_t pointer;
    ip6 local;
    ip6 peer;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);

    memset(body, 0xAB, sizeof(body));
    mock_link_capture_reset();
    /* 253 is reserved for experimentation (RFC 3692) and is not a protocol
     * this stack knows. */
    (void)sock6_deliver_raw6(&s, &peer, &local, 253, body, sizeof(body));

    err = sock6_last_icmp6(staging);
    ck_assert_ptr_nonnull(err);
    ck_assert_uint_eq(err->type, ICMP6_PARAM_PROBLEM);
    ck_assert_uint_eq(err->code, ICMP6_PARAM_NEXTHDR);
    pointer = ((uint32_t)err->data[0] << 24) | ((uint32_t)err->data[1] << 16) |
              ((uint32_t)err->data[2] << 8) | err->data[3];
    ck_assert_uint_eq(pointer, 6);
}
END_TEST

/* RFC 4443 section 2.4 (e.1): never in response to another error message,
 * or two nodes sustain the exchange forever. */
START_TEST(test_icmp6_error_is_not_sent_in_response_to_an_error)
{
    struct wolfIP s;
    uint8_t body[16];
    uint64_t now = 0;
    ip6 local;
    ip6 peer;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);

    /* An ICMPv6 error carrying an unroutable inner packet. Delivered by
     * hand rather than through icmp6_input(), because what is being pinned
     * down is the generator's own rule. */
    memset(body, 0, sizeof(body));
    body[0] = ICMP6_DEST_UNREACH;
    body[1] = ICMP6_DST_NO_ROUTE;
    mock_link_capture_reset();
    {
        uint8_t frame[LINK_MTU];
        struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)frame;

        memset(frame, 0, sizeof(frame));
        ip6_hdr_set_vtf(pkt, 0, 0);
        pkt->payload_len = ee16(sizeof(body));
        pkt->next_hdr = IP6_NEXTHDR_ICMPV6;
        pkt->hop_limit = 64;
        ip6_hdr_set_src(pkt, &peer);
        ip6_hdr_set_dst(pkt, &local);
        memcpy(pkt->data, body, sizeof(body));
        icmp6_send_error(&s, TEST_PRIMARY_IF, pkt,
                         (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN +
                                    sizeof(body)),
                         ICMP6_DEST_UNREACH, ICMP6_DST_PORT_UNREACH, 0);
    }
    ck_assert_uint_eq(last_frame_sent_size, 0);

    /* An informational ICMPv6 message is not an error, so it may provoke
     * one - otherwise nothing addressed by ping could ever be reported. */
    {
        uint8_t frame[LINK_MTU];
        struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)frame;

        memset(frame, 0, sizeof(frame));
        ip6_hdr_set_vtf(pkt, 0, 0);
        pkt->payload_len = ee16(sizeof(body));
        pkt->next_hdr = IP6_NEXTHDR_ICMPV6;
        pkt->hop_limit = 64;
        ip6_hdr_set_src(pkt, &peer);
        ip6_hdr_set_dst(pkt, &local);
        pkt->data[0] = ICMP6_ECHO_REQUEST;
        mock_link_capture_reset();
        icmp6_send_error(&s, TEST_PRIMARY_IF, pkt,
                         (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN +
                                    sizeof(body)),
                         ICMP6_DEST_UNREACH, ICMP6_DST_ADDR_UNREACH, 0);
    }
    ck_assert_uint_gt(last_frame_sent_size, 0);
}
END_TEST

/* RFC 4443 section 2.4 (e.2)/(e.3): no error for a multicast destination,
 * except Packet Too Big and Parameter Problem code 2. This is the rule that
 * stops multicast amplification. And (e.5): no error to a source that does
 * not name a single node. */
START_TEST(test_icmp6_error_suppression_rules)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)frame;
    uint64_t now = 0;
    uint32_t flen = (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN + 8);
    ip6 local;
    ip6 peer;
    ip6 group;
    ip6 unspec;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    ip6_set_all_nodes(&group);
    ip6_set_unspecified(&unspec);

    memset(frame, 0, sizeof(frame));
    ip6_hdr_set_vtf(pkt, 0, 0);
    pkt->payload_len = ee16(8);
    pkt->next_hdr = IP6_NEXTHDR_UDP;
    pkt->hop_limit = 64;

    /* Multicast destination: suppressed. */
    ip6_hdr_set_src(pkt, &peer);
    ip6_hdr_set_dst(pkt, &group);
    mock_link_capture_reset();
    icmp6_send_error(&s, TEST_PRIMARY_IF, pkt, flen, ICMP6_DEST_UNREACH,
                     ICMP6_DST_PORT_UNREACH, 0);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    /* ...but Packet Too Big is allowed, or multicast path MTU discovery
     * could not work. */
    mock_link_capture_reset();
    icmp6_send_error(&s, TEST_PRIMARY_IF, pkt, flen, ICMP6_PACKET_TOO_BIG, 0,
                     1280);
    ck_assert_uint_gt(last_frame_sent_size, 0);

    /* ...and so is Parameter Problem code 2, which reports an option the
     * sender has to hear about. */
    mock_link_capture_reset();
    icmp6_send_error(&s, TEST_PRIMARY_IF, pkt, flen, ICMP6_PARAM_PROBLEM,
                     ICMP6_PARAM_OPTION, 40);
    ck_assert_uint_gt(last_frame_sent_size, 0);

    /* Parameter Problem code 1 to a multicast destination is not. */
    mock_link_capture_reset();
    icmp6_send_error(&s, TEST_PRIMARY_IF, pkt, flen, ICMP6_PARAM_PROBLEM,
                     ICMP6_PARAM_NEXTHDR, 6);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    /* A multicast source names no single node, so there is nobody to tell. */
    ip6_hdr_set_src(pkt, &group);
    ip6_hdr_set_dst(pkt, &local);
    mock_link_capture_reset();
    icmp6_send_error(&s, TEST_PRIMARY_IF, pkt, flen, ICMP6_DEST_UNREACH,
                     ICMP6_DST_PORT_UNREACH, 0);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    /* Neither does the unspecified address. */
    ip6_hdr_set_src(pkt, &unspec);
    mock_link_capture_reset();
    icmp6_send_error(&s, TEST_PRIMARY_IF, pkt, flen, ICMP6_DEST_UNREACH,
                     ICMP6_DST_PORT_UNREACH, 0);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

/* RFC 4443 section 2.4 (c): as much of the offending packet as fits without
 * the whole message exceeding the minimum IPv6 MTU. Unlike ICMPv4's fixed 8
 * bytes, this is deliberately as much as possible. */
START_TEST(test_icmp6_error_quotes_as_much_as_fits_in_min_mtu)
{
    struct wolfIP s;
    struct wolfIP_icmp6_packet *err;
    static uint8_t staging[LINK_MTU];
    static uint8_t big[LINK_MTU];
    uint8_t frame[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)frame;
    uint64_t now = 0;
    uint16_t body_len = 1200;
    uint32_t flen;
    ip6 local;
    ip6 peer;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);

    memset(big, 0x7E, sizeof(big));
    memset(frame, 0, sizeof(frame));
    ip6_hdr_set_vtf(pkt, 0, 0);
    pkt->payload_len = ee16(body_len);
    pkt->next_hdr = IP6_NEXTHDR_UDP;
    pkt->hop_limit = 64;
    ip6_hdr_set_src(pkt, &peer);
    ip6_hdr_set_dst(pkt, &local);
    memcpy(pkt->data, big, body_len);
    flen = (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) + body_len;

    mock_link_capture_reset();
    icmp6_send_error(&s, TEST_PRIMARY_IF, pkt, flen, ICMP6_DEST_UNREACH,
                     ICMP6_DST_PORT_UNREACH, 0);
    err = sock6_last_icmp6(staging);
    ck_assert_ptr_nonnull(err);

    /* The whole datagram, our own IPv6 header included, is capped at 1280. */
    ck_assert_uint_le(last_frame_sent_size - ETH_HEADER_LEN, IP6_MIN_MTU);
    /* And it is the cap that bound it, not the offending packet: the
     * quotation had more to give. */
    ck_assert_uint_eq(last_frame_sent_size - ETH_HEADER_LEN, IP6_MIN_MTU);
    ck_assert_uint_eq(ee16(err->ip6.payload_len),
                      IP6_MIN_MTU - IP6_HEADER_LEN);

    /* A short offending packet is quoted whole, with no padding. */
    pkt->payload_len = ee16(8);
    flen = (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN + 8);
    mock_link_capture_reset();
    icmp6_send_error(&s, TEST_PRIMARY_IF, pkt, flen, ICMP6_DEST_UNREACH,
                     ICMP6_DST_PORT_UNREACH, 0);
    err = sock6_last_icmp6(staging);
    ck_assert_ptr_nonnull(err);
    ck_assert_uint_eq(ee16(err->ip6.payload_len),
                      ICMP6_ECHO_MIN_LEN + IP6_HEADER_LEN + 8);
}
END_TEST

/* Packet Too Big carries the MTU in the type-specific word - the only path
 * MTU signal IPv6 has, since routers never fragment (RFC 4443 s3.2). Time
 * Exceeded carries a zero one (RFC 4443 s3.3). Both are generated by a
 * router; this stack does not forward IPv6 yet, so what is pinned here is
 * the message itself. */
START_TEST(test_icmp6_packet_too_big_and_time_exceeded_wire_format)
{
    struct wolfIP s;
    struct wolfIP_icmp6_packet *err;
    uint8_t staging[LINK_MTU];
    uint8_t frame[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)frame;
    uint64_t now = 0;
    uint32_t flen = (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN + 8);
    uint32_t word;
    ip6 local;
    ip6 peer;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    memset(frame, 0, sizeof(frame));
    ip6_hdr_set_vtf(pkt, 0, 0);
    pkt->payload_len = ee16(8);
    pkt->next_hdr = IP6_NEXTHDR_UDP;
    pkt->hop_limit = 64;
    ip6_hdr_set_src(pkt, &peer);
    ip6_hdr_set_dst(pkt, &local);

    mock_link_capture_reset();
    icmp6_send_error(&s, TEST_PRIMARY_IF, pkt, flen, ICMP6_PACKET_TOO_BIG, 0,
                     IP6_MIN_MTU);
    err = sock6_last_icmp6(staging);
    ck_assert_ptr_nonnull(err);
    ck_assert_uint_eq(err->type, ICMP6_PACKET_TOO_BIG);
    ck_assert_uint_eq(err->code, 0);
    word = ((uint32_t)err->data[0] << 24) | ((uint32_t)err->data[1] << 16) |
           ((uint32_t)err->data[2] << 8) | err->data[3];
    ck_assert_uint_eq(word, IP6_MIN_MTU);

    mock_link_capture_reset();
    icmp6_send_error(&s, TEST_PRIMARY_IF, pkt, flen, ICMP6_TIME_EXCEEDED,
                     ICMP6_TIME_HOP_LIMIT, 0);
    err = sock6_last_icmp6(staging);
    ck_assert_ptr_nonnull(err);
    ck_assert_uint_eq(err->type, ICMP6_TIME_EXCEEDED);
    ck_assert_uint_eq(err->code, ICMP6_TIME_HOP_LIMIT);
    word = ((uint32_t)err->data[0] << 24) | ((uint32_t)err->data[1] << 16) |
           ((uint32_t)err->data[2] << 8) | err->data[3];
    ck_assert_uint_eq(word, 0);
}
END_TEST

/* RFC 4443 section 2.4 (b): an unknown informational message is silently
 * discarded; an unknown error message is passed to the upper layer. */
START_TEST(test_icmp6_unknown_types_follow_the_error_split)
{
    struct wolfIP s;
    uint8_t buf[64];
    uint64_t now = 0;
    ip6 local;
    ip6 peer;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM,
                            WI_IPPROTO_ICMPV6);
    ck_assert_int_ge(fd, 0);

    /* Type 200: informational, unknown. Discarded, and nothing is sent
     * back - a node that cannot interpret it has nothing to say. */
    mock_link_capture_reset();
    sock6_deliver_icmp6_msg(&s, &peer, &local, 200, 0);
    ck_assert_uint_eq(last_frame_sent_size, 0);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0, NULL,
                                          NULL), -WOLFIP_EAGAIN);

    /* Type 100: an error, unknown. Must reach the application. */
    mock_link_capture_reset();
    sock6_deliver_icmp6_msg(&s, &peer, &local, 100, 0);
    ck_assert_int_gt(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0, NULL,
                                          NULL), 0);
    ck_assert_uint_eq(buf[0], 100);
    /* And it must not have provoked a reply of its own. */
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

/* An ICMPv6 socket sends an Echo Request and reads the Reply, with the peer
 * reported as a sockaddr_in6. */
START_TEST(test_icmp6_socket_echo_roundtrip)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in6 dst;
    struct wolfIP_sockaddr_in6 from;
    socklen_t fromlen = sizeof(from);
    struct wolfIP_icmp6_packet *sent;
    uint8_t staging[LINK_MTU];
    uint8_t req[12];
    uint8_t buf[64];
    uint64_t now = 0;
    ip6 local;
    ip6 peer;
    ip6 got;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM,
                            WI_IPPROTO_ICMPV6);
    ck_assert_int_ge(fd, 0);

    memset(req, 0, sizeof(req));
    req[0] = ICMP6_ECHO_REQUEST;
    req[1] = 0;
    /* identifier 0xBEEF, sequence 1 */
    req[4] = 0xBE; req[5] = 0xEF;
    req[6] = 0x00; req[7] = 0x01;
    memcpy(req + 8, "abcd", 4);

    sock6_addr(&dst, S6_PEER, 0);
    mock_link_capture_reset();
    ck_assert_int_eq(wolfIP_sock_sendto(&s, fd, req, sizeof(req), 0,
                                        (struct wolfIP_sockaddr *)&dst,
                                        sizeof(dst)), (int)sizeof(req));
    now += 100;
    wolfIP_poll(&s, now);

    sent = sock6_last_icmp6(staging);
    ck_assert_ptr_nonnull(sent);
    ck_assert_uint_eq(sent->ip6.next_hdr, IP6_NEXTHDR_ICMPV6);
    ck_assert_uint_eq(sent->type, ICMP6_ECHO_REQUEST);
    ck_assert_uint_eq(ee16(sent->ip6.payload_len), sizeof(req));
    /* The stack computes the checksum: it covers the pseudo-header, so the
     * application cannot have done it before source selection. */
    ck_assert_uint_ne(sent->csum, 0);
    ip6_hdr_get_dst(&sent->ip6, &got);
    ck_assert_int_eq(ip6_cmp(&got, &peer), 0);
    /* The socket adopted the identifier it sent. */
    ck_assert_uint_eq(s.icmpsockets[SOCKET_UNMARK(fd)].src_port, 0xBEEF);

    /* Answer it. */
    sock6_deliver_icmp6_echo(&s, &peer, &local, ICMP6_ECHO_REPLY, 0xBEEF, 1);
    ck_assert_int_gt(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0,
                                          (struct wolfIP_sockaddr *)&from,
                                          &fromlen), 0);
    ck_assert_uint_eq(buf[0], ICMP6_ECHO_REPLY);
    ck_assert_uint_eq(from.sin6_family, AF_INET6);
    memcpy(got.addr, &from.sin6_addr, 16);
    ck_assert_int_eq(ip6_cmp(&got, &peer), 0);
}
END_TEST

/* A reply carrying somebody else's identifier belongs to somebody else. */
START_TEST(test_icmp6_socket_filters_on_the_echo_identifier)
{
    struct wolfIP s;
    uint8_t buf[64];
    uint64_t now = 0;
    ip6 local;
    ip6 peer;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM,
                            WI_IPPROTO_ICMPV6);
    ck_assert_int_ge(fd, 0);
    s.icmpsockets[SOCKET_UNMARK(fd)].src_port = 0x1234;

    sock6_deliver_icmp6_echo(&s, &peer, &local, ICMP6_ECHO_REPLY, 0x9999, 1);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0, NULL,
                                          NULL), -WOLFIP_EAGAIN);

    sock6_deliver_icmp6_echo(&s, &peer, &local, ICMP6_ECHO_REPLY, 0x1234, 1);
    ck_assert_int_gt(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0, NULL,
                                          NULL), 0);
    ck_assert_uint_eq(buf[0], ICMP6_ECHO_REPLY);
}
END_TEST

/* An error message reaches the socket whatever identifier it carries: an
 * error quotes the packet that caused it and has no identifier of its own,
 * so filtering on one would hide exactly the reports worth having. */
START_TEST(test_icmp6_socket_receives_errors_regardless_of_identifier)
{
    struct wolfIP s;
    uint8_t buf[64];
    uint64_t now = 0;
    ip6 local;
    ip6 peer;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    fd = wolfIP_sock_socket(&s, AF_INET6, IPSTACK_SOCK_DGRAM,
                            WI_IPPROTO_ICMPV6);
    ck_assert_int_ge(fd, 0);
    s.icmpsockets[SOCKET_UNMARK(fd)].src_port = 0x1234;

    mock_link_capture_reset();
    sock6_deliver_icmp6_msg(&s, &peer, &local, ICMP6_DEST_UNREACH,
                            ICMP6_DST_PORT_UNREACH);
    ck_assert_int_gt(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0, NULL,
                                          NULL), 0);
    ck_assert_uint_eq(buf[0], ICMP6_DEST_UNREACH);
    ck_assert_uint_eq(buf[1], ICMP6_DST_PORT_UNREACH);
}
END_TEST

/* An AF_INET ICMP socket must never be handed an ICMPv6 message: the two
 * are different protocols with different type numbering. */
START_TEST(test_icmp6_af_inet_icmp_socket_never_receives_icmpv6)
{
    struct wolfIP s;
    uint8_t buf[64];
    uint64_t now = 0;
    ip6 local;
    ip6 peer;
    int fd;

    sock6_setup(&s);
    sock6_ready(&s, &now);
    ck_assert_int_eq(atoip6(S6_TEST_GLOBAL, &local), 0);
    ck_assert_int_eq(atoip6(S6_PEER, &peer), 0);
    fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_ge(fd, 0);

    sock6_deliver_icmp6_echo(&s, &peer, &local, ICMP6_ECHO_REPLY, 0, 1);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, fd, buf, sizeof(buf), 0, NULL,
                                          NULL), -WOLFIP_EAGAIN);
}
END_TEST

#endif /* WOLFIP_IPV6 */

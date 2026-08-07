/* unit_tests_ifaddr.c
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

/* =========================================================================
 * Environment note
 * =========================================================================
 * The per-interface address list.
 *
 * struct ipconf is reached by more than fifty files, every board port among
 * them, so it cannot be replaced. The address list is therefore additive:
 *
 *   - ipconf[if_idx].ip/mask/gw remains the authoritative *primary* IPv4
 *     address of an interface, exactly as before. wolfIP_ipconfig_set/get
 *     and every existing caller keep working untouched.
 *   - The pool holds the *additional* addresses: IPv4 aliases and every
 *     IPv6 address. The primary is never duplicated into it, so the two
 *     cannot drift apart.
 *
 * Index 0 of an interface's IPv4 list is therefore always the primary, and
 * indices above 0 are aliases.
 *
 * WOLFIP_IF_CONF_MAX caps the total per interface, primary included. It is
 * 1 unless WOLFIP_IF_MULTICONF is on, which is what makes the feature
 * optional: with it off the API still exists and behaves, but an interface
 * holds exactly one address and the pool is not compiled in at all, so
 * struct wolfIP does not grow.
 *
 * The tests in the first section run in every build, including the default
 * IPv4-only one, which is what keeps the 100%-function-coverage gate on
 * src/wolfip.c satisfied. The later sections are gated.
 */

/* =========================================================================
 * Local helpers
 * ========================================================================= */

#define IFA_IP_A 0x0A0A0A02U /* 10.10.10.2 */
#define IFA_IP_B 0x0A0A0A03U /* 10.10.10.3 */
#define IFA_IP_C 0xC0A80101U /* 192.168.1.1 */
#define IFA_MASK 0xFFFFFF00U

static const uint8_t ifaddr_peer_mac[6] = {0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x22};

static void ifaddr_setup(struct wolfIP *s)
{
    wolfIP_init(s);
    mock_link_init(s);
    wolfIP_ipconfig_set_ex(s, TEST_PRIMARY_IF, IFA_IP_A, IFA_MASK, 0);
}

/* =========================================================================
 * Always-on: behaviour with a single configuration per interface
 * ========================================================================= */

START_TEST(test_ifaddr_primary_is_the_ipconf_address)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;

    ifaddr_setup(&s);

    /* The primary IPv4 address is whatever wolfIP_ipconfig_set_ex put in
     * ipconf; the list is a view over it, not a second copy. */
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET), 1);
    ck_assert_int_eq(wolfIP_ifaddr_get(&s, TEST_PRIMARY_IF, AF_INET, 0, &info), 0);
    ck_assert_uint_eq(info.v4, IFA_IP_A);
    ck_assert_uint_eq(info.family, AF_INET);
    ck_assert_uint_eq(info.if_idx, TEST_PRIMARY_IF);
    ck_assert_uint_eq(info.prefix_len, 24);
    ck_assert_uint_eq(info.state, WOLFIP_IFADDR_PREFERRED);

    /* Changing it through the old API is immediately visible here. */
    wolfIP_ipconfig_set_ex(&s, TEST_PRIMARY_IF, IFA_IP_C, 0xFFFF0000U, 0);
    ck_assert_int_eq(wolfIP_ifaddr_get(&s, TEST_PRIMARY_IF, AF_INET, 0, &info), 0);
    ck_assert_uint_eq(info.v4, IFA_IP_C);
    ck_assert_uint_eq(info.prefix_len, 16);
}
END_TEST

START_TEST(test_ifaddr_unconfigured_interface_has_no_addresses)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;

    wolfIP_init(&s);
    mock_link_init(&s);

    /* IPADDR_ANY is "unconfigured", not an address. */
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET), 0);
    ck_assert_int_lt(wolfIP_ifaddr_get(&s, TEST_PRIMARY_IF, AF_INET, 0, &info), 0);
}
END_TEST

START_TEST(test_ifaddr_add4_sets_the_primary_when_unconfigured)
{
    struct wolfIP s;
    ip4 ip = 0, mask = 0, gw = 0;

    wolfIP_init(&s);
    mock_link_init(&s);

    /* With no primary yet, an add lands in ipconf so that a single-address
     * build is usable through the new API alone. */
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_A, 24), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET), 1);

    wolfIP_ipconfig_get_ex(&s, TEST_PRIMARY_IF, &ip, &mask, &gw);
    ck_assert_uint_eq(ip, IFA_IP_A);
    ck_assert_uint_eq(mask, IFA_MASK);
}
END_TEST

START_TEST(test_ifaddr_add4_rejects_a_duplicate)
{
    struct wolfIP s;

    ifaddr_setup(&s);
    /* Already the primary. */
    ck_assert_int_lt(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_A, 24), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET), 1);
}
END_TEST

START_TEST(test_ifaddr_del4_clears_the_primary)
{
    struct wolfIP s;
    ip4 ip = 0, mask = 0, gw = 0;

    ifaddr_setup(&s);
    ck_assert_int_eq(wolfIP_ifaddr_del4(&s, TEST_PRIMARY_IF, IFA_IP_A), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET), 0);

    wolfIP_ipconfig_get_ex(&s, TEST_PRIMARY_IF, &ip, &mask, &gw);
    ck_assert_uint_eq(ip, IPADDR_ANY);

    /* Deleting an address that is not configured is an error, not a
     * silent success. */
    ck_assert_int_lt(wolfIP_ifaddr_del4(&s, TEST_PRIMARY_IF, IFA_IP_A), 0);
}
END_TEST

START_TEST(test_ifaddr_is_local4_matches_the_primary)
{
    struct wolfIP s;
    unsigned int found = 0xFFFFFFFFu;

    ifaddr_setup(&s);
    ck_assert_int_eq(wolfIP_ifaddr_is_local4(&s, IFA_IP_A, &found), 1);
    ck_assert_uint_eq(found, TEST_PRIMARY_IF);

    ck_assert_int_eq(wolfIP_ifaddr_is_local4(&s, IFA_IP_C, &found), 0);
    /* The out parameter is optional. */
    ck_assert_int_eq(wolfIP_ifaddr_is_local4(&s, IFA_IP_A, NULL), 1);
    /* IPADDR_ANY is never one of ours, even on an unconfigured stack. */
    ck_assert_int_eq(wolfIP_ifaddr_is_local4(&s, IPADDR_ANY, NULL), 0);
}
END_TEST

START_TEST(test_ifaddr_capacity_is_one_without_multiconf)
{
    struct wolfIP s;

    ifaddr_setup(&s);
#if WOLFIP_IF_MULTICONF
    /* With the feature on there is room for aliases; covered below. */
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);
#else
    /* With the feature off an interface holds exactly one address, and a
     * second must be refused rather than silently replacing the first. */
    ck_assert_int_lt(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET), 1);
    ck_assert_int_eq(wolfIP_ifaddr_is_local4(&s, IFA_IP_A, NULL), 1);
    ck_assert_int_eq(wolfIP_ifaddr_is_local4(&s, IFA_IP_B, NULL), 0);
#endif
}
END_TEST

START_TEST(test_ifaddr_rejects_invalid_arguments)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;
    ip6 a6;

    ifaddr_setup(&s);
    ip6_set_loopback(&a6);

    ck_assert_int_lt(wolfIP_ifaddr_add4(NULL, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);
    ck_assert_int_lt(wolfIP_ifaddr_del4(NULL, TEST_PRIMARY_IF, IFA_IP_A), 0);
    ck_assert_int_lt(wolfIP_ifaddr_add6(NULL, TEST_PRIMARY_IF, &a6, 64), 0);
    ck_assert_int_lt(wolfIP_ifaddr_del6(NULL, TEST_PRIMARY_IF, &a6), 0);
    ck_assert_int_lt(wolfIP_ifaddr_get(NULL, TEST_PRIMARY_IF, AF_INET, 0, &info), 0);
    ck_assert_int_eq(wolfIP_ifaddr_count(NULL, TEST_PRIMARY_IF, AF_INET), 0);
    ck_assert_int_eq(wolfIP_ifaddr_is_local4(NULL, IFA_IP_A, NULL), 0);

    /* Out-of-range interface index. */
    ck_assert_int_lt(wolfIP_ifaddr_add4(&s, 99, IFA_IP_B, 24), 0);
    ck_assert_int_lt(wolfIP_ifaddr_get(&s, 99, AF_INET, 0, &info), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, 99, AF_INET), 0);

    /* NULL address pointers and output buffer. */
    ck_assert_int_lt(wolfIP_ifaddr_add6(&s, TEST_PRIMARY_IF, NULL, 64), 0);
    ck_assert_int_lt(wolfIP_ifaddr_del6(&s, TEST_PRIMARY_IF, NULL), 0);
    ck_assert_int_lt(wolfIP_ifaddr_get(&s, TEST_PRIMARY_IF, AF_INET, 0, NULL), 0);

    /* Nonsense prefix lengths. */
    ck_assert_int_lt(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 33), 0);
    ck_assert_int_lt(wolfIP_ifaddr_add6(&s, TEST_PRIMARY_IF, &a6, 129), 0);

    /* Unknown family. */
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, 1234), 0);
    ck_assert_int_lt(wolfIP_ifaddr_get(&s, TEST_PRIMARY_IF, 1234, 0, &info), 0);

    /* Index past the end. */
    ck_assert_int_lt(wolfIP_ifaddr_get(&s, TEST_PRIMARY_IF, AF_INET, 99, &info), 0);
}
END_TEST

START_TEST(test_ifaddr_v6_requires_ipv6_enabled)
{
    struct wolfIP s;
    ip6 a6;

    ifaddr_setup(&s);
    ck_assert_int_eq(atoip6("2001:db8::1", &a6), 0);

#if WOLFIP_IPV6
    ck_assert_int_eq(wolfIP_ifaddr_add6(&s, TEST_PRIMARY_IF, &a6, 64), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 1);
    ck_assert_int_eq(wolfIP_ifaddr_del6(&s, TEST_PRIMARY_IF, &a6), 0);
#else
    /* Without IPv6 compiled in there is nowhere to put a v6 address, and
     * the call must say so rather than appear to succeed. */
    ck_assert_int_lt(wolfIP_ifaddr_add6(&s, TEST_PRIMARY_IF, &a6, 64), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 0);
    ck_assert_int_lt(wolfIP_ifaddr_del6(&s, TEST_PRIMARY_IF, &a6), 0);
#endif
}
END_TEST

/* =========================================================================
 * IPv4 aliasing - needs WOLFIP_IF_MULTICONF, not IPv6
 * ========================================================================= */
#if WOLFIP_IF_MULTICONF

START_TEST(test_ifaddr_multiple_ipv4_addresses_on_one_interface)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;
    ip4 ip = 0, mask = 0, gw = 0;

    ifaddr_setup(&s);
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_C, 16), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET), 3);

    /* Index 0 is always the primary; aliases follow in insertion order. */
    ck_assert_int_eq(wolfIP_ifaddr_get(&s, TEST_PRIMARY_IF, AF_INET, 0, &info), 0);
    ck_assert_uint_eq(info.v4, IFA_IP_A);
    ck_assert_int_eq(wolfIP_ifaddr_get(&s, TEST_PRIMARY_IF, AF_INET, 1, &info), 0);
    ck_assert_uint_eq(info.v4, IFA_IP_B);
    ck_assert_uint_eq(info.prefix_len, 24);
    ck_assert_int_eq(wolfIP_ifaddr_get(&s, TEST_PRIMARY_IF, AF_INET, 2, &info), 0);
    ck_assert_uint_eq(info.v4, IFA_IP_C);
    ck_assert_uint_eq(info.prefix_len, 16);

    /* Adding an alias must not disturb the primary, which is what every
     * existing caller of wolfIP_ipconfig_get_ex still reads. */
    wolfIP_ipconfig_get_ex(&s, TEST_PRIMARY_IF, &ip, &mask, &gw);
    ck_assert_uint_eq(ip, IFA_IP_A);
    ck_assert_uint_eq(mask, IFA_MASK);
}
END_TEST

START_TEST(test_ifaddr_aliases_are_local_addresses)
{
    struct wolfIP s;
    unsigned int found = 0xFFFFFFFFu;

    ifaddr_setup(&s);
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);

    /* An alias has to count as one of ours, or inbound traffic addressed
     * to it is dropped and the alias is decorative. */
    ck_assert_int_eq(wolfIP_ifaddr_is_local4(&s, IFA_IP_B, &found), 1);
    ck_assert_uint_eq(found, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_ifaddr_alias_removal_leaves_the_others)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;

    ifaddr_setup(&s);
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_C, 16), 0);

    /* Remove the middle one. */
    ck_assert_int_eq(wolfIP_ifaddr_del4(&s, TEST_PRIMARY_IF, IFA_IP_B), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET), 2);
    ck_assert_int_eq(wolfIP_ifaddr_is_local4(&s, IFA_IP_B, NULL), 0);
    ck_assert_int_eq(wolfIP_ifaddr_is_local4(&s, IFA_IP_A, NULL), 1);
    ck_assert_int_eq(wolfIP_ifaddr_is_local4(&s, IFA_IP_C, NULL), 1);

    /* The surviving alias is still reachable by index, with no hole. */
    ck_assert_int_eq(wolfIP_ifaddr_get(&s, TEST_PRIMARY_IF, AF_INET, 1, &info), 0);
    ck_assert_uint_eq(info.v4, IFA_IP_C);
}
END_TEST

START_TEST(test_ifaddr_clearing_the_primary_keeps_aliases)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;

    ifaddr_setup(&s);
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);

    /* Removing the primary must not take the aliases with it. The first
     * remaining address becomes index 0. */
    ck_assert_int_eq(wolfIP_ifaddr_del4(&s, TEST_PRIMARY_IF, IFA_IP_A), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET), 1);
    ck_assert_int_eq(wolfIP_ifaddr_get(&s, TEST_PRIMARY_IF, AF_INET, 0, &info), 0);
    ck_assert_uint_eq(info.v4, IFA_IP_B);
    ck_assert_int_eq(wolfIP_ifaddr_is_local4(&s, IFA_IP_B, NULL), 1);
}
END_TEST

START_TEST(test_ifaddr_per_interface_capacity_is_enforced)
{
    struct wolfIP s;
    unsigned int i;

    ifaddr_setup(&s);
    /* The primary counts towards WOLFIP_IF_CONF_MAX, so there is room for
     * that many minus one aliases. */
    for (i = 1; i < WOLFIP_IF_CONF_MAX; i++) {
        ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF,
                                            IFA_IP_A + i, 24), 0);
    }
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET),
                      WOLFIP_IF_CONF_MAX);
    /* One more must be refused, not silently dropped or overflow. */
    ck_assert_int_lt(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_C, 24), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET),
                      WOLFIP_IF_CONF_MAX);
}
END_TEST

START_TEST(test_ifaddr_interfaces_do_not_share_addresses)
{
    struct wolfIP s;
    unsigned int found = 0xFFFFFFFFu;

    ifaddr_setup(&s);
    wolfIP_ipconfig_set_ex(&s, TEST_SECOND_IF, IFA_IP_C, 0xFFFF0000U, 0);
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_SECOND_IF, IFA_IP_B, 16), 0);

    /* An alias belongs to exactly one interface. */
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET), 1);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_SECOND_IF, AF_INET), 2);
    ck_assert_int_eq(wolfIP_ifaddr_is_local4(&s, IFA_IP_B, &found), 1);
    ck_assert_uint_eq(found, TEST_SECOND_IF);

    /* Deleting it from the wrong interface must fail. */
    ck_assert_int_lt(wolfIP_ifaddr_del4(&s, TEST_PRIMARY_IF, IFA_IP_B), 0);
    ck_assert_int_eq(wolfIP_ifaddr_is_local4(&s, IFA_IP_B, NULL), 1);
}
END_TEST

START_TEST(test_ifaddr_the_same_alias_may_not_be_added_twice)
{
    struct wolfIP s;

    ifaddr_setup(&s);
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);
    ck_assert_int_lt(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET), 2);
    /* Nor may an alias collide with the primary. */
    ck_assert_int_lt(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_A, 24), 0);
}
END_TEST

START_TEST(test_ifaddr_pool_is_shared_across_interfaces)
{
    struct wolfIP s;
    unsigned int added = 0;
    unsigned int i;

    ifaddr_setup(&s);
    wolfIP_ipconfig_set_ex(&s, TEST_SECOND_IF, IFA_IP_C, 0xFFFF0000U, 0);

    /* The pool is a flat shared array, so it can be exhausted from one
     * interface. Filling it must never corrupt another interface's list. */
    for (i = 0; i < (WOLFIP_IFADDR_MAX + 4u); i++) {
        if (wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF,
                               0x0B000000U + i, 24) == 0)
            added++;
    }
    ck_assert_uint_lt(added, WOLFIP_IF_CONF_MAX);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET),
                      added + 1u);
    ck_assert_int_eq(wolfIP_ifaddr_is_local4(&s, IFA_IP_C, NULL), 1);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_SECOND_IF, AF_INET), 1);
}
END_TEST

START_TEST(test_ifaddr_socket_binds_to_an_alias_on_the_right_interface)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    struct tsocket *ts;
    int fd;

    ifaddr_setup(&s);
    wolfIP_ipconfig_set_ex(&s, TEST_SECOND_IF, IFA_IP_C, 0xFFFF0000U, 0);
    /* The alias lives on the *second* interface, not the primary. */
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_SECOND_IF, IFA_IP_B, 16), 0);

    fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_ge(fd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7777);
    sin.sin_addr.s_addr = ee32(IFA_IP_B);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd, (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), 0);

    /* Binding to an alias must resolve to the interface that owns it.
     * Without the alias list this silently fell back to the primary
     * interface, which is the bug that makes an alias decorative. */
    ts = wolfIP_socket_from_fd(&s, fd);
    ck_assert_ptr_nonnull(ts);
    ck_assert_uint_eq(ts->if_idx, TEST_SECOND_IF);
    ck_assert_uint_eq(ts->local_ip, IFA_IP_B);
}
END_TEST

/* =========================================================================
 * bind() and source selection with several addresses on one interface
 * =========================================================================
 * Reference behaviour (Linux, and what POSIX implies for the TCP 4-tuple):
 *
 *   - Binding to a specific local address restricts the socket to that
 *     address. Traffic to a *different* local address on the same
 *     interface must not be delivered to it.
 *   - Binding to INADDR_ANY is a wildcard: the socket receives traffic
 *     addressed to any local address.
 *   - Outbound traffic from a socket bound to a specific address uses that
 *     address as its source (RFC 6724 rule 1 states this explicitly for
 *     IPv6; for IPv4 it is RFC 1122 section 3.3.4.3 plus long-standing
 *     practice).
 *   - Binding to an address that is not local must fail.
 */

#define IFA_REMOTE 0x0A0A0A63U /* 10.10.10.99 */

static int ifaddr_udp_bind(struct wolfIP *s, ip4 addr, uint16_t port)
{
    struct wolfIP_sockaddr_in sin;
    int fd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);

    ck_assert_int_ge(fd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(port);
    sin.sin_addr.s_addr = ee32(addr);
    if (wolfIP_sock_bind(s, fd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)) != 0)
        return -1;
    return fd;
}

/* Did a datagram sent to dst_ip reach the socket? */
static int ifaddr_udp_delivered(struct wolfIP *s, int fd, ip4 dst_ip,
                                uint16_t port)
{
    static const uint8_t payload[4] = {'p', 'i', 'n', 'g'};
    uint8_t buf[16];

    inject_udp_datagram(s, TEST_PRIMARY_IF, IFA_REMOTE, dst_ip, 4444, port,
                        payload, sizeof(payload));
    return (wolfIP_sock_recvfrom(s, fd, buf, sizeof(buf), 0, NULL, NULL) > 0);
}

START_TEST(test_ifaddr_bind_to_alias_receives_only_its_own_traffic)
{
    struct wolfIP s;
    int fd;

    ifaddr_setup(&s);
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);

    fd = ifaddr_udp_bind(&s, IFA_IP_B, 5001);
    ck_assert_int_ge(fd, 0);

    /* Traffic to the bound alias arrives. */
    ck_assert_int_eq(ifaddr_udp_delivered(&s, fd, IFA_IP_B, 5001), 1);
    /* Traffic to the primary on the same interface must not, or binding to
     * an address would mean nothing. */
    ck_assert_int_eq(ifaddr_udp_delivered(&s, fd, IFA_IP_A, 5001), 0);
}
END_TEST

START_TEST(test_ifaddr_bind_to_primary_does_not_receive_alias_traffic)
{
    struct wolfIP s;
    int fd;

    ifaddr_setup(&s);
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);

    fd = ifaddr_udp_bind(&s, IFA_IP_A, 5002);
    ck_assert_int_ge(fd, 0);
    ck_assert_int_eq(ifaddr_udp_delivered(&s, fd, IFA_IP_A, 5002), 1);
    ck_assert_int_eq(ifaddr_udp_delivered(&s, fd, IFA_IP_B, 5002), 0);
}
END_TEST

START_TEST(test_ifaddr_bind_to_a_foreign_address_is_refused)
{
    struct wolfIP s;

    ifaddr_setup(&s);
    /* Not configured anywhere on this stack. */
    ck_assert_int_lt(ifaddr_udp_bind(&s, IFA_REMOTE, 5003), 0);
    /* An alias that has been removed again is equally foreign. */
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);
    ck_assert_int_eq(wolfIP_ifaddr_del4(&s, TEST_PRIMARY_IF, IFA_IP_B), 0);
    ck_assert_int_lt(ifaddr_udp_bind(&s, IFA_IP_B, 5004), 0);
}
END_TEST

START_TEST(test_ifaddr_sendto_from_an_alias_uses_it_as_source)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in dst;
    struct wolfIP_ip_packet *ip;
    static const uint8_t payload[4] = {'d', 'a', 't', 'a'};
    int fd;

    ifaddr_setup(&s);
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);
    fd = ifaddr_udp_bind(&s, IFA_IP_B, 5005);
    ck_assert_int_ge(fd, 0);

    /* Teach ARP the peer so the datagram can actually leave. */
    arp_store_neighbor(&s, TEST_PRIMARY_IF, IFA_REMOTE, ifaddr_peer_mac);

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = ee16(4444);
    dst.sin_addr.s_addr = ee32(IFA_REMOTE);
    last_frame_sent_size = 0;
    ck_assert_int_gt(wolfIP_sock_sendto(&s, fd, payload, sizeof(payload), 0,
                                        (struct wolfIP_sockaddr *)&dst,
                                        sizeof(dst)), 0);
    wolfIP_poll(&s, 1000);

    /* The source address on the wire must be the address the socket was
     * bound to, not the interface's primary. */
    ck_assert_uint_gt((uint32_t)last_frame_sent_size, 0u);
    ip = (struct wolfIP_ip_packet *)last_frame_sent;
    ck_assert_uint_eq(ee32(ip->src), IFA_IP_B);
}
END_TEST

START_TEST(test_ifaddr_wildcard_bind_receives_traffic_to_any_local_address)
{
    struct wolfIP s;
    int fd;

    ifaddr_setup(&s);
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);

    fd = ifaddr_udp_bind(&s, IPADDR_ANY, 5006);
    ck_assert_int_ge(fd, 0);

    /* A wildcard bind must accept traffic to every local address, which is
     * what INADDR_ANY means on every other stack. */
    ck_assert_int_eq(ifaddr_udp_delivered(&s, fd, IFA_IP_A, 5006), 1);
    ck_assert_int_eq(ifaddr_udp_delivered(&s, fd, IFA_IP_B, 5006), 1);
}
END_TEST

START_TEST(test_ifaddr_tcp_wildcard_listener_accepts_connections_to_an_alias)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    int fd;

    ifaddr_setup(&s);
    ck_assert_int_eq(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);

    fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(fd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5007);
    sin.sin_addr.s_addr = ee32(IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd, (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, fd, 1), 0);

    /* A wildcard listener records bound_local_ip == IPADDR_ANY, and the SYN
     * path filters on that rather than on local_ip, so a connection to an
     * alias is accepted. */
    ck_assert_uint_eq(s.tcpsockets[SOCKET_UNMARK(fd)].bound_local_ip,
                      IPADDR_ANY);
}
END_TEST

#endif /* WOLFIP_IF_MULTICONF */

/* =========================================================================
 * IPv6 addresses in the list
 * ========================================================================= */
#if WOLFIP_IPV6

START_TEST(test_ifaddr_v6_addresses_are_independent_of_v4)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;
    ip6 ll6;
    ip6 gua;

    ifaddr_setup(&s);
    ck_assert_int_eq(atoip6("fe80::1", &ll6), 0);
    ck_assert_int_eq(atoip6("2001:db8::1", &gua), 0);

    ck_assert_int_eq(wolfIP_ifaddr_add6(&s, TEST_PRIMARY_IF, &ll6, 64), 0);
    ck_assert_int_eq(wolfIP_ifaddr_add6(&s, TEST_PRIMARY_IF, &gua, 64), 0);

    /* A link-local and a global address coexisting is the normal IPv6 case
     * and is the reason this feature exists at all. */
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 2);
    /* The IPv4 list is untouched by any of it. */
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET), 1);

    ck_assert_int_eq(wolfIP_ifaddr_get(&s, TEST_PRIMARY_IF, AF_INET6, 0, &info), 0);
    ck_assert_uint_eq(info.family, AF_INET6);
    ck_assert_int_eq(ip6_cmp(&info.v6, &ll6), 0);
    ck_assert_uint_eq(info.prefix_len, 64);
    ck_assert_int_eq(wolfIP_ifaddr_get(&s, TEST_PRIMARY_IF, AF_INET6, 1, &info), 0);
    ck_assert_int_eq(ip6_cmp(&info.v6, &gua), 0);
}
END_TEST

START_TEST(test_ifaddr_v6_duplicate_is_rejected_and_removal_works)
{
    struct wolfIP s;
    ip6 a6;

    ifaddr_setup(&s);
    ck_assert_int_eq(atoip6("2001:db8::1", &a6), 0);

    ck_assert_int_eq(wolfIP_ifaddr_add6(&s, TEST_PRIMARY_IF, &a6, 64), 0);
    ck_assert_int_lt(wolfIP_ifaddr_add6(&s, TEST_PRIMARY_IF, &a6, 64), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 1);

    ck_assert_int_eq(wolfIP_ifaddr_del6(&s, TEST_PRIMARY_IF, &a6), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 0);
    ck_assert_int_lt(wolfIP_ifaddr_del6(&s, TEST_PRIMARY_IF, &a6), 0);
}
END_TEST

START_TEST(test_ifaddr_v6_link_local_address_is_scoped_per_interface)
{
    struct wolfIP s;
    ip6 ll6;

    ifaddr_setup(&s);
    mock_link_init_idx(&s, TEST_SECOND_IF, NULL);
    ck_assert_int_eq(atoip6("fe80::1", &ll6), 0);

    /* RFC 4007 section 5: the zone is part of a link-local address's
     * identity, so the same numeric address may exist on two links. */
    ck_assert_int_eq(wolfIP_ifaddr_add6(&s, TEST_PRIMARY_IF, &ll6, 64), 0);
    ck_assert_int_eq(wolfIP_ifaddr_add6(&s, TEST_SECOND_IF, &ll6, 64), 0);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 1);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_SECOND_IF, AF_INET6), 1);
}
END_TEST

START_TEST(test_ifaddr_v6_and_v4_share_the_per_interface_budget)
{
    struct wolfIP s;
    ip6 a6;
    unsigned int i;
    unsigned int added = 0;

    ifaddr_setup(&s);
    ip6_set_unspecified(&a6);

    /* Both families draw on the same WOLFIP_IF_CONF_MAX budget, so a v6
     * address consumes a slot a v4 alias could have used. */
    for (i = 0; i < (WOLFIP_IF_CONF_MAX + 2u); i++) {
        a6.addr[0] = 0x20;
        a6.addr[1] = 0x01;
        a6.addr[15] = (uint8_t)(i + 1u);
        if (wolfIP_ifaddr_add6(&s, TEST_PRIMARY_IF, &a6, 64) == 0)
            added++;
    }
    ck_assert_uint_eq(added, WOLFIP_IF_CONF_MAX - 1u);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), added);
    /* And with the budget spent, a v4 alias no longer fits. */
    ck_assert_int_lt(wolfIP_ifaddr_add4(&s, TEST_PRIMARY_IF, IFA_IP_B, 24), 0);
}
END_TEST

#endif /* WOLFIP_IPV6 */

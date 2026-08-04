/* unit_tests_ipv6_addr.c
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
 * These tests cover the IPv6 addressing layer in wolfip6.h. That header holds
 * only a typedef and static inline functions and is included unconditionally
 * from wolfip.h, so this file is deliberately NOT gated on WOLFIP_IPV6: the
 * address layer is exercised by the default `make unit` build, and therefore
 * by every compiler in the CI matrix, on macOS and FreeBSD, and under the
 * sanitizers, without needing the IPv6 stack to be enabled.
 *
 * Reference material: RFC 4291 (addressing architecture), RFC 4193 (unique
 * local addresses), RFC 3587 (global unicast format), RFC 2464 section 7
 * (Ethernet multicast mapping), RFC 4862 section 5.5.3 (address formation)
 * and RFC 5952 (canonical text representation).
 */

/* =========================================================================
 * Local helpers
 * ========================================================================= */

/* Parse a literal that the test asserts is well formed. */
static ip6 ip6_lit(const char *s)
{
    ip6 a;

    ck_assert_int_eq(atoip6(s, &a), 0);
    return a;
}

/* Assert that a literal parses and renders back to the expected canonical
 * form. `in` and `expect` differ whenever `in` is not already canonical. */
static void ip6_check_text(const char *in, const char *expect)
{
    char buf[WOLFIP_IP6_ADDRSTRLEN];
    ip6 a;

    ck_assert_int_eq(atoip6(in, &a), 0);
    ip6toa(&a, buf);
    ck_assert_str_eq(buf, expect);
}

/* Assert that a literal is rejected. */
static void ip6_check_bad(const char *in)
{
    ip6 a;

    ip6_set_loopback(&a); /* poison, so a silent success is visible */
    ck_assert_int_eq(atoip6(in, &a), -1);
}

/* =========================================================================
 * Basic operations
 * ========================================================================= */

START_TEST(test_ip6_cmp_and_copy)
{
    ip6 a = ip6_lit("2001:db8::1");
    ip6 b = ip6_lit("2001:db8::1");
    ip6 c = ip6_lit("2001:db8::2");
    ip6 dst;

    ck_assert_int_eq(ip6_cmp(&a, &b), 0);
    ck_assert_int_ne(ip6_cmp(&a, &c), 0);
    /* Ordering is stable and antisymmetric. */
    ck_assert_int_lt(ip6_cmp(&a, &c), 0);
    ck_assert_int_gt(ip6_cmp(&c, &a), 0);

    ip6_set_unspecified(&dst);
    ip6_copy(&dst, &a);
    ck_assert_int_eq(ip6_cmp(&dst, &a), 0);
}
END_TEST

START_TEST(test_ip6_cmp_differs_in_every_byte_position)
{
    int i;

    /* A byte-wise comparison must not miss a difference at any offset. */
    for (i = 0; i < 16; i++) {
        ip6 a;
        ip6 b;

        ip6_set_unspecified(&a);
        ip6_set_unspecified(&b);
        b.addr[i] = 0x01;
        ck_assert_int_ne(ip6_cmp(&a, &b), 0);
        ck_assert_int_lt(ip6_cmp(&a, &b), 0);
    }
}
END_TEST

START_TEST(test_ip6_set_wellknown_addresses)
{
    ip6 a;
    ip6 ref;

    ip6_set_unspecified(&a);
    ref = ip6_lit("::");
    ck_assert_int_eq(ip6_cmp(&a, &ref), 0);

    ip6_set_loopback(&a);
    ref = ip6_lit("::1");
    ck_assert_int_eq(ip6_cmp(&a, &ref), 0);

    ip6_set_all_nodes(&a);
    ref = ip6_lit("ff02::1");
    ck_assert_int_eq(ip6_cmp(&a, &ref), 0);

    ip6_set_all_routers(&a);
    ref = ip6_lit("ff02::2");
    ck_assert_int_eq(ip6_cmp(&a, &ref), 0);
}
END_TEST

START_TEST(test_ip6_init_macros_match_setters)
{
    ip6 any = WOLFIP_IN6ADDR_ANY_INIT;
    ip6 lo = WOLFIP_IN6ADDR_LOOPBACK_INIT;
    ip6 ref;

    ip6_set_unspecified(&ref);
    ck_assert_int_eq(ip6_cmp(&any, &ref), 0);
    ip6_set_loopback(&ref);
    ck_assert_int_eq(ip6_cmp(&lo, &ref), 0);
}
END_TEST

/* =========================================================================
 * Type and scope predicates
 * ========================================================================= */

START_TEST(test_ip6_is_unspecified)
{
    ip6 a = ip6_lit("::");
    ip6 b = ip6_lit("::1");
    int i;

    ck_assert_int_eq(ip6_is_unspecified(&a), 1);
    ck_assert_int_eq(ip6_is_unspecified(&b), 0);
    ck_assert_int_eq(ip6_is_unicast(&a), 0);

    /* A single non-zero byte anywhere disqualifies it. */
    for (i = 0; i < 16; i++) {
        ip6 c;

        ip6_set_unspecified(&c);
        c.addr[i] = 0x01;
        ck_assert_int_eq(ip6_is_unspecified(&c), 0);
    }
}
END_TEST

START_TEST(test_ip6_is_loopback)
{
    ip6 a = ip6_lit("::1");
    ip6 b = ip6_lit("::2");
    ip6 c = ip6_lit("::");
    ip6 d = ip6_lit("1::1");

    ck_assert_int_eq(ip6_is_loopback(&a), 1);
    ck_assert_int_eq(ip6_is_loopback(&b), 0);
    ck_assert_int_eq(ip6_is_loopback(&c), 0);
    ck_assert_int_eq(ip6_is_loopback(&d), 0);
}
END_TEST

START_TEST(test_ip6_is_multicast)
{
    ip6 a = ip6_lit("ff02::1");
    ip6 b = ip6_lit("ff00::");
    ip6 c = ip6_lit("fe80::1");
    ip6 d = ip6_lit("2001:db8::1");

    ck_assert_int_eq(ip6_is_multicast(&a), 1);
    ck_assert_int_eq(ip6_is_multicast(&b), 1);
    ck_assert_int_eq(ip6_is_multicast(&c), 0);
    ck_assert_int_eq(ip6_is_multicast(&d), 0);
    /* Multicast is never a valid unicast source. */
    ck_assert_int_eq(ip6_is_unicast(&a), 0);
}
END_TEST

START_TEST(test_ip6_is_link_local_covers_whole_fe80_10)
{
    /* fe80::/10 spans fe80:: through febf:ffff:... */
    ip6 lo = ip6_lit("fe80::");
    ip6 hi = ip6_lit("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    ip6 just_below = ip6_lit("fe7f:ffff::");
    ip6 just_above = ip6_lit("fec0::");

    ck_assert_int_eq(ip6_is_link_local(&lo), 1);
    ck_assert_int_eq(ip6_is_link_local(&hi), 1);
    ck_assert_int_eq(ip6_is_link_local(&just_below), 0);
    /* fec0::/10 is the deprecated site-local range, not link-local. */
    ck_assert_int_eq(ip6_is_link_local(&just_above), 0);
}
END_TEST

START_TEST(test_ip6_is_ula_covers_whole_fc00_7)
{
    ip6 fc = ip6_lit("fc00::");
    ip6 fd = ip6_lit("fd00::1");
    ip6 hi = ip6_lit("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    ip6 below = ip6_lit("fbff::");
    ip6 above = ip6_lit("fe00::");

    ck_assert_int_eq(ip6_is_ula(&fc), 1);
    ck_assert_int_eq(ip6_is_ula(&fd), 1);
    ck_assert_int_eq(ip6_is_ula(&hi), 1);
    ck_assert_int_eq(ip6_is_ula(&below), 0);
    ck_assert_int_eq(ip6_is_ula(&above), 0);
    /* A ULA is not global unicast. */
    ck_assert_int_eq(ip6_is_global(&fd), 0);
}
END_TEST

START_TEST(test_ip6_is_global_covers_whole_2000_3)
{
    ip6 lo = ip6_lit("2000::");
    ip6 doc = ip6_lit("2001:db8::1");
    ip6 hi = ip6_lit("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    ip6 below = ip6_lit("1fff::");
    ip6 above = ip6_lit("4000::");

    ck_assert_int_eq(ip6_is_global(&lo), 1);
    ck_assert_int_eq(ip6_is_global(&doc), 1);
    ck_assert_int_eq(ip6_is_global(&hi), 1);
    ck_assert_int_eq(ip6_is_global(&below), 0);
    ck_assert_int_eq(ip6_is_global(&above), 0);
    ck_assert_int_eq(ip6_is_unicast(&doc), 1);
}
END_TEST

START_TEST(test_ip6_multicast_flags_and_scope)
{
    ip6 iface = ip6_lit("ff01::1");
    ip6 link = ip6_lit("ff02::1");
    ip6 site = ip6_lit("ff05::1");
    ip6 global = ip6_lit("ff0e::1");
    ip6 transient = ip6_lit("ff12::1");

    ck_assert_uint_eq(ip6_mcast_scope(&iface), WOLFIP_IP6_SCOPE_INTERFACE_LOCAL);
    ck_assert_uint_eq(ip6_mcast_scope(&link), WOLFIP_IP6_SCOPE_LINK_LOCAL);
    ck_assert_uint_eq(ip6_mcast_scope(&site), WOLFIP_IP6_SCOPE_SITE_LOCAL);
    ck_assert_uint_eq(ip6_mcast_scope(&global), WOLFIP_IP6_SCOPE_GLOBAL);

    ck_assert_uint_eq(ip6_mcast_flags(&link), 0);
    ck_assert_uint_eq(ip6_mcast_flags(&transient), 1);

    ck_assert_int_eq(ip6_is_mcast_link_local(&link), 1);
    ck_assert_int_eq(ip6_is_mcast_link_local(&site), 0);
    /* A unicast address is never link-local multicast. */
    ck_assert_int_eq(ip6_is_mcast_link_local(&(ip6){{0xfe, 0x80}}), 0);
}
END_TEST

START_TEST(test_ip6_is_all_nodes_and_all_routers)
{
    ip6 nodes = ip6_lit("ff02::1");
    ip6 routers = ip6_lit("ff02::2");
    ip6 other = ip6_lit("ff02::3");
    ip6 wrong_scope = ip6_lit("ff05::1");

    ck_assert_int_eq(ip6_is_all_nodes(&nodes), 1);
    ck_assert_int_eq(ip6_is_all_nodes(&routers), 0);
    ck_assert_int_eq(ip6_is_all_routers(&routers), 1);
    ck_assert_int_eq(ip6_is_all_routers(&nodes), 0);
    ck_assert_int_eq(ip6_is_all_nodes(&other), 0);
    ck_assert_int_eq(ip6_is_all_nodes(&wrong_scope), 0);
}
END_TEST

/* =========================================================================
 * IPv4-mapped and IPv4-compatible ranges
 * ========================================================================= */

START_TEST(test_ip6_v4mapped_roundtrip)
{
    ip6 a;
    ip6 parsed;

    ip6_set_v4mapped(&a, 0x0A0A0A02U); /* 10.10.10.2 */
    ck_assert_int_eq(ip6_is_v4mapped(&a), 1);
    ck_assert_uint_eq(ip6_get_v4mapped(&a), 0x0A0A0A02U);

    /* The literal form must produce the identical byte pattern. */
    parsed = ip6_lit("::ffff:10.10.10.2");
    ck_assert_int_eq(ip6_cmp(&a, &parsed), 0);
}
END_TEST

START_TEST(test_ip6_v4mapped_boundaries)
{
    ip6 prefix = ip6_lit("::ffff:0.0.0.0");
    ip6 broadcast = ip6_lit("::ffff:255.255.255.255");
    ip6 not_mapped = ip6_lit("::fffe:0:0");
    ip6 high_bit_set = ip6_lit("1::ffff:0:0");

    ck_assert_int_eq(ip6_is_v4mapped(&prefix), 1);
    ck_assert_int_eq(ip6_is_v4mapped(&broadcast), 1);
    ck_assert_uint_eq(ip6_get_v4mapped(&broadcast), 0xFFFFFFFFU);
    ck_assert_int_eq(ip6_is_v4mapped(&not_mapped), 0);
    ck_assert_int_eq(ip6_is_v4mapped(&high_bit_set), 0);

    /* :: and ::1 must not be mistaken for the mapped range. */
    ck_assert_int_eq(ip6_is_v4mapped(&(ip6)WOLFIP_IN6ADDR_ANY_INIT), 0);
    ck_assert_int_eq(ip6_is_v4mapped(&(ip6)WOLFIP_IN6ADDR_LOOPBACK_INIT), 0);
}
END_TEST

START_TEST(test_ip6_v4compat_excludes_any_and_loopback)
{
    ip6 compat = ip6_lit("::1.2.3.4");
    ip6 any = ip6_lit("::");
    ip6 lo = ip6_lit("::1");
    ip6 mapped = ip6_lit("::ffff:1.2.3.4");

    ck_assert_int_eq(ip6_is_v4compat(&compat), 1);
    /* :: and ::1 are the unspecified and loopback addresses, not
     * IPv4-compatible addresses, even though they sit in ::/96. */
    ck_assert_int_eq(ip6_is_v4compat(&any), 0);
    ck_assert_int_eq(ip6_is_v4compat(&lo), 0);
    ck_assert_int_eq(ip6_is_v4compat(&mapped), 0);
}
END_TEST

/* =========================================================================
 * Prefix operations
 * ========================================================================= */

START_TEST(test_ip6_prefix_cmp_byte_aligned)
{
    ip6 a = ip6_lit("2001:db8:1:2::5");
    ip6 b = ip6_lit("2001:db8:1:2::9");
    ip6 c = ip6_lit("2001:db8:1:3::5");

    ck_assert_int_eq(ip6_prefix_cmp(&a, &b, 64), 0);
    ck_assert_int_ne(ip6_prefix_cmp(&a, &b, 128), 0);
    ck_assert_int_eq(ip6_prefix_cmp(&a, &c, 48), 0);
    ck_assert_int_ne(ip6_prefix_cmp(&a, &c, 64), 0);
}
END_TEST

START_TEST(test_ip6_prefix_cmp_non_byte_aligned)
{
    /* 2001:0db8 vs 2001:0dbf differ only in the low nibble of byte 3, so
     * they agree on the first 28 bits but not on 32. */
    ip6 a = ip6_lit("2001:db8::1");
    ip6 b = ip6_lit("2001:dbf::2");

    ck_assert_int_eq(ip6_prefix_cmp(&a, &b, 28), 0);
    ck_assert_int_ne(ip6_prefix_cmp(&a, &b, 32), 0);
    /* Bit 29 is the first difference. */
    ck_assert_int_eq(ip6_prefix_cmp(&a, &b, 29), 0);
    ck_assert_int_ne(ip6_prefix_cmp(&a, &b, 30), 0);
}
END_TEST

START_TEST(test_ip6_prefix_cmp_zero_and_clamped)
{
    ip6 a = ip6_lit("2001:db8::1");
    ip6 b = ip6_lit("fe80::abcd");

    /* A zero-length prefix matches everything. */
    ck_assert_int_eq(ip6_prefix_cmp(&a, &b, 0), 0);
    /* Lengths above 128 are clamped rather than reading out of bounds. */
    ck_assert_int_ne(ip6_prefix_cmp(&a, &b, 200), 0);
    ck_assert_int_eq(ip6_prefix_cmp(&a, &a, 255), 0);
}
END_TEST

START_TEST(test_ip6_prefix_mask)
{
    ip6 a = ip6_lit("2001:db8:1:2:3:4:5:6");
    ip6 expect;

    ip6_prefix_mask(&a, 64);
    expect = ip6_lit("2001:db8:1:2::");
    ck_assert_int_eq(ip6_cmp(&a, &expect), 0);

    a = ip6_lit("2001:dbf::1");
    ip6_prefix_mask(&a, 28);
    expect = ip6_lit("2001:db0::");
    ck_assert_int_eq(ip6_cmp(&a, &expect), 0);

    /* /0 clears everything, /128 changes nothing. */
    a = ip6_lit("2001:db8::1");
    ip6_prefix_mask(&a, 0);
    ck_assert_int_eq(ip6_is_unspecified(&a), 1);

    a = ip6_lit("2001:db8::1");
    expect = a;
    ip6_prefix_mask(&a, 128);
    ck_assert_int_eq(ip6_cmp(&a, &expect), 0);
}
END_TEST

START_TEST(test_ip6_prefix_mask_every_length_is_consistent)
{
    unsigned int plen;

    /* For every prefix length, including the non-byte-aligned ones, masking
     * must preserve every bit inside the prefix and clear every bit outside
     * it. Checked bit by bit rather than by comparing whole addresses,
     * because masking is legitimately a no-op when the host part is already
     * zero. */
    for (plen = 0; plen <= 128; plen++) {
        ip6 orig = ip6_lit("2001:db8:aaaa:5555:1234:5678:9abc:def0");
        ip6 masked = orig;
        unsigned int bit;

        ip6_prefix_mask(&masked, (uint8_t)plen);
        ck_assert_int_eq(ip6_prefix_cmp(&orig, &masked, (uint8_t)plen), 0);
        for (bit = 0; bit < 128; bit++) {
            unsigned int got = (masked.addr[bit / 8] >> (7 - (bit % 8))) & 1u;
            unsigned int want = (orig.addr[bit / 8] >> (7 - (bit % 8))) & 1u;

            if (bit >= plen)
                want = 0;
            ck_assert_uint_eq(got, want);
        }
    }
}
END_TEST

START_TEST(test_ip6_prefix_mask_clears_a_set_host_part)
{
    /* The companion to the loop above: when the host part really does carry
     * set bits, masking must visibly change the address. */
    ip6 a = ip6_lit("2001:db8::ffff:ffff:ffff:ffff");
    ip6 before = a;
    ip6 expect = ip6_lit("2001:db8::");

    ip6_prefix_mask(&a, 64);
    ck_assert_int_ne(ip6_cmp(&a, &before), 0);
    ck_assert_int_eq(ip6_cmp(&a, &expect), 0);
}
END_TEST

START_TEST(test_ip6_make_addr_from_prefix_and_iid)
{
    ip6 prefix = ip6_lit("2001:db8:1:2::");
    ip6 iid = ip6_lit("::1122:33ff:fe44:5566");
    ip6 out;
    ip6 expect;

    ip6_make_addr(&out, &prefix, 64, &iid);
    expect = ip6_lit("2001:db8:1:2:1122:33ff:fe44:5566");
    ck_assert_int_eq(ip6_cmp(&out, &expect), 0);
}
END_TEST

START_TEST(test_ip6_make_addr_non_byte_aligned_prefix)
{
    /* A /60 splits byte 7: the top nibble comes from the prefix, the bottom
     * nibble from the interface identifier. */
    ip6 prefix = ip6_lit("2001:db8:1:20::");
    ip6 iid = ip6_lit("::f:1122:33ff:fe44:5566");
    ip6 out;
    ip6 expect;

    ip6_make_addr(&out, &prefix, 60, &iid);
    expect = ip6_lit("2001:db8:1:2f:1122:33ff:fe44:5566");
    ck_assert_int_eq(ip6_cmp(&out, &expect), 0);
}
END_TEST

/* =========================================================================
 * Link layer mapping
 * ========================================================================= */

START_TEST(test_ip6_solicited_node_from_target)
{
    ip6 target = ip6_lit("fe80::11:22ff:fe33:4455");
    ip6 sol;
    ip6 expect;

    ip6_set_solicited_node(&sol, &target);
    expect = ip6_lit("ff02::1:ff33:4455");
    ck_assert_int_eq(ip6_cmp(&sol, &expect), 0);
    ck_assert_int_eq(ip6_is_solicited_node(&sol), 1);
    ck_assert_int_eq(ip6_is_multicast(&sol), 1);
}
END_TEST

START_TEST(test_ip6_solicited_node_depends_only_on_low_24_bits)
{
    ip6 a = ip6_lit("2001:db8::aabb:ccdd");
    ip6 b = ip6_lit("fe80::9999:99bb:ccdd");
    ip6 sa;
    ip6 sb;

    /* Different addresses that share the low 24 bits map to the same
     * solicited-node group - this collision is by design, and the neighbour
     * cache must not assume the mapping is unique. */
    ip6_set_solicited_node(&sa, &a);
    ip6_set_solicited_node(&sb, &b);
    ck_assert_int_eq(ip6_cmp(&sa, &sb), 0);
}
END_TEST

START_TEST(test_ip6_is_solicited_node_rejects_near_misses)
{
    ip6 good = ip6_lit("ff02::1:ff33:4455");
    ip6 wrong_scope = ip6_lit("ff05::1:ff33:4455");
    ip6 wrong_prefix = ip6_lit("ff02::2:ff33:4455");
    ip6 all_nodes = ip6_lit("ff02::1");
    ip6 transient = ip6_lit("ff12::1:ff33:4455");

    ck_assert_int_eq(ip6_is_solicited_node(&good), 1);
    ck_assert_int_eq(ip6_is_solicited_node(&wrong_scope), 0);
    ck_assert_int_eq(ip6_is_solicited_node(&wrong_prefix), 0);
    ck_assert_int_eq(ip6_is_solicited_node(&all_nodes), 0);
    /* Flags must be zero for a solicited-node address. */
    ck_assert_int_eq(ip6_is_solicited_node(&transient), 0);
}
END_TEST

START_TEST(test_ip6_mcast_to_eth_mapping)
{
    ip6 sol = ip6_lit("ff02::1:ff33:4455");
    ip6 nodes = ip6_lit("ff02::1");
    uint8_t mac[6];
    const uint8_t expect_sol[6] = {0x33, 0x33, 0xFF, 0x33, 0x44, 0x55};
    const uint8_t expect_nodes[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};

    ip6_mcast_to_eth(&sol, mac);
    ck_assert_mem_eq(mac, expect_sol, 6);

    ip6_mcast_to_eth(&nodes, mac);
    ck_assert_mem_eq(mac, expect_nodes, 6);
}
END_TEST

START_TEST(test_ip6_iid_from_mac_eui64)
{
    /* RFC 4291 appendix A: 00:1b:21:0a:0b:0c becomes 021b:21ff:fe0a:0b0c,
     * with the universal/local bit inverted. */
    const uint8_t mac[6] = {0x00, 0x1b, 0x21, 0x0a, 0x0b, 0x0c};
    ip6 iid;
    ip6 prefix = ip6_lit("fe80::");
    ip6 out;
    ip6 expect;

    ip6_iid_from_mac(&iid, mac);
    ck_assert_uint_eq(iid.addr[8], 0x02);
    ck_assert_uint_eq(iid.addr[11], 0xFF);
    ck_assert_uint_eq(iid.addr[12], 0xFE);

    ip6_make_addr(&out, &prefix, 64, &iid);
    expect = ip6_lit("fe80::21b:21ff:fe0a:b0c");
    ck_assert_int_eq(ip6_cmp(&out, &expect), 0);
}
END_TEST

START_TEST(test_ip6_iid_from_mac_inverts_ul_bit_both_ways)
{
    const uint8_t local_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    const uint8_t universal_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    ip6 iid;

    /* A locally administered MAC (bit set) yields a cleared bit. */
    ip6_iid_from_mac(&iid, local_mac);
    ck_assert_uint_eq(iid.addr[8], 0x00);
    /* A universal MAC (bit clear) yields a set bit. */
    ip6_iid_from_mac(&iid, universal_mac);
    ck_assert_uint_eq(iid.addr[8], 0x02);
}
END_TEST

/* =========================================================================
 * Text parsing - well formed input
 * ========================================================================= */

START_TEST(test_ip6_parse_canonical_forms)
{
    ip6_check_text("::", "::");
    ip6_check_text("::1", "::1");
    ip6_check_text("1::", "1::");
    ip6_check_text("fe80::1", "fe80::1");
    ip6_check_text("2001:db8::1", "2001:db8::1");
    ip6_check_text("1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8");
    ip6_check_text("ff02::1", "ff02::1");
}
END_TEST

START_TEST(test_ip6_parse_normalises_noncanonical_input)
{
    /* Leading zeros are dropped. */
    ip6_check_text("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1");
    /* Uppercase is normalised to lowercase. */
    ip6_check_text("FE80::ABCD", "fe80::abcd");
    ip6_check_text("2001:DB8::1", "2001:db8::1");
    /* A fully written out zero address compresses. */
    ip6_check_text("0:0:0:0:0:0:0:0", "::");
}
END_TEST

START_TEST(test_ip6_parse_embedded_ipv4)
{
    ip6_check_text("::ffff:1.2.3.4", "::ffff:1.2.3.4");
    ip6_check_text("::ffff:0.0.0.0", "::ffff:0.0.0.0");
    ip6_check_text("::ffff:255.255.255.255", "::ffff:255.255.255.255");
    /* An IPv4-compatible address is not printed in dotted form. */
    ip6_check_text("::1.2.3.4", "::102:304");
    /* The dotted tail is also accepted in a non-compressed literal. */
    ip6_check_text("0:0:0:0:0:ffff:1.2.3.4", "::ffff:1.2.3.4");
}
END_TEST

START_TEST(test_ip6_parse_gap_at_every_position)
{
    /* "::" must work wherever it appears. Each of these elides two or more
     * groups, so the compressed form survives the round trip unchanged. */
    ip6_check_text("::3:4:5:6:7:8", "::3:4:5:6:7:8");
    ip6_check_text("1::4:5:6:7:8", "1::4:5:6:7:8");
    ip6_check_text("1:2::5:6:7:8", "1:2::5:6:7:8");
    ip6_check_text("1:2:3::6:7:8", "1:2:3::6:7:8");
    ip6_check_text("1:2:3:4::7:8", "1:2:3:4::7:8");
    ip6_check_text("1:2:3:4:5::8", "1:2:3:4:5::8");
    ip6_check_text("1:2:3:4:5:6::", "1:2:3:4:5:6::");
}
END_TEST

START_TEST(test_ip6_parse_accepts_single_group_gap_but_writes_it_out)
{
    /* RFC 4291 allows "::" to stand for a single zero group on input, but
     * RFC 5952 section 4.2.2 forbids compressing one group on output. Such
     * literals are therefore accepted and normalised to the expanded form.
     * This asymmetry is deliberate; it is the reason the round-trip tests
     * above use gaps of two or more groups. */
    ip6_check_text("::2:3:4:5:6:7:8", "0:2:3:4:5:6:7:8");
    ip6_check_text("1::3:4:5:6:7:8", "1:0:3:4:5:6:7:8");
    ip6_check_text("1:2::4:5:6:7:8", "1:2:0:4:5:6:7:8");
    ip6_check_text("1:2:3:4:5:6::8", "1:2:3:4:5:6:0:8");
    ip6_check_text("1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:0");
}
END_TEST

/* =========================================================================
 * Text parsing - malformed input must be rejected
 * ========================================================================= */

START_TEST(test_ip6_parse_rejects_malformed)
{
    ip6_check_bad("");
    ip6_check_bad(":");
    ip6_check_bad(":1");           /* single leading colon */
    ip6_check_bad("1:");           /* trailing single colon */
    ip6_check_bad("1:::2");        /* three colons */
    ip6_check_bad("::1::2");       /* two "::" runs */
    ip6_check_bad("1::2::3");
    ip6_check_bad("gg::");         /* non-hex digit */
    ip6_check_bad("12345::");      /* group longer than four digits */
    ip6_check_bad("1:2:3:4:5:6:7:8:9"); /* too many groups */
    ip6_check_bad("1:2:3:4:5:6:7");     /* too few, no "::" */
    ip6_check_bad("1.2.3.4");           /* bare IPv4 is not an IPv6 literal */
}
END_TEST

START_TEST(test_ip6_parse_rejects_gap_that_elides_nothing)
{
    /* "::" must stand for at least one group of zeros, so a literal that
     * already supplies all eight groups may not also contain one. */
    ip6_check_bad("1:2:3:4::5:6:7:8");
}
END_TEST

START_TEST(test_ip6_parse_rejects_bad_ipv4_tail)
{
    ip6_check_bad("::1.2.3");            /* too few octets */
    ip6_check_bad("::1.2.3.4.5");        /* too many octets */
    ip6_check_bad("::ffff:256.1.1.1");   /* octet out of range */
    ip6_check_bad("::ffff:1.2.3.");      /* trailing dot */
    ip6_check_bad("::ffff:1.2.3.4:5");   /* garbage after the quad */
    ip6_check_bad("::ffff:0001.2.3.4");  /* over-long octet */
    ip6_check_bad("1.2.3.4::");
}
END_TEST

START_TEST(test_ip6_parse_rejects_null_arguments)
{
    ip6 a;

    ck_assert_int_eq(atoip6(NULL, &a), -1);
    ck_assert_int_eq(atoip6("::1", NULL), -1);
}
END_TEST

START_TEST(test_ip6_parse_leaves_output_untouched_on_failure)
{
    ip6 a = ip6_lit("2001:db8::1");
    ip6 expect = a;

    ck_assert_int_eq(atoip6("not-an-address", &a), -1);
    /* A rejected parse must not have partially overwritten the caller's
     * address - callers routinely parse into a live configuration slot. */
    ck_assert_int_eq(ip6_cmp(&a, &expect), 0);
}
END_TEST

/* =========================================================================
 * Text rendering - RFC 5952 canonical form
 * ========================================================================= */

START_TEST(test_ip6toa_compresses_longest_zero_run)
{
    /* Two runs of zeros: the longer one must be compressed. */
    ip6_check_text("1:0:0:2:0:0:0:3", "1:0:0:2::3");
    ip6_check_text("1:0:0:0:2:0:0:3", "1::2:0:0:3");
}
END_TEST

START_TEST(test_ip6toa_compresses_leftmost_run_on_tie)
{
    /* Equal length runs: RFC 5952 section 4.2.3 requires the first. */
    ip6_check_text("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1");
    ip6_check_text("1:0:0:2:0:0:3:4", "1::2:0:0:3:4");
}
END_TEST

START_TEST(test_ip6toa_does_not_compress_single_zero_group)
{
    /* RFC 5952 section 4.2.2: a lone zero group is written as "0". */
    ip6_check_text("1:0:2:3:4:5:6:7", "1:0:2:3:4:5:6:7");
    ip6_check_text("1:2:3:4:5:6:0:8", "1:2:3:4:5:6:0:8");
    ip6_check_text("0:1:2:3:4:5:6:7", "0:1:2:3:4:5:6:7");
}
END_TEST

START_TEST(test_ip6toa_run_at_start_and_end)
{
    ip6_check_text("0:0:0:0:0:0:0:1", "::1");
    ip6_check_text("1:0:0:0:0:0:0:0", "1::");
    ip6_check_text("0:1:0:0:0:0:0:0", "0:1::");
    ip6_check_text("0:0:0:0:0:0:1:0", "::1:0");
}
END_TEST

START_TEST(test_ip6toa_handles_null_arguments)
{
    char buf[WOLFIP_IP6_ADDRSTRLEN];

    buf[0] = 'x';
    ip6toa(NULL, buf);
    ck_assert_str_eq(buf, "");
    /* A NULL buffer must simply be ignored rather than dereferenced. */
    ip6toa(&(ip6)WOLFIP_IN6ADDR_LOOPBACK_INIT, NULL);
}
END_TEST

START_TEST(test_ip6toa_never_exceeds_addrstrlen)
{
    /* The longest possible output is the fully expanded mapped form. */
    ip6 widest = ip6_lit("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    ip6 mapped = ip6_lit("::ffff:255.255.255.255");
    char buf[WOLFIP_IP6_ADDRSTRLEN];
    size_t i;
    size_t len = 0;

    ip6toa(&widest, buf);
    while (buf[len] != '\0')
        len++;
    ck_assert_uint_lt(len, (size_t)WOLFIP_IP6_ADDRSTRLEN);

    ip6toa(&mapped, buf);
    len = 0;
    while (buf[len] != '\0')
        len++;
    ck_assert_uint_lt(len, (size_t)WOLFIP_IP6_ADDRSTRLEN);

    /* Every group at maximum width, to confirm the bound is not merely
     * met by the compressed forms above. */
    for (i = 0; i < 16; i++)
        widest.addr[i] = 0xFF;
    ip6toa(&widest, buf);
    len = 0;
    while (buf[len] != '\0')
        len++;
    ck_assert_uint_lt(len, (size_t)WOLFIP_IP6_ADDRSTRLEN);
}
END_TEST

START_TEST(test_ip6_text_roundtrip_is_stable)
{
    static const char *addrs[] = {
        "::", "::1", "1::", "fe80::1", "2001:db8::1",
        "ff02::1", "ff02::1:ff33:4455", "fd12:3456:789a:1::1",
        "1:2:3:4:5:6:7:8", "::ffff:192.168.1.1",
        "2001:db8:0:1:1:1:1:1", "1:0:0:2::3",
    };
    size_t i;

    /* Rendering a parsed address and parsing it again must be a fixed
     * point, for every canonical form. */
    for (i = 0; i < (sizeof(addrs) / sizeof(addrs[0])); i++) {
        char first[WOLFIP_IP6_ADDRSTRLEN];
        char second[WOLFIP_IP6_ADDRSTRLEN];
        ip6 a;
        ip6 b;

        ck_assert_int_eq(atoip6(addrs[i], &a), 0);
        ip6toa(&a, first);
        ck_assert_int_eq(atoip6(first, &b), 0);
        ip6toa(&b, second);
        ck_assert_int_eq(ip6_cmp(&a, &b), 0);
        ck_assert_str_eq(first, second);
    }
}
END_TEST

START_TEST(test_ip6_text_roundtrip_exhaustive_single_bit)
{
    int bit;

    /* Every one of the 128 bits must survive a render/parse round trip.
     * This is the cheapest way to catch a byte-order or shift mistake in
     * either direction. */
    for (bit = 0; bit < 128; bit++) {
        char buf[WOLFIP_IP6_ADDRSTRLEN];
        ip6 a;
        ip6 b;

        ip6_set_unspecified(&a);
        a.addr[bit / 8] = (uint8_t)(1u << (7 - (bit % 8)));
        ip6toa(&a, buf);
        ck_assert_int_eq(atoip6(buf, &b), 0);
        ck_assert_int_eq(ip6_cmp(&a, &b), 0);
    }
}
END_TEST

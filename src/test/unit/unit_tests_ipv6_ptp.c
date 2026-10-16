/* unit_tests_ipv6_ptp.c
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
 * IPv6 over a point-to-point link: an interface with ll->non_ethernet set,
 * which is what linux_tun.c and utun_darwin.c present. Such a link has no
 * link-layer address, which changes three things and nothing else:
 *
 *   1. There is no ethertype, so the version nibble is the whole demux.
 *   2. There is no address to derive an interface identifier from, so one
 *      is generated (or supplied by the application).
 *   3. There is no address to advertise, so the link-layer address options
 *      in Neighbor Discovery are omitted - address resolution is not
 *      performed at all on such a link (RFC 4861 section 3).
 *
 * The frames here carry the same ETH_HEADER_LEN of headroom that
 * poll_devices() reserves before handing the buffer to the driver, because
 * that is the contract the whole stack is written against; the difference
 * is that nothing fills it in and the driver never sees it.
 */

#define PTP_TICK_STEP_MS 50u

/* Advance the clock, polling often enough that the 100ms ND tick fires. */
static void ptp_advance(struct wolfIP *s, uint64_t *now, uint64_t ms)
{
    uint64_t target = *now + ms;

    while (*now < target) {
        *now += PTP_TICK_STEP_MS;
        wolfIP_poll(s, *now);
    }
}

/* A stack whose primary interface is a point-to-point link: no link-layer
 * address, and non_ethernet set the way a tun driver sets it. */
static void ptp_setup(struct wolfIP *s)
{
    struct wolfIP_ll_dev *ll;

    wolfIP_init(s);
    mock_link_init(s);
    ll = wolfIP_getdev_ex(s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);
    memset(ll->mac, 0, sizeof(ll->mac));
    ll->non_ethernet = 1;
    mock_link_capture_reset();
    last_frame_sent_size = 0;
}

/* The one IPv6 address on the interface in a given state, or 0 if none. */
static int ptp_addr_in_state(struct wolfIP *s, uint8_t state,
                             struct wolfIP_ifaddr_info *out)
{
    unsigned int n = wolfIP_ifaddr_count(s, TEST_PRIMARY_IF, AF_INET6);
    unsigned int i;

    for (i = 0; i < n; i++) {
        struct wolfIP_ifaddr_info info;

        if (wolfIP_ifaddr_get(s, TEST_PRIMARY_IF, AF_INET6, i, &info) != 0)
            continue;
        if (info.state != state)
            continue;
        if (out != NULL)
            *out = info;
        return 1;
    }
    return 0;
}

/* A point-to-point driver is handed the packet with no link header, so the
 * captured frame starts at the IP header while every packet accessor
 * expects the stack's headroom in front of it. Re-add it in a staging
 * buffer; indexing behind the capture array would be out of bounds. */
static uint8_t ptp_staged[LINK_MTU + ETH_HEADER_LEN];

static void *ptp_restage(const uint8_t *frame, uint32_t len)
{
    ck_assert_uint_le(len, (uint32_t)LINK_MTU);
    memset(ptp_staged, 0, sizeof(ptp_staged));
    memcpy(ptp_staged + ETH_HEADER_LEN, frame, len);
    return ptp_staged;
}

/* Deliver an ICMPv6 message over the point-to-point link: headroom zeroed,
 * no Ethernet header written, exactly as poll_devices() hands it over. */
static void ptp_deliver_icmp6(struct wolfIP *s, uint8_t *frame,
                              const ip6 *src, const ip6 *dst,
                              uint16_t payload_len, uint8_t hop_limit)
{
    struct wolfIP_icmp6_packet *icmp = (struct wolfIP_icmp6_packet *)frame;
    union transport6_pseudo_header ph;

    memset(frame, 0, ETH_HEADER_LEN);
    ip6_hdr_set_vtf(&icmp->ip6, 0, 0);
    icmp->ip6.payload_len = ee16(payload_len);
    icmp->ip6.next_hdr = IP6_NEXTHDR_ICMPV6;
    icmp->ip6.hop_limit = hop_limit;
    ip6_hdr_set_src(&icmp->ip6, src);
    ip6_hdr_set_dst(&icmp->ip6, dst);
    icmp->csum = 0;
    transport6_pseudo_header_init(&ph, src, dst, payload_len,
                                  IP6_NEXTHDR_ICMPV6);
    icmp->csum = ee16(transport6_checksum(&ph, &icmp->type));
    /* On such an interface wolfIP_recv_ex() takes the bare IP packet and
     * adds the headroom itself, which is what a tun driver hands it. The
     * frame is built with the headroom in front only so the packet
     * accessors above can be used on it. */
    wolfIP_recv_ex(s, TEST_PRIMARY_IF, frame + ETH_HEADER_LEN,
                   (uint32_t)IP6_HEADER_LEN + payload_len);
}

/* =========================================================================
 * 1. Interface identifier: the generated default
 * ========================================================================= */

/* RFC 5453 names three ranges that must never be assigned. The predicate is
 * a pure function of the eight octets, so it is checked directly. */
START_TEST(test_ptp_reserved_iids_are_recognised)
{
    const uint8_t subnet_router[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    const uint8_t iana_low[8]  = {0x02, 0x00, 0x5E, 0xFF, 0xFE, 0x00, 0x00, 0x00};
    const uint8_t iana_high[8] = {0x02, 0x00, 0x5E, 0xFF, 0xFE, 0x00, 0xFF, 0xFF};
    const uint8_t anycast_low[8]  = {0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80};
    const uint8_t anycast_high[8] = {0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    /* One below the reserved subnet anycast range, so still assignable. */
    const uint8_t anycast_below[8] = {0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
    const uint8_t ordinary[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};

    ck_assert_int_eq(ip6_iid_is_reserved(subnet_router), 1);
    ck_assert_int_eq(ip6_iid_is_reserved(iana_low), 1);
    ck_assert_int_eq(ip6_iid_is_reserved(iana_high), 1);
    ck_assert_int_eq(ip6_iid_is_reserved(anycast_low), 1);
    ck_assert_int_eq(ip6_iid_is_reserved(anycast_high), 1);
    ck_assert_int_eq(ip6_iid_is_reserved(anycast_below), 0);
    ck_assert_int_eq(ip6_iid_is_reserved(ordinary), 0);
}
END_TEST

/* With no link-layer address the identifier cannot be a modified EUI-64.
 * The all-zero MAC would otherwise produce fe80::200:ff:fe00:0 on every
 * point-to-point interface of every node, which is the bug this replaces. */
START_TEST(test_ptp_link_local_is_not_derived_from_the_null_mac)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;
    ip6 eui64_from_zero;
    ip6 prefix;
    ip6 iid;
    uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};

    ptp_setup(&s);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);

    ck_assert_int_eq(ptp_addr_in_state(&s, WOLFIP_IFADDR_TENTATIVE, &info), 1);
    ck_assert_int_eq(ip6_is_link_local(&info.v6), 1);

    ck_assert_int_eq(atoip6("fe80::", &prefix), 0);
    ip6_iid_from_mac(&iid, zero_mac);
    ip6_make_addr(&eui64_from_zero, &prefix, 64, &iid);
    ck_assert_int_ne(ip6_cmp(&info.v6, &eui64_from_zero), 0);
}
END_TEST

/* A generated identifier is not derived from a universal IEEE identifier
 * and must not claim to be: the 'u' bit is zero (RFC 7217 section 5). It
 * must also avoid the reserved ranges (RFC 5453). */
START_TEST(test_ptp_generated_iid_has_u_bit_clear_and_is_assignable)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;

    ptp_setup(&s);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    ck_assert_int_eq(ptp_addr_in_state(&s, WOLFIP_IFADDR_TENTATIVE, &info), 1);

    ck_assert_uint_eq(info.v6.addr[8] & 0x02u, 0);
    ck_assert_int_eq(ip6_iid_is_reserved(&info.v6.addr[8]), 0);
}
END_TEST

/* The identifier comes from the random source, so it tracks it. The mock
 * generator is deterministic, which is what makes the expected value
 * computable here rather than merely asserted to be "not the old one". */
START_TEST(test_ptp_generated_iid_comes_from_the_random_source)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;
    uint32_t hi = wolfIP_getrandom();
    uint32_t lo = wolfIP_getrandom();
    uint8_t expect[8];

    expect[0] = (uint8_t)((hi >> 24) & 0xFFu);
    expect[1] = (uint8_t)((hi >> 16) & 0xFFu);
    expect[2] = (uint8_t)((hi >> 8) & 0xFFu);
    expect[3] = (uint8_t)(hi & 0xFFu);
    expect[4] = (uint8_t)((lo >> 24) & 0xFFu);
    expect[5] = (uint8_t)((lo >> 16) & 0xFFu);
    expect[6] = (uint8_t)((lo >> 8) & 0xFFu);
    expect[7] = (uint8_t)(lo & 0xFFu);
    expect[0] &= (uint8_t)~0x02u;
    /* The mock generator never returns a reserved draw; if that ever
     * changes this test is measuring the retry path instead. */
    ck_assert_int_eq(ip6_iid_is_reserved(expect), 0);

    ptp_setup(&s);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    ck_assert_int_eq(ptp_addr_in_state(&s, WOLFIP_IFADDR_TENTATIVE, &info), 1);
    ck_assert_mem_eq(&info.v6.addr[8], expect, 8);
}
END_TEST

/* A generator stuck at zero draws the Subnet-Router anycast identifier every
 * time. Assigning it would be a protocol violation, so the retries give up
 * and fall back to something assignable rather than honouring the draw. */
START_TEST(test_ptp_stuck_random_source_does_not_yield_a_reserved_iid)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;

    test_rand_override_enabled = 1;
    test_rand_override_value = 0;

    ptp_setup(&s);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    ck_assert_int_eq(ptp_addr_in_state(&s, WOLFIP_IFADDR_TENTATIVE, &info), 1);

    test_rand_override_enabled = 0;

    ck_assert_int_eq(ip6_iid_is_reserved(&info.v6.addr[8]), 0);
    ck_assert_uint_eq(info.v6.addr[8] & 0x02u, 0);
}
END_TEST

/* Every address on the interface shares one identifier: the link-local one
 * and anything SLAAC forms from an advertised prefix. Drawing twice would
 * put two unrelated identifiers on one interface. */
START_TEST(test_ptp_slaac_address_shares_the_link_local_iid)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    struct nd6_ra_msg *ra = (struct nd6_ra_msg *)frame;
    struct nd6_opt_prefix *po;
    struct wolfIP_ifaddr_info info;
    uint64_t now = 0;
    ip6 src;
    ip6 dst;
    ip6 prefix;
    ip6 link_local;
    unsigned int n;
    unsigned int i;
    int found = 0;

    ptp_setup(&s);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    /* Let duplicate address detection finish, so the link-local address is
     * usable and the advertisement is acted on. */
    ptp_advance(&s, &now, 3000u);
    ck_assert_int_eq(ptp_addr_in_state(&s, WOLFIP_IFADDR_PREFERRED, &info), 1);
    ip6_copy(&link_local, &info.v6);

    memset(frame, 0, sizeof(frame));
    ck_assert_int_eq(atoip6("fe80::1", &src), 0);
    ip6_set_all_nodes(&dst);
    ck_assert_int_eq(atoip6("2001:db8::", &prefix), 0);
    ra->type = ICMP6_ROUTER_ADVERT;
    ra->code = 0;
    ra->cur_hop_limit = 64;
    ra->router_lifetime = ee16(1800);
    po = (struct nd6_opt_prefix *)ra->options;
    po->type = ND6_OPT_PREFIX;
    po->len = 4;
    po->prefix_len = 64;
    po->flags = ND6_PREFIX_ONLINK | ND6_PREFIX_AUTO;
    po->valid_lifetime = ee32(3600);
    po->preferred_lifetime = ee32(3600);
    memcpy(po->prefix, prefix.addr, 16);
    ptp_deliver_icmp6(&s, frame, &src, &dst, (uint16_t)(16u + 32u), 255);

    n = wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6);
    for (i = 0; i < n; i++) {
        if (wolfIP_ifaddr_get(&s, TEST_PRIMARY_IF, AF_INET6, i, &info) != 0)
            continue;
        if (ip6_is_link_local(&info.v6))
            continue;
        found = 1;
        ck_assert_mem_eq(&info.v6.addr[8], &link_local.addr[8], 8);
    }
    ck_assert_int_eq(found, 1);
}
END_TEST

/* =========================================================================
 * 2. Interface identifier: the application override
 * ========================================================================= */

#if WOLFIP_IPV6_IID_OVERRIDE

/* The whole point of the override: an identifier the application chose -
 * an RFC 7217 one, or one restored from storage - is the one that lands in
 * the address. */
START_TEST(test_ptp_iid_override_is_used_for_the_link_local_address)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;
    const uint8_t iid[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};

    ptp_setup(&s);
    ck_assert_int_eq(wolfIP_ipv6_set_iid(&s, TEST_PRIMARY_IF, iid), 0);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);

    ck_assert_int_eq(ptp_addr_in_state(&s, WOLFIP_IFADDR_TENTATIVE, &info), 1);
    ck_assert_int_eq(ip6_is_link_local(&info.v6), 1);
    ck_assert_mem_eq(&info.v6.addr[8], iid, 8);
}
END_TEST

/* Reading back is how an application persists a generated identifier for
 * the next boot, so it has to answer before any address exists and it has
 * to agree with the address that is then formed. */
START_TEST(test_ptp_get_iid_reads_back_what_will_be_used)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;
    uint8_t read_back[8];

    ptp_setup(&s);
    ck_assert_int_eq(wolfIP_ipv6_get_iid(&s, TEST_PRIMARY_IF, read_back), 0);
    ck_assert_int_eq(ip6_iid_is_reserved(read_back), 0);

    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    ck_assert_int_eq(ptp_addr_in_state(&s, WOLFIP_IFADDR_TENTATIVE, &info), 1);
    ck_assert_mem_eq(&info.v6.addr[8], read_back, 8);
}
END_TEST

/* An identifier restored from storage reproduces the address it produced
 * last time, which is the property the whole override exists for. */
START_TEST(test_ptp_restored_iid_reproduces_the_previous_address)
{
    struct wolfIP first;
    struct wolfIP second;
    struct wolfIP_ifaddr_info a;
    struct wolfIP_ifaddr_info b;
    uint8_t saved[8];

    ptp_setup(&first);
    ck_assert_int_eq(wolfIP_ipv6_get_iid(&first, TEST_PRIMARY_IF, saved), 0);
    ck_assert_int_eq(wolfIP_ipv6_start(&first, TEST_PRIMARY_IF), 0);
    ck_assert_int_eq(ptp_addr_in_state(&first, WOLFIP_IFADDR_TENTATIVE, &a), 1);

    /* A fresh stack, as after a reboot, handed the stored identifier. */
    ptp_setup(&second);
    ck_assert_int_eq(wolfIP_ipv6_set_iid(&second, TEST_PRIMARY_IF, saved), 0);
    ck_assert_int_eq(wolfIP_ipv6_start(&second, TEST_PRIMARY_IF), 0);
    ck_assert_int_eq(ptp_addr_in_state(&second, WOLFIP_IFADDR_TENTATIVE, &b), 1);

    ck_assert_int_eq(ip6_cmp(&a.v6, &b.v6), 0);
}
END_TEST

/* Refused rather than silently corrected: an RFC 7217 generator is required
 * to redraw on a reserved value, and would never learn that it must. */
START_TEST(test_ptp_iid_override_refuses_reserved_identifiers)
{
    struct wolfIP s;
    const uint8_t subnet_router[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    const uint8_t anycast[8] = {0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80};
    const uint8_t good[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};

    ptp_setup(&s);
    ck_assert_int_lt(wolfIP_ipv6_set_iid(&s, TEST_PRIMARY_IF, subnet_router), 0);
    ck_assert_int_lt(wolfIP_ipv6_set_iid(&s, TEST_PRIMARY_IF, anycast), 0);
    ck_assert_int_lt(wolfIP_ipv6_set_iid(&s, TEST_PRIMARY_IF, NULL), 0);
    ck_assert_int_lt(wolfIP_ipv6_set_iid(&s, WOLFIP_MAX_INTERFACES, good), 0);
    ck_assert_int_lt(wolfIP_ipv6_set_iid(NULL, TEST_PRIMARY_IF, good), 0);
    /* A valid one still works after the refusals. */
    ck_assert_int_eq(wolfIP_ipv6_set_iid(&s, TEST_PRIMARY_IF, good), 0);
}
END_TEST

#else /* !WOLFIP_IPV6_IID_OVERRIDE */

/* Compiled out, but still linkable: a consumer gets a run-time answer
 * rather than an undefined symbol. */
START_TEST(test_ptp_iid_override_reports_not_implemented)
{
    struct wolfIP s;
    const uint8_t iid[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    uint8_t read_back[8];

    ptp_setup(&s);
    ck_assert_int_eq(wolfIP_ipv6_set_iid(&s, TEST_PRIMARY_IF, iid),
                     -WOLFIP_ENOSYS);
    ck_assert_int_eq(wolfIP_ipv6_get_iid(&s, TEST_PRIMARY_IF, read_back),
                     -WOLFIP_ENOSYS);
}
END_TEST

#endif /* WOLFIP_IPV6_IID_OVERRIDE */

/* =========================================================================
 * 3. Ingress demux: the version nibble is all there is
 * ========================================================================= */

/* The routing check. An Echo Request arriving with no link header at all is
 * answered, and the reply goes out as a bare IPv6 packet: the stack's
 * headroom is stripped before the driver sees it. */
START_TEST(test_ptp_icmp6_echo_request_is_answered)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    struct wolfIP_icmp6_packet *icmp = (struct wolfIP_icmp6_packet *)frame;
    struct wolfIP_icmp6_packet *reply;
    struct wolfIP_ifaddr_info info;
    uint64_t now = 0;
    uint16_t payload_len = 12; /* header + identifier/sequence + 4 bytes */
    ip6 peer;
    ip6 got_src;
    ip6 got_dst;

    ptp_setup(&s);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    ptp_advance(&s, &now, 3000u);
    ck_assert_int_eq(ptp_addr_in_state(&s, WOLFIP_IFADDR_PREFERRED, &info), 1);

    ck_assert_int_eq(atoip6("fe80::1", &peer), 0);
    memset(frame, 0, sizeof(frame));
    icmp->type = ICMP6_ECHO_REQUEST;
    icmp->code = 0;
    mock_link_capture_reset();
    ptp_deliver_icmp6(&s, frame, &peer, &info.v6, payload_len, 64);

    /* One frame out, and it is the bare IPv6 packet: wolfIP_ll_send_frame()
     * hands the driver buf+ETH_HEADER_LEN on such a link, so the length
     * carries no link header. */
    ck_assert_uint_eq(last_frame_sent_size,
                      (uint32_t)IP6_HEADER_LEN + payload_len);
    ck_assert_uint_eq((uint32_t)(last_frame_sent[0] >> 4), 6u);

    /* Read the reply back through the same headroom convention the stack
     * uses, so the header accessors line up. */
    reply = (struct wolfIP_icmp6_packet *)ptp_restage(last_frame_sent,
                                                     last_frame_sent_size);
    ck_assert_uint_eq(reply->type, ICMP6_ECHO_REPLY);
    ck_assert_uint_eq(reply->code, 0);
    ip6_hdr_get_src(&reply->ip6, &got_src);
    ip6_hdr_get_dst(&reply->ip6, &got_dst);
    ck_assert_int_eq(ip6_cmp(&got_src, &info.v6), 0);
    ck_assert_int_eq(ip6_cmp(&got_dst, &peer), 0);
}
END_TEST

/* The version switch must not have cost IPv4 its path on the same link. */
START_TEST(test_ptp_ipv4_still_reaches_the_v4_path)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    struct wolfIP_icmp_packet *icmp = (struct wolfIP_icmp_packet *)frame;
    struct wolfIP_ip_packet *reply;
    uint32_t total_len = (uint32_t)IP_HEADER_LEN + 8u;

    ptp_setup(&s);
    wolfIP_ipconfig_set_ex(&s, TEST_PRIMARY_IF, atoip4("10.0.0.2"),
                           atoip4("255.255.255.0"), atoip4("10.0.0.1"));

    memset(frame, 0, sizeof(frame));
    icmp->ip.ver_ihl = 0x45;
    icmp->ip.tos = 0;
    icmp->ip.len = ee16((uint16_t)total_len);
    icmp->ip.id = 0;
    icmp->ip.flags_fo = 0;
    icmp->ip.ttl = 64;
    icmp->ip.proto = WI_IPPROTO_ICMP;
    icmp->ip.src = ee32(atoip4("10.0.0.1"));
    icmp->ip.dst = ee32(atoip4("10.0.0.2"));
    iphdr_set_checksum(&icmp->ip);
    icmp->type = ICMP_ECHO_REQUEST;
    icmp->code = 0;
    icmp->csum = 0;
    icmp->csum = ee16(icmp_checksum(icmp, (uint16_t)(total_len - IP_HEADER_LEN)));

    mock_link_capture_reset();
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame + ETH_HEADER_LEN, total_len);

    ck_assert_uint_eq(last_frame_sent_size, total_len);
    reply = (struct wolfIP_ip_packet *)ptp_restage(last_frame_sent,
                                                   last_frame_sent_size);
    ck_assert_uint_eq((uint32_t)(reply->ver_ihl >> 4), 4u);
    ck_assert_uint_eq(((struct wolfIP_icmp_packet *)reply)->type,
                      ICMP_ECHO_REPLY);
}
END_TEST

/* Anything that is not IP has nowhere to go on a link with no ethertype.
 * Dropping it is the only option; crashing on it is not. */
START_TEST(test_ptp_non_ip_version_nibble_is_dropped)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];

    ptp_setup(&s);
    memset(frame, 0, sizeof(frame));
    frame[0] = 0x50; /* version 5 */
    mock_link_capture_reset();
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, 40u);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    /* An empty read from the driver must not be dereferenced either. */
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, 0);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

/* =========================================================================
 * 4. Neighbor Discovery without link-layer addresses
 * ========================================================================= */

/* RFC 4861 section 4.6.1: the option carries the sender's link-layer
 * address, so on a link with none there is nothing to put in it. Sending it
 * anyway would advertise six zero bytes as an address. */
START_TEST(test_ptp_router_solicitation_carries_no_source_lla)
{
    struct wolfIP s;
    struct nd6_rs_msg *rs;
    uint64_t now = 0;
    uint32_t i;
    int seen = 0;

    ptp_setup(&s);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    /* Past duplicate address detection, so the solicitation has a source
     * address and would carry the option on an Ethernet link. */
    ptp_advance(&s, &now, 5000u);

    for (i = 0; i < mock_sent_frames_count; i++) {
        rs = (struct nd6_rs_msg *)ptp_restage(mock_sent_frames[i],
                                              mock_sent_frames_size[i]);
        if (rs->type != ICMP6_ROUTER_SOLICIT)
            continue;
        seen = 1;
        /* 8 octets of Router Solicitation and no option after it. */
        ck_assert_uint_eq(ee16(rs->ip6.payload_len), 8u);
        ck_assert_uint_eq(mock_sent_frames_size[i],
                          (uint32_t)IP6_HEADER_LEN + 8u);
    }
    ck_assert_int_eq(seen, 1);
}
END_TEST

/* Duplicate address detection still runs: one probe, and it is answered by
 * the peer claiming the address, so the address is abandoned. That the
 * probe carries no link-layer address option is required on any link (RFC
 * 4861 section 4.3), so what this pins is that the link still works. */
START_TEST(test_ptp_dad_still_detects_a_duplicate)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;
    uint8_t frame[LINK_MTU];
    struct nd6_msg *na = (struct nd6_msg *)frame;
    uint64_t now = 0;
    ip6 peer;
    ip6 all_nodes;
    ip6 tentative;

    ptp_setup(&s);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    ck_assert_int_eq(ptp_addr_in_state(&s, WOLFIP_IFADDR_TENTATIVE, &info), 1);
    ip6_copy(&tentative, &info.v6);

    /* Somebody else already has it. */
    ck_assert_int_eq(atoip6("fe80::1", &peer), 0);
    ip6_set_all_nodes(&all_nodes);
    memset(frame, 0, sizeof(frame));
    na->type = ICMP6_NEIGHBOR_ADVERT;
    na->code = 0;
    na->flags = ND6_NA_OVERRIDE;
    memcpy(na->target, tentative.addr, 16);
    ptp_deliver_icmp6(&s, frame, &peer, &all_nodes, 24u, 255);

    ptp_advance(&s, &now, 3000u);
    ck_assert_int_eq(ptp_addr_in_state(&s, WOLFIP_IFADDR_PREFERRED, NULL), 0);
}
END_TEST

/* A solicitation for our address is still answered - the advertisement is
 * what fails somebody else's duplicate address detection - but it carries
 * no Target Link-Layer Address option, because there is no address to put
 * in one and resolution is not performed on such a link (RFC 4861 s3). */
START_TEST(test_ptp_solicitation_is_answered_without_a_target_lla)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;
    uint8_t frame[LINK_MTU];
    struct nd6_msg *ns = (struct nd6_msg *)frame;
    struct nd6_msg *na;
    uint64_t now = 0;
    ip6 peer;

    ptp_setup(&s);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    ptp_advance(&s, &now, 3000u);
    ck_assert_int_eq(ptp_addr_in_state(&s, WOLFIP_IFADDR_PREFERRED, &info), 1);

    ck_assert_int_eq(atoip6("fe80::1", &peer), 0);
    memset(frame, 0, sizeof(frame));
    ns->type = ICMP6_NEIGHBOR_SOLICIT;
    ns->code = 0;
    memcpy(ns->target, info.v6.addr, 16);
    mock_link_capture_reset();
    ptp_deliver_icmp6(&s, frame, &peer, &info.v6, 24u, 255);

    ck_assert_uint_eq(last_frame_sent_size, (uint32_t)IP6_HEADER_LEN + 24u);
    na = (struct nd6_msg *)ptp_restage(last_frame_sent, last_frame_sent_size);
    ck_assert_uint_eq(na->type, ICMP6_NEIGHBOR_ADVERT);
    ck_assert_uint_eq(ee16(na->ip6.payload_len), 24u);
    ck_assert_int_eq(memcmp(na->target, info.v6.addr, 16), 0);
}
END_TEST

/* A peer that wrongly includes a Source Link-Layer Address option is still
 * answered. There is no frame header to cross-check it against, so the
 * Ethernet rule that a mismatch is a forgery cannot apply; ignoring the
 * option is the only reading that leaves the link working. */
START_TEST(test_ptp_solicitation_with_a_stray_source_lla_is_still_answered)
{
    struct wolfIP s;
    struct wolfIP_ifaddr_info info;
    uint8_t frame[LINK_MTU];
    struct nd6_msg *ns = (struct nd6_msg *)frame;
    struct nd6_opt_lla *opt;
    struct nd6_msg *na;
    const uint8_t stray[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    uint64_t now = 0;
    ip6 peer;

    ptp_setup(&s);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    ptp_advance(&s, &now, 3000u);
    ck_assert_int_eq(ptp_addr_in_state(&s, WOLFIP_IFADDR_PREFERRED, &info), 1);

    ck_assert_int_eq(atoip6("fe80::1", &peer), 0);
    memset(frame, 0, sizeof(frame));
    ns->type = ICMP6_NEIGHBOR_SOLICIT;
    ns->code = 0;
    memcpy(ns->target, info.v6.addr, 16);
    opt = (struct nd6_opt_lla *)ns->options;
    opt->type = ND6_OPT_SLLA;
    opt->len = 1;
    memcpy(opt->mac, stray, 6);
    mock_link_capture_reset();
    ptp_deliver_icmp6(&s, frame, &peer, &info.v6, (uint16_t)(24u + 8u), 255);

    na = (struct nd6_msg *)ptp_restage(last_frame_sent, last_frame_sent_size);
    ck_assert_uint_eq(last_frame_sent_size, (uint32_t)IP6_HEADER_LEN + 24u);
    ck_assert_uint_eq(na->type, ICMP6_NEIGHBOR_ADVERT);
}
END_TEST

#endif /* WOLFIP_IPV6 */

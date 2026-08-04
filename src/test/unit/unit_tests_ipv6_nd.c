/* unit_tests_ipv6_nd.c
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
 * Neighbor Discovery (RFC 4861) and duplicate address detection
 * (RFC 4862 section 5.4).
 *
 * Five scenarios, in the order they matter operationally:
 *   1. joining a network from cold
 *   2. neighbour advertisements, the ones to accept and the ones to refuse
 *   3. duplicate address detection, both outcomes
 *   4. router advertisements, enough for an ordinary site network
 *   5. a statically assigned ULA alongside all of it
 *
 * Everything is driven through the real ingress path with wolfIP_recv_ex()
 * and observed through the frames the stack actually transmits, plus the
 * public address list. Time advances by explicit wolfIP_poll() calls, so
 * the periodic ND tick is deterministic.
 */

#define ND_TICK_STEP_MS 50u

static const uint8_t nd_peer_mac[6]   = {0x02, 0xAA, 0x00, 0x00, 0x00, 0x01};
static const uint8_t nd_router_mac[6] = {0x02, 0xBB, 0x00, 0x00, 0x00, 0x01};
static const uint8_t nd_other_mac[6]  = {0x02, 0xCC, 0x00, 0x00, 0x00, 0x01};

/* Advance the clock, polling often enough that the 100ms ND tick fires. */
static void nd_advance(struct wolfIP *s, uint64_t *now, uint64_t ms)
{
    uint64_t target = *now + ms;

    while (*now < target) {
        *now += ND_TICK_STEP_MS;
        wolfIP_poll(s, *now);
    }
}

/* The stack's own link-local address, as wolfIP_ipv6_start() forms it. */
static void nd_our_link_local(struct wolfIP *s, ip6 *out)
{
    struct wolfIP_ll_dev *ll = wolfIP_getdev_ex(s, TEST_PRIMARY_IF);
    ip6 prefix;
    ip6 iid;

    ck_assert_ptr_nonnull(ll);
    ck_assert_int_eq(atoip6("fe80::", &prefix), 0);
    ip6_iid_from_mac(&iid, ll->mac);
    ip6_make_addr(out, &prefix, 64, &iid);
}

/* State of an address in the interface list, or -1 if it is not there. */
static int nd_addr_state(struct wolfIP *s, const ip6 *addr)
{
    struct wolfIP_ifaddr_info info;
    unsigned int n = wolfIP_ifaddr_count(s, TEST_PRIMARY_IF, AF_INET6);
    unsigned int i;

    for (i = 0; i < n; i++) {
        if (wolfIP_ifaddr_get(s, TEST_PRIMARY_IF, AF_INET6, i, &info) != 0)
            continue;
        if (ip6_cmp(&info.v6, addr) == 0)
            return (int)info.state;
    }
    return -1;
}

static struct wolfIP_icmp6_packet *nd_sent(void)
{
    if (last_frame_sent_size == 0)
        return NULL;
    return (struct wolfIP_icmp6_packet *)last_frame_sent;
}

/* Finish an ICMPv6 frame: checksum it and hand it to the stack. */
static void nd_deliver(struct wolfIP *s, uint8_t *frame, const ip6 *src,
                       const ip6 *dst, uint16_t payload_len,
                       uint8_t hop_limit, const uint8_t *src_mac)
{
    struct wolfIP_icmp6_packet *icmp = (struct wolfIP_icmp6_packet *)frame;
    struct wolfIP_ll_dev *ll = wolfIP_getdev_ex(s, TEST_PRIMARY_IF);
    union transport6_pseudo_header ph;

    ck_assert_ptr_nonnull(ll);
    if (ip6_is_multicast(dst))
        ip6_mcast_to_eth(dst, icmp->ip6.eth.dst);
    else
        memcpy(icmp->ip6.eth.dst, ll->mac, 6);
    memcpy(icmp->ip6.eth.src, src_mac, 6);
    icmp->ip6.eth.type = ee16(ETH_TYPE_IPV6);
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
    wolfIP_recv_ex(s, TEST_PRIMARY_IF, frame,
                   (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN) + payload_len);
}

/* Neighbor Solicitation. `lla` may be NULL to omit the option, which is what
 * a duplicate-address-detection probe looks like. */
static void nd_send_ns(struct wolfIP *s, const ip6 *src, const ip6 *dst,
                       const ip6 *target, const uint8_t *lla,
                       uint8_t hop_limit, const uint8_t *src_mac)
{
    uint8_t frame[LINK_MTU];
    struct nd6_msg *ns = (struct nd6_msg *)frame;
    uint16_t payload_len = 24;

    memset(frame, 0, sizeof(frame));
    ns->type = ICMP6_NEIGHBOR_SOLICIT;
    ns->code = 0;
    memcpy(ns->target, target->addr, 16);
    if (lla != NULL) {
        struct nd6_opt_lla *opt = (struct nd6_opt_lla *)ns->options;

        opt->type = ND6_OPT_SLLA;
        opt->len = 1;
        memcpy(opt->mac, lla, 6);
        payload_len = (uint16_t)(payload_len + 8u);
    }
    nd_deliver(s, frame, src, dst, payload_len, hop_limit, src_mac);
}

/* Neighbor Advertisement. */
static void nd_send_na(struct wolfIP *s, const ip6 *src, const ip6 *dst,
                       const ip6 *target, uint8_t flags, const uint8_t *tlla,
                       uint8_t hop_limit, const uint8_t *src_mac)
{
    uint8_t frame[LINK_MTU];
    struct nd6_msg *na = (struct nd6_msg *)frame;
    uint16_t payload_len = 24;

    memset(frame, 0, sizeof(frame));
    na->type = ICMP6_NEIGHBOR_ADVERT;
    na->code = 0;
    na->flags = flags;
    memcpy(na->target, target->addr, 16);
    if (tlla != NULL) {
        struct nd6_opt_lla *opt = (struct nd6_opt_lla *)na->options;

        opt->type = ND6_OPT_TLLA;
        opt->len = 1;
        memcpy(opt->mac, tlla, 6);
        payload_len = (uint16_t)(payload_len + 8u);
    }
    nd_deliver(s, frame, src, dst, payload_len, hop_limit, src_mac);
}

/* Router Advertisement with at most one Prefix Information option. Pass
 * prefix_str NULL for an advertisement carrying no prefix. */
static void nd_send_ra(struct wolfIP *s, const char *src_str,
                       uint16_t router_lifetime, const char *prefix_str,
                       uint8_t prefix_len, uint8_t pio_flags,
                       uint32_t valid, uint8_t hop_limit)
{
    uint8_t frame[LINK_MTU];
    struct nd6_ra_msg *ra = (struct nd6_ra_msg *)frame;
    uint16_t payload_len = 16;
    ip6 src;
    ip6 dst;

    memset(frame, 0, sizeof(frame));
    ck_assert_int_eq(atoip6(src_str, &src), 0);
    ip6_set_all_nodes(&dst);
    ra->type = ICMP6_ROUTER_ADVERT;
    ra->code = 0;
    ra->cur_hop_limit = 64;
    ra->flags = 0;
    ra->router_lifetime = ee16(router_lifetime);
    if (prefix_str != NULL) {
        struct nd6_opt_prefix *po = (struct nd6_opt_prefix *)ra->options;
        ip6 prefix;

        ck_assert_int_eq(atoip6(prefix_str, &prefix), 0);
        po->type = ND6_OPT_PREFIX;
        po->len = 4; /* 32 octets */
        po->prefix_len = prefix_len;
        po->flags = pio_flags;
        po->valid_lifetime = ee32(valid);
        po->preferred_lifetime = ee32(valid);
        memcpy(po->prefix, prefix.addr, 16);
        payload_len = (uint16_t)(payload_len + 32u);
    }
    nd_deliver(s, frame, &src, &dst, payload_len, hop_limit, nd_router_mac);
}

static void nd_setup(struct wolfIP *s)
{
    wolfIP_init(s);
    mock_link_init(s);
    last_frame_sent_size = 0;
}

/* =========================================================================
 * 1. Joining a network
 * ========================================================================= */

START_TEST(test_nd_join_forms_link_local_and_probes_it)
{
    struct wolfIP s;
    struct nd6_msg *ns;
    uint64_t now = 1000;
    ip6 ll6;
    ip6 solicited;
    ip6 got;
    ip6 target;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);

    /* RFC 4862 section 5.3: the link-local address exists immediately but is
     * tentative, so nothing may use it yet. */
    nd_our_link_local(&s, &ll6);
    ck_assert_int_eq(nd_addr_state(&s, &ll6), WOLFIP_IFADDR_TENTATIVE);

    /* The first tick sends the duplicate address detection probe. */
    last_frame_sent_size = 0;
    nd_advance(&s, &now, 200);
    ck_assert_ptr_nonnull(nd_sent());
    ns = (struct nd6_msg *)last_frame_sent;
    ck_assert_uint_eq(ns->type, ICMP6_NEIGHBOR_SOLICIT);
    ck_assert_uint_eq(ns->code, 0);

    /* RFC 4861 section 7.1.1: hop limit 255, which is what keeps Neighbor
     * Discovery on the local link. */
    ck_assert_uint_eq(ns->ip6.hop_limit, 255);
    /* RFC 4862 section 5.4.2: source is the unspecified address... */
    ip6_hdr_get_src(&ns->ip6, &got);
    ck_assert_int_eq(ip6_is_unspecified(&got), 1);
    /* ...and the destination is the target's solicited-node group. */
    ip6_set_solicited_node(&solicited, &ll6);
    ip6_hdr_get_dst(&ns->ip6, &got);
    ck_assert_int_eq(ip6_cmp(&got, &solicited), 0);
    memcpy(target.addr, ns->target, 16);
    ck_assert_int_eq(ip6_cmp(&target, &ll6), 0);
    /* 33:33:ff:xx:xx:xx, the multicast mapping of that group. */
    ck_assert_uint_eq(ns->ip6.eth.dst[0], 0x33);
    ck_assert_uint_eq(ns->ip6.eth.dst[1], 0x33);
    ck_assert_uint_eq(ns->ip6.eth.dst[2], 0xFF);

    /* RFC 4861 section 4.3: no Source Link-Layer Address option is allowed
     * when the source is unspecified - there is no address to advertise. */
    ck_assert_uint_eq(ee16(ns->ip6.payload_len), 24);
}
END_TEST

START_TEST(test_nd_join_completes_and_solicits_routers)
{
    struct wolfIP s;
    uint64_t now = 1000;
    ip6 ll6;
    ip6 all_routers;
    ip6 got;
    int saw_rs = 0;
    int i;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_our_link_local(&s, &ll6);

    /* Nobody objects, so after the retransmit interval the address is ours
     * (RFC 4862 section 5.4.4). */
    nd_advance(&s, &now, 1500);
    ck_assert_int_eq(nd_addr_state(&s, &ll6), WOLFIP_IFADDR_PREFERRED);

    /* With a usable source address the stack solicits routers. */
    ip6_set_all_routers(&all_routers);
    for (i = 0; i < 40; i++) {
        last_frame_sent_size = 0;
        nd_advance(&s, &now, 100);
        if ((last_frame_sent_size > 0) &&
                (((struct nd6_msg *)last_frame_sent)->type ==
                 ICMP6_ROUTER_SOLICIT)) {
            struct nd6_rs_msg *rs = (struct nd6_rs_msg *)last_frame_sent;

            ip6_hdr_get_dst(&rs->ip6, &got);
            ck_assert_int_eq(ip6_cmp(&got, &all_routers), 0);
            ck_assert_uint_eq(rs->ip6.hop_limit, 255);
            /* Sourced from the link-local address, so it carries a Source
             * Link-Layer Address option. */
            ip6_hdr_get_src(&rs->ip6, &got);
            ck_assert_int_eq(ip6_cmp(&got, &ll6), 0);
            ck_assert_uint_eq(ee16(rs->ip6.payload_len), 16);
            saw_rs = 1;
            break;
        }
    }
    ck_assert_int_eq(saw_rs, 1);
}
END_TEST

/* =========================================================================
 * 2. Neighbor advertisements, good and bad
 * ========================================================================= */

START_TEST(test_nd_na_resolves_an_incomplete_entry)
{
    struct wolfIP s;
    uint64_t now = 1000;
    uint8_t mac[6];
    ip6 ll6;
    ip6 peer;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_advance(&s, &now, 1500);
    nd_our_link_local(&s, &ll6);
    ck_assert_int_eq(atoip6("fe80::2", &peer), 0);

    /* Unresolved to begin with. */
    ck_assert_int_lt(wolfIP_nd6_lookup(&s, TEST_PRIMARY_IF, &peer, mac), 0);
    (void)nd6_store_neighbor(&s, TEST_PRIMARY_IF, &peer, NULL,
                             ND6_INCOMPLETE, 0);
    ck_assert_int_lt(wolfIP_nd6_lookup(&s, TEST_PRIMARY_IF, &peer, mac), 0);

    /* A solicited advertisement with a target link-layer address answers it. */
    nd_send_na(&s, &peer, &ll6, &peer,
               ND6_NA_SOLICITED | ND6_NA_OVERRIDE, nd_peer_mac, 255,
               nd_peer_mac);
    ck_assert_int_eq(wolfIP_nd6_lookup(&s, TEST_PRIMARY_IF, &peer, mac), 0);
    ck_assert_mem_eq(mac, nd_peer_mac, 6);
    ck_assert_int_eq(s.nd6.neighbors[nd6_neighbor_index(&s, TEST_PRIMARY_IF,
                                                        &peer)].state,
                     ND6_REACHABLE);
}
END_TEST

START_TEST(test_nd_na_without_target_lla_resolves_nothing)
{
    struct wolfIP s;
    uint64_t now = 1000;
    uint8_t mac[6];
    ip6 ll6;
    ip6 peer;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_advance(&s, &now, 1500);
    nd_our_link_local(&s, &ll6);
    ck_assert_int_eq(atoip6("fe80::2", &peer), 0);
    (void)nd6_store_neighbor(&s, TEST_PRIMARY_IF, &peer, NULL,
                             ND6_INCOMPLETE, 0);

    /* Nothing has been learned, so the entry must stay unresolved rather
     * than become reachable with a garbage address. */
    nd_send_na(&s, &peer, &ll6, &peer, ND6_NA_SOLICITED, NULL, 255,
               nd_peer_mac);
    ck_assert_int_lt(wolfIP_nd6_lookup(&s, TEST_PRIMARY_IF, &peer, mac), 0);
}
END_TEST

START_TEST(test_nd_na_without_override_may_not_replace_a_known_mac)
{
    struct wolfIP s;
    uint64_t now = 1000;
    uint8_t mac[6];
    ip6 ll6;
    ip6 peer;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_advance(&s, &now, 1500);
    nd_our_link_local(&s, &ll6);
    ck_assert_int_eq(atoip6("fe80::2", &peer), 0);
    ck_assert_int_eq(wolfIP_nd6_neighbor_add(&s, TEST_PRIMARY_IF, &peer,
                                             nd_peer_mac), 0);

    /* RFC 4861 section 7.2.5: without the Override flag, a different
     * link-layer address must not replace the one already held. This is
     * what stops an advertisement hijacking an established neighbour. */
    nd_send_na(&s, &peer, &ll6, &peer, ND6_NA_SOLICITED, nd_other_mac, 255,
               nd_other_mac);
    ck_assert_int_eq(wolfIP_nd6_lookup(&s, TEST_PRIMARY_IF, &peer, mac), 0);
    ck_assert_mem_eq(mac, nd_peer_mac, 6);
    /* The entry does drop to STALE, so its reachability is re-verified
     * rather than being confirmed by an advertisement we refused to act
     * on. Asserting the state, not just the address, is what makes this
     * test able to tell the two behaviours apart. */
    ck_assert_int_eq(s.nd6.neighbors[nd6_neighbor_index(&s, TEST_PRIMARY_IF,
                                                        &peer)].state,
                     ND6_STALE);

    /* With the Override flag it is accepted. */
    nd_send_na(&s, &peer, &ll6, &peer, ND6_NA_SOLICITED | ND6_NA_OVERRIDE,
               nd_other_mac, 255, nd_other_mac);
    ck_assert_int_eq(wolfIP_nd6_lookup(&s, TEST_PRIMARY_IF, &peer, mac), 0);
    ck_assert_mem_eq(mac, nd_other_mac, 6);
}
END_TEST

START_TEST(test_nd_messages_with_wrong_hop_limit_are_refused)
{
    struct wolfIP s;
    uint64_t now = 1000;
    uint8_t mac[6];
    ip6 ll6;
    ip6 peer;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_advance(&s, &now, 1500);
    nd_our_link_local(&s, &ll6);
    ck_assert_int_eq(atoip6("fe80::2", &peer), 0);
    (void)nd6_store_neighbor(&s, TEST_PRIMARY_IF, &peer, NULL,
                             ND6_INCOMPLETE, 0);

    /* RFC 4861 sections 6.1 and 7.1: anything other than 255 means the
     * message crossed a router. A hop limit of 254 is the off-link attacker
     * case, and 64 is what a careless implementation would send. */
    nd_send_na(&s, &peer, &ll6, &peer, ND6_NA_SOLICITED | ND6_NA_OVERRIDE,
               nd_peer_mac, 254, nd_peer_mac);
    ck_assert_int_lt(wolfIP_nd6_lookup(&s, TEST_PRIMARY_IF, &peer, mac), 0);
    nd_send_na(&s, &peer, &ll6, &peer, ND6_NA_SOLICITED | ND6_NA_OVERRIDE,
               nd_peer_mac, 64, nd_peer_mac);
    ck_assert_int_lt(wolfIP_nd6_lookup(&s, TEST_PRIMARY_IF, &peer, mac), 0);

    /* 255 is accepted, so the refusals above are about the hop limit and
     * nothing else. */
    nd_send_na(&s, &peer, &ll6, &peer, ND6_NA_SOLICITED | ND6_NA_OVERRIDE,
               nd_peer_mac, 255, nd_peer_mac);
    ck_assert_int_eq(wolfIP_nd6_lookup(&s, TEST_PRIMARY_IF, &peer, mac), 0);
}
END_TEST

START_TEST(test_nd_solicitation_for_our_address_is_answered)
{
    struct wolfIP s;
    struct nd6_msg *na;
    uint64_t now = 1000;
    uint8_t mac[6];
    ip6 ll6;
    ip6 peer;
    ip6 got;
    ip6 target;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_advance(&s, &now, 1500);
    nd_our_link_local(&s, &ll6);
    ck_assert_int_eq(atoip6("fe80::2", &peer), 0);

    last_frame_sent_size = 0;
    nd_send_ns(&s, &peer, &ll6, &ll6, nd_peer_mac, 255, nd_peer_mac);

    ck_assert_ptr_nonnull(nd_sent());
    na = (struct nd6_msg *)last_frame_sent;
    ck_assert_uint_eq(na->type, ICMP6_NEIGHBOR_ADVERT);
    ck_assert_uint_eq(na->ip6.hop_limit, 255);
    /* Solicited and Override, addressed back to the asker. */
    ck_assert_uint_eq(na->flags & ND6_NA_SOLICITED, ND6_NA_SOLICITED);
    memcpy(target.addr, na->target, 16);
    ck_assert_int_eq(ip6_cmp(&target, &ll6), 0);
    ip6_hdr_get_dst(&na->ip6, &got);
    ck_assert_int_eq(ip6_cmp(&got, &peer), 0);
    /* The Source Link-Layer Address option in the solicitation is recorded,
     * so the reverse direction is resolved without another exchange. */
    ck_assert_int_eq(wolfIP_nd6_lookup(&s, TEST_PRIMARY_IF, &peer, mac), 0);
    ck_assert_mem_eq(mac, nd_peer_mac, 6);
}
END_TEST

START_TEST(test_nd_solicitation_for_a_foreign_address_is_ignored)
{
    struct wolfIP s;
    uint64_t now = 1000;
    ip6 peer;
    ip6 foreign;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_advance(&s, &now, 1500);
    ck_assert_int_eq(atoip6("fe80::2", &peer), 0);
    ck_assert_int_eq(atoip6("fe80::dead", &foreign), 0);

    /* Answering for an address we do not hold would be answering on behalf
     * of another node. */
    last_frame_sent_size = 0;
    nd_send_ns(&s, &peer, &foreign, &foreign, nd_peer_mac, 255, nd_peer_mac);
    ck_assert_ptr_null(nd_sent());
}
END_TEST

/* =========================================================================
 * 3. Duplicate address detection
 * ========================================================================= */

START_TEST(test_dad_succeeds_when_nobody_answers)
{
    struct wolfIP s;
    uint64_t now = 1000;
    ip6 ll6;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_our_link_local(&s, &ll6);

    ck_assert_int_eq(nd_addr_state(&s, &ll6), WOLFIP_IFADDR_TENTATIVE);
    nd_advance(&s, &now, 1500);
    ck_assert_int_eq(nd_addr_state(&s, &ll6), WOLFIP_IFADDR_PREFERRED);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 1);
}
END_TEST

START_TEST(test_dad_fails_when_a_neighbour_advertises_the_address)
{
    struct wolfIP s;
    uint64_t now = 1000;
    ip6 ll6;
    ip6 all_nodes;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_our_link_local(&s, &ll6);
    nd_advance(&s, &now, 200); /* probe is out */

    /* Somebody already owns it and says so. RFC 4862 section 5.4.4. */
    ip6_set_all_nodes(&all_nodes);
    nd_send_na(&s, &ll6, &all_nodes, &ll6, ND6_NA_OVERRIDE, nd_peer_mac, 255,
               nd_peer_mac);

    /* RFC 4862 section 5.4.5: the address must not be assigned. */
    ck_assert_int_eq(nd_addr_state(&s, &ll6), -1);
    nd_advance(&s, &now, 2000);
    ck_assert_int_eq(nd_addr_state(&s, &ll6), -1);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 0);
}
END_TEST

START_TEST(test_dad_fails_on_a_simultaneous_probe_from_another_node)
{
    struct wolfIP s;
    uint64_t now = 1000;
    ip6 ll6;
    ip6 unspec;
    ip6 solicited;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_our_link_local(&s, &ll6);
    nd_advance(&s, &now, 200);

    /* RFC 4862 section 5.4.3: a solicitation for our tentative address from
     * the unspecified source means another node is probing the same address
     * at the same time. Neither may use it. */
    ip6_set_unspecified(&unspec);
    ip6_set_solicited_node(&solicited, &ll6);
    last_frame_sent_size = 0;
    nd_send_ns(&s, &unspec, &solicited, &ll6, NULL, 255, nd_peer_mac);

    ck_assert_int_eq(nd_addr_state(&s, &ll6), -1);
    /* And it must not have been defended: a tentative address is not ours. */
    ck_assert_ptr_null(nd_sent());
}
END_TEST

START_TEST(test_dad_tentative_address_is_not_defended)
{
    struct wolfIP s;
    uint64_t now = 1000;
    ip6 ll6;
    ip6 peer;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_our_link_local(&s, &ll6);
    nd_advance(&s, &now, 200);
    ck_assert_int_eq(nd_addr_state(&s, &ll6), WOLFIP_IFADDR_TENTATIVE);
    ck_assert_int_eq(atoip6("fe80::2", &peer), 0);

    /* An ordinary solicitation from a real node, while we are still
     * probing. Replying would claim an address we have not yet verified. */
    last_frame_sent_size = 0;
    nd_send_ns(&s, &peer, &ll6, &ll6, nd_peer_mac, 255, nd_peer_mac);
    ck_assert_ptr_null(nd_sent());
}
END_TEST

/* =========================================================================
 * 4. Router advertisements
 * ========================================================================= */

START_TEST(test_ra_assigns_a_global_address_and_a_default_router)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *ll;
    uint64_t now = 1000;
    ip6 prefix;
    ip6 iid;
    ip6 expected;
    ip6 router;
    ip6 nexthop;
    ip6 offlink;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_advance(&s, &now, 1500);

    /* The ordinary site case: one router, one /64, autonomous and on-link. */
    nd_send_ra(&s, "fe80::1", 1800, "2001:db8:1:2::", 64,
               ND6_PREFIX_ONLINK | ND6_PREFIX_AUTO, 7200, 255);

    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);
    ck_assert_int_eq(atoip6("2001:db8:1:2::", &prefix), 0);
    ip6_iid_from_mac(&iid, ll->mac);
    ip6_make_addr(&expected, &prefix, 64, &iid);

    /* RFC 4862 section 5.5.3: prefix plus interface identifier, and it too
     * has to pass duplicate address detection before use. */
    ck_assert_int_eq(nd_addr_state(&s, &expected), WOLFIP_IFADDR_TENTATIVE);
    nd_advance(&s, &now, 1500);
    ck_assert_int_eq(nd_addr_state(&s, &expected), WOLFIP_IFADDR_PREFERRED);
    /* The link-local address is still there alongside it. */
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 2);

    /* The advertising router became the default route, and an off-link
     * destination now resolves to it. */
    ck_assert_int_eq(atoip6("fe80::1", &router), 0);
    ck_assert_int_eq(atoip6("2001:db8:99::1", &offlink), 0);
    ck_assert_int_eq(wolfIP_ipv6_nexthop(&s, TEST_PRIMARY_IF, &offlink,
                                         &nexthop), 0);
    ck_assert_int_eq(ip6_cmp(&nexthop, &router), 0);

    /* A destination inside the advertised prefix is on-link, so the next hop
     * is the destination itself. */
    {
        ip6 onlink;

        ck_assert_int_eq(atoip6("2001:db8:1:2::99", &onlink), 0);
        ck_assert_int_eq(wolfIP_ipv6_nexthop(&s, TEST_PRIMARY_IF, &onlink,
                                             &nexthop), 0);
        ck_assert_int_eq(ip6_cmp(&nexthop, &onlink), 0);
    }
}
END_TEST

START_TEST(test_ra_from_a_non_link_local_source_is_ignored)
{
    struct wolfIP s;
    uint64_t now = 1000;
    ip6 offlink;
    ip6 nexthop;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_advance(&s, &now, 1500);

    /* RFC 4861 section 6.1.2. Accepting a global source would let anything
     * off the link install a default route and a prefix. */
    nd_send_ra(&s, "2001:db8::ffff", 1800, "2001:db8:1:2::", 64,
               ND6_PREFIX_ONLINK | ND6_PREFIX_AUTO, 7200, 255);

    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 1);
    ck_assert_int_eq(atoip6("2001:db8:99::1", &offlink), 0);
    ck_assert_int_lt(wolfIP_ipv6_nexthop(&s, TEST_PRIMARY_IF, &offlink,
                                         &nexthop), 0);
}
END_TEST

START_TEST(test_ra_with_wrong_hop_limit_is_ignored)
{
    struct wolfIP s;
    uint64_t now = 1000;
    ip6 offlink;
    ip6 nexthop;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_advance(&s, &now, 1500);

    nd_send_ra(&s, "fe80::1", 1800, "2001:db8:1:2::", 64,
               ND6_PREFIX_ONLINK | ND6_PREFIX_AUTO, 7200, 64);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 1);
    ck_assert_int_eq(atoip6("2001:db8:99::1", &offlink), 0);
    ck_assert_int_lt(wolfIP_ipv6_nexthop(&s, TEST_PRIMARY_IF, &offlink,
                                         &nexthop), 0);
}
END_TEST

START_TEST(test_ra_ignores_a_link_local_prefix_option)
{
    struct wolfIP s;
    uint64_t now = 1000;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_advance(&s, &now, 1500);

    /* RFC 4862 section 5.5.3 (a): an advertised link-local prefix is
     * silently ignored, so a hostile advertisement cannot redefine
     * fe80::/10 or make us form a second link-local address. */
    nd_send_ra(&s, "fe80::1", 1800, "fe80::", 64,
               ND6_PREFIX_ONLINK | ND6_PREFIX_AUTO, 7200, 255);
    nd_advance(&s, &now, 1500);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 1);
}
END_TEST

START_TEST(test_ra_prefix_that_is_not_64_bits_forms_no_address)
{
    struct wolfIP s;
    uint64_t now = 1000;
    ip6 onlink;
    ip6 nexthop;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_advance(&s, &now, 1500);

    /* RFC 4862 section 5.5.3 (d): the prefix length plus the interface
     * identifier length must be 128. A /48 leaves no room, so no address is
     * formed - but the prefix is still on-link. */
    nd_send_ra(&s, "fe80::1", 1800, "2001:db8:1::", 48,
               ND6_PREFIX_ONLINK | ND6_PREFIX_AUTO, 7200, 255);
    nd_advance(&s, &now, 1500);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 1);

    ck_assert_int_eq(atoip6("2001:db8:1::5", &onlink), 0);
    ck_assert_int_eq(wolfIP_ipv6_nexthop(&s, TEST_PRIMARY_IF, &onlink,
                                         &nexthop), 0);
    ck_assert_int_eq(ip6_cmp(&nexthop, &onlink), 0);
}
END_TEST

START_TEST(test_ra_with_zero_router_lifetime_is_not_a_default_route)
{
    struct wolfIP s;
    uint64_t now = 1000;
    ip6 offlink;
    ip6 nexthop;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_advance(&s, &now, 1500);

    /* RFC 4861 section 6.3.4: lifetime zero means the sender is not a
     * default router, though its prefixes still apply. */
    nd_send_ra(&s, "fe80::1", 0, "2001:db8:1:2::", 64,
               ND6_PREFIX_ONLINK | ND6_PREFIX_AUTO, 7200, 255);
    ck_assert_int_eq(atoip6("2001:db8:99::1", &offlink), 0);
    ck_assert_int_lt(wolfIP_ipv6_nexthop(&s, TEST_PRIMARY_IF, &offlink,
                                         &nexthop), 0);

    /* A later advertisement with a real lifetime installs the route, and
     * one with lifetime zero withdraws it again. */
    nd_send_ra(&s, "fe80::1", 1800, NULL, 0, 0, 0, 255);
    ck_assert_int_eq(wolfIP_ipv6_nexthop(&s, TEST_PRIMARY_IF, &offlink,
                                         &nexthop), 0);
    nd_send_ra(&s, "fe80::1", 0, NULL, 0, 0, 0, 255);
    ck_assert_int_lt(wolfIP_ipv6_nexthop(&s, TEST_PRIMARY_IF, &offlink,
                                         &nexthop), 0);
}
END_TEST

START_TEST(test_ra_with_a_zero_length_option_terminates)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    struct nd6_ra_msg *ra = (struct nd6_ra_msg *)frame;
    uint64_t now = 1000;
    ip6 src;
    ip6 dst;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    nd_advance(&s, &now, 1500);

    /* RFC 4861 section 4.6: option lengths are in units of 8 octets and zero
     * is invalid. A parser that does not reject it makes no forward progress
     * and loops forever on a frame an attacker controls. If this test hangs,
     * that is the bug. */
    memset(frame, 0, sizeof(frame));
    ck_assert_int_eq(atoip6("fe80::1", &src), 0);
    ip6_set_all_nodes(&dst);
    ra->type = ICMP6_ROUTER_ADVERT;
    ra->code = 0;
    ra->router_lifetime = ee16(1800);
    ra->options[0] = ND6_OPT_PREFIX;
    ra->options[1] = 0; /* invalid */
    nd_deliver(&s, frame, &src, &dst, (uint16_t)(16 + 8), 255, nd_router_mac);

    /* Reached, so the walk terminated. */
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 1);
}
END_TEST

/* =========================================================================
 * 5. A statically assigned ULA
 * ========================================================================= */

START_TEST(test_ula_is_verified_by_dad_and_then_usable)
{
    struct wolfIP s;
    uint64_t now = 1000;
    ip6 ula;
    ip6 ll6;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(atoip6("fd00:db8:1::1", &ula), 0);

    /* A pre-assigned unique local address, configured before the interface
     * has any other IPv6 configuration. RFC 4862 section 5.4 wants
     * duplicate address detection on it too, so it starts tentative. */
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    ck_assert_int_eq(wolfIP_ipv6_addr_add(&s, TEST_PRIMARY_IF, &ula, 64), 0);
    ck_assert_int_eq(nd_addr_state(&s, &ula), WOLFIP_IFADDR_TENTATIVE);
    ck_assert_int_eq(ip6_is_ula(&ula), 1);

    nd_advance(&s, &now, 1500);
    ck_assert_int_eq(nd_addr_state(&s, &ula), WOLFIP_IFADDR_PREFERRED);

    /* It coexists with the link-local address. */
    nd_our_link_local(&s, &ll6);
    ck_assert_int_eq(nd_addr_state(&s, &ll6), WOLFIP_IFADDR_PREFERRED);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 2);
}
END_TEST

START_TEST(test_ula_is_defended_and_survives_a_router_advertisement)
{
    struct wolfIP s;
    struct nd6_msg *na;
    uint64_t now = 1000;
    ip6 ula;
    ip6 peer;
    ip6 target;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(atoip6("fd00:db8:1::1", &ula), 0);
    ck_assert_int_eq(atoip6("fe80::2", &peer), 0);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    ck_assert_int_eq(wolfIP_ipv6_addr_add(&s, TEST_PRIMARY_IF, &ula, 64), 0);
    nd_advance(&s, &now, 1500);

    /* Once it is ours, solicitations for it are answered. */
    last_frame_sent_size = 0;
    nd_send_ns(&s, &peer, &ula, &ula, nd_peer_mac, 255, nd_peer_mac);
    ck_assert_ptr_nonnull(nd_sent());
    na = (struct nd6_msg *)last_frame_sent;
    ck_assert_uint_eq(na->type, ICMP6_NEIGHBOR_ADVERT);
    memcpy(target.addr, na->target, 16);
    ck_assert_int_eq(ip6_cmp(&target, &ula), 0);

    /* A router advertising a global prefix adds an address; it must not
     * disturb the statically configured one. */
    nd_send_ra(&s, "fe80::1", 1800, "2001:db8:1:2::", 64,
               ND6_PREFIX_ONLINK | ND6_PREFIX_AUTO, 7200, 255);
    nd_advance(&s, &now, 1500);
    ck_assert_int_eq(nd_addr_state(&s, &ula), WOLFIP_IFADDR_PREFERRED);
    /* link-local + ULA + SLAAC global */
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 3);
}
END_TEST

START_TEST(test_ula_duplicate_is_rejected)
{
    struct wolfIP s;
    uint64_t now = 1000;
    ip6 ula;
    ip6 all_nodes;

    nd_setup(&s);
    wolfIP_poll(&s, now);
    ck_assert_int_eq(atoip6("fd00:db8:1::1", &ula), 0);
    ck_assert_int_eq(wolfIP_ipv6_start(&s, TEST_PRIMARY_IF), 0);
    ck_assert_int_eq(wolfIP_ipv6_addr_add(&s, TEST_PRIMARY_IF, &ula, 64), 0);
    nd_advance(&s, &now, 200);

    /* Two nodes configured with the same ULA by mistake is exactly what
     * duplicate address detection is for. */
    ip6_set_all_nodes(&all_nodes);
    nd_send_na(&s, &ula, &all_nodes, &ula, ND6_NA_OVERRIDE, nd_peer_mac, 255,
               nd_peer_mac);
    ck_assert_int_eq(nd_addr_state(&s, &ula), -1);

    /* The link-local address is unaffected: only the duplicate is dropped. */
    nd_advance(&s, &now, 1500);
    ck_assert_uint_eq(wolfIP_ifaddr_count(&s, TEST_PRIMARY_IF, AF_INET6), 1);
}
END_TEST

#endif /* WOLFIP_IPV6 */

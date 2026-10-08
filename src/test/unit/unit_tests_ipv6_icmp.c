/* unit_tests_ipv6_icmp.c
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
 * ICMPv6 Echo (RFC 4443 section 4).
 *
 * Answering an Echo Request needs neither sockets nor Neighbor Discovery:
 * the reply goes back to the source MAC of the request, exactly as the
 * IPv4 path does. That makes it the first piece of IPv6 that is useful on
 * its own, and it gives ip6_output_add_header() its first production
 * caller.
 *
 * Sending Echo Requests is deliberately not here. That needs the peer's
 * link-layer address, which means Neighbor Discovery.
 *
 * Every frame is delivered through the real ingress path with
 * wolfIP_recv_ex(), and every assertion is made against the frame the
 * stack actually transmitted (last_frame_sent).
 */

/* ICMP6_ECHO_REQUEST / ICMP6_ECHO_REPLY come from src/wolfip6.c. */

#define ICMP6_OUR_ADDR    "2001:db8::1"
#define ICMP6_OUR_LL      "fe80::1"
#define ICMP6_PEER_ADDR   "2001:db8::2"

static const uint8_t icmp6_peer_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};

/* Bring up a stack with one global and one link-local IPv6 address. */
static void icmp6_setup(struct wolfIP *s)
{
    ip6 a;

    wolfIP_init(s);
    mock_link_init(s);
    ck_assert_int_eq(atoip6(ICMP6_OUR_ADDR, &a), 0);
    ck_assert_int_eq(wolfIP_ifaddr_add6(s, TEST_PRIMARY_IF, &a, 64), 0);
    ck_assert_int_eq(atoip6(ICMP6_OUR_LL, &a), 0);
    ck_assert_int_eq(wolfIP_ifaddr_add6(s, TEST_PRIMARY_IF, &a, 64), 0);
    last_frame_sent_size = 0;
}

/* Build an ICMPv6 message of `type` with a valid checksum and return the
 * frame length. `body_len` counts the bytes after the 4-byte ICMPv6 header
 * (identifier, sequence and payload for Echo). */
static uint32_t icmp6_build(uint8_t *frame, struct wolfIP *s,
                            const char *src, const char *dst, uint8_t type,
                            uint16_t id, uint16_t seq,
                            const uint8_t *payload, uint16_t payload_len,
                            int corrupt_csum)
{
    struct wolfIP_icmp6_packet *icmp = (struct wolfIP_icmp6_packet *)frame;
    struct wolfIP_ll_dev *ll = wolfIP_getdev_ex(s, TEST_PRIMARY_IF);
    union transport6_pseudo_header ph;
    uint16_t body_len = (uint16_t)(4u + payload_len); /* id+seq+payload */
    uint16_t upper_len = (uint16_t)(4u + body_len);   /* + ICMPv6 header */
    ip6 s6;
    ip6 d6;

    ck_assert_ptr_nonnull(ll);
    memset(frame, 0, LINK_MTU);
    ck_assert_int_eq(atoip6(src, &s6), 0);
    ck_assert_int_eq(atoip6(dst, &d6), 0);

    /* Destination MAC: our unicast address, or the 33:33 mapping when the
     * request is addressed to a multicast group. */
    if (ip6_is_multicast(&d6))
        ip6_mcast_to_eth(&d6, icmp->ip6.eth.dst);
    else
        memcpy(icmp->ip6.eth.dst, ll->mac, 6);
    memcpy(icmp->ip6.eth.src, icmp6_peer_mac, 6);
    icmp->ip6.eth.type = ee16(ETH_TYPE_IPV6);

    ip6_hdr_set_vtf(&icmp->ip6, 0, 0);
    icmp->ip6.payload_len = ee16(upper_len);
    icmp->ip6.next_hdr = IP6_NEXTHDR_ICMPV6;
    icmp->ip6.hop_limit = 64;
    ip6_hdr_set_src(&icmp->ip6, &s6);
    ip6_hdr_set_dst(&icmp->ip6, &d6);

    icmp->type = type;
    icmp->code = 0;
    icmp->csum = 0;
    icmp->data[0] = (uint8_t)(id >> 8);
    icmp->data[1] = (uint8_t)(id & 0xFFu);
    icmp->data[2] = (uint8_t)(seq >> 8);
    icmp->data[3] = (uint8_t)(seq & 0xFFu);
    if (payload_len && payload)
        memcpy(&icmp->data[4], payload, payload_len);

    transport6_pseudo_header_init(&ph, &s6, &d6, upper_len,
                                  IP6_NEXTHDR_ICMPV6);
    icmp->csum = ee16(transport6_checksum(&ph, &icmp->type));
    if (corrupt_csum)
        icmp->csum = (uint16_t)(icmp->csum ^ ee16(0x0001));

    return (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN + upper_len);
}

/* The reply the stack transmitted, or NULL if it sent nothing. */
static struct wolfIP_icmp6_packet *icmp6_reply(void)
{
    if (last_frame_sent_size == 0)
        return NULL;
    return (struct wolfIP_icmp6_packet *)last_frame_sent;
}

/* =========================================================================
 * Echo Request is answered
 * ========================================================================= */

START_TEST(test_icmp6_echo_request_is_answered)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    static const uint8_t payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    struct wolfIP_icmp6_packet *rep;
    uint32_t len;
    ip6 ours;
    ip6 peer;
    ip6 got;

    icmp6_setup(&s);
    ck_assert_int_eq(atoip6(ICMP6_OUR_ADDR, &ours), 0);
    ck_assert_int_eq(atoip6(ICMP6_PEER_ADDR, &peer), 0);

    len = icmp6_build(frame, &s, ICMP6_PEER_ADDR, ICMP6_OUR_ADDR,
                      ICMP6_ECHO_REQUEST, 0xABCD, 7, payload, sizeof(payload),
                      0);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);

    rep = icmp6_reply();
    ck_assert_ptr_nonnull(rep);
    /* RFC 4443 section 4.2 */
    ck_assert_uint_eq(rep->type, ICMP6_ECHO_REPLY);
    ck_assert_uint_eq(rep->code, 0);
    /* Identifier, sequence number and payload are echoed verbatim. */
    ck_assert_uint_eq(rep->data[0], 0xAB);
    ck_assert_uint_eq(rep->data[1], 0xCD);
    ck_assert_uint_eq(rep->data[2], 0);
    ck_assert_uint_eq(rep->data[3], 7);
    ck_assert_mem_eq(&rep->data[4], payload, sizeof(payload));

    /* Source and destination are swapped. */
    ip6_hdr_get_src(&rep->ip6, &got);
    ck_assert_int_eq(ip6_cmp(&got, &ours), 0);
    ip6_hdr_get_dst(&rep->ip6, &got);
    ck_assert_int_eq(ip6_cmp(&got, &peer), 0);

    /* It goes back to the requester's MAC, which is why no Neighbor
     * Discovery is needed to answer a ping. */
    ck_assert_mem_eq(rep->ip6.eth.dst, icmp6_peer_mac, 6);
    ck_assert_uint_eq(ee16(rep->ip6.eth.type), ETH_TYPE_IPV6);

    /* And the whole thing is a valid IPv6 packet. */
    ck_assert_uint_eq(ip6_hdr_version(&rep->ip6), 6);
    ck_assert_uint_eq(ee16(rep->ip6.payload_len), 4u + 4u + sizeof(payload));
    ck_assert_int_eq(ip6_verify_transport_checksum(&rep->ip6), 0);
}
END_TEST

START_TEST(test_icmp6_echo_request_with_no_payload_is_answered)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    uint32_t len;

    icmp6_setup(&s);
    /* A bare Echo with identifier and sequence but no data is legal. */
    len = icmp6_build(frame, &s, ICMP6_PEER_ADDR, ICMP6_OUR_ADDR,
                      ICMP6_ECHO_REQUEST, 1, 1, NULL, 0, 0);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);

    ck_assert_ptr_nonnull(icmp6_reply());
    ck_assert_uint_eq(icmp6_reply()->type, ICMP6_ECHO_REPLY);
    ck_assert_int_eq(ip6_verify_transport_checksum(&icmp6_reply()->ip6), 0);
}
END_TEST

START_TEST(test_icmp6_echo_to_link_local_is_answered_from_it)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    uint32_t len;
    ip6 ll6;
    ip6 got;

    icmp6_setup(&s);
    ck_assert_int_eq(atoip6(ICMP6_OUR_LL, &ll6), 0);

    len = icmp6_build(frame, &s, "fe80::2", ICMP6_OUR_LL,
                      ICMP6_ECHO_REQUEST, 5, 5, NULL, 0, 0);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);

    ck_assert_ptr_nonnull(icmp6_reply());
    /* The reply must come from the address that was pinged, not from some
     * other address of ours - a link-local request answered from a global
     * address would be dropped by the peer. */
    ip6_hdr_get_src(&icmp6_reply()->ip6, &got);
    ck_assert_int_eq(ip6_cmp(&got, &ll6), 0);
}
END_TEST

/* =========================================================================
 * Requests that must NOT be answered
 * ========================================================================= */

START_TEST(test_icmp6_echo_with_bad_checksum_is_ignored)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    uint32_t len;

    icmp6_setup(&s);
    /* RFC 4443 section 2.3: a message with a bad checksum is silently
     * discarded. */
    len = icmp6_build(frame, &s, ICMP6_PEER_ADDR, ICMP6_OUR_ADDR,
                      ICMP6_ECHO_REQUEST, 1, 1, NULL, 0, 1 /* corrupt */);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);
    ck_assert_ptr_null(icmp6_reply());
}
END_TEST

START_TEST(test_icmp6_echo_with_nonzero_code_is_ignored)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    struct wolfIP_icmp6_packet *icmp = (struct wolfIP_icmp6_packet *)frame;
    union transport6_pseudo_header ph;
    uint32_t len;
    uint16_t upper_len;
    ip6 src;
    ip6 dst;

    icmp6_setup(&s);
    len = icmp6_build(frame, &s, ICMP6_PEER_ADDR, ICMP6_OUR_ADDR,
                      ICMP6_ECHO_REQUEST, 1, 1, NULL, 0, 0);
    icmp->code = 7;
    icmp->csum = 0;
    upper_len = ee16(icmp->ip6.payload_len);
    ip6_hdr_get_src(&icmp->ip6, &src);
    ip6_hdr_get_dst(&icmp->ip6, &dst);
    transport6_pseudo_header_init(&ph, &src, &dst, upper_len,
                                  IP6_NEXTHDR_ICMPV6);
    icmp->csum = ee16(transport6_checksum(&ph, &icmp->type));

    /* RFC 4443 section 4.1 defines Code as zero. A valid checksum must not
     * make an otherwise malformed Echo Request actionable. */
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);
    ck_assert_ptr_null(icmp6_reply());
}
END_TEST

START_TEST(test_icmp6_echo_to_an_address_that_is_not_ours_is_ignored)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    uint32_t len;

    icmp6_setup(&s);
    /* Addressed to a global address we do not hold. Frames like this reach
     * the stack whenever the link is shared, and answering one would both
     * leak our existence and answer for somebody else. */
    len = icmp6_build(frame, &s, ICMP6_PEER_ADDR, "2001:db8::99",
                      ICMP6_ECHO_REQUEST, 1, 1, NULL, 0, 0);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);
    ck_assert_ptr_null(icmp6_reply());
}
END_TEST

START_TEST(test_icmp6_echo_from_unspecified_source_is_ignored)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    uint32_t len;

    icmp6_setup(&s);
    /* There is nowhere to send the reply, and :: as a source is reserved
     * for duplicate address detection. */
    len = icmp6_build(frame, &s, "::", ICMP6_OUR_ADDR,
                      ICMP6_ECHO_REQUEST, 1, 1, NULL, 0, 0);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);
    ck_assert_ptr_null(icmp6_reply());
}
END_TEST

START_TEST(test_icmp6_echo_to_tentative_address_is_ignored)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    uint32_t len;
    ip6 tentative;

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(atoip6(ICMP6_OUR_ADDR, &tentative), 0);
    ck_assert_int_eq(wolfIP_ipv6_addr_add(&s, TEST_PRIMARY_IF, &tentative,
                                         64), 0);

    /* RFC 4862 section 5.4.5: a tentative address is not assigned to the
     * interface yet and may only be used by Duplicate Address Detection. */
    last_frame_sent_size = 0;
    len = icmp6_build(frame, &s, ICMP6_PEER_ADDR, ICMP6_OUR_ADDR,
                      ICMP6_ECHO_REQUEST, 1, 1, NULL, 0, 0);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);
    ck_assert_ptr_null(icmp6_reply());
}
END_TEST

START_TEST(test_icmp6_link_local_address_is_not_local_on_another_interface)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    uint32_t len;
    ip6 ll6;

    wolfIP_init(&s);
    mock_link_init(&s);
    mock_link_init_idx(&s, TEST_SECOND_IF, NULL);
    ck_assert_int_eq(atoip6(ICMP6_OUR_LL, &ll6), 0);
    ck_assert_int_eq(wolfIP_ifaddr_add6(&s, TEST_SECOND_IF, &ll6, 64), 0);

    /* The numeric address belongs to the second link's zone, not the ingress
     * link. Answering here would violate RFC 4007 scoping. */
    last_frame_sent_size = 0;
    len = icmp6_build(frame, &s, "fe80::2", ICMP6_OUR_LL,
                      ICMP6_ECHO_REQUEST, 1, 1, NULL, 0, 0);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);
    ck_assert_ptr_null(icmp6_reply());
}
END_TEST

START_TEST(test_icmp6_echo_reply_does_not_generate_another_reply)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    uint32_t len;

    icmp6_setup(&s);
    /* Answering a reply with a reply is an infinite loop between two
     * hosts. */
    len = icmp6_build(frame, &s, ICMP6_PEER_ADDR, ICMP6_OUR_ADDR,
                      ICMP6_ECHO_REPLY, 1, 1, NULL, 0, 0);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);
    ck_assert_ptr_null(icmp6_reply());
}
END_TEST

START_TEST(test_icmp6_unhandled_types_are_ignored_without_replying)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    uint32_t len;
    unsigned int type;
    static const uint8_t types[] = {
        1,   /* Destination Unreachable */
        2,   /* Packet Too Big */
        3,   /* Time Exceeded */
        4,   /* Parameter Problem */
        133, /* Router Solicitation */
        134, /* Router Advertisement */
        135, /* Neighbor Solicitation */
        136, /* Neighbor Advertisement */
        137, /* Redirect */
        200  /* unassigned */
    };

    icmp6_setup(&s);
    /* None of these are implemented yet. They must be dropped quietly, and
     * in particular must never draw an Echo Reply. */
    for (type = 0; type < (sizeof(types) / sizeof(types[0])); type++) {
        last_frame_sent_size = 0;
        len = icmp6_build(frame, &s, ICMP6_PEER_ADDR, ICMP6_OUR_ADDR,
                          types[type], 1, 1, NULL, 0, 0);
        wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame, len);
        ck_assert_ptr_null(icmp6_reply());
    }
}
END_TEST

START_TEST(test_icmp6_truncated_echo_is_ignored)
{
    struct wolfIP s;
    uint8_t frame[LINK_MTU];
    struct wolfIP_icmp6_packet *icmp = (struct wolfIP_icmp6_packet *)frame;
    uint32_t len;

    icmp6_setup(&s);
    len = icmp6_build(frame, &s, ICMP6_PEER_ADDR, ICMP6_OUR_ADDR,
                      ICMP6_ECHO_REQUEST, 1, 1, NULL, 0, 0);

    /* An Echo needs 8 bytes: type, code, checksum, identifier, sequence.
     * Claim fewer and the identifier and sequence are not there to copy. */
    icmp->ip6.payload_len = ee16(4);
    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, frame,
                   (uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN + 4));
    ck_assert_ptr_null(icmp6_reply());
    (void)len;
}
END_TEST

#endif /* WOLFIP_IPV6 */

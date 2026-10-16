/* unit_tests_ipv6_hdr.c
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
 * Covers the IPv6 header itself: the wire layout, the field accessors, the
 * 40-byte pseudo-header checksum of RFC 8200 section 8.1, and the transmit
 * side encapsulation in ip6_output_add_header().
 *
 * Built only by `make unit-ipv6`, which passes -DWOLFIP_IPV6=1. The address
 * layer that this builds on is tested unconditionally in
 * unit_tests_ipv6_addr.c.
 */

/* =========================================================================
 * Local helpers
 * ========================================================================= */

#define IP6_TEST_FRAME_LEN(payload) \
    ((uint32_t)(ETH_HEADER_LEN + IP6_HEADER_LEN + (payload)))

/* Lay down a well formed IPv6 header at the start of buf and return it. */
static struct wolfIP_ip6_packet *ip6_mkhdr(uint8_t *buf, const char *src,
                                           const char *dst, uint8_t next_hdr,
                                           uint16_t payload_len)
{
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    ip6 s6;
    ip6 d6;

    memset(buf, 0, ETH_HEADER_LEN + IP6_HEADER_LEN);
    ck_assert_int_eq(atoip6(src, &s6), 0);
    ck_assert_int_eq(atoip6(dst, &d6), 0);
    ip6_hdr_set_vtf(pkt, 0, 0);
    pkt->payload_len = ee16(payload_len);
    pkt->next_hdr = next_hdr;
    pkt->hop_limit = 64;
    ip6_hdr_set_src(pkt, &s6);
    ip6_hdr_set_dst(pkt, &d6);
    return pkt;
}

/* =========================================================================
 * Wire layout
 * ========================================================================= */

START_TEST(test_ip6_header_wire_layout)
{
    /* RFC 8200 section 3: the header is exactly 40 bytes and every field
     * sits at a fixed offset. The Ethernet header is embedded by value, in
     * the same way the IPv4 structures do it. */
    ck_assert_uint_eq(sizeof(struct wolfIP_ip6_wire), IP6_HEADER_LEN);
    ck_assert_uint_eq(sizeof(struct wolfIP_ip6_packet),
                      (size_t)(ETH_HEADER_LEN + IP6_HEADER_LEN));

    ck_assert_uint_eq(offsetof(struct wolfIP_ip6_wire, ver_tc_fl), 0);
    ck_assert_uint_eq(offsetof(struct wolfIP_ip6_wire, payload_len), 4);
    ck_assert_uint_eq(offsetof(struct wolfIP_ip6_wire, next_hdr), 6);
    ck_assert_uint_eq(offsetof(struct wolfIP_ip6_wire, hop_limit), 7);
    ck_assert_uint_eq(offsetof(struct wolfIP_ip6_wire, src), 8);
    ck_assert_uint_eq(offsetof(struct wolfIP_ip6_wire, dst), 24);
    ck_assert_uint_eq(offsetof(struct wolfIP_ip6_wire, data), 40);
}
END_TEST

START_TEST(test_ip6_transport_wire_layout)
{
    /* The upper-layer headers sit immediately after the 40-byte IPv6
     * header, 20 bytes further along than their IPv4 counterparts. Getting
     * this wrong is the single easiest way to corrupt every packet, so the
     * offsets are pinned. */
    ck_assert_uint_eq(offsetof(struct wolfIP_tcp6_seg, src_port),
                      (size_t)(ETH_HEADER_LEN + IP6_HEADER_LEN));
    ck_assert_uint_eq(offsetof(struct wolfIP_udp6_datagram, src_port),
                      (size_t)(ETH_HEADER_LEN + IP6_HEADER_LEN));
    ck_assert_uint_eq(offsetof(struct wolfIP_icmp6_packet, type),
                      (size_t)(ETH_HEADER_LEN + IP6_HEADER_LEN));

    /* And they are exactly 20 bytes further along than the IPv4 layout. */
    ck_assert_uint_eq(offsetof(struct wolfIP_tcp6_seg, src_port) -
                      offsetof(struct wolfIP_tcp_seg, src_port), 20);
    ck_assert_uint_eq(offsetof(struct wolfIP_udp6_datagram, src_port) -
                      offsetof(struct wolfIP_udp_datagram, src_port), 20);
}
END_TEST

START_TEST(test_ip6_pseudo_header_is_40_bytes)
{
    /* RFC 8200 section 8.1. The IPv4 pseudo-header is 12 bytes; conflating
     * the two silently produces checksums that no peer will accept. */
    ck_assert_uint_eq(sizeof(union transport6_pseudo_header), 40);
    ck_assert_uint_eq(offsetof(struct ph6, src), 0);
    ck_assert_uint_eq(offsetof(struct ph6, dst), 16);
    ck_assert_uint_eq(offsetof(struct ph6, len), 32);
    ck_assert_uint_eq(offsetof(struct ph6, zero), 36);
    ck_assert_uint_eq(offsetof(struct ph6, proto), 39);
}
END_TEST

/* =========================================================================
 * Field accessors
 * ========================================================================= */

START_TEST(test_ip6_hdr_version_traffic_class_flow_label)
{
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;

    memset(buf, 0, sizeof(buf));

    ip6_hdr_set_vtf(pkt, 0, 0);
    ck_assert_uint_eq(ip6_hdr_version(pkt), 6);
    ck_assert_uint_eq(ip6_hdr_traffic_class(pkt), 0);
    ck_assert_uint_eq(ip6_hdr_flow_label(pkt), 0);

    /* All three fields must be independently recoverable. */
    ip6_hdr_set_vtf(pkt, 0xB8, 0xFEDCB);
    ck_assert_uint_eq(ip6_hdr_version(pkt), 6);
    ck_assert_uint_eq(ip6_hdr_traffic_class(pkt), 0xB8);
    ck_assert_uint_eq(ip6_hdr_flow_label(pkt), 0xFEDCB);

    /* Maximum values do not bleed into one another. */
    ip6_hdr_set_vtf(pkt, 0xFF, 0xFFFFF);
    ck_assert_uint_eq(ip6_hdr_version(pkt), 6);
    ck_assert_uint_eq(ip6_hdr_traffic_class(pkt), 0xFF);
    ck_assert_uint_eq(ip6_hdr_flow_label(pkt), 0xFFFFF);

    /* A flow label wider than 20 bits is masked, never allowed to corrupt
     * the traffic class or version above it. */
    ip6_hdr_set_vtf(pkt, 0, 0xFFFFFFFFu);
    ck_assert_uint_eq(ip6_hdr_version(pkt), 6);
    ck_assert_uint_eq(ip6_hdr_traffic_class(pkt), 0);
    ck_assert_uint_eq(ip6_hdr_flow_label(pkt), 0xFFFFF);
}
END_TEST

START_TEST(test_ip6_hdr_first_word_byte_order)
{
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    const uint8_t *raw = buf + ETH_HEADER_LEN;

    memset(buf, 0, sizeof(buf));
    ip6_hdr_set_vtf(pkt, 0x00, 0);
    /* Version 6 occupies the high nibble of the first octet on the wire,
     * regardless of host endianness. */
    ck_assert_uint_eq(raw[0] & 0xF0u, 0x60);

    ip6_hdr_set_vtf(pkt, 0xFF, 0);
    /* Traffic class straddles the first two octets: low nibble of byte 0,
     * high nibble of byte 1. */
    ck_assert_uint_eq(raw[0], 0x6F);
    ck_assert_uint_eq(raw[1] & 0xF0u, 0xF0);

    ip6_hdr_set_vtf(pkt, 0, 0x12345);
    ck_assert_uint_eq(raw[1] & 0x0Fu, 0x01);
    ck_assert_uint_eq(raw[2], 0x23);
    ck_assert_uint_eq(raw[3], 0x45);
}
END_TEST

START_TEST(test_ip6_hdr_address_accessors_roundtrip)
{
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    ip6 src;
    ip6 dst;
    ip6 got;

    memset(buf, 0, sizeof(buf));
    ck_assert_int_eq(atoip6("2001:db8::1", &src), 0);
    ck_assert_int_eq(atoip6("fe80::2", &dst), 0);

    ip6_hdr_set_src(pkt, &src);
    ip6_hdr_set_dst(pkt, &dst);

    ip6_hdr_get_src(pkt, &got);
    ck_assert_int_eq(ip6_cmp(&got, &src), 0);
    ip6_hdr_get_dst(pkt, &got);
    ck_assert_int_eq(ip6_cmp(&got, &dst), 0);

    /* Source and destination must not overlap: writing one may not disturb
     * the other. */
    ck_assert_mem_eq(buf + ETH_HEADER_LEN + 8, src.addr, 16);
    ck_assert_mem_eq(buf + ETH_HEADER_LEN + 24, dst.addr, 16);
}
END_TEST

/* =========================================================================
 * Pseudo-header checksum
 * ========================================================================= */

START_TEST(test_transport6_checksum_self_verifies)
{
    uint8_t buf[LINK_MTU];
    struct wolfIP_udp6_datagram *udp;
    union transport6_pseudo_header ph;
    ip6 src;
    ip6 dst;
    const uint16_t payload = 8 + 4; /* UDP header + 4 bytes of data */

    ip6_mkhdr(buf, "2001:db8::1", "2001:db8::2", IP6_NEXTHDR_UDP, payload);
    udp = (struct wolfIP_udp6_datagram *)buf;
    udp->src_port = ee16(1234);
    udp->dst_port = ee16(5678);
    udp->len = ee16(payload);
    udp->csum = 0;
    memcpy(udp->data, "abcd", 4);

    ck_assert_int_eq(atoip6("2001:db8::1", &src), 0);
    ck_assert_int_eq(atoip6("2001:db8::2", &dst), 0);
    transport6_pseudo_header_init(&ph, &src, &dst, payload, IP6_NEXTHDR_UDP);
    udp->csum = ee16(transport6_checksum(&ph, &udp->src_port));

    /* A non-trivial packet must not produce a zero checksum by accident,
     * and re-summing including the checksum field must give zero. */
    ck_assert_uint_ne(udp->csum, 0);
    ck_assert_int_eq(transport6_verify_checksum(&ph, &udp->src_port), 0);
    ck_assert_int_eq(ip6_verify_transport_checksum(
                         (struct wolfIP_ip6_packet *)buf), 0);
}
END_TEST

START_TEST(test_transport6_checksum_detects_every_single_bit_flip)
{
    uint8_t buf[LINK_MTU];
    struct wolfIP_udp6_datagram *udp;
    union transport6_pseudo_header ph;
    ip6 src;
    ip6 dst;
    const uint16_t payload = 8 + 6;
    unsigned int byte;

    ip6_mkhdr(buf, "2001:db8::1", "2001:db8::2", IP6_NEXTHDR_UDP, payload);
    udp = (struct wolfIP_udp6_datagram *)buf;
    udp->src_port = ee16(1234);
    udp->dst_port = ee16(5678);
    udp->len = ee16(payload);
    udp->csum = 0;
    memcpy(udp->data, "abcdef", 6);
    ck_assert_int_eq(atoip6("2001:db8::1", &src), 0);
    ck_assert_int_eq(atoip6("2001:db8::2", &dst), 0);
    transport6_pseudo_header_init(&ph, &src, &dst, payload, IP6_NEXTHDR_UDP);
    udp->csum = ee16(transport6_checksum(&ph, &udp->src_port));
    ck_assert_int_eq(transport6_verify_checksum(&ph, &udp->src_port), 0);

    /* Flip one bit at a time across the whole upper-layer region. A one's
     * complement sum catches every single-bit error, so each flip must be
     * detected and the packet must verify again once restored. */
    for (byte = 0; byte < payload; byte++) {
        uint8_t *p = ((uint8_t *)&udp->src_port) + byte;
        unsigned int bit;

        for (bit = 0; bit < 8; bit++) {
            *p = (uint8_t)(*p ^ (1u << bit));
            ck_assert_int_ne(transport6_verify_checksum(&ph, &udp->src_port), 0);
            *p = (uint8_t)(*p ^ (1u << bit));
        }
    }
    ck_assert_int_eq(transport6_verify_checksum(&ph, &udp->src_port), 0);
}
END_TEST

START_TEST(test_transport6_checksum_covers_the_pseudo_header)
{
    uint8_t buf[LINK_MTU];
    struct wolfIP_udp6_datagram *udp;
    union transport6_pseudo_header ph;
    ip6 src;
    ip6 dst;
    ip6 other;
    const uint16_t payload = 8;
    uint16_t csum_a;
    uint16_t csum_b;

    ip6_mkhdr(buf, "2001:db8::1", "2001:db8::2", IP6_NEXTHDR_UDP, payload);
    udp = (struct wolfIP_udp6_datagram *)buf;
    udp->src_port = ee16(1234);
    udp->dst_port = ee16(5678);
    udp->len = ee16(payload);
    udp->csum = 0;
    ck_assert_int_eq(atoip6("2001:db8::1", &src), 0);
    ck_assert_int_eq(atoip6("2001:db8::2", &dst), 0);
    ck_assert_int_eq(atoip6("2001:db8::3", &other), 0);

    transport6_pseudo_header_init(&ph, &src, &dst, payload, IP6_NEXTHDR_UDP);
    csum_a = transport6_checksum(&ph, &udp->src_port);

    /* Changing only the destination address must change the checksum: that
     * is the whole point of the pseudo-header. */
    transport6_pseudo_header_init(&ph, &src, &other, payload, IP6_NEXTHDR_UDP);
    csum_b = transport6_checksum(&ph, &udp->src_port);
    ck_assert_uint_ne(csum_a, csum_b);

    /* So must changing the next header, which is why TCP and UDP payloads
     * that are otherwise identical checksum differently. */
    transport6_pseudo_header_init(&ph, &src, &dst, payload, IP6_NEXTHDR_TCP);
    ck_assert_uint_ne(transport6_checksum(&ph, &udp->src_port), csum_a);
}
END_TEST

START_TEST(test_transport6_checksum_handles_odd_length_payload)
{
    uint8_t buf[LINK_MTU];
    struct wolfIP_udp6_datagram *udp;
    union transport6_pseudo_header ph;
    ip6 src;
    ip6 dst;
    const uint16_t payload = 8 + 5; /* odd data length */

    ip6_mkhdr(buf, "2001:db8::1", "2001:db8::2", IP6_NEXTHDR_UDP, payload);
    udp = (struct wolfIP_udp6_datagram *)buf;
    udp->src_port = ee16(1);
    udp->dst_port = ee16(2);
    udp->len = ee16(payload);
    udp->csum = 0;
    memcpy(udp->data, "hello", 5);
    /* Poison the byte just past the payload: the odd-length tail handling
     * must not read it. */
    udp->data[5] = 0xFF;

    ck_assert_int_eq(atoip6("2001:db8::1", &src), 0);
    ck_assert_int_eq(atoip6("2001:db8::2", &dst), 0);
    transport6_pseudo_header_init(&ph, &src, &dst, payload, IP6_NEXTHDR_UDP);
    udp->csum = ee16(transport6_checksum(&ph, &udp->src_port));
    ck_assert_int_eq(transport6_verify_checksum(&ph, &udp->src_port), 0);

    /* Changing the poisoned byte beyond the payload must not invalidate it. */
    udp->data[5] = 0x00;
    ck_assert_int_eq(transport6_verify_checksum(&ph, &udp->src_port), 0);
}
END_TEST

/* =========================================================================
 * Transmit encapsulation
 * ========================================================================= */

START_TEST(test_ip6_output_add_header_fills_the_header)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_udp6_datagram *udp = (struct wolfIP_udp6_datagram *)buf;
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    const uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    ip6 src;
    ip6 dst;
    ip6 got;
    const uint16_t payload = 8 + 4;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(buf, 0, sizeof(buf));
    ck_assert_int_eq(atoip6("2001:db8::1", &src), 0);
    ck_assert_int_eq(atoip6("2001:db8::2", &dst), 0);

    udp->src_port = ee16(1234);
    udp->dst_port = ee16(5678);
    udp->len = ee16(payload);
    memcpy(udp->data, "wxyz", 4);

    ck_assert_int_eq(ip6_output_add_header(&s, TEST_PRIMARY_IF, pkt, &src, &dst,
                                           IP6_NEXTHDR_UDP, payload, 64, mac),
                     0);

    ck_assert_uint_eq(ip6_hdr_version(pkt), 6);
    /* RFC 8200 section 6: a source that does not use flow labelling sets
     * the field to zero. */
    ck_assert_uint_eq(ip6_hdr_flow_label(pkt), 0);
    ck_assert_uint_eq(ip6_hdr_traffic_class(pkt), 0);
    ck_assert_uint_eq(ee16(pkt->payload_len), payload);
    ck_assert_uint_eq(pkt->next_hdr, IP6_NEXTHDR_UDP);
    ck_assert_uint_eq(pkt->hop_limit, 64);
    ip6_hdr_get_src(pkt, &got);
    ck_assert_int_eq(ip6_cmp(&got, &src), 0);
    ip6_hdr_get_dst(pkt, &got);
    ck_assert_int_eq(ip6_cmp(&got, &dst), 0);

    /* The Ethernet header must carry the IPv6 ethertype and the supplied
     * next-hop MAC. */
    ck_assert_uint_eq(ee16(pkt->eth.type), ETH_TYPE_IPV6);
    ck_assert_mem_eq(pkt->eth.dst, mac, 6);

    /* And the checksum must be valid over the resulting header. */
    ck_assert_int_eq(ip6_verify_transport_checksum(pkt), 0);
}
END_TEST

START_TEST(test_ip6_output_add_header_defaults_hop_limit)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    const uint8_t mac[6] = {0x02, 0, 0, 0, 0, 1};
    ip6 src;
    ip6 dst;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(buf, 0, sizeof(buf));
    ck_assert_int_eq(atoip6("2001:db8::1", &src), 0);
    ck_assert_int_eq(atoip6("2001:db8::2", &dst), 0);

    /* A hop limit of zero means "caller did not care", not "expire this
     * packet immediately". */
    ck_assert_int_eq(ip6_output_add_header(&s, TEST_PRIMARY_IF, pkt, &src, &dst,
                                           IP6_NEXTHDR_UDP, 8, 0, mac), 0);
    ck_assert_uint_eq(pkt->hop_limit, IP6_HOP_LIMIT_DEFAULT);

    /* An explicit 255, as Neighbor Discovery requires, is preserved. */
    ck_assert_int_eq(ip6_output_add_header(&s, TEST_PRIMARY_IF, pkt, &src, &dst,
                                           IP6_NEXTHDR_ICMPV6, 8, 255, mac), 0);
    ck_assert_uint_eq(pkt->hop_limit, 255);
}
END_TEST

START_TEST(test_ip6_output_add_header_udp_zero_checksum_becomes_ffff)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_udp6_datagram *udp = (struct wolfIP_udp6_datagram *)buf;
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    const uint8_t mac[6] = {0x02, 0, 0, 0, 0, 1};
    ip6 src;
    ip6 dst;
    unsigned int attempt;
    int saw_ffff = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(atoip6("2001:db8::1", &src), 0);
    ck_assert_int_eq(atoip6("2001:db8::2", &dst), 0);

    /* RFC 8200 section 8.1: a zero UDP checksum is forbidden over IPv6
     * (unlike IPv4, where it means "not computed"), so a computed zero must
     * be sent as 0xFFFF. Search a small space of payloads for one that sums
     * to zero, then assert the substitution happened. */
    for (attempt = 0; attempt < 0x10000u; attempt++) {
        const uint16_t payload = 8 + 2;

        memset(buf, 0, sizeof(buf));
        udp->src_port = ee16(1);
        udp->dst_port = ee16(2);
        udp->len = ee16(payload);
        udp->data[0] = (uint8_t)(attempt >> 8);
        udp->data[1] = (uint8_t)(attempt & 0xFFu);
        ck_assert_int_eq(ip6_output_add_header(&s, TEST_PRIMARY_IF, pkt, &src,
                                               &dst, IP6_NEXTHDR_UDP, payload,
                                               64, mac), 0);
        /* Whatever the payload, the checksum field is never left at zero. */
        ck_assert_uint_ne(udp->csum, 0);
        if (udp->csum == 0xFFFFu) {
            saw_ffff = 1;
            break;
        }
    }
    ck_assert_int_eq(saw_ffff, 1);
}
END_TEST

START_TEST(test_ip6_output_add_header_icmp6_checksum_uses_pseudo_header)
{
    struct wolfIP s;
    uint8_t buf_a[LINK_MTU];
    uint8_t buf_b[LINK_MTU];
    struct wolfIP_icmp6_packet *a = (struct wolfIP_icmp6_packet *)buf_a;
    struct wolfIP_icmp6_packet *b = (struct wolfIP_icmp6_packet *)buf_b;
    const uint8_t mac[6] = {0x02, 0, 0, 0, 0, 1};
    ip6 src;
    ip6 dst1;
    ip6 dst2;

    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(atoip6("fe80::1", &src), 0);
    ck_assert_int_eq(atoip6("ff02::1", &dst1), 0);
    ck_assert_int_eq(atoip6("ff02::2", &dst2), 0);

    memset(buf_a, 0, sizeof(buf_a));
    memset(buf_b, 0, sizeof(buf_b));
    a->type = 128; /* Echo Request */
    a->code = 0;
    b->type = 128;
    b->code = 0;

    ck_assert_int_eq(ip6_output_add_header(&s, TEST_PRIMARY_IF,
                                           (struct wolfIP_ip6_packet *)a,
                                           &src, &dst1, IP6_NEXTHDR_ICMPV6,
                                           4, 255, mac), 0);
    ck_assert_int_eq(ip6_output_add_header(&s, TEST_PRIMARY_IF,
                                           (struct wolfIP_ip6_packet *)b,
                                           &src, &dst2, IP6_NEXTHDR_ICMPV6,
                                           4, 255, mac), 0);

    /* Identical ICMPv6 bodies to different destinations must checksum
     * differently. ICMPv4 has no pseudo-header and would produce the same
     * value for both; this is the check that catches that mistake being
     * carried over. */
    ck_assert_uint_ne(a->csum, b->csum);
    ck_assert_int_eq(ip6_verify_transport_checksum(
                         (struct wolfIP_ip6_packet *)a), 0);
    ck_assert_int_eq(ip6_verify_transport_checksum(
                         (struct wolfIP_ip6_packet *)b), 0);
}
END_TEST

START_TEST(test_ip6_output_add_header_tcp_checksum)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_tcp6_seg *tcp = (struct wolfIP_tcp6_seg *)buf;
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    const uint8_t mac[6] = {0x02, 0, 0, 0, 0, 1};
    ip6 src;
    ip6 dst;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(buf, 0, sizeof(buf));
    ck_assert_int_eq(atoip6("2001:db8::1", &src), 0);
    ck_assert_int_eq(atoip6("2001:db8::2", &dst), 0);

    tcp->src_port = ee16(443);
    tcp->dst_port = ee16(51000);
    tcp->seq = ee32(0x11223344);
    tcp->hlen = 0x50;
    tcp->flags = 0x02; /* SYN */
    tcp->win = ee16(64240);

    ck_assert_int_eq(ip6_output_add_header(&s, TEST_PRIMARY_IF, pkt, &src, &dst,
                                           IP6_NEXTHDR_TCP, 20, 64, mac), 0);
    ck_assert_uint_ne(tcp->csum, 0);
    ck_assert_int_eq(ip6_verify_transport_checksum(pkt), 0);
    ck_assert_uint_eq(ee16(pkt->eth.type), ETH_TYPE_IPV6);
}
END_TEST

START_TEST(test_ip6_output_add_header_rejects_null_arguments)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    ip6 a;

    wolfIP_init(&s);
    mock_link_init(&s);
    ip6_set_loopback(&a);

    ck_assert_int_eq(ip6_output_add_header(&s, TEST_PRIMARY_IF, NULL, &a, &a,
                                           IP6_NEXTHDR_UDP, 8, 64, NULL),
                     -WOLFIP_EINVAL);
    ck_assert_int_eq(ip6_output_add_header(&s, TEST_PRIMARY_IF, pkt, NULL, &a,
                                           IP6_NEXTHDR_UDP, 8, 64, NULL),
                     -WOLFIP_EINVAL);
    ck_assert_int_eq(ip6_output_add_header(&s, TEST_PRIMARY_IF, pkt, &a, NULL,
                                           IP6_NEXTHDR_UDP, 8, 64, NULL),
                     -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_ip6_output_add_header_without_mac_leaves_ethernet_alone)
{
    struct wolfIP s;
    uint8_t buf[LINK_MTU];
    struct wolfIP_ip6_packet *pkt = (struct wolfIP_ip6_packet *)buf;
    ip6 src;
    ip6 dst;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(buf, 0, sizeof(buf));
    ck_assert_int_eq(atoip6("2001:db8::1", &src), 0);
    ck_assert_int_eq(atoip6("2001:db8::2", &dst), 0);

    /* A NULL next-hop MAC means the caller handles the link layer, as the
     * raw-IP ports do. The Ethernet header must be left untouched. */
    ck_assert_int_eq(ip6_output_add_header(&s, TEST_PRIMARY_IF, pkt, &src, &dst,
                                           IP6_NEXTHDR_UDP, 8, 64, NULL), 0);
    ck_assert_uint_eq(pkt->eth.type, 0);
    /* The IPv6 header itself is still fully populated. */
    ck_assert_uint_eq(ip6_hdr_version(pkt), 6);
    ck_assert_uint_eq(ee16(pkt->payload_len), 8);
}
END_TEST

#endif /* WOLFIP_IPV6 */

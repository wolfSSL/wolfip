/* unit_tests_ipv6_pending.c
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
 * Requirement-derived tests for IPv6 behaviour that is not implemented yet
 * =========================================================================
 *
 * Each group is guarded by a named WOLFIP_IPV6_HAVE_* macro, all of which
 * default to 0 in config.h. The phase that implements a feature flips its
 * macro to 1 in the same commit, which switches these tests on. They are
 * named macros rather than "#if 0" so that the amount of work still
 * outstanding is greppable - `make unit-ipv6-pending-count` reports it.
 *
 * These tests are the specification. They were written from the low-level
 * requirements before the code exists, so they also fix the API shape: the
 * function names and signatures used below are the contract the
 * implementation is expected to meet. Changing a name here is a deliberate
 * interface decision, not a test fixup.
 *
 * Test names are descriptive and carry no requirement identifiers: the
 * requirement documents are internal, and the mapping from requirement to
 * test is maintained off-tree, keyed by test function name. Keep the names
 * stable.
 */

#if WOLFIP_IPV6

/* =========================================================================
 * ICMPv6 - RFC 4443
 * ========================================================================= */
#if WOLFIP_IPV6_HAVE_ICMP6

/* Echo Request and Reply, and the receive checksum, are implemented and
 * have real tests in unit_tests_ipv6_icmp.c. What remains here is the
 * error-message half of RFC 4443. */




START_TEST(test_icmp6_error_is_not_sent_in_response_to_an_error)
{
    /* RFC 4443 s2.4 (e.3): an ICMPv6 error message must never be generated
     * in response to another ICMPv6 error message. Without this rule two
     * hosts can sustain an error loop. */
    ck_abort_msg("pending: ICMPv6 error suppression");
}
END_TEST

START_TEST(test_icmp6_error_is_not_sent_for_multicast_destinations)
{
    /* RFC 4443 s2.4 (e.3): no error for a packet sent to a multicast
     * address, with the two Packet Too Big and Parameter Problem
     * exceptions. This is the rule that stops multicast amplification. */
    ck_abort_msg("pending: ICMPv6 multicast error suppression");
}
END_TEST

START_TEST(test_icmp6_error_quotes_as_much_as_fits_in_min_mtu)
{
    /* RFC 4443 s2.4 (c): the error carries as much of the offending packet
     * as fits without exceeding the 1280-byte minimum IPv6 MTU. */
    ck_abort_msg("pending: ICMPv6 error quoting");
}
END_TEST

START_TEST(test_icmp6_destination_unreachable_codes)
{
    /* Type 1, codes 0 to 4 (RFC 4443 s3.1). Port unreachable (code 4) is
     * the one UDP needs when no socket matches. */
    ck_abort_msg("pending: ICMPv6 destination unreachable");
}
END_TEST

START_TEST(test_icmp6_packet_too_big_carries_the_mtu)
{
    /* Type 2 (RFC 4443 s3.2). IPv6 routers never fragment, so this is the
     * only path MTU signal there is. */
    ck_abort_msg("pending: ICMPv6 packet too big");
}
END_TEST

START_TEST(test_icmp6_time_exceeded_on_hop_limit_zero_when_forwarding)
{
    /* Type 3 code 0 (RFC 4443 s3.3). Note this is a forwarding-time event:
     * a packet addressed to us at hop limit zero is accepted, which
     * test_ip6_recv_accepts_hop_limit_zero already pins down. */
    ck_abort_msg("pending: ICMPv6 time exceeded");
}
END_TEST

START_TEST(test_icmp6_parameter_problem_points_at_the_bad_octet)
{
    /* Type 4 (RFC 4443 s3.4): the pointer field must be the offset of the
     * offending octet from the start of the IPv6 header. */
    ck_abort_msg("pending: ICMPv6 parameter problem");
}
END_TEST

START_TEST(test_icmp6_unknown_informational_message_is_discarded)
{
    /* RFC 4443 s2.4 (b): an unknown informational message (type >= 128) is
     * silently discarded, whereas an unknown error message (type < 128)
     * must be passed to the upper layer. */
    ck_abort_msg("pending: ICMPv6 unknown type handling");
}
END_TEST

#endif /* WOLFIP_IPV6_HAVE_ICMP6 */

/* =========================================================================
 * Neighbor Discovery - RFC 4861
 * ========================================================================= */
#if WOLFIP_IPV6_HAVE_ND6

START_TEST(test_nd6_solicitation_goes_to_the_solicited_node_group)
{
    /* RFC 4861 s7.2.2: address resolution sends a Neighbor Solicitation to
     * the solicited-node multicast address of the target, not to the
     * all-nodes group - that is the whole point of the mapping. */
    ck_abort_msg("pending: ND address resolution");
}
END_TEST

START_TEST(test_nd6_solicitation_carries_source_link_layer_address_option)
{
    /* RFC 4861 s4.3: the source link-layer address option must be present
     * when the source is not the unspecified address, and must be absent
     * when it is (during DAD). */
    ck_abort_msg("pending: ND SLLA option");
}
END_TEST

START_TEST(test_nd6_advertisement_updates_the_neighbor_cache)
{
    ck_abort_msg("pending: ND neighbor cache update");
}
END_TEST

START_TEST(test_nd6_messages_with_hop_limit_not_255_are_discarded)
{
    /* RFC 4861 s6.1.1 and s7.1.1: every NDP message must arrive with a hop
     * limit of exactly 255. This is the entire off-link attack defence for
     * Neighbor Discovery - a router cannot forward a packet and leave the
     * hop limit at 255 - so it is the single most important NDP check. */
    ck_abort_msg("pending: ND hop limit 255 enforcement");
}
END_TEST

START_TEST(test_nd6_messages_with_icmp_code_not_zero_are_discarded)
{
    /* RFC 4861 s7.1.1 */
    ck_abort_msg("pending: ND code validation");
}
END_TEST

START_TEST(test_nd6_solicitation_with_unspecified_source_must_be_multicast)
{
    /* RFC 4861 s7.1.1: if the source is the unspecified address, the
     * destination must be a solicited-node multicast address. */
    ck_abort_msg("pending: ND DAD solicitation validation");
}
END_TEST

START_TEST(test_nd6_cache_state_machine_transitions)
{
    /* RFC 4861 s7.3.2: INCOMPLETE, REACHABLE, STALE, DELAY, PROBE. */
    ck_abort_msg("pending: ND cache state machine");
}
END_TEST

START_TEST(test_nd6_cache_eviction_when_full)
{
    /* WOLFIP_ND6_CACHE_SIZE entries. Note the IPv4 ARP table silently
     * refuses new entries when full rather than evicting; the IPv6 cache
     * must not inherit that, or one burst of scan traffic locks out every
     * real neighbour. */
    ck_abort_msg("pending: ND cache eviction");
}
END_TEST

START_TEST(test_nd6_queues_one_packet_per_pending_resolution)
{
    /* RFC 4861 s7.2.2: at least one packet is queued while resolution is
     * in flight, and the queue is bounded. */
    ck_abort_msg("pending: ND pending packet queue");
}
END_TEST

START_TEST(test_nd6_router_solicitation_is_sent_on_startup)
{
    /* RFC 4861 s6.3.7 */
    ck_abort_msg("pending: ND router solicitation");
}
END_TEST

START_TEST(test_nd6_router_advertisement_populates_prefix_and_router_lists)
{
    /* RFC 4861 s6.3.4 */
    ck_abort_msg("pending: ND RA processing");
}
END_TEST

START_TEST(test_nd6_router_advertisement_from_non_link_local_is_ignored)
{
    /* RFC 4861 s6.1.2: the source of an RA must be a link-local address. */
    ck_abort_msg("pending: ND RA source validation");
}
END_TEST

START_TEST(test_nd6_prefix_option_with_length_over_128_is_ignored)
{
    /* RFC 4861 s4.6.2. A prefix length above 128 would otherwise index off
     * the end of a 16-byte address. */
    ck_abort_msg("pending: ND prefix option validation");
}
END_TEST

START_TEST(test_nd6_option_with_zero_length_is_rejected)
{
    /* RFC 4861 s4.6: option lengths are in units of 8 octets and a length
     * of zero is invalid. Accepting it makes the option parser loop
     * forever - this is a classic NDP denial of service. */
    ck_abort_msg("pending: ND option length validation");
}
END_TEST

START_TEST(test_nd6_redirect_messages_are_ignored)
{
    /* Redirect (type 137) is out of scope for a host-only stack and must
     * be ignored rather than acted on. */
    ck_abort_msg("pending: ND redirect handling");
}
END_TEST

#endif /* WOLFIP_IPV6_HAVE_ND6 */

/* =========================================================================
 * SLAAC and DAD - RFC 4862
 * ========================================================================= */
#if WOLFIP_IPV6_HAVE_SLAAC

START_TEST(test_slaac_forms_link_local_from_interface_identifier)
{
    /* RFC 4862 s5.3: fe80::/64 plus the interface identifier. */
    ck_abort_msg("pending: SLAAC link-local formation");
}
END_TEST

START_TEST(test_slaac_link_local_is_tentative_until_dad_completes)
{
    /* RFC 4862 s5.4: an address is TENTATIVE while DAD runs and must not
     * be used as a source, other than for the DAD solicitation itself. */
    ck_abort_msg("pending: SLAAC tentative state");
}
END_TEST

START_TEST(test_slaac_dad_success_promotes_address_to_preferred)
{
    ck_abort_msg("pending: DAD success path");
}
END_TEST

START_TEST(test_slaac_dad_failure_abandons_the_address)
{
    /* RFC 4862 s5.4.5: on a duplicate, the address must not be assigned.
     * If it was the link-local address, IPv6 on that interface stops. */
    ck_abort_msg("pending: DAD failure path");
}
END_TEST

START_TEST(test_slaac_dad_detects_a_duplicate_advertisement)
{
    ck_abort_msg("pending: DAD duplicate detection");
}
END_TEST

START_TEST(test_slaac_dad_detects_a_simultaneous_solicitation)
{
    /* RFC 4862 s5.4.3: receiving a solicitation for our own tentative
     * address, from the unspecified source, means another node is running
     * DAD for the same address at the same time. Both must abandon it. */
    ck_abort_msg("pending: DAD simultaneous probe");
}
END_TEST

START_TEST(test_slaac_forms_global_address_from_advertised_prefix)
{
    /* RFC 4862 s5.5.3 */
    ck_abort_msg("pending: SLAAC global address formation");
}
END_TEST

START_TEST(test_slaac_ignores_prefix_that_is_not_64_bits)
{
    /* RFC 4862 s5.5.3 (d): if the prefix length plus the interface
     * identifier length is not 128, the option must be ignored. */
    ck_abort_msg("pending: SLAAC prefix length check");
}
END_TEST

START_TEST(test_slaac_ignores_link_local_prefix_in_advertisement)
{
    /* RFC 4862 s5.5.3 (a): an advertised fe80::/10 prefix is silently
     * ignored, which stops a hostile RA from redefining link-local. */
    ck_abort_msg("pending: SLAAC link-local prefix rejection");
}
END_TEST

START_TEST(test_slaac_preferred_lifetime_expiry_deprecates_address)
{
    /* RFC 4862 s5.5.4: a deprecated address may still be used by existing
     * connections but must not be chosen for new ones. */
    ck_abort_msg("pending: SLAAC address deprecation");
}
END_TEST

START_TEST(test_slaac_valid_lifetime_expiry_removes_address)
{
    ck_abort_msg("pending: SLAAC address expiry");
}
END_TEST

START_TEST(test_slaac_lifetime_extension_is_bounded)
{
    /* RFC 4862 s5.5.3 (e): the two-hour rule. Without it an attacker can
     * extend the lifetime of an address indefinitely with one forged RA. */
    ck_abort_msg("pending: SLAAC two-hour rule");
}
END_TEST

START_TEST(test_slaac_respects_the_address_table_limit)
{
    /* WOLFIP_IP6_ADDR_MAX per interface. A stream of RAs advertising
     * distinct prefixes must not overflow the table. */
    ck_abort_msg("pending: SLAAC address table bound");
}
END_TEST

#endif /* WOLFIP_IPV6_HAVE_SLAAC */

/* =========================================================================
 * DHCPv6 client - RFC 8415
 * ========================================================================= */
#if WOLFIP_IPV6_HAVE_DHCP6

START_TEST(test_dhcp6_solicit_goes_to_all_dhcp_servers_multicast)
{
    /* RFC 8415 s16: ff02::1:2, from a link-local source, UDP 546 to 547. */
    ck_abort_msg("pending: DHCPv6 solicit");
}
END_TEST

START_TEST(test_dhcp6_solicit_carries_client_id_and_ia_na)
{
    /* RFC 8415 s18.2.1 */
    ck_abort_msg("pending: DHCPv6 solicit options");
}
END_TEST

START_TEST(test_dhcp6_advertise_with_mismatched_transaction_id_is_ignored)
{
    /* RFC 8415 s16.3. Without this an off-path attacker can answer a
     * request it never saw. */
    ck_abort_msg("pending: DHCPv6 transaction id check");
}
END_TEST

START_TEST(test_dhcp6_reply_assigns_the_offered_address)
{
    ck_abort_msg("pending: DHCPv6 reply handling");
}
END_TEST

START_TEST(test_dhcp6_retransmission_uses_exponential_backoff)
{
    /* RFC 8415 s15: RT is doubled with randomisation, and clamped at MRT. */
    ck_abort_msg("pending: DHCPv6 retransmission timing");
}
END_TEST

START_TEST(test_dhcp6_renew_at_t1_and_rebind_at_t2)
{
    /* RFC 8415 s18.2.4 and s18.2.5 */
    ck_abort_msg("pending: DHCPv6 renew and rebind");
}
END_TEST

START_TEST(test_dhcp6_option_longer_than_the_message_is_rejected)
{
    /* An option whose declared length runs past the end of the datagram
     * must abort parsing, not read beyond the buffer. */
    ck_abort_msg("pending: DHCPv6 option bounds");
}
END_TEST

START_TEST(test_dhcp6_message_larger_than_buffer_is_rejected)
{
    /* WOLFIP_DHCP6_BUF_SIZE */
    ck_abort_msg("pending: DHCPv6 buffer bound");
}
END_TEST

#endif /* WOLFIP_IPV6_HAVE_DHCP6 */

/* =========================================================================
 * Extension headers - RFC 8200 section 4
 * ========================================================================= */
#if WOLFIP_IPV6_HAVE_EXTHDR

START_TEST(test_ip6_walks_hop_by_hop_and_destination_options)
{
    /* When extension header support lands, these two must be skipped to
     * reach the upper-layer header. Until then ip6_recv rejects them, which
     * test_ip6_recv_rejects_every_extension_header pins down. */
    ck_abort_msg("pending: extension header chain walk");
}
END_TEST

START_TEST(test_ip6_extension_header_chain_length_is_capped)
{
    /* An unbounded chain of tiny option headers is a denial of service.
     * The walk must stop after a fixed number of headers. */
    ck_abort_msg("pending: extension header chain cap");
}
END_TEST

START_TEST(test_ip6_extension_header_with_zero_length_is_rejected)
{
    /* A header claiming zero total length makes the walk loop forever. */
    ck_abort_msg("pending: extension header length validation");
}
END_TEST

START_TEST(test_ip6_routing_header_type_zero_is_still_rejected)
{
    /* RFC 5095 deprecated routing header type 0 because it enabled traffic
     * amplification. Enabling the chain walk must not resurrect it. */
    ck_abort_msg("pending: routing header type 0 rejection");
}
END_TEST

#endif /* WOLFIP_IPV6_HAVE_EXTHDR */

/* =========================================================================
 * Sockets and dual stack
 * ========================================================================= */
#if WOLFIP_IPV6_HAVE_SOCKETS

START_TEST(test_socket_af_inet6_stream_and_dgram_are_created)
{
    ck_abort_msg("pending: AF_INET6 socket creation");
}
END_TEST

START_TEST(test_socket_bind_and_getsockname_roundtrip_ipv6)
{
    ck_abort_msg("pending: AF_INET6 bind");
}
END_TEST

START_TEST(test_socket_v4_mapped_destination_is_framed_as_ipv4)
{
    /* The family that decides framing is that of the destination address,
     * not the socket domain: a v4-mapped destination on an AF_INET6 socket
     * must go out as a 20-byte IPv4 header, not a 40-byte IPv6 one. This is
     * the central correctness risk of the dual-stack design. */
    ck_abort_msg("pending: v4-mapped framing");
}
END_TEST

START_TEST(test_socket_v4_mapped_peer_is_reported_as_mapped_address)
{
    /* An IPv4 peer arriving on a dual-stack AF_INET6 socket is reported as
     * ::ffff:a.b.c.d by recvfrom and getpeername. */
    ck_abort_msg("pending: v4-mapped peer reporting");
}
END_TEST

START_TEST(test_socket_ipv6_only_option_is_honoured_not_silently_accepted)
{
    /* setsockopt and getsockopt currently return 0 for unknown options, so
     * IPV6_V6ONLY would appear to work whatever the stack actually does.
     * The option must be genuinely stored and reported. */
    ck_abort_msg("pending: IPV6_V6ONLY");
}
END_TEST

START_TEST(test_socket_ipv6_only_socket_rejects_v4_mapped_destination)
{
    ck_abort_msg("pending: IPV6_V6ONLY enforcement");
}
END_TEST

START_TEST(test_socket_tcp_mss_accounts_for_the_40_byte_header)
{
    /* The IPv6 header is 20 bytes larger than IPv4, so the MSS derived
     * from the same link MTU must be 20 bytes smaller. */
    ck_abort_msg("pending: IPv6 TCP MSS");
}
END_TEST

START_TEST(test_socket_udp_oversize_datagram_is_refused)
{
    /* No fragmentation: a datagram larger than the path MTU less headers
     * must be refused at sendto rather than silently truncated. */
    ck_abort_msg("pending: IPv6 UDP size limit");
}
END_TEST

START_TEST(test_socket_ipv4_and_ipv6_sockets_coexist_on_one_port)
{
    ck_abort_msg("pending: dual-stack port sharing");
}
END_TEST

#endif /* WOLFIP_IPV6_HAVE_SOCKETS */

#endif /* WOLFIP_IPV6 */

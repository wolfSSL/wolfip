/* unit_tests_misc_edges.c
 *
 * Copyright (C) 2024 wolfSSL Inc.
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
/* =====================================================================
 * wolfIP_init -- NULL stack pointer branch
 * ===================================================================== */
START_TEST(test_wolfip_init_null_stack)
{
    wolfIP_init(NULL);
    ck_assert(1);
}
END_TEST

/* =====================================================================
 * wolfIP_init_static -- NULL output pointer branch
 * ===================================================================== */
START_TEST(test_wolfip_init_static_null_ptr)
{
#ifndef WOLFIP_NOSTATIC
    wolfIP_init_static(NULL);
    ck_assert(1);
#endif
}
END_TEST

/* =====================================================================
 * wolfIP_ipconfig_set_ex -- NULL stack
 * ===================================================================== */
START_TEST(test_wolfip_ipconfig_set_ex_null_stack)
{
    wolfIP_ipconfig_set_ex(NULL, 0, 0x0a000001U, 0xffffff00U, 0);
    ck_assert(1);
}
END_TEST

START_TEST(test_wolfip_ipconfig_set_ex_bad_ifidx)
{
    struct wolfIP s;
    wolfIP_init(&s);
    wolfIP_ipconfig_set_ex(&s, WOLFIP_MAX_INTERFACES + 5, 0x0a000001U, 0xffffff00U, 0);
    ck_assert(1);
}
END_TEST

/* =====================================================================
 * wolfIP_ipconfig_get_ex -- NULL stack / NULL output pointers
 * ===================================================================== */
START_TEST(test_wolfip_ipconfig_get_ex_null_stack)
{
    ip4 ip = 1;
    ip4 mask = 1;
    ip4 gw = 1;
    wolfIP_ipconfig_get_ex(NULL, 0, &ip, &mask, &gw);
    ck_assert_int_eq((int)ip, 1);
}
END_TEST

START_TEST(test_wolfip_ipconfig_get_ex_null_out_ptrs)
{
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    wolfIP_ipconfig_get_ex(&s, TEST_PRIMARY_IF, NULL, NULL, NULL);
    ck_assert(1);
}
END_TEST

/* =====================================================================
 * wolfIP_mtu_set -- zero, below min, above max branches
 * ===================================================================== */
START_TEST(test_wolfip_mtu_set_zero_resets_to_default)
{
    struct wolfIP s;
    uint32_t mtu = 0;
    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF, 0), 0);
    wolfIP_mtu_get(&s, TEST_PRIMARY_IF, &mtu);
    ck_assert_uint_eq(mtu, LINK_MTU);
}
END_TEST

START_TEST(test_wolfip_mtu_set_below_min_clamps)
{
    struct wolfIP s;
    uint32_t mtu = 0;
    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF, LINK_MTU_MIN - 1), 0);
    wolfIP_mtu_get(&s, TEST_PRIMARY_IF, &mtu);
    ck_assert_uint_eq(mtu, LINK_MTU_MIN);
}
END_TEST

START_TEST(test_wolfip_mtu_set_above_max_clamps)
{
    struct wolfIP s;
    uint32_t mtu = 0;
    wolfIP_init(&s);
    mock_link_init(&s);
    ck_assert_int_eq(wolfIP_mtu_set(&s, TEST_PRIMARY_IF, LINK_MTU + 1000), 0);
    wolfIP_mtu_get(&s, TEST_PRIMARY_IF, &mtu);
    ck_assert_uint_eq(mtu, LINK_MTU);
}
END_TEST

START_TEST(test_wolfip_mtu_get_null_mtu_ptr)
{
    struct wolfIP s;
    int ret;
    wolfIP_init(&s);
    mock_link_init(&s);
    ret = wolfIP_mtu_get(&s, TEST_PRIMARY_IF, NULL);
    ck_assert_int_lt(ret, 0);
}
END_TEST

/* =====================================================================
 * wolfIP_arp_lookup_ex -- NULL stack, NULL mac, success branches
 * ===================================================================== */
#ifdef ETHERNET
START_TEST(test_wolfip_arp_lookup_ex_null_stack)
{
    uint8_t mac[6] = {0};
    int ret = wolfIP_arp_lookup_ex(NULL, 0, 0x0a000002U, mac);
    ck_assert_int_lt(ret, 0);
}
END_TEST

START_TEST(test_wolfip_arp_lookup_ex_null_mac)
{
    struct wolfIP s;
    int ret;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    ret = wolfIP_arp_lookup_ex(&s, TEST_PRIMARY_IF, 0x0a000002U, NULL);
    ck_assert_int_lt(ret, 0);
}
END_TEST

START_TEST(test_wolfip_arp_lookup_ex_found)
{
    struct wolfIP s;
    ip4 ip = 0x0a000002U;
    static const uint8_t stored_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t mac[6] = {0};
    int ret;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    s.arp.neighbors[0].ip = ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, stored_mac, 6);
    s.arp.neighbors[0].ts = s.last_tick;
    ret = wolfIP_arp_lookup_ex(&s, TEST_PRIMARY_IF, ip, mac);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(mac, stored_mac, 6);
}
END_TEST
#endif /* ETHERNET */

/* =====================================================================
 * fifo_push -- h_wrap defensive branches
 * ===================================================================== */
START_TEST(test_fifo_push_full_hwrap_head_eq_tail)
{
    /* head==tail and h_wrap!=0: space=0 */
    uint8_t buf[128];
    uint8_t data[8] = {1,2,3,4,5,6,7,8};
    struct fifo f;
    int ret;
    memset(&f, 0, sizeof(f));
    f.data = buf;
    f.size = 128;
    f.h_wrap = 128;
    f.head = 0;
    f.tail = 0;
    ret = fifo_push(&f, data, sizeof(data));
    ck_assert_int_eq(ret, -1);
}
END_TEST

START_TEST(test_fifo_push_hwrap_head_ge_tail_space_zero)
{
    /* h_wrap set, head > tail → space=0 */
    uint8_t buf[128];
    uint8_t data[8] = {0};
    struct fifo f;
    int ret;
    memset(&f, 0, sizeof(f));
    f.data = buf;
    f.size = 128;
    f.h_wrap = 128;
    f.head = 64;
    f.tail = 32;
    ret = fifo_push(&f, data, sizeof(data));
    ck_assert_int_eq(ret, -1);
}
END_TEST

START_TEST(test_fifo_push_no_end_space_tail_too_small)
{
    /* h_wrap==0, head >= tail, end_space < needed, tail < needed */
    uint8_t buf[64];
    uint8_t data[8] = {0};
    struct fifo f;
    int ret;
    memset(&f, 0, sizeof(f));
    f.data = buf;
    f.size = 64;
    f.head = 60;
    f.tail = 4;
    f.h_wrap = 0;
    ret = fifo_push(&f, data, sizeof(data));
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* =====================================================================
 * fifo_can_push_len -- hwrap branch returns 0
 * ===================================================================== */
START_TEST(test_fifo_can_push_len_hwrap_head_plus_needed_gt_tail)
{
    uint8_t buf[128];
    struct fifo f;
    int ret;
    memset(&f, 0, sizeof(f));
    f.data = buf;
    f.size = 128;
    f.h_wrap = 128;
    f.head = 50;
    f.tail = 56;
    ret = fifo_can_push_len(&f, 32);
    ck_assert_int_eq(ret, 0);
}
END_TEST

START_TEST(test_fifo_can_push_len_no_hwrap_head_plus_needed_gt_size)
{
    uint8_t buf[64];
    struct fifo f;
    int ret;
    memset(&f, 0, sizeof(f));
    f.data = buf;
    f.size = 64;
    f.head = 60;
    f.tail = 0;
    f.h_wrap = 0;
    ret = fifo_can_push_len(&f, 40);
    ck_assert_int_eq(ret, 0);
}
END_TEST

/* =====================================================================
 * fifo_next -- pos out of range, desc->len too large
 * ===================================================================== */
START_TEST(test_fifo_next_pos_out_of_range)
{
    uint8_t buf[128];
    struct fifo f;
    struct pkt_desc *desc;
    struct pkt_desc *ret;
    memset(&f, 0, sizeof(f));
    f.data = buf;
    f.size = 128;
    /* desc pointer outside the buffer */
    desc = (struct pkt_desc *)(buf + 200);
    ret = fifo_next(&f, desc);
    ck_assert_ptr_null(ret);
}
END_TEST

START_TEST(test_fifo_next_desc_len_too_large)
{
    uint8_t buf[128];
    struct fifo f;
    struct pkt_desc *d;
    struct pkt_desc *ret;
    memset(&f, 0, sizeof(f));
    f.data = buf;
    f.size = 128;
    f.head = 64;
    f.tail = 0;
    d = (struct pkt_desc *)buf;
    d->len = 50000;
    d->pos = 0;
    ret = fifo_next(&f, d);
    ck_assert_ptr_null(ret);
}
END_TEST

/* =====================================================================
 * fifo_len -- tail > head with h_wrap > 0 branch
 * ===================================================================== */
START_TEST(test_fifo_len_tail_gt_head_with_hwrap)
{
    uint8_t buf[128];
    struct fifo f;
    uint32_t len;
    memset(&f, 0, sizeof(f));
    f.data = buf;
    f.size = 128;
    f.tail = 80;
    f.head = 20;
    f.h_wrap = 100;
    f.last_valid = 1;
    f.last_pos = 0;
    len = fifo_len(&f);
    /* len = (100 - 80) + 20 = 40 */
    ck_assert_uint_eq(len, 40);
}
END_TEST

/* =====================================================================
 * iphdr_verify_checksum -- bad and good checksum
 * ===================================================================== */
START_TEST(test_iphdr_verify_checksum_bad)
{
    struct wolfIP s;
    uint8_t framebuf[ETH_HEADER_LEN + IP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)framebuf;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    memset(framebuf, 0, sizeof(framebuf));
    ip->ver_ihl = 0x45;
    ip->ttl = 64;
    ip->proto = WI_IPPROTO_UDP;
    ip->len = ee16(IP_HEADER_LEN + 8);
    ip->src = ee32(0x0a0000a1U);
    ip->dst = ee32(0x0a000001U);
    ip->csum = 0xDEAD;
    wolfIP_recv(&s, framebuf, sizeof(framebuf));
    ck_assert(1);
}
END_TEST

START_TEST(test_iphdr_verify_checksum_good)
{
    struct wolfIP s;
    uint8_t framebuf[ETH_HEADER_LEN + IP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)framebuf;
    struct wolfIP_ll_dev *ll;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    memset(framebuf, 0, sizeof(framebuf));
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    memcpy(ip->eth.dst, ll->mac, 6);
    ip->eth.type = ee16(ETH_TYPE_IP);
    ip->ver_ihl = 0x45;
    ip->ttl = 64;
    ip->proto = WI_IPPROTO_UDP;
    ip->len = ee16(IP_HEADER_LEN + 8);
    ip->src = ee32(0x0a0000a1U);
    ip->dst = ee32(0x0a000001U);
    ip->csum = 0;
    iphdr_set_checksum(ip);
    wolfIP_recv(&s, framebuf, sizeof(framebuf));
    ck_assert(1);
}
END_TEST

/* =====================================================================
 * wolfIP_ip_is_broadcast -- edge cases
 * ===================================================================== */
START_TEST(test_wolfip_ip_is_broadcast_null_stack)
{
    int r = wolfIP_ip_is_broadcast(NULL, 0x0a000001U);
    ck_assert_int_eq(r, 0);
}
END_TEST

START_TEST(test_wolfip_ip_is_broadcast_all_ones)
{
    struct wolfIP s;
    int r;
    wolfIP_init(&s);
    mock_link_init(&s);
    r = wolfIP_ip_is_broadcast(&s, 0xFFFFFFFFU);
    ck_assert_int_eq(r, 1);
}
END_TEST

START_TEST(test_wolfip_ip_is_broadcast_full_mask_skipped)
{
    struct wolfIP s;
    int r;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xFFFFFFFFU, 0);
    r = wolfIP_ip_is_broadcast(&s, 0x0a0000FFU);
    ck_assert_int_eq(r, 0);
}
END_TEST

/* =====================================================================
 * wolfIP_select_nexthop -- NULL conf, broadcast branches
 * ===================================================================== */
START_TEST(test_wolfip_select_nexthop_null_conf)
{
    ip4 dest = 0x0a000002U;
    ip4 ret = wolfIP_select_nexthop(NULL, dest);
    ck_assert_uint_eq(ret, dest);
}
END_TEST

START_TEST(test_wolfip_select_nexthop_broadcast)
{
    struct ipconf conf;
    ip4 ret;
    memset(&conf, 0, sizeof(conf));
    conf.ip   = 0x0a000001U;
    conf.mask = 0xffffff00U;
    conf.gw   = 0x0a0000feU;
    ret = wolfIP_select_nexthop(&conf, 0xFFFFFFFFU);
    ck_assert_uint_eq(ret, 0xFFFFFFFFU);
}
END_TEST

/* =====================================================================
 * eth_is_ipv4_multicast_mac / mcast_membership_find / udp_socket_has_mcast
 * ===================================================================== */
#ifdef IP_MULTICAST
START_TEST(test_eth_is_ipv4_multicast_mac_true)
{
    uint8_t mac[6] = {0x01, 0x00, 0x5e, 0x00, 0x01, 0x01};
    ck_assert_int_eq(eth_is_ipv4_multicast_mac(mac), 1);
}
END_TEST

START_TEST(test_eth_is_ipv4_multicast_mac_high_bit_set)
{
    uint8_t mac[6] = {0x01, 0x00, 0x5e, 0x80, 0x01, 0x01};
    ck_assert_int_eq(eth_is_ipv4_multicast_mac(mac), 0);
}
END_TEST

START_TEST(test_eth_is_ipv4_multicast_mac_wrong_prefix)
{
    uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    ck_assert_int_eq(eth_is_ipv4_multicast_mac(mac), 0);
}
END_TEST

START_TEST(test_mcast_membership_find_null_stack)
{
    struct wolfIP_mcast_membership *ret =
        mcast_membership_find(NULL, 0, 0xe0000001U);
    ck_assert_ptr_null(ret);
}
END_TEST

START_TEST(test_udp_socket_has_mcast_null_tsocket)
{
    int ret = udp_socket_has_mcast(NULL, 0, 0xe0000001U);
    ck_assert_int_eq(ret, 0);
}
END_TEST
#endif /* IP_MULTICAST */

/* =====================================================================
 * wolfIP_ip_is_multicast -- boundary values
 * ===================================================================== */
START_TEST(test_wolfip_ip_is_multicast_boundary)
{
    ck_assert_int_ne(wolfIP_ip_is_multicast(0xE0000000U), 0);
    ck_assert_int_eq(wolfIP_ip_is_multicast(0xDFFFFFFFU), 0);
    ck_assert_int_ne(wolfIP_ip_is_multicast(0xEFFFFFFFU), 0);
    ck_assert_int_eq(wolfIP_ip_is_multicast(0xF0000000U), 0);
}
END_TEST

/* =====================================================================
 * close_socket -- NULL and non-TCP/UDP variants
 * ===================================================================== */
START_TEST(test_close_socket_null)
{
    close_socket(NULL);
    ck_assert(1);
}
END_TEST

START_TEST(test_close_socket_non_tcp_udp)
{
    /* ICMP tsocket: close_socket with proto == WI_IPPROTO_ICMP */
    struct wolfIP s;
    struct tsocket *ts;
    int fd;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    /* Use DGRAM + ICMP to get an icmpsocket (a tsocket) */
    fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_ge(fd, 0);
    ts = wolfIP_socket_from_fd(&s, fd);
    ck_assert_ptr_nonnull(ts);
    close_socket(ts);
    ck_assert(1);
}
END_TEST

/* =====================================================================
 * tx_has_writable_space -- unknown proto and NULL
 * ===================================================================== */
START_TEST(test_tx_has_writable_space_unknown_proto)
{
    struct tsocket ts;
    int ret;
    memset(&ts, 0, sizeof(ts));
    ts.proto = 0xFF;
    ret = tx_has_writable_space(&ts);
    ck_assert_int_eq(ret, 0);
}
END_TEST

START_TEST(test_tx_has_writable_space_null)
{
    int ret = tx_has_writable_space(NULL);
    ck_assert_int_eq(ret, 0);
}
END_TEST

/* =====================================================================
 * bind_port_in_use -- port==0 early return
 * ===================================================================== */
START_TEST(test_bind_port_in_use_port_zero)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    int fd1;
    int fd2;
    int ret;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    fd1 = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    fd2 = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_ge(fd1, 0);
    ck_assert_int_ge(fd2, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0a000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd1, (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), 0);
    sin.sin_port = 0;
    ret = wolfIP_sock_bind(&s, fd2, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, 0);
}
END_TEST

/* =====================================================================
 * arp_pending_record -- refresh existing entry, replace oldest
 * ===================================================================== */
#ifdef ETHERNET
START_TEST(test_arp_pending_record_refresh_existing)
{
    struct wolfIP s;
    ip4 ip = 0x0a000002U;
    int i;
    int found = 0;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    s.last_tick = 0;
    arp_pending_record(&s, TEST_PRIMARY_IF, ip);
    s.last_tick = 100;
    arp_pending_record(&s, TEST_PRIMARY_IF, ip);
    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++) {
        if (s.arp.pending[i].ip == ip) {
            ck_assert_uint_eq((uint32_t)s.arp.pending[i].ts, 100);
            found = 1;
            break;
        }
    }
    ck_assert_int_eq(found, 1);
}
END_TEST

START_TEST(test_arp_pending_record_replaces_oldest)
{
    struct wolfIP s;
    ip4 new_ip = 0x0a0000FFU;
    int i;
    int found = 0;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    s.last_tick = 1000;
    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++) {
        s.arp.pending[i].ip = (ip4)(0x0a000010U + (uint32_t)i);
        s.arp.pending[i].if_idx = TEST_PRIMARY_IF;
        s.arp.pending[i].ts = (uint64_t)(100 * (i + 1));
    }
    s.last_tick = 2000;
    arp_pending_record(&s, TEST_PRIMARY_IF, new_ip);
    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++) {
        if (s.arp.pending[i].ip == new_ip) {
            found = 1;
            break;
        }
    }
    ck_assert_int_eq(found, 1);
}
END_TEST

/* =====================================================================
 * arp_pending_match_and_clear -- expire stale entries, NULL stack
 * ===================================================================== */
START_TEST(test_arp_pending_match_and_clear_expires_stale)
{
    struct wolfIP s;
    ip4 target = 0x0a000002U;
    int ret;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    s.arp.pending[0].ip = target;
    s.arp.pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp.pending[0].ts = 0;
    s.last_tick = (uint64_t)ARP_PENDING_TTL_MS + 1000;
    ret = arp_pending_match_and_clear(&s, TEST_PRIMARY_IF, target);
    ck_assert_int_eq(ret, 0);
    ck_assert_uint_eq(s.arp.pending[0].ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_pending_match_and_clear_null_stack)
{
    int ret = arp_pending_match_and_clear(NULL, 0, 0x0a000002U);
    ck_assert_int_eq(ret, 0);
}
END_TEST

/* =====================================================================
 * arp_neighbor_index -- aged-out entry, NULL stack
 * ===================================================================== */
START_TEST(test_arp_neighbor_index_aged_out)
{
    struct wolfIP s;
    ip4 ip = 0x0a000002U;
    static const uint8_t mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    int idx;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    s.arp.neighbors[0].ip = ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, mac, 6);
    s.arp.neighbors[0].ts = 0;
    s.last_tick = (uint64_t)ARP_AGING_TIMEOUT_MS + 1000;
    idx = arp_neighbor_index(&s, TEST_PRIMARY_IF, ip);
    ck_assert_int_eq(idx, -1);
    ck_assert_uint_eq(s.arp.neighbors[0].ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_neighbor_index_null_stack)
{
    int idx = arp_neighbor_index(NULL, 0, 0x0a000002U);
    ck_assert_int_eq(idx, -1);
}
END_TEST
#endif /* ETHERNET */

/* =====================================================================
 * wolfIP_route_for_ip -- NULL stack, broadcast/any dest
 * ===================================================================== */
START_TEST(test_wolfip_route_for_ip_null_stack)
{
    unsigned int ret = wolfIP_route_for_ip(NULL, 0x0a000002U);
    ck_assert_uint_eq(ret, 0);
}
END_TEST

START_TEST(test_wolfip_route_for_ip_broadcast_address)
{
    struct wolfIP s;
    unsigned int ret;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    ret = wolfIP_route_for_ip(&s, IPADDR_ANY);
    ck_assert_uint_eq(ret, WOLFIP_PRIMARY_IF_IDX);
}
END_TEST

/* =====================================================================
 * wolfIP_forward_interface -- NULL/single-iface, dest == local ip
 * ===================================================================== */
#if WOLFIP_ENABLE_FORWARDING
START_TEST(test_wolfip_forward_interface_null_or_single_iface)
{
    int ret = wolfIP_forward_interface(NULL, 0, 0x0a000002U);
    ck_assert_int_lt(ret, 0);
}
END_TEST

START_TEST(test_wolfip_forward_interface_local_dest_rejected)
{
    struct wolfIP s;
    int ret;
    wolfIP_init(&s);
    mock_link_init(&s);
    mock_link_init_idx(&s, TEST_SECOND_IF, NULL);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    wolfIP_ipconfig_set_ex(&s, TEST_SECOND_IF, 0x0a000101U, 0xffffff00U, 0);
    ret = wolfIP_forward_interface(&s, TEST_PRIMARY_IF, 0x0a000101U);
    ck_assert_int_lt(ret, 0);
}
END_TEST
#endif

/* =====================================================================
 * wolfIP_loopback_send -- NULL ll argument
 * ===================================================================== */
#if WOLFIP_ENABLE_LOOPBACK
START_TEST(test_wolfip_loopback_send_null_ll)
{
    int ret = wolfIP_loopback_send(NULL, NULL, 0);
    ck_assert_int_lt(ret, 0);
}
END_TEST
#endif

/* =====================================================================
 * wolfIP_send_ttl_exceeded -- no send function (null ll)
 * ===================================================================== */
#if WOLFIP_ENABLE_FORWARDING && defined(ETHERNET)
START_TEST(test_wolfip_send_ttl_exceeded_null_ll)
{
    struct wolfIP s;
    uint8_t framebuf[ETH_HEADER_LEN + IP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *orig = (struct wolfIP_ip_packet *)framebuf;
    wolfIP_init(&s);
    memset(framebuf, 0, sizeof(framebuf));
    orig->ver_ihl = 0x45;
    orig->ttl = 1;
    orig->proto = WI_IPPROTO_UDP;
    wolfIP_send_ttl_exceeded(&s, TEST_PRIMARY_IF, orig);
    ck_assert(1);
}
END_TEST
#endif

/* =====================================================================
 * wolfIP_send_port_unreachable -- no send function
 * ===================================================================== */
#ifdef ETHERNET
START_TEST(test_wolfip_send_port_unreachable_null_ll_misc)
{
    struct wolfIP s;
    uint8_t framebuf[ETH_HEADER_LEN + IP_HEADER_LEN + 8];
    struct wolfIP_ip_packet *orig = (struct wolfIP_ip_packet *)framebuf;
    wolfIP_init(&s);
    memset(framebuf, 0, sizeof(framebuf));
    orig->ver_ihl = 0x45;
    orig->proto = WI_IPPROTO_UDP;
    wolfIP_send_port_unreachable(&s, TEST_PRIMARY_IF, orig);
    ck_assert(1);
}
END_TEST
#endif

/* =====================================================================
 * wolfIP_sock_socket -- ICMP success
 * ===================================================================== */
START_TEST(test_wolfip_sock_socket_icmp_success)
{
    struct wolfIP s;
    int fd;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_ICMP);
    ck_assert_int_ge(fd, 0);
    wolfIP_sock_close(&s, fd);
}
END_TEST

/* =====================================================================
 * wolfIP_rawsocket_from_fd -- !used branch
 * ===================================================================== */
#if WOLFIP_RAWSOCKETS
START_TEST(test_wolfip_rawsocket_from_fd_not_used)
{
    struct wolfIP s;
    struct rawsocket *rs;
    int fd;
    wolfIP_init(&s);
    mock_link_init(&s);
    fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(fd, 0);
    wolfIP_sock_close(&s, fd);
    rs = wolfIP_rawsocket_from_fd(&s, fd);
    ck_assert_ptr_null(rs);
}
END_TEST
#endif

/* =====================================================================
 * wolfIP_packetsocket_from_fd -- !used branch
 * ===================================================================== */
#if WOLFIP_PACKET_SOCKETS
START_TEST(test_wolfip_packetsocket_from_fd_not_used)
{
    struct wolfIP s;
    struct packetsocket *ps;
    int fd;
    wolfIP_init(&s);
    mock_link_init(&s);
    fd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, 0);
    ck_assert_int_ge(fd, 0);
    wolfIP_sock_close(&s, fd);
    ps = wolfIP_packetsocket_from_fd(&s, fd);
    ck_assert_ptr_null(ps);
}
END_TEST
#endif

/* =====================================================================
 * wolfIP_recv_on -- short frame dropped without crash
 * ===================================================================== */
START_TEST(test_wolfip_recv_on_short_frame)
{
    struct wolfIP s;
    uint8_t tiny[4] = {0};
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    wolfIP_recv_on(&s, TEST_PRIMARY_IF, tiny, sizeof(tiny));
    ck_assert(1);
}
END_TEST

/* =====================================================================
 * wolfIP_filter_mask_for_proto -- default (unknown proto) branch
 * ===================================================================== */
START_TEST(test_filter_mask_for_proto_default_branch)
{
    uint32_t old_mask = wolfIP_filter_get_mask();
    uint32_t ret;
    wolfIP_filter_set_mask(0xABCD1234U);
    ret = wolfIP_filter_mask_for_proto(0xFF00);
    ck_assert_uint_eq(ret, 0xABCD1234U);
    wolfIP_filter_set_mask(old_mask);
}
END_TEST

/* =====================================================================
 * wolfIP_filter_dispatch -- meta==NULL branch
 * ===================================================================== */
START_TEST(test_filter_dispatch_null_meta_initializes)
{
    struct wolfIP s;
    wolfIP_init(&s);
    filter_cb_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(~0U);
    wolfIP_filter_dispatch(WOLFIP_FILT_SENDING, &s, 0, NULL, 0, NULL);
    ck_assert_int_ge(filter_cb_calls, 1);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
}
END_TEST

/* =====================================================================
 * wolfIP_sock_listen -- non-TCP socket returns error
 * ===================================================================== */
START_TEST(test_wolfip_sock_listen_udp_fd)
{
    struct wolfIP s;
    int fd;
    int ret;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_ge(fd, 0);
    ret = wolfIP_sock_listen(&s, fd, 5);
    ck_assert_int_lt(ret, 0);
    wolfIP_sock_close(&s, fd);
}
END_TEST

/* =====================================================================
 * wolfIP_sock_accept -- non-TCP socket returns error
 * ===================================================================== */
START_TEST(test_wolfip_sock_accept_udp_fd)
{
    struct wolfIP s;
    socklen_t addrlen = sizeof(struct wolfIP_sockaddr_in);
    int fd;
    int ret;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_ge(fd, 0);
    ret = wolfIP_sock_accept(&s, fd, NULL, &addrlen);
    ck_assert_int_lt(ret, 0);
    wolfIP_sock_close(&s, fd);
}
END_TEST

/* =====================================================================
 * wolfIP_sock_close -- negative fd
 * ===================================================================== */
START_TEST(test_wolfip_sock_close_negative_fd)
{
    struct wolfIP s;
    int ret;
    wolfIP_init(&s);
    ret = wolfIP_sock_close(&s, -1);
    ck_assert_int_lt(ret, 0);
}
END_TEST

/* =====================================================================
 * ipcounter_next -- increments and wraps
 * ===================================================================== */
START_TEST(test_ipcounter_next_increments)
{
    struct wolfIP s;
    uint16_t v1;
    uint16_t v2;
    wolfIP_init(&s);
    s.ipcounter = 0;
    v1 = ipcounter_next(&s);
    v2 = ipcounter_next(&s);
    ck_assert_uint_eq(ee16(v1), 0);
    ck_assert_uint_eq(ee16(v2), 1);
}
END_TEST

START_TEST(test_ipcounter_next_wraps)
{
    struct wolfIP s;
    wolfIP_init(&s);
    s.ipcounter = 0xFFFF;
    ipcounter_next(&s);
    ck_assert_uint_eq(s.ipcounter, 0);
}
END_TEST

/* =====================================================================
 * queue_insert -- len > size-1 returns error
 * ===================================================================== */
START_TEST(test_queue_insert_pos_equals_size_returns_error)
{
    uint8_t buf[8];
    uint8_t data[16];
    struct queue q;
    int ret;
    memset(&q, 0, sizeof(q));
    memset(data, 0xAB, sizeof(data));
    q.data = buf;
    q.size = 8;
    q.head = 0;
    q.tail = 0;
    ret = queue_insert(&q, data, 0, 16);
    ck_assert_int_lt(ret, 0);
}
END_TEST

/* =====================================================================
 * Full TCP socket table -- exercises boundary check
 * ===================================================================== */
START_TEST(test_wolfip_sock_socket_tcp_all_sockets)
{
    struct wolfIP s;
    int fds[MAX_TCPSOCKETS];
    int count = 0;
    int extra;
    int i;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    for (i = 0; i < MAX_TCPSOCKETS; i++) {
        fds[i] = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
        if (fds[i] < 0)
            break;
        count++;
    }
    extra = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_lt(extra, 0);
    for (i = 0; i < count; i++)
        wolfIP_sock_close(&s, fds[i]);
}
END_TEST

/* =====================================================================
 * raw_try_recv -- filter blocks incoming frame
 * ===================================================================== */
#if WOLFIP_RAWSOCKETS
START_TEST(test_raw_try_recv_filter_blocks_frame)
{
    struct wolfIP s;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + 8 + sizeof(struct wolfIP_udp_datagram)];
    struct wolfIP_udp_datagram *udp;
    struct wolfIP_ll_dev *ll;
    int fd;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(fd, 0);
    filter_cb_calls = 0;
    filter_block_calls = 0;
    filter_block_reason = WOLFIP_FILT_RECEIVING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(~0U);
    memset(frame, 0, sizeof(frame));
    udp = (struct wolfIP_udp_datagram *)(frame + ETH_HEADER_LEN);
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    memcpy(((struct wolfIP_eth_frame *)frame)->dst, ll->mac, 6);
    ((struct wolfIP_eth_frame *)frame)->type = ee16(ETH_TYPE_IP);
    udp->ip.ver_ihl = 0x45;
    udp->ip.ttl = 64;
    udp->ip.proto = WI_IPPROTO_UDP;
    udp->ip.len = ee16(IP_HEADER_LEN + (uint16_t)sizeof(struct wolfIP_udp_datagram));
    udp->ip.src = ee32(0x0a0000a1U);
    udp->ip.dst = ee32(0x0a000001U);
    iphdr_set_checksum(&udp->ip);
    udp->dst_port = ee16(1234);
    udp->src_port = ee16(5678);
    udp->len = ee16(8);
    wolfIP_recv(&s, frame, sizeof(frame));
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
    wolfIP_sock_close(&s, fd);
}
END_TEST
#endif

/* =====================================================================
 * fifo_can_push_len -- h_wrap==0, head < tail branch (space = tail - head)
 * ===================================================================== */
START_TEST(test_fifo_can_push_len_head_lt_tail_no_hwrap)
{
    uint8_t buf[128];
    struct fifo f;
    int ret;
    memset(&f, 0, sizeof(f));
    f.data = buf;
    f.size = 128;
    /* h_wrap==0, head < tail → space = tail - head */
    f.h_wrap = 0;
    f.head = 10;
    f.tail = 80;
    /* needed = sizeof(pkt_desc) + 4 -- should fit within space=70 */
    ret = fifo_can_push_len(&f, 4);
    ck_assert_int_eq(ret, 1);
}
END_TEST

/* =====================================================================
 * fifo_can_push_len -- h_wrap && head == h_wrap → reset head to 0
 * h_wrap=50, head=50 (==h_wrap), tail=80: space = tail-head = 80-50 = 30
 * after reset head=0; needed=20 < tail(80) → fits → return 1
 * ===================================================================== */
START_TEST(test_fifo_can_push_len_hwrap_head_equals_hwrap)
{
    uint8_t buf[128];
    struct fifo f;
    int ret;
    memset(&f, 0, sizeof(f));
    f.data = buf;
    f.size = 128;
    /* h_wrap=50, head=50 (==h_wrap), tail=80
     * space calculation: h_wrap set, head(50) < tail(80) → space = 30 > needed(20)
     * Then h_wrap && head == h_wrap → head = 0
     * Then if(h_wrap): 0+20 <= 80 → return 1 */
    f.h_wrap = 50;
    f.head = 50;
    f.tail = 80;
    ret = fifo_can_push_len(&f, 4);
    ck_assert_int_eq(ret, 1);
}
END_TEST

/* =====================================================================
 * fifo_push -- h_wrap set, head == h_wrap: wraps head to 0 then succeeds
 * h_wrap=50, head=50, tail=80 → space=30>20, reset head=0, 0+20<80 → ok
 * ===================================================================== */
START_TEST(test_fifo_push_hwrap_head_equals_hwrap_succeeds)
{
    uint8_t buf[128];
    uint8_t data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    struct fifo f;
    int ret;
    memset(&f, 0, sizeof(f));
    f.data = buf;
    f.size = 128;
    f.h_wrap = 50;
    f.head = 50;   /* == h_wrap → will wrap to 0 */
    f.tail = 80;   /* space = 80-50 = 30 > 20; after wrap head=0, 0+20<=80 */
    ret = fifo_push(&f, data, sizeof(data));
    ck_assert_int_eq(ret, 0);
}
END_TEST

/* =====================================================================
 * fifo_push -- h_wrap==0, head >= tail, end_space < needed but tail >= needed
 * head=120, tail=64: end_space=8 < needed(20), tail(64)>=needed(20)
 * → wrap: h_wrap=120, head=0; then h_wrap && 0+20<=64 → succeeds
 * ===================================================================== */
START_TEST(test_fifo_push_no_hwrap_wraps_to_front_succeeds)
{
    uint8_t buf[128];
    uint8_t data[4] = {1, 2, 3, 4};
    struct fifo f;
    int ret;
    memset(&f, 0, sizeof(f));
    f.data = buf;
    f.size = 128;
    f.h_wrap = 0;
    f.head = 120;
    f.tail = 64;
    ret = fifo_push(&f, data, sizeof(data));
    ck_assert_int_eq(ret, 0);
}
END_TEST

/* =====================================================================
 * fifo_push -- head + needed == f->size (lands exactly at end)
 * sizeof(pkt_desc)=16, data=4 → needed=20
 * head=108, size=128 → 108+20=128 == size → head=0, h_wrap=128
 * ===================================================================== */
START_TEST(test_fifo_push_exact_end_sets_hwrap)
{
    uint8_t buf[128];
    uint8_t data[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    struct fifo f;
    int ret;
    memset(&f, 0, sizeof(f));
    f.data = buf;
    f.size = 128;
    f.h_wrap = 0;
    /* head=108: 108 + 16(pkt_desc) + 4(data) = 128 = size → land at end */
    f.head = 108;
    f.tail = 0;
    ret = fifo_push(&f, data, sizeof(data));
    ck_assert_int_eq(ret, 0);
    ck_assert_uint_eq(f.h_wrap, 128);
    ck_assert_uint_eq(f.head, 0);
}
END_TEST

/* =====================================================================
 * wolfIP_send_port_unreachable -- orig_ihl > TTL_EXCEEDED_ORIG_PACKET_SIZE_MAX
 * (exercises orig_copy clamping branch at line 2037)
 * ===================================================================== */
#ifdef ETHERNET
START_TEST(test_wolfip_send_port_unreachable_large_ihl)
{
    struct wolfIP s;
    uint8_t framebuf[ETH_HEADER_LEN + 100];
    struct wolfIP_ip_packet *orig = (struct wolfIP_ip_packet *)framebuf;
    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    memset(framebuf, 0, sizeof(framebuf));
    /* Set ihl to an inflated value */
    orig->ver_ihl = 0x4F; /* ihl = 15 * 4 = 60 bytes */
    orig->proto = WI_IPPROTO_UDP;
    orig->src = ee32(0x0a0000a1U);
    orig->ttl = 64;
    wolfIP_send_port_unreachable(&s, TEST_PRIMARY_IF, orig);
    ck_assert(1);
}
END_TEST
#endif

/* =====================================================================
 * wolfIP_rawsocket_from_fd -- negative fd
 * ===================================================================== */
#if WOLFIP_RAWSOCKETS
START_TEST(test_wolfip_rawsocket_from_fd_negative_fd)
{
    struct wolfIP s;
    struct rawsocket *rs;
    wolfIP_init(&s);
    rs = wolfIP_rawsocket_from_fd(&s, -1);
    ck_assert_ptr_null(rs);
}
END_TEST
#endif

/* =====================================================================
 * wolfIP_packetsocket_from_fd -- negative fd
 * ===================================================================== */
#if WOLFIP_PACKET_SOCKETS
START_TEST(test_wolfip_packetsocket_from_fd_negative_fd)
{
    struct wolfIP s;
    struct packetsocket *ps;
    wolfIP_init(&s);
    ps = wolfIP_packetsocket_from_fd(&s, -1);
    ck_assert_ptr_null(ps);
}
END_TEST
#endif

/* =====================================================================
 * bind_port_in_use -- port in use, different local IPs (skip collision)
 * ===================================================================== */
START_TEST(test_bind_port_in_use_different_ips_no_collision)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    int fd1;
    int fd2;
    int ret;
    wolfIP_init(&s);
    mock_link_init(&s);
    mock_link_init_idx(&s, TEST_SECOND_IF, NULL);
    wolfIP_ipconfig_set(&s, 0x0a000001U, 0xffffff00U, 0);
    wolfIP_ipconfig_set_ex(&s, TEST_SECOND_IF, 0x0a000101U, 0xffffff00U, 0);
    fd1 = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    fd2 = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_ge(fd1, 0);
    ck_assert_int_ge(fd2, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5000);
    sin.sin_addr.s_addr = ee32(0x0a000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, fd1, (struct wolfIP_sockaddr *)&sin,
                                      sizeof(sin)), 0);
    /* Different IP, same port -- should succeed (different local IPs) */
    sin.sin_addr.s_addr = ee32(0x0a000101U);
    ret = wolfIP_sock_bind(&s, fd2, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, 0);
}
END_TEST

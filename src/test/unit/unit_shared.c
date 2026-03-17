/* unit.c
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
#include "check.h"
#include "../../../config.h"
#undef DEBUG_UDP
#define DEBUG_UDP 1
#undef CONFIG_IPFILTER
#define CONFIG_IPFILTER 1
#undef WOLFIP_MAX_INTERFACES
#define WOLFIP_MAX_INTERFACES 3
#undef WOLFIP_ENABLE_LOOPBACK
#define WOLFIP_ENABLE_LOOPBACK 1
#undef WOLFIP_ENABLE_FORWARDING
#ifndef WOLFIP_ENABLE_FORWARDING
#define WOLFIP_ENABLE_FORWARDING 1
#endif
#if WOLFIP_ENABLE_LOOPBACK
#define TEST_LOOPBACK_IF 0U
#define TEST_PRIMARY_IF 1U
#define TEST_SECOND_IF 2U
#else
#define TEST_LOOPBACK_IF 0U
#define TEST_PRIMARY_IF 0U
#define TEST_SECOND_IF 1U
#endif
#include <stdio.h>
#include "../../wolfip.c"
#include <stdlib.h> /* for random() */
#include "mocks/wolfssl/wolfcrypt/settings.h"
#include "mocks/wolfssl/wolfcrypt/memory.h"
#include "mocks/wolfssl/ssl.h"

/* MOCKS */
/* pseudo random number generator to mock the random number generator */
static int test_rand_override_enabled;
static uint32_t test_rand_override_value;

uint32_t wolfIP_getrandom(void)
{
    unsigned int seed = 0xDAC0FFEE;
    if (test_rand_override_enabled)
        return test_rand_override_value;
    srandom(seed);
    return random();
}

static uint8_t mem[8 * 1024];
static uint32_t memsz = 8 * 1024;
static const uint8_t ifmac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
static uint8_t last_frame_sent[LINK_MTU];
static uint32_t last_frame_sent_size = 0;

static int mock_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t  len)
{
    (void)dev;
    memcpy(last_frame_sent, frame, len);
    last_frame_sent_size = len;
    return 0;
}

static int mock_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    (void)dev;
    (void)frame;
    (void)len;
    return 0;
}

static void mock_link_init_idx(struct wolfIP *s, unsigned int idx, const uint8_t *mac_override)
{
    struct wolfIP_ll_dev *ll = wolfIP_getdev_ex(s, idx);
    ck_assert_ptr_nonnull(ll);
    memset(ll, 0, sizeof(*ll));
    snprintf((char *)ll->ifname, sizeof(ll->ifname), "mock%u", idx);
    if (mac_override) {
        memcpy(ll->mac, mac_override, 6);
    } else {
        memcpy(ll->mac, ifmac, 6);
        ll->mac[5] ^= (uint8_t)(idx + 1);
    }
    ll->poll = mock_poll;
    ll->send = mock_send;
}

/* wolfSSL IO mocks (used by tests below) */
static CallbackIORecv g_ctx_recv_cb;
static CallbackIOSend g_ctx_send_cb;
static void *g_last_read_ctx;
static void *g_last_write_ctx;
static WOLFSSL_CTX *g_last_ctx;
static int test_recv_ret;
static int test_send_ret;
static uint8_t test_recv_fill[32];
static int test_recv_fill_len;
static uint8_t test_send_capture[32];
static int test_send_capture_len;
static int test_send_last_len;
static int test_recv_step;
static int test_recv_steps_len;
static int test_recv_steps[8];
static int test_recv_step_total;
static int filter_cb_calls;
static struct wolfIP_filter_event filter_last_event;
static enum wolfIP_filter_reason filter_block_reason;
static int filter_block_calls;
static int socket_cb_calls;
static int socket_cb_last_fd;
static uint16_t socket_cb_last_events;
static int timer_cb_calls;
static uint32_t dns_lookup_ip;
static int dns_lookup_calls;

struct tcp_seg_buf {
    struct wolfIP_tcp_seg seg;
    uint8_t pad[TCP_HEADER_LEN];
};

int wolfSSL_SetIORecv(WOLFSSL_CTX *ctx, CallbackIORecv cb)
{
    g_last_ctx = ctx;
    g_ctx_recv_cb = cb;
    return 0;
}

int wolfSSL_SetIOSend(WOLFSSL_CTX *ctx, CallbackIOSend cb)
{
    g_last_ctx = ctx;
    g_ctx_send_cb = cb;
    return 0;
}

int wolfSSL_SetIOReadCtx(WOLFSSL *ssl, void *ctx)
{
    if (ssl)
        ssl->rctx = ctx;
    g_last_read_ctx = ctx;
    return 0;
}

int wolfSSL_SetIOWriteCtx(WOLFSSL *ssl, void *ctx)
{
    if (ssl)
        ssl->wctx = ctx;
    g_last_write_ctx = ctx;
    return 0;
}

WOLFSSL_CTX *wolfSSL_get_SSL_CTX(WOLFSSL *ssl)
{
    if (!ssl)
        return NULL;
    return ssl->ctx;
}

static int test_wolfIP_sock_recv(struct wolfIP *s, int fd, void *buf, int sz, int flags)
{
    (void)s;
    (void)fd;
    (void)flags;
    if (test_recv_steps_len > 0) {
        int step = 0;
        if (test_recv_step < test_recv_steps_len)
            step = test_recv_steps[test_recv_step++];
        if (step == -WOLFIP_EAGAIN) {
            return -WOLFIP_EAGAIN;
        } else if (step > 0) {
            int offset = test_recv_step_total;
            int copy_len = step;
            if (copy_len > sz)
                copy_len = sz;
            if (offset + copy_len > (int)sizeof(test_recv_fill))
                copy_len = (int)sizeof(test_recv_fill) - offset;
            if (copy_len > 0) {
                memcpy(buf, test_recv_fill + offset, (size_t)copy_len);
                test_recv_step_total += copy_len;
            }
            return step;
        } else {
            return step;
        }
    }
    if (test_recv_fill_len > 0 && test_recv_ret > 0) {
        int copy_len = test_recv_fill_len;
        if (copy_len > sz)
            copy_len = sz;
        memcpy(buf, test_recv_fill, (size_t)copy_len);
    }
    return test_recv_ret;
}

static int test_wolfIP_sock_send(struct wolfIP *s, int fd, const void *buf, int sz, int flags)
{
    (void)s;
    (void)fd;
    (void)flags;
    test_send_last_len = sz;
    if (test_send_capture_len > 0) {
        int copy_len = test_send_capture_len;
        if (copy_len > sz)
            copy_len = sz;
        memcpy(test_send_capture, buf, (size_t)copy_len);
    }
    return test_send_ret;
}

#define wolfIP_sock_recv test_wolfIP_sock_recv
#define wolfIP_sock_send test_wolfIP_sock_send
#include "../../port/wolfssl_io.c"
#undef wolfIP_sock_recv
#undef wolfIP_sock_send

static void reset_wolfssl_io_state(void)
{
    memset(ctx_map, 0, sizeof(ctx_map));
    memset(io_descs, 0, sizeof(io_descs));
    g_ctx_recv_cb = NULL;
    g_ctx_send_cb = NULL;
    g_last_read_ctx = NULL;
    g_last_write_ctx = NULL;
    g_last_ctx = NULL;
    test_recv_ret = 0;
    test_send_ret = 0;
    test_recv_fill_len = 0;
    test_send_capture_len = 0;
    test_send_last_len = 0;
    test_recv_step = 0;
    test_recv_steps_len = 0;
    test_recv_step_total = 0;
    memset(test_recv_steps, 0, sizeof(test_recv_steps));
    memset(test_recv_fill, 0, sizeof(test_recv_fill));
    memset(test_send_capture, 0, sizeof(test_send_capture));
}

static int test_filter_cb(void *arg, const struct wolfIP_filter_event *event)
{
    (void)arg;
    if (event) {
        filter_last_event = *event;
        filter_cb_calls++;
    }
    return 0;
}

static int test_filter_cb_block(void *arg, const struct wolfIP_filter_event *event)
{
    (void)arg;
    if (event) {
        filter_block_calls++;
        if (event->reason == filter_block_reason)
            return 1;
    }
    return 0;
}

static void test_socket_cb(int sock_fd, uint16_t events, void *arg)
{
    (void)arg;
    socket_cb_calls++;
    socket_cb_last_fd = sock_fd;
    socket_cb_last_events = events;
}

static void test_timer_cb(void *arg)
{
    (void)arg;
    timer_cb_calls++;
}

static void test_dns_lookup_cb(uint32_t ip)
{
    dns_lookup_ip = ip;
    dns_lookup_calls++;
}

static void test_dns_ptr_cb(const char *name)
{
    (void)name;
}

void mock_link_init(struct wolfIP *s)
{
    unsigned int idx = 0;
#if WOLFIP_ENABLE_LOOPBACK
    idx = 1;
#endif
    mock_link_init_idx(s, idx, NULL);
}

static struct timers_binheap heap;
static void reset_heap(void) {
    heap.size = 0;
}

static void setup_stack_with_two_ifaces(struct wolfIP *s, ip4 primary_ip, ip4 secondary_ip)
{
    wolfIP_init(s);
    mock_link_init(s);
    mock_link_init_idx(s, TEST_SECOND_IF, NULL);
    wolfIP_ipconfig_set(s, primary_ip, 0xFFFFFF00U, 0);
    wolfIP_ipconfig_set_ex(s, TEST_SECOND_IF, secondary_ip, 0xFFFFFF00U, 0);
}

static void inject_tcp_syn(struct wolfIP *s, unsigned int if_idx, ip4 dst_ip, uint16_t dst_port)
{
    struct wolfIP_tcp_seg syn;
    struct wolfIP_ll_dev *ll = wolfIP_getdev_ex(s, if_idx);
    union transport_pseudo_header ph;
    static const uint8_t src_mac[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};

    ck_assert_ptr_nonnull(ll);
    memset(&syn, 0, sizeof(syn));
    memcpy(syn.ip.eth.dst, ll->mac, 6);
    memcpy(syn.ip.eth.src, src_mac, 6);
    syn.ip.eth.type = ee16(ETH_TYPE_IP);
    syn.ip.ver_ihl = 0x45;
    syn.ip.ttl = 64;
    syn.ip.proto = WI_IPPROTO_TCP;
    syn.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    syn.ip.src = ee32(0x0A0000A1U);
    syn.ip.dst = ee32(dst_ip);
    syn.ip.csum = 0;
    iphdr_set_checksum(&syn.ip);

    syn.src_port = ee16(40000);
    syn.dst_port = ee16(dst_port);
    syn.seq = ee32(1);
    syn.ack = 0;
    syn.hlen = TCP_HEADER_LEN << 2;
    syn.flags = TCP_FLAG_SYN;
    syn.win = ee16(65535);
    syn.csum = 0;
    syn.urg = 0;

    memset(&ph, 0, sizeof(ph));
    ph.ph.src = syn.ip.src;
    ph.ph.dst = syn.ip.dst;
    ph.ph.proto = WI_IPPROTO_TCP;
    ph.ph.len = ee16(TCP_HEADER_LEN);
    syn.csum = ee16(transport_checksum(&ph, &syn.src_port));

    tcp_input(s, if_idx, &syn, sizeof(struct wolfIP_eth_frame) + IP_HEADER_LEN + TCP_HEADER_LEN);
}

static void inject_tcp_segment(struct wolfIP *s, unsigned int if_idx, ip4 src_ip, ip4 dst_ip,
        uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack, uint8_t flags)
{
    struct wolfIP_tcp_seg seg;
    struct wolfIP_ll_dev *ll = wolfIP_getdev_ex(s, if_idx);
    union transport_pseudo_header ph;
    static const uint8_t src_mac[6] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25};

    ck_assert_ptr_nonnull(ll);
    memset(&seg, 0, sizeof(seg));
    memcpy(seg.ip.eth.dst, ll->mac, 6);
    memcpy(seg.ip.eth.src, src_mac, 6);
    seg.ip.eth.type = ee16(ETH_TYPE_IP);
    seg.ip.ver_ihl = 0x45;
    seg.ip.ttl = 64;
    seg.ip.proto = WI_IPPROTO_TCP;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(src_ip);
    seg.ip.dst = ee32(dst_ip);
    seg.ip.csum = 0;
    iphdr_set_checksum(&seg.ip);

    seg.src_port = ee16(src_port);
    seg.dst_port = ee16(dst_port);
    seg.seq = ee32(seq);
    seg.ack = ee32(ack);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = flags;
    seg.win = ee16(65535);
    seg.csum = 0;
    seg.urg = 0;

    memset(&ph, 0, sizeof(ph));
    ph.ph.src = seg.ip.src;
    ph.ph.dst = seg.ip.dst;
    ph.ph.proto = WI_IPPROTO_TCP;
    ph.ph.len = ee16(TCP_HEADER_LEN);
    seg.csum = ee16(transport_checksum(&ph, &seg.src_port));

    tcp_input(s, if_idx, &seg, sizeof(struct wolfIP_eth_frame) + IP_HEADER_LEN + TCP_HEADER_LEN);
}

static int tcp_option_find(const struct wolfIP_tcp_seg *tcp, uint8_t kind)
{
    const uint8_t *opt = tcp->data;
    int opt_len = (tcp->hlen >> 2) - TCP_HEADER_LEN;
    int i = 0;

    while (i < opt_len) {
        if (opt[i] == TCP_OPTION_EOO)
            break;
        if (opt[i] == TCP_OPTION_NOP) {
            i++;
            continue;
        }
        if (i + 1 >= opt_len || opt[i + 1] < 2)
            break;
        if (opt[i] == kind)
            return i;
        i += opt[i + 1];
    }
    return -1;
}

/* Helper to compute and set IP header checksum on an already-constructed packet */
static void fix_ip_checksum(struct wolfIP_ip_packet *ip)
{
    ip->csum = 0;
    iphdr_set_checksum(ip);
}

/* Helper to compute and set TCP checksum on an already-constructed segment.
 * tcp_len is the TCP header + payload length (not including IP/Ethernet headers) */
static void fix_tcp_checksum(struct wolfIP_tcp_seg *tcp, uint16_t tcp_len)
{
    union transport_pseudo_header ph;
    memset(&ph, 0, sizeof(ph));
    ph.ph.src = tcp->ip.src;
    ph.ph.dst = tcp->ip.dst;
    ph.ph.proto = WI_IPPROTO_TCP;
    ph.ph.len = ee16(tcp_len);
    tcp->csum = 0;
    tcp->csum = ee16(transport_checksum(&ph, &tcp->src_port));
}

/* Helper to fix both IP and TCP checksums on a segment */
static void fix_tcp_checksums(struct wolfIP_tcp_seg *tcp)
{
    uint16_t tcp_len = ee16(tcp->ip.len) - IP_HEADER_LEN;
    fix_ip_checksum(&tcp->ip);
    fix_tcp_checksum(tcp, tcp_len);
}

/* Helper to compute and set UDP checksum on an already-constructed datagram.
 * udp_len is the UDP header + payload length (not including IP/Ethernet headers) */
static void fix_udp_checksum(struct wolfIP_udp_datagram *udp, uint16_t udp_len)
{
    union transport_pseudo_header ph;
    memset(&ph, 0, sizeof(ph));
    ph.ph.src = udp->ip.src;
    ph.ph.dst = udp->ip.dst;
    ph.ph.proto = WI_IPPROTO_UDP;
    ph.ph.len = ee16(udp_len);
    udp->csum = 0;
    udp->csum = ee16(transport_checksum(&ph, &udp->src_port));
}

/* Helper to fix both IP and UDP checksums on a datagram */
static void fix_udp_checksums(struct wolfIP_udp_datagram *udp)
{
    uint16_t udp_len = ee16(udp->ip.len) - IP_HEADER_LEN;
    fix_ip_checksum(&udp->ip);
    fix_udp_checksum(udp, udp_len);
}

static void fix_ip_checksum_with_hlen(struct wolfIP_ip_packet *ip, uint16_t ip_hlen)
{
    uint32_t sum = 0;
    uint32_t i;
    const uint8_t *ptr = (const uint8_t *)(&ip->ver_ihl);

    ip->csum = 0;
    for (i = 0; i < ip_hlen; i += 2) {
        uint16_t word;
        memcpy(&word, ptr + i, sizeof(word));
        sum += ee16(word);
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    ip->csum = ee16((uint16_t)~sum);
}

static void fix_udp_checksum_raw(struct wolfIP_ip_packet *ip, void *udp_hdr, uint16_t udp_len)
{
    union transport_pseudo_header ph;
    uint16_t *udp_csum = (uint16_t *)((uint8_t *)udp_hdr + 6);

    memset(&ph, 0, sizeof(ph));
    ph.ph.src = ip->src;
    ph.ph.dst = ip->dst;
    ph.ph.proto = WI_IPPROTO_UDP;
    ph.ph.len = ee16(udp_len);
    *udp_csum = 0;
    *udp_csum = ee16(transport_checksum(&ph, udp_hdr));
}

static void inject_udp_datagram(struct wolfIP *s, unsigned int if_idx, ip4 src_ip, ip4 dst_ip,
        uint16_t src_port, uint16_t dst_port, const uint8_t *payload, uint16_t payload_len)
{
    uint8_t frame[LINK_MTU];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)frame;
    struct wolfIP_ll_dev *ll = wolfIP_getdev_ex(s, if_idx);
    static const uint8_t src_mac[6] = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95};

    ck_assert_ptr_nonnull(ll);
    memset(udp, 0, sizeof(frame));
    memcpy(udp->ip.eth.dst, ll->mac, 6);
    memcpy(udp->ip.eth.src, src_mac, 6);
    udp->ip.eth.type = ee16(ETH_TYPE_IP);
    udp->ip.ver_ihl = 0x45;
    udp->ip.ttl = 64;
    udp->ip.proto = WI_IPPROTO_UDP;
    udp->ip.len = ee16(IP_HEADER_LEN + UDP_HEADER_LEN + payload_len);
    udp->ip.src = ee32(src_ip);
    udp->ip.dst = ee32(dst_ip);
    udp->ip.csum = 0;
    iphdr_set_checksum(&udp->ip);

    udp->src_port = ee16(src_port);
    udp->dst_port = ee16(dst_port);
    udp->len = ee16(UDP_HEADER_LEN + payload_len);
    udp->csum = 0;
    if (payload_len && payload) {
        memcpy(udp->data, payload, payload_len);
    }

    udp_try_recv(s, if_idx, udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + payload_len));
}

static int enqueue_tcp_tx(struct tsocket *ts, uint32_t payload_len, uint8_t flags)
{
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 16];
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)buf;
    uint32_t total_len = IP_HEADER_LEN + TCP_HEADER_LEN + payload_len;
    uint32_t frame_len = ETH_HEADER_LEN + total_len;

    ck_assert_uint_le(payload_len, 16);
    memset(tcp, 0, sizeof(buf));
    tcp->ip.len = ee16((uint16_t)total_len);
    tcp->hlen = TCP_HEADER_LEN << 2;
    tcp->flags = flags;
    tcp->seq = ee32(ts->sock.tcp.seq);
    tcp->ack = ee32(ts->sock.tcp.ack);
    tcp->src_port = ee16(ts->src_port);
    tcp->dst_port = ee16(ts->dst_port);
    if (payload_len > 0) {
        uint8_t *payload = (uint8_t *)tcp->ip.data + TCP_HEADER_LEN;
        memset(payload, 0xAB, payload_len);
    }
    return fifo_push(&ts->sock.tcp.txbuf, tcp, frame_len);
}

static int enqueue_tcp_tx_with_payload(struct tsocket *ts, const uint8_t *payload_data,
        uint32_t payload_len, uint8_t flags)
{
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 16];
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)buf;
    uint32_t total_len = IP_HEADER_LEN + TCP_HEADER_LEN + payload_len;
    uint32_t frame_len = ETH_HEADER_LEN + total_len;
    uint8_t *payload;

    ck_assert_uint_le(payload_len, 16);
    memset(tcp, 0, sizeof(buf));
    tcp->ip.len = ee16((uint16_t)total_len);
    tcp->hlen = TCP_HEADER_LEN << 2;
    tcp->flags = flags;
    tcp->seq = ee32(ts->sock.tcp.seq);
    tcp->ack = ee32(ts->sock.tcp.ack);
    tcp->src_port = ee16(ts->src_port);
    tcp->dst_port = ee16(ts->dst_port);
    if (payload_len > 0) {
        payload = (uint8_t *)tcp->ip.data + TCP_HEADER_LEN;
        memcpy(payload, payload_data, payload_len);
    }
    return fifo_push(&ts->sock.tcp.txbuf, tcp, frame_len);
}

static void enqueue_udp_rx(struct tsocket *ts, const void *payload, uint16_t payload_len, uint16_t src_port)
{
    uint8_t buf[sizeof(struct wolfIP_udp_datagram) + 1024];
    struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)buf;
    uint16_t total = UDP_HEADER_LEN + payload_len;

    ck_assert_uint_le(payload_len, 1024);
    memset(udp, 0, sizeof(buf));
    udp->src_port = ee16(src_port);
    udp->dst_port = ee16(ts->src_port);
    udp->len = ee16(total);
    memcpy(udp->data, payload, payload_len);
    (void)fifo_push(&ts->sock.udp.rxbuf, udp, sizeof(struct wolfIP_udp_datagram) + payload_len);
}



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
    syn.flags = 0x02;
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


START_TEST(test_fifo_init)
{
    struct fifo f;
    fifo_init(&f, mem, memsz);
    ck_assert_int_eq(fifo_len(&f), 0);
    ck_assert_int_eq(fifo_space(&f), memsz);
    ck_assert_int_eq(fifo_len(&f), 0);
}
END_TEST

START_TEST(test_fifo_peek_wraps_tail_when_head_lt_tail)
{
    struct fifo f;
    uint8_t data[64];
    struct pkt_desc *desc;

    fifo_init(&f, data, sizeof(data));
    f.head = 0;
    f.tail = 4;
    f.h_wrap = 0;

    /* With head at 0 and tail aligned, peek should return the current tail
     * descriptor without altering tail or wrap state. */
    desc = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(f.tail, 4);
}
END_TEST

START_TEST(test_fifo_peek_no_wrap_when_space_available)
{
    struct fifo f;
    uint8_t data[4096];
    struct pkt_desc *desc;

    fifo_init(&f, data, sizeof(data));
    f.head = 0;
    f.tail = 4;
    f.h_wrap = 0;

    /* When no wrap boundary is set, peek must not change tail. */
    desc = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(f.tail, 4);
}
END_TEST

START_TEST(test_fifo_next_wraps_on_hwrap)
{
    struct fifo f;
    uint8_t data[4096];
    struct pkt_desc *desc0;
    struct pkt_desc *desc1;
    struct pkt_desc *next;
    uint32_t len;

    fifo_init(&f, data, sizeof(data));

    desc0 = (struct pkt_desc *)data;
    desc0->pos = 0;
    desc0->len = 4;
    len = sizeof(struct pkt_desc) + desc0->len;
    while (len % 4)
        len++;

    desc1 = (struct pkt_desc *)(data + len);
    desc1->pos = 0;
    desc1->len = 0;
    f.h_wrap = len;
    f.head = len + 8;

    next = fifo_next(&f, desc0);
    ck_assert_ptr_eq(next, (struct pkt_desc *)data);
}
END_TEST

START_TEST(test_fifo_pop_aligns_tail_to_head_returns_null)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    f.head = 4;
    f.tail = 1;

    /* Aligning tail to head means the FIFO is empty; pop should return NULL. */
    ck_assert_ptr_eq(fifo_pop(&f), NULL);
}
END_TEST

START_TEST(test_fifo_pop_wraps_tail_when_head_lt_tail)
{
    struct fifo f;
    uint8_t data[64];
    struct pkt_desc *desc;

    fifo_init(&f, data, sizeof(data));
    f.head = 0;
    f.tail = 4;
    f.h_wrap = 0;

    desc = (struct pkt_desc *)(data + 4);
    desc->pos = 4;
    desc->len = 0;

    /* Popping a zero-length packet should advance tail past the descriptor. */
    ck_assert_ptr_nonnull(fifo_pop(&f));
    ck_assert_uint_eq(f.tail, 4 + sizeof(struct pkt_desc));
}
END_TEST

START_TEST(test_fifo_pop_no_wrap_when_space_available)
{
    struct fifo f;
    uint8_t data[4096];
    struct pkt_desc *desc;
    uint32_t expected_tail;

    fifo_init(&f, data, sizeof(data));
    f.head = 0;
    f.tail = 4;
    f.h_wrap = 0;

    desc = (struct pkt_desc *)(data + 4);
    desc->pos = 4;
    desc->len = 0;
    expected_tail = 4 + sizeof(struct pkt_desc);

    /* With no wrap, pop should advance tail to the next descriptor. */
    ck_assert_ptr_nonnull(fifo_pop(&f));
    ck_assert_uint_eq(f.tail, expected_tail);
}
END_TEST

START_TEST(test_fifo_peek_empty_unaligned_tail)
{
    struct fifo f;
    uint8_t data[64];
    struct pkt_desc *desc;

    fifo_init(&f, data, sizeof(data));
    f.head = 3;
    f.tail = 3;
    f.h_wrap = 0;

    desc = fifo_peek(&f);
    ck_assert_ptr_eq(desc, NULL);
    ck_assert_uint_eq(f.tail, 3);
    ck_assert_uint_eq(f.h_wrap, 0);
}
END_TEST

START_TEST(test_fifo_len_empty_unaligned_tail)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    f.head = 3;
    f.tail = 3;
    f.h_wrap = 0;

    ck_assert_uint_eq(fifo_len(&f), 0);
    ck_assert_uint_eq(f.tail, 3);
}
END_TEST

START_TEST(test_fifo_pop_empty_unaligned_tail)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    f.head = 3;
    f.tail = 3;
    f.h_wrap = 0;

    ck_assert_ptr_eq(fifo_pop(&f), NULL);
    ck_assert_uint_eq(f.tail, 3);
}
END_TEST

START_TEST(test_fifo_push_pop_odd_sizes_drains_cleanly)
{
    struct fifo f;
    uint8_t data[256];
    struct pkt_desc *desc;
    uint8_t p1[3] = {0x01, 0x02, 0x03};
    uint8_t p2[5] = {0x11, 0x12, 0x13, 0x14, 0x15};
    uint8_t p3[7] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27};

    fifo_init(&f, data, sizeof(data));
    ck_assert_int_eq(fifo_push(&f, p1, sizeof(p1)), 0);
    ck_assert_int_eq(fifo_push(&f, p2, sizeof(p2)), 0);
    ck_assert_int_eq(fifo_push(&f, p3, sizeof(p3)), 0);

    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), p1, sizeof(p1));
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), p2, sizeof(p2));
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), p3, sizeof(p3));

    ck_assert_uint_eq(fifo_len(&f), 0);
    ck_assert_ptr_eq(fifo_peek(&f), NULL);
}
END_TEST

START_TEST(test_fifo_full_wrap_does_not_appear_empty_or_discard_packets)
{
    struct fifo f;
    uint8_t data[120];
    uint8_t payload[8];
    struct pkt_desc *desc;
    int i;

    memset(payload, 0xAB, sizeof(payload));
    fifo_init(&f, data, sizeof(data));

    /* 5 * (sizeof(pkt_desc)=16 + payload=8) == 120: fills FIFO exactly and
     * forces head == tail with wrap marker set (full, not empty). */
    for (i = 0; i < 5; i++) {
        payload[0] = (uint8_t)i;
        ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    }

    ck_assert_uint_eq(fifo_space(&f), 0);
    ck_assert_uint_eq(f.head, f.tail);
    ck_assert_uint_eq(f.h_wrap, sizeof(data));

    /* Full FIFO must still expose packets. */
    desc = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(desc->len, sizeof(payload));
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 0);

    for (i = 0; i < 5; i++) {
        desc = fifo_pop(&f);
        ck_assert_ptr_nonnull(desc);
        ck_assert_uint_eq(desc->len, sizeof(payload));
        ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), (uint8_t)i);
    }

    ck_assert_ptr_eq(fifo_peek(&f), NULL);
    ck_assert_uint_eq(fifo_len(&f), 0);
}
END_TEST

START_TEST(test_fifo_next_stops_at_aligned_head_when_head_unaligned)
{
    struct fifo f;
    uint8_t data[128];
    uint8_t p1[3] = {0x11, 0x12, 0x13};
    uint8_t p2[5] = {0x21, 0x22, 0x23, 0x24, 0x25};
    struct pkt_desc *d1;
    struct pkt_desc *d2;
    struct pkt_desc *d3;

    fifo_init(&f, data, sizeof(data));
    ck_assert_int_eq(fifo_push(&f, p1, sizeof(p1)), 0);
    ck_assert_int_eq(fifo_push(&f, p2, sizeof(p2)), 0);

    /* fifo_push aligns only on insertion boundaries; head can stay unaligned. */
    ck_assert_uint_ne(f.head % 4, 0);

    d1 = fifo_peek(&f);
    ck_assert_ptr_nonnull(d1);
    ck_assert_uint_eq(d1->len, sizeof(p1));
    ck_assert_uint_eq(*((uint8_t *)f.data + d1->pos + sizeof(*d1)), p1[0]);

    d2 = fifo_next(&f, d1);
    ck_assert_ptr_nonnull(d2);
    ck_assert_uint_eq(d2->len, sizeof(p2));
    ck_assert_uint_eq(*((uint8_t *)f.data + d2->pos + sizeof(*d2)), p2[0]);

    /* Must stop at aligned insertion cursor, not scan padding as descriptors. */
    d3 = fifo_next(&f, d2);
    ck_assert_ptr_eq(d3, NULL);
}
END_TEST

START_TEST(test_fifo_full_wrap_next_iterates_all_entries_without_loss)
{
    struct fifo f;
    uint8_t data[120];
    uint8_t payload[8];
    struct pkt_desc *desc;
    int i;

    memset(payload, 0xCD, sizeof(payload));
    fifo_init(&f, data, sizeof(data));

    for (i = 0; i < 5; i++) {
        payload[0] = (uint8_t)i;
        ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    }

    ck_assert_uint_eq(f.head, f.tail);
    ck_assert_uint_eq(f.h_wrap, sizeof(data));
    ck_assert_uint_eq(fifo_space(&f), 0);

    desc = fifo_peek(&f);
    for (i = 0; i < 5; i++) {
        ck_assert_ptr_nonnull(desc);
        ck_assert_uint_eq(desc->len, sizeof(payload));
        ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), (uint8_t)i);
        desc = fifo_next(&f, desc);
    }
    ck_assert_ptr_eq(desc, NULL);
}
END_TEST

START_TEST(test_fifo_wrap_full_pop_then_refill_keeps_order_without_drops)
{
    struct fifo f;
    uint8_t data[120];
    uint8_t payload[8];
    struct pkt_desc *desc;
    int i;

    memset(payload, 0xEF, sizeof(payload));
    fifo_init(&f, data, sizeof(data));

    for (i = 0; i < 5; i++) {
        payload[0] = (uint8_t)i;
        ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    }
    ck_assert_uint_eq(f.head, f.tail);
    ck_assert_uint_eq(f.h_wrap, sizeof(data));

    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 0);

    payload[0] = 5;
    ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    ck_assert_uint_eq(f.head, f.tail);
    ck_assert_uint_eq(f.h_wrap, sizeof(data));

    for (i = 1; i <= 5; i++) {
        desc = fifo_pop(&f);
        ck_assert_ptr_nonnull(desc);
        ck_assert_uint_eq(desc->len, sizeof(payload));
        ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), (uint8_t)i);
    }

    ck_assert_ptr_eq(fifo_peek(&f), NULL);
    ck_assert_uint_eq(fifo_len(&f), 0);
}
END_TEST

START_TEST(test_fifo_wrap_flag_transitions_push_pop_around_boundary)
{
    struct fifo f;
    uint8_t data[100];
    uint8_t payload[8];
    struct pkt_desc *desc;
    int i;

    fifo_init(&f, data, sizeof(data));
    memset(payload, 0, sizeof(payload));

    /* Fill descriptors at offsets 0,24,48,72 (head=96, no wrap yet). */
    for (i = 0; i < 4; i++) {
        payload[0] = (uint8_t)i;
        ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    }
    ck_assert_uint_eq(f.h_wrap, 0);
    ck_assert_uint_eq(f.head, 96);
    ck_assert_uint_eq(f.tail, 0);

    /* Drain first two packets so tail moves past "needed". */
    for (i = 0; i < 2; i++) {
        desc = fifo_pop(&f);
        ck_assert_ptr_nonnull(desc);
        ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), (uint8_t)i);
    }
    ck_assert_uint_eq(f.tail, 48);
    ck_assert_uint_eq(f.h_wrap, 0);

    /* Next push must wrap head to start and set h_wrap to old head (96). */
    payload[0] = 4;
    ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    ck_assert_uint_eq(f.h_wrap, 96);
    ck_assert_uint_eq(f.head, 24);
    ck_assert_uint_eq(f.tail, 48);

    /* Pop packet at 48: still before wrap marker, flag remains set. */
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 2);
    ck_assert_uint_eq(f.h_wrap, 96);
    ck_assert_uint_eq(f.tail, 72);

    /* Pop packet at 72 crosses wrap marker: tail wraps and h_wrap clears. */
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 3);
    ck_assert_uint_eq(f.h_wrap, 0);
    ck_assert_uint_eq(f.tail, 0);

    /* Wrapped packet remains readable after flag clear. */
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 4);
    ck_assert_ptr_eq(fifo_peek(&f), NULL);
}
END_TEST

START_TEST(test_fifo_wrap_flag_repeated_flips_keep_data_consistent)
{
    struct fifo f;
    uint8_t data[100];
    uint8_t payload[8];
    struct pkt_desc *desc;
    int i;

    fifo_init(&f, data, sizeof(data));
    memset(payload, 0, sizeof(payload));

    for (i = 0; i < 4; i++) {
        payload[0] = (uint8_t)i;
        ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    }
    for (i = 0; i < 2; i++) {
        desc = fifo_pop(&f);
        ck_assert_ptr_nonnull(desc);
        ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), (uint8_t)i);
    }

    payload[0] = 4;
    ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    ck_assert_uint_eq(f.h_wrap, 96);

    desc = fifo_pop(&f); /* 2 */
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 2);
    desc = fifo_pop(&f); /* 3, clears wrap */
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 3);
    ck_assert_uint_eq(f.h_wrap, 0);
    desc = fifo_pop(&f); /* 4 */
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 4);

    /* Build another wrap cycle with new packets 5,6,7,8. */
    for (i = 5; i <= 7; i++) {
        payload[0] = (uint8_t)i;
        ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    }
    desc = fifo_pop(&f); /* 5 */
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 5);

    payload[0] = 8;
    ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    ck_assert_uint_eq(f.h_wrap, 96);

    desc = fifo_pop(&f); /* 6 */
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 6);
    desc = fifo_pop(&f); /* 7, crosses wrap => clear */
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 7);
    ck_assert_uint_eq(f.h_wrap, 0);
    desc = fifo_pop(&f); /* 8 */
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 8);

    ck_assert_ptr_eq(fifo_peek(&f), NULL);
    ck_assert_uint_eq(fifo_len(&f), 0);
}
END_TEST

START_TEST(test_fifo_wrap_flag_transitions_with_odd_payload_sizes)
{
    struct fifo f;
    uint8_t data[80];
    uint8_t p3[3] = {0};
    uint8_t p5[5] = {0};
    struct pkt_desc *desc;

    fifo_init(&f, data, sizeof(data));

    p3[0] = 1; ck_assert_int_eq(fifo_push(&f, p3, sizeof(p3)), 0); /* pos 0 */
    p5[0] = 2; ck_assert_int_eq(fifo_push(&f, p5, sizeof(p5)), 0); /* pos 20 */
    p3[0] = 3; ck_assert_int_eq(fifo_push(&f, p3, sizeof(p3)), 0); /* pos 44 */

    /* Drain first two; leave packet 3 in pre-wrap region. */
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(desc->len, sizeof(p3));
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 1);
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(desc->len, sizeof(p5));
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 2);

    /* Force wrap with odd-size payload and verify wrap marker set. */
    p5[0] = 4;
    ck_assert_int_eq(fifo_push(&f, p5, sizeof(p5)), 0);
    ck_assert_uint_eq(f.h_wrap, 64);
    ck_assert_uint_ne(f.head % 4, 0);

    /* Pop remaining pre-wrap packet; marker stays until boundary crossing. */
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(desc->len, sizeof(p3));
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 3);
    ck_assert_uint_eq(f.h_wrap, 64);

    /* Next pop crosses wrap and clears marker; wrapped payload remains valid. */
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(desc->len, sizeof(p5));
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 4);
    ck_assert_uint_eq(f.h_wrap, 0);
    ck_assert_ptr_eq(fifo_peek(&f), NULL);
}
END_TEST

START_TEST(test_fifo_wrap_flag_repeated_flips_with_odd_payload_sizes)
{
    struct fifo f;
    uint8_t data[80];
    uint8_t p3[3] = {0};
    uint8_t p5[5] = {0};
    uint8_t p7[7] = {0};
    struct pkt_desc *desc;

    fifo_init(&f, data, sizeof(data));

    p7[0] = 5; ck_assert_int_eq(fifo_push(&f, p7, sizeof(p7)), 0); /* pos 0 */
    p3[0] = 6; ck_assert_int_eq(fifo_push(&f, p3, sizeof(p3)), 0); /* pos 24 */
    p5[0] = 7; ck_assert_int_eq(fifo_push(&f, p5, sizeof(p5)), 0); /* pos 44 */

    /* Pop two, then wrap once with odd payload. */
    desc = fifo_pop(&f); ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 5);
    desc = fifo_pop(&f); ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 6);

    p7[0] = 8;
    ck_assert_int_eq(fifo_push(&f, p7, sizeof(p7)), 0);
    ck_assert_uint_eq(f.h_wrap, 68);

    /* Drain remaining in-order, including wrapped element; wrap clears. */
    desc = fifo_pop(&f); ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 7);
    ck_assert_uint_eq(f.h_wrap, 68);
    desc = fifo_pop(&f); ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 8);
    ck_assert_uint_eq(f.h_wrap, 0);
    ck_assert_ptr_eq(fifo_peek(&f), NULL);
}
END_TEST

START_TEST(test_queue_insert_len_gt_space)
{
    struct queue q;
    uint8_t data[8];
    uint8_t payload[6] = {0};

    queue_init(&q, data, sizeof(data), 0);
    ck_assert_int_eq(queue_insert(&q, payload, 0, 6), 0);
    ck_assert_int_eq(queue_insert(&q, payload, 6, 4), -1);
}
END_TEST

START_TEST(test_queue_insert_len_gt_size_returns_error)
{
    struct queue q;
    uint8_t data[8];
    uint8_t payload[12] = {0};

    queue_init(&q, data, sizeof(data), 0);
    ck_assert_int_eq(queue_insert(&q, payload, 0, sizeof(payload)), -1);
}
END_TEST

START_TEST(test_queue_insert_updates_head_when_pos_plus_len_gt_head)
{
    struct queue q;
    uint8_t data[16];
    uint8_t payload[4] = {1,2,3,4};

    queue_init(&q, data, sizeof(data), 0);
    ck_assert_int_eq(queue_insert(&q, payload, 0, 4), 0);
    ck_assert_uint_eq(q.head, 4);
    ck_assert_int_eq(queue_insert(&q, payload, 4, 4), 0);
    ck_assert_uint_eq(q.head, 8);
}
END_TEST

START_TEST(test_queue_insert_no_head_update_when_pos_plus_len_le_head)
{
    struct queue q;
    uint8_t data[16];
    uint8_t payload[4] = {1,2,3,4};
    uint32_t head_before;

    queue_init(&q, data, sizeof(data), 0);
    ck_assert_int_eq(queue_insert(&q, payload, 0, 8), 0);
    head_before = q.head;
    ck_assert_int_eq(queue_insert(&q, payload, 2, 2), 0);
    ck_assert_uint_eq(q.head, head_before);
}
END_TEST

START_TEST(test_wolfip_poll_executes_timers_and_callbacks)
{
    struct wolfIP s;
    struct wolfIP_timer tmr;
    int udp_sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    timer_cb_calls = 0;
    socket_cb_calls = 0;
    socket_cb_last_fd = -1;
    socket_cb_last_events = 0;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 100;
    tmr.arg = NULL;
    timers_binheap_insert(&s.timers, tmr);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    wolfIP_register_callback(&s, udp_sd, test_socket_cb, NULL);
    s.udpsockets[SOCKET_UNMARK(udp_sd)].events = CB_EVENT_READABLE;

    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(timer_cb_calls, 1);
    ck_assert_int_eq(socket_cb_calls, 1);
    ck_assert_int_eq(socket_cb_last_fd, udp_sd);
    ck_assert_int_eq(socket_cb_last_events, CB_EVENT_READABLE);
    ck_assert_int_eq(s.udpsockets[SOCKET_UNMARK(udp_sd)].events, 0);
}
END_TEST

START_TEST(test_filter_notify_tcp_metadata)
{
    struct wolfIP s;
    struct wolfIP_tcp_seg tcp;

    memset(&s, 0, sizeof(s));
    memset(&tcp, 0, sizeof(tcp));
    tcp.ip.src = ee32(0x0A000001U);
    tcp.ip.dst = ee32(0x0A000002U);
    tcp.ip.proto = WI_IPPROTO_TCP;
    tcp.src_port = ee16(1234);
    tcp.dst_port = ee16(5678);
    tcp.flags = 0x12;

    filter_cb_calls = 0;
    memset(&filter_last_event, 0, sizeof(filter_last_event));
    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));

    (void)wolfIP_filter_notify_tcp(WOLFIP_FILT_SENDING, &s, 1, &tcp, sizeof(tcp));
    ck_assert_int_eq(filter_cb_calls, 1);
    ck_assert_uint_eq(filter_last_event.meta.ip_proto, WOLFIP_FILTER_PROTO_TCP);
    ck_assert_uint_eq(filter_last_event.meta.l4.tcp.src_port, tcp.src_port);
    ck_assert_uint_eq(filter_last_event.meta.l4.tcp.dst_port, tcp.dst_port);
    ck_assert_uint_eq(filter_last_event.meta.l4.tcp.flags, tcp.flags);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_filter_dispatch_no_callback)
{
    struct wolfIP s;
    struct wolfIP_filter_metadata meta;

    memset(&s, 0, sizeof(s));
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));

    wolfIP_filter_init_metadata(&meta);
    meta.ip_proto = WOLFIP_FILTER_PROTO_TCP;

    ck_assert_int_eq(wolfIP_filter_dispatch(WOLFIP_FILT_RECEIVING, &s, 0, NULL, 0, &meta), 0);
}
END_TEST

START_TEST(test_filter_dispatch_mask_not_set)
{
    struct wolfIP s;
    struct wolfIP_filter_metadata meta;

    memset(&s, 0, sizeof(s));
    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(0);

    filter_cb_calls = 0;
    wolfIP_filter_init_metadata(&meta);
    meta.ip_proto = WOLFIP_FILTER_PROTO_TCP;

    ck_assert_int_eq(wolfIP_filter_dispatch(WOLFIP_FILT_RECEIVING, &s, 0, NULL, 0, &meta), 0);
    ck_assert_int_eq(filter_cb_calls, 0);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_filter_dispatch_lock_blocks)
{
    struct wolfIP s;
    struct wolfIP_filter_metadata meta;

    memset(&s, 0, sizeof(s));
    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));

    filter_cb_calls = 0;
    wolfIP_filter_init_metadata(&meta);
    meta.ip_proto = WOLFIP_FILTER_PROTO_TCP;

    wolfip_filter_lock = 1;
    ck_assert_int_eq(wolfIP_filter_dispatch(WOLFIP_FILT_RECEIVING, &s, 0, NULL, 0, &meta), 0);
    ck_assert_int_eq(filter_cb_calls, 0);
    wolfip_filter_lock = 0;

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_filter_dispatch_meta_null_initializes)
{
    struct wolfIP s;

    memset(&s, 0, sizeof(s));
    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));
    filter_cb_calls = 0;
    memset(&filter_last_event, 0xA5, sizeof(filter_last_event));

    ck_assert_int_eq(wolfIP_filter_dispatch(WOLFIP_FILT_RECEIVING, &s, 0, NULL, 0, NULL), 0);
    ck_assert_int_eq(filter_cb_calls, 1);
    ck_assert_uint_eq(filter_last_event.meta.ip_proto, 0);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_filter_socket_event_unknown_proto)
{
    struct wolfIP s;
    struct tsocket ts;

    wolfIP_init(&s);
    memset(&ts, 0, sizeof(ts));
    ts.S = &s;
    ts.proto = 0;

    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_CONNECTING));
    filter_cb_calls = 0;

    (void)wolfIP_filter_notify_socket_event(WOLFIP_FILT_CONNECTING, &s, &ts,
            0x0A000001U, 1234, 0x0A000002U, 4321);
    ck_assert_int_eq(filter_cb_calls, 1);
    ck_assert_uint_eq(filter_last_event.meta.ip_proto, 0);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_filter_socket_event_proto_variants)
{
    struct wolfIP s;
    struct tsocket ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint16_t local_port = 1234;
    uint16_t remote_port = 4321;

    wolfIP_init(&s);
    memset(&ts, 0, sizeof(ts));
    ts.S = &s;
    ts.if_idx = TEST_PRIMARY_IF;

    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_CONNECTING));
    filter_cb_calls = 0;

    ts.proto = WI_IPPROTO_TCP;
    (void)wolfIP_filter_notify_socket_event(WOLFIP_FILT_CONNECTING, &s, &ts,
            local_ip, local_port, remote_ip, remote_port);
    ck_assert_int_eq(filter_cb_calls, 1);
    ck_assert_uint_eq(filter_last_event.meta.ip_proto, WOLFIP_FILTER_PROTO_TCP);
    ck_assert_uint_eq(filter_last_event.meta.l4.tcp.src_port, ee16(local_port));
    ck_assert_uint_eq(filter_last_event.meta.l4.tcp.dst_port, ee16(remote_port));

    ts.proto = WI_IPPROTO_UDP;
    (void)wolfIP_filter_notify_socket_event(WOLFIP_FILT_CONNECTING, &s, &ts,
            local_ip, local_port, remote_ip, remote_port);
    ck_assert_int_eq(filter_cb_calls, 2);
    ck_assert_uint_eq(filter_last_event.meta.ip_proto, WOLFIP_FILTER_PROTO_UDP);
    ck_assert_uint_eq(filter_last_event.meta.l4.udp.src_port, ee16(local_port));
    ck_assert_uint_eq(filter_last_event.meta.l4.udp.dst_port, ee16(remote_port));

    ts.proto = WI_IPPROTO_ICMP;
    (void)wolfIP_filter_notify_socket_event(WOLFIP_FILT_CONNECTING, &s, &ts,
            local_ip, local_port, remote_ip, remote_port);
    ck_assert_int_eq(filter_cb_calls, 3);
    ck_assert_uint_eq(filter_last_event.meta.ip_proto, WOLFIP_FILTER_PROTO_ICMP);
    ck_assert_uint_eq(filter_last_event.meta.l4.icmp.type, 0);
    ck_assert_uint_eq(filter_last_event.meta.l4.icmp.code, 0);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_filter_setters_and_get_mask)
{
    wolfIP_filter_set_mask(0x1234U);
    ck_assert_uint_eq(wolfIP_filter_get_mask(), 0x1234U);
    wolfIP_filter_set_eth_mask(0x10U);
    wolfIP_filter_set_ip_mask(0x20U);
    wolfIP_filter_set_tcp_mask(0x40U);
    wolfIP_filter_set_udp_mask(0x80U);
    wolfIP_filter_set_icmp_mask(0x100U);
    ck_assert_uint_eq(wolfIP_filter_get_mask(), 0x1234U);
}
END_TEST

START_TEST(test_filter_mask_for_proto_variants)
{
    wolfIP_filter_set_mask(0x1U);
    wolfIP_filter_set_eth_mask(0);
    wolfIP_filter_set_ip_mask(0);
    wolfIP_filter_set_tcp_mask(0);
    wolfIP_filter_set_udp_mask(0);
    wolfIP_filter_set_icmp_mask(0);

    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_ETH), 0x1U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_IP), 0x1U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_TCP), 0x1U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_UDP), 0x1U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_ICMP), 0x1U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(0xFFFF), 0x1U);

    wolfIP_filter_set_eth_mask(0x10U);
    wolfIP_filter_set_ip_mask(0x20U);
    wolfIP_filter_set_tcp_mask(0x40U);
    wolfIP_filter_set_udp_mask(0x80U);
    wolfIP_filter_set_icmp_mask(0x100U);

    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_ETH), 0x10U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_IP), 0x20U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_TCP), 0x40U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_UDP), 0x80U);
    ck_assert_uint_eq(wolfIP_filter_mask_for_proto(WOLFIP_FILTER_PROTO_ICMP), 0x100U);
}
END_TEST

START_TEST(test_filter_dispatch_paths)
{
    struct wolfIP s;
    struct wolfIP_filter_metadata meta;
    int ret;

    wolfIP_init(&s);
    filter_cb_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb, NULL);
    wolfIP_filter_set_mask(0);
    wolfIP_filter_set_tcp_mask(0);

    wolfip_filter_lock = 1;
    ret = wolfIP_filter_dispatch(WOLFIP_FILT_SENDING, &s, 0, NULL, 0, NULL);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(filter_cb_calls, 0);
    wolfip_filter_lock = 0;

    ret = wolfIP_filter_dispatch(WOLFIP_FILT_SENDING, &s, 0, NULL, 0, NULL);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(filter_cb_calls, 0);

    wolfIP_filter_set_tcp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    wolfIP_filter_init_metadata(&meta);
    meta.ip_proto = WOLFIP_FILTER_PROTO_TCP;
    ret = wolfIP_filter_dispatch(WOLFIP_FILT_SENDING, &s, 0, NULL, 0, &meta);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(filter_cb_calls, 1);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
    wolfIP_filter_set_tcp_mask(0);
}
END_TEST

START_TEST(test_sock_wrappers_basic)
{
    struct wolfIP s;
    int udp_sd;
    uint8_t buf[8];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ret = wolfIP_sock_send(&s, udp_sd, buf, sizeof(buf), 0);
    ck_assert_int_eq(ret, -1);

    ret = wolfIP_sock_write(&s, udp_sd, buf, sizeof(buf));
    ck_assert_int_eq(ret, -1);

    ret = wolfIP_sock_recv(&s, udp_sd, buf, sizeof(buf), 0);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);

    ret = wolfIP_sock_read(&s, udp_sd, buf, sizeof(buf));
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_socket_errors)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_socket(&s, 0, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP), -1);
    ck_assert_int_eq(wolfIP_sock_socket(&s, AF_INET, 0xFF, WI_IPPROTO_UDP), -1);
    ck_assert_int_eq(wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_TCP), -1);
}
END_TEST
START_TEST(test_udp_sendto_and_recvfrom)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    uint8_t rxbuf[8] = {0};
    struct wolfIP_sockaddr_in from;
    socklen_t from_len = sizeof(from);
    int ret;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint16_t local_port = 4000;
    uint16_t remote_port = 5000;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ret = wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(remote_port);
    sin.sin_addr.s_addr = ee32(remote_ip);
    ret = wolfIP_sock_sendto(&s, sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, (int)sizeof(payload));

    ts = &s.udpsockets[SOCKET_UNMARK(sd)];
    ck_assert_uint_gt(ts->src_port, 0);
    ck_assert_uint_eq(ts->dst_port, remote_port);
    ck_assert_uint_eq(ts->remote_ip, remote_ip);
    ck_assert_uint_gt(fifo_len(&ts->sock.udp.txbuf), 0);

    inject_udp_datagram(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            payload, sizeof(payload));

    memset(&from, 0, sizeof(from));
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len);
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(rxbuf, payload, sizeof(payload));
    ck_assert_uint_eq(from.sin_port, ee16(remote_port));
}
END_TEST

START_TEST(test_udp_recvfrom_sets_remote_ip)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t rxbuf[4] = {0};
    struct wolfIP_sockaddr_in from;
    socklen_t from_len = sizeof(from);
    int ret;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint16_t local_port = 4001;
    uint16_t remote_port = 5001;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ret = wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, 0);

    ts = &s.udpsockets[SOCKET_UNMARK(sd)];
    ck_assert_uint_eq(ts->remote_ip, 0);

    inject_udp_datagram(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            payload, sizeof(payload));

    memset(&from, 0, sizeof(from));
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len);
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(rxbuf, payload, sizeof(payload));
    ck_assert_uint_eq(from.sin_addr.s_addr, ee32(remote_ip));
    ck_assert_uint_eq(ts->remote_ip, remote_ip);
}
END_TEST

START_TEST(test_udp_recvfrom_null_src_addr_len)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t rxbuf[4] = {0};
    int ret;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint16_t local_port = 4002;
    uint16_t remote_port = 5002;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ret = wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, 0);

    inject_udp_datagram(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            payload, sizeof(payload));

    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(rxbuf, payload, sizeof(payload));
}
END_TEST

START_TEST(test_udp_recvfrom_preserves_remote_ip)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {0x55, 0x66, 0x77, 0x88};
    uint8_t rxbuf[4] = {0};
    struct wolfIP_sockaddr_in from;
    socklen_t from_len = sizeof(from);
    int ret;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    ip4 preset_remote_ip = 0x0A000099U;
    uint16_t local_port = 4003;
    uint16_t remote_port = 5003;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ret = wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, 0);

    ts = &s.udpsockets[SOCKET_UNMARK(sd)];
    ts->remote_ip = preset_remote_ip;

    inject_udp_datagram(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            payload, sizeof(payload));

    memset(&from, 0, sizeof(from));
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len);
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(rxbuf, payload, sizeof(payload));
    ck_assert_uint_eq(from.sin_addr.s_addr, ee32(remote_ip));
    ck_assert_uint_eq(ts->remote_ip, preset_remote_ip);
}
END_TEST

START_TEST(test_udp_recvfrom_null_addrlen)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {0x9A, 0xBC, 0xDE, 0xF0};
    uint8_t rxbuf[4] = {0};
    struct wolfIP_sockaddr_in from;
    int ret;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint16_t local_port = 4004;
    uint16_t remote_port = 5004;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ret = wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, 0);

    inject_udp_datagram(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            payload, sizeof(payload));

    memset(&from, 0, sizeof(from));
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
            (struct wolfIP_sockaddr *)&from, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_udp_recvfrom_src_equals_local_ip_does_not_persist_remote)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t rxbuf[4] = {0};
    struct wolfIP_sockaddr_in from;
    socklen_t from_len = sizeof(from);
    int ret;
    ip4 local_ip = 0x0A000001U;
    uint16_t local_port = 4005;
    uint16_t remote_port = 5005;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ret = wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, 0);

    ts = &s.udpsockets[SOCKET_UNMARK(sd)];
    ck_assert_uint_eq(ts->remote_ip, 0);

    inject_udp_datagram(&s, TEST_PRIMARY_IF, local_ip, local_ip, remote_port, local_port,
            payload, sizeof(payload));

    memset(&from, 0, sizeof(from));
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len);
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(rxbuf, payload, sizeof(payload));
    ck_assert_uint_eq(from.sin_addr.s_addr, ee32(local_ip));
    ck_assert_uint_eq(ts->remote_ip, 0);
}
END_TEST

START_TEST(test_sock_error_paths)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4];
    int ret;
    socklen_t alen;

    wolfIP_init(&s);
    mock_link_init(&s);

    ret = wolfIP_sock_sendto(&s, -1, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    ret = wolfIP_sock_recvfrom(&s, -1, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    ret = wolfIP_sock_getsockname(&s, -1, (struct wolfIP_sockaddr *)&sin, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    ret = wolfIP_sock_getpeername(&s, -1, (struct wolfIP_sockaddr *)&sin, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    alen = (socklen_t)(sizeof(sin) - 1);
    ret = wolfIP_sock_bind(&s, -1, (struct wolfIP_sockaddr *)&sin, alen);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST
START_TEST(test_dns_format_ptr_name)
{
    char out[64];
    int ret;
    ret = dns_format_ptr_name(out, sizeof(out), 0xC0A80102U);
    ck_assert_int_eq(ret, 0);
    ck_assert_str_eq(out, "2.1.168.192.in-addr.arpa");
}
END_TEST

START_TEST(test_sock_name_and_opt_errors)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen;
    int opt;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ret = wolfIP_sock_getsockname(&s, udp_sd, NULL, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    memset(&sin, 0, sizeof(sin));
    alen = (socklen_t)(sizeof(sin) - 1);
    ret = wolfIP_sock_getsockname(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, &alen);
    ck_assert_int_eq(ret, -1);

    ret = wolfIP_sock_getpeername(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, &alen);
    ck_assert_int_eq(ret, -1);

    opt = 1;
    ret = wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, NULL, sizeof(opt));
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    alen = 1;
    ret = wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &opt, &alen);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST
START_TEST(test_dns_skip_and_copy_name)
{
    uint8_t buf[64];
    int pos = 0;
    int ret;
    char out[64];

    /* www.example.com */
    buf[pos++] = 3; memcpy(&buf[pos], "www", 3); pos += 3;
    buf[pos++] = 7; memcpy(&buf[pos], "example", 7); pos += 7;
    buf[pos++] = 3; memcpy(&buf[pos], "com", 3); pos += 3;
    buf[pos++] = 0;

    ret = dns_skip_name(buf, sizeof(buf), 0);
    ck_assert_int_eq(ret, pos);

    ret = dns_copy_name(buf, sizeof(buf), 0, out, sizeof(out));
    ck_assert_int_eq(ret, 0);
    ck_assert_str_eq(out, "www.example.com");

    /* add a pointer to the name at offset 0 */
    buf[pos++] = 0xC0;
    buf[pos++] = 0x00;
    ret = dns_copy_name(buf, sizeof(buf), pos - 2, out, sizeof(out));
    ck_assert_int_eq(ret, 0);
    ck_assert_str_eq(out, "www.example.com");
}
END_TEST

START_TEST(test_inline_helpers)
{
    char buf[32];
    ck_assert_uint_eq(atou("0"), 0);
    ck_assert_uint_eq(atou("1234"), 1234);

    ck_assert_uint_eq(atoip4("10.0.0.1"), 0x0A000001U);
    ck_assert_uint_eq(atoip4("192.168.1.2"), 0xC0A80102U);

    iptoa(0xC0A80102U, buf);
    ck_assert_str_eq(buf, "192.168.1.2");
    iptoa(0x0A000001U, buf);
    ck_assert_str_eq(buf, "10.0.0.1");
}
END_TEST

START_TEST(test_sock_bind_wrong_family)
{
    struct wolfIP s;
    int udp_sd;
    int tcp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = 0;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_bind(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_bind_invalid_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    ck_assert_int_eq(wolfIP_sock_bind(&s, -1, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_bind(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    ck_assert_int_eq(wolfIP_sock_bind(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    ck_assert_int_eq(wolfIP_sock_bind(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_bind_tcp_state_not_closed)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    ck_assert_int_eq(wolfIP_sock_bind(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_bind_tcp_filter_blocks)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;
    ts->local_ip = 0;
    ts->src_port = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    filter_block_reason = WOLFIP_FILT_BINDING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_BINDING));

    ck_assert_int_eq(wolfIP_sock_bind(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    ck_assert_uint_eq(ts->local_ip, 0U);
    ck_assert_uint_eq(ts->src_port, 0U);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_sock_bind_udp_src_port_nonzero)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 1234;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5678);
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_bind_udp_filter_blocks)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 0;
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(2222);
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    filter_block_reason = WOLFIP_FILT_BINDING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_BINDING));

    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    ck_assert_uint_eq(ts->local_ip, 0U);
    ck_assert_uint_eq(ts->src_port, 0U);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_sock_bind_icmp_success)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->src_port = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7);
    sin.sin_addr.s_addr = ee32(0x0A000001U);

    ck_assert_int_eq(wolfIP_sock_bind(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->src_port, 7U);
}
END_TEST

START_TEST(test_sock_connect_wrong_family)
{
    struct wolfIP s;
    int tcp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = 0;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_accept_error_paths)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_LISTEN;

    alen = (socklen_t)(sizeof(sin) - 1);
    ck_assert_int_eq(wolfIP_sock_accept(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, &alen), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_accept(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, NULL), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_accept(&s, tcp_sd, NULL, NULL), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_accept_non_tcp_socket_sets_addrlen)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = sizeof(sin);

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_accept(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, &alen), -WOLFIP_EINVAL);
    ck_assert_uint_eq(alen, sizeof(sin));
}
END_TEST

START_TEST(test_sock_accept_null_addr_with_addrlen)
{
    struct wolfIP s;
    int tcp_sd;
    socklen_t alen = 123;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_accept(&s, tcp_sd, NULL, &alen), -1);
    ck_assert_uint_eq(alen, sizeof(struct wolfIP_sockaddr_in));
}
END_TEST

START_TEST(test_sock_recvfrom_short_addrlen)
{
    struct wolfIP s;
    int udp_sd;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen;
    uint8_t buf[4];

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    alen = (socklen_t)1;
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, &alen), -WOLFIP_EINVAL);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    alen = (socklen_t)1;
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, icmp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, &alen), -WOLFIP_EINVAL);
}
END_TEST
START_TEST(test_dns_query_and_callback_a)
{
    struct wolfIP s;
    uint16_t id = 0;
    uint8_t response[128];
    int pos = 0;
    struct dns_header *hdr = (struct dns_header *)response;
    struct dns_question *q;
    struct dns_rr *rr;
    const uint8_t ip_bytes[4] = {0x0A, 0x00, 0x00, 0x42};
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    s.dns_server = 0x08080808U;
    dns_lookup_calls = 0;
    dns_lookup_ip = 0;
    s.dns_lookup_cb = test_dns_lookup_cb;

    ck_assert_int_eq(dns_send_query(&s, "example.com", &id, DNS_A), 0);
    ck_assert_uint_ne(id, 0);
    ck_assert_uint_eq(s.dns_id, id);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_A);

    memset(response, 0, sizeof(response));
    hdr->id = ee16(id);
    hdr->flags = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(1);
    pos = sizeof(struct dns_header);
    /* question name */
    response[pos++] = 7; memcpy(&response[pos], "example", 7); pos += 7;
    response[pos++] = 3; memcpy(&response[pos], "com", 3); pos += 3;
    response[pos++] = 0;
    q = (struct dns_question *)(response + pos);
    q->qtype = ee16(DNS_A);
    q->qclass = ee16(1);
    pos += sizeof(struct dns_question);
    /* answer name pointer to question */
    response[pos++] = 0xC0;
    response[pos++] = (uint8_t)sizeof(struct dns_header);
    rr = (struct dns_rr *)(response + pos);
    rr->type = ee16(DNS_A);
    rr->class = ee16(1);
    rr->ttl = ee32(60);
    rr->rdlength = ee16(4);
    pos += sizeof(struct dns_rr);
    memcpy(&response[pos], ip_bytes, sizeof(ip_bytes));
    pos += sizeof(ip_bytes);

    ts = &s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)];
    inject_udp_datagram(&s, TEST_PRIMARY_IF, s.dns_server, local_ip, DNS_PORT, ts->src_port,
            response, (uint16_t)pos);

    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_int_eq(dns_lookup_calls, 1);
    ck_assert_uint_eq(dns_lookup_ip, ee32(0x0A000042U));
    ck_assert_int_eq(s.dns_id, 0);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
}
END_TEST

START_TEST(test_sock_bind_non_local_ip_fails)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A0000FFU);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_connect_bad_addrlen)
{
    struct wolfIP s;
    int icmp_sd;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, (socklen_t)1), -WOLFIP_EINVAL);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, (socklen_t)1), 0);
}
END_TEST

START_TEST(test_sock_connect_tcp_bad_addrlen)
{
    struct wolfIP s;
    int tcp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, (socklen_t)1), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_invalid_args)
{
    struct wolfIP s;
    int tcp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, NULL, sizeof(sin)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_connect(&s, -1, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_invalid_tcp_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    int bad_fd = MARK_TCP_SOCKET | MAX_TCPSOCKETS;

    wolfIP_init(&s);
    mock_link_init(&s);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, bad_fd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_connect(&s, 0, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_udp_invalid_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    int bad_fd = MARK_UDP_SOCKET | MAX_UDPSOCKETS;

    wolfIP_init(&s);
    mock_link_init(&s);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, bad_fd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_icmp_invalid_fd)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    int bad_fd = MARK_ICMP_SOCKET | MAX_ICMPSOCKETS;

    wolfIP_init(&s);
    mock_link_init(&s);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, bad_fd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_udp_sets_local_ip_from_conf)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(remote_ip);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ck_assert_uint_eq(ts->local_ip, local_ip);
}
END_TEST

START_TEST(test_sock_connect_udp_falls_back_to_primary)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(remote_ip);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ck_assert_uint_eq(ts->local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_connect_udp_primary_missing)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ck_assert_uint_eq(ts->local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_connect_udp_bound_local_ip_no_match)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->bound_local_ip = 0x0B000001U;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_udp_bound_local_ip_match)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->bound_local_ip = local_ip;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, local_ip);
    ck_assert_uint_eq(ts->if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_sock_connect_icmp_sets_local_ip_from_conf)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, local_ip);
}
END_TEST

START_TEST(test_sock_connect_icmp_wrong_family)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = 0;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_icmp_local_ip_pre_set)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0x0A000001U;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, 0x0A000001U);
}
END_TEST

START_TEST(test_sock_connect_icmp_conf_null)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_connect_icmp_falls_back_to_primary)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_connect_icmp_primary_ip_any)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_connect_icmp_primary_ip_fallback)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 primary_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = TEST_SECOND_IF + 1;
    s.ipconf[TEST_PRIMARY_IF].ip = primary_ip;
    s.ipconf[TEST_PRIMARY_IF].mask = 0xFFFFFF00U;
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0B000001U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST

START_TEST(test_sock_connect_tcp_established_returns_zero)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
}
END_TEST

START_TEST(test_sock_connect_tcp_bound_local_ip_match)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;
    ts->bound_local_ip = local_ip;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_uint_eq(ts->local_ip, local_ip);
    ck_assert_uint_eq(ts->if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_sock_connect_tcp_bound_local_ip_no_match)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;
    ts->bound_local_ip = 0x0B000001U;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_tcp_filter_blocks)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    filter_block_reason = WOLFIP_FILT_CONNECTING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_CONNECTING));

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSED);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST
START_TEST(test_sock_connect_tcp_local_ip_from_conf)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_uint_eq(ts->local_ip, local_ip);
}
END_TEST

START_TEST(test_sock_connect_tcp_local_ip_from_primary)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_uint_eq(ts->local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_connect_tcp_primary_ip_fallback)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 primary_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = TEST_SECOND_IF + 1;
    s.ipconf[TEST_PRIMARY_IF].ip = primary_ip;
    s.ipconf[TEST_PRIMARY_IF].mask = 0xFFFFFF00U;
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0B000001U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST
START_TEST(test_sock_accept_negative_fd)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_accept(&s, -1, NULL, NULL), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_tcp_conf_null_primary_null)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_uint_eq(ts->local_ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_sock_connect_tcp_state_not_closed)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_LISTEN;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST
START_TEST(test_sock_accept_invalid_tcp_fd)
{
    struct wolfIP s;
    int bad_fd = MARK_TCP_SOCKET | MAX_TCPSOCKETS;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_accept(&s, bad_fd, NULL, NULL), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_accept_success_sets_addr)
{
    struct wolfIP s;
    int listen_sd;
    int client_sd;
    struct tsocket *listener;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = sizeof(sin);

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    listener = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(listener->sock.tcp.state, TCP_SYN_RCVD);

    client_sd = wolfIP_sock_accept(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, &alen);
    ck_assert_int_gt(client_sd, 0);
    ck_assert_uint_eq(alen, sizeof(sin));
    ck_assert_uint_eq(sin.sin_family, AF_INET);
}
END_TEST

START_TEST(test_sock_accept_no_available_socket)
{
    struct wolfIP s;
    int listen_sd;
    struct wolfIP_sockaddr_in sin;
    struct tsocket *ts;
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);

    for (i = 0; i < MAX_TCPSOCKETS; i++) {
        ts = &s.tcpsockets[i];
        ts->proto = WI_IPPROTO_TCP;
        ts->sock.tcp.state = TCP_ESTABLISHED;
    }

    ck_assert_int_eq(wolfIP_sock_accept(&s, listen_sd, NULL, NULL), -1);
}
END_TEST

START_TEST(test_sock_accept_no_free_socket_syn_rcvd)
{
    struct wolfIP s;
    int listen_sd;
    struct wolfIP_sockaddr_in sin;
    struct tsocket *ts;
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);

    for (i = 0; i < MAX_TCPSOCKETS; i++) {
        if (i == SOCKET_UNMARK(listen_sd)) {
            continue;
        }
        s.tcpsockets[i].proto = WI_IPPROTO_TCP;
        s.tcpsockets[i].sock.tcp.state = TCP_ESTABLISHED;
    }

    ck_assert_int_eq(wolfIP_sock_accept(&s, listen_sd, NULL, NULL), -1);
}
END_TEST

START_TEST(test_sock_accept_listen_no_connection)
{
    struct wolfIP s;
    int listen_sd;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ck_assert_int_eq(wolfIP_sock_accept(&s, listen_sd, NULL, NULL), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_accept_bound_local_ip_no_match)
{
    struct wolfIP s;
    int listen_sd;
    int client_sd;
    struct tsocket *listener;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    listener = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    listener->bound_local_ip = 0x0A000001U;
    listener->if_idx = TEST_PRIMARY_IF;

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    s.if_count = 0;

    client_sd = wolfIP_sock_accept(&s, listen_sd, NULL, NULL);
    ck_assert_int_gt(client_sd, 0);
    ck_assert_uint_eq(listener->if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_sock_sendto_error_paths)
{
    struct wolfIP s;
    int tcp_sd;
    int udp_sd;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[8];

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0), -1);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, (size_t)(WI_IP_MTU), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, buf, (size_t)(ICMP_HEADER_LEN - 1), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_sendto_null_buf_or_len_zero)
{
    struct wolfIP s;
    int udp_sd;
    uint8_t buf[1] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, NULL, 1, 0, NULL, 0), -1);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, 0, 0, NULL, 0), -1);
}
END_TEST

START_TEST(test_sock_sendto_tcp_not_established)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t buf[4] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;

    ck_assert_int_eq(wolfIP_sock_sendto(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0), -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_sets_dest_and_assigns)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {1,2,3,4};
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 0;
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(9999);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(buf));
    ck_assert_uint_eq(ts->dst_port, 9999U);
    ck_assert_uint_eq(ts->remote_ip, 0x0A000002U);
    ck_assert_uint_ge(ts->src_port, 1024U);
    ck_assert_uint_eq(ts->local_ip, local_ip);
}
END_TEST

START_TEST(test_sock_sendto_icmp_assigns_src_port_and_sets_echo_id)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};
    struct pkt_desc *desc;
    struct wolfIP_icmp_packet *icmp;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->src_port = 0;
    ts->local_ip = 0;

    payload[0] = ICMP_ECHO_REQUEST;
    payload[1] = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    ck_assert_uint_ne(ts->src_port, 0);
    ck_assert_uint_eq(ts->local_ip, 0x0A000001U);

    desc = fifo_peek(&ts->sock.udp.txbuf);
    ck_assert_ptr_nonnull(desc);
    icmp = (struct wolfIP_icmp_packet *)(ts->txmem + desc->pos + sizeof(*desc));
    ck_assert_uint_eq(icmp_echo_id(icmp), ts->src_port);
}
END_TEST

START_TEST(test_sock_sendto_invalid_socket_ids)
{
    struct wolfIP s;
    uint8_t buf[1] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS, buf, sizeof(buf), 0, NULL, 0), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS, buf, sizeof(buf), 0, NULL, 0), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS, buf, sizeof(buf), 0, NULL, 0), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_sendto_non_socket_returns_minus_one)
{
    struct wolfIP s;
    uint8_t buf[1] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, 1, buf, sizeof(buf), 0, NULL, 0), -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_remote_ip_zero)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    uint8_t buf[4] = {1,2,3,4};

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->dst_port = 1234;
    ts->remote_ip = 0;

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0, NULL, 0), -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_primary_ip_fallback)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {1,2,3,4};
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 0;
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7777);
    sin.sin_addr.s_addr = ee32(0xC0A80199U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(buf));
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST

START_TEST(test_sock_sendto_udp_zero_port_in_addr)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {1,2,3,4};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 1234;
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_src_port_low_adjusts)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {1,2,3,4};
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 0;
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(9999);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    test_rand_override_enabled = 1;
    test_rand_override_value = 5;
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(buf));
    test_rand_override_enabled = 0;

    ck_assert_uint_eq(ts->src_port, 5U + 1024U);
}
END_TEST

START_TEST(test_sock_sendto_udp_local_ip_conf_null)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {1,2,3,4};

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 1234;
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7777);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(buf));
    ck_assert_uint_eq(ts->local_ip, 0U);
}
END_TEST

START_TEST(test_sock_sendto_udp_local_ip_from_primary)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[4] = {1,2,3,4};
    ip4 primary_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = TEST_SECOND_IF + 1;
    s.ipconf[TEST_PRIMARY_IF].ip = primary_ip;
    s.ipconf[TEST_PRIMARY_IF].mask = 0xFFFFFF00U;
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 1234;
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(7777);
    sin.sin_addr.s_addr = ee32(0x0B000001U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(buf));
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST

START_TEST(test_sock_sendto_tcp_multiple_segments_flags)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    size_t seg_payload = TCP_MSS - TCP_OPTIONS_LEN;
    size_t payload_len = seg_payload * 2;
    uint8_t buf[TCP_MSS * 2];
    uint8_t txbuf[4096];
    struct pkt_desc *first;
    struct pkt_desc *second;
    struct wolfIP_tcp_seg *tcp1;
    struct wolfIP_tcp_seg *tcp2;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    fifo_init(&ts->sock.tcp.txbuf, txbuf, sizeof(txbuf));

    memset(buf, 0xAA, payload_len);
    ret = wolfIP_sock_sendto(&s, tcp_sd, buf, payload_len, 0, NULL, 0);
    ck_assert_int_eq(ret, (int)payload_len);

    first = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(first);
    tcp1 = (struct wolfIP_tcp_seg *)(txbuf + first->pos + sizeof(*first));
    ck_assert_uint_eq(tcp1->flags & 0x18, 0x18);

    second = fifo_next(&ts->sock.tcp.txbuf, first);
    ck_assert_ptr_nonnull(second);
    tcp2 = (struct wolfIP_tcp_seg *)(txbuf + second->pos + sizeof(*second));
    ck_assert_uint_eq(tcp2->flags & 0x18, 0x10);
}
END_TEST

START_TEST(test_sock_sendto_icmp_src_port_zero_random_zero_sets_one)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->src_port = 0;
    ts->local_ip = 0;

    payload[0] = ICMP_ECHO_REQUEST;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    test_rand_override_enabled = 1;
    test_rand_override_value = 0;
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    test_rand_override_enabled = 0;

    ck_assert_uint_eq(ts->src_port, 1U);
}
END_TEST

START_TEST(test_sock_sendto_icmp_non_echo_no_set_id)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};
    struct pkt_desc *desc;
    struct wolfIP_icmp_packet *icmp;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->src_port = 1234;
    ts->local_ip = 0;

    payload[0] = ICMP_ECHO_REPLY;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));

    desc = fifo_peek(&ts->sock.udp.txbuf);
    ck_assert_ptr_nonnull(desc);
    icmp = (struct wolfIP_icmp_packet *)(ts->txmem + desc->pos + sizeof(*desc));
    ck_assert_uint_eq(icmp_echo_id(icmp), 0U);
}
END_TEST

START_TEST(test_sock_sendto_icmp_local_ip_from_primary)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};
    ip4 primary_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = TEST_SECOND_IF + 1;
    s.ipconf[TEST_PRIMARY_IF].ip = primary_ip;
    s.ipconf[TEST_PRIMARY_IF].mask = 0xFFFFFF00U;
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;
    ts->src_port = 1234;

    payload[0] = ICMP_ECHO_REQUEST;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0B000001U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST

START_TEST(test_sock_sendto_icmp_local_ip_pre_set)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0x0A000001U;
    ts->src_port = 1234;

    payload[0] = ICMP_ECHO_REQUEST;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    ck_assert_uint_eq(ts->local_ip, 0x0A000001U);
}
END_TEST

START_TEST(test_sock_sendto_icmp_conf_null_primary_null)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;
    ts->src_port = 1234;

    payload[0] = ICMP_ECHO_REQUEST;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    ck_assert_uint_eq(ts->local_ip, 0U);
}
END_TEST
START_TEST(test_sock_recvfrom_tcp_close_wait_empty_returns_zero)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t buf[8];

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, NULL), 0);
}
END_TEST

START_TEST(test_sock_recvfrom_tcp_close_wait_with_data)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t buf[8];
    uint8_t payload[4] = {1,2,3,4};

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    ck_assert_int_eq(queue_insert(&ts->sock.tcp.rxbuf, payload, 0, sizeof(payload)), 0);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, NULL), (int)sizeof(payload));
}
END_TEST

START_TEST(test_sock_recvfrom_tcp_established_sets_readable)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t buf[4];
    uint8_t payload[8] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);

    ck_assert_int_eq(queue_insert(&ts->sock.tcp.rxbuf, payload, 0, sizeof(payload)), 0);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, NULL), (int)sizeof(buf));
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, CB_EVENT_READABLE);
}
END_TEST

START_TEST(test_sock_recvfrom_tcp_established_no_remaining_data)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t buf[8];
    uint8_t payload[8] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    ck_assert_int_eq(queue_insert(&ts->sock.tcp.rxbuf, payload, 0, sizeof(payload)), 0);

    ts->events = 0;
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, NULL), (int)sizeof(buf));
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, 0);
}
END_TEST

START_TEST(test_sock_recvfrom_invalid_socket_ids)
{
    struct wolfIP s;
    uint8_t buf[4];

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS, buf, sizeof(buf), 0, NULL, NULL), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS, buf, sizeof(buf), 0, NULL, NULL), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS, buf, sizeof(buf), 0, NULL, NULL), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_recvfrom_non_socket)
{
    struct wolfIP s;
    uint8_t buf[4];

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, 1, buf, sizeof(buf), 0, NULL, NULL), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_recvfrom_icmp_success)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_icmp_packet icmp;
    struct wolfIP_sockaddr_in from;
    socklen_t from_len = sizeof(from);
    uint8_t buf[ICMP_HEADER_LEN];

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.ip.src = ee32(0x0A000002U);
    icmp.type = ICMP_ECHO_REPLY;
    fifo_push(&ts->sock.udp.rxbuf, &icmp, sizeof(icmp));

    memset(&from, 0, sizeof(from));
    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, icmp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len), (int)ICMP_HEADER_LEN);
    ck_assert_uint_eq(from.sin_family, AF_INET);
    ck_assert_uint_eq(from.sin_addr.s_addr, icmp.ip.src);
}
END_TEST

START_TEST(test_sock_setsockopt_recvttl)
{
    struct wolfIP s;
    int udp_sd;
    int enable = 1;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &enable, sizeof(enable)), 0);
    ck_assert_int_eq(s.udpsockets[SOCKET_UNMARK(udp_sd)].recv_ttl, 1);
}
END_TEST

START_TEST(test_sock_setsockopt_invalid_socket)
{
    struct wolfIP s;
    int enable = 1;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS,
            WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &enable, sizeof(enable)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_getsockopt_recvttl_value)
{
    struct wolfIP s;
    int udp_sd;
    int value = 0;
    socklen_t len = sizeof(value);

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    s.udpsockets[SOCKET_UNMARK(udp_sd)].recv_ttl = 1;
    s.udpsockets[SOCKET_UNMARK(udp_sd)].last_pkt_ttl = 77;

    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &value, &len), 0);
    ck_assert_int_eq(value, 77);
}
END_TEST

START_TEST(test_sock_getsockopt_invalid_socket)
{
    struct wolfIP s;
    int value = 0;
    socklen_t len = sizeof(value);

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS,
            WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &value, &len), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_get_recv_ttl_invalid_socket)
{
    struct wolfIP s;
    int ttl = 0;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_get_recv_ttl(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS, &ttl), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_setsockopt_recvttl_invalid_params)
{
    struct wolfIP s;
    int udp_sd;
    int enable = 1;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, NULL, sizeof(enable)), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &enable, (socklen_t)1), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_getsockopt_recvttl_invalid_params)
{
    struct wolfIP s;
    int udp_sd;
    int value = 0;
    socklen_t len = sizeof(value);

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, NULL, &len), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &value, NULL), -WOLFIP_EINVAL);
    len = 1;
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &value, &len), -WOLFIP_EINVAL);
}
END_TEST
START_TEST(test_dhcp_parse_offer_and_ack)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct ipconf *primary;
    uint32_t offer_ip = 0x0A000064U;
    uint32_t server_ip = 0x0A000001U;
    uint32_t mask = 0xFFFFFF00U;

    wolfIP_init(&s);
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    memset(&msg, 0, sizeof(msg));
    msg.yiaddr = ee32(offer_ip);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_OFFER;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_SERVER_ID;
    opt->len = 4;
    opt->data[0] = (server_ip >> 24) & 0xFF;
    opt->data[1] = (server_ip >> 16) & 0xFF;
    opt->data[2] = (server_ip >> 8) & 0xFF;
    opt->data[3] = (server_ip >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_SUBNET_MASK;
    opt->len = 4;
    opt->data[0] = (mask >> 24) & 0xFF;
    opt->data[1] = (mask >> 16) & 0xFF;
    opt->data[2] = (mask >> 8) & 0xFF;
    opt->data[3] = (mask >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg), 0);
    ck_assert_uint_eq(s.dhcp_ip, offer_ip);
    ck_assert_uint_eq(s.dhcp_server_ip, server_ip);
    ck_assert_uint_eq(primary->mask, mask);
    ck_assert_int_eq(s.dhcp_state, DHCP_REQUEST_SENT);

    memset(&msg, 0, sizeof(msg));
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_SERVER_ID;
    opt->len = 4;
    opt->data[0] = (server_ip >> 24) & 0xFF;
    opt->data[1] = (server_ip >> 16) & 0xFF;
    opt->data[2] = (server_ip >> 8) & 0xFF;
    opt->data[3] = (server_ip >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_SUBNET_MASK;
    opt->len = 4;
    opt->data[0] = (mask >> 24) & 0xFF;
    opt->data[1] = (mask >> 16) & 0xFF;
    opt->data[2] = (mask >> 8) & 0xFF;
    opt->data[3] = (mask >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_DNS;
    opt->len = 4;
    opt->data[0] = (server_ip >> 24) & 0xFF;
    opt->data[1] = (server_ip >> 16) & 0xFF;
    opt->data[2] = (server_ip >> 8) & 0xFF;
    opt->data[3] = (server_ip >> 0) & 0xFF;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg), 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_BOUND);
    ck_assert_uint_eq(s.dns_server, server_ip);
}
END_TEST

START_TEST(test_sock_recvfrom_tcp_states)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t buf[4];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];

    ts->sock.tcp.state = TCP_SYN_SENT;
    ret = wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, -1);

    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    ret = wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, 0);

    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->events = 0;
    ret = wolfIP_sock_recvfrom(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_opts_unknown_level)
{
    struct wolfIP s;
    int udp_sd;
    int value = 1;
    socklen_t len = sizeof(value);

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, 0xFFFF, 0, &value, len), 0);
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, 0xFFFF, 0, &value, &len), 0);
}
END_TEST

START_TEST(test_sock_opts_sol_ip_unknown_optname)
{
    struct wolfIP s;
    int udp_sd;
    int value = 1;
    socklen_t len = sizeof(value);

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP, 0xFFFF, &value, len), 0);
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, 0xFFFF, &value, &len), 0);
}
END_TEST

START_TEST(test_sock_accept_wrong_state)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;

    ck_assert_int_eq(wolfIP_sock_accept(&s, tcp_sd, NULL, NULL), -1);
}
END_TEST
START_TEST(test_sock_opts_and_names)
{
    struct wolfIP s;
    int udp_sd;
    int tcp_sd;
    int enable = 1;
    int ttl = 0;
    socklen_t optlen;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_sockaddr_in peer;
    socklen_t sin_len = sizeof(sin);
    socklen_t peer_len = sizeof(peer);
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL,
            &enable, sizeof(enable)), 0);
    s.udpsockets[SOCKET_UNMARK(udp_sd)].last_pkt_ttl = 42;
    ck_assert_int_eq(wolfIP_sock_get_recv_ttl(&s, udp_sd, &ttl), 1);
    ck_assert_int_eq(ttl, 42);

    optlen = sizeof(ttl);
    ttl = 0;
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL,
            &ttl, &optlen), 0);
    ck_assert_int_eq(ttl, 42);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(local_ip);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    memset(&sin, 0, sizeof(sin));
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, &sin_len), 0);
    ck_assert_uint_eq(sin.sin_port, ee16(1234));
    ck_assert_uint_eq(sin.sin_addr.s_addr, ee32(local_ip));

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->src_port = 4321;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->dst_port = 2222;

    memset(&sin, 0, sizeof(sin));
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, &sin_len), 0);
    ck_assert_uint_eq(sin.sin_port, 4321);
    ck_assert_uint_eq(sin.sin_addr.s_addr, local_ip);

    memset(&peer, 0, sizeof(peer));
    ck_assert_int_eq(wolfIP_sock_getpeername(&s, tcp_sd, (struct wolfIP_sockaddr *)&peer, &peer_len), 0);
    ck_assert_uint_eq(peer.sin_port, ee16(2222));
    ck_assert_uint_eq(peer.sin_addr.s_addr, ee32(remote_ip));
}
END_TEST

START_TEST(test_sock_get_recv_ttl_disabled)
{
    struct wolfIP s;
    int udp_sd;
    int ttl = 123;
    socklen_t len = sizeof(ttl);

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_get_recv_ttl(&s, udp_sd, &ttl), 0);
    ck_assert_int_eq(wolfIP_sock_getsockopt(&s, udp_sd, WOLFIP_SOL_IP, WOLFIP_IP_RECVTTL, &ttl, &len), 0);
    ck_assert_int_eq(ttl, 0);
}
END_TEST

START_TEST(test_sock_get_recv_ttl_null)
{
    struct wolfIP s;
    int udp_sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    s.udpsockets[SOCKET_UNMARK(udp_sd)].recv_ttl = 1;
    s.udpsockets[SOCKET_UNMARK(udp_sd)].last_pkt_ttl = 99;

    ck_assert_int_eq(wolfIP_sock_get_recv_ttl(&s, udp_sd, NULL), 1);
}
END_TEST

START_TEST(test_sock_connect_tcp_states)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(80);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ts->sock.tcp.state = TCP_SYN_SENT;
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);

    ts->sock.tcp.state = TCP_ESTABLISHED;
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
}
END_TEST

START_TEST(test_sock_listen_errors)
{
    struct wolfIP s;
    int udp_sd;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, udp_sd, 1), -1);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ck_assert_int_eq(wolfIP_sock_listen(&s, tcp_sd, 1), -1);

    ts->sock.tcp.state = TCP_CLOSED;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    filter_block_reason = WOLFIP_FILT_LISTENING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_LISTENING));
    ck_assert_int_eq(wolfIP_sock_listen(&s, tcp_sd, 1), -1);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSED);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
}
END_TEST

START_TEST(test_sock_getpeername_errors)
{
    struct wolfIP s;
    int tcp_sd;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t len = 1;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_getpeername(&s, -1, (struct wolfIP_sockaddr *)&sin, &len), -WOLFIP_EINVAL);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_getpeername(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, &len), -1);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_getpeername(&s, tcp_sd, NULL, &len), -1);
    ck_assert_int_eq(wolfIP_sock_getpeername(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, &len), -1);
}
END_TEST

START_TEST(test_sock_getsockname_errors)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t len = 1;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_getsockname(&s, -1, (struct wolfIP_sockaddr *)&sin, &len), -WOLFIP_EINVAL);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, &len), -1);
}
END_TEST

START_TEST(test_sock_getsockname_null_addr)
{
    struct wolfIP s;
    int tcp_sd;
    socklen_t len = sizeof(struct wolfIP_sockaddr_in);

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, tcp_sd, NULL, &len), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_getsockname_invalid_socket_ids)
{
    struct wolfIP s;
    struct wolfIP_sockaddr_in sin;
    socklen_t len = sizeof(sin);

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_getsockname(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, &len), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, &len), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_getsockname(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS,
            (struct wolfIP_sockaddr *)&sin, &len), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_getsockname_icmp_success)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t len = sizeof(sin);
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->src_port = 7;
    ts->local_ip = 0x0A000001U;

    ck_assert_int_eq(wolfIP_sock_getsockname(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, &len), 0);
    ck_assert_uint_eq(sin.sin_family, AF_INET);
    ck_assert_uint_eq(sin.sin_port, ee16(7));
    ck_assert_uint_eq(sin.sin_addr.s_addr, ee32(0x0A000001U));
}
END_TEST

START_TEST(test_sock_socket_udp_protocol_zero)
{
    struct wolfIP s;
    int udp_sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_gt(udp_sd, 0);
}
END_TEST

START_TEST(test_sock_socket_full_tables)
{
    struct wolfIP s;
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);

    for (i = 0; i < MAX_TCPSOCKETS; i++)
        s.tcpsockets[i].proto = WI_IPPROTO_TCP;
    ck_assert_int_eq(wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP), -1);

    for (i = 0; i < MAX_UDPSOCKETS; i++)
        s.udpsockets[i].proto = WI_IPPROTO_UDP;
    ck_assert_int_eq(wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP), -1);

    for (i = 0; i < MAX_ICMPSOCKETS; i++)
        s.icmpsockets[i].proto = WI_IPPROTO_ICMP;
    ck_assert_int_eq(wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP), -1);
}
END_TEST

START_TEST(test_register_callback_variants)
{
    struct wolfIP s;
    int tcp_sd;
    int udp_sd;
    int icmp_sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);

    wolfIP_register_callback(&s, -1, test_socket_cb, NULL);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    wolfIP_register_callback(&s, tcp_sd, test_socket_cb, NULL);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ck_assert_ptr_eq(ts->callback, test_socket_cb);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    wolfIP_register_callback(&s, udp_sd, test_socket_cb, NULL);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ck_assert_ptr_eq(ts->callback, test_socket_cb);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    wolfIP_register_callback(&s, icmp_sd, test_socket_cb, NULL);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ck_assert_ptr_eq(ts->callback, test_socket_cb);

    wolfIP_register_callback(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS, test_socket_cb, NULL);
    wolfIP_register_callback(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS, test_socket_cb, NULL);
    wolfIP_register_callback(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS, test_socket_cb, NULL);
}
END_TEST

START_TEST(test_sock_connect_udp_bound_ip_not_local)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->bound_local_ip = 0x0A0000FEU;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5555);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)),
            -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_connect_udp_bound_ip_success)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->bound_local_ip = local_ip;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5555);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, local_ip);
    ck_assert_uint_eq(ts->if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_sock_connect_udp_primary_fallback)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5555);
    sin.sin_addr.s_addr = ee32(0xC0A80199U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST

START_TEST(test_sock_connect_icmp_primary_fallback)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = ee32(0xC0A80199U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, icmp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_uint_eq(ts->local_ip, primary_ip);
}
END_TEST

START_TEST(test_sock_connect_tcp_filter_drop)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    filter_block_reason = WOLFIP_FILT_CONNECTING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_CONNECTING));

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5555);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSED);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
}
END_TEST

START_TEST(test_sock_connect_tcp_src_port_low)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_CLOSED;
    ts->src_port = 1;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5555);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_uint_eq(ts->src_port, 1025);
}
END_TEST

START_TEST(test_sock_sendto_more_error_paths)
{
    struct wolfIP s;
    int tcp_sd;
    int udp_sd;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[64];
    uint8_t tiny[128];
    uint8_t tiny_udp[32];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    fifo_init(&ts->sock.tcp.txbuf, tiny, sizeof(tiny));
    ret = wolfIP_sock_sendto(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, -1);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    fifo_init(&ts->sock.udp.txbuf, tiny_udp, sizeof(tiny_udp));
    ret = wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_int_eq(ret, -1);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ret = wolfIP_sock_sendto(&s, icmp_sd, NULL, 0, 0, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_no_dest)
{
    struct wolfIP s;
    int udp_sd;
    uint8_t buf[4] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0, NULL, 0), -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_addrlen_short)
{
    struct wolfIP s;
    int udp_sd;
    uint8_t buf[4] = {0};
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, 1), -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_len_too_large)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[WI_IP_MTU] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf,
            (size_t)(WI_IP_MTU - IP_HEADER_LEN - UDP_HEADER_LEN + 1), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -1);
}
END_TEST

START_TEST(test_sock_sendto_udp_fifo_full)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t tiny[2];
    uint8_t buf[4] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    fifo_init(&ts->sock.udp.txbuf, tiny, sizeof(tiny));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_sendto_icmp_len_invalid)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[ICMP_HEADER_LEN - 1] = {0};
    uint8_t bigbuf[WI_IP_MTU] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, bigbuf,
            (size_t)(WI_IP_MTU - IP_HEADER_LEN + 1), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_sendto_icmp_fifo_full)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t tiny[2];
    uint8_t buf[ICMP_HEADER_LEN] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    fifo_init(&ts->sock.udp.txbuf, tiny, sizeof(tiny));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_sendto_icmp_addrlen_short)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t buf[ICMP_HEADER_LEN] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, 1), -1);
}
END_TEST

START_TEST(test_sock_sendto_icmp_remote_zero)
{
    struct wolfIP s;
    int icmp_sd;
    uint8_t buf[ICMP_HEADER_LEN] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, buf, sizeof(buf), 0, NULL, 0), -1);
}
END_TEST

START_TEST(test_sock_sendto_tcp_txbuf_full)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    uint8_t buf[8] = {0};
    uint8_t tiny[16];

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    fifo_init(&ts->sock.tcp.txbuf, tiny, sizeof(tiny));

    ck_assert_int_eq(wolfIP_sock_sendto(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0), -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_sendto_tcp_partial_send_only)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    size_t seg_payload = TCP_MSS - TCP_OPTIONS_LEN;
    size_t payload_len = seg_payload;
    uint8_t buf[seg_payload * 2];
    size_t required = sizeof(struct pkt_desc) + sizeof(struct wolfIP_tcp_seg) +
        TCP_OPTIONS_LEN + payload_len;
    /* Provide a small alignment cushion so one segment fits but two do not. */
    uint8_t txbuf[required + 8];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);
    fifo_init(&ts->sock.tcp.txbuf, txbuf, sizeof(txbuf));

    memset(buf, 0xAB, sizeof(buf));
    /* Expect a partial send because the tx buffer fits only one segment
     * (includes full TCP/IP header size and alignment padding). */
    ret = wolfIP_sock_sendto(&s, tcp_sd, buf, sizeof(buf), 0, NULL, 0);
    ck_assert_msg(ret > 0, "expected partial send, got %d", ret);
}
END_TEST

START_TEST(test_sock_sendto_udp_fifo_push_fails_returns_eagain)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    uint8_t txbuf[4096];
    enum { UDP_PAYLOAD_LEN =
        (WI_IP_MTU - IP_HEADER_LEN - UDP_HEADER_LEN) > 1000
            ? 1000
            : (WI_IP_MTU - IP_HEADER_LEN - UDP_HEADER_LEN)
    };
    uint8_t payload[UDP_PAYLOAD_LEN];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->dst_port = 4321;
    ts->remote_ip = 0x0A000002U;
    ts->local_ip = 0x0A000001U;

    fifo_init(&ts->sock.udp.txbuf, txbuf, sizeof(txbuf));
    ts->sock.udp.txbuf.head = 100;
    ts->sock.udp.txbuf.tail = 100 + UDP_PAYLOAD_LEN;
    ts->sock.udp.txbuf.h_wrap = 3000;

    memset(payload, 0xEE, sizeof(payload));
    ret = wolfIP_sock_sendto(&s, udp_sd, payload, sizeof(payload), 0, NULL, 0);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_sendto_icmp_fifo_push_fails_returns_eagain)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    uint8_t txbuf[4096];
    enum { ICMP_PAYLOAD_LEN =
        (WI_IP_MTU - IP_HEADER_LEN) > 1000
            ? 1000
            : (WI_IP_MTU - IP_HEADER_LEN)
    };
    uint8_t payload[ICMP_PAYLOAD_LEN];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->remote_ip = 0x0A000002U;

    fifo_init(&ts->sock.udp.txbuf, txbuf, sizeof(txbuf));
    ts->sock.udp.txbuf.head = 100;
    ts->sock.udp.txbuf.tail = 100 + ICMP_PAYLOAD_LEN;
    ts->sock.udp.txbuf.h_wrap = 3000;

    memset(payload, 0xEE, sizeof(payload));
    payload[0] = ICMP_ECHO_REQUEST;
    ret = wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0, NULL, 0);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_recvfrom_icmp_paths)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct {
        struct wolfIP_icmp_packet icmp;
        uint8_t payload[2];
    } icmp_frame;
    struct pkt_desc *desc;
    uint8_t rxbuf[ICMP_HEADER_LEN + 2];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    fifo_init(&ts->sock.udp.rxbuf, ts->rxmem, RXBUF_SIZE);

    ret = wolfIP_sock_recvfrom(&s, icmp_sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);

    memset(&icmp_frame, 0, sizeof(icmp_frame));
    icmp_frame.icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN + sizeof(icmp_frame.payload));
    icmp_frame.icmp.type = ICMP_ECHO_REPLY;
    icmp_frame.icmp.code = 0;
    {
        uint8_t *payload = ((uint8_t *)&icmp_frame.icmp.type) + ICMP_HEADER_LEN;
        payload[0] = 0xAA;
        payload[1] = 0xBB;
    }
    ck_assert_int_eq(fifo_push(&ts->sock.udp.rxbuf, &icmp_frame, sizeof(icmp_frame)), 0);
    desc = fifo_peek(&ts->sock.udp.rxbuf);
    ck_assert_ptr_nonnull(desc);

    ret = wolfIP_sock_recvfrom(&s, icmp_sd, rxbuf, (size_t)(ICMP_HEADER_LEN - 1), 0, NULL, NULL);
    ck_assert_int_eq(ret, -1);

    ret = wolfIP_sock_recvfrom(&s, icmp_sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, ICMP_HEADER_LEN + 2);
}
END_TEST

START_TEST(test_sock_recvfrom_udp_short_addrlen)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = 1;
    uint8_t buf[8];

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, &alen), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_recvfrom_icmp_short_addrlen)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = 1;
    uint8_t buf[8];

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);

    ck_assert_int_eq(wolfIP_sock_recvfrom(&s, icmp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&sin, &alen), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_sock_recvfrom_udp_fifo_alignment)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in from;
    socklen_t from_len;
    uint8_t buf[16];
    uint8_t payload1[3] = {0xA1, 0xA2, 0xA3};
    uint8_t payload2[5] = {0xB1, 0xB2, 0xB3, 0xB4, 0xB5};
    uint8_t payload3[7] = {0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7};
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 1234;

    enqueue_udp_rx(ts, payload1, sizeof(payload1), 1111);
    enqueue_udp_rx(ts, payload2, sizeof(payload2), 2222);
    enqueue_udp_rx(ts, payload3, sizeof(payload3), 3333);

    memset(buf, 0, sizeof(buf));
    ret = wolfIP_sock_recv(&s, udp_sd, buf, sizeof(buf), 0);
    ck_assert_int_eq(ret, (int)sizeof(payload1));
    ck_assert_mem_eq(buf, payload1, sizeof(payload1));

    memset(&from, 0, sizeof(from));
    from_len = sizeof(from);
    memset(buf, 0, sizeof(buf));
    ret = wolfIP_sock_recvfrom(&s, udp_sd, buf, sizeof(buf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len);
    ck_assert_int_eq(ret, (int)sizeof(payload2));
    ck_assert_mem_eq(buf, payload2, sizeof(payload2));
    ck_assert_uint_eq(from.sin_port, ee16(2222));
    ck_assert_uint_eq(from_len, sizeof(from));

    memset(buf, 0, sizeof(buf));
    ret = wolfIP_sock_recv(&s, udp_sd, buf, sizeof(buf), 0);
    ck_assert_int_eq(ret, (int)sizeof(payload3));
    ck_assert_mem_eq(buf, payload3, sizeof(payload3));

    ret = wolfIP_sock_recv(&s, udp_sd, buf, sizeof(buf), 0);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_sock_recvfrom_udp_payload_too_long)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[16] = {0};
    uint8_t rxbuf[4];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);

    inject_udp_datagram(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U, 4321, 1234,
            payload, sizeof(payload));

    ret = wolfIP_sock_recvfrom(&s, udp_sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, -1);
}
END_TEST

START_TEST(test_sock_recvfrom_icmp_payload_too_long)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_icmp_packet icmp;
    uint8_t rxbuf[4];
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN + 8);
    fifo_push(&ts->sock.udp.rxbuf, &icmp, sizeof(icmp));

    ret = wolfIP_sock_recvfrom(&s, icmp_sd, rxbuf, sizeof(rxbuf), 0, NULL, NULL);
    ck_assert_int_eq(ret, -1);
}
END_TEST

START_TEST(test_icmp_input_echo_reply_queues)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->src_port = ee16(0x1234);

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(ts->remote_ip);
    icmp.ip.dst = ee32(ts->local_ip);
    icmp.ip.ttl = 55;
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REPLY;
    icmp_set_echo_id(&icmp, ts->src_port);
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.rxbuf));
    ck_assert_uint_eq(ts->last_pkt_ttl, 55);
}
END_TEST

START_TEST(test_icmp_input_echo_request_reply_sent)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_OFF;
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.ttl = 64;
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(((struct wolfIP_icmp_packet *)last_frame_sent)->type, ICMP_ECHO_REPLY);
}
END_TEST

START_TEST(test_icmp_input_echo_request_dhcp_running_no_reply)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_DISCOVER_SENT;
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_icmp_input_echo_request_filter_drop)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_OFF;
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_icmp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_icmp_mask(0);
}
END_TEST

START_TEST(test_icmp_input_echo_request_ip_filter_drop)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_OFF;
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_ip_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_ip_mask(0);
}
END_TEST

START_TEST(test_icmp_input_echo_request_eth_filter_drop)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_OFF;
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

START_TEST(test_icmp_input_filter_drop_receiving)
{
    struct wolfIP s;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);
    filter_block_reason = WOLFIP_FILT_RECEIVING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_icmp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));
    last_frame_sent_size = 0;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.type = ICMP_ECHO_REQUEST;
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_input(&s, TEST_PRIMARY_IF, (struct wolfIP_ip_packet *)&icmp, frame_len);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_icmp_mask(0);
}
END_TEST
START_TEST(test_dns_send_query_errors)
{
    struct wolfIP s;
    uint16_t id = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0;
    ck_assert_int_eq(dns_send_query(&s, "example.com", &id, DNS_A), -101);

    s.dns_server = 0x08080808U;
    s.dns_id = 123;
    ck_assert_int_eq(dns_send_query(&s, "example.com", &id, DNS_A), -16);
}
END_TEST
START_TEST(test_fifo_push_and_pop) {
    struct fifo f;
    struct pkt_desc *desc, *desc2;
    uint8_t data[] = {1, 2, 3, 4, 5};

    fifo_init(&f, mem, memsz);

    ck_assert_int_eq(fifo_space(&f), memsz);
    /* Push one payload and verify descriptors reflect its size. */
    ck_assert_int_eq(fifo_push(&f, data, sizeof(data)), 0);

    /* Peek should return the current head descriptor without consuming data. */
    desc = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->len, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data));
    desc2 = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc2);
    ck_assert_ptr_eq(desc, desc2);
    ck_assert_int_eq(fifo_len(&f), desc->len + sizeof(struct pkt_desc));


    /* Pop should consume the packet and restore full space. */
    desc = fifo_pop(&f);
    ck_assert_int_eq(fifo_space(&f), memsz);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->len, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data));
    ck_assert_ptr_eq(fifo_peek(&f), NULL);
}
END_TEST

START_TEST(test_sock_accept_success)
{
    struct wolfIP s;
    int listen_sd;
    int new_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = sizeof(sin);
    struct tsocket *listen_ts;
    struct tsocket *new_ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);

    new_sd = wolfIP_sock_accept(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, &alen);
    ck_assert_int_gt(new_sd, 0);
    new_ts = &s.tcpsockets[SOCKET_UNMARK(new_sd)];
    ck_assert_int_eq(new_ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(sin.sin_port, ee16(new_ts->dst_port));

    listen_ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(listen_ts->sock.tcp.state, TCP_LISTEN);
}
END_TEST

START_TEST(test_sock_accept_filtered_out)
{
    struct wolfIP s;
    int listen_sd;
    int new_sd;
    struct wolfIP_sockaddr_in sin;
    socklen_t alen = sizeof(sin);
    struct tsocket *listen_ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    filter_block_reason = WOLFIP_FILT_ACCEPTING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_ACCEPTING));

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    new_sd = wolfIP_sock_accept(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, &alen);
    ck_assert_int_eq(new_sd, -1);
    ck_assert_int_gt(filter_block_calls, 0);

    listen_ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(listen_ts->sock.tcp.state, TCP_LISTEN);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST
START_TEST(test_tcp_handshake_and_fin_close_wait)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000A1U;
    uint16_t local_port = 8080;
    uint16_t remote_port = 40000;
    uint32_t server_seq;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ck_assert_int_eq(wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, local_ip, local_port);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(ts->remote_ip, remote_ip);
    ck_assert_uint_eq(ts->dst_port, remote_port);

    server_seq = ts->sock.tcp.seq;
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port, 2, server_seq + 1, 0x10);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);

    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port, 3, server_seq + 1, 0x01);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSE_WAIT);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, CB_EVENT_CLOSED);
}
END_TEST

START_TEST(test_poll_tcp_ack_only_skips_send)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.ack = 10;
    ts->sock.tcp.last_ack = 10;
    ts->sock.tcp.rto = 100;
    /* Ensure send window allows processing of the queued ACK-only segment. */
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.peer_rwnd = TCP_MSS;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 0, 0x10), 0);
    (void)wolfIP_poll(&s, 100);

    ck_assert_ptr_eq(fifo_peek(&ts->sock.tcp.txbuf), NULL);
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x00);
    ck_assert_int_eq(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_poll_tcp_send_on_arp_hit)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xef};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.ack = 20;
    ts->sock.tcp.last_ack = 0;
    ts->sock.tcp.rto = 100;
    /* Ensure send window allows emitting the queued data segment. */
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, 0x18), 0);
    (void)wolfIP_poll(&s, 200);

    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x00);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_poll_tcp_arp_request_on_miss)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.rto = 100;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, 0x18), 0);
    (void)wolfIP_poll(&s, 2000);

    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x06);
}
END_TEST
START_TEST(test_tcp_rto_cb_resets_flags_and_arms_timer)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.rto_backoff = 0;
    ts->sock.tcp.cwnd = TCP_MSS * 2;
    ts->sock.tcp.snd_una = 101;
    ts->sock.tcp.seq = 101;

    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, 0x18), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    s.last_tick = 1000;
    tcp_rto_cb(ts);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, PKT_FLAG_SENT);
    ck_assert_uint_gt(ts->sock.tcp.rto_backoff, 0);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_rto_cb_no_pending_resets_backoff)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto_backoff = 3;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    tcp_rto_cb(ts);
    ck_assert_uint_eq(ts->sock.tcp.rto_backoff, 0);
}
END_TEST

START_TEST(test_tcp_rto_cb_skips_unsent_desc)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg tcp;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto_backoff = 7;

    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    memset(&tcp, 0, sizeof(tcp));
    fifo_push(&ts->sock.tcp.txbuf, &tcp, sizeof(tcp));
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);

    tcp_rto_cb(ts);
    ck_assert_uint_eq(ts->sock.tcp.rto_backoff, 0);
}
END_TEST

START_TEST(test_tcp_rto_cb_non_tcp_noop)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_UDP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto_backoff = 5;

    tcp_rto_cb(ts);
    ck_assert_uint_eq(ts->sock.tcp.rto_backoff, 5);
}
END_TEST

START_TEST(test_tcp_rto_cb_non_established_noop)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->sock.tcp.rto_backoff = 2;

    tcp_rto_cb(ts);
    ck_assert_uint_eq(ts->sock.tcp.rto_backoff, 2);
}
END_TEST

START_TEST(test_tcp_rto_cb_cancels_existing_timer)
{
    struct wolfIP s;
    struct tsocket *ts;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.tmr_rto = 1;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    tcp_rto_cb(ts);
    ck_assert_int_eq(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_tcp_rto_cb_clears_sack_and_marks_lowest_only)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc1;
    struct pkt_desc *desc2;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.cwnd = TCP_MSS * 8;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 100;
    ts->sock.tcp.bytes_in_flight = 2;
    ts->sock.tcp.peer_sack_count = 1;
    ts->sock.tcp.peer_sack[0].left = 101;
    ts->sock.tcp.peer_sack[0].right = 102;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, 0x18), 0);
    ts->sock.tcp.seq = 101;
    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, 0x18), 0);
    desc1 = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc1);
    desc2 = fifo_next(&ts->sock.tcp.txbuf, desc1);
    ck_assert_ptr_nonnull(desc2);
    ck_assert_ptr_ne(desc2, desc1);

    desc1->flags |= PKT_FLAG_SENT;
    desc2->flags |= PKT_FLAG_SENT;

    s.last_tick = 1000;
    tcp_rto_cb(ts);

    ck_assert_uint_eq(ts->sock.tcp.peer_sack_count, 0);
    ck_assert_int_eq(desc1->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc1->flags & PKT_FLAG_RETRANS, 0);
    ck_assert_int_ne(desc2->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_eq(desc2->flags & PKT_FLAG_RETRANS, 0);
    ck_assert_uint_eq(ts->sock.tcp.cwnd, TCP_MSS);
    ck_assert_uint_eq(ts->sock.tcp.ssthresh, TCP_MSS * 4);
}
END_TEST

START_TEST(test_tcp_rto_cb_ssthresh_floor_two_mss)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.snd_una = 101;
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.bytes_in_flight = 1;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, 0x18), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    s.last_tick = 1000;
    tcp_rto_cb(ts);

    ck_assert_uint_eq(ts->sock.tcp.cwnd, TCP_MSS);
    ck_assert_uint_eq(ts->sock.tcp.ssthresh, TCP_MSS * 2);
}
END_TEST

START_TEST(test_tcp_rto_cb_fallback_marks_lowest_sent_when_no_snd_una_cover)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.snd_una = 50;
    ts->sock.tcp.seq = 100;
    ts->sock.tcp.bytes_in_flight = 1;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 1, 0x18), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    s.last_tick = 1000;
    tcp_rto_cb(ts);

    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc->flags & PKT_FLAG_RETRANS, 0);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, 50U);
    ck_assert_uint_eq(ts->sock.tcp.cwnd, TCP_MSS);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
}
END_TEST

START_TEST(test_poll_udp_send_on_arp_hit)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {1, 2, 3, 4};
    uint8_t peer_mac[6] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ret = wolfIP_sock_sendto(&s, udp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, (int)sizeof(payload));

    (void)wolfIP_poll(&s, 100);
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x00);
}
END_TEST

START_TEST(test_poll_icmp_send_on_arp_hit)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN + 1];
    uint8_t peer_mac[6] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x06};
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    memset(payload, 0, sizeof(payload));
    payload[0] = ICMP_ECHO_REQUEST;
    ret = wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, (int)sizeof(payload));

    (void)wolfIP_poll(&s, 100);
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x00);
}
END_TEST

START_TEST(test_dhcp_timer_cb_paths)
{
    struct wolfIP s;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    s.dhcp_xid = 1;

    s.dhcp_state = DHCP_DISCOVER_SENT;
    s.dhcp_timeout_count = 0;
    ret = dhcp_send_discover(&s);
    ck_assert_int_eq(ret, 0);
    dhcp_timer_cb(&s);
    ck_assert_int_eq(s.dhcp_timeout_count, 1);

    s.dhcp_timeout_count = DHCP_DISCOVER_RETRIES;
    dhcp_timer_cb(&s);
    ck_assert_int_eq(s.dhcp_state, DHCP_OFF);

    s.dhcp_state = DHCP_REQUEST_SENT;
    s.dhcp_timeout_count = 0;
    ret = dhcp_send_request(&s);
    ck_assert_int_eq(ret, 0);
    dhcp_timer_cb(&s);
    ck_assert_int_eq(s.dhcp_timeout_count, 1);
}
END_TEST

START_TEST(test_dhcp_client_init_and_bound)
{
    struct wolfIP s;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_BOUND;
    ret = dhcp_client_init(&s);
    ck_assert_int_eq(ret, -1);

    s.dhcp_state = DHCP_OFF;
    ret = dhcp_client_init(&s);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(dhcp_bound(&s), 0);
}
END_TEST
START_TEST(test_sock_close_udp_icmp)
{
    struct wolfIP s;
    int udp_sd;
    int icmp_sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->src_port = 1234;
    ck_assert_int_eq(wolfIP_sock_close(&s, udp_sd), 0);
    ck_assert_int_eq(ts->proto, 0);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->src_port = 1;
    ck_assert_int_eq(wolfIP_sock_close(&s, icmp_sd), 0);
    ck_assert_int_eq(ts->proto, 0);
}
END_TEST

START_TEST(test_sock_close_invalid_fds)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_int_eq(wolfIP_sock_close(&s, -1), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_close(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_close(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_close(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolfIP_sock_close(&s, 1), -1);
}
END_TEST

START_TEST(test_sock_close_tcp_fin_wait_1)
{
    struct wolfIP s;
    struct tsocket *ts;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_FIN_WAIT_1;

    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSING);
}
END_TEST

START_TEST(test_sock_close_tcp_other_state_closes)
{
    struct wolfIP s;
    struct tsocket *ts;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;

    ck_assert_int_eq(wolfIP_sock_close(&s, sd), 0);
    ck_assert_int_eq(ts->proto, 0);
}
END_TEST

START_TEST(test_sock_close_tcp_closed_returns_minus_one)
{
    struct wolfIP s;
    struct tsocket *ts;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_CLOSED;

    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -1);
}
END_TEST
START_TEST(test_fifo_push_and_pop_multiple) {
    struct fifo f;
    uint8_t data[] = {1, 2, 3, 4, 5};
    uint8_t data2[] = {6, 7, 8, 9, 10};
    struct pkt_desc *desc;

    fifo_init(&f, mem, memsz);
    ck_assert_int_eq(fifo_space(&f), memsz);

    // Test push
    ck_assert_int_eq(fifo_push(&f, data, sizeof(data)), 0);
    ck_assert_int_eq(fifo_len(&f), sizeof(data) + sizeof(struct pkt_desc));
    ck_assert_int_eq(fifo_space(&f), f.size - (sizeof(data) + sizeof(struct pkt_desc)));
    ck_assert_int_eq(fifo_push(&f, data2, sizeof(data2)), 0);

    // Test pop
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->len, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data));

    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->len, sizeof(data2));
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data2, sizeof(data2));
}
END_TEST

START_TEST(test_dhcp_poll_offer_and_ack)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;
    struct tsocket *ts;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dhcp_udp_sd)];

    memset(&msg, 0, sizeof(msg));
    msg.yiaddr = ee32(0x0A000064U);
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_OFFER;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_SERVER_ID;
    opt->len = 4;
    opt->data[0] = 0x0A;
    opt->data[1] = 0x00;
    opt->data[2] = 0x00;
    opt->data[3] = 0x01;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_SUBNET_MASK;
    opt->len = 4;
    opt->data[0] = 0xFF;
    opt->data[1] = 0xFF;
    opt->data[2] = 0xFF;
    opt->data[3] = 0x00;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    s.dhcp_state = DHCP_DISCOVER_SENT;
    enqueue_udp_rx(ts, &msg, sizeof(msg), DHCP_SERVER_PORT);
    ret = dhcp_poll(&s);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_REQUEST_SENT);

    memset(&msg, 0, sizeof(msg));
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_SERVER_ID;
    opt->len = 4;
    opt->data[0] = 0x0A;
    opt->data[1] = 0x00;
    opt->data[2] = 0x00;
    opt->data[3] = 0x01;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_SUBNET_MASK;
    opt->len = 4;
    opt->data[0] = 0xFF;
    opt->data[1] = 0xFF;
    opt->data[2] = 0xFF;
    opt->data[3] = 0x00;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_ROUTER;
    opt->len = 4;
    opt->data[0] = 0x0A;
    opt->data[1] = 0x00;
    opt->data[2] = 0x00;
    opt->data[3] = 0x01;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_DNS;
    opt->len = 4;
    opt->data[0] = 0x08;
    opt->data[1] = 0x08;
    opt->data[2] = 0x08;
    opt->data[3] = 0x08;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    s.dhcp_state = DHCP_REQUEST_SENT;
    enqueue_udp_rx(ts, &msg, sizeof(msg), DHCP_SERVER_PORT);
    ret = dhcp_poll(&s);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_BOUND);
}
END_TEST

START_TEST(test_dns_callback_ptr_response)
{
    struct wolfIP s;
    uint8_t response[192];
    int pos;
    struct dns_header *hdr = (struct dns_header *)response;
    struct dns_question *q;
    struct dns_rr *rr;
    const char *ptr_name = "1.0.0.10.in-addr.arpa";
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_query_type = DNS_QUERY_TYPE_PTR;
    s.dns_id = 0x1234;
    s.dns_ptr_cb = test_dns_ptr_cb;
    s.dns_lookup_cb = NULL;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)];

    memset(response, 0, sizeof(response));
    hdr->id = ee16(s.dns_id);
    hdr->flags = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(1);
    pos = sizeof(struct dns_header);
    response[pos++] = 1; response[pos++] = 'a';
    response[pos++] = 3; memcpy(&response[pos], "com", 3); pos += 3;
    response[pos++] = 0;
    q = (struct dns_question *)(response + pos);
    q->qtype = ee16(DNS_PTR);
    q->qclass = ee16(1);
    pos += sizeof(struct dns_question);
    response[pos++] = 0xC0;
    response[pos++] = (uint8_t)sizeof(struct dns_header);
    rr = (struct dns_rr *)(response + pos);
    rr->type = ee16(DNS_PTR);
    rr->class = ee16(1);
    rr->ttl = ee32(60);
    rr->rdlength = ee16((uint16_t)(strlen(ptr_name) + 2));
    pos += sizeof(struct dns_rr);
    response[pos++] = (uint8_t)strlen(ptr_name);
    memcpy(&response[pos], ptr_name, strlen(ptr_name));
    pos += (int)strlen(ptr_name);
    response[pos++] = 0;

    enqueue_udp_rx(ts, response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
}
END_TEST
START_TEST(test_tcp_syn_sent_to_established)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000B1U;
    uint16_t remote_port = 12345;
    uint32_t client_seq;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(remote_port);
    sin.sin_addr.s_addr = ee32(remote_ip);

    ck_assert_int_eq(wolfIP_sock_connect(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);
    ck_assert_uint_eq(ts->remote_ip, remote_ip);
    ck_assert_uint_eq(ts->dst_port, remote_port);

    client_seq = ts->sock.tcp.seq;
    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, ts->src_port,
            100, client_seq + 1, 0x12);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.ack, 101);
}
END_TEST

START_TEST(test_udp_try_recv_short_frame)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_udp_datagram udp;
    uint32_t local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = ee16(1234);
    ts->local_ip = local_ip;

    memset(&udp, 0, sizeof(udp));
    udp.ip.dst = ee32(local_ip);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN + 4);
    udp_try_recv(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN));
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_udp_try_recv_filter_drop)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_udp_datagram udp;
    uint32_t local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = ee16(1234);
    ts->local_ip = local_ip;

    filter_block_reason = WOLFIP_FILT_RECEIVING;
    filter_block_calls = 0;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_udp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));

    memset(&udp, 0, sizeof(udp));
    udp.ip.dst = ee32(local_ip);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN + 4);
    udp_try_recv(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
    ck_assert_int_gt(filter_block_calls, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_udp_mask(0);
}
END_TEST

START_TEST(test_udp_try_recv_conf_null)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_udp_datagram udp;
    uint32_t dst_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = dst_ip;
    ts->remote_ip = 0;

    memset(&udp, 0, sizeof(udp));
    udp.ip.dst = ee32(dst_ip);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN + 4);
    udp_try_recv(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.rxbuf));
}
END_TEST

START_TEST(test_udp_try_recv_remote_ip_matches_local_ip)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_udp_datagram udp;
    uint32_t local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = local_ip;
    ts->remote_ip = local_ip;

    memset(&udp, 0, sizeof(udp));
    udp.ip.dst = ee32(local_ip);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN + 4);
    udp_try_recv(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_udp_try_recv_dhcp_running_local_zero)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_udp_datagram udp;
    uint32_t local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_state = DHCP_DISCOVER_SENT;
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->local_ip = 0;

    memset(&udp, 0, sizeof(udp));
    udp.ip.dst = ee32(local_ip);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN + 4);
    udp_try_recv(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.rxbuf));
}
END_TEST

START_TEST(test_udp_try_recv_short_expected_len)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_udp_datagram udp;
    uint32_t local_ip = 0x0A000001U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = udp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = ee16(1234);
    ts->local_ip = local_ip;

    memset(&udp, 0, sizeof(udp));
    udp.ip.dst = ee32(local_ip);
    udp.dst_port = ee16(1234);
    udp.len = ee16(UDP_HEADER_LEN + 10);
    udp_try_recv(&s, TEST_PRIMARY_IF, &udp, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 4));
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_dns_callback_bad_flags)
{
    struct wolfIP s;
    uint8_t response[32];
    struct dns_header *hdr = (struct dns_header *)response;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_id = 0x1234;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    memset(response, 0, sizeof(response));
    hdr->id = ee16(s.dns_id);
    hdr->flags = 0;

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)], response, sizeof(response), DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_uint_eq(s.dns_id, 0x1234);
}
END_TEST

START_TEST(test_dns_callback_bad_name)
{
    struct wolfIP s;
    uint8_t response[64];
    int pos;
    struct dns_header *hdr = (struct dns_header *)response;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_id = 0x1234;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    memset(response, 0, sizeof(response));
    hdr->id = ee16(s.dns_id);
    hdr->flags = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(0);
    pos = sizeof(struct dns_header);
    response[pos++] = 60;
    memset(&response[pos], 'a', 5);
    pos += 5;

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)], response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_uint_eq(s.dns_id, 0);
}
END_TEST

START_TEST(test_tcp_input_ttl_zero_sends_icmp)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    last_frame_sent_size = 0;

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 5678;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    memset(&seg, 0, sizeof(seg));
    seg.ip.ttl = 0;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(ts->dst_port);
    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_uint_gt(last_frame_sent_size, 0);
}
END_TEST
START_TEST(test_tcp_rst_closes_socket)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000C1U;
    uint16_t local_port = 2222;
    uint16_t remote_port = 3333;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port = local_port;
    ts->dst_port = remote_port;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            5, 0, 0x04);
    ck_assert_int_eq(ts->proto, 0);
}
END_TEST

START_TEST(test_tcp_rst_ignored_in_listen)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A0000A1U, 0x0A000001U, 40000, 1234, 1, 0, 0x04);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
    ck_assert_int_eq(ts->proto, WI_IPPROTO_TCP);
}
END_TEST

START_TEST(test_tcp_rst_syn_rcvd_returns_to_listen)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000A1U;
    uint16_t local_port = 1234;
    uint16_t remote_port = 40000;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, local_ip, local_port);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);

    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port, 1, 0, 0x04);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
    ck_assert_uint_eq(ts->remote_ip, IPADDR_ANY);
    ck_assert_uint_eq(ts->dst_port, 0);
}
END_TEST

START_TEST(test_tcp_input_fin_wait_2_fin_sets_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    uint32_t seq = 111;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_2;
    ts->src_port = 1234;
    ts->dst_port = 2222;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    memset(&seg, 0, sizeof(seg));
    seg.ip.ttl = 64;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(ts->dst_port);
    seg.flags = 0x01;
    seg.seq = ee32(seq);

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_2);
    ck_assert_uint_eq(ts->sock.tcp.ack, seq + 1);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, CB_EVENT_CLOSED);
}
END_TEST

START_TEST(test_tcp_input_fin_wait_2_ack_with_payload_receives)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->sock.tcp.state = TCP_FIN_WAIT_2;
    ts->sock.tcp.ack = 50;
    ts->src_port = 1234;
    ts->dst_port = 2222;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    memset(buf, 0, sizeof(buf));
    seg->ip.ttl = 64;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->ip.src = ee32(ts->remote_ip);
    seg->ip.dst = ee32(ts->local_ip);
    seg->dst_port = ee16(ts->src_port);
    seg->src_port = ee16(ts->dst_port);
    seg->seq = ee32(50);
    seg->ack = ee32(10);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = 0x10;
    seg->data[0] = TCP_OPTION_EOO;

    tcp_input(&s, TEST_PRIMARY_IF, seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 1));
    ck_assert_uint_eq(ts->sock.tcp.ack, 50);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, 0);
}
END_TEST

START_TEST(test_dns_callback_bad_rr_rdlen)
{
    struct wolfIP s;
    uint8_t response[128];
    int pos;
    struct dns_header *hdr = (struct dns_header *)response;
    struct dns_question *q;
    struct dns_rr *rr;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_id = 0x1234;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    memset(response, 0, sizeof(response));
    hdr->id = ee16(s.dns_id);
    hdr->flags = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(1);
    pos = sizeof(struct dns_header);
    response[pos++] = 1; response[pos++] = 'a';
    response[pos++] = 0;
    q = (struct dns_question *)(response + pos);
    q->qtype = ee16(DNS_A);
    q->qclass = ee16(1);
    pos += sizeof(struct dns_question);
    response[pos++] = 0xC0;
    response[pos++] = (uint8_t)sizeof(struct dns_header);
    rr = (struct dns_rr *)(response + pos);
    rr->type = ee16(DNS_A);
    rr->class = ee16(1);
    rr->ttl = ee32(60);
    rr->rdlength = ee16(64);
    pos += sizeof(struct dns_rr);

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)], response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);
    ck_assert_uint_eq(s.dns_id, 0);
}
END_TEST

START_TEST(test_dhcp_parse_offer_no_match)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_REQUEST;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_invalid)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct dhcp_option *opt;

    wolfIP_init(&s);
    memset(&msg, 0, sizeof(msg));
    opt = (struct dhcp_option *)msg.options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = DHCP_ACK;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_END;
    opt->len = 0;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg), -1);
}
END_TEST

START_TEST(test_dhcp_poll_no_data_and_wrong_state)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);

    s.dhcp_state = DHCP_OFF;
    ck_assert_int_eq(dhcp_poll(&s), -1);
}
END_TEST
START_TEST(test_tcp_fin_wait_1_to_closing)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000D1U;
    uint16_t local_port = 4444;
    uint16_t remote_port = 5555;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port = local_port;
    ts->dst_port = remote_port;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            9, 0, 0x01);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSING);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, CB_EVENT_CLOSED);
}
END_TEST

#if WOLFIP_ENABLE_FORWARDING
START_TEST(test_forward_prepare_paths)
{
    struct wolfIP s;
    uint8_t mac[6] = {0};
    int broadcast = 0;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    ret = wolfIP_forward_prepare(&s, TEST_LOOPBACK_IF, 0x0A000002U, mac, &broadcast);
    ck_assert_int_eq(ret, 1);
    ck_assert_int_eq(broadcast, 0);

    ret = wolfIP_forward_prepare(&s, TEST_PRIMARY_IF, 0xFFFFFFFFU, mac, &broadcast);
    ck_assert_int_eq(ret, 1);
    ck_assert_int_eq(broadcast, 1);

    last_frame_sent_size = 0;
    s.last_tick = 2000;
    ret = wolfIP_forward_prepare(&s, TEST_PRIMARY_IF, 0x0A000002U, mac, &broadcast);
    ck_assert_int_eq(ret, 0);
    ck_assert_uint_gt(last_frame_sent_size, 0);

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);
    ret = wolfIP_forward_prepare(&s, TEST_PRIMARY_IF, 0x0A000002U, mac, &broadcast);
    ck_assert_int_eq(ret, 1);
    ck_assert_int_eq(broadcast, 0);
    ck_assert_mem_eq(mac, "\x01\x02\x03\x04\x05\x06", 6);
}
END_TEST

START_TEST(test_forward_prepare_null_args)
{
    struct wolfIP s;
    uint8_t mac[6];
    int broadcast = 0;
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    ret = wolfIP_forward_prepare(&s, TEST_PRIMARY_IF, 0x0A000002U, NULL, &broadcast);
    ck_assert_int_eq(ret, 0);
    ret = wolfIP_forward_prepare(&s, TEST_PRIMARY_IF, 0x0A000002U, mac, NULL);
    ck_assert_int_eq(ret, 0);
    ret = wolfIP_forward_prepare(&s, TEST_PRIMARY_IF, 0x0A000002U, NULL, NULL);
    ck_assert_int_eq(ret, 0);
}
END_TEST

START_TEST(test_forward_prepare_loopback_no_ll)
{
    struct wolfIP s;
    uint8_t mac[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    int broadcast = 1;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;

    ck_assert_int_eq(wolfIP_forward_prepare(&s, TEST_LOOPBACK_IF, 0x0A000002U, mac, &broadcast), 1);
    ck_assert_int_eq(broadcast, 0);
    ck_assert_mem_eq(mac, "\xaa\xbb\xcc\xdd\xee\xff", 6);
}
END_TEST

START_TEST(test_forward_packet_invalid_if)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;

    wolfIP_init(&s);
    mock_link_init(&s);
    last_frame_sent_size = 0;

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_TCP;

    wolfIP_forward_packet(&s, s.if_count + 1, ip, (uint32_t)sizeof(buf), NULL, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_select_nexthop_variants)
{
    struct ipconf conf;
    ip4 dest = 0x0A0000A1U;

    memset(&conf, 0, sizeof(conf));
    ck_assert_uint_eq(wolfIP_select_nexthop(NULL, dest), dest);
    ck_assert_uint_eq(wolfIP_select_nexthop(&conf, 0xFFFFFFFFU), 0xFFFFFFFFU);

    conf.ip = 0x0A000001U;
    conf.mask = 0xFFFFFF00U;
    conf.gw = 0x0A0000FEU;
    ck_assert_uint_eq(wolfIP_select_nexthop(&conf, 0x0A000099U), 0x0A000099U);
    ck_assert_uint_eq(wolfIP_select_nexthop(&conf, 0x0A010101U), conf.gw);

    conf.gw = IPADDR_ANY;
    ck_assert_uint_eq(wolfIP_select_nexthop(&conf, 0x0A010101U), 0x0A010101U);
}
END_TEST

START_TEST(test_route_for_ip_variants)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    s.ipconf[TEST_PRIMARY_IF].gw = 0x0A0000FEU;
    s.ipconf[TEST_SECOND_IF].gw = 0;

    ck_assert_uint_eq(wolfIP_route_for_ip(&s, IPADDR_ANY), TEST_PRIMARY_IF);
    ck_assert_uint_eq(wolfIP_route_for_ip(&s, 0xFFFFFFFFU), TEST_PRIMARY_IF);
    ck_assert_uint_eq(wolfIP_route_for_ip(&s, 0x0A000055U), TEST_PRIMARY_IF);
    ck_assert_uint_eq(wolfIP_route_for_ip(&s, 0xC0A80122U), TEST_SECOND_IF);
    ck_assert_uint_eq(wolfIP_route_for_ip(&s, 0x0B000001U), TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_route_for_ip_dest_matches_iface_ip)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);

    ck_assert_uint_eq(wolfIP_route_for_ip(&s, primary_ip), TEST_PRIMARY_IF);
    ck_assert_uint_eq(wolfIP_route_for_ip(&s, secondary_ip), TEST_SECOND_IF);
}
END_TEST

START_TEST(test_route_for_ip_gw_and_nonloop_fallback)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    s.ipconf[TEST_PRIMARY_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_PRIMARY_IF].gw = 0;
    s.ipconf[TEST_SECOND_IF].gw = 0xC0A801FEU;

    ck_assert_uint_eq(wolfIP_route_for_ip(&s, 0x0B000001U), TEST_SECOND_IF);

    s.ipconf[TEST_SECOND_IF].gw = IPADDR_ANY;
    ck_assert_uint_eq(wolfIP_route_for_ip(&s, 0x0B000001U), TEST_SECOND_IF);
}
END_TEST

START_TEST(test_route_for_ip_no_primary_index)
{
    struct wolfIP s;

    wolfIP_init(&s);
    s.if_count = 1;
    s.ipconf[0].ip = 0x0A000001U;
    s.ipconf[0].mask = 0xFFFFFF00U;

    ck_assert_uint_eq(wolfIP_route_for_ip(&s, 0x0A000055U), 0U);
}
END_TEST

START_TEST(test_route_for_ip_null_stack)
{
    ck_assert_uint_eq(wolfIP_route_for_ip(NULL, 0x0A000001U), 0U);
}
END_TEST

START_TEST(test_inline_ip_helpers)
{
    char buf[20];

    ck_assert_uint_eq(atou("1234"), 1234U);
    ck_assert_uint_eq(atou("12x"), 12U);
    ck_assert_uint_eq(atou(""), 0U);

    ck_assert_uint_eq(atoip4("10.0.1.2"), 0x0A000102U);
    ck_assert_uint_eq(atoip4("192.168"), 0xC0A80000U);

    iptoa(0x010C7B00U, buf);
    ck_assert_str_eq(buf, "1.12.123.0");
}
END_TEST

START_TEST(test_forward_interface_variants)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    unsigned int out_if;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    out_if = wolfIP_forward_interface(&s, TEST_PRIMARY_IF, 0xC0A80199U);
    ck_assert_uint_eq(out_if, TEST_SECOND_IF);

    out_if = wolfIP_forward_interface(&s, TEST_PRIMARY_IF, secondary_ip);
    ck_assert_int_eq((int)out_if, -1);

    s.if_count = 1;
    ck_assert_uint_eq(wolfIP_forward_interface(&s, TEST_PRIMARY_IF, 0x0A000099U), 1U);
}
END_TEST

START_TEST(test_forward_interface_skips_ipaddr_any)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    s.ipconf[TEST_SECOND_IF].ip = IPADDR_ANY;
    s.ipconf[TEST_SECOND_IF].mask = 0xFFFFFF00U;

    ck_assert_int_eq((int)wolfIP_forward_interface(&s, TEST_PRIMARY_IF, 0xC0A80199U), -1);
}
END_TEST

START_TEST(test_forward_interface_dest_is_local_ip)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    unsigned int out_if;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    out_if = wolfIP_forward_interface(&s, TEST_PRIMARY_IF, secondary_ip);
    ck_assert_int_eq((int)out_if, -1);
}
END_TEST

START_TEST(test_forward_interface_short_circuit_cases)
{
    struct wolfIP s;

    ck_assert_int_eq(wolfIP_forward_interface(NULL, 0, 0x0A000001U), 0);

    wolfIP_init(&s);
    s.if_count = 1;
    ck_assert_uint_eq(wolfIP_forward_interface(&s, 0, 0x0A000001U), 1U);
}
END_TEST

START_TEST(test_ip_recv_forward_ttl_exceeded)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    ip.eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.ver_ihl = 0x45;
    ip.ttl = 1;
    ip.proto = WI_IPPROTO_UDP;
    ip.len = ee16(IP_HEADER_LEN);
    ip.src = ee32(primary_ip);
    ip.dst = ee32(0xC0A80155U);

    ip_recv(&s, TEST_PRIMARY_IF, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_gt(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_ip_recv_forward_arp_queue_and_flush)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    struct arp_packet arp_reply;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip = 0xC0A80155U;
    uint8_t dest_mac[6] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15};

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    s.last_tick = 2000;
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    ip.eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.ver_ihl = 0x45;
    ip.ttl = 2;
    ip.proto = WI_IPPROTO_TCP;
    ip.len = ee16(IP_HEADER_LEN);
    ip.src = ee32(primary_ip);
    ip.dst = ee32(dest_ip);

    ip_recv(&s, TEST_PRIMARY_IF, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(s.arp_pending[0].dest, dest_ip);
    ck_assert_uint_eq(s.arp_pending[0].if_idx, TEST_SECOND_IF);
    ck_assert_uint_gt(s.arp_pending[0].len, 0);

    memset(&arp_reply, 0, sizeof(arp_reply));
    arp_reply.opcode = ee16(ARP_REPLY);
    arp_reply.sip = ee32(dest_ip);
    memcpy(arp_reply.sma, dest_mac, 6);
    arp_recv(&s, TEST_SECOND_IF, &arp_reply, sizeof(arp_reply));
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_flush_pending_ttl_expired)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    struct arp_packet arp_reply;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    ip4 dest_ip = 0xC0A80166U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    wolfIP_filter_set_callback(NULL, NULL);
    s.last_tick = 2000;
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    ip.ver_ihl = 0x45;
    ip.ttl = 1;
    ip.proto = WI_IPPROTO_TCP;
    ip.len = ee16(IP_HEADER_LEN);
    ip.src = ee32(primary_ip);
    ip.dst = ee32(dest_ip);

    arp_queue_packet(&s, TEST_SECOND_IF, dest_ip, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(s.arp_pending[0].dest, dest_ip);

    memset(&arp_reply, 0, sizeof(arp_reply));
    arp_reply.opcode = ee16(ARP_REPLY);
    arp_reply.sip = ee32(dest_ip);
    memcpy(arp_reply.sma, "\x01\x02\x03\x04\x05\x06", 6);
    arp_recv(&s, TEST_SECOND_IF, &arp_reply, sizeof(arp_reply));
    ck_assert_uint_eq(last_frame_sent_size, 0);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_queue_packet_invalid_args)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    s.arp_pending[0].dest = 0x0A000002U;
    arp_queue_packet(NULL, TEST_PRIMARY_IF, 0x0A000002U, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(s.arp_pending[0].dest, 0x0A000002U);

    arp_queue_packet(&s, TEST_PRIMARY_IF, 0x0A000003U, &ip, 0);
    ck_assert_uint_eq(s.arp_pending[0].dest, 0x0A000002U);
}
END_TEST

START_TEST(test_arp_queue_packet_reuses_existing_slot)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    const ip4 dest_ip = 0x0A0000A1U;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    s.arp_pending[0].dest = dest_ip;
    s.arp_pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp_pending[0].len = 4;

    arp_queue_packet(&s, TEST_PRIMARY_IF, dest_ip, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(s.arp_pending[0].dest, dest_ip);
    ck_assert_uint_eq(s.arp_pending[0].if_idx, TEST_PRIMARY_IF);
    ck_assert_uint_gt(s.arp_pending[0].len, 0U);
}
END_TEST

START_TEST(test_arp_queue_packet_same_dest_different_if)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    const ip4 dest_ip = 0x0A0000A1U;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    s.arp_pending[0].dest = dest_ip;
    s.arp_pending[0].if_idx = TEST_SECOND_IF;

    arp_queue_packet(&s, TEST_PRIMARY_IF, dest_ip, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(s.arp_pending[1].dest, dest_ip);
    ck_assert_uint_eq(s.arp_pending[1].if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_arp_queue_packet_uses_empty_slot)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    const ip4 dest_ip = 0x0A0000A2U;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    s.arp_pending[0].dest = 0x0A0000B1U;
    s.arp_pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp_pending[1].dest = IPADDR_ANY;

    arp_queue_packet(&s, TEST_PRIMARY_IF, dest_ip, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(s.arp_pending[1].dest, dest_ip);
}
END_TEST

START_TEST(test_arp_queue_packet_truncates_len)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    uint32_t len = LINK_MTU + 16;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    arp_queue_packet(&s, TEST_PRIMARY_IF, 0x0A0000A3U, &ip, len);
    ck_assert_uint_eq(s.arp_pending[0].len, LINK_MTU);
}
END_TEST

START_TEST(test_arp_queue_packet_slot_fallback_zero)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++) {
        s.arp_pending[i].dest = (ip4)(0x0A000100U + (uint32_t)i);
        s.arp_pending[i].if_idx = TEST_PRIMARY_IF;
        s.arp_pending[i].len = 1;
    }

    arp_queue_packet(&s, TEST_PRIMARY_IF, 0x0A0000C1U, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(s.arp_pending[0].dest, 0x0A0000C1U);
}
END_TEST

START_TEST(test_arp_flush_pending_no_neighbor)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    s.arp_pending[0].dest = 0x0A0000A1U;
    s.arp_pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp_pending[0].len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN);
    memcpy(s.arp_pending[0].frame, &ip, sizeof(ip));

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp_pending[0].dest, 0x0A0000A1U);
}
END_TEST

START_TEST(test_arp_flush_pending_len_zero_clears)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    s.arp_pending[0].dest = 0x0A0000A1U;
    s.arp_pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp_pending[0].len = 0;

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_flush_pending_null_stack)
{
    arp_flush_pending(NULL, TEST_PRIMARY_IF, 0x0A0000A1U);
}
END_TEST

START_TEST(test_arp_flush_pending_skips_non_matching)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    s.arp_pending[0].dest = 0x0A0000A2U;
    s.arp_pending[0].if_idx = TEST_SECOND_IF;
    s.arp_pending[0].len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN);
    memcpy(s.arp_pending[0].frame, &ip, sizeof(ip));

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp_pending[0].dest, 0x0A0000A2U);
}
END_TEST

START_TEST(test_arp_flush_pending_same_dest_if_idx_mismatch)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));
    ip.ttl = 64;

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    s.arp_pending[0].dest = 0x0A0000A1U;
    s.arp_pending[0].if_idx = TEST_SECOND_IF;
    s.arp_pending[0].len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN);
    memcpy(s.arp_pending[0].frame, &ip, sizeof(ip));

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp_pending[0].dest, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp_pending[0].if_idx, TEST_SECOND_IF);
    ck_assert_uint_eq(s.arp_pending[0].len, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
}
END_TEST

START_TEST(test_arp_flush_pending_truncates_len)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));
    ip.ttl = 64;

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    s.arp_pending[0].dest = 0x0A0000A1U;
    s.arp_pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp_pending[0].len = LINK_MTU + 8;
    memcpy(s.arp_pending[0].frame, &ip, sizeof(ip));

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_flush_pending_processes_matching_entry)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));
    ip.ttl = 64;

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    s.arp_pending[0].dest = 0x0A0000A1U;
    s.arp_pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp_pending[0].len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN);
    memcpy(s.arp_pending[0].frame, &ip, sizeof(ip));
    last_frame_sent_size = 0;

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_flush_pending_match_condition_false)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));
    ip.ttl = 64;

    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++) {
        s.arp_pending[i].dest = IPADDR_ANY;
        s.arp_pending[i].if_idx = 0;
        s.arp_pending[i].len = 0;
    }

    s.arp.neighbors[0].ip = 0x0A0000A2U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    s.arp_pending[0].dest = 0x0A0000A2U;
    s.arp_pending[0].if_idx = TEST_PRIMARY_IF;
    s.arp_pending[0].len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN);
    memcpy(s.arp_pending[0].frame, &ip, sizeof(ip));

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000A2U);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_queue_and_flush_matching_entry)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(&ip, 0, sizeof(ip));
    ip.ttl = 64;

    arp_queue_packet(&s, TEST_PRIMARY_IF, 0x0A0000B1U, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));

    s.arp.neighbors[0].ip = 0x0A0000B1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    arp_flush_pending(&s, TEST_PRIMARY_IF, 0x0A0000B1U);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_flush_pending_loopback_match)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);

    s.arp.neighbors[0].ip = 0x7F000001U;
    s.arp.neighbors[0].if_idx = TEST_LOOPBACK_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    s.arp_pending[0].dest = 0x7F000001U;
    s.arp_pending[0].if_idx = TEST_LOOPBACK_IF;
    s.arp_pending[0].len = 0;

    arp_flush_pending(&s, TEST_LOOPBACK_IF, 0x7F000001U);
    ck_assert_uint_eq(s.arp_pending[0].dest, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_store_neighbor_updates_existing)
{
    struct wolfIP s;
    uint8_t old_mac[6] = {0, 1, 2, 3, 4, 5};
    uint8_t new_mac[6] = {6, 7, 8, 9, 10, 11};

    wolfIP_init(&s);
    mock_link_init(&s);

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, old_mac, 6);

    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A0000A1U, new_mac);
    ck_assert_mem_eq(s.arp.neighbors[0].mac, new_mac, 6);
}
END_TEST

START_TEST(test_arp_store_neighbor_empty_slot)
{
    struct wolfIP s;
    uint8_t mac[6] = {1, 2, 3, 4, 5, 6};

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(s.arp.neighbors, 0, sizeof(s.arp.neighbors));

    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A0000A1U, mac);
    ck_assert_uint_eq(s.arp.neighbors[0].ip, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp.neighbors[0].if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_arp_store_neighbor_same_ip_diff_if)
{
    struct wolfIP s;
    uint8_t mac0[6] = {1, 2, 3, 4, 5, 6};
    uint8_t mac1[6] = {6, 7, 8, 9, 10, 11};

    wolfIP_init(&s);
    mock_link_init(&s);
    memset(s.arp.neighbors, 0, sizeof(s.arp.neighbors));

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_SECOND_IF;
    memcpy(s.arp.neighbors[0].mac, mac0, 6);

    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A0000A1U, mac1);
    ck_assert_mem_eq(s.arp.neighbors[0].mac, mac0, 6);
    ck_assert_uint_eq(s.arp.neighbors[1].ip, 0x0A0000A1U);
    ck_assert_uint_eq(s.arp.neighbors[1].if_idx, TEST_PRIMARY_IF);
}
END_TEST

START_TEST(test_arp_store_neighbor_no_space)
{
    struct wolfIP s;
    uint8_t mac[6] = {1, 2, 3, 4, 5, 6};
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);

    for (i = 0; i < MAX_NEIGHBORS; i++) {
        s.arp.neighbors[i].ip = (ip4)(0x0A000100U + (uint32_t)i);
        s.arp.neighbors[i].if_idx = TEST_PRIMARY_IF;
        memcpy(s.arp.neighbors[i].mac, "\x00\x00\x00\x00\x00\x00", 6);
    }

    arp_store_neighbor(&s, TEST_PRIMARY_IF, 0x0A0000A1U, mac);
    ck_assert_uint_ne(s.arp.neighbors[0].ip, IPADDR_ANY);
}
END_TEST

START_TEST(test_arp_store_neighbor_null_stack)
{
    uint8_t mac[6] = {1, 2, 3, 4, 5, 6};
    arp_store_neighbor(NULL, TEST_PRIMARY_IF, 0x0A0000A1U, mac);
}
END_TEST

START_TEST(test_arp_lookup_if_idx_mismatch)
{
    struct wolfIP s;
    uint8_t mac[6] = {0};
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);

    s.arp.neighbors[0].ip = 0x0A0000A1U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, "\x01\x02\x03\x04\x05\x06", 6);

    ret = arp_lookup(&s, TEST_SECOND_IF, 0x0A0000A1U, mac);
    ck_assert_int_eq(ret, -1);
}
END_TEST

START_TEST(test_arp_request_missing_conf)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;
    last_frame_sent_size = 0;

    arp_request(&s, TEST_PRIMARY_IF, 0x0A000002U);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_request_null_stack)
{
    arp_request(NULL, TEST_PRIMARY_IF, 0x0A000002U);
}
END_TEST

START_TEST(test_arp_recv_request_other_ip_no_reply)
{
    struct wolfIP s;
    struct arp_packet arp_req;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    last_frame_sent_size = 0;

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(0x0A000002U);
    memcpy(arp_req.sma, "\x01\x02\x03\x04\x05\x06", 6);
    arp_req.tip = ee32(0x0A000099U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_recv_null_stack)
{
    struct arp_packet arp_req;

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.tip = ee32(0x0A000001U);

    arp_recv(NULL, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
}
END_TEST

START_TEST(test_arp_recv_request_no_send_fn)
{
    struct wolfIP s;
    struct arp_packet arp_req;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    s.ll_dev[TEST_PRIMARY_IF].send = NULL;
    last_frame_sent_size = 0;

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(0x0A000002U);
    memcpy(arp_req.sma, "\x01\x02\x03\x04\x05\x06", 6);
    arp_req.tip = ee32(0x0A000001U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_recv_request_sends_reply)
{
    struct wolfIP s;
    struct arp_packet arp_req;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
    last_frame_sent_size = 0;

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(0x0A000002U);
    memcpy(arp_req.sma, "\x01\x02\x03\x04\x05\x06", 6);
    arp_req.tip = ee32(0x0A000001U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
    ck_assert_uint_eq(last_frame_sent_size, sizeof(struct arp_packet));
}
END_TEST

START_TEST(test_send_ttl_exceeded_filter_drop)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_icmp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.src = ee32(0x0A000002U);
    ip.dst = ee32(0x0A000001U);

    wolfIP_send_ttl_exceeded(&s, TEST_PRIMARY_IF, &ip);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_icmp_mask(0);
}
END_TEST

START_TEST(test_send_ttl_exceeded_ip_filter_drop)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_ip_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    wolfIP_filter_set_icmp_mask(0);
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.src = ee32(0x0A000002U);
    ip.dst = ee32(0x0A000001U);

    wolfIP_send_ttl_exceeded(&s, TEST_PRIMARY_IF, &ip);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_ip_mask(0);
}
END_TEST

START_TEST(test_send_ttl_exceeded_eth_filter_drop)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    wolfIP_filter_set_icmp_mask(0);
    wolfIP_filter_set_ip_mask(0);
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.src = ee32(0x0A000002U);
    ip.dst = ee32(0x0A000001U);

    wolfIP_send_ttl_exceeded(&s, TEST_PRIMARY_IF, &ip);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

START_TEST(test_send_ttl_exceeded_no_send)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    s.ll_dev[TEST_PRIMARY_IF].send = NULL;
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.src = ee32(0x0A000002U);
    ip.dst = ee32(0x0A000001U);

    wolfIP_send_ttl_exceeded(&s, TEST_PRIMARY_IF, &ip);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_request_filter_drop)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    s.last_tick = 2000;
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;

    arp_request(&s, TEST_PRIMARY_IF, 0x0A000002U);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

START_TEST(test_arp_request_invalid_interface)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    last_frame_sent_size = 0;

    arp_request(&s, WOLFIP_MAX_INTERFACES, 0x0A000002U);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_reply_filter_drop)
{
    struct wolfIP s;
    struct arp_packet arp_req;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(0x0A000002U);
    memcpy(arp_req.sma, "\x01\x02\x03\x04\x05\x06", 6);
    arp_req.tip = ee32(0x0A000001U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

START_TEST(test_arp_request_no_send_fn)
{
    struct wolfIP s;
    ip4 target_ip = 0x0A000002U;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.last_tick = 2000;
    s.ll_dev[TEST_PRIMARY_IF].send = NULL;
    last_frame_sent_size = 0;

    arp_request(&s, TEST_PRIMARY_IF, target_ip);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_recv_invalid_iface)
{
    struct wolfIP s;
    struct arp_packet arp_req;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.if_count = 0;
    last_frame_sent_size = 0;

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.tip = ee32(0x0A000001U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_recv_filter_drop)
{
    struct wolfIP s;
    struct arp_packet arp_req;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    last_frame_sent_size = 0;

    memset(&arp_req, 0, sizeof(arp_req));
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(0x0A000002U);
    memcpy(arp_req.sma, "\x01\x02\x03\x04\x05\x06", 6);
    arp_req.tip = ee32(0x0A000001U);

    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
    ck_assert_uint_eq(last_frame_sent_size, 0);
    ck_assert_int_ne(s.arp.neighbors[0].ip, IPADDR_ANY);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

START_TEST(test_wolfip_if_for_local_ip_paths)
{
    struct wolfIP s;
    int found = 1;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    ck_assert_uint_eq(wolfIP_if_for_local_ip(NULL, primary_ip, &found), 0U);
    ck_assert_int_eq(found, 0);

    wolfIP_init(&s);
    s.if_count = 0;
    found = 1;
    ck_assert_uint_eq(wolfIP_if_for_local_ip(&s, primary_ip, &found), 0U);
    ck_assert_int_eq(found, 0);

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    found = 0;
    ck_assert_uint_eq(wolfIP_if_for_local_ip(&s, IPADDR_ANY, &found), TEST_PRIMARY_IF);

    found = 0;
    ck_assert_uint_eq(wolfIP_if_for_local_ip(&s, secondary_ip, &found), TEST_SECOND_IF);
    ck_assert_int_eq(found, 1);

    found = 1;
    ck_assert_uint_eq(wolfIP_if_for_local_ip(&s, 0x0B000001U, &found), TEST_PRIMARY_IF);
    ck_assert_int_eq(found, 0);
}
END_TEST

START_TEST(test_wolfip_if_for_local_ip_null_found)
{
    struct wolfIP s;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    ck_assert_uint_eq(wolfIP_if_for_local_ip(&s, secondary_ip, NULL), TEST_SECOND_IF);
}
END_TEST

START_TEST(test_wolfip_socket_if_idx_invalid)
{
    struct tsocket t;
    struct wolfIP s;

    ck_assert_uint_eq(wolfIP_socket_if_idx(NULL), 0U);

    memset(&t, 0, sizeof(t));
    ck_assert_uint_eq(wolfIP_socket_if_idx(&t), 0U);

    wolfIP_init(&s);
    memset(&t, 0, sizeof(t));
    t.S = &s;
    t.if_idx = (uint8_t)(s.if_count + 1);
    ck_assert_uint_eq(wolfIP_socket_if_idx(&t), 0U);
}
END_TEST

START_TEST(test_icmp_try_recv_mismatch_paths)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->src_port = ee16(0x1234);

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.ip.src = ee32(ts->remote_ip);
    icmp.ip.dst = ee32(0x0A000003U);
    icmp_set_echo_id(&icmp, ts->src_port);
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);

    icmp.ip.dst = ee32(ts->local_ip);
    icmp_set_echo_id(&icmp, ee16(0x9999));
    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);

    icmp_set_echo_id(&icmp, ts->src_port);
    icmp.ip.src = ee32(0x0A000099U);
    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);

    icmp.ip.src = ee32(ts->remote_ip);
    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len - 1);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_icmp_try_recv_mismatch_local_ip)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = icmp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->local_ip = 0x0A000001U;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000099U);
    icmp_set_echo_id(&icmp, 0);
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_icmp_try_recv_mismatch_src_port)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = icmp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->local_ip = 0;
    ts->src_port = ee16(1234);

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.ip.src = ee32(0x0A000002U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp_set_echo_id(&icmp, ee16(4321));
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_icmp_try_recv_mismatch_remote_ip)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_icmp_packet icmp;
    uint32_t frame_len;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = icmp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->remote_ip = 0x0A000002U;

    memset(&icmp, 0, sizeof(icmp));
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.ip.src = ee32(0x0A000099U);
    icmp.ip.dst = ee32(0x0A000001U);
    icmp_set_echo_id(&icmp, 0);
    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);

    icmp_try_recv(&s, TEST_PRIMARY_IF, &icmp, frame_len);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.udp.rxbuf), NULL);
}
END_TEST

START_TEST(test_wolfip_recv_on_not_for_us)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    uint8_t other_mac[6] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15};

    wolfIP_init(&s);
    mock_link_init(&s);
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    ip.eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip.eth.dst, other_mac, 6);
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.ver_ihl = 0x45;

    wolfIP_recv_on(&s, TEST_PRIMARY_IF, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_wolfip_recv_on_filter_drop_eth)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;

    wolfIP_init(&s);
    mock_link_init(&s);
    filter_block_reason = WOLFIP_FILT_RECEIVING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    ip.eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.ver_ihl = 0x45;

    wolfIP_recv_on(&s, TEST_PRIMARY_IF, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST

#if WOLFIP_ENABLE_FORWARDING
START_TEST(test_wolfip_recv_on_forward_ttl_exceeded)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    mock_link_init(&s);
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    ip.eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.ver_ihl = 0x45;
    ip.ttl = 1;
    ip.src = ee32(0x0A000099U);
    ip.dst = ee32(0xC0A80199U);

    wolfIP_recv_on(&s, TEST_PRIMARY_IF, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(((struct wolfIP_icmp_ttl_exceeded_packet *)last_frame_sent)->type, ICMP_TTL_EXCEEDED);
}
END_TEST

START_TEST(test_wolfip_recv_on_forward_arp_queue)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    int found = 0;
    int i;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    mock_link_init(&s);
    s.last_tick = 2000;
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    ip.eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.ver_ihl = 0x45;
    ip.ttl = 4;
    ip.src = ee32(0x0A000099U);
    ip.dst = ee32(0xC0A80199U);

    wolfIP_recv_on(&s, TEST_PRIMARY_IF, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_gt(last_frame_sent_size, 0);
    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++) {
        if (s.arp_pending[i].dest == ee32(ip.dst)) {
            found = 1;
            ck_assert_uint_eq(s.arp_pending[i].if_idx, TEST_SECOND_IF);
            break;
        }
    }
    ck_assert_int_eq(found, 1);
}
END_TEST

START_TEST(test_wolfip_recv_on_forward_arp_hit_sends)
{
    struct wolfIP s;
    struct wolfIP_ip_packet ip;
    ip4 primary_ip = 0x0A000001U;
    ip4 secondary_ip = 0xC0A80101U;
    uint8_t mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);
    mock_link_init(&s);
    arp_store_neighbor(&s, TEST_SECOND_IF, 0xC0A80199U, mac);
    last_frame_sent_size = 0;

    memset(&ip, 0, sizeof(ip));
    ip.eth.type = ee16(ETH_TYPE_IP);
    memcpy(ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(ip.eth.src, "\x01\x02\x03\x04\x05\x06", 6);
    ip.ver_ihl = 0x45;
    ip.ttl = 4;
    ip.src = ee32(0x0A000099U);
    ip.dst = ee32(0xC0A80199U);

    wolfIP_recv_on(&s, TEST_PRIMARY_IF, &ip, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN));
    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_uint_eq(((struct wolfIP_ip_packet *)last_frame_sent)->ttl, 3);
}
END_TEST
#endif

START_TEST(test_forward_packet_no_send)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.ll_dev[TEST_PRIMARY_IF].send = NULL;

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_TCP;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), NULL, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_forward_packet_filter_drop)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    filter_block_reason = WOLFIP_FILT_SENDING;

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_TCP;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), NULL, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_forward_packet_send_paths)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    uint8_t mac[6] = {0x01,0x02,0x03,0x04,0x05,0x06};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_filter_set_callback(NULL, NULL);

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_TCP;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), mac, 0);
    ck_assert_uint_gt(last_frame_sent_size, 0);

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_UDP;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), mac, 1);
    ck_assert_uint_gt(last_frame_sent_size, 0);

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_ICMP;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), mac, 0);
    ck_assert_uint_gt(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_forward_packet_filter_drop_udp_icmp)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));
    filter_block_reason = WOLFIP_FILT_SENDING;

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_UDP;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), NULL, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    memset(ip, 0, sizeof(buf));
    ip->proto = WI_IPPROTO_ICMP;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), NULL, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST
#endif

START_TEST(test_forward_packet_ip_filter_drop)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    uint8_t mac[6] = {0x01,0x02,0x03,0x04,0x05,0x06};

    wolfIP_init(&s);
    mock_link_init(&s);
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_ip_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));

    memset(ip, 0, sizeof(buf));
    ip->proto = 0x00;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), mac, 0);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_ip_mask(0);
}
END_TEST

START_TEST(test_forward_packet_eth_filter_drop)
{
    struct wolfIP s;
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN];
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    uint8_t mac[6] = {0x01,0x02,0x03,0x04,0x05,0x06};

    wolfIP_init(&s);
    mock_link_init(&s);
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_eth_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));

    memset(ip, 0, sizeof(buf));
    ip->proto = 0x00;
    last_frame_sent_size = 0;
    wolfIP_forward_packet(&s, TEST_PRIMARY_IF, ip, (uint32_t)sizeof(buf), mac, 0);
    ck_assert_uint_eq(last_frame_sent_size, 0);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_eth_mask(0);
}
END_TEST
START_TEST(test_tcp_last_ack_closes_socket)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000E1U;
    uint16_t local_port = 6666;
    uint16_t remote_port = 7777;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LAST_ACK;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port = local_port;
    ts->dst_port = remote_port;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, remote_ip, local_ip, remote_port, local_port,
            10, 0, 0x10);
    ck_assert_int_eq(ts->proto, 0);
}
END_TEST
START_TEST(test_fifo_pop_success) {
    struct fifo f;
    uint8_t data[] = {1, 2, 3, 4};
    struct pkt_desc *desc;
    fifo_init(&f, mem, memsz);
    fifo_push(&f, data, sizeof(data)); // Add data to FIFO

    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc); // Ensure we got a valid descriptor
    ck_assert_int_eq(desc->len, sizeof(data)); // Check length
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data)); // Check data
}

START_TEST(test_fifo_pop_empty) {
    struct fifo f;
    struct pkt_desc *desc;
    fifo_init(&f, mem, memsz);

    desc = fifo_pop(&f);
    ck_assert_ptr_eq(desc, NULL); // Ensure pop returns NULL on empty FIFO
}

START_TEST(test_fifo_push_full) {
    struct fifo f;
    uint8_t data[8 * 1024] = {1, 2, 3, 4};
    int ret;
    fifo_init(&f, mem, memsz);
    fifo_push(&f, data, sizeof(data)); // Add data to FIFO

    ret = fifo_push(&f, data, sizeof(data));
    ck_assert_int_eq(ret, -1); // Ensure push returns -1 when FIFO is full
}
END_TEST

START_TEST(test_tcp_process_ts_uses_ecr)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN];
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *opt = (struct tcp_opt_ts *)tcp->data;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;

    memset(tcp, 0, sizeof(buf));
    tcp->hlen = (TCP_HEADER_LEN + TCP_OPTIONS_LEN) << 2;
    opt->opt = TCP_OPTION_TS;
    opt->len = TCP_OPTION_TS_LEN;
    opt->val = ee32(1000);
    opt->ecr = ee32(900);
    opt->pad = TCP_OPTION_NOP;
    opt->eoo = TCP_OPTION_EOO;

    s.last_tick = 1000;
    ck_assert_int_eq(tcp_process_ts(ts, tcp, sizeof(buf)), 0);
    ck_assert_uint_eq(ts->sock.tcp.rtt, 100);
}
END_TEST

START_TEST(test_tcp_process_ts_nop_then_ts)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN + 1];
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *opt;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;

    memset(tcp, 0, sizeof(buf));
    tcp->hlen = (TCP_HEADER_LEN + TCP_OPTIONS_LEN + 1) << 2;
    tcp->data[0] = TCP_OPTION_NOP;
    opt = (struct tcp_opt_ts *)&tcp->data[1];
    opt->opt = TCP_OPTION_TS;
    opt->len = TCP_OPTION_TS_LEN;
    opt->val = ee32(100);
    opt->ecr = ee32(50);
    opt->pad = TCP_OPTION_NOP;
    opt->eoo = TCP_OPTION_EOO;

    s.last_tick = 120;
    ck_assert_int_eq(tcp_process_ts(ts, tcp, sizeof(buf)), 0);
}
END_TEST

START_TEST(test_tcp_process_ts_skips_unknown_option)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN + 4];
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *opt;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;

    memset(tcp, 0, sizeof(buf));
    tcp->hlen = (TCP_HEADER_LEN + TCP_OPTIONS_LEN + 4) << 2;
    tcp->data[0] = 0x22;
    tcp->data[1] = 4;
    tcp->data[2] = 0;
    tcp->data[3] = 0;
    opt = (struct tcp_opt_ts *)&tcp->data[4];
    opt->opt = TCP_OPTION_TS;
    opt->len = TCP_OPTION_TS_LEN;
    opt->val = ee32(200);
    opt->ecr = ee32(100);
    opt->pad = TCP_OPTION_NOP;
    opt->eoo = TCP_OPTION_EOO;

    s.last_tick = 250;
    ck_assert_int_eq(tcp_process_ts(ts, tcp, sizeof(buf)), 0);
}
END_TEST

START_TEST(test_tcp_process_ts_no_ecr)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN];
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *opt = (struct tcp_opt_ts *)tcp->data;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;

    memset(tcp, 0, sizeof(buf));
    tcp->hlen = (TCP_HEADER_LEN + TCP_OPTIONS_LEN) << 2;
    opt->opt = TCP_OPTION_TS;
    opt->len = TCP_OPTION_TS_LEN;
    opt->val = ee32(100);
    opt->ecr = 0;
    opt->pad = TCP_OPTION_NOP;
    opt->eoo = TCP_OPTION_EOO;

    ck_assert_int_eq(tcp_process_ts(ts, tcp, sizeof(buf)), -1);
}
END_TEST

START_TEST(test_tcp_process_ts_updates_rtt_when_set)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN];
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *opt = (struct tcp_opt_ts *)tcp->data;
    uint32_t old_rtt;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.rtt = 10;
    old_rtt = ts->sock.tcp.rtt;

    memset(tcp, 0, sizeof(buf));
    tcp->hlen = (TCP_HEADER_LEN + TCP_OPTIONS_LEN) << 2;
    opt->opt = TCP_OPTION_TS;
    opt->len = TCP_OPTION_TS_LEN;
    opt->val = ee32(100);
    opt->ecr = ee32(90);
    opt->pad = TCP_OPTION_NOP;
    opt->eoo = TCP_OPTION_EOO;

    s.last_tick = 120;
    ck_assert_int_eq(tcp_process_ts(ts, tcp, sizeof(buf)), 0);
    ck_assert_uint_ne(ts->sock.tcp.rtt, old_rtt);
}
END_TEST

START_TEST(test_tcp_send_syn_advertises_sack_permitted)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg *syn;
    int off;

    wolfIP_init(&s);
    ts = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->src_port = 1234;
    ts->dst_port = 4321;

    tcp_send_syn(ts, 0x02);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    syn = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
    off = tcp_option_find(syn, TCP_OPTION_SACK_PERMITTED);
    ck_assert_int_ge(off, 0);
    ck_assert_uint_eq(syn->data[off + 1], TCP_OPTION_SACK_PERMITTED_LEN);
}
END_TEST

START_TEST(test_tcp_build_ack_options_does_not_write_past_returned_len)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t opts[TCP_MAX_OPTIONS_LEN];
    uint8_t len;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.sack_permitted = 0;
    ts->sock.tcp.rx_sack_count = 0;

    memset(opts, 0xCC, sizeof(opts));
    len = tcp_build_ack_options(ts, opts, sizeof(opts));
    ck_assert_uint_eq(len, TCP_OPTION_TS_LEN + 2); /* TS + 2-byte NOP pad */
    ck_assert_uint_eq((uint8_t)(len % 4), 0);
    ck_assert_uint_eq(opts[len], 0xCC);
}
END_TEST

START_TEST(test_tcp_sort_sack_blocks_swaps_out_of_order)
{
    struct tcp_sack_block blocks[3];

    blocks[0].left = 30; blocks[0].right = 40;
    blocks[1].left = 10; blocks[1].right = 20;
    blocks[2].left = 25; blocks[2].right = 26;

    tcp_sort_sack_blocks(blocks, 3);
    ck_assert_uint_eq(blocks[0].left, 10);
    ck_assert_uint_eq(blocks[1].left, 25);
    ck_assert_uint_eq(blocks[2].left, 30);
}
END_TEST

START_TEST(test_tcp_merge_sack_blocks_adjacent_and_disjoint)
{
    struct tcp_sack_block blocks[3];
    uint8_t merged;

    blocks[0].left = 30; blocks[0].right = 35;
    blocks[1].left = 20; blocks[1].right = 30;
    blocks[2].left = 40; blocks[2].right = 45;

    merged = tcp_merge_sack_blocks(blocks, 3);
    ck_assert_uint_eq(merged, 2);
    ck_assert_uint_eq(blocks[0].left, 20);
    ck_assert_uint_eq(blocks[0].right, 35);
    ck_assert_uint_eq(blocks[1].left, 40);
    ck_assert_uint_eq(blocks[1].right, 45);
}
END_TEST

START_TEST(test_tcp_recv_tracks_holes_and_sack_blocks)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg_buf_ooo[sizeof(struct wolfIP_tcp_seg) + 1];
    uint8_t seg_buf_in[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg_ooo = (struct wolfIP_tcp_seg *)seg_buf_ooo;
    struct wolfIP_tcp_seg *seg_in = (struct wolfIP_tcp_seg *)seg_buf_in;
    struct pkt_desc *desc;
    struct wolfIP_tcp_seg *ackseg;
    uint8_t out[2];

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 1;
    ts->sock.tcp.ack = 100;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 100);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(seg_ooo, 0, sizeof(seg_buf_ooo));
    seg_ooo->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg_ooo->hlen = TCP_HEADER_LEN << 2;
    seg_ooo->seq = ee32(101);
    seg_ooo->data[0] = 'b';
    tcp_recv(ts, seg_ooo);
    ck_assert_uint_eq(ts->sock.tcp.ack, 100);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 1);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].left, 101);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].right, 102);

    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ackseg = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
    ck_assert_int_ge(tcp_option_find(ackseg, TCP_OPTION_SACK), 0);

    (void)fifo_pop(&ts->sock.tcp.txbuf);

    memset(seg_in, 0, sizeof(seg_buf_in));
    seg_in->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg_in->hlen = TCP_HEADER_LEN << 2;
    seg_in->seq = ee32(100);
    seg_in->data[0] = 'a';
    tcp_recv(ts, seg_in);
    ck_assert_uint_eq(ts->sock.tcp.ack, 102);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 0);

    ck_assert_int_eq(queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out)), 2);
    ck_assert_mem_eq(out, "ab", 2);
}
END_TEST

START_TEST(test_tcp_rebuild_rx_sack_right_edge_wraps)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t payload[8] = {0};

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;

    ck_assert_int_eq(tcp_store_ooo_segment(ts, payload, 0xFFFFFFFCU, 8), 0);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 1);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].left, 0xFFFFFFFCU);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].right, 4U);
}
END_TEST

START_TEST(test_tcp_consume_ooo_wrap_trim_and_promote)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t out[8];
    uint8_t payload[8] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' };

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 2;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 2);

    ts->sock.tcp.ooo[0].used = 1;
    ts->sock.tcp.ooo[0].seq = 0xFFFFFFFCU;
    ts->sock.tcp.ooo[0].len = 8;
    memcpy(ts->sock.tcp.ooo[0].data, payload, sizeof(payload));

    tcp_consume_ooo(ts);
    ck_assert_uint_eq(ts->sock.tcp.ack, 4U);
    ck_assert_int_eq(ts->sock.tcp.ooo[0].used, 0);
    ck_assert_int_eq(queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out)), 2);
    ck_assert_mem_eq(out, payload + 6, 2);
}
END_TEST

START_TEST(test_tcp_consume_ooo_wrap_drop_fully_acked)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t payload[8] = {0};

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 4;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 4);

    ts->sock.tcp.ooo[0].used = 1;
    ts->sock.tcp.ooo[0].seq = 0xFFFFFFFCU;
    ts->sock.tcp.ooo[0].len = 8;
    memcpy(ts->sock.tcp.ooo[0].data, payload, sizeof(payload));

    tcp_consume_ooo(ts);
    ck_assert_uint_eq(ts->sock.tcp.ack, 4U);
    ck_assert_int_eq(ts->sock.tcp.ooo[0].used, 0);
    ck_assert_int_eq(ts->sock.tcp.ooo[0].len, 0);
}
END_TEST

START_TEST(test_tcp_ack_sack_early_retransmit_before_three_dupack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf1;
    struct tcp_seg_buf segbuf2;
    struct wolfIP_tcp_seg *seg1;
    struct wolfIP_tcp_seg *seg2;
    uint8_t ackbuf[sizeof(struct wolfIP_tcp_seg) + 12];
    struct wolfIP_tcp_seg *ackseg = (struct wolfIP_tcp_seg *)ackbuf;
    struct pkt_desc *desc;
    uint32_t left, right;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 1;
    ts->sock.tcp.seq = 102;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.bytes_in_flight = 2;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf1, 0, sizeof(segbuf1));
    seg1 = &segbuf1.seg;
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg1->hlen = TCP_HEADER_LEN << 2;
    seg1->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf1, sizeof(segbuf1)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&segbuf2, 0, sizeof(segbuf2));
    seg2 = &segbuf2.seg;
    seg2->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg2->hlen = TCP_HEADER_LEN << 2;
    seg2->seq = ee32(101);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf2, sizeof(segbuf2)), 0);
    desc = fifo_next(&ts->sock.tcp.txbuf, desc);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(ackbuf, 0, sizeof(ackbuf));
    ackseg->ack = ee32(100);
    ackseg->hlen = (TCP_HEADER_LEN + 12) << 2;
    ackseg->flags = 0x10;
    ackseg->data[0] = TCP_OPTION_NOP;
    ackseg->data[1] = TCP_OPTION_NOP;
    ackseg->data[2] = TCP_OPTION_SACK;
    ackseg->data[3] = 10;
    left = ee32(101);
    right = ee32(102);
    memcpy(&ackseg->data[4], &left, sizeof(left));
    memcpy(&ackseg->data[8], &right, sizeof(right));

    tcp_ack(ts, ackseg);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_uint_eq(ts->sock.tcp.dup_acks, 1);

    tcp_ack(ts, ackseg);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_uint_eq(ts->sock.tcp.dup_acks, 2);
}
END_TEST

START_TEST(test_tcp_input_listen_syn_without_sack_disables_sack)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ts->sock.tcp.sack_permitted = 1;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A0000A1U, 0x0A000001U, 40000, 1234, 1, 0, 0x02);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(ts->sock.tcp.sack_permitted, 0);
}
END_TEST

START_TEST(test_tcp_input_syn_sent_synack_without_sack_disables_sack)
{
    struct wolfIP s;
    struct tsocket *ts;
    int tcp_sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
    wolfIP_filter_set_tcp_mask(0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->sock.tcp.seq = 100;
    ts->sock.tcp.sack_offer = 1;
    ts->sock.tcp.sack_permitted = 1;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U, 4321, 1234, 10, 101, 0x12);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.sack_permitted, 0);
}
END_TEST

START_TEST(test_tcp_recv_partial_hole_fill_consumes_stored_ooo)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg_ooo_buf[sizeof(struct wolfIP_tcp_seg) + 10];
    uint8_t seg_in_buf[sizeof(struct wolfIP_tcp_seg) + 5];
    struct wolfIP_tcp_seg *seg_ooo = (struct wolfIP_tcp_seg *)seg_ooo_buf;
    struct wolfIP_tcp_seg *seg_in = (struct wolfIP_tcp_seg *)seg_in_buf;
    uint8_t out[16];

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 1;
    ts->sock.tcp.ack = 100;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 100);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(seg_ooo, 0, sizeof(seg_ooo_buf));
    seg_ooo->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    seg_ooo->hlen = TCP_HEADER_LEN << 2;
    seg_ooo->seq = ee32(105);
    memcpy(seg_ooo->data, "FGHIJKLMNO", 10);
    tcp_recv(ts, seg_ooo);
    ck_assert_uint_eq(ts->sock.tcp.ack, 100);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 1);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].left, 105);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].right, 115);

    memset(seg_in, 0, sizeof(seg_in_buf));
    seg_in->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 5);
    seg_in->hlen = TCP_HEADER_LEN << 2;
    seg_in->seq = ee32(100);
    memcpy(seg_in->data, "ABCDE", 5);
    tcp_recv(ts, seg_in);
    ck_assert_uint_eq(ts->sock.tcp.ack, 115);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 0);

    ck_assert_int_eq(queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out)), 15);
    ck_assert_mem_eq(out, "ABCDEFGHIJKLMNO", 15);
}
END_TEST

START_TEST(test_tcp_ack_ignores_sack_when_not_negotiated)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf1;
    struct tcp_seg_buf segbuf2;
    struct wolfIP_tcp_seg *seg1;
    struct wolfIP_tcp_seg *seg2;
    uint8_t ackbuf[sizeof(struct wolfIP_tcp_seg) + 12];
    struct wolfIP_tcp_seg *ackseg = (struct wolfIP_tcp_seg *)ackbuf;
    struct pkt_desc *desc;
    uint32_t left, right;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 0;
    ts->sock.tcp.seq = 102;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.bytes_in_flight = 2;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf1, 0, sizeof(segbuf1));
    seg1 = &segbuf1.seg;
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg1->hlen = TCP_HEADER_LEN << 2;
    seg1->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf1, sizeof(segbuf1)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&segbuf2, 0, sizeof(segbuf2));
    seg2 = &segbuf2.seg;
    seg2->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg2->hlen = TCP_HEADER_LEN << 2;
    seg2->seq = ee32(101);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf2, sizeof(segbuf2)), 0);
    desc = fifo_next(&ts->sock.tcp.txbuf, desc);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(ackbuf, 0, sizeof(ackbuf));
    ackseg->ack = ee32(100);
    ackseg->hlen = (TCP_HEADER_LEN + 12) << 2;
    ackseg->flags = 0x10;
    ackseg->data[0] = TCP_OPTION_NOP;
    ackseg->data[1] = TCP_OPTION_NOP;
    ackseg->data[2] = TCP_OPTION_SACK;
    ackseg->data[3] = 10;
    left = ee32(101);
    right = ee32(102);
    memcpy(&ackseg->data[4], &left, sizeof(left));
    memcpy(&ackseg->data[8], &right, sizeof(right));

    tcp_ack(ts, ackseg);
    ck_assert_uint_eq(ts->sock.tcp.peer_sack_count, 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_uint_eq(ts->sock.tcp.dup_acks, 1);
}
END_TEST

START_TEST(test_tcp_ack_malformed_sack_does_not_early_retransmit)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    uint8_t ackbuf[sizeof(struct wolfIP_tcp_seg) + 12];
    struct wolfIP_tcp_seg *ackseg = (struct wolfIP_tcp_seg *)ackbuf;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 1;
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.bytes_in_flight = 1;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(ackbuf, 0, sizeof(ackbuf));
    ackseg->ack = ee32(100);
    ackseg->hlen = (TCP_HEADER_LEN + 12) << 2;
    ackseg->flags = 0x10;
    ackseg->data[0] = TCP_OPTION_NOP;
    ackseg->data[1] = TCP_OPTION_NOP;
    ackseg->data[2] = TCP_OPTION_SACK;
    ackseg->data[3] = 11; /* malformed length */
    ackseg->data[4] = 0;

    tcp_ack(ts, ackseg);
    ck_assert_uint_eq(ts->sock.tcp.peer_sack_count, 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_uint_eq(ts->sock.tcp.dup_acks, 1);
}
END_TEST

START_TEST(test_tcp_ack_early_retransmit_once_per_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf1;
    struct tcp_seg_buf segbuf2;
    struct wolfIP_tcp_seg *seg1;
    struct wolfIP_tcp_seg *seg2;
    uint8_t ackbuf[sizeof(struct wolfIP_tcp_seg) + 12];
    struct wolfIP_tcp_seg *ackseg = (struct wolfIP_tcp_seg *)ackbuf;
    struct pkt_desc *desc1, *desc2;
    uint32_t left, right;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 1;
    ts->sock.tcp.seq = 102;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.bytes_in_flight = 2;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf1, 0, sizeof(segbuf1));
    seg1 = &segbuf1.seg;
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg1->hlen = TCP_HEADER_LEN << 2;
    seg1->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf1, sizeof(segbuf1)), 0);
    desc1 = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc1);
    desc1->flags |= PKT_FLAG_SENT;

    memset(&segbuf2, 0, sizeof(segbuf2));
    seg2 = &segbuf2.seg;
    seg2->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg2->hlen = TCP_HEADER_LEN << 2;
    seg2->seq = ee32(101);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf2, sizeof(segbuf2)), 0);
    desc2 = fifo_next(&ts->sock.tcp.txbuf, desc1);
    ck_assert_ptr_nonnull(desc2);
    desc2->flags |= PKT_FLAG_SENT;

    memset(ackbuf, 0, sizeof(ackbuf));
    ackseg->ack = ee32(100);
    ackseg->hlen = (TCP_HEADER_LEN + 12) << 2;
    ackseg->flags = 0x10;
    ackseg->data[0] = TCP_OPTION_NOP;
    ackseg->data[1] = TCP_OPTION_NOP;
    ackseg->data[2] = TCP_OPTION_SACK;
    ackseg->data[3] = 10;
    left = ee32(101);
    right = ee32(102);
    memcpy(&ackseg->data[4], &left, sizeof(left));
    memcpy(&ackseg->data[8], &right, sizeof(right));

    tcp_ack(ts, ackseg);
    ck_assert_int_ne(desc1->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc2->flags & PKT_FLAG_SENT, 0);

    tcp_ack(ts, ackseg);
    ck_assert_int_eq(desc1->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc2->flags & PKT_FLAG_SENT, 0);

    desc1->flags |= PKT_FLAG_SENT; /* emulate transmit loop sending it again */
    tcp_ack(ts, ackseg);
    ck_assert_int_eq(desc1->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc2->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_tcp_ack_no_sack_requires_three_dupacks)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 0;
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.bytes_in_flight = 1;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(100);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
    tcp_ack(ts, &ackseg);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
    tcp_ack(ts, &ackseg);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_tcp_ack_no_sack_three_dupacks_with_zero_rwnd_triggers_retransmit)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 0;
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.bytes_in_flight = 1;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = 0;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(100);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
    tcp_ack(ts, &ackseg);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
    tcp_ack(ts, &ackseg);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc->flags & PKT_FLAG_RETRANS, 0);
}
END_TEST

START_TEST(test_tcp_ack_wraparound_delta_reduces_inflight)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg ackseg;
    uint32_t snd_una = 0xFFFFFFF0U;
    uint32_t ack = 0x00000010U;
    uint32_t pre_flight = 0x40U;
    uint32_t delta = 0x20U;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.snd_una = snd_una;
    ts->sock.tcp.seq = 0x00000020U;
    ts->sock.tcp.bytes_in_flight = pre_flight;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(ack);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, ack);
    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, pre_flight - delta);
}
END_TEST

START_TEST(test_tcp_ack_wraparound_delta_saturates_inflight)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg ackseg;
    uint32_t snd_una = 0xFFFFFFF0U;
    uint32_t ack = 0x00000010U;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.snd_una = snd_una;
    ts->sock.tcp.seq = 0x00000020U;
    ts->sock.tcp.bytes_in_flight = 8;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(ack);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, ack);
    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, 0);
}
END_TEST

START_TEST(test_tcp_mark_unsacked_for_retransmit_wrap_seg_end)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct pkt_desc *desc;
    int ret;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 32);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(0xFFFFFFF0U);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    /* seg_end wraps to 0x10. With ack=0x10, segment should be treated as
     * fully acknowledged and thus not selected for retransmit. */
    ret = tcp_mark_unsacked_for_retransmit(ts, 0x00000010U);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_tcp_mark_unsacked_retransmits_partially_acked_segment)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf1;
    struct tcp_seg_buf segbuf2;
    struct wolfIP_tcp_seg *seg1;
    struct wolfIP_tcp_seg *seg2;
    struct pkt_desc *desc1, *desc2;
    int ret;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf1, 0, sizeof(segbuf1));
    seg1 = &segbuf1.seg;
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    seg1->hlen = TCP_HEADER_LEN << 2;
    seg1->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf1, sizeof(segbuf1)), 0);
    desc1 = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc1);
    desc1->flags |= PKT_FLAG_SENT;

    memset(&segbuf2, 0, sizeof(segbuf2));
    seg2 = &segbuf2.seg;
    seg2->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    seg2->hlen = TCP_HEADER_LEN << 2;
    seg2->seq = ee32(110);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf2, sizeof(segbuf2)), 0);
    desc2 = fifo_next(&ts->sock.tcp.txbuf, desc1);
    ck_assert_ptr_nonnull(desc2);
    desc2->flags |= PKT_FLAG_SENT;

    ret = tcp_mark_unsacked_for_retransmit(ts, 105);
    ck_assert_int_eq(ret, 1);
    ck_assert_int_eq(desc1->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc1->flags & PKT_FLAG_RETRANS, 0);
    ck_assert_int_ne(desc2->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_eq(desc2->flags & PKT_FLAG_RETRANS, 0);
}
END_TEST

START_TEST(test_tcp_mark_unsacked_rescans_after_clearing_stale_sack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct pkt_desc *desc;
    int ret;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 101;
    ts->sock.tcp.bytes_in_flight = 1;
    ts->sock.tcp.peer_sack_count = 1;
    ts->sock.tcp.peer_sack[0].left = 100;
    ts->sock.tcp.peer_sack[0].right = 101;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    /* First pass sees stale peer SACK covering the only hole and would skip it.
     * Function must clear SACK once and rescan, then mark the segment. */
    ret = tcp_mark_unsacked_for_retransmit(ts, 100);
    ck_assert_int_eq(ret, 1);
    ck_assert_uint_eq(ts->sock.tcp.peer_sack_count, 0);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
    ck_assert_int_ne(desc->flags & PKT_FLAG_RETRANS, 0);
}
END_TEST

START_TEST(test_tcp_ack_sack_blocks_clamped_and_dropped)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t ackbuf[sizeof(struct wolfIP_tcp_seg) + 12];
    struct wolfIP_tcp_seg *ackseg = (struct wolfIP_tcp_seg *)ackbuf;
    uint32_t left, right;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 1;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 200;

    memset(ackbuf, 0, sizeof(ackbuf));
    ackseg->ack = ee32(100);
    ackseg->hlen = (TCP_HEADER_LEN + 12) << 2;
    ackseg->flags = 0x10;
    ackseg->data[0] = TCP_OPTION_NOP;
    ackseg->data[1] = TCP_OPTION_NOP;
    ackseg->data[2] = TCP_OPTION_SACK;
    ackseg->data[3] = 10;
    left = ee32(50);
    right = ee32(250);
    memcpy(&ackseg->data[4], &left, sizeof(left));
    memcpy(&ackseg->data[8], &right, sizeof(right));
    tcp_ack(ts, ackseg);
    ck_assert_uint_eq(ts->sock.tcp.peer_sack_count, 1);
    ck_assert_uint_eq(ts->sock.tcp.peer_sack[0].left, 100);
    ck_assert_uint_eq(ts->sock.tcp.peer_sack[0].right, 200);

    left = ee32(10);
    right = ee32(90);
    memcpy(&ackseg->data[4], &left, sizeof(left));
    memcpy(&ackseg->data[8], &right, sizeof(right));
    tcp_ack(ts, ackseg);
    ck_assert_uint_eq(ts->sock.tcp.peer_sack_count, 0);
}
END_TEST

START_TEST(test_tcp_recv_ooo_capacity_limit)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t segbuf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)segbuf;
    uint8_t inbuf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *in = (struct wolfIP_tcp_seg *)inbuf;
    int i;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 1;
    ts->sock.tcp.ack = 100;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 100);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    for (i = 0; i < 5; i++) {
        memset(seg, 0, sizeof(segbuf));
        seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
        seg->hlen = TCP_HEADER_LEN << 2;
        seg->seq = ee32(101 + i);
        seg->data[0] = (uint8_t)('b' + i);
        tcp_recv(ts, seg);
    }
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 1);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].left, 101);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].right, 105);

    memset(in, 0, sizeof(inbuf));
    in->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    in->hlen = TCP_HEADER_LEN << 2;
    in->seq = ee32(100);
    in->data[0] = 'a';
    tcp_recv(ts, in);
    ck_assert_uint_eq(ts->sock.tcp.ack, 105);
}
END_TEST

START_TEST(test_tcp_recv_overlapping_ooo_segments_coalesce_on_consume)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg1buf[sizeof(struct wolfIP_tcp_seg) + 10];
    uint8_t seg2buf[sizeof(struct wolfIP_tcp_seg) + 10];
    uint8_t inbuf[sizeof(struct wolfIP_tcp_seg) + 10];
    struct wolfIP_tcp_seg *seg1 = (struct wolfIP_tcp_seg *)seg1buf;
    struct wolfIP_tcp_seg *seg2 = (struct wolfIP_tcp_seg *)seg2buf;
    struct wolfIP_tcp_seg *in = (struct wolfIP_tcp_seg *)inbuf;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.sack_permitted = 1;
    ts->sock.tcp.ack = 100;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 100);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(seg1, 0, sizeof(seg1buf));
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    seg1->hlen = TCP_HEADER_LEN << 2;
    seg1->seq = ee32(110);
    memcpy(seg1->data, "KLMNOPQRST", 10);
    tcp_recv(ts, seg1);

    memset(seg2, 0, sizeof(seg2buf));
    seg2->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    seg2->hlen = TCP_HEADER_LEN << 2;
    seg2->seq = ee32(115);
    memcpy(seg2->data, "PQRSTUVWXY", 10);
    tcp_recv(ts, seg2);

    memset(in, 0, sizeof(inbuf));
    in->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 10);
    in->hlen = TCP_HEADER_LEN << 2;
    in->seq = ee32(100);
    memcpy(in->data, "ABCDEFGHIJ", 10);
    tcp_recv(ts, in);
    ck_assert_uint_eq(ts->sock.tcp.ack, 125);
}
END_TEST

START_TEST(test_tcp_input_syn_with_sack_option_enables_sack)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct {
        uint8_t frame[sizeof(struct wolfIP_tcp_seg) + 4];
        uint8_t canary[8];
    } pkt;
    struct wolfIP_tcp_seg *syn = (struct wolfIP_tcp_seg *)pkt.frame;
    struct wolfIP_ll_dev *ll;
    union transport_pseudo_header ph;
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    memset(&pkt, 0, sizeof(pkt));
    memset(pkt.canary, 0xA5, sizeof(pkt.canary));
    memcpy(syn->ip.eth.dst, ll->mac, 6);
    syn->ip.eth.type = ee16(ETH_TYPE_IP);
    syn->ip.ver_ihl = 0x45;
    syn->ip.ttl = 64;
    syn->ip.proto = WI_IPPROTO_TCP;
    syn->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    syn->ip.src = ee32(0x0A0000A1U);
    syn->ip.dst = ee32(0x0A000001U);
    iphdr_set_checksum(&syn->ip);
    syn->src_port = ee16(40000);
    syn->dst_port = ee16(1234);
    syn->seq = ee32(1);
    syn->hlen = (TCP_HEADER_LEN + 4) << 2;
    syn->flags = 0x02;
    syn->win = ee16(65535);
    syn->data[0] = TCP_OPTION_SACK_PERMITTED;
    syn->data[1] = TCP_OPTION_SACK_PERMITTED_LEN;
    syn->data[2] = TCP_OPTION_NOP;
    syn->data[3] = TCP_OPTION_NOP;
    for (i = 0; i < (int)sizeof(pkt.canary); i++)
        ck_assert_uint_eq(pkt.canary[i], 0xA5);

    memset(&ph, 0, sizeof(ph));
    ph.ph.src = syn->ip.src;
    ph.ph.dst = syn->ip.dst;
    ph.ph.proto = WI_IPPROTO_TCP;
    ph.ph.len = ee16(TCP_HEADER_LEN + 4);
    syn->csum = ee16(transport_checksum(&ph, &syn->src_port));

    tcp_input(&s, TEST_PRIMARY_IF, syn,
            sizeof(struct wolfIP_eth_frame) + IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    ck_assert_uint_eq(ts->sock.tcp.sack_permitted, 1);
}
END_TEST

START_TEST(test_tcp_input_syn_with_sack_option_respects_local_sack_offer)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct {
        uint8_t frame[sizeof(struct wolfIP_tcp_seg) + 4];
    } pkt;
    struct wolfIP_tcp_seg *syn = (struct wolfIP_tcp_seg *)pkt.frame;
    struct wolfIP_ll_dev *ll;
    union transport_pseudo_header ph;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ts->sock.tcp.sack_offer = 0;
    ll = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    memset(&pkt, 0, sizeof(pkt));
    memcpy(syn->ip.eth.dst, ll->mac, 6);
    syn->ip.eth.type = ee16(ETH_TYPE_IP);
    syn->ip.ver_ihl = 0x45;
    syn->ip.ttl = 64;
    syn->ip.proto = WI_IPPROTO_TCP;
    syn->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    syn->ip.src = ee32(0x0A0000A1U);
    syn->ip.dst = ee32(0x0A000001U);
    iphdr_set_checksum(&syn->ip);
    syn->src_port = ee16(40000);
    syn->dst_port = ee16(1234);
    syn->seq = ee32(1);
    syn->hlen = (TCP_HEADER_LEN + 4) << 2;
    syn->flags = 0x02;
    syn->win = ee16(65535);
    syn->data[0] = TCP_OPTION_SACK_PERMITTED;
    syn->data[1] = TCP_OPTION_SACK_PERMITTED_LEN;
    syn->data[2] = TCP_OPTION_NOP;
    syn->data[3] = TCP_OPTION_NOP;

    memset(&ph, 0, sizeof(ph));
    ph.ph.src = syn->ip.src;
    ph.ph.dst = syn->ip.dst;
    ph.ph.proto = WI_IPPROTO_TCP;
    ph.ph.len = ee16(TCP_HEADER_LEN + 4);
    syn->csum = ee16(transport_checksum(&ph, &syn->src_port));

    tcp_input(&s, TEST_PRIMARY_IF, syn,
            sizeof(struct wolfIP_eth_frame) + IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    ck_assert_uint_eq(ts->sock.tcp.sack_permitted, 0);
}
END_TEST

START_TEST(test_tcp_input_syn_listen_mismatch)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ts->bound_local_ip = 0x0A000001U;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A0000A1U, IPADDR_ANY, 40000, 1234, 1, 0, 0x02);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
}
END_TEST

START_TEST(test_tcp_input_syn_sent_unexpected_flags)
{
    struct wolfIP s;
    struct tsocket *ts;
    int tcp_sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
    wolfIP_filter_set_tcp_mask(0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U, 4321, 1234, 10, 0, 0x02);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);
}
END_TEST

START_TEST(test_tcp_input_syn_sent_synack_transitions)
{
    struct wolfIP s;
    struct tsocket *ts;
    int tcp_sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
    wolfIP_filter_set_tcp_mask(0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->sock.tcp.seq = 100;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A000002U, 0x0A000001U, 4321, 1234, 10, 101, 0x12);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.ack, 11);
}
END_TEST

START_TEST(test_tcp_input_iplen_too_big)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;

    memset(&seg, 0, sizeof(seg));
    seg.ip.len = ee16(2000);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(ts->dst_port);
    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST
START_TEST(test_tcp_ack_acks_data_and_sets_writable)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint8_t payload[1] = { TCP_OPTION_EOO };
    uint32_t seq = 100;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.ssthresh = TCP_MSS * 4;
    /* Ensure cwnd growth is gated by bytes_in_flight and not rwnd-capped. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(seg, 0, sizeof(seg_buf));
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    seg->flags = 0x10;
    memcpy(seg->data, payload, sizeof(payload));
    fifo_push(&ts->sock.tcp.txbuf, seg, sizeof(seg_buf));
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    desc->time_sent = 10;
    /* Simulate cwnd-limited flight and initialize snd_una. */
    ts->sock.tcp.bytes_in_flight = TCP_MSS;
    ts->sock.tcp.snd_una = seq;
    ts->sock.tcp.seq = seq + TCP_MSS;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq + sizeof(payload));
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    /* FIFO should be empty after acked data is removed. */
    ck_assert_ptr_eq(fifo_peek(&ts->sock.tcp.txbuf), NULL);
    ck_assert_uint_eq(ts->events & CB_EVENT_WRITABLE, CB_EVENT_WRITABLE);
    ck_assert_uint_gt(ts->sock.tcp.cwnd, TCP_MSS);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_resend_clears_sent)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq = 200;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.ssthresh = TCP_MSS * 4;
    /* Allow duplicate-ACK path without rwnd cap. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(seg, 0, sizeof(seg_buf));
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    seg->flags = 0x10;
    seg->data[0] = TCP_OPTION_EOO;
    fifo_push(&ts->sock.tcp.txbuf, seg, sizeof(seg_buf));
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq + 1000);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_tcp_ack_discards_zero_len_segment)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(100);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.tcp.txbuf), NULL);
}
END_TEST

START_TEST(test_tcp_ack_closes_last_ack_socket)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq = 100;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_LAST_ACK;
    ts->sock.tcp.last = seq;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_int_eq(ts->proto, 0);
}
END_TEST

START_TEST(test_tcp_ack_last_seq_match_no_close)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq = 200;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.last = seq;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_int_eq(ts->proto, WI_IPPROTO_TCP);
}
END_TEST

START_TEST(test_tcp_ack_fresh_desc_updates_rtt_existing)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq = 300;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.ssthresh = TCP_MSS * 4;
    ts->sock.tcp.rtt = 50;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    s.last_tick = 1000;

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    seg->data[0] = TCP_OPTION_EOO;
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    desc->time_sent = 900;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq + 1);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_gt(ts->sock.tcp.rtt, 0);
    ck_assert_uint_eq(ts->events & CB_EVENT_WRITABLE, CB_EVENT_WRITABLE);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_zero_len_segment_large_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf1;
    struct tcp_seg_buf segbuf2;
    struct wolfIP_tcp_seg *seg1;
    struct wolfIP_tcp_seg *seg2;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.ssthresh = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf1, 0, sizeof(segbuf1));
    seg1 = &segbuf1.seg;
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 2000);
    seg1->hlen = TCP_HEADER_LEN << 2;
    seg1->seq = ee32(400);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf1, sizeof(segbuf1)), 0);

    memset(&segbuf2, 0, sizeof(segbuf2));
    seg2 = &segbuf2.seg;
    seg2->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg2->hlen = TCP_HEADER_LEN << 2;
    seg2->seq = ee32(500);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf2, sizeof(segbuf2)), 0);

    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    desc = fifo_next(&ts->sock.tcp.txbuf, desc);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    /* Force duplicate ACK handling with outstanding bytes. */
    ts->sock.tcp.bytes_in_flight = TCP_MSS * 2;
    /* Treat this ACK as a duplicate (snd_una == ack). */
    ts->sock.tcp.snd_una = 0xF0000000U;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(0xF0000000U);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    /* Prime dup-ack counter so a single ACK triggers fast retransmit. */
    ts->sock.tcp.dup_acks = 2;
    tcp_ack(ts, &ackseg);
    ck_assert_uint_le(fifo_len(&ts->sock.tcp.txbuf), TXBUF_SIZE);
    ck_assert_uint_eq(ts->sock.tcp.ssthresh, TCP_MSS * 2);
    ck_assert_uint_eq(ts->sock.tcp.cwnd, TCP_MSS * 3);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_seq_match_large_seg_len)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq = 500;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    /* Allow duplicate-ACK path without rwnd cap. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 2000);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    /* Force duplicate ACK handling with outstanding bytes. */
    ts->sock.tcp.bytes_in_flight = TCP_MSS * 2;
    ts->sock.tcp.snd_una = seq;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    /* Trigger fast retransmit by delivering three duplicate ACKs. */
    tcp_ack(ts, &ackseg);
    tcp_ack(ts, &ackseg);
    tcp_ack(ts, &ackseg);
    ck_assert_int_ne(desc->flags & PKT_FLAG_SENT, PKT_FLAG_SENT);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_clears_sent_flag)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf1;
    struct tcp_seg_buf segbuf2;
    struct wolfIP_tcp_seg *seg1;
    struct wolfIP_tcp_seg *seg2;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq1 = 100;
    uint32_t seq2 = 200;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf1, 0, sizeof(segbuf1));
    seg1 = &segbuf1.seg;
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg1->hlen = TCP_HEADER_LEN << 2;
    seg1->seq = ee32(seq1);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf1, sizeof(segbuf1)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&segbuf2, 0, sizeof(segbuf2));
    seg2 = &segbuf2.seg;
    seg2->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg2->hlen = TCP_HEADER_LEN << 2;
    seg2->seq = ee32(seq2);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf2, sizeof(segbuf2)), 0);

    /* Force duplicate ACK handling with outstanding bytes. */
    ts->sock.tcp.bytes_in_flight = TCP_MSS * 2;
    ts->sock.tcp.snd_una = seq1;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq1);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    /* Prime dup-ack counter so a single ACK triggers fast retransmit. */
    ts->sock.tcp.dup_acks = 2;
    tcp_ack(ts, &ackseg);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_discards_zero_len_segment)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf1;
    struct tcp_seg_buf segbuf2;
    struct wolfIP_tcp_seg *seg1;
    struct wolfIP_tcp_seg *seg2;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf1, 0, sizeof(segbuf1));
    seg1 = &segbuf1.seg;
    seg1->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg1->hlen = TCP_HEADER_LEN << 2;
    seg1->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf1, sizeof(segbuf1)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&segbuf2, 0, sizeof(segbuf2));
    seg2 = &segbuf2.seg;
    seg2->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg2->hlen = TCP_HEADER_LEN << 2;
    seg2->seq = ee32(200);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf2, sizeof(segbuf2)), 0);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(50);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    {
        struct wolfIP_tcp_seg *cur = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
        ck_assert_uint_eq(ee32(cur->seq), 200U);
    }
}
END_TEST

START_TEST(test_tcp_ack_progress_resets_rto_recovery_state)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    struct wolfIP_timer tmr;
    uint32_t seq = 100;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.ssthresh = 2 * TCP_MSS;
    ts->sock.tcp.seq = seq + 64;
    ts->sock.tcp.snd_una = seq;
    ts->sock.tcp.bytes_in_flight = TCP_MSS;
    ts->sock.tcp.rto_backoff = 4;
    ts->sock.tcp.dup_acks = 2;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    seg->data[0] = TCP_OPTION_EOO;
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    desc->time_sent = 10;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 1000;
    ts->sock.tcp.tmr_rto = timers_binheap_insert(&s.timers, tmr);
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq + 1);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);

    ck_assert_uint_eq(ts->sock.tcp.snd_una, seq + 1);
    ck_assert_uint_eq(ts->sock.tcp.rto_backoff, 0);
    ck_assert_uint_eq(ts->sock.tcp.dup_acks, 0);
    /* Forward ACK clears recovery backoff, but if data is still in-flight
     * the sender must keep an RTO armed so loss recovery can continue. */
    ck_assert_int_ne(ts->sock.tcp.tmr_rto, NO_TIMER);
    ck_assert_uint_gt(ts->sock.tcp.cwnd, TCP_MSS);
}
END_TEST

START_TEST(test_tcp_ack_cwnd_grows_when_payload_acked_is_mss_minus_options)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t payload = TCP_MSS - TCP_OPTIONS_LEN;
    uint32_t seq = 100;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.ssthresh = TCP_MSS * 8;
    ts->sock.tcp.snd_una = seq;
    ts->sock.tcp.seq = seq + payload;
    ts->sock.tcp.bytes_in_flight = payload;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + payload);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq + payload);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.cwnd, TCP_MSS * 2);
}
END_TEST

START_TEST(test_tcp_ack_inflight_deflate_sets_writable_without_acked_desc)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg ackseg;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 200;
    ts->sock.tcp.bytes_in_flight = 64;
    ts->events = 0;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(120);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.snd_una, 120U);
    ck_assert_uint_eq(ts->sock.tcp.bytes_in_flight, 44U);
    ck_assert_uint_eq(ts->events & CB_EVENT_WRITABLE, CB_EVENT_WRITABLE);
}
END_TEST

START_TEST(test_tcp_input_peer_rwnd_growth_sets_writable)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg ackseg;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 5001;
    ts->dst_port = 40000;
    ts->local_ip = 0xC0A80102U;
    ts->remote_ip = 0xC0A80104U;
    ts->sock.tcp.seq = 200;
    ts->sock.tcp.snd_una = 150;
    ts->sock.tcp.ack = 1234;
    ts->sock.tcp.peer_rwnd = 0;
    ts->events = 0;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ip.src = ee32(ts->remote_ip);
    ackseg.ip.dst = ee32(ts->local_ip);
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ackseg.ip.ttl = 64;
    ackseg.src_port = ee16(ts->dst_port);
    ackseg.dst_port = ee16(ts->src_port);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;
    ackseg.ack = ee32(ts->sock.tcp.snd_una);
    ackseg.win = ee16(8);

    tcp_input(&s, TEST_PRIMARY_IF, &ackseg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));

    ck_assert_uint_eq(ts->sock.tcp.peer_rwnd, 8U);
    ck_assert_uint_eq(ts->events & CB_EVENT_WRITABLE, CB_EVENT_WRITABLE);
}
END_TEST

START_TEST(test_tcp_input_synack_negotiates_peer_mss)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct {
        struct wolfIP_tcp_seg seg;
        uint8_t mss_opt[4];
    } synack;
    uint16_t mss_be;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->src_port = 23456;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5001);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);

    memset(&synack, 0, sizeof(synack));
    synack.seg.ip.ttl = 64;
    synack.seg.ip.src = ee32(0x0A000002U);
    synack.seg.ip.dst = ee32(0x0A000001U);
    synack.seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    synack.seg.src_port = ee16(5001);
    synack.seg.dst_port = ee16(ts->src_port);
    synack.seg.seq = ee32(100);
    synack.seg.ack = ee32(ts->sock.tcp.seq + 1);
    synack.seg.hlen = (TCP_HEADER_LEN + 4) << 2;
    synack.seg.flags = 0x12;
    synack.seg.win = ee16(65535);
    synack.mss_opt[0] = TCP_OPTION_MSS;
    synack.mss_opt[1] = TCP_OPTION_MSS_LEN;
    mss_be = ee16(512);
    memcpy(&synack.mss_opt[2], &mss_be, sizeof(mss_be));

    tcp_input(&s, TEST_PRIMARY_IF, &synack.seg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 4));

    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
    ck_assert_uint_eq(ts->sock.tcp.peer_mss, 512U);
}
END_TEST

START_TEST(test_sock_sendto_tcp_respects_negotiated_peer_mss)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct {
        struct wolfIP_tcp_seg seg;
        uint8_t mss_opt[4];
    } synack;
    uint16_t mss_be;
    uint8_t payload[1200];
    int ret;
    struct pkt_desc *desc;
    int seg_count = 0;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->src_port = 23457;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5002);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);

    memset(&synack, 0, sizeof(synack));
    synack.seg.ip.ttl = 64;
    synack.seg.ip.src = ee32(0x0A000002U);
    synack.seg.ip.dst = ee32(0x0A000001U);
    synack.seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 4);
    synack.seg.src_port = ee16(5002);
    synack.seg.dst_port = ee16(ts->src_port);
    synack.seg.seq = ee32(100);
    synack.seg.ack = ee32(ts->sock.tcp.seq + 1);
    synack.seg.hlen = (TCP_HEADER_LEN + 4) << 2;
    synack.seg.flags = 0x12;
    synack.seg.win = ee16(65535);
    synack.mss_opt[0] = TCP_OPTION_MSS;
    synack.mss_opt[1] = TCP_OPTION_MSS_LEN;
    mss_be = ee16(512);
    memcpy(&synack.mss_opt[2], &mss_be, sizeof(mss_be));

    tcp_input(&s, TEST_PRIMARY_IF, &synack.seg,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + 4));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);

    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    memset(payload, 0xA5, sizeof(payload));
    ret = wolfIP_sock_sendto(&s, tcp_sd, payload, sizeof(payload), 0, NULL, 0);
    ck_assert_int_eq(ret, (int)sizeof(payload));

    desc = fifo_peek(&ts->sock.tcp.txbuf);
    while (desc != NULL) {
        struct wolfIP_tcp_seg *seg;
        uint32_t seg_payload;
        uint32_t hdr_len;
        uint32_t opt_len;
        uint32_t base_len;

        seg = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
        hdr_len = (uint32_t)(seg->hlen >> 2);
        ck_assert_uint_ge(hdr_len, TCP_HEADER_LEN);
        opt_len = hdr_len - TCP_HEADER_LEN;
        base_len = (uint32_t)(sizeof(struct wolfIP_tcp_seg) + opt_len);
        ck_assert_uint_ge(desc->len, base_len);
        seg_payload = desc->len - base_len;
        ck_assert_uint_le(seg_payload, 512U);

        seg_count++;
        desc = fifo_next(&ts->sock.tcp.txbuf, desc);
    }
    ck_assert_int_ge(seg_count, 3);
}
END_TEST

START_TEST(test_sock_sendto_tcp_defaults_to_rfc_mss_when_unset_by_peer)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_tcp_seg synack;
    uint8_t payload[1200];
    int ret;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->src_port = 23458;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5003);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_connect(&s, tcp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_SENT);

    memset(&synack, 0, sizeof(synack));
    synack.ip.ttl = 64;
    synack.ip.src = ee32(0x0A000002U);
    synack.ip.dst = ee32(0x0A000001U);
    synack.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    synack.src_port = ee16(5003);
    synack.dst_port = ee16(ts->src_port);
    synack.seq = ee32(100);
    synack.ack = ee32(ts->sock.tcp.seq + 1);
    synack.hlen = TCP_HEADER_LEN << 2;
    synack.flags = 0x12;
    synack.win = ee16(65535);

    tcp_input(&s, TEST_PRIMARY_IF, &synack,
            (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);

    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    memset(payload, 0x5A, sizeof(payload));
    ret = wolfIP_sock_sendto(&s, tcp_sd, payload, sizeof(payload), 0, NULL, 0);
    ck_assert_int_eq(ret, (int)sizeof(payload));

    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    while (desc != NULL) {
        struct wolfIP_tcp_seg *seg;
        uint32_t seg_payload;
        uint32_t hdr_len;
        uint32_t opt_len;
        uint32_t base_len;

        seg = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
        hdr_len = (uint32_t)(seg->hlen >> 2);
        ck_assert_uint_ge(hdr_len, TCP_HEADER_LEN);
        opt_len = hdr_len - TCP_HEADER_LEN;
        base_len = (uint32_t)(sizeof(struct wolfIP_tcp_seg) + opt_len);
        ck_assert_uint_ge(desc->len, base_len);
        seg_payload = desc->len - base_len;
        ck_assert_uint_le(seg_payload, TCP_DEFAULT_MSS);

        desc = fifo_next(&ts->sock.tcp.txbuf, desc);
    }
}
END_TEST

START_TEST(test_tcp_input_syn_rcvd_ack_established)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_tcp_seg ackseg;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ip.ttl = 64;
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ackseg.dst_port = ee16(ts->src_port);
    ackseg.src_port = ee16(ts->dst_port);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;
    tcp_input(&s, TEST_PRIMARY_IF, &ackseg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

START_TEST(test_tcp_recv_queues_payload_and_advances_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_timer tmr;
    uint8_t payload[3] = { 'a', 'b', 'c' };
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + sizeof(payload)];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;
    uint32_t seq = 50;
    int ret;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = seq;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, seq);

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 100;
    ts->sock.tcp.tmr_rto = timers_binheap_insert(&s.timers, tmr);

    memset(seg, 0, sizeof(seg_buf));
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    seg->flags = 0x18;
    memcpy(seg->data, payload, sizeof(payload));

    tcp_recv(ts, seg);
    ck_assert_uint_eq(ts->sock.tcp.ack, seq + sizeof(payload));
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, CB_EVENT_READABLE);
    ck_assert_int_eq(ts->sock.tcp.tmr_rto, NO_TIMER);

    {
        uint8_t out[4] = {0};
        ret = queue_pop(&ts->sock.tcp.rxbuf, out, sizeof(out));
        ck_assert_int_eq(ret, (int)sizeof(payload));
        ck_assert_mem_eq(out, payload, sizeof(payload));
    }
}
END_TEST

START_TEST(test_tcp_recv_wrong_state_does_nothing)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_SYN_SENT;
    ts->sock.tcp.ack = 10;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);

    memset(&seg, 0, sizeof(seg));
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.seq = ee32(10);

    tcp_recv(ts, &seg);
    ck_assert_uint_eq(queue_len(&ts->sock.tcp.rxbuf), 0);
    ck_assert_uint_eq(ts->sock.tcp.ack, 10);
}
END_TEST

START_TEST(test_tcp_recv_ack_mismatch_does_nothing)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 10;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);

    memset(&seg, 0, sizeof(seg));
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.seq = ee32(11);

    tcp_recv(ts, &seg);
    ck_assert_uint_eq(queue_len(&ts->sock.tcp.rxbuf), 0U);
}
END_TEST

START_TEST(test_tcp_recv_wrap_seq_ahead_not_trimmed)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t seg_buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)seg_buf;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 0xFFFFFFF0U;
    ts->sock.tcp.sack_permitted = 1;
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, ts->sock.tcp.ack);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(seg, 0, sizeof(seg_buf));
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(0x00000010U); /* numerically lower, but ahead across wrap */
    seg->data[0] = 0x5A;

    tcp_recv(ts, seg);
    ck_assert_uint_eq(ts->sock.tcp.ack, 0xFFFFFFF0U);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack_count, 1);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].left, 0x00000010U);
    ck_assert_uint_eq(ts->sock.tcp.rx_sack[0].right, 0x00000011U);
}
END_TEST

START_TEST(test_tcp_recv_close_wait_ack_match)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;

    wolfIP_init(&s);
    ts = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    ts->sock.tcp.ack = 100;

    memset(buf, 0, sizeof(buf));
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    seg->data[0] = 0x5a;

    tcp_recv(ts, seg);
    ck_assert_uint_eq(ts->sock.tcp.ack, 101);
    ck_assert_uint_eq(ts->events & CB_EVENT_READABLE, CB_EVENT_READABLE);
}
END_TEST

START_TEST(test_tcp_recv_queue_full_sends_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    uint8_t tiny[4];

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.ack = 10;
    queue_init(&ts->sock.tcp.rxbuf, tiny, sizeof(tiny), 0);
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&seg, 0, sizeof(seg));
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 8);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.seq = ee32(10);

    tcp_recv(ts, &seg);
    ck_assert_uint_eq(ts->sock.tcp.ack, 10);
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.tcp.txbuf));
}
END_TEST

START_TEST(test_tcp_ack_cwnd_count_wrap)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS * 4;
    ts->sock.tcp.ssthresh = TCP_MSS;
    ts->sock.tcp.cwnd_count = ts->sock.tcp.cwnd - 1;
    /* Ensure cwnd growth path is taken and not rwnd-capped. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    /* Simulate cwnd-limited flight and initialize snd_una. */
    ts->sock.tcp.bytes_in_flight = ts->sock.tcp.cwnd;
    /* Advance ACK by 1 byte to exercise cwnd_count wrap. */
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 100 + TCP_MSS;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(101);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    /* Expect cwnd_count to wrap to (cwnd_count + MSS - cwnd). */
    ck_assert_uint_eq(ts->sock.tcp.cwnd_count, (TCP_MSS - 1));
    ck_assert_uint_eq(ts->sock.tcp.cwnd, (TCP_MSS * 5));
}
END_TEST

START_TEST(test_tcp_ack_updates_rtt_and_cwnd)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + TCP_OPTION_TS_LEN + 1];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    struct tcp_opt_ts *tsopt;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.ssthresh = TCP_MSS * 4;
    /* Ensure cwnd growth path is taken and not rwnd-capped. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    s.last_tick = 1000;

    memset(buf, 0, sizeof(buf));
    seg->ip.len = ee16(IP_HEADER_LEN + (TCP_HEADER_LEN + TCP_OPTION_TS_LEN) + 1);
    seg->hlen = (TCP_HEADER_LEN + TCP_OPTION_TS_LEN) << 2;
    seg->seq = ee32(100);
    tsopt = (struct tcp_opt_ts *)seg->data;
    tsopt->opt = TCP_OPTION_TS;
    tsopt->len = TCP_OPTION_TS_LEN;
    tsopt->val = ee32(123);
    tsopt->ecr = ee32(990);

    fifo_push(&ts->sock.tcp.txbuf, seg, sizeof(buf));
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    /* Simulate cwnd-limited flight and initialize snd_una. */
    ts->sock.tcp.bytes_in_flight = ts->sock.tcp.cwnd;
    ts->sock.tcp.snd_una = 100;
    ts->sock.tcp.seq = 100 + TCP_MSS;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(101);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_gt(ts->sock.tcp.rtt, 0);
    ck_assert_uint_eq(ts->sock.tcp.cwnd, TCP_MSS * 2);
    ck_assert_uint_eq(ts->events & CB_EVENT_WRITABLE, CB_EVENT_WRITABLE);
}
END_TEST

START_TEST(test_tcp_ack_last_seq_not_last_ack_state)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.last = 100;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(100);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

START_TEST(test_tcp_ack_no_progress_when_ack_far_ahead)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;
    uint32_t seq = 100;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    /* Allow duplicate-ACK path without rwnd cap. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(seq);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    /* Force duplicate ACK handling with outstanding bytes. */
    ts->sock.tcp.bytes_in_flight = TCP_MSS * 2;
    ts->sock.tcp.snd_una = 500;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(seq + 0x100000U);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.tcp.txbuf), NULL);
}
END_TEST

START_TEST(test_tcp_ack_coarse_rtt_sets_writable)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    ts->sock.tcp.ssthresh = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
    s.last_tick = 1000;

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    desc->time_sent = 900;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(101);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_eq(ts->sock.tcp.rtt, 100U);
    ck_assert_uint_eq(ts->events & CB_EVENT_WRITABLE, CB_EVENT_WRITABLE);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_clears_sent_large_seg_len)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    /* Allow duplicate-ACK path without rwnd cap. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 2000);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(500);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    /* Force duplicate ACK handling with outstanding bytes. */
    ts->sock.tcp.bytes_in_flight = TCP_MSS * 2;
    ts->sock.tcp.snd_una = 500;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(500);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    /* Trigger fast retransmit by delivering three duplicate ACKs. */
    tcp_ack(ts, &ackseg);
    tcp_ack(ts, &ackseg);
    tcp_ack(ts, &ackseg);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_discards_zero_len_segment_far_ack)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(1000);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_ptr_eq(fifo_peek(&ts->sock.tcp.txbuf), NULL);
}
END_TEST

START_TEST(test_tcp_ack_duplicate_ssthresh_min)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct tcp_seg_buf segbuf;
    struct wolfIP_tcp_seg *seg;
    struct wolfIP_tcp_seg ackseg;
    struct pkt_desc *desc;

    wolfIP_init(&s);
    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->sock.tcp.cwnd = TCP_MSS;
    /* Allow duplicate-ACK path without rwnd cap. */
    ts->sock.tcp.peer_rwnd = TCP_MSS * 8;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&segbuf, 0, sizeof(segbuf));
    seg = &segbuf.seg;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + 1);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->seq = ee32(100);
    ck_assert_int_eq(fifo_push(&ts->sock.tcp.txbuf, &segbuf, sizeof(segbuf)), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;
    /* Force duplicate ACK handling with outstanding bytes. */
    ts->sock.tcp.bytes_in_flight = TCP_MSS;
    ts->sock.tcp.snd_una = 50;

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ack = ee32(50);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x10;

    tcp_ack(ts, &ackseg);
    ck_assert_uint_ge(ts->sock.tcp.cwnd, TCP_MSS);
}
END_TEST

START_TEST(test_tcp_input_filter_drop)
{
    struct wolfIP s;
    struct wolfIP_tcp_seg seg;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_tcp_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING));
    filter_block_reason = WOLFIP_FILT_RECEIVING;

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;

    memset(&seg, 0, sizeof(seg));
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(ts->dst_port);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = 0x10;

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);

    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_tcp_mask(0);
}
END_TEST

START_TEST(test_tcp_input_port_mismatch_skips_socket)
{
    struct wolfIP s;
    struct wolfIP_tcp_seg seg;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;

    memset(&seg, 0, sizeof(seg));
    seg.ip.ttl = 64;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(9999);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = 0x10;

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

START_TEST(test_tcp_input_syn_bound_ip_mismatch)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ts->bound_local_ip = 0x0A000001U;

    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A0000A1U, 0x0A000002U, 40000, 1234, 1, 0, 0x02);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
}
END_TEST

START_TEST(test_tcp_input_syn_dst_not_local)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A0000A1U, 0x0A000002U, 40000, 1234, 1, 0, 0x02);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
}
END_TEST

START_TEST(test_tcp_input_syn_dst_outside_subnet)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    inject_tcp_segment(&s, TEST_PRIMARY_IF, 0x0A0000A1U, 0x0B000001U, 40000, 1234, 1, 0, 0x02);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
}
END_TEST

START_TEST(test_tcp_input_listen_dst_match_false)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_tcp_seg seg;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    wolfIP_filter_set_mask(0);
    wolfIP_filter_set_tcp_mask(0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ts->bound_local_ip = IPADDR_ANY;
    memset(&seg, 0, sizeof(seg));
    seg.ip.ttl = 64;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(0x0A000002U);
    seg.ip.dst = ee32(0x0B000001U);
    seg.src_port = ee16(40000);
    seg.dst_port = ee16(ts->src_port);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = 0x02;

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LISTEN);
}
END_TEST

START_TEST(test_tcp_input_established_fin_sets_close_wait)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A0000B1U;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->src_port = 1234;
    ts->dst_port = 4321;

    memset(&seg, 0, sizeof(seg));
    seg.ip.ttl = 64;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.ip.src = ee32(remote_ip);
    seg.ip.dst = ee32(local_ip);
    seg.src_port = ee16(ts->dst_port);
    seg.dst_port = ee16(ts->src_port);
    seg.seq = ee32(10);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = 0x01;

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSE_WAIT);
    ck_assert_uint_eq(ts->sock.tcp.ack, 11);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, CB_EVENT_CLOSED);
}
END_TEST

START_TEST(test_tcp_input_fin_wait_1_fin_with_payload_returns)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    uint8_t payload[4] = {1,2,3,4};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_FIN_WAIT_1;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;

    memset(buf, 0, sizeof(buf));
    seg->ip.ttl = 64;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->dst_port = ee16(ts->src_port);
    seg->src_port = ee16(ts->dst_port);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = 0x11;
    memcpy(seg->data, payload, sizeof(payload));

    tcp_input(&s, TEST_PRIMARY_IF, seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload)));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_CLOSING);
}
END_TEST

START_TEST(test_tcp_input_fin_wait_2_fin_with_payload_queues)
{
    struct wolfIP s;
    struct tsocket *ts;
    uint8_t buf[sizeof(struct wolfIP_tcp_seg) + 4];
    struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)buf;
    uint8_t payload[4] = {9, 8, 7, 6};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    ts = tcp_new_socket(&s);
    ck_assert_ptr_nonnull(ts);
    ts->sock.tcp.state = TCP_FIN_WAIT_2;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    ts->local_ip = 0x0A000001U;
    ts->remote_ip = 0x0A000002U;
    ts->sock.tcp.ack = 100;

    memset(buf, 0, sizeof(buf));
    seg->ip.ttl = 64;
    seg->ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload));
    seg->ip.src = ee32(ts->remote_ip);
    seg->ip.dst = ee32(ts->local_ip);
    seg->dst_port = ee16(ts->src_port);
    seg->src_port = ee16(ts->dst_port);
    seg->seq = ee32(200);
    seg->ack = ee32(100);
    seg->hlen = TCP_HEADER_LEN << 2;
    seg->flags = 0x01;
    memcpy(seg->data, payload, sizeof(payload));

    tcp_input(&s, TEST_PRIMARY_IF, seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(payload)));
    ck_assert_uint_eq(ts->sock.tcp.ack, 201);
    ck_assert_uint_eq(ts->events & CB_EVENT_CLOSED, CB_EVENT_CLOSED);
}
END_TEST

START_TEST(test_socket_from_fd_invalid)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);

    ck_assert_ptr_eq(wolfIP_socket_from_fd(NULL, 1), NULL);
    ck_assert_ptr_eq(wolfIP_socket_from_fd(&s, -1), NULL);
    ck_assert_ptr_eq(wolfIP_socket_from_fd(&s, MARK_TCP_SOCKET | MAX_TCPSOCKETS), NULL);
    ck_assert_ptr_eq(wolfIP_socket_from_fd(&s, MARK_UDP_SOCKET | MAX_UDPSOCKETS), NULL);
    ck_assert_ptr_eq(wolfIP_socket_from_fd(&s, MARK_ICMP_SOCKET | MAX_ICMPSOCKETS), NULL);
}
END_TEST

START_TEST(test_socket_from_fd_valid)
{
    struct wolfIP s;
    int tcp_sd;
    int udp_sd;
    int icmp_sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(tcp_sd, 0);
    ck_assert_int_gt(udp_sd, 0);
    ck_assert_int_gt(icmp_sd, 0);

    ts = wolfIP_socket_from_fd(&s, tcp_sd);
    ck_assert_ptr_eq(ts, &s.tcpsockets[SOCKET_UNMARK(tcp_sd)]);
    ts = wolfIP_socket_from_fd(&s, udp_sd);
    ck_assert_ptr_eq(ts, &s.udpsockets[SOCKET_UNMARK(udp_sd)]);
    ts = wolfIP_socket_from_fd(&s, icmp_sd);
    ck_assert_ptr_eq(ts, &s.icmpsockets[SOCKET_UNMARK(icmp_sd)]);
}
END_TEST

START_TEST(test_tcp_input_syn_rcvd_ack_wrong_flags)
{
    struct wolfIP s;
    int listen_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_tcp_seg ackseg;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    listen_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(listen_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(1234);
    sin.sin_addr.s_addr = ee32(0x0A000001U);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_sd, 1), 0);

    inject_tcp_syn(&s, TEST_PRIMARY_IF, 0x0A000001U, 1234);
    ts = &s.tcpsockets[SOCKET_UNMARK(listen_sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);

    memset(&ackseg, 0, sizeof(ackseg));
    ackseg.ip.ttl = 64;
    ackseg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    ackseg.dst_port = ee16(ts->src_port);
    ackseg.src_port = ee16(ts->dst_port);
    ackseg.hlen = TCP_HEADER_LEN << 2;
    ackseg.flags = 0x18;
    tcp_input(&s, TEST_PRIMARY_IF, &ackseg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);
}
END_TEST

START_TEST(test_tcp_input_established_ack_only_returns)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_tcp_seg seg;

    wolfIP_init(&s);
    mock_link_init(&s);

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->src_port = 1234;
    ts->dst_port = 4321;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    memset(&seg, 0, sizeof(seg));
    seg.ip.ttl = 64;
    seg.ip.len = ee16(IP_HEADER_LEN + TCP_HEADER_LEN);
    seg.dst_port = ee16(ts->src_port);
    seg.src_port = ee16(ts->dst_port);
    seg.hlen = TCP_HEADER_LEN << 2;
    seg.flags = 0x10;

    tcp_input(&s, TEST_PRIMARY_IF, &seg, (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN));
    ck_assert_int_eq(ts->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

START_TEST(test_tcp_sock_close_state_transitions)
{
    struct wolfIP s;
    struct tsocket *ts;
    int sd;

    wolfIP_init(&s);
    mock_link_init(&s);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_FIN_WAIT_1);

    ts->sock.tcp.state = TCP_CLOSE_WAIT;
    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_LAST_ACK);

    ts->sock.tcp.state = TCP_FIN_WAIT_2;
    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_TIME_WAIT);

    ts->sock.tcp.state = TCP_CLOSING;
    ck_assert_int_eq(wolfIP_sock_close(&s, sd), -WOLFIP_EAGAIN);
    ck_assert_int_eq(ts->sock.tcp.state, TCP_TIME_WAIT);

    ts->sock.tcp.state = TCP_LISTEN;
    ck_assert_int_eq(wolfIP_sock_close(&s, sd), 0);
    ck_assert_int_eq(ts->proto, 0);
}
END_TEST
START_TEST(test_fifo_push_wrap) {
    struct fifo f;
    uint8_t buffer[100];
    uint8_t data[] = {1, 2, 3, 4};
    int ret;
    struct pkt_desc *desc;
    fifo_init(&f, buffer, sizeof(buffer));
    fifo_push(&f, data, sizeof(data)); // Add data to FIFO

    // Pop the data to make space
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);

    // Push data to wrap around the buffer
    ret = fifo_push(&f, data, sizeof(data));
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(desc->len, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data));
}
END_TEST

START_TEST(test_fifo_push_wrap_multiple) {
    struct fifo f;
    uint8_t data[] = {1, 2, 3, 4};
    uint8_t data2[] = {5, 6, 7, 8, 9};
    int ret;
    struct pkt_desc *desc;
    fifo_init(&f, mem, memsz);
    fifo_push(&f, data, sizeof(data)); // Add data to FIFO

    // Pop the data to make space
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);

    // Push data to wrap around the buffer
    ret = fifo_push(&f, data, sizeof(data));
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(desc->len, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data));

    // Push more data to wrap around the buffer
    ret = fifo_push(&f, data2, sizeof(data2));
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(fifo_len(&f), sizeof(data2) + sizeof(data) + 2 * sizeof(struct pkt_desc));
}
END_TEST

START_TEST(test_fifo_space_wrap_sets_hwrap)
{
    struct fifo f;
    size_t total = sizeof(struct pkt_desc) + LINK_MTU + 64;
    uint8_t *buf = malloc(total);
    uint32_t space;
    uint32_t expected;

    ck_assert_ptr_nonnull(buf);
    fifo_init(&f, buf, (uint32_t)total);
    f.head = (uint32_t)(total - 8);
    f.tail = (uint32_t)(sizeof(struct pkt_desc) + LINK_MTU + 8);
    f.h_wrap = 0;

    space = fifo_space(&f);
    expected = (uint32_t)total - (f.head - f.tail);
    ck_assert_uint_eq(f.h_wrap, 0);
    ck_assert_uint_eq(space, expected);

    free(buf);
}
END_TEST

START_TEST(test_fifo_space_wrap_returns_zero)
{
    struct fifo f;
    size_t total = sizeof(struct pkt_desc) + LINK_MTU + 32;
    uint8_t *buf = malloc(total);
    uint32_t space;

    ck_assert_ptr_nonnull(buf);
    fifo_init(&f, buf, (uint32_t)total);
    f.head = (uint32_t)(total - 8);
    f.tail = 8;
    f.h_wrap = 0;

    space = fifo_space(&f);
    ck_assert_uint_eq(space, (uint32_t)total - (f.head - f.tail));
    ck_assert_uint_eq(f.h_wrap, 0);

    free(buf);
}
END_TEST

START_TEST(test_fifo_peek_wrap_to_start)
{
    struct fifo f;
    size_t total = sizeof(struct pkt_desc) + LINK_MTU + 8;
    uint8_t *buf = malloc(total);
    struct pkt_desc *desc;
    struct pkt_desc *peeked;

    ck_assert_ptr_nonnull(buf);
    fifo_init(&f, buf, (uint32_t)total);
    f.head = 8;
    f.tail = 4;
    f.h_wrap = 8;

    desc = (struct pkt_desc *)buf;
    memset(desc, 0, sizeof(*desc));
    desc->len = 1;
    desc->pos = 0;

    /* When tail crosses h_wrap, peek should wrap to the start and return
     * the first descriptor at offset 0. */
    peeked = fifo_peek(&f);
    ck_assert_ptr_eq(peeked, desc);

    free(buf);
}
END_TEST

START_TEST(test_fifo_len_with_hwrap)
{
    struct fifo f;
    uint8_t buf[256];

    fifo_init(&f, buf, sizeof(buf));
    f.head = 64;
    f.tail = 128;
    f.h_wrap = 200;

    ck_assert_uint_eq(fifo_len(&f), f.h_wrap - f.tail + f.head);
}
END_TEST

START_TEST(test_fifo_peek_aligns_tail)
{
    struct fifo f;
    uint8_t buf[64];
    struct pkt_desc *desc;
    struct pkt_desc *peeked;

    fifo_init(&f, buf, sizeof(buf));
    f.tail = 2;
    f.head = 16;
    desc = (struct pkt_desc *)(buf + 4);
    memset(desc, 0, sizeof(*desc));
    desc->len = 1;
    desc->pos = 4;

    /* Peek aligns tail to 4-byte boundary before reading the descriptor. */
    peeked = fifo_peek(&f);
    ck_assert_ptr_eq(peeked, desc);
    ck_assert_uint_eq(f.tail, 4);
}
END_TEST

START_TEST(test_fifo_next_wraps_to_start)
{
    struct fifo f;
    size_t total = sizeof(struct pkt_desc) + LINK_MTU + 8;
    uint8_t *buf = malloc(total);
    struct pkt_desc *desc;
    struct pkt_desc *next;
    uint32_t h_wrap = 64;
    uint32_t len;

    ck_assert_ptr_nonnull(buf);
    fifo_init(&f, buf, (uint32_t)total);
    desc = (struct pkt_desc *)buf;
    memset(desc, 0, sizeof(*desc));
    desc->pos = 0;
    len = h_wrap - desc->pos;
    desc->len = len - sizeof(struct pkt_desc);
    f.head = 128;
    f.h_wrap = h_wrap;

    next = fifo_next(&f, desc);
    ck_assert_ptr_eq(next, (struct pkt_desc *)buf);

    free(buf);
}
END_TEST

START_TEST(test_fifo_space_head_lt_tail)
{
    struct fifo f;
    size_t total = sizeof(struct pkt_desc) + LINK_MTU + 128;
    uint8_t *buf = malloc(total);
    uint32_t space;

    ck_assert_ptr_nonnull(buf);
    fifo_init(&f, buf, (uint32_t)total);
    f.head = 50;
    f.tail = 200;
    f.h_wrap = 0;

    space = fifo_space(&f);
    ck_assert_uint_eq(space, f.tail - f.head);

    free(buf);
}
END_TEST

START_TEST(test_fifo_space_with_hwrap)
{
    struct fifo f;
    uint8_t buf[512];
    uint32_t space;

    fifo_init(&f, buf, sizeof(buf));
    f.head = 50;
    f.tail = 200;
    f.h_wrap = 300;

    space = fifo_space(&f);
    ck_assert_uint_eq(space, f.tail - f.head);
}
END_TEST

START_TEST(test_fifo_space_hwrap_head_hits_wrap)
{
    struct fifo f;
    uint8_t buf[512];
    uint32_t space;

    fifo_init(&f, buf, sizeof(buf));
    f.head = 300;
    f.tail = 200;
    f.h_wrap = 300;

    space = fifo_space(&f);
    ck_assert_uint_eq(space, 0);
}
END_TEST

START_TEST(test_fifo_space_hwrap_head_ge_tail_returns_zero)
{
    struct fifo f;
    uint8_t buf[512];
    uint32_t space;

    fifo_init(&f, buf, sizeof(buf));
    f.head = 220;
    f.tail = 200;
    f.h_wrap = 300;

    space = fifo_space(&f);
    ck_assert_uint_eq(space, 0);
}
END_TEST

START_TEST(test_fifo_push_no_contiguous_space_even_with_space)
{
    struct fifo f;
    uint8_t buf[4096];
    uint8_t payload[1592];
    int ret;

    fifo_init(&f, buf, sizeof(buf));
    f.head = 2506;
    f.tail = 1500;
    f.h_wrap = 0;

    memset(payload, 0xCD, sizeof(payload));
    ret = fifo_push(&f, payload, sizeof(payload));
    ck_assert_int_eq(ret, -1);
    ck_assert_uint_eq(f.h_wrap, 0);
}
END_TEST

START_TEST(test_fifo_next_hits_hwrap)
{
    struct fifo f;
    uint8_t buf[256];
    struct pkt_desc *desc;
    struct pkt_desc *next;
    uint32_t pos = 20;
    uint32_t h_wrap = 64;
    uint32_t len;

    fifo_init(&f, buf, sizeof(buf));
    f.head = 120;
    f.h_wrap = h_wrap;

    desc = (struct pkt_desc *)(buf + pos);
    memset(desc, 0, sizeof(*desc));
    len = h_wrap - pos;
    if (len < sizeof(struct pkt_desc))
        len = sizeof(struct pkt_desc);
    desc->len = len - sizeof(struct pkt_desc);
    while ((desc->pos + sizeof(struct pkt_desc) + desc->len) % 4)
        desc->len++;
    desc->pos = pos;

    next = fifo_next(&f, desc);
    ck_assert_ptr_eq(next, (struct pkt_desc *)buf);
}
END_TEST

START_TEST(test_fifo_next_aligned_len_exceeds_size_returns_null)
{
    struct fifo f;
    uint8_t buf[128];
    struct pkt_desc *desc;
    struct pkt_desc *next;
    uint32_t sz = (uint32_t)(sizeof(struct pkt_desc) + 1U);
    uint32_t pos = 1U;
    uint32_t adv;

    fifo_init(&f, buf, sz);
    f.head = 8;
    f.h_wrap = 0;

    desc = (struct pkt_desc *)(buf + pos);
    memset(desc, 0, sizeof(*desc));
    desc->pos = pos;
    desc->len = 1U; /* accepted by precheck: <= f.size - sizeof(pkt_desc). */

    adv = (uint32_t)(sizeof(struct pkt_desc) + desc->len);
    while ((pos + adv) % 4U)
        adv++;
    ck_assert_uint_gt(adv, (f.size - pos));

    /* Alignment padding would make traversal exceed queue bounds. */
    next = fifo_next(&f, desc);
    ck_assert_ptr_null(next);
}
END_TEST

START_TEST(test_fifo_len_tail_gt_head_no_hwrap)
{
    struct fifo f;
    uint8_t buf[256];

    fifo_init(&f, buf, sizeof(buf));
    f.head = 20;
    f.tail = 100;
    f.h_wrap = 0;

    ck_assert_uint_eq(fifo_len(&f), f.size - (f.tail - f.head));
}
END_TEST

START_TEST(test_fifo_pop_wrap_to_start)
{
    struct fifo f;
    size_t total = sizeof(struct pkt_desc) + LINK_MTU + 8;
    uint8_t *buf = malloc(total);
    struct pkt_desc *desc;
    struct pkt_desc *popped;

    ck_assert_ptr_nonnull(buf);
    fifo_init(&f, buf, (uint32_t)total);
    f.head = 8;
    f.tail = 4;
    f.h_wrap = 8;

    desc = (struct pkt_desc *)buf;
    memset(desc, 0, sizeof(*desc));
    desc->len = 1;
    desc->pos = 0;

    /* Pop should wrap to start and return the descriptor at offset 0. */
    popped = fifo_pop(&f);
    ck_assert_ptr_eq(popped, desc);

    free(buf);
}
END_TEST

START_TEST(test_fifo_next_success) {
    struct fifo f;
    uint8_t data1[] = {1, 2, 3, 4};
    uint8_t data2[] = {5, 6, 7, 8, 9};
    struct pkt_desc *desc;
    struct pkt_desc *next_desc;

    fifo_init(&f, mem, memsz);

    // Add two packets to the FIFO
    fifo_push(&f, data1, sizeof(data1));
    fifo_push(&f, data2, sizeof(data2));
    ck_assert_int_eq(fifo_len(&f), sizeof(data1) + sizeof(data2) + 2 * sizeof(struct pkt_desc));

    // Get the first packet descriptor
    desc = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc);

    // Get the next packet descriptor using fifo_next
    next_desc = fifo_next(&f, desc);
    ck_assert_ptr_nonnull(next_desc); // Ensure next descriptor is valid
    ck_assert_int_eq(next_desc->len, sizeof(data2)); // Check length of next packet
}

START_TEST(test_fifo_next_empty_fifo) {
    struct fifo f;
    struct pkt_desc *desc;
    struct pkt_desc *next_desc;
    fifo_init(&f, mem, memsz);

    // Start with an empty FIFO
    desc = NULL;
    next_desc = fifo_next(&f, desc);
    ck_assert_ptr_eq(next_desc, NULL); // Ensure next returns NULL on empty FIFO
}

START_TEST(test_fifo_next_end_of_fifo) {
    struct fifo f;
    uint8_t data[] = {1, 2, 3, 4};
    struct pkt_desc *desc;
    struct pkt_desc *next_desc;

    fifo_init(&f, mem, memsz);
    fifo_push(&f, data, sizeof(data));

    desc = fifo_peek(&f); // Get first packet
    fifo_pop(&f); // Simulate removing the packet
    next_desc = fifo_next(&f, desc);
    ck_assert_ptr_eq(next_desc, NULL); // Should return NULL as there are no more packets
}
END_TEST
START_TEST(test_queue_init) {
    struct queue q;
    queue_init(&q, mem, memsz, 0x12345678);
    ck_assert_int_eq(q.size, memsz);
    ck_assert_ptr_eq(q.data, mem);
    ck_assert_int_eq(q.head, 0);
    ck_assert_int_eq(q.tail, 0);
    ck_assert_int_eq(q.seq_base, 0x12345678);

}
END_TEST

START_TEST(test_queue_space_empty) {
    struct queue q;

    queue_init(&q, mem, memsz, 0x12345678);
    ck_assert_int_eq(queue_space(&q), memsz - 1);  // Reserve one byte to disambiguate full/empty

}
END_TEST

START_TEST(test_queue_len_empty) {
    struct queue q;

    queue_init(&q, mem, memsz, 0x12345678);
    ck_assert_int_eq(queue_len(&q), 0);  // No bytes should be in use

}
END_TEST

START_TEST(test_queue_partial_fill) {
    struct queue q;
    queue_init(&q, mem, memsz, 0x12345678);
    q.head = 256;  // Simulate adding 256 bytes of data
    ck_assert_int_eq(queue_space(&q), memsz - 257);
    ck_assert_int_eq(queue_len(&q), 256);

}
END_TEST

START_TEST(test_queue_wrap_around) {
    struct queue q;
    queue_init(&q, mem, memsz, 0x12345678);
    q.head = 800;
    q.tail = 200;  // Head has wrapped around, so 600 bytes are filled
    ck_assert_int_eq(queue_space(&q), q.size - 601);
    ck_assert_int_eq(queue_len(&q), 600);  // 600 bytes filled
}
END_TEST

START_TEST(test_queue_insert_empty) {
    struct queue q;
    uint8_t data[] = {1, 2, 3, 4};
    int res;
    queue_init(&q, mem, memsz, 0x12345678);

    res = queue_insert(&q, data, 0, sizeof(data));
    ck_assert_int_eq(res, 0);
    ck_assert_int_eq(queue_len(&q), sizeof(data));
    ck_assert_int_eq(q.head, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)q.data, data, sizeof(data));
}
END_TEST

START_TEST(test_queue_insert_sequential) {
    struct queue q;
    uint8_t data1[] = {1, 2};
    uint8_t data2[] = {3, 4};
    int res1;
    int res2;
    queue_init(&q, mem, memsz, 0x12345678);

    res1 = queue_insert(&q, data1, 0, sizeof(data1));
    res2 = queue_insert(&q, data2, 2, sizeof(data2));
    ck_assert_int_eq(res1, 0);
    ck_assert_int_eq(res2, 0);
    ck_assert_int_eq(queue_len(&q), sizeof(data1) + sizeof(data2));
    ck_assert_mem_eq((const uint8_t *)q.data, data1, sizeof(data1));
    ck_assert_mem_eq((uint8_t *)q.data + 2, data2, sizeof(data2));
}
END_TEST

START_TEST(test_queue_insert_negative_diff)
{
    struct queue q;
    uint8_t mem[32];
    uint8_t data[4] = {1, 2, 3, 4};

    queue_init(&q, mem, sizeof(mem), 100);
    ck_assert_int_eq(queue_insert(&q, data, 100, sizeof(data)), 0);
    ck_assert_int_eq(queue_insert(&q, data, 90, sizeof(data)), -1);
}
END_TEST

START_TEST(test_queue_insert_wraparound_contiguous_and_old_rejected)
{
    struct queue q;
    uint8_t mem[64];
    uint8_t data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t out[32];
    uint32_t next_seq;

    queue_init(&q, mem, sizeof(mem), 0xFFFFFFFCU);
    ck_assert_int_eq(queue_insert(&q, data, 0xFFFFFFFCU, sizeof(data)), 0);
    next_seq = 0xFFFFFFFCU + (uint32_t)sizeof(data);
    ck_assert_int_eq(queue_insert(&q, data, next_seq, sizeof(data)), 0);
    ck_assert_int_eq(queue_len(&q), (int)(sizeof(data) * 2));

    /* A sequence behind base after wrap must not be accepted. */
    ck_assert_int_eq(queue_insert(&q, data, 0xFFFFFFF0U, sizeof(data)), -1);
    ck_assert_int_eq(queue_pop(&q, out, sizeof(out)), (int)(sizeof(data) * 2));
}
END_TEST

START_TEST(test_queue_insert_pos_gt_size)
{
    struct queue q;
    uint8_t mem[16];
    uint8_t data[4] = {1, 2, 3, 4};

    queue_init(&q, mem, sizeof(mem), 0);
    ck_assert_int_eq(queue_insert(&q, data, 0, sizeof(data)), 0);
    ck_assert_int_eq(queue_insert(&q, data, 32, sizeof(data)), -1);
}
END_TEST

START_TEST(test_queue_insert_ancient_data)
{
    struct queue q;
    uint8_t mem[32];
    uint8_t data[8] = {0};
    uint8_t out[4];

    queue_init(&q, mem, sizeof(mem), 0);
    ck_assert_int_eq(queue_insert(&q, data, 0, sizeof(data)), 0);
    ck_assert_int_eq(queue_pop(&q, out, sizeof(out)), (int)sizeof(out));
    ck_assert_int_eq(queue_insert(&q, data, 5, sizeof(data)), 0);
}
END_TEST

START_TEST(test_queue_insert_wrap)
{
    struct queue q;
    uint8_t mem[16];
    uint8_t first[12];
    uint8_t second[3];
    uint8_t out[16];

    memset(first, 0xAB, sizeof(first));
    memset(second, 0xCD, sizeof(second));
    queue_init(&q, mem, sizeof(mem), 0);
    ck_assert_int_eq(queue_insert(&q, first, 0, sizeof(first)), 0);
    ck_assert_int_eq(queue_pop(&q, out, 10), 10);
    ck_assert_int_eq(queue_insert(&q, second, 12, sizeof(second)), 0);
    ck_assert_uint_eq(queue_len(&q), 5);
    ck_assert_int_eq(queue_pop(&q, out, 2), 2);
    ck_assert_mem_eq(out, first + 10, 2);
    ck_assert_int_eq(queue_pop(&q, out, 3), 3);
    ck_assert_mem_eq(out, second, 3);
}
END_TEST

START_TEST(test_queue_space_wrap)
{
    struct queue q;
    uint8_t mem[16];

    queue_init(&q, mem, sizeof(mem), 0);
    q.head = 4;
    q.tail = 12;
    ck_assert_uint_eq(queue_space(&q), (q.tail - q.head) - 1);
}
END_TEST

START_TEST(test_queue_full_state_not_empty_and_drains_data)
{
    struct queue q;
    uint8_t mem[16];
    uint8_t data[15];
    uint8_t out[15];
    int i;

    for (i = 0; i < (int)sizeof(data); i++)
        data[i] = (uint8_t)(i + 1);
    queue_init(&q, mem, sizeof(mem), 1000);
    ck_assert_int_eq(queue_insert(&q, data, 1000, sizeof(data)), 0);
    ck_assert_uint_eq(queue_len(&q), sizeof(data));
    ck_assert_uint_eq(queue_space(&q), 0);
    ck_assert_int_eq(queue_pop(&q, out, sizeof(out)), (int)sizeof(out));
    ck_assert_mem_eq(out, data, sizeof(data));
    ck_assert_uint_eq(queue_len(&q), 0);
    ck_assert_uint_eq(queue_space(&q), sizeof(mem) - 1);
}
END_TEST

START_TEST(test_poll_tcp_residual_window_gates_data_segment)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xef};
    struct pkt_desc *desc;
    struct pkt_desc *sent_desc;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.ack = 20;
    ts->sock.tcp.last_ack = 0;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.cwnd = 32;
    ts->sock.tcp.peer_rwnd = 20;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* Keep 12 bytes in-flight, then queue 16 new bytes. Residual window is 8. */
    ck_assert_int_eq(enqueue_tcp_tx(ts, 12, 0x18), 0);
    sent_desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(sent_desc);
    sent_desc->flags |= PKT_FLAG_SENT;
    ts->sock.tcp.bytes_in_flight = 12;

    ts->sock.tcp.seq = 12;
    ck_assert_int_eq(enqueue_tcp_tx(ts, 16, 0x18), 0);
    desc = fifo_next(&ts->sock.tcp.txbuf, sent_desc);
    ck_assert_ptr_nonnull(desc);

    (void)wolfIP_poll(&s, 200);

    ck_assert_uint_eq(last_frame_sent_size, 0);
    ck_assert_ptr_eq(fifo_next(&ts->sock.tcp.txbuf, sent_desc), desc);
    ck_assert_int_eq(desc->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_poll_tcp_residual_window_allows_exact_fit)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *sent_desc;
    struct pkt_desc *data_desc;
    ip4 local_ip = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xf0};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    ts = &s.tcpsockets[0];
    memset(ts, 0, sizeof(*ts));
    ts->proto = WI_IPPROTO_TCP;
    ts->S = &s;
    ts->sock.tcp.state = TCP_ESTABLISHED;
    ts->local_ip = local_ip;
    ts->remote_ip = remote_ip;
    ts->if_idx = TEST_PRIMARY_IF;
    ts->src_port = 1111;
    ts->dst_port = 2222;
    ts->sock.tcp.ack = 20;
    ts->sock.tcp.last_ack = 0;
    ts->sock.tcp.rto = 100;
    ts->sock.tcp.cwnd = 32;
    ts->sock.tcp.peer_rwnd = 20;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);

    /* Keep 4 bytes in-flight, then queue 16 bytes: exact residual-window fit. */
    ck_assert_int_eq(enqueue_tcp_tx(ts, 4, 0x18), 0);
    sent_desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(sent_desc);
    sent_desc->flags |= PKT_FLAG_SENT;
    ts->sock.tcp.bytes_in_flight = 4;

    ts->sock.tcp.seq = 4;
    ck_assert_int_eq(enqueue_tcp_tx(ts, 16, 0x18), 0);
    data_desc = fifo_next(&ts->sock.tcp.txbuf, sent_desc);
    ck_assert_ptr_nonnull(data_desc);

    (void)wolfIP_poll(&s, 200);

    ck_assert_uint_gt(last_frame_sent_size, 0);
    ck_assert_int_ne(data_desc->flags & PKT_FLAG_SENT, 0);
}
END_TEST

START_TEST(test_queue_insert_len_gt_size)
{
    struct queue q;
    uint8_t mem[8];
    uint8_t data[16] = {0};

    queue_init(&q, mem, sizeof(mem), 0);
    ck_assert_int_eq(queue_insert(&q, data, 0, sizeof(data)), -1);
}
END_TEST

START_TEST(test_queue_pop) {
    struct queue q;
    uint8_t data[] = {5, 6, 7, 8};
    uint8_t out[4];
    int len;
    queue_init(&q, mem, memsz, 0x12345678);

    queue_insert(&q, data, 0, sizeof(data));
    len = queue_pop(&q, out, sizeof(out));
    ck_assert_int_eq(len, sizeof(out));
    ck_assert_mem_eq(out, data, sizeof(data));
    ck_assert_int_eq(queue_len(&q), 0);
    ck_assert_int_eq(q.tail, 4);
}
END_TEST

START_TEST(test_queue_pop_wraparound) {
    struct queue q;
    uint8_t data[] = {9, 10, 11, 12};
    uint8_t out[4];
    int len;
    queue_init(&q, mem, memsz, 0x12345678);

    q.head = memsz - 1;
    q.tail = memsz - 1;
    queue_insert(&q, data, 0, sizeof(data));
    len = queue_pop(&q, out, sizeof(out));
    ck_assert_int_eq(len, sizeof(out));
    ck_assert_mem_eq(out, data, sizeof(data));
    ck_assert_int_eq(queue_len(&q), 0);
}
END_TEST


/* Utils */
START_TEST(test_insert_timer) {
    struct wolfIP_timer tmr1 = { .expires = 100 };
    struct wolfIP_timer tmr2 = { .expires = 50 };
    struct wolfIP_timer tmr3 = { .expires = 200 };
    int id1;
    int id2;
    int id3;

    reset_heap();

    id1 = timers_binheap_insert(&heap, tmr1);
    id2 = timers_binheap_insert(&heap, tmr2);
    id3 = timers_binheap_insert(&heap, tmr3);

    ck_assert_int_eq(heap.size, 3);
    ck_assert_int_lt(heap.timers[0].expires, heap.timers[1].expires);
    ck_assert_int_lt(heap.timers[0].expires, heap.timers[2].expires);
    ck_assert_int_ne(id1, id2);
    ck_assert_int_ne(id2, id3);
}
END_TEST

START_TEST(test_timer_insert_skips_zero_head)
{
    struct timers_binheap local = {0};
    struct wolfIP_timer tmr = {0};

    local.size = 1;
    local.timers[0].expires = 0;
    local.timers[0].id = 99;

    tmr.expires = 10;
    tmr.cb = test_timer_cb;

    timers_binheap_insert(&local, tmr);
    ck_assert_uint_eq(local.size, 1);
    ck_assert_uint_eq(local.timers[0].expires, 10);
}
END_TEST

START_TEST(test_timer_cancel_existing_and_missing)
{
    struct timers_binheap local = {0};
    struct wolfIP_timer tmr = {0};
    uint32_t id;

    tmr.expires = 5;
    tmr.cb = test_timer_cb;
    id = timers_binheap_insert(&local, tmr);
    ck_assert_uint_eq(local.timers[0].expires, 5);

    timer_binheap_cancel(&local, id);
    ck_assert_uint_eq(local.timers[0].expires, 0);

    timer_binheap_cancel(&local, id + 1);
}
END_TEST

START_TEST(test_pop_timer) {
    struct wolfIP_timer tmr1 = { .expires = 300 };
    struct wolfIP_timer tmr2 = { .expires = 100 };
    struct wolfIP_timer tmr3 = { .expires = 200 };
    struct wolfIP_timer popped;

    reset_heap();

    timers_binheap_insert(&heap, tmr1);
    timers_binheap_insert(&heap, tmr2);
    timers_binheap_insert(&heap, tmr3);

    popped = timers_binheap_pop(&heap);
    ck_assert_int_eq(popped.expires, 100);
    ck_assert_int_eq(heap.size, 2);
    ck_assert_int_lt(heap.timers[0].expires, heap.timers[1].expires);
}
END_TEST

START_TEST(test_is_timer_expired) {
    struct wolfIP_timer tmr = { .expires = 150 };

    reset_heap();
    timers_binheap_insert(&heap, tmr);

    ck_assert_int_eq(is_timer_expired(&heap, 100), 0);
    ck_assert_int_eq(is_timer_expired(&heap, 150), 1);
    ck_assert_int_eq(is_timer_expired(&heap, 200), 1);
}
END_TEST

START_TEST(test_cancel_timer) {
    struct wolfIP_timer tmr1 = { .expires = 100 };
    struct wolfIP_timer tmr2 = { .expires = 200 };
    int id1;
    int id2;
    struct wolfIP_timer popped;

    reset_heap();

    id1 = timers_binheap_insert(&heap, tmr1);
    id2 = timers_binheap_insert(&heap, tmr2);
    (void)id2;

    timer_binheap_cancel(&heap, id1);
    ck_assert_int_eq(heap.timers[0].expires, 0);  // tmr1 canceled

    popped = timers_binheap_pop(&heap);
    ck_assert_int_eq(popped.expires, 200);  // Only tmr2 should remain
    ck_assert_int_eq(heap.size, 0);
}
END_TEST

START_TEST(test_timer_pop_skips_zero_expires)
{
    struct timers_binheap h;
    struct wolfIP_timer tmr1 = { .expires = 50 };
    struct wolfIP_timer tmr2 = { .expires = 10 };
    struct wolfIP_timer popped;

    memset(&h, 0, sizeof(h));
    tmr1.id = timers_binheap_insert(&h, tmr1);
    tmr2.id = timers_binheap_insert(&h, tmr2);
    timer_binheap_cancel(&h, tmr2.id);

    popped = timers_binheap_pop(&h);
    ck_assert_uint_ne(popped.expires, 0);
}
END_TEST

START_TEST(test_timer_pop_reorders_heap)
{
    struct timers_binheap h;
    struct wolfIP_timer t1 = { .expires = 30 };
    struct wolfIP_timer t2 = { .expires = 20 };
    struct wolfIP_timer t3 = { .expires = 10 };
    struct wolfIP_timer popped;

    memset(&h, 0, sizeof(h));
    timers_binheap_insert(&h, t1);
    timers_binheap_insert(&h, t2);
    timers_binheap_insert(&h, t3);

    popped = timers_binheap_pop(&h);
    ck_assert_uint_eq(popped.expires, 10);
}
END_TEST

START_TEST(test_timer_pop_right_child_swap)
{
    struct timers_binheap h;
    struct wolfIP_timer popped;

    memset(&h, 0, sizeof(h));
    h.size = 4;
    h.timers[0].expires = 10;
    h.timers[1].expires = 40;
    h.timers[2].expires = 20;
    h.timers[3].expires = 30;

    popped = timers_binheap_pop(&h);
    ck_assert_uint_eq(popped.expires, 10);
    ck_assert_uint_eq(h.size, 3);
    ck_assert_uint_eq(h.timers[0].expires, 20);
}
END_TEST

START_TEST(test_timer_pop_break_when_root_small)
{
    struct timers_binheap h;
    struct wolfIP_timer popped;

    memset(&h, 0, sizeof(h));
    h.size = 4;
    h.timers[0].expires = 10;
    h.timers[1].expires = 20;
    h.timers[2].expires = 30;
    h.timers[3].expires = 15;

    popped = timers_binheap_pop(&h);
    ck_assert_uint_eq(popped.expires, 10);
    ck_assert_uint_eq(h.size, 3);
    ck_assert_uint_eq(h.timers[0].expires, 15);
}
END_TEST

START_TEST(test_is_timer_expired_skips_zero_head)
{
    struct timers_binheap h;

    memset(&h, 0, sizeof(h));
    h.size = 2;
    h.timers[0].expires = 0;
    h.timers[1].expires = 50;

    ck_assert_int_eq(is_timer_expired(&h, 10), 0);
    ck_assert_uint_eq(h.size, 0);
}
END_TEST


/* Arp suite */
START_TEST(test_arp_request_basic)
{
    struct wolfIP s;
    struct arp_packet *arp;
    uint32_t target_ip = 0xC0A80002; /* 192.168.0.2 */

    wolfIP_init(&s);
    mock_link_init(&s);
    s.last_tick = 1000;
    arp_request(&s, TEST_PRIMARY_IF, target_ip);
    ck_assert_int_eq(last_frame_sent_size, sizeof(struct arp_packet));
    arp = (struct arp_packet *)last_frame_sent;
    ck_assert_mem_eq(arp->eth.dst, "\xff\xff\xff\xff\xff\xff", 6);
    ck_assert_mem_eq(arp->eth.src, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    ck_assert_int_eq(arp->eth.type, ee16(0x0806));
    ck_assert_int_eq(arp->htype, ee16(1));
    ck_assert_int_eq(arp->ptype, ee16(0x0800));
    ck_assert_int_eq(arp->hlen, 6);
    ck_assert_int_eq(arp->plen, 4);
    ck_assert_int_eq(arp->opcode, ee16(ARP_REQUEST));
    ck_assert_mem_eq(arp->sma, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    ck_assert_int_eq(arp->sip, ee32(s.ipconf[TEST_PRIMARY_IF].ip));
    ck_assert_mem_eq(arp->tma, "\x00\x00\x00\x00\x00\x00", 6);
    ck_assert_int_eq(arp->tip, ee32(target_ip));
}
END_TEST

START_TEST(test_arp_request_throttle)
{
    struct wolfIP s;
    uint32_t target_ip = 0xC0A80002; /*192.168.0.2*/

    wolfIP_init(&s);
    mock_link_init(&s);
    s.last_tick = 1000;
    s.arp.last_arp[TEST_PRIMARY_IF] = 880;
    last_frame_sent_size = 0;
    arp_request(&s, TEST_PRIMARY_IF, target_ip);
    ck_assert_int_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_request_target_ip) {
    struct wolfIP s;
    uint32_t target_ip = 0xC0A80002;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.last_tick = 1000;
    arp_request(&s, TEST_PRIMARY_IF, target_ip);
    ck_assert_int_eq(((struct arp_packet *)(last_frame_sent))->tip, ee32(target_ip));
}
END_TEST

START_TEST(test_arp_request_handling) {
    struct arp_packet arp_req;
    struct arp_packet *arp_reply;
    uint32_t req_ip = 0xC0A80002; // 192.168.0.2
    uint32_t device_ip = 0xC0A80001; // 192.168.0.1
    uint8_t req_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    //uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    struct wolfIP s;

    memset(&arp_req, 0, sizeof(arp_req));
    wolfIP_init(&s);
    mock_link_init(&s);
    s.ipconf[TEST_PRIMARY_IF].ip = device_ip;

    /* Prepare ARP request */
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(req_ip);
    memcpy(arp_req.sma, req_mac, 6);
    arp_req.tip = ee32(device_ip);

    /* Call arp_recv with the ARP request */
    arp_recv(&s, TEST_PRIMARY_IF, &arp_req, sizeof(arp_req));
    wolfIP_poll(&s, 1000);
    wolfIP_poll(&s, 1001);
    wolfIP_poll(&s, 1002);

    /* Check if ARP table updated with requester's MAC and IP */
    /* TODO */
    //ck_assert_int_eq(arp_lookup(&s, req_ip, mac), 0);
    //ck_assert_mem_eq(mac, req_mac, 6);

    /* Check if an ARP reply was generated */
    arp_reply = (struct arp_packet *)last_frame_sent;
    ck_assert_int_eq(last_frame_sent_size, sizeof(struct arp_packet));
    ck_assert_int_eq(arp_reply->opcode, ee16(ARP_REPLY));
    ck_assert_mem_eq(arp_reply->sma, s.ll_dev[TEST_PRIMARY_IF].mac, 6);     // source MAC
    ck_assert_int_eq(arp_reply->sip, ee32(device_ip));     // source IP
    ck_assert_mem_eq(arp_reply->tma, req_mac, 6);          // target MAC
    ck_assert_int_eq(arp_reply->tip, ee32(req_ip));        // target IP
}
END_TEST

START_TEST(test_arp_reply_handling) {
    struct arp_packet arp_reply;
    uint32_t reply_ip = 0xC0A80003; // 192.168.0.3
    uint8_t reply_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    uint8_t new_mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    struct wolfIP s;

    memset(&arp_reply, 0, sizeof(arp_reply));
    wolfIP_init(&s);
    mock_link_init(&s);

    /* Prepare ARP reply */
    arp_reply.opcode = ee16(ARP_REPLY);
    arp_reply.sip = ee32(reply_ip);
    memcpy(arp_reply.sma, reply_mac, 6);

    /* Call arp_recv with the ARP reply */
    arp_recv(&s, TEST_PRIMARY_IF, &arp_reply, sizeof(arp_reply));

    /* Check if ARP table updated with reply IP and MAC */
    ck_assert_int_eq(s.arp.neighbors[0].ip, reply_ip);
    ck_assert_mem_eq(s.arp.neighbors[0].mac, reply_mac, 6);

    /* Update same IP with a different MAC address */
    memcpy(arp_reply.sma, new_mac, 6);
    arp_recv(&s, TEST_PRIMARY_IF, &arp_reply, sizeof(arp_reply));

    /* Check if ARP table updates with new MAC */
    ck_assert_mem_eq(s.arp.neighbors[0].mac, new_mac, 6);
}
END_TEST

START_TEST(test_arp_lookup_success) {
    uint8_t found_mac[6];
    uint32_t ip = 0xC0A80002;
    const uint8_t mock_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    struct wolfIP s;
    int result;

    wolfIP_init(&s);
    mock_link_init(&s);

    /* Add a known IP-MAC pair */
    s.arp.neighbors[0].ip = ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, mock_mac, 6);

    /* Test arp_lookup */
    result = arp_lookup(&s, TEST_PRIMARY_IF, ip, found_mac);
    ck_assert_int_eq(result, 0);
    ck_assert_mem_eq(found_mac, mock_mac, 6);
}
END_TEST

START_TEST(test_arp_lookup_failure) {
    uint8_t found_mac[6];
    uint32_t ip = 0xC0A80004;
    struct wolfIP s;
    int result;
    uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};

    wolfIP_init(&s);
    mock_link_init(&s);

    /* Ensure arp_lookup fails for unknown IP */
    result = arp_lookup(&s, TEST_PRIMARY_IF, ip, found_mac);
    ck_assert_int_eq(result, -1);
    ck_assert_mem_eq(found_mac, zero_mac, 6);
}
END_TEST

START_TEST(test_wolfip_getdev_ex_api)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *ll_def;
    wolfIP_init(&s);
    ll_def = wolfIP_getdev(&s);
    ck_assert_ptr_nonnull(ll_def);
    ck_assert_ptr_eq(ll_def, wolfIP_getdev_ex(&s, TEST_PRIMARY_IF));
#if WOLFIP_ENABLE_LOOPBACK
    ck_assert_ptr_ne(ll_def, wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF));
#endif
    ck_assert_ptr_null(wolfIP_getdev_ex(&s, WOLFIP_MAX_INTERFACES));
}
END_TEST

START_TEST(test_wolfip_ll_at_and_ipconf_at_invalid)
{
    struct wolfIP s;

    wolfIP_init(&s);

    ck_assert_ptr_eq(wolfIP_ll_at(NULL, 0), NULL);
    ck_assert_ptr_eq(wolfIP_ll_at(&s, s.if_count), NULL);
    ck_assert_ptr_eq(wolfIP_ipconf_at(NULL, 0), NULL);
    ck_assert_ptr_eq(wolfIP_ipconf_at(&s, s.if_count), NULL);
}
END_TEST

START_TEST(test_ip_is_local_conf_variants)
{
    struct ipconf conf;
    ip4 addr = 0x0A000001U;

    ck_assert_int_eq(ip_is_local_conf(NULL, addr), 0);

    memset(&conf, 0, sizeof(conf));
    conf.ip = addr;
    conf.mask = 0;
    ck_assert_int_eq(ip_is_local_conf(&conf, addr), 1);
}
END_TEST

#if WOLFIP_ENABLE_LOOPBACK
START_TEST(test_wolfip_loopback_defaults)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *loop;
    struct wolfIP_ll_dev *hw;
    ip4 ip = 0, mask = 0, gw = 0;

    wolfIP_init(&s);

    loop = wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF);
    ck_assert_ptr_nonnull(loop);
    ck_assert_ptr_nonnull(loop->send);
    ck_assert_uint_eq(loop->mac[0], 0x02);

    wolfIP_ipconfig_get_ex(&s, TEST_LOOPBACK_IF, &ip, &mask, &gw);
    ck_assert_uint_eq(ip, 0x7F000001U);
    ck_assert_uint_eq(mask, 0xFF000000U);
    ck_assert_uint_eq(gw, 0U);

    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0x0A0000FEU);
    wolfIP_ipconfig_get_ex(&s, TEST_PRIMARY_IF, &ip, &mask, &gw);
    ck_assert_uint_eq(ip, 0x0A000001U);
    ck_assert_uint_eq(mask, 0xFFFFFF00U);
    ck_assert_uint_eq(gw, 0x0A0000FEU);

    hw = wolfIP_getdev(&s);
    ck_assert_ptr_eq(hw, wolfIP_getdev_ex(&s, TEST_PRIMARY_IF));
}
END_TEST

START_TEST(test_wolfip_loopback_send_paths)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *loop;
    uint8_t frame[16] = {0};

    wolfIP_init(&s);
    loop = wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF);
    ck_assert_ptr_nonnull(loop);

    ck_assert_int_eq(wolfIP_loopback_send(NULL, frame, sizeof(frame)), -1);
    ck_assert_int_eq(wolfIP_loopback_send(loop, NULL, sizeof(frame)), -1);
    ck_assert_int_eq(wolfIP_loopback_send(loop, frame, sizeof(frame)), (int)sizeof(frame));
}
END_TEST

START_TEST(test_wolfip_loopback_send_truncates)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *loop;
    uint8_t frame[LINK_MTU + 8];

    wolfIP_init(&s);
    loop = wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF);
    ck_assert_ptr_nonnull(loop);

    memset(frame, 0xAB, sizeof(frame));
    ck_assert_int_eq(wolfIP_loopback_send(loop, frame, (uint32_t)sizeof(frame)), LINK_MTU);
}
END_TEST

START_TEST(test_wolfip_loopback_send_null_container)
{
    uintptr_t off = (uintptr_t)offsetof(struct wolfIP, ll_dev);
    struct wolfIP_ll_dev *ll;
    uint8_t frame[4] = {0};

    if (off == 0)
        return;

    ll = (struct wolfIP_ll_dev *)off;
    ck_assert_int_eq(wolfIP_loopback_send(ll, frame, sizeof(frame)), -1);
}
END_TEST
#endif

START_TEST(test_wolfip_ipconfig_ex_per_interface)
{
    struct wolfIP s;
    ip4 base_ip = 0x0A000001;
    ip4 base_mask = 0xFFFFFF00;
    ip4 base_gw = 0x0A0000FE;
    ip4 iface_ip = 0x0A000201;
    ip4 iface_mask = 0xFFFF0000;
    ip4 iface_gw = 0x0A0002FE;
    ip4 out_ip = 0, out_mask = 0, out_gw = 0;
    ip4 def_ip = 0, def_mask = 0, def_gw = 0;

    wolfIP_init(&s);
    wolfIP_ipconfig_set(&s, base_ip, base_mask, base_gw);

    wolfIP_ipconfig_set_ex(&s, TEST_SECOND_IF, iface_ip, iface_mask, iface_gw);
    wolfIP_ipconfig_get_ex(&s, TEST_SECOND_IF, &out_ip, &out_mask, &out_gw);

    ck_assert_uint_eq(out_ip, iface_ip);
    ck_assert_uint_eq(out_mask, iface_mask);
    ck_assert_uint_eq(out_gw, iface_gw);

    wolfIP_ipconfig_get(&s, &def_ip, &def_mask, &def_gw);
    ck_assert_uint_eq(def_ip, base_ip);
    ck_assert_uint_eq(def_mask, base_mask);
    ck_assert_uint_eq(def_gw, base_gw);

    wolfIP_ipconfig_set_ex(&s, WOLFIP_MAX_INTERFACES, 0xDEADBEEF, 0xFFFFFFFF, 0x01010101);
    ck_assert_uint_eq(s.ipconf[TEST_SECOND_IF].ip, iface_ip);
    ck_assert_uint_eq(s.ipconf[TEST_SECOND_IF].mask, iface_mask);
    ck_assert_uint_eq(s.ipconf[TEST_SECOND_IF].gw, iface_gw);

    wolfIP_ipconfig_get_ex(&s, TEST_SECOND_IF, NULL, NULL, NULL);
}
END_TEST

START_TEST(test_wolfip_recv_ex_multi_interface_arp_reply)
{
    struct wolfIP s;
    struct arp_packet arp_req;
    struct arp_packet *arp_reply;
    uint8_t requester_mac[6] = {0x10, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t iface1_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};

    wolfIP_init(&s);
    mock_link_init(&s);
    mock_link_init_idx(&s, TEST_SECOND_IF, iface1_mac);
    wolfIP_ipconfig_set(&s, 0xC0A80001, 0xFFFFFF00, 0);
    wolfIP_ipconfig_set_ex(&s, TEST_SECOND_IF, 0xC0A80101, 0xFFFFFF00, 0);

    memset(&arp_req, 0, sizeof(arp_req));
    memset(last_frame_sent, 0, sizeof(last_frame_sent));
    last_frame_sent_size = 0;

    memset(arp_req.eth.dst, 0xFF, sizeof(arp_req.eth.dst));
    memcpy(arp_req.eth.src, requester_mac, 6);
    arp_req.eth.type = ee16(ETH_TYPE_ARP);
    arp_req.htype = ee16(1);
    arp_req.ptype = ee16(ETH_TYPE_IP);
    arp_req.hlen = 6;
    arp_req.plen = 4;
    arp_req.opcode = ee16(ARP_REQUEST);
    memcpy(arp_req.sma, requester_mac, 6);
    arp_req.sip = ee32(0xC0A80164);
    memset(arp_req.tma, 0, sizeof(arp_req.tma));
    arp_req.tip = ee32(0xC0A80101);

    wolfIP_recv_ex(&s, TEST_SECOND_IF, &arp_req, sizeof(arp_req));

    ck_assert_uint_eq(last_frame_sent_size, sizeof(struct arp_packet));
    arp_reply = (struct arp_packet *)last_frame_sent;
    ck_assert_uint_eq(arp_reply->opcode, ee16(ARP_REPLY));
    ck_assert_mem_eq(arp_reply->eth.src, iface1_mac, 6);
    ck_assert_mem_eq(arp_reply->sma, iface1_mac, 6);
    ck_assert_uint_eq(arp_reply->sip, ee32(s.ipconf[TEST_SECOND_IF].ip));
}
END_TEST

START_TEST(test_wolfip_forwarding_basic)
{
    struct wolfIP s;
    struct wolfIP_ip_packet frame;
    struct wolfIP_ip_packet *fwd;
    uint8_t src_mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    uint8_t iface1_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    uint8_t next_hop_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    uint32_t dest_ip = 0xC0A80164; /* 192.168.1.100 */
    uint8_t initial_ttl = 2;
    uint16_t orig_csum;
    uint16_t expected_csum;

    wolfIP_init(&s);
    mock_link_init(&s);
    mock_link_init_idx(&s, TEST_SECOND_IF, iface1_mac);
    wolfIP_ipconfig_set(&s, 0xC0A80001, 0xFFFFFF00, 0);
    wolfIP_ipconfig_set_ex(&s, TEST_SECOND_IF, 0xC0A80101, 0xFFFFFF00, 0);
    s.arp.neighbors[0].ip = dest_ip;
    s.arp.neighbors[0].if_idx = TEST_SECOND_IF;
    memcpy(s.arp.neighbors[0].mac, next_hop_mac, 6);

    memset(&frame, 0, sizeof(frame));
    memcpy(frame.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(frame.eth.src, src_mac, 6);
    frame.eth.type = ee16(ETH_TYPE_IP);
    frame.ver_ihl = 0x45;
    frame.ttl = initial_ttl;
    frame.proto = WI_IPPROTO_UDP;
    frame.len = ee16(IP_HEADER_LEN);
    frame.src = ee32(0xC0A800AA);
    frame.dst = ee32(dest_ip);
    frame.csum = 0;
    iphdr_set_checksum(&frame);
    orig_csum = ee16(frame.csum);

    memset(last_frame_sent, 0, sizeof(last_frame_sent));
    last_frame_sent_size = 0;

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, &frame, sizeof(frame));

    ck_assert_uint_eq(last_frame_sent_size, sizeof(struct wolfIP_ip_packet));
    fwd = (struct wolfIP_ip_packet *)last_frame_sent;
    ck_assert_mem_eq(fwd->eth.dst, next_hop_mac, 6);
    ck_assert_mem_eq(fwd->eth.src, s.ll_dev[TEST_SECOND_IF].mac, 6);
    ck_assert_uint_eq(fwd->ttl, (uint8_t)(initial_ttl - 1));
    {
        uint32_t sum = orig_csum + 0x0100;
        sum = (sum & 0xFFFF) + (sum >> 16);
        expected_csum = (uint16_t)sum;
        if (expected_csum == 0)
            expected_csum = 0xFFFF;
    }
    ck_assert_uint_eq(ee16(fwd->csum), expected_csum);
}
END_TEST

START_TEST(test_wolfip_forwarding_ttl_expired)
{
    struct wolfIP s;
    struct wolfIP_ip_packet frame;
    struct wolfIP_icmp_ttl_exceeded_packet *icmp;
    uint8_t src_mac[6] = {0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC};
    uint8_t iface1_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};
    uint32_t dest_ip = 0xC0A80110;

    wolfIP_init(&s);
    mock_link_init(&s);
    mock_link_init_idx(&s, TEST_SECOND_IF, iface1_mac);
    wolfIP_ipconfig_set(&s, 0xC0A80001, 0xFFFFFF00, 0);
    wolfIP_ipconfig_set_ex(&s, TEST_SECOND_IF, 0xC0A80101, 0xFFFFFF00, 0);

    memset(&frame, 0, sizeof(frame));
    memcpy(frame.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(frame.eth.src, src_mac, 6);
    frame.eth.type = ee16(ETH_TYPE_IP);
    frame.ver_ihl = 0x45;
    frame.ttl = 1;
    frame.proto = WI_IPPROTO_UDP;
    frame.len = ee16(IP_HEADER_LEN);
    frame.src = ee32(0xC0A800AA);
    frame.dst = ee32(dest_ip);
    frame.csum = 0;
    iphdr_set_checksum(&frame);

    memset(last_frame_sent, 0, sizeof(last_frame_sent));
    last_frame_sent_size = 0;

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, &frame, sizeof(frame));

    ck_assert_uint_eq(last_frame_sent_size,
            sizeof(struct wolfIP_icmp_ttl_exceeded_packet));
    icmp = (struct wolfIP_icmp_ttl_exceeded_packet *)last_frame_sent;
    ck_assert_uint_eq(icmp->type, ICMP_TTL_EXCEEDED);
    ck_assert_uint_eq(icmp->code, 0);
    ck_assert_mem_eq(icmp->unused, "\x00\x00\x00\x00", sizeof(icmp->unused));
    ck_assert_mem_eq(icmp->ip.eth.dst, src_mac, 6);
    ck_assert_mem_eq(icmp->ip.eth.src, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    ck_assert_uint_eq(icmp->ip.ttl, 64);
    ck_assert_uint_eq(ee16(icmp->ip.len),
            (uint16_t)(IP_HEADER_LEN + ICMP_TTL_EXCEEDED_SIZE));
    ck_assert_uint_eq(ee32(icmp->ip.src), s.ipconf[TEST_PRIMARY_IF].ip);
    ck_assert_uint_eq(ee32(icmp->ip.dst), ee32(frame.src));
    ck_assert_mem_eq(icmp->orig_packet,
            ((uint8_t *)&frame) + ETH_HEADER_LEN,
            ee16(frame.len) < TTL_EXCEEDED_ORIG_PACKET_SIZE ?
            ee16(frame.len) : TTL_EXCEEDED_ORIG_PACKET_SIZE);
    ck_assert_uint_eq(frame.ttl, 1); /* original packet should remain unchanged */
}
END_TEST

START_TEST(test_loopback_dest_not_forwarded)
{
    struct wolfIP s;
    struct wolfIP_ip_packet frame;
    uint8_t src_mac[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};

    wolfIP_init(&s);
    mock_link_init(&s);
    mock_link_init_idx(&s, TEST_SECOND_IF, NULL);
    wolfIP_ipconfig_set(&s, 0xC0A80001, 0xFFFFFF00, 0);

    memset(&frame, 0, sizeof(frame));
    memcpy(frame.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(frame.eth.src, src_mac, 6);
    frame.eth.type = ee16(ETH_TYPE_IP);
    frame.ver_ihl = 0x45;
    frame.ttl = 64;
    frame.proto = WI_IPPROTO_UDP;
    frame.len = ee16(IP_HEADER_LEN);
    frame.src = ee32(0x0A000002U);
    frame.dst = ee32(0x7F000001U);
    frame.csum = 0;
    iphdr_set_checksum(&frame);

    memset(last_frame_sent, 0, sizeof(last_frame_sent));
    last_frame_sent_size = 0;

    wolfIP_recv_ex(&s, TEST_PRIMARY_IF, &frame, sizeof(frame));

    ck_assert_uint_eq(last_frame_sent_size, 0);
}
END_TEST

/* wolfSSL IO glue tests */
START_TEST(test_wolfssl_io_ctx_registers_callbacks)
{
    struct wolfIP s;
    WOLFSSL_CTX ctx;

    memset(&ctx, 0, sizeof(ctx));
    reset_wolfssl_io_state();
    wolfSSL_SetIO_wolfIP_CTX(&ctx, &s);

    ck_assert_ptr_eq(g_ctx_recv_cb, wolfIP_io_recv);
    ck_assert_ptr_eq(g_ctx_send_cb, wolfIP_io_send);
    ck_assert_ptr_eq(g_last_ctx, &ctx);
    ck_assert_ptr_eq(wolfIP_lookup_stack(&ctx), &s);
}
END_TEST

START_TEST(test_wolfssl_io_setio_success)
{
    struct wolfIP s;
    WOLFSSL_CTX ctx;
    WOLFSSL ssl;
    int ret;
    struct wolfip_io_desc *desc;

    memset(&ctx, 0, sizeof(ctx));
    memset(&ssl, 0, sizeof(ssl));
    ssl.ctx = &ctx;

    reset_wolfssl_io_state();
    wolfSSL_SetIO_wolfIP_CTX(&ctx, &s);
    ret = wolfSSL_SetIO_wolfIP(&ssl, 7);
    ck_assert_int_eq(ret, 0);
    ck_assert_ptr_nonnull(ssl.rctx);
    ck_assert_ptr_eq(ssl.rctx, ssl.wctx);
    ck_assert_ptr_eq(g_last_read_ctx, ssl.rctx);
    ck_assert_ptr_eq(g_last_write_ctx, ssl.wctx);
    desc = (struct wolfip_io_desc *)ssl.rctx;
    ck_assert_int_eq(desc->fd, 7);
    ck_assert_ptr_eq(desc->stack, &s);
}
END_TEST

START_TEST(test_wolfssl_io_setio_invalid_ssl)
{
    reset_wolfssl_io_state();
    ck_assert_int_eq(wolfSSL_SetIO_wolfIP(NULL, 1), -1);
}
END_TEST

START_TEST(test_wolfssl_io_setio_invalid_ctx)
{
    WOLFSSL ssl;
    memset(&ssl, 0, sizeof(ssl));
    reset_wolfssl_io_state();
    ck_assert_int_eq(wolfSSL_SetIO_wolfIP(&ssl, 1), -1);
}
END_TEST

START_TEST(test_wolfssl_io_setio_invalid_fd)
{
    struct wolfIP s;
    WOLFSSL_CTX ctx;
    WOLFSSL ssl;

    memset(&ctx, 0, sizeof(ctx));
    memset(&ssl, 0, sizeof(ssl));
    ssl.ctx = &ctx;
    reset_wolfssl_io_state();
    wolfSSL_SetIO_wolfIP_CTX(&ctx, &s);
    ck_assert_int_eq(wolfSSL_SetIO_wolfIP(&ssl, -1), -1);
}
END_TEST

START_TEST(test_wolfssl_io_setio_no_stack)
{
    WOLFSSL_CTX ctx;
    WOLFSSL ssl;

    memset(&ctx, 0, sizeof(ctx));
    memset(&ssl, 0, sizeof(ssl));
    ssl.ctx = &ctx;
    reset_wolfssl_io_state();
    ck_assert_int_eq(wolfSSL_SetIO_wolfIP(&ssl, 4), WOLFSSL_CBIO_ERR_GENERAL);
}
END_TEST

START_TEST(test_wolfssl_io_recv_behaviors)
{
    struct wolfIP s;
    struct wolfip_io_desc desc;
    char buf[8];
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.stack = &s;

    reset_wolfssl_io_state();
    test_recv_ret = -WOLFIP_EAGAIN;
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_READ);

    test_recv_ret = -1;
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_READ);

    test_recv_ret = 0;
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_CONN_CLOSE);

    memset(test_recv_fill, 0, sizeof(test_recv_fill));
    test_recv_fill[0] = 0xA1;
    test_recv_fill[1] = 0xB2;
    test_recv_fill_len = 2;
    test_recv_ret = 2;
    memset(buf, 0, sizeof(buf));
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, 2);
    ck_assert_int_eq((unsigned char)buf[0], 0xA1);
    ck_assert_int_eq((unsigned char)buf[1], 0xB2);
}
END_TEST

START_TEST(test_wolfssl_io_recv_invalid_desc)
{
    char buf[4];
    int ret;

    reset_wolfssl_io_state();
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), NULL);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_GENERAL);
}
END_TEST

START_TEST(test_wolfssl_io_recv_fragmented_sequence)
{
    struct wolfIP s;
    struct wolfip_io_desc desc;
    char buf[4];
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.stack = &s;
    reset_wolfssl_io_state();

    test_recv_fill[0] = 0xAA;
    test_recv_fill_len = 1;
    test_recv_ret = 1;
    memset(buf, 0, sizeof(buf));
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, 1);
    ck_assert_int_eq((unsigned char)buf[0], 0xAA);

    test_recv_fill[0] = 0xBB;
    test_recv_fill_len = 1;
    test_recv_ret = 1;
    ret = wolfIP_io_recv(NULL, buf + 1, (int)(sizeof(buf) - 1), &desc);
    ck_assert_int_eq(ret, 1);
    ck_assert_int_eq((unsigned char)buf[1], 0xBB);
}
END_TEST

START_TEST(test_wolfssl_io_recv_respects_buffer_size)
{
    struct wolfIP s;
    struct wolfip_io_desc desc;
    char buf[2];
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.stack = &s;
    reset_wolfssl_io_state();

    test_recv_fill[0] = 0x11;
    test_recv_fill[1] = 0x22;
    test_recv_fill[2] = 0x33;
    test_recv_fill_len = 3;
    test_recv_ret = 2;
    memset(buf, 0, sizeof(buf));
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, 2);
    ck_assert_int_eq((unsigned char)buf[0], 0x11);
    ck_assert_int_eq((unsigned char)buf[1], 0x22);
}
END_TEST

START_TEST(test_wolfssl_io_recv_want_read_keeps_buffer)
{
    struct wolfIP s;
    struct wolfip_io_desc desc;
    char buf[3] = {0x5A, 0x5A, 0x5A};
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.stack = &s;
    reset_wolfssl_io_state();

    test_recv_ret = -WOLFIP_EAGAIN;
    ret = wolfIP_io_recv(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_READ);
    ck_assert_mem_eq(buf, "\x5A\x5A\x5A", 3);
}
END_TEST

START_TEST(test_wolfssl_io_recv_alternating_eagain_short_reads)
{
    struct wolfIP s;
    struct wolfip_io_desc desc;
    char buf[6];
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.stack = &s;
    reset_wolfssl_io_state();

    test_recv_fill[0] = 0x01;
    test_recv_fill[1] = 0x02;
    test_recv_fill[2] = 0x03;
    test_recv_fill[3] = 0x04;
    test_recv_fill[4] = 0x05;
    test_recv_fill[5] = 0x06;
    test_recv_steps_len = 5;
    test_recv_steps[0] = -WOLFIP_EAGAIN;
    test_recv_steps[1] = 2;
    test_recv_steps[2] = -WOLFIP_EAGAIN;
    test_recv_steps[3] = 2;
    test_recv_steps[4] = 2;

    memset(buf, 0, sizeof(buf));
    ret = wolfIP_io_recv(NULL, buf, 2, &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_READ);

    ret = wolfIP_io_recv(NULL, buf, 2, &desc);
    ck_assert_int_eq(ret, 2);
    ck_assert_int_eq((unsigned char)buf[0], 0x01);
    ck_assert_int_eq((unsigned char)buf[1], 0x02);

    ret = wolfIP_io_recv(NULL, buf + 2, 2, &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_READ);

    ret = wolfIP_io_recv(NULL, buf + 2, 2, &desc);
    ck_assert_int_eq(ret, 2);
    ck_assert_int_eq((unsigned char)buf[2], 0x03);
    ck_assert_int_eq((unsigned char)buf[3], 0x04);

    ret = wolfIP_io_recv(NULL, buf + 4, 2, &desc);
    ck_assert_int_eq(ret, 2);
    ck_assert_int_eq((unsigned char)buf[4], 0x05);
    ck_assert_int_eq((unsigned char)buf[5], 0x06);
}
END_TEST

START_TEST(test_wolfssl_io_send_behaviors)
{
    struct wolfIP s;
    struct wolfip_io_desc desc;
    char buf[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.stack = &s;

    reset_wolfssl_io_state();
    test_send_ret = -WOLFIP_EAGAIN;
    ret = wolfIP_io_send(NULL, buf, 4, &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_WRITE);

    test_send_ret = -1;
    ret = wolfIP_io_send(NULL, buf, 4, &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_WRITE);

    test_send_ret = 0;
    ret = wolfIP_io_send(NULL, buf, 4, &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_CONN_CLOSE);

    test_send_capture_len = 4;
    test_send_ret = 4;
    memset(test_send_capture, 0, sizeof(test_send_capture));
    ret = wolfIP_io_send(NULL, buf, 4, &desc);
    ck_assert_int_eq(ret, 4);
    ck_assert_int_eq(test_send_last_len, 4);
    ck_assert_mem_eq(test_send_capture, buf, 4);
}
END_TEST

START_TEST(test_wolfssl_io_send_want_write_keeps_buffer)
{
    struct wolfIP s;
    struct wolfip_io_desc desc;
    char buf[3] = {0x6B, 0x6B, 0x6B};
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.stack = &s;
    reset_wolfssl_io_state();

    test_send_ret = -WOLFIP_EAGAIN;
    ret = wolfIP_io_send(NULL, buf, sizeof(buf), &desc);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_WANT_WRITE);
    ck_assert_mem_eq(buf, "\x6B\x6B\x6B", 3);
}
END_TEST

START_TEST(test_wolfssl_io_send_invalid_desc)
{
    char buf[4] = {0};
    int ret;

    reset_wolfssl_io_state();
    ret = wolfIP_io_send(NULL, buf, sizeof(buf), NULL);
    ck_assert_int_eq(ret, WOLFSSL_CBIO_ERR_GENERAL);
}
END_TEST

START_TEST(test_tcp_listen_rejects_wrong_interface)
{
    struct wolfIP s;
    const ip4 primary_ip = 0xC0A80001U;
    const ip4 secondary_ip = 0xC0A80101U;
    const uint16_t listen_port = 12345;
    int listen_fd;
    struct wolfIP_sockaddr_in addr;
    struct tsocket *listener;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);

    listen_fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(listen_fd, 0);
    listener = &s.tcpsockets[SOCKET_UNMARK(listen_fd)];

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(listen_port);
    addr.sin_addr.s_addr = ee32(primary_ip);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_fd, (struct wolfIP_sockaddr *)&addr, sizeof(addr)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_fd, 1), 0);

    inject_tcp_syn(&s, TEST_SECOND_IF, secondary_ip, listen_port);

    ck_assert_int_eq(listener->sock.tcp.state, TCP_LISTEN);
    ck_assert_int_eq(listener->events & CB_EVENT_READABLE, 0);
}
END_TEST

START_TEST(test_tcp_listen_accepts_bound_interface)
{
    struct wolfIP s;
    const ip4 primary_ip = 0xC0A80002U;
    const ip4 secondary_ip = 0xC0A80101U;
    const uint16_t listen_port = 23456;
    int listen_fd;
    int client_fd;
    struct wolfIP_sockaddr_in addr;
    struct tsocket *listener;
    struct tsocket *client;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);

    listen_fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(listen_fd, 0);
    listener = &s.tcpsockets[SOCKET_UNMARK(listen_fd)];

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(listen_port);
    addr.sin_addr.s_addr = ee32(secondary_ip);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_fd, (struct wolfIP_sockaddr *)&addr, sizeof(addr)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_fd, 1), 0);

    inject_tcp_syn(&s, TEST_SECOND_IF, secondary_ip, listen_port);

    ck_assert_int_eq(listener->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(listener->local_ip, secondary_ip);
    ck_assert_uint_eq(listener->if_idx, TEST_SECOND_IF);

    client_fd = wolfIP_sock_accept(&s, listen_fd, NULL, NULL);
    ck_assert_int_ge(client_fd, 0);
    client = &s.tcpsockets[SOCKET_UNMARK(client_fd)];
    ck_assert_uint_eq(client->local_ip, secondary_ip);
    ck_assert_uint_eq(client->bound_local_ip, secondary_ip);
    ck_assert_int_eq(client->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

START_TEST(test_tcp_listen_accepts_any_interface)
{
    struct wolfIP s;
    const ip4 primary_ip = 0xC0A80005U;
    const ip4 secondary_ip = 0xC0A80105U;
    const uint16_t listen_port = 34567;
    int listen_fd;
    int client_fd;
    struct wolfIP_sockaddr_in addr;
    struct tsocket *listener;
    struct tsocket *client;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);

    listen_fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(listen_fd, 0);
    listener = &s.tcpsockets[SOCKET_UNMARK(listen_fd)];

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(listen_port);
    addr.sin_addr.s_addr = ee32(IPADDR_ANY);
    ck_assert_int_eq(wolfIP_sock_bind(&s, listen_fd, (struct wolfIP_sockaddr *)&addr, sizeof(addr)), 0);
    ck_assert_int_eq(wolfIP_sock_listen(&s, listen_fd, 1), 0);

    inject_tcp_syn(&s, TEST_SECOND_IF, secondary_ip, listen_port);

    ck_assert_int_eq(listener->sock.tcp.state, TCP_SYN_RCVD);
    ck_assert_uint_eq(listener->local_ip, secondary_ip);
    ck_assert_uint_eq(listener->if_idx, TEST_SECOND_IF);

    client_fd = wolfIP_sock_accept(&s, listen_fd, NULL, NULL);
    ck_assert_int_ge(client_fd, 0);
    client = &s.tcpsockets[SOCKET_UNMARK(client_fd)];
    ck_assert_uint_eq(client->local_ip, secondary_ip);
    ck_assert_int_eq(client->sock.tcp.state, TCP_ESTABLISHED);
}
END_TEST

START_TEST(test_sock_connect_selects_local_ip_multi_if)
{
    struct wolfIP s;
    const ip4 primary_ip = 0xC0A80009U;
    const ip4 secondary_ip = 0xC0A80109U;
    const ip4 remote_primary = 0xC0A800AAU;
    const ip4 remote_secondary = 0xC0A801A1U;
    int udp_fd;
    int tcp_fd;
    struct wolfIP_sockaddr_in dst;
    struct tsocket *ts;
    int ret;

    setup_stack_with_two_ifaces(&s, primary_ip, secondary_ip);

    udp_fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    ck_assert_int_ge(udp_fd, 0);
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = ee16(5555);
    dst.sin_addr.s_addr = ee32(remote_secondary);
    ck_assert_int_eq(wolfIP_sock_connect(&s, udp_fd, (struct wolfIP_sockaddr *)&dst, sizeof(dst)), 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_fd)];
    ck_assert_uint_eq(ts->local_ip, secondary_ip);
    ck_assert_uint_eq(ts->if_idx, TEST_SECOND_IF);

    tcp_fd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    ck_assert_int_ge(tcp_fd, 0);
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = ee16(8080);
    dst.sin_addr.s_addr = ee32(remote_primary);
    ret = wolfIP_sock_connect(&s, tcp_fd, (struct wolfIP_sockaddr *)&dst, sizeof(dst));
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_fd)];
    ck_assert_uint_eq(ts->local_ip, primary_ip);
    ck_assert_uint_eq(ts->if_idx, TEST_PRIMARY_IF);
}
END_TEST


// Test for `transport_checksum` calculation
START_TEST(test_transport_checksum) {
    union transport_pseudo_header ph;
    struct wolfIP_tcp_seg tcp_data;
    uint16_t checksum;
    memset(&ph, 0, sizeof(ph));
    memset(&tcp_data, 0, sizeof(tcp_data));

    // Set up pseudo-header values for test
    ph.ph.src = 0xc0a80101; // 192.168.1.1
    ph.ph.dst = 0xc0a80102; // 192.168.1.2
    ph.ph.proto = WI_IPPROTO_TCP;
    ph.ph.len = ee16(20); // TCP header length (without options)

    // Test with a simple TCP header with src/dst ports and no data
    tcp_data.src_port = ee16(12345);
    tcp_data.dst_port = ee16(80);
    tcp_data.seq = ee32(1);
    tcp_data.ack = ee32(0);
    tcp_data.hlen = 5; // offset=5 (20 bytes)
    tcp_data.flags = 0x02; // SYN
    tcp_data.win = ee16(65535);

    checksum = transport_checksum(&ph, &tcp_data.src_port);
    ck_assert_msg(checksum != 0, "Transport checksum should not be zero");
}
END_TEST

// Test for `iphdr_set_checksum` calculation
START_TEST(test_iphdr_set_checksum) {
    struct wolfIP_ip_packet ip;
    memset(&ip, 0, sizeof(ip));

    ip.ver_ihl = 0x45;
    ip.tos = 0;
    ip.len = ee16(20);
    ip.id = ee16(1);
    ip.flags_fo = 0;
    ip.ttl = 64;
    ip.proto = WI_IPPROTO_TCP;
    ip.src = ee32(0xc0a80101); // 192.168.1.1
    ip.dst = ee32(0xc0a80102); // 192.168.1.2

    iphdr_set_checksum(&ip);
    ck_assert_msg(ip.csum != 0, "IP header checksum should not be zero");
}
END_TEST

// Test for `eth_output_add_header` to add Ethernet headers
START_TEST(test_eth_output_add_header) {
    struct wolfIP_eth_frame eth_frame;
    struct wolfIP S;
    uint8_t test_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    struct wolfIP_ll_dev *ll;

    wolfIP_init(&S);
    memset(&eth_frame, 0, sizeof(eth_frame));

    ll = wolfIP_getdev_ex(&S, TEST_PRIMARY_IF);
    memcpy(ll->mac, test_mac, 6);

    eth_output_add_header(&S, TEST_PRIMARY_IF, NULL, &eth_frame, ETH_TYPE_IP);

    ck_assert_mem_eq(eth_frame.dst, "\xff\xff\xff\xff\xff\xff", 6);  // Broadcast
    ck_assert_mem_eq(eth_frame.src, test_mac, 6);
    ck_assert_uint_eq(eth_frame.type, ee16(ETH_TYPE_IP));
}
END_TEST

START_TEST(test_eth_output_add_header_invalid_if)
{
    struct wolfIP_eth_frame eth_frame;
    struct wolfIP S;
    int ret;

    wolfIP_init(&S);
    memset(&eth_frame, 0, sizeof(eth_frame));

    ret = eth_output_add_header(&S, WOLFIP_MAX_INTERFACES, NULL, &eth_frame, ETH_TYPE_IP);
    ck_assert_int_eq(ret, -1);
}
END_TEST

// Test for `ip_output_add_header` to set up IP headers and calculate checksums
START_TEST(test_ip_output_add_header) {
    struct tsocket t;
    struct wolfIP_ip_packet ip;
    struct wolfIP S;
    int result;
    struct wolfIP_tcp_seg *tcp;

    memset(&t, 0, sizeof(t));
    memset(&ip, 0, sizeof(ip));
    wolfIP_init(&S);

    // Setup socket and IP stack parameters
    t.local_ip = 0xc0a80101;   // 192.168.1.1
    t.remote_ip = 0xc0a80102;  // 192.168.1.2
    t.S = &S;

    // Run the function for a TCP packet
    result = ip_output_add_header(&t, &ip, WI_IPPROTO_TCP, 40);
    ck_assert_int_eq(result, 0);

    // Validate IP header fields
    ck_assert_uint_eq(ip.ver_ihl, 0x45);
    ck_assert_uint_eq(ip.ttl, 64);
    ck_assert_uint_eq(ip.proto, WI_IPPROTO_TCP);
    ck_assert_uint_eq(ip.src, ee32(t.local_ip));
    ck_assert_uint_eq(ip.dst, ee32(t.remote_ip));
    ck_assert_msg(ip.csum != 0, "IP header checksum should not be zero");

    // Check the pseudo-header checksum calculation for TCP segment
    tcp = (struct wolfIP_tcp_seg *)&ip;
    ck_assert_msg(tcp->csum != 0, "TCP checksum should not be zero");
}
END_TEST

START_TEST(test_ip_output_add_header_icmp)
{
    struct tsocket t;
    struct wolfIP_ip_packet ip;
    struct wolfIP S;
    int result;
    struct wolfIP_icmp_packet *icmp;

    memset(&t, 0, sizeof(t));
    memset(&ip, 0, sizeof(ip));
    wolfIP_init(&S);

    t.local_ip = 0xc0a80101;
    t.remote_ip = 0xc0a80102;
    t.S = &S;
    t.if_idx = TEST_PRIMARY_IF;
    mock_link_init(&S);

    result = ip_output_add_header(&t, &ip, WI_IPPROTO_ICMP, IP_HEADER_LEN + ICMP_HEADER_LEN);
    ck_assert_int_eq(result, 0);

    icmp = (struct wolfIP_icmp_packet *)&ip;
    ck_assert_msg(icmp->csum != 0, "ICMP checksum should not be zero");
}
END_TEST

START_TEST(test_icmp_socket_send_recv)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN + 4];
    uint32_t local_ip = 0x0A000001U;
    uint32_t remote_ip = 0x0A000002U;
    struct tsocket *ts;
    struct wolfIP_icmp_packet *sent_pkt;
    uint8_t reply_buf[sizeof(struct wolfIP_icmp_packet) + sizeof(payload)];
    struct wolfIP_icmp_packet *reply = (struct wolfIP_icmp_packet *)reply_buf;
    uint8_t peer_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x01};
    uint8_t rxbuf[sizeof(payload)];
    struct wolfIP_sockaddr_in from;
    socklen_t from_len = sizeof(from);
    int ret;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, sizeof(peer_mac));

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(sd)];
    ck_assert_uint_gt(fifo_space(&ts->sock.udp.txbuf), (uint32_t)sizeof(payload));
    fifo_init(&ts->sock.udp.txbuf, ts->txmem, TXBUF_SIZE);
    fifo_init(&ts->sock.udp.rxbuf, ts->rxmem, RXBUF_SIZE);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(remote_ip);

    memset(payload, 0, sizeof(payload));
    payload[0] = ICMP_ECHO_REQUEST;
    payload[1] = 0;
    payload[ICMP_HEADER_LEN] = 'P';
    payload[ICMP_HEADER_LEN + 1] = 'I';
    payload[ICMP_HEADER_LEN + 2] = 'N';
    payload[ICMP_HEADER_LEN + 3] = 'G';

    ret = wolfIP_sock_sendto(&s, sd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ts = &s.icmpsockets[SOCKET_UNMARK(sd)];
    ck_assert_uint_eq(ts->if_idx, TEST_PRIMARY_IF);

    {
        struct pkt_desc *desc = fifo_peek(&ts->sock.udp.txbuf);
        ck_assert_ptr_nonnull(desc);
        sent_pkt = (struct wolfIP_icmp_packet *)(ts->txmem + desc->pos + sizeof(*desc));
        ck_assert_uint_eq(sent_pkt->type, ICMP_ECHO_REQUEST);
        ck_assert_uint_eq(icmp_echo_id(sent_pkt), ts->src_port);
        fifo_pop(&ts->sock.udp.txbuf);
    }

    memset(reply, 0, sizeof(reply_buf));
    memcpy(reply->ip.eth.dst, s.ll_dev[TEST_PRIMARY_IF].mac, 6);
    memcpy(reply->ip.eth.src, peer_mac, 6);
    reply->ip.eth.type = ee16(ETH_TYPE_IP);
    reply->ip.ver_ihl = 0x45;
    reply->ip.ttl = 64;
    reply->ip.proto = WI_IPPROTO_ICMP;
    reply->ip.len = ee16(IP_HEADER_LEN + sizeof(payload));
    reply->ip.src = ee32(remote_ip);
    reply->ip.dst = ee32(local_ip);
    reply->type = ICMP_ECHO_REPLY;
    reply->code = 0;
    icmp_set_echo_id(reply, ts->src_port);
    {
        uint16_t seq = ee16(1);
        memcpy(reply->unused + sizeof(uint16_t), &seq, sizeof(seq));
    }
    memcpy(((uint8_t *)&reply->type) + ICMP_HEADER_LEN,
            payload + ICMP_HEADER_LEN,
            sizeof(payload) - ICMP_HEADER_LEN);
    reply->csum = 0;
    reply->csum = ee16(icmp_checksum(reply, sizeof(payload)));
    reply->ip.csum = 0;
    iphdr_set_checksum(&reply->ip);

    wolfIP_recv(&s, reply, ETH_HEADER_LEN + IP_HEADER_LEN + sizeof(payload));

    memset(&from, 0, sizeof(from));
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
            (struct wolfIP_sockaddr *)&from, &from_len);
    ck_assert_int_eq(ret, (int)sizeof(payload));
    ck_assert_mem_eq(rxbuf, &reply->type, sizeof(payload));
    ck_assert_uint_eq(from.sin_addr.s_addr, ee32(remote_ip));
    ck_assert_uint_eq(from_len, sizeof(from));

    /* Ensure the packet was removed from the queue */
    memset(rxbuf, 0, sizeof(rxbuf));
    ret = wolfIP_sock_recvfrom(&s, sd, rxbuf, sizeof(rxbuf), 0,
            NULL, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EAGAIN);
}
END_TEST

START_TEST(test_regression_snd_una_initialized_on_syn_rcvd)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_in sin;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    uint16_t local_port = 8080;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port   = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    wolfIP_sock_listen(&s, sd, 1);

    /* inject_tcp_syn uses a deterministic PRNG seed so seq is reproducible */
    inject_tcp_syn(&s, TEST_PRIMARY_IF, local_ip, local_port);

    ts = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ck_assert_int_eq(ts->sock.tcp.state, TCP_SYN_RCVD);

    /* snd_una must equal the ISN that was placed in seq, not 0 */
    ck_assert_uint_eq(ts->sock.tcp.snd_una, ts->sock.tcp.seq);

    /* The wrap-aware ordering invariant: snd_una <= seq */
    ck_assert_int_eq(tcp_seq_leq(ts->sock.tcp.snd_una, ts->sock.tcp.seq), 1);
}
END_TEST

START_TEST(test_regression_duplicate_syn_rejected_on_established)
{
    struct wolfIP s;
    int sd, sd2;
    struct wolfIP_sockaddr_in sin;
    struct tsocket *listener, *established;
    ip4 local_ip   = 0x0A000001U;
    ip4 remote_ip  = 0x0A0000A1U; /* hardcoded in inject_tcp_syn */
    uint16_t local_port  = 8080;
    uint16_t remote_port = 40000; /* hardcoded in inject_tcp_syn */

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    /* Create a listening socket that must stay in LISTEN throughout */
    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port   = ee16(local_port);
    sin.sin_addr.s_addr = ee32(local_ip);
    wolfIP_sock_bind(&s, sd, (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    wolfIP_sock_listen(&s, sd, 4);
    listener = &s.tcpsockets[SOCKET_UNMARK(sd)];
    ck_assert_int_eq(listener->sock.tcp.state, TCP_LISTEN);

    /* Allocate a second socket slot and wire it as ESTABLISHED with the
     * same 4-tuple that inject_tcp_syn will use.  This simulates a live
     * connection that was established by a previous handshake. */
    sd2 = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(sd2, 0);
    established = &s.tcpsockets[SOCKET_UNMARK(sd2)];
    established->sock.tcp.state   = TCP_ESTABLISHED;
    established->local_ip         = local_ip;
    established->remote_ip        = remote_ip;
    established->if_idx           = TEST_PRIMARY_IF;
    established->src_port         = local_port;
    established->dst_port         = remote_port;
    established->sock.tcp.seq     = 1000;
    established->sock.tcp.snd_una = 1000;
    established->sock.tcp.ack     = 2;
    established->sock.tcp.cwnd    = TCP_MSS;
    established->sock.tcp.peer_rwnd = TCP_MSS;
    queue_init(&established->sock.tcp.rxbuf, established->rxmem, RXBUF_SIZE, 0);
    fifo_init(&established->sock.tcp.txbuf, established->txmem, TXBUF_SIZE);

    /* Send a SYN whose tuple matches the established connection above.
     * Without the fix (da5c792): listener → TCP_SYN_RCVD.
     * With the fix:              listener stays in TCP_LISTEN. */
    inject_tcp_syn(&s, TEST_PRIMARY_IF, local_ip, local_port);

    ck_assert_int_eq(listener->sock.tcp.state, TCP_LISTEN);
}
END_TEST

/* ----------------------------------------------------------------------- */

Suite *wolf_suite(void)
{
    Suite *s;
    TCase *tc_core, *tc_proto, *tc_utils, *tc_wolfssl;

    s = suite_create("wolfIP");
    tc_core = tcase_create("Core");
    tc_utils = tcase_create("Utils");
    tc_proto = tcase_create("Protocols");
    tc_wolfssl = tcase_create("wolfSSL-IO");


    tcase_add_test(tc_core, test_fifo_init);
    tcase_add_test(tc_core, test_fifo_peek_wraps_tail_when_head_lt_tail);
    tcase_add_test(tc_core, test_fifo_peek_no_wrap_when_space_available);
    tcase_add_test(tc_core, test_fifo_next_wraps_on_hwrap);
    tcase_add_test(tc_core, test_fifo_pop_aligns_tail_to_head_returns_null);
    tcase_add_test(tc_core, test_fifo_pop_wraps_tail_when_head_lt_tail);
    tcase_add_test(tc_core, test_fifo_pop_no_wrap_when_space_available);
    tcase_add_test(tc_core, test_fifo_peek_empty_unaligned_tail);
    tcase_add_test(tc_core, test_fifo_len_empty_unaligned_tail);
    tcase_add_test(tc_core, test_fifo_pop_empty_unaligned_tail);
    tcase_add_test(tc_core, test_fifo_push_pop_odd_sizes_drains_cleanly);
    tcase_add_test(tc_core, test_fifo_full_wrap_does_not_appear_empty_or_discard_packets);
    tcase_add_test(tc_core, test_fifo_next_stops_at_aligned_head_when_head_unaligned);
    tcase_add_test(tc_core, test_fifo_full_wrap_next_iterates_all_entries_without_loss);
    tcase_add_test(tc_core, test_fifo_wrap_full_pop_then_refill_keeps_order_without_drops);
    tcase_add_test(tc_core, test_fifo_wrap_flag_transitions_push_pop_around_boundary);
    tcase_add_test(tc_core, test_fifo_wrap_flag_repeated_flips_keep_data_consistent);
    tcase_add_test(tc_core, test_fifo_wrap_flag_transitions_with_odd_payload_sizes);
    tcase_add_test(tc_core, test_fifo_wrap_flag_repeated_flips_with_odd_payload_sizes);

    tcase_add_test(tc_core, test_fifo_push_and_pop);
    tcase_add_test(tc_core, test_fifo_push_and_pop_multiple);
    tcase_add_test(tc_core, test_fifo_pop_success);
    tcase_add_test(tc_core, test_fifo_pop_empty);
    tcase_add_test(tc_core, test_fifo_push_full);
    tcase_add_test(tc_core, test_fifo_push_wrap);
    tcase_add_test(tc_core, test_fifo_push_wrap_multiple);
    tcase_add_test(tc_core, test_fifo_space_wrap_sets_hwrap);
    tcase_add_test(tc_core, test_fifo_space_wrap_returns_zero);
    tcase_add_test(tc_core, test_fifo_peek_wrap_to_start);
    tcase_add_test(tc_core, test_fifo_len_with_hwrap);
    tcase_add_test(tc_core, test_fifo_peek_aligns_tail);
    tcase_add_test(tc_core, test_fifo_next_wraps_to_start);
    tcase_add_test(tc_core, test_fifo_space_head_lt_tail);
    tcase_add_test(tc_core, test_fifo_space_with_hwrap);
    tcase_add_test(tc_core, test_fifo_space_hwrap_head_hits_wrap);
    tcase_add_test(tc_core, test_fifo_space_hwrap_head_ge_tail_returns_zero);
    tcase_add_test(tc_core, test_fifo_next_hits_hwrap);
    tcase_add_test(tc_core, test_fifo_push_no_contiguous_space_even_with_space);
    tcase_add_test(tc_core, test_fifo_next_aligned_len_exceeds_size_returns_null);
    tcase_add_test(tc_core, test_fifo_len_tail_gt_head_no_hwrap);
    tcase_add_test(tc_core, test_fifo_pop_wrap_to_start);
    tcase_add_test(tc_core, test_fifo_next_success);
    tcase_add_test(tc_core, test_fifo_next_empty_fifo);
    tcase_add_test(tc_core, test_fifo_next_end_of_fifo);

    tcase_add_test(tc_core, test_queue_init);
    tcase_add_test(tc_core, test_queue_space_empty);
    tcase_add_test(tc_core, test_queue_len_empty);
    tcase_add_test(tc_core, test_queue_partial_fill);
    tcase_add_test(tc_core, test_queue_wrap_around);
    tcase_add_test(tc_core, test_queue_insert_empty);
    tcase_add_test(tc_core, test_queue_insert_sequential);
    tcase_add_test(tc_core, test_queue_insert_negative_diff);
    tcase_add_test(tc_core, test_queue_insert_wraparound_contiguous_and_old_rejected);
    tcase_add_test(tc_core, test_queue_insert_pos_gt_size);
    tcase_add_test(tc_core, test_queue_insert_ancient_data);
    tcase_add_test(tc_core, test_queue_insert_wrap);
    tcase_add_test(tc_core, test_queue_space_wrap);
    tcase_add_test(tc_core, test_queue_insert_len_gt_size);
    tcase_add_test(tc_core, test_queue_insert_len_gt_space);
    tcase_add_test(tc_core, test_queue_insert_len_gt_size_returns_error);
    tcase_add_test(tc_core, test_queue_pop);
    tcase_add_test(tc_core, test_queue_pop_wraparound);
    tcase_add_test(tc_core, test_queue_insert_updates_head_when_pos_plus_len_gt_head);
    tcase_add_test(tc_core, test_queue_insert_no_head_update_when_pos_plus_len_le_head);
    tcase_add_test(tc_core, test_queue_full_state_not_empty_and_drains_data);

    tcase_add_test(tc_utils, test_insert_timer);
    tcase_add_test(tc_utils, test_timer_insert_skips_zero_head);
    tcase_add_test(tc_utils, test_timer_cancel_existing_and_missing);
    tcase_add_test(tc_utils, test_pop_timer);
    tcase_add_test(tc_utils, test_is_timer_expired);
    tcase_add_test(tc_utils, test_cancel_timer);
    tcase_add_test(tc_utils, test_timer_pop_skips_zero_expires);
    tcase_add_test(tc_utils, test_timer_pop_reorders_heap);
    tcase_add_test(tc_utils, test_timer_pop_right_child_swap);
    tcase_add_test(tc_utils, test_timer_pop_break_when_root_small);
    tcase_add_test(tc_utils, test_is_timer_expired_skips_zero_head);
    tcase_add_test(tc_utils, test_wolfip_getdev_ex_api);
    tcase_add_test(tc_utils, test_wolfip_ll_at_and_ipconf_at_invalid);
    tcase_add_test(tc_utils, test_ip_is_local_conf_variants);
#if WOLFIP_ENABLE_LOOPBACK
    tcase_add_test(tc_utils, test_wolfip_loopback_defaults);
    tcase_add_test(tc_utils, test_wolfip_loopback_send_paths);
    tcase_add_test(tc_utils, test_wolfip_loopback_send_truncates);
    tcase_add_test(tc_utils, test_wolfip_loopback_send_null_container);
#endif
    tcase_add_test(tc_utils, test_wolfip_ipconfig_ex_per_interface);
    tcase_add_test(tc_utils, test_wolfip_poll_executes_timers_and_callbacks);
    tcase_add_test(tc_utils, test_filter_notify_tcp_metadata);
    tcase_add_test(tc_utils, test_filter_dispatch_no_callback);
    tcase_add_test(tc_utils, test_filter_dispatch_mask_not_set);
    tcase_add_test(tc_utils, test_filter_dispatch_lock_blocks);
    tcase_add_test(tc_utils, test_filter_dispatch_meta_null_initializes);
    tcase_add_test(tc_utils, test_filter_socket_event_unknown_proto);
    tcase_add_test(tc_utils, test_filter_socket_event_proto_variants);
    tcase_add_test(tc_utils, test_filter_setters_and_get_mask);
    tcase_add_test(tc_utils, test_sock_socket_errors);
    tcase_add_test(tc_utils, test_sock_socket_udp_protocol_zero);
    tcase_add_test(tc_utils, test_sock_socket_full_tables);
    tcase_add_test(tc_utils, test_filter_mask_for_proto_variants);
    tcase_add_test(tc_utils, test_filter_dispatch_paths);
    tcase_add_test(tc_utils, test_sock_wrappers_basic);
    tcase_add_test(tc_utils, test_sock_error_paths);
    tcase_add_test(tc_utils, test_sock_name_and_opt_errors);
    tcase_add_test(tc_utils, test_inline_helpers);
    tcase_add_test(tc_utils, test_sock_bind_wrong_family);
    tcase_add_test(tc_utils, test_sock_bind_invalid_fd);
    tcase_add_test(tc_utils, test_sock_bind_tcp_state_not_closed);
    tcase_add_test(tc_utils, test_sock_bind_tcp_filter_blocks);
    tcase_add_test(tc_utils, test_sock_bind_udp_src_port_nonzero);
    tcase_add_test(tc_utils, test_sock_bind_udp_filter_blocks);
    tcase_add_test(tc_utils, test_sock_bind_icmp_success);
    tcase_add_test(tc_utils, test_sock_connect_wrong_family);
    tcase_add_test(tc_utils, test_sock_accept_error_paths);
    tcase_add_test(tc_utils, test_sock_accept_non_tcp_socket_sets_addrlen);
    tcase_add_test(tc_utils, test_sock_accept_null_addr_with_addrlen);
    tcase_add_test(tc_utils, test_sock_recvfrom_short_addrlen);
    tcase_add_test(tc_utils, test_sock_recvfrom_udp_short_addrlen);
    tcase_add_test(tc_utils, test_sock_recvfrom_icmp_short_addrlen);
    tcase_add_test(tc_utils, test_sock_recvfrom_udp_fifo_alignment);
    tcase_add_test(tc_utils, test_sock_bind_non_local_ip_fails);
    tcase_add_test(tc_utils, test_sock_connect_bad_addrlen);
    tcase_add_test(tc_utils, test_sock_connect_tcp_bad_addrlen);
    tcase_add_test(tc_utils, test_sock_connect_invalid_args);
    tcase_add_test(tc_utils, test_sock_connect_invalid_tcp_fd);
    tcase_add_test(tc_utils, test_sock_connect_udp_invalid_fd);
    tcase_add_test(tc_utils, test_sock_connect_icmp_invalid_fd);
    tcase_add_test(tc_utils, test_sock_connect_udp_sets_local_ip_from_conf);
    tcase_add_test(tc_utils, test_sock_connect_udp_falls_back_to_primary);
    tcase_add_test(tc_utils, test_sock_connect_udp_primary_missing);
    tcase_add_test(tc_utils, test_sock_connect_udp_bound_local_ip_no_match);
    tcase_add_test(tc_utils, test_sock_connect_udp_bound_local_ip_match);
    tcase_add_test(tc_utils, test_sock_connect_icmp_sets_local_ip_from_conf);
    tcase_add_test(tc_utils, test_sock_connect_icmp_wrong_family);
    tcase_add_test(tc_utils, test_sock_connect_icmp_local_ip_pre_set);
    tcase_add_test(tc_utils, test_sock_connect_icmp_conf_null);
    tcase_add_test(tc_utils, test_sock_connect_icmp_falls_back_to_primary);
    tcase_add_test(tc_utils, test_sock_connect_icmp_primary_ip_any);
    tcase_add_test(tc_utils, test_sock_connect_icmp_primary_ip_fallback);
    tcase_add_test(tc_utils, test_sock_connect_tcp_established_returns_zero);
    tcase_add_test(tc_utils, test_sock_connect_tcp_bound_local_ip_match);
    tcase_add_test(tc_utils, test_sock_connect_tcp_bound_local_ip_no_match);
    tcase_add_test(tc_utils, test_sock_connect_tcp_filter_blocks);
    tcase_add_test(tc_utils, test_sock_connect_tcp_local_ip_from_conf);
    tcase_add_test(tc_utils, test_sock_connect_tcp_local_ip_from_primary);
    tcase_add_test(tc_utils, test_sock_connect_tcp_primary_ip_fallback);
    tcase_add_test(tc_utils, test_sock_connect_tcp_conf_null_primary_null);
    tcase_add_test(tc_utils, test_sock_connect_tcp_state_not_closed);
    tcase_add_test(tc_utils, test_sock_accept_negative_fd);
    tcase_add_test(tc_utils, test_sock_accept_invalid_tcp_fd);
    tcase_add_test(tc_utils, test_sock_accept_success_sets_addr);
    tcase_add_test(tc_utils, test_sock_accept_no_available_socket);
    tcase_add_test(tc_utils, test_sock_accept_no_free_socket_syn_rcvd);
    tcase_add_test(tc_utils, test_sock_accept_listen_no_connection);
    tcase_add_test(tc_utils, test_sock_accept_bound_local_ip_no_match);
    tcase_add_test(tc_utils, test_sock_sendto_error_paths);
    tcase_add_test(tc_utils, test_sock_sendto_null_buf_or_len_zero);
    tcase_add_test(tc_utils, test_sock_sendto_tcp_not_established);
    tcase_add_test(tc_utils, test_sock_recvfrom_tcp_states);
    tcase_add_test(tc_utils, test_sock_recvfrom_tcp_close_wait_empty_returns_zero);
    tcase_add_test(tc_utils, test_sock_recvfrom_tcp_close_wait_with_data);
    tcase_add_test(tc_utils, test_sock_recvfrom_tcp_established_sets_readable);
    tcase_add_test(tc_utils, test_sock_recvfrom_tcp_established_no_remaining_data);
    tcase_add_test(tc_utils, test_sock_recvfrom_invalid_socket_ids);
    tcase_add_test(tc_utils, test_sock_recvfrom_non_socket);
    tcase_add_test(tc_utils, test_sock_recvfrom_icmp_success);
    tcase_add_test(tc_utils, test_sock_opts_unknown_level);
    tcase_add_test(tc_utils, test_sock_opts_sol_ip_unknown_optname);
    tcase_add_test(tc_utils, test_sock_setsockopt_recvttl);
    tcase_add_test(tc_utils, test_sock_setsockopt_invalid_socket);
    tcase_add_test(tc_utils, test_sock_setsockopt_recvttl_invalid_params);
    tcase_add_test(tc_utils, test_sock_getsockopt_recvttl_value);
    tcase_add_test(tc_utils, test_sock_getsockopt_invalid_socket);
    tcase_add_test(tc_utils, test_sock_getsockopt_recvttl_invalid_params);
    tcase_add_test(tc_utils, test_sock_get_recv_ttl_invalid_socket);
    tcase_add_test(tc_utils, test_sock_accept_wrong_state);
    tcase_add_test(tc_utils, test_sock_get_recv_ttl_disabled);
    tcase_add_test(tc_utils, test_sock_get_recv_ttl_null);
    tcase_add_test(tc_utils, test_sock_connect_tcp_states);
    tcase_add_test(tc_utils, test_sock_listen_errors);
    tcase_add_test(tc_utils, test_sock_getpeername_errors);
    tcase_add_test(tc_utils, test_sock_getsockname_errors);
    tcase_add_test(tc_utils, test_sock_getsockname_null_addr);
    tcase_add_test(tc_utils, test_sock_getsockname_invalid_socket_ids);
    tcase_add_test(tc_utils, test_sock_getsockname_icmp_success);
    tcase_add_test(tc_utils, test_register_callback_variants);
    tcase_add_test(tc_utils, test_sock_connect_udp_bound_ip_not_local);
    tcase_add_test(tc_utils, test_sock_connect_udp_bound_ip_success);
    tcase_add_test(tc_utils, test_sock_connect_udp_primary_fallback);
    tcase_add_test(tc_utils, test_sock_connect_icmp_primary_fallback);
    tcase_add_test(tc_utils, test_sock_connect_tcp_filter_drop);
    tcase_add_test(tc_utils, test_sock_connect_tcp_src_port_low);
    tcase_add_test(tc_utils, test_sock_sendto_more_error_paths);
    tcase_add_test(tc_utils, test_sock_sendto_udp_no_dest);
    tcase_add_test(tc_utils, test_sock_sendto_udp_sets_dest_and_assigns);
    tcase_add_test(tc_utils, test_sock_sendto_udp_addrlen_short);
    tcase_add_test(tc_utils, test_sock_sendto_udp_len_too_large);
    tcase_add_test(tc_utils, test_sock_sendto_udp_fifo_full);
    tcase_add_test(tc_utils, test_sock_sendto_icmp_len_invalid);
    tcase_add_test(tc_utils, test_sock_sendto_icmp_fifo_full);
    tcase_add_test(tc_utils, test_sock_sendto_icmp_addrlen_short);
    tcase_add_test(tc_utils, test_sock_sendto_icmp_remote_zero);
    tcase_add_test(tc_utils, test_sock_sendto_icmp_assigns_src_port_and_sets_echo_id);
    tcase_add_test(tc_utils, test_sock_sendto_invalid_socket_ids);
    tcase_add_test(tc_utils, test_sock_sendto_non_socket_returns_minus_one);
    tcase_add_test(tc_utils, test_sock_sendto_udp_remote_ip_zero);
    tcase_add_test(tc_utils, test_sock_sendto_udp_primary_ip_fallback);
    tcase_add_test(tc_utils, test_sock_sendto_udp_zero_port_in_addr);
    tcase_add_test(tc_utils, test_sock_sendto_udp_src_port_low_adjusts);
    tcase_add_test(tc_utils, test_sock_sendto_udp_local_ip_conf_null);
    tcase_add_test(tc_utils, test_sock_sendto_udp_local_ip_from_primary);
    tcase_add_test(tc_utils, test_sock_sendto_tcp_txbuf_full);
    tcase_add_test(tc_utils, test_sock_sendto_tcp_partial_send_only);
    tcase_add_test(tc_utils, test_sock_sendto_tcp_multiple_segments_flags);
    tcase_add_test(tc_utils, test_sock_sendto_udp_fifo_push_fails_returns_eagain);
    tcase_add_test(tc_utils, test_sock_sendto_icmp_fifo_push_fails_returns_eagain);
    tcase_add_test(tc_utils, test_sock_sendto_icmp_src_port_zero_random_zero_sets_one);
    tcase_add_test(tc_utils, test_sock_sendto_icmp_non_echo_no_set_id);
    tcase_add_test(tc_utils, test_sock_sendto_icmp_local_ip_from_primary);
    tcase_add_test(tc_utils, test_sock_sendto_icmp_local_ip_pre_set);
    tcase_add_test(tc_utils, test_sock_sendto_icmp_conf_null_primary_null);
    tcase_add_test(tc_utils, test_sock_recvfrom_icmp_paths);
    tcase_add_test(tc_utils, test_sock_recvfrom_udp_payload_too_long);
    tcase_add_test(tc_utils, test_sock_recvfrom_icmp_payload_too_long);
    tcase_add_test(tc_utils, test_sock_accept_success);
    tcase_add_test(tc_utils, test_sock_accept_filtered_out);
    tcase_add_test(tc_utils, test_poll_tcp_ack_only_skips_send);
    tcase_add_test(tc_utils, test_poll_tcp_send_on_arp_hit);
    tcase_add_test(tc_utils, test_poll_tcp_residual_window_gates_data_segment);
    tcase_add_test(tc_utils, test_poll_tcp_residual_window_allows_exact_fit);
    tcase_add_test(tc_utils, test_poll_tcp_arp_request_on_miss);
    tcase_add_test(tc_utils, test_poll_udp_send_on_arp_hit);
    tcase_add_test(tc_utils, test_poll_icmp_send_on_arp_hit);
    tcase_add_test(tc_utils, test_dhcp_timer_cb_paths);
    tcase_add_test(tc_utils, test_dhcp_client_init_and_bound);
    tcase_add_test(tc_utils, test_dhcp_poll_offer_and_ack);
    tcase_add_test(tc_utils, test_dns_callback_ptr_response);
    tcase_add_test(tc_utils, test_udp_try_recv_short_frame);
    tcase_add_test(tc_utils, test_udp_try_recv_filter_drop);
    tcase_add_test(tc_utils, test_udp_try_recv_dhcp_running_local_zero);
    tcase_add_test(tc_utils, test_udp_try_recv_short_expected_len);
    tcase_add_test(tc_utils, test_udp_try_recv_conf_null);
    tcase_add_test(tc_utils, test_udp_try_recv_remote_ip_matches_local_ip);
    tcase_add_test(tc_utils, test_dns_callback_bad_flags);
    tcase_add_test(tc_utils, test_dns_callback_bad_name);
    tcase_add_test(tc_utils, test_tcp_input_ttl_zero_sends_icmp);
    tcase_add_test(tc_utils, test_dns_callback_bad_rr_rdlen);
    tcase_add_test(tc_utils, test_dhcp_parse_offer_no_match);
    tcase_add_test(tc_utils, test_dhcp_parse_ack_invalid);
    tcase_add_test(tc_utils, test_dhcp_poll_no_data_and_wrong_state);
#if WOLFIP_ENABLE_FORWARDING
    tcase_add_test(tc_utils, test_forward_prepare_paths);
    tcase_add_test(tc_utils, test_forward_prepare_loopback_no_ll);
    tcase_add_test(tc_utils, test_forward_packet_invalid_if);
    tcase_add_test(tc_utils, test_forward_packet_no_send);
    tcase_add_test(tc_utils, test_forward_packet_filter_drop);
    tcase_add_test(tc_utils, test_forward_packet_send_paths);
    tcase_add_test(tc_utils, test_forward_packet_filter_drop_udp_icmp);
#endif
    tcase_add_test(tc_utils, test_dns_format_ptr_name);
    tcase_add_test(tc_utils, test_dns_skip_and_copy_name);
    tcase_add_test(tc_utils, test_sock_opts_and_names);
    tcase_add_test(tc_utils, test_dns_send_query_errors);
    tcase_add_test(tc_utils, test_tcp_rto_cb_resets_flags_and_arms_timer);
    tcase_add_test(tc_utils, test_tcp_rto_cb_no_pending_resets_backoff);
    tcase_add_test(tc_utils, test_tcp_rto_cb_skips_unsent_desc);
    tcase_add_test(tc_utils, test_tcp_rto_cb_non_tcp_noop);
    tcase_add_test(tc_utils, test_tcp_rto_cb_non_established_noop);
    tcase_add_test(tc_utils, test_tcp_rto_cb_cancels_existing_timer);
    tcase_add_test(tc_utils, test_tcp_rto_cb_clears_sack_and_marks_lowest_only);
    tcase_add_test(tc_utils, test_tcp_rto_cb_ssthresh_floor_two_mss);
    tcase_add_test(tc_utils, test_tcp_rto_cb_fallback_marks_lowest_sent_when_no_snd_una_cover);
    tcase_add_test(tc_utils, test_sock_close_udp_icmp);
    tcase_add_test(tc_utils, test_sock_close_invalid_fds);
    tcase_add_test(tc_utils, test_sock_close_tcp_fin_wait_1);
    tcase_add_test(tc_utils, test_sock_close_tcp_other_state_closes);
    tcase_add_test(tc_utils, test_sock_close_tcp_closed_returns_minus_one);
    tcase_add_test(tc_utils, test_tcp_syn_sent_to_established);
    tcase_add_test(tc_utils, test_tcp_input_syn_sent_unexpected_flags);
    tcase_add_test(tc_utils, test_tcp_input_syn_sent_synack_transitions);
    tcase_add_test(tc_utils, test_tcp_input_syn_listen_mismatch);
    tcase_add_test(tc_utils, test_tcp_input_syn_rcvd_ack_established);
    tcase_add_test(tc_utils, test_tcp_input_filter_drop);
    tcase_add_test(tc_utils, test_tcp_input_port_mismatch_skips_socket);
    tcase_add_test(tc_utils, test_tcp_input_syn_bound_ip_mismatch);
    tcase_add_test(tc_utils, test_tcp_input_syn_rcvd_ack_wrong_flags);
    tcase_add_test(tc_utils, test_tcp_input_established_ack_only_returns);
    tcase_add_test(tc_utils, test_tcp_input_syn_dst_not_local);
    tcase_add_test(tc_utils, test_tcp_input_syn_dst_outside_subnet);
    tcase_add_test(tc_utils, test_tcp_input_listen_dst_match_false);
    tcase_add_test(tc_utils, test_tcp_input_established_fin_sets_close_wait);
    tcase_add_test(tc_utils, test_tcp_rst_closes_socket);
    tcase_add_test(tc_utils, test_tcp_rst_ignored_in_listen);
    tcase_add_test(tc_utils, test_tcp_rst_syn_rcvd_returns_to_listen);
    tcase_add_test(tc_utils, test_tcp_fin_wait_1_to_closing);
    tcase_add_test(tc_utils, test_tcp_last_ack_closes_socket);
    tcase_add_test(tc_utils, test_tcp_ack_acks_data_and_sets_writable);
    tcase_add_test(tc_utils, test_tcp_ack_duplicate_resend_clears_sent);
    tcase_add_test(tc_utils, test_tcp_ack_discards_zero_len_segment);
    tcase_add_test(tc_utils, test_tcp_ack_closes_last_ack_socket);
    tcase_add_test(tc_utils, test_tcp_ack_last_seq_match_no_close);
    tcase_add_test(tc_utils, test_tcp_ack_fresh_desc_updates_rtt_existing);
    tcase_add_test(tc_utils, test_tcp_ack_duplicate_zero_len_segment_large_ack);
    tcase_add_test(tc_utils, test_tcp_ack_duplicate_seq_match_large_seg_len);
    tcase_add_test(tc_utils, test_tcp_ack_duplicate_clears_sent_flag);
    tcase_add_test(tc_utils, test_tcp_ack_duplicate_discards_zero_len_segment);
    tcase_add_test(tc_utils, test_tcp_ack_cwnd_count_wrap);
    tcase_add_test(tc_utils, test_tcp_ack_updates_rtt_and_cwnd);
    tcase_add_test(tc_utils, test_tcp_ack_last_seq_not_last_ack_state);
    tcase_add_test(tc_utils, test_tcp_ack_no_progress_when_ack_far_ahead);
    tcase_add_test(tc_utils, test_tcp_ack_coarse_rtt_sets_writable);
    tcase_add_test(tc_utils, test_tcp_ack_duplicate_clears_sent_large_seg_len);
    tcase_add_test(tc_utils, test_tcp_ack_duplicate_discards_zero_len_segment_far_ack);
    tcase_add_test(tc_utils, test_tcp_ack_duplicate_ssthresh_min);
    tcase_add_test(tc_utils, test_tcp_ack_progress_resets_rto_recovery_state);
    tcase_add_test(tc_utils, test_tcp_ack_cwnd_grows_when_payload_acked_is_mss_minus_options);
    tcase_add_test(tc_utils, test_tcp_ack_inflight_deflate_sets_writable_without_acked_desc);
    tcase_add_test(tc_utils, test_tcp_input_peer_rwnd_growth_sets_writable);
    tcase_add_test(tc_utils, test_tcp_input_synack_negotiates_peer_mss);
    tcase_add_test(tc_utils, test_sock_sendto_tcp_respects_negotiated_peer_mss);
    tcase_add_test(tc_utils, test_sock_sendto_tcp_defaults_to_rfc_mss_when_unset_by_peer);
    tcase_add_test(tc_utils, test_tcp_recv_queues_payload_and_advances_ack);
    tcase_add_test(tc_utils, test_tcp_recv_wrong_state_does_nothing);
    tcase_add_test(tc_utils, test_tcp_recv_ack_mismatch_does_nothing);
    tcase_add_test(tc_utils, test_tcp_recv_wrap_seq_ahead_not_trimmed);
    tcase_add_test(tc_utils, test_tcp_recv_close_wait_ack_match);
    tcase_add_test(tc_utils, test_tcp_recv_queue_full_sends_ack);
    tcase_add_test(tc_utils, test_tcp_process_ts_uses_ecr);
    tcase_add_test(tc_utils, test_tcp_process_ts_nop_then_ts);
    tcase_add_test(tc_utils, test_tcp_process_ts_skips_unknown_option);
    tcase_add_test(tc_utils, test_tcp_process_ts_no_ecr);
    tcase_add_test(tc_utils, test_tcp_process_ts_updates_rtt_when_set);
    tcase_add_test(tc_utils, test_tcp_send_syn_advertises_sack_permitted);
    tcase_add_test(tc_utils, test_tcp_build_ack_options_does_not_write_past_returned_len);
    tcase_add_test(tc_utils, test_tcp_sort_sack_blocks_swaps_out_of_order);
    tcase_add_test(tc_utils, test_tcp_merge_sack_blocks_adjacent_and_disjoint);
    tcase_add_test(tc_utils, test_tcp_recv_tracks_holes_and_sack_blocks);
    tcase_add_test(tc_utils, test_tcp_rebuild_rx_sack_right_edge_wraps);
    tcase_add_test(tc_utils, test_tcp_consume_ooo_wrap_trim_and_promote);
    tcase_add_test(tc_utils, test_tcp_consume_ooo_wrap_drop_fully_acked);
    tcase_add_test(tc_utils, test_tcp_ack_sack_early_retransmit_before_three_dupack);
    tcase_add_test(tc_utils, test_tcp_input_listen_syn_without_sack_disables_sack);
    tcase_add_test(tc_utils, test_tcp_input_syn_sent_synack_without_sack_disables_sack);
    tcase_add_test(tc_utils, test_tcp_recv_partial_hole_fill_consumes_stored_ooo);
    tcase_add_test(tc_utils, test_tcp_ack_ignores_sack_when_not_negotiated);
    tcase_add_test(tc_utils, test_tcp_ack_malformed_sack_does_not_early_retransmit);
    tcase_add_test(tc_utils, test_tcp_ack_early_retransmit_once_per_ack);
    tcase_add_test(tc_utils, test_tcp_ack_no_sack_requires_three_dupacks);
    tcase_add_test(tc_utils, test_tcp_ack_no_sack_three_dupacks_with_zero_rwnd_triggers_retransmit);
    tcase_add_test(tc_utils, test_tcp_ack_wraparound_delta_reduces_inflight);
    tcase_add_test(tc_utils, test_tcp_ack_wraparound_delta_saturates_inflight);
    tcase_add_test(tc_utils, test_tcp_mark_unsacked_for_retransmit_wrap_seg_end);
    tcase_add_test(tc_utils, test_tcp_mark_unsacked_retransmits_partially_acked_segment);
    tcase_add_test(tc_utils, test_tcp_mark_unsacked_rescans_after_clearing_stale_sack);
    tcase_add_test(tc_utils, test_tcp_ack_sack_blocks_clamped_and_dropped);
    tcase_add_test(tc_utils, test_tcp_recv_ooo_capacity_limit);
    tcase_add_test(tc_utils, test_tcp_recv_overlapping_ooo_segments_coalesce_on_consume);
    tcase_add_test(tc_utils, test_tcp_input_syn_with_sack_option_enables_sack);
    tcase_add_test(tc_utils, test_tcp_input_syn_with_sack_option_respects_local_sack_offer);
    tcase_add_test(tc_utils, test_tcp_input_iplen_too_big);
    tcase_add_test(tc_utils, test_tcp_input_fin_wait_2_fin_sets_ack);
    tcase_add_test(tc_utils, test_tcp_input_fin_wait_2_ack_with_payload_receives);
    tcase_add_test(tc_utils, test_tcp_input_fin_wait_2_fin_with_payload_queues);
    tcase_add_test(tc_utils, test_tcp_sock_close_state_transitions);
    tcase_add_test(tc_utils, test_tcp_input_fin_wait_1_fin_with_payload_returns);
    tcase_add_test(tc_utils, test_socket_from_fd_invalid);
    tcase_add_test(tc_utils, test_socket_from_fd_valid);

    tcase_add_test(tc_proto, test_arp_request_basic);
    tcase_add_test(tc_proto, test_arp_request_throttle);
    tcase_add_test(tc_proto, test_arp_request_target_ip);
    tcase_add_test(tc_proto, test_arp_request_handling);
    tcase_add_test(tc_proto, test_arp_reply_handling);
    tcase_add_test(tc_proto, test_arp_lookup_success);
    tcase_add_test(tc_proto, test_arp_lookup_failure);
    tcase_add_test(tc_proto, test_wolfip_recv_ex_multi_interface_arp_reply);
    tcase_add_test(tc_proto, test_forward_prepare_null_args);
    tcase_add_test(tc_proto, test_send_ttl_exceeded_filter_drop);
    tcase_add_test(tc_proto, test_send_ttl_exceeded_ip_filter_drop);
    tcase_add_test(tc_proto, test_send_ttl_exceeded_eth_filter_drop);
    tcase_add_test(tc_proto, test_send_ttl_exceeded_no_send);
    tcase_add_test(tc_proto, test_arp_request_filter_drop);
    tcase_add_test(tc_proto, test_arp_request_invalid_interface);
    tcase_add_test(tc_proto, test_arp_request_no_send_fn);
    tcase_add_test(tc_proto, test_arp_reply_filter_drop);
    tcase_add_test(tc_proto, test_arp_recv_invalid_iface);
    tcase_add_test(tc_proto, test_arp_recv_filter_drop);
    tcase_add_test(tc_proto, test_arp_queue_packet_invalid_args);
    tcase_add_test(tc_proto, test_arp_queue_packet_reuses_existing_slot);
    tcase_add_test(tc_proto, test_arp_queue_packet_same_dest_different_if);
    tcase_add_test(tc_proto, test_arp_queue_packet_uses_empty_slot);
    tcase_add_test(tc_proto, test_arp_queue_packet_truncates_len);
    tcase_add_test(tc_proto, test_arp_queue_packet_slot_fallback_zero);
    tcase_add_test(tc_proto, test_arp_flush_pending_no_neighbor);
    tcase_add_test(tc_proto, test_arp_flush_pending_len_zero_clears);
    tcase_add_test(tc_proto, test_arp_flush_pending_null_stack);
    tcase_add_test(tc_proto, test_arp_flush_pending_skips_non_matching);
    tcase_add_test(tc_proto, test_arp_flush_pending_same_dest_if_idx_mismatch);
    tcase_add_test(tc_proto, test_arp_flush_pending_truncates_len);
    tcase_add_test(tc_proto, test_arp_flush_pending_processes_matching_entry);
    tcase_add_test(tc_proto, test_arp_flush_pending_match_condition_false);
    tcase_add_test(tc_proto, test_arp_queue_and_flush_matching_entry);
    tcase_add_test(tc_proto, test_arp_flush_pending_loopback_match);
    tcase_add_test(tc_proto, test_arp_store_neighbor_updates_existing);
    tcase_add_test(tc_proto, test_arp_store_neighbor_empty_slot);
    tcase_add_test(tc_proto, test_arp_store_neighbor_same_ip_diff_if);
    tcase_add_test(tc_proto, test_arp_store_neighbor_no_space);
    tcase_add_test(tc_proto, test_arp_store_neighbor_null_stack);
    tcase_add_test(tc_proto, test_arp_lookup_if_idx_mismatch);
    tcase_add_test(tc_proto, test_arp_request_missing_conf);
    tcase_add_test(tc_proto, test_arp_request_null_stack);
    tcase_add_test(tc_proto, test_arp_recv_request_other_ip_no_reply);
    tcase_add_test(tc_proto, test_arp_recv_null_stack);
    tcase_add_test(tc_proto, test_arp_recv_request_sends_reply);
    tcase_add_test(tc_proto, test_arp_recv_request_no_send_fn);
    tcase_add_test(tc_proto, test_wolfip_if_for_local_ip_paths);
    tcase_add_test(tc_proto, test_wolfip_if_for_local_ip_null_found);
    tcase_add_test(tc_proto, test_wolfip_socket_if_idx_invalid);
    tcase_add_test(tc_proto, test_icmp_try_recv_mismatch_paths);
    tcase_add_test(tc_proto, test_icmp_try_recv_mismatch_local_ip);
    tcase_add_test(tc_proto, test_icmp_try_recv_mismatch_src_port);
    tcase_add_test(tc_proto, test_icmp_try_recv_mismatch_remote_ip);
    tcase_add_test(tc_proto, test_wolfip_recv_on_not_for_us);
    tcase_add_test(tc_proto, test_wolfip_recv_on_filter_drop_eth);
#if WOLFIP_ENABLE_FORWARDING
    tcase_add_test(tc_proto, test_wolfip_recv_on_forward_ttl_exceeded);
    tcase_add_test(tc_proto, test_wolfip_recv_on_forward_arp_queue);
    tcase_add_test(tc_proto, test_wolfip_recv_on_forward_arp_hit_sends);
#endif
    tcase_add_test(tc_proto, test_select_nexthop_variants);
    tcase_add_test(tc_proto, test_route_for_ip_variants);
    tcase_add_test(tc_proto, test_route_for_ip_dest_matches_iface_ip);
    tcase_add_test(tc_proto, test_route_for_ip_no_primary_index);
    tcase_add_test(tc_proto, test_route_for_ip_null_stack);
    tcase_add_test(tc_proto, test_route_for_ip_gw_and_nonloop_fallback);
    tcase_add_test(tc_proto, test_inline_ip_helpers);
    tcase_add_test(tc_proto, test_forward_interface_variants);
    tcase_add_test(tc_proto, test_forward_interface_skips_ipaddr_any);
    tcase_add_test(tc_proto, test_forward_interface_dest_is_local_ip);
    tcase_add_test(tc_proto, test_forward_interface_short_circuit_cases);
    tcase_add_test(tc_proto, test_ip_recv_forward_ttl_exceeded);
    tcase_add_test(tc_proto, test_ip_recv_forward_arp_queue_and_flush);
    tcase_add_test(tc_proto, test_arp_flush_pending_ttl_expired);
    tcase_add_test(tc_proto, test_wolfip_forwarding_basic);
    tcase_add_test(tc_proto, test_wolfip_forwarding_ttl_expired);
    tcase_add_test(tc_proto, test_forward_packet_ip_filter_drop);
    tcase_add_test(tc_proto, test_forward_packet_eth_filter_drop);
    tcase_add_test(tc_proto, test_loopback_dest_not_forwarded);
    tcase_add_test(tc_proto, test_tcp_listen_rejects_wrong_interface);
    tcase_add_test(tc_proto, test_tcp_listen_accepts_bound_interface);
    tcase_add_test(tc_proto, test_tcp_listen_accepts_any_interface);
    tcase_add_test(tc_proto, test_sock_connect_selects_local_ip_multi_if);
    tcase_add_test(tc_proto, test_icmp_socket_send_recv);
    tcase_add_test(tc_proto, test_icmp_input_echo_reply_queues);
    tcase_add_test(tc_proto, test_icmp_input_echo_request_reply_sent);
    tcase_add_test(tc_proto, test_icmp_input_echo_request_dhcp_running_no_reply);
    tcase_add_test(tc_proto, test_icmp_input_echo_request_filter_drop);
    tcase_add_test(tc_proto, test_icmp_input_echo_request_ip_filter_drop);
    tcase_add_test(tc_proto, test_icmp_input_echo_request_eth_filter_drop);
    tcase_add_test(tc_proto, test_icmp_input_filter_drop_receiving);
    tcase_add_test(tc_proto, test_udp_sendto_and_recvfrom);
    tcase_add_test(tc_proto, test_udp_recvfrom_sets_remote_ip);
    tcase_add_test(tc_proto, test_udp_recvfrom_null_src_addr_len);
    tcase_add_test(tc_proto, test_udp_recvfrom_preserves_remote_ip);
    tcase_add_test(tc_proto, test_udp_recvfrom_null_addrlen);
    tcase_add_test(tc_proto, test_udp_recvfrom_src_equals_local_ip_does_not_persist_remote);
    tcase_add_test(tc_proto, test_dns_query_and_callback_a);
    tcase_add_test(tc_proto, test_dhcp_parse_offer_and_ack);
    tcase_add_test(tc_proto, test_tcp_handshake_and_fin_close_wait);

    tcase_add_test(tc_proto, test_regression_snd_una_initialized_on_syn_rcvd);
    tcase_add_test(tc_proto, test_regression_duplicate_syn_rejected_on_established);

    tcase_add_test(tc_utils, test_transport_checksum);
    tcase_add_test(tc_utils, test_iphdr_set_checksum);
    tcase_add_test(tc_utils, test_eth_output_add_header);
    tcase_add_test(tc_utils, test_eth_output_add_header_invalid_if);
    tcase_add_test(tc_utils, test_ip_output_add_header);
    tcase_add_test(tc_utils, test_ip_output_add_header_icmp);

    tcase_add_test(tc_wolfssl, test_wolfssl_io_ctx_registers_callbacks);
    tcase_add_test(tc_wolfssl, test_wolfssl_io_setio_success);
    tcase_add_test(tc_wolfssl, test_wolfssl_io_setio_invalid_ssl);
    tcase_add_test(tc_wolfssl, test_wolfssl_io_setio_invalid_ctx);
    tcase_add_test(tc_wolfssl, test_wolfssl_io_setio_invalid_fd);
    tcase_add_test(tc_wolfssl, test_wolfssl_io_setio_no_stack);
    tcase_add_test(tc_wolfssl, test_wolfssl_io_recv_behaviors);
    tcase_add_test(tc_wolfssl, test_wolfssl_io_recv_invalid_desc);
    tcase_add_test(tc_wolfssl, test_wolfssl_io_recv_fragmented_sequence);
    tcase_add_test(tc_wolfssl, test_wolfssl_io_recv_respects_buffer_size);
    tcase_add_test(tc_wolfssl, test_wolfssl_io_recv_want_read_keeps_buffer);
    tcase_add_test(tc_wolfssl, test_wolfssl_io_recv_alternating_eagain_short_reads);
    tcase_add_test(tc_wolfssl, test_wolfssl_io_send_behaviors);
    tcase_add_test(tc_wolfssl, test_wolfssl_io_send_invalid_desc);
    tcase_add_test(tc_wolfssl, test_wolfssl_io_send_want_write_keeps_buffer);
    suite_add_tcase(s, tc_core);
    suite_add_tcase(s, tc_utils);
    suite_add_tcase(s, tc_proto);
    suite_add_tcase(s, tc_wolfssl);
    return s;
}



int main(void)
{
    int n_fail = 0;
    Suite *s;
    SRunner *sr;

    s = wolf_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    n_fail = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (n_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;

}

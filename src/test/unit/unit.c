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

/* MOCKS */
/* pseudo random number generator to mock the random number generator */
uint32_t wolfIP_getrandom(void)
{
    unsigned int seed = 0xDAC0FFEE;
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


START_TEST(test_fifo_init)
{
    struct fifo f;
    fifo_init(&f, mem, memsz);
    ck_assert_int_eq(fifo_len(&f), 0);
    ck_assert_int_eq(fifo_space(&f), memsz);
    ck_assert_int_eq(fifo_len(&f), 0);
}
END_TEST

START_TEST(test_fifo_push_and_pop) {
    struct fifo f;
    struct pkt_desc *desc, *desc2;
    uint8_t data[] = {1, 2, 3, 4, 5};

    fifo_init(&f, mem, memsz);

    ck_assert_int_eq(fifo_space(&f), memsz);
    // Test push
    ck_assert_int_eq(fifo_push(&f, data, sizeof(data)), 0);

    // Test peek
    desc = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->len, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data));
    desc2 = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc2);
    ck_assert_ptr_eq(desc, desc2);
    ck_assert_int_eq(fifo_len(&f), desc->len + sizeof(struct pkt_desc));


    // Test pop
    desc = fifo_pop(&f);
    ck_assert_int_eq(fifo_space(&f), memsz);
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->len, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data));
    ck_assert_int_eq(fifo_len(&f), 0);
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
    ck_assert_int_eq(queue_space(&q), memsz);  // Full space should be available

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
    ck_assert_int_eq(queue_space(&q), memsz - 256);
    ck_assert_int_eq(queue_len(&q), 256);

}
END_TEST

START_TEST(test_queue_wrap_around) {
    struct queue q;
    queue_init(&q, mem, memsz, 0x12345678);
    q.head = 800;
    q.tail = 200;  // Head has wrapped around, so 600 bytes are filled
    ck_assert_int_eq(queue_space(&q), q.size - 600);
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
            TTL_EXCEEDED_ORIG_PACKET_SIZE);
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
    listener = &s.tcpsockets[listen_fd & ~MARK_TCP_SOCKET];

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
    listener = &s.tcpsockets[listen_fd & ~MARK_TCP_SOCKET];

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
    client = &s.tcpsockets[client_fd & ~MARK_TCP_SOCKET];
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
    listener = &s.tcpsockets[listen_fd & ~MARK_TCP_SOCKET];

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
    client = &s.tcpsockets[client_fd & ~MARK_TCP_SOCKET];
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
    ts = &s.udpsockets[udp_fd & ~MARK_UDP_SOCKET];
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
    ts = &s.tcpsockets[tcp_fd & ~MARK_TCP_SOCKET];
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

// Test for `ip_output_add_header` to set up IP headers and calculate checksums
START_TEST(test_ip_output_add_header) {
    struct tsocket t;
    struct wolfIP_ip_packet ip;
    struct wolfIP S;
    int result;
    struct wolfIP_tcp_seg *tcp;

    memset(&t, 0, sizeof(t));
    memset(&ip, 0, sizeof(ip));
    memset(&S, 0, sizeof(S));

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



Suite *wolf_suite(void)
{
    Suite *s;
    TCase *tc_core, *tc_proto, *tc_utils;

    s = suite_create("wolfIP");
    tc_core = tcase_create("Core");
    tc_utils = tcase_create("Utils");
    tc_proto = tcase_create("Protocols");


    tcase_add_test(tc_core, test_fifo_init);
    suite_add_tcase(s, tc_core);
    suite_add_tcase(s, tc_utils);
    suite_add_tcase(s, tc_proto);

    tcase_add_test(tc_core, test_fifo_push_and_pop);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_fifo_push_and_pop_multiple);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_fifo_pop_success);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_fifo_pop_empty);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_fifo_push_full);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_fifo_push_wrap);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_fifo_push_wrap_multiple);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_fifo_next_success);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_fifo_next_empty_fifo);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_fifo_next_end_of_fifo);
    suite_add_tcase(s, tc_core);

    tcase_add_test(tc_core, test_queue_init);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_queue_space_empty);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_queue_len_empty);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_queue_partial_fill);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_queue_wrap_around);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_queue_insert_empty);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_queue_insert_sequential);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_queue_pop);
    suite_add_tcase(s, tc_core);
    tcase_add_test(tc_core, test_queue_pop_wraparound);
    suite_add_tcase(s, tc_core);

    tcase_add_test(tc_utils, test_insert_timer);
    suite_add_tcase(s, tc_utils);
    tcase_add_test(tc_utils, test_pop_timer);
    suite_add_tcase(s, tc_utils);
    tcase_add_test(tc_utils, test_is_timer_expired);
    suite_add_tcase(s, tc_utils);
    tcase_add_test(tc_utils, test_cancel_timer);
    suite_add_tcase(s, tc_utils);
    tcase_add_test(tc_utils, test_wolfip_getdev_ex_api);
    suite_add_tcase(s, tc_utils);
#if WOLFIP_ENABLE_LOOPBACK
    tcase_add_test(tc_utils, test_wolfip_loopback_defaults);
    suite_add_tcase(s, tc_utils);
#endif
    tcase_add_test(tc_utils, test_wolfip_ipconfig_ex_per_interface);
    suite_add_tcase(s, tc_utils);

    tcase_add_test(tc_proto, test_arp_request_basic);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_proto, test_arp_request_throttle);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_proto, test_arp_request_target_ip);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_proto, test_arp_request_handling);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_proto, test_arp_reply_handling);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_proto, test_arp_lookup_success);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_proto, test_arp_lookup_failure);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_proto, test_wolfip_recv_ex_multi_interface_arp_reply);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_proto, test_wolfip_forwarding_basic);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_proto, test_wolfip_forwarding_ttl_expired);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_proto, test_loopback_dest_not_forwarded);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_proto, test_tcp_listen_rejects_wrong_interface);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_proto, test_tcp_listen_accepts_bound_interface);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_proto, test_tcp_listen_accepts_any_interface);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_proto, test_sock_connect_selects_local_ip_multi_if);
    suite_add_tcase(s, tc_proto);
    
    tcase_add_test(tc_utils, test_transport_checksum);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_utils, test_iphdr_set_checksum);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_utils, test_eth_output_add_header);
    suite_add_tcase(s, tc_proto);
    tcase_add_test(tc_utils, test_ip_output_add_header);
    suite_add_tcase(s, tc_proto);
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

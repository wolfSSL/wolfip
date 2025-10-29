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
static const char ifname[] = "mock0";
static const uint8_t ifmac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
static uint8_t last_frame_sent[LINK_MTU];
static uint32_t last_frame_sent_size = 0;

static int mock_send(struct ll *dev, void *frame, uint32_t  len)
{
    (void)dev;
    memcpy(last_frame_sent, frame, len);
    last_frame_sent_size = len;
    return 0;
}

static int mock_poll(struct ll *dev, void *frame, uint32_t len)
{
    (void)dev;
    (void)frame;
    (void)len;
    return 0;
}


void mock_link_init(struct wolfIP *s)
{
    struct ll *ll = &s->ll_dev;
    strncpy((char *)ll->ifname, ifname, sizeof(ll->ifname) - 1);
    memcpy(ll->mac, ifmac, 6);
    ll->mac[5] ^= 1;
    ll->poll = mock_poll;
    ll->send = mock_send;
}

static struct timers_binheap heap;
static void reset_heap(void) {
    heap.size = 0;
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

    fifo_init(&f, mem, memsz);
    ck_assert_int_eq(fifo_space(&f), memsz);

    // Test push
    ck_assert_int_eq(fifo_push(&f, data, sizeof(data)), 0);
    ck_assert_int_eq(fifo_len(&f), sizeof(data) + sizeof(struct pkt_desc));
    ck_assert_int_eq(fifo_space(&f), f.size - (sizeof(data) + sizeof(struct pkt_desc)));
    ck_assert_int_eq(fifo_push(&f, data2, sizeof(data2)), 0);

    // Test pop
    struct pkt_desc *desc = fifo_pop(&f);
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
    fifo_init(&f, mem, memsz);
    fifo_push(&f, data, sizeof(data)); // Add data to FIFO

    struct pkt_desc *desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc); // Ensure we got a valid descriptor
    ck_assert_int_eq(desc->len, sizeof(data)); // Check length
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), data, sizeof(data)); // Check data
}

START_TEST(test_fifo_pop_empty) {
    struct fifo f;
    fifo_init(&f, mem, memsz);

    struct pkt_desc *desc = fifo_pop(&f);
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
    fifo_init(&f, buffer, sizeof(buffer));
    fifo_push(&f, data, sizeof(data)); // Add data to FIFO

    // Pop the data to make space
    struct pkt_desc *desc = fifo_pop(&f);
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
    fifo_init(&f, mem, memsz);
    fifo_push(&f, data, sizeof(data)); // Add data to FIFO

    // Pop the data to make space
    struct pkt_desc *desc = fifo_pop(&f);
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

    fifo_init(&f, mem, memsz);

    // Add two packets to the FIFO
    fifo_push(&f, data1, sizeof(data1));
    fifo_push(&f, data2, sizeof(data2));
    ck_assert_int_eq(fifo_len(&f), sizeof(data1) + sizeof(data2) + 2 * sizeof(struct pkt_desc));

    // Get the first packet descriptor
    struct pkt_desc *desc = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc);

    // Get the next packet descriptor using fifo_next
    struct pkt_desc *next_desc = fifo_next(&f, desc);
    ck_assert_ptr_nonnull(next_desc); // Ensure next descriptor is valid
    ck_assert_int_eq(next_desc->len, sizeof(data2)); // Check length of next packet
}

START_TEST(test_fifo_next_empty_fifo) {
    struct fifo f;
    fifo_init(&f, mem, memsz);

    // Start with an empty FIFO
    struct pkt_desc *desc = NULL;
    struct pkt_desc *next_desc = fifo_next(&f, desc);
    ck_assert_ptr_eq(next_desc, NULL); // Ensure next returns NULL on empty FIFO
}

START_TEST(test_fifo_next_end_of_fifo) {
    struct fifo f;
    uint8_t data[] = {1, 2, 3, 4};

    fifo_init(&f, mem, memsz);
    fifo_push(&f, data, sizeof(data));

    struct pkt_desc *desc = fifo_peek(&f); // Get first packet
    fifo_pop(&f); // Simulate removing the packet
    struct pkt_desc *next_desc = fifo_next(&f, desc);
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
    queue_init(&q, mem, memsz, 0x12345678);
    uint8_t data[] = {1, 2, 3, 4};

    int res = queue_insert(&q, data, 0, sizeof(data));
    ck_assert_int_eq(res, 0);
    ck_assert_int_eq(queue_len(&q), sizeof(data));
    ck_assert_int_eq(q.head, sizeof(data));
    ck_assert_mem_eq((const uint8_t *)q.data, data, sizeof(data));
}
END_TEST

START_TEST(test_queue_insert_sequential) {
    struct queue q;
    queue_init(&q, mem, memsz, 0x12345678);
    uint8_t data1[] = {1, 2};
    uint8_t data2[] = {3, 4};

    int res1 = queue_insert(&q, data1, 0, sizeof(data1));
    int res2 = queue_insert(&q, data2, 2, sizeof(data2));
    ck_assert_int_eq(res1, 0);
    ck_assert_int_eq(res2, 0);
    ck_assert_int_eq(queue_len(&q), sizeof(data1) + sizeof(data2));
    ck_assert_mem_eq((const uint8_t *)q.data, data1, sizeof(data1));
    ck_assert_mem_eq((uint8_t *)q.data + 2, data2, sizeof(data2));
}
END_TEST

START_TEST(test_queue_pop) {
    struct queue q;
    queue_init(&q, mem, memsz, 0x12345678);
    uint8_t data[] = {5, 6, 7, 8};
    uint8_t out[4];

    queue_insert(&q, data, 0, sizeof(data));
    int len = queue_pop(&q, out, sizeof(out));
    ck_assert_int_eq(len, sizeof(out));
    ck_assert_mem_eq(out, data, sizeof(data));
    ck_assert_int_eq(queue_len(&q), 0);
    ck_assert_int_eq(q.tail, 4);
}
END_TEST

START_TEST(test_queue_pop_wraparound) {
    struct queue q;
    queue_init(&q, mem, memsz, 0x12345678);
    uint8_t data[] = {9, 10, 11, 12};
    uint8_t out[4];

    q.head = memsz - 1;
    q.tail = memsz - 1;
    queue_insert(&q, data, 0, sizeof(data));
    int len = queue_pop(&q, out, sizeof(out));
    ck_assert_int_eq(len, sizeof(out));
    ck_assert_mem_eq(out, data, sizeof(data));
    ck_assert_int_eq(queue_len(&q), 0);
}
END_TEST


/* Utils */
START_TEST(test_insert_timer) {
    reset_heap();

    struct wolfIP_timer tmr1 = { .expires = 100 };
    struct wolfIP_timer tmr2 = { .expires = 50 };
    struct wolfIP_timer tmr3 = { .expires = 200 };

    int id1 = timers_binheap_insert(&heap, tmr1);
    int id2 = timers_binheap_insert(&heap, tmr2);
    int id3 = timers_binheap_insert(&heap, tmr3);

    ck_assert_int_eq(heap.size, 3);
    ck_assert_int_lt(heap.timers[0].expires, heap.timers[1].expires);
    ck_assert_int_lt(heap.timers[0].expires, heap.timers[2].expires);
    ck_assert_int_ne(id1, id2);
    ck_assert_int_ne(id2, id3);
}
END_TEST

START_TEST(test_pop_timer) {
    reset_heap();

    struct wolfIP_timer tmr1 = { .expires = 300 };
    struct wolfIP_timer tmr2 = { .expires = 100 };
    struct wolfIP_timer tmr3 = { .expires = 200 };

    timers_binheap_insert(&heap, tmr1);
    timers_binheap_insert(&heap, tmr2);
    timers_binheap_insert(&heap, tmr3);

    struct wolfIP_timer popped = timers_binheap_pop(&heap);
    ck_assert_int_eq(popped.expires, 100);
    ck_assert_int_eq(heap.size, 2);
    ck_assert_int_lt(heap.timers[0].expires, heap.timers[1].expires);
}
END_TEST

START_TEST(test_is_timer_expired) {
    reset_heap();

    struct wolfIP_timer tmr = { .expires = 150 };
    timers_binheap_insert(&heap, tmr);

    ck_assert_int_eq(is_timer_expired(&heap, 100), 0);
    ck_assert_int_eq(is_timer_expired(&heap, 150), 1);
    ck_assert_int_eq(is_timer_expired(&heap, 200), 1);
}
END_TEST

START_TEST(test_cancel_timer) {
    reset_heap();

    struct wolfIP_timer tmr1 = { .expires = 100 };
    struct wolfIP_timer tmr2 = { .expires = 200 };

    int id1 = timers_binheap_insert(&heap, tmr1);
    int id2 = timers_binheap_insert(&heap, tmr2);
    (void)id2;

    timer_binheap_cancel(&heap, id1);
    ck_assert_int_eq(heap.timers[0].expires, 0);  // tmr1 canceled

    struct wolfIP_timer popped = timers_binheap_pop(&heap);
    ck_assert_int_eq(popped.expires, 200);  // Only tmr2 should remain
    ck_assert_int_eq(heap.size, 0);
}
END_TEST


/* Arp suite */
START_TEST(test_arp_request_basic)
{
    struct wolfIP s;
    struct arp_packet *arp;
    wolfIP_init(&s);
    uint32_t target_ip = 0xC0A80002; /* 192.168.0.2 */
    mock_link_init(&s);
    s.last_tick = 1000;
    arp_request(&s, target_ip);
    ck_assert_int_eq(last_frame_sent_size, sizeof(struct arp_packet));
    arp = (struct arp_packet *)last_frame_sent;
    ck_assert_mem_eq(arp->eth.dst, "\xff\xff\xff\xff\xff\xff", 6);
    ck_assert_mem_eq(arp->eth.src, s.ll_dev.mac, 6);
    ck_assert_int_eq(arp->eth.type, ee16(0x0806));
    ck_assert_int_eq(arp->htype, ee16(1));
    ck_assert_int_eq(arp->ptype, ee16(0x0800));
    ck_assert_int_eq(arp->hlen, 6);
    ck_assert_int_eq(arp->plen, 4);
    ck_assert_int_eq(arp->opcode, ee16(ARP_REQUEST));
    ck_assert_mem_eq(arp->sma, s.ll_dev.mac, 6);
    ck_assert_int_eq(arp->sip, ee32(s.ipconf.ip));
    ck_assert_mem_eq(arp->tma, "\x00\x00\x00\x00\x00\x00", 6);
    ck_assert_int_eq(arp->tip, ee32(target_ip));
}
END_TEST

START_TEST(test_arp_request_throttle)
{
    struct wolfIP s;
    wolfIP_init(&s);
    uint32_t target_ip = 0xC0A80002; /*192.168.0.2*/
    mock_link_init(&s);
    s.last_tick = 1000;
    s.arp.last_arp = 880;
    last_frame_sent_size = 0;
    arp_request(&s, target_ip);
    ck_assert_int_eq(last_frame_sent_size, 0);
}
END_TEST

START_TEST(test_arp_request_target_ip) {
    uint32_t target_ip = 0xC0A80002;
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);
    s.last_tick = 1000;
    arp_request(&s, target_ip);
    ck_assert_int_eq(((struct arp_packet *)(last_frame_sent))->tip, ee32(target_ip));
}
END_TEST

START_TEST(test_arp_request_handling) {
    struct arp_packet arp_req;
    struct arp_packet *arp_reply;
    memset(&arp_req, 0, sizeof(arp_req));
    uint32_t req_ip = 0xC0A80002; // 192.168.0.2
    uint32_t device_ip = 0xC0A80001; // 192.168.0.1
    uint8_t req_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    //uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);
    s.ipconf.ip = device_ip;

    /* Prepare ARP request */
    arp_req.opcode = ee16(ARP_REQUEST);
    arp_req.sip = ee32(req_ip);
    memcpy(arp_req.sma, req_mac, 6);
    arp_req.tip = ee32(device_ip);

    /* Call arp_recv with the ARP request */
    arp_recv(&s, &arp_req, sizeof(arp_req));
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
    ck_assert_mem_eq(arp_reply->sma, s.ll_dev.mac, 6);     // source MAC
    ck_assert_int_eq(arp_reply->sip, ee32(device_ip));     // source IP
    ck_assert_mem_eq(arp_reply->tma, req_mac, 6);          // target MAC
    ck_assert_int_eq(arp_reply->tip, ee32(req_ip));        // target IP
}
END_TEST

START_TEST(test_arp_reply_handling) {
    struct arp_packet arp_reply;
    memset(&arp_reply, 0, sizeof(arp_reply));
    uint32_t reply_ip = 0xC0A80003; // 192.168.0.3
    uint8_t reply_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);

    /* Prepare ARP reply */
    arp_reply.opcode = ee16(ARP_REPLY);
    arp_reply.sip = ee32(reply_ip);
    memcpy(arp_reply.sma, reply_mac, 6);

    /* Call arp_recv with the ARP reply */
    arp_recv(&s, &arp_reply, sizeof(arp_reply));

    /* Check if ARP table updated with reply IP and MAC */
    ck_assert_int_eq(s.arp.neighbors[0].ip, reply_ip);
    ck_assert_mem_eq(s.arp.neighbors[0].mac, reply_mac, 6);

    /* Update same IP with a different MAC address */
    uint8_t new_mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    memcpy(arp_reply.sma, new_mac, 6);
    arp_recv(&s, &arp_reply, sizeof(arp_reply));

    /* Check if ARP table updates with new MAC */
    ck_assert_mem_eq(s.arp.neighbors[0].mac, new_mac, 6);
}
END_TEST

START_TEST(test_arp_lookup_success) {
    uint8_t found_mac[6];
    uint32_t ip = 0xC0A80002;
    const uint8_t mock_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);

    /* Add a known IP-MAC pair */
    s.arp.neighbors[0].ip = ip;
    memcpy(s.arp.neighbors[0].mac, mock_mac, 6);

    /* Test arp_lookup */
    int result = arp_lookup(&s, ip, found_mac);
    ck_assert_int_eq(result, 0);
    ck_assert_mem_eq(found_mac, mock_mac, 6);
}
END_TEST

START_TEST(test_arp_lookup_failure) {
    uint8_t found_mac[6];
    uint32_t ip = 0xC0A80004;
    struct wolfIP s;
    wolfIP_init(&s);
    mock_link_init(&s);

    /* Ensure arp_lookup fails for unknown IP */
    int result = arp_lookup(&s, ip, found_mac);
    ck_assert_int_eq(result, -1);
    uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};
    ck_assert_mem_eq(found_mac, zero_mac, 6);
}
END_TEST


// Test for `transport_checksum` calculation
START_TEST(test_transport_checksum) {
    union transport_pseudo_header ph;
    struct wolfIP_tcp_seg tcp_data;
    memset(&ph, 0, sizeof(ph));
    memset(&tcp_data, 0, sizeof(tcp_data));

    // Set up pseudo-header values for test
    ph.ph.src = 0xc0a80101; // 192.168.1.1
    ph.ph.dst = 0xc0a80102; // 192.168.1.2
    ph.ph.proto = FT_IPPROTO_TCP;
    ph.ph.len = ee16(20); // TCP header length (without options)

    // Test with a simple TCP header with src/dst ports and no data
    tcp_data.src_port = ee16(12345);
    tcp_data.dst_port = ee16(80);
    tcp_data.seq = ee32(1);
    tcp_data.ack = ee32(0);
    tcp_data.hlen = 5; // offset=5 (20 bytes)
    tcp_data.flags = 0x02; // SYN
    tcp_data.win = ee16(65535);

    uint16_t checksum = transport_checksum(&ph, &tcp_data.src_port);
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
    ip.proto = FT_IPPROTO_TCP;
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
    memset(&S, 0, sizeof(S));
    memset(&eth_frame, 0, sizeof(eth_frame));

    uint8_t test_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    memcpy(S.ll_dev.mac, test_mac, 6);

    eth_output_add_header(&S, NULL, &eth_frame, ETH_TYPE_IP);

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
    memset(&t, 0, sizeof(t));
    memset(&ip, 0, sizeof(ip));
    memset(&S, 0, sizeof(S));

    // Setup socket and IP stack parameters
    t.local_ip = 0xc0a80101;   // 192.168.1.1
    t.remote_ip = 0xc0a80102;  // 192.168.1.2
    t.S = &S;

    // Run the function for a TCP packet
    int result = ip_output_add_header(&t, &ip, FT_IPPROTO_TCP, 40);
    ck_assert_int_eq(result, 0);

    // Validate IP header fields
    ck_assert_uint_eq(ip.ver_ihl, 0x45);
    ck_assert_uint_eq(ip.ttl, 64);
    ck_assert_uint_eq(ip.proto, FT_IPPROTO_TCP);
    ck_assert_uint_eq(ip.src, ee32(t.local_ip));
    ck_assert_uint_eq(ip.dst, ee32(t.remote_ip));
    ck_assert_msg(ip.csum != 0, "IP header checksum should not be zero");

    // Check the pseudo-header checksum calculation for TCP segment
    struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)&ip;
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

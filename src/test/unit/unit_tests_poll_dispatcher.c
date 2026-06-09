/* unit_tests_poll_dispatcher.c
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
/* ------------------------------------------------------------------ */
/* Helper state local to this file                                     */
/* ------------------------------------------------------------------ */

static int poll_dispatcher_poll_calls;
static int poll_dispatcher_frames_left;
/* Custom poll callback that synthesises minimal non-Ethernet frames */
static int poll_noneth_frame_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    (void)dev;
    (void)len;
    if (poll_dispatcher_frames_left <= 0)
        return 0;
    poll_dispatcher_frames_left--;
    poll_dispatcher_poll_calls++;
    /* Return a minimal payload of 1 byte so len > 0 */
    memset(frame, 0, 1);
    return 1;
}

/* Poll that always returns 0 (no data) */
static int poll_returns_zero(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    (void)dev; (void)frame; (void)len;
    poll_dispatcher_poll_calls++;
    return 0;
}

/* Poll that returns negative (error) */
static int poll_returns_negative(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    (void)dev; (void)frame; (void)len;
    poll_dispatcher_poll_calls++;
    return -1;
}

/* Timer that re-arms itself once */
static int poll_rearm_timer_count;
static struct wolfIP *poll_rearm_stack_ptr;
static void poll_rearm_timer_cb(void *arg)
{
    struct wolfIP_timer new_tmr;
    (void)arg;
    poll_rearm_timer_count++;
    if (poll_rearm_timer_count == 1 && poll_rearm_stack_ptr) {
        memset(&new_tmr, 0, sizeof(new_tmr));
        new_tmr.cb = test_timer_cb;
        new_tmr.expires = 50; /* already expired at t=100 */
        timers_binheap_insert(&poll_rearm_stack_ptr->timers, new_tmr);
    }
}

/* Timer that cancels the next head in the heap */
static int poll_cancel_next_count;
static struct wolfIP *poll_cancel_next_stack;
static int poll_cancel_next_handle;
static void poll_cancel_first_timer_cb(void *arg)
{
    (void)arg;
    poll_cancel_next_count++;
    if (poll_cancel_next_stack && poll_cancel_next_handle != NO_TIMER)
        timer_binheap_cancel(&poll_cancel_next_stack->timers, poll_cancel_next_handle);
}

/* EAGAIN-returning send mock */
static int eagain_send_count;
static int eagain_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    (void)dev; (void)frame; (void)len;
    eagain_send_count++;
    return -WOLFIP_EAGAIN;
}

/* ------------------------------------------------------------------ */
/* Device-poll path tests                                              */
/* ------------------------------------------------------------------ */

START_TEST(test_poll_device_poll_returns_zero_exits_loop)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *ll;

    wolfIP_init(&s);
    mock_link_init(&s);
    ll = wolfIP_ll_at(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    poll_dispatcher_poll_calls = 0;
    ll->poll = poll_returns_zero;
    ll->non_ethernet = 0;

    (void)wolfIP_poll(&s, 100);
    /* poll was called exactly once (returned 0, loop exits) */
    ck_assert_int_eq(poll_dispatcher_poll_calls, 1);
}
END_TEST

START_TEST(test_poll_device_poll_returns_negative_exits_loop)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *ll;

    wolfIP_init(&s);
    mock_link_init(&s);
    ll = wolfIP_ll_at(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    poll_dispatcher_poll_calls = 0;
    ll->poll = poll_returns_negative;
    ll->non_ethernet = 0;

    (void)wolfIP_poll(&s, 100);
    /* poll was called once, negative means len <= 0, loop exits */
    ck_assert_int_eq(poll_dispatcher_poll_calls, 1);
}
END_TEST

START_TEST(test_poll_device_non_ethernet_path_receives)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *ll;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    ll = wolfIP_ll_at(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    /* Configure as non-ethernet device and give it one frame to deliver */
    ll->non_ethernet = 1;
    ll->mtu = 128;
    poll_dispatcher_poll_calls = 0;
    poll_dispatcher_frames_left = 1;
    ll->poll = poll_noneth_frame_poll;

    (void)wolfIP_poll(&s, 100);
    /* poll was called at least once (the frame was fetched) */
    ck_assert_int_ge(poll_dispatcher_poll_calls, 1);
}
END_TEST

START_TEST(test_poll_device_non_ethernet_minimum_mtu_clamped)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *ll;

    wolfIP_init(&s);
    mock_link_init(&s);
    ll = wolfIP_ll_at(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    ll->non_ethernet = 1;
    /* Set mtu to LINK_MTU_MIN (64); wolfIP_ll_frame_mtu returns 64.
     * frame_mtu - ETH_HEADER_LEN == 64-14 = 50 bytes of payload space.
     * The poll loop should proceed (not break) since 64 > ETH_HEADER_LEN. */
    ll->mtu = LINK_MTU_MIN;
    poll_dispatcher_poll_calls = 0;
    poll_dispatcher_frames_left = 1;
    ll->poll = poll_noneth_frame_poll;

    (void)wolfIP_poll(&s, 100);
    /* poll was called (frame fetched) because frame_mtu > ETH_HEADER_LEN */
    ck_assert_int_ge(poll_dispatcher_poll_calls, 1);
}
END_TEST

START_TEST(test_poll_device_budget_exhaustion_stops_at_budget)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *ll;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    ll = wolfIP_ll_at(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    /* Give budget+5 frames; poll should consume exactly WOLFIP_POLL_BUDGET */
    poll_dispatcher_frames_left = WOLFIP_POLL_BUDGET + 5;
    poll_dispatcher_poll_calls = 0;
    ll->non_ethernet = 1;
    ll->mtu = 256;
    ll->poll = poll_noneth_frame_poll;

    (void)wolfIP_poll(&s, 100);
    ck_assert_int_le(poll_dispatcher_poll_calls, WOLFIP_POLL_BUDGET + 1);
    /* At least WOLFIP_POLL_BUDGET calls were made */
    ck_assert_int_ge(poll_dispatcher_poll_calls, WOLFIP_POLL_BUDGET);
}
END_TEST

START_TEST(test_poll_device_no_poll_callback_skipped)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *ll;

    wolfIP_init(&s);
    mock_link_init(&s);
    ll = wolfIP_ll_at(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);

    /* Remove poll callback entirely; wolfIP_poll should not crash */
    ll->poll = NULL;
    (void)wolfIP_poll(&s, 100);
    /* no assertion needed beyond "does not crash" */
    ck_assert_int_eq(0, 0);
}
END_TEST

/* ------------------------------------------------------------------ */
/* Timer tests                                                         */
/* ------------------------------------------------------------------ */

START_TEST(test_poll_timer_fires_multiple_in_one_tick)
{
    struct wolfIP s;
    struct wolfIP_timer tmr;
    int i;

    wolfIP_init(&s);
    mock_link_init(&s);
    timer_cb_calls = 0;

    for (i = 0; i < 5; i++) {
        memset(&tmr, 0, sizeof(tmr));
        tmr.cb = test_timer_cb;
        tmr.expires = (uint64_t)(50 + i * 10);
        timers_binheap_insert(&s.timers, tmr);
    }
    /* Poll at t=100: all 5 timers are expired */
    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(timer_cb_calls, 5);
    ck_assert_uint_eq(s.timers.size, 0U);
}
END_TEST

START_TEST(test_poll_timer_cancelled_tombstone_drained_before_live_timer)
{
    struct wolfIP s;
    struct wolfIP_timer tmr;
    int handle;

    wolfIP_init(&s);
    mock_link_init(&s);
    timer_cb_calls = 0;

    /* Insert one timer and cancel it immediately — tombstone only */
    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 50;
    handle = timers_binheap_insert(&s.timers, tmr);

    /* Cancel to create a tombstone */
    timer_binheap_cancel(&s.timers, handle);

    /* Insert a second live timer after the cancelled one */
    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 60;
    timers_binheap_insert(&s.timers, tmr);

    /* Poll at t=100: the tombstone is at the heap head; is_timer_expired
     * drains it via timers_binheap_pop which also consumes the next timer.
     * Verify poll does not crash and heap is empty after draining. */
    (void)wolfIP_poll(&s, 100);
    /* Heap must be empty after tombstone draining */
    ck_assert_uint_eq(s.timers.size, 0U);
}
END_TEST

START_TEST(test_poll_timer_callback_rearms_itself)
{
    struct wolfIP s;
    struct wolfIP_timer tmr;

    wolfIP_init(&s);
    mock_link_init(&s);
    timer_cb_calls = 0;
    poll_rearm_timer_count = 0;
    poll_rearm_stack_ptr = &s;

    /* Insert the rearm-on-first-fire timer */
    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = poll_rearm_timer_cb;
    tmr.expires = 50;
    timers_binheap_insert(&s.timers, tmr);

    /* First poll fires the timer, which inserts another timer at t=50 */
    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(poll_rearm_timer_count, 1);
    /* The re-armed timer (expires=50, already expired) should also fire */
    ck_assert_int_eq(timer_cb_calls, 1);
    /* Total timers used = 0 now (heap should be empty) */
    ck_assert_uint_eq(s.timers.size, 0U);

    poll_rearm_stack_ptr = NULL;
}
END_TEST

START_TEST(test_poll_timer_callback_cancels_sibling)
{
    struct wolfIP s;
    struct wolfIP_timer tmr;

    wolfIP_init(&s);
    mock_link_init(&s);
    timer_cb_calls = 0;
    poll_cancel_next_count = 0;
    poll_cancel_next_stack = &s;

    /* Insert the sibling timer first so it gets a known handle */
    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 60;
    poll_cancel_next_handle = timers_binheap_insert(&s.timers, tmr);

    /* Insert the canceller at lower expiry so it fires first */
    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = poll_cancel_first_timer_cb;
    tmr.expires = 30;
    timers_binheap_insert(&s.timers, tmr);

    /* At t=100 both are expired; canceller fires first and cancels sibling */
    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(poll_cancel_next_count, 1);
    /* The sibling was cancelled; timer_cb should NOT have fired */
    ck_assert_int_eq(timer_cb_calls, 0);

    poll_cancel_next_stack = NULL;
    poll_cancel_next_handle = NO_TIMER;
}
END_TEST

/* ------------------------------------------------------------------ */
/* Socket callback dispatch                                            */
/* ------------------------------------------------------------------ */

START_TEST(test_poll_icmp_socket_callback_dispatched)
{
    struct wolfIP s;
    int icmp_sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    socket_cb_calls = 0;
    socket_cb_last_fd = -1;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    wolfIP_register_callback(&s, icmp_sd, test_socket_cb, NULL);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    ts->events = CB_EVENT_READABLE;

    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(socket_cb_calls, 1);
    ck_assert_int_eq(socket_cb_last_fd, icmp_sd);
    ck_assert_uint_eq(ts->events, 0U); /* cleared after dispatch */
}
END_TEST

START_TEST(test_poll_tcp_socket_callback_dispatched)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    socket_cb_calls = 0;
    socket_cb_last_fd = -1;

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    ts->sock.tcp.state = TCP_ESTABLISHED;
    wolfIP_register_callback(&s, tcp_sd, test_socket_cb, NULL);
    ts->events = CB_EVENT_READABLE;

    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(socket_cb_calls, 1);
    ck_assert_int_eq(socket_cb_last_fd, tcp_sd);
    ck_assert_uint_eq(ts->events, 0U);
}
END_TEST

START_TEST(test_poll_udp_socket_callback_dispatched)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    socket_cb_calls = 0;
    socket_cb_last_fd = -1;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    wolfIP_register_callback(&s, udp_sd, test_socket_cb, NULL);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->events = CB_EVENT_WRITABLE;

    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(socket_cb_calls, 1);
    ck_assert_int_eq(socket_cb_last_fd, udp_sd);
    ck_assert_uint_eq(ts->events, 0U);
}
END_TEST

#if WOLFIP_RAWSOCKETS
START_TEST(test_poll_raw_socket_callback_dispatched)
{
    struct wolfIP s;
    int raw_sd;
    struct rawsocket *r;

    wolfIP_init(&s);
    mock_link_init(&s);
    socket_cb_calls = 0;
    socket_cb_last_fd = -1;

    raw_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_ICMP);
    ck_assert_int_ge(raw_sd, 0);
    wolfIP_register_callback(&s, raw_sd, test_socket_cb, NULL);
    r = &s.rawsockets[SOCKET_UNMARK(raw_sd)];
    r->events = CB_EVENT_READABLE;

    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(socket_cb_calls, 1);
    ck_assert_int_eq(socket_cb_last_fd, raw_sd);
    ck_assert_uint_eq(r->events, 0U);
}
END_TEST
#endif /* WOLFIP_RAWSOCKETS */

#if WOLFIP_PACKET_SOCKETS
START_TEST(test_poll_packet_socket_callback_dispatched)
{
    struct wolfIP s;
    int pkt_sd;
    struct packetsocket *p;

    wolfIP_init(&s);
    mock_link_init(&s);
    socket_cb_calls = 0;
    socket_cb_last_fd = -1;

    pkt_sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, ee16(ETH_TYPE_IP));
    ck_assert_int_ge(pkt_sd, 0);
    wolfIP_register_callback(&s, pkt_sd, test_socket_cb, NULL);
    p = &s.packetsockets[SOCKET_UNMARK(pkt_sd)];
    p->events = CB_EVENT_READABLE;

    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(socket_cb_calls, 1);
    ck_assert_int_eq(socket_cb_last_fd, pkt_sd);
    ck_assert_uint_eq(p->events, 0U);
}
END_TEST
#endif /* WOLFIP_PACKET_SOCKETS */

/* ------------------------------------------------------------------ */
/* TCP TX loop                                                         */
/* ------------------------------------------------------------------ */

/* Helper: set up a minimal ESTABLISHED TCP socket */
static void setup_tcp_socket(struct wolfIP *s, struct tsocket *ts,
                              ip4 local_ip, ip4 remote_ip,
                              unsigned int if_idx)
{
    memset(ts, 0, sizeof(*ts));
    ts->proto   = WI_IPPROTO_TCP;
    ts->S       = s;
    ts->sock.tcp.state  = TCP_ESTABLISHED;
    ts->local_ip        = local_ip;
    ts->remote_ip       = remote_ip;
    ts->if_idx          = (uint8_t)if_idx;
    ts->src_port        = 9000;
    ts->dst_port        = 80;
    ts->sock.tcp.rto    = 100;
    ts->sock.tcp.cwnd   = TCP_MSS * 4;
    ts->sock.tcp.peer_rwnd = TCP_MSS * 4;
    fifo_init(&ts->sock.tcp.txbuf, ts->txmem, TXBUF_SIZE);
}

START_TEST(test_poll_tx_tcp_pkt_flag_sent_desc_skipped)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);

    /* Pre-populate ARP so send can proceed */
    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, 6);

    ts = &s.tcpsockets[0];
    setup_tcp_socket(&s, ts, local_ip, remote_ip, TEST_PRIMARY_IF);

    /* Enqueue one segment and mark it PKT_FLAG_SENT */
    ck_assert_int_eq(enqueue_tcp_tx(ts, 4, TCP_FLAG_ACK | TCP_FLAG_PSH), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    desc->flags |= PKT_FLAG_SENT;

    last_frame_sent_size = 0;
    (void)wolfIP_poll(&s, 200);

    /* The already-sent descriptor is skipped; nothing new sent */
    ck_assert_uint_eq(last_frame_sent_size, 0U);
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.tcp.txbuf));
}
END_TEST

START_TEST(test_poll_tx_tcp_arp_miss_emits_arp_request)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A0000FEU; /* no ARP entry */

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    ts = &s.tcpsockets[0];
    setup_tcp_socket(&s, ts, local_ip, remote_ip, TEST_PRIMARY_IF);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 4, TCP_FLAG_ACK | TCP_FLAG_PSH), 0);

    /* Use now >= 1000 to pass the ARP rate-limit check (last_arp + 1000 > now) */
    (void)wolfIP_poll(&s, 2000);

    /* An ARP request (EtherType 0x0806) should have been emitted */
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x06);
    /* The queued segment is still pending */
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.tcp.txbuf));
}
END_TEST

START_TEST(test_poll_tx_tcp_filter_tcp_blocks_send)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, 6);

    /* Block all SENDING events from the filter */
    filter_block_calls = 0;
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));

    ts = &s.tcpsockets[0];
    setup_tcp_socket(&s, ts, local_ip, remote_ip, TEST_PRIMARY_IF);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 4, TCP_FLAG_ACK | TCP_FLAG_PSH), 0);
    last_frame_sent_size = 0;

    (void)wolfIP_poll(&s, 200);

    /* Filter should have been invoked and blocked the send */
    ck_assert_int_ge(filter_block_calls, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0U);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_poll_tx_tcp_send_eagain_breaks_loop)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct wolfIP_ll_dev *ll;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, 6);

    ll = wolfIP_ll_at(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);
    eagain_send_count = 0;
    ll->send = eagain_send;

    ts = &s.tcpsockets[0];
    setup_tcp_socket(&s, ts, local_ip, remote_ip, TEST_PRIMARY_IF);
    /* Add TX space so CB_EVENT_WRITABLE may be set */
    queue_init(&ts->sock.tcp.rxbuf, ts->rxmem, RXBUF_SIZE, 0);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 4, TCP_FLAG_ACK | TCP_FLAG_PSH), 0);

    (void)wolfIP_poll(&s, 200);
    ck_assert_int_ge(eagain_send_count, 1);
    /* Descriptor remains in queue after EAGAIN */
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.tcp.txbuf));
}
END_TEST

START_TEST(test_poll_tx_tcp_zero_window_starts_persist)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x04};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, 6);

    ts = &s.tcpsockets[0];
    setup_tcp_socket(&s, ts, local_ip, remote_ip, TEST_PRIMARY_IF);
    /* Force zero peer window */
    ts->sock.tcp.peer_rwnd = 0;
    ts->sock.tcp.cwnd      = TCP_MSS;

    ck_assert_int_eq(enqueue_tcp_tx(ts, 4, TCP_FLAG_ACK | TCP_FLAG_PSH), 0);
    ck_assert_int_eq(ts->sock.tcp.persist_active, 0);

    (void)wolfIP_poll(&s, 200);
    /* Persist must have been started because window == 0 */
    ck_assert_int_eq(ts->sock.tcp.persist_active, 1);
}
END_TEST

START_TEST(test_poll_tx_tcp_retransmit_replay)
{
    struct wolfIP s;
    struct tsocket *ts;
    struct pkt_desc *desc;
    ip4 local_ip  = 0x0A000001U;
    ip4 remote_ip = 0x0A000002U;
    uint8_t peer_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x05};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, local_ip, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);

    s.arp.neighbors[0].ip = remote_ip;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, 6);

    ts = &s.tcpsockets[0];
    setup_tcp_socket(&s, ts, local_ip, remote_ip, TEST_PRIMARY_IF);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 4, TCP_FLAG_ACK | TCP_FLAG_PSH), 0);
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    ck_assert_ptr_nonnull(desc);
    /* Mark as retransmit */
    desc->flags |= PKT_FLAG_RETRANS;
    last_frame_sent_size = 0;

    (void)wolfIP_poll(&s, 200);
    /* Retransmit path was taken; frame was sent */
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x00);
}
END_TEST

/* ------------------------------------------------------------------ */
/* TCP TX loop – loopback path                                         */
/* ------------------------------------------------------------------ */

#if WOLFIP_ENABLE_LOOPBACK
START_TEST(test_poll_tx_tcp_loopback_path)
{
    struct wolfIP s;
    struct tsocket *ts;
    ip4 loopback_ip = 0x7F000001U; /* 127.0.0.1 */

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_filter_set_callback(NULL, NULL);

    ts = &s.tcpsockets[0];
    setup_tcp_socket(&s, ts, loopback_ip, loopback_ip, TEST_LOOPBACK_IF);

    ck_assert_int_eq(enqueue_tcp_tx(ts, 4, TCP_FLAG_ACK | TCP_FLAG_PSH), 0);
    last_frame_sent_size = 0;

    (void)wolfIP_poll(&s, 200);
    /* On the loopback path, the MAC is filled from the loop device */
    /* The segment is either sent or retains; no crash expected */
    ck_assert_int_eq(0, 0);
}
END_TEST
#endif /* WOLFIP_ENABLE_LOOPBACK */

/* ------------------------------------------------------------------ */
/* UDP TX loop                                                         */
/* ------------------------------------------------------------------ */

START_TEST(test_poll_tx_udp_sends_on_arp_hit)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t peer_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, 6);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5000);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));

    (void)wolfIP_poll(&s, 200);
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x00);
}
END_TEST

START_TEST(test_poll_tx_udp_filter_ip_blocks_send)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {1, 2, 3, 4};
    uint8_t peer_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x77};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, 6);

    filter_block_calls = 0;
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5001);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));

    last_frame_sent_size = 0;
    (void)wolfIP_poll(&s, 200);

    ck_assert_int_ge(filter_block_calls, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0U);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_poll_tx_udp_eagain_retains_queue)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_ll_dev *ll;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {1, 2, 3, 4};
    uint8_t peer_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x88};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, 6);

    ll = wolfIP_ll_at(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);
    eagain_send_count = 0;
    ll->send = eagain_send;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5002);
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    ts->if_idx = TEST_PRIMARY_IF;

    (void)wolfIP_poll(&s, 200);
    ck_assert_int_ge(eagain_send_count, 1);
    /* Descriptor must still be in queue */
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.txbuf));

    ll->send = mock_send;
}
END_TEST

START_TEST(test_poll_tx_udp_drain_sets_writable)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[1400];
    uint8_t peer_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x99};
    int rc;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, 6);

    memset(payload, 0xAB, sizeof(payload));
    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5004);
    sin.sin_addr.s_addr = ee32(0x0A000002U);

    /* Fill the UDP txbuf until sendto() reports the buffer full. */
    do {
        rc = wolfIP_sock_sendto(&s, udp_sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin));
    } while (rc > 0);
    ck_assert_int_eq(rc, -WOLFIP_EAGAIN);
    ts->if_idx = TEST_PRIMARY_IF;

    /* A blocked sendto() would now be waiting for CB_EVENT_WRITABLE. */
    ts->events = 0;

    /* Poll drains the queue over the wire (mock_send succeeds). */
    (void)wolfIP_poll(&s, 200);

    /* Draining freed txbuf space, so the drain must raise CB_EVENT_WRITABLE to
     * wake a blocked sender. Before the fix this bit was never set for
     * non-loopback UDP sockets and the sender deadlocked. */
    ck_assert_uint_ne((unsigned)(ts->events & CB_EVENT_WRITABLE), 0U);
}
END_TEST

START_TEST(test_poll_tx_udp_broadcast_sets_ff_mac)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[4] = {1, 2, 3, 4};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5003);
    /* Subnet-directed broadcast: 10.0.0.255 */
    sin.sin_addr.s_addr = ee32(0x0A0000FFU);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));

    (void)wolfIP_poll(&s, 200);
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    /* Destination MAC should be FF:FF:FF:FF:FF:FF */
    ck_assert_uint_eq(last_frame_sent[0], 0xFF);
    ck_assert_uint_eq(last_frame_sent[1], 0xFF);
    ck_assert_uint_eq(last_frame_sent[2], 0xFF);
}
END_TEST

#if WOLFIP_ENABLE_LOOPBACK
START_TEST(test_poll_tx_udp_loopback_path_no_crash)
{
    struct wolfIP s;
    struct tsocket *t;
    struct wolfIP_sockaddr_in sin;
    int udp_sd;
    uint8_t payload[4] = {0x11, 0x22, 0x33, 0x44};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x7F000001U, 0xFF000000U, 0);
    wolfIP_filter_set_callback(NULL, NULL);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    t = &s.udpsockets[SOCKET_UNMARK(udp_sd)];

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(6000);
    sin.sin_addr.s_addr = ee32(0x7F000001U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    /* Force the socket to use the loopback interface */
    t->if_idx = TEST_LOOPBACK_IF;

    (void)wolfIP_poll(&s, 200);
    /* No crash expected; loopback MAC fill executed */
    ck_assert_int_eq(0, 0);
}
END_TEST
#endif /* WOLFIP_ENABLE_LOOPBACK */

/* ------------------------------------------------------------------ */
/* ICMP TX loop                                                        */
/* ------------------------------------------------------------------ */

START_TEST(test_poll_tx_icmp_sends_on_arp_hit)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN + 4];
    uint8_t peer_mac[6] = {0xAA, 0x11, 0x22, 0x33, 0x44, 0x55};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, 6);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    memset(payload, 0, sizeof(payload));
    payload[0] = ICMP_ECHO_REQUEST;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));

    (void)wolfIP_poll(&s, 200);
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x00);
}
END_TEST

START_TEST(test_poll_tx_icmp_filter_blocks_send)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN + 4];
    uint8_t peer_mac[6] = {0xAA, 0x11, 0x22, 0x33, 0x44, 0x66};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, 6);

    filter_block_calls = 0;
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    memset(payload, 0, sizeof(payload));
    payload[0] = ICMP_ECHO_REQUEST;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));

    last_frame_sent_size = 0;
    (void)wolfIP_poll(&s, 200);

    ck_assert_int_ge(filter_block_calls, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0U);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

START_TEST(test_poll_tx_icmp_eagain_retains_queue)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_ll_dev *ll;
    struct tsocket *ts;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN + 4];
    uint8_t peer_mac[6] = {0xAA, 0x11, 0x22, 0x33, 0x44, 0x77};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, peer_mac, 6);

    ll = wolfIP_ll_at(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(ll);
    eagain_send_count = 0;
    ll->send = eagain_send;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    ts = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    memset(payload, 0, sizeof(payload));
    payload[0] = ICMP_ECHO_REQUEST;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    ts->if_idx = TEST_PRIMARY_IF;

    (void)wolfIP_poll(&s, 200);
    ck_assert_int_ge(eagain_send_count, 1);
    ck_assert_ptr_nonnull(fifo_peek(&ts->sock.udp.txbuf));

    ll->send = mock_send;
}
END_TEST

START_TEST(test_poll_tx_icmp_broadcast_sets_ff_mac)
{
    struct wolfIP s;
    int icmp_sd;
    struct wolfIP_sockaddr_in sin;
    uint8_t payload[ICMP_HEADER_LEN + 4];

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    memset(payload, 0, sizeof(payload));
    payload[0] = ICMP_ECHO_REQUEST;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A0000FFU); /* .255 broadcast */
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));

    (void)wolfIP_poll(&s, 200);
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    ck_assert_uint_eq(last_frame_sent[0], 0xFF);
    ck_assert_uint_eq(last_frame_sent[1], 0xFF);
    ck_assert_uint_eq(last_frame_sent[2], 0xFF);
}
END_TEST

#if WOLFIP_ENABLE_LOOPBACK
START_TEST(test_poll_tx_icmp_loopback_path_no_crash)
{
    struct wolfIP s;
    struct tsocket *t;
    struct wolfIP_sockaddr_in sin;
    int icmp_sd;
    uint8_t payload[ICMP_HEADER_LEN + 4];

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x7F000001U, 0xFF000000U, 0);
    wolfIP_filter_set_callback(NULL, NULL);

    icmp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_ICMP);
    ck_assert_int_gt(icmp_sd, 0);
    t = &s.icmpsockets[SOCKET_UNMARK(icmp_sd)];
    memset(payload, 0, sizeof(payload));
    payload[0] = ICMP_ECHO_REQUEST;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x7F000001U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, icmp_sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));
    t->if_idx = TEST_LOOPBACK_IF;

    (void)wolfIP_poll(&s, 200);
    ck_assert_int_eq(0, 0);
}
END_TEST
#endif /* WOLFIP_ENABLE_LOOPBACK */

/* ------------------------------------------------------------------ */
/* RAW TX loop                                                         */
/* ------------------------------------------------------------------ */

#if WOLFIP_RAWSOCKETS
START_TEST(test_poll_tx_raw_sends_on_arp_hit)
{
    struct wolfIP s;
    int sd;
    uint8_t payload[8];
    struct wolfIP_sockaddr_in sin;
    uint8_t nh_mac[6] = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, nh_mac, 6);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    memset(payload, 0xCC, sizeof(payload));
    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));

    last_frame_sent_size = 0;
    (void)wolfIP_poll(&s, 100);
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x00);
}
END_TEST

START_TEST(test_poll_tx_raw_arp_miss_emits_request)
{
    struct wolfIP s;
    int sd;
    uint8_t payload[8];
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A00FFFEU); /* no ARP entry */
    memset(payload, 0, sizeof(payload));
    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));

    /* Use now >= 1000 to pass the ARP rate-limit check */
    (void)wolfIP_poll(&s, 2000);
    /* ARP request must have been emitted */
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    ck_assert_uint_eq(last_frame_sent[12], 0x08);
    ck_assert_uint_eq(last_frame_sent[13], 0x06);
}
END_TEST

START_TEST(test_poll_tx_raw_dst_zero_skips_descriptor)
{
    struct wolfIP s;
    int sd;
    struct rawsocket *r;
    struct wolfIP_ip_packet *ip_pkt;
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN + 4];

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    r = &s.rawsockets[SOCKET_UNMARK(sd)];

    /* struct wolfIP_ip_packet already includes the Ethernet header at
     * offset 0; cast the whole buffer (do NOT advance by ETH_HEADER_LEN). */
    memset(buf, 0, sizeof(buf));
    ip_pkt = (struct wolfIP_ip_packet *)buf;
    ip_pkt->dst = 0; /* zero dst triggers skip */
    ip_pkt->src = ee32(0x0A000001U);
    ip_pkt->ver_ihl = 0x45;
    ip_pkt->proto = WI_IPPROTO_UDP;
    ip_pkt->len = ee16(IP_HEADER_LEN + 4);
    iphdr_set_checksum(ip_pkt);
    ck_assert_int_eq(fifo_push(&r->txbuf, buf, sizeof(buf)), 0);

    last_frame_sent_size = 0;
    (void)wolfIP_poll(&s, 100);
    /* Descriptor with dst==0 must have been silently discarded */
    ck_assert_ptr_eq(fifo_peek(&r->txbuf), NULL);
    ck_assert_uint_eq(last_frame_sent_size, 0U);
}
END_TEST

START_TEST(test_poll_tx_raw_filter_blocks_send)
{
    struct wolfIP s;
    int sd;
    uint8_t payload[8];
    struct wolfIP_sockaddr_in sin;
    uint8_t nh_mac[6] = {0x60, 0x61, 0x62, 0x63, 0x64, 0x65};

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);

    s.arp.neighbors[0].ip = 0x0A000002U;
    s.arp.neighbors[0].if_idx = TEST_PRIMARY_IF;
    memcpy(s.arp.neighbors[0].mac, nh_mac, 6);

    filter_block_calls = 0;
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x0A000002U);
    memset(payload, 0, sizeof(payload));
    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));

    last_frame_sent_size = 0;
    (void)wolfIP_poll(&s, 100);
    ck_assert_int_ge(filter_block_calls, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0U);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST

#if WOLFIP_ENABLE_LOOPBACK
START_TEST(test_poll_tx_raw_loopback_path)
{
    struct wolfIP s;
    int sd;
    struct rawsocket *r;
    uint8_t payload[8];
    struct wolfIP_sockaddr_in sin;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x7F000001U, 0xFF000000U, 0);
    wolfIP_filter_set_callback(NULL, NULL);

    sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_RAW, WI_IPPROTO_UDP);
    ck_assert_int_ge(sd, 0);
    r = &s.rawsockets[SOCKET_UNMARK(sd)];
    r->if_idx = TEST_LOOPBACK_IF;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ee32(0x7F000001U);
    memset(payload, 0xAB, sizeof(payload));
    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));

    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(0, 0);
}
END_TEST
#endif /* WOLFIP_ENABLE_LOOPBACK */

#endif /* WOLFIP_RAWSOCKETS */

/* ------------------------------------------------------------------ */
/* PACKET TX loop                                                      */
/* ------------------------------------------------------------------ */

#if WOLFIP_PACKET_SOCKETS
START_TEST(test_poll_tx_packet_sends_frame)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_ll sll;
    uint8_t frame_buf[ETH_HEADER_LEN + 8];
    struct wolfIP_eth_frame *ethf = (struct wolfIP_eth_frame *)frame_buf;
    struct wolfIP_sockaddr_ll bind_sll;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, ee16(ETH_TYPE_IP));
    ck_assert_int_ge(sd, 0);

    memset(&bind_sll, 0, sizeof(bind_sll));
    bind_sll.sll_family   = AF_PACKET;
    bind_sll.sll_protocol = ee16(ETH_TYPE_IP);
    bind_sll.sll_ifindex  = TEST_PRIMARY_IF;
    bind_sll.sll_halen    = 6;
    memset(bind_sll.sll_addr, 0xFF, 6);
    ck_assert_int_eq(wolfIP_sock_bind(&s, sd,
                (struct wolfIP_sockaddr *)&bind_sll, sizeof(bind_sll)), 0);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = ee16(ETH_TYPE_IP);
    sll.sll_ifindex  = TEST_PRIMARY_IF;
    sll.sll_halen    = 6;
    memset(sll.sll_addr, 0xFF, 6);

    memset(frame_buf, 0, sizeof(frame_buf));
    memcpy(ethf->dst, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(ethf->src, "\x01\x02\x03\x04\x05\x06", 6);
    ethf->type = ee16(ETH_TYPE_IP);
    memset(ethf->data, 0x5A, 8);

    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, frame_buf, sizeof(frame_buf), 0,
                (struct wolfIP_sockaddr *)&sll, sizeof(sll)), (int)sizeof(frame_buf));

    (void)wolfIP_poll(&s, 100);
    ck_assert_uint_eq(last_frame_sent_size, sizeof(frame_buf));
}
END_TEST

START_TEST(test_poll_tx_packet_filter_blocks_advances_desc)
{
    struct wolfIP s;
    int sd;
    struct wolfIP_sockaddr_ll sll;
    uint8_t frame1[ETH_HEADER_LEN + 4];
    uint8_t frame2[ETH_HEADER_LEN + 4];
    struct wolfIP_eth_frame *ethf1 = (struct wolfIP_eth_frame *)frame1;
    struct wolfIP_eth_frame *ethf2 = (struct wolfIP_eth_frame *)frame2;
    struct wolfIP_sockaddr_ll bind_sll;

    wolfIP_init(&s);
    mock_link_init(&s);

    /* Block all SENDING events — packet socket loop calls fifo_next on block */
    filter_block_calls = 0;
    filter_block_reason = WOLFIP_FILT_SENDING;
    wolfIP_filter_set_callback(test_filter_cb_block, NULL);
    wolfIP_filter_set_mask(WOLFIP_FILT_MASK(WOLFIP_FILT_SENDING));

    sd = wolfIP_sock_socket(&s, AF_PACKET, IPSTACK_SOCK_RAW, ee16(ETH_TYPE_IP));
    ck_assert_int_ge(sd, 0);

    memset(&bind_sll, 0, sizeof(bind_sll));
    bind_sll.sll_family   = AF_PACKET;
    bind_sll.sll_protocol = ee16(ETH_TYPE_IP);
    bind_sll.sll_ifindex  = TEST_PRIMARY_IF;
    bind_sll.sll_halen    = 6;
    memset(bind_sll.sll_addr, 0xFF, 6);
    ck_assert_int_eq(wolfIP_sock_bind(&s, sd,
                (struct wolfIP_sockaddr *)&bind_sll, sizeof(bind_sll)), 0);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = ee16(ETH_TYPE_IP);
    sll.sll_ifindex  = TEST_PRIMARY_IF;
    sll.sll_halen    = 6;
    memset(sll.sll_addr, 0xFF, 6);

    memset(frame1, 0, sizeof(frame1));
    memcpy(ethf1->dst, "\xff\xff\xff\xff\xff\xff", 6);
    ethf1->type = ee16(ETH_TYPE_IP);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, frame1, sizeof(frame1), 0,
                (struct wolfIP_sockaddr *)&sll, sizeof(sll)), (int)sizeof(frame1));

    memset(frame2, 0, sizeof(frame2));
    memcpy(ethf2->dst, "\xff\xff\xff\xff\xff\xff", 6);
    ethf2->type = ee16(ETH_TYPE_IP);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, sd, frame2, sizeof(frame2), 0,
                (struct wolfIP_sockaddr *)&sll, sizeof(sll)), (int)sizeof(frame2));

    last_frame_sent_size = 0;
    (void)wolfIP_poll(&s, 100);

    /* Filter blocked both frames; calls should be > 0 */
    ck_assert_int_ge(filter_block_calls, 1);
    ck_assert_uint_eq(last_frame_sent_size, 0U);

    wolfIP_filter_set_callback(NULL, NULL);
}
END_TEST
#endif /* WOLFIP_PACKET_SOCKETS */

/* ------------------------------------------------------------------ */
/* Combined / integration tests                                        */
/* ------------------------------------------------------------------ */

START_TEST(test_poll_combined_timer_and_socket_cb_in_same_tick)
{
    struct wolfIP s;
    struct wolfIP_timer tmr;
    int udp_sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    timer_cb_calls = 0;
    socket_cb_calls = 0;

    memset(&tmr, 0, sizeof(tmr));
    tmr.cb = test_timer_cb;
    tmr.expires = 50;
    timers_binheap_insert(&s.timers, tmr);

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    wolfIP_register_callback(&s, udp_sd, test_socket_cb, NULL);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    ts->events = CB_EVENT_READABLE;

    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(timer_cb_calls, 1);
    ck_assert_int_eq(socket_cb_calls, 1);
}
END_TEST

START_TEST(test_poll_no_timers_and_no_events_is_noop)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    /* Nothing registered; should return 0 silently */
    ck_assert_int_eq(wolfIP_poll(&s, 100), 0);
    ck_assert_int_eq(wolfIP_poll(&s, 101), 0);
}
END_TEST

START_TEST(test_poll_last_tick_updated)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);

    (void)wolfIP_poll(&s, 12345ULL);
    ck_assert_uint_eq(s.last_tick, 12345ULL);
    (void)wolfIP_poll(&s, 99999ULL);
    ck_assert_uint_eq(s.last_tick, 99999ULL);
}
END_TEST

#if WOLFIP_ENABLE_LOOPBACK
START_TEST(test_poll_loopback_interface_iterated)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *ll;

    wolfIP_init(&s);
    mock_link_init(&s);

    /* Attach a counter poll to the loopback device */
    ll = wolfIP_ll_at(&s, TEST_LOOPBACK_IF);
    ck_assert_ptr_nonnull(ll);

    poll_dispatcher_poll_calls = 0;
    ll->poll = poll_returns_zero;

    (void)wolfIP_poll(&s, 100);
    /* Loopback has its own poll; should have been called */
    ck_assert_int_ge(poll_dispatcher_poll_calls, 1);
}
END_TEST
#endif /* WOLFIP_ENABLE_LOOPBACK */

START_TEST(test_poll_multiple_udp_sockets_both_cbs_dispatched)
{
    struct wolfIP s;
    int udp_sd1, udp_sd2;
    struct tsocket *ts1, *ts2;

    wolfIP_init(&s);
    mock_link_init(&s);
    socket_cb_calls = 0;

    udp_sd1 = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd1, 0);
    wolfIP_register_callback(&s, udp_sd1, test_socket_cb, NULL);
    ts1 = &s.udpsockets[SOCKET_UNMARK(udp_sd1)];
    ts1->events = CB_EVENT_READABLE;

    udp_sd2 = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd2, 0);
    wolfIP_register_callback(&s, udp_sd2, test_socket_cb, NULL);
    ts2 = &s.udpsockets[SOCKET_UNMARK(udp_sd2)];
    ts2->events = CB_EVENT_WRITABLE;

    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(socket_cb_calls, 2);
}
END_TEST

START_TEST(test_poll_tcp_cb_not_dispatched_when_closed)
{
    struct wolfIP s;
    int tcp_sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    socket_cb_calls = 0;

    tcp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_STREAM, WI_IPPROTO_TCP);
    ck_assert_int_gt(tcp_sd, 0);
    ts = &s.tcpsockets[SOCKET_UNMARK(tcp_sd)];
    /* Leave state == TCP_CLOSED */
    ts->sock.tcp.state = TCP_CLOSED;
    wolfIP_register_callback(&s, tcp_sd, test_socket_cb, NULL);
    ts->events = CB_EVENT_READABLE;

    (void)wolfIP_poll(&s, 100);
    /* Callback must NOT fire for CLOSED state */
    ck_assert_int_eq(socket_cb_calls, 0);
}
END_TEST

START_TEST(test_poll_udp_cb_not_dispatched_without_events)
{
    struct wolfIP s;
    int udp_sd;
    struct tsocket *ts;

    wolfIP_init(&s);
    mock_link_init(&s);
    socket_cb_calls = 0;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);
    wolfIP_register_callback(&s, udp_sd, test_socket_cb, NULL);
    ts = &s.udpsockets[SOCKET_UNMARK(udp_sd)];
    /* No events set */
    ts->events = 0;

    (void)wolfIP_poll(&s, 100);
    ck_assert_int_eq(socket_cb_calls, 0);
}
END_TEST

#ifdef IP_MULTICAST
START_TEST(test_poll_tx_udp_multicast_arp_skipped_uses_mcast_mac)
{
    struct wolfIP s;
    int udp_sd;
    struct wolfIP_sockaddr_in sin;
    struct wolfIP_ip_mreq mreq;
    uint8_t payload[4] = {1, 2, 3, 4};
    int one = 1;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0);
    wolfIP_filter_set_callback(NULL, NULL);
    last_frame_sent_size = 0;

    udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(udp_sd, 0);

    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = ee32(0xE0000001U); /* 224.0.0.1 */
    mreq.imr_interface.s_addr = ee32(0x0A000001U);
    (void)wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    (void)wolfIP_sock_setsockopt(&s, udp_sd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_LOOP, &one, sizeof(one));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(5500);
    sin.sin_addr.s_addr = ee32(0xE0000001U);
    ck_assert_int_eq(wolfIP_sock_sendto(&s, udp_sd, payload, sizeof(payload), 0,
                (struct wolfIP_sockaddr *)&sin, sizeof(sin)), (int)sizeof(payload));

    (void)wolfIP_poll(&s, 200);
    /* Frame sent (multicast MAC derived from IP, no ARP needed) */
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    /* Destination MAC should be 01:00:5E:xx:xx:xx */
    ck_assert_uint_eq(last_frame_sent[0], 0x01);
    ck_assert_uint_eq(last_frame_sent[1], 0x00);
    ck_assert_uint_eq(last_frame_sent[2], 0x5E);
}
END_TEST
#endif /* IP_MULTICAST */

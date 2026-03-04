/* unit_wolfguard.c
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

/*
 * Unit tests for wolfip_wolfguard.c, driver logic (no kernel required).
 *
 * The tests replace the real TUN file descriptor with the write-end of a
 * pipe so that wg_send/wg_poll can be exercised in a fully userspace
 * environment.  Kernel operations (interface creation, netlink config,
 * ioctl bring-up) are bypassed by calling the internal helpers directly
 * rather than going through wolfIP_wg_init().
 */

#ifndef WOLFIP_WOLFGUARD
# define WOLFIP_WOLFGUARD
#endif

#include "check.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

/* Pull in the implementation directly (same approach as unit_esp.c) */
#include "../../wolfip_wolfguard.c"


/* Pipe fds: write_fd is used as the mock TUN fd in wg_state.tun_fd.
 * Tests write IP packets to read_fd to simulate incoming kernel traffic,
 * and read from read_fd to inspect what was sent toward the kernel. */
static int pipe_rd;  /* read end, inspect wg_send output */
static int pipe_wr;  /* write end, inject wg_poll input   */

/* A minimal wolfIP_ll_dev used as the argument to wg_poll/wg_send. */
static struct wolfIP_ll_dev test_ll;

/*
 * Ethernet frame constants reused in tests.
 * (These mirror the private defines inside wolfip_wolfguard.c but are
 *  redefined here so the test file does not depend on internal naming.)
 */
#define T_ETH_HDR_LEN  14
#define T_ARP_PKT_LEN  42
#define T_ETH_IP       0x0800
#define T_ETH_ARP      0x0806
#define T_ARP_REQ      1
#define T_ARP_REP      2

/* Build a minimal 14-byte Ethernet header at @buf.
 * @dst/@src are 6-byte MAC arrays; @etype is the ethertype (host byte order). */
static void make_eth_hdr(uint8_t *buf,
                          const uint8_t *dst, const uint8_t *src,
                          uint16_t etype)
{
    memcpy(buf + 0, dst, 6);
    memcpy(buf + 6, src, 6);
    buf[12] = (uint8_t)(etype >> 8);
    buf[13] = (uint8_t)(etype & 0xFF);
}

/*
 * Build a 42-byte ARP request frame at @buf.
 *
 * @sha: sender hardware (MAC) address
 * @sip: sender IP in network byte order
 * @tha: target hardware address (zeros for a request)
 * @tip: target IP in network byte order
 */
static void make_arp_request(uint8_t *buf,
                              const uint8_t *sha, uint32_t sip,
                              const uint8_t *tha, uint32_t tip)
{
    static const uint8_t bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    make_eth_hdr(buf, bcast, sha, T_ETH_ARP);
    buf[14] = 0x00; buf[15] = 0x01;  /* htype = Ethernet */
    buf[16] = 0x08; buf[17] = 0x00;  /* ptype = IPv4     */
    buf[18] = 6;                       /* hlen             */
    buf[19] = 4;                       /* plen             */
    buf[20] = 0x00; buf[21] = T_ARP_REQ; /* opcode        */
    memcpy(buf + 22, sha, 6);
    memcpy(buf + 28, &sip, 4);
    memcpy(buf + 32, tha, 6);
    memcpy(buf + 38, &tip, 4);
}

static void setup(void)
{
    int fds[2];

    memset(&wg_state, 0, sizeof(wg_state));
    memset(&test_ll,  0, sizeof(test_ll));

    /* Create a pipe that acts as the mock TUN fd */
    ck_assert_int_eq(pipe(fds), 0);
    pipe_rd = fds[0];
    pipe_wr = fds[1];

    /* Make both ends non-blocking */
    fcntl(pipe_rd, F_SETFL, O_NONBLOCK);
    fcntl(pipe_wr, F_SETFL, O_NONBLOCK);

    /*
     * wg_send() writes to wg_state.tun_fd;  we read back from pipe_rd.
     * wg_poll() reads from wg_state.tun_fd; we write test data to pipe_wr.
     *
     * For wg_send tests:  tun_fd = pipe_wr  (write end → read via pipe_rd)
     * For wg_poll tests:  tun_fd = pipe_rd  (read end  ← written via pipe_wr)
     *
     * We set tun_fd per-test.
     */

    memcpy(test_ll.mac, wg_local_mac, 6);
    test_ll.poll = wg_poll;
    test_ll.send = wg_send;
}

static void teardown(void)
{
    close(pipe_rd);
    close(pipe_wr);
    memset(&wg_state, 0, sizeof(wg_state));
    wg_state.tun_fd = -1;
}

/*
 * wg_send() with an IPv4 frame must strip the 14-byte Ethernet header and
 * write the remaining IP packet to the TUN fd.
 */
START_TEST(test_wg_send_ipv4)
{
    uint8_t frame[64];
    uint8_t payload[] = {0x45, 0x00, 0x00, 0x14}; /* fake IP header start */
    uint8_t read_buf[64];
    int ret, n;

    static const uint8_t src[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    static const uint8_t dst[6] = {0x11,0x22,0x33,0x44,0x55,0x66};

    memset(frame, 0, sizeof(frame));
    make_eth_hdr(frame, dst, src, T_ETH_IP);
    memcpy(frame + T_ETH_HDR_LEN, payload, sizeof(payload));

    /* Use the write end of the pipe as the TUN fd */
    wg_state.tun_fd = pipe_wr;

    ret = wg_send(&test_ll, frame, (uint32_t)(T_ETH_HDR_LEN + sizeof(payload)));
    ck_assert_int_eq(ret, 0);

    /* Verify what was written to the pipe (i.e. what would go to the kernel) */
    n = (int)read(pipe_rd, read_buf, sizeof(read_buf));
    ck_assert_int_eq(n, (int)sizeof(payload));
    ck_assert_mem_eq(read_buf, payload, sizeof(payload));
}
END_TEST

/*
 * wg_send() with a frame shorter than the Ethernet header must return -1.
 */
START_TEST(test_wg_send_short_frame)
{
    uint8_t frame[4] = {0x00, 0x01, 0x02, 0x03};
    int ret;

    wg_state.tun_fd = pipe_wr;
    ret = wg_send(&test_ll, frame, sizeof(frame));
    ck_assert_int_eq(ret, -1);
}
END_TEST

/*
 * wg_send() with an unknown ethertype must silently drop the frame (return 0)
 * without writing anything to the TUN fd.
 */
START_TEST(test_wg_send_unknown_etype_drop)
{
    uint8_t frame[64];
    uint8_t read_buf[64];
    int n;
    static const uint8_t mac[6] = {0};

    memset(frame, 0, sizeof(frame));
    make_eth_hdr(frame, mac, mac, 0x86DD);  /* IPv6 — not handled */

    wg_state.tun_fd = pipe_wr;
    ck_assert_int_eq(wg_send(&test_ll, frame, sizeof(frame)), 0);

    /* Nothing should have been written to the pipe */
    n = (int)read(pipe_rd, read_buf, sizeof(read_buf));
    ck_assert_int_lt(n, 1);  /* EAGAIN → -1, or 0 if the pipe is closed */
}
END_TEST

/*
 * After wg_send() receives an ARP request, arp_reply_pending must be set.
 */
START_TEST(test_wg_arp_proxy_pending)
{
    uint8_t frame[T_ARP_PKT_LEN];
    static const uint8_t sha[6]  = {0x02,0x00,0x57,0x47,0x00,0x01};
    static const uint8_t tha[6]  = {0};
    uint32_t sip = htonl(0x0A000001);  /* 10.0.0.1 */
    uint32_t tip = htonl(0x0A000002);  /* 10.0.0.2 */

    wg_state.tun_fd = pipe_wr;
    wg_state.arp_reply_pending = 0;

    make_arp_request(frame, sha, sip, tha, tip);
    ck_assert_int_eq(wg_send(&test_ll, frame, sizeof(frame)), 0);
    ck_assert_int_eq(wg_state.arp_reply_pending, 1);
}
END_TEST

/*
 * After an ARP request is processed by wg_send(), wg_poll() must return the
 * synthetic reply and clear arp_reply_pending.
 */
START_TEST(test_wg_arp_proxy_poll_returns_reply)
{
    uint8_t req[T_ARP_PKT_LEN];
    uint8_t poll_buf[128];
    static const uint8_t sha[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    static const uint8_t tha[6] = {0};
    uint32_t sip = htonl(0x0A000001);
    uint32_t tip = htonl(0x0A000002);
    int n;

    wg_state.tun_fd = pipe_wr;  /* poll reads from tun_fd; won't be used here */

    make_arp_request(req, sha, sip, tha, tip);
    ck_assert_int_eq(wg_send(&test_ll, req, sizeof(req)), 0);
    ck_assert_int_eq(wg_state.arp_reply_pending, 1);

    /* Now call wg_poll() with the read end as tun_fd (no data there) */
    wg_state.tun_fd = pipe_rd;
    n = wg_poll(&test_ll, poll_buf, sizeof(poll_buf));

    ck_assert_int_eq(n, T_ARP_PKT_LEN);
    ck_assert_int_eq(wg_state.arp_reply_pending, 0);

    /* Reply ethertype must be ARP */
    ck_assert_uint_eq(poll_buf[12], 0x08);
    ck_assert_uint_eq(poll_buf[13], 0x06);
    /* Reply opcode must be 2 (ARP_REPLY) */
    ck_assert_uint_eq(poll_buf[20], 0x00);
    ck_assert_uint_eq(poll_buf[21], T_ARP_REP);
}
END_TEST

/*
 * The synthetic ARP reply must have:
 *   - Correct sender IP (= target IP from request)
 *   - Correct target IP (= sender IP from request)
 *   - Sender MAC = wg_peer_mac
 *   - Target MAC = sender MAC from request
 */
START_TEST(test_wg_arp_reply_fields)
{
    uint8_t req[T_ARP_PKT_LEN];
    uint8_t poll_buf[128];
    static const uint8_t sha[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    static const uint8_t tha[6] = {0};
    uint32_t sip = htonl(0x0A000001);  /* 10.0.0.1 */
    uint32_t tip = htonl(0x0A000002);  /* 10.0.0.2 */
    int n;

    wg_state.tun_fd = pipe_wr;
    make_arp_request(req, sha, sip, tha, tip);
    ck_assert_int_eq(wg_send(&test_ll, req, sizeof(req)), 0);

    wg_state.tun_fd = pipe_rd;
    n = wg_poll(&test_ll, poll_buf, sizeof(poll_buf));
    ck_assert_int_eq(n, T_ARP_PKT_LEN);

    /* Sender MAC in reply == wg_peer_mac */
    ck_assert_mem_eq(poll_buf + 22, wg_peer_mac, 6);
    /* Sender IP in reply == tip from request (10.0.0.2) */
    ck_assert_mem_eq(poll_buf + 28, &tip, 4);
    /* Target MAC in reply == sha from request */
    ck_assert_mem_eq(poll_buf + 32, sha, 6);
    /* Target IP in reply == sip from request (10.0.0.1) */
    ck_assert_mem_eq(poll_buf + 38, &sip, 4);
}
END_TEST

/*
 * An ARP request with opcode != 1 must NOT set arp_reply_pending.
 */
START_TEST(test_wg_arp_non_request_ignored)
{
    uint8_t frame[T_ARP_PKT_LEN];
    static const uint8_t mac[6] = {0};
    uint32_t ip = htonl(0x0A000001);

    wg_state.tun_fd = pipe_wr;
    wg_state.arp_reply_pending = 0;

    make_arp_request(frame, mac, ip, mac, ip);
    /* Overwrite the opcode to 2 (ARP reply) */
    frame[20] = 0x00;
    frame[21] = T_ARP_REP;

    ck_assert_int_eq(wg_send(&test_ll, frame, sizeof(frame)), 0);
    ck_assert_int_eq(wg_state.arp_reply_pending, 0);
}
END_TEST

/*
 * wg_poll() must prepend a 14-byte Ethernet header with ethertype 0x0800
 * to raw IP data read from the TUN fd.
 */
START_TEST(test_wg_poll_prepends_eth_header)
{
    uint8_t ip_pkt[] = {0x45, 0x00, 0x00, 0x1C,
                        0x00, 0x01, 0x40, 0x00,
                        0x40, 0x11, 0x00, 0x00,
                        0x0A, 0x00, 0x00, 0x01,
                        0x0A, 0x00, 0x00, 0x02}; /* minimal IP header */
    uint8_t poll_buf[128];
    int n;

    /* Inject raw IP into the read end of the pipe */
    wg_state.tun_fd = pipe_rd;
    ck_assert_int_gt((int)write(pipe_wr, ip_pkt, sizeof(ip_pkt)), 0);

    n = wg_poll(&test_ll, poll_buf, sizeof(poll_buf));
    ck_assert_int_eq(n, (int)(T_ETH_HDR_LEN + sizeof(ip_pkt)));

    /* dst MAC == wg_local_mac */
    ck_assert_mem_eq(poll_buf + 0, wg_local_mac, 6);
    /* src MAC == wg_peer_mac */
    ck_assert_mem_eq(poll_buf + 6, wg_peer_mac,  6);
    /* ethertype == 0x0800 */
    ck_assert_uint_eq(poll_buf[12], 0x08);
    ck_assert_uint_eq(poll_buf[13], 0x00);
    /* IP payload is intact */
    ck_assert_mem_eq(poll_buf + T_ETH_HDR_LEN, ip_pkt, sizeof(ip_pkt));
}
END_TEST

/*
 * wg_poll() must return -1 when an ARP reply is pending but the caller's
 * buffer is too small to hold WG_ARP_PKT_LEN bytes.
 */
START_TEST(test_wg_poll_arp_reply_buf_too_small)
{
    uint8_t req[T_ARP_PKT_LEN];
    uint8_t small_buf[T_ARP_PKT_LEN - 1];
    static const uint8_t sha[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    static const uint8_t tha[6] = {0};
    uint32_t sip = htonl(0x0A000001);
    uint32_t tip = htonl(0x0A000002);

    wg_state.tun_fd = pipe_wr;
    make_arp_request(req, sha, sip, tha, tip);
    ck_assert_int_eq(wg_send(&test_ll, req, sizeof(req)), 0);
    ck_assert_int_eq(wg_state.arp_reply_pending, 1);

    wg_state.tun_fd = pipe_rd;
    ck_assert_int_eq(wg_poll(&test_ll, small_buf, sizeof(small_buf)), -1);
}
END_TEST

/*
 * wg_send() with an ARP frame shorter than WG_ARP_PKT_LEN must return -1
 * and must NOT set arp_reply_pending.
 */
START_TEST(test_wg_send_arp_buf_too_small)
{
    uint8_t frame[T_ARP_PKT_LEN - 1];
    static const uint8_t mac[6] = {0};

    memset(frame, 0, sizeof(frame));
    /* Build an ARP request header in what space we have */
    make_eth_hdr(frame, mac, mac, T_ETH_ARP);
    frame[20] = 0x00;
    frame[21] = T_ARP_REQ;

    wg_state.tun_fd = pipe_wr;
    wg_state.arp_reply_pending = 0;

    ck_assert_int_eq(wg_send(&test_ll, frame, sizeof(frame)), -1);
    ck_assert_int_eq(wg_state.arp_reply_pending, 0);
}
END_TEST

/*
 * wg_poll() must return a non-positive value (timeout or error) when no data
 * is available on the TUN fd and no ARP reply is pending.
 */
START_TEST(test_wg_poll_timeout_no_data)
{
    uint8_t buf[128];
    int n;

    /* Use the read end of the pipe (nothing written to write end) */
    wg_state.tun_fd = pipe_rd;
    wg_state.arp_reply_pending = 0;

    n = wg_poll(&test_ll, buf, sizeof(buf));
    ck_assert_int_le(n, 0);  /* 0 = timeout, -1 = error/would-block */
}
END_TEST

static Suite *wolfguard_suite(void)
{
    Suite *s = suite_create("wolfguard");
    TCase *tc;

    tc = tcase_create("wg_send");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, test_wg_send_ipv4);
    tcase_add_test(tc, test_wg_send_short_frame);
    tcase_add_test(tc, test_wg_send_unknown_etype_drop);
    suite_add_tcase(s, tc);

    tc = tcase_create("arp_proxy");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, test_wg_arp_proxy_pending);
    tcase_add_test(tc, test_wg_arp_proxy_poll_returns_reply);
    tcase_add_test(tc, test_wg_arp_reply_fields);
    tcase_add_test(tc, test_wg_arp_non_request_ignored);
    tcase_add_test(tc, test_wg_send_arp_buf_too_small);
    suite_add_tcase(s, tc);

    tc = tcase_create("wg_poll");
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, test_wg_poll_prepends_eth_header);
    tcase_add_test(tc, test_wg_poll_timeout_no_data);
    tcase_add_test(tc, test_wg_poll_arp_reply_buf_too_small);
    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    int failed;
    Suite   *s  = wolfguard_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failed == 0) ? 0 : 1;
}

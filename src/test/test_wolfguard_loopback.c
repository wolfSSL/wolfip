/* test_wolfguard_loopback.c
 *
 * Integration tests for wolfGuard: two wolfIP stacks connected back-to-back
 * with wolfGuard tunnels, validating the full TX/RX path.
 *
 * Covers plan sections:
 *   - Loopback client-server round-trip
 *   - Session lifecycle (rekey, key zeroing, reconnect)
 *   - DoS cookie test
 *
 * Copyright (C) 2026 wolfSSL Inc.
 */

#ifndef WOLFGUARD
#define WOLFGUARD
#endif

#undef  WOLFIP_MAX_INTERFACES
#define WOLFIP_MAX_INTERFACES 3

#include "check.h"
#include "../../config.h"

#if WOLFIP_ENABLE_LOOPBACK
#define TEST_PHYS_IF 1U
#define TEST_WG_IF   2U
#else
#define TEST_PHYS_IF 0U
#define TEST_WG_IF   1U
#endif

/* Override after config.h */
#undef  MAX_UDPSOCKETS
#define MAX_UDPSOCKETS 8

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Unity build */
#include "../wolfip.c"
#include "../wolfguard/wg_crypto.c"
#include "../wolfguard/wg_noise.c"
#include "../wolfguard/wg_cookie.c"
#include "../wolfguard/wg_allowedips.c"
#include "../wolfguard/wg_packet.c"
#include "../wolfguard/wg_timers.c"
#include "../wolfguard/wolfguard.c"

uint32_t wolfIP_getrandom(void)
{
    return (uint32_t)random();
}

/*
 * In-memory frame ring buffer connecting two physical interfaces
 * */

#define RING_SIZE 32

struct frame_ring {
    uint8_t data[RING_SIZE][LINK_MTU];
    uint16_t lens[RING_SIZE];
    int head;
    int count;
};

static struct frame_ring ring_a_to_b;
static struct frame_ring ring_b_to_a;

/* Additional rings for 3-stack multi-peer test */
static struct frame_ring ring_a_to_c;
static struct frame_ring ring_c_to_a;

static int ring_push(struct frame_ring *r, const void *buf, uint32_t len)
{
    int idx;
    if (r->count >= RING_SIZE)
        return -1;
    idx = (r->head + r->count) % RING_SIZE;
    if (len > LINK_MTU)
        len = LINK_MTU;
    memcpy(r->data[idx], buf, len);
    r->lens[idx] = (uint16_t)len;
    r->count++;
    return 0;
}

static int ring_pop(struct frame_ring *r, void *buf, uint32_t max_len)
{
    uint16_t len;
    if (r->count == 0)
        return 0;
    len = r->lens[r->head];
    if (len > (uint16_t)max_len)
        len = (uint16_t)max_len;
    memcpy(buf, r->data[r->head], len);
    r->head = (r->head + 1) % RING_SIZE;
    r->count--;
    return (int)len;
}

/* Stack A physical interface callbacks */
static int phys_a_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    return ring_push(&ring_a_to_b, buf, len);
}

static int phys_a_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    return ring_pop(&ring_b_to_a, buf, len);
}

/* Stack B physical interface callbacks */
static int phys_b_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    return ring_push(&ring_b_to_a, buf, len);
}

static int phys_b_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    return ring_pop(&ring_a_to_b, buf, len);
}

/*
 * Global test state
 * */

static struct wolfIP stack_a;
static struct wolfIP stack_b;
static struct wolfIP stack_c;
static struct wg_device wg_dev_a;
static struct wg_device wg_dev_b;
static struct wg_device wg_dev_c;
static WC_RNG test_rng;
static int rng_initialized;

/* Application-layer receive state */
static uint8_t app_recv_buf[1500];
static int app_recv_len;
static int app_recv_count;

static void app_udp_callback(int sock_fd, uint16_t events, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    struct wolfIP_sockaddr_in src;
    socklen_t src_len = sizeof(src);

    (void)sock_fd;
    if (!(events & CB_EVENT_READABLE))
        return;

    app_recv_len = wolfIP_sock_recvfrom(s, sock_fd, app_recv_buf,
                                         sizeof(app_recv_buf), 0,
                                         (struct wolfIP_sockaddr *)&src,
                                         &src_len);
    if (app_recv_len > 0)
        app_recv_count++;
}

static void init_test_rng(void)
{
    if (!rng_initialized) {
#ifdef WC_RNG_SEED_CB
        wc_SetSeed_Cb(wc_GenerateSeed);
#endif
        ck_assert_int_eq(wc_InitRng(&test_rng), 0);
        rng_initialized = 1;
    }
}

/* Pump both stacks for N iterations, advancing time by step_ms each */
static void pump_stacks(uint64_t *now, int iterations, uint64_t step_ms)
{
    int i;
    for (i = 0; i < iterations; i++) {
        wolfIP_poll(&stack_a, *now);
        wolfguard_poll(&wg_dev_a, *now);
        wolfIP_poll(&stack_b, *now);
        wolfguard_poll(&wg_dev_b, *now);
        *now += step_ms;
    }
}

/* Helper: make an ip4 in host byte order (wolfIP internal format) */
#define MAKE_IP4(a,b,c,d) ((ip4)( \
    ((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | \
    ((uint32_t)(c) << 8)  | (uint32_t)(d) ))

/*
 * Setup: create two wolfIP stacks with wolfGuard tunnels
 * */

static void setup_loopback_stacks(uint64_t *now)
{
    struct wolfIP_ll_dev *ll;
    uint8_t priv_a[WG_PRIVATE_KEY_LEN], priv_b[WG_PRIVATE_KEY_LEN];
    int peer_idx;

    init_test_rng();
    *now = 1000;

    /* Clear ring buffers */
    memset(&ring_a_to_b, 0, sizeof(ring_a_to_b));
    memset(&ring_b_to_a, 0, sizeof(ring_b_to_a));
    app_recv_len = 0;
    app_recv_count = 0;

    /* ---- Stack A ---- */
    wolfIP_init(&stack_a);

    /* Physical interface (non_ethernet, index 0) */
    ll = wolfIP_getdev_ex(&stack_a, TEST_PHYS_IF);
    ll->non_ethernet = 1;
    ll->poll = phys_a_poll;
    ll->send = phys_a_send;
    strncpy(ll->ifname, "eth_a", sizeof(ll->ifname) - 1);

    wolfIP_ipconfig_set_ex(&stack_a, TEST_PHYS_IF, MAKE_IP4(192,168,1,1),
                           MAKE_IP4(255,255,255,0), 0);

    /* wolfGuard on interface 1 (wg0) */
    ck_assert_int_eq(wolfguard_init(&wg_dev_a, &stack_a, TEST_WG_IF, 51820), 0);

    /* Generate and set keys for A */
    wc_RNG_GenerateBlock(&test_rng, priv_a, WG_PRIVATE_KEY_LEN);
    ck_assert_int_eq(wolfguard_set_private_key(&wg_dev_a, priv_a), 0);

    wolfIP_ipconfig_set_ex(&stack_a, TEST_WG_IF, MAKE_IP4(10,0,0,1),
                           MAKE_IP4(255,255,255,0), 0);

    /* Stack B */
    wolfIP_init(&stack_b);

    /* Physical interface (non_ethernet, index 0) */
    ll = wolfIP_getdev_ex(&stack_b, TEST_PHYS_IF);
    ll->non_ethernet = 1;
    ll->poll = phys_b_poll;
    ll->send = phys_b_send;
    strncpy(ll->ifname, "eth_b", sizeof(ll->ifname) - 1);

    wolfIP_ipconfig_set_ex(&stack_b, TEST_PHYS_IF, MAKE_IP4(192,168,1,2),
                           MAKE_IP4(255,255,255,0), 0);

    /* wolfGuard on interface 1 (wg0) */
    ck_assert_int_eq(wolfguard_init(&wg_dev_b, &stack_b, TEST_WG_IF, 51820), 0);

    /* Generate and set keys for B */
    wc_RNG_GenerateBlock(&test_rng, priv_b, WG_PRIVATE_KEY_LEN);
    ck_assert_int_eq(wolfguard_set_private_key(&wg_dev_b, priv_b), 0);

    wolfIP_ipconfig_set_ex(&stack_b, TEST_WG_IF, MAKE_IP4(10,0,0,2),
                           MAKE_IP4(255,255,255,0), 0);

    /* Add peers (A knows B, B knows A) */
    /* endpoint_ip: network byte order for sin_addr.s_addr */
    /* endpoint_port: network byte order for sin_port */
    peer_idx = wolfguard_add_peer(&wg_dev_a, wg_dev_b.static_public, NULL,
                                  ee32(MAKE_IP4(192,168,1,2)),
                                  ee16(51820), 0);
    ck_assert_int_ge(peer_idx, 0);
    ck_assert_int_eq(wolfguard_add_allowed_ip(&wg_dev_a, peer_idx,
                     ee32(MAKE_IP4(10,0,0,0)), 24), 0);

    peer_idx = wolfguard_add_peer(&wg_dev_b, wg_dev_a.static_public, NULL,
                                  ee32(MAKE_IP4(192,168,1,1)),
                                  ee16(51820), 0);
    ck_assert_int_ge(peer_idx, 0);
    ck_assert_int_eq(wolfguard_add_allowed_ip(&wg_dev_b, peer_idx,
                     ee32(MAKE_IP4(10,0,0,0)), 24), 0);

    /* Set initial time on both devices */
    wg_dev_a.now = *now;
    wg_dev_b.now = *now;
}

static void teardown_stacks(void)
{
    wolfguard_destroy(&wg_dev_a);
    wolfguard_destroy(&wg_dev_b);
}

/*
 * Loopback client-server round-trip
 * */

START_TEST(test_loopback_roundtrip)
{
    uint64_t now;
    int app_sock_a, app_sock_b;
    struct wolfIP_sockaddr_in bind_addr, dst_addr;
    const char *payload = "Hello wolfGuard!";
    int ret;

    setup_loopback_stacks(&now);

    /* Create application UDP socket on stack B, listening on port 7777 */
    app_sock_b = wolfIP_sock_socket(&stack_b, AF_INET, SOCK_DGRAM, 0);
    ck_assert_int_ge(app_sock_b, 0);

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = ee16(7777);
    bind_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,0,2));
    ret = wolfIP_sock_bind(&stack_b, app_sock_b,
                           (struct wolfIP_sockaddr *)&bind_addr,
                           sizeof(bind_addr));
    ck_assert_int_ge(ret, 0);

    wolfIP_register_callback(&stack_b, app_sock_b, app_udp_callback, &stack_b);

    /* Create application UDP socket on stack A, bind to wg0 IP */
    app_sock_a = wolfIP_sock_socket(&stack_a, AF_INET, SOCK_DGRAM, 0);
    ck_assert_int_ge(app_sock_a, 0);

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = ee16(9999);
    bind_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,0,1));
    ret = wolfIP_sock_bind(&stack_a, app_sock_a,
                           (struct wolfIP_sockaddr *)&bind_addr,
                           sizeof(bind_addr));
    ck_assert_int_ge(ret, 0);

    /* Send from A to B's tunnel IP (10.0.0.2:7777) */
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = ee16(7777);
    dst_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,0,2));

    ret = wolfIP_sock_sendto(&stack_a, app_sock_a,
                             payload, strlen(payload), 0,
                             (const struct wolfIP_sockaddr *)&dst_addr,
                             sizeof(dst_addr));
    ck_assert_int_ge(ret, 0);

    /* Pump both stacks, so handshake + data delivery */
    pump_stacks(&now, 200, 10);

    /* Verify B received the payload */
    ck_assert_int_gt(app_recv_count, 0);
    ck_assert_int_eq(app_recv_len, (int)strlen(payload));
    ck_assert_int_eq(memcmp(app_recv_buf, payload, strlen(payload)), 0);

    /* Verify handshake completed (peer has valid current keypair) */
    ck_assert_ptr_nonnull(wg_dev_a.peers[0].keypairs.current);
    ck_assert_int_eq(wg_dev_a.peers[0].keypairs.current->sending.is_valid, 1);

    /* Verify TX byte counter incremented on A */
    ck_assert_uint_gt(wg_dev_a.peers[0].tx_bytes, 0);

    /* Now send a reply from B to A */
    app_recv_count = 0;
    app_recv_len = 0;

    /* Register callback on A's socket */
    wolfIP_register_callback(&stack_a, app_sock_a, app_udp_callback, &stack_a);

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = ee16(9999);
    dst_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,0,1));

    {
        const char *reply = "Reply from B!";
        ret = wolfIP_sock_sendto(&stack_b, app_sock_b,
                                 reply, strlen(reply), 0,
                                 (const struct wolfIP_sockaddr *)&dst_addr,
                                 sizeof(dst_addr));
        ck_assert_int_ge(ret, 0);

        pump_stacks(&now, 100, 10);

        ck_assert_int_gt(app_recv_count, 0);
        ck_assert_int_eq(app_recv_len, (int)strlen(reply));
        ck_assert_int_eq(memcmp(app_recv_buf, reply, strlen(reply)), 0);
    }

    /* Verify RX bytes on B */
    ck_assert_uint_gt(wg_dev_b.peers[0].rx_bytes, 0);

    wolfIP_sock_close(&stack_a, app_sock_a);
    wolfIP_sock_close(&stack_b, app_sock_b);
    teardown_stacks();
}
END_TEST

/*
 * Session lifecycle
 * */

START_TEST(test_session_lifecycle)
{
    uint64_t now;
    int app_sock_a, app_sock_b;
    struct wolfIP_sockaddr_in bind_addr, dst_addr;
    const char *payload = "lifecycle test";
    int ret;
    uint64_t first_session_id;

    setup_loopback_stacks(&now);

    /* Setup sockets */
    app_sock_b = wolfIP_sock_socket(&stack_b, AF_INET, SOCK_DGRAM, 0);
    ck_assert_int_ge(app_sock_b, 0);

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = ee16(8888);
    bind_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,0,2));
    wolfIP_sock_bind(&stack_b, app_sock_b,
                     (struct wolfIP_sockaddr *)&bind_addr,
                     sizeof(bind_addr));
    wolfIP_register_callback(&stack_b, app_sock_b, app_udp_callback, &stack_b);

    app_sock_a = wolfIP_sock_socket(&stack_a, AF_INET, SOCK_DGRAM, 0);
    ck_assert_int_ge(app_sock_a, 0);

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = ee16(9999);
    bind_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,0,1));
    wolfIP_sock_bind(&stack_a, app_sock_a,
                     (struct wolfIP_sockaddr *)&bind_addr,
                     sizeof(bind_addr));

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = ee16(8888);
    dst_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,0,2));

    /* Phase 1: Initial handshake + data exchange */
    ret = wolfIP_sock_sendto(&stack_a, app_sock_a,
                             payload, strlen(payload), 0,
                             (const struct wolfIP_sockaddr *)&dst_addr,
                             sizeof(dst_addr));
    ck_assert_int_ge(ret, 0);

    pump_stacks(&now, 200, 10);

    ck_assert_int_gt(app_recv_count, 0);
    ck_assert_ptr_nonnull(wg_dev_a.peers[0].keypairs.current);
    first_session_id = wg_dev_a.peers[0].keypairs.current->internal_id;

    /* Phase 2: Advance time past REKEY_AFTER_TIME (120s) */
    now += (uint64_t)WG_REKEY_AFTER_TIME * 1000ULL + 1000;

    /* Send another packet — should trigger rekey */
    app_recv_count = 0;
    ret = wolfIP_sock_sendto(&stack_a, app_sock_a,
                             payload, strlen(payload), 0,
                             (const struct wolfIP_sockaddr *)&dst_addr,
                             sizeof(dst_addr));
    ck_assert_int_ge(ret, 0);

    pump_stacks(&now, 300, 10);

    /* Verify data still flows after rekey */
    ck_assert_int_gt(app_recv_count, 0);

    /* Phase 3: Advance time past REJECT_AFTER_TIME * 3 (540s) with no traffic */
    now += (uint64_t)WG_REJECT_AFTER_TIME * 3000ULL + 1000;
    pump_stacks(&now, 50, 100);

    /* Verify keys are zeroed */
    ck_assert_ptr_null(wg_dev_a.peers[0].keypairs.current);

    /* Phase 4: Send packet again, it should trigger fresh handshake */
    app_recv_count = 0;

    ret = wolfIP_sock_sendto(&stack_a, app_sock_a,
                             payload, strlen(payload), 0,
                             (const struct wolfIP_sockaddr *)&dst_addr,
                             sizeof(dst_addr));
    ck_assert_int_ge(ret, 0);

    pump_stacks(&now, 300, 10);

    /* Verify data flows with new session */
    ck_assert_int_gt(app_recv_count, 0);
    ck_assert_ptr_nonnull(wg_dev_a.peers[0].keypairs.current);

    /* Verify it's a different session */
    ck_assert_uint_ne(wg_dev_a.peers[0].keypairs.current->internal_id,
                      first_session_id);

    wolfIP_sock_close(&stack_a, app_sock_a);
    wolfIP_sock_close(&stack_b, app_sock_b);
    teardown_stacks();
}
END_TEST

/*
 * DoS cookie test
 *
 * Tests the cookie mechanism at the wolfGuard API level:
 * 1. Create an initiation with valid mac1 but invalid mac2
 * 2. Verify cookie_validate returns VALID (mac1 ok, no mac2 required)
 * 3. Create a cookie reply
 * 4. Consume the cookie reply
 * 5. Re-add macs (now with valid cookie) — verify mac2 is present
 * */

START_TEST(test_dos_cookie_mechanism)
{
    struct wg_device dev;
    struct wg_peer peer;
    struct wg_msg_initiation init_msg;
    struct wg_msg_cookie cookie_reply;
    enum wg_cookie_mac_state state;
    size_t mac_off;
    uint8_t priv[WG_PRIVATE_KEY_LEN];
    int ret;
    uint8_t zero_mac[WG_COOKIE_LEN];

    init_test_rng();

    memset(&dev, 0, sizeof(dev));
    memset(&peer, 0, sizeof(peer));
    memset(zero_mac, 0, sizeof(zero_mac));

    /* Setup device */
    wc_RNG_GenerateBlock(&test_rng, priv, WG_PRIVATE_KEY_LEN);
    memcpy(dev.static_private, priv, WG_PRIVATE_KEY_LEN);
    wg_pubkey_from_private(dev.static_public, dev.static_private);
    memcpy(&dev.rng, &test_rng, sizeof(WC_RNG));
    dev.now = 5000;

    wg_cookie_checker_init(&dev.cookie_checker, dev.static_public);

    /* Setup peer (peer is sending TO this device) */
    memcpy(peer.public_key, dev.static_public, WG_PUBLIC_KEY_LEN);
    wg_cookie_init(&peer.cookie, dev.static_public);

    /* Step 1: Create initiation with valid mac1 (no cookie -> mac2 is zero) */
    memset(&init_msg, 0xAA, sizeof(init_msg));
    mac_off = offsetof(struct wg_msg_initiation, macs);

    ret = wg_cookie_add_macs(&peer, &init_msg, sizeof(init_msg), mac_off);
    ck_assert_int_eq(ret, 0);

    /* Verify mac2 is zero (no cookie available) */
    ck_assert_int_eq(memcmp(init_msg.macs.mac2, zero_mac, WG_COOKIE_LEN), 0);

    /* Step 2: Validate, mac1 valid, no mac2 */
    state = wg_cookie_validate(&dev.cookie_checker, &init_msg,
                               sizeof(init_msg), mac_off,
                               0x0A0A0A01, 12345, dev.now);
    ck_assert_int_eq(state, WG_COOKIE_MAC_VALID);

    /* Step 3: Device creates cookie reply (simulating "under load" response) */
    ret = wg_cookie_create_reply(&dev, &cookie_reply, &init_msg,
                                 offsetof(struct wg_msg_initiation, macs),
                                 init_msg.sender_index,
                                 0x0A0A0A01, 12345);
    ck_assert_int_eq(ret, 0);

    /* Step 4: Peer consumes cookie reply */
    ret = wg_cookie_consume_reply(&peer, &cookie_reply);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(peer.cookie.is_valid, 1);

    /* Step 5: Re-create initiation with mac1 + mac2 (using cookie) */
    memset(&init_msg, 0xBB, sizeof(init_msg));
    ret = wg_cookie_add_macs(&peer, &init_msg, sizeof(init_msg), mac_off);
    ck_assert_int_eq(ret, 0);

    /* Verify mac2 is NOT zero anymore */
    ck_assert_int_ne(memcmp(init_msg.macs.mac2, zero_mac, WG_COOKIE_LEN), 0);

    /* Step 6: Validate with cookie,it should return VALID_WITH_COOKIE */
    state = wg_cookie_validate(&dev.cookie_checker, &init_msg,
                               sizeof(init_msg), mac_off,
                               0x0A0A0A01, 12345, dev.now);
    ck_assert_int_eq(state, WG_COOKIE_MAC_VALID_WITH_COOKIE);
}
END_TEST

/*
 * Roaming test: verify endpoint update on authenticated packets
 *
 * After establishing a tunnel with A at 192.168.1.1, we change A's
 * physical IP to 192.168.1.100 and verify that B updates the endpoint.
 * */

START_TEST(test_roaming)
{
    uint64_t now;
    int app_sock_a, app_sock_b;
    struct wolfIP_sockaddr_in bind_addr, dst_addr;
    const char *payload1 = "before roaming";
    int ret;
    uint32_t original_endpoint;

    setup_loopback_stacks(&now);

    /* Create app sockets */
    app_sock_b = wolfIP_sock_socket(&stack_b, AF_INET, SOCK_DGRAM, 0);
    ck_assert_int_ge(app_sock_b, 0);

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = ee16(7777);
    bind_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,0,2));
    wolfIP_sock_bind(&stack_b, app_sock_b,
                     (struct wolfIP_sockaddr *)&bind_addr, sizeof(bind_addr));
    wolfIP_register_callback(&stack_b, app_sock_b, app_udp_callback, &stack_b);

    app_sock_a = wolfIP_sock_socket(&stack_a, AF_INET, SOCK_DGRAM, 0);
    ck_assert_int_ge(app_sock_a, 0);

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = ee16(9999);
    bind_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,0,1));
    wolfIP_sock_bind(&stack_a, app_sock_a,
                     (struct wolfIP_sockaddr *)&bind_addr, sizeof(bind_addr));

    /* Phase 1: Establish tunnel with original IP */
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = ee16(7777);
    dst_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,0,2));

    ret = wolfIP_sock_sendto(&stack_a, app_sock_a,
                             payload1, strlen(payload1), 0,
                             (const struct wolfIP_sockaddr *)&dst_addr,
                             sizeof(dst_addr));
    ck_assert_int_ge(ret, 0);

    pump_stacks(&now, 200, 10);

    ck_assert_int_gt(app_recv_count, 0);
    ck_assert_int_eq(app_recv_len, (int)strlen(payload1));

    /* Record original endpoint */
    original_endpoint = wg_dev_b.peers[0].endpoint_ip;
    ck_assert_uint_eq(original_endpoint, ee32(MAKE_IP4(192,168,1,1)));

    /* Phase 2: Simulate roaming by directly injecting an authenticated
     * packet into B's wolfGuard receiver with a different source IP.
     *
     * We bypass wolfIP's UDP layer because wolfIP caches the source IP
     * on existing sockets (ts->local_ip), so wolfIP_ipconfig_set() alone
     * won't change the source IP in outgoing packets.  Injecting directly
     * into wg_packet_receive() tests the wolfGuard roaming code path
     * (wg_handle_data updating peer->endpoint_ip) without that limitation. */
    {
        struct wg_keypair *kp = wg_dev_a.peers[0].keypairs.current;
        uint8_t msg_buf[sizeof(struct wg_msg_data) + WG_AUTHTAG_LEN];
        struct wg_msg_data *data_msg = (struct wg_msg_data *)msg_buf;
        uint64_t ctr;

        ck_assert_ptr_nonnull(kp);

        ctr = kp->sending_counter++;

        /* Build wire-format data message (keepalive: empty payload) */
        data_msg->header.type = wg_le32_encode(WG_MSG_DATA);
        data_msg->receiver_index = wg_le32_encode(kp->remote_index);
        data_msg->counter = wg_le64_encode(ctr);

        /* Encrypt empty plaintext — produces only the 16-byte auth tag */
        ck_assert_int_eq(
            wg_aead_encrypt(data_msg->encrypted_data, kp->sending.key,
                            ctr, NULL, 0, NULL, 0), 0);

        /* Feed to B with a NEW source IP, simulating A roaming */
        wg_packet_receive(&wg_dev_b, msg_buf, sizeof(msg_buf),
                          ee32(MAKE_IP4(192,168,1,100)),
                          ee16(51820));

        /* Verify endpoint was updated to the new IP */
        ck_assert_uint_eq(wg_dev_b.peers[0].endpoint_ip,
                          ee32(MAKE_IP4(192,168,1,100)));
        ck_assert_uint_ne(wg_dev_b.peers[0].endpoint_ip, original_endpoint);
    }

    wolfIP_sock_close(&stack_a, app_sock_a);
    wolfIP_sock_close(&stack_b, app_sock_b);
    teardown_stacks();
}
END_TEST

/*
 * Multi-peer test: 3 stacks (A, B, C) where A has two peers.
 *
 * Topology:
 *   Stack A (eth0: 192.168.1.1, wg0: 10.0.0.1) — peers B and C
 *   Stack B (eth0: 192.168.1.2, wg0: 10.0.1.1) — peer A
 *   Stack C (eth0: 192.168.1.3, wg0: 10.0.2.1) — peer A
 *
 * A's send callback routes by dest IP to the correct ring.
 * */

/* Multi-peer physical interface callbacks: A routes by dest IP */
static int phys_a_send_multi(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    uint32_t dst_ip;
    (void)ll;

    if (len >= 20) {
        /* non_ethernet=1: frame is raw IP, dest IP at offset 16 */
        memcpy(&dst_ip, (uint8_t *)buf + 16, 4);
        if (dst_ip == ee32(MAKE_IP4(192,168,1,2)))
            return ring_push(&ring_a_to_b, buf, len);
        else if (dst_ip == ee32(MAKE_IP4(192,168,1,3)))
            return ring_push(&ring_a_to_c, buf, len);
    }
    /* Broadcast / unknown: send to both */
    ring_push(&ring_a_to_b, buf, len);
    ring_push(&ring_a_to_c, buf, len);
    return 0;
}

static int phys_a_poll_multi(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    int n;
    (void)ll;
    /* Check B -> A first, then C -> A */
    n = ring_pop(&ring_b_to_a, buf, len);
    if (n > 0)
        return n;
    return ring_pop(&ring_c_to_a, buf, len);
}

/* Stack C physical interface callbacks */
static int phys_c_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    return ring_push(&ring_c_to_a, buf, len);
}

static int phys_c_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    return ring_pop(&ring_a_to_c, buf, len);
}

/* Second app recv buffer (for distinguishing B vs C responses) */
static uint8_t app_recv_buf2[1500];
static int app_recv_len2;
static int app_recv_count2;

static void app_udp_callback2(int sock_fd, uint16_t events, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    struct wolfIP_sockaddr_in src;
    socklen_t src_len = sizeof(src);

    (void)sock_fd;
    if (!(events & CB_EVENT_READABLE))
        return;

    app_recv_len2 = wolfIP_sock_recvfrom(s, sock_fd, app_recv_buf2,
                                          sizeof(app_recv_buf2), 0,
                                          (struct wolfIP_sockaddr *)&src,
                                          &src_len);
    if (app_recv_len2 > 0)
        app_recv_count2++;
}

static void pump_three_stacks(uint64_t *now, int iterations, uint64_t step_ms)
{
    int i;
    for (i = 0; i < iterations; i++) {
        wolfIP_poll(&stack_a, *now);
        wolfguard_poll(&wg_dev_a, *now);
        wolfIP_poll(&stack_b, *now);
        wolfguard_poll(&wg_dev_b, *now);
        wolfIP_poll(&stack_c, *now);
        wolfguard_poll(&wg_dev_c, *now);
        *now += step_ms;
    }
}

START_TEST(test_multi_peer)
{
    uint64_t now;
    struct wolfIP_ll_dev *ll;
    uint8_t priv_a[WG_PRIVATE_KEY_LEN], priv_b[WG_PRIVATE_KEY_LEN],
            priv_c[WG_PRIVATE_KEY_LEN];
    int peer_idx;
    int app_sock_a, app_sock_b, app_sock_c;
    struct wolfIP_sockaddr_in bind_addr, dst_addr;
    const char *payload_to_b = "Hello peer B!";
    const char *payload_to_c = "Hello peer C!";
    int ret;

    init_test_rng();
    now = 1000;

    /* Clear all ring buffers */
    memset(&ring_a_to_b, 0, sizeof(ring_a_to_b));
    memset(&ring_b_to_a, 0, sizeof(ring_b_to_a));
    memset(&ring_a_to_c, 0, sizeof(ring_a_to_c));
    memset(&ring_c_to_a, 0, sizeof(ring_c_to_a));
    app_recv_len = 0;
    app_recv_count = 0;
    app_recv_len2 = 0;
    app_recv_count2 = 0;

    /* Stack A (hub, 2 peers) */
    wolfIP_init(&stack_a);
    ll = wolfIP_getdev_ex(&stack_a, TEST_PHYS_IF);
    ll->non_ethernet = 1;
    ll->poll = phys_a_poll_multi;
    ll->send = phys_a_send_multi;
    strncpy(ll->ifname, "eth_a", sizeof(ll->ifname) - 1);
    wolfIP_ipconfig_set_ex(&stack_a, TEST_PHYS_IF, MAKE_IP4(192,168,1,1),
                           MAKE_IP4(255,255,255,0), 0);

    ck_assert_int_eq(wolfguard_init(&wg_dev_a, &stack_a, TEST_WG_IF, 51820), 0);
    wc_RNG_GenerateBlock(&test_rng, priv_a, WG_PRIVATE_KEY_LEN);
    ck_assert_int_eq(wolfguard_set_private_key(&wg_dev_a, priv_a), 0);
    wolfIP_ipconfig_set_ex(&stack_a, TEST_WG_IF, MAKE_IP4(10,0,0,1),
                           MAKE_IP4(255,0,0,0), 0);

    /* Stack B */
    wolfIP_init(&stack_b);
    ll = wolfIP_getdev_ex(&stack_b, TEST_PHYS_IF);
    ll->non_ethernet = 1;
    ll->poll = phys_b_poll;
    ll->send = phys_b_send;
    strncpy(ll->ifname, "eth_b", sizeof(ll->ifname) - 1);
    wolfIP_ipconfig_set_ex(&stack_b, TEST_PHYS_IF, MAKE_IP4(192,168,1,2),
                           MAKE_IP4(255,255,255,0), 0);

    ck_assert_int_eq(wolfguard_init(&wg_dev_b, &stack_b, TEST_WG_IF, 51820), 0);
    wc_RNG_GenerateBlock(&test_rng, priv_b, WG_PRIVATE_KEY_LEN);
    ck_assert_int_eq(wolfguard_set_private_key(&wg_dev_b, priv_b), 0);
    wolfIP_ipconfig_set_ex(&stack_b, TEST_WG_IF, MAKE_IP4(10,0,1,1),
                           MAKE_IP4(255,255,255,0), 0);

    /* Stack C */
    wolfIP_init(&stack_c);
    ll = wolfIP_getdev_ex(&stack_c, TEST_PHYS_IF);
    ll->non_ethernet = 1;
    ll->poll = phys_c_poll;
    ll->send = phys_c_send;
    strncpy(ll->ifname, "eth_c", sizeof(ll->ifname) - 1);
    wolfIP_ipconfig_set_ex(&stack_c, TEST_PHYS_IF, MAKE_IP4(192,168,1,3),
                           MAKE_IP4(255,255,255,0), 0);

    ck_assert_int_eq(wolfguard_init(&wg_dev_c, &stack_c, TEST_WG_IF, 51820), 0);
    wc_RNG_GenerateBlock(&test_rng, priv_c, WG_PRIVATE_KEY_LEN);
    ck_assert_int_eq(wolfguard_set_private_key(&wg_dev_c, priv_c), 0);
    wolfIP_ipconfig_set_ex(&stack_c, TEST_WG_IF, MAKE_IP4(10,0,2,1),
                           MAKE_IP4(255,255,255,0), 0);

    /* Add peers */

    /* A knows B (allowed IPs: 10.0.1.0/24) */
    peer_idx = wolfguard_add_peer(&wg_dev_a, wg_dev_b.static_public, NULL,
                                  ee32(MAKE_IP4(192,168,1,2)),
                                  ee16(51820), 0);
    ck_assert_int_ge(peer_idx, 0);
    ck_assert_int_eq(wolfguard_add_allowed_ip(&wg_dev_a, peer_idx,
                     ee32(MAKE_IP4(10,0,1,0)), 24), 0);

    /* A knows C (allowed IPs: 10.0.2.0/24) */
    peer_idx = wolfguard_add_peer(&wg_dev_a, wg_dev_c.static_public, NULL,
                                  ee32(MAKE_IP4(192,168,1,3)),
                                  ee16(51820), 0);
    ck_assert_int_ge(peer_idx, 0);
    ck_assert_int_eq(wolfguard_add_allowed_ip(&wg_dev_a, peer_idx,
                     ee32(MAKE_IP4(10,0,2,0)), 24), 0);

    /* B knows A (allowed IPs: 10.0.0.0/8, basically covers all tunnel subnets) */
    peer_idx = wolfguard_add_peer(&wg_dev_b, wg_dev_a.static_public, NULL,
                                  ee32(MAKE_IP4(192,168,1,1)),
                                  ee16(51820), 0);
    ck_assert_int_ge(peer_idx, 0);
    ck_assert_int_eq(wolfguard_add_allowed_ip(&wg_dev_b, peer_idx,
                     ee32(MAKE_IP4(10,0,0,0)), 8), 0);

    /* C knows A */
    peer_idx = wolfguard_add_peer(&wg_dev_c, wg_dev_a.static_public, NULL,
                                  ee32(MAKE_IP4(192,168,1,1)),
                                  ee16(51820), 0);
    ck_assert_int_ge(peer_idx, 0);
    ck_assert_int_eq(wolfguard_add_allowed_ip(&wg_dev_c, peer_idx,
                     ee32(MAKE_IP4(10,0,0,0)), 8), 0);

    wg_dev_a.now = now;
    wg_dev_b.now = now;
    wg_dev_c.now = now;

    /* Create app sockets */

    /* B listens on 10.0.1.1:7777 */
    app_sock_b = wolfIP_sock_socket(&stack_b, AF_INET, SOCK_DGRAM, 0);
    ck_assert_int_ge(app_sock_b, 0);
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = ee16(7777);
    bind_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,1,1));
    wolfIP_sock_bind(&stack_b, app_sock_b,
                     (struct wolfIP_sockaddr *)&bind_addr, sizeof(bind_addr));
    wolfIP_register_callback(&stack_b, app_sock_b, app_udp_callback, &stack_b);

    /* C listens on 10.0.2.1:7777 */
    app_sock_c = wolfIP_sock_socket(&stack_c, AF_INET, SOCK_DGRAM, 0);
    ck_assert_int_ge(app_sock_c, 0);
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = ee16(7777);
    bind_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,2,1));
    wolfIP_sock_bind(&stack_c, app_sock_c,
                     (struct wolfIP_sockaddr *)&bind_addr, sizeof(bind_addr));
    wolfIP_register_callback(&stack_c, app_sock_c, app_udp_callback2, &stack_c);

    /* A sends from 10.0.0.1:9999 */
    app_sock_a = wolfIP_sock_socket(&stack_a, AF_INET, SOCK_DGRAM, 0);
    ck_assert_int_ge(app_sock_a, 0);
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = ee16(9999);
    bind_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,0,1));
    wolfIP_sock_bind(&stack_a, app_sock_a,
                     (struct wolfIP_sockaddr *)&bind_addr, sizeof(bind_addr));

    /* Test 1: Send from A to B (10.0.1.1) */
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = ee16(7777);
    dst_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,1,1));

    ret = wolfIP_sock_sendto(&stack_a, app_sock_a,
                             payload_to_b, strlen(payload_to_b), 0,
                             (const struct wolfIP_sockaddr *)&dst_addr,
                             sizeof(dst_addr));
    ck_assert_int_ge(ret, 0);

    pump_three_stacks(&now, 300, 10);

    /* Verify B received the data */
    ck_assert_int_gt(app_recv_count, 0);
    ck_assert_int_eq(app_recv_len, (int)strlen(payload_to_b));
    ck_assert_int_eq(memcmp(app_recv_buf, payload_to_b,
                            strlen(payload_to_b)), 0);

    /* C should NOT have received this data */
    ck_assert_int_eq(app_recv_count2, 0);

    /* Test 2: Send from A to C (10.0.2.1) */
    app_recv_count = 0;
    app_recv_len = 0;

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = ee16(7777);
    dst_addr.sin_addr.s_addr = ee32(MAKE_IP4(10,0,2,1));

    ret = wolfIP_sock_sendto(&stack_a, app_sock_a,
                             payload_to_c, strlen(payload_to_c), 0,
                             (const struct wolfIP_sockaddr *)&dst_addr,
                             sizeof(dst_addr));
    ck_assert_int_ge(ret, 0);

    pump_three_stacks(&now, 300, 10);

    /* Verify C received the data */
    ck_assert_int_gt(app_recv_count2, 0);
    ck_assert_int_eq(app_recv_len2, (int)strlen(payload_to_c));
    ck_assert_int_eq(memcmp(app_recv_buf2, payload_to_c,
                            strlen(payload_to_c)), 0);

    /* Verify both peers on A have valid sessions */
    ck_assert_ptr_nonnull(wg_dev_a.peers[0].keypairs.current);
    ck_assert_ptr_nonnull(wg_dev_a.peers[1].keypairs.current);

    /* Verify TX bytes on both peers */
    ck_assert_uint_gt(wg_dev_a.peers[0].tx_bytes, 0);
    ck_assert_uint_gt(wg_dev_a.peers[1].tx_bytes, 0);

    wolfIP_sock_close(&stack_a, app_sock_a);
    wolfIP_sock_close(&stack_b, app_sock_b);
    wolfIP_sock_close(&stack_c, app_sock_c);

    wolfguard_destroy(&wg_dev_a);
    wolfguard_destroy(&wg_dev_b);
    wolfguard_destroy(&wg_dev_c);
}
END_TEST

/*
 * Test suite assembly
 * */

static Suite *wolfguard_integration_suite(void)
{
    Suite *s = suite_create("wolfGuard Integration");
    TCase *tc;

    /* Loopback round-trip */
    tc = tcase_create("loopback");
    tcase_set_timeout(tc, 120);
    tcase_add_test(tc, test_loopback_roundtrip);
    suite_add_tcase(s, tc);

    /* Session lifecycle */
    tc = tcase_create("lifecycle");
    tcase_set_timeout(tc, 120);
    tcase_add_test(tc, test_session_lifecycle);
    suite_add_tcase(s, tc);

    /* DoS cookie */
    tc = tcase_create("cookie_dos");
    tcase_set_timeout(tc, 30);
    tcase_add_test(tc, test_dos_cookie_mechanism);
    suite_add_tcase(s, tc);

    /* Roaming: endpoint update on IP change */
    tc = tcase_create("roaming");
    tcase_set_timeout(tc, 120);
    tcase_add_test(tc, test_roaming);
    suite_add_tcase(s, tc);

    /* Multi-peer: A<->B and A<->C with different allowed-IP subnets */
    tc = tcase_create("multi_peer");
    tcase_set_timeout(tc, 120);
    tcase_add_test(tc, test_multi_peer);
    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    int      nfailed;
    Suite   *s  = wolfguard_integration_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    nfailed = srunner_ntests_failed(sr);
    srunner_free(sr);

    if (rng_initialized)
        wc_FreeRng(&test_rng);

    return (nfailed == 0) ? 0 : 1;
}

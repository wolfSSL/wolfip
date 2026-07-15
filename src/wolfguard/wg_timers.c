/* wg_timers.c
 *
 * wolfGuard timer state machine
 *
 * Evaluated per-peer each poll cycle. Handles:
 * - Handshake retransmit with backoff
 * - Passive keepalive
 * - Session rekey after time
 * - Stale session detection
 * - Key material zeroing
 * - Persistent keepalive
 *
 * Copyright (C) 2026 wolfSSL Inc.
 */

#ifdef WOLFGUARD

#include "wolfguard.h"
#include <string.h>

/* Convert timer constants (seconds) to milliseconds */
#define MS(sec) ((uint64_t)(sec) * 1000ULL)

/* Generate random jitter in [0, REKEY_TIMEOUT/3) ms for timer-driven
 * initiations, per spec Section 6.1: "an additional amount of jitter
 * is added to the expiration, in order to prevent two peers from
 * repeatedly initiating handshakes at the same time." */
static void wg_regenerate_jitter(struct wg_peer *peer, WC_RNG *rng)
{
    uint16_t r = 0;
    wc_RNG_GenerateBlock(rng, (byte *)&r, sizeof(r));
    peer->rekey_jitter_ms = r % (WG_REKEY_TIMEOUT * 1000 / 3);
}

/*
 * Timer event notifications (called from packet processing)
 * */
void wg_timers_data_sent(struct wg_peer *peer, uint64_t now)
{
    peer->timer_last_data_sent = now;
}

void wg_timers_data_received(struct wg_peer *peer, uint64_t now)
{
    peer->timer_last_data_received = now;
}

void wg_timers_handshake_initiated(struct wg_peer *peer, uint64_t now)
{
    peer->timer_handshake_initiated = now;
    peer->handshake_attempts++;
}

void wg_timers_handshake_complete(struct wg_peer *peer, uint64_t now)
{
    peer->timer_last_handshake_completed = now;
    peer->handshake_attempts = 0;
}

/*
 * Reset a peer's handshake to a clean, un-started state while keeping the
 * long-term key material (remote static, precomputed static-static DH, PSK)
 * needed to start a fresh handshake later.
 *
 * wg_noise_handshake_init() snapshots the PSK before it zeroes the handshake,
 * so passing the peer's own (aliased) preshared_key pointer is safe.
 * */
static void wg_reset_handshake(struct wg_device *dev, struct wg_peer *peer)
{
    wg_noise_handshake_init(&peer->handshake, dev->static_private,
                            peer->public_key, peer->handshake.preshared_key,
                            &dev->rng);
}

/*
 * Start a fresh handshake with the peer: generate new ephemeral keys, build an
 * initiation message, attach its mac1/mac2, send it to the peer's endpoint, and
 * arm the retransmit/attempt timers. No-op on any construction failure.
 * */
static void wg_send_handshake_initiation(struct wg_device *dev,
                                         struct wg_peer *peer, uint64_t now_ms)
{
    struct wg_msg_initiation msg;
    struct wolfIP_sockaddr_in dst;

    wg_reset_handshake(dev, peer);      /* fresh ephemeral keys */

    if (wg_noise_create_initiation(dev, peer, &msg) != 0)
        return;

    wg_cookie_add_macs(peer, &msg, sizeof(msg),
                       offsetof(struct wg_msg_initiation, macs), now_ms);

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = peer->endpoint_ip;
    dst.sin_port = peer->endpoint_port;

    wolfIP_sock_sendto(dev->stack, dev->udp_sock_fd, &msg, sizeof(msg), 0,
                       (const struct wolfIP_sockaddr *)&dst, sizeof(dst));

    wg_timers_handshake_initiated(peer, now_ms);
}

/*
 * Handshake retransmit / give-up.
 *
 * From the spec (Section 6.4):
 *   "if a handshake response message is not subsequently received after
 *    Rekey-Timeout seconds, a new handshake initiation message is constructed
 *    (with new random ephemeral keys) and sent. This reinitiation is attempted
 *    for Rekey-Attempt-Time seconds before giving up"
 *
 * We retransmit every REKEY_TIMEOUT (5s) with fresh ephemeral keys. After
 * WG_MAX_HANDSHAKE_ATTEMPTS (18) retries (18 * 5s = 90s = REKEY_ATTEMPT_TIME)
 * we give up and clear the handshake state.
 *
 * Note: the spec mentions "critically important future work includes adjusting
 * the Rekey-Timeout value to use exponential backoff." The kernel WireGuard
 * implementation still uses the fixed 5s interval, so we follow that.
 * */
static void wg_timer_handshake_retransmit(struct wg_device *dev,
                                          struct wg_peer *peer, uint64_t now_ms)
{
    if (peer->handshake.state != WG_HANDSHAKE_CREATED_INITIATION ||
        peer->timer_handshake_initiated == 0)
        return;

    if (peer->handshake_attempts >= WG_MAX_HANDSHAKE_ATTEMPTS) {
        /* Gave up after REKEY_ATTEMPT_TIME of retries: drop the in-flight
         * handshake but keep long-term keys so a later send can re-initiate. */
        wg_reset_handshake(dev, peer);
        peer->handshake_attempts = 0;
        peer->timer_handshake_initiated = 0;
    } else if (now_ms - peer->timer_handshake_initiated >= MS(WG_REKEY_TIMEOUT)) {
        wg_send_handshake_initiation(dev, peer, now_ms);
    }
}

/*
 * Passive keepalive: we received data recently but have not sent anything
 * back, so emit an empty keepalive to acknowledge the peer.
 * */
static void wg_timer_passive_keepalive(struct wg_device *dev,
                                       struct wg_peer *peer, uint64_t now_ms)
{
    struct wg_keypair *current = peer->keypairs.current;

    if (current == NULL || !current->sending.is_valid)
        return;
    /* Must have received data within the last KEEPALIVE_TIMEOUT */
    if (peer->timer_last_data_received == 0 ||
        now_ms - peer->timer_last_data_received >= MS(WG_KEEPALIVE_TIMEOUT))
        return;
    /* ...and not have sent data recently */
    if (peer->timer_last_data_sent != 0 &&
        now_ms - peer->timer_last_data_sent < MS(WG_KEEPALIVE_TIMEOUT))
        return;
    /* ...and not have sent a keepalive recently */
    if (peer->timer_last_keepalive_sent != 0 &&
        now_ms - peer->timer_last_keepalive_sent < MS(WG_KEEPALIVE_TIMEOUT))
        return;

    wg_packet_send_keepalive(dev, peer);
    peer->timer_last_keepalive_sent = now_ms;
}

/*
 * Rekey after time (initiator only, with jitter): proactively start a new
 * handshake once the current session reaches REKEY_AFTER_TIME, before it can
 * expire at REJECT_AFTER_TIME.
 * */
static void wg_timer_rekey_after_time(struct wg_device *dev,
                                      struct wg_peer *peer, uint64_t now_ms)
{
    struct wg_keypair *current = peer->keypairs.current;

    if (current == NULL || !current->sending.is_valid ||
        !current->i_am_initiator ||
        peer->handshake.state != WG_HANDSHAKE_ZEROED)
        return;
    if (now_ms - current->sending.birthdate <
        MS(WG_REKEY_AFTER_TIME) + peer->rekey_jitter_ms)
        return;

    wg_regenerate_jitter(peer, &dev->rng);
    wg_send_handshake_initiation(dev, peer, now_ms);
}

/*
 * New handshake on stale receive (with jitter): we sent data but have not heard
 * back, so re-initiate to recover a possibly-dead session.
 * */
static void wg_timer_initiate_after_stale(struct wg_device *dev,
                                          struct wg_peer *peer, uint64_t now_ms)
{
    struct wg_keypair *current = peer->keypairs.current;

    if (current == NULL ||
        peer->handshake.state != WG_HANDSHAKE_ZEROED ||
        peer->timer_last_data_sent == 0 ||
        now_ms - peer->timer_last_data_sent >=
            MS(WG_KEEPALIVE_TIMEOUT + WG_REKEY_TIMEOUT))
        return;
    /* Only when we sent more recently than we received (awaiting a reply) */
    if (peer->timer_last_data_received != 0 &&
        peer->timer_last_data_sent <= peer->timer_last_data_received)
        return;
    /* Don't re-initiate if we already did recently */
    if (peer->timer_handshake_initiated != 0 &&
        now_ms - peer->timer_handshake_initiated <
            MS(WG_REKEY_TIMEOUT) + peer->rekey_jitter_ms)
        return;

    wg_regenerate_jitter(peer, &dev->rng);
    wg_send_handshake_initiation(dev, peer, now_ms);
}

/*
 * Zero key material after REJECT_AFTER_TIME * 3: the session is long dead and
 * cannot be revived, so wipe the keypairs and reset the handshake.
 * */
static void wg_timer_zero_expired_keys(struct wg_device *dev,
                                       struct wg_peer *peer, uint64_t now_ms)
{
    struct wg_keypair *current = peer->keypairs.current;

    if (current == NULL ||
        now_ms - current->sending.birthdate < MS(WG_REJECT_AFTER_TIME) * 3ULL)
        return;

    wg_memzero(&peer->keypairs.keypair_slots,
               sizeof(peer->keypairs.keypair_slots));
    peer->keypairs.current = NULL;
    peer->keypairs.previous = NULL;
    peer->keypairs.next = NULL;

    wg_reset_handshake(dev, peer);
}

/*
 * Persistent keepalive: if configured, send an empty keepalive whenever the
 * link has been idle for the configured interval.
 * */
static void wg_timer_persistent_keepalive(struct wg_device *dev,
                                          struct wg_peer *peer, uint64_t now_ms)
{
    struct wg_keypair *current = peer->keypairs.current;

    if (peer->persistent_keepalive_interval == 0 ||
        current == NULL || !current->sending.is_valid)
        return;
    if (peer->timer_last_data_sent != 0 &&
        now_ms - peer->timer_last_data_sent <
            MS(peer->persistent_keepalive_interval))
        return;

    wg_packet_send_keepalive(dev, peer);
    peer->timer_last_keepalive_sent = now_ms;
}

/*
 * Main timer tick: called every wolfIP_poll() cycle. Each active peer is run
 * through the timer rules in order; a rule may change state that a later rule
 * observes in the same tick (e.g. initiating a handshake sets the state that
 * suppresses the stale-receive rule), so the ordering is significant.
 * */
void wg_timers_tick(struct wg_device *dev, uint64_t now_ms)
{
    int i;

    for (i = 0; i < WOLFGUARD_MAX_PEERS; i++) {
        struct wg_peer *peer = &dev->peers[i];

        if (!peer->is_active)
            continue;

        wg_timer_handshake_retransmit(dev, peer, now_ms);
        wg_timer_passive_keepalive(dev, peer, now_ms);
        wg_timer_rekey_after_time(dev, peer, now_ms);
        wg_timer_initiate_after_stale(dev, peer, now_ms);
        wg_timer_zero_expired_keys(dev, peer, now_ms);
        wg_timer_persistent_keepalive(dev, peer, now_ms);
    }
}

#endif /* WOLFGUARD */

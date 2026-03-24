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
 * Main timer tick, this gets called called every wolfIP_poll() cycle
 * */

void wg_timers_tick(struct wg_device *dev, uint64_t now_ms)
{
    int i;

    for (i = 0; i < WOLFGUARD_MAX_PEERS; i++) {
        struct wg_peer *peer = &dev->peers[i];
        struct wg_keypair *current;

        if (!peer->is_active)
            continue;

        current = peer->keypairs.current;

        /* Handshake retransmit
         *
         * From the spec (Section 6.4):
         *   "if a handshake response message is not subsequently received
         *    after Rekey-Timeout seconds, a new handshake initiation message
         *    is constructed (with new random ephemeral keys) and sent.
         *    This reinitiation is attempted for Rekey-Attempt-Time seconds
         *    before giving up"
         *
         * We retransmit every REKEY_TIMEOUT (5s) with fresh ephemeral keys.
         * After WG_MAX_HANDSHAKE_ATTEMPTS (18) retries (18 * 5s = 90s =
         * REKEY_ATTEMPT_TIME), we give up and clear the handshake state.
         *
         * Note: the spec mentions "critically important future work includes
         * adjusting the Rekey-Timeout value to use exponential backoff."
         * The kernel WireGuard implementation still uses the fixed 5s interval,
         * so we follow that.
         * */
        if (peer->handshake.state == WG_HANDSHAKE_CREATED_INITIATION &&
            peer->timer_handshake_initiated > 0) {

            if (peer->handshake_attempts >= WG_MAX_HANDSHAKE_ATTEMPTS) {
                /* Give up after REKEY_ATTEMPT_TIME worth of retries.
                 * Re-initialize handshake: zero ephemeral/session state
                 * but restore long-term keys so future sends can
                 * re-initiate a fresh handshake. */
                {
                    uint8_t psk[WG_SYMMETRIC_KEY_LEN];
                    memcpy(psk, peer->handshake.preshared_key,
                           WG_SYMMETRIC_KEY_LEN);
                    wg_noise_handshake_init(&peer->handshake,
                                            dev->static_private,
                                            peer->public_key,
                                            psk, &dev->rng);
                    wg_memzero(psk, sizeof(psk));
                }
                peer->handshake_attempts = 0;
                peer->timer_handshake_initiated = 0;
            } else if (now_ms - peer->timer_handshake_initiated >=
                           MS(WG_REKEY_TIMEOUT)) {
                /* Retransmit initiation */
                struct wg_msg_initiation msg;
                struct wolfIP_sockaddr_in dst;

                /* Re-init handshake for fresh ephemeral */
                wg_noise_handshake_init(&peer->handshake,
                                        dev->static_private,
                                        peer->public_key,
                                        peer->handshake.preshared_key,
                                        &dev->rng);

                if (wg_noise_create_initiation(dev, peer, &msg) == 0) {
                    size_t mac_off =
                        offsetof(struct wg_msg_initiation, macs);
                    wg_cookie_add_macs(peer, &msg, sizeof(msg), mac_off);

                    memset(&dst, 0, sizeof(dst));
                    dst.sin_family = AF_INET;
                    dst.sin_addr.s_addr = peer->endpoint_ip;
                    dst.sin_port = peer->endpoint_port;

                    wolfIP_sock_sendto(dev->stack, dev->udp_sock_fd,
                                       &msg, sizeof(msg), 0,
                                       (const struct wolfIP_sockaddr *)&dst, sizeof(dst));

                    wg_timers_handshake_initiated(peer, now_ms);
                }
            }
        }

        /* Passive keepalive: received data recently but haven't sent */
        if (current != NULL && current->sending.is_valid &&
            peer->timer_last_data_received > 0 &&
            now_ms - peer->timer_last_data_received < MS(WG_KEEPALIVE_TIMEOUT) &&
            (peer->timer_last_data_sent == 0 ||
             now_ms - peer->timer_last_data_sent >=
                 MS(WG_KEEPALIVE_TIMEOUT)) &&
            (peer->timer_last_keepalive_sent == 0 ||
             now_ms - peer->timer_last_keepalive_sent >=
                 MS(WG_KEEPALIVE_TIMEOUT))) {

            wg_packet_send_keepalive(dev, peer);
            peer->timer_last_keepalive_sent = now_ms;
        }

        /* Rekey after time (initiator only, with jitter) */
        if (current != NULL && current->sending.is_valid &&
            current->i_am_initiator &&
            now_ms - current->sending.birthdate >=
                MS(WG_REKEY_AFTER_TIME) + peer->rekey_jitter_ms &&
            peer->handshake.state == WG_HANDSHAKE_ZEROED) {

            struct wg_msg_initiation msg;
            struct wolfIP_sockaddr_in dst;

            wg_regenerate_jitter(peer, &dev->rng);

            wg_noise_handshake_init(&peer->handshake,
                                    dev->static_private,
                                    peer->public_key,
                                    peer->handshake.preshared_key,
                                    &dev->rng);

            if (wg_noise_create_initiation(dev, peer, &msg) == 0) {
                size_t mac_off = offsetof(struct wg_msg_initiation, macs);
                wg_cookie_add_macs(peer, &msg, sizeof(msg), mac_off);

                memset(&dst, 0, sizeof(dst));
                dst.sin_family = AF_INET;
                dst.sin_addr.s_addr = peer->endpoint_ip;
                dst.sin_port = peer->endpoint_port;

                wolfIP_sock_sendto(dev->stack, dev->udp_sock_fd,
                                   &msg, sizeof(msg), 0,
                                   (const struct wolfIP_sockaddr *)&dst, sizeof(dst));

                wg_timers_handshake_initiated(peer, now_ms);
            }
        }

        /* New handshake on stale receive (sent data but no reply, with jitter) */
        if (current != NULL &&
            peer->timer_last_data_sent > 0 &&
            now_ms - peer->timer_last_data_sent <
                MS(WG_KEEPALIVE_TIMEOUT + WG_REKEY_TIMEOUT) &&
            (peer->timer_last_data_received == 0 ||
             peer->timer_last_data_sent > peer->timer_last_data_received) &&
            peer->handshake.state == WG_HANDSHAKE_ZEROED) {

            /* Don't re-initiate if we already did recently */
            if (peer->timer_handshake_initiated == 0 ||
                now_ms - peer->timer_handshake_initiated >=
                    MS(WG_REKEY_TIMEOUT) + peer->rekey_jitter_ms) {
                struct wg_msg_initiation msg;
                struct wolfIP_sockaddr_in dst;

                wg_regenerate_jitter(peer, &dev->rng);

                wg_noise_handshake_init(&peer->handshake,
                                        dev->static_private,
                                        peer->public_key,
                                        peer->handshake.preshared_key,
                                        &dev->rng);

                if (wg_noise_create_initiation(dev, peer, &msg) == 0) {
                    size_t mac_off =
                        offsetof(struct wg_msg_initiation, macs);
                    wg_cookie_add_macs(peer, &msg, sizeof(msg), mac_off);

                    memset(&dst, 0, sizeof(dst));
                    dst.sin_family = AF_INET;
                    dst.sin_addr.s_addr = peer->endpoint_ip;
                    dst.sin_port = peer->endpoint_port;

                    wolfIP_sock_sendto(dev->stack, dev->udp_sock_fd,
                                       &msg, sizeof(msg), 0,
                                       (const struct wolfIP_sockaddr *)&dst, sizeof(dst));

                    wg_timers_handshake_initiated(peer, now_ms);
                }
            }
        }

        /* Zero key material after REJECT_AFTER_TIME * 3 */
        if (current != NULL &&
            now_ms - current->sending.birthdate >=
                MS(WG_REJECT_AFTER_TIME) * 3ULL) {

            wg_memzero(&peer->keypairs.keypair_slots,
                              sizeof(peer->keypairs.keypair_slots));
            peer->keypairs.current = NULL;
            peer->keypairs.previous = NULL;
            peer->keypairs.next = NULL;

            /* Re-initialize handshake: zero ephemeral/session state but
             * restore long-term keys so future handshakes can proceed */
            {
                uint8_t psk[WG_SYMMETRIC_KEY_LEN];
                memcpy(psk, peer->handshake.preshared_key,
                       WG_SYMMETRIC_KEY_LEN);
                wg_noise_handshake_init(&peer->handshake,
                                        dev->static_private,
                                        peer->public_key,
                                        psk, &dev->rng);
                wg_memzero(psk, sizeof(psk));
            }
        }

        /* Persistent keepalive */
        if (peer->persistent_keepalive_interval > 0 &&
            current != NULL && current->sending.is_valid &&
            (peer->timer_last_data_sent == 0 ||
             now_ms - peer->timer_last_data_sent >=
                 MS(peer->persistent_keepalive_interval))) {

            wg_packet_send_keepalive(dev, peer);
            peer->timer_last_keepalive_sent = now_ms;
        }
    }
}

#endif /* WOLFGUARD */

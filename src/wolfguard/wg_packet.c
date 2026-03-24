/* wg_packet.c
 *
 * wolfGuard packet send/receive processing
 *
 * TX: encrypt plaintext IP packet -> WG data message -> send via UDP
 * RX: receive WG message from UDP -> dispatch by type -> decrypt -> inject
 *
 * Copyright (C) 2026 wolfSSL Inc.
 */

#ifdef WOLFGUARD

#include "wolfguard.h"
#include <string.h>

/* LE32 helpers */
static uint32_t wg_le32_encode(uint32_t v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return v;
#else
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) |
           ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
#endif
}

static uint32_t wg_le32_decode(uint32_t v)
{
    return wg_le32_encode(v);
}

static uint64_t wg_le64_encode(uint64_t v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return v;
#else
    return ((v & 0xFFULL) << 56) | ((v & 0xFF00ULL) << 40) |
           ((v & 0xFF0000ULL) << 24) | ((v & 0xFF000000ULL) << 8) |
           ((v >> 8) & 0xFF000000ULL) | ((v >> 24) & 0xFF0000ULL) |
           ((v >> 40) & 0xFF00ULL) | ((v >> 56) & 0xFFULL);
#endif
}

static uint64_t wg_le64_decode(uint64_t v)
{
    return wg_le64_encode(v);
}

/*
 * Replay counter validation (sliding window)
 * */

int wg_counter_validate(struct wg_keypair *kp, uint64_t counter)
{
    uint64_t diff;
    uint32_t bit_idx, word, bit;

    if (counter >= WG_REJECT_AFTER_MESSAGES)
        return 0;

    if (counter > kp->receiving_counter_max) {
        /* Advance window */
        diff = counter - kp->receiving_counter_max;
        if (diff >= WOLFGUARD_COUNTER_WINDOW) {
            /* New counter is way ahead, clear entire bitmap */
            memset(kp->receiving_counter_bitmap, 0,
                   sizeof(kp->receiving_counter_bitmap));
        } else {
            /* Shift bitmap: mark bits for skipped counters as unseen */
            uint64_t i;
            for (i = kp->receiving_counter_max + 1; i <= counter; i++) {
                bit_idx = (uint32_t)(i % WOLFGUARD_COUNTER_WINDOW);
                word = bit_idx / 32;
                bit = bit_idx % 32;
                kp->receiving_counter_bitmap[word] &= ~(1U << bit);
            }
        }
        kp->receiving_counter_max = counter;
    } else if (counter + WOLFGUARD_COUNTER_WINDOW <= kp->receiving_counter_max) {
        return 0; /* Too old */
    }

    /* Check/set bit in bitmap */
    bit_idx = (uint32_t)(counter % WOLFGUARD_COUNTER_WINDOW);
    word = bit_idx / 32;
    bit = bit_idx % 32;

    if (kp->receiving_counter_bitmap[word] & (1U << bit))
        return 0; /* Replay */

    kp->receiving_counter_bitmap[word] |= (1U << bit);
    return 1;
}

/*
 * Pad plaintext to 16-byte multiple (WireGuard spec requirement)
 * */

static size_t wg_pad_len(size_t len)
{
    size_t padded = len;
    if (padded % 16 != 0)
        padded += 16 - (padded % 16);
    return padded;
}

/*
 * Find keypair by receiver index (linear scan — fine for small N)
 * */

static struct wg_peer *wg_find_peer_by_index(struct wg_device *dev,
                                             uint32_t receiver_index,
                                             struct wg_keypair **kp_out)
{
    int i;

    for (i = 0; i < WOLFGUARD_MAX_PEERS; i++) {
        struct wg_peer *p = &dev->peers[i];
        struct wg_keypairs *kps;

        if (!p->is_active)
            continue;

        kps = &p->keypairs;

        if (kps->current && kps->current->local_index == receiver_index) {
            *kp_out = kps->current;
            return p;
        }
        if (kps->previous && kps->previous->local_index == receiver_index) {
            *kp_out = kps->previous;
            return p;
        }
        if (kps->next && kps->next->local_index == receiver_index) {
            *kp_out = kps->next;
            return p;
        }
    }

    *kp_out = NULL;
    return NULL;
}

/*
 * Stage a packet (queue while handshake is in progress)
 *
 * When the queue is full, new arrivals are dropped.  The Linux kernel
 * WireGuard implementation drops the oldest packet instead, but the
 * whitepaper does not prescribe queue-full behaviour (Section 7.1 only
 * says "after queuing the packet").  Dropping new arrivals is simpler
 * and avoids memmove/ring-buffer overhead on an embedded target.
 * */

static void wg_stage_packet(struct wg_peer *peer,
                            const uint8_t *packet, size_t len)
{
    if (peer->staged_count >= WOLFGUARD_STAGED_PACKETS)
        return;

    if (len > LINK_MTU)
        len = LINK_MTU;

    memcpy(peer->staged_packets[peer->staged_count], packet, len);
    peer->staged_packet_lens[peer->staged_count] = (uint16_t)len;
    peer->staged_count++;
}

/*
 * TX: encrypt and send a plaintext IP packet as WG data message
 * */

int wg_packet_send(struct wg_device *dev, struct wg_peer *peer,
                   const uint8_t *plaintext, size_t len)
{
    struct wg_keypair *kp = peer->keypairs.current;
    uint8_t buf[LINK_MTU + 64]; /* Room for header + padding + tag */
    struct wg_msg_data *data_msg = (struct wg_msg_data *)buf;
    size_t padded_len, total_len;
    uint8_t padded[LINK_MTU];
    struct wolfIP_sockaddr_in dst;
    int ret;

    /* Check for valid sending keypair */
    if (kp == NULL || !kp->sending.is_valid) {
        /* No valid session — stage packet and initiate handshake */
        wg_stage_packet(peer, plaintext, len);
        if (peer->handshake.state == WG_HANDSHAKE_ZEROED) {
            struct wg_msg_initiation init_msg;
            ret = wg_noise_create_initiation(dev, peer, &init_msg);
            if (ret == 0) {
                size_t mac_off = offsetof(struct wg_msg_initiation, macs);
                wg_cookie_add_macs(peer, &init_msg, sizeof(init_msg),
                                   mac_off);
                memset(&dst, 0, sizeof(dst));
                dst.sin_family = AF_INET;
                dst.sin_addr.s_addr = peer->endpoint_ip;
                dst.sin_port = peer->endpoint_port;
                wolfIP_sock_sendto(dev->stack, dev->udp_sock_fd,
                                   &init_msg, sizeof(init_msg), 0,
                                   (const struct wolfIP_sockaddr *)&dst, sizeof(dst));
                wg_timers_handshake_initiated(peer, dev->now);
            }
        }

        return 0;
    }

    /* Check key age / message count limits */
    if (kp->sending_counter >= WG_REKEY_AFTER_MESSAGES ||
        (dev->now - kp->sending.birthdate) >=
            (uint64_t)WG_REJECT_AFTER_TIME * 1000ULL) {
        kp->sending.is_valid = 0;
        wg_stage_packet(peer, plaintext, len);
        return 0;
    }

    /* Pad plaintext to 16-byte multiple */
    padded_len = wg_pad_len(len);
    if (padded_len > sizeof(padded))
        return -1;
    memcpy(padded, plaintext, len);
    if (padded_len > len)
        memset(padded + len, 0, padded_len - len);

    /* Build data message header */
    data_msg->header.type = wg_le32_encode(WG_MSG_DATA);
    data_msg->receiver_index = wg_le32_encode(kp->remote_index);
    data_msg->counter = wg_le64_encode(kp->sending_counter);

    /* Encrypt: AEAD(sending_key, counter, padded_plaintext, empty_aad) */
    ret = wg_aead_encrypt(data_msg->encrypted_data,
                          kp->sending.key, kp->sending_counter,
                          padded, padded_len,
                          NULL, 0);
    if (ret != 0) {
        wg_memzero(padded, sizeof(padded));
        return -1;
    }

    kp->sending_counter++;

    /* Total: header(4) + receiver(4) + counter(8) + ciphertext + tag(16) */
    total_len = sizeof(struct wg_msg_data) + padded_len + WG_AUTHTAG_LEN;

    /* Send via UDP to peer's endpoint */
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = peer->endpoint_ip;
    dst.sin_port = peer->endpoint_port;

    wolfIP_sock_sendto(dev->stack, dev->udp_sock_fd,
                       buf, total_len, 0, (const struct wolfIP_sockaddr *)&dst, sizeof(dst));

    peer->tx_bytes += len;
    wg_timers_data_sent(peer, dev->now);

    /* Trigger rekey if approaching limits */
    if (kp->sending_counter >= WG_REKEY_AFTER_MESSAGES ||
        (dev->now - kp->sending.birthdate) >=
            (uint64_t)WG_REKEY_AFTER_TIME * 1000ULL) {
        if (kp->i_am_initiator) {
            struct wg_msg_initiation init_msg;
            if (wg_noise_create_initiation(dev, peer, &init_msg) == 0) {
                size_t mac_off = offsetof(struct wg_msg_initiation, macs);
                wg_cookie_add_macs(peer, &init_msg, sizeof(init_msg),
                                   mac_off);
                memset(&dst, 0, sizeof(dst));
                dst.sin_family = AF_INET;
                dst.sin_addr.s_addr = peer->endpoint_ip;
                dst.sin_port = peer->endpoint_port;
                wolfIP_sock_sendto(dev->stack, dev->udp_sock_fd,
                                   &init_msg, sizeof(init_msg), 0,
                                   (const struct wolfIP_sockaddr *)&dst, sizeof(dst));
                wg_timers_handshake_initiated(peer, dev->now);
            }
        }
    }

    wg_memzero(padded, sizeof(padded));
    return 0;
}

/*
 * Send staged (queued) packets after handshake completes
 * */

void wg_packet_send_staged(struct wg_device *dev, struct wg_peer *peer)
{
    int i;
    uint8_t count = peer->staged_count;

    peer->staged_count = 0;

    for (i = 0; i < count; i++) {
        wg_packet_send(dev, peer,
                       peer->staged_packets[i],
                       peer->staged_packet_lens[i]);
        wg_memzero(peer->staged_packets[i],
                peer->staged_packet_lens[i]);
        peer->staged_packet_lens[i] = 0;
    }
}

/*
 * Send keepalive (empty encrypted data message)
 * */

int wg_packet_send_keepalive(struct wg_device *dev, struct wg_peer *peer)
{
    struct wg_keypair *kp = peer->keypairs.current;
    uint8_t buf[sizeof(struct wg_msg_data) + WG_AUTHTAG_LEN];
    struct wg_msg_data *data_msg = (struct wg_msg_data *)buf;
    struct wolfIP_sockaddr_in dst;
    int ret;

    if (kp == NULL || !kp->sending.is_valid)
        return -1;

    /* enforce the same reject-after limits as data
     * send from the specification (6.2):
     * "After Reject-After-Messages transport data messages or after the
     * current secure session is RejectAfter-Time seconds old, whichever
     * comes first, WireGuard will refuse to send or receive any more transport data
     * messages using the current secure session, until a new secure session
     * is created through the 1-RTT handshake."
     */
    if (kp->sending_counter >= WG_REJECT_AFTER_MESSAGES)
       return -1;
    if ((dev->now - kp->sending.birthdate) >=
            (uint64_t)WG_REJECT_AFTER_TIME * 1000ULL)
        return -1;

    data_msg->header.type = wg_le32_encode(WG_MSG_DATA);
    data_msg->receiver_index = wg_le32_encode(kp->remote_index);
    data_msg->counter = wg_le64_encode(kp->sending_counter);

    /* Encrypt empty plaintext */
    ret = wg_aead_encrypt(data_msg->encrypted_data,
                          kp->sending.key, kp->sending_counter,
                          NULL, 0, NULL, 0);
    if (ret != 0)
        return -1;

    kp->sending_counter++;

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = peer->endpoint_ip;
    dst.sin_port = peer->endpoint_port;

    wolfIP_sock_sendto(dev->stack, dev->udp_sock_fd,
                       buf, sizeof(buf), 0, (const struct wolfIP_sockaddr *)&dst, sizeof(dst));

    /* Don't call wg_timers_data_sent, keepalives are not user data
     * and should not trigger the "stale receive" handshake timer */
    return 0;
}

/*
 * RX: handle incoming data message (type 4)
 * */

static void wg_handle_data(struct wg_device *dev, const uint8_t *data,
                           size_t len, uint32_t src_ip, uint16_t src_port)
{
    const struct wg_msg_data *msg = (const struct wg_msg_data *)data;
    uint32_t receiver_index;
    uint64_t counter;
    struct wg_keypair *kp;
    struct wg_peer *peer;
    size_t encrypted_len, plaintext_len = 0;
    uint8_t plaintext[LINK_MTU];
    uint32_t inner_src_ip;
    int peer_idx;

    if (len < sizeof(struct wg_msg_data) + WG_AUTHTAG_LEN)
        return;

    receiver_index = wg_le32_decode(msg->receiver_index);
    counter = wg_le64_decode(msg->counter);

    peer = wg_find_peer_by_index(dev, receiver_index, &kp);
    if (peer == NULL || kp == NULL)
        return;

    if (!kp->receiving.is_valid)
        return;

    /* Check key expiration */
    if ((dev->now - kp->receiving.birthdate) >=
        (uint64_t)WG_REJECT_AFTER_TIME * 1000ULL)
        return;

    /* Decrypt */
    encrypted_len = len - sizeof(struct wg_msg_data);
    if (encrypted_len < WG_AUTHTAG_LEN)
        return;
    plaintext_len = encrypted_len - WG_AUTHTAG_LEN;

    if (plaintext_len > sizeof(plaintext))
        return;

    if (wg_aead_decrypt(plaintext, kp->receiving.key, counter,
                        msg->encrypted_data, encrypted_len,
                        NULL, 0) != 0)
        goto out;

    /* Replay check */
    if (!wg_counter_validate(kp, counter))
        goto out;

    /* If this is from the "next" keypair (responder), confirm session */
    if (kp == peer->keypairs.next) {
        if (peer->keypairs.previous != NULL)
            wg_memzero(peer->keypairs.previous,
                              sizeof(struct wg_keypair));
        peer->keypairs.previous = peer->keypairs.current;
        peer->keypairs.current = kp;
        peer->keypairs.next = NULL;
    }

    /* Update peer endpoint (roaming) */
    peer->endpoint_ip = src_ip;
    peer->endpoint_port = src_port;

    peer->rx_bytes += plaintext_len;
    wg_timers_data_received(peer, dev->now);

    /* Empty plaintext = keepalive, don't inject */
    if (plaintext_len == 0)
        goto out;

    /* Validate inner source IP against allowed IPs */
    if (plaintext_len >= 20) {
        memcpy(&inner_src_ip, plaintext + 12, 4); /* IPv4 src addr offset */
        peer_idx = wg_allowedips_lookup(dev, inner_src_ip);
        if (peer_idx < 0 || &dev->peers[peer_idx] != peer)
            goto out; /* Source IP not allowed for this peer */
    }

    /* Inject decrypted packet into the wg0 interface */
    wolfIP_recv_ex(dev->stack, dev->wg_if_idx, (void *)plaintext,
                   (uint16_t)plaintext_len);

out:
    wg_memzero(plaintext, plaintext_len);
}

/*
 * RX: handle incoming handshake initiation (type 1)
 * */

static void wg_handle_initiation(struct wg_device *dev, const uint8_t *data,
                                 size_t len, uint32_t src_ip,
                                 uint16_t src_port)
{
    struct wg_msg_initiation *msg;
    struct wg_msg_response resp;
    struct wg_peer *peer;
    struct wolfIP_sockaddr_in dst;
    size_t mac_off;
    enum wg_cookie_mac_state mac_state;

    if (len < sizeof(struct wg_msg_initiation)) {
        return;
    }

    msg = (struct wg_msg_initiation *)data;

    /* Validate MACs */
    mac_off = offsetof(struct wg_msg_initiation, macs);
    mac_state = wg_cookie_validate(&dev->cookie_checker, msg, len,
                                   mac_off, src_ip, src_port, dev->now);
    if (mac_state == WG_COOKIE_MAC_INVALID) {
        return;
    }

    dev->handshakes_per_cycle++;

    /* Under load: require valid cookie (mac2) or send cookie reply */
    if (dev->under_load && mac_state != WG_COOKIE_MAC_VALID_WITH_COOKIE) {
        struct wg_msg_cookie cookie_reply;
        struct wolfIP_sockaddr_in dst;
        uint32_t sender_idx = ((struct wg_msg_initiation *)data)->sender_index;

        if (wg_cookie_create_reply(dev, &cookie_reply, msg, mac_off,
                                   sender_idx, src_ip, src_port) == 0) {
            memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            dst.sin_addr.s_addr = src_ip;
            dst.sin_port = src_port;
            wolfIP_sock_sendto(dev->stack, dev->udp_sock_fd,
                               &cookie_reply, sizeof(cookie_reply), 0,
                               (const struct wolfIP_sockaddr *)&dst,
                               sizeof(dst));
        }
        return;
    }

    /* Consume initiation */
    peer = wg_noise_consume_initiation(dev, msg);
    if (peer == NULL) {
        return;
    }

    /* Update endpoint */
    peer->endpoint_ip = src_ip;
    peer->endpoint_port = src_port;

    /* Create response */
    if (wg_noise_create_response(dev, peer, &resp) != 0) {
        return;
    }

    /* Add MACs to response */
    mac_off = offsetof(struct wg_msg_response, macs);
    wg_cookie_add_macs(peer, &resp, sizeof(resp), mac_off);

    /* Send response */
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = peer->endpoint_ip;
    dst.sin_port = peer->endpoint_port;

    wolfIP_sock_sendto(dev->stack, dev->udp_sock_fd,
                       &resp, sizeof(resp), 0, (const struct wolfIP_sockaddr *)&dst, sizeof(dst));

    /* Derive transport keys */
    if (wg_noise_begin_session(dev, peer) == 0) {
        wg_timers_handshake_complete(peer, dev->now);
        wg_packet_send_staged(dev, peer);
    }
}

/*
 * RX: handle incoming handshake response (type 2)
 * */

static void wg_handle_response(struct wg_device *dev, const uint8_t *data,
                                size_t len, uint32_t src_ip,
                                uint16_t src_port)
{
    struct wg_msg_response *msg;
    uint32_t receiver_index;
    struct wg_peer *peer = NULL;
    size_t mac_off;
    enum wg_cookie_mac_state mac_state;
    int i;

    if (len < sizeof(struct wg_msg_response)) {
        return;
    }

    msg = (struct wg_msg_response *)data;

    /* Validate MACs */
    mac_off = offsetof(struct wg_msg_response, macs);
    mac_state = wg_cookie_validate(&dev->cookie_checker, msg, len,
                                   mac_off, src_ip, src_port, dev->now);
    if (mac_state == WG_COOKIE_MAC_INVALID) {
        return;
    }

    dev->handshakes_per_cycle++;

    /* Under load: require valid cookie (mac2) or send cookie reply */
    if (dev->under_load && mac_state != WG_COOKIE_MAC_VALID_WITH_COOKIE) {
        struct wg_msg_cookie cookie_reply;
        struct wolfIP_sockaddr_in dst;
        uint32_t sender_idx = ((struct wg_msg_response *)data)->sender_index;

        if (wg_cookie_create_reply(dev, &cookie_reply, msg, mac_off,
                                   sender_idx, src_ip, src_port) == 0) {
            memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            dst.sin_addr.s_addr = src_ip;
            dst.sin_port = src_port;
            wolfIP_sock_sendto(dev->stack, dev->udp_sock_fd,
                               &cookie_reply, sizeof(cookie_reply), 0,
                               (const struct wolfIP_sockaddr *)&dst,
                               sizeof(dst));
        }
        return;
    }

    /* Find peer by receiver_index (our sender_index from initiation) */
    receiver_index = wg_le32_decode(msg->receiver_index);
    for (i = 0; i < WOLFGUARD_MAX_PEERS; i++) {
        if (dev->peers[i].is_active &&
            dev->peers[i].handshake.state == WG_HANDSHAKE_CREATED_INITIATION &&
            dev->peers[i].handshake.local_index == receiver_index) {
            peer = &dev->peers[i];
            break;
        }
    }

    if (peer == NULL) {
        return;
    }

    /* Consume response */
    if (wg_noise_consume_response(dev, peer, msg) != 0) {
        return;
    }

    /* Update endpoint */
    peer->endpoint_ip = src_ip;
    peer->endpoint_port = src_port;

    /* Derive transport keys */
    if (wg_noise_begin_session(dev, peer) == 0) {
        wg_timers_handshake_complete(peer, dev->now);
        wg_packet_send_staged(dev, peer);

        /* If no staged packets were sent, send a keepalive so the
         * responder can confirm the session (Section 6.3: responder
         * cannot send until it receives the first transport message
         * from the initiator). */
        if (peer->keypairs.current &&
            peer->keypairs.current->sending_counter == 0)
            wg_packet_send_keepalive(dev, peer);
    }
}

/*
 * RX: handle incoming cookie reply (type 3)
 * */

static void wg_handle_cookie(struct wg_device *dev, const uint8_t *data,
                              size_t len)
{
    struct wg_msg_cookie *msg;
    uint32_t receiver_index;
    struct wg_peer *peer = NULL;
    int i;

    if (len < sizeof(struct wg_msg_cookie))
        return;

    msg = (struct wg_msg_cookie *)data;
    receiver_index = wg_le32_decode(msg->receiver_index);

    /* Find peer by receiver_index (matches our handshake local_index) */
    for (i = 0; i < WOLFGUARD_MAX_PEERS; i++) {
        if (dev->peers[i].is_active &&
            dev->peers[i].cookie.have_sent_mac1 &&
            dev->peers[i].handshake.local_index == receiver_index) {
            peer = &dev->peers[i];
            break;
        }
    }

    if (peer == NULL)
        return;

    wg_cookie_consume_reply(peer, msg);
}

/*
 * RX: main dispatch, receive and dispatch incoming WG message
 * */

void wg_packet_receive(struct wg_device *dev, const uint8_t *data, size_t len,
                       uint32_t src_ip, uint16_t src_port)
{
    uint32_t msg_type;

    if (len < 4)
        return;

    memcpy(&msg_type, data, sizeof(msg_type));
    msg_type = wg_le32_decode(msg_type);

    switch (msg_type) {
    case WG_MSG_INITIATION:
        wg_handle_initiation(dev, data, len, src_ip, src_port);
        break;
    case WG_MSG_RESPONSE:
        wg_handle_response(dev, data, len, src_ip, src_port);
        break;
    case WG_MSG_COOKIE:
        wg_handle_cookie(dev, data, len);
        break;
    case WG_MSG_DATA:
        wg_handle_data(dev, data, len, src_ip, src_port);
        break;
    default:
        break;
    }
}

#endif /* WOLFGUARD */

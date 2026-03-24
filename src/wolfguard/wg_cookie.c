/* wg_cookie.c
 *
 * wolfGuard cookie/MAC generation and validation (used against DoS and replay attacks)
 *
 * MAC computation (WireGuard spec section 5.4.4):
 *   mac1 = Mac(Hash("mac1----" || S_remote_pub), msg_alpha)
 *   mac2 = Mac(cookie, msg_beta)
 *
 * Copyright (C) 2026 wolfSSL Inc.
 */

#ifdef WOLFGUARD

#include "wolfguard.h"
#include <string.h>

/*
 * Pre-compute device-level MAC/cookie keys from static public key
 *
 * message_mac1_key = Hash("mac1----" || device_public_key)
 * cookie_encryption_key = Hash("cookie--" || device_public_key)
 * */

void wg_cookie_checker_init(struct wg_cookie_checker *checker,
                            const uint8_t *device_public_key)
{
    memset(checker, 0, sizeof(*checker));

    wg_hash2(checker->message_mac1_key,
             (const uint8_t *)WG_LABEL_MAC1, strlen(WG_LABEL_MAC1),
             device_public_key, WG_PUBLIC_KEY_LEN);

    wg_hash2(checker->cookie_encryption_key,
             (const uint8_t *)WG_LABEL_COOKIE, strlen(WG_LABEL_COOKIE),
             device_public_key, WG_PUBLIC_KEY_LEN);
}

/*
 * Pre-compute per-peer MAC/cookie keys (for outgoing messages)
 *
 * Keys are derived from the remote peer's public key.
 * */

void wg_cookie_init(struct wg_cookie *cookie,
                    const uint8_t *peer_public_key)
{
    memset(cookie, 0, sizeof(*cookie));

    wg_hash2(cookie->message_mac1_key,
             (const uint8_t *)WG_LABEL_MAC1, strlen(WG_LABEL_MAC1),
             peer_public_key, WG_PUBLIC_KEY_LEN);

    wg_hash2(cookie->cookie_decryption_key,
             (const uint8_t *)WG_LABEL_COOKIE, strlen(WG_LABEL_COOKIE),
             peer_public_key, WG_PUBLIC_KEY_LEN);
}

/*
 * Add mac1 and mac2 to outgoing handshake message
 *
 * mac1 = Mac(message_mac1_key, msg[0..mac_offset))
 * mac2 = Mac(cookie, msg[0..mac_offset+16))  if cookie is valid
 * */

int wg_cookie_add_macs(struct wg_peer *peer, void *msg, size_t msg_len,
                       size_t mac_offset)
{
    uint8_t *msg_bytes = (uint8_t *)msg;
    struct wg_msg_macs *macs;
    int ret;

    if (mac_offset + sizeof(struct wg_msg_macs) > msg_len)
        return -1;

    macs = (struct wg_msg_macs *)(msg_bytes + mac_offset);

    /* mac1 = Mac(message_mac1_key, msg[0..mac_offset)) */
    ret = wg_mac(macs->mac1, peer->cookie.message_mac1_key,
                 WG_SYMMETRIC_KEY_LEN, msg_bytes, mac_offset);
    if (ret != 0)
        return -1;

    /* Save mac1 for potential cookie reply handling */
    memcpy(peer->cookie.last_mac1_sent, macs->mac1, WG_COOKIE_LEN);
    peer->cookie.have_sent_mac1 = 1;

    /* mac2: only if we have a valid cookie */
    if (peer->cookie.is_valid) {
        ret = wg_mac(macs->mac2, peer->cookie.cookie, WG_COOKIE_LEN,
                     msg_bytes, mac_offset + WG_COOKIE_LEN);
        if (ret != 0)
            return -1;
    } else {
        memset(macs->mac2, 0, WG_COOKIE_LEN);
    }

    return 0;
}

/*
 * Validate mac1 (and optionally mac2) on incoming handshake message
 * */

enum wg_cookie_mac_state wg_cookie_validate(
    struct wg_cookie_checker *checker, void *msg, size_t msg_len,
    size_t mac_offset, uint32_t src_ip, uint16_t src_port, uint64_t now)
{
    uint8_t *msg_bytes = (uint8_t *)msg;
    struct wg_msg_macs *macs;
    uint8_t computed_mac[WG_COOKIE_LEN];
    uint8_t zero_mac[WG_COOKIE_LEN];

    if (mac_offset + sizeof(struct wg_msg_macs) > msg_len)
        return WG_COOKIE_MAC_INVALID;

    macs = (struct wg_msg_macs *)(msg_bytes + mac_offset);

    /* Validate mac1 = Mac(message_mac1_key, msg[0..mac_offset)) */
    if (wg_mac(computed_mac, checker->message_mac1_key,
               WG_SYMMETRIC_KEY_LEN, msg_bytes, mac_offset) != 0)
        return WG_COOKIE_MAC_INVALID;

    if (wg_memcmp(computed_mac, macs->mac1, WG_COOKIE_LEN) != 0)
        return WG_COOKIE_MAC_INVALID;

    /* Check if mac2 is present (non-zero) */
    memset(zero_mac, 0, WG_COOKIE_LEN);
    if (wg_memcmp(macs->mac2, zero_mac, WG_COOKIE_LEN) == 0)
        return WG_COOKIE_MAC_VALID;

    /* Validate mac2 if cookie secret is fresh */
    if (now - checker->secret_birthdate > WG_COOKIE_SECRET_MAX_AGE * 1000ULL)
        return WG_COOKIE_MAC_VALID; /* Secret expired, ignore mac2 */

    /* Compute cookie for this source: Mac(secret, src_ip || src_port) */
    {
        uint8_t src_data[6]; /* 4 bytes IP + 2 bytes port */
        uint8_t cookie[WG_COOKIE_LEN];

        memcpy(src_data, &src_ip, 4);
        src_data[4] = (uint8_t)(src_port);
        src_data[5] = (uint8_t)(src_port >> 8);

        if (wg_mac(cookie, checker->secret, WG_HASH_LEN,
                   src_data, sizeof(src_data)) != 0)
            return WG_COOKIE_MAC_VALID;

        /* mac2 = Mac(cookie, msg[0..mac_offset+16)) */
        if (wg_mac(computed_mac, cookie, WG_COOKIE_LEN,
                   msg_bytes, mac_offset + WG_COOKIE_LEN) != 0)
            return WG_COOKIE_MAC_VALID;

        if (wg_memcmp(computed_mac, macs->mac2, WG_COOKIE_LEN) == 0)
            return WG_COOKIE_MAC_VALID_WITH_COOKIE;
    }

    return WG_COOKIE_MAC_VALID;
}

/*
 * Create cookie reply message
 * */

int wg_cookie_create_reply(struct wg_device *dev, struct wg_msg_cookie *reply,
                           const void *triggering_msg, size_t mac_offset,
                           uint32_t sender_index,
                           uint32_t src_ip, uint16_t src_port)
{
    struct wg_cookie_checker *checker = &dev->cookie_checker;
    uint8_t src_data[6];
    uint8_t cookie[WG_COOKIE_LEN];
    uint8_t mac1_of_trigger[WG_COOKIE_LEN];
    int ret;

    /* Rotate secret if needed */
    if (dev->now - checker->secret_birthdate >
        WG_COOKIE_SECRET_MAX_AGE * 1000ULL) {
        ret = wc_RNG_GenerateBlock(&dev->rng, checker->secret, WG_HASH_LEN);
        if (ret != 0)
            return -1;
        checker->secret_birthdate = dev->now;
    }

    /* Compute cookie = Mac(secret, src_ip || src_port) */
    memcpy(src_data, &src_ip, 4);
    src_data[4] = (uint8_t)(src_port);
    src_data[5] = (uint8_t)(src_port >> 8);

    ret = wg_mac(cookie, checker->secret, WG_HASH_LEN,
                 src_data, sizeof(src_data));
    if (ret != 0)
        return -1;

    /* Get mac1 from triggering message as AAD */
    {
        const uint8_t *trigger_bytes = (const uint8_t *)triggering_msg;
        memcpy(mac1_of_trigger, trigger_bytes + mac_offset, WG_COOKIE_LEN);
    }

    /* Fill reply */
    memset(reply, 0, sizeof(*reply));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    reply->header.type = WG_MSG_COOKIE;
#else
    reply->header.type = ((WG_MSG_COOKIE & 0xFF) << 24) |
                         ((WG_MSG_COOKIE & 0xFF00) << 8) |
                         ((WG_MSG_COOKIE >> 8) & 0xFF00) |
                         ((WG_MSG_COOKIE >> 24) & 0xFF);
#endif
    reply->receiver_index = sender_index; /* Already in wire format */

    /* Generate random nonce */
    ret = wc_RNG_GenerateBlock(&dev->rng, reply->nonce, WG_COOKIE_NONCE_LEN);
    if (ret != 0)
        return -1;

    /* encrypted_cookie = XAEAD(cookie_encryption_key, nonce, cookie, mac1) */
    ret = wg_xaead_encrypt(reply->encrypted_cookie,
                           checker->cookie_encryption_key,
                           reply->nonce,
                           cookie, WG_COOKIE_LEN,
                           mac1_of_trigger, WG_COOKIE_LEN);

    wg_memzero(cookie, sizeof(cookie));
    return ret;
}

/*
 * Consume cookie reply message
 * */

int wg_cookie_consume_reply(struct wg_peer *peer, struct wg_msg_cookie *msg)
{
    uint8_t cookie[WG_COOKIE_LEN];
    int ret;

    if (!peer->cookie.have_sent_mac1)
        return -1;

    /* Decrypt: cookie = XAEAD_decrypt(cookie_decryption_key, nonce,
     *                                 encrypted_cookie, last_mac1_sent) */
    ret = wg_xaead_decrypt(cookie, peer->cookie.cookie_decryption_key,
                           msg->nonce,
                           msg->encrypted_cookie,
                           WG_COOKIE_LEN + WG_AUTHTAG_LEN,
                           peer->cookie.last_mac1_sent, WG_COOKIE_LEN);
    if (ret != 0)
        return -1;

    memcpy(peer->cookie.cookie, cookie, WG_COOKIE_LEN);
    peer->cookie.is_valid = 1;
    peer->cookie.have_sent_mac1 = 0;

    wg_memzero(cookie, sizeof(cookie));
    return 0;
}

#endif /* WOLFGUARD */

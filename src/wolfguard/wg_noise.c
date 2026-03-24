/* wg_noise.c
 *
 * wolfGuard Noise_IKpsk2 handshake implementation
 *
 * Implements the Noise_IKpsk2 pattern with FIPS crypto:
 *   Initiator -> Responder:  e, es, s, ss, {timestamp}
 *   Responder -> Initiator:  e, ee, se, psk, {}
 *
 * Copyright (C) 2026 wolfSSL Inc.
 */

#ifdef WOLFGUARD

#include "wolfguard.h"
#include <string.h>

/* Helper: generate a new sender index.
 * Per spec 5.4.2: "Ii (sender index 4 bytes) is generated randomly (p4)
 * p^n represents a random bitstring of length n bytes.
 * */
static uint32_t wg_new_index(struct wg_device *dev)
{
    uint32_t index = 0;

    /* generate random 32-bit index, reject zero*/
    while (index == 0) {
        if (wc_RNG_GenerateBlock(&dev->rng, (byte*)&index,
                    sizeof(index)) != 0) {
            return 0;
        }
    }

    return index;
}

/* Helper: mix hash */
static int mix_hash(uint8_t *hash, const uint8_t *data, size_t len)
{
    return wg_hash2(hash, hash, WG_HASH_LEN, data, len);
}

/* Helper: LE32 encode/decode */
static uint32_t le32_encode(uint32_t v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return v;
#else
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) |
           ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
#endif
}

static uint32_t le32_decode(uint32_t v)
{
    return le32_encode(v); /* Same operation for swap */
}

/*
 * Initialize handshake state for a peer
 * */

void wg_noise_handshake_init(struct wg_handshake *hs,
                             const uint8_t *local_static_private,
                             const uint8_t *remote_static_public,
                             const uint8_t *preshared_key,
                             WC_RNG *rng)
{
    /* Save PSK before memset — preshared_key may alias hs->preshared_key */
    uint8_t psk_buf[WG_SYMMETRIC_KEY_LEN];
    if (preshared_key != NULL)
        memcpy(psk_buf, preshared_key, WG_SYMMETRIC_KEY_LEN);
    else
        memset(psk_buf, 0, WG_SYMMETRIC_KEY_LEN);

    memset(hs, 0, sizeof(*hs));

    memcpy(hs->remote_static, remote_static_public, WG_PUBLIC_KEY_LEN);
    memcpy(hs->preshared_key, psk_buf, WG_SYMMETRIC_KEY_LEN);
    wg_memzero(psk_buf,sizeof(psk_buf));

    /* Pre-compute static-static DH */
    if (wg_dh(hs->precomputed_static_static, local_static_private,
              remote_static_public, rng) != 0) {
        wg_memzero(hs, sizeof(*hs));
        hs->state = WG_HANDSHAKE_ZEROED;
    }
}

/*
 * Create handshake initiation (initiator side)
 *
 * Noise IK pattern, message 1:
 *   C = Hash(Construction)
 *   H = Hash(C || Identifier)
 *   H = Hash(H || S_r_pub)
 *   (E_i_priv, E_i_pub) = DH-Generate()
 *   C = KDF1(C, E_i_pub)
 *   msg.ephemeral = E_i_pub
 *   H = Hash(H || msg.ephemeral)
 *   (C, k) = KDF2(C, DH(E_i_priv, S_r_pub))
 *   msg.static = AEAD(k, 0, S_i_pub, H)
 *   H = Hash(H || msg.static)
 *   (C, k) = KDF2(C, DH(S_i_priv, S_r_pub))
 *   msg.timestamp = AEAD(k, 0, Timestamp(), H)
 *   H = Hash(H || msg.timestamp)
 * */

int wg_noise_create_initiation(struct wg_device *dev, struct wg_peer *peer,
                               struct wg_msg_initiation *msg)
{
    struct wg_handshake *hs = &peer->handshake;
    uint8_t key[WG_SYMMETRIC_KEY_LEN];
    uint8_t ephemeral_public[WG_PUBLIC_KEY_LEN];
    uint8_t dh_result[WG_SYMMETRIC_KEY_LEN];
    uint8_t timestamp[WG_TIMESTAMP_LEN];
    int ret;

    memset(msg, 0, sizeof(*msg));

    /* C = Hash(Construction) */
    ret = wg_hash(hs->chaining_key,
                  (const uint8_t *)WG_CONSTRUCTION, strlen(WG_CONSTRUCTION));
    if (ret != 0)
        return -1;

    /* H = Hash(C || Identifier) */
    ret = wg_hash2(hs->hash, hs->chaining_key, WG_HASH_LEN,
                   (const uint8_t *)WG_IDENTIFIER, strlen(WG_IDENTIFIER));
    if (ret != 0)
        return -1;

    /* H = Hash(H || S_r_pub) */
    ret = mix_hash(hs->hash, hs->remote_static, WG_PUBLIC_KEY_LEN);
    if (ret != 0)
        return -1;
    /* Generate ephemeral key */
    ret = wg_dh_generate(hs->ephemeral_private, ephemeral_public, &dev->rng);
    if (ret != 0)
        return -1;

    /* C = KDF1(C, E_i_pub) */
    ret = wg_kdf1(hs->chaining_key, hs->chaining_key,
                  ephemeral_public, WG_PUBLIC_KEY_LEN);
    if (ret != 0)
        return -1;
    /* msg.ephemeral = E_i_pub */
    memcpy(msg->ephemeral, ephemeral_public, WG_PUBLIC_KEY_LEN);

    /* H = Hash(H || msg.ephemeral) */
    ret = mix_hash(hs->hash, msg->ephemeral, WG_PUBLIC_KEY_LEN);
    if (ret != 0)
        return -1;
    /* (C, k) = KDF2(C, DH(E_i_priv, S_r_pub)) */
    ret = wg_dh(dh_result, hs->ephemeral_private, hs->remote_static, &dev->rng);
    if (ret != 0)
        goto fail;
    ret = wg_kdf2(hs->chaining_key, key, hs->chaining_key,
                  dh_result, WG_SYMMETRIC_KEY_LEN);
    if (ret != 0)
        goto fail;

    /* msg.static = AEAD(k, 0, S_i_pub, H) */
    ret = wg_aead_encrypt(msg->encrypted_static, key, 0,
                          dev->static_public, WG_PUBLIC_KEY_LEN,
                          hs->hash, WG_HASH_LEN);
    if (ret != 0)
        goto fail;
    /* H = Hash(H || msg.static) */
    ret = mix_hash(hs->hash, msg->encrypted_static,
                   WG_PUBLIC_KEY_LEN + WG_AUTHTAG_LEN);
    if (ret != 0)
        goto fail;
    /* (C, k) = KDF2(C, DH(S_i_priv, S_r_pub)) = KDF2(C, precomputed) */
    ret = wg_kdf2(hs->chaining_key, key, hs->chaining_key,
                  hs->precomputed_static_static, WG_SYMMETRIC_KEY_LEN);
    if (ret != 0)
        goto fail;
    /* msg.timestamp = AEAD(k, 0, Timestamp(), H) */
    wg_timestamp_now(timestamp, dev->now);
    ret = wg_aead_encrypt(msg->encrypted_timestamp, key, 0,
                          timestamp, WG_TIMESTAMP_LEN,
                          hs->hash, WG_HASH_LEN);
    if (ret != 0)
        goto fail;
    /* H = Hash(H || msg.timestamp) */
    ret = mix_hash(hs->hash, msg->encrypted_timestamp,
                   WG_TIMESTAMP_LEN + WG_AUTHTAG_LEN);
    if (ret != 0)
        goto fail;

    /* Fill header */
    msg->header.type = le32_encode(WG_MSG_INITIATION);
    hs->local_index = wg_new_index(dev);
    if (hs->local_index == 0)
        goto fail;
    msg->sender_index = le32_encode(hs->local_index);

    hs->state = WG_HANDSHAKE_CREATED_INITIATION;

    wg_memzero(key, sizeof(key));
    wg_memzero(dh_result, sizeof(dh_result));
    wg_memzero(timestamp, sizeof(timestamp));

    return 0;

fail:
    wg_memzero(key, sizeof(key));
    wg_memzero(dh_result, sizeof(dh_result));
    wg_memzero(timestamp, sizeof(timestamp));
    return -1;
}

/*
 * Consume handshake initiation (responder side)
 *
 * Returns the peer if valid, NULL on failure.
 * */

struct wg_peer *wg_noise_consume_initiation(struct wg_device *dev,
                                            struct wg_msg_initiation *msg)
{
    uint8_t hash[WG_HASH_LEN];
    uint8_t chaining_key[WG_HASH_LEN];
    uint8_t key[WG_SYMMETRIC_KEY_LEN];
    uint8_t dh_result[WG_SYMMETRIC_KEY_LEN];
    uint8_t decrypted_static[WG_PUBLIC_KEY_LEN];
    uint8_t decrypted_timestamp[WG_TIMESTAMP_LEN];
    uint8_t ephemeral_public[WG_PUBLIC_KEY_LEN];
    struct wg_peer *peer = NULL;
    int i, ret;

    /* C = Hash(Construction) */
    ret = wg_hash(chaining_key,
                  (const uint8_t *)WG_CONSTRUCTION, strlen(WG_CONSTRUCTION));
    if (ret != 0)
        return NULL;

    /* H = Hash(C || Identifier) */
    ret = wg_hash2(hash, chaining_key, WG_HASH_LEN,
                   (const uint8_t *)WG_IDENTIFIER, strlen(WG_IDENTIFIER));
    if (ret != 0)
        return NULL;

    /* H = Hash(H || S_r_pub), our public key since we're the responder */
    ret = mix_hash(hash, dev->static_public, WG_PUBLIC_KEY_LEN);
    if (ret != 0)
        return NULL;

    /* Extract ephemeral from message */
    memcpy(ephemeral_public, msg->ephemeral, WG_PUBLIC_KEY_LEN);

    /* C = KDF1(C, E_i_pub) */
    ret = wg_kdf1(chaining_key, chaining_key,
                  ephemeral_public, WG_PUBLIC_KEY_LEN);
    if (ret != 0)
        return NULL;

    /* H = Hash(H || msg.ephemeral) */
    ret = mix_hash(hash, ephemeral_public, WG_PUBLIC_KEY_LEN);
    if (ret != 0)
        return NULL;

    /* (C, k) = KDF2(C, DH(S_r_priv, E_i_pub)) */
    ret = wg_dh(dh_result, dev->static_private, ephemeral_public, &dev->rng);
    if (ret != 0)
        goto done;

    ret = wg_kdf2(chaining_key, key, chaining_key,
                  dh_result, WG_SYMMETRIC_KEY_LEN);
    if (ret != 0)
        goto done;

    /* Decrypt static: S_i_pub = AEAD_decrypt(k, 0, msg.static, H) */
    ret = wg_aead_decrypt(decrypted_static, key, 0,
                          msg->encrypted_static,
                          WG_PUBLIC_KEY_LEN + WG_AUTHTAG_LEN,
                          hash, WG_HASH_LEN);
    if (ret != 0)
        goto done;

    /* H = Hash(H || msg.static) */
    ret = mix_hash(hash, msg->encrypted_static,
                   WG_PUBLIC_KEY_LEN + WG_AUTHTAG_LEN);
    if (ret != 0)
        goto done;

    /* Look up peer by decrypted static public key */
    for (i = 0; i < WOLFGUARD_MAX_PEERS; i++) {
        if (dev->peers[i].is_active &&
            wg_memcmp(dev->peers[i].public_key, decrypted_static,
                             WG_PUBLIC_KEY_LEN) == 0) {
            peer = &dev->peers[i];
            break;
        }
    }
    if (peer == NULL)
        goto done;

    /* Rate-limit, reject initiations within REKEY_TIMEOUT of the last one,
     * per spec Section 5.1 and 6.4: "Under no circumstances will WireGuard
     * send an initiation message more than once every Rekey-Timeout." */
    if (peer->last_initiation_consumption > 0 &&
            (dev->now - peer->last_initiation_consumption) <
            (uint64_t)WG_REKEY_TIMEOUT * 1000ULL) {
        peer = NULL;
        goto done;
    }

    /* (C, k) = KDF2(C, DH(S_r_priv, S_i_pub)) = KDF2(C, precomputed) */
    ret = wg_kdf2(chaining_key, key, chaining_key,
                  peer->handshake.precomputed_static_static,
                  WG_SYMMETRIC_KEY_LEN);
    if (ret != 0) {
        peer = NULL;
        goto done;
    }

    /* Decrypt timestamp: ts = AEAD_decrypt(k, 0, msg.timestamp, H) */
    ret = wg_aead_decrypt(decrypted_timestamp, key, 0,
                          msg->encrypted_timestamp,
                          WG_TIMESTAMP_LEN + WG_AUTHTAG_LEN,
                          hash, WG_HASH_LEN);
    if (ret != 0) {
        peer = NULL;
        goto done;
    }

    /* H = Hash(H || msg.timestamp) */
    ret = mix_hash(hash, msg->encrypted_timestamp,
                   WG_TIMESTAMP_LEN + WG_AUTHTAG_LEN);
    if (ret != 0) {
        peer = NULL;
        goto done;
    }

    /*
     * Replay protection: timestamp must be strictly newer than last seen.
     * */
    if (memcmp(decrypted_timestamp, peer->latest_timestamp,
                WG_TIMESTAMP_LEN) <= 0) {
        peer = NULL;
        goto done;
    }

    /* Save state into peer's handshake */
    memcpy(peer->handshake.hash, hash, WG_HASH_LEN);
    memcpy(peer->handshake.chaining_key, chaining_key, WG_HASH_LEN);
    memcpy(peer->handshake.remote_ephemeral, ephemeral_public,
           WG_PUBLIC_KEY_LEN);
    memcpy(peer->latest_timestamp, decrypted_timestamp,
           WG_TIMESTAMP_LEN);
    peer->handshake.remote_index = le32_decode(msg->sender_index);
    peer->handshake.state = WG_HANDSHAKE_CONSUMED_INITIATION;
    peer->last_initiation_consumption = dev->now;

done:
    wg_memzero(key, sizeof(key));
    wg_memzero(dh_result, sizeof(dh_result));
    wg_memzero(chaining_key, sizeof(chaining_key));
    wg_memzero(hash, sizeof(hash));
    wg_memzero(decrypted_static, sizeof(decrypted_static));
    wg_memzero(decrypted_timestamp, sizeof(decrypted_timestamp));
    return peer;
}

/*
 * Create handshake response (responder side)
 *
 * Noise IK pattern, message 2:
 *   (E_r_priv, E_r_pub) = DH-Generate()
 *   C = KDF1(C, E_r_pub)
 *   msg.ephemeral = E_r_pub
 *   H = Hash(H || msg.ephemeral)
 *   (C) = KDF1(C, DH(E_r_priv, E_i_pub))
 *   (C) = KDF1(C, DH(E_r_priv, S_i_pub))
 *   (C, tau, k) = KDF3(C, psk)
 *   H = Hash(H || tau)
 *   msg.empty = AEAD(k, 0, empty, H)
 *   H = Hash(H || msg.empty)
 * */

int wg_noise_create_response(struct wg_device *dev, struct wg_peer *peer,
                             struct wg_msg_response *msg)
{
    struct wg_handshake *hs = &peer->handshake;
    uint8_t key[WG_SYMMETRIC_KEY_LEN];
    uint8_t tau[WG_HASH_LEN];
    uint8_t dh_result[WG_SYMMETRIC_KEY_LEN];
    uint8_t ephemeral_public[WG_PUBLIC_KEY_LEN];
    int ret;

    if (hs->state != WG_HANDSHAKE_CONSUMED_INITIATION)
        return -1;

    memset(msg, 0, sizeof(*msg));

    /* Generate ephemeral key */
    ret = wg_dh_generate(hs->ephemeral_private, ephemeral_public, &dev->rng);
    if (ret != 0)
        return -1;

    /* C = KDF1(C, E_r_pub) */
    ret = wg_kdf1(hs->chaining_key, hs->chaining_key,
                  ephemeral_public, WG_PUBLIC_KEY_LEN);
    if (ret != 0)
        goto fail;

    /* msg.ephemeral = E_r_pub */
    memcpy(msg->ephemeral, ephemeral_public, WG_PUBLIC_KEY_LEN);

    /* H = Hash(H || msg.ephemeral) */
    ret = mix_hash(hs->hash, msg->ephemeral, WG_PUBLIC_KEY_LEN);
    if (ret != 0)
        goto fail;

    /* C = KDF1(C, DH(E_r_priv, E_i_pub)) */
    ret = wg_dh(dh_result, hs->ephemeral_private, hs->remote_ephemeral, &dev->rng);
    if (ret != 0)
        goto fail;

    ret = wg_kdf1(hs->chaining_key, hs->chaining_key,
                  dh_result, WG_SYMMETRIC_KEY_LEN);
    if (ret != 0)
        goto fail;

    /* C = KDF1(C, DH(E_r_priv, S_i_pub)) */
    ret = wg_dh(dh_result, hs->ephemeral_private, hs->remote_static, &dev->rng);
    if (ret != 0)
        goto fail;

    ret = wg_kdf1(hs->chaining_key, hs->chaining_key,
                  dh_result, WG_SYMMETRIC_KEY_LEN);
    if (ret != 0)
        goto fail;

    /* (C, tau, k) = KDF3(C, psk) */
    ret = wg_kdf3(hs->chaining_key, tau, key, hs->chaining_key,
                  hs->preshared_key, WG_SYMMETRIC_KEY_LEN);
    if (ret != 0)
        goto fail;

    /* H = Hash(H || tau) */
    ret = mix_hash(hs->hash, tau, WG_HASH_LEN);
    if (ret != 0)
        goto fail;

    /* msg.empty = AEAD(k, 0, empty, H) */
    ret = wg_aead_encrypt(msg->encrypted_nothing, key, 0,
                          NULL, 0, hs->hash, WG_HASH_LEN);
    if (ret != 0)
        goto fail;

    /* H = Hash(H || msg.empty) */
    ret = mix_hash(hs->hash, msg->encrypted_nothing, WG_AUTHTAG_LEN);
    if (ret != 0)
        goto fail;

    /* Fill header */
    msg->header.type = le32_encode(WG_MSG_RESPONSE);
    hs->local_index = wg_new_index(dev);
    if (hs->local_index == 0)
        goto fail;
    msg->sender_index = le32_encode(hs->local_index);
    msg->receiver_index = le32_encode(hs->remote_index);

    hs->state = WG_HANDSHAKE_CREATED_RESPONSE;

    wg_memzero(key, sizeof(key));
    wg_memzero(tau, sizeof(tau));
    wg_memzero(dh_result, sizeof(dh_result));
    return 0;

fail:
    wg_memzero(key, sizeof(key));
    wg_memzero(tau, sizeof(tau));
    wg_memzero(dh_result, sizeof(dh_result));
    return -1;
}

/*
 * Consume handshake response (initiator side)
 * */

int wg_noise_consume_response(struct wg_device *dev, struct wg_peer *peer,
                              struct wg_msg_response *msg)
{
    struct wg_handshake *hs = &peer->handshake;
    uint8_t key[WG_SYMMETRIC_KEY_LEN];
    uint8_t tau[WG_HASH_LEN];
    uint8_t dh_result[WG_SYMMETRIC_KEY_LEN];
    uint8_t ephemeral_public[WG_PUBLIC_KEY_LEN];
    int ret;

    if (hs->state != WG_HANDSHAKE_CREATED_INITIATION)
        return -1;

    memcpy(ephemeral_public, msg->ephemeral, WG_PUBLIC_KEY_LEN);

    /* C = KDF1(C, E_r_pub) */
    ret = wg_kdf1(hs->chaining_key, hs->chaining_key,
                  ephemeral_public, WG_PUBLIC_KEY_LEN);
    if (ret != 0)
        return -1;

    /* H = Hash(H || msg.ephemeral) */
    ret = mix_hash(hs->hash, ephemeral_public, WG_PUBLIC_KEY_LEN);
    if (ret != 0)
        return -1;

    /* C = KDF1(C, DH(E_i_priv, E_r_pub)) */
    ret = wg_dh(dh_result, hs->ephemeral_private, ephemeral_public, &dev->rng);
    if (ret != 0)
        goto fail;

    ret = wg_kdf1(hs->chaining_key, hs->chaining_key,
                  dh_result, WG_SYMMETRIC_KEY_LEN);
    if (ret != 0)
        goto fail;

    /* C = KDF1(C, DH(S_i_priv, E_r_pub)), use our static private */
    ret = wg_dh(dh_result, dev->static_private, ephemeral_public, &dev->rng);
    if (ret != 0)
        goto fail;

    ret = wg_kdf1(hs->chaining_key, hs->chaining_key,
                  dh_result, WG_SYMMETRIC_KEY_LEN);
    if (ret != 0)
        goto fail;

    /* (C, tau, k) = KDF3(C, psk) */
    ret = wg_kdf3(hs->chaining_key, tau, key, hs->chaining_key,
                  hs->preshared_key, WG_SYMMETRIC_KEY_LEN);
    if (ret != 0)
        goto fail;

    /* H = Hash(H || tau) */
    ret = mix_hash(hs->hash, tau, WG_HASH_LEN);
    if (ret != 0)
        goto fail;

    /* Decrypt empty: AEAD_decrypt(k, 0, msg.empty, H) */
    {
        uint8_t nothing[1]; /* Dummy buffer for zero-length decrypt */
        ret = wg_aead_decrypt(nothing, key, 0,
                              msg->encrypted_nothing, WG_AUTHTAG_LEN,
                              hs->hash, WG_HASH_LEN);
    }
    if (ret != 0)
        goto fail;

    /* H = Hash(H || msg.empty) */
    ret = mix_hash(hs->hash, msg->encrypted_nothing, WG_AUTHTAG_LEN);
    if (ret != 0)
        goto fail;

    hs->remote_index = le32_decode(msg->sender_index);
    hs->state = WG_HANDSHAKE_CONSUMED_RESPONSE;

    wg_memzero(key, sizeof(key));
    wg_memzero(tau, sizeof(tau));
    wg_memzero(dh_result, sizeof(dh_result));
    return 0;

fail:
    wg_memzero(key, sizeof(key));
    wg_memzero(tau, sizeof(tau));
    wg_memzero(dh_result, sizeof(dh_result));
    return -1;
}

/*
 * Derive transport data keys after handshake
 *
 * (T_send, T_recv) = KDF2(C, empty)
 * Initiator: send=T1, recv=T2
 * Responder: send=T2, recv=T1
 * */

int wg_noise_begin_session(struct wg_device *dev, struct wg_peer *peer)
{
    struct wg_handshake *hs = &peer->handshake;
    struct wg_keypairs *kps = &peer->keypairs;
    struct wg_keypair *new_kp;
    uint8_t t1[WG_SYMMETRIC_KEY_LEN], t2[WG_SYMMETRIC_KEY_LEN];
    int ret;
    int is_initiator;

    if (hs->state != WG_HANDSHAKE_CONSUMED_RESPONSE &&
        hs->state != WG_HANDSHAKE_CREATED_RESPONSE)
        return -1;

    is_initiator = (hs->state == WG_HANDSHAKE_CONSUMED_RESPONSE);

    /* (T1, T2) = KDF2(C, empty) */
    ret = wg_kdf2(t1, t2, hs->chaining_key, NULL, 0);
    if (ret != 0) {
        wg_memzero(t1, sizeof(t1));
        wg_memzero(t2, sizeof(t2));
        return -1;
    }

    /* Rotate keypairs: previous = current, current = new */
    if (kps->next != NULL) {
        /* Discard unconfirmed next */
        wg_memzero(kps->next, sizeof(struct wg_keypair));
        kps->next = NULL;
    }

    /* Find a free slot */
    {
        int slot = -1;
        int i;
        for (i = 0; i < 3; i++) {
            if (&kps->keypair_slots[i] != kps->current &&
                &kps->keypair_slots[i] != kps->previous) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            /* Use previous slot */
            if (kps->previous != NULL) {
                slot = (int)(kps->previous - kps->keypair_slots);
                wg_memzero(kps->previous, sizeof(struct wg_keypair));
                kps->previous = NULL;
            } else {
                slot = 0;
            }
        }
        new_kp = &kps->keypair_slots[slot];
    }

    memset(new_kp, 0, sizeof(*new_kp));

    if (is_initiator) {
        memcpy(new_kp->sending.key, t1, WG_SYMMETRIC_KEY_LEN);
        memcpy(new_kp->receiving.key, t2, WG_SYMMETRIC_KEY_LEN);
    } else {
        memcpy(new_kp->sending.key, t2, WG_SYMMETRIC_KEY_LEN);
        memcpy(new_kp->receiving.key, t1, WG_SYMMETRIC_KEY_LEN);
    }

    new_kp->sending.birthdate = dev->now;
    new_kp->receiving.birthdate = dev->now;
    new_kp->sending.is_valid = 1;
    new_kp->receiving.is_valid = 1;
    new_kp->sending_counter = 0;
    new_kp->receiving_counter_max = 0;
    memset(new_kp->receiving_counter_bitmap, 0,
           sizeof(new_kp->receiving_counter_bitmap));
    new_kp->i_am_initiator = (uint8_t)is_initiator;
    new_kp->remote_index = hs->remote_index;
    new_kp->local_index = hs->local_index;
    new_kp->internal_id = ++dev->keypair_counter;

    if (is_initiator) {
        /* Initiator: new session is immediately current */
        kps->previous = kps->current;
        kps->current = new_kp;
    } else {
        /* Responder: new session is "next" until confirmed by data */
        kps->next = new_kp;
    }

    /* Clear handshake state */
    wg_memzero(hs->ephemeral_private, WG_PRIVATE_KEY_LEN);
    wg_memzero(hs->chaining_key, WG_HASH_LEN);
    wg_memzero(hs->hash, WG_HASH_LEN);
    hs->state = WG_HANDSHAKE_ZEROED;

    wg_memzero(t1, sizeof(t1));
    wg_memzero(t2, sizeof(t2));
    return 0;
}

#endif /* WOLFGUARD */

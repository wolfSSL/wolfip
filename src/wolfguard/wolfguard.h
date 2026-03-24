/* wolfguard.h
 *
 * wolfGuard, FIPS-compliant WireGuard implementation for wolfIP
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP.
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
 * along with wolfIP.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef WOLFGUARD_H
#define WOLFGUARD_H

#ifdef WOLFGUARD

#include <stdint.h>
#include <stddef.h>
#include <wolfssl/options.h>
#include "config.h"
#include "wolfip.h"

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/memory.h>

#ifndef WOLFGUARD_MAX_PEERS
#define WOLFGUARD_MAX_PEERS         8
#endif

#ifndef WOLFGUARD_MAX_ALLOWED_IPS
#define WOLFGUARD_MAX_ALLOWED_IPS   32
#endif

#ifndef WOLFGUARD_STAGED_PACKETS
#define WOLFGUARD_STAGED_PACKETS    16
#endif

#ifndef WOLFGUARD_COUNTER_WINDOW
#define WOLFGUARD_COUNTER_WINDOW    1024
#endif

/* Constants (FIPS: P-256 + AES-256-GCM + SHA-256) */

#define WG_PUBLIC_KEY_LEN       65   /* Uncompressed SECP256R1 (P-256) point */
#define WG_PRIVATE_KEY_LEN      32
#define WG_SYMMETRIC_KEY_LEN    32   /* AES-256 */
#define WG_AUTHTAG_LEN          16   /* AES-GCM tag */
#define WG_HASH_LEN             32   /* SHA-256 */
#define WG_COOKIE_NONCE_LEN     16   /* AES-GCM IV (replaces XChaCha20 24B nonce) */

#define WG_TIMESTAMP_LEN        12   /* TAI64N */
#define WG_COOKIE_LEN           32   /* SHA-256 HMAC output */
#define WG_HEADER_LEN           16   /* type(4) + receiver(4) + counter(8) */
#define WG_AEAD_NONCE_LEN       16   /* AES-GCM IV */

/* Message Types */

#define WG_MSG_INITIATION       1 /* starts the handshake process */
#define WG_MSG_RESPONSE         2 /* response to the initiation process,
                                     concludes the handshake */
#define WG_MSG_COOKIE           3 /*  encrypted cookie value for
                                      use in resending either the rejected
                                      handshake initiation message or
                                      handshake response message */
#define WG_MSG_DATA             4 /* An encapsulated and encrypted IP
                                     packet that uses the secure session
                                     negotiated by the handshake.*/

/* Timer Constants (seconds) */

#define WG_REKEY_AFTER_MESSAGES     (1ULL << 60)
/*
 * small note: the purpose of this constant is to stop sending
 * before the 64 bit counter wraps around, so that there is enough space
 * for the replay window.
 * from the whitepaper they use 2^13 = 8192 as the window size
 * for the linux kernel implementation.
 *
 * We push it down to 2^10, so smaller to make it more suitable for embedded devices.
 * */
#define WG_REJECT_AFTER_MESSAGES    (UINT64_MAX - WOLFGUARD_COUNTER_WINDOW - 1)
#define WG_REKEY_AFTER_TIME         120
#define WG_REJECT_AFTER_TIME        180
#define WG_REKEY_ATTEMPT_TIME       90
#define WG_REKEY_TIMEOUT            5
#define WG_KEEPALIVE_TIMEOUT        10
#define WG_MAX_HANDSHAKE_ATTEMPTS   18
#define WG_COOKIE_SECRET_MAX_AGE    120  /* seconds */

/* Construction and Identifier strings (FIPS) */

#define WG_CONSTRUCTION     "Noise_IKpsk2_SECP256R1_AesGcm_SHA256"
#define WG_IDENTIFIER       "WolfGuard v1 info@wolfssl.com"
#define WG_LABEL_MAC1       "mac1----"
#define WG_LABEL_COOKIE     "cookie--"

/* Wire Message Structures (packed, little-endian) */

struct __attribute__((packed)) wg_msg_header {
    uint32_t type;          /* LE: type in low byte, 3 reserved zero bytes */
};

struct __attribute__((packed)) wg_msg_macs {
    uint8_t mac1[WG_COOKIE_LEN];
    uint8_t mac2[WG_COOKIE_LEN];
};

struct __attribute__((packed)) wg_msg_initiation {
    struct wg_msg_header header;
    uint32_t sender_index;
    uint8_t ephemeral[WG_PUBLIC_KEY_LEN];
    uint8_t encrypted_static[WG_PUBLIC_KEY_LEN + WG_AUTHTAG_LEN];
    uint8_t encrypted_timestamp[WG_TIMESTAMP_LEN + WG_AUTHTAG_LEN];
    struct wg_msg_macs macs;
};

struct __attribute__((packed)) wg_msg_response {
    struct wg_msg_header header;
    uint32_t sender_index;
    uint32_t receiver_index;
    uint8_t ephemeral[WG_PUBLIC_KEY_LEN];
    uint8_t encrypted_nothing[WG_AUTHTAG_LEN];
    struct wg_msg_macs macs;
};

struct __attribute__((packed)) wg_msg_cookie {
    struct wg_msg_header header;
    uint32_t receiver_index;
    uint8_t nonce[WG_COOKIE_NONCE_LEN];
    uint8_t encrypted_cookie[WG_COOKIE_LEN + WG_AUTHTAG_LEN];
};

struct __attribute__((packed)) wg_msg_data {
    struct wg_msg_header header;
    uint32_t receiver_index;
    uint64_t counter;
    uint8_t encrypted_data[];  /* Variable: plaintext + 16B tag */
};

/* Noise Handshake */

enum wg_handshake_state {
    WG_HANDSHAKE_ZEROED = 0,
    WG_HANDSHAKE_CREATED_INITIATION,
    WG_HANDSHAKE_CONSUMED_INITIATION,
    WG_HANDSHAKE_CREATED_RESPONSE,
    WG_HANDSHAKE_CONSUMED_RESPONSE
};

struct wg_handshake {
    enum wg_handshake_state state;
    uint8_t ephemeral_private[WG_PRIVATE_KEY_LEN];
    uint8_t remote_static[WG_PUBLIC_KEY_LEN];
    uint8_t remote_ephemeral[WG_PUBLIC_KEY_LEN];
    uint8_t precomputed_static_static[WG_SYMMETRIC_KEY_LEN];
    uint8_t preshared_key[WG_SYMMETRIC_KEY_LEN];
    uint8_t hash[WG_HASH_LEN];
    uint8_t chaining_key[WG_HASH_LEN];
    uint32_t remote_index;
    uint32_t local_index;           /* Our sender_index from the handshake message */
};

/* Symmetric Session Keys */

struct wg_symmetric_key {
    uint8_t key[WG_SYMMETRIC_KEY_LEN];
    uint64_t birthdate;     /* wolfIP_poll() time when created */
    uint8_t is_valid;
};

struct wg_keypair {
    struct wg_symmetric_key sending;
    struct wg_symmetric_key receiving;
    uint64_t sending_counter;
    uint64_t receiving_counter_max;
    uint32_t receiving_counter_bitmap[WOLFGUARD_COUNTER_WINDOW / 32];
    uint32_t local_index;
    uint32_t remote_index;
    uint8_t i_am_initiator;
    uint64_t internal_id;
};

struct wg_keypairs {
    struct wg_keypair *current;
    struct wg_keypair *previous;
    struct wg_keypair *next;        /* Unconfirmed session for responder */
    /* Static storage — no dynamic alloc */
    struct wg_keypair keypair_slots[3];
};

/* Cookie State */

struct wg_cookie {
    uint64_t birthdate;
    uint8_t is_valid;
    uint8_t cookie[WG_COOKIE_LEN];
    uint8_t last_mac1_sent[WG_COOKIE_LEN];
    uint8_t have_sent_mac1;
    /* Pre-computed keys */
    uint8_t cookie_decryption_key[WG_SYMMETRIC_KEY_LEN];
    uint8_t message_mac1_key[WG_SYMMETRIC_KEY_LEN];
};

struct wg_cookie_checker {
    uint8_t secret[WG_HASH_LEN];
    uint64_t secret_birthdate;
    uint8_t cookie_encryption_key[WG_SYMMETRIC_KEY_LEN];
    uint8_t message_mac1_key[WG_SYMMETRIC_KEY_LEN];
};

/* Allowed IPs (flat table with longest prefix match) */

struct wg_allowed_ip {
    uint32_t ip;            /* Network byte order */
    uint8_t cidr;           /* Prefix length 0-32 */
    uint8_t peer_idx;       /* Index into device peer array */
    uint8_t in_use;
};

/* Peer */

struct wg_peer {
    uint8_t public_key[WG_PUBLIC_KEY_LEN];
    struct wg_handshake handshake;
    struct wg_keypairs keypairs;
    struct wg_cookie cookie;

    /* persistent replay protection, survies handshake re-init */
    uint8_t latest_timestamp[WG_TIMESTAMP_LEN];

    /* rate-limit initiation processing */
    uint64_t last_initiation_consumption;

    /* Endpoint: where to send UDP packets to this peer */
    uint32_t endpoint_ip;       /* Network byte order */
    uint16_t endpoint_port;     /* Network byte order */

    /* Staged packets: queued while handshake is in progress */
    uint8_t staged_packets[WOLFGUARD_STAGED_PACKETS][LINK_MTU];
    uint16_t staged_packet_lens[WOLFGUARD_STAGED_PACKETS];
    uint8_t staged_count;

    /* Timers (stored as absolute wolfIP_poll time in ms) */
    uint64_t timer_handshake_initiated;
    uint64_t timer_last_data_sent;
    uint64_t timer_last_data_received;
    uint64_t timer_last_keepalive_sent;
    uint64_t timer_last_handshake_completed;
    uint16_t rekey_jitter_ms;   /* random jitter for timer-driven initiations */
    uint8_t  handshake_attempts;
    uint16_t persistent_keepalive_interval;

    /* Stats */
    uint64_t rx_bytes;
    uint64_t tx_bytes;

    uint8_t is_active;
};

/* Device */

struct wg_device {
    /* Identity */
    uint8_t static_private[WG_PRIVATE_KEY_LEN];
    uint8_t static_public[WG_PUBLIC_KEY_LEN];

    /* Peers */
    struct wg_peer peers[WOLFGUARD_MAX_PEERS];
    uint8_t num_peers;

    /* Allowed IPs table */
    struct wg_allowed_ip allowed_ips[WOLFGUARD_MAX_ALLOWED_IPS];

    /* Cookie checker (for DoS protection as responder) */
    struct wg_cookie_checker cookie_checker;
    uint8_t under_load;
    uint16_t handshakes_per_cycle;

    /* wolfIP integration */
    struct wolfIP *stack;
    unsigned int wg_if_idx;     /* Index of the wg0 interface */
    int udp_sock_fd;            /* wolfIP UDP socket for outer transport */
    uint16_t listen_port;       /* UDP port */

    /* RNG */
    WC_RNG rng;

    /* Timers */
    uint64_t now;               /* Updated each poll cycle */

    /* Internal keypair ID counter */
    uint64_t keypair_counter;
};

/*
 * Public API, implemented in wolfguard.c
 * */

int wolfguard_init(struct wg_device *dev, struct wolfIP *stack,
                   unsigned int wg_if_idx, uint16_t listen_port);
int wolfguard_set_private_key(struct wg_device *dev,
                              const uint8_t *private_key);
int wolfguard_add_peer(struct wg_device *dev,
                       const uint8_t *public_key,
                       const uint8_t *preshared_key,
                       uint32_t endpoint_ip, uint16_t endpoint_port,
                       uint16_t persistent_keepalive);
int wolfguard_add_allowed_ip(struct wg_device *dev, int peer_idx,
                             uint32_t ip, uint8_t cidr);
void wolfguard_poll(struct wg_device *dev, uint64_t now_ms);
int wolfguard_output(struct wg_device *dev, const uint8_t *packet, size_t len);
void wolfguard_destroy(struct wg_device *dev);

/*
 * Crypto primitives, implemented in wg_crypto.c
 * */

int wg_dh_generate(uint8_t *private_key, uint8_t *public_key, WC_RNG *rng);
int wg_dh(uint8_t *shared_out, const uint8_t *private_key,
           const uint8_t *public_key, WC_RNG *rng);
int wg_pubkey_from_private(uint8_t *public_key, const uint8_t *private_key);

int wg_aead_encrypt(uint8_t *dst, const uint8_t *key, uint64_t counter,
                    const uint8_t *plaintext, size_t plaintext_len,
                    const uint8_t *aad, size_t aad_len);
int wg_aead_decrypt(uint8_t *dst, const uint8_t *key, uint64_t counter,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    const uint8_t *aad, size_t aad_len);

int wg_xaead_encrypt(uint8_t *dst, const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *aad, size_t aad_len);
int wg_xaead_decrypt(uint8_t *dst, const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *ciphertext, size_t ciphertext_len,
                     const uint8_t *aad, size_t aad_len);

int wg_hash(uint8_t *out, const uint8_t *input, size_t len);
int wg_hash2(uint8_t *out, const uint8_t *a, size_t a_len,
             const uint8_t *b, size_t b_len);

int wg_mac(uint8_t *out, const uint8_t *key, size_t key_len,
           const uint8_t *input, size_t input_len);

int wg_hmac(uint8_t *out, const uint8_t *key, size_t key_len,
            const uint8_t *input, size_t input_len);

int wg_kdf1(uint8_t *t1, const uint8_t *key, const uint8_t *input,
            size_t input_len);
int wg_kdf2(uint8_t *t1, uint8_t *t2, const uint8_t *key,
            const uint8_t *input, size_t input_len);
int wg_kdf3(uint8_t *t1, uint8_t *t2, uint8_t *t3, const uint8_t *key,
            const uint8_t *input, size_t input_len);

void wg_timestamp_now(uint8_t *out, uint64_t now_ms);

int wg_memcmp(const uint8_t *a, const uint8_t *b, size_t len);
void wg_memzero(void *ptr, size_t len);

/*
 * Noise IK handshake, implemented in wg_noise.c
 * */

void wg_noise_handshake_init(struct wg_handshake *hs,
                             const uint8_t *local_static_private,
                             const uint8_t *remote_static_public,
                             const uint8_t *preshared_key,
                             WC_RNG *rng);

int wg_noise_create_initiation(struct wg_device *dev, struct wg_peer *peer,
                               struct wg_msg_initiation *msg);

struct wg_peer *wg_noise_consume_initiation(struct wg_device *dev,
                                            struct wg_msg_initiation *msg);

int wg_noise_create_response(struct wg_device *dev, struct wg_peer *peer,
                             struct wg_msg_response *msg);

int wg_noise_consume_response(struct wg_device *dev, struct wg_peer *peer,
                              struct wg_msg_response *msg);

int wg_noise_begin_session(struct wg_device *dev, struct wg_peer *peer);

/*
 * Cookie / DoS protection, implemented in wg_cookie.c
 * */

enum wg_cookie_mac_state {
    WG_COOKIE_MAC_INVALID = 0,
    WG_COOKIE_MAC_VALID,
    WG_COOKIE_MAC_VALID_WITH_COOKIE
};

void wg_cookie_checker_init(struct wg_cookie_checker *checker,
                            const uint8_t *device_public_key);

void wg_cookie_init(struct wg_cookie *cookie,
                    const uint8_t *peer_public_key);

int wg_cookie_add_macs(struct wg_peer *peer, void *msg, size_t msg_len,
                       size_t mac_offset);

enum wg_cookie_mac_state wg_cookie_validate(
    struct wg_cookie_checker *checker, void *msg, size_t msg_len,
    size_t mac_offset, uint32_t src_ip, uint16_t src_port, uint64_t now);

int wg_cookie_create_reply(struct wg_device *dev, struct wg_msg_cookie *reply,
                           const void *triggering_msg, size_t mac_offset,
                           uint32_t sender_index,
                           uint32_t src_ip, uint16_t src_port);

int wg_cookie_consume_reply(struct wg_peer *peer, struct wg_msg_cookie *msg);

/*
 * Allowed IPs, implemented in wg_allowedips.c
 * */

int wg_allowedips_insert(struct wg_device *dev, uint32_t ip, uint8_t cidr,
                         uint8_t peer_idx);
int wg_allowedips_lookup(struct wg_device *dev, uint32_t ip);
void wg_allowedips_remove_by_peer(struct wg_device *dev, uint8_t peer_idx);

/*
 * Packet processing, implemented in wg_packet.c
 * */

int wg_packet_send(struct wg_device *dev, struct wg_peer *peer,
                   const uint8_t *plaintext, size_t len);

void wg_packet_receive(struct wg_device *dev, const uint8_t *data, size_t len,
                       uint32_t src_ip, uint16_t src_port);

void wg_packet_send_staged(struct wg_device *dev, struct wg_peer *peer);

int wg_packet_send_keepalive(struct wg_device *dev, struct wg_peer *peer);

int wg_counter_validate(struct wg_keypair *kp, uint64_t counter);

/*
 * Timer state machine, implemented in wg_timers.c
 * */

void wg_timers_tick(struct wg_device *dev, uint64_t now_ms);
void wg_timers_data_sent(struct wg_peer *peer, uint64_t now);
void wg_timers_data_received(struct wg_peer *peer, uint64_t now);
void wg_timers_handshake_initiated(struct wg_peer *peer, uint64_t now);
void wg_timers_handshake_complete(struct wg_peer *peer, uint64_t now);

#endif /* WOLFGUARD */
#endif /* WOLFGUARD_H */

/* unit_esp.c
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

#ifndef WOLFIP_ESP
#define WOLFIP_ESP
#endif
#ifndef WOLFSSL_WOLFIP
#define WOLFSSL_WOLFIP
#endif
#undef  WOLFIP_MAX_INTERFACES
#define WOLFIP_MAX_INTERFACES 1
#undef  WOLFIP_ENABLE_LOOPBACK

#include "check.h"
#include "../../../config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../wolfip.c"

uint32_t wolfIP_getrandom(void)
{
    return (uint32_t)random();
}

/* Test key material */
/* AES-128 encryption key (16 bytes). */
static uint8_t k_aes128[16] = {
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
};

/* AES-256 encryption key (32 bytes). */
static uint8_t k_aes256[32] = {
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB
};

/* AES-256 key + 4-byte GCM salt (36 bytes total). */
static uint8_t k_aes256_gcm[36] = {
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xDE, 0xAD, 0xBE, 0xEF   /* 4-byte salt */
};

/* HMAC authentication key (16 bytes). */
static uint8_t k_auth16[16] = {
    0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
    0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD
};

/* Oversized auth key (one byte over ESP_MAX_KEY_LEN=32, triggers -1). */
static uint8_t k_auth_too_big[33] = { 0 };

/* A fixed SPI used for round-trip tests (in and out SAs share it so
 * the SPI embedded in the wrapped packet matches the inbound SA lookup). */
static uint8_t spi_rt[4]  = { 0xAB, 0xCD, 0xEF, 0x01 };

/* Additional SPIs for SA-pool tests. */
static uint8_t spi_a[4]   = { 0x11, 0x22, 0x33, 0x44 };
static uint8_t spi_b[4]   = { 0x55, 0x66, 0x77, 0x88 };
static uint8_t spi_c[4]   = { 0x99, 0xAA, 0xBB, 0xCC };
static uint8_t spi_d[4]   = { 0xFF, 0xEE, 0xDD, 0xCC }; /* overflows pool */

/* Test IP addresses. */
#define T_SRC  "192.168.1.1"
#define T_DST  "192.168.1.2"

/*
 * builds a minimal IPv4 packet (with Ethernet frame header).
 */
static uint32_t build_ip_packet(uint8_t *buf, size_t buf_size,
                                uint8_t proto,
                                const uint8_t *payload, uint16_t plen)
{
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    uint16_t ip_len   = (uint16_t)(IP_HEADER_LEN + plen);
    uint32_t frame_len = ETH_HEADER_LEN + ip_len;

    ck_assert_uint_le(frame_len + 128U, buf_size);
    memset(buf, 0, frame_len + 128U);

    /* Ethernet header: set EtherType = IPv4. */
    ip->eth.type = ee16(0x0800U);

    /* IPv4 header. */
    ip->ver_ihl   = 0x45U;
    ip->tos       = 0U;
    ip->len       = ee16(ip_len);
    ip->id        = 0U;
    ip->flags_fo  = 0U;
    ip->ttl       = 64U;
    ip->proto     = proto;
    ip->csum      = 0U;
    /* ip->src / ip->dst are in network byte order in the raw packet.
     * atoip4() returns a "logical" host-byte-order value; ee32() converts
     * it to the wire representation. */
    ip->src       = ee32(atoip4(T_SRC));
    ip->dst       = ee32(atoip4(T_DST));
    iphdr_set_checksum(ip);

    if (payload != NULL && plen > 0U) {
        memcpy(ip->data, payload, plen);
    }

    return frame_len;
}

static void esp_setup(void)
{
    int ret = wolfIP_esp_init();
    ck_assert_int_eq(ret, 0);
}

/* Creating a CBC+HMAC SA with valid params must succeed. */
START_TEST(test_sa_cbc_hmac_good)
{
    int ret;
    esp_setup();
    ret = wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_a,
                                     atoip4(T_SRC), atoip4(T_DST),
                                     (uint8_t *)k_aes128, sizeof(k_aes128),
                                     ESP_AUTH_SHA256_RFC4868,
                                     (uint8_t *)k_auth16, sizeof(k_auth16),
                                     ESP_ICVLEN_HMAC_128);
    ck_assert_int_eq(ret, 0);
}
END_TEST

/* AES key length not in {16, 24, 32} must be rejected. */
START_TEST(test_sa_cbc_bad_enc_key_len)
{
    int ret;
    esp_setup();
    ret = wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_a,
                                     atoip4(T_SRC), atoip4(T_DST),
                                     (uint8_t *)k_aes128, 15U, /* invalid */
                                     ESP_AUTH_SHA256_RFC4868,
                                     (uint8_t *)k_auth16, sizeof(k_auth16),
                                     ESP_ICVLEN_HMAC_128);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* auth_key_len > ESP_MAX_KEY_LEN (32) must be rejected. */
START_TEST(test_sa_cbc_bad_auth_key_len)
{
    int ret;
    esp_setup();
    ret = wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_a,
                                     atoip4(T_SRC), atoip4(T_DST),
                                     (uint8_t *)k_aes128, sizeof(k_aes128),
                                     ESP_AUTH_SHA256_RFC4868,
                                     (uint8_t *)k_auth_too_big,
                                     sizeof(k_auth_too_big), /* 33 > 32 */
                                     ESP_ICVLEN_HMAC_128);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* GCM SA creation with a valid key+salt length must succeed. */
START_TEST(test_sa_gcm_good)
{
    int ret;
    esp_setup();
    ret = wolfIP_esp_sa_new_gcm(1, (uint8_t *)spi_a,
                                atoip4(T_SRC), atoip4(T_DST),
                                ESP_ENC_GCM_RFC4543,
                                (uint8_t *)k_aes256_gcm,
                                sizeof(k_aes256_gcm));
    ck_assert_int_eq(ret, 0);
}
END_TEST

/* GCM SA with a key length that is not (AES_N_KEY_SIZE + 4) must be
 * rejected. */
START_TEST(test_sa_gcm_bad_key_len)
{
    int ret;
    esp_setup();
    /* 33 is not 20, 28, or 36 */
    ret = wolfIP_esp_sa_new_gcm(1, (uint8_t *)spi_a,
                                atoip4(T_SRC), atoip4(T_DST),
                                ESP_ENC_GCM_RFC4543,
                                (uint8_t *)k_aes256_gcm, 33U);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* The inbound pool holds WOLFIP_ESP_NUM_SA (2) entries; a 3rd must fail. */
START_TEST(test_sa_pool_exhaustion)
{
    int ret;
    esp_setup();

    ret = wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_a,
                                     atoip4(T_SRC), atoip4(T_DST),
                                     (uint8_t *)k_aes128, sizeof(k_aes128),
                                     ESP_AUTH_SHA256_RFC4868,
                                     (uint8_t *)k_auth16, sizeof(k_auth16),
                                     ESP_ICVLEN_HMAC_128);
    ck_assert_int_eq(ret, 0);

    ret = wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_b,
                                     atoip4(T_SRC), atoip4(T_DST),
                                     (uint8_t *)k_aes128, sizeof(k_aes128),
                                     ESP_AUTH_SHA256_RFC4868,
                                     (uint8_t *)k_auth16, sizeof(k_auth16),
                                     ESP_ICVLEN_HMAC_128);
    ck_assert_int_eq(ret, 0);

    /* Pool is now full; the 3rd SA must be refused. */
    ret = wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_c,
                                     atoip4(T_SRC), atoip4(T_DST),
                                     (uint8_t *)k_aes128, sizeof(k_aes128),
                                     ESP_AUTH_SHA256_RFC4868,
                                     (uint8_t *)k_auth16, sizeof(k_auth16),
                                     ESP_ICVLEN_HMAC_128);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* Deleting a specific SA by SPI frees its slot for reuse. */
START_TEST(test_sa_del_frees_slot)
{
    int ret;
    esp_setup();

    /* Fill the inbound pool. */
    wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_a, atoip4(T_SRC), atoip4(T_DST),
                               (uint8_t *)k_aes128, sizeof(k_aes128),
                               ESP_AUTH_SHA256_RFC4868,
                               (uint8_t *)k_auth16, sizeof(k_auth16),
                               ESP_ICVLEN_HMAC_128);
    wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_b, atoip4(T_SRC), atoip4(T_DST),
                               (uint8_t *)k_aes128, sizeof(k_aes128),
                               ESP_AUTH_SHA256_RFC4868,
                               (uint8_t *)k_auth16, sizeof(k_auth16),
                               ESP_ICVLEN_HMAC_128);
    wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_c, atoip4(T_SRC), atoip4(T_DST),
                               (uint8_t *)k_aes128, sizeof(k_aes128),
                               ESP_AUTH_SHA256_RFC4868,
                               (uint8_t *)k_auth16, sizeof(k_auth16),
                               ESP_ICVLEN_HMAC_128);

    /* Delete one entry and verify the slot is reusable. */
    wolfIP_esp_sa_del(1, (uint8_t *)spi_b);

    ret = wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_d,
                                     atoip4(T_SRC), atoip4(T_DST),
                                     (uint8_t *)k_aes128, sizeof(k_aes128),
                                     ESP_AUTH_SHA256_RFC4868,
                                     (uint8_t *)k_auth16, sizeof(k_auth16),
                                     ESP_ICVLEN_HMAC_128);
    ck_assert_int_eq(ret, 0);
}
END_TEST

/* wolfIP_esp_sa_del_all clears every entry in both directions. */
START_TEST(test_sa_del_all)
{
    int ret;
    esp_setup();

    /* Fill both inbound and outbound pools. */
    wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_a, atoip4(T_SRC), atoip4(T_DST),
                               (uint8_t *)k_aes128, sizeof(k_aes128),
                               ESP_AUTH_SHA256_RFC4868,
                               (uint8_t *)k_auth16, sizeof(k_auth16),
                               ESP_ICVLEN_HMAC_128);
    wolfIP_esp_sa_new_cbc_hmac(0, (uint8_t *)spi_a, atoip4(T_SRC), atoip4(T_DST),
                               (uint8_t *)k_aes128, sizeof(k_aes128),
                               ESP_AUTH_SHA256_RFC4868,
                               (uint8_t *)k_auth16, sizeof(k_auth16),
                               ESP_ICVLEN_HMAC_128);

    wolfIP_esp_sa_del_all();

    /* After del_all both directions must have free slots for two new SAs. */
    ret = wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_a, atoip4(T_SRC), atoip4(T_DST),
                                     (uint8_t *)k_aes128, sizeof(k_aes128),
                                     ESP_AUTH_SHA256_RFC4868,
                                     (uint8_t *)k_auth16, sizeof(k_auth16),
                                     ESP_ICVLEN_HMAC_128);
    ck_assert_int_eq(ret, 0);
    ret = wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_b, atoip4(T_SRC), atoip4(T_DST),
                                     (uint8_t *)k_aes128, sizeof(k_aes128),
                                     ESP_AUTH_SHA256_RFC4868,
                                     (uint8_t *)k_auth16, sizeof(k_auth16),
                                     ESP_ICVLEN_HMAC_128);
    ck_assert_int_eq(ret, 0);
}
END_TEST

/*
 * replay window (esp_check_replay)
 * valid initial window: [1 .. 32]  (seq=0 is always invalid per RFC 4303)
 * */

/* seq=0 must always be rejected (RFC 4303 §3.4.3). */
START_TEST(test_replay_seq_zero_rejected)
{
    replay_t r;
    esp_replay_init(r);
    ck_assert_int_ne(esp_check_replay(&r, 0U), 0);
}
END_TEST

/* First valid packet at the low edge of the initial window (seq=1). */
START_TEST(test_replay_first_packet_accepted)
{
    replay_t r;
    esp_replay_init(r); /* hi_seq=32, seq_low=1 */
    ck_assert_int_eq(esp_check_replay(&r, 1U), 0);
}
END_TEST

/* A sequence number inside the window received a second time must be
 * rejected (duplicate / replay). */
START_TEST(test_replay_duplicate_rejected)
{
    replay_t r;
    esp_replay_init(r);
    ck_assert_int_eq(esp_check_replay(&r, 5U), 0);  /* first time: ok  */
    ck_assert_int_ne(esp_check_replay(&r, 5U), 0);  /* second time: replayed */
}
END_TEST

/* Multiple distinct in-window sequences must all be accepted once. */
START_TEST(test_replay_multiple_in_window)
{
    replay_t r;
    uint32_t i;
    esp_replay_init(r); /* window [1..32] */
    for (i = 1U; i <= 31U; i++) {
        ck_assert_int_eq(esp_check_replay(&r, i), 0);
    }
}
END_TEST

/* A sequence number strictly below the current window must be rejected. */
START_TEST(test_replay_below_window_rejected)
{
    replay_t r;
    esp_replay_init(r);
    /* Advance the window by receiving a high sequence number. */
    ck_assert_int_eq(esp_check_replay(&r, 64U), 0); /* hi_seq=64, seq_low=34 */
    /* seq=1 is now below the window floor. */
    ck_assert_int_ne(esp_check_replay(&r, 1U), 0);
}
END_TEST

/* A sequence number above hi_seq advances the window. */
START_TEST(test_replay_advance_hi_seq)
{
    replay_t r;
    esp_replay_init(r); /* hi_seq=32 */
    ck_assert_int_eq(esp_check_replay(&r, 33U), 0);
    ck_assert_uint_eq(r.hi_seq, 33U);
}
END_TEST

/* A jump larger than the window width resets the bitmap. */
START_TEST(test_replay_jump_resets_bitmap)
{
    replay_t r;
    esp_replay_init(r);
    /* Accept some sequences so the bitmap has bits set. */
    ck_assert_int_eq(esp_check_replay(&r, 1U), 0);
    ck_assert_int_eq(esp_check_replay(&r, 2U), 0);
    /* Jump more than ESP_REPLAY_WIN (32) ahead. */
    ck_assert_int_eq(esp_check_replay(&r, 1000U), 0);
    ck_assert_uint_eq(r.hi_seq, 1000U);
    /* seq=1 is now far outside the window. */
    ck_assert_int_ne(esp_check_replay(&r, 1U), 0);
}
END_TEST

/* Sequence numbers that were inside the window before a large jump fall
 * outside after it and must be rejected. */
START_TEST(test_replay_old_seqs_after_jump)
{
    replay_t r;
    esp_replay_init(r);
    ck_assert_int_eq(esp_check_replay(&r, 10U), 0);
    ck_assert_int_eq(esp_check_replay(&r, 500U), 0); /* jump > 32 */
    /* 10 is now well below the new window floor (500-31=469). */
    ck_assert_int_ne(esp_check_replay(&r, 10U), 0);
}
END_TEST

/*
 * esp_transport_unwrap error paths
 */
/* Frame shorter than ETH + IP header must be rejected immediately. */
START_TEST(test_unwrap_frame_too_small)
{
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN];
    uint32_t frame_len = ETH_HEADER_LEN + IP_HEADER_LEN;
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    int ret;

    esp_setup();
    memset(buf, 0, sizeof(buf));
    ip->ver_ihl = 0x45U;
    ip->proto   = 0x32U; /* ESP */

    ret = esp_transport_unwrap(ip, &frame_len);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* Frame with ESP header but no room for even SPI+SEQ must be rejected. */
START_TEST(test_unwrap_esp_header_too_small)
{
    /* Just ETH + IP + 4 bytes (only SPI, no SEQ). */
    uint8_t buf[ETH_HEADER_LEN + IP_HEADER_LEN + 4];
    uint32_t frame_len = sizeof(buf);
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    int ret;

    esp_setup();
    memset(buf, 0, sizeof(buf));
    ip->ver_ihl = 0x45U;
    ip->proto   = 0x32U;

    ret = esp_transport_unwrap(ip, &frame_len);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* An ESP packet whose SPI is not in the SA list must be dropped. */
START_TEST(test_unwrap_unknown_spi)
{
    uint8_t buf[LINK_MTU + 128];
    uint8_t payload[ESP_SPI_LEN + ESP_SEQ_LEN + 32]; /* some bytes */
    uint8_t unknown_spi[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    uint32_t frame_len;
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    int ret;

    esp_setup(); /* no SAs configured */
    frame_len = build_ip_packet(buf, sizeof(buf), 0x32U,
                                payload, sizeof(payload));
    /* Overwrite the first 4 bytes (SPI field) with an unknown value. */
    memcpy(ip->data, unknown_spi, 4U);

    ret = esp_transport_unwrap(ip, &frame_len);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* A packet whose total length is below the minimum required by its SA
 * (SPI+SEQ+IV+pad_len+nxt_hdr+ICV) must be rejected. */
START_TEST(test_unwrap_below_min_len)
{
    uint8_t buf[LINK_MTU + 128];
    /* 8 bytes: SPI + SEQ only, not enough for AES-CBC's IV, trailer, ICV. */
    uint8_t short_esp[8] = { 0xAB, 0xCD, 0xEF, 0x01, /* SPI = spi_rt */
                              0x00, 0x00, 0x00, 0x01  /* seq = 1     */ };
    uint32_t frame_len;
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    int ret;

    esp_setup();
    /* Register an inbound CBC+HMAC SA with this SPI. */
    wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_rt,
                               atoip4(T_SRC), atoip4(T_DST),
                               (uint8_t *)k_aes128, sizeof(k_aes128),
                               ESP_AUTH_SHA256_RFC4868,
                               (uint8_t *)k_auth16, sizeof(k_auth16),
                               ESP_ICVLEN_HMAC_128);

    frame_len = build_ip_packet(buf, sizeof(buf), 0x32U,
                                short_esp, sizeof(short_esp));
    ret = esp_transport_unwrap(ip, &frame_len);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/*
 * full enc/dec round-trips
 * */
/* Internal helper shared by all CBC+HMAC round-trip cases. */
static void do_roundtrip_cbc_hmac(uint8_t *enc_key, uint8_t enc_key_len,
                                  esp_auth_t auth,
                                  uint8_t *auth_key, uint8_t auth_key_len,
                                  uint8_t icv_len)
{
    static uint8_t buf[LINK_MTU + 256];
    uint8_t ref[64];
    uint32_t frame_len;
    uint16_t ip_len;
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    uint8_t restored_proto;
    int ret;
    uint32_t i;

    /* Fill reference payload with a known pattern. */
    for (i = 0U; i < sizeof(ref); i++) {
        ref[i] = (uint8_t)(i & 0xFFU);
    }

    esp_setup();

    /* Outbound SA: encrypts packets sent to T_DST.
     * esp_transport_wrap looks up by ip->dst == ee32(out_sa.dst). */
    ret = wolfIP_esp_sa_new_cbc_hmac(0, (uint8_t *)spi_rt,
                                     atoip4(T_SRC), atoip4(T_DST),
                                     enc_key, enc_key_len,
                                     auth, auth_key, auth_key_len,
                                     icv_len);
    ck_assert_int_eq(ret, 0);

    /* Inbound SA: decrypts packets carrying spi_rt. */
    ret = wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_rt,
                                     atoip4(T_SRC), atoip4(T_DST),
                                     enc_key, enc_key_len,
                                     auth, auth_key, auth_key_len,
                                     icv_len);
    ck_assert_int_eq(ret, 0);

    /* Build a plaintext IPv4/UDP packet. */
    frame_len = build_ip_packet(buf, sizeof(buf), WI_IPPROTO_UDP,
                                ref, sizeof(ref));
    ip_len    = (uint16_t)(frame_len - ETH_HEADER_LEN);

    /* --- Wrap --- */
    ret = esp_transport_wrap(ip, &ip_len);
    ck_assert_int_eq(ret, 0);

    /* esp_send normally fixes these up; we must do it manually. */
    frame_len   = (uint32_t)ip_len + ETH_HEADER_LEN;
    ip->proto   = 0x32U; /* IP proto = ESP */
    ip->len     = ee16(ip_len);
    ip->csum    = 0U;
    iphdr_set_checksum(ip);

    /* --- Unwrap --- */
    ret = esp_transport_unwrap(ip, &frame_len);
    ck_assert_int_eq(ret, 0);

    /* The inner protocol must be restored. */
    restored_proto = ip->proto;
    ck_assert_uint_eq(restored_proto, WI_IPPROTO_UDP);

    /* The payload must match the original plaintext exactly. */
    ck_assert_mem_eq(ip->data, ref, sizeof(ref));
}

START_TEST(test_roundtrip_aes128_cbc_sha256_128)
{
    do_roundtrip_cbc_hmac(k_aes128, sizeof(k_aes128),
                          ESP_AUTH_SHA256_RFC4868,
                          k_auth16, sizeof(k_auth16),
                          ESP_ICVLEN_HMAC_128);
}
END_TEST

START_TEST(test_roundtrip_aes128_cbc_sha256_96)
{
    do_roundtrip_cbc_hmac(k_aes128, sizeof(k_aes128),
                          ESP_AUTH_SHA256_RFC4868,
                          k_auth16, sizeof(k_auth16),
                          ESP_ICVLEN_HMAC_96);
}
END_TEST

START_TEST(test_roundtrip_aes128_cbc_sha1)
{
    do_roundtrip_cbc_hmac(k_aes128, sizeof(k_aes128),
                          ESP_AUTH_SHA1_RFC2404,
                          k_auth16, sizeof(k_auth16),
                          ESP_ICVLEN_HMAC_96);
}
END_TEST

START_TEST(test_roundtrip_aes128_cbc_md5)
{
    do_roundtrip_cbc_hmac(k_aes128, sizeof(k_aes128),
                          ESP_AUTH_MD5_RFC2403,
                          k_auth16, sizeof(k_auth16),
                          ESP_ICVLEN_HMAC_96);
}
END_TEST

START_TEST(test_roundtrip_aes256_cbc_sha256_128)
{
    do_roundtrip_cbc_hmac(k_aes256, sizeof(k_aes256),
                          ESP_AUTH_SHA256_RFC4868,
                          k_auth16, sizeof(k_auth16),
                          ESP_ICVLEN_HMAC_128);
}
END_TEST

#ifndef NO_DES3
/* 3DES-CBC + HMAC-SHA256 round-trip. */
START_TEST(test_roundtrip_des3_sha256)
{
    static uint8_t buf[LINK_MTU + 256];
    uint8_t ref[64];
    /* 3DES key is always 24 bytes. */
    static uint8_t k_des3[24] = {
        0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
        0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
        0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE
    };
    uint32_t frame_len, i;
    uint16_t ip_len;
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    int ret;

    for (i = 0U; i < sizeof(ref); i++) ref[i] = (uint8_t)(i & 0xFFU);

    esp_setup();

    ret = wolfIP_esp_sa_new_des3_hmac(0, (uint8_t *)spi_rt,
                                      atoip4(T_SRC), atoip4(T_DST),
                                      (uint8_t *)k_des3,
                                      ESP_AUTH_SHA256_RFC4868,
                                      (uint8_t *)k_auth16, sizeof(k_auth16),
                                      ESP_ICVLEN_HMAC_128);
    ck_assert_int_eq(ret, 0);

    ret = wolfIP_esp_sa_new_des3_hmac(1, (uint8_t *)spi_rt,
                                      atoip4(T_SRC), atoip4(T_DST),
                                      (uint8_t *)k_des3,
                                      ESP_AUTH_SHA256_RFC4868,
                                      (uint8_t *)k_auth16, sizeof(k_auth16),
                                      ESP_ICVLEN_HMAC_128);
    ck_assert_int_eq(ret, 0);

    frame_len = build_ip_packet(buf, sizeof(buf), WI_IPPROTO_UDP,
                                ref, sizeof(ref));
    ip_len    = (uint16_t)(frame_len - ETH_HEADER_LEN);

    ret = esp_transport_wrap(ip, &ip_len);
    ck_assert_int_eq(ret, 0);

    frame_len = (uint32_t)ip_len + ETH_HEADER_LEN;
    ip->proto = 0x32U;
    ip->len   = ee16(ip_len);
    ip->csum  = 0U;
    iphdr_set_checksum(ip);

    ret = esp_transport_unwrap(ip, &frame_len);
    ck_assert_int_eq(ret, 0);

    ck_assert_uint_eq(ip->proto, WI_IPPROTO_UDP);
    ck_assert_mem_eq(ip->data, ref, sizeof(ref));
}
END_TEST
#endif /* !NO_DES3 */

#if defined(WOLFSSL_AESGCM_STREAM)
/* AES-GCM (RFC 4106) round-trip. */
START_TEST(test_roundtrip_aes_gcm_rfc4106)
{
    static uint8_t buf[LINK_MTU + 256];
    uint8_t ref[64];
    uint32_t frame_len, i;
    uint16_t ip_len;
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    int ret;

    for (i = 0U; i < sizeof(ref); i++) ref[i] = (uint8_t)(i & 0xFFU);

    esp_setup();

    /* Both SAs share the same key+salt so GCM enc/dec succeeds. */
    ret = wolfIP_esp_sa_new_gcm(0, (uint8_t *)spi_rt,
                                atoip4(T_SRC), atoip4(T_DST),
                                ESP_ENC_GCM_RFC4106,
                                (uint8_t *)k_aes256_gcm,
                                sizeof(k_aes256_gcm));
    ck_assert_int_eq(ret, 0);

    ret = wolfIP_esp_sa_new_gcm(1, (uint8_t *)spi_rt,
                                atoip4(T_SRC), atoip4(T_DST),
                                ESP_ENC_GCM_RFC4106,
                                (uint8_t *)k_aes256_gcm,
                                sizeof(k_aes256_gcm));
    ck_assert_int_eq(ret, 0);

    frame_len = build_ip_packet(buf, sizeof(buf), WI_IPPROTO_UDP,
                                ref, sizeof(ref));
    ip_len    = (uint16_t)(frame_len - ETH_HEADER_LEN);

    ret = esp_transport_wrap(ip, &ip_len);
    ck_assert_int_eq(ret, 0);

    frame_len = (uint32_t)ip_len + ETH_HEADER_LEN;
    ip->proto = 0x32U;
    ip->len   = ee16(ip_len);
    ip->csum  = 0U;
    iphdr_set_checksum(ip);

    ret = esp_transport_unwrap(ip, &frame_len);
    ck_assert_int_eq(ret, 0);

    ck_assert_uint_eq(ip->proto, WI_IPPROTO_UDP);
    ck_assert_mem_eq(ip->data, ref, sizeof(ref));
}
END_TEST
#endif /* WOLFSSL_AESGCM_STREAM */

/* AES-GMAC (RFC 4543) round-trip: auth-only, no encryption. */
START_TEST(test_roundtrip_aes_gmac_rfc4543)
{
    static uint8_t buf[LINK_MTU + 256];
    uint8_t ref[64];
    uint32_t frame_len, i;
    uint16_t ip_len;
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    int ret;

    for (i = 0U; i < sizeof(ref); i++) ref[i] = (uint8_t)(i & 0xFFU);

    esp_setup();

    ret = wolfIP_esp_sa_new_gcm(0, (uint8_t *)spi_rt,
                                atoip4(T_SRC), atoip4(T_DST),
                                ESP_ENC_GCM_RFC4543,
                                (uint8_t *)k_aes256_gcm,
                                sizeof(k_aes256_gcm));
    ck_assert_int_eq(ret, 0);

    ret = wolfIP_esp_sa_new_gcm(1, (uint8_t *)spi_rt,
                                atoip4(T_SRC), atoip4(T_DST),
                                ESP_ENC_GCM_RFC4543,
                                (uint8_t *)k_aes256_gcm,
                                sizeof(k_aes256_gcm));
    ck_assert_int_eq(ret, 0);

    frame_len = build_ip_packet(buf, sizeof(buf), WI_IPPROTO_UDP,
                                ref, sizeof(ref));
    ip_len    = (uint16_t)(frame_len - ETH_HEADER_LEN);

    ret = esp_transport_wrap(ip, &ip_len);
    ck_assert_int_eq(ret, 0);

    frame_len = (uint32_t)ip_len + ETH_HEADER_LEN;
    ip->proto = 0x32U;
    ip->len   = ee16(ip_len);
    ip->csum  = 0U;
    iphdr_set_checksum(ip);

    ret = esp_transport_unwrap(ip, &frame_len);
    ck_assert_int_eq(ret, 0);

    /* GMAC is auth-only: payload must be byte-for-byte identical. */
    ck_assert_uint_eq(ip->proto, WI_IPPROTO_UDP);
    ck_assert_mem_eq(ip->data, ref, sizeof(ref));
}
END_TEST

/*
 * icv tamper detection
 *
 * after a successful wrap, flip a byte in the ICV; the subsequent unwrap
 * must fail.
 * */
/* helper: wrap a packet with CBC+SHA256-128, flip the last ICV byte. */
static void do_icv_tamper(void)
{
    static uint8_t buf[LINK_MTU + 256];
    uint8_t ref[64];
    uint32_t frame_len, esp_len, i;
    uint16_t ip_len;
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    int ret;

    for (i = 0U; i < sizeof(ref); i++) ref[i] = (uint8_t)(i & 0xFFU);

    esp_setup();

    wolfIP_esp_sa_new_cbc_hmac(0, (uint8_t *)spi_rt,
                               atoip4(T_SRC), atoip4(T_DST),
                               (uint8_t *)k_aes128, sizeof(k_aes128),
                               ESP_AUTH_SHA256_RFC4868,
                               (uint8_t *)k_auth16, sizeof(k_auth16),
                               ESP_ICVLEN_HMAC_128);
    wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_rt,
                               atoip4(T_SRC), atoip4(T_DST),
                               (uint8_t *)k_aes128, sizeof(k_aes128),
                               ESP_AUTH_SHA256_RFC4868,
                               (uint8_t *)k_auth16, sizeof(k_auth16),
                               ESP_ICVLEN_HMAC_128);

    frame_len = build_ip_packet(buf, sizeof(buf), WI_IPPROTO_UDP,
                                ref, sizeof(ref));
    ip_len    = (uint16_t)(frame_len - ETH_HEADER_LEN);

    ret = esp_transport_wrap(ip, &ip_len);
    ck_assert_int_eq(ret, 0);

    frame_len = (uint32_t)ip_len + ETH_HEADER_LEN;
    ip->proto = 0x32U;
    ip->len   = ee16(ip_len);
    ip->csum  = 0U;
    iphdr_set_checksum(ip);

    /* esp_len = ip_len - IP_HEADER_LEN.  The ICV occupies the last
     * ESP_ICVLEN_HMAC_128 (16) bytes of ip->data[0..esp_len-1]. */
    esp_len = ip_len - IP_HEADER_LEN;
    ip->data[esp_len - 1U] ^= 0xFFU; /* corrupt last ICV byte */

    ret = esp_transport_unwrap(ip, &frame_len);
    ck_assert_int_eq(ret, -1); /* must be rejected */
}

START_TEST(test_icv_tamper_cbc_sha256)
{
    do_icv_tamper();
}
END_TEST

/* Tampering with a ciphertext byte (not the ICV) must also be caught by
 * the HMAC check: the MAC covers the encrypted payload. */
START_TEST(test_ciphertext_tamper_cbc_sha256)
{
    static uint8_t buf[LINK_MTU + 256];
    uint8_t ref[64];
    uint32_t frame_len, i;
    uint16_t ip_len;
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    /* Byte offset into ip->data[] where ciphertext starts:
     * SPI(4) + SEQ(4) + IV(16) = 24.  Any index >= 24 and before the
     * ICV is encrypted payload. */
    uint32_t ct_offset = ESP_SPI_LEN + ESP_SEQ_LEN + ESP_CBC_RFC3602_IV_LEN;
    int ret;

    for (i = 0U; i < sizeof(ref); i++) ref[i] = (uint8_t)(i & 0xFFU);

    esp_setup();

    wolfIP_esp_sa_new_cbc_hmac(0, (uint8_t *)spi_rt,
                               atoip4(T_SRC), atoip4(T_DST),
                               (uint8_t *)k_aes128, sizeof(k_aes128),
                               ESP_AUTH_SHA256_RFC4868,
                               (uint8_t *)k_auth16, sizeof(k_auth16),
                               ESP_ICVLEN_HMAC_128);
    wolfIP_esp_sa_new_cbc_hmac(1, (uint8_t *)spi_rt,
                               atoip4(T_SRC), atoip4(T_DST),
                               (uint8_t *)k_aes128, sizeof(k_aes128),
                               ESP_AUTH_SHA256_RFC4868,
                               (uint8_t *)k_auth16, sizeof(k_auth16),
                               ESP_ICVLEN_HMAC_128);

    frame_len = build_ip_packet(buf, sizeof(buf), WI_IPPROTO_UDP,
                                ref, sizeof(ref));
    ip_len    = (uint16_t)(frame_len - ETH_HEADER_LEN);

    ret = esp_transport_wrap(ip, &ip_len);
    ck_assert_int_eq(ret, 0);

    frame_len = (uint32_t)ip_len + ETH_HEADER_LEN;
    ip->proto = 0x32U;
    ip->len   = ee16(ip_len);
    ip->csum  = 0U;
    iphdr_set_checksum(ip);

    ip->data[ct_offset] ^= 0x01U; /* single bit flip in ciphertext */

    ret = esp_transport_unwrap(ip, &frame_len);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/*
 * no matching outbound SA (esp_transport_wrap returns 1)
 * */
/* When no outbound SA matches ip->dst, wrap must return 1 (caller should
 * send plaintext). */
START_TEST(test_wrap_no_matching_sa)
{
    static uint8_t buf[LINK_MTU + 256];
    uint8_t ref[32];
    uint32_t frame_len;
    uint16_t ip_len;
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
    int ret;

    memset(ref, 0xABU, sizeof(ref));
    esp_setup(); /* no SAs configured */

    frame_len = build_ip_packet(buf, sizeof(buf), WI_IPPROTO_UDP,
                                ref, sizeof(ref));
    ip_len    = (uint16_t)(frame_len - ETH_HEADER_LEN);

    ret = esp_transport_wrap(ip, &ip_len);
    /* 1 = "no policy found, send plaintext" */
    ck_assert_int_eq(ret, 1);
}
END_TEST

static Suite *esp_suite(void)
{
    Suite *s;
    TCase *tc;

    s = suite_create("ESP");

    /* SA management */
    tc = tcase_create("sa_management");
    tcase_add_test(tc, test_sa_cbc_hmac_good);
    tcase_add_test(tc, test_sa_cbc_bad_enc_key_len);
    tcase_add_test(tc, test_sa_cbc_bad_auth_key_len);
    tcase_add_test(tc, test_sa_gcm_good);
    tcase_add_test(tc, test_sa_gcm_bad_key_len);
    tcase_add_test(tc, test_sa_pool_exhaustion);
    tcase_add_test(tc, test_sa_del_frees_slot);
    tcase_add_test(tc, test_sa_del_all);
    suite_add_tcase(s, tc);

    /* Replay window */
    tc = tcase_create("replay_window");
    tcase_add_test(tc, test_replay_seq_zero_rejected);
    tcase_add_test(tc, test_replay_first_packet_accepted);
    tcase_add_test(tc, test_replay_duplicate_rejected);
    tcase_add_test(tc, test_replay_multiple_in_window);
    tcase_add_test(tc, test_replay_below_window_rejected);
    tcase_add_test(tc, test_replay_advance_hi_seq);
    tcase_add_test(tc, test_replay_jump_resets_bitmap);
    tcase_add_test(tc, test_replay_old_seqs_after_jump);
    suite_add_tcase(s, tc);

    /* Unwrap error paths */
    tc = tcase_create("unwrap_errors");
    tcase_add_test(tc, test_unwrap_frame_too_small);
    tcase_add_test(tc, test_unwrap_esp_header_too_small);
    tcase_add_test(tc, test_unwrap_unknown_spi);
    tcase_add_test(tc, test_unwrap_below_min_len);
    suite_add_tcase(s, tc);

    /* Crypto round-trips */
    tc = tcase_create("roundtrip");
    tcase_set_timeout(tc, 30);
    tcase_add_test(tc, test_roundtrip_aes128_cbc_sha256_128);
    tcase_add_test(tc, test_roundtrip_aes128_cbc_sha256_96);
    tcase_add_test(tc, test_roundtrip_aes128_cbc_sha1);
    tcase_add_test(tc, test_roundtrip_aes128_cbc_md5);
    tcase_add_test(tc, test_roundtrip_aes256_cbc_sha256_128);
#ifndef NO_DES3
    tcase_add_test(tc, test_roundtrip_des3_sha256);
#endif
#if defined(WOLFSSL_AESGCM_STREAM)
    tcase_add_test(tc, test_roundtrip_aes_gcm_rfc4106);
#endif
    tcase_add_test(tc, test_roundtrip_aes_gmac_rfc4543);
    suite_add_tcase(s, tc);

    /* ICV / ciphertext integrity */
    tc = tcase_create("integrity");
    tcase_add_test(tc, test_icv_tamper_cbc_sha256);
    tcase_add_test(tc, test_ciphertext_tamper_cbc_sha256);
    suite_add_tcase(s, tc);

    /* No-SA outbound path */
    tc = tcase_create("no_sa");
    tcase_add_test(tc, test_wrap_no_matching_sa);
    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    int      nfailed;
    Suite   *s  = esp_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    nfailed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (nfailed == 0) ? 0 : 1;
}

/* wolfesp.c
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

#if defined(WOLFIP_ESP) && !defined(WOLFESP_SRC)
#define WOLFESP_SRC
#include "wolfesp.h"
static WC_RNG          wc_rng;
static volatile int    rng_inited = 0;
/* security association static pool*/
static wolfIP_esp_sa   in_sa_list[WOLFIP_ESP_NUM_SA];
static wolfIP_esp_sa   out_sa_list[WOLFIP_ESP_NUM_SA];
static uint16_t        in_sa_num = WOLFIP_ESP_NUM_SA;
static uint16_t        out_sa_num = WOLFIP_ESP_NUM_SA;

/* for err and important messages */
#define ESP_LOG(fmt, ...) LOG(fmt, ##__VA_ARGS__)

/* for verbose debug */
#ifdef DEBUG_ESP
    #define ESP_DEBUG(fmt, ...) \
        LOG(fmt, ##__VA_ARGS__)
#else
    #define ESP_DEBUG(fmt, ...) \
        do { } while (0)
#endif /* DEBUG_ESP */

int wolfIP_esp_init(void)
{
    int err = 0;

    wolfIP_esp_sa_del_all();

    if (rng_inited == 0) {
        err = wc_InitRng_ex(&wc_rng, NULL, INVALID_DEVID);
        if (err) {
            ESP_LOG("error: wc_InitRng_ex: %d\n", err);
        }
        else {
            rng_inited = 1;
        }
    }

    return err;
}

void wolfIP_esp_sa_del_all(void)
{
    memset(in_sa_list, 0, sizeof(in_sa_list));
    memset(out_sa_list, 0, sizeof(out_sa_list));
    return;
}

static inline wolfIP_esp_sa *
esp_sa_get(int in, const uint8_t * spi)
{
    uint8_t         empty_sa[4] = {0x00, 0x00, 0x00, 0x00};
    wolfIP_esp_sa * list = NULL;
    size_t          i = 0;

    if (spi == NULL) {
        spi = empty_sa;
    }

    in = (in == 0 ? 0 : 1);
    if (in == 1) {
        list = in_sa_list;
    }
    else {
        list = out_sa_list;
    }

    for (i = 0; i < WOLFIP_ESP_NUM_SA; ++i) {
        if (memcmp(list[i].spi, spi, ESP_SPI_LEN) == 0) {
            return &list[i];
        }
    }

    return NULL;
}

void wolfIP_esp_sa_del_spi(int in, uint8_t * spi)
{
    wolfIP_esp_sa * sa = NULL;
    sa = esp_sa_get(in, spi);
    if (sa != NULL) {
        memset(sa, 0, sizeof(*sa));
    }
    return;
}

/* Configure a new Security Association based on either
 * enc = ESP_ENC_GCM_RFC4106 (gcm), or enc = ESP_AUTH_GCM_RFC4543 (gmac).
 * */
int wolfIP_esp_sa_new_gcm(int in, uint8_t * spi, ip4 src, ip4 dst,
                          esp_enc_t enc, uint8_t * enc_key,
                          uint8_t enc_key_len)
{
    wolfIP_esp_sa * new_sa = NULL;
    int             err = 0;
    esp_auth_t      auth = 0;

    new_sa = esp_sa_get(in, NULL);
    if (new_sa == NULL) {
        ESP_LOG("error: sa %s pool is full\n", in == 1 ? "in" : "out");
        return -1;
    }

    switch (enc) {
    #if defined(WOLFSSL_AESGCM_STREAM)
    case ESP_ENC_GCM_RFC4106:
        auth = ESP_AUTH_GCM_RFC4106;
        break;
    #endif /* WOLFSSL_AESGCM_STREAM */
    case ESP_ENC_GCM_RFC4543:
        auth = ESP_AUTH_GCM_RFC4543;
        break;
    default:
        ESP_LOG("error: unsupported enc: %d\n", enc);
        return -1;
    }

    memset(new_sa, 0, sizeof(*new_sa));
    esp_replay_init(new_sa->replay);
    memcpy(new_sa->spi, spi, ESP_SPI_LEN);
    memcpy(new_sa->enc_key, enc_key, enc_key_len);
    new_sa->src         = src;
    new_sa->dst         = dst;
    new_sa->enc         = enc;
    new_sa->enc_key_len = enc_key_len;
    new_sa->auth        = auth;
    /* rfc4106 and rfc4543 follow the same IV and ICV standards. */
    new_sa->icv_len     = ESP_GCM_RFC4106_ICV_LEN;

    /* Generate pre-iv for gcm. */
    err = wc_RNG_GenerateBlock(&wc_rng, new_sa->pre_iv,
                               ESP_GCM_RFC4106_IV_LEN);
    if (err) {
        ESP_LOG("error: wc_RNG_GenerateBlock: %d\n", err);
        memset(new_sa, 0, sizeof(*new_sa));
        err = -1;
    }

    ESP_DEBUG("info: esp_sa_new_gcm: %s\n", in == 1 ? "in" : "out");
    return err;
}

/* Configure a new Security Association based on aes-cbc with hmac.
 * */
int wolfIP_esp_sa_new_cbc_hmac(int in, uint8_t * spi, ip4 src, ip4 dst,
                               uint8_t * enc_key, uint8_t enc_key_len,
                               esp_auth_t auth, uint8_t * auth_key,
                               uint8_t auth_key_len, uint8_t icv_len)
{
    wolfIP_esp_sa * new_sa = NULL;

    new_sa = esp_sa_get(in, NULL);
    if (new_sa == NULL) {
        ESP_LOG("error: sa %s pool is full\n", in == 1 ? "in" : "out");
        return -1;
    }

    memset(new_sa, 0, sizeof(*new_sa));
    esp_replay_init(new_sa->replay);
    memcpy(new_sa->spi, spi, ESP_SPI_LEN);
    memcpy(new_sa->enc_key, enc_key, enc_key_len);
    memcpy(new_sa->auth_key, auth_key, auth_key_len);
    new_sa->src          = src;
    new_sa->dst          = dst;
    new_sa->enc          = ESP_ENC_CBC_AES;
    new_sa->enc_key_len  = enc_key_len;
    new_sa->auth         = auth;
    new_sa->auth_key_len = auth_key_len;
    new_sa->icv_len      = icv_len;

    ESP_DEBUG("info: esp_sa_new_cbc_hmac: %s\n", in == 1 ? "in" : "out");
    return 0;
}

/* Configure a new Security Association based on des3 with hmac.
 * */
int
wolfIP_esp_sa_new_des3_hmac(int in, uint8_t * spi, ip4 src, ip4 dst,
                            uint8_t * enc_key, esp_auth_t auth,
                            uint8_t * auth_key, uint8_t auth_key_len,
                            uint8_t icv_len)
{
    wolfIP_esp_sa * new_sa = NULL;

    new_sa = esp_sa_get(in, NULL);
    if (new_sa == NULL) {
        ESP_LOG("error: sa %s pool is full\n", in == 1 ? "in" : "out");
        return -1;
    }

    memset(new_sa, 0, sizeof(*new_sa));
    esp_replay_init(new_sa->replay);
    memcpy(new_sa->spi, spi, ESP_SPI_LEN);
    memcpy(new_sa->enc_key, enc_key, ESP_DES3_KEY_LEN);
    memcpy(new_sa->auth_key, auth_key, auth_key_len);
    new_sa->src          = src;
    new_sa->dst          = dst;
    new_sa->enc          = ESP_ENC_CBC_DES3;
    new_sa->enc_key_len  = ESP_DES3_KEY_LEN;
    new_sa->auth         = auth;
    new_sa->auth_key_len = auth_key_len;
    new_sa->icv_len      = icv_len;

    ESP_DEBUG("info: esp_sa_new_des3_hmac: %s\n", in == 1 ? "in" : "out");
    return 0;
}

static uint8_t
esp_block_len_from_enc(esp_enc_t enc)
{
    uint8_t block_len = 0;

    switch (enc) {
    #ifndef NO_DES3
    case ESP_ENC_CBC_DES3:
        block_len = DES_BLOCK_SIZE;
        break;
    #endif /* !NO_DES3 */
    case ESP_ENC_CBC_AES:
        block_len = AES_BLOCK_SIZE;
        break;
    case ESP_ENC_GCM_RFC4106:
    case ESP_ENC_GCM_RFC4543:
    case ESP_ENC_NONE:
    default:
        block_len = 0;
        break;
    }

    return block_len;
}

static uint8_t
esp_iv_len_from_enc(esp_enc_t enc)
{
    uint8_t iv_len = 0;

    switch (enc) {
    #ifndef NO_DES3
    case ESP_ENC_CBC_DES3:
        iv_len = ESP_DES3_IV_LEN;
        break;
    #endif /* !NO_DES3 */
    case ESP_ENC_CBC_AES:
        iv_len = ESP_CBC_RFC3602_IV_LEN;
        break;
    case ESP_ENC_GCM_RFC4106:
    case ESP_ENC_GCM_RFC4543:
        iv_len = ESP_GCM_RFC4106_IV_LEN;
        break;
    case ESP_ENC_NONE:
    default:
        iv_len = 0;
        break;
    }

    return iv_len;
}

#ifdef DEBUG_ESP
#define esp_print_sep \
    LOG("+------------------+\n")
#define esp_str_4hex \
    "|  %02x  %02x  %02x  %02x  |"
#define esp_str_skip \
    "|  ..  ..  ..  ..  |"
#define esp_pad_fld \
    "| %02x%02x | %02d | 0x%02x |"

static inline void
esp_print_field(const char * fld, const uint8_t * val,
                uint32_t val_len)
{
    esp_print_sep;
    LOG(esp_str_4hex " (%s, %d bytes)\n",
        val[0], val[1], val[2], val[3], fld, val_len);
    if (val_len > 4) {
        for (size_t i = 4; i < val_len; i += 4) {
            if (i > 16 || (i + 4) > val_len) {
                LOG(esp_str_skip "\n");
                break;
            }

            LOG(esp_str_4hex"\n",
                val[0 + i], val[1 + i], val[2 + i], val[3 + i]);
        }
    }
    return;
}

/**
 * Print an ESP packet.
 *     _______________________________________________
 *    |orig IP hdr | ESP | UDP |      | ESP     | ESP |
 *    |(PROTO=50)  | hdr | hdr | Data | Trailer | ICV |
 *     -----------------------------------------------
 *                       |<---- encrypted ----->|
 *                 |<--- integrity checked ---->|
 * */
static void wolfIP_print_esp(const wolfIP_esp_sa * esp_sa,
                             const uint8_t * esp_data, uint32_t esp_len,
                             uint8_t pad_len, uint8_t nxt_hdr)
{
    const uint8_t * spi     = esp_data;
    const uint8_t * seq     = esp_data + ESP_SPI_LEN;
    const uint8_t * payload = esp_data + ESP_SPI_LEN + ESP_SEQ_LEN;
    const uint8_t * iv = NULL;
    const uint8_t * icv = NULL;
    uint8_t         iv_len = 0;
    const uint8_t * padding = NULL;
    uint32_t        payload_len = esp_len - ESP_SPI_LEN - ESP_SEQ_LEN
                                  - pad_len - ESP_PADDING_LEN
                                  - ESP_NEXT_HEADER_LEN ;

    iv_len = esp_iv_len_from_enc(esp_sa->enc);

    if (iv_len) {
        iv = payload;
        payload += iv_len;
        payload_len -= iv_len;
    }

    if (esp_sa->icv_len) {
        icv = esp_data + esp_len - esp_sa->icv_len;
    }

    /* last 2 bytes of padding */
    padding = esp_data + esp_len - esp_sa->icv_len - 4;

    LOG("esp packet: (%d bytes)\n", esp_len);

   /**   ESP header
    *     ______________
    *    | SPI | Seq    |
    *    |     | Number |
    *     -------------- */
    esp_print_field("spi", spi, ESP_SPI_LEN);
    esp_print_field("seq", seq, ESP_SEQ_LEN);

   /**
    * ESP payload (includes IV).
    * */
    if (iv) {
        esp_print_field("iv", iv, iv_len);
    }

    esp_print_field("payload", payload, payload_len);

   /**  ESP trailer
    *     _____________________________________
    *    | Padding           | Pad    | Next   |
    *    | (variable length) | Length | Header |
    *     ------------------------------------- */
    esp_print_sep;
    LOG(esp_pad_fld " (padding last 2 bytes, pad len, nxt hdr)\n",
        padding[0], padding[1], pad_len, nxt_hdr);

    if (icv) {
        esp_print_field("icv", icv, esp_sa->icv_len);
    }

    esp_print_sep;

    return;
}
#endif /* DEBUG_ESP */

/*
 * esp_data covers from start of ESP header to end of ESP trailer, but does not
 * include the ESP ICV after trailer.
 * */
static int
esp_calc_icv_hmac(uint8_t * hash, const wolfIP_esp_sa * esp_sa,
                  const uint8_t * esp_data, uint32_t esp_len)
{
    /* SHA1 and MD5 have these digest sizes:
     *   - WC_SHA_DIGEST_SIZE 20 bytes
     *   - WC_MD5_DIGEST_SIZE 16 bytes
     * */
    Hmac      hmac;
    int       err = 0;
    int       type = 0;
    uint32_t  auth_len = esp_len;

    switch (esp_sa->auth) {
    case ESP_AUTH_MD5_RFC2403:
        type = WC_MD5;
        break;
    case ESP_AUTH_SHA1_RFC2404:
        type = WC_SHA;
        break;
    case ESP_AUTH_SHA256_RFC4868:
        type = WC_SHA256;
        break;
    case ESP_AUTH_NONE:
    default:
        ESP_LOG("error: esp_calc_icv_hmac: invalid auth: %d\n", esp_sa->auth);
        return -1;
    }

    /* the icv is not included in icv calculation. */
    auth_len = esp_len - esp_sa->icv_len;

    err = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (err) {
        ESP_LOG("error: wc_HmacSetKey: %d\n", err);
        goto calc_icv_hmac_end;
    }

    err = wc_HmacSetKey(&hmac, type, esp_sa->auth_key, esp_sa->auth_key_len);
    if (err) {
        ESP_LOG("error: wc_HmacSetKey: %d\n", err);
        goto calc_icv_hmac_end;
    }

    /* Now calculate the ICV. The ICV covers from SPI to Next Header,
     * inclusive. */
    err = wc_HmacUpdate(&hmac, (const byte *)esp_data, auth_len);
    if (err) {
        ESP_LOG("error: wc_HmacUpdate: %d\n", err);
        goto calc_icv_hmac_end;
    }

    err = wc_HmacFinal(&hmac, hash);
    if (err) {
        ESP_LOG("error: wc_HmacFinal: %d\n", err);
        goto calc_icv_hmac_end;
    }

calc_icv_hmac_end:
    wc_HmacFree(&hmac);

    return err;
}

/* From wolfcrypt misc.c */
static int
esp_const_memcmp(const uint8_t * vec_a, const uint8_t * vec_b, uint32_t len)
{
    uint32_t i = 0;
    int      sum = 0;

    for (i = 0; i < len; i++) {
        sum |= vec_a[i] ^ vec_b[i];
    }

    return sum;
}

/**
 * Get the encryption length for an ESP payload.
 * */
#define esp_enc_len(esp_len, iv_len, icv_len) \
        (esp_len) - ESP_SPI_LEN - ESP_SEQ_LEN \
        - (iv_len) - (icv_len)

/**
 * Get pointer to raw encryption ESP IV, skipping ESP header.
 * */
#define esp_enc_iv(data, iv_len) \
        (data) + ESP_SPI_LEN + ESP_SEQ_LEN

/**
 * Get pointer to raw encryption ESP ICV.
 * */
#define esp_enc_icv(data, esp_len, icv_len) \
        (data) + (esp_len) - (icv_len)

/**
 * Get pointer to raw encryption ESP payload, skipping ESP header and IV.
 * */
#define esp_enc_payload(data, iv_len) \
        (data) + ESP_SPI_LEN + ESP_SEQ_LEN + (iv_len)

static int
esp_aes_rfc3602_dec(const wolfIP_esp_sa * esp_sa, uint8_t * esp_data,
                    uint32_t esp_len)
{
    Aes       cbc_dec;
    int       ret = -1;
    uint8_t   icv_len = esp_sa->icv_len;
    uint8_t   iv_len = ESP_CBC_RFC3602_IV_LEN;
    uint8_t * enc_payload = NULL;
    uint8_t * iv = NULL;
    uint16_t  enc_len = 0;
    uint8_t   inited = 0;

    ESP_DEBUG("info: aes cbc dec: %d\n", esp_len);

    enc_len = esp_enc_len(esp_len, iv_len, icv_len);
    enc_payload = esp_enc_payload(esp_data, iv_len);
    iv = esp_enc_iv(esp_data, iv_len);

    ret = wc_AesInit(&cbc_dec, NULL, INVALID_DEVID);
    if (ret != 0) {
        ESP_LOG("error: wc_AesInit: %d\n", ret);
        goto aes_dec_out;
    }
    inited = 1;

    ret = wc_AesSetKey(&cbc_dec, esp_sa->enc_key, esp_sa->enc_key_len,
                       iv, AES_DECRYPTION);
    if (ret != 0) {
        ESP_LOG("error: wc_AesSetKey: %d\n", ret);
        goto aes_dec_out;
    }

    /* decrypt in place. */
    ret = wc_AesCbcDecrypt(&cbc_dec, enc_payload, enc_payload, enc_len);
    if (ret != 0) {
        ESP_LOG("error: wc_AesCbcDecrypt: %d\n", ret);
        goto aes_dec_out;
    }

aes_dec_out:
    if (inited) {
        wc_AesFree(&cbc_dec);
        inited = 0;
    }

    return ret;
}

static int
esp_aes_rfc3602_enc(const wolfIP_esp_sa * esp_sa, uint8_t * esp_data,
                    uint32_t esp_len)
{
    Aes          cbc_enc;
    int          ret = -1;
    uint8_t      icv_len = esp_sa->icv_len;
    uint8_t      iv_len = ESP_CBC_RFC3602_IV_LEN;
    uint8_t *    enc_payload = NULL;
    uint8_t *    iv = NULL;
    uint16_t     enc_len = 0;
    uint8_t      inited = 0;

    ESP_DEBUG("info: aes cbc enc: %d\n", esp_len);

    enc_len = esp_enc_len(esp_len, iv_len, icv_len);
    enc_payload = esp_enc_payload(esp_data, iv_len);
    iv = esp_enc_iv(esp_data, iv_len);

    /* Generate random iv block for cbc method. */
    ret = wc_RNG_GenerateBlock(&wc_rng, iv, iv_len);
    if (ret) {
        ESP_LOG("error: wc_RNG_GenerateBlock: %d\n", ret);
        goto aes_enc_out;
    }

    ret = wc_AesInit(&cbc_enc, NULL, INVALID_DEVID);
    if (ret != 0) {
        ESP_LOG("error: wc_AesInit: %d\n", ret);
        goto aes_enc_out;
    }

    inited = 1;
    ret = wc_AesSetKey(&cbc_enc, esp_sa->enc_key, esp_sa->enc_key_len,
                       iv, AES_ENCRYPTION);
    if (ret != 0) {
        ESP_LOG("error: wc_AesSetKey: %d\n", ret);
        goto aes_enc_out;
    }

    ret = wc_AesCbcEncrypt(&cbc_enc, enc_payload, enc_payload, enc_len);
    if (ret != 0) {
        ESP_LOG("error: wc_AesCbcEncrypt: %d\n", ret);
        goto aes_enc_out;
    }

aes_enc_out:
    if (inited) {
        wc_AesFree(&cbc_enc);
        inited = 0;
    }

    return ret;
}

#ifndef NO_DES3
static int
esp_des3_rfc2451_dec(const wolfIP_esp_sa * esp_sa, uint8_t * esp_data,
                     uint32_t esp_len)
{
    Des3      des3_dec;
    int       ret = -1;
    uint8_t   icv_len = esp_sa->icv_len;
    uint8_t   iv_len = ESP_DES3_IV_LEN;
    uint8_t * enc_payload = NULL;
    uint8_t * iv = NULL;
    uint16_t  enc_len = 0;
    uint8_t   inited = 0;

    ESP_DEBUG("info: des3 dec: %d\n", esp_len);

    if (esp_sa->enc_key_len != ESP_DES3_KEY_LEN) {
        ESP_LOG("error: des3_rfc2451_dec: key len = %d, expected %d\n",
               esp_sa->enc_key_len, ESP_DES3_KEY_LEN);
        goto des3_dec_out;
    }

    enc_len = esp_enc_len(esp_len, iv_len, icv_len);
    enc_payload = esp_enc_payload(esp_data, iv_len);
    iv = esp_enc_iv(esp_data, iv_len);

    ret = wc_Des3Init(&des3_dec, NULL, INVALID_DEVID);
    if (ret != 0) {
        ESP_LOG("error: wc_Des3Init: %d\n", ret);
        goto des3_dec_out;
    }
    inited = 1;

    ret = wc_Des3_SetKey(&des3_dec, esp_sa->enc_key, iv, DES_DECRYPTION);
    if (ret != 0) {
        ESP_LOG("error: wc_Des3_SetKey: %d\n", ret);
        goto des3_dec_out;
    }

    /* decrypt in place. */
    ret = wc_Des3_CbcDecrypt(&des3_dec, enc_payload, enc_payload, enc_len);
    if (ret != 0) {
        ESP_LOG("error: wc_Des3_CbcDecrypt: %d\n", ret);
        goto des3_dec_out;
    }

des3_dec_out:
    if (inited) {
        wc_Des3Free(&des3_dec);
        inited = 0;
    }

    return ret;
}

static int
esp_des3_rfc2451_enc(const wolfIP_esp_sa * esp_sa, uint8_t * esp_data,
                     uint32_t esp_len)
{
    Des3      des3_enc;
    int       ret = -1;
    uint8_t   icv_len = esp_sa->icv_len;
    uint8_t   iv_len = ESP_DES3_IV_LEN;
    uint8_t * enc_payload = NULL;
    uint8_t * iv = NULL;
    uint16_t  enc_len = 0;
    uint8_t   inited = 0;

    ESP_DEBUG("info: des3 enc: %d\n", esp_len);

    if (esp_sa->enc_key_len != ESP_DES3_KEY_LEN) {
        ESP_LOG("error: des3_rfc2451_enc: key len = %d, expected %d\n",
               esp_sa->enc_key_len, ESP_DES3_KEY_LEN);
        goto des3_enc_out;
    }

    enc_len = esp_enc_len(esp_len, iv_len, icv_len);
    enc_payload = esp_enc_payload(esp_data, iv_len);
    iv = esp_enc_iv(esp_data, iv_len);

    ret = wc_Des3Init(&des3_enc, NULL, INVALID_DEVID);

    if (ret != 0) {
        ESP_LOG("error: wc_Des3Init: %d\n", ret);
        goto des3_enc_out;
    }
    inited = 1;

    ret = wc_Des3_SetKey(&des3_enc, esp_sa->enc_key, iv, DES_ENCRYPTION);
    if (ret != 0) {
        ESP_LOG("error: wc_Des3_SetKey: %d\n", ret);
        goto des3_enc_out;
    }

    /* encrypt in place. */
    ret = wc_Des3_CbcEncrypt(&des3_enc, enc_payload, enc_payload, enc_len);
    if (ret != 0) {
        ESP_LOG("error: wc_Des3_CbcEncrypt: %d\n", ret);
        goto des3_enc_out;
    }

des3_enc_out:
    if (inited) {
        wc_Des3Free(&des3_enc);
        inited = 0;
    }

    return ret;
}
#endif /* !NO_DES3 */

/**
 * AES-GCM-ESP
 *    The KEYMAT requested for each AES-GCM key is N + 4 octets.  The first
 *    N octets are the AES key, and the remaining four octets are used as the
 *    salt value in the nonce.
 * */
#define esp_rfc4106_salt(esp_sa) (esp_sa)->enc_key \
                                 + (esp_sa)->enc_key_len \
                                 - ESP_GCM_RFC4106_SALT_LEN

#if defined(WOLFSSL_AESGCM_STREAM)
static int
esp_aes_rfc4106_dec(const wolfIP_esp_sa * esp_sa, uint8_t * esp_data,
                    uint32_t esp_len)
{
    Aes             gcm_dec;
    int             err = -1;
    uint8_t *       icv = NULL;
    uint8_t         icv_len = esp_sa->icv_len;
    uint8_t         iv_len = ESP_GCM_RFC4106_IV_LEN;
    uint8_t *       enc_payload = NULL;
    uint8_t *       iv = NULL;
    uint16_t        enc_len = 0;
    uint8_t         inited = 0;
    uint8_t *       aad = NULL;
    uint16_t        aad_len = ESP_SPI_LEN + ESP_SEQ_LEN;
    const uint8_t * salt = NULL;
    uint8_t         salt_len = ESP_GCM_RFC4106_SALT_LEN;
    uint8_t         nonce[ESP_GCM_RFC4106_NONCE_LEN]; /* 4 salt + 8 iv */

    ESP_DEBUG("info: aes gcm dec: %d\n", esp_len);

    /* get enc payload, iv, and icv pointers. */
    enc_len = esp_enc_len(esp_len, iv_len, icv_len);
    enc_payload = esp_enc_payload(esp_data, iv_len);
    aad = esp_data;
    iv = esp_enc_iv(esp_data, iv_len);
    icv = esp_enc_icv(esp_data, esp_len, esp_sa->icv_len);

    /* Get the salt, and construct nonce. */
    salt = esp_rfc4106_salt(esp_sa);
    memcpy(nonce, salt, salt_len);
    memcpy(nonce + salt_len, iv, iv_len);

    err = wc_AesInit(&gcm_dec, NULL, INVALID_DEVID);
    if (err != 0) {
        ESP_LOG("error: wc_AesInit: %d\n", err);
        goto rfc4106_dec_out;
    }
    inited = 1;

    /* subtract 4 byte salt from enc_key_len */
    err = wc_AesGcmInit(&gcm_dec, esp_sa->enc_key, esp_sa->enc_key_len - 4,
                        nonce, sizeof(nonce));
    if (err != 0) {
        ESP_LOG("error: wc_AesGcmInit: %d\n", err);
        goto rfc4106_dec_out;
    }

    err = wc_AesGcmSetKey(&gcm_dec, esp_sa->enc_key, esp_sa->enc_key_len - 4);
    if (err != 0) {
        ESP_LOG("error: wc_AesGcmSetKey: %d\n", err);
        goto rfc4106_dec_out;
    }

    err = wc_AesGcmDecrypt(&gcm_dec, enc_payload, enc_payload, enc_len,
                           nonce, sizeof(nonce), icv, icv_len, aad, aad_len);
    if (err != 0) {
        ESP_LOG("error: wc_AesGcmDecrypt: %d\n", err);
        goto rfc4106_dec_out;
    }

rfc4106_dec_out:
    if (inited) {
        wc_AesFree(&gcm_dec);
        inited = 0;
    }

    return err;
}

static int
esp_aes_rfc4106_enc(const wolfIP_esp_sa * esp_sa, uint8_t * esp_data,
                    uint32_t esp_len)
{
    Aes             gcm_enc;
    int             err = -1;
    uint8_t *       icv = NULL;
    uint8_t         icv_len = esp_sa->icv_len;
    uint8_t         iv_len = ESP_GCM_RFC4106_IV_LEN;
    uint8_t *       enc_payload = NULL;
    uint8_t *       iv = NULL;
    uint16_t        enc_len = 0;
    uint8_t         inited = 0;
    uint8_t *       aad = NULL;
    uint16_t        aad_len = ESP_SPI_LEN + ESP_SEQ_LEN;
    const uint8_t * salt = NULL;
    uint8_t         salt_len = ESP_GCM_RFC4106_SALT_LEN;
    uint8_t         nonce[ESP_GCM_RFC4106_NONCE_LEN]; /* 4 salt + 8 iv */

    ESP_DEBUG("info: aes gcm enc: %d\n", esp_len);

    /* get enc payload, iv, and icv pointers. */
    enc_len = esp_enc_len(esp_len, iv_len, icv_len);
    enc_payload = esp_enc_payload(esp_data, iv_len);
    aad = esp_data;
    iv = esp_enc_iv(esp_data, iv_len);
    icv = esp_enc_icv(esp_data, esp_len, esp_sa->icv_len);

    /* Get the salt, and construct nonce. */
    salt = esp_rfc4106_salt(esp_sa);

    {
        /* Deterministic iv construction using pre-iv salt and sequence number.
         * NIST SP 800-38D, section 8.2.1 Deterministic Construction, using
         * an integer counter. The sequence number is used as a counter, and
         * xor'ed with pre-iv salt. Based on linux kernel crypto/seqiv.c.
         * */
        uint32_t  seq_num = 0;
        uint8_t * seq_num_u8 = (uint8_t *) &seq_num;

        seq_num = ee32(esp_sa->replay.oseq);

        /* copy in the pre_iv. */
        memcpy(iv, esp_sa->pre_iv, sizeof(esp_sa->pre_iv));

        /* xor pre-iv salt with current sequence number. */
        for (size_t i = 0; i < sizeof(uint32_t); ++i) {
            iv[i + sizeof(uint32_t)] ^= seq_num_u8[i];
        }
    }

    memcpy(nonce, salt, salt_len);
    memcpy(nonce + salt_len, iv, iv_len);

    err = wc_AesInit(&gcm_enc, NULL, INVALID_DEVID);
    if (err != 0) {
        ESP_LOG("error: wc_AesInit: %d\n", err);
        goto rfc4106_enc_out;
    }
    inited = 1;

    /* subtract 4 byte salt from enc_key_len */
    err = wc_AesGcmInit(&gcm_enc, esp_sa->enc_key, esp_sa->enc_key_len - 4,
                        nonce, sizeof(nonce));
    if (err != 0) {
        ESP_LOG("error: wc_AesGcmInit: %d\n", err);
        goto rfc4106_enc_out;
    }

    err = wc_AesGcmSetKey(&gcm_enc, esp_sa->enc_key, esp_sa->enc_key_len - 4);
    if (err != 0) {
        ESP_LOG("error: wc_AesGcmSetKey: %d\n", err);
        goto rfc4106_enc_out;
    }

    err = wc_AesGcmEncrypt(&gcm_enc, enc_payload, enc_payload, enc_len,
                           nonce, sizeof(nonce), icv, icv_len, aad, aad_len);
    if (err != 0) {
        ESP_LOG("error: wc_AesGcmDecrypt: %d\n", err);
        goto rfc4106_enc_out;
    }

rfc4106_enc_out:
    if (inited) {
        wc_AesFree(&gcm_enc);
        inited = 0;
    }

    return err;
}
#endif /*WOLFSSL_AESGCM_STREAM */

/**
 * In rfc4543(gcm(aes)) the AAD consists ofthe SPI, Sequence Number,
 * and ESP Payload, and the AES-GCM plaintext is zero-length, while in
 * rfc4106(gcm(aes)) the AAD consists only of the SPI and Sequence Number,
 * and the AES-GCM plaintext consists of the ESP Payload.
 *  _____________     _______________________________________________________
 * |aad (N bytes)| = |SPI (4 bytes) + Sequence Number (4 bytes) + ESP Payload|
 *  -------------     -------------------------------------------------------
 * */
static int
esp_aes_rfc4543_dec(const wolfIP_esp_sa * esp_sa, uint8_t * esp_data,
                    uint32_t esp_len)
{
    int             err = -1;
    uint8_t *       icv = NULL;
    uint8_t         icv_len = esp_sa->icv_len;
    uint8_t         iv_len = ESP_GCM_RFC4106_IV_LEN;
    uint8_t *       iv = NULL;
    uint8_t *       aad = esp_data;
    uint16_t        aad_len = esp_len - icv_len;
    const uint8_t * salt = NULL;
    uint8_t         salt_len = ESP_GCM_RFC4106_SALT_LEN;
    uint8_t         nonce[ESP_GCM_RFC4106_NONCE_LEN]; /* 4 salt + 8 iv */

    ESP_DEBUG("info: aes gcm rfc4543 dec: %d\n", esp_len);

    /* get enc payload, iv, and icv pointers. */
    iv = esp_enc_iv(esp_data, iv_len);
    icv = esp_enc_icv(esp_data, esp_len, esp_sa->icv_len);

    /* Get the salt, and construct nonce. */
    salt = esp_rfc4106_salt(esp_sa);
    memcpy(nonce, salt, salt_len);
    memcpy(nonce + salt_len, iv, iv_len);

    err = wc_GmacVerify(esp_sa->enc_key, esp_sa->enc_key_len - 4,
                        nonce, sizeof(nonce), aad, aad_len,
                        icv, icv_len);
    if (err != 0) {
        ESP_LOG("error: wc_GmacVerify: %d\n", err);
        goto rfc4543_dec_out;
    }

rfc4543_dec_out:
    return err;
}

static int
esp_aes_rfc4543_enc(const wolfIP_esp_sa * esp_sa, uint8_t * esp_data,
                    uint32_t esp_len)
{
    Gmac            gmac_enc;
    int             err = -1;
    uint8_t *       icv = NULL;
    uint8_t         icv_len = esp_sa->icv_len;
    uint8_t         iv_len = ESP_GCM_RFC4106_IV_LEN;
    uint8_t *       iv = NULL;
    uint8_t         inited = 0;
    uint8_t *       aad = esp_data;
    uint16_t        aad_len = esp_len - icv_len;
    const uint8_t * salt = NULL;
    uint8_t         salt_len = ESP_GCM_RFC4106_SALT_LEN;
    uint8_t         nonce[ESP_GCM_RFC4106_NONCE_LEN]; /* 4 salt + 8 iv */

    ESP_DEBUG("info: aes gcm enc: %d\n", esp_len);

    /* get enc payload, iv, and icv pointers. */
    iv = esp_enc_iv(esp_data, iv_len);
    icv = esp_enc_icv(esp_data, esp_len, esp_sa->icv_len);

    /* Get the salt. */
    salt = esp_rfc4106_salt(esp_sa);

    {
        /* Deterministic iv construction using pre-iv salt and sequence number.
         * NIST SP 800-38D, section 8.2.1 Deterministic Construction, using
         * an integer counter. The sequence number is used as a counter, and
         * xor'ed with pre-iv salt. Based on linux kernel crypto/seqiv.c.
         * */
        uint32_t  seq_num = 0;
        uint8_t * seq_num_u8 = (uint8_t *) &seq_num;

        seq_num = ee32(esp_sa->replay.oseq);

        /* copy in the pre_iv. */
        memcpy(iv, esp_sa->pre_iv, sizeof(esp_sa->pre_iv));

        /* xor pre-iv salt with current sequence number. */
        for (size_t i = 0; i < sizeof(uint32_t); ++i) {
            iv[i + sizeof(uint32_t)] ^= seq_num_u8[i];
        }
    }

    memcpy(nonce, salt, salt_len);
    memcpy(nonce + salt_len, iv, iv_len);

    err = wc_AesInit(&gmac_enc.aes, NULL, INVALID_DEVID);
    if (err != 0) {
        ESP_LOG("error: wc_AesInit: %d\n", err);
        goto rfc4543_enc_out;
    }
    inited = 1;

    /* subtract 4 byte salt from enc_key_len */
    err = wc_GmacSetKey(&gmac_enc, esp_sa->enc_key, esp_sa->enc_key_len - 4);
    if (err != 0) {
        ESP_LOG("error: wc_AesGcmSetKey: %d\n", err);
        goto rfc4543_enc_out;
    }

    err = wc_GmacUpdate(&gmac_enc, nonce, sizeof(nonce), aad, aad_len,
                        icv, icv_len);
    if (err != 0) {
        ESP_LOG("error: wc_AesGmacUpdate: %d\n", err);
        goto rfc4543_enc_out;
    }

rfc4543_enc_out:
    if (inited) {
        wc_AesFree(&gmac_enc.aes);
        inited = 0;
    }

    return err;
}

/**
 * esp_data covers from start of ESP header to end of ESP trailer, but does not
 * include the ESP ICV after trailer.
 * */
static int
esp_check_icv_hmac(const wolfIP_esp_sa * esp_sa, uint8_t * esp_data,
                   uint32_t esp_len)
{
    /* SHA and MD5 have these digest sizes:
     *   - WC_MD5_DIGEST_SIZE    16 bytes
     *   - WC_SHA_DIGEST_SIZE    20 bytes
     *   - WC_SHA256_DIGEST_SIZE 32 bytes
     * */
    int              rc = 0;
    const uint8_t *  icv = NULL;
    byte             hash[WC_SHA256_DIGEST_SIZE];

    rc = esp_calc_icv_hmac(hash, esp_sa, esp_data, esp_len);
    if (rc) {
        return rc;
    }

    icv = esp_data + esp_len - esp_sa->icv_len;

    /* compare the first N bits depending on truncation type. */
    rc = esp_const_memcmp(icv, hash, esp_sa->icv_len);
    return rc;
}

/**
 * Check sequence number against replay_t state.
 *
 * return 0 on success.
 * */
static int
esp_check_replay(struct replay_t * replay, uint32_t seq)
{
    #if !defined(ESP_REPLAY_WIN)
    /* anti-replay service not enabled */
    (void)replay;
    (void)seq;
    #else
    uint32_t diff = 0;
    uint32_t bitn = 0;
    uint32_t seq_low = replay->hi_seq - ESP_REPLAY_WIN;

    if (seq == 0) {
        return -1;
    }

    if (seq < seq_low) {
        ESP_LOG("error: seq (%d) below window (%d)\n", seq, seq_low);
        return -1;
    }

    /* Simple 32 bit replay window:
     *   seq_low - - - - - - - seq - - - - - - hi_seq
     *   |<----------- ESP_REPLAY_WIN --------------|
     * */
    if (seq < replay->hi_seq) {
        /* seq number within window. */
        bitn = 1U << (replay->hi_seq - seq);

        if ((replay->bitmap & bitn) != 0U) {
            ESP_LOG("error: seq replayed: %u, %d\n", bitn, seq);
            return -1;
        }
        else {
            ESP_DEBUG("info: new seq : %d\n", seq);
            replay->bitmap |= bitn;
        }
    }
    else {
        /* seq number above window. */
        ESP_DEBUG("info: new hi_seq : %d, %d\n", replay->hi_seq, seq);
        diff = seq - replay->hi_seq;
        if (diff < ESP_REPLAY_WIN) {
            /* within a window width, slide up. */
            replay->bitmap = replay->bitmap << diff;
        }
        else {
            /* reset window. */
            replay->bitmap = 1;
        }

        replay->hi_seq = seq;
    }
    #endif /* ESP_REPLAY_WIN */

    return 0;
}

/**
 * Decapsulate an ipv4 ESP packet, transport mode. The packet is
 * unwrapped in-place without extra copying.
 *
 * The ip.proto, ip.len, and frame_len are updated
 * after unwrap.
 *
 * Transport Mode:
 *   before:
 *     _______________________________________________
 *    |orig IP hdr | ESP | UDP |      | ESP     | ESP |
 *    |(PROTO=50)  | hdr | hdr | Data | Trailer | ICV |
 *     -----------------------------------------------
 *                       |<---- encrypted ----->|
 *                 |<--- integrity checked ---->|
 *
 *   after:
 *     _________________________
 *    |orig IP hdr | UDP |      |
 *    |(PROTO=17)  | hdr | Data |
 *     -------------------------
 *
 *   Returns  0 on success.
 *   Returns -1 on error.
 * */
static int
esp_transport_unwrap(struct wolfIP_ip_packet *ip, uint32_t * frame_len)
{
    uint8_t         spi[ESP_SPI_LEN];
    uint32_t        seq = 0;
    wolfIP_esp_sa * esp_sa = NULL;
    uint32_t        esp_len = 0;
    uint8_t         pad_len = 0;
    uint8_t         nxt_hdr = 0;
    uint8_t         iv_len = 0;
    int             err = 0;

    memset(spi, 0, sizeof(spi));

    if (*frame_len <= (ETH_HEADER_LEN + IP_HEADER_LEN)) {
        ESP_LOG("error: esp: malformed frame: %d\n", *frame_len);
        return -1;
    }

    esp_len = *frame_len - ETH_HEADER_LEN - IP_HEADER_LEN;

    /* If not at least SPI and sequence, something wrong. */
    if (esp_len < (ESP_SPI_LEN + ESP_SEQ_LEN)) {
        ESP_LOG("error: esp: malformed packet: %d\n", esp_len);
        return -1;
    }

    /* First 4 bytes are the spi (Security Parameters Index). */
    memcpy(spi, ip->data, sizeof(spi));
    /* Next 4 bytes are the seq (Sequence Number).*/
    memcpy(&seq, ip->data + ESP_SPI_LEN, sizeof(seq));
    seq = ee32(seq);

    for (size_t i = 0; i < in_sa_num; ++i) {
        if (memcmp(spi, in_sa_list[i].spi, sizeof(spi)) == 0) {
            ESP_DEBUG("info: found sa: 0x%02x%02x%02x%02x\n",
                      spi[0], spi[1], spi[2], spi[3]);
            esp_sa = &in_sa_list[i];
            break;
        }
    }

    if (esp_sa == NULL) {
        /* RFC4303:
         *   If no valid Security Association exists for this packet, the
         *   receiver MUST discard the packet; this is an auditable event.
         * */
        ESP_LOG("error: unknown spi: 0x%02x%02x%02x%02x\n",
               spi[0], spi[1], spi[2], spi[3]);
        return -1;
    }

    err = esp_check_replay(&esp_sa->replay, seq);
    if (err) {
        return -1;
    }

    iv_len = esp_iv_len_from_enc(esp_sa->enc);
    {
        /* calculate min expected length based on the security association. */
        uint32_t min_len = 0;

        min_len = (ESP_SPI_LEN + ESP_SEQ_LEN + iv_len +
                   ESP_PADDING_LEN + ESP_NEXT_HEADER_LEN + esp_sa->icv_len);

        if (esp_len < min_len) {
            ESP_LOG("error: esp: got %d, expected >= %d frame len", esp_len,
                   min_len);
            return -1;
        }
    }

    if (esp_sa->icv_len) {
        switch (esp_sa->auth) {
        case ESP_AUTH_MD5_RFC2403:
        case ESP_AUTH_SHA1_RFC2404:
        case ESP_AUTH_SHA256_RFC4868:
            err = esp_check_icv_hmac(esp_sa, ip->data, esp_len);
            break;
        case ESP_AUTH_GCM_RFC4106:
        case ESP_AUTH_GCM_RFC4543:
            /* icv calculated during decrypt */
            err = 0;
            break;
        case ESP_AUTH_NONE:
        default:
            err = -1;
            break;
        }

        if (err) {
            ESP_LOG("error: icv check failed\n");
            return -1;
        }
    }

    /* icv check good, now finish unwrapping esp packet. */
    if (iv_len != 0) {
        /* Decrypt the payload in place. */
        switch(esp_sa->enc) {
        #ifndef NO_DES3
        case ESP_ENC_CBC_DES3:
            err = esp_des3_rfc2451_dec(esp_sa, ip->data, esp_len);
            break;
        #endif /* !NO_DES3 */

        case ESP_ENC_CBC_AES:
            err = esp_aes_rfc3602_dec(esp_sa, ip->data, esp_len);
            break;

        #if defined(WOLFSSL_AESGCM_STREAM)
        case ESP_ENC_GCM_RFC4106:
            err = esp_aes_rfc4106_dec(esp_sa, ip->data, esp_len);
            break;
        #endif /*WOLFSSL_AESGCM_STREAM */

        case ESP_ENC_GCM_RFC4543:
            err = esp_aes_rfc4543_dec(esp_sa, ip->data, esp_len);
            break;

        case ESP_ENC_NONE:
        default:
            ESP_LOG("error: decrypt unsupported: %d\n", esp_sa->enc);
            err = -1;
            break;
        }

        if (err) {
            ESP_LOG("error: esp_decrypt(%02x): %d\n", esp_sa->enc,
                   err);
            return -1;
        }
    }

    /* Payload is now decrypted. We can now parse
     * the ESP trailer for next header and padding. */
    pad_len = *(ip->data + esp_len - esp_sa->icv_len - ESP_NEXT_HEADER_LEN
                - ESP_PADDING_LEN);
    nxt_hdr = *(ip->data + esp_len - esp_sa->icv_len - ESP_NEXT_HEADER_LEN);

    #ifdef DEBUG_ESP
    wolfIP_print_esp(esp_sa, ip->data, esp_len, pad_len, nxt_hdr);
    #endif /* DEBUG_ESP */

    /* move ip payload forward to hide ESP header (SPI, SEQ, IV). */
    memmove(ip->data, ip->data + ESP_SPI_LEN + ESP_SEQ_LEN + iv_len,
            esp_len - (ESP_SPI_LEN + ESP_SEQ_LEN + iv_len));

    /* subtract ESP header from frame_len and ip.len. */
    *frame_len = *frame_len - (iv_len + ESP_SPI_LEN + ESP_SEQ_LEN);
    ip->len = ee16(ip->len) - (iv_len + ESP_SPI_LEN + ESP_SEQ_LEN);

    /* subtract ESP trailer from frame_len and ip.len. */
    *frame_len = *frame_len - (pad_len + ESP_PADDING_LEN +
                               ESP_NEXT_HEADER_LEN + esp_sa->icv_len);
    ip->len = ip->len - (pad_len + ESP_PADDING_LEN +
                         ESP_NEXT_HEADER_LEN + esp_sa->icv_len);

    /* update len, set proto to next header, recalculate iphdr checksum. */
    ip->len = ee16(ip->len);
    ip->proto = nxt_hdr;
    ip->csum = 0;
    iphdr_set_checksum(ip);
    return 0;
}

/**
 * Encapsulate an ipv4 packet with ESP transport mode.
 *
 * Transport Mode:
 *   before:
 *     _________________________
 *    |orig IP hdr |     |      |
 *    |(PROTO=17)  | UDP | Data |
 *     -------------------------
 *
 *   after:
 *     _______________________________________________
 *    |orig IP hdr | ESP |     |      | ESP     | ESP |
 *    |(PROTO=50)  | hdr | UDP | Data | Trailer | ICV |
 *     -----------------------------------------------
 *                       |<---- encrypted ----->|
 *                 |<--- integrity checked ---->|
 *
 *   Returns  0 on success.
 *   Returns  1 if no ipsec policy found (send plaintext)
 *   Returns -1 on error.
 * */
static int
esp_transport_wrap(struct wolfIP_ip_packet *ip, uint16_t * ip_len)
{
    uint8_t   block_len = 0;
    uint16_t  orig_ip_len = *ip_len;
    uint16_t  orig_payload_len = orig_ip_len - IP_HEADER_LEN;
    uint16_t  payload_len = 0;
    uint8_t * payload = ip->data;
    uint8_t   pad_len = 0;
    uint32_t  seq_n = 0; /* sequence num in network order */
    uint16_t  icv_offset = 0;
    wolfIP_esp_sa * esp_sa = NULL;
    uint8_t   iv_len = 0;

    /* todo: priority, proto / port filtering. currently this grabs
     * the first dst match. */
    for (size_t i = 0; i < out_sa_num; ++i) {
        if (ip->dst == ee32(out_sa_list[i].dst)) {
            esp_sa = &out_sa_list[i];
            ESP_DEBUG("info: found out sa: 0x%02x%02x%02x%02x\n",
                      esp_sa->spi[0], esp_sa->spi[1], esp_sa->spi[2],
                      esp_sa->spi[3]);
            break;
        }
    }

    if (esp_sa == NULL) {
        /* no ipsec match found */
        return 1;
    }

    iv_len = esp_iv_len_from_enc(esp_sa->enc);
   /* move ip payload back to make room for ESP header (SPI, SEQ) + IV. */
    memmove(ip->data + ESP_SPI_LEN + ESP_SEQ_LEN + iv_len,
            ip->data, orig_payload_len);

    /* Copy in SPI and sequence number fields. */
    memcpy(payload, esp_sa->spi, sizeof(esp_sa->spi));
    payload += ESP_SPI_LEN;

    seq_n = ee32(esp_sa->replay.oseq);
    memcpy(payload, &seq_n, sizeof(seq_n));
    payload += ESP_SEQ_LEN;
    esp_sa->replay.oseq++;

    if (iv_len) {
        /* skip iv field, will generate later. */
        payload += iv_len;
    }

    block_len = esp_block_len_from_enc(esp_sa->enc);

    if (block_len) {
        /* Block cipher. Calculate padding and encrypted length, then
         * icv_offset. */
        uint32_t enc_len = 0;
        enc_len = iv_len + orig_payload_len + pad_len
                  + ESP_PADDING_LEN + ESP_NEXT_HEADER_LEN;

        /* Determine padding. This needs to be flexible for
         * des3 (8 byte) or aes (16 byte) block sizes.*/
        if (enc_len % block_len) {
            pad_len = block_len - (enc_len % block_len);
        }

        icv_offset = ESP_SPI_LEN + ESP_SEQ_LEN + iv_len
                   + orig_payload_len + pad_len + ESP_PADDING_LEN
                   + ESP_NEXT_HEADER_LEN;
    }
    else {
        /* Stream cipher or auth-only. Calculate the icv offset directly. */
        icv_offset = ESP_SPI_LEN + ESP_SEQ_LEN + iv_len
                   + orig_payload_len + pad_len + ESP_PADDING_LEN
                   + ESP_NEXT_HEADER_LEN;

        /* Determine padding. */
        if (icv_offset % ESP_ICV_ALIGNMENT) {
            pad_len = ESP_ICV_ALIGNMENT - (icv_offset % ESP_ICV_ALIGNMENT);
            icv_offset += pad_len;
        }
    }

    /* Skip past the original payload, add padding. */
    payload += orig_payload_len;

    if (pad_len) {
        /* rfc4303: monotonic increasing sequence for padding. */
        uint8_t i = 0;
        for (i = 0; i < pad_len; ++i) {
            payload[i] = (i + 1);
        }

        payload += pad_len;
    }

    /* ESP trailer. Copy in padding len and next header fields. */
    memcpy(payload, &pad_len, ESP_PADDING_LEN);
    payload += ESP_PADDING_LEN;

    memcpy(payload, &ip->proto, ESP_NEXT_HEADER_LEN);
    payload += ESP_NEXT_HEADER_LEN;

    /* calculate final esp payload length. */
    payload_len =  orig_ip_len - IP_HEADER_LEN;
    payload_len += ESP_SPI_LEN + ESP_SEQ_LEN + iv_len +
                   pad_len + ESP_PADDING_LEN + ESP_NEXT_HEADER_LEN +
                   esp_sa->icv_len;

    /* encrypt from payload to end of ESP trailer. */
    if (iv_len) {
        int err =  -1;

        switch(esp_sa->enc) {
        #ifndef NO_DES3
        case ESP_ENC_CBC_DES3:
            err = esp_des3_rfc2451_enc(esp_sa, ip->data, payload_len);
            break;
        #endif /* !NO_DES3 */

        case ESP_ENC_CBC_AES:
            err = esp_aes_rfc3602_enc(esp_sa, ip->data, payload_len);
            break;

        #if defined(WOLFSSL_AESGCM_STREAM)
        case ESP_ENC_GCM_RFC4106:
            err = esp_aes_rfc4106_enc(esp_sa, ip->data, payload_len);
            break;
        #endif /*WOLFSSL_AESGCM_STREAM */

        case ESP_ENC_GCM_RFC4543:
            err = esp_aes_rfc4543_enc(esp_sa, ip->data, payload_len);
            break;

        case ESP_ENC_NONE:
        default:
            ESP_LOG("error: encrypt unsupported: %d\n", esp_sa->enc);
            err = -1;
            break;
        }

        if (err) {
            ESP_LOG("error: esp_encrypt(%02x): %d\n", esp_sa->enc, err);
            return -1;
        }
        /* Payload is now encrypted. Now calculate ICV.  */
    }

    if (esp_sa->icv_len) {
        uint8_t * icv = NULL;
        int       err = 0;

        switch (esp_sa->auth) {
        case ESP_AUTH_MD5_RFC2403:
        case ESP_AUTH_SHA1_RFC2404:
        case ESP_AUTH_SHA256_RFC4868:
            icv = ip->data + icv_offset;
            err = esp_calc_icv_hmac(icv, esp_sa, ip->data, payload_len);
            break;
        case ESP_AUTH_GCM_RFC4106:
        case ESP_AUTH_GCM_RFC4543:
            /* icv already calculated during encrypt */
            err = 0;
            break;
        case ESP_AUTH_NONE:
        default:
            err = -1;
            break;
        }

        if (err) {
            ESP_LOG("error: icv check: %d\n", err);
            return -1;
        }
    }

    *ip_len = payload_len + IP_HEADER_LEN;

    #ifdef DEBUG_ESP
    wolfIP_print_esp(esp_sa, ip->data, payload_len, pad_len, ip->proto);
    #endif /* DEBUG_ESP */

    return 0;
}

/**
 * Copy frame to new packet so we can expand and wrap in place
 * without stepping on the fifo circular buffer.
 *
 * A better way to do this would be to save extra scratch space in the fifo
 * circular buffer for each packet, so we can expand in place.
 *
 * Returns  0 on success.
 * Returns  1 if no ipsec policy found (send plaintext)
 * Returns -1 on error.
 * */
static int
esp_send(struct wolfIP_ll_dev * ll_dev, const struct wolfIP_ip_packet *ip,
         uint16_t len)
{
    /**
     * 60 is reasonable max ESP overhead (for now), rounded up to 4 bytes.
     *      8 bytes (esp header)
     *   + 16 bytes (iv, prepended to payload)
     *   + 15 bytes (max padding with block cipher)
     *   +  2 bytes (pad_len + nxt_hdr fields)
     *   + 16 bytes (icv)
     * may need to increase depending on algs supported.
     * */
    struct wolfIP_ip_packet * esp;
    uint8_t                   frame[LINK_MTU + 60];
    uint16_t                  ip_final_len = len;
    int                       esp_rc = 0;

    esp = (struct wolfIP_ip_packet *) frame;
    memcpy(esp, ip, sizeof(struct wolfIP_ip_packet) + len);

    esp_rc = esp_transport_wrap(esp, &ip_final_len);

    if (esp_rc) {
        ESP_DEBUG("info: esp_wrap: %d\n", esp_rc);
        return esp_rc;
    }

    /* update len, set proto to ESP 0x32 (50), recalculate iphdr checksum. */
    esp->len = ee16(ip_final_len);
    esp->proto = 0x32;
    esp->csum = 0;
    iphdr_set_checksum(esp);
    /* send it */
    ll_dev->send(ll_dev, esp, ip_final_len + ETH_HEADER_LEN);
    return 0;
}
#endif /* WOLFIP_ESP && !WOLFESP_SRC */

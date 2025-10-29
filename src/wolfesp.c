#if defined(WOLFIP_ESP) && !defined(WOLFESP_SRC)
#define WOLFESP_SRC

#include "wolfesp.h"

static WC_RNG  wc_rng;
static uint8_t rng_inited = 0;

int
esp_init(void)
{
    int ret = 0;

    if (rng_inited == 0) {
        ret = wc_InitRng_ex(&wc_rng, NULL, INVALID_DEVID);

        if (ret) {
            printf("error: wc_InitRng_ex returned: %d\n", ret);
        }
        else {
            rng_inited = 1;
        }
    }

    return ret;
}


static struct wolfIP_esp_sa * in_sa_list = NULL;
static struct wolfIP_esp_sa * out_sa_list = NULL;
static uint16_t               in_sa_num = 0;
static uint16_t               out_sa_num = 0;

void
esp_load_sa_list(struct wolfIP_esp_sa * sa_list, uint16_t num, uint16_t in)
{
    if (in == 1) {
        in_sa_list = sa_list;
        in_sa_num = num;
    }
    else {
        out_sa_list = sa_list;
        out_sa_num = num;
    }

    return;
}

#ifdef WOLFIP_DEBUG_ESP
    #ifdef WOLFIP_DEBUG_ESP_VERBOSE
    static void
    esp_dump_data_verbose(const char * what, const uint8_t * data,
                          size_t data_len)
    {
        printf("info: %s: \n", what);

        for (size_t i = 0; i < data_len; ++i) {
            printf("%02x", data[i]);
            if (i && ((i + 1) % 8) == 0) {
                printf("\n");
            }
        }

        printf("\n");
        return;
    }
    #endif /* WOLFIP_DEBUG_ESP_VERBOSE */

static void
esp_dump_data(const char * what, const uint8_t * data, size_t data_len)
{
    printf("info: %s: 0x", what);

    for (size_t i = 0; i < data_len; ++i) {
        printf("%02x", data[i]);
    }

    printf("\n");
    return;
}

#define esp_print_sep \
    printf("+------------------+\n")
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
    printf(esp_str_4hex " (%s, %d bytes)\n",
           val[0], val[1], val[2], val[3], fld, val_len);
    if (val_len > 4) {
        for (size_t i = 4; i < val_len; i += 4) {
            if (i > 16 || (i + 4) > val_len) {
                printf(esp_str_skip "\n");
                break;
            }

            printf(esp_str_4hex"\n",
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
static void wolfIP_print_esp(const struct wolfIP_esp_sa * esp_sa,
                             const uint8_t * esp_data, uint32_t esp_len,
                             uint8_t pad_len, uint8_t nxt_hdr)
{
    const uint8_t * spi     = esp_data;
    const uint8_t * seq     = esp_data + ESP_SPI_LEN;
    const uint8_t * payload = esp_data + ESP_SPI_LEN + ESP_SEQ_LEN;
    const uint8_t * iv = NULL;
    const uint8_t * icv = NULL;
    const uint8_t * padding = NULL;
    uint32_t        payload_len = esp_len - ESP_SPI_LEN - ESP_SEQ_LEN
                                  - pad_len - ESP_PADDING_LEN
                                  - ESP_NEXT_HEADER_LEN ;

    if (esp_sa->iv_len) {
        iv = payload;
        payload += esp_sa->iv_len;
        payload_len -= esp_sa->iv_len;
    }

    if (esp_sa->icv_len) {
        icv = esp_data + esp_len - esp_sa->icv_len;
    }

    /* last 2 bytes of padding */
    padding = esp_data + esp_len - esp_sa->icv_len - 4;

    printf("esp packet: (%d bytes)\n", esp_len);

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
        esp_print_field("iv", iv, esp_sa->iv_len);
    }

    esp_print_field("payload", payload, payload_len);

   /**  ESP trailer
    *     _____________________________________
    *    | Padding           | Pad    | Next   |
    *    | (variable length) | Length | Header |
    *     ------------------------------------- */
    esp_print_sep;
    printf(esp_pad_fld " (padding last 2 bytes, pad len, nxt hdr)\n",
           padding[0], padding[1], pad_len, nxt_hdr);

    if (icv) {
        esp_print_field("icv", icv, esp_sa->icv_len);
    }

    esp_print_sep;

    return;
}
#endif /* WOLFIP_DEBUG_ESP */

uint8_t
esp_block_len_from_enc(esp_enc_t enc)
{
    uint8_t block_len = 0;

    switch (enc) {
    case ESP_ENC_NONE:
        block_len = 0;
        break;
    case ESP_ENC_CBC_AES:
        block_len = WC_AES_BLOCK_SIZE;
        break;
    case ESP_ENC_CBC_DES3:
        block_len = DES_BLOCK_SIZE;
        break;
    case ESP_ENC_GCM_RFC4106:
    case ESP_ENC_GCM_RFC4543:
    default:
        block_len = 0;
        break;
    }

    return block_len;
}

/*
 * esp_data covers from start of ESP header to end of ESP trailer, but does not
 * include the ESP ICV after trailer.
 * */
static int
esp_calc_icv_hmac(uint8_t * hash, const struct wolfIP_esp_sa * esp_sa,
                  const uint8_t * esp_data, uint32_t esp_len)
{
    /* SHA1 and MD5 have these digest sizes:
     *   - WC_SHA_DIGEST_SIZE 20 bytes
     *   - WC_MD5_DIGEST_SIZE 16 bytes
     * */
    Hmac      hmac;
    int       wolf_ret = 0;
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
        printf("error: esp_calc_icv_hmac: invalid auth: %d\n",
               esp_sa->auth);
        return -1;
    }

    /* the icv is not included in icv calculation. */
    auth_len = esp_len - esp_sa->icv_len;

    wolf_ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);

    if (wolf_ret) {
        printf("error: wc_HmacSetKey returned %d\n", wolf_ret);
        goto calc_icv_hmac_end;
    }

    wolf_ret = wc_HmacSetKey(&hmac, type, esp_sa->auth_key,
                             esp_sa->auth_key_len);
    if (wolf_ret) {
        printf("error: wc_HmacSetKey returned %d\n", wolf_ret);
        goto calc_icv_hmac_end;
    }

    /* Now calculate the ICV. The ICV covers from SPI to Next Header,
     * inclusive. */
    wolf_ret = wc_HmacUpdate(&hmac, (const byte *)esp_data, auth_len);
    if (wolf_ret) {
        printf("error: wc_HmacUpdate returned %d\n", wolf_ret);
        goto calc_icv_hmac_end;
    }

    wolf_ret = wc_HmacFinal(&hmac, hash);
    if (wolf_ret) {
        printf("error: wc_HmacFinal returned %d\n", wolf_ret);
        goto calc_icv_hmac_end;
    }

calc_icv_hmac_end:
    wc_HmacFree(&hmac);

    return wolf_ret;
}

static int
esp_const_memcmp(const uint8_t * vec_a, const uint8_t * vec_b, uint32_t len)
{
    uint32_t i;
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
 * Get pointer to raw encryption ESP payload, skipping ESP header and IV.
 * */
#define esp_enc_payload(data, iv_len) \
        (data) + ESP_SPI_LEN + ESP_SEQ_LEN + (iv_len)

static int
esp_aes_rfc3602_dec(const struct wolfIP_esp_sa * esp_sa, uint8_t * esp_data,
                    uint32_t esp_len)
{
    Aes       cbc_dec;
    int       ret = -1;
    uint8_t   icv_len = esp_sa->icv_len;
    uint8_t   iv_len = esp_sa->iv_len;
    uint8_t * enc_payload = NULL;
    uint8_t * iv = NULL;
    uint16_t  enc_len = 0;
    uint8_t   inited = 0;

    #ifdef WOLFIP_DEBUG_ESP
    printf("info: aes cbc dec\n");
    #endif /* WOLFIP_DEBUG_ESP */

    enc_len = esp_enc_len(esp_len, iv_len, icv_len);
    enc_payload = esp_enc_payload(esp_data, iv_len);
    iv = esp_enc_iv(esp_data, iv_len);

    ret = wc_AesInit(&cbc_dec, NULL, INVALID_DEVID);

    if (ret != 0) {
        printf("error: wc_AesInit returned: %d\n", ret);
        goto aes_dec_out;
    }

    inited = 1;
    ret = wc_AesSetKey(&cbc_dec, esp_sa->enc_key, esp_sa->enc_key_len,
                       iv, AES_DECRYPTION);

    if (ret != 0) {
        printf("error: wc_AesSetKey returned: %d\n", ret);
        goto aes_dec_out;
    }

    /* decrypt in place. */
    ret = wc_AesCbcDecrypt(&cbc_dec, enc_payload, enc_payload, enc_len);

    if (ret != 0) {
        printf("error: wc_AesCbcDecrypt returned: %d\n", ret);
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
esp_aes_rfc3602_enc(const struct wolfIP_esp_sa * esp_sa, uint8_t * esp_data,
                    uint32_t esp_len)
{
    Aes          cbc_enc;
    int          ret = -1;
    uint8_t      icv_len = esp_sa->icv_len;
    uint8_t      iv_len = esp_sa->iv_len;
    uint8_t *    enc_payload = NULL;
    uint8_t *    iv = NULL;
    uint16_t     enc_len = 0;
    uint8_t      inited = 0;

    #ifdef WOLFIP_DEBUG_ESP
    printf("info: aes cbc enc\n");
    #endif /* WOLFIP_DEBUG_ESP */

    enc_len = esp_enc_len(esp_len, iv_len, icv_len);
    enc_payload = esp_enc_payload(esp_data, iv_len);
    iv = esp_enc_iv(esp_data, iv_len);

    /* Generate random iv block for cbc method. */
    ret = wc_RNG_GenerateBlock(&wc_rng, iv, iv_len);

    if (ret) {
        printf("error: wc_RNG_GenerateBlock returned: %d\n", ret);
        goto aes_enc_out;
    }

    ret = wc_AesInit(&cbc_enc, NULL, INVALID_DEVID);

    if (ret != 0) {
        printf("error: wc_AesInit returned: %d\n", ret);
        goto aes_enc_out;
    }

    inited = 1;
    ret = wc_AesSetKey(&cbc_enc, esp_sa->enc_key, AES_BLOCK_SIZE,
                       iv, AES_ENCRYPTION);

    if (ret != 0) {
        printf("error: wc_AesSetKey returned: %d\n", ret);
        goto aes_enc_out;
    }

    ret = wc_AesCbcEncrypt(&cbc_enc, enc_payload, enc_payload, enc_len);

    if (ret != 0) {
        printf("error: wc_AesCbcEncrypt returned: %d\n", ret);
        goto aes_enc_out;
    }

aes_enc_out:
    if (inited) {
        wc_AesFree(&cbc_enc);
        inited = 0;
    }

    return ret;
}


/**
 * esp_data covers from start of ESP header to end of ESP trailer, but does not
 * include the ESP ICV after trailer.
 * */
static int
esp_check_icv_hmac(const struct wolfIP_esp_sa * esp_sa, uint8_t * esp_data,
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
    if (rc) {
        #ifdef WOLFIP_DEBUG_ESP
        esp_dump_data("icv not matched", hash, esp_sa->icv_len);
        #endif /* WOLFIP_DEBUG_ESP */
    }

    return rc;
}

/**
 * Decapsulate an ipv4 ESP packet. The packet is
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
static int esp_unwrap(struct wolfIP *s, struct wolfIP_ip_packet *ip,
                      uint32_t * frame_len)
{
    uint8_t                spi[ESP_SPI_LEN];
    uint32_t               seq = 0;
    struct wolfIP_esp_sa * esp_sa = NULL;
    uint32_t               esp_len = 0;
    uint8_t                pad_len = 0;
    uint8_t                nxt_hdr = 0;
    int                    rc = 0;

    memset(spi, 0, sizeof(spi));

    if (*frame_len <= (ETH_HEADER_LEN + IP_HEADER_LEN)) {
        #ifdef WOLFIP_DEBUG_ESP
        printf("error: esp: malformed frame: %d\n", *frame_len);
        #endif /* WOLFIP_DEBUG_ESP */
        return -1;
    }

    esp_len = *frame_len - ETH_HEADER_LEN - IP_HEADER_LEN;

    /* If not at least SPI and sequence, something wrong. */
    if (esp_len < (ESP_SPI_LEN + ESP_SEQ_LEN)) {
        #ifdef WOLFIP_DEBUG_ESP
        printf("error: esp: malformed packet: %d\n", esp_len);
        #endif /* WOLFIP_DEBUG_ESP */
        return -1;
    }

    /* First 4 bytes are the spi (Security Parameters Index). */
    memcpy(spi, ip->data, sizeof(spi));
    /* Next 4 bytes are the seq (Sequence Number).*/
    memcpy(&seq, ip->data + ESP_SPI_LEN, sizeof(seq));
    seq = ee32(seq);

    for (size_t i = 0; i < in_sa_num; ++i) {
        if (memcmp(spi, in_sa_list[i].spi, sizeof(spi)) == 0) {
            #ifdef WOLFIP_DEBUG_ESP
            printf("info: found sa: 0x%02x%02x%02x%02x\n",
                   spi[0], spi[1], spi[2], spi[3]);
            #endif /* WOLFIP_DEBUG_ESP */
            esp_sa = &in_sa_list[i];
            break;
        }
    }

    if (esp_sa == NULL) {
        /**
         * RFC4303:
         *   If no valid Security Association exists for this packet, the
         *   receiver MUST discard the packet; this is an auditable event.
         * */
        printf("error: unknown spi: 0x%02x%02x%02x%02x\n",
               spi[0], spi[1], spi[2], spi[3]);
        return -1;
    }

    {
        /* calculate min expected length based on the security association. */
        uint32_t min_len = 0;

        min_len = (ESP_SPI_LEN + ESP_SEQ_LEN + esp_sa->iv_len +
                   ESP_PADDING_LEN + ESP_NEXT_HEADER_LEN + esp_sa->icv_len);

        if (esp_len < min_len) {
            printf("error: esp: got %d, expected >= %d frame len", esp_len,
                   min_len);
            return -1;
        }
    }

    if (esp_sa->icv_len) {
        rc = esp_check_icv_hmac(esp_sa, ip->data, esp_len);
        if (rc) {
            printf("error: icv check failed\n");
            return -1;
        }
    }

    if (esp_sa->iv_len != 0) {
        /* Decrypt the payload in place. */
        int err = -1;

        switch(esp_sa->enc) {
        case ESP_ENC_CBC_AES:
            err = esp_aes_rfc3602_dec(esp_sa, ip->data, esp_len);
            break;

        case ESP_ENC_NONE:
        default:
            printf("error: decrypt: invalid enc: %d\n", esp_sa->enc);
            err = -1;
            break;
        }

        if (err) {
            printf("error: esp_decrypt(%02x) returned: %d\n", esp_sa->enc, err);
            return -1;
        }

        /* Payload is now decrypted. We can now parse
         * the ESP trailer for next header and padding. */
    }

    /* icv check good, now finish unwrapping esp packet. */
    pad_len = *(ip->data + esp_len - esp_sa->icv_len - ESP_NEXT_HEADER_LEN
                - ESP_PADDING_LEN);
    nxt_hdr = *(ip->data + esp_len - esp_sa->icv_len - ESP_NEXT_HEADER_LEN);

    #ifdef WOLFIP_DEBUG_ESP
    wolfIP_print_esp(esp_sa, ip->data, esp_len, pad_len, nxt_hdr);
    #endif /* WOLFIP_DEBUG_ESP */

    #ifdef WOLFIP_DEBUG_ESP_VERBOSE
    esp_dump_data_verbose("esp_packet before unwrap", ip->data, esp_len);
    #endif /* WOLFIP_DEBUG_ESP_VERBOSE */

    /* move ip payload forward to hide ESP header (SPI, SEQ, IV). */
    memmove(ip->data, ip->data + ESP_SPI_LEN + ESP_SEQ_LEN + esp_sa->iv_len,
            esp_len - (ESP_SPI_LEN + ESP_SEQ_LEN + esp_sa->iv_len));

    /* subtract ESP header from frame_len and ip.len. */
    *frame_len = *frame_len - (esp_sa->iv_len + ESP_SPI_LEN + ESP_SEQ_LEN);
    ip->len = ee16(ip->len) - (esp_sa->iv_len + ESP_SPI_LEN + ESP_SEQ_LEN);

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

    #ifdef WOLFIP_DEBUG_ESP_VERBOSE
    esp_dump_data_verbose("esp_packet after unwrap", ip->data,
                          *frame_len - ETH_HEADER_LEN - IP_HEADER_LEN);
    #endif /* WOLFIP_DEBUG_ESP_VERBOSE */

    (void)s;
    return 0;
}

/**
 * Encapsulate an ipv4 packet with ESP.
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
 *   Returns -1 on error.
 * */
static int esp_wrap(struct wolfIP_ip_packet *ip, uint16_t * ip_len)
{
    uint8_t   block_len = 0;
    uint16_t  orig_ip_len = *ip_len;
    uint16_t  orig_payload_len = orig_ip_len - IP_HEADER_LEN;
    uint16_t  payload_len = 0;
    uint8_t * payload = ip->data;
    uint8_t   pad_len = 0;
    uint32_t  seq_n = 0; /* sequence num in network order */
    uint16_t  icv_offset = 0;
    struct wolfIP_esp_sa * esp_sa = NULL;

    /* TODO: priority, tcp/udp port-filtering? */
    for (size_t i = 0; i < out_sa_num; ++i) {
        if (ip->dst == out_sa_list[i].dst) {
            esp_sa = &out_sa_list[i];
            #ifdef WOLFIP_DEBUG_ESP
            printf("info: found out sa: 0x%02x%02x%02x%02x\n",
                   esp_sa->spi[0], esp_sa->spi[1], esp_sa->spi[2], esp_sa->spi[3]);
            #endif /* WOLFIP_DEBUG_ESP */
            break;
        }
    }

    if (esp_sa == NULL) {
        /* nothing to do */
        #ifdef WOLFIP_DEBUG_ESP
        char ip_str[32];
        memset(ip_str, '\0', sizeof(ip_str));
        iptoa(ip->dst, ip_str);
        printf("info: ip dst not found: %s\n", ip_str);
        #endif /* WOLFIP_DEBUG_ESP */
        return 0;
    }

    #ifdef WOLFIP_DEBUG_ESP_VERBOSE
    esp_dump_data_verbose("ip packet before wrap", ip->data, orig_payload_len);
    #endif /* WOLFIP_DEBUG_ESP_VERBOSE */

    #if 0
    /* return early, do nothing. */
    return 0;
    #endif

   /* move ip payload back to make room for ESP header (SPI, SEQ) + IV. */
    memmove(ip->data + ESP_SPI_LEN + ESP_SEQ_LEN + esp_sa->iv_len,
            ip->data, orig_payload_len);

    /* Copy in SPI and sequence number fields. */
    memcpy(payload, esp_sa->spi, sizeof(esp_sa->spi));
    payload += ESP_SPI_LEN;

    esp_sa->oseq++;
    seq_n = ee32(esp_sa->oseq);
    memcpy(payload, &seq_n, sizeof(seq_n));
    payload += ESP_SEQ_LEN;

    if (esp_sa->iv_len) {
        /* skip iv field, will generate later. */
        payload += esp_sa->iv_len;
    }

    block_len = esp_block_len_from_enc(esp_sa->enc);

    if (block_len) {
        /* Block cipher. Calculate padding and encrypted length, then
         * icv_offset. */
        uint32_t enc_len = 0;
        enc_len = esp_sa->iv_len + orig_payload_len + pad_len
                  + ESP_PADDING_LEN + ESP_NEXT_HEADER_LEN;

        /* Determine padding. This needs to be flexible for
         * des3 (8 byte) or aes (16 byte) block sizes.*/
        if (enc_len % block_len) {
            pad_len = block_len - (enc_len % block_len);
        }

        icv_offset = ESP_SPI_LEN + ESP_SEQ_LEN + esp_sa->iv_len
                   + orig_payload_len + pad_len + ESP_PADDING_LEN
                   + ESP_NEXT_HEADER_LEN;
    }
    else {
        /* Stream cipher or auth-only. Calculate the icv offset directly. */
        icv_offset = ESP_SPI_LEN + ESP_SEQ_LEN + esp_sa->iv_len
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
    payload_len += ESP_SPI_LEN + ESP_SEQ_LEN + esp_sa->iv_len +
                   pad_len + ESP_PADDING_LEN + ESP_NEXT_HEADER_LEN +
                   esp_sa->icv_len;

    /* encrypt from payload to end of ESP trailer. */
    if (esp_sa->iv_len) {
        int err =  -1;

        switch(esp_sa->enc) {
        case ESP_ENC_CBC_AES:
            err = esp_aes_rfc3602_enc(esp_sa, ip->data, payload_len);
            break;

        case ESP_ENC_NONE:
        default:
            printf("error: encrypt: invalid enc: %d\n", esp_sa->enc);
            err = -1;
            break;
        }

        if (err) {
            printf("error: esp_encrypt(%02x) returned: %d\n", esp_sa->enc, err);
            return -1;
        }

        /* Payload is now encrypted. Now calculate ICV.  */
    }

    if (esp_sa->icv_len) {
        uint8_t * icv = NULL;
        int       rc = 0;

        icv = ip->data + icv_offset;

        rc = esp_calc_icv_hmac(icv, esp_sa, ip->data, payload_len);
        if (rc) {
            return -1;
        }
    }

    *ip_len = payload_len + IP_HEADER_LEN;

    #ifdef WOLFIP_DEBUG_ESP
    wolfIP_print_esp(esp_sa, ip->data, payload_len, pad_len, ip->proto);
    #endif /* WOLFIP_DEBUG_ESP */

    #ifdef WOLFIP_DEBUG_ESP_VERBOSE
    esp_dump_data_verbose("ip packet after wrap", ip->data, payload_len);
    #endif /* WOLFIP_DEBUG_ESP_VERBOSE */

    return 0;
}

/**
 * Copy frame to new packet so we can expand and wrap in place
 * without stepping on the fifo tcp circular buffer.
 * */
static int esp_output(struct wolfIP *s, const struct wolfIP_ip_packet *ip,
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

    esp_rc = esp_wrap(esp, &ip_final_len);

    if (esp_rc) {
        #ifdef WOLFIP_DEBUG_ESP
        printf("error: esp_wrap returned: %d\n", esp_rc);
        #endif /* WOLFIP_DEBUG_ESP */
        return esp_rc;
    }

    /* update len, set proto to ESP 0x32 (50), recalculate iphdr checksum. */
    esp->len = ee16(ip_final_len);
    esp->proto = 0x32;
    esp->csum = 0;
    iphdr_set_checksum(esp);

    s->ll_dev.send(&s->ll_dev, esp, ip_final_len + ETH_HEADER_LEN);

    return 0;
}
#endif /* WOLFIP_ESP && !WOLFESP_SRC */

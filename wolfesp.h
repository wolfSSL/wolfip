#ifndef WOLFESP_H
#define WOLFESP_H

#define ESP_SPI_LEN          4
#define ESP_SEQ_LEN          4
#define ESP_PADDING_LEN      1
#define ESP_NEXT_HEADER_LEN  1
#define ESP_ICV_ALIGNMENT    4
/* hmac-[sha256, sha1, md5]-96*/
#define ESP_ICVLEN_HMAC_96   12
#define ESP_ICVLEN_HMAC_128  16
#define WOLFIP_ESP_NUM_SA    2

/* aes-128 */
#define ESP_128_KEY_LEN            16
#define ESP_128_IV_LEN             16

/* gcm */
#define ESP_GCM_RFC4106_SALT_LEN   4
#define ESP_GCM_RFC4106_IV_LEN     8
#define ESP_GCM_RFC4106_NONCE_LEN (ESP_GCM_RFC4106_SALT_LEN \

typedef enum {
  ESP_ENC_NONE = 0,
  ESP_ENC_CBC_AES,
  ESP_ENC_CBC_DES3,
  ESP_ENC_GCM_RFC4106,
  ESP_ENC_GCM_RFC4543, /* placeholder to indicate gmac auth. */
} esp_enc_t;

typedef enum {
  ESP_AUTH_NONE = 0,
  ESP_AUTH_MD5_RFC2403,    /* hmac(md5)-96 */
  ESP_AUTH_SHA1_RFC2404,   /* hmac(sha1)-96 */
  ESP_AUTH_SHA256_RFC4868, /* hmac(sha256)-N, N=96,128  */
  ESP_AUTH_GCM_RFC4106,    /* placeholder to indicate gcm auth. */
  ESP_AUTH_GCM_RFC4543     /* rfc4543 gmac */
} esp_auth_t;

/* Minimal ESP Security Association structure.
 * Supports only transport mode.
 * */
struct wolfIP_esp_sa {
    uint8_t    spi[ESP_SPI_LEN]; /* security parameter index */
    ip4        src; /* ip src and dst in network byte order */
    ip4        dst;
    uint32_t   oseq; /* outbound sequence number */
    uint32_t   seq; /* inbound sequence number */
    uint8_t    iv_len;
    esp_enc_t  enc;
    uint8_t    enc_key[32];
    uint8_t    enc_key_len;
    esp_auth_t auth;
    uint8_t    auth_key[32];
    uint8_t    auth_key_len;
    uint8_t    icv_len;
    #if 0
    uint8_t    pre_iv[ESP_GCM_RFC4106_IV_LEN]; /* unique salt that is xor'ed with
                                                * oseq to generate the iv. */
    #endif
};

int  esp_init(void);
void esp_load_sa_list(struct wolfIP_esp_sa * sa_list, uint16_t num, uint16_t in);

#endif /* !WOLFESP_H */

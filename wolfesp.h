#ifndef WOLFESP_H
#define WOLFESP_H

/* size of static pool */
#define WOLFIP_ESP_NUM_SA  3
/* ESP packet parameters */
#define ESP_SPI_LEN               4
#define ESP_SEQ_LEN               4
#define ESP_PADDING_LEN           1
#define ESP_NEXT_HEADER_LEN       1
#define ESP_ICV_ALIGNMENT         4
/* hmac-[sha256, sha1, md5]-96*/
#define ESP_ICVLEN_HMAC_96        12
#define ESP_ICVLEN_HMAC_128       16
/* des3-cbc */
#ifndef NO_DES3
#define ESP_DES3_KEY_LEN          24
#define ESP_DES3_IV_LEN            8
#endif /* !NO_DES3 */
/* max key size */
#define ESP_MAX_KEY_LEN           32
/* aes-cbc */
#define ESP_CBC_RFC3602_IV_LEN    16
/* aes-gcm */
#define ESP_GCM_RFC4106_ICV_LEN   16
#define ESP_GCM_RFC4106_SALT_LEN  4
#define ESP_GCM_RFC4106_IV_LEN    8
#define ESP_GCM_RFC4106_NONCE_LEN (ESP_GCM_RFC4106_SALT_LEN \
                                 + ESP_GCM_RFC4106_IV_LEN)

typedef enum {
  ESP_ENC_NONE = 0,
  ESP_ENC_CBC_AES,
  #ifndef NO_DES3
  ESP_ENC_CBC_DES3,
  #endif /* !NO_DES3 */
  #if defined(WOLFSSL_AESGCM_STREAM)
  ESP_ENC_GCM_RFC4106,
  #endif /* WOLFSSL_AESGCM_STREAM */
  ESP_ENC_GCM_RFC4543, /* placeholder to indicate gmac auth. */
} esp_enc_t;

typedef enum {
  ESP_AUTH_NONE = 0,
  ESP_AUTH_MD5_RFC2403,    /* hmac(md5)-96 */
  ESP_AUTH_SHA1_RFC2404,   /* hmac(sha1)-96 */
  ESP_AUTH_SHA256_RFC4868, /* hmac(sha256)-N, N=96,128  */
  #if defined(WOLFSSL_AESGCM_STREAM)
  ESP_AUTH_GCM_RFC4106,    /* placeholder to indicate gcm auth. */
  #endif /* WOLFSSL_AESGCM_STREAM */
  ESP_AUTH_GCM_RFC4543     /* rfc4543 gmac */
} esp_auth_t;

/* simple static 32 bit replay window */
#define ESP_MAX_32_SEQ  0xffffffffUL
#define ESP_REPLAY_WIN  32U

struct replay_t {
  uint32_t  bitmap; /* inbound sequence bitmap */
  uint32_t  hi_seq; /* inbound high sequence number */
  uint32_t  oseq; /* outbound sequence number */
};

typedef struct replay_t replay_t;

#define esp_replay_init(r) \
  (r).bitmap = 0U; (r).hi_seq = ESP_REPLAY_WIN; (r).oseq = 1U; \

/* Minimal ESP Security Association structure.
 * Supports only transport mode.
 * todo: support port/proto filtering, and priority sorting. */
struct wolfIP_esp_sa {
    uint8_t    spi[ESP_SPI_LEN]; /* security parameter index */
    ip4        src; /* ip src and dst in network byte order */
    ip4        dst;
    replay_t   replay;
    esp_enc_t  enc;
    uint8_t    enc_key[ESP_MAX_KEY_LEN + ESP_GCM_RFC4106_SALT_LEN];
    uint8_t    enc_key_len;
    esp_auth_t auth;
    uint8_t    auth_key[ESP_MAX_KEY_LEN];
    uint8_t    auth_key_len;
    uint8_t    icv_len;
    uint8_t    pre_iv[ESP_GCM_RFC4106_IV_LEN]; /* unique salt that is xor'ed
                                                * with oseq to generate iv. */
};
typedef struct wolfIP_esp_sa wolfIP_esp_sa;

int  wolfIP_esp_init(void);
void wolfIP_esp_sa_del(int in, uint8_t * spi);
void wolfIP_esp_sa_del_all(void);
int  wolfIP_esp_sa_new_gcm(int in, uint8_t * spi, ip4 src, ip4 dst,
                           esp_enc_t enc, uint8_t * enc_key,
                           uint8_t enc_key_len);
int  wolfIP_esp_sa_new_cbc_hmac(int in, uint8_t * spi, ip4 src, ip4 dst,
                                uint8_t * enc_key, uint8_t enc_key_len,
                                esp_auth_t auth, uint8_t * auth_key,
                                uint8_t auth_key_len, uint8_t icv_len);
int  wolfIP_esp_sa_new_des3_hmac(int in, uint8_t * spi, ip4 src, ip4 dst,
                                 uint8_t * enc_key, esp_auth_t auth,
                                 uint8_t * auth_key, uint8_t auth_key_len,
                                 uint8_t icv_len);
#endif /* !WOLFESP_H */

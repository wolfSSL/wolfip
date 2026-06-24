/* test_supplicant_eap_tls.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * End-to-end WPA2-Enterprise (EAP-TLS) integration test.
 *
 * The wolfIP supplicant runs unmodified in auth_mode = WOLFIP_AUTH_EAP_TLS.
 * In the same process, a fake EAP authenticator drives the AP side:
 *
 *   EAPOL-Start         <-- supplicant (after kick)
 *   EAP-Req/Identity    --> supplicant
 *   EAP-Resp/Identity   <-- supplicant
 *   EAP-Req/EAP-TLS S   --> supplicant
 *   ... TLS handshake fragmented through EAP-TLS Request/Response ...
 *   EAP-Success         --> supplicant
 *   <both sides export MSK; PMK = MSK[0..31]>
 *   EAPOL-Key M1        --> supplicant
 *   EAPOL-Key M2        <-- supplicant (carries RSN IE)
 *   EAPOL-Key M3        --> supplicant (carries AP RSN IE + wrapped GTK)
 *   EAPOL-Key M4        <-- supplicant
 *   State: AUTHENTICATED, PTK + GTK installed via wifi_ops.
 *
 * Verifies the seam between EAP-Success and 4-way: the PMK derived from
 * the TLS MSK on both sides must let the 4-way handshake's MIC verify.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include "wpa_crypto.h"
#include "eapol.h"
#include "rsn_ie.h"
#include "eap.h"
#include "eap_tls.h"
#include "supplicant.h"
#include "test_eap_certs.h"

/* ---- shared mailbox between supplicant and authenticator ---- */

struct mbox {
    uint8_t buf[2048];
    size_t  len;
    int     has;
};
static struct mbox to_supp;
static struct mbox to_auth;

/* Supplicant TX callback: forwards EAPOL frames to the authenticator. */
static int supp_send_cb(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    if (to_auth.has) return -1;
    if (len > sizeof(to_auth.buf)) return -1;
    memcpy(to_auth.buf, frame, len);
    to_auth.len = len;
    to_auth.has = 1;
    return 0;
}

struct install_rec {
    int      pairwise_set;
    int      group_set;
    uint8_t  tk[WPA_TK_LEN];
    uint8_t  gtk[WPA_GTK_MAX_LEN];
    size_t   gtk_len;
};
static struct install_rec installs;

static int supp_install_cb(void *ctx, wolfip_supplicant_keytype_t kt,
                           uint8_t idx, const uint8_t *key, size_t len)
{
    (void)ctx; (void)idx;
    if (kt == SUPP_KEY_PAIRWISE) {
        if (len != WPA_TK_LEN) return -1;
        memcpy(installs.tk, key, len);
        installs.pairwise_set = 1;
    }
    else {
        if (len == 0 || len > WPA_GTK_MAX_LEN) return -1;
        memcpy(installs.gtk, key, len);
        installs.gtk_len = len;
        installs.group_set = 1;
    }
    return 0;
}

/* ---- fake EAP authenticator state ---- */

typedef enum {
    AUTH_IDLE,
    AUTH_WAIT_IDENTITY_RESP,
    AUTH_TLS,
    AUTH_EAP_DONE,
    AUTH_4WAY_WAIT_M2,
    AUTH_4WAY_WAIT_M4,
    AUTH_COMPLETE
} auth_state_t;

struct auth_io {
    uint8_t buf[8192];
    size_t  filled;
    size_t  drained;
};

struct authenticator {
    auth_state_t state;
    uint8_t      next_eap_id;
    uint8_t      last_eap_id;          /* mirrors what supp last received */

    WOLFSSL_CTX *ssl_ctx;
    WOLFSSL     *ssl;
    struct auth_io tls_in;             /* TLS bytes received from supp     */
    struct auth_io tls_out;            /* TLS bytes for next EAP-Request   */

    /* PSK / 4-way handshake state. */
    uint8_t  pmk[WPA_PMK_LEN];
    uint8_t  aa[WPA_MAC_LEN];
    uint8_t  sa[WPA_MAC_LEN];
    uint8_t  anonce[WPA_NONCE_LEN];
    uint8_t  snonce[WPA_NONCE_LEN];
    uint8_t  replay[WPA_REPLAY_CTR_LEN];
    uint8_t  gtk[16];
    uint8_t  rsn_ie[64];
    size_t   rsn_ie_len;
    struct wpa_ptk ptk;
    int      have_ptk;
};

/* wolfSSL custom IO for the authenticator's server-side session. */
static int auth_io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    struct authenticator *a = (struct authenticator *)ctx;
    size_t avail, take;
    (void)ssl;
    if (a->tls_in.filled <= a->tls_in.drained) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    avail = a->tls_in.filled - a->tls_in.drained;
    take = (size_t)sz < avail ? (size_t)sz : avail;
    memcpy(buf, a->tls_in.buf + a->tls_in.drained, take);
    a->tls_in.drained += take;
    if (a->tls_in.drained == a->tls_in.filled) {
        a->tls_in.drained = 0;
        a->tls_in.filled = 0;
    }
    return (int)take;
}

static int auth_io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    struct authenticator *a = (struct authenticator *)ctx;
    size_t cap;
    (void)ssl;
    if (a->tls_out.filled > sizeof(a->tls_out.buf)) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    cap = sizeof(a->tls_out.buf) - a->tls_out.filled;
    if ((size_t)sz > cap) sz = (int)cap;
    memcpy(a->tls_out.buf + a->tls_out.filled, buf, (size_t)sz);
    a->tls_out.filled += (size_t)sz;
    return sz;
}

/* ---- helpers to ship frames TO the supplicant ---- */

static int put_to_supp(const uint8_t *frame, size_t len)
{
    if (to_supp.has) return -1;
    if (len > sizeof(to_supp.buf)) return -1;
    memcpy(to_supp.buf, frame, len);
    to_supp.len = len;
    to_supp.has = 1;
    return 0;
}

/* Build a complete EAPOL/EAP frame and put it in the mailbox.
 * eap_payload is the EAP packet body (code|id|len|type|type-data). */
static int auth_send_eap(const uint8_t *eap_payload, size_t eap_len)
{
    uint8_t frame[4 + 1024];
    if (eap_len + 4 > sizeof(frame)) return -1;
    frame[0] = EAPOL_PROTO_VER;
    frame[1] = EAPOL_TYPE_EAP_PACKET;
    frame[2] = (uint8_t)((eap_len >> 8) & 0xFFU);
    frame[3] = (uint8_t)(eap_len & 0xFFU);
    memcpy(frame + 4, eap_payload, eap_len);
    return put_to_supp(frame, eap_len + 4);
}

static int auth_send_eap_request_identity(struct authenticator *a)
{
    uint8_t eap[5];
    a->next_eap_id++;
    eap[0] = EAP_CODE_REQUEST;
    eap[1] = a->next_eap_id;
    eap[2] = 0x00; eap[3] = 0x05;
    eap[4] = EAP_TYPE_IDENTITY;
    return auth_send_eap(eap, sizeof(eap));
}

static int auth_send_eap_request_tls(struct authenticator *a,
                                     uint8_t flags,
                                     const uint8_t *tls_data, size_t tls_len,
                                     int include_length, uint32_t total_len)
{
    uint8_t eap[1100];
    size_t  off = 0;
    size_t  total;
    a->next_eap_id++;
    if (1 + (include_length ? 4 : 0) + tls_len + 5 > sizeof(eap)) return -1;
    eap[off++] = EAP_CODE_REQUEST;
    eap[off++] = a->next_eap_id;
    /* length filled below */
    off += 2;
    eap[off++] = EAP_TYPE_TLS;
    eap[off++] = flags;
    if (include_length) {
        eap[off++] = (uint8_t)(total_len >> 24);
        eap[off++] = (uint8_t)(total_len >> 16);
        eap[off++] = (uint8_t)(total_len >> 8);
        eap[off++] = (uint8_t)(total_len);
    }
    if (tls_len > 0) {
        memcpy(&eap[off], tls_data, tls_len);
        off += tls_len;
    }
    total = off;
    eap[2] = (uint8_t)((total >> 8) & 0xFFU);
    eap[3] = (uint8_t)(total & 0xFFU);
    return auth_send_eap(eap, total);
}

static int auth_send_eap_success(struct authenticator *a)
{
    uint8_t eap[4];
    eap[0] = EAP_CODE_SUCCESS;
    eap[1] = a->next_eap_id; /* echo last */
    eap[2] = 0x00; eap[3] = 0x04;
    return auth_send_eap(eap, sizeof(eap));
}

/* Drain authenticator's wolfSSL output into one Request/EAP-TLS. For
 * simplicity we use an MTU large enough to fit the whole TLS message
 * in one fragment (works for our P-256 + short chain certs). */
static int auth_send_tls_burst(struct authenticator *a)
{
    size_t out_avail = a->tls_out.filled - a->tls_out.drained;
    if (out_avail == 0) return 0;
    /* Single-fragment, no L bit needed. */
    if (auth_send_eap_request_tls(a, 0,
                                  a->tls_out.buf + a->tls_out.drained,
                                  out_avail, 0, 0) != 0) {
        return -1;
    }
    a->tls_out.drained = a->tls_out.filled;
    a->tls_out.filled = 0; a->tls_out.drained = 0;
    return 0;
}

/* ---- inbound from supplicant ---- */

static int auth_handle_supp_eap(struct authenticator *a,
                                const uint8_t *frame, size_t len)
{
    struct eap_view ev;
    uint16_t body_len = (uint16_t)((frame[2] << 8) | frame[3]);
    uint8_t  msk[64];
    (void)len;
    if (eap_parse(frame + 4, body_len, &ev) != 0) return -1;
    if (ev.code != EAP_CODE_RESPONSE) return -1;
    a->last_eap_id = ev.id;

    if (ev.type == EAP_TYPE_IDENTITY) {
        if (a->state != AUTH_WAIT_IDENTITY_RESP) return -1;
        printf("    [auth] got Identity='%.*s'\n",
               (int)ev.type_data_len, (const char *)ev.type_data);
        /* Send EAP-TLS Start packet (Flags=S, no TLS data). */
        if (auth_send_eap_request_tls(a, EAP_TLS_FLAG_S,
                                      NULL, 0, 0, 0) != 0) return -1;
        a->state = AUTH_TLS;
        return 0;
    }
    if (ev.type == EAP_TYPE_TLS) {
        uint8_t flags;
        size_t  tls_off = 1;
        size_t  tls_len;
        int     accept_ret;

        /* AUTH_EAP_DONE: TLS finished on AP side and the last outbound
         * fragment was already sent. Supplicant's ACK arrives here -
         * derive PMK and send EAP-Success. */
        if (a->state == AUTH_EAP_DONE) {
            uint8_t msk[64];
            if (wolfSSL_make_eap_keys(a->ssl, msk, 64,
                                      "client EAP encryption") != 0) {
                return -1;
            }
            memcpy(a->pmk, msk, WPA_PMK_LEN);
            wpa_secure_zero(msk, sizeof(msk));
            if (auth_send_eap_success(a) != 0) return -1;
            a->state = AUTH_COMPLETE;
            return 0;
        }
        if (a->state != AUTH_TLS) return -1;
        if (ev.type_data_len < 1) return -1;
        flags = ev.type_data[0];
        if (flags & EAP_TLS_FLAG_L) tls_off += 4;
        if (ev.type_data_len < tls_off) return -1;
        tls_len = ev.type_data_len - tls_off;

        if (tls_len > 0) {
            size_t cap = sizeof(a->tls_in.buf) - a->tls_in.filled;
            if (tls_len > cap) return -1;
            memcpy(a->tls_in.buf + a->tls_in.filled,
                   ev.type_data + tls_off, tls_len);
            a->tls_in.filled += tls_len;
        }
        if (flags & EAP_TLS_FLAG_M) {
            /* More fragments coming - ACK and wait. */
            if (auth_send_eap_request_tls(a, 0, NULL, 0, 0, 0) != 0) return -1;
            return 0;
        }
        /* Drive wolfSSL_accept. */
        accept_ret = wolfSSL_accept(a->ssl);
        if (accept_ret == WOLFSSL_SUCCESS) {
            /* Handshake done from auth side. Drain any final TLS bytes,
             * then send EAP-Success. */
            if (a->tls_out.filled > a->tls_out.drained) {
                if (auth_send_tls_burst(a) != 0) return -1;
                /* Need one more round-trip: supp ACKs, we send Success. */
                a->state = AUTH_EAP_DONE;
                return 0;
            }
            /* No outbound data left - send EAP-Success directly. */
            if (auth_send_eap_success(a) != 0) return -1;
            /* Derive PMK from MSK. */
            if (wolfSSL_make_eap_keys(a->ssl, msk, 64,
                                      "client EAP encryption") != 0) {
                return -1;
            }
            memcpy(a->pmk, msk, WPA_PMK_LEN);
            wpa_secure_zero(msk, sizeof(msk));
            a->state = AUTH_COMPLETE; /* placeholder; 4-way starts next */
            return 0;
        }
        else {
            int err = wolfSSL_get_error(a->ssl, accept_ret);
            if (err != WOLFSSL_ERROR_WANT_READ
                && err != WOLFSSL_ERROR_WANT_WRITE) {
                char emsg[80];
                wolfSSL_ERR_error_string((unsigned long)err, emsg);
                printf("    [auth] wolfSSL_accept err=%d (%s)\n", err, emsg);
                return -1;
            }
            /* In progress. Drain outbound to supp. */
            if (a->tls_out.filled > a->tls_out.drained) {
                if (auth_send_tls_burst(a) != 0) return -1;
            }
            return 0;
        }
    }
    return -1;
}

/* ---- 4-way handshake helpers (very lightly reused from PSK test) ---- */

static int auth_send_eapol_key(struct authenticator *a,
                               uint16_t key_info,
                               const uint8_t *nonce,
                               const uint8_t *key_data, uint16_t kd_len,
                               int mic)
{
    uint8_t frame[EAPOL_KEY_FIXED_LEN + 128];
    uint8_t local[EAPOL_KEY_FIXED_LEN + 128];
    uint8_t mic_buf[WPA_MIC_LEN];
    size_t  total;
    int     ret;

    a->replay[WPA_REPLAY_CTR_LEN - 1]++;
    ret = eapol_key_build(frame, sizeof(frame), key_info, 16,
                          a->replay, nonce, key_data, kd_len, &total);
    if (ret != 0) return ret;
    if (mic) {
        memcpy(local, frame, total);
        ret = wpa_eapol_mic(a->ptk.kck, local, total, mic_buf);
        if (ret != 0) return ret;
        memcpy(frame + EAPOL_HEADER_LEN + KEYBODY_OFF_MIC, mic_buf,
               WPA_MIC_LEN);
    }
    return put_to_supp(frame, total);
}

static int auth_send_m1(struct authenticator *a)
{
    memset(a->anonce, 0xA1, sizeof(a->anonce));
    return auth_send_eapol_key(a,
        (uint16_t)(KEY_INFO_VER_AES_HMAC | KEY_INFO_KEY_TYPE
                   | KEY_INFO_KEY_ACK),
        a->anonce, NULL, 0, 0);
}

static int auth_send_m3(struct authenticator *a)
{
    uint8_t kde_plain[96];
    uint8_t kde_wrap[104];
    size_t  plain_len = 0;
    int     ret;

    memcpy(&kde_plain[plain_len], a->rsn_ie, a->rsn_ie_len);
    plain_len += a->rsn_ie_len;
    kde_plain[plain_len + 0] = KDE_TYPE;
    kde_plain[plain_len + 1] = 22;
    kde_plain[plain_len + 2] = KDE_OUI_0;
    kde_plain[plain_len + 3] = KDE_OUI_1;
    kde_plain[plain_len + 4] = KDE_OUI_2;
    kde_plain[plain_len + 5] = KDE_DATATYPE_GTK;
    kde_plain[plain_len + 6] = 0x01;
    kde_plain[plain_len + 7] = 0x00;
    memset(a->gtk, 0xC7, sizeof(a->gtk));
    memcpy(&kde_plain[plain_len + 8], a->gtk, sizeof(a->gtk));
    plain_len += 24;
    if ((plain_len % 8) != 0) {
        kde_plain[plain_len++] = 0xDDU;
        while ((plain_len % 8) != 0) kde_plain[plain_len++] = 0x00U;
    }
    ret = wpa_aes_keywrap(a->ptk.kek, WPA_KEK_LEN,
                          kde_plain, plain_len, kde_wrap);
    if (ret != 0) return ret;
    return auth_send_eapol_key(a,
        (uint16_t)(KEY_INFO_VER_AES_HMAC | KEY_INFO_KEY_TYPE
                   | KEY_INFO_KEY_MIC | KEY_INFO_KEY_ACK
                   | KEY_INFO_INSTALL | KEY_INFO_SECURE
                   | KEY_INFO_ENCR_KEY_DATA),
        a->anonce, kde_wrap, (uint16_t)(plain_len + 8), 1);
}

static int auth_handle_key_frame(struct authenticator *a,
                                 const uint8_t *frame, size_t len)
{
    struct eapol_key_view kv;
    uint8_t copy[EAPOL_KEY_FIXED_LEN + 256];
    int ret;
    if (eapol_key_parse(frame, len, &kv) != 0) return -1;

    if (a->state == AUTH_4WAY_WAIT_M2) {
        memcpy(a->snonce, kv.nonce, WPA_NONCE_LEN);
        ret = wpa_ptk_derive(a->pmk, a->aa, a->sa,
                             a->anonce, a->snonce, &a->ptk);
        if (ret != 0) return ret;
        a->have_ptk = 1;
        memcpy(copy, frame, kv.frame_len);
        memset(copy + EAPOL_HEADER_LEN + KEYBODY_OFF_MIC, 0, WPA_MIC_LEN);
        if (wpa_eapol_mic_verify(a->ptk.kck, copy, kv.frame_len,
                                 kv.mic) != 0) {
            printf("    [auth] M2 MIC verify FAILED (PMK mismatch?)\n");
            return -1;
        }
        printf("    [auth] M2 MIC OK -> sending M3\n");
        if (auth_send_m3(a) != 0) return -1;
        a->state = AUTH_4WAY_WAIT_M4;
        return 0;
    }
    if (a->state == AUTH_4WAY_WAIT_M4) {
        memcpy(copy, frame, kv.frame_len);
        memset(copy + EAPOL_HEADER_LEN + KEYBODY_OFF_MIC, 0, WPA_MIC_LEN);
        if (wpa_eapol_mic_verify(a->ptk.kck, copy, kv.frame_len,
                                 kv.mic) != 0) {
            printf("    [auth] M4 MIC verify FAILED\n");
            return -1;
        }
        printf("    [auth] M4 MIC OK -> AUTHENTICATED on AP side too\n");
        a->state = AUTH_COMPLETE;
        return 0;
    }
    return -1;
}

/* Single ingress handler from supp -> auth. */
static int auth_handle_from_supp(struct authenticator *a,
                                 const uint8_t *frame, size_t len)
{
    if (len < EAPOL_HEADER_LEN) return -1;
    if (frame[1] == EAPOL_TYPE_EAPOL_START) {
        if (a->state != AUTH_IDLE) return 0;
        printf("    [auth] got EAPOL-Start\n");
        if (auth_send_eap_request_identity(a) != 0) return -1;
        a->state = AUTH_WAIT_IDENTITY_RESP;
        return 0;
    }
    if (frame[1] == EAPOL_TYPE_EAP_PACKET) {
        return auth_handle_supp_eap(a, frame, len);
    }
    if (frame[1] == EAPOL_TYPE_KEY_DESCRIPTOR) {
        return auth_handle_key_frame(a, frame, len);
    }
    return -1;
}

/* ---- main ---- */

int main(void)
{
    struct eap_test_creds creds;
    struct authenticator  auth;
    struct wolfip_supplicant *supp;
    struct wolfip_supplicant_cfg cfg;
    int  iter;
    int  fails = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Loading EAP-TLS test credentials\n");
    if (eap_test_load_creds(&creds) != 0) {
        printf("  [FAIL] cert generation/load\n");
        return 1;
    }

    /* Authenticator setup. */
    memset(&auth, 0, sizeof(auth));
    memset(&installs, 0, sizeof(installs));
    memset(&to_supp, 0, sizeof(to_supp));
    memset(&to_auth, 0, sizeof(to_auth));
    auth.aa[5] = 0x11; auth.sa[5] = 0x22;
    if (rsn_ie_build_wpa2_psk(auth.rsn_ie, sizeof(auth.rsn_ie),
                              &auth.rsn_ie_len) != 0) {
        printf("  [FAIL] rsn_ie_build\n"); return 1;
    }
    wolfSSL_Init();
    auth.ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    if (auth.ssl_ctx == NULL) { printf("  [FAIL] auth CTX\n"); return 1; }
    wolfSSL_CTX_set_verify(auth.ssl_ctx, WOLFSSL_VERIFY_PEER, NULL);
    if (wolfSSL_CTX_load_verify_buffer(auth.ssl_ctx, creds.ca, creds.ca_len,
                                       WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS
     || wolfSSL_CTX_use_certificate_buffer(auth.ssl_ctx,
                                           creds.srv_cert, creds.srv_cert_len,
                                           WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS
     || wolfSSL_CTX_use_PrivateKey_buffer(auth.ssl_ctx,
                                          creds.srv_key, creds.srv_key_len,
                                          WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("  [FAIL] auth cert/key load\n"); return 1;
    }
    wolfSSL_CTX_SetIORecv(auth.ssl_ctx, auth_io_recv);
    wolfSSL_CTX_SetIOSend(auth.ssl_ctx, auth_io_send);
    auth.ssl = wolfSSL_new(auth.ssl_ctx);
    if (auth.ssl == NULL) { printf("  [FAIL] auth SSL\n"); return 1; }
    wolfSSL_SetIOReadCtx(auth.ssl,  &auth);
    wolfSSL_SetIOWriteCtx(auth.ssl, &auth);
    wolfSSL_KeepArrays(auth.ssl);

    /* Supplicant setup (auth_mode = EAP-TLS). */
    memset(&cfg, 0, sizeof(cfg));
    cfg.ssid = "wolfIP-Enterprise"; cfg.ssid_len = strlen(cfg.ssid);
    cfg.auth_mode = WOLFIP_AUTH_EAP_TLS;
    cfg.identity = "alice@wolfip.local"; cfg.identity_len = strlen(cfg.identity);
    memcpy(cfg.ap_mac,  auth.aa, WPA_MAC_LEN);
    memcpy(cfg.sta_mac, auth.sa, WPA_MAC_LEN);
    cfg.ap_rsn_ie = auth.rsn_ie; cfg.ap_rsn_ie_len = auth.rsn_ie_len;
    cfg.eap_tls.ca = creds.ca; cfg.eap_tls.ca_len = creds.ca_len;
    cfg.eap_tls.ca_format = WOLFIP_EAP_TLS_FMT_DER;
    cfg.eap_tls.client_cert = creds.cli_cert;
    cfg.eap_tls.client_cert_len = creds.cli_cert_len;
    cfg.eap_tls.client_cert_format = WOLFIP_EAP_TLS_FMT_DER;
    cfg.eap_tls.client_key = creds.cli_key;
    cfg.eap_tls.client_key_len = creds.cli_key_len;
    cfg.eap_tls.client_key_format = WOLFIP_EAP_TLS_FMT_DER;
    cfg.eap_tls.tls_version_pin = 1;
    cfg.eap_tls.server_name_pin = "auth.wolfip.local";
    cfg.ops.send_eapol = supp_send_cb;
    cfg.ops.install_key = supp_install_cb;

    supp = wolfip_supplicant_new(&cfg);
    if (supp == NULL) { printf("  [FAIL] supplicant_new\n"); return 1; }
    if (wolfip_supplicant_kick(supp, 0) != 0) {
        printf("  [FAIL] kick\n"); wolfip_supplicant_free(supp); return 1;
    }
    printf("Supplicant kicked (state should be EAP_IDENTITY_WAIT)\n");
    printf("Initial state: %d\n", (int)wolfip_supplicant_state(supp));

    /* Pump frames until both sides finish or we give up. */
    for (iter = 0; iter < 64; iter++) {
        int progressed = 0;
        if (to_auth.has) {
            if (auth_handle_from_supp(&auth, to_auth.buf, to_auth.len) != 0) {
                printf("  [FAIL] authenticator rejected frame at iter %d\n",
                       iter);
                fails++; break;
            }
            to_auth.has = 0;
            progressed = 1;
        }
        if (to_supp.has) {
            int r = wolfip_supplicant_rx(supp, to_supp.buf, to_supp.len, 0);
            to_supp.has = 0;
            if (r != 0
                && wolfip_supplicant_state(supp) == SUPP_STATE_FAILED) {
                printf("  [FAIL] supplicant entered FAILED at iter %d\n",
                       iter);
                fails++; break;
            }
            progressed = 1;
        }
        /* After EAP-Success has been delivered and there's nothing
         * else in flight, start the 4-way by sending M1. */
        if (auth.state == AUTH_COMPLETE && !auth.have_ptk
            && wolfip_supplicant_state(supp) == SUPP_STATE_4WAY_M1_WAIT
            && !to_supp.has && !to_auth.has) {
            printf("    [auth] EAP-Success delivered, starting 4-way\n");
            if (auth_send_m1(&auth) != 0) {
                printf("  [FAIL] auth M1\n"); fails++; break;
            }
            auth.state = AUTH_4WAY_WAIT_M2;
            progressed = 1;
        }
        if (wolfip_supplicant_state(supp) == SUPP_STATE_AUTHENTICATED
            && auth.state == AUTH_COMPLETE
            && !to_supp.has && !to_auth.has) {
            break;
        }
        if (!progressed) {
            /* Possibly the supp produced no frame after rx (e.g.
             * pending Success arriving in next round). Continue. */
        }
    }

    printf("Final supplicant state: %d, auth state: %d, iter=%d\n",
           (int)wolfip_supplicant_state(supp), (int)auth.state, iter);

    if (wolfip_supplicant_state(supp) != SUPP_STATE_AUTHENTICATED) {
        printf("  [FAIL] supplicant did not reach AUTHENTICATED\n");
        fails++;
    }
    else {
        printf("  [OK]   supplicant AUTHENTICATED via EAP-TLS + 4-way\n");
    }
    if (!installs.pairwise_set || !installs.group_set) {
        printf("  [FAIL] install_key not called for both PTK and GTK\n");
        fails++;
    }
    else {
        printf("  [OK]   PTK + GTK installed via wifi_ops.set_key\n");
    }
    if (auth.have_ptk
        && memcmp(installs.tk, auth.ptk.tk, WPA_TK_LEN) != 0) {
        printf("  [FAIL] PTK TK mismatch between supp and auth\n");
        fails++;
    }
    else if (auth.have_ptk) {
        printf("  [OK]   PTK derived identically on both sides "
               "(from MSK-derived PMK)\n");
    }
    if (installs.gtk_len != sizeof(auth.gtk)
        || memcmp(installs.gtk, auth.gtk, sizeof(auth.gtk)) != 0) {
        printf("  [FAIL] GTK mismatch\n");
        fails++;
    }
    else {
        printf("  [OK]   GTK round-trips through M3 encrypted KDE\n");
    }

    wolfSSL_free(auth.ssl);
    wolfSSL_CTX_free(auth.ssl_ctx);
    wolfSSL_Cleanup();
    wolfip_supplicant_free(supp);

    if (fails == 0) {
        printf("\nEnterprise EAP-TLS integration test passed.\n");
        return 0;
    }
    printf("\n%d enterprise test failure(s).\n", fails);
    return 1;
}

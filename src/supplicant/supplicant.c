/* supplicant.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfIP.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* WPA2-Personal supplicant state machine. Driven by inbound EAPOL frames
 * (wolfip_supplicant_rx) and a single "associated" trigger
 * (wolfip_supplicant_kick). No timers in v1; retry logic moves in with
 * Phase C wolfIP integration.
 */

#include "supplicant.h"
#include "eapol.h"
#include "rsn_ie.h"
#include "eap.h"
#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
#include "eap_tls.h"
#include "eap_tls_engine.h"
#endif
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
#include "sae_crypto.h"
#endif
#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
#include "mschapv2.h"
#include "eap_peap.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

struct wolfip_supplicant {
    /* Configuration. */
    uint8_t  ssid[WOLFIP_SUPPLICANT_MAX_SSID];
    size_t   ssid_len;
    uint8_t  ap_mac[WPA_MAC_LEN];
    uint8_t  sta_mac[WPA_MAC_LEN];
    wolfip_auth_mode_t auth_mode;
    struct wolfip_supplicant_ops ops;

#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
    /* EAP-TLS / PEAP. Allocated/initialized in wolfip_supplicant_new()
     * when auth_mode is one of the EAP variants. */
    struct eap_tls_engine eap_tls;
    int      eap_tls_inited;
    uint8_t  identity[WOLFIP_SUPPLICANT_MAX_IDENTITY];
    size_t   identity_len;
    uint8_t  last_eap_id;
#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
    /* PEAP-specific. */
    uint8_t  inner_identity[WOLFIP_SUPPLICANT_MAX_IDENTITY];
    size_t   inner_identity_len;
    uint8_t  password[64];
    size_t   password_len;
    uint8_t  peer_challenge[16];
    uint8_t  auth_challenge[16];
    uint8_t  nt_response[24];
    int      have_nt_response;
#endif
#endif /* WOLFIP_ENABLE_EAP_TLS */

    /* Cached RSN IEs. own_rsn_ie is sent in M2 Key Data and (by the
     * driver) in our (Re)Assoc Request. ap_rsn_ie is what we expect
     * the AP to echo in M3 - byte-for-byte equality required.
     */
    uint8_t  own_rsn_ie[WOLFIP_SUPPLICANT_MAX_RSN_IE];
    size_t   own_rsn_ie_len;
    uint8_t  ap_rsn_ie[WOLFIP_SUPPLICANT_MAX_RSN_IE];
    size_t   ap_rsn_ie_len;

    /* Derived secrets. */
    uint8_t  pmk[WPA_PMK_LEN];
    struct wpa_ptk ptk;
    int      have_ptk;

    /* Handshake transient state. */
    uint8_t  anonce[WPA_NONCE_LEN];
    uint8_t  snonce[WPA_NONCE_LEN];
    uint8_t  last_replay[WPA_REPLAY_CTR_LEN];
    int      have_replay;

    /* Retransmit bookkeeping for M2. m2_send_ms is the timestamp at
     * which we last transmitted M2; m2_retries_left counts remaining
     * tries before declaring the handshake failed. Both reset when
     * the supplicant exits the M3_WAIT state. */
    uint64_t m2_send_ms;
    uint8_t  m2_retries_left;

#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
    /* SAE state (WPA3-Personal). */
    struct sae_ctx sae;
    int            sae_inited;
    int            pmk_installed;     /* 1 if FullMAC chip supplied PMK */
    int            sae_h2e;           /* 0 = H&P, 1 = H2E (status 126) */
#endif

    wolfip_supplicant_state_t state;
};

/* ---- helpers ---- */

static void zero_secrets(struct wolfip_supplicant *s)
{
    wpa_secure_zero(s->pmk, sizeof(s->pmk));
    wpa_secure_zero(&s->ptk, sizeof(s->ptk));
    wpa_secure_zero(s->anonce, sizeof(s->anonce));
    wpa_secure_zero(s->snonce, sizeof(s->snonce));
    s->have_ptk = 0;
#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
    /* PEAP-MSCHAPv2 inner credentials must be zeroed on every error
     * path - the password and derived NT-response are PSK-equivalent
     * secrets. */
    wpa_secure_zero(s->password,       sizeof(s->password));
    wpa_secure_zero(s->inner_identity, sizeof(s->inner_identity));
    wpa_secure_zero(s->peer_challenge, sizeof(s->peer_challenge));
    wpa_secure_zero(s->auth_challenge, sizeof(s->auth_challenge));
    wpa_secure_zero(s->nt_response,    sizeof(s->nt_response));
    s->password_len       = 0;
    s->inner_identity_len = 0;
    s->have_nt_response   = 0;
#endif
}

static int gen_snonce(uint8_t out[WPA_NONCE_LEN])
{
    WC_RNG rng;
    int ret;

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        return ret;
    }
    ret = wc_RNG_GenerateBlock(&rng, out, WPA_NONCE_LEN);
    wc_FreeRng(&rng);
    return ret;
}

/* Build, MIC-sign, and ship an EAPOL-Key frame. mic_required indicates
 * whether to compute MIC over the buffer (MIC field zero) and overwrite
 * the MIC offset. */
static int supp_send_key(struct wolfip_supplicant *s,
                         uint16_t key_info,
                         uint16_t key_len,
                         const uint8_t replay[WPA_REPLAY_CTR_LEN],
                         const uint8_t nonce[WPA_NONCE_LEN],
                         const uint8_t *key_data, uint16_t key_data_len,
                         int mic_required)
{
    uint8_t  buf[EAPOL_KEY_FIXED_LEN + 64];
    size_t   total;
    uint8_t  mic[WPA_MIC_LEN];
    int      ret;

    if ((size_t)EAPOL_KEY_FIXED_LEN + key_data_len > sizeof(buf)) {
        return -1;
    }
    ret = eapol_key_build(buf, sizeof(buf),
                          key_info, key_len, replay, nonce,
                          key_data, key_data_len, &total);
    if (ret != 0) {
        return ret;
    }
    if (mic_required) {
        ret = wpa_eapol_mic(s->ptk.kck, buf, total, mic);
        if (ret != 0) {
            return ret;
        }
        memcpy(buf + EAPOL_HEADER_LEN + KEYBODY_OFF_MIC, mic, WPA_MIC_LEN);
        wpa_secure_zero(mic, sizeof(mic));
    }
    if (s->ops.send_eapol == NULL) {
        return -1;
    }
    return s->ops.send_eapol(s->ops.ctx, buf, total);
}

/* ---- EAP / EAP-TLS plumbing ---- */

#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
/* Wrap a payload (already in the form expected for the EAPOL packet
 * type) with a 4-byte 802.1X header and ship via the integrator's
 * send_eapol callback. */
static int supp_send_eapol_packet(struct wolfip_supplicant *s,
                                  uint8_t eapol_type,
                                  const uint8_t *payload, size_t payload_len)
{
    uint8_t buf[EAPOL_HEADER_LEN + WOLFIP_SUPPLICANT_EAP_MTU + 32];
    size_t  total;

    if (payload_len + EAPOL_HEADER_LEN > sizeof(buf)) {
        return -1;
    }
    if (eapol_eap_build(buf, sizeof(buf), eapol_type,
                        payload, payload_len, &total) != 0) {
        return -1;
    }
    if (s->ops.send_eapol == NULL) {
        return -1;
    }
    return s->ops.send_eapol(s->ops.ctx, buf, total);
}

static int supp_send_eapol_start(struct wolfip_supplicant *s)
{
    return supp_send_eapol_packet(s, EAPOL_TYPE_EAPOL_START, NULL, 0);
}

static int supp_send_eap_identity(struct wolfip_supplicant *s, uint8_t id)
{
    uint8_t  eap[EAP_HEADER_LEN + 1U + WOLFIP_SUPPLICANT_MAX_IDENTITY];
    size_t   total;

    if (eap_build_identity_response(eap, sizeof(eap), id,
                                    s->identity, s->identity_len,
                                    &total) != 0) {
        return -1;
    }
    return supp_send_eapol_packet(s, EAPOL_TYPE_EAP_PACKET, eap, total);
}
#endif /* WOLFIP_ENABLE_EAP_TLS */

#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
/* Emit an EAP-Response with Type=EAP-TLS (13) or Type=EAP-PEAP (25). If
 * is_ack is non-zero a 1-byte Flags=0 payload is sent; otherwise the
 * next outbound TLS fragment is drained from the engine's tx buffer. */
static int supp_send_eap_tls_typed(struct wolfip_supplicant *s,
                                   uint8_t id, uint8_t eap_type, int is_ack)
{
    uint8_t eap[EAP_HEADER_LEN + 1U + WOLFIP_SUPPLICANT_EAP_MTU];
    uint8_t *type_data = &eap[EAP_HEADER_LEN + 1U];
    size_t   payload_len;
    size_t   total;
    int      more = 0;

    if (is_ack) {
        if (eap_tls_build_ack(type_data,
                              sizeof(eap) - (EAP_HEADER_LEN + 1U),
                              &payload_len) != 0) {
            return -1;
        }
    }
    else {
        if (eap_tls_tx_fragment(&s->eap_tls.io,
                                type_data,
                                WOLFIP_SUPPLICANT_EAP_MTU,
                                &payload_len, &more) != 0) {
            return -1;
        }
    }
    total = EAP_HEADER_LEN + 1U + payload_len;
    if (total > 0xFFFFU) {
        return -1;
    }
    eap[0] = EAP_CODE_RESPONSE;
    eap[1] = id;
    eap[2] = (uint8_t)((total >> 8) & 0xFFU);
    eap[3] = (uint8_t)(total & 0xFFU);
    eap[4] = eap_type;
    return supp_send_eapol_packet(s, EAPOL_TYPE_EAP_PACKET, eap, total);
}

static int supp_send_eap_tls(struct wolfip_supplicant *s,
                             uint8_t id, int is_ack)
{
    return supp_send_eap_tls_typed(s, id, EAP_TYPE_TLS, is_ack);
}

static int supp_handle_eap_request(struct wolfip_supplicant *s,
                                   const struct eap_view *eap)
{
    s->last_eap_id = eap->id;

    if (eap->type == EAP_TYPE_IDENTITY) {
        if (s->state != SUPP_STATE_EAP_IDENTITY_WAIT
            && s->state != SUPP_STATE_EAP_TLS_INPROGRESS) {
            return -1;
        }
        if (supp_send_eap_identity(s, eap->id) != 0) {
            return -1;
        }
        s->state = SUPP_STATE_EAP_TLS_INPROGRESS;
        return 0;
    }

    if (eap->type == EAP_TYPE_TLS) {
        uint8_t flags;
        int     rfrag;
        int     step = 0;

        if (s->state != SUPP_STATE_EAP_TLS_INPROGRESS) {
            return -1;
        }
        rfrag = eap_tls_rx_fragment(&s->eap_tls.io,
                                    eap->type_data, eap->type_data_len,
                                    &flags);
        if (rfrag < 0) {
            return -1;
        }
        if (rfrag == 1) {
            /* Server's EAP-TLS Start packet: drive engine to emit
             * ClientHello, then send first outbound fragment. */
            step = eap_tls_engine_step(&s->eap_tls);
            if (step < 0) {
                return -1;
            }
        }
        else if (!s->eap_tls.io.rx_complete) {
            /* Partial fragment - acknowledge and wait for next. */
            return supp_send_eap_tls(s, eap->id, 1);
        }
        else {
            /* Full inbound TLS message ready. */
            step = eap_tls_engine_step(&s->eap_tls);
            if (step < 0) {
                return -1;
            }
        }
        if (s->eap_tls.io.tx_filled > 0U) {
            return supp_send_eap_tls(s, eap->id, 0);
        }
        /* Handshake done or no output yet - ACK. */
        return supp_send_eap_tls(s, eap->id, 1);
    }

#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
    if (eap->type == EAP_TYPE_PEAP
        && s->auth_mode == WOLFIP_AUTH_PEAP_MSCHAPV2) {
        uint8_t flags;
        int     rfrag;
        int     step = 0;

        if (s->state != SUPP_STATE_EAP_TLS_INPROGRESS) {
            return -1;
        }
        rfrag = eap_tls_rx_fragment(&s->eap_tls.io,
                                    eap->type_data, eap->type_data_len,
                                    &flags);
        if (rfrag < 0) {
            return -1;
        }
        if (rfrag == 1) {
            /* Server's EAP-PEAP Start. Drive engine -> emits ClientHello. */
            step = eap_tls_engine_step(&s->eap_tls);
            if (step < 0) return -1;
        }
        else if (!s->eap_tls.io.rx_complete) {
            return supp_send_eap_tls_typed(s, eap->id, EAP_TYPE_PEAP, 1);
        }
        else if (!s->eap_tls.handshake_complete) {
            step = eap_tls_engine_step(&s->eap_tls);
            if (step < 0) return -1;
        }
        else {
            /* Phase 2 (PEAPv0 Microsoft variant): compressed inner
             * framing. The server sends just the EAP type byte
             * followed by method-specific payload - there is no inner
             * EAP code / id / length. Type 0x01 is Identity (compressed
             * to just the type byte); type 0x1A is MSCHAPv2.
             */
            uint8_t plain[512];
            uint8_t inner_resp[256];
            int     pl;
            size_t  inner_resp_len = 0;
            uint8_t inner_type;

            pl = wolfSSL_read(s->eap_tls.ssl, plain, sizeof(plain));
            if (pl <= 0) {
                return supp_send_eap_tls_typed(s, eap->id,
                                               EAP_TYPE_PEAP, 1);
            }
            inner_type = plain[0];

            /* In PHASE2_TLV (after MSCHAPv2 Success), hostapd skips its
             * compressed-header synthesis and sends a FULL EAP-wrapped
             * Request with type=33 (EAP-TLV). Distinguish by checking
             * for the EAP-Request code at offset 0 with type-TLV at 4. */
            if (pl >= 11 && plain[0] == EAP_CODE_REQUEST
                && plain[4] == 33 /* EAP_TYPE_TLV */) {
                /* Build EAP-Response with a Result TLV indicating
                 * Success (no crypto-binding). hostapd has
                 * OPTIONAL_BINDING so this satisfies it. */
                if (sizeof(inner_resp) < 11) return -1;
                inner_resp[0] = EAP_CODE_RESPONSE;
                inner_resp[1] = plain[1];        /* echo inner id  */
                inner_resp[2] = 0x00;
                inner_resp[3] = 0x0B;            /* total len = 11 */
                inner_resp[4] = 33;              /* EAP-TLV type   */
                inner_resp[5] = 0x80;            /* M=1, type hi   */
                inner_resp[6] = 0x03;            /* TLV type=3 (Result) */
                inner_resp[7] = 0x00;
                inner_resp[8] = 0x02;            /* TLV length=2   */
                inner_resp[9] = 0x00;
                inner_resp[10] = 0x01;           /* Result = Success */
                inner_resp_len = 11;
            }
            else if (inner_type == EAP_TYPE_IDENTITY) {
                /* PEAPv0 compressed Identity Request -> compressed
                 * Response (hostapd will synthesize the inner EAP
                 * header from our outer Response). */
                if (s->inner_identity_len + 1U > sizeof(inner_resp)) {
                    return -1;
                }
                inner_resp[0] = EAP_TYPE_IDENTITY;
                memcpy(&inner_resp[1], s->inner_identity,
                       s->inner_identity_len);
                inner_resp_len = 1U + s->inner_identity_len;
            }
            else if (inner_type == 26 /* MSCHAPv2 */) {
                struct mschapv2_challenge_view ch;
                if (eap_peap_parse_mschapv2_challenge(plain,
                        (size_t)pl, &ch) == 0) {
                    WC_RNG rng;
                    int rng_ret;
                    memcpy(s->auth_challenge, ch.auth_challenge, 16);
                    rng_ret = wc_InitRng(&rng);
                    if (rng_ret != 0) return -1;
                    wc_RNG_GenerateBlock(&rng, s->peer_challenge, 16);
                    wc_FreeRng(&rng);
                    if (mschapv2_generate_nt_response(s->auth_challenge,
                            s->peer_challenge,
                            (const char *)s->inner_identity,
                            s->inner_identity_len,
                            (const char *)s->password, s->password_len,
                            s->nt_response) != 0) {
                        return -1;
                    }
                    s->have_nt_response = 1;
                    if (eap_peap_build_mschapv2_response(inner_resp,
                            sizeof(inner_resp), eap->id, ch.ms_id,
                            s->peer_challenge, s->nt_response,
                            (const char *)s->inner_identity,
                            s->inner_identity_len,
                            &inner_resp_len) != 0) {
                        return -1;
                    }
                }
                else {
                    char authresp[42];
                    if (eap_peap_extract_authresp(plain, (size_t)pl,
                                                  authresp) != 0
                        || !s->have_nt_response) {
                        return -1;
                    }
                    if (mschapv2_verify_authenticator_response(
                            (const char *)s->password, s->password_len,
                            s->nt_response, s->peer_challenge,
                            s->auth_challenge,
                            (const char *)s->inner_identity,
                            s->inner_identity_len,
                            authresp) != 0) {
                        return -1;
                    }
                    if (eap_peap_build_mschapv2_ack(inner_resp,
                            sizeof(inner_resp), eap->id,
                            &inner_resp_len) != 0) {
                        return -1;
                    }
                }
            }
            else {
                return -1;
            }

            if (wolfSSL_write(s->eap_tls.ssl, inner_resp,
                              (int)inner_resp_len) <= 0) {
                return -1;
            }
        }

        if (s->eap_tls.io.tx_filled > 0U) {
            return supp_send_eap_tls_typed(s, eap->id, EAP_TYPE_PEAP, 0);
        }
        return supp_send_eap_tls_typed(s, eap->id, EAP_TYPE_PEAP, 1);
    }
#endif

    /* Unrecognised EAP type. v1 fails the handshake; future work could
     * emit an EAP-NAK suggesting EAP-TLS / PEAP. */
    return -1;
}

static int supp_handle_eap_success(struct wolfip_supplicant *s)
{
    uint8_t msk[WOLFIP_EAP_TLS_MSK_LEN];
    int     ret;
    int     is_eap_mode = 0;

    if (s->auth_mode == WOLFIP_AUTH_EAP_TLS) is_eap_mode = 1;
#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
    if (s->auth_mode == WOLFIP_AUTH_PEAP_MSCHAPV2) is_eap_mode = 1;
#endif
    if (!is_eap_mode) {
        return -1;
    }
    if (s->state != SUPP_STATE_EAP_TLS_INPROGRESS) {
        return -1;
    }
    if (!s->eap_tls.handshake_complete) {
        return -1;
    }
    ret = eap_tls_engine_export_msk(&s->eap_tls, msk);
    if (ret != 0) {
        return -1;
    }
    /* RFC 5216: PMK = MSK[0..31]. The remaining 32 bytes form the EMSK
     * and are unused in v1. */
    memcpy(s->pmk, msk, WPA_PMK_LEN);
    wpa_secure_zero(msk, sizeof(msk));

    /* Hand off to the existing 4-way handshake path. */
    s->state = SUPP_STATE_4WAY_M1_WAIT;
    return 0;
}
#endif /* WOLFIP_ENABLE_EAP_TLS */

/* Send (or re-send) M2. Uses the supplicant's cached SNonce, replay
 * counter (echoed from M1) and own RSN IE. MIC is computed with the
 * current KCK (already populated when this is reached). */
static int supp_send_m2(struct wolfip_supplicant *s)
{
    return supp_send_key(s,
                         (uint16_t)(KEY_INFO_VER_AES_HMAC
                                    | KEY_INFO_KEY_TYPE
                                    | KEY_INFO_KEY_MIC),
                         0U,
                         s->last_replay,
                         s->snonce,
                         s->own_rsn_ie, (uint16_t)s->own_rsn_ie_len,
                         1);
}

/* ---- M1 handling: derive PTK, reply with M2 ---- */

static int supp_handle_m1(struct wolfip_supplicant *s,
                          const struct eapol_key_view *kv,
                          uint64_t now_ms)
{
    int ret;

    /* M1: KeyAck=1, MIC=0, Pairwise=1. */
    if ((kv->key_info & KEY_INFO_KEY_TYPE) == 0) {
        return -1;
    }
    if ((kv->key_info & KEY_INFO_KEY_ACK) == 0) {
        return -1;
    }
    if ((kv->key_info & KEY_INFO_KEY_MIC) != 0) {
        return -1;
    }

    memcpy(s->anonce, kv->nonce, WPA_NONCE_LEN);

    ret = gen_snonce(s->snonce);
    if (ret != 0) {
        return ret;
    }
    ret = wpa_ptk_derive(s->pmk, s->ap_mac, s->sta_mac,
                         s->anonce, s->snonce, &s->ptk);
    if (ret != 0) {
        return ret;
    }
    s->have_ptk = 1;

    /* Track replay counter. */
    memcpy(s->last_replay, kv->replay_counter, WPA_REPLAY_CTR_LEN);
    s->have_replay = 1;

    /* Send M2: MIC=1, Pairwise=1, SNonce, Key Data = our RSN IE.
     * Including the IE is required by IEEE 802.11-2020 12.7.6.3 so the
     * authenticator can confirm we negotiated the same cipher/AKM in
     * (Re)Assoc Request. Most production APs reject M2 without it. */
    ret = supp_send_m2(s);
    if (ret != 0) {
        return ret;
    }
    s->m2_send_ms      = now_ms;
    s->m2_retries_left = WOLFIP_SUPPLICANT_M2_MAX_RETRIES;
    s->state = SUPP_STATE_4WAY_M3_WAIT;
    return 0;
}

/* Decrypt M3 key data (AES Key Wrap with KEK) and walk the elements:
 *   - type 0x30 (RSN IE): byte-compared to s->ap_rsn_ie for downgrade
 *     check (IEEE 802.11-2020 12.7.6.4).
 *   - type 0xDD (KDE) with OUI 00:0F:AC: GTK KDE extraction.
 *
 * Returns 0 on success. Both an RSN IE match and a GTK must be found.
 */
static int supp_parse_m3_key_data(const struct wolfip_supplicant *s,
                                  const struct eapol_key_view *kv,
                                  uint8_t  out_gtk[WPA_GTK_MAX_LEN],
                                  size_t  *out_gtk_len,
                                  uint8_t *out_key_idx)
{
    uint8_t plain[256];
    size_t  plain_len;
    size_t  i;
    int     ret;
    int     have_rsn_match = 0;
    int     have_gtk       = 0;

    if (kv->key_data_len < 16 || kv->key_data_len > sizeof(plain) + 8) {
        return -1;
    }
    if ((kv->key_data_len % 8) != 0) {
        return -1;
    }
    if ((kv->key_info & KEY_INFO_ENCR_KEY_DATA) == 0) {
        return -1;
    }
    plain_len = kv->key_data_len - 8U;
    ret = wpa_aes_keyunwrap(s->ptk.kek, WPA_KEK_LEN,
                            kv->key_data, kv->key_data_len, plain);
    if (ret != 0) {
        return ret;
    }

    for (i = 0; i + 2U <= plain_len; ) {
        uint8_t type = plain[i];
        uint8_t len  = plain[i + 1U];
        size_t  end;

        if (i + 2U + len > plain_len) {
            break;
        }
        end = i + 2U + len;

        if (type == RSN_IE_ELEMENT_ID) {
            /* Whole IE including its 2-byte header. */
            size_t ie_total = (size_t)len + 2U;
            ret = rsn_ie_equal(&plain[i], ie_total,
                               s->ap_rsn_ie, s->ap_rsn_ie_len);
            if (ret == 0) {
                have_rsn_match = 1;
            }
            else {
                /* Downgrade: AP advertised different cipher in M3 vs
                 * Beacon. Abort the handshake. */
                wpa_secure_zero(plain, sizeof(plain));
                return -1;
            }
        }
        else if (type == KDE_TYPE
                 && len >= 4U
                 && plain[i + 2U] == KDE_OUI_0
                 && plain[i + 3U] == KDE_OUI_1
                 && plain[i + 4U] == KDE_OUI_2) {
            uint8_t dt = plain[i + 5U];
            if (dt == KDE_DATATYPE_GTK && len >= 6U) {
                size_t gtk_len = (size_t)len - 6U;
                if (gtk_len == 0U || gtk_len > WPA_GTK_MAX_LEN) {
                    wpa_secure_zero(plain, sizeof(plain));
                    return -1;
                }
                *out_key_idx = (uint8_t)(plain[i + 6U] & 0x03U);
                memcpy(out_gtk, &plain[i + 8U], gtk_len);
                *out_gtk_len = gtk_len;
                have_gtk = 1;
            }
            /* Other KDEs (MAC, lifetime, etc.) ignored for v1. */
        }
        /* Padding KDE (type 0xDD len 0 OR a single 0xDD byte) terminates. */

        i = end;
    }
    wpa_secure_zero(plain, sizeof(plain));
    if (!have_rsn_match || !have_gtk) {
        return -1;
    }
    return 0;
}

/* Extract GTK from a Group Key M1's encrypted Key Data. Unlike the
 * 4-way M3 parser this expects only KDEs (no RSN IE re-echo). */
static int supp_parse_group_m1_data(const struct wolfip_supplicant *s,
                                    const struct eapol_key_view *kv,
                                    uint8_t  out_gtk[WPA_GTK_MAX_LEN],
                                    size_t  *out_gtk_len,
                                    uint8_t *out_key_idx)
{
    uint8_t plain[256];
    size_t  plain_len;
    size_t  i;
    int     ret;

    if (kv->key_data_len < 16U || kv->key_data_len > sizeof(plain) + 8U) {
        return -1;
    }
    if ((kv->key_data_len % 8U) != 0U) {
        return -1;
    }
    if ((kv->key_info & KEY_INFO_ENCR_KEY_DATA) == 0U) {
        return -1;
    }
    plain_len = kv->key_data_len - 8U;
    ret = wpa_aes_keyunwrap(s->ptk.kek, WPA_KEK_LEN,
                            kv->key_data, kv->key_data_len, plain);
    if (ret != 0) {
        return ret;
    }
    for (i = 0; i + 2U <= plain_len; ) {
        uint8_t type = plain[i];
        uint8_t len  = plain[i + 1U];
        size_t  end;

        if (i + 2U + len > plain_len) break;
        end = i + 2U + len;

        if (type == KDE_TYPE && len >= 6U
            && plain[i + 2U] == KDE_OUI_0
            && plain[i + 3U] == KDE_OUI_1
            && plain[i + 4U] == KDE_OUI_2
            && plain[i + 5U] == KDE_DATATYPE_GTK) {
            size_t gtk_len = (size_t)len - 6U;
            if (gtk_len == 0U || gtk_len > WPA_GTK_MAX_LEN) break;
            *out_key_idx = (uint8_t)(plain[i + 6U] & 0x03U);
            memcpy(out_gtk, &plain[i + 8U], gtk_len);
            *out_gtk_len = gtk_len;
            wpa_secure_zero(plain, sizeof(plain));
            return 0;
        }
        i = end;
    }
    wpa_secure_zero(plain, sizeof(plain));
    return -1;
}

/* ---- Group Key M1: verify, install new GTK, reply with Group M2 ---- */

static int supp_handle_group_m1(struct wolfip_supplicant *s,
                                const struct eapol_key_view *kv,
                                uint8_t *frame_copy_for_mic,
                                size_t   frame_copy_len)
{
    uint8_t gtk[WPA_GTK_MAX_LEN];
    size_t  gtk_len = 0;
    uint8_t gtk_idx = 0;
    int     ret;
    uint8_t zero_nonce[WPA_NONCE_LEN];

    /* Group M1: Pairwise=0, KeyAck=1, MIC=1, Secure=1, Encrypted=1. */
    if ((kv->key_info & KEY_INFO_KEY_ACK) == 0) return -1;
    if ((kv->key_info & KEY_INFO_KEY_MIC) == 0) return -1;
    if ((kv->key_info & KEY_INFO_SECURE)  == 0) return -1;
    if ((kv->key_info & KEY_INFO_ENCR_KEY_DATA) == 0) return -1;

    /* Replay counter must strictly advance. */
    if (s->have_replay
        && memcmp(kv->replay_counter, s->last_replay,
                  WPA_REPLAY_CTR_LEN) <= 0) {
        return -1;
    }
    /* MIC over frame with MIC field zeroed. */
    if (frame_copy_for_mic == NULL || frame_copy_len < kv->frame_len) {
        return -1;
    }
    memset(frame_copy_for_mic + EAPOL_HEADER_LEN + KEYBODY_OFF_MIC, 0,
           WPA_MIC_LEN);
    ret = wpa_eapol_mic_verify(s->ptk.kck,
                               frame_copy_for_mic, kv->frame_len, kv->mic);
    if (ret != 0) return -1;

    ret = supp_parse_group_m1_data(s, kv, gtk, &gtk_len, &gtk_idx);
    if (ret != 0) return -1;

    /* Install rekeyed GTK. */
    if (s->ops.install_key != NULL) {
        ret = s->ops.install_key(s->ops.ctx, SUPP_KEY_GROUP, gtk_idx,
                                 gtk, gtk_len);
        if (ret != 0) {
            wpa_secure_zero(gtk, sizeof(gtk));
            return ret;
        }
    }
    wpa_secure_zero(gtk, sizeof(gtk));

    /* Update replay counter, send Group M2 (MIC=1, Secure=1, no data,
     * empty nonce). */
    memcpy(s->last_replay, kv->replay_counter, WPA_REPLAY_CTR_LEN);
    memset(zero_nonce, 0, sizeof(zero_nonce));
    ret = supp_send_key(s,
                        (uint16_t)(KEY_INFO_VER_AES_HMAC
                                   | KEY_INFO_KEY_MIC
                                   | KEY_INFO_SECURE),
                        0U,
                        s->last_replay,
                        zero_nonce,
                        NULL, 0,
                        1);
    return ret;
}

/* ---- M3 handling: verify MIC, install keys, reply with M4 ---- */

static int supp_handle_m3(struct wolfip_supplicant *s,
                          const struct eapol_key_view *kv,
                          uint8_t *frame_copy_for_mic, size_t frame_copy_len)
{
    uint8_t  gtk[WPA_GTK_MAX_LEN];
    size_t   gtk_len = 0;
    uint8_t  gtk_idx = 0;
    int      ret;

    /* M3: KeyAck=1, MIC=1, Install=1, Pairwise=1, Secure=1, Encrypted=1. */
    if ((kv->key_info & KEY_INFO_KEY_ACK) == 0) {
        return -1;
    }
    if ((kv->key_info & KEY_INFO_KEY_MIC) == 0) {
        return -1;
    }
    if ((kv->key_info & KEY_INFO_INSTALL) == 0) {
        return -1;
    }
    /* Replay counter must strictly advance. */
    if (s->have_replay
        && memcmp(kv->replay_counter, s->last_replay,
                  WPA_REPLAY_CTR_LEN) <= 0) {
        return -1;
    }
    /* ANonce must match what we saw in M1. */
    if (memcmp(kv->nonce, s->anonce, WPA_NONCE_LEN) != 0) {
        return -1;
    }
    /* Verify MIC over a copy with the MIC field zeroed. */
    if (frame_copy_for_mic == NULL || frame_copy_len < kv->frame_len) {
        return -1;
    }
    memset(frame_copy_for_mic + EAPOL_HEADER_LEN + KEYBODY_OFF_MIC, 0,
           WPA_MIC_LEN);
    ret = wpa_eapol_mic_verify(s->ptk.kck,
                               frame_copy_for_mic, kv->frame_len,
                               kv->mic);
    if (ret != 0) {
        return -1;
    }
    /* Parse encrypted key data: verify RSN IE matches Beacon (downgrade
     * check) and extract the GTK. */
    ret = supp_parse_m3_key_data(s, kv, gtk, &gtk_len, &gtk_idx);
    if (ret != 0) {
        return -1;
    }
    /* Send M4 (MIC=1, Secure=1, no key data). */
    memcpy(s->last_replay, kv->replay_counter, WPA_REPLAY_CTR_LEN);
    ret = supp_send_key(s,
                        (uint16_t)(KEY_INFO_VER_AES_HMAC | KEY_INFO_KEY_TYPE
                                   | KEY_INFO_KEY_MIC | KEY_INFO_SECURE),
                        0U,
                        s->last_replay,
                        s->snonce, /* unused but echoed in some impls; some send zeros */
                        NULL, 0,
                        1);
    if (ret != 0) {
        wpa_secure_zero(gtk, sizeof(gtk));
        return ret;
    }
    /* Install keys via driver callback. */
    if (s->ops.install_key != NULL) {
        ret = s->ops.install_key(s->ops.ctx,
                                 SUPP_KEY_PAIRWISE, 0,
                                 s->ptk.tk, WPA_TK_LEN);
        if (ret == 0 && gtk_len > 0) {
            ret = s->ops.install_key(s->ops.ctx,
                                     SUPP_KEY_GROUP, gtk_idx,
                                     gtk, gtk_len);
        }
        if (ret != 0) {
            wpa_secure_zero(gtk, sizeof(gtk));
            return ret;
        }
    }
    wpa_secure_zero(gtk, sizeof(gtk));
    s->state = SUPP_STATE_AUTHENTICATED;
    return 0;
}

/* ---- public API ---- */

struct wolfip_supplicant *
wolfip_supplicant_new(const struct wolfip_supplicant_cfg *cfg)
{
    struct wolfip_supplicant *s;
    int ret;

    if (cfg == NULL || cfg->ssid == NULL) {
        return NULL;
    }
    if (cfg->ssid_len == 0 || cfg->ssid_len > WOLFIP_SUPPLICANT_MAX_SSID) {
        return NULL;
    }
    if (cfg->ops.send_eapol == NULL) {
        return NULL;
    }
    if (cfg->auth_mode == WOLFIP_AUTH_PSK) {
        if (cfg->passphrase == NULL) return NULL;
    }
#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
    else if (cfg->auth_mode == WOLFIP_AUTH_EAP_TLS) {
        if (cfg->identity == NULL || cfg->identity_len == 0
            || cfg->identity_len > WOLFIP_SUPPLICANT_MAX_IDENTITY) {
            return NULL;
        }
        if (cfg->eap_tls.ca == NULL || cfg->eap_tls.client_cert == NULL
            || cfg->eap_tls.client_key == NULL) {
            return NULL;
        }
    }
#endif
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
    else if (cfg->auth_mode == WOLFIP_AUTH_SAE) {
        if (cfg->passphrase == NULL || cfg->passphrase_len < 8
            || cfg->passphrase_len > 63) {
            return NULL;
        }
    }
#endif
#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
    else if (cfg->auth_mode == WOLFIP_AUTH_PEAP_MSCHAPV2) {
        if (cfg->identity == NULL || cfg->identity_len == 0
            || cfg->identity_len > WOLFIP_SUPPLICANT_MAX_IDENTITY) {
            return NULL;
        }
        if (cfg->inner_identity == NULL || cfg->inner_identity_len == 0
            || cfg->inner_identity_len > WOLFIP_SUPPLICANT_MAX_IDENTITY) {
            return NULL;
        }
        if (cfg->password == NULL || cfg->password_len == 0
            || cfg->password_len > 63) {
            return NULL;
        }
        if (cfg->eap_tls.ca == NULL) {
            return NULL;
        }
        /* PEAP doesn't require client cert; ca alone is enough. */
    }
#endif
    else {
        return NULL;
    }

    s = (struct wolfip_supplicant *)malloc(sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    memset(s, 0, sizeof(*s));
    memcpy(s->ssid, cfg->ssid, cfg->ssid_len);
    s->ssid_len = cfg->ssid_len;
    memcpy(s->ap_mac,  cfg->ap_mac,  WPA_MAC_LEN);
    memcpy(s->sta_mac, cfg->sta_mac, WPA_MAC_LEN);
    s->auth_mode = cfg->auth_mode;
    s->ops = cfg->ops;

    if (s->auth_mode == WOLFIP_AUTH_PSK) {
        ret = wpa_pmk_from_passphrase(cfg->passphrase, cfg->passphrase_len,
                                      s->ssid, s->ssid_len, s->pmk);
        if (ret != 0) {
            zero_secrets(s);
            free(s);
            return NULL;
        }
    }
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
    else if (s->auth_mode == WOLFIP_AUTH_SAE) {
        int g = (cfg->sae_group != 0) ? cfg->sae_group : SAE_GROUP_19;
        if (sae_ctx_init(&s->sae, g) != 0) {
            sae_ctx_free(&s->sae);
            zero_secrets(s);
            free(s);
            return NULL;
        }
        s->sae_inited = 1;
        s->sae_h2e    = cfg->sae_h2e ? 1 : 0;
        if (s->sae_h2e) {
#if defined(WOLFIP_ENABLE_SAE_H2E) && WOLFIP_ENABLE_SAE_H2E
            /* H2E path: derive PT(password, SSID) once, then per-handshake
             * PWE = val * PT from the MAC pair. */
            if (sae_h2e_compute_pt(&s->sae,
                                   cfg->passphrase, cfg->passphrase_len,
                                   NULL, 0,
                                   (const uint8_t *)cfg->ssid,
                                   cfg->ssid_len) != 0
             || sae_compute_pwe_h2e(&s->sae,
                                    cfg->sta_mac, cfg->ap_mac) != 0) {
                sae_ctx_free(&s->sae);
                zero_secrets(s);
                free(s);
                return NULL;
            }
            s->sae.h2e = 1;
#else
            /* H2E requested but disabled at build time. */
            sae_ctx_free(&s->sae);
            zero_secrets(s);
            free(s);
            return NULL;
#endif
        }
        else if (sae_compute_pwe_hnp(&s->sae, cfg->passphrase,
                                     cfg->passphrase_len,
                                     cfg->sta_mac, cfg->ap_mac) != 0) {
            sae_ctx_free(&s->sae);
            zero_secrets(s);
            free(s);
            return NULL;
        }
    }
#endif
#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
    else {
        /* EAP-TLS or PEAP: defer PMK derivation until EAP-Success. */
        memcpy(s->identity, cfg->identity, cfg->identity_len);
        s->identity_len = cfg->identity_len;
        if (eap_tls_engine_init(&s->eap_tls, &cfg->eap_tls) != 0) {
            zero_secrets(s);
            free(s);
            return NULL;
        }
        s->eap_tls_inited = 1;
#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
        if (cfg->auth_mode == WOLFIP_AUTH_PEAP_MSCHAPV2) {
            memcpy(s->inner_identity, cfg->inner_identity,
                   cfg->inner_identity_len);
            s->inner_identity_len = cfg->inner_identity_len;
            memcpy(s->password, cfg->password, cfg->password_len);
            s->password_len = cfg->password_len;
        }
#endif
    }
#endif /* WOLFIP_ENABLE_EAP_TLS */

    /* Build the supplicant's own WPA2-PSK RSN IE - this is also what
     * the integrator must put in the (Re)Assoc Request to the AP. */
    ret = rsn_ie_build_wpa2_psk(s->own_rsn_ie, sizeof(s->own_rsn_ie),
                                &s->own_rsn_ie_len);
    if (ret != 0) {
        zero_secrets(s);
        free(s);
        return NULL;
    }

    /* AP RSN IE (from Beacon/Probe Response). If the integrator supplied
     * one, store it; otherwise fall back to our own (acceptable for a
     * homogeneous WPA2-PSK closed deployment). */
    if (cfg->ap_rsn_ie != NULL && cfg->ap_rsn_ie_len > 0
        && cfg->ap_rsn_ie_len <= sizeof(s->ap_rsn_ie)) {
        memcpy(s->ap_rsn_ie, cfg->ap_rsn_ie, cfg->ap_rsn_ie_len);
        s->ap_rsn_ie_len = cfg->ap_rsn_ie_len;
    }
    else {
        memcpy(s->ap_rsn_ie, s->own_rsn_ie, s->own_rsn_ie_len);
        s->ap_rsn_ie_len = s->own_rsn_ie_len;
    }

    s->state = SUPP_STATE_IDLE;
    return s;
}

void wolfip_supplicant_free(struct wolfip_supplicant *s)
{
    if (s == NULL) {
        return;
    }
#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
    if (s->eap_tls_inited) {
        eap_tls_engine_free(&s->eap_tls);
        s->eap_tls_inited = 0;
    }
#endif
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
    if (s->sae_inited) {
        sae_ctx_free(&s->sae);
        s->sae_inited = 0;
    }
#endif
    zero_secrets(s);
    wpa_secure_zero(s, sizeof(*s));
    free(s);
}

#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
/* Build + send an SAE Commit Authentication frame body. The body
 * starts at the Auth header (alg/seq/status); no 802.11 MAC header. */
static int supp_sae_send_commit_frame(struct wolfip_supplicant *s)
{
    uint8_t buf[6 + 2 + 3U * SAE_MAX_PRIME_LEN];
    size_t  body_len = 0;
    int     ret;
    if (s->ops.send_auth_frame == NULL) return -1;
    if (sae_generate_commit(&s->sae) != 0) return -1;
    /* 6-byte Auth frame fixed fields. */
    buf[0] = 0x03; buf[1] = 0x00;          /* alg = SAE (3)       */
    buf[2] = 0x01; buf[3] = 0x00;          /* seq = Commit (1)    */
    /* status: 0 (success) for legacy H&P, 126 (SAE_HASH_TO_ELEMENT
     * per IEEE 802.11-2020 Table 9-78) when H2E is in use. */
    if (s->sae_h2e) { buf[4] = 126; buf[5] = 0; }
    else            { buf[4] = 0;   buf[5] = 0; }
    ret = sae_serialize_commit(&s->sae, &buf[6], sizeof(buf) - 6, &body_len);
    if (ret != 0) return ret;
    return s->ops.send_auth_frame(s->ops.ctx, buf, 6U + body_len);
}

static int supp_sae_send_confirm_frame(struct wolfip_supplicant *s,
                                       uint16_t send_confirm)
{
    uint8_t buf[6 + 2 + SAE_MAX_HASH_LEN];
    uint8_t mac[SAE_MAX_HASH_LEN];
    size_t  mac_len = 0;
    if (s->ops.send_auth_frame == NULL) return -1;
    if (sae_compute_confirm(&s->sae, send_confirm,
                            mac, sizeof(mac), &mac_len) != 0) {
        return -1;
    }
    buf[0] = 0x03; buf[1] = 0x00;
    buf[2] = 0x02; buf[3] = 0x00;          /* seq = Confirm (2)   */
    buf[4] = 0x00; buf[5] = 0x00;
    buf[6] = (uint8_t)(send_confirm & 0xFFU);
    buf[7] = (uint8_t)((send_confirm >> 8) & 0xFFU);
    memcpy(&buf[8], mac, mac_len);
    return s->ops.send_auth_frame(s->ops.ctx, buf, 8U + mac_len);
}

int wolfip_supplicant_install_pmk(struct wolfip_supplicant *s,
                                  const uint8_t *pmk, size_t pmk_len)
{
    if (s == NULL || pmk == NULL || pmk_len != WPA_PMK_LEN) return -1;
    if (s->auth_mode != WOLFIP_AUTH_SAE) return -1;
    memcpy(s->pmk, pmk, pmk_len);
    s->pmk_installed = 1;
    return 0;
}
#endif /* WOLFIP_ENABLE_SAE - covers supp_sae_send_*, install_pmk */

int wolfip_supplicant_kick(struct wolfip_supplicant *s, uint64_t now_ms)
{
    if (s == NULL) {
        return -1;
    }
    if (s->state != SUPP_STATE_IDLE) {
        return -1;
    }
    s->m2_send_ms      = now_ms;
    s->m2_retries_left = WOLFIP_SUPPLICANT_M2_MAX_RETRIES;

#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
    {
        int is_eap_mode = (s->auth_mode == WOLFIP_AUTH_EAP_TLS);
#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
        if (s->auth_mode == WOLFIP_AUTH_PEAP_MSCHAPV2) is_eap_mode = 1;
#endif
        if (is_eap_mode) {
            /* Emit EAPOL-Start to prompt the authenticator to begin EAP.
             * Some APs send EAP-Request/Identity unprompted on association;
             * sending Start is harmless and covers both cases. */
            if (supp_send_eapol_start(s) != 0) {
                return -1;
            }
            s->state = SUPP_STATE_EAP_IDENTITY_WAIT;
            return 0;
        }
    }
#endif
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
    if (s->auth_mode == WOLFIP_AUTH_SAE) {
        if (s->pmk_installed) {
            /* FullMAC chip already did SAE - skip software path. */
            s->state = SUPP_STATE_4WAY_M1_WAIT;
            return 0;
        }
        if (supp_sae_send_commit_frame(s) != 0) {
            return -1;
        }
        s->state = SUPP_STATE_SAE_COMMIT_SENT;
        return 0;
    }
#endif
    s->state = SUPP_STATE_4WAY_M1_WAIT;
    return 0;
}

#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
int wolfip_supplicant_rx_auth_frame(struct wolfip_supplicant *s,
                                    const uint8_t *frame, size_t len,
                                    uint64_t now_ms)
{
    uint16_t alg, seq, status;
    (void)now_ms;
    if (s == NULL || frame == NULL || len < 6) return -1;
    if (s->auth_mode != WOLFIP_AUTH_SAE) return -1;

    alg    = (uint16_t)(frame[0] | ((uint16_t)frame[1] << 8));
    seq    = (uint16_t)(frame[2] | ((uint16_t)frame[3] << 8));
    status = (uint16_t)(frame[4] | ((uint16_t)frame[5] << 8));
    if (alg != 3U) return -1;
    /* SAE Commit may carry status 0 (legacy) or 126 (H2E,
     * SAE_HASH_TO_ELEMENT per IEEE 802.11-2020 Table 9-78). Confirm
     * always uses status 0. We accept matching values only - a peer
     * sending status 126 while we are configured for H&P (or vice
     * versa) indicates a negotiation mismatch. */
    if (seq == 1U) {
        uint16_t exp = s->sae_h2e ? 126U : 0U;
        if (status != exp) { s->state = SUPP_STATE_FAILED; return -1; }
    }
    else if (status != 0U) {
        s->state = SUPP_STATE_FAILED;
        return -1;
    }

    if (seq == 1U) {
        if (s->state != SUPP_STATE_SAE_COMMIT_SENT) return -1;
        if (sae_parse_peer_commit(&s->sae, &frame[6], len - 6U) != 0) {
            s->state = SUPP_STATE_FAILED;
            return -1;
        }
        if (sae_derive_k_and_pmk(&s->sae) != 0) {
            s->state = SUPP_STATE_FAILED;
            return -1;
        }
        if (supp_sae_send_confirm_frame(s, 1) != 0) {
            s->state = SUPP_STATE_FAILED;
            return -1;
        }
        s->state = SUPP_STATE_SAE_CONFIRM_SENT;
        return 0;
    }
    if (seq == 2U) {
        uint16_t recv_sc;
        if (s->state != SUPP_STATE_SAE_CONFIRM_SENT) return -1;
        if (len < 8U + 32U) return -1;
        recv_sc = (uint16_t)(frame[6] | ((uint16_t)frame[7] << 8));
        if (sae_verify_peer_confirm(&s->sae, recv_sc,
                                    &frame[8], len - 8U) != 0) {
            s->state = SUPP_STATE_FAILED;
            return -1;
        }
        /* SAE complete: copy PMK and hand off to 4-way. */
        memcpy(s->pmk, s->sae.pmk, WPA_PMK_LEN);
        s->state = SUPP_STATE_4WAY_M1_WAIT;
        return 0;
    }
    return -1;
}
#endif /* WOLFIP_ENABLE_SAE */

void wolfip_supplicant_tick(struct wolfip_supplicant *s, uint64_t now_ms)
{
    uint64_t elapsed;
    int      ret;

    if (s == NULL) {
        return;
    }
    if (s->state != SUPP_STATE_4WAY_M3_WAIT) {
        return;
    }
    /* Guard against backwards clock or first tick after kick. */
    if (now_ms <= s->m2_send_ms) {
        return;
    }
    elapsed = now_ms - s->m2_send_ms;
    if (elapsed < WOLFIP_SUPPLICANT_M2_RETRY_MS) {
        return;
    }
    if (s->m2_retries_left == 0U) {
        s->state = SUPP_STATE_FAILED;
        return;
    }
    s->m2_retries_left--;
    ret = supp_send_m2(s);
    if (ret != 0) {
        s->state = SUPP_STATE_FAILED;
        return;
    }
    s->m2_send_ms = now_ms;
}

int wolfip_supplicant_rx(struct wolfip_supplicant *s,
                         const uint8_t *frame, size_t len,
                         uint64_t now_ms)
{
    struct eapol_key_view kv;
    uint8_t frame_copy[EAPOL_KEY_FIXED_LEN + 256];
    int ret;

    if (s == NULL || frame == NULL) {
        return -1;
    }
    if (len < EAPOL_HEADER_LEN) {
        return -1;
    }

    /* Dispatch on the 802.1X packet type at offset 1. EAP packets are
     * type 0; key descriptor frames are type 3. EAP handling is gated
     * on the EAP-TLS build flag (PEAP rides on the same code path). */
    if (frame[1] == EAPOL_TYPE_EAP_PACKET) {
#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
        struct eap_view ev;
        uint16_t body_len;
        body_len = (uint16_t)(((uint16_t)frame[2] << 8) | frame[3]);
        if ((size_t)body_len + EAPOL_HEADER_LEN > len) {
            return -1;
        }
        if (eap_parse(frame + EAPOL_HEADER_LEN, body_len, &ev) != 0) {
            return -1;
        }
        if (ev.code == EAP_CODE_REQUEST) {
            ret = supp_handle_eap_request(s, &ev);
            if (ret != 0) s->state = SUPP_STATE_FAILED;
            return ret;
        }
        if (ev.code == EAP_CODE_SUCCESS) {
            ret = supp_handle_eap_success(s);
            if (ret != 0) {
                s->state = SUPP_STATE_FAILED;
            }
            return ret;
        }
        if (ev.code == EAP_CODE_FAILURE) {
            s->state = SUPP_STATE_FAILED;
            return -1;
        }
#endif /* WOLFIP_ENABLE_EAP_TLS */
        return -1;
    }
    if (frame[1] != EAPOL_TYPE_KEY_DESCRIPTOR) {
        return -1;
    }

    if (eapol_key_parse(frame, len, &kv) != 0) {
        return -1;
    }
    if ((kv.key_info & KEY_INFO_VER_MASK) != KEY_INFO_VER_AES_HMAC) {
        return -1;
    }
    /* For MIC-bearing frames, work on a writable copy so we can zero
     * the MIC field for verification. */
    if (kv.frame_len > sizeof(frame_copy)) {
        return -1;
    }
    memcpy(frame_copy, frame, kv.frame_len);

    switch (s->state) {
    case SUPP_STATE_4WAY_M1_WAIT:
        ret = supp_handle_m1(s, &kv, now_ms);
        if (ret != 0) {
            s->state = SUPP_STATE_FAILED;
        }
        return ret;

    case SUPP_STATE_4WAY_M3_WAIT:
        ret = supp_handle_m3(s, &kv, frame_copy, sizeof(frame_copy));
        if (ret != 0) {
            s->state = SUPP_STATE_FAILED;
        }
        return ret;

    case SUPP_STATE_AUTHENTICATED:
        /* Only Group Key handshake frames are accepted post-4-way. A
         * pairwise EAPOL-Key after AUTHENTICATED is treated as an AP-
         * initiated rekey - not handled in v1 (returns benign error). */
        if ((kv.key_info & KEY_INFO_KEY_TYPE) == 0) {
            ret = supp_handle_group_m1(s, &kv,
                                       frame_copy, sizeof(frame_copy));
            if (ret != 0) {
                /* Stay authenticated; a malformed group message
                 * shouldn't tear down the link. The AP will retry. */
                return -1;
            }
            return 0;
        }
        return -1;

    case SUPP_STATE_IDLE:
    case SUPP_STATE_GROUP_KEY_WAIT:
    case SUPP_STATE_FAILED:
    default:
        return -1;
    }
}

wolfip_supplicant_state_t
wolfip_supplicant_state(const struct wolfip_supplicant *s)
{
    if (s == NULL) {
        return SUPP_STATE_FAILED;
    }
    return s->state;
}

const uint8_t *wolfip_supplicant_kck(const struct wolfip_supplicant *s)
{
    return (s != NULL && s->have_ptk) ? s->ptk.kck : NULL;
}
const uint8_t *wolfip_supplicant_tk(const struct wolfip_supplicant *s)
{
    return (s != NULL && s->have_ptk) ? s->ptk.tk : NULL;
}
const uint8_t *wolfip_supplicant_snonce(const struct wolfip_supplicant *s)
{
    return (s != NULL) ? s->snonce : NULL;
}

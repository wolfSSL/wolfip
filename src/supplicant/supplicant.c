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
#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#endif

#include <stdlib.h>
#include <string.h>

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hash.h>     /* wc_Sha256Hash: PMKSA passphrase bind */

/* struct wolfip_supplicant lives in supplicant.h so callers (especially
 * bare-metal MCU ports) can allocate it statically and avoid malloc. */

/* helpers */

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

/* WPA3-SAE uses Key Descriptor Version 0 (AKM-defined: AES-128-CMAC MIC),
 * whereas WPA2-PSK uses Version 2 (HMAC-SHA1-128). These helpers pick the
 * right MIC algorithm and key-info version for the active auth mode. */
static int supp_is_cmac_akm(const struct wolfip_supplicant *s)
{
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
    return (s->auth_mode == WOLFIP_AUTH_SAE) ? 1 : 0;
#else
    (void)s;
    return 0;
#endif
}

static uint16_t supp_key_desc_ver(const struct wolfip_supplicant *s)
{
    return supp_is_cmac_akm(s) ? KEY_INFO_VER_AKM_DEFINED
                               : KEY_INFO_VER_AES_HMAC;
}

static int supp_mic(const struct wolfip_supplicant *s,
                    const uint8_t *frame, size_t len,
                    uint8_t out_mic[WPA_MIC_LEN])
{
    if (supp_is_cmac_akm(s)) {
        return wpa_eapol_mic_aes_cmac(s->ptk.kck, frame, len, out_mic);
    }
    return wpa_eapol_mic(s->ptk.kck, frame, len, out_mic);
}

static int supp_mic_verify(const struct wolfip_supplicant *s,
                           const uint8_t *frame, size_t len,
                           const uint8_t expected[WPA_MIC_LEN])
{
    if (supp_is_cmac_akm(s)) {
        return wpa_eapol_mic_aes_cmac_verify(s->ptk.kck, frame, len, expected);
    }
    return wpa_eapol_mic_verify(s->ptk.kck, frame, len, expected);
}

/* key_info bit guard: 1 iff every bit in `required` is set and every bit in
 * `forbidden` is clear. Centralizes the M1 / M3 / Group-M1 / retransmit
 * acceptance checks that were open-coded as parallel `if` chains. */
static int supp_key_info_has(uint16_t key_info,
                             uint16_t required, uint16_t forbidden)
{
    return ((key_info & required) == required)
        && ((key_info & forbidden) == 0U);
}

/* Verify the EAPOL-Key MIC over a writable copy of the frame with the MIC
 * field zeroed (the MIC is computed with that field as zero on the wire).
 * Shared by M3 and Group-M1 handling. Returns 0 on a valid MIC. */
static int supp_verify_frame_mic(const struct wolfip_supplicant *s,
                                 const struct eapol_key_view *kv,
                                 uint8_t *frame_copy, size_t frame_copy_len)
{
    if (frame_copy == NULL || frame_copy_len < kv->frame_len) {
        return -1;
    }
    memset(frame_copy + EAPOL_HEADER_LEN + KEYBODY_OFF_MIC, 0, WPA_MIC_LEN);
    return supp_mic_verify(s, frame_copy, kv->frame_len, kv->mic);
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
        ret = supp_mic(s, buf, total, mic);
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

/* EAP / EAP-TLS plumbing */

#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
/* 1 if the active auth mode runs an EAP exchange (EAP-TLS, or PEAP when
 * built in) ahead of the 4-way. Collapses the #if-gated EAP_TLS/PEAP mode
 * checks that were duplicated in eap_success handling and kick(). */
static int supp_is_eap_mode(const struct wolfip_supplicant *s)
{
    if (s->auth_mode == WOLFIP_AUTH_EAP_TLS) {
        return 1;
    }
#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
    if (s->auth_mode == WOLFIP_AUTH_PEAP_MSCHAPV2) {
        return 1;
    }
#endif
    return 0;
}

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

#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
/* PEAPv0 Phase-2 inner MSCHAPv2: on the Challenge build the NT-Response;
 * on the success Authenticator-Response verify it and emit the inner ACK.
 * Writes the inner EAP response into inner_resp; returns 0 on success. */
static int peap_phase2_mschapv2(struct wolfip_supplicant *s,
                                const struct eap_view *eap,
                                const uint8_t *plain, int pl,
                                uint8_t *inner_resp, size_t inner_resp_cap,
                                size_t *inner_resp_len)
{
    struct mschapv2_challenge_view ch;

    if (eap_peap_parse_mschapv2_challenge(plain, (size_t)pl, &ch) == 0) {
        WC_RNG rng;
        int    rng_ret;
        memcpy(s->auth_challenge, ch.auth_challenge, 16);
        rng_ret = wc_InitRng(&rng);
        if (rng_ret != 0) return -1;
        rng_ret = wc_RNG_GenerateBlock(&rng, s->peer_challenge, 16);
        wc_FreeRng(&rng);
        if (rng_ret != 0) return -1;
        if (mschapv2_generate_nt_response(s->auth_challenge,
                s->peer_challenge,
                (const char *)s->inner_identity, s->inner_identity_len,
                (const char *)s->password, s->password_len,
                s->nt_response) != 0) {
            return -1;
        }
        s->have_nt_response = 1;
        if (eap_peap_build_mschapv2_response(inner_resp, inner_resp_cap,
                eap->id, ch.ms_id,
                s->peer_challenge, s->nt_response,
                (const char *)s->inner_identity, s->inner_identity_len,
                inner_resp_len) != 0) {
            return -1;
        }
    }
    else {
        char authresp[42];
        if (eap_peap_extract_authresp(plain, (size_t)pl, authresp) != 0
            || !s->have_nt_response) {
            return -1;
        }
        if (mschapv2_verify_authenticator_response(
                (const char *)s->password, s->password_len,
                s->nt_response, s->peer_challenge, s->auth_challenge,
                (const char *)s->inner_identity, s->inner_identity_len,
                authresp, sizeof(authresp)) != 0) {
            return -1;
        }
        if (eap_peap_build_mschapv2_ack(inner_resp, inner_resp_cap,
                eap->id, inner_resp_len) != 0) {
            return -1;
        }
    }
    return 0;
}

/* Dispatch a decrypted PEAPv0 Phase-2 inner request (compressed framing:
 * EAP-TLV Result, compressed Identity, or MSCHAPv2) and build the inner
 * response into inner_resp. Returns 0 on success, -1 on a rejected /
 * malformed inner request. */
static int peap_phase2_build_inner(struct wolfip_supplicant *s,
                                   const struct eap_view *eap,
                                   const uint8_t *plain, int pl,
                                   uint8_t *inner_resp, size_t inner_resp_cap,
                                   size_t *inner_resp_len)
{
    uint8_t inner_type = plain[0];

    /* In PHASE2_TLV (after MSCHAPv2 Success), hostapd skips its
     * compressed-header synthesis and sends a FULL EAP-wrapped Request
     * with type=33 (EAP-TLV). Distinguish by the EAP-Request code at
     * offset 0 with type-TLV at 4. */
    if (pl >= 11 && plain[0] == EAP_CODE_REQUEST
        && plain[4] == 33 /* EAP_TYPE_TLV */) {
        /* Build EAP-Response with a Result TLV indicating Success (no
         * crypto-binding). hostapd has OPTIONAL_BINDING so this suffices. */
        if (inner_resp_cap < 11) return -1;
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
        *inner_resp_len = 11;
    }
    else if (inner_type == EAP_TYPE_IDENTITY) {
        /* PEAPv0 compressed Identity Request -> compressed Response
         * (hostapd synthesizes the inner EAP header from our Response). */
        if (s->inner_identity_len + 1U > inner_resp_cap) {
            return -1;
        }
        inner_resp[0] = EAP_TYPE_IDENTITY;
        memcpy(&inner_resp[1], s->inner_identity, s->inner_identity_len);
        *inner_resp_len = 1U + s->inner_identity_len;
    }
    else if (inner_type == 26 /* MSCHAPv2 */) {
        return peap_phase2_mschapv2(s, eap, plain, pl,
                                    inner_resp, inner_resp_cap,
                                    inner_resp_len);
    }
    else {
        return -1;
    }
    return 0;
}

/* PEAPv0 (Microsoft variant) request handler: drive the TLS tunnel, then
 * once the tunnel is up run the compressed Phase-2 inner exchange. Mirrors
 * supp_handle_eap_request's EAP-TLS arm but with EAP_TYPE_PEAP framing. */
static int supp_handle_peap_request(struct wolfip_supplicant *s,
                                    const struct eap_view *eap)
{
    uint8_t flags;
    int     rfrag;
    int     step = 0;

    if (s->state != SUPP_STATE_EAP_TLS_INPROGRESS) {
        return -1;
    }
    rfrag = eap_tls_rx_fragment(&s->eap_tls.io,
                                eap->type_data, eap->type_data_len, &flags);
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
        uint8_t plain[512];
        uint8_t inner_resp[256];
        int     pl;
        size_t  inner_resp_len = 0;
        int     prc = 0;

        pl = wolfSSL_read(s->eap_tls.ssl, plain, sizeof(plain));
        if (pl <= 0) {
            return supp_send_eap_tls_typed(s, eap->id, EAP_TYPE_PEAP, 1);
        }
        if (peap_phase2_build_inner(s, eap, plain, pl,
                                    inner_resp, sizeof(inner_resp),
                                    &inner_resp_len) != 0
            || wolfSSL_write(s->eap_tls.ssl, inner_resp,
                             (int)inner_resp_len) <= 0) {
            prc = -1;
        }
        /* plain[] held the decrypted inner-EAP and inner_resp[] the
         * password-derived NT-Response; scrub both before returning. */
        wpa_secure_zero(plain, sizeof(plain));
        wpa_secure_zero(inner_resp, sizeof(inner_resp));
        if (prc != 0) {
            return -1;
        }
    }

    if (s->eap_tls.io.tx_filled > 0U) {
        return supp_send_eap_tls_typed(s, eap->id, EAP_TYPE_PEAP, 0);
    }
    return supp_send_eap_tls_typed(s, eap->id, EAP_TYPE_PEAP, 1);
}
#endif /* WOLFIP_ENABLE_PEAP_MSCHAPV2 */

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
        return supp_handle_peap_request(s, eap);
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

    if (!supp_is_eap_mode(s)) {
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

/* Handle an inbound EAPOL-EAP packet (802.1X type 0): parse the EAP header
 * and dispatch Request / Success / Failure. Split out of wolfip_supplicant_rx. */
static int supp_rx_eap(struct wolfip_supplicant *s,
                       const uint8_t *frame, size_t len)
{
    struct eap_view ev;
    uint16_t        body_len;
    int             ret;

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
        if (ret != 0) s->state = SUPP_STATE_FAILED;
        return ret;
    }
    if (ev.code == EAP_CODE_FAILURE) {
        s->state = SUPP_STATE_FAILED;
        return -1;
    }
    return -1;
}
#endif /* WOLFIP_ENABLE_EAP_TLS */

/* Send (or re-send) M2. Uses the supplicant's cached SNonce, replay
 * counter (echoed from M1) and own RSN IE. MIC is computed with the
 * current KCK (already populated when this is reached). */
static int supp_send_m2(struct wolfip_supplicant *s)
{
    /* Echo the pairwise Key Length (CCMP-128 = WPA_TK_LEN) in M2, matching M1;
     * IEEE 802.11-2020 12.7.6.3 and stricter APs expect it (vs sending 0). */
    return supp_send_key(s,
                         (uint16_t)(supp_key_desc_ver(s)
                                    | KEY_INFO_KEY_TYPE
                                    | KEY_INFO_KEY_MIC),
                         WPA_TK_LEN,
                         s->last_replay,
                         s->snonce,
                         s->own_rsn_ie, (uint16_t)s->own_rsn_ie_len,
                         1);
}

/* M1 handling: derive PTK, reply with M2 */

static int supp_handle_m1(struct wolfip_supplicant *s,
                          const struct eapol_key_view *kv,
                          uint64_t now_ms)
{
    int ret;

    /* M1: KeyAck=1, MIC=0, Pairwise=1. */
    if (!supp_key_info_has(kv->key_info,
                           KEY_INFO_KEY_TYPE | KEY_INFO_KEY_ACK,
                           KEY_INFO_KEY_MIC)) {
        return -1;
    }

    memcpy(s->anonce, kv->nonce, WPA_NONCE_LEN);

    ret = gen_snonce(s->snonce);
    if (ret != 0) {
        return ret;
    }
    /* SAE (and other SHA-256 AKMs) derive the PTK with the HMAC-SHA256
     * KDF; WPA2-PSK uses the legacy HMAC-SHA1 PRF. */
    if (supp_is_cmac_akm(s)) {
        ret = wpa_ptk_derive_sha256(s->pmk, s->ap_mac, s->sta_mac,
                                    s->anonce, s->snonce, &s->ptk);
    }
    else {
        ret = wpa_ptk_derive(s->pmk, s->ap_mac, s->sta_mac,
                             s->anonce, s->snonce, &s->ptk);
    }
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

/* Decrypt EAPOL-Key encrypted Key Data (AES Key Wrap with KEK) and extract
 * the GTK KDE (type 0xDD, OUI 00:0F:AC, datatype GTK).
 *
 * When expect_rsn_ie is set this is a 4-way M3 (IEEE 802.11-2020 12.7.6.4):
 * the embedded RSN IE (type 0x30) is byte-compared against s->ap_rsn_ie for
 * the downgrade check and BOTH an RSN-IE match and a GTK are required; a
 * mismatch aborts the handshake. The Group Key M1 (12.7.7.3) carries only
 * KDEs (no RSN IE re-echo), so it asks for the GTK alone.
 *
 * Returns 0 on success.
 */
static int supp_parse_key_data(const struct wolfip_supplicant *s,
                               const struct eapol_key_view *kv,
                               int      expect_rsn_ie,
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

    /* Lower bound 24 = one 8-byte wrapped data block + the 64-bit IV, which is
     * wpa_aes_keyunwrap()'s real minimum (RFC 3394); anything shorter cannot
     * carry even an empty KDE set. */
    if (kv->key_data_len < 24U || kv->key_data_len > sizeof(plain) + 8U) {
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
        /* wc_AesKeyUnWrap writes intermediate unwrapped semiblocks before it
         * detects the IV mismatch, so KEK-keystream-derived bytes can linger
         * on the stack; scrub before returning, like every other exit. */
        wpa_secure_zero(plain, sizeof(plain));
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

        if (expect_rsn_ie && type == RSN_IE_ELEMENT_ID) {
            /* Whole IE including its 2-byte header. */
            size_t ie_total = (size_t)len + 2U;
            ret = rsn_ie_equal(&plain[i], ie_total,
                               s->ap_rsn_ie, s->ap_rsn_ie_len);
            if (ret == 0) {
                have_rsn_match = 1;
            }
            else {
                /* Downgrade: AP advertised a different cipher in M3 vs
                 * Beacon. Abort the handshake. */
                wpa_secure_zero(plain, sizeof(plain));
                return -1;
            }
        }
        else if (type == KDE_TYPE
                 && len >= 6U
                 && plain[i + 2U] == KDE_OUI_0
                 && plain[i + 3U] == KDE_OUI_1
                 && plain[i + 4U] == KDE_OUI_2
                 && plain[i + 5U] == KDE_DATATYPE_GTK) {
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
        /* Other KDEs (MAC, lifetime, padding) ignored. */

        i = end;
    }
    wpa_secure_zero(plain, sizeof(plain));
    if ((expect_rsn_ie && !have_rsn_match) || !have_gtk) {
        return -1;
    }
    return 0;
}

/* Group Key M1: verify, install new GTK, reply with Group M2 */

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

    /* Group M1: Pairwise=0, KeyAck=1, MIC=1, Secure=1, Encrypted=1.
     * (Pairwise=0 is already guaranteed by the caller's dispatch.) */
    if (!supp_key_info_has(kv->key_info,
                           KEY_INFO_KEY_ACK | KEY_INFO_KEY_MIC
                           | KEY_INFO_SECURE | KEY_INFO_ENCR_KEY_DATA,
                           0U)) {
        return -1;
    }

    /* Replay counter must strictly advance. */
    if (s->have_replay
        && memcmp(kv->replay_counter, s->last_replay,
                  WPA_REPLAY_CTR_LEN) <= 0) {
        return -1;
    }
    /* MIC over frame with MIC field zeroed. */
    ret = supp_verify_frame_mic(s, kv, frame_copy_for_mic, frame_copy_len);
    if (ret != 0) return -1;

    ret = supp_parse_key_data(s, kv, 0 /* no RSN IE */,
                              gtk, &gtk_len, &gtk_idx);
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
                        (uint16_t)(supp_key_desc_ver(s)
                                   | KEY_INFO_KEY_MIC
                                   | KEY_INFO_SECURE),
                        0U,
                        s->last_replay,
                        zero_nonce,
                        NULL, 0,
                        1);
    return ret;
}

/* M3 handling: verify MIC, install keys, reply with M4 */

static int supp_handle_m3(struct wolfip_supplicant *s,
                          const struct eapol_key_view *kv,
                          uint8_t *frame_copy_for_mic, size_t frame_copy_len)
{
    uint8_t  gtk[WPA_GTK_MAX_LEN];
    size_t   gtk_len = 0;
    uint8_t  gtk_idx = 0;
    uint8_t  zero_nonce[WPA_NONCE_LEN];
    int      ret;

    /* M3: Pairwise=1, KeyAck=1, MIC=1, Install=1, Secure=1, Encrypted=1.
     * Require KEY_TYPE (Pairwise) so a Group-type frame with Ack/MIC/Install
     * cannot be mistaken for M3 (IEEE 802.11-2020 12.7.6.4). */
    if (!supp_key_info_has(kv->key_info,
                           KEY_INFO_KEY_TYPE | KEY_INFO_KEY_ACK
                           | KEY_INFO_KEY_MIC | KEY_INFO_INSTALL, 0U)) {
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
    ret = supp_verify_frame_mic(s, kv, frame_copy_for_mic, frame_copy_len);
    if (ret != 0) {
        return -1;
    }
    /* Parse encrypted key data: verify RSN IE matches Beacon (downgrade
     * check) and extract the GTK. */
    ret = supp_parse_key_data(s, kv, 1 /* expect RSN IE */,
                              gtk, &gtk_len, &gtk_idx);
    if (ret != 0) {
        return -1;
    }
    /* Install the PTK/GTK BEFORE sending M4: M4 is the supplicant's
     * commitment that the keys are installed (IEEE 802.11-2020 12.7.6.5), so a
     * key-install failure must abort the handshake cleanly rather than let the
     * AP complete the 4-way and start encrypting with a PTK we never installed.
     * EAPOL (incl. M4) rides the controlled port unencrypted, so installing the
     * pairwise key first does not affect M4 transmission. */
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

    /* Send M4 (MIC=1, Secure=1, no key data) echoing the pairwise Key Length.
     * IEEE 802.11-2020 12.7.6.5 sets the Key Nonce to 0 in message 4. */
    memset(zero_nonce, 0, sizeof(zero_nonce));
    memcpy(s->last_replay, kv->replay_counter, WPA_REPLAY_CTR_LEN);
    ret = supp_send_key(s,
                        (uint16_t)(supp_key_desc_ver(s) | KEY_INFO_KEY_TYPE
                                   | KEY_INFO_KEY_MIC | KEY_INFO_SECURE),
                        WPA_TK_LEN,
                        s->last_replay,
                        zero_nonce,
                        NULL, 0,
                        1);
    if (ret != 0) {
        return ret;
    }
    /* Cache the PMKSA so a re-init / reconnect on this context for the same
     * SSID + BSSID can fast-reconnect: PSK skips PBKDF2; SAE skips the
     * dragonfly via the cached PMKID (wolfip_supplicant_pmksa_reconnect). */
    s->pmksa_magic    = WOLFIP_PMKSA_MAGIC;
    s->pmksa_ssid_len = (uint8_t)s->ssid_len;
    memcpy(s->pmksa_pmk,   s->pmk,    WPA_PMK_LEN);
    memcpy(s->pmksa_ssid,  s->ssid,   WOLFIP_SUPPLICANT_MAX_SSID);
    memcpy(s->pmksa_bssid, s->ap_mac, WPA_MAC_LEN);
    s->pmksa_have_pmkid = 0;
    /* Bind the cached PMK to the passphrase that produced it so a re-init
     * with a changed passphrase (rotation / typo fix) for the same SSID does
     * not silently reuse a stale PMK (see the fast path in _init). */
    if (s->have_pp_hash) {
        memcpy(s->pmksa_pp_hash, s->pp_hash, sizeof(s->pmksa_pp_hash));
        s->pmksa_have_pp = 1;
    }
    else {
        s->pmksa_have_pp = 0;
    }
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
    if (s->auth_mode == WOLFIP_AUTH_SAE) {
        memcpy(s->pmksa_pmkid, s->sae.pmkid, WPA_PMKID_LEN);
        s->pmksa_have_pmkid = 1;
    }
#endif
    s->state = SUPP_STATE_AUTHENTICATED;
    return 0;
}

/* public API */

/* Per-mode config validation (cfg-only; the caller null-checks s and cfg). */
static int supp_validate_cfg(const struct wolfip_supplicant_cfg *cfg)
{
    if (cfg->ssid == NULL) {
        return -1;
    }
    if (cfg->ssid_len == 0 || cfg->ssid_len > WOLFIP_SUPPLICANT_MAX_SSID) {
        return -1;
    }
    if (cfg->ops.send_eapol == NULL) {
        return -1;
    }
    if (cfg->auth_mode == WOLFIP_AUTH_PSK) {
        /* Either a passphrase (PBKDF2 derives PMK) or a pre-derived 32 B
         * PMK is required. The cached-PMK path skips PBKDF2 entirely. */
        if (cfg->psk_pmk != NULL) {
            if (cfg->psk_pmk_len != WPA_PMK_LEN) return -1;
        }
        else if (cfg->passphrase == NULL) {
            return -1;
        }
    }
#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
    else if (cfg->auth_mode == WOLFIP_AUTH_EAP_TLS) {
        if (cfg->identity == NULL || cfg->identity_len == 0
            || cfg->identity_len > WOLFIP_SUPPLICANT_MAX_IDENTITY) {
            return -1;
        }
        if (cfg->eap_tls.ca == NULL || cfg->eap_tls.client_cert == NULL
            || cfg->eap_tls.client_key == NULL) {
            return -1;
        }
    }
#endif
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
    else if (cfg->auth_mode == WOLFIP_AUTH_SAE) {
        if (cfg->passphrase == NULL || cfg->passphrase_len < 8
            || cfg->passphrase_len > 63) {
            return -1;
        }
    }
#endif
#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
    else if (cfg->auth_mode == WOLFIP_AUTH_PEAP_MSCHAPV2) {
        if (cfg->identity == NULL || cfg->identity_len == 0
            || cfg->identity_len > WOLFIP_SUPPLICANT_MAX_IDENTITY) {
            return -1;
        }
        if (cfg->inner_identity == NULL || cfg->inner_identity_len == 0
            || cfg->inner_identity_len > WOLFIP_SUPPLICANT_MAX_IDENTITY) {
            return -1;
        }
        if (cfg->password == NULL || cfg->password_len == 0
            || cfg->password_len > 63) {
            return -1;
        }
        if (cfg->eap_tls.ca == NULL) {
            return -1;
        }
        /* PEAP doesn't require client cert; ca alone is enough. */
    }
#endif
    else {
        return -1;
    }
    return 0;
}

/* Snapshot of the prior PMKSA fields, taken before the context is zeroed so a
 * re-init on the same context can fast-reconnect for the same SSID. */
struct supp_pmksa_snapshot {
    uint32_t magic;
    uint8_t  ssid_len;
    uint8_t  have_pp;
    uint8_t  pmk[WPA_PMK_LEN];
    uint8_t  ssid[WOLFIP_SUPPLICANT_MAX_SSID];
    uint8_t  bssid[WPA_MAC_LEN];
    uint8_t  pp_hash[32];
};

/* Capture the prior PMKSA entry. Trusted later only if BOTH the magic and the
 * SSID match, so a garbage context on the very first init cannot pass as a
 * hit. The caller must zero the context before the first init (the heap
 * wrapper calloc()s it; static/pool storage is zeroed by the C runtime; stack
 * callers must memset / "= {0}") so these reads are defined. */
static void supp_pmksa_snapshot(const struct wolfip_supplicant *s,
                                struct supp_pmksa_snapshot *snap)
{
    snap->magic    = s->pmksa_magic;
    snap->ssid_len = s->pmksa_ssid_len;
    snap->have_pp  = s->pmksa_have_pp;
    memcpy(snap->pmk,     s->pmksa_pmk,     WPA_PMK_LEN);
    memcpy(snap->ssid,    s->pmksa_ssid,    WOLFIP_SUPPLICANT_MAX_SSID);
    memcpy(snap->bssid,   s->pmksa_bssid,   WPA_MAC_LEN);
    memcpy(snap->pp_hash, s->pmksa_pp_hash, sizeof(snap->pp_hash));
}

/* Re-apply the snapshot iff valid for this SSID. Returns 1 on a PMKSA hit. */
static int supp_pmksa_restore(struct wolfip_supplicant *s,
                              const struct supp_pmksa_snapshot *snap,
                              const struct wolfip_supplicant_cfg *cfg)
{
    if (snap->magic == WOLFIP_PMKSA_MAGIC
        && (size_t)snap->ssid_len == cfg->ssid_len
        && memcmp(snap->ssid, cfg->ssid, cfg->ssid_len) == 0) {
        s->pmksa_magic    = snap->magic;
        s->pmksa_ssid_len = snap->ssid_len;
        s->pmksa_have_pp  = snap->have_pp;
        memcpy(s->pmksa_pmk,     snap->pmk,     WPA_PMK_LEN);
        memcpy(s->pmksa_ssid,    snap->ssid,    WOLFIP_SUPPLICANT_MAX_SSID);
        memcpy(s->pmksa_bssid,   snap->bssid,   WPA_MAC_LEN);
        memcpy(s->pmksa_pp_hash, snap->pp_hash, sizeof(s->pmksa_pp_hash));
        return 1;
    }
    return 0;
}

/* PSK: derive (or reuse a cached) PMK. */
static int supp_init_psk(struct wolfip_supplicant *s,
                         const struct wolfip_supplicant_cfg *cfg,
                         int pmksa_hit)
{
    int pp_ok = 0;

    /* Hash this session's passphrase so a cached PMK can be bound to it
     * (PSK mode only, when no pre-derived psk_pmk is supplied). */
    if (cfg->psk_pmk == NULL && cfg->passphrase != NULL) {
        if (wc_Sha256Hash((const byte *)cfg->passphrase,
                          (word32)cfg->passphrase_len, s->pp_hash) == 0) {
            s->have_pp_hash = 1;
        }
    }
    /* A cached PMK is reused only if produced by the SAME passphrase (or the
     * integrator supplied psk_pmk); a changed passphrase falls to PBKDF2. */
    if (s->have_pp_hash && pmksa_hit && s->pmksa_have_pp
        && memcmp(s->pp_hash, s->pmksa_pp_hash, sizeof(s->pp_hash)) == 0) {
        pp_ok = 1;
    }
    if (cfg->psk_pmk != NULL) {
        memcpy(s->pmk, cfg->psk_pmk, WPA_PMK_LEN);
    }
    else if (pmksa_hit && pp_ok) {
        /* Cached PMK for this SSID + passphrase - skip the 4096-iter PBKDF2. */
        memcpy(s->pmk, s->pmksa_pmk, WPA_PMK_LEN);
    }
    else {
        if (wpa_pmk_from_passphrase(cfg->passphrase, cfg->passphrase_len,
                                    s->ssid, s->ssid_len, s->pmk) != 0) {
            return -1;
        }
    }
    return 0;
}

#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
/* SAE: init the dragonfly context and compute the PWE (H2E or hunt-and-peck). */
static int supp_init_sae(struct wolfip_supplicant *s,
                         const struct wolfip_supplicant_cfg *cfg)
{
    int g = (cfg->sae_group != 0) ? cfg->sae_group : SAE_GROUP_19;

    if (sae_ctx_init(&s->sae, g) != 0) {
        return -1;
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
            return -1;
        }
        s->sae.h2e = 1;
#else
        /* H2E requested but disabled at build time. */
        return -1;
#endif
    }
    else {
#if WOLFIP_ENABLE_SAE_HNP
        if (sae_compute_pwe_hnp(&s->sae, cfg->passphrase,
                                cfg->passphrase_len,
                                cfg->sta_mac, cfg->ap_mac) != 0) {
            return -1;
        }
#else
        /* Hunt-and-peck PWE compiled out (WOLFIP_ENABLE_SAE_HNP=0).
         * Build with WOLFIP_ENABLE_SAE_H2E=1 and set cfg.sae_h2e = 1. */
        return -1;
#endif
    }
    return 0;
}
#endif /* WOLFIP_ENABLE_SAE */

#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
/* EAP-TLS / PEAP: stash the identity (+ inner creds) and init the TLS engine.
 * PMK derivation is deferred until EAP-Success. */
static int supp_init_eap(struct wolfip_supplicant *s,
                         const struct wolfip_supplicant_cfg *cfg)
{
    memcpy(s->identity, cfg->identity, cfg->identity_len);
    s->identity_len = cfg->identity_len;
    if (eap_tls_engine_init(&s->eap_tls, &cfg->eap_tls) != 0) {
        return -1;
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
    return 0;
}
#endif /* WOLFIP_ENABLE_EAP_TLS */

/* Build the supplicant's own RSN IE (and store the AP's). The integrator must
 * put the own IE in the (Re)Assoc Request: the authenticator compares the M2
 * RSN IE byte-for-byte against it, so the AKM suite here must match the join. */
static int supp_build_rsn_ies(struct wolfip_supplicant *s,
                              const struct wolfip_supplicant_cfg *cfg)
{
    uint16_t caps     = 0U;
    uint8_t  akm_type = RSN_AKM_PSK;

    if (cfg->mfp_capable)  caps |= RSN_CAP_MFPC;
    if (cfg->mfp_required) caps |= RSN_CAP_MFPR | RSN_CAP_MFPC;
    if (rsn_ie_build_wpa2_psk_ex(s->own_rsn_ie, sizeof(s->own_rsn_ie),
                                 &s->own_rsn_ie_len, caps) != 0) {
        return -1;
    }
    /* The builder emits a fixed-layout IE with the PSK AKM suite. Patch the
     * AKM suite type (last byte of the single AKM suite, just before RSN
     * capabilities) to match the auth mode, so the M2 RSN IE matches the
     * (Re)Assoc Request AKM the AP negotiated:
     *   SAE -> 00:0F:AC:08,  802.1X EAP -> 00:0F:AC:01,  PSK -> :02. */
    if (s->own_rsn_ie_len >= RSN_IE_MIN_LEN) {
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
        if (s->auth_mode == WOLFIP_AUTH_SAE) akm_type = RSN_AKM_SAE;
#endif
#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
        if (s->auth_mode == WOLFIP_AUTH_EAP_TLS) akm_type = RSN_AKM_8021X;
#endif
#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
        if (s->auth_mode == WOLFIP_AUTH_PEAP_MSCHAPV2)
            akm_type = RSN_AKM_8021X;
#endif
        s->own_rsn_ie[s->own_rsn_ie_len - 3] = akm_type;
    }

    /* AP RSN IE (from Beacon/Probe Response). If the integrator supplied one,
     * store it; otherwise fall back to our own (acceptable for a homogeneous
     * WPA2-PSK closed deployment). */
    if (cfg->ap_rsn_ie != NULL && cfg->ap_rsn_ie_len > 0
        && cfg->ap_rsn_ie_len <= sizeof(s->ap_rsn_ie)) {
        memcpy(s->ap_rsn_ie, cfg->ap_rsn_ie, cfg->ap_rsn_ie_len);
        s->ap_rsn_ie_len = cfg->ap_rsn_ie_len;
    }
    else {
        memcpy(s->ap_rsn_ie, s->own_rsn_ie, s->own_rsn_ie_len);
        s->ap_rsn_ie_len = s->own_rsn_ie_len;
    }
    return 0;
}

int
wolfip_supplicant_init(struct wolfip_supplicant *s,
                       const struct wolfip_supplicant_cfg *cfg)
{
    struct supp_pmksa_snapshot snap;
    int ret = 0;
    int pmksa_hit;

    if (s == NULL || cfg == NULL) {
        return -1;
    }
    if (supp_validate_cfg(cfg) != 0) {
        return -1;
    }

    supp_pmksa_snapshot(s, &snap);

    memset(s, 0, sizeof(*s));
    memcpy(s->ssid, cfg->ssid, cfg->ssid_len);
    s->ssid_len = cfg->ssid_len;
    memcpy(s->ap_mac,  cfg->ap_mac,  WPA_MAC_LEN);
    memcpy(s->sta_mac, cfg->sta_mac, WPA_MAC_LEN);
    s->auth_mode = cfg->auth_mode;
    s->ops = cfg->ops;

    pmksa_hit = supp_pmksa_restore(s, &snap, cfg);
    wpa_secure_zero(snap.pmk, sizeof(snap.pmk));

    if (s->auth_mode == WOLFIP_AUTH_PSK) {
        ret = supp_init_psk(s, cfg, pmksa_hit);
    }
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
    else if (s->auth_mode == WOLFIP_AUTH_SAE) {
        ret = supp_init_sae(s, cfg);
    }
#endif
#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
    else {
        ret = supp_init_eap(s, cfg);
    }
#endif
    if (ret != 0) {
        wolfip_supplicant_deinit(s);
        return -1;
    }

    if (supp_build_rsn_ies(s, cfg) != 0) {
        wolfip_supplicant_deinit(s);
        return -1;
    }

    s->state = SUPP_STATE_IDLE;
    return 0;
}

void wolfip_supplicant_deinit(struct wolfip_supplicant *s)
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
}

/* Heap-allocated convenience wrappers, kept for POSIX tests. */
struct wolfip_supplicant *
wolfip_supplicant_new(const struct wolfip_supplicant_cfg *cfg)
{
    struct wolfip_supplicant *s;

    /* calloc (not malloc): wolfip_supplicant_init snapshots the prior PMKSA
     * fields before it zeroes the context, so the block must be initialized
     * first or that first-init read is of uninitialized memory. Static and
     * pool callers are already zeroed; stack callers must zero before the
     * first init. */
    s = (struct wolfip_supplicant *)calloc(1, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    if (wolfip_supplicant_init(s, cfg) != 0) {
        free(s);
        return NULL;
    }
    return s;
}

void wolfip_supplicant_free(struct wolfip_supplicant *s)
{
    if (s == NULL) {
        return;
    }
    wolfip_supplicant_deinit(s);
    free(s);
}

#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
/* SAE Authentication frame 6-byte fixed header: algorithm (always 3 = SAE),
 * transaction sequence (1 = Commit, 2 = Confirm) and status, each a
 * little-endian u16. Shared by the Commit/Confirm senders and the rx parser. */
static void sae_auth_hdr_write(uint8_t *buf, uint16_t seq, uint16_t status)
{
    buf[0] = 0x03; buf[1] = 0x00;
    buf[2] = (uint8_t)(seq & 0xFFU);
    buf[3] = (uint8_t)((seq >> 8) & 0xFFU);
    buf[4] = (uint8_t)(status & 0xFFU);
    buf[5] = (uint8_t)((status >> 8) & 0xFFU);
}

static void sae_auth_hdr_read(const uint8_t *frame, uint16_t *alg,
                              uint16_t *seq, uint16_t *status)
{
    *alg    = (uint16_t)(frame[0] | ((uint16_t)frame[1] << 8));
    *seq    = (uint16_t)(frame[2] | ((uint16_t)frame[3] << 8));
    *status = (uint16_t)(frame[4] | ((uint16_t)frame[5] << 8));
}

/* Build + send an SAE Commit Authentication frame body. The body
 * starts at the Auth header (alg/seq/status); no 802.11 MAC header. */
static int supp_sae_send_commit_frame(struct wolfip_supplicant *s)
{
    uint8_t buf[6 + 2 + 3U * SAE_MAX_PRIME_LEN];
    size_t  body_len = 0;
    int     ret;
    if (s->ops.send_auth_frame == NULL) return -1;
    if (sae_generate_commit(&s->sae) != 0) return -1;
    /* 6-byte Auth header. status: 0 (success) for legacy H&P,
     * SAE_STATUS_H2E for H2E. */
    sae_auth_hdr_write(buf, 1U, s->sae_h2e ? (uint16_t)SAE_STATUS_H2E : 0U);
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
    sae_auth_hdr_write(buf, 2U, 0U);       /* seq = Confirm (2)   */
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
    s->hs_start_ms     = now_ms;   /* overall-deadline reference (tick()) */
    s->m2_retries_left = WOLFIP_SUPPLICANT_M2_MAX_RETRIES;

#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
    if (supp_is_eap_mode(s)) {
        /* Emit EAPOL-Start to prompt the authenticator to begin EAP.
         * Some APs send EAP-Request/Identity unprompted on association;
         * sending Start is harmless and covers both cases. */
        if (supp_send_eapol_start(s) != 0) {
            return -1;
        }
        s->state = SUPP_STATE_EAP_IDENTITY_WAIT;
        return 0;
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
    /* Policy: malformed / out-of-order / short auth frames return -1 WITHOUT
     * moving to FAILED (tolerate junk and keep waiting for a valid frame,
     * mirroring the group-key tolerance in wolfip_supplicant_rx); only an
     * actual SAE crypto failure below transitions to FAILED. The overall
     * handshake deadline in wolfip_supplicant_tick() bounds a peer that
     * never sends a valid frame. */
    if (s == NULL || frame == NULL || len < 6) return -1;
    if (s->auth_mode != WOLFIP_AUTH_SAE) return -1;

    sae_auth_hdr_read(frame, &alg, &seq, &status);
    if (alg != 3U) return -1;
    /* SAE Commit may carry status 0 (legacy) or SAE_STATUS_H2E (H2E).
     * Confirm always uses status 0. We accept matching values only - a
     * mismatch (peer H2E while we are H&P, or vice versa) is a
     * negotiation error. */
    if (seq == 1U) {
        uint16_t exp = s->sae_h2e ? (uint16_t)SAE_STATUS_H2E : 0U;
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

    /* Overall handshake deadline: any non-terminal state that has not
     * reached AUTHENTICATED within the window becomes FAILED, so a stalled
     * SAE / EAP / M1-wait (peer never replies) is observable rather than
     * hanging. IDLE (not yet kicked) and the terminal states are exempt. */
    if (WOLFIP_SUPPLICANT_HS_TIMEOUT_MS != 0U
        && s->state != SUPP_STATE_IDLE
        && s->state != SUPP_STATE_AUTHENTICATED
        && s->state != SUPP_STATE_FAILED
        && now_ms > s->hs_start_ms
        && (now_ms - s->hs_start_ms) >= WOLFIP_SUPPLICANT_HS_TIMEOUT_MS) {
        s->state = SUPP_STATE_FAILED;
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

/* In M3_WAIT, a MIC-less pairwise KeyAck is an M1 retransmit (the AP did not
 * receive our M2). Honor it ONLY if it carries the SAME ANonce as the original
 * M1 - then resend the cached M2 (reuse the existing SNonce/PTK; do NOT
 * re-derive). A forged M1 with a different ANonce is silently ignored:
 * re-deriving the PTK from attacker-controlled values would let an off-path
 * attacker wedge the legitimate M3 (DoS). Returns 1 if the frame was an M1
 * retransmit (handled/tolerated; stay in M3_WAIT), 0 if it is not an M1 and
 * the caller should process it as M3. The overall handshake deadline in
 * tick() bounds a genuinely stuck handshake. */
static int supp_handle_m1_retransmit(struct wolfip_supplicant *s,
                                     const struct eapol_key_view *kv,
                                     uint64_t now_ms)
{
    if (!supp_key_info_has(kv->key_info,
                           KEY_INFO_KEY_TYPE | KEY_INFO_KEY_ACK,
                           KEY_INFO_KEY_MIC)) {
        return 0;
    }
    if (s->have_ptk
        && memcmp(kv->nonce, s->anonce, WPA_NONCE_LEN) == 0) {
        if (supp_send_m2(s) == 0) {
            s->m2_send_ms      = now_ms;
            s->m2_retries_left = WOLFIP_SUPPLICANT_M2_MAX_RETRIES;
        }
    }
    return 1;
}

/* Handle an inbound EAPOL-Key frame (802.1X type 3): parse, check the Key
 * Descriptor Version against the active AKM, then dispatch on state. Split
 * out of wolfip_supplicant_rx. */
static int supp_rx_key(struct wolfip_supplicant *s,
                       const uint8_t *frame, size_t len, uint64_t now_ms)
{
    struct eapol_key_view kv;
    uint8_t *frame_copy = s->rx_frame_copy;
    int      ret;

    if (eapol_key_parse(frame, len, &kv) != 0) {
        return -1;
    }
    /* Accept the Key Descriptor Version matching the active AKM: Version 2
     * (HMAC-SHA1-128) for WPA2-PSK, Version 0 (AES-128-CMAC) for WPA3-SAE.
     * Reject anything else (e.g. Version 1 / TKIP). */
    if ((kv.key_info & KEY_INFO_VER_MASK) != supp_key_desc_ver(s)) {
        return -1;
    }
    /* For MIC-bearing frames, work on a writable copy so we can zero
     * the MIC field for verification. */
    if (kv.frame_len > sizeof(s->rx_frame_copy)) {
        return -1;
    }
    memcpy(frame_copy, frame, kv.frame_len);

    switch (s->state) {
    case SUPP_STATE_4WAY_M1_WAIT:
        ret = supp_handle_m1(s, &kv, now_ms);
        if (ret != 0) s->state = SUPP_STATE_FAILED;
        return ret;

    case SUPP_STATE_4WAY_M3_WAIT:
        if (supp_handle_m1_retransmit(s, &kv, now_ms)) {
            return 0;   /* tolerate; stay in M3_WAIT */
        }
        ret = supp_handle_m3(s, &kv, frame_copy, sizeof(s->rx_frame_copy));
        if (ret != 0) s->state = SUPP_STATE_FAILED;
        return ret;

    case SUPP_STATE_AUTHENTICATED:
        /* Only Group Key handshake frames are accepted post-4-way. A
         * pairwise EAPOL-Key after AUTHENTICATED is treated as an AP-
         * initiated rekey - not handled in v1 (returns benign error). */
        if ((kv.key_info & KEY_INFO_KEY_TYPE) == 0) {
            ret = supp_handle_group_m1(s, &kv,
                                       frame_copy, sizeof(s->rx_frame_copy));
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

int wolfip_supplicant_rx(struct wolfip_supplicant *s,
                         const uint8_t *frame, size_t len,
                         uint64_t now_ms)
{
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
        return supp_rx_eap(s, frame, len);
#else
        return -1;
#endif
    }
    if (frame[1] != EAPOL_TYPE_KEY_DESCRIPTOR) {
        return -1;
    }
    return supp_rx_key(s, frame, len, now_ms);
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

int wolfip_supplicant_get_pmk(const struct wolfip_supplicant *s,
                              uint8_t out_pmk[WPA_PMK_LEN])
{
    if (s == NULL || out_pmk == NULL) {
        return -1;
    }
    if (s->state == SUPP_STATE_IDLE && !s->have_ptk
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
        && !s->pmk_installed
#endif
        && s->auth_mode != WOLFIP_AUTH_PSK) {
        /* EAP / SAE: no PMK yet. */
        return -1;
    }
    memcpy(out_pmk, s->pmk, WPA_PMK_LEN);
    return 0;
}

void wolfip_supplicant_pmksa_clear(struct wolfip_supplicant *s)
{
    if (s == NULL) {
        return;
    }
    wpa_secure_zero(s->pmksa_pmk, sizeof(s->pmksa_pmk));
    wpa_secure_zero(s->pmksa_pmkid, sizeof(s->pmksa_pmkid));
    s->pmksa_magic       = 0U;
    s->pmksa_ssid_len    = 0U;
    s->pmksa_have_pmkid  = 0U;
}

int wolfip_supplicant_get_pmkid(const struct wolfip_supplicant *s,
                                uint8_t out_pmkid[WPA_PMKID_LEN])
{
    if (s == NULL || out_pmkid == NULL) {
        return -1;
    }
    if (s->pmksa_magic != WOLFIP_PMKSA_MAGIC || !s->pmksa_have_pmkid) {
        return -1;
    }
    memcpy(out_pmkid, s->pmksa_pmkid, WPA_PMKID_LEN);
    return 0;
}

int wolfip_supplicant_pmksa_reconnect(struct wolfip_supplicant *s)
{
    if (s == NULL) {
        return -1;
    }
    /* Require a cached PMKSA with a PMKID for this exact SSID + BSSID. */
    if (s->pmksa_magic != WOLFIP_PMKSA_MAGIC || !s->pmksa_have_pmkid) {
        return -1;
    }
    if ((size_t)s->pmksa_ssid_len != s->ssid_len
        || memcmp(s->pmksa_ssid, s->ssid, s->ssid_len) != 0
        || memcmp(s->pmksa_bssid, s->ap_mac, WPA_MAC_LEN) != 0) {
        return -1;
    }

    /* Append the PMKID to the (Re)Assoc / M2 RSN IE if not already present.
     * Layout after the fixed 20-byte body: PMKID count (2, LE) || PMKID(16).
     * Bump the element length byte by 18. Guarded by pmkid_in_own_ie so a
     * second call (retry / roam loop) is idempotent and never appends a
     * second PMKID block (which would malform the IE). */
    if (!s->pmkid_in_own_ie) {
        if (s->own_rsn_ie_len + 18U <= sizeof(s->own_rsn_ie)
            && s->own_rsn_ie_len >= RSN_IE_MIN_LEN
            && s->own_rsn_ie[1] + 18 <= 0xFF) {
            uint8_t *p = s->own_rsn_ie + s->own_rsn_ie_len;
            *p++ = 0x01; *p++ = 0x00;             /* PMKID count = 1 (LE) */
            memcpy(p, s->pmksa_pmkid, WPA_PMKID_LEN);
            s->own_rsn_ie_len += 18U;
            s->own_rsn_ie[1]  = (uint8_t)(s->own_rsn_ie[1] + 18);
            s->pmkid_in_own_ie = 1;
        }
        else {
            return -1;
        }
    }

    /* Reuse the cached PMK and skip authentication: pmk_installed makes
     * kick() jump straight to 4WAY_M1_WAIT. */
    memcpy(s->pmk, s->pmksa_pmk, WPA_PMK_LEN);
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
    s->pmk_installed = 1;
#endif
    /* Reset the per-handshake state so the fresh 4-way starts clean. */
    s->state        = SUPP_STATE_IDLE;
    s->have_ptk     = 0;
    s->have_replay  = 0;
    s->m2_retries_left = 0;
    wpa_secure_zero(s->snonce, sizeof(s->snonce));
    wpa_secure_zero(s->anonce, sizeof(s->anonce));
    return 0;
}

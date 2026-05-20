/* supplicant.h
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

/* wolfIP WPA2-Personal supplicant. v1 supports the 4-way handshake and
 * the Group Key handshake. EAP / EAP-TLS / PEAP are out of scope for v1
 * but the layout (state enum, key derivation hook) leaves room for them.
 *
 * The supplicant is transport-agnostic. The integrator supplies two
 * callbacks:
 *   - send_eapol  : write an EAPOL frame to the link (driver TX).
 *   - install_key : install PTK/GTK into the radio (driver control).
 *
 * Phase B uses an in-memory transport (test harness). Phase C wires
 * send_eapol to ll->send() at ethertype 0x888E inside the wolfIP poll
 * loop, and install_key to wolfIP_ll_dev::wifi_ops::set_key.
 */

#ifndef WOLFIP_SUPPLICANT_H
#define WOLFIP_SUPPLICANT_H

#include <stdint.h>
#include <stddef.h>

#include "wpa_crypto.h"
#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
#include "eap_tls_engine.h"
#endif

#ifndef WOLFIP_SUPPLICANT_MAX_SSID
#define WOLFIP_SUPPLICANT_MAX_SSID 32
#endif

#ifndef WOLFIP_SUPPLICANT_MAX_IDENTITY
#define WOLFIP_SUPPLICANT_MAX_IDENTITY 64
#endif

/* M2 retransmit interval (milliseconds) and maximum retry count.
 * Matches IEEE 802.11-2020 dot11RSNAConfigPairwiseUpdateTimeout (1 s)
 * and dot11RSNAConfigPairwiseUpdateCount (3). */
#ifndef WOLFIP_SUPPLICANT_M2_RETRY_MS
#define WOLFIP_SUPPLICANT_M2_RETRY_MS 1000U
#endif
#ifndef WOLFIP_SUPPLICANT_M2_MAX_RETRIES
#define WOLFIP_SUPPLICANT_M2_MAX_RETRIES 3U
#endif

typedef enum {
    SUPP_STATE_IDLE = 0,
    /* EAP-only states; skipped entirely in PSK / SAE mode. */
    SUPP_STATE_EAP_IDENTITY_WAIT,
    SUPP_STATE_EAP_TLS_INPROGRESS,
    SUPP_STATE_EAP_SUCCESS_WAIT,
    /* SAE-only states (WPA3-Personal). */
    SUPP_STATE_SAE_COMMIT_SENT,
    SUPP_STATE_SAE_CONFIRM_SENT,
    /* Common 4-way + group + final. */
    SUPP_STATE_4WAY_M1_WAIT,
    SUPP_STATE_4WAY_M3_WAIT,
    SUPP_STATE_GROUP_KEY_WAIT,
    SUPP_STATE_AUTHENTICATED,
    SUPP_STATE_FAILED
} wolfip_supplicant_state_t;

typedef enum {
    WOLFIP_AUTH_PSK             = 0   /* WPA2-Personal                  */
#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
    , WOLFIP_AUTH_EAP_TLS       = 1   /* WPA2-Enterprise EAP-TLS         */
#endif
#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
    , WOLFIP_AUTH_PEAP_MSCHAPV2 = 2   /* WPA2-Enterprise PEAPv0/MSCHAPv2 */
#endif
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
    , WOLFIP_AUTH_SAE           = 3   /* WPA3-Personal SAE / dragonfly   */
#endif
} wolfip_auth_mode_t;

/* Key destination passed to install_key(). */
typedef enum {
    SUPP_KEY_PAIRWISE = 0,
    SUPP_KEY_GROUP    = 1
} wolfip_supplicant_keytype_t;

struct wolfip_supplicant; /* opaque */

/* Transport hooks. send_eapol + install_key are required. send_auth_frame
 * is required for AUTH_SAE (software dragonfly) and unused otherwise.
 *
 *   send_eapol      - emit an EAPOL frame (PSK 4-way, EAP, PEAP).
 *   install_key     - install pairwise/group key into the radio.
 *   send_auth_frame - emit an 802.11 Authentication management frame
 *                     body (auth_alg + auth_seq + status + content)
 *                     for SAE Commit / Confirm. Returns 0 on success.
 */
struct wolfip_supplicant_ops {
    int (*send_eapol)(void *ctx, const uint8_t *frame, size_t len);
    int (*install_key)(void *ctx,
                       wolfip_supplicant_keytype_t kt,
                       uint8_t key_idx,
                       const uint8_t *key, size_t key_len);
    int (*send_auth_frame)(void *ctx, const uint8_t *frame, size_t len);
    void *ctx;
};

/* Init parameters. */
struct wolfip_supplicant_cfg {
    const char *ssid;          /* not NUL-terminated requirement, but C str OK */
    size_t      ssid_len;
    /* Authentication mode. Default 0 = WPA2-Personal (PSK). */
    wolfip_auth_mode_t auth_mode;
    /* PSK fields. Required when auth_mode == WOLFIP_AUTH_PSK; ignored
     * otherwise. */
    const char *passphrase;    /* 8..63 chars                                 */
    size_t      passphrase_len;
#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
    /* EAP-TLS / PEAP fields. Required when auth_mode is an EAP variant.
     *
     * identity   = outer EAP-Response/Identity payload (e.g.
     *              "alice@realm"). For PEAP this may be an anonymous
     *              outer identity like "anonymous@realm"; the real user
     *              name goes in inner_identity below.
     *
     * inner_identity / password (PEAP only): inner EAP-MSCHAPv2
     *              credentials sent encrypted inside the TLS tunnel.
     */
    const char *identity;
    size_t      identity_len;
#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
    const char *inner_identity;
    size_t      inner_identity_len;
    const char *password;
    size_t      password_len;
#endif
    struct eap_tls_engine_cfg eap_tls;
#endif /* WOLFIP_ENABLE_EAP_TLS */
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
    /* SAE-specific (auth_mode = WOLFIP_AUTH_SAE):
     *   passphrase is shared with PSK mode.
     *   sae_group selects the ECC group (19/20/21). Default 19 if 0.
     *   sae_h2e: 0 = legacy hunt-and-peck PWE (status code 0 in Commit),
     *            1 = H2E (RFC 9380 SSWU, status code 126). Requires
     *            WOLFIP_ENABLE_SAE_H2E at build time.
     */
    int         sae_group;
    int         sae_h2e;
#endif
    uint8_t     ap_mac[WPA_MAC_LEN];
    uint8_t     sta_mac[WPA_MAC_LEN];
    /* AP's RSN IE as seen in Beacon / Probe Response. The supplicant
     * compares this byte-for-byte against the RSN IE the AP echoes in
     * M3 to detect downgrade attacks (IEEE 802.11-2020 12.7.6.4).
     *
     * If ap_rsn_ie is NULL, the supplicant falls back to using its own
     * default WPA2-PSK RSN IE for the comparison. This is acceptable
     * for a closed PSK deployment where supplicant and AP agree on
     * cipher choices by configuration, but real hardware ports should
     * pass the IE from the chip's scan results.
     */
    const uint8_t *ap_rsn_ie;
    size_t         ap_rsn_ie_len;
    struct wolfip_supplicant_ops ops;
};

/* Maximum stored RSN IE size (one pairwise + one AKM + caps + tiny slack). */
#define WOLFIP_SUPPLICANT_MAX_RSN_IE 64

#ifdef __cplusplus
extern "C" {
#endif

/* Allocate and initialise a supplicant from cfg. PMK is derived now;
 * actual handshake does not start until wolfip_supplicant_kick() is
 * called (caller signals 'association complete, ready for EAPOL').
 *
 * Returns NULL on bad args. Caller must wolfip_supplicant_free().
 */
struct wolfip_supplicant *wolfip_supplicant_new(
                              const struct wolfip_supplicant_cfg *cfg);

void wolfip_supplicant_free(struct wolfip_supplicant *s);

/* Signal that the radio reports "associated" - supplicant moves from
 * IDLE to 4WAY_M1_WAIT. (On real hardware, called by the driver after
 * the FullMAC chip completes auth+assoc.) `now_ms` is the current
 * monotonic timestamp; the supplicant uses it as the handshake start.
 */
int wolfip_supplicant_kick(struct wolfip_supplicant *s, uint64_t now_ms);

/* Feed one inbound EAPOL frame to the supplicant. now_ms is the current
 * monotonic timestamp - used to (re)arm retransmit deadlines. */
int wolfip_supplicant_rx(struct wolfip_supplicant *s,
                         const uint8_t *frame, size_t len,
                         uint64_t now_ms);

#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
/* Feed one inbound 802.11 Authentication management-frame body (SAE
 * Commit / Confirm). Only used in WOLFIP_AUTH_SAE mode. frame starts
 * at the Auth-frame body (auth_alg(2) || auth_seq(2) || status(2) ||
 * content), NOT at the 802.11 MAC header. */
int wolfip_supplicant_rx_auth_frame(struct wolfip_supplicant *s,
                                    const uint8_t *frame, size_t len,
                                    uint64_t now_ms);

/* PMK-from-below fallback API. For FullMAC chips (e.g. CYW43439) that
 * perform SAE internally and present a pre-derived PMK to the host,
 * call this once before kick() to seed the 4-way handshake. The
 * software SAE state machine is bypassed.
 *
 * pmk must be 32 bytes per IEEE 802.11-2020. Returns 0 on success.
 */
int wolfip_supplicant_install_pmk(struct wolfip_supplicant *s,
                                  const uint8_t *pmk, size_t pmk_len);
#endif /* WOLFIP_ENABLE_SAE */

/* Service retransmit and timeout deadlines. The integrator calls this
 * once per wolfIP poll iteration (or on a timer). Safe to call at any
 * frequency >= a few times per second. */
void wolfip_supplicant_tick(struct wolfip_supplicant *s, uint64_t now_ms);

wolfip_supplicant_state_t
wolfip_supplicant_state(const struct wolfip_supplicant *s);

/* Test/inspection helpers (Phase B only). */
const uint8_t *wolfip_supplicant_kck(const struct wolfip_supplicant *s);
const uint8_t *wolfip_supplicant_tk (const struct wolfip_supplicant *s);
const uint8_t *wolfip_supplicant_snonce(const struct wolfip_supplicant *s);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_SUPPLICANT_H */

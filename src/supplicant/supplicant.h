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

/* wolfIP Wi-Fi supplicant: WPA2-Personal (PSK) 4-way + Group Key
 * handshakes, with optional WPA2-Enterprise (EAP-TLS, PEAP/MSCHAPv2) and
 * WPA3-Personal (SAE) selected at build time (see supplicant_features.h).
 *
 * Transport-agnostic: the integrator supplies callbacks, chiefly
 *   - send_eapol  : write an EAPOL frame to the link (driver TX).
 *   - install_key : install PTK/GTK into the radio (driver control).
 */

#ifndef WOLFIP_SUPPLICANT_H
#define WOLFIP_SUPPLICANT_H

#include <stdint.h>
#include <stddef.h>

#include "supplicant_features.h"  /* wolfCrypt feature detection (before any WOLFIP_ENABLE_* gate) */
#include "wpa_crypto.h"
#include "eapol.h"        /* EAPOL_KEY_FIXED_LEN for the rx MIC scratch */
#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
#include "eap_tls_engine.h"
#endif
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
#include "sae_crypto.h"
#endif

#ifndef WOLFIP_SUPPLICANT_MAX_SSID
#define WOLFIP_SUPPLICANT_MAX_SSID 32
#endif

#ifndef WOLFIP_SUPPLICANT_MAX_IDENTITY
#define WOLFIP_SUPPLICANT_MAX_IDENTITY 64
#endif

/* Sentinel marking a populated PMKSA cache entry (see the cache fields
 * in struct wolfip_supplicant). Distinct, non-trivial value so a garbage
 * context on first init is not mistaken for a valid cache. */
#define WOLFIP_PMKSA_MAGIC 0x504D4B53U   /* "PMKS" */

/* M2 retransmit interval (milliseconds) and maximum retry count.
 * Matches IEEE 802.11-2020 dot11RSNAConfigPairwiseUpdateTimeout (1 s)
 * and dot11RSNAConfigPairwiseUpdateCount (3). */
#ifndef WOLFIP_SUPPLICANT_M2_RETRY_MS
#define WOLFIP_SUPPLICANT_M2_RETRY_MS 1000U
#endif
#ifndef WOLFIP_SUPPLICANT_M2_MAX_RETRIES
#define WOLFIP_SUPPLICANT_M2_MAX_RETRIES 3U
#endif

/* Overall handshake deadline (milliseconds). If the supplicant has been
 * kicked but has not reached AUTHENTICATED or FAILED within this window,
 * wolfip_supplicant_tick() drives it to SUPP_STATE_FAILED so a stalled
 * SAE / EAP / M1-wait (peer never replies) becomes observable instead of
 * hanging forever. 0 disables the overall deadline. */
#ifndef WOLFIP_SUPPLICANT_HS_TIMEOUT_MS
#define WOLFIP_SUPPLICANT_HS_TIMEOUT_MS 10000U
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

/* Forward decl of the supplicant context. Full definition follows below
 * so callers can allocate it statically (no heap on bare-metal MCUs). */
struct wolfip_supplicant;

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
    /* Optional pre-derived PMK (32 bytes). If non-NULL, used instead of
     * running PBKDF2-HMAC-SHA1 over passphrase + SSID. Lets a caller
     * persist the PMK across boots and skip the 4096-iter PBKDF2 on
     * reconnect to the same SSID. Get the current PMK via
     * wolfip_supplicant_get_pmk() after AUTHENTICATED. */
    const uint8_t *psk_pmk;
    size_t         psk_pmk_len;
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
    /* IEEE 802.11w / Management Frame Protection.
     *   mfp_capable = 1 advertises MFPC (RSN cap bit 0x0080). Required
     *                 to join WPA3 APs and any WPA2 AP with MFP enabled.
     *   mfp_required = 1 also advertises MFPR (cap bit 0x0040), which
     *                 tells the AP we will only associate with MFP active.
     * Both default to 0 for backwards compatibility with legacy WPA2-only
     * APs that may reject unknown caps. WPA3-Personal callers should set
     * mfp_capable = 1; WPA3-only callers should set both to 1.
     */
    uint8_t     mfp_capable;
    uint8_t     mfp_required;
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

/* Full supplicant context. Exposed in the header (rather than opaque) so
 * bare-metal ports can allocate it statically and never invoke malloc.
 * POSIX callers can still use wolfip_supplicant_new()/_free() if they
 * prefer the heap. */
struct wolfip_supplicant {
    uint8_t  ssid[WOLFIP_SUPPLICANT_MAX_SSID];
    size_t   ssid_len;
    uint8_t  ap_mac[WPA_MAC_LEN];
    uint8_t  sta_mac[WPA_MAC_LEN];
    wolfip_auth_mode_t auth_mode;
    struct wolfip_supplicant_ops ops;

#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS
    struct eap_tls_engine eap_tls;
    int      eap_tls_inited;
    uint8_t  identity[WOLFIP_SUPPLICANT_MAX_IDENTITY];
    size_t   identity_len;
    uint8_t  last_eap_id;
#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
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

    uint8_t  own_rsn_ie[WOLFIP_SUPPLICANT_MAX_RSN_IE];
    size_t   own_rsn_ie_len;
    uint8_t  ap_rsn_ie[WOLFIP_SUPPLICANT_MAX_RSN_IE];
    size_t   ap_rsn_ie_len;

    uint8_t  pmk[WPA_PMK_LEN];
    struct wpa_ptk ptk;
    int      have_ptk;

    uint8_t  anonce[WPA_NONCE_LEN];
    uint8_t  snonce[WPA_NONCE_LEN];
    uint8_t  last_replay[WPA_REPLAY_CTR_LEN];
    int      have_replay;

    uint64_t m2_send_ms;
    uint64_t hs_start_ms;        /* handshake start (kick); overall deadline */
    uint8_t  m2_retries_left;

#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
    struct sae_ctx sae;
    int            sae_inited;
    int            pmk_installed;
    int            sae_h2e;
#endif

    /* PMKSA cache (single entry). Populated on reaching AUTHENTICATED.
     * A subsequent wolfip_supplicant_init() on the SAME context for the
     * SAME SSID reuses the cached PMK and skips the 4096-iteration
     * PBKDF2 (PSK passphrase mode only). The cache survives _init()'s
     * context zero but is wiped by _deinit() and _pmksa_clear().
     *
     * Reuse requires BOTH pmksa_magic == WOLFIP_PMKSA_MAGIC AND an exact
     * SSID match, so an uninitialized (garbage) context on the very first
     * init cannot be mistaken for a valid cache. */
    uint32_t pmksa_magic;
    uint8_t  pmksa_pmk[WPA_PMK_LEN];
    uint8_t  pmksa_pmkid[16];   /* PMKID of the cached PMKSA (for reconnect) */
    uint8_t  pmksa_pp_hash[32]; /* SHA-256 of the passphrase that made the   */
                               /* cached PMK; the PSK fast path is taken    */
                               /* only when the new passphrase still hashes  */
                               /* to this (PSK mode, no psk_pmk supplied).   */
    uint8_t  pmksa_ssid[WOLFIP_SUPPLICANT_MAX_SSID];
    uint8_t  pmksa_bssid[WPA_MAC_LEN];
    uint8_t  pmksa_ssid_len;
    uint8_t  pmksa_have_pmkid; /* 1 once a PMKID has been cached            */
    uint8_t  pmksa_have_pp;    /* 1 once pmksa_pp_hash is valid             */
    uint8_t  pmkid_in_own_ie;  /* 1 once a PMKID was appended to own_rsn_ie */
    uint8_t  pp_hash[32];      /* SHA-256 of this session's passphrase      */
    uint8_t  have_pp_hash;     /* 1 if pp_hash is valid (PSK passphrase set)*/

    /* Scratch for EAPOL-Key MIC verification: the inbound frame is copied
     * here so the MIC field can be zeroed before recomputing the MIC. Held
     * in the context (not on the RX stack) to keep stack use bounded on
     * small targets without adding a heap dependency. */
    uint8_t  rx_frame_copy[EAPOL_KEY_FIXED_LEN + 256];

    wolfip_supplicant_state_t state;
};

#ifdef __cplusplus
extern "C" {
#endif

/* Caller-allocated init. `out` is a struct provided by the caller (stack,
 * static, or pool) and is fully populated from cfg on success. Returns 0
 * on success, negative on bad args / crypto failure. On failure, the
 * struct is left zeroed; caller does not need to call _deinit.
 */
int wolfip_supplicant_init(struct wolfip_supplicant *out,
                           const struct wolfip_supplicant_cfg *cfg);

/* Release per-context resources (TLS engine, SAE mp_ints) and zero
 * secrets. Does NOT free the struct itself. Safe to call on a
 * partially-initialized context. */
void wolfip_supplicant_deinit(struct wolfip_supplicant *s);

/* Heap-allocated convenience wrappers around _init / _deinit, kept for
 * POSIX tests and integrators that prefer the heap. The bare-metal MCU
 * path should use _init / _deinit directly to keep the supplicant
 * allocation-free.
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

/* Test/inspection helpers. */
const uint8_t *wolfip_supplicant_kck(const struct wolfip_supplicant *s);
const uint8_t *wolfip_supplicant_tk (const struct wolfip_supplicant *s);
const uint8_t *wolfip_supplicant_snonce(const struct wolfip_supplicant *s);

/* Export the current PMK (32 bytes). Returns 0 on success, -1 if no
 * PMK is available (state == IDLE / FAILED, or auth_mode never derived
 * a PSK-grade PMK). Caller can persist the PMK and pass it back via
 * cfg.psk_pmk on the next wolfip_supplicant_init() to skip PBKDF2. */
int wolfip_supplicant_get_pmk(const struct wolfip_supplicant *s,
                              uint8_t out_pmk[WPA_PMK_LEN]);

/* Clear the PMKSA cache and zero the cached PMK. Call when roaming to a
 * different SSID or on an explicit credential change so a later re-init
 * cannot reuse a stale PMK. Safe to call at any time. */
void wolfip_supplicant_pmksa_clear(struct wolfip_supplicant *s);

/* Export the PMKID of the established/cached PMKSA (16 bytes). Returns 0 on
 * success, -1 if none is available. The integrator passes this to the
 * radio (e.g. NL80211_CMD_SET_PMKSA) for a PMKSA fast reconnect. */
int wolfip_supplicant_get_pmkid(const struct wolfip_supplicant *s,
                                uint8_t out_pmkid[WPA_PMKID_LEN]);

/* Set up a PMKSA "fast reconnect": when a valid PMKSA is cached for the
 * current SSID + BSSID (from a prior AUTHENTICATED session on this context),
 * reuse the cached PMK + PMKID, skip the SAE/EAP authentication entirely,
 * include the PMKID in the (Re)Assoc RSN IE, and go straight to the 4-way
 * handshake on the next wolfip_supplicant_kick(). Call after _init() (which
 * preserves the cache) and before kick(). Returns 0 if a usable PMKSA was
 * found and armed, -1 otherwise (caller should fall back to a full auth). */
int wolfip_supplicant_pmksa_reconnect(struct wolfip_supplicant *s);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_SUPPLICANT_H */

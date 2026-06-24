/* wpa_crypto.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfIP.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfIP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Clean-room implementation of WPA2-Personal cryptographic helpers, per
 * IEEE 802.11i-2004 (now folded into IEEE 802.11-2020 clause 12). All
 * primitives delegate to wolfCrypt; this file only handles concatenation
 * order, byte counts, and the IEEE-defined PRF iteration.
 */

#ifndef WOLFIP_WPA_CRYPTO_H
#define WOLFIP_WPA_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* Fixed key sizes for WPA2-Personal (CCMP-only) per IEEE 802.11i. */
#define WPA_PMK_LEN          32U   /* Pairwise Master Key      */
#define WPA_PTK_LEN          48U   /* CCMP PTK: 16 KCK + 16 KEK + 16 TK */
#define WPA_KCK_LEN          16U   /* EAPOL-Key MIC key        */
#define WPA_KEK_LEN          16U   /* EAPOL-Key encryption key */
#define WPA_TK_LEN           16U   /* Temporal (CCMP) key      */
#define WPA_MIC_LEN          16U   /* HMAC-SHA1-128 truncated  */
#define WPA_NONCE_LEN        32U
#define WPA_MAC_LEN           6U
#define WPA_REPLAY_CTR_LEN    8U
#define WPA_GTK_MAX_LEN      32U   /* Group key, AES = 16, allow growth */
#define WPA_PMKID_LEN        16U   /* RSN PMKID (truncated HMAC)         */
#define WPA_KEYWRAP_SEMIBLOCK 8U   /* RFC 3394 64-bit semiblock / IV     */

/* PBKDF2 iteration count fixed at 4096 per IEEE 802.11i-2004 H.4.1. */
#define WPA_PBKDF2_ITERS  4096U

#ifdef __cplusplus
extern "C" {
#endif

/* Pairwise Transient Key, 48 bytes split into KCK || KEK || TK. */
struct wpa_ptk {
    uint8_t kck[WPA_KCK_LEN];
    uint8_t kek[WPA_KEK_LEN];
    uint8_t tk[WPA_TK_LEN];
};

/* PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32). passphrase is 8..63
 * ASCII chars (IEEE 802.11i Annex H), ssid_len is 1..32; neither is
 * NUL-terminated. Returns 0 on success, negative wolfCrypt error otherwise. */
int wpa_pmk_from_passphrase(const char *passphrase, size_t passphrase_len,
                            const uint8_t *ssid, size_t ssid_len,
                            uint8_t out_pmk[WPA_PMK_LEN]);

/* PTK = IEEE 802.11i PRF-384(PMK, "Pairwise key expansion",
 * min(AA,SA) || max(AA,SA) || min(ANonce,SNonce) || max(ANonce,SNonce)).
 * AA/SA are the Authenticator/Supplicant MACs. out_ptk receives
 * KCK || KEK || TK. */
int wpa_ptk_derive(const uint8_t pmk[WPA_PMK_LEN],
                   const uint8_t aa[WPA_MAC_LEN],
                   const uint8_t sa[WPA_MAC_LEN],
                   const uint8_t anonce[WPA_NONCE_LEN],
                   const uint8_t snonce[WPA_NONCE_LEN],
                   struct wpa_ptk *out_ptk);

/* PTK derivation for SHA-256 AKMs (WPA3-SAE, 802.1X-SHA256). Identical
 * inputs to wpa_ptk_derive, but uses the IEEE 802.11 KDF with HMAC-SHA256
 * ("Pairwise key expansion") instead of the legacy HMAC-SHA1 PRF. The
 * resulting KCK/KEK are used with the AES-128-CMAC EAPOL-Key MIC. */
int wpa_ptk_derive_sha256(const uint8_t pmk[WPA_PMK_LEN],
                          const uint8_t aa[WPA_MAC_LEN],
                          const uint8_t sa[WPA_MAC_LEN],
                          const uint8_t anonce[WPA_NONCE_LEN],
                          const uint8_t snonce[WPA_NONCE_LEN],
                          struct wpa_ptk *out_ptk);

/* IEEE 802.11i PRF over arbitrary lengths (multiple of 8 bits).
 * Concatenates HMAC-SHA1(key, label || 0x00 || data || i) for i = 0..n
 * until at least out_len bytes are produced, then truncates to out_len.
 *
 * Used by wpa_ptk_derive() for the WPA2 PTK and exposed for test vectors.
 */
int wpa_prf_sha1(const uint8_t *key, size_t key_len,
                 const char *label,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out, size_t out_len);

/* EAPOL-Key MIC over the whole 802.1X frame (MIC field pre-zeroed by the
 * caller). WPA2-AES-CCMP uses HMAC-SHA1 truncated to 16 bytes (Key
 * Descriptor Version 2). */
int wpa_eapol_mic(const uint8_t kck[WPA_KCK_LEN],
                  const uint8_t *frame, size_t frame_len,
                  uint8_t out_mic[WPA_MIC_LEN]);

/* Constant-time MIC verify. Returns 0 on match, -1 on mismatch. */
int wpa_eapol_mic_verify(const uint8_t kck[WPA_KCK_LEN],
                         const uint8_t *frame, size_t frame_len,
                         const uint8_t expected_mic[WPA_MIC_LEN]);

/* EAPOL-Key MIC using AES-128-CMAC (Key Descriptor Version 0, the
 * "AKM-defined" integrity used by WPA3-SAE and other SHA-256/PMF AKMs),
 * truncated to 128 bits. Same frame/out contract as wpa_eapol_mic. */
int wpa_eapol_mic_aes_cmac(const uint8_t kck[WPA_KCK_LEN],
                           const uint8_t *frame, size_t frame_len,
                           uint8_t out_mic[WPA_MIC_LEN]);

/* Constant-time AES-CMAC MIC verify. Returns 0 on match, -1 on mismatch. */
int wpa_eapol_mic_aes_cmac_verify(const uint8_t kck[WPA_KCK_LEN],
                                  const uint8_t *frame, size_t frame_len,
                                  const uint8_t expected_mic[WPA_MIC_LEN]);

/* AES Key Wrap / Unwrap (RFC 3394) for the EAPOL-Key Data field (GTK and
 * other KDEs) in M3. key is the 16-byte KEK; in_len is a multiple of 8 and
 * >= 16 (wrap) / >= 24 (unwrap); out holds in_len +/- 8. Returns 0 on
 * success. */
int wpa_aes_keywrap(const uint8_t *key, size_t key_len,
                    const uint8_t *in, size_t in_len,
                    uint8_t *out);

int wpa_aes_keyunwrap(const uint8_t *key, size_t key_len,
                      const uint8_t *in, size_t in_len,
                      uint8_t *out);

/* Zero secrets using wolfCrypt's compiler-resistant ForceZero. */
void wpa_secure_zero(void *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_WPA_CRYPTO_H */

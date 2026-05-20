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

/* PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32).
 *
 * passphrase   ASCII passphrase, 8..63 chars per IEEE 802.11i Annex H.
 *              No NUL terminator counted.
 * passphrase_len   strlen(passphrase).
 * ssid         SSID bytes (not NUL-terminated).
 * ssid_len     1..32.
 * out_pmk      32-byte PMK output buffer.
 *
 * Returns 0 on success, negative wolfCrypt-style error otherwise.
 */
int wpa_pmk_from_passphrase(const char *passphrase, size_t passphrase_len,
                            const uint8_t *ssid, size_t ssid_len,
                            uint8_t out_pmk[WPA_PMK_LEN]);

/* PTK = IEEE 802.11i PRF-384 over:
 *   key      = PMK (32 bytes)
 *   label    = "Pairwise key expansion"
 *   data     = min(AA, SA) || max(AA, SA) || min(ANonce, SNonce)
 *              || max(ANonce, SNonce)
 *
 * AA/SA are 6-byte MAC addresses (Authenticator / Supplicant).
 * ANonce/SNonce are 32 bytes each.
 * out_ptk receives KCK || KEK || TK on return.
 */
int wpa_ptk_derive(const uint8_t pmk[WPA_PMK_LEN],
                   const uint8_t aa[WPA_MAC_LEN],
                   const uint8_t sa[WPA_MAC_LEN],
                   const uint8_t anonce[WPA_NONCE_LEN],
                   const uint8_t snonce[WPA_NONCE_LEN],
                   struct wpa_ptk *out_ptk);

/* IEEE 802.11i PRF over arbitrary lengths (multiple of 8 bits).
 * Concatenates HMAC-SHA1(key, label || 0x00 || data || i) for i = 0..n
 * until at least out_len bytes are produced, then truncates to out_len.
 *
 * Exposed for test vectors and EAP-TLS PRF use (not currently used).
 */
int wpa_prf_sha1(const uint8_t *key, size_t key_len,
                 const char *label,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out, size_t out_len);

/* Compute the EAPOL-Key MIC over the entire EAPOL frame with the MIC
 * field zeroed. WPA2-AES-CCMP uses HMAC-SHA1 truncated to 16 bytes
 * (Key Descriptor Version 2).
 *
 * kck       16-byte Key Confirmation Key from PTK.
 * frame     Pointer to start of the 802.1X header (EAPOL).
 * frame_len Total bytes of frame including the (zeroed) MIC field.
 * out_mic   16-byte MIC output.
 */
int wpa_eapol_mic(const uint8_t kck[WPA_KCK_LEN],
                  const uint8_t *frame, size_t frame_len,
                  uint8_t out_mic[WPA_MIC_LEN]);

/* Constant-time MIC verify. Returns 0 on match, -1 on mismatch. */
int wpa_eapol_mic_verify(const uint8_t kck[WPA_KCK_LEN],
                         const uint8_t *frame, size_t frame_len,
                         const uint8_t expected_mic[WPA_MIC_LEN]);

/* AES Key Wrap / Unwrap (RFC 3394) used to encrypt the EAPOL-Key Data
 * field carrying the GTK (and other KDEs) in M3 of the 4-way handshake.
 *
 * key/key_len  KEK from PTK; 16 bytes for WPA2-Personal.
 * in/in_len    Plaintext; in_len must be a multiple of 8 bytes.
 * out          Caller-owned buffer of size in_len + 8.
 *
 * Returns 0 on success.
 */
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

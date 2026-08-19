/* macsec_crypto.h
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

/* Clean-room MACsec Key Agreement (MKA) key hierarchy, per IEEE Std
 * 802.1X-2010. This module owns the cryptographic derivations only (the
 * AES-CMAC KDF of 6.2.1, the CAK/CKN/KEK/ICK/SAK derivations of 9.3.3, the
 * MKPDU ICV, and the AES Key Wrap of the SAK); the protocol state machine
 * lives in mka.c and the 802.1AE frame transform in macsec_secy.c.
 *
 * The AES-CMAC PRF uses wolfCrypt's wc_AesCmacGenerate (WOLFSSL_CMAC), which
 * supports both 128- and 256-bit keys. AES Key Wrap and secret zeroization
 * reuse the shared helpers in the supplicant crypto layer (wpa_crypto.h).
 */

#ifndef WOLFIP_MACSEC_CRYPTO_H
#define WOLFIP_MACSEC_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key and identifier sizes (IEEE 802.1X-2010 / 802.1AE). AES-128 variants
 * use 16-byte keys, AES-256 variants 32. */
#define MACSEC_KEY_LEN_128     16U
#define MACSEC_KEY_LEN_256     32U
#define MACSEC_KEY_LEN_MAX     32U   /* CAK / KEK / ICK / SAK upper bound   */
#define MACSEC_ICV_LEN         16U   /* MKPDU ICV and 802.1AE frame ICV     */
#define MACSEC_CKN_MAX_LEN     32U   /* Connectivity Association Key Name   */
#define MACSEC_MI_LEN          12U   /* Member Identifier (96 bits)         */
#define MACSEC_KS_NONCE_LEN    32U   /* Key Server nonce for SAK generation */
#define MACSEC_SCI_LEN          8U   /* Secure Channel Identifier           */
#define MACSEC_KN_LEN           4U   /* Key Number (SAK), big-endian        */
#define MACSEC_MAC_LEN          6U

/* 802.1AE Cipher Suite identifiers (64-bit, big-endian on the wire).
 * XPN suites are intentionally out of scope for this module. */
#define MACSEC_CIPHER_GCM_AES_128  0x0080C20001000001ULL
#define MACSEC_CIPHER_GCM_AES_256  0x0080C20001000004ULL

/* KDF label strings (IEEE 802.1X-2010). Exact ASCII, no NUL in the KDF
 * input; the 0x00 separator is added by the KDF construction itself. */
#define MACSEC_LABEL_EAP_CAK   "IEEE8021 EAP CAK"
#define MACSEC_LABEL_EAP_CKN   "IEEE8021 EAP CKN"
#define MACSEC_LABEL_KEK       "IEEE8021 KEK"
#define MACSEC_LABEL_ICK       "IEEE8021 ICK"
#define MACSEC_LABEL_SAK       "IEEE8021 SAK"

/* IEEE 802.1X-2010 6.2.1 KDF, AES-CMAC in NIST SP 800-108 counter mode.
 *
 * For each output block i = 1..ceil(out_bits/128):
 *     T_i = AES-CMAC(key, i(1 octet) || label || 0x00 || context ||
 *                         out_bits(2 octets, big-endian))
 * out receives the leftmost out_bits (rounded up to whole octets) of the
 * concatenated T_i. key_len selects AES-128 (16) or AES-256 (32) CMAC.
 * label is a C string (its bytes, excluding the terminating NUL, are hashed).
 * out_bits must be a multiple of 8 and <= 256 (n <= 2). Returns 0 on success,
 * negative wolfCrypt error otherwise. */
int macsec_kdf(const uint8_t *key, size_t key_len,
               const char *label,
               const uint8_t *context, size_t ctx_len,
               uint16_t out_bits, uint8_t *out);

/* CAK from an EAP MSK (802.1X-2010 9.3.1). The KDK is the leftmost cak_len
 * bytes of the MSK; context is peer_mac || auth_mac. cak_len is 16 or 32.
 *
 * NOTE: the two-MAC context ordering is not yet cross-checked against
 * wpa_supplicant EAP-MKA (current interop uses a PSK CAK). The KDF core and
 * the KEK/ICK-from-CAK path below are byte-verified against wpa_supplicant. */
int macsec_derive_cak(const uint8_t *msk, size_t msk_len, size_t cak_len,
                      const uint8_t peer_mac[MACSEC_MAC_LEN],
                      const uint8_t auth_mac[MACSEC_MAC_LEN],
                      uint8_t *cak);

/* CKN from an EAP MSK (802.1X-2010 9.3.1). Context is the EAP Session-Id
 * followed by peer_mac || auth_mac. ckn_len is 1..32.
 *
 * NOTE: context ordering not yet cross-checked against wpa_supplicant (as
 * for macsec_derive_cak above). */
int macsec_derive_ckn(const uint8_t *msk, size_t msk_len,
                      const uint8_t *eap_session_id, size_t session_id_len,
                      const uint8_t peer_mac[MACSEC_MAC_LEN],
                      const uint8_t auth_mac[MACSEC_MAC_LEN],
                      uint8_t *ckn, size_t ckn_len);

/* KEK (Key Encrypting Key) from the CAK (802.1X-2010 9.3.3). Context is the
 * leftmost 16 bytes of the CKN (zero-padded if the CKN is shorter). Output
 * length matches cak_len (16 or 32). */
int macsec_derive_kek(const uint8_t *cak, size_t cak_len,
                      const uint8_t *ckn, size_t ckn_len,
                      uint8_t *kek);

/* ICK (ICV Key) from the CAK (802.1X-2010 9.3.3). Same context rule as the
 * KEK; used to compute/verify the MKPDU ICV. Output length matches cak_len. */
int macsec_derive_ick(const uint8_t *cak, size_t cak_len,
                      const uint8_t *ckn, size_t ckn_len,
                      uint8_t *ick);

/* SAK generation by the Key Server (802.1X-2010 9.3.3 / 9.8). Context is
 * ks_nonce(32) || mi_list || kn(4, big-endian), where mi_list is the
 * concatenated Member Identifiers of all live participants. sak_len is 16
 * (GCM-AES-128) or 32 (GCM-AES-256). */
int macsec_generate_sak(const uint8_t *cak, size_t cak_len, size_t sak_len,
                        const uint8_t ks_nonce[MACSEC_KS_NONCE_LEN],
                        const uint8_t *mi_list, size_t mi_list_len,
                        uint32_t kn, uint8_t *sak);

/* MKPDU ICV = AES-CMAC(ICK, mkpdu). The ICV parameter set body is excluded
 * by the caller (it passes the MKPDU up to and including the ICV parameter
 * set header, with the ICV octets themselves omitted). Truncated to 16
 * bytes. ick_len is 16 or 32. */
int macsec_mkpdu_icv(const uint8_t *ick, size_t ick_len,
                     const uint8_t *mkpdu, size_t mkpdu_len,
                     uint8_t icv[MACSEC_ICV_LEN]);

/* Constant-time ICV verify. Returns 0 on match, -1 on mismatch, negative
 * wolfCrypt error on failure to compute. */
int macsec_mkpdu_icv_verify(const uint8_t *ick, size_t ick_len,
                            const uint8_t *mkpdu, size_t mkpdu_len,
                            const uint8_t expected_icv[MACSEC_ICV_LEN]);

/* Wrap / unwrap the SAK under the KEK for the Distributed SAK parameter set
 * (AES Key Wrap, RFC 3394). wrapped holds sak_len + 8 bytes; unwrap reverses
 * it. sak_len is 16 or 32. Returns 0 on success. */
int macsec_wrap_sak(const uint8_t *kek, size_t kek_len,
                    const uint8_t *sak, size_t sak_len,
                    uint8_t *wrapped);

int macsec_unwrap_sak(const uint8_t *kek, size_t kek_len,
                      const uint8_t *wrapped, size_t wrapped_len,
                      uint8_t *sak);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_MACSEC_CRYPTO_H */

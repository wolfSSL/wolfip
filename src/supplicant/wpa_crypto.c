/* wpa_crypto.c
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

#include "wpa_crypto.h"
#include "supplicant_features.h"  /* wolfSSL config + always-on PSK baseline check */

#include <string.h>

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/aes.h>

/* Local constant-time byte compare. wolfCrypt's ConstantCompare() is
 * WOLFSSL_LOCAL and not exported by libwolfssl, so we provide our own
 * with identical semantics: returns 0 on match, non-zero otherwise,
 * without leaking the position of the first differing byte through
 * branch timing.
 */
static int wpa_const_compare(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return (int)diff;
}

/* IEEE 802.11i PRF label used to derive the pairwise key material. */
static const char WPA_PTK_LABEL[] = "Pairwise key expansion";

/* Lexicographic min/max copy of two equal-length byte strings, used by the
 * PRF data construction so both peers produce the same key independent of
 * who is the supplicant vs authenticator. Used for the MAC addresses
 * (WPA_MAC_LEN) and the nonces (WPA_NONCE_LEN).
 */
static void bytes_min_max(const uint8_t *a, const uint8_t *b, size_t len,
                          uint8_t *out_min, uint8_t *out_max)
{
    if (memcmp(a, b, len) < 0) {
        XMEMCPY(out_min, a, len);
        XMEMCPY(out_max, b, len);
    }
    else {
        XMEMCPY(out_min, b, len);
        XMEMCPY(out_max, a, len);
    }
}

void wpa_secure_zero(void *p, size_t n)
{
    if (p != NULL && n > 0) {
        wc_ForceZero(p, n);
    }
}

/* One-shot HMAC over an ordered list of segments: Init, SetKey, Update
 * each segment, Final, Free. type is WC_SHA or WC_SHA256. The Hmac
 * context (holding the key) is always freed before returning. Factors the
 * boilerplate shared by the PRF, the SHA-256 KDF, and the EAPOL-Key MIC. */
struct hmac_seg { const uint8_t *p; word32 len; };
static int hmac_oneshot(int type, const uint8_t *key, word32 key_len,
                        const struct hmac_seg *segs, size_t n_segs,
                        uint8_t *out_digest)
{
    Hmac   hmac;
    int    ret;
    size_t i;

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_HmacSetKey(&hmac, type, key, key_len);
    for (i = 0; ret == 0 && i < n_segs; i++) {
        ret = wc_HmacUpdate(&hmac, segs[i].p, segs[i].len);
    }
    if (ret == 0) {
        ret = wc_HmacFinal(&hmac, out_digest);
    }
    wc_HmacFree(&hmac);
    return ret;
}

int wpa_pmk_from_passphrase(const char *passphrase, size_t passphrase_len,
                            const uint8_t *ssid, size_t ssid_len,
                            uint8_t out_pmk[WPA_PMK_LEN])
{
    int ret;

    if (passphrase == NULL || ssid == NULL || out_pmk == NULL) {
        return BAD_FUNC_ARG;
    }
    if (passphrase_len < 8 || passphrase_len > 63) {
        return BAD_FUNC_ARG;
    }
    if (ssid_len < 1 || ssid_len > 32) {
        return BAD_FUNC_ARG;
    }

    ret = wc_PBKDF2(out_pmk,
                    (const byte *)passphrase, (int)passphrase_len,
                    ssid, (int)ssid_len,
                    (int)WPA_PBKDF2_ITERS,
                    (int)WPA_PMK_LEN,
                    WC_SHA);
    return ret;
}

int wpa_prf_sha1(const uint8_t *key, size_t key_len,
                 const char *label,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out, size_t out_len)
{
    uint8_t digest[WC_SHA_DIGEST_SIZE];
    uint8_t counter;
    uint8_t sep = 0x00;
    size_t produced = 0;
    size_t label_len;
    int ret;

    if (key == NULL || label == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (data == NULL && data_len != 0) {
        return BAD_FUNC_ARG;
    }
    if (out_len == 0) {
        return 0;
    }
    /* The block counter is a single byte, so the PRF can emit at most
     * 256 * 20 = 5120 bytes before T_256 would alias T_0 and silently repeat
     * key material. Reject larger requests rather than produce weak output.
     * (The only in-tree caller derives a 48-byte PTK, well under the cap.) */
    if (out_len > 256U * (size_t)WC_SHA_DIGEST_SIZE) {
        return BAD_FUNC_ARG;
    }

    label_len = XSTRLEN(label);
    counter = 0;

    while (produced < out_len) {
        struct hmac_seg segs[4];
        size_t          n_segs = 0;
        size_t          copy_len;

        /* T_i = HMAC-SHA1(key, label || 0x00 || data || counter) */
        segs[n_segs].p = (const uint8_t *)label;
        segs[n_segs++].len = (word32)label_len;
        segs[n_segs].p = &sep;
        segs[n_segs++].len = 1;
        if (data_len > 0) {
            segs[n_segs].p = data;
            segs[n_segs++].len = (word32)data_len;
        }
        segs[n_segs].p = &counter;
        segs[n_segs++].len = 1;

        ret = hmac_oneshot(WC_SHA, key, (word32)key_len, segs, n_segs, digest);
        if (ret != 0) {
            wpa_secure_zero(digest, sizeof(digest));
            return ret;
        }

        copy_len = out_len - produced;
        if (copy_len > sizeof(digest)) {
            copy_len = sizeof(digest);
        }
        XMEMCPY(out + produced, digest, copy_len);
        produced += copy_len;
        counter++;
    }

    wpa_secure_zero(digest, sizeof(digest));
    return 0;
}

int wpa_ptk_derive(const uint8_t pmk[WPA_PMK_LEN],
                   const uint8_t aa[WPA_MAC_LEN],
                   const uint8_t sa[WPA_MAC_LEN],
                   const uint8_t anonce[WPA_NONCE_LEN],
                   const uint8_t snonce[WPA_NONCE_LEN],
                   struct wpa_ptk *out_ptk)
{
    uint8_t data[2 * WPA_MAC_LEN + 2 * WPA_NONCE_LEN];
    uint8_t ptk_buf[WPA_PTK_LEN];
    int ret;

    if (pmk == NULL || aa == NULL || sa == NULL || anonce == NULL
        || snonce == NULL || out_ptk == NULL) {
        return BAD_FUNC_ARG;
    }

    bytes_min_max(aa, sa, WPA_MAC_LEN, &data[0], &data[WPA_MAC_LEN]);
    bytes_min_max(anonce, snonce, WPA_NONCE_LEN,
                  &data[2 * WPA_MAC_LEN],
                  &data[2 * WPA_MAC_LEN + WPA_NONCE_LEN]);

    ret = wpa_prf_sha1(pmk, WPA_PMK_LEN,
                       WPA_PTK_LABEL,
                       data, sizeof(data),
                       ptk_buf, sizeof(ptk_buf));
    if (ret != 0) {
        wpa_secure_zero(ptk_buf, sizeof(ptk_buf));
        wpa_secure_zero(data, sizeof(data));
        return ret;
    }

    XMEMCPY(out_ptk->kck, ptk_buf,                          WPA_KCK_LEN);
    XMEMCPY(out_ptk->kek, ptk_buf + WPA_KCK_LEN,            WPA_KEK_LEN);
    XMEMCPY(out_ptk->tk,  ptk_buf + WPA_KCK_LEN + WPA_KEK_LEN, WPA_TK_LEN);

    wpa_secure_zero(ptk_buf, sizeof(ptk_buf));
    wpa_secure_zero(data, sizeof(data));
    return 0;
}

/* IEEE 802.11 KDF-Hash-Length with HMAC-SHA256 (12.7.1.6.2):
 *   block_i = HMAC-SHA256(key, i_LE16 || label || data || L_LE16)
 * where L = out_bits. Output truncated to ceil(out_bits/8) bytes. */
static int wpa_kdf_sha256(const uint8_t *key, size_t key_len,
                          const char *label,
                          const uint8_t *data, size_t data_len,
                          uint8_t *out, size_t out_bits)
{
    uint8_t  digest[WC_SHA256_DIGEST_SIZE];
    uint8_t  counter_le[2], length_le[2];
    size_t   label_len = XSTRLEN(label);
    size_t   produced = 0;
    size_t   out_len = (out_bits + 7U) / 8U;
    uint16_t counter = 1;
    int      ret;

    length_le[0] = (uint8_t)(out_bits & 0xFFU);
    length_le[1] = (uint8_t)((out_bits >> 8) & 0xFFU);

    while (produced < out_len) {
        struct hmac_seg segs[4];
        size_t          n_segs = 0;
        size_t          take;

        counter_le[0] = (uint8_t)(counter & 0xFFU);
        counter_le[1] = (uint8_t)((counter >> 8) & 0xFFU);

        /* block = HMAC-SHA256(key, counter_LE16 || label || data || L_LE16) */
        segs[n_segs].p = counter_le;            segs[n_segs++].len = 2;
        segs[n_segs].p = (const uint8_t *)label; segs[n_segs++].len = (word32)label_len;
        if (data_len > 0) {
            segs[n_segs].p = data;              segs[n_segs++].len = (word32)data_len;
        }
        segs[n_segs].p = length_le;             segs[n_segs++].len = 2;

        ret = hmac_oneshot(WC_SHA256, key, (word32)key_len, segs, n_segs, digest);
        if (ret != 0) {
            wpa_secure_zero(digest, sizeof(digest));
            return ret;
        }

        take = out_len - produced;
        if (take > sizeof(digest)) take = sizeof(digest);
        XMEMCPY(out + produced, digest, take);
        produced += take;
        counter++;
    }
    wpa_secure_zero(digest, sizeof(digest));
    return 0;
}

int wpa_ptk_derive_sha256(const uint8_t pmk[WPA_PMK_LEN],
                          const uint8_t aa[WPA_MAC_LEN],
                          const uint8_t sa[WPA_MAC_LEN],
                          const uint8_t anonce[WPA_NONCE_LEN],
                          const uint8_t snonce[WPA_NONCE_LEN],
                          struct wpa_ptk *out_ptk)
{
    uint8_t data[2 * WPA_MAC_LEN + 2 * WPA_NONCE_LEN];
    uint8_t ptk_buf[WPA_PTK_LEN];
    int ret;

    if (pmk == NULL || aa == NULL || sa == NULL || anonce == NULL
        || snonce == NULL || out_ptk == NULL) {
        return BAD_FUNC_ARG;
    }

    bytes_min_max(aa, sa, WPA_MAC_LEN, &data[0], &data[WPA_MAC_LEN]);
    bytes_min_max(anonce, snonce, WPA_NONCE_LEN,
                  &data[2 * WPA_MAC_LEN],
                  &data[2 * WPA_MAC_LEN + WPA_NONCE_LEN]);

    ret = wpa_kdf_sha256(pmk, WPA_PMK_LEN, WPA_PTK_LABEL,
                         data, sizeof(data),
                         ptk_buf, WPA_PTK_LEN * 8U);
    if (ret != 0) {
        wpa_secure_zero(ptk_buf, sizeof(ptk_buf));
        wpa_secure_zero(data, sizeof(data));
        return ret;
    }

    XMEMCPY(out_ptk->kck, ptk_buf,                          WPA_KCK_LEN);
    XMEMCPY(out_ptk->kek, ptk_buf + WPA_KCK_LEN,            WPA_KEK_LEN);
    XMEMCPY(out_ptk->tk,  ptk_buf + WPA_KCK_LEN + WPA_KEK_LEN, WPA_TK_LEN);

    wpa_secure_zero(ptk_buf, sizeof(ptk_buf));
    wpa_secure_zero(data, sizeof(data));
    return 0;
}

int wpa_eapol_mic(const uint8_t kck[WPA_KCK_LEN],
                  const uint8_t *frame, size_t frame_len,
                  uint8_t out_mic[WPA_MIC_LEN])
{
    /* WPA2 Key Descriptor Version 2 uses HMAC-SHA1 truncated to 128 bits.
     * Caller must have zeroed the MIC field in the frame before calling.
     */
    uint8_t digest[WC_SHA_DIGEST_SIZE];
    struct hmac_seg seg;
    int ret;

    if (kck == NULL || frame == NULL || out_mic == NULL) {
        return BAD_FUNC_ARG;
    }

    seg.p = frame;
    seg.len = (word32)frame_len;
    ret = hmac_oneshot(WC_SHA, kck, WPA_KCK_LEN, &seg, 1, digest);
    if (ret != 0) {
        wpa_secure_zero(digest, sizeof(digest));
        return ret;
    }

    XMEMCPY(out_mic, digest, WPA_MIC_LEN);
    wpa_secure_zero(digest, sizeof(digest));
    return 0;
}

int wpa_eapol_mic_verify(const uint8_t kck[WPA_KCK_LEN],
                         const uint8_t *frame, size_t frame_len,
                         const uint8_t expected_mic[WPA_MIC_LEN])
{
    uint8_t computed[WPA_MIC_LEN];
    int ret;

    if (expected_mic == NULL) {
        return BAD_FUNC_ARG;
    }
    ret = wpa_eapol_mic(kck, frame, frame_len, computed);
    if (ret != 0) {
        wpa_secure_zero(computed, sizeof(computed));
        return ret;
    }
    ret = wpa_const_compare(computed, expected_mic, WPA_MIC_LEN);
    wpa_secure_zero(computed, sizeof(computed));
    return (ret == 0) ? 0 : -1;
}

/* AES-128 single-block ECB encryption E_K(in) implemented via CBC with a
 * zero IV (avoids depending on the optional WOLFSSL_CMAC / AES-ECB build
 * flags; only AES-CBC is required, which the supplicant build already
 * uses). The Aes context must hold the key. */
static int wpa_aes_ecb_block(Aes *aes, const uint8_t in[WC_AES_BLOCK_SIZE],
                             uint8_t out[WC_AES_BLOCK_SIZE])
{
    static const uint8_t zero_iv[WC_AES_BLOCK_SIZE] = { 0 };
    int ret = wc_AesSetIV(aes, zero_iv);
    if (ret != 0) {
        return ret;
    }
    return wc_AesCbcEncrypt(aes, out, in, WC_AES_BLOCK_SIZE);
}

static void wpa_cmac_lshift(const uint8_t in[WC_AES_BLOCK_SIZE],
                            uint8_t out[WC_AES_BLOCK_SIZE])
{
    int     i;
    uint8_t carry = 0;
    for (i = (int)WC_AES_BLOCK_SIZE - 1; i >= 0; i--) {
        uint8_t b = in[i];
        out[i] = (uint8_t)((b << 1) | carry);
        carry  = (uint8_t)((b >> 7) & 1U);
    }
}

static void wpa_cmac_xor16(const uint8_t a[WC_AES_BLOCK_SIZE],
                           const uint8_t b[WC_AES_BLOCK_SIZE],
                           uint8_t out[WC_AES_BLOCK_SIZE])
{
    int i;
    for (i = 0; i < (int)WC_AES_BLOCK_SIZE; i++) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

int wpa_eapol_mic_aes_cmac(const uint8_t kck[WPA_KCK_LEN],
                           const uint8_t *frame, size_t frame_len,
                           uint8_t out_mic[WPA_MIC_LEN])
{
    /* Key Descriptor Version 0 (AKM-defined): AES-128-CMAC (RFC 4493)
     * over the EAPOL-Key frame with the MIC field zeroed, truncated to
     * 128 bits. KCK is 16 bytes for the SAE AKM. Implemented in terms of
     * AES-CBC so it works regardless of whether wolfSSL was built with
     * --enable-cmac. */
    static const uint8_t Rb[WC_AES_BLOCK_SIZE] =
        { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x87 };
    static const uint8_t zero[WC_AES_BLOCK_SIZE] = { 0 };
    Aes     aes;
    uint8_t L[WC_AES_BLOCK_SIZE], K1[WC_AES_BLOCK_SIZE], K2[WC_AES_BLOCK_SIZE];
    uint8_t X[WC_AES_BLOCK_SIZE], Y[WC_AES_BLOCK_SIZE], Mlast[WC_AES_BLOCK_SIZE];
    size_t  n, i, rem;
    int     complete, ret;

    if (kck == NULL || frame == NULL || out_mic == NULL) {
        return BAD_FUNC_ARG;
    }
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_AesSetKey(&aes, kck, WPA_KCK_LEN, zero, AES_ENCRYPTION);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }

    /* Subkeys K1, K2 from L = E_K(0). */
    ret = wpa_aes_ecb_block(&aes, zero, L);
    if (ret != 0) goto out;
    wpa_cmac_lshift(L, K1);
    if (L[0] & 0x80) wpa_cmac_xor16(K1, Rb, K1);
    wpa_cmac_lshift(K1, K2);
    if (K1[0] & 0x80) wpa_cmac_xor16(K2, Rb, K2);

    /* Block count; build the final (possibly padded) block. */
    if (frame_len == 0) {
        n = 1;
        complete = 0;
    }
    else {
        n = (frame_len + (WC_AES_BLOCK_SIZE - 1U)) / WC_AES_BLOCK_SIZE;
        complete = ((frame_len % WC_AES_BLOCK_SIZE) == 0U);
    }
    if (complete) {
        wpa_cmac_xor16(frame + WC_AES_BLOCK_SIZE * (n - 1U), K1, Mlast);
    }
    else {
        uint8_t padded[WC_AES_BLOCK_SIZE];
        rem = frame_len - WC_AES_BLOCK_SIZE * (n - 1U);   /* 0..blk-1 */
        memset(padded, 0, sizeof(padded));
        if (rem > 0U) {
            memcpy(padded, frame + WC_AES_BLOCK_SIZE * (n - 1U), rem);
        }
        padded[rem] = 0x80;
        wpa_cmac_xor16(padded, K2, Mlast);
        wpa_secure_zero(padded, sizeof(padded));
    }

    /* CBC-MAC. */
    memset(X, 0, sizeof(X));
    for (i = 0; i + 1U < n; i++) {
        wpa_cmac_xor16(X, frame + WC_AES_BLOCK_SIZE * i, Y);
        ret = wpa_aes_ecb_block(&aes, Y, X);
        if (ret != 0) goto out;
    }
    wpa_cmac_xor16(X, Mlast, Y);
    ret = wpa_aes_ecb_block(&aes, Y, X);
    if (ret != 0) goto out;

    memcpy(out_mic, X, WPA_MIC_LEN);
out:
    /* Free the key schedule and scrub all CMAC-derived stack material on every
     * path; K1/K2 are deterministic functions of the KCK. */
    wc_AesFree(&aes);
    wpa_secure_zero(L, sizeof(L));
    wpa_secure_zero(K1, sizeof(K1));
    wpa_secure_zero(K2, sizeof(K2));
    wpa_secure_zero(X, sizeof(X));
    wpa_secure_zero(Y, sizeof(Y));
    wpa_secure_zero(Mlast, sizeof(Mlast));
    return ret;
}

int wpa_eapol_mic_aes_cmac_verify(const uint8_t kck[WPA_KCK_LEN],
                                  const uint8_t *frame, size_t frame_len,
                                  const uint8_t expected_mic[WPA_MIC_LEN])
{
    uint8_t computed[WPA_MIC_LEN];
    int ret;

    if (expected_mic == NULL) {
        return BAD_FUNC_ARG;
    }
    ret = wpa_eapol_mic_aes_cmac(kck, frame, frame_len, computed);
    if (ret != 0) {
        wpa_secure_zero(computed, sizeof(computed));
        return ret;
    }
    ret = wpa_const_compare(computed, expected_mic, WPA_MIC_LEN);
    wpa_secure_zero(computed, sizeof(computed));
    return (ret == 0) ? 0 : -1;
}

int wpa_aes_keywrap(const uint8_t *key, size_t key_len,
                    const uint8_t *in, size_t in_len,
                    uint8_t *out)
{
    int ret;

    if (key == NULL || in == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    /* RFC 3394 / wc_AesKeyWrap require at least one 64-bit block of
     * plaintext plus the 64-bit IV, i.e. >= 16 input bytes (matches the
     * keyunwrap guard below). */
    if ((in_len % WPA_KEYWRAP_SEMIBLOCK) != 0
        || in_len < 2 * WPA_KEYWRAP_SEMIBLOCK) {
        return BAD_FUNC_ARG;
    }
    ret = wc_AesKeyWrap(key, (word32)key_len,
                        in, (word32)in_len,
                        out, (word32)(in_len + WPA_KEYWRAP_SEMIBLOCK),
                        NULL);
    return (ret >= 0) ? 0 : ret;
}

int wpa_aes_keyunwrap(const uint8_t *key, size_t key_len,
                      const uint8_t *in, size_t in_len,
                      uint8_t *out)
{
    int ret;

    if (key == NULL || in == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    /* Wrapped input = plaintext (>= 16, two semiblocks) + the 64-bit IV
     * block, so the minimum valid ciphertext is 24 bytes (RFC 3394 /
     * wc_AesKeyUnWrap); a 16-byte input would unwrap to an 8-byte plaintext
     * which KW does not produce. */
    if ((in_len % WPA_KEYWRAP_SEMIBLOCK) != 0
        || in_len < 3 * WPA_KEYWRAP_SEMIBLOCK) {
        return BAD_FUNC_ARG;
    }
    ret = wc_AesKeyUnWrap(key, (word32)key_len,
                          in, (word32)in_len,
                          out, (word32)(in_len - WPA_KEYWRAP_SEMIBLOCK),
                          NULL);
    return (ret >= 0) ? 0 : ret;
}

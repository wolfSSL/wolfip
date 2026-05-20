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

#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/hmac.h>
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

/* Lexicographic min/max copy of two MAC addresses, used by the PRF
 * data construction so both peers produce the same key independent
 * of who is the supplicant vs authenticator.
 */
static void mac_min_max(const uint8_t a[WPA_MAC_LEN],
                        const uint8_t b[WPA_MAC_LEN],
                        uint8_t out_min[WPA_MAC_LEN],
                        uint8_t out_max[WPA_MAC_LEN])
{
    int cmp = memcmp(a, b, WPA_MAC_LEN);
    if (cmp < 0) {
        XMEMCPY(out_min, a, WPA_MAC_LEN);
        XMEMCPY(out_max, b, WPA_MAC_LEN);
    }
    else {
        XMEMCPY(out_min, b, WPA_MAC_LEN);
        XMEMCPY(out_max, a, WPA_MAC_LEN);
    }
}

/* Same idea for the nonces (32 bytes each). */
static void nonce_min_max(const uint8_t a[WPA_NONCE_LEN],
                          const uint8_t b[WPA_NONCE_LEN],
                          uint8_t out_min[WPA_NONCE_LEN],
                          uint8_t out_max[WPA_NONCE_LEN])
{
    int cmp = memcmp(a, b, WPA_NONCE_LEN);
    if (cmp < 0) {
        XMEMCPY(out_min, a, WPA_NONCE_LEN);
        XMEMCPY(out_max, b, WPA_NONCE_LEN);
    }
    else {
        XMEMCPY(out_min, b, WPA_NONCE_LEN);
        XMEMCPY(out_max, a, WPA_NONCE_LEN);
    }
}

void wpa_secure_zero(void *p, size_t n)
{
    if (p != NULL && n > 0) {
        wc_ForceZero(p, n);
    }
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
    /* IEEE 802.11i PRF: for i = 0, 1, ...
     *   T_i = HMAC-SHA1(key, label || 0x00 || data || i)
     * Output = T_0 || T_1 || ... truncated to out_len.
     *
     * Each T_i is 20 bytes (SHA1 digest size).
     */
    Hmac hmac;
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

    label_len = XSTRLEN(label);
    counter = 0;

    while (produced < out_len) {
        size_t copy_len;

        ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
        if (ret != 0) {
            return ret;
        }
        ret = wc_HmacSetKey(&hmac, WC_SHA, key, (word32)key_len);
        if (ret != 0) {
            wc_HmacFree(&hmac);
            return ret;
        }
        ret = wc_HmacUpdate(&hmac, (const byte *)label, (word32)label_len);
        if (ret == 0) {
            ret = wc_HmacUpdate(&hmac, &sep, 1);
        }
        if (ret == 0 && data_len > 0) {
            ret = wc_HmacUpdate(&hmac, data, (word32)data_len);
        }
        if (ret == 0) {
            ret = wc_HmacUpdate(&hmac, &counter, 1);
        }
        if (ret == 0) {
            ret = wc_HmacFinal(&hmac, digest);
        }
        wc_HmacFree(&hmac);
        if (ret != 0) {
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

    mac_min_max(aa, sa, &data[0], &data[WPA_MAC_LEN]);
    nonce_min_max(anonce, snonce,
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

    XMEMCPY(out_ptk->kck, ptk_buf + 0,  WPA_KCK_LEN);
    XMEMCPY(out_ptk->kek, ptk_buf + 16, WPA_KEK_LEN);
    XMEMCPY(out_ptk->tk,  ptk_buf + 32, WPA_TK_LEN);

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
    Hmac hmac;
    uint8_t digest[WC_SHA_DIGEST_SIZE];
    int ret;

    if (kck == NULL || frame == NULL || out_mic == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_HmacSetKey(&hmac, WC_SHA, kck, WPA_KCK_LEN);
    if (ret == 0) {
        ret = wc_HmacUpdate(&hmac, frame, (word32)frame_len);
    }
    if (ret == 0) {
        ret = wc_HmacFinal(&hmac, digest);
    }
    wc_HmacFree(&hmac);

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

int wpa_aes_keywrap(const uint8_t *key, size_t key_len,
                    const uint8_t *in, size_t in_len,
                    uint8_t *out)
{
    int ret;

    if (key == NULL || in == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((in_len % 8) != 0 || in_len < 8) {
        return BAD_FUNC_ARG;
    }
    ret = wc_AesKeyWrap(key, (word32)key_len,
                        in, (word32)in_len,
                        out, (word32)(in_len + 8),
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
    if ((in_len % 8) != 0 || in_len < 16) {
        return BAD_FUNC_ARG;
    }
    ret = wc_AesKeyUnWrap(key, (word32)key_len,
                          in, (word32)in_len,
                          out, (word32)(in_len - 8),
                          NULL);
    return (ret >= 0) ? 0 : ret;
}

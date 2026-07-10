/* macsec_crypto.c
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

#include "macsec_crypto.h"
#include "supplicant_features.h"
#include "wpa_crypto.h"          /* wpa_aes_keywrap/unwrap, wpa_secure_zero */

#include <string.h>

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cmac.h>

#ifndef WOLFSSL_CMAC
#error "wolfIP MACsec requires wolfSSL built with WOLFSSL_CMAC (--enable-cmac)"
#endif

/* AES-CMAC output block size (bits and bytes). The KDF counter mode of
 * IEEE 802.1X-2010 6.2.1 emits one 128-bit block per iteration. */
#define MACSEC_CMAC_BLOCK_BITS  128U
#define MACSEC_CMAC_BLOCK_LEN    16U

/* A segment of the KDF context, so a caller can supply a logically
 * concatenated context (e.g. ks_nonce || mi_list || kn) without assembling
 * it into one contiguous buffer - important for the multipoint SAK where
 * the Member Identifier list can be large. */
struct macsec_kdf_seg {
    const uint8_t *p;
    size_t         len;
};

/* Constant-time compare of two byte strings. Returns 0 when equal, -1
 * otherwise. Branch-free accumulate so timing does not leak the ICV. */
static int macsec_const_compare(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    size_t  i;

    for (i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return (diff == 0) ? 0 : -1;
}

/* One AES-CMAC over the ordered segments, key selects AES-128/256 by length.
 * out must hold MACSEC_CMAC_BLOCK_LEN bytes. */
static int macsec_cmac_segments(const uint8_t *key, size_t key_len,
                                const struct macsec_kdf_seg *segs, size_t nseg,
                                uint8_t out[MACSEC_CMAC_BLOCK_LEN])
{
    Cmac    cmac;
    word32  out_sz = MACSEC_CMAC_BLOCK_LEN;
    size_t  i;
    int     ret;

    ret = wc_InitCmac(&cmac, key, (word32)key_len, WC_CMAC_AES, NULL);
    if (ret != 0) {
        return ret;
    }
    for (i = 0; i < nseg; i++) {
        if (segs[i].len == 0) {
            continue;
        }
        ret = wc_CmacUpdate(&cmac, segs[i].p, (word32)segs[i].len);
        if (ret != 0) {
            /* Finalize into a scratch block to release any CMAC state. */
            (void)wc_CmacFinal(&cmac, out, &out_sz);
            return ret;
        }
    }
    return wc_CmacFinal(&cmac, out, &out_sz);
}

/* IEEE 802.1X-2010 6.2.1 KDF over segmented context. Builds, per block i:
 *   i(1) || label || 0x00 || <segments> || out_bits(2, big-endian)
 * and concatenates blocks until out_bits are produced. */
static int macsec_kdf_core(const uint8_t *key, size_t key_len,
                           const char *label,
                           const struct macsec_kdf_seg *ctx_segs,
                           size_t ctx_nseg,
                           uint16_t out_bits, uint8_t *out)
{
    struct macsec_kdf_seg segs[8];
    uint8_t block[MACSEC_CMAC_BLOCK_LEN];
    uint8_t ctr;
    uint8_t sep;
    uint8_t len_be[2];
    size_t  label_len;
    size_t  out_len;
    size_t  copied;
    size_t  n;
    size_t  i;
    unsigned int blk;
    int     ret;

    if (key == NULL || label == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((out_bits & 0x7U) != 0 || out_bits == 0
        || out_bits > (2U * MACSEC_CMAC_BLOCK_BITS)) {
        return BAD_FUNC_ARG;
    }
    /* Fixed leading (ctr, label, sep) + context segments + trailing length;
     * bounded so the segs[] array cannot overflow. */
    if (ctx_nseg + 4U > (sizeof(segs) / sizeof(segs[0]))) {
        return BAD_FUNC_ARG;
    }

    label_len = strlen(label);
    sep       = 0x00;
    out_len   = (size_t)(out_bits / 8U);
    len_be[0] = (uint8_t)((out_bits >> 8) & 0xFFU);
    len_be[1] = (uint8_t)(out_bits & 0xFFU);
    n         = (size_t)((out_bits + MACSEC_CMAC_BLOCK_BITS - 1U)
                         / MACSEC_CMAC_BLOCK_BITS);

    copied = 0;
    ret    = 0;
    for (blk = 1; blk <= n; blk++) {
        size_t s = 0;

        ctr        = (uint8_t)blk;
        segs[s].p   = &ctr;      segs[s].len = 1;               s++;
        segs[s].p   = (const uint8_t *)label; segs[s].len = label_len; s++;
        segs[s].p   = &sep;       segs[s].len = 1;               s++;
        for (i = 0; i < ctx_nseg; i++) {
            segs[s].p = ctx_segs[i].p; segs[s].len = ctx_segs[i].len; s++;
        }
        segs[s].p   = len_be;     segs[s].len = 2;               s++;

        ret = macsec_cmac_segments(key, key_len, segs, s, block);
        if (ret != 0) {
            break;
        }
        {
            size_t take = out_len - copied;
            if (take > MACSEC_CMAC_BLOCK_LEN) {
                take = MACSEC_CMAC_BLOCK_LEN;
            }
            memcpy(out + copied, block, take);
            copied += take;
        }
    }

    wpa_secure_zero(block, sizeof(block));
    if (ret != 0) {
        wpa_secure_zero(out, out_len);
    }
    return ret;
}

int macsec_kdf(const uint8_t *key, size_t key_len,
               const char *label,
               const uint8_t *context, size_t ctx_len,
               uint16_t out_bits, uint8_t *out)
{
    struct macsec_kdf_seg seg;

    seg.p   = context;
    seg.len = ctx_len;
    return macsec_kdf_core(key, key_len, label, &seg,
                           (context != NULL && ctx_len > 0) ? 1U : 0U,
                           out_bits, out);
}

int macsec_derive_cak(const uint8_t *msk, size_t msk_len, size_t cak_len,
                      const uint8_t peer_mac[MACSEC_MAC_LEN],
                      const uint8_t auth_mac[MACSEC_MAC_LEN],
                      uint8_t *cak)
{
    struct macsec_kdf_seg segs[2];

    if (msk == NULL || peer_mac == NULL || auth_mac == NULL || cak == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((cak_len != MACSEC_KEY_LEN_128 && cak_len != MACSEC_KEY_LEN_256)
        || msk_len < cak_len) {
        return BAD_FUNC_ARG;
    }
    /* KDK is the leftmost cak_len bytes of the MSK. */
    segs[0].p = peer_mac; segs[0].len = MACSEC_MAC_LEN;
    segs[1].p = auth_mac; segs[1].len = MACSEC_MAC_LEN;
    return macsec_kdf_core(msk, cak_len, MACSEC_LABEL_EAP_CAK,
                           segs, 2U, (uint16_t)(cak_len * 8U), cak);
}

int macsec_derive_ckn(const uint8_t *msk, size_t msk_len,
                      const uint8_t *eap_session_id, size_t session_id_len,
                      const uint8_t peer_mac[MACSEC_MAC_LEN],
                      const uint8_t auth_mac[MACSEC_MAC_LEN],
                      uint8_t *ckn, size_t ckn_len)
{
    struct macsec_kdf_seg segs[3];

    if (msk == NULL || eap_session_id == NULL || peer_mac == NULL
        || auth_mac == NULL || ckn == NULL) {
        return BAD_FUNC_ARG;
    }
    if (ckn_len == 0 || ckn_len > MACSEC_CKN_MAX_LEN
        || (ckn_len & 0x1U) != 0 || msk_len < MACSEC_KEY_LEN_128) {
        return BAD_FUNC_ARG;
    }
    /* KDK is a 128-bit key: the leftmost 16 bytes of the MSK. */
    segs[0].p = eap_session_id; segs[0].len = session_id_len;
    segs[1].p = peer_mac;       segs[1].len = MACSEC_MAC_LEN;
    segs[2].p = auth_mac;       segs[2].len = MACSEC_MAC_LEN;
    return macsec_kdf_core(msk, MACSEC_KEY_LEN_128, MACSEC_LABEL_EAP_CKN,
                           segs, 3U, (uint16_t)(ckn_len * 8U), ckn);
}

/* Shared KEK/ICK derivation: both take the CAK as KDK and the leftmost 16
 * bytes of the CKN (zero-padded) as context, differing only in the label. */
static int macsec_derive_kek_ick(const uint8_t *cak, size_t cak_len,
                                 const uint8_t *ckn, size_t ckn_len,
                                 const char *label, uint8_t *out)
{
    uint8_t ctx[16];

    if (cak == NULL || ckn == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (cak_len != MACSEC_KEY_LEN_128 && cak_len != MACSEC_KEY_LEN_256) {
        return BAD_FUNC_ARG;
    }
    if (ckn_len == 0) {
        return BAD_FUNC_ARG;
    }
    memset(ctx, 0, sizeof(ctx));
    memcpy(ctx, ckn, (ckn_len < sizeof(ctx)) ? ckn_len : sizeof(ctx));
    return macsec_kdf(cak, cak_len, label, ctx, sizeof(ctx),
                      (uint16_t)(cak_len * 8U), out);
}

int macsec_derive_kek(const uint8_t *cak, size_t cak_len,
                      const uint8_t *ckn, size_t ckn_len,
                      uint8_t *kek)
{
    return macsec_derive_kek_ick(cak, cak_len, ckn, ckn_len,
                                 MACSEC_LABEL_KEK, kek);
}

int macsec_derive_ick(const uint8_t *cak, size_t cak_len,
                      const uint8_t *ckn, size_t ckn_len,
                      uint8_t *ick)
{
    return macsec_derive_kek_ick(cak, cak_len, ckn, ckn_len,
                                 MACSEC_LABEL_ICK, ick);
}

int macsec_generate_sak(const uint8_t *cak, size_t cak_len, size_t sak_len,
                        const uint8_t ks_nonce[MACSEC_KS_NONCE_LEN],
                        const uint8_t *mi_list, size_t mi_list_len,
                        uint32_t kn, uint8_t *sak)
{
    struct macsec_kdf_seg segs[3];
    uint8_t kn_be[MACSEC_KN_LEN];

    if (cak == NULL || ks_nonce == NULL || mi_list == NULL || sak == NULL) {
        return BAD_FUNC_ARG;
    }
    if (cak_len != MACSEC_KEY_LEN_128 && cak_len != MACSEC_KEY_LEN_256) {
        return BAD_FUNC_ARG;
    }
    if (sak_len != MACSEC_KEY_LEN_128 && sak_len != MACSEC_KEY_LEN_256) {
        return BAD_FUNC_ARG;
    }
    if (mi_list_len == 0 || (mi_list_len % MACSEC_MI_LEN) != 0) {
        return BAD_FUNC_ARG;
    }
    kn_be[0] = (uint8_t)((kn >> 24) & 0xFFU);
    kn_be[1] = (uint8_t)((kn >> 16) & 0xFFU);
    kn_be[2] = (uint8_t)((kn >>  8) & 0xFFU);
    kn_be[3] = (uint8_t)(kn & 0xFFU);

    segs[0].p = ks_nonce; segs[0].len = MACSEC_KS_NONCE_LEN;
    segs[1].p = mi_list;  segs[1].len = mi_list_len;
    segs[2].p = kn_be;    segs[2].len = MACSEC_KN_LEN;
    return macsec_kdf_core(cak, cak_len, MACSEC_LABEL_SAK,
                           segs, 3U, (uint16_t)(sak_len * 8U), sak);
}

int macsec_mkpdu_icv(const uint8_t *ick, size_t ick_len,
                     const uint8_t *mkpdu, size_t mkpdu_len,
                     uint8_t icv[MACSEC_ICV_LEN])
{
    word32 out_sz = MACSEC_ICV_LEN;

    if (ick == NULL || mkpdu == NULL || icv == NULL) {
        return BAD_FUNC_ARG;
    }
    if (ick_len != MACSEC_KEY_LEN_128 && ick_len != MACSEC_KEY_LEN_256) {
        return BAD_FUNC_ARG;
    }
    return wc_AesCmacGenerate(icv, &out_sz, mkpdu, (word32)mkpdu_len,
                              ick, (word32)ick_len);
}

int macsec_mkpdu_icv_verify(const uint8_t *ick, size_t ick_len,
                            const uint8_t *mkpdu, size_t mkpdu_len,
                            const uint8_t expected_icv[MACSEC_ICV_LEN])
{
    uint8_t computed[MACSEC_ICV_LEN];
    int     ret;

    if (expected_icv == NULL) {
        return BAD_FUNC_ARG;
    }
    ret = macsec_mkpdu_icv(ick, ick_len, mkpdu, mkpdu_len, computed);
    if (ret != 0) {
        wpa_secure_zero(computed, sizeof(computed));
        return ret;
    }
    ret = macsec_const_compare(computed, expected_icv, MACSEC_ICV_LEN);
    wpa_secure_zero(computed, sizeof(computed));
    return (ret == 0) ? 0 : -1;
}

int macsec_wrap_sak(const uint8_t *kek, size_t kek_len,
                    const uint8_t *sak, size_t sak_len,
                    uint8_t *wrapped)
{
    if (sak_len != MACSEC_KEY_LEN_128 && sak_len != MACSEC_KEY_LEN_256) {
        return BAD_FUNC_ARG;
    }
    return wpa_aes_keywrap(kek, kek_len, sak, sak_len, wrapped);
}

int macsec_unwrap_sak(const uint8_t *kek, size_t kek_len,
                      const uint8_t *wrapped, size_t wrapped_len,
                      uint8_t *sak)
{
    if (wrapped_len != (MACSEC_KEY_LEN_128 + WPA_KEYWRAP_SEMIBLOCK)
        && wrapped_len != (MACSEC_KEY_LEN_256 + WPA_KEYWRAP_SEMIBLOCK)) {
        return BAD_FUNC_ARG;
    }
    return wpa_aes_keyunwrap(kek, kek_len, wrapped, wrapped_len, sak);
}

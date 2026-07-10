/* macsec_secy.c
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

#include "macsec_secy.h"
#include "supplicant_features.h"
#include "wpa_crypto.h"          /* wpa_secure_zero */

#include <string.h>

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>

#ifndef HAVE_AESGCM
#error "wolfIP MACsec SecY requires wolfSSL built with HAVE_AESGCM (--enable-aesgcm)"
#endif

#define MACSEC_ETH_ADDR_PAIR_LEN  12U   /* DA(6) + SA(6)                     */

/* conf_offset is limited to the 802.1AE-permitted values. */
static int macsec_offset_valid(size_t off)
{
    return (off == 0U || off == 30U || off == 50U);
}

/* Assemble the 12-byte GCM nonce SCI(8) || PN(4, big-endian). */
static void macsec_build_nonce(uint8_t nonce[MACSEC_GCM_NONCE_LEN],
                               const uint8_t sci[MACSEC_SCI_LEN], uint32_t pn)
{
    memcpy(nonce, sci, MACSEC_SCI_LEN);
    nonce[8]  = (uint8_t)((pn >> 24) & 0xFFU);
    nonce[9]  = (uint8_t)((pn >> 16) & 0xFFU);
    nonce[10] = (uint8_t)((pn >>  8) & 0xFFU);
    nonce[11] = (uint8_t)(pn & 0xFFU);
}

int macsec_sectag_build(uint8_t *out, size_t out_cap,
                        const struct macsec_protect_params *p,
                        size_t secure_data_len)
{
    uint8_t tci_an;
    size_t  len;

    if (out == NULL || p == NULL) {
        return BAD_FUNC_ARG;
    }
    if (p->an > MACSEC_AN_MASK) {
        return BAD_FUNC_ARG;
    }
    len = p->include_sci ? MACSEC_SECTAG_MAX_LEN : MACSEC_SECTAG_MIN_LEN;
    if (out_cap < len) {
        return BAD_FUNC_ARG;
    }

    tci_an = (uint8_t)(p->an & MACSEC_AN_MASK);   /* V bit stays 0 */
    if (p->end_station) {
        tci_an |= MACSEC_TCI_ES;
    }
    if (p->include_sci) {
        tci_an |= MACSEC_TCI_SC;
    }
    if (p->scb) {
        tci_an |= MACSEC_TCI_SCB;
    }
    if (p->encrypt) {
        /* Confidentiality: both E (encrypted) and C (changed text) set. */
        tci_an |= (uint8_t)(MACSEC_TCI_E | MACSEC_TCI_C);
    }

    out[0] = (uint8_t)((MACSEC_ETHERTYPE >> 8) & 0xFFU);
    out[1] = (uint8_t)(MACSEC_ETHERTYPE & 0xFFU);
    out[2] = tci_an;
    out[3] = (secure_data_len < MACSEC_MIN_SECURE_DATA)
                 ? (uint8_t)secure_data_len : 0U;
    out[4] = (uint8_t)((p->pn >> 24) & 0xFFU);
    out[5] = (uint8_t)((p->pn >> 16) & 0xFFU);
    out[6] = (uint8_t)((p->pn >>  8) & 0xFFU);
    out[7] = (uint8_t)(p->pn & 0xFFU);
    if (p->include_sci) {
        memcpy(out + 8, p->sci, MACSEC_SCI_LEN);
    }
    return (int)len;
}

int macsec_sectag_parse(const uint8_t *in, size_t in_len,
                        struct macsec_sectag *out)
{
    uint8_t tci_an;

    if (in == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (in_len < MACSEC_SECTAG_MIN_LEN) {
        return BAD_FUNC_ARG;
    }
    if (in[0] != (uint8_t)((MACSEC_ETHERTYPE >> 8) & 0xFFU)
        || in[1] != (uint8_t)(MACSEC_ETHERTYPE & 0xFFU)) {
        return BAD_FUNC_ARG;
    }
    tci_an = in[2];
    if ((tci_an & MACSEC_TCI_V) != 0U) {
        return BAD_FUNC_ARG;                 /* version must be 0 */
    }

    memset(out, 0, sizeof(*out));
    out->tci_an = tci_an;
    out->sl     = in[3];
    out->pn     = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16)
                | ((uint32_t)in[6] << 8)  | (uint32_t)in[7];
    if ((tci_an & MACSEC_TCI_SC) != 0U) {
        if (in_len < MACSEC_SECTAG_MAX_LEN) {
            return BAD_FUNC_ARG;
        }
        out->sci_present = 1U;
        memcpy(out->sci, in + 8, MACSEC_SCI_LEN);
        out->len = MACSEC_SECTAG_MAX_LEN;
    }
    else {
        out->len = MACSEC_SECTAG_MIN_LEN;
    }
    return 0;
}

int macsec_protect(const struct macsec_protect_params *p,
                   const uint8_t *payload, size_t payload_len,
                   uint8_t *out, size_t out_cap, size_t *out_len)
{
    Aes     aes;
    uint8_t nonce[MACSEC_GCM_NONCE_LEN];
    uint8_t tag[MACSEC_ICV_LEN];
    size_t  sectag_len;
    size_t  hdr_len;
    size_t  cleartext_len;
    size_t  enc_len;
    size_t  total;
    int     ret;
    int     built;

    if (p == NULL || payload == NULL || out == NULL || out_len == NULL) {
        return BAD_FUNC_ARG;
    }
    if (p->da == NULL || p->sa == NULL || p->sci == NULL || p->sak == NULL) {
        return BAD_FUNC_ARG;
    }
    if (p->sak_len != MACSEC_KEY_LEN_128 && p->sak_len != MACSEC_KEY_LEN_256) {
        return BAD_FUNC_ARG;
    }
    if (p->encrypt && !macsec_offset_valid(p->conf_offset)) {
        return BAD_FUNC_ARG;
    }
    if (out_cap < MACSEC_ETH_ADDR_PAIR_LEN) {
        return BAD_FUNC_ARG;
    }

    /* Build the SecTAG directly in place after the DA/SA pair. */
    built = macsec_sectag_build(out + MACSEC_ETH_ADDR_PAIR_LEN,
                                out_cap - MACSEC_ETH_ADDR_PAIR_LEN,
                                p, payload_len);
    if (built < 0) {
        return built;
    }
    sectag_len = (size_t)built;
    hdr_len = MACSEC_ETH_ADDR_PAIR_LEN + sectag_len;

    /* cleartext_len: encrypted frames leave conf_offset octets in the clear
     * (bounded by the payload); integrity-only frames keep the whole MSDU. */
    if (p->encrypt) {
        cleartext_len = (p->conf_offset < payload_len)
                            ? p->conf_offset : payload_len;
    }
    else {
        cleartext_len = payload_len;
    }
    enc_len = payload_len - cleartext_len;

    total = hdr_len + payload_len + MACSEC_ICV_LEN;
    if (out_cap < total) {
        return BAD_FUNC_ARG;
    }

    /* SecTAG is already at out[12]; write the DA || SA pair in front of it. */
    memcpy(out, p->da, MACSEC_MAC_LEN);
    memcpy(out + MACSEC_MAC_LEN, p->sa, MACSEC_MAC_LEN);

    /* Secure Data = [cleartext prefix] || [ciphertext]. Copy the cleartext
     * prefix; the AAD is exactly out[0 .. hdr_len + cleartext_len). */
    memcpy(out + hdr_len, payload, cleartext_len);

    macsec_build_nonce(nonce, p->sci, p->pn);

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_AesGcmSetKey(&aes, p->sak, (word32)p->sak_len);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }
    ret = wc_AesGcmEncrypt(&aes,
                           out + hdr_len + cleartext_len,
                           payload + cleartext_len, (word32)enc_len,
                           nonce, MACSEC_GCM_NONCE_LEN,
                           tag, MACSEC_ICV_LEN,
                           out, (word32)(hdr_len + cleartext_len));
    wc_AesFree(&aes);
    if (ret != 0) {
        wpa_secure_zero(nonce, sizeof(nonce));
        return ret;
    }

    memcpy(out + hdr_len + payload_len, tag, MACSEC_ICV_LEN);
    *out_len = total;

    wpa_secure_zero(nonce, sizeof(nonce));
    wpa_secure_zero(tag, sizeof(tag));
    return 0;
}

int macsec_validate(const struct macsec_validate_params *p,
                    const uint8_t *frame, size_t frame_len,
                    uint8_t *out_payload, size_t out_cap,
                    size_t *out_payload_len,
                    struct macsec_sectag *out_tag)
{
    struct macsec_sectag tag;
    Aes            aes;
    uint8_t        nonce[MACSEC_GCM_NONCE_LEN];
    const uint8_t *sci;
    const uint8_t *icv;
    size_t  hdr_len;
    size_t  sd_len;
    size_t  cleartext_len;
    size_t  enc_len;
    int     encrypted;
    int     ret;

    if (p == NULL || frame == NULL || out_payload == NULL
        || out_payload_len == NULL || out_tag == NULL) {
        return BAD_FUNC_ARG;
    }
    if (p->sak == NULL
        || (p->sak_len != MACSEC_KEY_LEN_128
            && p->sak_len != MACSEC_KEY_LEN_256)) {
        return BAD_FUNC_ARG;
    }
    if (!macsec_offset_valid(p->conf_offset)) {
        return BAD_FUNC_ARG;
    }
    if (frame_len < MACSEC_ETH_ADDR_PAIR_LEN + MACSEC_SECTAG_MIN_LEN
                    + MACSEC_ICV_LEN) {
        return BAD_FUNC_ARG;
    }

    ret = macsec_sectag_parse(frame + MACSEC_ETH_ADDR_PAIR_LEN,
                              frame_len - MACSEC_ETH_ADDR_PAIR_LEN, &tag);
    if (ret != 0) {
        return ret;
    }
    hdr_len = MACSEC_ETH_ADDR_PAIR_LEN + tag.len;
    if (frame_len < hdr_len + MACSEC_ICV_LEN) {
        return BAD_FUNC_ARG;
    }
    sd_len = frame_len - hdr_len - MACSEC_ICV_LEN;
    icv    = frame + hdr_len + sd_len;

    /* Nonce SCI: the SecTAG's if present, otherwise the SC's configured SCI. */
    if (tag.sci_present) {
        sci = tag.sci;
    }
    else if (p->sci != NULL) {
        sci = p->sci;
    }
    else {
        return BAD_FUNC_ARG;
    }

    encrypted = ((tag.tci_an & MACSEC_TCI_E) != 0U);
    if (encrypted) {
        cleartext_len = (p->conf_offset < sd_len) ? p->conf_offset : sd_len;
    }
    else {
        cleartext_len = sd_len;
    }
    enc_len = sd_len - cleartext_len;

    if (out_cap < sd_len) {
        return BAD_FUNC_ARG;
    }

    /* Copy the cleartext prefix; AAD is frame[0 .. hdr_len + cleartext_len). */
    memcpy(out_payload, frame + hdr_len, cleartext_len);

    macsec_build_nonce(nonce, sci, tag.pn);

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_AesGcmSetKey(&aes, p->sak, (word32)p->sak_len);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }
    ret = wc_AesGcmDecrypt(&aes,
                           out_payload + cleartext_len,
                           frame + hdr_len + cleartext_len, (word32)enc_len,
                           nonce, MACSEC_GCM_NONCE_LEN,
                           icv, MACSEC_ICV_LEN,
                           frame, (word32)(hdr_len + cleartext_len));
    wc_AesFree(&aes);
    wpa_secure_zero(nonce, sizeof(nonce));
    if (ret != 0) {
        /* ICV mismatch (AES_GCM_AUTH_E) or crypto error: scrub output. */
        wpa_secure_zero(out_payload, sd_len);
        return -1;
    }

    *out_payload_len = sd_len;
    memcpy(out_tag, &tag, sizeof(tag));
    return 0;
}

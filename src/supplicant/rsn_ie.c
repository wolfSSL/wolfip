/* rsn_ie.c
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

#include "rsn_ie.h"

#include <string.h>

static uint16_t rd16_le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static void wr16_le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)(v >> 8);
}

static int suite_oui_ok(const uint8_t *suite)
{
    return (suite[0] == RSN_SUITE_OUI_0
         && suite[1] == RSN_SUITE_OUI_1
         && suite[2] == RSN_SUITE_OUI_2) ? 1 : 0;
}

int rsn_ie_parse(const uint8_t *ie, size_t ie_len, struct rsn_ie_view *out)
{
    size_t   off;
    size_t   end;
    uint16_t ver;
    uint16_t pairwise_count;
    uint16_t akm_count;
    uint8_t  declared_len;

    if (ie == NULL || out == NULL) {
        return -1;
    }
    if (ie_len < 2U) {
        return -1;
    }
    if (ie[0] != RSN_IE_ELEMENT_ID) {
        return -1;
    }
    declared_len = ie[1];
    if ((size_t)declared_len + 2U > ie_len) {
        return -1;
    }
    /* Minimum body = ver(2) + group(4) + pw_count(2) + 1*pw(4)
     *                + akm_count(2) + 1*akm(4) = 18, but the spec also
     * allows count=0 (use default), so accept the formal minimum of 18.
     */
    if (declared_len < 18U) {
        return -1;
    }
    end = 2U + (size_t)declared_len;

    off = 2U;
    ver = rd16_le(&ie[off]);
    off += 2U;
    if (ver != 1U) {
        return -1;
    }
    /* Group cipher suite. */
    if (off + 4U > end) {
        return -1;
    }
    if (!suite_oui_ok(&ie[off])) {
        return -1;
    }
    out->version      = ver;
    out->group_cipher = ie[off + 3U];
    off += 4U;

    /* Pairwise list. */
    if (off + 2U > end) {
        return -1;
    }
    pairwise_count = rd16_le(&ie[off]);
    off += 2U;
    if (pairwise_count > 64U) {
        return -1;
    }
    if (off + (size_t)pairwise_count * 4U > end) {
        return -1;
    }
    out->pairwise_count = pairwise_count;
    out->pairwise_list  = (pairwise_count > 0) ? &ie[off] : NULL;
    off += (size_t)pairwise_count * 4U;

    /* AKM list. */
    if (off + 2U > end) {
        return -1;
    }
    akm_count = rd16_le(&ie[off]);
    off += 2U;
    if (akm_count > 64U) {
        return -1;
    }
    if (off + (size_t)akm_count * 4U > end) {
        return -1;
    }
    out->akm_count = akm_count;
    out->akm_list  = (akm_count > 0) ? &ie[off] : NULL;
    off += (size_t)akm_count * 4U;

    /* Optional RSN Capabilities. */
    if (off + 2U <= end) {
        out->rsn_caps      = rd16_le(&ie[off]);
        out->have_rsn_caps = 1;
    }
    else {
        out->rsn_caps      = 0;
        out->have_rsn_caps = 0;
    }
    /* PMKID / Group Mgmt cipher are ignored in v1. */
    return 0;
}

int rsn_ie_build_wpa2_psk(uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t total = 22U;
    size_t i = 0;

    if (out == NULL || out_len == NULL || out_cap < total) {
        return -1;
    }
    out[i++] = RSN_IE_ELEMENT_ID;     /* Element ID                       */
    out[i++] = (uint8_t)(total - 2U); /* Length                           */
    wr16_le(&out[i], 1U); i += 2U;    /* Version                          */
    /* Group cipher: 00:0F:AC:04 (CCMP-128). */
    out[i++] = RSN_SUITE_OUI_0;
    out[i++] = RSN_SUITE_OUI_1;
    out[i++] = RSN_SUITE_OUI_2;
    out[i++] = RSN_CIPHER_CCMP_128;
    /* One pairwise suite: CCMP-128. */
    wr16_le(&out[i], 1U); i += 2U;
    out[i++] = RSN_SUITE_OUI_0;
    out[i++] = RSN_SUITE_OUI_1;
    out[i++] = RSN_SUITE_OUI_2;
    out[i++] = RSN_CIPHER_CCMP_128;
    /* One AKM suite: PSK. */
    wr16_le(&out[i], 1U); i += 2U;
    out[i++] = RSN_SUITE_OUI_0;
    out[i++] = RSN_SUITE_OUI_1;
    out[i++] = RSN_SUITE_OUI_2;
    out[i++] = RSN_AKM_PSK;
    /* RSN Capabilities = 0. */
    wr16_le(&out[i], 0U); i += 2U;

    *out_len = total;
    return 0;
}

int rsn_ie_equal(const uint8_t *a, size_t a_len,
                 const uint8_t *b, size_t b_len)
{
    if (a == NULL || b == NULL) {
        return -1;
    }
    if (a_len != b_len) {
        return -1;
    }
    return (memcmp(a, b, a_len) == 0) ? 0 : -1;
}

int rsn_suite_in_list(const uint8_t *suite_list, uint16_t count,
                      uint8_t suite_type)
{
    uint16_t i;
    if (suite_list == NULL) {
        return 0;
    }
    for (i = 0; i < count; i++) {
        const uint8_t *p = &suite_list[(size_t)i * 4U];
        if (suite_oui_ok(p) && p[3] == suite_type) {
            return 1;
        }
    }
    return 0;
}

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

static void wr16_le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)(v >> 8);
}

int rsn_ie_build_wpa2_psk_ex(uint8_t *out, size_t out_cap, size_t *out_len,
                             uint16_t caps)
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
    /* RSN Capabilities. */
    wr16_le(&out[i], caps); i += 2U;

    *out_len = total;
    return 0;
}

int rsn_ie_build_wpa2_psk(uint8_t *out, size_t out_cap, size_t *out_len)
{
    return rsn_ie_build_wpa2_psk_ex(out, out_cap, out_len, 0U);
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

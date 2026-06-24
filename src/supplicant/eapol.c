/* eapol.c
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

#include "eapol.h"

#include <string.h>

int eapol_key_parse(const uint8_t *frame, size_t frame_len,
                    struct eapol_key_view *out)
{
    uint16_t body_len;
    uint16_t key_data_len;
    const uint8_t *body;

    if (frame == NULL || out == NULL) {
        return -1;
    }
    if (frame_len < EAPOL_KEY_FIXED_LEN) {
        return -1;
    }
    /* 802.1X header sanity. */
    if (frame[0] != EAPOL_PROTO_VER && frame[0] != 0x01U) {
        /* Accept v1 and v2; reject anything else. */
        return -1;
    }
    if (frame[1] != EAPOL_TYPE_KEY) {
        return -1;
    }
    body_len = eapol_rd16(&frame[2]);
    if ((size_t)body_len + EAPOL_HEADER_LEN > frame_len) {
        return -1;
    }
    if (body_len < KEYBODY_FIXED_LEN) {
        return -1;
    }
    body = frame + EAPOL_HEADER_LEN;
    if (body[KEYBODY_OFF_DESC_TYPE] != EAPOL_KEY_DESC_RSN) {
        return -1;
    }
    key_data_len = eapol_rd16(&body[KEYBODY_OFF_KEY_DATA_LEN]);
    if ((size_t)KEYBODY_FIXED_LEN + key_data_len > body_len) {
        return -1;
    }

    out->frame          = frame;
    out->frame_len      = (size_t)body_len + EAPOL_HEADER_LEN;
    out->body_len       = body_len;
    out->key_info       = eapol_rd16(&body[KEYBODY_OFF_KEY_INFO]);
    out->key_len        = eapol_rd16(&body[KEYBODY_OFF_KEY_LEN]);
    out->replay_counter = &body[KEYBODY_OFF_REPLAY];
    out->nonce          = &body[KEYBODY_OFF_NONCE];
    out->mic            = &body[KEYBODY_OFF_MIC];
    out->key_data_len   = key_data_len;
    out->key_data       = (key_data_len > 0) ?
                          &body[KEYBODY_OFF_KEY_DATA] : NULL;
    return 0;
}

int eapol_key_build(uint8_t *out, size_t out_cap,
                    uint16_t key_info,
                    uint16_t key_len,
                    const uint8_t replay_counter[WPA_REPLAY_CTR_LEN],
                    const uint8_t nonce[WPA_NONCE_LEN],
                    const uint8_t *key_data, uint16_t key_data_len,
                    size_t *out_total_len)
{
    size_t total;
    uint8_t *body;
    uint16_t body_len;

    if (out == NULL || replay_counter == NULL || nonce == NULL
        || out_total_len == NULL) {
        return -1;
    }
    if (key_data == NULL && key_data_len != 0) {
        return -1;
    }
    /* Guard the 802.1X body-length field (uint16_t) against overflow. */
    if ((size_t)KEYBODY_FIXED_LEN + key_data_len > 0xFFFFU) {
        return -1;
    }
    total = EAPOL_KEY_FIXED_LEN + (size_t)key_data_len;
    if (total > out_cap) {
        return -1;
    }

    memset(out, 0, total);

    /* 802.1X header. */
    body_len = (uint16_t)(KEYBODY_FIXED_LEN + key_data_len);
    out[0] = EAPOL_PROTO_VER;
    out[1] = EAPOL_TYPE_KEY;
    eapol_wr16(&out[2], body_len);

    body = out + EAPOL_HEADER_LEN;
    body[KEYBODY_OFF_DESC_TYPE] = EAPOL_KEY_DESC_RSN;
    eapol_wr16(&body[KEYBODY_OFF_KEY_INFO], key_info);
    eapol_wr16(&body[KEYBODY_OFF_KEY_LEN],  key_len);
    memcpy(&body[KEYBODY_OFF_REPLAY], replay_counter, WPA_REPLAY_CTR_LEN);
    memcpy(&body[KEYBODY_OFF_NONCE],  nonce,          WPA_NONCE_LEN);
    /* IV, RSC, Reserved, MIC, KeyData already zero from memset. */
    eapol_wr16(&body[KEYBODY_OFF_KEY_DATA_LEN], key_data_len);
    if (key_data_len > 0) {
        memcpy(&body[KEYBODY_OFF_KEY_DATA], key_data, key_data_len);
    }

    *out_total_len = total;
    return 0;
}

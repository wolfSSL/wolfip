/* eap.c
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

#include "eap.h"
#include "eapol.h"

#include <string.h>

int eap_parse(const uint8_t *body, size_t body_len, struct eap_view *out)
{
    uint16_t total;

    if (body == NULL || out == NULL) {
        return -1;
    }
    if (body_len < EAP_HEADER_LEN) {
        return -1;
    }
    out->code   = body[0];
    out->id     = body[1];
    total       = (uint16_t)(((uint16_t)body[2] << 8) | body[3]);
    if (total < EAP_HEADER_LEN || (size_t)total > body_len) {
        return -1;
    }
    out->length = total;

    if (out->code == EAP_CODE_REQUEST || out->code == EAP_CODE_RESPONSE) {
        if (total < EAP_HEADER_LEN + 1U) {
            return -1;
        }
        out->type          = body[4];
        out->type_data     = (total > EAP_HEADER_LEN + 1U) ? &body[5] : NULL;
        out->type_data_len = (uint16_t)(total - (EAP_HEADER_LEN + 1U));
    }
    else {
        /* Success / Failure / unknown carry no type. */
        out->type          = 0U;
        out->type_data     = NULL;
        out->type_data_len = 0U;
    }
    return 0;
}

int eapol_eap_build(uint8_t *out, size_t out_cap,
                    uint8_t eapol_type,
                    const uint8_t *payload, size_t payload_len,
                    size_t *out_total_len)
{
    size_t total;

    if (out == NULL || out_total_len == NULL) {
        return -1;
    }
    if (payload == NULL && payload_len != 0U) {
        return -1;
    }
    /* The 802.1X body-length field is 16-bit; reject payloads that would
     * wrap it (matches eap_build_identity_response). */
    if (payload_len > 0xFFFFU) {
        return -1;
    }
    total = EAPOL_HEADER_LEN + payload_len;
    if (total > out_cap) {
        return -1;
    }
    /* 802.1X header. */
    out[0] = EAPOL_PROTO_VER;
    out[1] = eapol_type;
    out[2] = (uint8_t)((payload_len >> 8) & 0xFFU);
    out[3] = (uint8_t)(payload_len & 0xFFU);
    if (payload_len > 0U) {
        memcpy(out + EAPOL_HEADER_LEN, payload, payload_len);
    }
    *out_total_len = total;
    return 0;
}

int eap_build_identity_response(uint8_t *out, size_t out_cap,
                                uint8_t  id,
                                const uint8_t *identity, size_t identity_len,
                                size_t *out_total_len)
{
    size_t total;

    if (out == NULL || out_total_len == NULL) {
        return -1;
    }
    if (identity == NULL && identity_len != 0U) {
        return -1;
    }
    total = EAP_HEADER_LEN + 1U + identity_len;
    if (total > out_cap || total > 0xFFFFU) {
        return -1;
    }
    out[0] = EAP_CODE_RESPONSE;
    out[1] = id;
    out[2] = (uint8_t)((total >> 8) & 0xFFU);
    out[3] = (uint8_t)(total & 0xFFU);
    out[4] = EAP_TYPE_IDENTITY;
    if (identity_len > 0U) {
        memcpy(&out[5], identity, identity_len);
    }
    *out_total_len = total;
    return 0;
}

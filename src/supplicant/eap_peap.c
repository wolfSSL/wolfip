/* eap_peap.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Inner EAP-MSCHAPv2 framing for PEAPv0. See eap_peap.h. The TLS outer
 * framing reuses eap_tls.c; this module only handles the contents of
 * the TLS tunnel (inner EAP-Request/Response packets).
 */

#include "eap_peap.h"
#include "eap.h"

#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2

#include <string.h>

int eap_peap_parse_mschapv2_challenge(const uint8_t *eap, size_t eap_len,
                                      struct mschapv2_challenge_view *out)
{
    /* PEAPv0 inner MSCHAPv2 framing is COMPRESSED: there is no outer
     * EAP code/id/length, just the EAP type byte followed by the
     * MSCHAPv2 body. Layout:
     *   type(1)=26  opcode(1)=Challenge  ms_id(1)  ms_length(2)
     *   value_size(1)=16  auth_challenge[16]  server_name[...]
     * Minimum length = 6 + 16 = 22 bytes.
     */
    if (eap == NULL || out == NULL) return -1;
    if (eap_len < 22) return -1;
    if (eap[0] != 26) return -1;                    /* EAP type MSCHAPv2 */
    if (eap[1] != MSCHAPV2_OP_CHALLENGE) return -1; /* opcode */

    out->ms_id     = eap[2];
    out->ms_length = (uint16_t)(((uint16_t)eap[3] << 8) | eap[4]);
    if (eap[5] != 16) return -1;                    /* value size */
    memcpy(out->auth_challenge, &eap[6], 16);
    if (eap_len > 22U) {
        out->server_name     = &eap[22];
        out->server_name_len = eap_len - 22U;
    }
    else {
        out->server_name     = NULL;
        out->server_name_len = 0;
    }
    return 0;
}

int eap_peap_build_mschapv2_response(uint8_t *out, size_t out_cap,
                                     uint8_t  eap_id,
                                     uint8_t  ms_id,
                                     const uint8_t peer_challenge[16],
                                     const uint8_t nt_response[24],
                                     const char *username,
                                     size_t      username_len,
                                     size_t *out_len)
{
    /* PEAPv0 compressed inner Response (peap_version=0 makes hostapd
     * synthesize the inner EAP header from our outer Response):
     *   type=26  opcode=Response(2)  ms_id  ms_length(BE)  value_size=49
     *   peer_challenge[16]  reserved[8]=0  nt_response[24]  flags=0
     *   username[]
     */
    size_t   total;
    uint16_t ms_length;
    (void)eap_id;

    if (out == NULL || peer_challenge == NULL || nt_response == NULL
        || (username == NULL && username_len != 0) || out_len == NULL) {
        return -1;
    }
    /* Bytes: type(1) opcode(1) ms_id(1) ms_length(2) value_size(1)
     *        peer_challenge(16) reserved(8) nt_response(24) flags(1)
     *        username(N). Sum = 55 + N. ms_length covers opcode through
     *        username inclusive = 54 + N. */
    total = 55U + username_len;
    if (total > out_cap || total > 0xFFFFU) {
        return -1;
    }
    ms_length = (uint16_t)(54U + username_len);

    out[0]  = 26;                               /* type = MSCHAPv2     */
    out[1]  = MSCHAPV2_OP_RESPONSE;
    out[2]  = ms_id;
    out[3]  = (uint8_t)((ms_length >> 8) & 0xFFU);
    out[4]  = (uint8_t)(ms_length & 0xFFU);
    out[5]  = 49;
    memcpy(&out[6],  peer_challenge, 16);
    memset(&out[22], 0, 8);
    memcpy(&out[30], nt_response, 24);
    out[54] = 0;
    if (username_len > 0) {
        memcpy(&out[55], username, username_len);
    }
    *out_len = total;
    return 0;
}

int eap_peap_build_mschapv2_ack(uint8_t *out, size_t out_cap,
                                uint8_t  eap_id,
                                size_t  *out_len)
{
    /* Compressed: just type=26 opcode=Success. */
    (void)eap_id;
    if (out == NULL || out_len == NULL || out_cap < 2) return -1;
    out[0] = 26;
    out[1] = MSCHAPV2_OP_SUCCESS;
    *out_len = 2;
    return 0;
}

int eap_peap_extract_authresp(const uint8_t *eap, size_t eap_len,
                              char out_buf[42])
{
    /* PEAPv0 compressed Success request:
     *   type(1)=26  opcode(1)=3  ms_id(1)  ms_length(2)  message[...]
     * message is ASCII, typically "S=<40 hex chars> M=<text>".
     */
    size_t   off;
    size_t   i;

    if (eap == NULL || out_buf == NULL) return -1;
    if (eap_len < 6) return -1;
    if (eap[0] != 26 || eap[1] != MSCHAPV2_OP_SUCCESS) return -1;
    off = 5U;
    if (eap_len <= off) return -1;
    for (i = off; i + 42U <= eap_len; i++) {
        if (eap[i] == 'S' && eap[i + 1U] == '=') {
            memcpy(out_buf, &eap[i], 42);
            return 0;
        }
    }
    return -1;
}

#endif /* WOLFIP_ENABLE_PEAP_MSCHAPV2 */

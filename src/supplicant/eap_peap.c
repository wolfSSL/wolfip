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
#include "mschapv2.h"   /* MSCHAPV2_*_LEN field sizes */

#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2

#include <string.h>

/* PEAPv0 inner MSCHAPv2 is "compressed": the outer EAP code/id/length
 * header is omitted, so a frame is the EAP type byte followed directly by
 * the MSCHAPv2 body (RFC 2759 + the draft-kamath EAP binding). */
#define PEAP_MS_HDR_LEN      5U    /* type, opcode, ms_id, ms_length(2)     */
#define PEAP_MS_RESERVED_LEN 8U
#define PEAP_MS_VALUE_SIZE   49U   /* Response Value-Size: peer_ch+resv+nt+flags */
#define PEAP_MS_OFF_VALUE    (PEAP_MS_HDR_LEN + 1U)  /* after the Value-Size byte */
#define PEAP_MS_OFF_RESERVED (PEAP_MS_OFF_VALUE + MSCHAPV2_PEER_CHALLENGE_LEN)
#define PEAP_MS_OFF_NT_RESP  (PEAP_MS_OFF_RESERVED + PEAP_MS_RESERVED_LEN)
#define PEAP_MS_OFF_FLAGS    (PEAP_MS_OFF_NT_RESP + MSCHAPV2_NT_RESPONSE_LEN)
#define PEAP_MS_OFF_USERNAME (PEAP_MS_OFF_FLAGS + 1U)
#define PEAP_MS_CHALLENGE_MIN_LEN (PEAP_MS_OFF_VALUE + MSCHAPV2_AUTH_CHALLENGE_LEN)

/* Parse a compressed inner MSCHAPv2 Challenge into out. Returns 0 on
 * success, -1 on malformed/short input. */
int eap_peap_parse_mschapv2_challenge(const uint8_t *eap, size_t eap_len,
                                      struct mschapv2_challenge_view *out)
{
    if (eap == NULL || out == NULL) return -1;
    if (eap_len < PEAP_MS_CHALLENGE_MIN_LEN) return -1;
    if (eap[0] != EAP_TYPE_MSCHAPV2) return -1;
    if (eap[1] != MSCHAPV2_OP_CHALLENGE) return -1;

    out->ms_id     = eap[2];
    out->ms_length = (uint16_t)(((uint16_t)eap[3] << 8) | eap[4]);
    /* Reject an over-long declared length: it covers OpCode..Name = eap_len-1
     * (eap_len >= min, so no underflow), guarding against a malformed peer. */
    if ((size_t)out->ms_length > eap_len - 1U) return -1;
    if (eap[PEAP_MS_HDR_LEN] != MSCHAPV2_AUTH_CHALLENGE_LEN) return -1; /* Value-Size */
    memcpy(out->auth_challenge, &eap[PEAP_MS_OFF_VALUE], MSCHAPV2_AUTH_CHALLENGE_LEN);
    if (eap_len > PEAP_MS_CHALLENGE_MIN_LEN) {
        out->server_name     = &eap[PEAP_MS_CHALLENGE_MIN_LEN];
        out->server_name_len = eap_len - PEAP_MS_CHALLENGE_MIN_LEN;
    }
    else {
        out->server_name     = NULL;
        out->server_name_len = 0;
    }
    return 0;
}

/* Build a compressed inner MSCHAPv2 Response (peap_version=0 lets hostapd
 * synthesize the inner EAP header). *out_len receives the bytes written.
 * Returns 0 on success, -1 on bad args or insufficient out_cap. */
int eap_peap_build_mschapv2_response(uint8_t *out, size_t out_cap,
                                     uint8_t  eap_id,
                                     uint8_t  ms_id,
                                     const uint8_t peer_challenge[16],
                                     const uint8_t nt_response[24],
                                     const char *username,
                                     size_t      username_len,
                                     size_t *out_len)
{
    size_t   total;
    uint16_t ms_length;
    (void)eap_id;

    if (out == NULL || peer_challenge == NULL || nt_response == NULL
        || (username == NULL && username_len != 0) || out_len == NULL) {
        return -1;
    }
    total = PEAP_MS_OFF_USERNAME + username_len;
    if (total > out_cap || total > 0xFFFFU) {
        return -1;
    }
    ms_length = (uint16_t)(total - 1U);  /* covers OpCode..username */

    out[0] = EAP_TYPE_MSCHAPV2;
    out[1] = MSCHAPV2_OP_RESPONSE;
    out[2] = ms_id;
    out[3] = (uint8_t)((ms_length >> 8) & 0xFFU);
    out[4] = (uint8_t)(ms_length & 0xFFU);
    out[PEAP_MS_HDR_LEN] = PEAP_MS_VALUE_SIZE;
    memcpy(&out[PEAP_MS_OFF_VALUE], peer_challenge, MSCHAPV2_PEER_CHALLENGE_LEN);
    memset(&out[PEAP_MS_OFF_RESERVED], 0, PEAP_MS_RESERVED_LEN);
    memcpy(&out[PEAP_MS_OFF_NT_RESP], nt_response, MSCHAPV2_NT_RESPONSE_LEN);
    out[PEAP_MS_OFF_FLAGS] = 0;
    if (username_len > 0) {
        memcpy(&out[PEAP_MS_OFF_USERNAME], username, username_len);
    }
    *out_len = total;
    return 0;
}

/* Build the 2-byte compressed inner MSCHAPv2 Success ack (type, Success). */
int eap_peap_build_mschapv2_ack(uint8_t *out, size_t out_cap,
                                uint8_t  eap_id,
                                size_t  *out_len)
{
    (void)eap_id;
    if (out == NULL || out_len == NULL || out_cap < 2) return -1;
    out[0] = EAP_TYPE_MSCHAPV2;
    out[1] = MSCHAPV2_OP_SUCCESS;
    *out_len = 2;
    return 0;
}

/* Extract the 42-byte "S=<40 hex>" authenticator response from a Success
 * Request's ASCII Message field. Returns 0 on success, -1 if not found. */
int eap_peap_extract_authresp(const uint8_t *eap, size_t eap_len,
                              char out_buf[42])
{
    size_t   i;

    if (eap == NULL || out_buf == NULL) return -1;
    if (eap_len < PEAP_MS_HDR_LEN + 1U) return -1;
    if (eap[0] != EAP_TYPE_MSCHAPV2 || eap[1] != MSCHAPV2_OP_SUCCESS) return -1;
    for (i = PEAP_MS_HDR_LEN; i + MSCHAPV2_AUTH_RESPONSE_LEN <= eap_len; i++) {
        if (eap[i] == 'S' && eap[i + 1U] == '=') {
            memcpy(out_buf, &eap[i], MSCHAPV2_AUTH_RESPONSE_LEN);
            return 0;
        }
    }
    return -1;
}

#endif /* WOLFIP_ENABLE_PEAP_MSCHAPV2 */

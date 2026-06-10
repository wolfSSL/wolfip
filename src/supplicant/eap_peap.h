/* eap_peap.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * EAP-PEAPv0 with MSCHAPv2 inner method for WPA2-Enterprise. Gated on
 * WOLFIP_ENABLE_PEAP_MSCHAPV2.
 *
 * The PEAP *outer* framing is identical to EAP-TLS - same Flags byte,
 * same fragmentation - the supplicant just uses EAP type 25 instead of
 * 13 when emitting Response frames. After the TLS handshake completes,
 * inner EAP packets ride as TLS application data:
 *
 *   server  -> EAP-Req/Identity     (inner, plaintext after wolfSSL_read)
 *   client  <- EAP-Resp/Identity    (we encrypt via wolfSSL_write)
 *   server  -> EAP-Req/MSCHAPv2 Challenge
 *   client  <- EAP-Resp/MSCHAPv2 Response
 *   server  -> EAP-Req/MSCHAPv2 Success (with "S=<authresp>")
 *   client  <- EAP-Resp/MSCHAPv2 Success (ack)
 *   server  -> EAP-Success          (outer, unencrypted)
 */

#ifndef WOLFIP_SUPPLICANT_EAP_PEAP_H
#define WOLFIP_SUPPLICANT_EAP_PEAP_H

#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2

#include <stdint.h>
#include <stddef.h>

/* MSCHAPv2 EAP OpCodes per draft-kamath-pppext-eap-mschapv2. */
#define MSCHAPV2_OP_CHALLENGE 0x01
#define MSCHAPV2_OP_RESPONSE  0x02
#define MSCHAPV2_OP_SUCCESS   0x03
#define MSCHAPV2_OP_FAILURE   0x04

struct mschapv2_challenge_view {
    uint8_t        ms_id;
    uint16_t       ms_length;
    uint8_t        auth_challenge[16];
    const uint8_t *server_name;
    size_t         server_name_len;
};

#ifdef __cplusplus
extern "C" {
#endif

/* Parse the type_data of an inner EAP-Request/MSCHAPv2 Challenge frame
 * (i.e. plain[5..] after EAP code/id/length/type=26). plain is the full
 * EAP packet starting at the Code byte; type=26 must already be checked
 * by the caller.
 *
 * Returns 0 on success.
 */
int eap_peap_parse_mschapv2_challenge(const uint8_t *eap, size_t eap_len,
                                      struct mschapv2_challenge_view *out);

/* Build an inner EAP-Response/MSCHAPv2 Response.
 *   out[Code=Resp, id=eap_id, length, type=26, opcode=Response,
 *       ms_id, ms_length, value_size=49, peer_ch[16], reserved[8]=0,
 *       nt_response[24], flags=0, username[]]
 *
 * out_len receives the total bytes written.
 */
int eap_peap_build_mschapv2_response(uint8_t *out, size_t out_cap,
                                     uint8_t  eap_id,
                                     uint8_t  ms_id,
                                     const uint8_t peer_challenge[16],
                                     const uint8_t nt_response[24],
                                     const char *username,
                                     size_t      username_len,
                                     size_t *out_len);

/* Build the trivial inner EAP-Response/MSCHAPv2 Success ack: 6 bytes,
 *   [Code=Resp, id, length=6 BE, type=26, opcode=Success]
 * sent in reply to the server's "S=..." Success Request.
 */
int eap_peap_build_mschapv2_ack(uint8_t *out, size_t out_cap,
                                uint8_t  eap_id,
                                size_t  *out_len);

/* Pull the "S=<40 hex>" string out of an inner MSCHAPv2 Success
 * Request's Message field. out_buf must hold at least 42 bytes.
 * Returns 0 on success, -1 if no "S=" segment is found.
 */
int eap_peap_extract_authresp(const uint8_t *eap, size_t eap_len,
                              char out_buf[42]);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_ENABLE_PEAP_MSCHAPV2 */

#endif /* WOLFIP_SUPPLICANT_EAP_PEAP_H */

/* eap.h
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

/* EAP packet framing per RFC 3748. WPA2-Enterprise carries EAP packets
 * inside EAPOL frames with EAPOL Packet Type = 0 (EAP-Packet). The 4-
 * byte 802.1X header (version, type, length) is the same as for
 * EAPOL-Key; the body that follows is an EAP packet.
 *
 * EAP header (RFC 3748 Sec. 4):
 *   Code  : 1 byte  (1=Request, 2=Response, 3=Success, 4=Failure)
 *   Id    : 1 byte  (matches Request <-> Response pairs)
 *   Length: 2 bytes big-endian (covers code+id+length+type+type-data)
 *   Type  : 1 byte  (only present for Request/Response: 1=Identity,
 *                   13=EAP-TLS, 25=PEAP, 26=MSCHAPv2, ...)
 *
 * Success / Failure carry no Type or data.
 */

#ifndef WOLFIP_SUPPLICANT_EAP_H
#define WOLFIP_SUPPLICANT_EAP_H

#include <stdint.h>
#include <stddef.h>

#define EAPOL_TYPE_EAP_PACKET       0x00U
#define EAPOL_TYPE_EAPOL_START      0x01U
#define EAPOL_TYPE_EAPOL_LOGOFF     0x02U
#define EAPOL_TYPE_KEY_DESCRIPTOR   0x03U   /* same as EAPOL-Key */

#define EAP_CODE_REQUEST            0x01U
#define EAP_CODE_RESPONSE           0x02U
#define EAP_CODE_SUCCESS            0x03U
#define EAP_CODE_FAILURE            0x04U

#define EAP_TYPE_IDENTITY           0x01U
#define EAP_TYPE_NAK                0x03U
#define EAP_TYPE_TLS                0x0DU   /* RFC 5216 / RFC 9190 */
#define EAP_TYPE_PEAP               0x19U
#define EAP_TYPE_MSCHAPV2           0x1AU

#define EAP_HEADER_LEN              4U      /* code + id + length */

/* Decoded view of an EAP packet inside the 802.1X body. Pointers refer
 * back into the caller's frame buffer.
 */
struct eap_view {
    uint8_t        code;       /* EAP_CODE_*                 */
    uint8_t        id;
    uint16_t       length;     /* host order, full EAP length */
    uint8_t        type;       /* 0 if Success/Failure        */
    const uint8_t *type_data;  /* type-specific payload      */
    uint16_t       type_data_len;
};

#ifdef __cplusplus
extern "C" {
#endif

/* Parse an EAP packet. body / body_len point at the byte immediately
 * after the 802.1X header (i.e. EAPOL packet-type byte must already be
 * 0x00 EAP_PACKET; body itself starts at the EAP Code byte).
 *
 * Returns 0 on success, -1 on malformed input.
 */
int eap_parse(const uint8_t *body, size_t body_len, struct eap_view *out);

/* Build the 802.1X header + EAPOL-type byte + EAP payload into out.
 * - eapol_type is one of EAPOL_TYPE_*. For EAP carriage, pass
 *   EAPOL_TYPE_EAP_PACKET; payload then contains the full EAP packet
 *   (code, id, length, type, type-data).
 * - For EAPOL-Start, eapol_type = EAPOL_TYPE_EAPOL_START, payload NULL,
 *   payload_len 0.
 *
 * out_cap must be >= 4 + payload_len.
 * Returns 0 on success and writes total bytes into *out_total_len.
 */
int eapol_eap_build(uint8_t *out, size_t out_cap,
                    uint8_t eapol_type,
                    const uint8_t *payload, size_t payload_len,
                    size_t *out_total_len);

/* Build a complete EAP-Response/Identity payload (Code=2 Resp,
 * Type=Identity, identity bytes). Returns 0 on success and writes
 * total EAP packet length (code+id+length+type+identity) to
 * *out_total_len.
 */
int eap_build_identity_response(uint8_t *out, size_t out_cap,
                                uint8_t  id,
                                const uint8_t *identity, size_t identity_len,
                                size_t *out_total_len);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_SUPPLICANT_EAP_H */

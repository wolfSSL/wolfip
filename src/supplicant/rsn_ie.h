/* rsn_ie.h
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

/* Robust Security Network Information Element per IEEE 802.11-2020
 * clause 9.4.2.24. Used by the supplicant in two places:
 *
 *   1. Sent in the EAPOL-Key M2 Key Data so the authenticator can
 *      confirm we negotiated the same cipher/AKM as in our (Re)Assoc
 *      Request.
 *
 *   2. The AP's RSN IE is echoed in M3 Key Data. We compare it byte-for-
 *      byte to the IE we saw in Beacon/Probe Response (passed in via
 *      cfg). A mismatch indicates a downgrade attack and aborts the
 *      handshake (IEEE 802.11-2020 12.7.6.4).
 *
 * Note: RSN IE multi-byte fields are LITTLE-ENDIAN (802.11 IE convention),
 * unlike EAPOL-Key fields which are big-endian. Beware mixing them.
 */

#ifndef WOLFIP_SUPPLICANT_RSN_IE_H
#define WOLFIP_SUPPLICANT_RSN_IE_H

#include <stdint.h>
#include <stddef.h>

#define RSN_IE_ELEMENT_ID       0x30U

/* Cipher / AKM suite identifiers. OUI 00-0F-AC is the IEEE 802.11
 * "internal" OUI used for all standard suites. */
#define RSN_SUITE_OUI_0         0x00U
#define RSN_SUITE_OUI_1         0x0FU
#define RSN_SUITE_OUI_2         0xACU

#define RSN_CIPHER_NONE         0x00U   /* "use group cipher"    */
#define RSN_CIPHER_TKIP         0x02U
#define RSN_CIPHER_CCMP_128     0x04U   /* AES-CCMP, WPA2 default */
#define RSN_CIPHER_GCMP_128     0x08U
#define RSN_CIPHER_GCMP_256     0x09U
#define RSN_CIPHER_CCMP_256     0x0AU

#define RSN_AKM_8021X           0x01U
#define RSN_AKM_PSK             0x02U
#define RSN_AKM_8021X_SHA256    0x05U
#define RSN_AKM_PSK_SHA256      0x06U
#define RSN_AKM_SAE             0x08U   /* WPA3 */

/* Minimum bytes for a well-formed RSN IE with one pairwise + one AKM
 * suite and no capabilities/PMKID. Element ID + Length + 20 body. */
#define RSN_IE_MIN_LEN          22U
#define RSN_IE_MAX_LEN          255U    /* IE length byte cap */

/* Parsed view of an RSN IE; pointers reference caller buffer. */
struct rsn_ie_view {
    uint16_t       version;        /* host order, must be 1                */
    uint8_t        group_cipher;   /* suite type only (OUI assumed 00:0F:AC) */
    uint16_t       pairwise_count;
    const uint8_t *pairwise_list;  /* 4 bytes per entry                    */
    uint16_t       akm_count;
    const uint8_t *akm_list;       /* 4 bytes per entry                    */
    uint16_t       rsn_caps;       /* host order; 0 if absent              */
    int            have_rsn_caps;
};

#ifdef __cplusplus
extern "C" {
#endif

/* Parse a RSN IE in place. ie points at the Element ID byte; ie_len is
 * the total bytes available including the 2-byte IE header.
 *
 * Performs bounds checking + version check. Returns 0 on success, -1
 * on malformed input.
 */
int rsn_ie_parse(const uint8_t *ie, size_t ie_len,
                 struct rsn_ie_view *out);

/* Build a minimal RSN IE for WPA2-Personal (CCMP-128 group + pairwise,
 * PSK AKM, RSN caps = 0). Writes element header (ID + Length) followed
 * by body. Total bytes = 22. Returns 0 on success, -1 on insufficient
 * buffer.
 */
int rsn_ie_build_wpa2_psk(uint8_t *out, size_t out_cap, size_t *out_len);

/* Constant-length-aware byte comparison of two RSN IEs. Returns 0 if
 * identical (including length), non-zero otherwise. Used for the M3
 * downgrade check.
 */
int rsn_ie_equal(const uint8_t *a, size_t a_len,
                 const uint8_t *b, size_t b_len);

/* Return 1 if the suite (OUI || suite_type) lives in suite_list. */
int rsn_suite_in_list(const uint8_t *suite_list, uint16_t count,
                      uint8_t suite_type);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_SUPPLICANT_RSN_IE_H */

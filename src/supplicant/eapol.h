/* eapol.h
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
 */

/* EAPOL / EAPOL-Key frame layout per IEEE 802.1X-2010 clause 11.3 and
 * IEEE 802.11i-2004 (now in IEEE 802.11-2020 clause 12.7). WPA2-Personal
 * 4-way and Group-Key handshakes only.
 *
 * All multi-byte fields are big-endian (network order). To avoid struct
 * padding/aliasing surprises across architectures, framing is done with
 * explicit byte arrays and accessor helpers.
 */

#ifndef WOLFIP_SUPPLICANT_EAPOL_H
#define WOLFIP_SUPPLICANT_EAPOL_H

#include <stdint.h>
#include <stddef.h>

#include "wpa_crypto.h"

/* Ethernet type for 802.1X PAE. */
#define EAPOL_ETHERTYPE         0x888EU

/* 802.1X header. */
#define EAPOL_PROTO_VER         0x02U
#define EAPOL_TYPE_KEY          0x03U
#define EAPOL_HEADER_LEN        4U   /* version + type + body length */

/* EAPOL-Key Descriptor Type for WPA2/RSN. */
#define EAPOL_KEY_DESC_RSN      0x02U

/* Key Information bit positions (per IEEE 802.11i Figure 11). The 16-bit
 * field is read as a big-endian word on the wire.
 */
#define KEY_INFO_VER_MASK       0x0007U   /* bits 0..2 */
#define KEY_INFO_VER_AKM_DEFINED 0x0000U  /* AES-128-CMAC MIC (SAE/SHA256 AKM) */
#define KEY_INFO_VER_AES_HMAC   0x0002U   /* HMAC-SHA1-128 + AES Key Wrap */
#define KEY_INFO_KEY_TYPE       0x0008U   /* 1 = Pairwise, 0 = Group     */
#define KEY_INFO_INSTALL        0x0040U
#define KEY_INFO_KEY_ACK        0x0080U
#define KEY_INFO_KEY_MIC        0x0100U
#define KEY_INFO_SECURE         0x0200U
#define KEY_INFO_ERROR          0x0400U
#define KEY_INFO_REQUEST        0x0800U
#define KEY_INFO_ENCR_KEY_DATA  0x1000U

/* Fixed offsets within the EAPOL-Key body (i.e. starting after the
 * 4-byte 802.1X header). The full fixed portion is 95 bytes; Key Data
 * follows the Key Data Length field.
 */
#define KEYBODY_OFF_DESC_TYPE   0U   /*  1 byte                          */
#define KEYBODY_OFF_KEY_INFO    1U   /*  2 bytes                         */
#define KEYBODY_OFF_KEY_LEN     3U   /*  2 bytes                         */
#define KEYBODY_OFF_REPLAY      5U   /*  8 bytes                         */
#define KEYBODY_OFF_NONCE       13U  /* 32 bytes                         */
#define KEYBODY_OFF_IV          45U  /* 16 bytes                         */
#define KEYBODY_OFF_RSC         61U  /*  8 bytes                         */
#define KEYBODY_OFF_RESERVED    69U  /*  8 bytes                         */
#define KEYBODY_OFF_MIC         77U  /* 16 bytes                         */
#define KEYBODY_OFF_KEY_DATA_LEN 93U /*  2 bytes                         */
#define KEYBODY_OFF_KEY_DATA    95U  /* variable                         */
#define KEYBODY_FIXED_LEN       95U
#define EAPOL_KEY_FIXED_LEN     (EAPOL_HEADER_LEN + KEYBODY_FIXED_LEN)

/* KDE types used inside encrypted Key Data on M3 (IEEE 802.11i Table 8).
 * KDE OUI = 00-0F-AC (Wi-Fi Alliance OUI inherited from 802.11i).
 */
#define KDE_TYPE                0xDDU   /* 802.11 vendor-specific element */
#define KDE_OUI_0               0x00U
#define KDE_OUI_1               0x0FU
#define KDE_OUI_2               0xACU
#define KDE_DATATYPE_GTK        0x01U

/* Decoded view of an EAPOL-Key frame (zero-copy: pointers reference
 * the caller's buffer). Use eapol_key_parse() to populate.
 */
struct eapol_key_view {
    const uint8_t *frame;          /* start of 802.1X header     */
    size_t         frame_len;      /* total bytes incl. header   */
    uint16_t       body_len;       /* from 802.1X header         */
    uint16_t       key_info;       /* host order                 */
    uint16_t       key_len;        /* host order                 */
    const uint8_t *replay_counter; /* 8 bytes                    */
    const uint8_t *nonce;          /* 32 bytes                   */
    const uint8_t *mic;            /* 16 bytes                   */
    uint16_t       key_data_len;   /* host order                 */
    const uint8_t *key_data;       /* key_data_len bytes         */
};

/* Convenience accessors. */
static inline uint16_t eapol_rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}
static inline void eapol_wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFU);
}

/* Parse an EAPOL-Key frame in-place. Performs bounds checks. Returns
 * 0 on success, -1 on malformed input. */
int eapol_key_parse(const uint8_t *frame, size_t frame_len,
                    struct eapol_key_view *out);

/* Build the fixed portion (95-byte body + 4-byte header). The caller
 * supplies the buffer (must be at least EAPOL_KEY_FIXED_LEN + key_data_len).
 * MIC field is left zeroed; caller computes MIC over the resulting buffer
 * (with the MIC field still zero) and writes it back into the MIC offset.
 *
 * key_data may be NULL when key_data_len == 0 (M1, M4).
 */
int eapol_key_build(uint8_t *out, size_t out_cap,
                    uint16_t key_info,
                    uint16_t key_len,
                    const uint8_t replay_counter[WPA_REPLAY_CTR_LEN],
                    const uint8_t nonce[WPA_NONCE_LEN],
                    const uint8_t *key_data, uint16_t key_data_len,
                    size_t *out_total_len);

#endif /* WOLFIP_SUPPLICANT_EAPOL_H */

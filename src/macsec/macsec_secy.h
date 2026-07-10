/* macsec_secy.h
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
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Clean-room 802.1AE SecY frame transform. These are stateless functions:
 * macsec_protect() turns a user MSDU (its Ethernet payload, starting at the
 * original EtherType) into a MACsec frame (DA || SA || SecTAG || Secure Data
 * || ICV), and macsec_validate() reverses it. Cipher Suites GCM-AES-128 and
 * GCM-AES-256 with 32-bit packet numbers (XPN out of scope). Confidentiality
 * (encrypt) with offset 0/30/50, and integrity-only, are supported.
 *
 * Secure Association state (PN counters, replay window, key install) is owned
 * by the caller / higher layer; this module only does the per-frame crypto so
 * it can be exercised with known-answer vectors.
 */

#ifndef WOLFIP_MACSEC_SECY_H
#define WOLFIP_MACSEC_SECY_H

#include <stdint.h>
#include <stddef.h>

#include "macsec_crypto.h"       /* key/SCI/ICV sizes */

#ifdef __cplusplus
extern "C" {
#endif

#define MACSEC_ETHERTYPE          0x88E5U
#define MACSEC_SECTAG_MIN_LEN     8U    /* EtherType(2)+TCI/AN(1)+SL(1)+PN(4) */
#define MACSEC_SECTAG_MAX_LEN     16U   /* + SCI(8) when the SC bit is set    */
#define MACSEC_MIN_SECURE_DATA    48U   /* below this, SL carries the length  */

/* SecTAG TCI bit masks (the high 6 bits of the TCI/AN octet). */
#define MACSEC_TCI_V              0x80U /* Version (always 0)                 */
#define MACSEC_TCI_ES             0x40U /* End Station                        */
#define MACSEC_TCI_SC             0x20U /* SCI present in the SecTAG          */
#define MACSEC_TCI_SCB            0x10U /* EPON Single Copy Broadcast         */
#define MACSEC_TCI_E              0x08U /* Encryption (confidentiality)       */
#define MACSEC_TCI_C              0x04U /* Changed Text                       */
#define MACSEC_AN_MASK            0x03U /* Association Number (low 2 bits)    */

/* GCM nonce = SCI(8) || PN(4). */
#define MACSEC_GCM_NONCE_LEN      12U

/* Decoded SecTAG (zero-copy view, SCI copied out since it is small). */
struct macsec_sectag {
    uint32_t pn;                        /* packet number                     */
    size_t   len;                       /* 8 or 16 (incl. MACsec EtherType)  */
    uint8_t  tci_an;                    /* raw TCI/AN octet                  */
    uint8_t  sl;                        /* short length (0 if >= 48)         */
    uint8_t  sci_present;               /* 1 if SC bit set                   */
    uint8_t  sci[MACSEC_SCI_LEN];
};

/* Per-frame protect parameters. sak_len selects GCM-AES-128 (16) or -256
 * (32). When encrypt is 0 the frame is integrity-only (TCI E=0,C=0) and
 * conf_offset is ignored; when encrypt is 1 the first conf_offset octets of
 * the user data stay in cleartext and are authenticated, the rest encrypted.
 * conf_offset must be 0, 30, or 50. include_sci sets the SC bit and copies
 * sci into the SecTAG; sci is used for the GCM nonce regardless. */
struct macsec_protect_params {
    const uint8_t *da;                  /* 6                                 */
    const uint8_t *sa;                  /* 6                                 */
    const uint8_t *sci;                 /* 8                                 */
    const uint8_t *sak;
    size_t         sak_len;
    size_t         conf_offset;
    uint32_t       pn;
    uint8_t        an;                  /* 0..3                              */
    uint8_t        encrypt;             /* 1 = confidentiality, 0 = integrity */
    uint8_t        include_sci;
    uint8_t        end_station;         /* TCI ES bit                        */
    uint8_t        scb;                 /* TCI SCB bit                       */
};

/* Per-frame validate parameters. sci is the Secure Channel's SCI used for the
 * GCM nonce when the received SecTAG omits it; when the SecTAG carries an SCI
 * that one is used instead. conf_offset must match the negotiated value. */
struct macsec_validate_params {
    const uint8_t *sak;
    const uint8_t *sci;                 /* 8, fallback nonce SCI (may be NULL)*/
    size_t         sak_len;
    size_t         conf_offset;
};

/* Build a SecTAG at out (capacity out_cap). Returns the SecTAG length written
 * (8 without SCI, 16 with SCI; the MACsec EtherType is included) or a negative
 * error. secure_data_len sets the SL field. */
int macsec_sectag_build(uint8_t *out, size_t out_cap,
                        const struct macsec_protect_params *p,
                        size_t secure_data_len);

/* Parse a SecTAG from in (starting at the MACsec EtherType). Returns 0 on
 * success, negative on malformed input. */
int macsec_sectag_parse(const uint8_t *in, size_t in_len,
                        struct macsec_sectag *out);

/* Protect a user MSDU into a MACsec frame. payload starts at the original
 * EtherType (it becomes the first octets of the Secure Data). out receives
 * DA || SA || SecTAG || Secure Data || ICV; *out_len is set on success.
 * Returns 0 on success, negative wolfCrypt/arg error otherwise. */
int macsec_protect(const struct macsec_protect_params *p,
                   const uint8_t *payload, size_t payload_len,
                   uint8_t *out, size_t out_cap, size_t *out_len);

/* Validate and recover a MACsec frame. frame is DA || SA || SecTAG ||
 * Secure Data || ICV. On success the recovered user MSDU (starting at the
 * original EtherType) is written to out_payload, *out_payload_len set, the
 * decoded SecTAG returned via *out_tag (for PN / AN / replay handling by the
 * caller). Returns 0 on success, -1 on ICV failure, negative on arg error. */
int macsec_validate(const struct macsec_validate_params *p,
                    const uint8_t *frame, size_t frame_len,
                    uint8_t *out_payload, size_t out_cap,
                    size_t *out_payload_len,
                    struct macsec_sectag *out_tag);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_MACSEC_SECY_H */

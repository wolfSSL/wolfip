/* mschapv2.h
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

/* MSCHAPv2 challenge-response and EAP-MSCHAPv2 MSK derivation per
 * RFC 2759 + RFC 3079 (with the EAP-MSCHAPv2 binding from RFC 3748 +
 * draft-kamath-pppext-eap-mschapv2). Used as the inner method of
 * EAP-PEAP for WPA2-Enterprise.
 *
 * This module pulls in two pieces of legacy cryptography: MD4 (for
 * NT password hashing) and single-DES (for the challenge-response
 * triple-DES splay). Both must be enabled in the linked wolfSSL build
 * (--enable-md4 --enable-des3). The whole module is gated by the
 * compile-time switch WOLFIP_ENABLE_PEAP_MSCHAPV2.
 *
 * The crypto here is deprecated for security reasons; this module
 * exists only to interoperate with deployed WPA2-Enterprise
 * infrastructure (Windows / Active Directory, eduroam, ...). Prefer
 * EAP-TLS for new deployments.
 */

#ifndef WOLFIP_SUPPLICANT_MSCHAPV2_H
#define WOLFIP_SUPPLICANT_MSCHAPV2_H

#include "supplicant_features.h"  /* may auto-disable PEAP if MD4/DES3/SHA-1 absent */

#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2

#include <stdint.h>
#include <stddef.h>

#define MSCHAPV2_PEER_CHALLENGE_LEN 16
#define MSCHAPV2_AUTH_CHALLENGE_LEN 16
#define MSCHAPV2_NT_RESPONSE_LEN    24
#define MSCHAPV2_NT_HASH_LEN        16
/* "S=" + 40 hex characters; no trailing NUL counted. */
#define MSCHAPV2_AUTH_RESPONSE_LEN  42
#define MSCHAPV2_MSK_LEN            64
#define MSCHAPV2_CHALLENGE_LEN       8  /* ChallengeHash output (RFC 2759 8.2)   */
#define MSCHAPV2_DES_BLOCK_LEN       8  /* single-DES block                      */
#define MSCHAPV2_KEY_LEN            16  /* MasterKey / MS-MPPE keys (RFC 3079)   */
#define MSCHAPV2_DES_KEY7_LEN        7  /* 7-byte DES sub-key                    */
#define MSCHAPV2_DES_KEY_COUNT       3  /* three sub-keys -> 24-byte NT-Response */

#ifdef __cplusplus
extern "C" {
#endif

/* NtPasswordHash(Password) = MD4(UTF-16LE(Password)).
 * password must be ASCII; this routine widens to UTF-16LE internally.
 * Returns 0 on success. */
int mschapv2_nt_password_hash(const char *password, size_t pw_len,
                              uint8_t out[MSCHAPV2_NT_HASH_LEN]);

/* Generate the 24-byte NT-Response from RFC 2759 sec. 8.1. Computes
 *   ChallengeHash  = SHA1(PeerCh || AuthCh || UserName)[0..7]
 *   NtPasswordHash = MD4(UTF-16LE(Password))
 *   NTResponse     = ChallengeResponse(ChallengeHash, NtPasswordHash)
 * where ChallengeResponse is three single-DES encryptions of the
 * 8-byte challenge using three 7-byte sub-keys split from the 21-byte
 * zero-padded NtPasswordHash.
 *
 * Returns 0 on success.
 */
int mschapv2_generate_nt_response(const uint8_t auth_challenge[16],
                                  const uint8_t peer_challenge[16],
                                  const char   *username, size_t un_len,
                                  const char   *password, size_t pw_len,
                                  uint8_t out_response[MSCHAPV2_NT_RESPONSE_LEN]);

/* Verify the authenticator-response (from RFC 2759 sec. 8.7) against
 * what the server sent. server_response is the 42-byte ASCII field
 * (e.g. "S=407A5589..."), supplied by the peer in the MSCHAPv2 Success
 * Request message; server_response_len is its length (must be >= 42, the
 * field is not NUL-terminated). A shorter buffer is rejected up front.
 *
 * Returns 0 on match, -1 on mismatch / short input.
 */
int mschapv2_verify_authenticator_response(
                              const char *password, size_t pw_len,
                              const uint8_t nt_response[MSCHAPV2_NT_RESPONSE_LEN],
                              const uint8_t peer_challenge[16],
                              const uint8_t auth_challenge[16],
                              const char *username, size_t un_len,
                              const char *server_response,
                              size_t server_response_len);

/* Derive the 64-byte EAP-MSCHAPv2 MSK per RFC 3079.
 *   MasterKey  = SHA1(PasswordHashHash || NTResponse || MagicConstant1)
 *   SendKey16  = GetAsymmetricStartKey(MasterKey, 16, server-to-client)
 *   RecvKey16  = GetAsymmetricStartKey(MasterKey, 16, client-to-server)
 *   MSK        = SendKey16 || RecvKey16 || 32 zero bytes (per RFC 3748)
 *
 * Note RFC 3748 sec.7.10 specifies how the EAP MSK is built from
 * MSCHAPv2 keys; we follow the "client" perspective: send = MS-MPPE-
 * Recv-Key, recv = MS-MPPE-Send-Key, then 32 zero bytes.
 */
int mschapv2_derive_msk(const char *password, size_t pw_len,
                        const uint8_t nt_response[MSCHAPV2_NT_RESPONSE_LEN],
                        uint8_t out_msk[MSCHAPV2_MSK_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_ENABLE_PEAP_MSCHAPV2 */

#endif /* WOLFIP_SUPPLICANT_MSCHAPV2_H */

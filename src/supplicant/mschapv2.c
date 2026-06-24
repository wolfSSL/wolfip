/* mschapv2.c
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

#include "mschapv2.h"

#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2

#include <string.h>

/* wolfSSL config (options/settings) comes via mschapv2.h -> supplicant_features.h. */
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/md4.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/des3.h>

/* RFC 2759 sec. 8.6 - Generic key-splay constants. */
static const uint8_t MAGIC1[39] = {
    0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
    0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x73,
    0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74,
    0x61, 0x6E, 0x74
};
static const uint8_t MAGIC2[41] = {
    0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B, 0x65, 0x20,
    0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x20, 0x74,
    0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E, 0x65, 0x20, 0x69, 0x74, 0x65, 0x72,
    0x61, 0x74, 0x69, 0x6F, 0x6E
};
/* RFC 3079 sec.3.3 - "This is the MPPE Master Key" */
static const uint8_t MAGIC_MASTER_KEY[27] = {
    0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
    0x4D, 0x50, 0x50, 0x45, 0x20, 0x4D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20,
    0x4B, 0x65, 0x79
};
/* RFC 3079 sec.3.4 - "On the client side, this is the send key; on the
 * server side, it is the receive key." */
static const uint8_t MAGIC_CLIENT_SEND[84] = {
    0x4F, 0x6E, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6C, 0x69, 0x65, 0x6E,
    0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2C, 0x20, 0x74, 0x68, 0x69, 0x73,
    0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6E, 0x64,
    0x20, 0x6B, 0x65, 0x79, 0x3B, 0x20, 0x6F, 0x6E, 0x20, 0x74, 0x68, 0x65,
    0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
    0x2C, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
    0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20, 0x6B, 0x65, 0x79, 0x2E
};
static const uint8_t MAGIC_CLIENT_RECV[84] = {
    0x4F, 0x6E, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6C, 0x69, 0x65, 0x6E,
    0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2C, 0x20, 0x74, 0x68, 0x69, 0x73,
    0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72, 0x65, 0x63, 0x65,
    0x69, 0x76, 0x65, 0x20, 0x6B, 0x65, 0x79, 0x3B, 0x20, 0x6F, 0x6E, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
    0x69, 0x64, 0x65, 0x2C, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74,
    0x68, 0x65, 0x20, 0x73, 0x65, 0x6E, 0x64, 0x20, 0x6B, 0x65, 0x79, 0x2E
};
/* SHS_PADS from RFC 3079 sec. 3.4 - 40-byte padding "blobs". */
static const uint8_t SHS_PAD1[40] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static const uint8_t SHS_PAD2[40] = {
    0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,
    0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,
    0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,
    0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2,0xF2
};

/* Expand a 7-byte key into the 8-byte DES key format, low bit per byte
 * reserved for parity (wc_Des_SetKey ignores it; this is the canonical
 * 56-bit-key embedding). */
static void des_key_setup_parity(const uint8_t *in7,
                                 uint8_t out8[MSCHAPV2_DES_BLOCK_LEN])
{
    out8[0] = (uint8_t)(in7[0] & 0xFE);
    out8[1] = (uint8_t)(((in7[0] << 7) | (in7[1] >> 1)) & 0xFE);
    out8[2] = (uint8_t)(((in7[1] << 6) | (in7[2] >> 2)) & 0xFE);
    out8[3] = (uint8_t)(((in7[2] << 5) | (in7[3] >> 3)) & 0xFE);
    out8[4] = (uint8_t)(((in7[3] << 4) | (in7[4] >> 4)) & 0xFE);
    out8[5] = (uint8_t)(((in7[4] << 3) | (in7[5] >> 5)) & 0xFE);
    out8[6] = (uint8_t)(((in7[5] << 2) | (in7[6] >> 6)) & 0xFE);
    out8[7] = (uint8_t)((in7[6] << 1) & 0xFE);
}

/* Encrypt one 8-byte block with single DES (CBC + zero IV == ECB once). */
static int des_encrypt_block(const uint8_t key8[MSCHAPV2_DES_BLOCK_LEN],
                             const uint8_t in[MSCHAPV2_DES_BLOCK_LEN],
                             uint8_t out[MSCHAPV2_DES_BLOCK_LEN])
{
    Des     des;
    uint8_t iv[MSCHAPV2_DES_BLOCK_LEN] = {0};
    int     ret;
    ret = wc_Des_SetKey(&des, key8, iv, DES_ENCRYPTION);
    if (ret == 0) {
        ret = wc_Des_CbcEncrypt(&des, out, in, MSCHAPV2_DES_BLOCK_LEN);
    }
    /* The expanded DES key schedule is derived from NT-hash key material;
     * scrub it off the stack on every path. */
    wc_ForceZero(&des, sizeof(des));
    return ret;
}

/* Convert an ASCII password to UTF-16LE (no BOM, no NUL). Returns
 * output length in bytes (= 2 * input length). */
static size_t password_to_utf16le(const char *ascii, size_t n,
                                  uint8_t *out, size_t out_cap)
{
    size_t i;
    if (n * 2U > out_cap) return 0;
    for (i = 0; i < n; i++) {
        out[i * 2U]      = (uint8_t)ascii[i];
        out[i * 2U + 1U] = 0x00;
    }
    return n * 2U;
}

int mschapv2_nt_password_hash(const char *password, size_t pw_len,
                              uint8_t out[MSCHAPV2_NT_HASH_LEN])
{
    uint8_t  utf16[256];
    size_t   utf16_len;
    Md4      md4;

    if (password == NULL || out == NULL) return BAD_FUNC_ARG;
    if (pw_len == 0 || pw_len > 127) return BAD_FUNC_ARG;
    utf16_len = password_to_utf16le(password, pw_len, utf16, sizeof(utf16));
    if (utf16_len == 0) return BAD_FUNC_ARG;

    /* wc_*Md4* return void in wolfSSL - no status to check. */
    wc_InitMd4(&md4);
    wc_Md4Update(&md4, utf16, (word32)utf16_len);
    wc_Md4Final(&md4, out);
    wc_ForceZero(&md4,  sizeof(md4));    /* chaining state from the password */
    wc_ForceZero(utf16, sizeof(utf16));
    return 0;
}

/* RFC 2759 sec. 8.2: ChallengeHash. */
static int challenge_hash(const uint8_t peer_ch[MSCHAPV2_PEER_CHALLENGE_LEN],
                          const uint8_t auth_ch[MSCHAPV2_AUTH_CHALLENGE_LEN],
                          const char *username, size_t un_len,
                          uint8_t out8[MSCHAPV2_CHALLENGE_LEN])
{
    wc_Sha sha;
    uint8_t digest[WC_SHA_DIGEST_SIZE];
    int    ret;
    ret = wc_InitSha(&sha);
    if (ret != 0) return ret;
    ret = wc_ShaUpdate(&sha, peer_ch,  MSCHAPV2_PEER_CHALLENGE_LEN);
    if (ret == 0) ret = wc_ShaUpdate(&sha, auth_ch,  MSCHAPV2_AUTH_CHALLENGE_LEN);
    if (ret == 0) ret = wc_ShaUpdate(&sha, (const byte *)username,
                                     (word32)un_len);
    if (ret == 0) ret = wc_ShaFinal(&sha, digest);
    if (ret != 0) {
        wc_ForceZero(&sha,   sizeof(sha));
        wc_ForceZero(digest, sizeof(digest));
        return ret;
    }
    memcpy(out8, digest, MSCHAPV2_CHALLENGE_LEN);
    wc_ForceZero(&sha,   sizeof(sha));
    wc_ForceZero(digest, sizeof(digest));
    return 0;
}

/* RFC 2759 sec. 8.5: ChallengeResponse. Zero-pad the 16-byte NtPasswordHash
 * to 21 bytes, split into three 7-byte DES sub-keys, and encrypt the same
 * 8-byte challenge under each to form the 24-byte response. */
static int challenge_response(const uint8_t challenge[MSCHAPV2_CHALLENGE_LEN],
                              const uint8_t nt_hash[MSCHAPV2_NT_HASH_LEN],
                              uint8_t response[MSCHAPV2_NT_RESPONSE_LEN])
{
    uint8_t z21[MSCHAPV2_DES_KEY_COUNT * MSCHAPV2_DES_KEY7_LEN];
    uint8_t key8[MSCHAPV2_DES_BLOCK_LEN];
    int     ret;
    size_t  i;

    memcpy(z21, nt_hash, MSCHAPV2_NT_HASH_LEN);
    memset(z21 + MSCHAPV2_NT_HASH_LEN, 0, sizeof(z21) - MSCHAPV2_NT_HASH_LEN);

    for (i = 0; i < MSCHAPV2_DES_KEY_COUNT; i++) {
        des_key_setup_parity(&z21[i * MSCHAPV2_DES_KEY7_LEN], key8);
        ret = des_encrypt_block(key8, challenge,
                                &response[i * MSCHAPV2_DES_BLOCK_LEN]);
        if (ret != 0) {
            wc_ForceZero(z21, sizeof(z21));
            wc_ForceZero(key8, sizeof(key8));
            return ret;
        }
    }
    wc_ForceZero(z21, sizeof(z21));
    wc_ForceZero(key8, sizeof(key8));
    return 0;
}

int mschapv2_generate_nt_response(const uint8_t auth_challenge[16],
                                  const uint8_t peer_challenge[16],
                                  const char   *username, size_t un_len,
                                  const char   *password, size_t pw_len,
                                  uint8_t out_response[MSCHAPV2_NT_RESPONSE_LEN])
{
    uint8_t challenge[MSCHAPV2_CHALLENGE_LEN];
    uint8_t nt_hash[MSCHAPV2_NT_HASH_LEN];
    int     ret;

    if (auth_challenge == NULL || peer_challenge == NULL
        || username == NULL || password == NULL || out_response == NULL) {
        return BAD_FUNC_ARG;
    }
    ret = challenge_hash(peer_challenge, auth_challenge,
                         username, un_len, challenge);
    if (ret != 0) return ret;
    ret = mschapv2_nt_password_hash(password, pw_len, nt_hash);
    if (ret != 0) return ret;
    ret = challenge_response(challenge, nt_hash, out_response);
    wc_ForceZero(nt_hash, sizeof(nt_hash));
    wc_ForceZero(challenge, sizeof(challenge));
    return ret;
}

/* RFC 2759 sec. 8.7: GenerateAuthenticatorResponse.
 * Builds the 42-byte "S=..." ASCII string the server is expected to
 * have sent. Returns 0 if equal to server_response, -1 if not. */
int mschapv2_verify_authenticator_response(
                              const char *password, size_t pw_len,
                              const uint8_t nt_response[MSCHAPV2_NT_RESPONSE_LEN],
                              const uint8_t peer_challenge[MSCHAPV2_PEER_CHALLENGE_LEN],
                              const uint8_t auth_challenge[MSCHAPV2_AUTH_CHALLENGE_LEN],
                              const char *username, size_t un_len,
                              const char *server_response,
                              size_t server_response_len)
{
    uint8_t nt_hash[MSCHAPV2_NT_HASH_LEN];
    uint8_t pw_hash_hash[MSCHAPV2_NT_HASH_LEN];
    uint8_t digest[WC_SHA_DIGEST_SIZE];
    uint8_t challenge[MSCHAPV2_CHALLENGE_LEN];
    wc_Sha  sha;
    Md4     md4;
    char    expected[MSCHAPV2_AUTH_RESPONSE_LEN + 1];
    static const char hex[] = "0123456789ABCDEF";
    uint8_t diff;
    int     ret;
    int     i;

    /* server_response is a fixed 42-byte field (no NUL); reject anything
     * shorter up front so the constant-time compare below cannot over-read. */
    if (server_response == NULL
        || server_response_len < (size_t)MSCHAPV2_AUTH_RESPONSE_LEN) {
        return -1;
    }
    if (mschapv2_nt_password_hash(password, pw_len, nt_hash) != 0) {
        return -1;
    }
    /* PasswordHashHash = MD4(NtPasswordHash). */
    wc_InitMd4(&md4);
    wc_Md4Update(&md4, nt_hash, MSCHAPV2_NT_HASH_LEN);
    wc_Md4Final(&md4, pw_hash_hash);
    /* Digest = SHA1(PasswordHashHash || NTResponse || Magic1). */
    ret = wc_InitSha(&sha);
    if (ret == 0) ret = wc_ShaUpdate(&sha, pw_hash_hash, MSCHAPV2_NT_HASH_LEN);
    if (ret == 0) ret = wc_ShaUpdate(&sha, nt_response,  MSCHAPV2_NT_RESPONSE_LEN);
    if (ret == 0) ret = wc_ShaUpdate(&sha, MAGIC1, sizeof(MAGIC1));
    if (ret == 0) ret = wc_ShaFinal(&sha, digest);
    if (ret != 0) goto out_err;

    /* Challenge = ChallengeHash(...). */
    ret = challenge_hash(peer_challenge, auth_challenge,
                         username, un_len, challenge);
    if (ret != 0) goto out_err;

    /* AuthResponse = SHA1(Digest || Challenge || Magic2). */
    ret = wc_InitSha(&sha);
    if (ret == 0) ret = wc_ShaUpdate(&sha, digest, sizeof(digest));
    if (ret == 0) ret = wc_ShaUpdate(&sha, challenge, MSCHAPV2_CHALLENGE_LEN);
    if (ret == 0) ret = wc_ShaUpdate(&sha, MAGIC2, sizeof(MAGIC2));
    if (ret == 0) ret = wc_ShaFinal(&sha, digest);
    if (ret != 0) goto out_err;

    expected[0] = 'S';
    expected[1] = '=';
    for (i = 0; i < WC_SHA_DIGEST_SIZE; i++) {
        expected[2 + i * 2]     = hex[(digest[i] >> 4) & 0x0F];
        expected[2 + i * 2 + 1] = hex[digest[i] & 0x0F];
    }
    expected[MSCHAPV2_AUTH_RESPONSE_LEN] = '\0';

    wc_ForceZero(nt_hash,      sizeof(nt_hash));
    wc_ForceZero(pw_hash_hash, sizeof(pw_hash_hash));
    wc_ForceZero(digest,       sizeof(digest));
    wc_ForceZero(challenge,    sizeof(challenge));
    wc_ForceZero(&md4,         sizeof(md4));
    wc_ForceZero(&sha,         sizeof(sha));

    /* Constant-time compare (XOR-accumulate) so a mismatch does not leak
     * the first differing position via branch timing, mirroring
     * sae_verify_peer_confirm. */
    diff = 0;
    for (i = 0; i < MSCHAPV2_AUTH_RESPONSE_LEN; i++) {
        diff |= (uint8_t)((uint8_t)server_response[i]
                          ^ (uint8_t)expected[i]);
    }
    return (diff == 0) ? 0 : -1;

out_err:
    /* Scrub all key-derived stack material on every failure path, mirroring
     * the success path above and mschapv2_derive_msk. */
    wc_ForceZero(nt_hash,      sizeof(nt_hash));
    wc_ForceZero(pw_hash_hash, sizeof(pw_hash_hash));
    wc_ForceZero(digest,       sizeof(digest));
    wc_ForceZero(challenge,    sizeof(challenge));
    wc_ForceZero(&md4,         sizeof(md4));
    wc_ForceZero(&sha,         sizeof(sha));
    return -1;
}

/* RFC 3079 sec.3.4: GetAsymmetricStartKey. Produces 16-byte half-MSK.
 * Returns 0 on success so a SHA failure propagates to mschapv2_derive_msk. */
static int get_asymmetric_start_key(const uint8_t master_key[MSCHAPV2_KEY_LEN],
                                    const uint8_t *magic, size_t magic_len,
                                    uint8_t out16[MSCHAPV2_KEY_LEN])
{
    wc_Sha  sha;
    uint8_t digest[WC_SHA_DIGEST_SIZE];
    int     ret;
    ret = wc_InitSha(&sha);
    if (ret == 0) ret = wc_ShaUpdate(&sha, master_key, MSCHAPV2_KEY_LEN);
    if (ret == 0) ret = wc_ShaUpdate(&sha, SHS_PAD1, sizeof(SHS_PAD1));
    if (ret == 0) ret = wc_ShaUpdate(&sha, magic, (word32)magic_len);
    if (ret == 0) ret = wc_ShaUpdate(&sha, SHS_PAD2, sizeof(SHS_PAD2));
    if (ret == 0) ret = wc_ShaFinal(&sha, digest);
    if (ret != 0) {
        wc_ForceZero(&sha,   sizeof(sha));
        wc_ForceZero(digest, sizeof(digest));
        return ret;
    }
    memcpy(out16, digest, MSCHAPV2_KEY_LEN);
    wc_ForceZero(&sha,   sizeof(sha));
    wc_ForceZero(digest, sizeof(digest));
    return 0;
}

/* RFC 3079 EAP-MSCHAPv2 MSK: MasterKey from the NT hash + NT-Response, then
 * the client send/recv asymmetric start keys. See mschapv2.h. */
int mschapv2_derive_msk(const char *password, size_t pw_len,
                        const uint8_t nt_response[MSCHAPV2_NT_RESPONSE_LEN],
                        uint8_t out_msk[MSCHAPV2_MSK_LEN])
{
    uint8_t nt_hash[MSCHAPV2_NT_HASH_LEN];
    uint8_t pw_hash_hash[MSCHAPV2_NT_HASH_LEN];
    uint8_t master_key[MSCHAPV2_KEY_LEN];
    uint8_t send_key[MSCHAPV2_KEY_LEN];
    uint8_t recv_key[MSCHAPV2_KEY_LEN];
    Md4     md4;
    wc_Sha  sha;
    uint8_t digest[WC_SHA_DIGEST_SIZE];
    int     ret;

    if (password == NULL || nt_response == NULL || out_msk == NULL) {
        return BAD_FUNC_ARG;
    }
    ret = mschapv2_nt_password_hash(password, pw_len, nt_hash);
    if (ret != 0) return ret;
    wc_InitMd4(&md4);
    wc_Md4Update(&md4, nt_hash, MSCHAPV2_NT_HASH_LEN);
    wc_Md4Final(&md4, pw_hash_hash);

    /* MasterKey = SHA1(PasswordHashHash || NTResponse || MasterKey magic)[0..15]. */
    ret = wc_InitSha(&sha);
    if (ret == 0) ret = wc_ShaUpdate(&sha, pw_hash_hash, MSCHAPV2_NT_HASH_LEN);
    if (ret == 0) ret = wc_ShaUpdate(&sha, nt_response, MSCHAPV2_NT_RESPONSE_LEN);
    if (ret == 0) ret = wc_ShaUpdate(&sha, MAGIC_MASTER_KEY,
                                     sizeof(MAGIC_MASTER_KEY));
    if (ret == 0) ret = wc_ShaFinal(&sha, digest);
    if (ret != 0) goto out;
    memcpy(master_key, digest, MSCHAPV2_KEY_LEN);

    /* From the client perspective (peer = us, sending TO server): */
    ret = get_asymmetric_start_key(master_key, MAGIC_CLIENT_SEND,
                                   sizeof(MAGIC_CLIENT_SEND), send_key);
    if (ret == 0) {
        ret = get_asymmetric_start_key(master_key, MAGIC_CLIENT_RECV,
                                       sizeof(MAGIC_CLIENT_RECV), recv_key);
    }
    if (ret != 0) goto out;

    /* RFC 3748: MSK = MS-MPPE-Recv-Key || MS-MPPE-Send-Key || 32 zeros.
     * From the client side: MS-MPPE-Recv-Key = recv_key (decrypt frames
     * from server) and MS-MPPE-Send-Key = send_key.
     */
    memcpy(&out_msk[0],                 recv_key, MSCHAPV2_KEY_LEN);
    memcpy(&out_msk[MSCHAPV2_KEY_LEN],   send_key, MSCHAPV2_KEY_LEN);
    memset(&out_msk[2 * MSCHAPV2_KEY_LEN], 0,
           MSCHAPV2_MSK_LEN - 2 * MSCHAPV2_KEY_LEN);
    ret = 0;

out:
    wc_ForceZero(nt_hash,      sizeof(nt_hash));
    wc_ForceZero(pw_hash_hash, sizeof(pw_hash_hash));
    wc_ForceZero(master_key,   sizeof(master_key));
    wc_ForceZero(send_key,     sizeof(send_key));
    wc_ForceZero(recv_key,     sizeof(recv_key));
    wc_ForceZero(digest,       sizeof(digest));
    wc_ForceZero(&md4,         sizeof(md4));
    wc_ForceZero(&sha,         sizeof(sha));
    return ret;
}

#endif /* WOLFIP_ENABLE_PEAP_MSCHAPV2 */

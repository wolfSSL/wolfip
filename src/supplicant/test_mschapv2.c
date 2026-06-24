/* test_mschapv2.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * MSCHAPv2 known-answer tests against RFC 2759 sec. 9.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mschapv2.h"

#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2

static int hex_eq(const uint8_t *got, const uint8_t *expect, size_t n,
                  const char *label)
{
    size_t i;
    if (memcmp(got, expect, n) == 0) {
        printf("  [OK]   %s\n", label);
        return 0;
    }
    printf("  [FAIL] %s\n", label);
    printf("    got:    ");
    for (i = 0; i < n; i++) printf("%02x", got[i]);
    printf("\n    expect: ");
    for (i = 0; i < n; i++) printf("%02x", expect[i]);
    printf("\n");
    return 1;
}

/* RFC 2759 sec.9 reference vectors:
 *   UserName             = "User"
 *   Password             = "clientPass"
 *   AuthenticatorChallenge = 5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28
 *   PeerChallenge          = 21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E
 *   NT-Response = 82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54
 *                 42 33 11 4A 3D 85 D6 DF
 *   PasswordHash = 44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE
 *   AuthResponse = "S=407A5589115FD0D6209F510FE9C04566932CDA56"
 */
static const char     USERNAME[] = "User";
static const char     PASSWORD[] = "clientPass";
static const uint8_t  AUTH_CH[16] = {
    0x5B,0x5D,0x7C,0x7D,0x7B,0x3F,0x2F,0x3E,
    0x3C,0x2C,0x60,0x21,0x32,0x26,0x26,0x28
};
static const uint8_t  PEER_CH[16] = {
    0x21,0x40,0x23,0x24,0x25,0x5E,0x26,0x2A,
    0x28,0x29,0x5F,0x2B,0x3A,0x33,0x7C,0x7E
};
static const uint8_t  EXPECTED_PW_HASH[16] = {
    0x44,0xEB,0xBA,0x8D,0x53,0x12,0xB8,0xD6,
    0x11,0x47,0x44,0x11,0xF5,0x69,0x89,0xAE
};
static const uint8_t  EXPECTED_NT_RESPONSE[24] = {
    0x82,0x30,0x9E,0xCD,0x8D,0x70,0x8B,0x5E,
    0xA0,0x8F,0xAA,0x39,0x81,0xCD,0x83,0x54,
    0x42,0x33,0x11,0x4A,0x3D,0x85,0xD6,0xDF
};
static const char     EXPECTED_AUTH_RESPONSE[] =
    "S=407A5589115FD0D6209F510FE9C04566932CDA56";

static int test_nt_password_hash(void)
{
    uint8_t hash[16];
    printf("Test 1: NT password hash (MD4 of UTF-16LE password)\n");
    if (mschapv2_nt_password_hash(PASSWORD, strlen(PASSWORD), hash) != 0) {
        printf("  [FAIL] mschapv2_nt_password_hash\n");
        return 1;
    }
    return hex_eq(hash, EXPECTED_PW_HASH, 16,
                  "RFC 2759 PasswordHash matches");
}

static int test_nt_response(void)
{
    uint8_t resp[24];
    printf("Test 2: GenerateNTResponse (challenge+response)\n");
    if (mschapv2_generate_nt_response(AUTH_CH, PEER_CH,
                                      USERNAME, strlen(USERNAME),
                                      PASSWORD, strlen(PASSWORD),
                                      resp) != 0) {
        printf("  [FAIL] mschapv2_generate_nt_response\n");
        return 1;
    }
    return hex_eq(resp, EXPECTED_NT_RESPONSE, 24,
                  "RFC 2759 NT-Response matches");
}

static int test_authenticator_response(void)
{
    int fails = 0;
    int ret;
    char tampered[MSCHAPV2_AUTH_RESPONSE_LEN + 1];
    printf("Test 3: AuthenticatorResponse verify\n");
    ret = mschapv2_verify_authenticator_response(
        PASSWORD, strlen(PASSWORD),
        EXPECTED_NT_RESPONSE, PEER_CH, AUTH_CH,
        USERNAME, strlen(USERNAME),
        EXPECTED_AUTH_RESPONSE, (size_t)MSCHAPV2_AUTH_RESPONSE_LEN);
    if (ret != 0) {
        printf("  [FAIL] valid server response rejected\n");
        fails++;
    }
    else {
        printf("  [OK]   valid 'S=' response verifies\n");
    }
    memcpy(tampered, EXPECTED_AUTH_RESPONSE, sizeof(tampered));
    tampered[10] ^= 0x01;
    ret = mschapv2_verify_authenticator_response(
        PASSWORD, strlen(PASSWORD),
        EXPECTED_NT_RESPONSE, PEER_CH, AUTH_CH,
        USERNAME, strlen(USERNAME),
        tampered, sizeof(tampered));
    if (ret == 0) {
        printf("  [FAIL] tampered server response wrongly accepted\n");
        fails++;
    }
    else {
        printf("  [OK]   tampered response rejected\n");
    }
    return fails;
}

static int test_msk_nonzero(void)
{
    uint8_t msk[MSCHAPV2_MSK_LEN];
    int     all_zero = 1;
    int     i;
    printf("Test 4: derive_msk sanity (non-zero, low half differs from high)\n");
    if (mschapv2_derive_msk(PASSWORD, strlen(PASSWORD),
                            EXPECTED_NT_RESPONSE, msk) != 0) {
        printf("  [FAIL] mschapv2_derive_msk\n");
        return 1;
    }
    for (i = 0; i < 32; i++) if (msk[i] != 0) { all_zero = 0; break; }
    if (all_zero) {
        printf("  [FAIL] MSK[0..31] all zero\n");
        return 1;
    }
    if (memcmp(&msk[0], &msk[16], 16) == 0) {
        printf("  [FAIL] send key == recv key (both halves equal)\n");
        return 1;
    }
    for (i = 32; i < 64; i++) if (msk[i] != 0) {
        printf("  [FAIL] MSK[32..63] not zero (RFC 3748 padding)\n");
        return 1;
    }
    printf("  [OK]   MSK has non-zero send/recv halves and 32B zero tail\n");
    return 0;
}

int main(void)
{
    int fails = 0;
    fails += test_nt_password_hash();
    fails += test_nt_response();
    fails += test_authenticator_response();
    fails += test_msk_nonzero();
    if (fails == 0) {
        printf("\nAll MSCHAPv2 tests passed.\n");
        return 0;
    }
    printf("\n%d MSCHAPv2 test failure(s).\n", fails);
    return 1;
}

#else  /* !WOLFIP_ENABLE_PEAP_MSCHAPV2 */

int main(void)
{
    printf("MSCHAPv2 support not built in. Configure with "
           "WOLFIP_ENABLE_PEAP_MSCHAPV2=1 and a wolfSSL built with "
           "--enable-md4 --enable-des3.\n");
    return 0;
}

#endif

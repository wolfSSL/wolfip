/* test_wpa_crypto.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Stand-alone test for src/supplicant/wpa_crypto.c. Verifies:
 *   1. PMK derivation against IEEE 802.11i-2004 Annex H.4 vector
 *      ("password" / "IEEE" -> known 32-byte PMK).
 *   2. AES Key Wrap round-trip (RFC 3394 single-block).
 *   3. PTK derivation peer symmetry: independently computing PTK with
 *      AA/SA swapped and ANonce/SNonce swapped must yield identical KCK,
 *      KEK and TK on both peers.
 *   4. MIC compute / constant-time verify round-trip.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "wpa_crypto.h"

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

/* IEEE 802.11i-2004 Annex H.4.2 (also reproduced in IEEE 802.11-2020
 * Annex J.4.2). Reference vector for PBKDF2-HMAC-SHA1 with the WPA
 * iteration count fixed at 4096. */
static int test_pmk_ieee_password_ieee(void)
{
    static const char ssid[] = "IEEE";
    static const char pass[] = "password";
    static const uint8_t expected[32] = {
        0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef,
        0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a, 0x5f, 0x90,
        0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2,
        0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10, 0xa1, 0x2e
    };
    uint8_t pmk[WPA_PMK_LEN];
    int ret;

    printf("Test 1: PMK = PBKDF2(\"password\", \"IEEE\", 4096, 32)\n");
    ret = wpa_pmk_from_passphrase(pass, strlen(pass),
                                  (const uint8_t *)ssid, strlen(ssid),
                                  pmk);
    if (ret != 0) {
        printf("  [FAIL] wpa_pmk_from_passphrase returned %d\n", ret);
        return 1;
    }
    return hex_eq(pmk, expected, sizeof(expected), "PMK matches IEEE vector");
}

static int test_aes_keywrap_roundtrip(void)
{
    /* RFC 3394 Section 4.1 single 128-bit block test vector. */
    static const uint8_t kek[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const uint8_t plain[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    static const uint8_t expect_wrap[24] = {
        0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47,
        0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82,
        0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5
    };
    uint8_t wrapped[24];
    uint8_t recovered[16];
    int fails = 0;
    int ret;

    printf("Test 2: AES Key Wrap (RFC 3394 4.1 vector + round-trip)\n");
    ret = wpa_aes_keywrap(kek, sizeof(kek), plain, sizeof(plain), wrapped);
    if (ret != 0) {
        printf("  [FAIL] wpa_aes_keywrap returned %d\n", ret);
        return 1;
    }
    fails += hex_eq(wrapped, expect_wrap, sizeof(expect_wrap),
                    "wrapped output matches RFC 3394");

    ret = wpa_aes_keyunwrap(kek, sizeof(kek),
                            wrapped, sizeof(wrapped), recovered);
    if (ret != 0) {
        printf("  [FAIL] wpa_aes_keyunwrap returned %d\n", ret);
        return 1;
    }
    fails += hex_eq(recovered, plain, sizeof(plain),
                    "unwrap recovers plaintext");
    return fails;
}

static int test_ptk_peer_symmetry(void)
{
    /* Both peers must derive the same PTK regardless of which side
     * supplies AA vs SA, or ANonce vs SNonce (the PRF input uses
     * lexicographic min/max ordering). */
    static const uint8_t pmk[WPA_PMK_LEN] = {
        0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef,
        0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a, 0x5f, 0x90,
        0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2,
        0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10, 0xa1, 0x2e
    };
    static const uint8_t ap_mac[6]   = {0x02,0x00,0x00,0x00,0x03,0x00};
    static const uint8_t sta_mac[6]  = {0x02,0x00,0x00,0x00,0x04,0x00};
    static const uint8_t anonce[32]  = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
    };
    static const uint8_t snonce[32]  = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f
    };
    struct wpa_ptk supp_ptk, auth_ptk;
    int fails = 0;
    int ret;

    printf("Test 3: PTK peer symmetry (supplicant vs authenticator view)\n");

    /* Supplicant view: aa = AP, sa = STA. */
    ret = wpa_ptk_derive(pmk, ap_mac, sta_mac, anonce, snonce, &supp_ptk);
    if (ret != 0) {
        printf("  [FAIL] supplicant wpa_ptk_derive ret %d\n", ret);
        return 1;
    }
    /* Authenticator view: arguments deliberately reordered to confirm
     * the min/max canonicalization. */
    ret = wpa_ptk_derive(pmk, sta_mac, ap_mac, snonce, anonce, &auth_ptk);
    if (ret != 0) {
        printf("  [FAIL] authenticator wpa_ptk_derive ret %d\n", ret);
        return 1;
    }

    fails += hex_eq(supp_ptk.kck, auth_ptk.kck, WPA_KCK_LEN, "KCK matches");
    fails += hex_eq(supp_ptk.kek, auth_ptk.kek, WPA_KEK_LEN, "KEK matches");
    fails += hex_eq(supp_ptk.tk,  auth_ptk.tk,  WPA_TK_LEN,  "TK  matches");
    return fails;
}

static int test_mic_roundtrip(void)
{
    /* Build a synthetic EAPOL-Key-like buffer, compute MIC with one
     * side's KCK, verify with the other peer's KCK (which must match
     * after PTK derivation). */
    static const uint8_t kck[WPA_KCK_LEN] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t frame[99];
    uint8_t mic[WPA_MIC_LEN];
    size_t i;
    int ret;
    int fails = 0;

    printf("Test 4: EAPOL MIC compute / verify round-trip\n");
    for (i = 0; i < sizeof(frame); i++) {
        frame[i] = (uint8_t)i;
    }

    ret = wpa_eapol_mic(kck, frame, sizeof(frame), mic);
    if (ret != 0) {
        printf("  [FAIL] wpa_eapol_mic ret %d\n", ret);
        return 1;
    }
    ret = wpa_eapol_mic_verify(kck, frame, sizeof(frame), mic);
    if (ret != 0) {
        printf("  [FAIL] wpa_eapol_mic_verify ret %d\n", ret);
        fails++;
    }
    else {
        printf("  [OK]   matching MIC verifies\n");
    }
    /* Tamper one byte and confirm verify fails. */
    frame[5] ^= 0x80;
    ret = wpa_eapol_mic_verify(kck, frame, sizeof(frame), mic);
    if (ret == 0) {
        printf("  [FAIL] verify wrongly accepted tampered frame\n");
        fails++;
    }
    else {
        printf("  [OK]   tampered frame rejected\n");
    }
    return fails;
}

int main(void)
{
    int fails = 0;
    fails += test_pmk_ieee_password_ieee();
    fails += test_aes_keywrap_roundtrip();
    fails += test_ptk_peer_symmetry();
    fails += test_mic_roundtrip();

    if (fails == 0) {
        printf("\nAll wpa_crypto tests passed.\n");
        return 0;
    }
    printf("\n%d wpa_crypto test failure(s).\n", fails);
    return 1;
}

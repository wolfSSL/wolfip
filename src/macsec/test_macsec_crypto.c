/* test_macsec_crypto.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Stand-alone test for src/macsec/macsec_crypto.c. Verifies:
 *   1. SAK wrap/unwrap: RFC 3394 4.1 vector + 128/256-bit round-trip.
 *   2. KDF construction: macsec_kdf output for a single 128-bit block equals
 *      a direct AES-CMAC over the exact IEEE 802.1X-2010 6.2.1 input
 *      (i || label || 0x00 || context || len_bits), locking the byte layout.
 *   3. KDF properties: determinism, label independence, and that a 256-bit
 *      output's two blocks differ (counter increments).
 *   4. KEK vs ICK independence (same CAK/CKN, different label -> different key).
 *   5. MKPDU ICV compute / constant-time verify + tamper rejection.
 *   6. SAK generation: determinism, KN sensitivity, length.
 *
 * The exact CAK/CKN/KEK/ICK/SAK byte values are locked against captured
 * wpa_supplicant / kernel-macsec vectors in the M4 interop tests.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "supplicant_features.h"     /* load wolfSSL config before wolfcrypt */
#include <wolfssl/wolfcrypt/cmac.h>

#include "macsec_crypto.h"
#include "macsec_test.h"

static int test_sak_wrap(void)
{
    static const uint8_t kek[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t sak[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    static const uint8_t expect_wrap[24] = {
        0x1f,0xa6,0x8b,0x0a,0x81,0x12,0xb4,0x47,
        0xae,0xf3,0x4b,0xd8,0xfb,0x5a,0x7b,0x82,
        0x9d,0x3e,0x86,0x23,0x71,0xd2,0xcf,0xe5
    };
    uint8_t kek256[32];
    uint8_t sak256[32];
    uint8_t wrapped[40];
    uint8_t recovered[32];
    int fails = 0;
    size_t i;

    printf("Test 1: SAK wrap/unwrap (RFC 3394 4.1 + round-trip)\n");
    if (macsec_wrap_sak(kek, sizeof(kek), sak, sizeof(sak), wrapped) != 0) {
        printf("  [FAIL] macsec_wrap_sak (128) error\n");
        return 1;
    }
    fails += hex_eq(wrapped, expect_wrap, sizeof(expect_wrap),
                    "GCM-AES-128 SAK wrap matches RFC 3394");
    if (macsec_unwrap_sak(kek, sizeof(kek), wrapped, 24, recovered) != 0) {
        printf("  [FAIL] macsec_unwrap_sak (128) error\n");
        fails++;
    }
    else {
        fails += hex_eq(recovered, sak, sizeof(sak), "128-bit SAK round-trip");
    }

    for (i = 0; i < sizeof(kek256); i++) { kek256[i] = (uint8_t)i; }
    for (i = 0; i < sizeof(sak256); i++) { sak256[i] = (uint8_t)(0x80 + i); }
    if (macsec_wrap_sak(kek256, sizeof(kek256), sak256, sizeof(sak256),
                        wrapped) != 0
        || macsec_unwrap_sak(kek256, sizeof(kek256), wrapped, 40,
                             recovered) != 0) {
        printf("  [FAIL] 256-bit SAK wrap/unwrap error\n");
        fails++;
    }
    else {
        fails += hex_eq(recovered, sak256, sizeof(sak256),
                        "256-bit SAK round-trip");
    }
    return fails;
}

static int test_kdf_construction(void)
{
    /* Verify macsec_kdf assembles i || label || 0x00 || context || len_bits
     * exactly, by comparing a single 128-bit block against a direct CMAC. */
    static const uint8_t key[16] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
    };
    static const char    label[] = "IEEE8021 ICK";
    static const uint8_t ctx[16] = {
        0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,
        0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99
    };
    uint8_t input[64];
    uint8_t expect[16];
    uint8_t got[16];
    word32  expect_sz = sizeof(expect);
    size_t  n = 0;
    int     fails = 0;

    printf("Test 2: KDF input assembly vs direct AES-CMAC (single block)\n");
    input[n++] = 0x01;                                  /* i = 1           */
    memcpy(input + n, label, strlen(label)); n += strlen(label);
    input[n++] = 0x00;                                  /* separator       */
    memcpy(input + n, ctx, sizeof(ctx)); n += sizeof(ctx);
    input[n++] = 0x00;                                  /* len_bits hi (128)*/
    input[n++] = 0x80;                                  /* len_bits lo      */

    if (wc_AesCmacGenerate(expect, &expect_sz, input, (word32)n,
                           key, sizeof(key)) != 0) {
        printf("  [FAIL] reference wc_AesCmacGenerate error\n");
        return 1;
    }
    if (macsec_kdf(key, sizeof(key), label, ctx, sizeof(ctx), 128, got) != 0) {
        printf("  [FAIL] macsec_kdf error\n");
        return 1;
    }
    fails += hex_eq(got, expect, sizeof(expect),
                    "macsec_kdf(128) == direct CMAC of spec input");
    return fails;
}

static int test_kdf_properties(void)
{
    static const uint8_t key[16] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00
    };
    static const uint8_t ctx[8] = { 1,2,3,4,5,6,7,8 };
    uint8_t a[16], b[16], c256[32], d[16];
    int fails = 0;

    printf("Test 3: KDF determinism / label independence / counter\n");
    macsec_kdf(key, sizeof(key), "IEEE8021 KEK", ctx, sizeof(ctx), 128, a);
    macsec_kdf(key, sizeof(key), "IEEE8021 KEK", ctx, sizeof(ctx), 128, b);
    fails += expect_true(memcmp(a, b, 16) == 0, "deterministic");
    macsec_kdf(key, sizeof(key), "IEEE8021 ICK", ctx, sizeof(ctx), 128, d);
    fails += expect_true(memcmp(a, d, 16) != 0, "different label -> different");
    macsec_kdf(key, sizeof(key), "IEEE8021 KEK", ctx, sizeof(ctx), 256, c256);
    fails += expect_true(memcmp(c256, c256 + 16, 16) != 0,
                         "256-bit output blocks differ (counter)");
    return fails;
}

static int test_kek_ick(void)
{
    static const uint8_t cak[16] = {
        0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,
        0xca,0xfe,0xba,0xbe,0xca,0xfe,0xba,0xbe
    };
    static const uint8_t ckn[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
    };
    uint8_t kek[16], ick[16];
    int fails = 0;

    printf("Test 4: KEK / ICK derivation independence\n");
    if (macsec_derive_kek(cak, sizeof(cak), ckn, sizeof(ckn), kek) != 0
        || macsec_derive_ick(cak, sizeof(cak), ckn, sizeof(ckn), ick) != 0) {
        printf("  [FAIL] derive error\n");
        return 1;
    }
    fails += expect_true(memcmp(kek, ick, 16) != 0, "KEK != ICK");
    return fails;
}

static int test_mkpdu_icv(void)
{
    static const uint8_t ick[16] = {
        0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x07,0x18,
        0x29,0x3a,0x4b,0x5c,0x6d,0x7e,0x8f,0x90
    };
    uint8_t mkpdu[80];
    uint8_t icv[16];
    size_t  i;
    int     fails = 0;

    printf("Test 5: MKPDU ICV compute / verify / tamper\n");
    for (i = 0; i < sizeof(mkpdu); i++) { mkpdu[i] = (uint8_t)(i * 7U); }

    if (macsec_mkpdu_icv(ick, sizeof(ick), mkpdu, sizeof(mkpdu), icv) != 0) {
        printf("  [FAIL] icv compute error\n");
        return 1;
    }
    fails += expect_true(
        macsec_mkpdu_icv_verify(ick, sizeof(ick), mkpdu, sizeof(mkpdu), icv)
            == 0, "ICV verifies");
    mkpdu[10] ^= 0x01;
    fails += expect_true(
        macsec_mkpdu_icv_verify(ick, sizeof(ick), mkpdu, sizeof(mkpdu), icv)
            != 0, "tampered MKPDU rejected");
    return fails;
}

static int test_sak_generation(void)
{
    static const uint8_t cak[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    uint8_t nonce[MACSEC_KS_NONCE_LEN];
    uint8_t mi_list[2 * MACSEC_MI_LEN];
    uint8_t sak_a[16], sak_b[16], sak_c[16];
    size_t  i;
    int     fails = 0;

    printf("Test 6: SAK generation determinism / KN sensitivity\n");
    for (i = 0; i < sizeof(nonce); i++)   { nonce[i] = (uint8_t)i; }
    for (i = 0; i < sizeof(mi_list); i++) { mi_list[i] = (uint8_t)(0x40 + i); }

    if (macsec_generate_sak(cak, sizeof(cak), 16, nonce, mi_list,
                            sizeof(mi_list), 1, sak_a) != 0
        || macsec_generate_sak(cak, sizeof(cak), 16, nonce, mi_list,
                               sizeof(mi_list), 1, sak_b) != 0
        || macsec_generate_sak(cak, sizeof(cak), 16, nonce, mi_list,
                               sizeof(mi_list), 2, sak_c) != 0) {
        printf("  [FAIL] SAK generate error\n");
        return 1;
    }
    fails += expect_true(memcmp(sak_a, sak_b, 16) == 0, "same inputs -> same SAK");
    fails += expect_true(memcmp(sak_a, sak_c, 16) != 0, "different KN -> different SAK");
    return fails;
}

int main(void)
{
    int fails = 0;
    setvbuf(stdout, NULL, _IONBF, 0);

    fails += test_sak_wrap();
    fails += test_kdf_construction();
    fails += test_kdf_properties();
    fails += test_kek_ick();
    fails += test_mkpdu_icv();
    fails += test_sak_generation();

    printf("\n%s: macsec_crypto (%d failure%s)\n",
           fails == 0 ? "PASS" : "FAIL", fails, fails == 1 ? "" : "s");
    return fails == 0 ? 0 : 1;
}

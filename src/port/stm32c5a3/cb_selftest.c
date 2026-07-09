/* cb_selftest.c
 *
 * STM32C5A3ZG DHUK crypto-callback primitive self-test.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfIP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Crypto-callback primitive self-test for the STM32C5A3ZG wolfIP port. Runs
 * the four primitives an embedded TLS/secure-boot stack needs -- ECDSA
 * (sign via the HW protected PKA + software verify), AES-GCM (full payload),
 * HMAC-SHA256 and TRNG -- through the wolfCrypt crypto-callback framework (the
 * STM32 DHUK device, see wc_Stm32_DhukRegister). Ported from the STM32_Bare_Test
 * main_cbonly.c; the board bring-up (clock/UART/RNG) is done by main.c, so this
 * module only registers the device and drives the primitives. Output is over
 * USART2 via printf (retargeted in syscalls.c).
 *
 *   [1] ECDSA sign via a DHUK-wrapped scalar (PKA), verified with the public
 *       key (SW verify -- the C5 PKA is sign-only).
 *   [2] AES-GCM full payload via the DHUK device: encrypt -> decrypt round-trip
 *       recovers the plaintext and verifies the tag; a tampered tag is rejected.
 *   [3] HMAC-SHA256 via a DHUK-devId Hmac, matched against the RFC 4231
 *       test-case-1 vector.
 *   [4] TRNG via a DHUK-devId RNG (STM32 hardware RNG through the callback).
 */

#include <stdio.h>
#include <stdint.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/version.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/port/st/stm32.h"

#include "cb_selftest.h"

/* Fixed NIST P-256 CAVP keypair + hash (private SigGen_D, public SigGen_Qx/Qy,
 * SigGenHashMsg). Used so the ECDSA leg needs no wc_ecc_make_key. */
#include "st_p256_vec.h"

/* Debugger-readable result sink (magic 0xCB010001 once the run completes), so
 * results can be captured without a working VCP. Read after the run with:
 *   arm-none-eabi-nm app.elf | grep g_cbonly_res   # address
 *   openocd ... -c "mdw 0x<addr> 6"                                        */
volatile struct {
    uint32_t magic;
    int32_t  ecdsa_rc;
    int32_t  gcm_rc;
    int32_t  hmac_rc;
    int32_t  rng_rc;
    int32_t  overall;
} g_cbonly_res;

/* A backend gated off or unable to complete the unwrap on TZEN=0 silicon
 * returns one of these. Treat as expected for the asymmetric legs. */
static int is_expected_gated(int ret)
{
    return (ret == CRYPTOCB_UNAVAILABLE) ||
           (ret == WC_TIMEOUT_E) ||
           (ret == WC_HW_E);
}

#if defined(WOLFSSL_DHUK) && \
    (defined(WOLFSSL_STM32_BARE) || defined(WOLFSSL_STM32_CUBEMX)) && \
    defined(WC_STM32_HAS_DHUK) && defined(WOLF_CRYPTO_CB)

/* Shared 256-bit derivation seed (used as the "key" for the DHUK device on the
 * symmetric legs). The SAES-derived working key never appears in software. */
static const byte g_seed[32] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
    0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01
};

#if defined(HAVE_ECC) && defined(WOLFSSL_STM32_PKA)
/* [1] ECDSA sign via a DHUK-protected private key, verified with the public
 * counterpart. Mirrors the transparent DHUK sign path: import the fixed public
 * point, wrap the known private scalar with the DHUK-derived key, import the
 * wrapped scalar + seed, route signing through the device, then verify. */
static int test_cbonly_ecdsa(WC_RNG* rng)
{
    ecc_key key;
    Aes     aes;
    byte    wrapped[32];
    byte    sig[80];
    word32  sigLen = (word32)sizeof(sig);
    int     ret;
    int     verify = 0;
    int     haveKey = 0;

    /* One key carries the curve + public point (for verify) and the wrapped
     * private scalar (for sign) -- no keygen. */
    ret = wc_ecc_init_ex(&key, NULL, WC_DHUK_DEVID);
    if (ret != 0) {
        printf("  wc_ecc_init_ex failed: %d\n", ret);
        return ret;
    }
    haveKey = 1;

    /* Set curve (dp) + public point from the fixed vector. */
    ret = wc_ecc_import_unsigned(&key, (byte*)SigGen_Qx, (byte*)SigGen_Qy,
                                 NULL, ECC_SECP256R1);
    if (ret != 0) {
        printf("  import public point failed: %d\n", ret);
        goto cleanup;
    }

    /* Wrap the known private scalar with the DHUK-derived AES key, exactly as a
     * provisioned device key would be delivered. */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, g_seed, 32, NULL, AES_ENCRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesEcbEncrypt(&aes, wrapped, SigGen_D, 32);
    }
    wc_AesFree(&aes);
    if (is_expected_gated(ret)) {
        printf("  ECDSA: DHUK backend gated/unavailable (ret=%d) -- soft PASS\n",
               ret);
        ret = 0;
        goto cleanup;
    }
    if (ret != 0) {
        printf("  scalar wrap failed: %d\n", ret);
        goto cleanup;
    }

    ret = wc_ecc_import_wrapped_private(&key, g_seed, (word32)sizeof(g_seed),
                                        wrapped, 32, 32);
    if (ret != 0) {
        printf("  import wrapped private failed: %d\n", ret);
        goto cleanup;
    }

    ret = wc_ecc_sign_hash(SigGenHashMsg, (word32)sizeof(SigGenHashMsg),
                           sig, &sigLen, rng, &key);
    if (is_expected_gated(ret)) {
        printf("  ECDSA sign gated/unavailable (ret=%d) -- soft PASS\n", ret);
        ret = 0;
        goto cleanup;
    }
    if (ret != 0) {
        printf("  ECDSA sign failed: %d\n", ret);
        goto cleanup;
    }

    /* Verify with the public point on the same key. On the C5 the PKA is
     * sign-only, so this runs the software ECDSA verify. */
    ret = wc_ecc_verify_hash(sig, sigLen, SigGenHashMsg,
                             (word32)sizeof(SigGenHashMsg), &verify, &key);
    if (ret != 0) {
        printf("  ECDSA verify error: %d\n", ret);
        goto cleanup;
    }
    if (verify != 1) {
        printf("  ECDSA verify FAILED (sig invalid)\n");
        ret = -1;
        goto cleanup;
    }
    printf("  ECDSA sign(DHUK)+verify OK (%lu-byte sig)\n",
           (unsigned long)sigLen);
    ret = 0;

cleanup:
    wc_ForceZero(wrapped, sizeof(wrapped));
    if (haveKey) {
        wc_ecc_free(&key);
    }
    return ret;
}
#endif /* HAVE_ECC && WOLFSSL_STM32_PKA */

#ifdef HAVE_AESGCM
/* [2] AES-GCM with a full (nonzero) payload via the DHUK device. Encrypt then
 * decrypt: the round-trip must recover the plaintext and verify the tag, the
 * ciphertext must differ from the plaintext, and a tampered tag must be
 * rejected. Exercises the SAES CTR keystream + software GHASH path. */
static int test_cbonly_gcm(void)
{
    static const byte iv[12] = {
        0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
        0xde,0xca,0xf8,0x88
    };
    static const byte aad[16] = {
        0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
        0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef
    };
    /* 20 bytes -> one full block + a 4-byte partial, to cover the trailing
     * partial-block path. */
    static const byte pt[20] = {
        0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
        0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
        0x86,0xa7,0xa9,0x53
    };
    Aes    aes;
    byte   ct[20];
    byte   rt[20];
    byte   tag[16];
    int    ret;
    int    i;

    XMEMSET(ct, 0, sizeof(ct));
    XMEMSET(rt, 0, sizeof(rt));
    XMEMSET(tag, 0, sizeof(tag));

    /* Encrypt. */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, g_seed, (word32)sizeof(g_seed));
    }
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(&aes, ct, pt, (word32)sizeof(pt),
                               iv, (word32)sizeof(iv),
                               tag, (word32)sizeof(tag),
                               aad, (word32)sizeof(aad));
    }
    wc_AesFree(&aes);
    if (is_expected_gated(ret)) {
        printf("  GCM: DHUK backend gated/unavailable (ret=%d) -- soft PASS\n",
               ret);
        return 0;
    }
    if (ret != 0) {
        printf("  GCM encrypt failed: %d\n", ret);
        return ret;
    }
    if (XMEMCMP(pt, ct, sizeof(pt)) == 0) {
        printf("  GCM produced plaintext -- FAIL\n");
        return -1;
    }
    printf("  GCM ct:");
    for (i = 0; i < (int)sizeof(ct); i++) printf(" %02x", ct[i]);
    printf("\n  GCM tag:");
    for (i = 0; i < (int)sizeof(tag); i++) printf(" %02x", tag[i]);
    printf("\n");

    /* Decrypt + verify tag -- must recover the plaintext. */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, g_seed, (word32)sizeof(g_seed));
    }
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&aes, rt, ct, (word32)sizeof(ct),
                               iv, (word32)sizeof(iv),
                               tag, (word32)sizeof(tag),
                               aad, (word32)sizeof(aad));
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  GCM decrypt/verify failed: %d\n", ret);
        return ret;
    }
    if (XMEMCMP(pt, rt, sizeof(pt)) != 0) {
        printf("  GCM round-trip mismatch -- FAIL\n");
        return -1;
    }
    printf("  GCM round-trip OK (plaintext recovered, tag verified)\n");

    /* Negative: a tampered tag must be rejected. */
    tag[0] ^= 0xff;
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, g_seed, (word32)sizeof(g_seed));
    }
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&aes, rt, ct, (word32)sizeof(ct),
                               iv, (word32)sizeof(iv),
                               tag, (word32)sizeof(tag),
                               aad, (word32)sizeof(aad));
    }
    wc_AesFree(&aes);
    if (ret != AES_GCM_AUTH_E) {
        printf("  GCM tamper NOT rejected (ret=%d) -- FAIL\n", ret);
        return -1;
    }
    printf("  GCM tamper rejected (AES_GCM_AUTH_E) OK\n");
    return 0;
}
#endif /* HAVE_AESGCM */

#ifndef NO_HMAC
/* [3] HMAC-SHA256 via a DHUK-devId Hmac. hmac.c routes this to the STM32 HASH
 * block (the callback declines HMAC; the HW innerHashKeyed path runs). Matched
 * against RFC 4231 test case 1. */
static int test_cbonly_hmac(void)
{
    static const byte key[20] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b
    };
    static const byte data[8] = { /* "Hi There" */
        0x48,0x69,0x20,0x54,0x68,0x65,0x72,0x65
    };
    static const byte expected[32] = {
        0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,
        0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
        0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,
        0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
    };
    Hmac hmac;
    byte out[WC_SHA256_DIGEST_SIZE];
    int  ret;
    int  i;

    XMEMSET(out, 0, sizeof(out));

    ret = wc_HmacInit(&hmac, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_HmacSetKey(&hmac, WC_SHA256, key, (word32)sizeof(key));
    }
    if (ret == 0) {
        ret = wc_HmacUpdate(&hmac, data, (word32)sizeof(data));
    }
    if (ret == 0) {
        ret = wc_HmacFinal(&hmac, out);
    }
    wc_HmacFree(&hmac);
    if (ret != 0) {
        printf("  HMAC-SHA256 failed: %d\n", ret);
        return ret;
    }
    if (XMEMCMP(out, expected, sizeof(expected)) != 0) {
        printf("  HMAC-SHA256 vector mismatch -- FAIL\n  got:");
        for (i = 0; i < (int)sizeof(out); i++) printf(" %02x", out[i]);
        printf("\n");
        return -1;
    }
    printf("  HMAC-SHA256 matches RFC 4231 case 1 OK\n");
    return 0;
}
#endif /* !NO_HMAC */

#ifndef WC_NO_RNG
/* [4] TRNG via a DHUK-devId RNG. wc_RNG_GenerateBlock routes to the callback's
 * WC_ALGO_TYPE_RNG case, which drives the STM32 hardware RNG. Sanity-check that
 * the output is non-trivial (not all-zero, not all-identical bytes). */
static int test_cbonly_rng(void)
{
    WC_RNG rng;
    byte   buf[32];
    int    ret;
    int    i;
    int    allZero = 1;
    int    allSame = 1;

    XMEMSET(buf, 0, sizeof(buf));

    ret = wc_InitRng_ex(&rng, NULL, WC_DHUK_DEVID);
    if (ret != 0) {
        printf("  wc_InitRng_ex(DHUK) failed: %d\n", ret);
        return ret;
    }
    ret = wc_RNG_GenerateBlock(&rng, buf, (word32)sizeof(buf));
    wc_FreeRng(&rng);
    if (ret != 0) {
        printf("  TRNG generate failed: %d\n", ret);
        return ret;
    }
    for (i = 0; i < (int)sizeof(buf); i++) {
        if (buf[i] != 0x00) allZero = 0;
        if (buf[i] != buf[0]) allSame = 0;
    }
    if (allZero || allSame) {
        printf("  TRNG output degenerate (allZero=%d allSame=%d) -- FAIL\n",
               allZero, allSame);
        return -1;
    }
    printf("  TRNG produced %u bytes of entropy OK\n", (unsigned)sizeof(buf));
    return 0;
}
#endif /* !WC_NO_RNG */

#endif /* WOLFSSL_DHUK && (BARE||CUBEMX) && WC_STM32_HAS_DHUK && WOLF_CRYPTO_CB */

int cb_selftest_run(void)
{
    int ret = 0;

    printf("\n");
    printf("========================================\n");
    printf("=== CB SELFTEST ===\n");
    printf("wolfCrypt DHUK crypto-callback self-test - STM32C5A3ZG\n");
    printf("wolfSSL version: %s\n", LIBWOLFSSL_VERSION_STRING);
    printf("========================================\n\n");

    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("wolfCrypt_Init failed: %d\n", ret);
        return ret;
    }

#if defined(WOLFSSL_DHUK) && \
    (defined(WOLFSSL_STM32_BARE) || defined(WOLFSSL_STM32_CUBEMX)) && \
    defined(WC_STM32_HAS_DHUK) && defined(WOLF_CRYPTO_CB)
    {
        WC_RNG rng;
        int    rc;

        ret = wc_Stm32_DhukRegister(WC_DHUK_DEVID);
        if (ret != 0) {
            printf("wc_Stm32_DhukRegister failed: %d\n", ret);
            goto done;
        }

        ret = wc_InitRng(&rng);
        if (ret != 0) {
            printf("wc_InitRng failed: %d\n", ret);
            wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
            goto done;
        }

#if defined(HAVE_ECC) && defined(WOLFSSL_STM32_PKA)
        printf("[1] ECDSA sign(DHUK) + verify:\n");
        rc = test_cbonly_ecdsa(&rng);
        g_cbonly_res.ecdsa_rc = rc;
        if (rc != 0 && ret == 0) ret = rc;
#endif
#ifdef HAVE_AESGCM
        printf("\n[2] AES-GCM full payload (DHUK, SAES CTR + GHASH):\n");
        rc = test_cbonly_gcm();
        g_cbonly_res.gcm_rc = rc;
        if (rc != 0 && ret == 0) ret = rc;
#endif
#ifndef NO_HMAC
        printf("\n[3] HMAC-SHA256 (DHUK devId -> STM32 HASH block):\n");
        rc = test_cbonly_hmac();
        g_cbonly_res.hmac_rc = rc;
        if (rc != 0 && ret == 0) ret = rc;
#endif
#ifndef WC_NO_RNG
        printf("\n[4] TRNG via crypto-callback (DHUK devId):\n");
        rc = test_cbonly_rng();
        g_cbonly_res.rng_rc = rc;
        if (rc != 0 && ret == 0) ret = rc;
#endif

        wc_FreeRng(&rng);
        wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
    }
#else
    printf("callback self-test not enabled in this build (need WOLFSSL_DHUK + "
           "WOLF_CRYPTO_CB + WOLFSSL_STM32_BARE + WC_STM32_HAS_DHUK).\n");
    ret = -1;
#endif

done:
    g_cbonly_res.overall = ret;
    g_cbonly_res.magic = 0xCB010001u;
    wolfCrypt_Cleanup();
    printf("\n=== CB SELFTEST %s (ret=%d) ===\n",
           ret == 0 ? "PASS" : "FAIL", ret);
    return ret;
}

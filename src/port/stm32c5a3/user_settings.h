/* user_settings.h
 *
 * wolfSSL configuration for STM32C5A3ZG bare-metal
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

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Build-mode shorthand
 *
 * WOLFSSL_STM32C5_CRYPTO_ARM gates the shared STM32C5 hardware-crypto config
 * so both the DHUK crypto-callback self-test (ENABLE_CB_SELFTEST) and the
 * TLS 1.3 mutual-auth client (ENABLE_TLS_CLIENT) get the same C5 arm without
 * duplicating the defines. TLS-only feature toggles are added on top under
 * the ENABLE_TLS gate further down.
 * ------------------------------------------------------------------------- */
#if defined(ENABLE_CB_SELFTEST) || defined(ENABLE_TLS_CLIENT) || \
    defined(WOLFSSL_STM32C5)
    #define WOLFSSL_STM32C5_CRYPTO_ARM
#endif

/* ------------------------------------------------------------------------- */
/* Platform / OS
 *
 * Network-only baseline: this file is only compiled when ENABLE_TLS or
 * ENABLE_CB_SELFTEST is set.
 * ------------------------------------------------------------------------- */
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_USER_IO           /* Use custom I/O callbacks (wolfssl_io.c) */
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER

/* Bare-metal: no system headers */
#define WOLFSSL_NO_SOCK
#define NO_WOLFSSL_DIR

/* ------------------------------------------------------------------------- */
/* STM32C5A3 hardware crypto (DHUK crypto-callback self-test build)
 *
 * The STM32C5A3 has TinyAES + HASH + RNG + SAES + PKA (V2 layout, all on
 * AHB2). For the ENABLE_CB_SELFTEST build we drive them via the direct-
 * register WOLFSSL_STM32_BARE path (the C5 new-generation HAL has no classic
 * CRYP/PKA driver APIs), mirroring the STM32_Bare_Test c5a3 crypto arm. The
 * network-only (ENABLE_TLS) baseline stays on the software crypto path -- the
 * HW enables below are additive and only activate for the self-test.
 *
 * Enabling WOLFSSL_STM32_PKA on the C5 auto-selects WC_STM32_PKA_SIGN_ONLY
 * (see wolfcrypt/port/st/stm32.h): HW signs via the protected PKA, software
 * verifies. WOLFSSL_STM32_BARE + SAES + PKA + WOLFSSL_DHUK together auto-
 * derive WC_STM32_HAS_DHUK inside stm32.h -- do not define it by hand.
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_STM32C5_CRYPTO_ARM
    #ifndef WOLFSSL_STM32C5      /* also passed as -DWOLFSSL_STM32C5 */
        #define WOLFSSL_STM32C5
    #endif
    #define WOLFSSL_STM32_BARE   /* direct-register HW crypto (no HAL) */
    #define STM32_CRYPTO         /* TinyAES HW */
    #define STM32_HASH           /* HW HASH (SHA-1/224/256/384/512) */
    #define NO_STM32_HMAC        /* HW HASH state machine does not survive HKDF */
    #define STM32_RNG            /* HW RNG (CK48 <- HSIDIV3, set up in main.c) */
    /* C5 silicon: the RNG clock-error detector (CR.CED) trips on the perfectly
     * valid 48 MHz CK48 kernel clock and stalls DRDY, which hangs the multi-word
     * Hash-DRBG seed pull inside wolfSSL_new. Suppress it (matches the Linux
     * STM32 RNG driver). main.c sets CR.CED when it enables the RNG too. */
    #define WC_STM32_RNG_CED_DISABLE
    #define NO_AES_192           /* TinyAES does not support 192-bit keys */
    #define WOLFSSL_STM32_PKA    /* auto-selects WC_STM32_PKA_SIGN_ONLY on C5 */
    #define WOLFSSL_SMALL_STACK  /* move large crypto temporaries to the heap */

    /* Crypto-callback + DHUK are harmless in 3A.0 (no session/key devId is
     * set anywhere), but wiring them here now means the later DHUK step only
     * has to register the callback and stamp a devId -- no user_settings churn.
     * Passed on the command line too (-DWOLF_CRYPTO_CB -DWOLFSSL_DHUK). */
    #ifndef WOLF_CRYPTO_CB
        #define WOLF_CRYPTO_CB
    #endif
    #ifndef WOLFSSL_DHUK
        #define WOLFSSL_DHUK
    #endif
    /* PK (EccSign) callback: lets the TLS client sign CertificateVerify with
     * the DHUK-wrapped identity key held by the app (ENABLE_DHUK_KEY build). */
    #ifndef HAVE_PK_CALLBACKS
        #define HAVE_PK_CALLBACKS
    #endif
#endif

/* ------------------------------------------------------------------------- */
/* Math - SP math with Cortex-M assembly optimizations
 * ------------------------------------------------------------------------- */
#define WOLFSSL_SP_MATH_ALL       /* Use SP math for all operations */
#define WOLFSSL_SP_SMALL          /* Smaller code size */
#define SP_WORD_SIZE 32           /* 32-bit platform */
#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_HAVE_SP_RSA
#define TFM_NO_ASM

/* ------------------------------------------------------------------------- */
/* TLS Configuration */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_SNI
#define NO_SESSION_CACHE

/* ------------------------------------------------------------------------- */
/* Cipher Suites */
/* ------------------------------------------------------------------------- */
#define HAVE_AESGCM
#define GCM_SMALL
#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_AES_DIRECT
#ifdef WOLFSSL_STM32C5_CRYPTO_ARM
    /* The DHUK ECDSA leg AES-ECB-wraps the P-256 scalar with the device key,
     * and the GCM/HMAC/RNG legs need the DRBG + ECB primitives. The TLS arm
     * uses the same C5 HW-RNG-seeded DRBG (HAVE_HASHDRBG + NO_DEV_RANDOM):
     * wc_GenerateSeed pulls from the STM32 HW RNG (STM32_RNG), no software
     * CUSTOM_RAND block. AES-ECB/DECRYPT are pulled in by the TinyAES BARE
     * path as well. */
    #define HAVE_AES_ECB
    #define HAVE_AES_DECRYPT
    #define HAVE_HASHDRBG
    #define NO_DEV_RANDOM
#endif
#define HAVE_CHACHA
#define HAVE_POLY1305
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define HAVE_HKDF

/* ------------------------------------------------------------------------- */
/* Key Exchange / Certificates */
/* ------------------------------------------------------------------------- */
#define HAVE_ECC
#define ECC_USER_CURVES
#define HAVE_ECC256
#define ECC_SHAMIR
#define ECC_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define WC_RSA_PSS
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_BASE64_ENCODE
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_EXT

/* ------------------------------------------------------------------------- */
/* Disable Unused Features */
/* ------------------------------------------------------------------------- */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_RABBIT
#define NO_HC128
#define NO_PSK
#define NO_PWDBASED
#define NO_OLD_TLS
#define NO_CHECK_PRIVATE_KEY
#define NO_DH

/* ------------------------------------------------------------------------- */
/* Memory */
/* ------------------------------------------------------------------------- */
#define ALT_ECC_SIZE
#define WOLFSSL_SMALL_CERT_VERIFY
#define BENCH_EMBEDDED

/* ------------------------------------------------------------------------- */
/* RNG
 *
 * Network baseline: seed from the wolfIP LFSR/HW-RNG shim (custom_rand_gen_block
 * in main.c). Any build that enables the STM32C5 crypto arm (self-test OR the
 * TLS 1.3 client) drives the real HW RNG (STM32_RNG) to seed the Hash-DRBG, so
 * the software custom block is compiled out there.
 * ------------------------------------------------------------------------- */
#ifndef WOLFSSL_STM32C5_CRYPTO_ARM
    #define CUSTOM_RAND_GENERATE_BLOCK custom_rand_gen_block
    int custom_rand_gen_block(unsigned char* output, unsigned int sz);
#endif

/* ------------------------------------------------------------------------- */
/* Debug (uncomment for troubleshooting) */
/* ------------------------------------------------------------------------- */
/* #define DEBUG_WOLFSSL */

#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_H */

/* user_settings.h
 *
 * wolfSSL configuration for STM32H753ZI with hardware acceleration
 *
 * This configuration enables:
 * - TLS 1.3 client support
 * - STM32 hardware HASH acceleration (SHA-1/256/384/512)
 * - STM32 hardware HMAC acceleration (for TLS PRF)
 * - STM32 hardware AES acceleration
 * - STM32 hardware RNG
 * - ECC P-256 for key exchange
 * - RSA for certificate verification
 *
 * Copyright (C) 2024 wolfSSL Inc.
 */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Platform / OS
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
/* STM32H7 Hardware Acceleration
 * ------------------------------------------------------------------------- */
#define WOLFSSL_STM32H7           /* STM32H753 variant */
#define WOLFSSL_STM32_CUBEMX      /* Use CubeMX HAL conventions */

/* Hardware HASH (SHA-1/256/384/512) */
#define STM32_HASH
#undef  NO_STM32_HASH

/* Hardware HMAC - accelerates TLS PRF operations */
#define STM32_HMAC
#undef  NO_STM32_HMAC

/* Hardware AES */
#define STM32_CRYPTO
#undef  NO_STM32_CRYPTO

/* Hardware RNG */
#define STM32_RNG
#undef  NO_STM32_RNG

/* Note: STM32H753 may not have PKA (public key accelerator)
 * If your variant has PKA, uncomment the following:
 * #define WOLFSSL_STM32_PKA
 */

/* ------------------------------------------------------------------------- */
/* Math Library
 * ------------------------------------------------------------------------- */
#define WOLFSSL_SP_MATH_ALL       /* Use SP math for all operations */
#define WOLFSSL_SP_SMALL          /* Smaller code size */
#define SP_WORD_SIZE 32           /* 32-bit platform */

/* Use Cortex-M assembly optimizations for better performance */
#define WOLFSSL_SP_ARM_CORTEX_M_ASM

/* Disable TFM ASM (we use SP math instead) */
#define TFM_NO_ASM

/* ------------------------------------------------------------------------- */
/* TLS Configuration
 * ------------------------------------------------------------------------- */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_SNI                  /* Server Name Indication - required by most servers */

/* Session - disable to save RAM */
#define NO_SESSION_CACHE
#define SMALL_SESSION_CACHE

/* ------------------------------------------------------------------------- */
/* Cipher Suites
 * ------------------------------------------------------------------------- */

/* AES-GCM (primary, hardware accelerated on STM32) */
#define HAVE_AESGCM
#define GCM_SMALL                 /* Smaller GCM tables */
#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_AES_DIRECT

/* ChaCha20-Poly1305 (fallback for non-AES scenarios) */
#define HAVE_CHACHA
#define HAVE_POLY1305

/* SHA-2 family (hardware accelerated) */
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

/* HKDF for TLS 1.3 key derivation */
#define HAVE_HKDF

/* ------------------------------------------------------------------------- */
/* Key Exchange / Certificates
 * ------------------------------------------------------------------------- */

/* ECC - primary key exchange */
#define HAVE_ECC
#define ECC_USER_CURVES           /* Only enable curves we specify */
#define HAVE_ECC256               /* P-256 (secp256r1) - most common */
#define ECC_SHAMIR
#define ECC_TIMING_RESISTANT

/* Hardening options */
#define TFM_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* RSA - needed for certificate verification (most servers use RSA certs) */
#define WC_RSA_PSS                /* Required for TLS 1.3 with RSA */

/* X.509 certificates */
#define WOLFSSL_ASN_TEMPLATE      /* Smaller ASN.1 code */
#define WOLFSSL_BASE64_ENCODE
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_EXT

/* ------------------------------------------------------------------------- */
/* Disable Unused Features
 * ------------------------------------------------------------------------- */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5                    /* MD5 deprecated */
#define NO_DES3
#define NO_RABBIT
#define NO_HC128
#define NO_PSK
#define NO_PWDBASED
#define NO_OLD_TLS                /* Disable TLS 1.0/1.1 */
#define NO_CHECK_PRIVATE_KEY      /* Save code - trust our own keys */

/* DH not needed if using ECC */
#define NO_DH

/* ------------------------------------------------------------------------- */
/* Memory Optimization
 * ------------------------------------------------------------------------- */
#define ALT_ECC_SIZE              /* Smaller ECC structs */
#define WOLFSSL_SMALL_CERT_VERIFY

/* ------------------------------------------------------------------------- */
/* RNG Configuration
 * ------------------------------------------------------------------------- */

/* Custom RNG block generator using STM32 hardware RNG */
#define CUSTOM_RAND_GENERATE_BLOCK custom_rand_gen_block
int custom_rand_gen_block(unsigned char* output, unsigned int sz);

/* ------------------------------------------------------------------------- */
/* Debug (uncomment for troubleshooting)
 * ------------------------------------------------------------------------- */
/* #define DEBUG_WOLFSSL */
/* #define WOLFSSL_DEBUG_TLS */

#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_H */

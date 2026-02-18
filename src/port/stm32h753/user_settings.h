/* user_settings.h
 *
 * wolfSSL configuration for STM32H753ZI bare-metal
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
/* STM32H753 Hardware HASH/HMAC Acceleration
 *
 * Uses the HASH peripheral for SHA-1/SHA-224/SHA-256 and HMAC.
 * Register definitions are in stm32_hash_register.h (no HAL required).
 * Note: We do NOT define WOLFSSL_STM32H7 or WOLFSSL_STM32_CUBEMX because
 * those trigger #include "stm32h7xx_hal.h". Instead we provide register
 * definitions directly via stm32_hash_register.h.
 * ------------------------------------------------------------------------- */
#include "stm32_hash_register.h"

#define STM32_HASH                    /* Enable HW hash (SHA-1/224/256) */
#define STM32_HMAC                    /* Enable HW HMAC */

/* ------------------------------------------------------------------------- */
/* Math - SP math with Cortex-M assembly optimizations
 * ------------------------------------------------------------------------- */
#define WOLFSSL_SP_MATH_ALL       /* Use SP math for all operations */
#define WOLFSSL_SP_SMALL          /* Smaller code size */
#define SP_WORD_SIZE 32           /* 32-bit platform */

/* Use Cortex-M assembly optimizations for SP math */
#define WOLFSSL_SP_ARM_CORTEX_M_ASM

/* SP ECC and RSA acceleration (uses sp_c32.c) */
#define WOLFSSL_HAVE_SP_ECC       /* SP-optimized ECC operations */
#define WOLFSSL_HAVE_SP_RSA       /* SP-optimized RSA operations */

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

/* AES-GCM (primary) */
#define HAVE_AESGCM
#define GCM_SMALL                 /* Smaller GCM tables */
#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_AES_DIRECT

/* ChaCha20-Poly1305 (fallback for non-AES scenarios) */
#define HAVE_CHACHA
#define HAVE_POLY1305

/* SHA-2 family */
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
#define BENCH_EMBEDDED            /* Use smaller benchmark/test buffers */

/* ------------------------------------------------------------------------- */
/* RNG Configuration
 * ------------------------------------------------------------------------- */

/* Custom RNG block generator (implemented in main.c using STM32H7 RNG peripheral) */
#define CUSTOM_RAND_GENERATE_BLOCK custom_rand_gen_block
int custom_rand_gen_block(unsigned char* output, unsigned int sz);

/* ------------------------------------------------------------------------- */
/* Debug (uncomment for troubleshooting)
 * ------------------------------------------------------------------------- */
/* #define DEBUG_WOLFSSL */
/* #define WOLFSSL_DEBUG_TLS */
/* #define DEBUG_STM32_HASH */

#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_H */

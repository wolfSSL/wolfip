/* user_settings.h
 *
 * wolfSSL/wolfSSH/wolfMQTT configuration for STM32H563 bare-metal
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
/* Platform / OS */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_USER_IO           /* Use custom I/O callbacks (wolfssl_io.c) */
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER

/* ------------------------------------------------------------------------- */
/* Math - Portable C implementation */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_SP_MATH_ALL       /* Use SP math for all operations */
#define WOLFSSL_SP_SMALL          /* Smaller code size */
#define SP_WORD_SIZE 32           /* 32-bit platform */

/* Use portable C code (no platform-specific assembly) */
#define TFM_NO_ASM
#define WOLFSSL_NO_ASM

/* ------------------------------------------------------------------------- */
/* TLS Configuration */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_SNI               /* Server Name Indication - required by most servers */

/* Session */
#define NO_SESSION_CACHE          /* Save RAM - no session resumption */
#define SMALL_SESSION_CACHE

/* ------------------------------------------------------------------------- */
/* Cipher Suites */
/* ------------------------------------------------------------------------- */

/* AES-GCM (primary) */
#define HAVE_AESGCM
#define GCM_SMALL                 /* Smaller GCM tables */
#define WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_AES_DIRECT

/* ChaCha20-Poly1305 (alternative, good for no-AES-HW platforms) */
#define HAVE_CHACHA
#define HAVE_POLY1305

/* SHA-2 family */
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

/* HKDF for TLS 1.3 */
#define HAVE_HKDF

/* ------------------------------------------------------------------------- */
/* Key Exchange / Certificates */
/* ------------------------------------------------------------------------- */

/* ECC */
#define HAVE_ECC
#define ECC_USER_CURVES           /* Only enable curves we specify */
#define HAVE_ECC256               /* P-256 (secp256r1) */
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
/* Disable Unused Features */
/* ------------------------------------------------------------------------- */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5                    /* MD5 deprecated, not needed */
#define NO_DES3
#define NO_RABBIT
#define NO_HC128
#define NO_PSK
#define NO_PWDBASED
#define NO_OLD_TLS                /* Disable TLS 1.0/1.1 */
#define NO_CHECK_PRIVATE_KEY      /* Save code - we trust our own keys */

/* DH not needed if using ECC */
#define NO_DH

/* ------------------------------------------------------------------------- */
/* Memory */
/* ------------------------------------------------------------------------- */

/* Use wolfSSL static memory if desired (optional)
 * For now, rely on newlib malloc from syscalls.c
 * #define WOLFSSL_STATIC_MEMORY
 * #define WOLFSSL_NO_MALLOC
 */

/* Reduce memory usage */
#define ALT_ECC_SIZE              /* Smaller ECC structs */
#define WOLFSSL_SMALL_CERT_VERIFY

/* ------------------------------------------------------------------------- */
/* RNG */
/* ------------------------------------------------------------------------- */
/* wc_GenerateSeed is implemented in tls_server.c
 * (wolfSSL will call it for entropy) */
#define CUSTOM_RAND_GENERATE_BLOCK custom_rand_gen_block
int custom_rand_gen_block(unsigned char* output, unsigned int sz);

/* ------------------------------------------------------------------------- */
/* Debug (comment out for production) */
/* ------------------------------------------------------------------------- */
/* #define DEBUG_WOLFSSL */
/* #define WOLFSSL_DEBUG_TLS */

/* ------------------------------------------------------------------------- */
/* wolfSSH Settings (when ENABLE_SSH=1) */
/* ------------------------------------------------------------------------- */
#ifdef ENABLE_SSH
/* Disable features not needed for basic shell */
#define WOLFSSH_NO_TIMESTAMP
#define WOLFSSH_NO_AGENT
#define WOLFSSH_NO_SFTP
#define WOLFSSH_NO_SCP

/* Memory optimization */
#define WOLFSSH_SMALL_STACK
#define DEFAULT_WINDOW_SZ (16 * 1024)
#define DEFAULT_HIGHWATER_MARK ((DEFAULT_WINDOW_SZ * 3) / 4)

/* Terminal support for shell */
#define WOLFSSH_TERM

/* Custom I/O - we use wolfIP sockets */
#define WOLFSSH_USER_IO

/* No certificate-based auth files */
#define NO_WOLFSSH_CERTS_FROM_FILE

/* ECC key support (matches our host key) */
#define WOLFSSH_KEYGEN
#endif

/* ------------------------------------------------------------------------- */
/* wolfMQTT Settings (when ENABLE_MQTT=1) */
/* ------------------------------------------------------------------------- */
#ifdef ENABLE_MQTT
#define WOLFMQTT_NONBLOCK
#define WOLFMQTT_NO_STDIO
#endif

#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_H */

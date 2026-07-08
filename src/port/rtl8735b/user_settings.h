/* user_settings.h
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
 *
 * wolfSSL config for the RTL8735B (AmebaPro2) wolfIP TLS-client demo, built in
 * the RealTek FreeRTOS SDK. Software crypto (no HUK offload for this port); the
 * TLS client uses wolfIP sockets via WOLFSSL_USER_IO and the wolfssl_io.c
 * bridge. Certificate verification is disabled in the demo (VERIFY_NONE), so no
 * CA store or RTC is required. Crypto set mirrors the proven wolfcrypt_huk_tls
 * example (ECDHE-ECDSA P-256, AES-GCM, SHA-2) so the TLS target should present
 * an ECDSA certificate. Only compiled when ENABLE_TLS_CLIENT is set.
 */
#ifndef RTL8735B_WOLFIP_USER_SETTINGS_H
#define RTL8735B_WOLFIP_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ---- platform / RTOS ---- */
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SIZEOF_LONG_LONG 8
#define SINGLE_THREADED           /* wolfIP + TLS run in one FreeRTOS task */
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define WOLFSSL_USER_IO           /* custom SetIORecv/Send; no BSD sockets */
#define WOLFSSL_NO_SOCK
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_ERROR_STRINGS

/* ---- TLS layer: TLS 1.2 + 1.3 client ---- */
#define NO_OLD_TLS
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_HKDF                 /* TLS 1.3 key schedule (kdf.c) */
#define WOLFSSL_NO_TLS12_RENEGOTIATION
#define NO_SESSION_CACHE
#define WOLFSSL_AEAD_ONLY         /* AES-GCM suites only (no CBC-HMAC) */
#define HAVE_SNI                  /* wolfSSL_UseSNI in tls_client.c */
#define NO_ASN_TIME               /* no RTC -> demo uses VERIFY_NONE */

/* ---- symmetric: AES-GCM ---- */
#define HAVE_AESGCM
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_256
#define WOLFSSL_AES_128
#define GCM_TABLE_4BIT

/* ---- hashing + DRBG ---- */
#undef  NO_SHA256
#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define HAVE_HASHDRBG

/* ---- ECC / ECDSA / ECDHE (P-256) ---- */
#define HAVE_ECC
#define HAVE_ECC_SIGN
#define HAVE_ECC_VERIFY
#define HAVE_ECC_DHE
#define ECC_USER_CURVES
#define HAVE_ECC256
#define ECC_TIMING_RESISTANT
#define WOLFSSL_SP_MATH_ALL

/* ---- trims ---- */
#define NO_RSA
#define NO_DSA
#define NO_DH
#define NO_DES3
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_PWDBASED
#define NO_PKCS12
#define NO_PKCS8

/* ---- custom RNG seed hook (provided in wolfip_rtl8735b.c via the SDK TRNG) ---- */
#define CUSTOM_RAND_GENERATE_SEED  rtl8735b_rand_seed
#ifndef __ASSEMBLER__
    #include <stddef.h>
    int rtl8735b_rand_seed(unsigned char* output, unsigned int sz);
#endif

#ifdef __cplusplus
}
#endif

#endif /* RTL8735B_WOLFIP_USER_SETTINGS_H */

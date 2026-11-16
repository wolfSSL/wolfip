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
 * wolfSSL settings for the Versal firmware update demo: TLS 1.3 client,
 * ML-KEM hybrid key exchange, ECDSA P-384 mutual authentication.
 */
#ifndef AMD_VERSAL_USER_SETTINGS_H
#define AMD_VERSAL_USER_SETTINGS_H

/* Platform: bare metal, one thread, I/O through wolfIP */
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_NO_SOCK
#define NO_WOLFSSL_DIR
#define WOLFSSL_USER_IO
#define NO_WOLFSSL_SERVER
#define NO_SESSION_CACHE
#define WOLFSSL_NO_FLOAT_FMT
#define NO_ERROR_STRINGS

/* Math: portable C, 64-bit words */
#define WOLFSSL_SP_MATH_ALL
#define SP_WORD_SIZE 64
#define HAVE___UINT128_T
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

/* TLS 1.3 only */
#define WOLFSSL_TLS13
#define NO_OLD_TLS
#define WOLFSSL_NO_TLS12
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define HAVE_AEAD
#define NO_RSA
#define NO_DH
#define NO_PSK

/* Key exchange: P-384 + ML-KEM-1024 hybrid */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_PQC_HYBRIDS
#define WOLFSSL_NO_ML_KEM_512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define HAVE_ECC
#define ECC_USER_CURVES
#define HAVE_ECC384
#define ECC_SHAMIR

/* Ciphers and hashes */
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

/* Random: no hardware TRNG is reachable from here, so seed the Hash-DRBG
 * from wolfCrypt's memory-timing entropy source (CNTVCT_EL0). */
#define HAVE_HASHDRBG
#define HAVE_ENTROPY_MEMUSE
#define ENTROPY_MEMUSE_FORCE_FAILURE /* no fallback to /dev/urandom */

/* Certificates. No RTC: dates are checked against the build time plus
 * uptime (OTA_BUILD_EPOCH, set by the Makefile). */
#ifndef __ASSEMBLER__
    #include <time.h>
    time_t ota_time(time_t *t);
    #define XTIME(t) ota_time((t))
#endif
#define WOLFSSL_ASN_TEMPLATE

/* Trim */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_DES3
#define NO_PWDBASED

#endif /* AMD_VERSAL_USER_SETTINGS_H */

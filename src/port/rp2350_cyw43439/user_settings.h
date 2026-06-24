/* user_settings.h - wolfCrypt config for the Pi Pico 2 W WPA2-PSK supplicant
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
 * Minimal wolfCrypt build for the host-run WPA2-PSK 4-way handshake on
 * bare-metal RP2350. Only the primitives wpa_crypto.c uses are enabled:
 *   PBKDF2-HMAC-SHA1 (PMK), HMAC-SHA1 / HMAC-SHA256 (PRF, KCK MIC,
 *   PMKID), AES key wrap/unwrap (GTK in M3), and a Hash-DRBG RNG seeded
 *   from the RP2350 ring oscillator (SNonce). No TLS, RSA, ECC, ASN, or
 *   filesystem - this is a wolfCrypt-only build (EAP-TLS / SAE are
 *   compiled out of the supplicant for this port).
 */

#ifndef WOLFIP_PICO2W_USER_SETTINGS_H
#define WOLFIP_PICO2W_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Bare metal: single threaded, no OS, no filesystem, small stack. */
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_SOCK
#define NO_WOLFSSL_STUB

/* wolfCrypt only - no TLS/SSL layer for WPA2-PSK. */
#define WOLFCRYPT_ONLY

/* Algorithms the 4-way handshake needs. */
#define HAVE_PBKDF2               /* wc_PBKDF2 (PMK from passphrase)      */
#define WOLFSSL_AES_DIRECT        /* required by the key-wrap ECB path    */
#define HAVE_AES_KEYWRAP          /* wc_AesKeyWrap / wc_AesKeyUnWrap (GTK)*/
#define WOLFSSL_AES_128           /* CCMP KEK is 128-bit                  */
#define WOLFSSL_AES_256
#define WOLFSSL_AES_SMALL_TABLES  /* smaller AES tables                   */
#define HAVE_HASHDRBG             /* SHA-256 Hash-DRBG for WC_RNG         */

/* RNG seed: the RP2350 ring oscillator (see rp2350_rng.c). */
extern int rp2350_wc_genseed(unsigned char *output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED rp2350_wc_genseed

/* Trim everything off the WPA2-PSK path to keep code size down. */
#define NO_RSA
#define NO_DSA
#define NO_DH
#define NO_DES3
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_PSK                    /* TLS-PSK, unrelated to WPA-PSK        */
#define NO_ASN
#define NO_CERTS
#define NO_PKCS12
#define NO_OLD_TLS
#define NO_RABBIT
#define NO_HC128
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_PICO2W_USER_SETTINGS_H */

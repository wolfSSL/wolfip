/* user_settings.h
 *
 * wolfCrypt configuration for the wolfIP PIC32MZ EF port.
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
#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h> /* for size_t */

/* ---- Platform -------------------------------------------------------- */
#define WOLFSSL_GENERAL_ALIGNMENT   4
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK

#define MICROCHIP_PIC32
#define WOLFSSL_MICROCHIP_PIC32MZ   /* auto-enables WOLFSSL_PIC32MZ_RNG */

/* This milestone exercises ONLY the hardware TRNG. Keep the PIC32MZ crypto
 * engine (AES/hash acceleration) disabled so SHA-256 (used by the Hash-DRBG)
 * runs in software and we don't need the pic32mz-crypt.c engine driver yet. */
#define NO_PIC32MZ_CRYPT
#define NO_PIC32MZ_HASH

/* ---- RNG ------------------------------------------------------------- */
#define HAVE_HASHDRBG               /* SHA-256 based DRBG seeded by the TRNG */

/* ---- Trim algorithms not needed for the RNG self-test ---------------- */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_AES
#define NO_DES3
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_SHA                      /* SHA-1 not needed; SHA-256 stays on */
#define NO_PWDBASED
#define NO_PSK
#define NO_OLD_TLS

/* ---- Environment ----------------------------------------------------- */
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_DEV_RANDOM               /* no /dev/random on bare metal */
#define NO_ASN_TIME                 /* no RTC */
#define WOLFSSL_NO_SOCK

/* WOLFSSL_MICROCHIP_PIC32MZ makes settings.h define WOLFSSL_HAVE_MIN/MAX,
 * which tells wolfcrypt that min()/max() are supplied externally (normally by
 * the Microchip framework). misc.h then omits its own min()/max() prototypes,
 * so the wolfcrypt sources need them declared here. This bare-metal port
 * supplies them in wolf_compat.c.
 *
 * These use "unsigned int" rather than word32 because word32 is not yet
 * defined at this point (types.h has not been included). wolf_compat.c defines
 * min()/max() with this same unsigned int signature and asserts unsigned int
 * is wide enough to hold a word32. */
extern unsigned int min(unsigned int a, unsigned int b);
extern unsigned int max(unsigned int a, unsigned int b);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */

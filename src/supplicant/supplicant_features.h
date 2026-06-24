/* supplicant_features.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfIP.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* Central wolfSupplicant feature / crypto configuration. Pulls the
 * wolfSSL build config so the NO_* / HAVE_* algorithm macros are visible,
 * then auto-disables any optional method whose required wolfCrypt
 * primitives are absent (with a #warning) and hard-errors when the
 * always-on WPA2-PSK baseline cannot be satisfied. Include this before
 * any WOLFIP_ENABLE_* feature gate. The WOLFIP_ENABLE_* defaults
 * themselves are set by the build system (see Makefile); this header only
 * turns features OFF, never on.
 */

#ifndef WOLFIP_SUPPLICANT_FEATURES_H
#define WOLFIP_SUPPLICANT_FEATURES_H

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

/* PEAPv0/MSCHAPv2 needs MD4 (opt-in: --enable-md4, i.e. !NO_MD4),
 * single-DES (the DES3 build, !NO_DES3), and SHA-1 (!NO_SHA). */
#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2
#if defined(NO_MD4) || defined(NO_DES3) || defined(NO_SHA)
#warning "wolfSupplicant: PEAP/MSCHAPv2 disabled (needs MD4 + DES3 + SHA-1)"
#undef  WOLFIP_ENABLE_PEAP_MSCHAPV2
#define WOLFIP_ENABLE_PEAP_MSCHAPV2 0
#endif
#endif

/* WPA3-SAE dragonfly needs ECC, HKDF, HMAC, and SHA-256. */
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE
#if !defined(HAVE_ECC) || !defined(HAVE_HKDF) || defined(NO_HMAC) \
    || defined(NO_SHA256)
#warning "wolfSupplicant: SAE disabled (needs HAVE_ECC + HAVE_HKDF + HMAC + SHA-256)"
#undef  WOLFIP_ENABLE_SAE
#define WOLFIP_ENABLE_SAE 0
#endif
#endif

/* WPA2-PSK is the unconditional baseline and cannot be turned off: the
 * 4-way handshake needs AES (CCMP / key-wrap / CMAC), HMAC, SHA-1,
 * SHA-256, PBKDF2, and RFC 3394 AES key wrap. */
#if defined(NO_AES) || defined(NO_HMAC) || defined(NO_SHA) \
    || defined(NO_SHA256) || defined(NO_PWDBASED) \
    || !defined(HAVE_AES_KEYWRAP)
#error "wolfSupplicant requires wolfCrypt AES, HMAC, SHA-1, SHA-256, PBKDF2, and AES key wrap"
#endif

#endif /* WOLFIP_SUPPLICANT_FEATURES_H */

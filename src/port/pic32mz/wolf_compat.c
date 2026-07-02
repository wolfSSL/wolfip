/* wolf_compat.c
 *
 * Small wolfCrypt compatibility shims for the bare-metal PIC32MZ port.
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

/* The WOLFSSL_MICROCHIP_PIC32MZ settings block defines WOLFSSL_HAVE_MIN /
 * WOLFSSL_HAVE_MAX, which tells wolfcrypt/src/misc.c NOT to define min()/max()
 * because the Microchip Harmony / TCP-IP framework normally provides them.
 * This bare-metal port does not use that framework, so provide them here. */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

/* Define these with the SAME unsigned int signature as the prototypes in
 * user_settings.h (word32 is not yet defined at that early include stage).
 * Using unsigned int here rather than word32 keeps the definitions matching
 * the prototypes exactly even if word32's underlying typedef is not literally
 * unsigned int (e.g. unsigned long of the same width), avoiding a
 * conflicting-type error. The assertion guards that unsigned int is wide
 * enough to hold a word32 without truncation on this target. */
typedef char wc_compat_uint_holds_word32[
    (sizeof(unsigned int) >= sizeof(word32)) ? 1 : -1];

unsigned int min(unsigned int a, unsigned int b)
{
    return (a < b) ? a : b;
}

unsigned int max(unsigned int a, unsigned int b)
{
    return (a > b) ? a : b;
}

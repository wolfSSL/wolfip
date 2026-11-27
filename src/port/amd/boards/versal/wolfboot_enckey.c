/* wolfboot_enckey.c
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

/* Demonstration image-encryption key provider, linked into wolfBoot for this
 * example with OBJS_EXTRA. The key and IV are fixed and public: a product
 * reads them from eFuse, BBRAM or a PUF-wrapped store instead. */
#include <stdint.h>
#include <string.h>
#include "wolfboot/wolfboot.h"
#include "image.h"

/* The demo key below is sized for AES-256 (32-byte key, 16-byte IV). */
typedef char demo_key_size_check[
    ((ENCRYPT_KEY_SIZE + ENCRYPT_NONCE_SIZE) == 48) ? 1 : -1];

/* Same bytes as the key file given to the sign tool: key || nonce. */
static const uint8_t demo_key[ENCRYPT_KEY_SIZE + ENCRYPT_NONCE_SIZE] =
    "0123456789abcdef0123456789abcdef0123456789abcdef";

int wolfBoot_get_encrypt_key(uint8_t *key, uint8_t *nonce)
{
    if (key == NULL || nonce == NULL)
        return -1;
    memcpy(key, demo_key, ENCRYPT_KEY_SIZE);
    memcpy(nonce, demo_key + ENCRYPT_KEY_SIZE, ENCRYPT_NONCE_SIZE);
    return 0;
}

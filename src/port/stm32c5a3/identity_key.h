/* identity_key.h
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

/* Device P-256 (secp256r1) identity keypair used by the TLS 1.3 mutual-auth
 * DHUK demo (ENABLE_DHUK_KEY): the private scalar is delivered to the device
 * only in DHUK-wrapped form (unwrapped inside SAES, signed on the HW PKA), and
 * the public point is bound into the client certificate in tls_certs.h.
 *
 * For this demo the keypair is a PUBLIC NIST P-256 CAVP (FIPS 186) known-answer
 * vector (US Government public domain, http://csrc.nist.gov/groups/STM/cavp/),
 * so it is not a real secret. In production the wrapped identity blob is
 * provisioned off-device and the plaintext scalar never exists here. If this
 * keypair changes, re-run gen_certs.py so the client certificate matches.
 */
#ifndef IDENTITY_KEY_H
#define IDENTITY_KEY_H
#include <stdint.h>

/* Private scalar d (kept only for the software bring-up path; the DHUK build
 * wraps it and signs through the callback instead). */
const uint8_t identity_key_d[] =
{
  0x70, 0x83, 0x09, 0xa7, 0x44, 0x9e, 0x15, 0x6b, 0x0d, 0xb7, 0x0e, 0x5b,
  0x52, 0xe6, 0x06, 0xc7, 0xe0, 0x94, 0xed, 0x67, 0x6c, 0xe8, 0x95, 0x3b,
  0xf6, 0xc1, 0x47, 0x57, 0xc8, 0x26, 0xf5, 0x90
};

/* Public point Q = d*G, uncompressed (qx || qy). */
const uint8_t identity_key_qx[] =
{
  0x29, 0x57, 0x8c, 0x7a, 0xb6, 0xce, 0x0d, 0x11, 0x49, 0x3c, 0x95, 0xd5,
  0xea, 0x05, 0xd2, 0x99, 0xd5, 0x36, 0x80, 0x1c, 0xa9, 0xcb, 0xd5, 0x0e,
  0x99, 0x24, 0xe4, 0x3b, 0x73, 0x3b, 0x83, 0xab
};

const uint8_t identity_key_qy[] =
{
  0x08, 0xc8, 0x04, 0x98, 0x79, 0xc6, 0x27, 0x8b, 0x22, 0x73, 0x34, 0x84,
  0x74, 0x15, 0x85, 0x15, 0xac, 0xca, 0xa3, 0x83, 0x44, 0x10, 0x6e, 0xf9,
  0x68, 0x03, 0xc5, 0xa0, 0x5a, 0xdc, 0x48, 0x00
};

#endif /* IDENTITY_KEY_H */

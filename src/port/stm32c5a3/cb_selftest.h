/* cb_selftest.h
 *
 * STM32C5A3ZG DHUK crypto-callback primitive self-test.
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

#ifndef CB_SELFTEST_H
#define CB_SELFTEST_H

#ifdef __cplusplus
extern "C" {
#endif

/* Run the DHUK crypto-callback primitive self-test (ECDSA sign via HW PKA +
 * SW verify, AES-GCM via SAES with a device-bound key, HMAC-SHA256, HW TRNG).
 * All output goes over USART2 via printf. Returns 0 on PASS, nonzero on FAIL. */
int cb_selftest_run(void);

#ifdef __cplusplus
}
#endif

#endif /* CB_SELFTEST_H */

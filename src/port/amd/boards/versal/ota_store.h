/* ota_store.h
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
 */
#ifndef AMD_VERSAL_OTA_STORE_H
#define AMD_VERSAL_OTA_STORE_H

#include <stdint.h>

/* Call from the main loop. On the first call it brings up the QSPI, finds
 * the slot wolfBoot booted and clears a rejected update. */
void ota_store_poll(uint32_t now_ms);

/* Non-zero while the running image is a new update that wolfBoot will roll
 * back at the next reset unless ota_store_confirm() is called. */
int ota_store_on_probation(void);
void ota_store_confirm(void);

/* Write a signed image to the inactive slot and mark it for probation.
 * Returns 0 on success; the caller then resets. */
int ota_store_write(const uint8_t *img, uint32_t len);

#endif /* AMD_VERSAL_OTA_STORE_H */

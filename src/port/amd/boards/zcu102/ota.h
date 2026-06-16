/* ota.h
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
 * Network-delivered firmware update for the ZCU102 wolfBoot + wolfIP demo.
 * The running (signed, verified) wolfIP app fetches a newer signed image
 * over TFTP and stages it to the SD OFP_B partition using wolfBoot's own
 * SD/disk drivers compiled into the app; a system reset then lets wolfBoot
 * verify and boot the higher-version image.
 */
#ifndef AMD_ZCU102_OTA_H
#define AMD_ZCU102_OTA_H

#include <stdint.h>
#include "wolfip.h"

/* Begin a TFTP GET of `filename` from `server_ip_be` (network byte order,
 * e.g. straight from sin_addr.s_addr) and stage it to OFP_B. One transfer
 * at a time; returns 0 if started, <0 on error or if already running. */
int ota_trigger(struct wolfIP *stack, uint32_t server_ip_be,
    const char *filename);

/* Drive the in-flight transfer. Call once per main-loop iteration with the
 * same millisecond clock fed to wolfIP_poll(). On a successful transfer it
 * writes OFP_B and resets the board (does not return). */
void ota_poll(struct wolfIP *stack, uint32_t now_ms);

/* Non-zero while a transfer is in progress. */
int ota_in_progress(void);

/* ZynqMP system soft reset (provided by sdhci_shim.c). */
void ota_system_reset(void);

#endif /* AMD_ZCU102_OTA_H */

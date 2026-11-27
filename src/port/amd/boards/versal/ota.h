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
 * Network-delivered firmware update for the Versal wolfBoot + wolfIP demo.
 * The running app fetches a newer signed image (HTTPS by default, TFTP with
 * OTA_TRANSPORT=tftp), writes it to the inactive QSPI slot and resets;
 * wolfBoot verifies it and boots it on probation.
 */
#ifndef AMD_VERSAL_OTA_H
#define AMD_VERSAL_OTA_H

#include <stdint.h>
#include "wolfip.h"

/* Request an update check. HTTPS: the server is the one built in
 * (OTA_SERVER_IP) and both arguments are ignored. TFTP: GET `filename` from
 * `server_ip_be` (network byte order). Returns 0 if accepted. */
int ota_trigger(struct wolfIP *stack, uint32_t server_ip_be,
    const char *filename);

/* Drive the in-flight transfer. Call once per main-loop iteration with the
 * same millisecond clock fed to wolfIP_poll(). On a successful transfer it
 * writes the inactive slot and resets the board (does not return). */
void ota_poll(struct wolfIP *stack, uint32_t now_ms);

/* Non-zero while a transfer is in progress. */
int ota_in_progress(void);

/* System reset through PSCI (provided by ota_store.c). */
void ota_system_reset(void);

#endif /* AMD_VERSAL_OTA_H */

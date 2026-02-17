/* vde_device.h
 *
 * Copyright (C) 2024 wolfSSL Inc.
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

#ifndef VDE_DEVICE_H
#define VDE_DEVICE_H

#include "wolfip.h"

/**
 * Initialize VDE device connection
 *
 * @param ll         Pointer to wolfIP_ll_dev structure to initialize
 * @param socket_path VDE switch socket path (e.g., "/tmp/vde_switch.ctl")
 * @param port       Optional port number (can be NULL for auto-assignment)
 * @param mac        Optional MAC address (6 bytes, NULL for auto-generated)
 * @return 0 on success, -1 on error
 */
int vde_init(struct wolfIP_ll_dev *ll, const char *socket_path,
             const char *port, const uint8_t *mac);

/**
 * Cleanup VDE connection
 */
void vde_cleanup(void);

#endif /* VDE_DEVICE_H */

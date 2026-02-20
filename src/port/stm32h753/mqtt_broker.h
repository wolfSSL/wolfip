/* mqtt_broker.h
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

#ifndef MQTT_BROKER_STM32_H
#define MQTT_BROKER_STM32_H

#include "wolfip.h"
#include <stdint.h>

/* Debug callback type */
typedef void (*mqtt_broker_debug_cb)(const char *msg);

/* MQTT broker configuration */
typedef struct {
    uint16_t port;            /* Broker port (default: 8883 for TLS, 1883 plain) */
    int use_tls;              /* Enable TLS (requires wolfSSL) */
} mqtt_broker_config_t;

/* Initialize MQTT broker
 * stack: wolfIP stack instance
 * config: broker configuration (NULL for defaults)
 * debug: debug callback for status messages
 * Returns 0 on success, -1 on failure */
int mqtt_broker_init(struct wolfIP *stack,
    const mqtt_broker_config_t *config, mqtt_broker_debug_cb debug);

/* Poll MQTT broker - call from main loop
 * Returns 0 on success */
int mqtt_broker_poll(void);

/* Check if MQTT broker is running
 * Returns 1 if running, 0 otherwise */
int mqtt_broker_is_running(void);

/* Get MQTT broker state as string (for debugging) */
const char *mqtt_broker_get_state_str(void);

#endif /* MQTT_BROKER_STM32_H */

/* mqtt_client.h
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

#ifndef MQTT_CLIENT_H
#define MQTT_CLIENT_H

#include "wolfip.h"
#include <stdint.h>

/* Debug callback type */
typedef void (*mqtt_debug_cb)(const char *msg);

/* MQTT client configuration */
typedef struct {
    const char *broker_ip;      /* Broker IP address (e.g., "192.168.0.1") */
    uint16_t broker_port;       /* Broker port (default: 8883 for TLS) */
    const char *client_id;      /* Client ID */
    const char *publish_topic;  /* Topic to publish to */
    uint16_t keep_alive_sec;    /* Keep-alive interval in seconds */
} mqtt_client_config_t;

/* Initialize MQTT client
 * stack: wolfIP stack instance
 * config: MQTT client configuration (NULL for defaults)
 * debug: Debug callback for status messages
 * Returns 0 on success, -1 on failure */
int mqtt_client_init(struct wolfIP *stack, const mqtt_client_config_t *config,
    mqtt_debug_cb debug);

/* Poll MQTT client - call from main loop
 * Returns 0 on success */
int mqtt_client_poll(void);

/* Publish message to configured topic
 * message: Message payload (null-terminated string)
 * Returns 0 on success, -1 on failure, 1 if busy */
int mqtt_client_publish(const char *message);

/* Check if MQTT client is connected
 * Returns 1 if connected, 0 otherwise */
int mqtt_client_is_connected(void);

/* Disconnect MQTT client cleanly
 * Returns 0 on success */
int mqtt_client_disconnect(void);

/* Get MQTT client state as string (for debugging) */
const char *mqtt_client_get_state_str(void);

#endif /* MQTT_CLIENT_H */

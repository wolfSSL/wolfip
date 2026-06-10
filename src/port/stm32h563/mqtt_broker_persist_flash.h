/* mqtt_broker_persist_flash.h
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

/* STM32H5 internal-flash persistence backend for the wolfMQTT broker.
 * Implements the MqttBrokerPersistHooks key/value API over a reserved
 * region of internal flash so broker session/subscription/retained/
 * outbound-queue state survives a reboot. */

#ifndef MQTT_BROKER_PERSIST_FLASH_H
#define MQTT_BROKER_PERSIST_FLASH_H

#include <wolfmqtt/mqtt_broker.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WOLFMQTT_BROKER_PERSIST

/* Populate `hooks` with the STM32H5 internal-flash KV backend and a
 * fixed development encryption key (when WOLFMQTT_BROKER_PERSIST_ENCRYPT
 * is enabled). Scans the reserved flash region and recovers the active
 * bank, or formats the region on first use / corruption.
 *
 * Returns 0 on success or a negative MQTT_CODE_ERROR_* on failure.
 * Call after MqttBroker_Init and before MqttBroker_Start. */
int MqttBrokerNet_PersistFlash_Init(MqttBrokerPersistHooks* hooks);

#endif /* WOLFMQTT_BROKER_PERSIST */

#ifdef __cplusplus
}
#endif

#endif /* MQTT_BROKER_PERSIST_FLASH_H */

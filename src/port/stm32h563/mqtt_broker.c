/* mqtt_broker.c
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

#include "mqtt_broker.h"
#include <wolfmqtt/mqtt_broker.h>
#include <wolfmqtt/mqtt_socket.h>
#include <wolfssl/ssl.h>
#include <string.h>

#include "certs.h"

/* Configuration defaults */
#define DEFAULT_BROKER_PORT_TLS     8883
#define DEFAULT_BROKER_PORT_PLAIN   1883

/* Broker state machine */
typedef enum {
    BROKER_STATE_IDLE,
    BROKER_STATE_INIT,
    BROKER_STATE_STARTING,
    BROKER_STATE_RUNNING,
    BROKER_STATE_ERROR
} broker_state_t;

/* Global uptime counter (updated by main loop) */
volatile unsigned long broker_uptime_sec = 0;

/* Broker context */
static struct {
    struct wolfIP *stack;
    MqttBroker broker;
    MqttBrokerNet net;
    WOLFSSL_CTX *ssl_ctx;
    broker_state_t state;
    mqtt_broker_debug_cb debug_cb;
    uint16_t port;
    int use_tls;
    int initialized;
} ctx;

/* wolfSSL TLS socket callbacks from wolfMQTT (mqtt_socket.c).
 * These route through MqttNet per-client callbacks, which in turn
 * call the broker's BrokerWolfIP_Read/Write via MqttBrokerNet. */
extern int MqttSocket_TlsSocketReceive(WOLFSSL* ssl, char *buf, int sz,
    void *ptr);
extern int MqttSocket_TlsSocketSend(WOLFSSL* ssl, char *buf, int sz,
    void *ptr);

/* Debug output helper */
static void debug_print(const char *msg)
{
    if (ctx.debug_cb) {
        ctx.debug_cb(msg);
    }
}

/* Format number to string (no printf on bare-metal) */
static void uint_to_str(uint32_t val, char *buf)
{
    char tmp[12];
    int i = 0;
    int j = 0;

    if (val == 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return;
    }

    while (val > 0) {
        tmp[i++] = '0' + (val % 10);
        val /= 10;
    }

    while (i > 0) {
        buf[j++] = tmp[--i];
    }
    buf[j] = '\0';
}

/* Initialize TLS context for broker (server-side) */
static int broker_tls_init(void)
{
    ctx.ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!ctx.ssl_ctx) {
        debug_print("MQTT Broker: TLS context create failed\n");
        return -1;
    }

    /* Load server certificate from embedded PEM */
    if (wolfSSL_CTX_use_certificate_buffer(ctx.ssl_ctx,
            (const unsigned char *)server_cert_pem,
            (long)server_cert_pem_len,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        debug_print("MQTT Broker: Load cert failed\n");
        wolfSSL_CTX_free(ctx.ssl_ctx);
        ctx.ssl_ctx = NULL;
        return -1;
    }

    /* Load server private key from embedded PEM */
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx.ssl_ctx,
            (const unsigned char *)server_key_pem,
            (long)server_key_pem_len,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        debug_print("MQTT Broker: Load key failed\n");
        wolfSSL_CTX_free(ctx.ssl_ctx);
        ctx.ssl_ctx = NULL;
        return -1;
    }

    /* Set wolfSSL I/O callbacks to route through the broker's MqttNet layer.
     * The chain is: wolfSSL -> MqttSocket_TlsSocketReceive/Send ->
     * MqttNet.read/write (per-client) -> broker->net.read/write ->
     * BrokerWolfIP_Read/Write -> wolfIP_sock_recv/send.
     * Do NOT use wolfSSL_SetIO_wolfIP_CTX here - that would bypass
     * the MqttNet layer and break the broker's per-client routing. */
    wolfSSL_CTX_SetIORecv(ctx.ssl_ctx, MqttSocket_TlsSocketReceive);
    wolfSSL_CTX_SetIOSend(ctx.ssl_ctx, MqttSocket_TlsSocketSend);

    debug_print("MQTT Broker: TLS initialized (TLS 1.3, ECC P-256)\n");
    return 0;
}

/* Handle init state */
static int handle_init(void)
{
    int ret;

    /* Initialize wolfIP broker network callbacks */
    ret = MqttBrokerNet_wolfIP_Init(&ctx.net, ctx.stack);
    if (ret != 0) {
        debug_print("MQTT Broker: Net init failed\n");
        ctx.state = BROKER_STATE_ERROR;
        return -1;
    }

    /* Initialize broker */
    ret = MqttBroker_Init(&ctx.broker, &ctx.net);
    if (ret != 0) {
        debug_print("MQTT Broker: Init failed\n");
        ctx.state = BROKER_STATE_ERROR;
        return -1;
    }

    /* Configure broker */
    ctx.broker.port = ctx.port;

    /* Set up TLS if enabled */
    if (ctx.use_tls) {
        ctx.broker.use_tls = 1;

        if (broker_tls_init() < 0) {
            ctx.state = BROKER_STATE_ERROR;
            return -1;
        }

        /* Assign pre-configured TLS context to broker */
        ctx.broker.tls_ctx = ctx.ssl_ctx;
    }

    ctx.state = BROKER_STATE_STARTING;
    return 0;
}

/* Handle starting state */
static int handle_starting(void)
{
    int ret;

    ret = MqttBroker_Start(&ctx.broker);
    if (ret != 0) {
        debug_print("MQTT Broker: Start failed\n");
        ctx.state = BROKER_STATE_ERROR;
        return -1;
    }

    debug_print("MQTT Broker: Running on port ");
    {
        char port_str[8];
        uint_to_str(ctx.port, port_str);
        debug_print(port_str);
    }
    if (ctx.use_tls) {
        debug_print(" (TLS)");
    }
    debug_print("\n");

    ctx.state = BROKER_STATE_RUNNING;
    return 0;
}

/* Handle running state */
static int handle_running(void)
{
    int ret;

    ret = MqttBroker_Step(&ctx.broker);
    if (ret < 0 && ret != MQTT_CODE_CONTINUE) {
        debug_print("MQTT Broker: Step error\n");
        ctx.state = BROKER_STATE_ERROR;
        return -1;
    }

    return 0;
}

int mqtt_broker_init(struct wolfIP *stack,
    const mqtt_broker_config_t *config, mqtt_broker_debug_cb debug)
{
    memset(&ctx, 0, sizeof(ctx));
    ctx.stack = stack;
    ctx.debug_cb = debug;
    ctx.state = BROKER_STATE_IDLE;

    /* Apply configuration */
    if (config) {
        if (config->port > 0) {
            ctx.port = config->port;
        }
        ctx.use_tls = config->use_tls;
    }

    /* Apply defaults for unset values */
    if (ctx.port == 0) {
        ctx.port = ctx.use_tls ? DEFAULT_BROKER_PORT_TLS
                               : DEFAULT_BROKER_PORT_PLAIN;
    }

    debug_print("MQTT Broker: Initializing\n");

    ctx.initialized = 1;
    ctx.state = BROKER_STATE_INIT;

    return 0;
}

int mqtt_broker_poll(void)
{
    if (!ctx.initialized) {
        return -1;
    }

    switch (ctx.state) {
        case BROKER_STATE_IDLE:
            break;

        case BROKER_STATE_INIT:
            handle_init();
            break;

        case BROKER_STATE_STARTING:
            handle_starting();
            break;

        case BROKER_STATE_RUNNING:
            handle_running();
            break;

        case BROKER_STATE_ERROR:
            /* Clean up and return to idle */
            MqttBroker_Free(&ctx.broker);
            if (ctx.ssl_ctx) {
                /* Note: MqttBroker_Free already frees tls_ctx,
                 * so only free if broker didn't own it */
                ctx.ssl_ctx = NULL;
            }
            ctx.state = BROKER_STATE_IDLE;
            break;

        default:
            break;
    }

    return 0;
}

int mqtt_broker_is_running(void)
{
    return (ctx.state == BROKER_STATE_RUNNING);
}

const char *mqtt_broker_get_state_str(void)
{
    switch (ctx.state) {
        case BROKER_STATE_IDLE:     return "IDLE";
        case BROKER_STATE_INIT:     return "INIT";
        case BROKER_STATE_STARTING: return "STARTING";
        case BROKER_STATE_RUNNING:  return "RUNNING";
        case BROKER_STATE_ERROR:    return "ERROR";
        default:                    return "UNKNOWN";
    }
}

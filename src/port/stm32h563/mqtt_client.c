/* mqtt_client.c
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

#include "mqtt_client.h"
#include <wolfmqtt/mqtt_client.h>
#include <wolfmqtt/mqtt_socket.h>
#include <wolfssl/ssl.h>
#include <string.h>

/* Configuration defaults */
#define DEFAULT_BROKER_IP       "54.36.178.49"  /* test.mosquitto.org */
#define DEFAULT_BROKER_PORT     8883    /* TLS port */
#define DEFAULT_CLIENT_ID       "wolfip-stm32h563"
#define DEFAULT_PUBLISH_TOPIC   "wolfip/status"
#define DEFAULT_KEEP_ALIVE      60      /* seconds */

/* Buffer sizes */
#define MQTT_TX_BUF_SIZE        512
#define MQTT_RX_BUF_SIZE        512
#define MQTT_CMD_TIMEOUT_MS     30000

/* MQTT client state machine */
typedef enum {
    MQTT_STATE_IDLE,
    MQTT_STATE_NET_CONNECT,
    MQTT_STATE_TLS_CONNECT,
    MQTT_STATE_MQTT_CONNECT,
    MQTT_STATE_CONNECTED,
    MQTT_STATE_PUBLISHING,
    MQTT_STATE_DISCONNECTING,
    MQTT_STATE_ERROR
} mqtt_state_t;

/* Client context */
static struct {
    struct wolfIP *stack;
    MqttClient client;
    MqttNet net;
    MqttConnect connect;
    MqttPublish publish;
    WOLFSSL_CTX *ssl_ctx;
    WOLFSSL *ssl;
    void *io_ctx;
    mqtt_state_t state;
    mqtt_debug_cb debug_cb;
    uint8_t tx_buf[MQTT_TX_BUF_SIZE];
    uint8_t rx_buf[MQTT_RX_BUF_SIZE];
    char broker_ip[32];
    char client_id[32];
    char publish_topic[64];
    uint16_t broker_port;
    uint16_t keep_alive;
    int socket_fd;
    int initialized;
    int publish_pending;
    char publish_msg[128];
} ctx;

/* External functions from wolfmqtt_io.c */
extern void *wolfMQTT_Init_wolfIP(MqttNet *net, struct wolfIP *stack);
extern void wolfMQTT_Cleanup_wolfIP(void *context);
extern int wolfMQTT_GetFd_wolfIP(void *context);
extern void wolfMQTT_SetFd_wolfIP(void *context, int fd);
extern int wolfMQTT_IsConnected_wolfIP(void *context);

/* External functions from wolfssl_io.c */
extern int wolfSSL_SetIO_wolfIP_CTX(WOLFSSL_CTX *ctx, struct wolfIP *s);
extern int wolfSSL_SetIO_wolfIP(WOLFSSL *ssl, int fd);

/* Debug output helper */
static void debug_print(const char *msg)
{
    if (ctx.debug_cb) {
        ctx.debug_cb(msg);
    }
}

/* Format number to string */
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

/* TLS receive callback for wolfMQTT */
static int mqtt_tls_read(void *context, byte *buf, int buf_len, int timeout_ms)
{
    int ret;
    (void)timeout_ms;
    (void)context;

    if (!ctx.ssl || !buf) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    ret = wolfSSL_read(ctx.ssl, buf, buf_len);
    if (ret < 0) {
        int err = wolfSSL_get_error(ctx.ssl, ret);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            return MQTT_CODE_CONTINUE;
        }
        return MQTT_CODE_ERROR_NETWORK;
    }
    if (ret == 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }
    return ret;
}

/* TLS send callback for wolfMQTT */
static int mqtt_tls_write(void *context, const byte *buf, int buf_len,
    int timeout_ms)
{
    int ret;
    (void)timeout_ms;
    (void)context;

    if (!ctx.ssl || !buf) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    ret = wolfSSL_write(ctx.ssl, buf, buf_len);
    if (ret < 0) {
        int err = wolfSSL_get_error(ctx.ssl, ret);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            return MQTT_CODE_CONTINUE;
        }
        return MQTT_CODE_ERROR_NETWORK;
    }
    return ret;
}

int mqtt_client_init(struct wolfIP *stack, const mqtt_client_config_t *config,
    mqtt_debug_cb debug)
{
    int ret;

    memset(&ctx, 0, sizeof(ctx));
    ctx.stack = stack;
    ctx.debug_cb = debug;
    ctx.state = MQTT_STATE_IDLE;
    ctx.socket_fd = -1;

    /* Apply configuration */
    if (config) {
        if (config->broker_ip) {
            strncpy(ctx.broker_ip, config->broker_ip, sizeof(ctx.broker_ip) - 1);
        }
        if (config->broker_port > 0) {
            ctx.broker_port = config->broker_port;
        }
        if (config->client_id) {
            strncpy(ctx.client_id, config->client_id, sizeof(ctx.client_id) - 1);
        }
        if (config->publish_topic) {
            strncpy(ctx.publish_topic, config->publish_topic,
                sizeof(ctx.publish_topic) - 1);
        }
        if (config->keep_alive_sec > 0) {
            ctx.keep_alive = config->keep_alive_sec;
        }
    }

    /* Apply defaults for unset values */
    if (ctx.broker_ip[0] == '\0') {
        strncpy(ctx.broker_ip, DEFAULT_BROKER_IP, sizeof(ctx.broker_ip) - 1);
    }
    if (ctx.broker_port == 0) {
        ctx.broker_port = DEFAULT_BROKER_PORT;
    }
    if (ctx.client_id[0] == '\0') {
        strncpy(ctx.client_id, DEFAULT_CLIENT_ID, sizeof(ctx.client_id) - 1);
    }
    if (ctx.publish_topic[0] == '\0') {
        strncpy(ctx.publish_topic, DEFAULT_PUBLISH_TOPIC,
            sizeof(ctx.publish_topic) - 1);
    }
    if (ctx.keep_alive == 0) {
        ctx.keep_alive = DEFAULT_KEEP_ALIVE;
    }

    debug_print("MQTT: Initializing client\n");

    /* Initialize wolfMQTT I/O callbacks for wolfIP */
    ctx.io_ctx = wolfMQTT_Init_wolfIP(&ctx.net, stack);
    if (!ctx.io_ctx) {
        debug_print("MQTT: Failed to init I/O\n");
        return -1;
    }

    /* Initialize MQTT client */
    ret = MqttClient_Init(&ctx.client, &ctx.net, NULL, ctx.tx_buf,
        MQTT_TX_BUF_SIZE, ctx.rx_buf, MQTT_RX_BUF_SIZE, MQTT_CMD_TIMEOUT_MS);
    if (ret != MQTT_CODE_SUCCESS) {
        debug_print("MQTT: Client init failed\n");
        wolfMQTT_Cleanup_wolfIP(ctx.io_ctx);
        return -1;
    }

    /* Initialize TLS context */
    ctx.ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx.ssl_ctx) {
        debug_print("MQTT: TLS context failed\n");
        MqttClient_DeInit(&ctx.client);
        wolfMQTT_Cleanup_wolfIP(ctx.io_ctx);
        return -1;
    }

    /* Disable certificate verification for test broker
     * (production should use proper CA certificates) */
    wolfSSL_CTX_set_verify(ctx.ssl_ctx, SSL_VERIFY_NONE, NULL);

    /* Register wolfIP I/O callbacks on the context */
    wolfSSL_SetIO_wolfIP_CTX(ctx.ssl_ctx, stack);

    ctx.initialized = 1;
    ctx.state = MQTT_STATE_NET_CONNECT;

    debug_print("MQTT: Initialized, connecting to ");
    debug_print(ctx.broker_ip);
    debug_print(":");
    {
        char port_str[8];
        uint_to_str(ctx.broker_port, port_str);
        debug_print(port_str);
    }
    debug_print("\n");

    return 0;
}

/* Handle network connection state */
static int handle_net_connect(void)
{
    int ret;
    static uint32_t connect_polls = 0;
    struct wolfIP_sockaddr_in addr;

    if (ctx.socket_fd < 0) {
        ctx.socket_fd = wolfIP_sock_socket(ctx.stack, AF_INET, IPSTACK_SOCK_STREAM, 0);
        if (ctx.socket_fd < 0) {
            debug_print("MQTT: Socket create failed\n");
            ctx.state = MQTT_STATE_ERROR;
            return -1;
        }
        debug_print("MQTT: Connecting...\n");
        connect_polls = 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(ctx.broker_port);
    addr.sin_addr.s_addr = ee32(atoip4(ctx.broker_ip));

    ret = wolfIP_sock_connect(ctx.stack, ctx.socket_fd,
        (struct wolfIP_sockaddr *)&addr, sizeof(addr));

    if (ret == 0) {
        debug_print("MQTT: TCP connected\n");
        wolfMQTT_SetFd_wolfIP(ctx.io_ctx, ctx.socket_fd);
        ctx.state = MQTT_STATE_TLS_CONNECT;
        connect_polls = 0;
        return 0;
    }

    if (ret == -WOLFIP_EAGAIN || ret == -11) {
        connect_polls++;
        /* Print status every ~50000 polls */
        if ((connect_polls % 50000) == 0) {
            debug_print("MQTT: Waiting for TCP...\n");
        }
        return 0; /* Still connecting (EAGAIN/EINPROGRESS) */
    }

    debug_print("MQTT: TCP connect failed\n");
    ctx.state = MQTT_STATE_ERROR;
    return -1;
}

/* Handle TLS handshake state */
static int handle_tls_connect(void)
{
    int ret;

    if (!ctx.ssl) {
        ctx.ssl = wolfSSL_new(ctx.ssl_ctx);
        if (!ctx.ssl) {
            debug_print("MQTT: TLS session create failed\n");
            ctx.state = MQTT_STATE_ERROR;
            return -1;
        }

        /* Set SNI for hostname-based virtual hosting */
        wolfSSL_UseSNI(ctx.ssl, WOLFSSL_SNI_HOST_NAME, ctx.broker_ip,
            (word16)strlen(ctx.broker_ip));

        /* Set wolfIP socket I/O callbacks */
        wolfSSL_SetIO_wolfIP(ctx.ssl, ctx.socket_fd);

        debug_print("MQTT: TLS handshake...\n");
    }

    ret = wolfSSL_connect(ctx.ssl);
    if (ret == WOLFSSL_SUCCESS) {
        debug_print("MQTT: TLS connected\n");

        /* Replace net callbacks with TLS versions */
        ctx.net.read = mqtt_tls_read;
        ctx.net.write = mqtt_tls_write;

        ctx.state = MQTT_STATE_MQTT_CONNECT;
        return 0;
    }

    int err = wolfSSL_get_error(ctx.ssl, ret);
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
        return 0; /* Still handshaking */
    }

    debug_print("MQTT: TLS handshake failed\n");
    ctx.state = MQTT_STATE_ERROR;
    return -1;
}

/* Handle MQTT CONNECT state */
static int handle_mqtt_connect(void)
{
    int ret;
    static int connect_sent = 0;

    /* Set up MQTT connect parameters (only once) */
    if (!connect_sent) {
        memset(&ctx.connect, 0, sizeof(ctx.connect));
        ctx.connect.keep_alive_sec = ctx.keep_alive;
        ctx.connect.clean_session = 1;
        ctx.connect.client_id = ctx.client_id;
        connect_sent = 1;
        debug_print("MQTT: Sending CONNECT...\n");
    }

    ret = MqttClient_Connect(&ctx.client, &ctx.connect);

    if (ret == MQTT_CODE_SUCCESS) {
        debug_print("MQTT: Connected to broker\n");
        ctx.state = MQTT_STATE_CONNECTED;
        connect_sent = 0;
        return 0;
    }

    if (ret == MQTT_CODE_CONTINUE) {
        return 0; /* Still connecting */
    }

    debug_print("MQTT: CONNECT failed\n");
    ctx.state = MQTT_STATE_ERROR;
    connect_sent = 0;
    return -1;
}

/* Handle connected state - process pending publishes */
static int handle_connected(void)
{
    int ret;

    /* Check for pending publish */
    if (ctx.publish_pending) {
        memset(&ctx.publish, 0, sizeof(ctx.publish));
        ctx.publish.topic_name = ctx.publish_topic;
        ctx.publish.buffer = (byte *)ctx.publish_msg;
        ctx.publish.total_len = (word16)strlen(ctx.publish_msg);
        ctx.publish.qos = MQTT_QOS_0;

        ctx.state = MQTT_STATE_PUBLISHING;
    }

    /* Ping to keep connection alive handled by wolfMQTT internally */
    ret = MqttClient_WaitMessage(&ctx.client, 0);
    if (ret == MQTT_CODE_ERROR_TIMEOUT || ret == MQTT_CODE_CONTINUE) {
        return 0;
    }
    if (ret < 0 && ret != MQTT_CODE_ERROR_TIMEOUT) {
        debug_print("MQTT: Connection error\n");
        ctx.state = MQTT_STATE_ERROR;
        return -1;
    }

    return 0;
}

/* Handle publishing state */
static int handle_publishing(void)
{
    int ret;

    ret = MqttClient_Publish(&ctx.client, &ctx.publish);
    if (ret == MQTT_CODE_SUCCESS) {
        ctx.publish_pending = 0;
        ctx.state = MQTT_STATE_CONNECTED;
        return 0;
    }

    if (ret == MQTT_CODE_CONTINUE) {
        return 0; /* Still publishing */
    }

    debug_print("MQTT: Publish failed\n");
    ctx.publish_pending = 0;
    ctx.state = MQTT_STATE_ERROR;
    return -1;
}

/* Handle disconnecting state */
static int handle_disconnecting(void)
{
    int ret;

    ret = MqttClient_Disconnect(&ctx.client);
    if (ret == MQTT_CODE_SUCCESS || ret != MQTT_CODE_CONTINUE) {
        debug_print("MQTT: Disconnected\n");

        /* Clean up TLS */
        if (ctx.ssl) {
            wolfSSL_shutdown(ctx.ssl);
            wolfSSL_free(ctx.ssl);
            ctx.ssl = NULL;
        }

        /* Clean up socket */
        if (ctx.socket_fd >= 0) {
            wolfIP_sock_close(ctx.stack, ctx.socket_fd);
            ctx.socket_fd = -1;
        }

        ctx.state = MQTT_STATE_IDLE;
    }

    return 0;
}

int mqtt_client_poll(void)
{
    if (!ctx.initialized) {
        return -1;
    }

    switch (ctx.state) {
        case MQTT_STATE_IDLE:
            /* Nothing to do */
            break;

        case MQTT_STATE_NET_CONNECT:
            handle_net_connect();
            break;

        case MQTT_STATE_TLS_CONNECT:
            handle_tls_connect();
            break;

        case MQTT_STATE_MQTT_CONNECT:
            handle_mqtt_connect();
            break;

        case MQTT_STATE_CONNECTED:
            handle_connected();
            break;

        case MQTT_STATE_PUBLISHING:
            handle_publishing();
            break;

        case MQTT_STATE_DISCONNECTING:
            handle_disconnecting();
            break;

        case MQTT_STATE_ERROR:
            /* Clean up and return to idle */
            if (ctx.ssl) {
                wolfSSL_free(ctx.ssl);
                ctx.ssl = NULL;
            }
            if (ctx.socket_fd >= 0) {
                wolfIP_sock_close(ctx.stack, ctx.socket_fd);
                ctx.socket_fd = -1;
            }
            ctx.publish_pending = 0;
            ctx.state = MQTT_STATE_IDLE;
            break;

        default:
            break;
    }

    return 0;
}

int mqtt_client_publish(const char *message)
{
    if (!ctx.initialized) {
        return -1;
    }

    if (ctx.state != MQTT_STATE_CONNECTED) {
        return 1; /* Not connected, busy */
    }

    if (ctx.publish_pending) {
        return 1; /* Already publishing */
    }

    if (!message || strlen(message) >= sizeof(ctx.publish_msg)) {
        return -1;
    }

    strncpy(ctx.publish_msg, message, sizeof(ctx.publish_msg) - 1);
    ctx.publish_msg[sizeof(ctx.publish_msg) - 1] = '\0';
    ctx.publish_pending = 1;

    return 0;
}

int mqtt_client_is_connected(void)
{
    return (ctx.state == MQTT_STATE_CONNECTED ||
            ctx.state == MQTT_STATE_PUBLISHING);
}

int mqtt_client_disconnect(void)
{
    if (!ctx.initialized) {
        return -1;
    }

    if (ctx.state == MQTT_STATE_CONNECTED ||
        ctx.state == MQTT_STATE_PUBLISHING) {
        ctx.state = MQTT_STATE_DISCONNECTING;
    }

    return 0;
}

const char *mqtt_client_get_state_str(void)
{
    switch (ctx.state) {
        case MQTT_STATE_IDLE:           return "IDLE";
        case MQTT_STATE_NET_CONNECT:    return "NET_CONNECT";
        case MQTT_STATE_TLS_CONNECT:    return "TLS_CONNECT";
        case MQTT_STATE_MQTT_CONNECT:   return "MQTT_CONNECT";
        case MQTT_STATE_CONNECTED:      return "CONNECTED";
        case MQTT_STATE_PUBLISHING:     return "PUBLISHING";
        case MQTT_STATE_DISCONNECTING:  return "DISCONNECTING";
        case MQTT_STATE_ERROR:          return "ERROR";
        default:                        return "UNKNOWN";
    }
}

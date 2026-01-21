/* wolfmqtt_io.c
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
 * wolfIP <-> wolfMQTT glue for custom IO callbacks.
 */
#include "wolfip.h"
#include <wolfmqtt/mqtt_client.h>
#include <wolfmqtt/mqtt_socket.h>

#ifndef MAX_WOLFMQTT_CTX
    #define MAX_WOLFMQTT_CTX 2
#endif

/* I/O descriptor for wolfMQTT clients */
struct wolfmqtt_io_desc {
    struct wolfIP *stack;
    int fd;
    int in_use;
    int connected;
};

static struct wolfmqtt_io_desc io_descs[MAX_WOLFMQTT_CTX];

/* Find or allocate an I/O descriptor */
static struct wolfmqtt_io_desc *io_desc_alloc(void)
{
    for (int i = 0; i < MAX_WOLFMQTT_CTX; i++) {
        if (!io_descs[i].in_use) {
            io_descs[i].in_use = 1;
            io_descs[i].connected = 0;
            return &io_descs[i];
        }
    }
    return NULL;
}

/* Free an I/O descriptor */
static void io_desc_free(struct wolfmqtt_io_desc *desc)
{
    if (desc) {
        desc->stack = NULL;
        desc->fd = -1;
        desc->in_use = 0;
        desc->connected = 0;
    }
}

/* wolfMQTT network connect callback */
static int wolfmqtt_net_connect(void *context, const char *host, word16 port,
    int timeout_ms)
{
    struct wolfmqtt_io_desc *desc = (struct wolfmqtt_io_desc *)context;
    struct wolfIP_sockaddr_in addr;
    int ret;
    (void)timeout_ms;

    if (!desc || !desc->stack || !host) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Create TCP socket */
    desc->fd = wolfIP_sock_socket(desc->stack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (desc->fd < 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }

    /* Set up address */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(port);
    addr.sin_addr.s_addr = atoip4(host);

    /* Initiate non-blocking connect */
    ret = wolfIP_sock_connect(desc->stack, desc->fd,
        (struct wolfIP_sockaddr *)&addr, sizeof(addr));

    if (ret == 0) {
        desc->connected = 1;
        return MQTT_CODE_SUCCESS;
    }

    if (ret == -WOLFIP_EAGAIN || ret == -11) {
        return MQTT_CODE_CONTINUE;  /* EAGAIN/EINPROGRESS */
    }

    /* Connection failed */
    wolfIP_sock_close(desc->stack, desc->fd);
    desc->fd = -1;
    return MQTT_CODE_ERROR_NETWORK;
}

/* wolfMQTT network read callback */
static int wolfmqtt_net_read(void *context, byte *buf, int buf_len,
    int timeout_ms)
{
    struct wolfmqtt_io_desc *desc = (struct wolfmqtt_io_desc *)context;
    int ret;
    (void)timeout_ms;

    if (!desc || !desc->stack || desc->fd < 0 || !buf) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    ret = wolfIP_sock_recv(desc->stack, desc->fd, buf, buf_len, 0);
    if (ret == -WOLFIP_EAGAIN || ret == -1) {
        return MQTT_CODE_CONTINUE;
    }
    if (ret == 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }
    if (ret < 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }
    return ret;
}

/* wolfMQTT network write callback */
static int wolfmqtt_net_write(void *context, const byte *buf, int buf_len,
    int timeout_ms)
{
    struct wolfmqtt_io_desc *desc = (struct wolfmqtt_io_desc *)context;
    int ret;
    (void)timeout_ms;

    if (!desc || !desc->stack || desc->fd < 0 || !buf) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    ret = wolfIP_sock_send(desc->stack, desc->fd, buf, buf_len, 0);
    if (ret == -WOLFIP_EAGAIN || ret == -1) {
        return MQTT_CODE_CONTINUE;
    }
    if (ret == 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }
    if (ret < 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }
    return ret;
}

/* wolfMQTT network disconnect callback */
static int wolfmqtt_net_disconnect(void *context)
{
    struct wolfmqtt_io_desc *desc = (struct wolfmqtt_io_desc *)context;

    if (!desc) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (desc->fd >= 0 && desc->stack) {
        wolfIP_sock_close(desc->stack, desc->fd);
        desc->fd = -1;
    }
    desc->connected = 0;

    return MQTT_CODE_SUCCESS;
}

/* Set up wolfMQTT network callbacks for wolfIP (call once during init)
 * Returns the I/O context that should be set via MqttClient_SetContext() */
void *wolfMQTT_Init_wolfIP(MqttNet *net, struct wolfIP *stack)
{
    struct wolfmqtt_io_desc *desc;

    if (!net || !stack) {
        return NULL;
    }

    desc = io_desc_alloc();
    if (!desc) {
        return NULL;
    }

    desc->stack = stack;
    desc->fd = -1;

    /* Set callbacks */
    net->connect = wolfmqtt_net_connect;
    net->read = wolfmqtt_net_read;
    net->write = wolfmqtt_net_write;
    net->disconnect = wolfmqtt_net_disconnect;
    net->context = desc;

    return desc;
}

/* Clean up wolfMQTT I/O context */
void wolfMQTT_Cleanup_wolfIP(void *context)
{
    struct wolfmqtt_io_desc *desc = (struct wolfmqtt_io_desc *)context;

    if (desc) {
        if (desc->fd >= 0 && desc->stack) {
            wolfIP_sock_close(desc->stack, desc->fd);
        }
        io_desc_free(desc);
    }
}

/* Get the socket file descriptor (useful for TLS setup) */
int wolfMQTT_GetFd_wolfIP(void *context)
{
    struct wolfmqtt_io_desc *desc = (struct wolfmqtt_io_desc *)context;
    if (desc) {
        return desc->fd;
    }
    return -1;
}

/* Check if socket is connected */
int wolfMQTT_IsConnected_wolfIP(void *context)
{
    struct wolfmqtt_io_desc *desc = (struct wolfmqtt_io_desc *)context;
    if (desc) {
        return desc->connected;
    }
    return 0;
}

/* Set socket file descriptor (useful when socket created externally for TLS) */
void wolfMQTT_SetFd_wolfIP(void *context, int fd)
{
    struct wolfmqtt_io_desc *desc = (struct wolfmqtt_io_desc *)context;
    if (desc) {
        desc->fd = fd;
        desc->connected = (fd >= 0) ? 1 : 0;
    }
}

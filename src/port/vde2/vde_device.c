/* vde_device.c
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/random.h>
#include <libvdeplug.h>

#define WOLF_POSIX
#include "config.h"
#include "wolfip.h"
#undef WOLF_POSIX

#include "vde_device.h"

/* Static VDE connection */
static VDECONN *vde_conn = NULL;

/**
 * Poll for incoming packets (non-blocking)
 *
 * @param ll  Link-layer device structure
 * @param buf Buffer to receive packet data
 * @param len Maximum buffer length
 * @return Number of bytes received, 0 if no data, -1 on error
 */
static int vde_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct pollfd pfd;
    int ret;
    (void)ll;

    if (!vde_conn) {
        return -1;
    }

    /* Get VDE file descriptor */
    pfd.fd = vde_datafd(vde_conn);
    pfd.events = POLLIN;

    /* Keep ll polling non-blocking to avoid adding per-call sleep latency. */
    ret = poll(&pfd, 1, 0);
    if (ret < 0) {
        perror("vde_poll: poll");
        return -1;
    }

    if (ret == 0) {
        /* No data available */
        return 0;
    }

    /* Read packet from VDE */
    ret = vde_recv(vde_conn, buf, len, 0);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        perror("vde_poll: vde_recv");
        return -1;
    }

    return ret;
}

/**
 * Send packet through VDE connection
 *
 * @param ll  Link-layer device structure
 * @param buf Buffer containing packet data
 * @param len Packet length
 * @return Number of bytes sent on success, -1 on error
 */
static int vde_ll_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    ssize_t ret;
    (void)ll;

    if (!vde_conn) {
        return -1;
    }

    ret = vde_send(vde_conn, buf, len, 0);
    if (ret < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("vde_ll_send");
        }
        return -1;
    }

    return (int)ret;
}

/**
 * Generate a random MAC address
 *
 * @param mac Output buffer (6 bytes)
 */
static void generate_random_mac(uint8_t *mac)
{
    uint32_t rand1, rand2;

    /* Get random data */
    rand1 = wolfIP_getrandom();
    rand2 = wolfIP_getrandom();

    /* Set unicast, locally administered MAC */
    mac[0] = 0x02;  /* Locally administered, unicast */
    mac[1] = (rand1 >> 24) & 0xFF;
    mac[2] = (rand1 >> 16) & 0xFF;
    mac[3] = (rand1 >> 8) & 0xFF;
    mac[4] = rand1 & 0xFF;
    mac[5] = (rand2 >> 24) & 0xFF;
}

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
             const char *port, const uint8_t *mac)
{
    struct vde_open_args open_args = {
        .port = 0,
        .group = NULL,
        .mode = 0700
    };
    int fd;
    int flags;

    if (!ll || !socket_path) {
        fprintf(stderr, "vde_init: invalid arguments\n");
        return -1;
    }

    /* Parse port number if provided */
    if (port) {
        open_args.port = atoi(port);
    }

    /* Open VDE connection (cast away const - vde_open won't modify) */
    vde_conn = vde_open((char *)socket_path, (char *)"wolfip", &open_args);
    if (!vde_conn) {
        perror("vde_init: vde_open");
        fprintf(stderr, "Failed to connect to VDE switch at %s\n", socket_path);
        return -1;
    }

    /* Set socket to non-blocking mode */
    fd = vde_datafd(vde_conn);
    if (fd < 0) {
        fprintf(stderr, "vde_init: failed to get VDE file descriptor\n");
        vde_close(vde_conn);
        vde_conn = NULL;
        return -1;
    }

    flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            perror("vde_init: fcntl F_SETFL");
            vde_close(vde_conn);
            vde_conn = NULL;
            return -1;
        }
    } else {
        perror("vde_init: fcntl F_GETFL");
        vde_close(vde_conn);
        vde_conn = NULL;
        return -1;
    }

    /* Set up link-layer device structure */
    snprintf(ll->ifname, sizeof(ll->ifname), "vde");

    /* Set MAC address */
    if (mac) {
        memcpy(ll->mac, mac, 6);
    } else {
        generate_random_mac(ll->mac);
    }

    /* Set function pointers */
    ll->poll = vde_poll;
    ll->send = vde_ll_send;

    fprintf(stderr, "Successfully initialized VDE device\n");
    fprintf(stderr, "  Socket: %s\n", socket_path);
    fprintf(stderr, "  Port: %d\n", open_args.port);
    fprintf(stderr, "  MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ll->mac[0], ll->mac[1], ll->mac[2],
           ll->mac[3], ll->mac[4], ll->mac[5]);

    return 0;
}

/**
 * Cleanup VDE connection
 */
void vde_cleanup(void)
{
    if (vde_conn) {
        vde_close(vde_conn);
        vde_conn = NULL;
        fprintf(stderr, "VDE connection closed\n");
    }
}

/**
 * Get random number for wolfIP (used for MAC generation)
 */
uint32_t wolfIP_getrandom(void)
{
    uint32_t ret;
    getrandom(&ret, sizeof(ret), 0);
    return ret;
}

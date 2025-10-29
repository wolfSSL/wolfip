/* linux_tap.c
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
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
/* tap device */
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <sys/poll.h>
#include <string.h>
#include "wolfip.h"
#include <netinet/in.h>
#include <arpa/inet.h>

static int tap_fd;

#ifdef DEBUG_TAP
void print_buffer(const char * what, uint8_t *buf, int len)
{
    int i;
    printf("%s (%d): ", what, len);
    for (i = 0; i < len; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
    printf("\n");
}
#endif /* DEBUG_TAP */

static int tap_poll(struct ll *ll, void *buf, uint32_t len)
{
    struct pollfd pfd;
    (void)ll;
    int ret;
    ssize_t n_read = 0;
    pfd.fd = tap_fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, 2);
    if (ret < 0) {
        perror("poll");
        return -1;
    }
    if (ret == 0) {
        return 0;
    }

    n_read = read(tap_fd, buf, len);

    #ifdef DEBUG_TAP
    if (n_read > 0) {
        print_buffer("tap_poll", buf, n_read);
    }
    #endif /* DEBUG_TAP */

    return n_read;
}

static int tap_send(struct ll *ll, void *buf, uint32_t len)
{
    (void)ll;
    #ifdef DEBUG_TAP
    print_buffer("tap_send", buf, len);
    #endif /* DEBUG_TAP */
    return write(tap_fd, buf, len);
}

int tap_init(struct ll *ll, const char *ifname, uint32_t host_ip)
{
    struct ifreq ifr;
    struct sockaddr_in *addr;
    int sock_fd;

    if ((tap_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("accessing /dev/net/tun");
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(tap_fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl TUNSETIFF");
        close(tap_fd);
        return -1;
    }

    /* Get mac address */
    if (ioctl(tap_fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(tap_fd);
        return -1;
    }
    strncpy(ll->ifname, ifname, sizeof(ll->ifname) - 1);
    memcpy(ll->mac, ifr.ifr_hwaddr.sa_data, 6);
    ll->mac[5] ^= 1;
    ll->poll = tap_poll;
    ll->send = tap_send;

    /* Set up network side */
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        close(tap_fd);
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        close(sock_fd);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        close(sock_fd);
        return -1;
    }
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = host_ip;
    if (ioctl(sock_fd, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl SIOCSIFADDR");
        close(sock_fd);
        return -1;
    }
    inet_pton(AF_INET, "255.255.255.0", &addr->sin_addr);
    if (ioctl(sock_fd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCSIFNETMASK");
        close(sock_fd);
        return -1;
    }
    if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        close(sock_fd);
        return -1;
    }
    ifr.ifr_flags = IFF_UP | IFF_RUNNING;
    if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        close(sock_fd);
        return -1;
    }
    printf("Successfully initialized tap device %s\n", ifname);
    return 0;
}

#include <sys/random.h>
uint32_t wolfIP_getrandom(void)
{
    uint32_t ret;
    getrandom(&ret, sizeof(ret), 0);
    return ret;
}

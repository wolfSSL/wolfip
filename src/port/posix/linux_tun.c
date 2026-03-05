/* linux_tun.c
 *
 * Linux TUN (L3) interface for wolfIP.
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
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define WOLF_POSIX
#include "config.h"
#include "wolfip.h"
#undef WOLF_POSIX

static int tun_fd = -1;

static int tun_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct pollfd pfd;
    int ret;
    (void)ll;
    if (tun_fd < 0)
        return -1;
    pfd.fd = tun_fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, 2);
    if (ret < 0) {
        perror("poll");
        return -1;
    }
    if (ret == 0)
        return 0;
    return read(tun_fd, buf, len);
}

static int tun_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    if (tun_fd < 0)
        return -1;
    return write(tun_fd, buf, len);
}

static int tun_add_host_route(const char *ifname, uint32_t peer_ip)
{
    char peer_str[INET_ADDRSTRLEN];
    char cmd[256];
    struct in_addr peer = { .s_addr = peer_ip };
    if (!inet_ntop(AF_INET, &peer, peer_str, sizeof(peer_str)))
        return -1;
    snprintf(cmd, sizeof(cmd), "ip route replace %s/32 dev %s >/dev/null 2>&1",
             peer_str, ifname);
    if (system(cmd) == 0)
        return 0;
    snprintf(cmd, sizeof(cmd), "route add -host %s dev %s >/dev/null 2>&1",
             peer_str, ifname);
    return (system(cmd) == 0) ? 0 : -1;
}

int tun_init(struct wolfIP_ll_dev *ll, const char *ifname,
             uint32_t host_ip, uint32_t peer_ip)
{
    struct ifreq ifr;
    struct sockaddr_in *addr;
    int sock_fd;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd < 0 || ioctl(tun_fd, TUNSETIFF, (void *)&ifr) != 0) {
        perror("ioctl TUNSETIFF");
        if (tun_fd >= 0) {
            close(tun_fd);
            tun_fd = -1;
        }
        return -1;
    }
    {
        int flags = fcntl(tun_fd, F_GETFL, 0);
        if (flags >= 0)
            (void)fcntl(tun_fd, F_SETFL, flags | O_NONBLOCK);
    }

    if (ll) {
        memset(ll->mac, 0, sizeof(ll->mac));
        strncpy(ll->ifname, ifname, sizeof(ll->ifname) - 1);
        ll->ifname[sizeof(ll->ifname) - 1] = '\0';
        ll->non_ethernet = 1;
        ll->poll = tun_poll;
        ll->send = tun_send;
    }

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        close(tun_fd);
        tun_fd = -1;
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        close(sock_fd);
        return -1;
    }
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING | IFF_POINTOPOINT);
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

    addr = (struct sockaddr_in *)&ifr.ifr_dstaddr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = peer_ip;
    if (ioctl(sock_fd, SIOCSIFDSTADDR, &ifr) < 0) {
        perror("ioctl SIOCSIFDSTADDR");
        close(sock_fd);
        return -1;
    }

    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(0xFFFFFFFFU);
    if (ioctl(sock_fd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCSIFNETMASK");
        close(sock_fd);
        return -1;
    }

    (void)tun_add_host_route(ifname, peer_ip);
    printf("Successfully initialized tun device %s\n", ifname);
    close(sock_fd);
    return 0;
}

/* tap_freebsd.c
 *
 * FreeBSD TAP integration for wolfIP POSIX examples.
 *
 * Copyright (C) 2025 wolfSSL Inc.
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
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_tap.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define WOLF_POSIX
#include "config.h"
#include "wolfip.h"
#undef WOLF_POSIX

static int tap_fd = -1;

static int tap_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct pollfd pfd;
    int ret;
    (void)ll;

    pfd.fd = tap_fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, 2);
    if (ret < 0) {
        perror("poll");
        return -1;
    }
    if (ret == 0)
        return 0;
    return (int)read(tap_fd, buf, len);
}

static int tap_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    return (int)write(tap_fd, buf, len);
}

static int tap_set_ipv4(int sock_fd, const char *ifname, uint32_t host_ip)
{
    struct ifreq ifr;
    struct ifaliasreq ifra;
    struct sockaddr_in *sin;
    uint32_t mask_host = 0xFFFFFF00U;
    uint32_t addr_host = ntohl(host_ip);
    uint32_t broad_host = (addr_host & mask_host) | (~mask_host);
    uint32_t mask_net = htonl(mask_host);
    uint32_t broad_net = htonl(broad_host);

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        return -1;
    }
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        return -1;
    }

    memset(&ifra, 0, sizeof(ifra));
    strlcpy(ifra.ifra_name, ifname, sizeof(ifra.ifra_name));

    sin = (struct sockaddr_in *)&ifra.ifra_addr;
    memset(sin, 0, sizeof(*sin));
    sin->sin_len = sizeof(*sin);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = host_ip;

    sin = (struct sockaddr_in *)&ifra.ifra_mask;
    memset(sin, 0, sizeof(*sin));
    sin->sin_len = sizeof(*sin);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = mask_net;

    sin = (struct sockaddr_in *)&ifra.ifra_broadaddr;
    memset(sin, 0, sizeof(*sin));
    sin->sin_len = sizeof(*sin);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = broad_net;

    if (ioctl(sock_fd, SIOCAIFADDR, &ifra) < 0) {
        perror("ioctl SIOCAIFADDR");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        return -1;
    }
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        return -1;
    }
    return 0;
}

static void tap_fetch_mac(struct wolfIP_ll_dev *ll)
{
    struct ifaddrs *ifas = NULL;

    if (getifaddrs(&ifas) != 0)
        return;

    for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
        struct sockaddr_dl *sdl;
        size_t alen;

        if (!ifa->ifa_addr)
            continue;
        if (ifa->ifa_addr->sa_family != AF_LINK)
            continue;
        if (strcmp(ifa->ifa_name, ll->ifname) != 0)
            continue;

        sdl = (struct sockaddr_dl *)ifa->ifa_addr;
        alen = sdl->sdl_alen;
        if (alen > sizeof(ll->mac))
            alen = sizeof(ll->mac);
        memcpy(ll->mac, LLADDR(sdl), alen);
        if (alen < sizeof(ll->mac))
            memset(ll->mac + alen, 0, sizeof(ll->mac) - alen);
        if (alen > 0)
            ll->mac[alen - 1] ^= 1;
        break;
    }

    freeifaddrs(ifas);
}

int tap_init(struct wolfIP_ll_dev *ll, const char *ifname, uint32_t host_ip)
{
    char devpath[PATH_MAX];
    struct ifreq ifr;
    int sock_fd;
    const char *final_ifname = ifname;
    int auto_name = 0;

    if (ifname && ifname[0] != '\0') {
        snprintf(devpath, sizeof(devpath), "/dev/%s", ifname);
    } else {
        snprintf(devpath, sizeof(devpath), "/dev/tap");
        auto_name = 1;
    }

    tap_fd = open(devpath, O_RDWR);
    if (tap_fd < 0 && ifname && ifname[0] != '\0') {
        snprintf(devpath, sizeof(devpath), "/dev/tap");
        tap_fd = open(devpath, O_RDWR);
        auto_name = 1;
    }
    if (tap_fd < 0) {
        perror("open tap device");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    if (auto_name) {
#ifdef TAPGIFNAME
        if (ioctl(tap_fd, TAPGIFNAME, (void *)&ifr) < 0) {
            perror("ioctl TAPGIFNAME");
            close(tap_fd);
            tap_fd = -1;
            return -1;
        }
        final_ifname = ifr.ifr_name;
#else
        final_ifname = "tap0";
#endif
    } else {
        strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    }

    strlcpy(ll->ifname, final_ifname, sizeof(ll->ifname));
    ll->poll = tap_poll;
    ll->send = tap_send;

    memset(ll->mac, 0, sizeof(ll->mac));
    tap_fetch_mac(ll);

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        close(tap_fd);
        tap_fd = -1;
        return -1;
    }

    if (tap_set_ipv4(sock_fd, ll->ifname, host_ip) < 0) {
        close(sock_fd);
        close(tap_fd);
        tap_fd = -1;
        return -1;
    }

    close(sock_fd);
    printf("Successfully initialized tap device %s\n", ll->ifname);
    return 0;
}

uint32_t wolfIP_getrandom(void)
{
    uint32_t val;
    arc4random_buf(&val, sizeof(val));
    return val;
}

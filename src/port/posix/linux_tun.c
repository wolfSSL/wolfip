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
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

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

static int nl_addattr(struct nlmsghdr *nlh, size_t maxlen, int type,
                      const void *data, size_t alen)
{
    size_t len = RTA_LENGTH(alen);
    struct rtattr *rta;
    size_t newlen = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(len);

    if (newlen > maxlen)
        return -1;
    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = (unsigned short)len;
    if (alen > 0 && data)
        memcpy(RTA_DATA(rta), data, alen);
    nlh->nlmsg_len = (unsigned int)newlen;
    return 0;
}

static int tun_add_host_route(const char *ifname, uint32_t peer_ip)
{
    int fd;
    int ifindex;
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char buf[128];
    } req;
    struct sockaddr_nl nladdr;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
        return -1;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_NEWROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
    req.nlh.nlmsg_seq = 1;
    req.rtm.rtm_family = AF_INET;
    req.rtm.rtm_dst_len = 32;
    req.rtm.rtm_table = RT_TABLE_MAIN;
    req.rtm.rtm_protocol = RTPROT_BOOT;
    req.rtm.rtm_scope = RT_SCOPE_LINK;
    req.rtm.rtm_type = RTN_UNICAST;

    if (nl_addattr(&req.nlh, sizeof(req), RTA_DST, &peer_ip, sizeof(peer_ip)) < 0)
        return -1;
    if (nl_addattr(&req.nlh, sizeof(req), RTA_OIF, &ifindex, sizeof(ifindex)) < 0)
        return -1;

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0)
        return -1;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    if (sendto(fd, &req, req.nlh.nlmsg_len, 0,
               (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
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
        close(tun_fd);
        tun_fd = -1;
        return -1;
    }
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING | IFF_POINTOPOINT);
    if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        close(sock_fd);
        close(tun_fd);
        tun_fd = -1;
        return -1;
    }

    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = host_ip;
    if (ioctl(sock_fd, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl SIOCSIFADDR");
        close(sock_fd);
        close(tun_fd);
        tun_fd = -1;
        return -1;
    }

    addr = (struct sockaddr_in *)&ifr.ifr_dstaddr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = peer_ip;
    if (ioctl(sock_fd, SIOCSIFDSTADDR, &ifr) < 0) {
        perror("ioctl SIOCSIFDSTADDR");
        close(sock_fd);
        close(tun_fd);
        tun_fd = -1;
        return -1;
    }

    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(0xFFFFFFFFU);
    if (ioctl(sock_fd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCSIFNETMASK");
        close(sock_fd);
        close(tun_fd);
        tun_fd = -1;
        return -1;
    }

    (void)tun_add_host_route(ifname, peer_ip);
    printf("Successfully initialized tun device %s\n", ifname);
    close(sock_fd);
    return 0;
}

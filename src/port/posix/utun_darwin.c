/* utun_darwin.c
 *
 * User-space utun (L3) point-to-point interface for macOS.
 *
 * A utun device is a native Layer-3 point-to-point link: it carries IP
 * packets prefixed with a 4-byte address family field and needs no ARP.
 * The link is therefore registered as non-ethernet: wolfIP supplies the
 * dummy link header on receive (poll_devices) and strips it on transmit
 * (wolfIP_ll_send_frame), and skips ARP for this interface entirely. This
 * is the same driver contract as the Linux TUN driver (linux_tun.c),
 * without the in-process ARP reply simulation the old tap_darwin.c
 * needed to fake an Ethernet link.
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
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#define WOLF_POSIX
#include "config.h"
#include "wolfip.h"
#undef WOLF_POSIX

/* utun packets are prefixed with a 4-byte address family field */
#define UTUN_AF_HDR_SIZE 4

static int utun_fd = -1;

/* Receive one IP packet into buf (the non-ethernet LL contract: the
 * dummy link header has already been zeroed before buf by the stack). */
static int utun_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct pollfd pfd;
    uint8_t tmp[LINK_MTU + UTUN_AF_HDR_SIZE];
    uint32_t af;
    uint32_t ip_len;
    ssize_t n;
    (void)ll;

    if (utun_fd < 0)
        return -1;

    pfd.fd = utun_fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, 0) <= 0)
        return 0;

    n = read(utun_fd, tmp, sizeof(tmp));
    if (n < 0)
        return (int)n;
    if (n <= (ssize_t)UTUN_AF_HDR_SIZE)
        return 0;

    memcpy(&af, tmp, UTUN_AF_HDR_SIZE);
    if (af != (uint32_t)htonl(AF_INET))
        return 0;

    ip_len = (uint32_t)(n - UTUN_AF_HDR_SIZE);
    if (ip_len > len)
        ip_len = len;
    memcpy(buf, tmp + UTUN_AF_HDR_SIZE, ip_len);
    return (int)ip_len;
}

/* Send one IP packet (buf is the IP payload; the dummy link header has
 * already been stripped by the stack). Single write so the AF prefix and
 * the packet reach utun as one datagram. */
static int utun_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    uint8_t tmp[UTUN_AF_HDR_SIZE + LINK_MTU];
    uint32_t af;
    (void)ll;

    if (utun_fd < 0)
        return -1;
    if (len > sizeof(tmp) - UTUN_AF_HDR_SIZE)
        return -1;

    af = htonl(AF_INET);
    memcpy(tmp, &af, UTUN_AF_HDR_SIZE);
    memcpy(tmp + UTUN_AF_HDR_SIZE, buf, len);
    if (write(utun_fd, tmp, len + UTUN_AF_HDR_SIZE) < 0)
        return -1;
    return (int)len;
}

static int utun_setup_ipv4(const char *ifname, uint32_t host_ip, uint32_t peer_ip)
{
    char cmd[256];
    char local_str[INET_ADDRSTRLEN];
    char peer_str[INET_ADDRSTRLEN];
    char netmask_str[INET_ADDRSTRLEN];
    struct in_addr local = { .s_addr = host_ip };
    struct in_addr peer = { .s_addr = peer_ip };
    struct in_addr netmask = { .s_addr = 0x00ffffff };

    if (!inet_ntop(AF_INET, &local, local_str, sizeof(local_str)))
        return -1;
    if (!inet_ntop(AF_INET, &peer, peer_str, sizeof(peer_str)))
        return -1;
    if (!inet_ntop(AF_INET, &netmask, netmask_str, sizeof(netmask_str)))
        return -1;

    printf("utun_setup_ipv4: ifname=%s local=%s peer=%s\n", ifname, local_str,
           peer_str);

    snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s inet %s %s netmask %s up",
            ifname, local_str, peer_str, netmask_str);
    if (system(cmd) != 0)
        return -1;

    snprintf(cmd, sizeof(cmd), "/sbin/route -n add -host %s -interface %s >/dev/null 2>&1",
            peer_str, ifname);
    system(cmd);

    return 0;
}

int tap_get_fd(void)
{
    return utun_fd;
}

int tap_init(struct wolfIP_ll_dev *ll, const char *requested_ifname, uint32_t host_ip)
{
    struct ctl_info info;
    struct sockaddr_ctl sc;
    char ifname_buf[IFNAMSIZ];
    socklen_t optlen;
    uint32_t peer_ip = htonl(atoip4(WOLFIP_IP));
    (void)requested_ifname;

    printf("utun_init: host_ip=0x%08x peer_ip=0x%08x\n", (unsigned)host_ip,
           (unsigned)peer_ip);

    utun_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (utun_fd < 0) {
        perror("socket utun");
        return -1;
    }

    memset(&info, 0, sizeof(info));
    strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
    if (ioctl(utun_fd, CTLIOCGINFO, &info) < 0) {
        perror("ioctl CTLIOCGINFO");
        close(utun_fd);
        utun_fd = -1;
        return -1;
    }

    memset(&sc, 0, sizeof(sc));
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_id = info.ctl_id;
    sc.sc_unit = 0;

    if (connect(utun_fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
        perror("connect utun");
        close(utun_fd);
        utun_fd = -1;
        return -1;
    }

    optlen = sizeof(ifname_buf);
    if (getsockopt(utun_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
                ifname_buf, &optlen) < 0) {
        perror("getsockopt UTUN_OPT_IFNAME");
        close(utun_fd);
        utun_fd = -1;
        return -1;
    }
    ifname_buf[IFNAMSIZ - 1] = '\0';

    fcntl(utun_fd, F_SETFL, O_NONBLOCK);

    memset(ll->mac, 0, sizeof(ll->mac));
    ll->poll = utun_poll;
    ll->send = utun_send;
    ll->non_ethernet = 1;
    strlcpy(ll->ifname, ifname_buf, sizeof(ll->ifname));

    if (utun_setup_ipv4(ifname_buf, host_ip, peer_ip) != 0) {
        close(utun_fd);
        utun_fd = -1;
        return -1;
    }

    return 0;
}

uint32_t wolfIP_getrandom(void)
{
    return arc4random();
}

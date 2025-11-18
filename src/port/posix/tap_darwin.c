/* tap_darwin.c
 *
 * User-space TAP implementation for macOS using utun (L3) interfaces. The code
 * synthesizes an Ethernet header around IP packets so the rest of wolfIP can
 * continue operating on Ethernet frames.
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
#include <net/if_dl.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
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

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif
#ifndef ETH_P_IP
#define ETH_P_IP ETHERTYPE_IP
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif

#define PACKED __attribute__((packed))
#define AF_HDR_SIZE 4

struct eth_hdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
} PACKED;

static int utun_fd = -1;
static uint8_t peer_mac[6] = {0x06, 0x00, 0x00, 0x00, 0x00, 0x01};
static pthread_mutex_t utun_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t pending_frame[LINK_MTU + sizeof(struct eth_hdr)];
static size_t pending_len = 0;
static pthread_mutex_t pending_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t host_ip_be;
static uint32_t peer_ip_be;

struct arp_packet {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sha[6];
    uint32_t spa;
    uint8_t tha[6];
    uint32_t tpa;
} PACKED;

static int enqueue_frame(const void *frame, size_t len)
{
    if (len > sizeof(pending_frame))
        return -1;
    pthread_mutex_lock(&pending_lock);
    memcpy(pending_frame, frame, len);
    pending_len = len;
    pthread_mutex_unlock(&pending_lock);
    return 0;
}

static int tap_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct pollfd pfd;
    uint8_t tmp[LINK_MTU + AF_HDR_SIZE];
    ssize_t n;
    size_t ip_len;
    struct eth_hdr *eth;

    if (utun_fd < 0)
        return -1;

    pthread_mutex_lock(&pending_lock);
    if (pending_len > 0) {
        size_t to_copy = pending_len;
        if (to_copy > len)
            to_copy = len;
        memcpy(buf, pending_frame, to_copy);
        pending_len = 0;
        pthread_mutex_unlock(&pending_lock);
        return (int)to_copy;
    }
    pthread_mutex_unlock(&pending_lock);

    pfd.fd = utun_fd;
    pfd.events = POLLIN;

    if (poll(&pfd, 1, 2) <= 0)
        return 0;

    pthread_mutex_lock(&utun_lock);
    n = read(utun_fd, tmp, sizeof(tmp));
    pthread_mutex_unlock(&utun_lock);

    if (n <= 0)
        return (int)n;
    if (n <= AF_HDR_SIZE)
        return 0;

    ip_len = (size_t)(n - AF_HDR_SIZE);
    if (sizeof(struct eth_hdr) + ip_len > len)
        ip_len = len - sizeof(struct eth_hdr);

    eth = (struct eth_hdr *)buf;
    memcpy(eth->dst, ll->mac, 6);
    memcpy(eth->src, peer_mac, 6);
    eth->type = htons(ETH_P_IP);
    memcpy(((uint8_t *)eth) + sizeof(struct eth_hdr), tmp + AF_HDR_SIZE, ip_len);
    return (int)(sizeof(struct eth_hdr) + ip_len);
}

static int tap_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    uint8_t tmp[LINK_MTU + AF_HDR_SIZE];
    struct eth_hdr *eth;
    size_t ip_len;
    struct arp_packet *arp;
    uint32_t af;
    (void)ll;

    if (utun_fd < 0)
        return -1;
    if (len < sizeof(struct eth_hdr))
        return 0;
    eth = (struct eth_hdr *)buf;
    if (ntohs(eth->type) == ETHERTYPE_ARP) {
        if (len < sizeof(struct eth_hdr) + sizeof(struct arp_packet))
            return (int)len;
        arp = (struct arp_packet *)(eth + 1);
        if (ntohs(arp->opcode) == 1 /* request */ &&
            arp->tpa == host_ip_be) {
            struct {
                struct eth_hdr eth;
                struct arp_packet arp;
            } PACKED reply;
            memset(&reply, 0, sizeof(reply));
            memcpy(reply.eth.dst, eth->src, sizeof(reply.eth.dst));
            memcpy(reply.eth.src, peer_mac, sizeof(reply.eth.src));
            reply.eth.type = htons(ETHERTYPE_ARP);
            reply.arp.htype = htons(1);
            reply.arp.ptype = htons(ETHERTYPE_IP);
            reply.arp.hlen = 6;
            reply.arp.plen = 4;
            reply.arp.opcode = htons(2);
            memcpy(reply.arp.sha, peer_mac, sizeof(reply.arp.sha));
            reply.arp.spa = host_ip_be;
            memcpy(reply.arp.tha, arp->sha, sizeof(reply.arp.tha));
            reply.arp.tpa = arp->spa;
            printf("tap_darwin: answering ARP request locally\n");
            enqueue_frame(&reply, sizeof(reply));
            return (int)len;
        }
        return (int)len;
    }
    if (ntohs(eth->type) != ETH_P_IP)
        return (int)len;

    ip_len = len - sizeof(struct eth_hdr);
    if (ip_len + AF_HDR_SIZE > sizeof(tmp))
        return -1;

    af = htonl(AF_INET);
    memcpy(tmp, &af, AF_HDR_SIZE);
    memcpy(tmp + AF_HDR_SIZE, ((uint8_t *)eth) + sizeof(struct eth_hdr), ip_len);

    pthread_mutex_lock(&utun_lock);
    if (write(utun_fd, tmp, ip_len + AF_HDR_SIZE) < 0) {
        pthread_mutex_unlock(&utun_lock);
        return -1;
    }
    pthread_mutex_unlock(&utun_lock);
    return (int)len;
}

static int tap_setup_ipv4(const char *ifname, uint32_t host_ip, uint32_t peer_ip)
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

    printf("tap_setup_ipv4: ifname=%s local=%s peer=%s\n", ifname, local_str, peer_str);

    snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s inet %s %s netmask %s up",
            ifname, local_str, peer_str, netmask_str);
    if (system(cmd) != 0)
        return -1;

    snprintf(cmd, sizeof(cmd), "/sbin/route -n add -host %s -interface %s >/dev/null 2>&1",
            peer_str, ifname);
    system(cmd);

    return 0;
}

int tap_init(struct wolfIP_ll_dev *ll, const char *requested_ifname, uint32_t host_ip)
{
    struct ctl_info info;
    struct sockaddr_ctl sc;
    char ifname_buf[IFNAMSIZ];
    socklen_t optlen;
    uint32_t peer_ip = htonl(atoip4(WOLFIP_IP));
    host_ip_be = host_ip;
    peer_ip_be = peer_ip;
    printf("tap_init: host_ip=0x%08x peer_ip=0x%08x\n", host_ip_be, peer_ip_be);
    (void)requested_ifname;

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

    memcpy(ll->mac, (uint8_t[]){0x02, 0x00, 0x00, 0x00, 0x00, 0x02}, 6);
    ll->poll = tap_poll;
    ll->send = tap_send;
    strlcpy(ll->ifname, ifname_buf, sizeof(ll->ifname));

    if (tap_setup_ipv4(ifname_buf, host_ip, peer_ip) != 0) {
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

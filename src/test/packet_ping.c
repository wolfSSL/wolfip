/*
 * packet_ping.c
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
 *
 * Very simplified ping-like utility using:
 *   socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))
 *
 * Sends 3 ICMP echo requests of 64 bytes (8B header + 56B data)
 * to the host given, via the specified interface.
 *
 * Needs root or CAP_NET_RAW.
 *
 * Usage:
 *   packet_raw_ping <iface> <host>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <net/if_arp.h>

#define NUM_PINGS_PACKET  3
#define NUM_PINGS_INET    2

#define ICMP_DATA_SIZE    56
#define ICMP_HEADER_SIZE  (sizeof(struct icmphdr))
#define ICMP_PACKET_SIZE  (ICMP_HEADER_SIZE + ICMP_DATA_SIZE)

#define IP_HEADER_SIZE    (sizeof(struct iphdr))
#define IP_PACKET_SIZE    (IP_HEADER_SIZE + ICMP_PACKET_SIZE)

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

#define ETH_FRAME_SIZE    (ETH_HLEN + IP_PACKET_SIZE)
#define RECV_BUF_SIZE     2048

#ifndef ETH_P_IP
/* Fallback if ETH_P_IP is not defined */
#define ETH_P_IP 0x0800
#endif

static unsigned short checksum(void *b, int len)
{
    unsigned short *buf;
    unsigned int sum;
    unsigned short result;

    buf = (unsigned short *)b;
    sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = (unsigned short)~sum;

    return result;
}

/* Get interface index, MAC address and IPv4 address */
static int get_iface_info(const char *ifname,
                          int *ifindex,
                          unsigned char *mac,
                          struct in_addr *ip)
{
    int fd;
    struct ifreq ifr;
    struct sockaddr_in *sin;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket(AF_INET,SOCK_DGRAM)");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    /* Get index */
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl(SIOCGIFINDEX)");
        close(fd);
        return -1;
    }
    *ifindex = ifr.ifr_ifindex;

    /* Get MAC address */
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(fd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    /* Get IPv4 address */
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl(SIOCGIFADDR)");
        close(fd);
        return -1;
    }
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip = sin->sin_addr;

    close(fd);
    return 0;
}

/* Build an IPv4 + ICMP echo request packet */
static void build_icmp_packet(char *buf, size_t buflen,
                              struct in_addr src_ip,
                              struct in_addr dst_ip,
                              uint16_t ident,
                              uint16_t seq)
{
    struct iphdr *ip = (struct iphdr *)buf;
    struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(struct iphdr));
    unsigned char *data = (unsigned char *)(icmp + 1);
    int icmp_len = (int)ICMP_PACKET_SIZE;

    memset(buf, 0, buflen);

    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(ident);
    icmp->un.echo.sequence = htons(seq);
    memset(data, 0xAB, ICMP_DATA_SIZE);

    icmp->checksum = 0;
    icmp->checksum = checksum(icmp, icmp_len);

    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(IP_PACKET_SIZE);
    ip->id = htons(seq);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;
    ip->saddr = src_ip.s_addr;
    ip->daddr = dst_ip.s_addr;
    ip->check = checksum(ip, IP_HEADER_SIZE);
}

int main(int argc, char *argv[])
{
    int sockfd;
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    const char *host;
    const char *iface;

    unsigned char if_mac[ETH_ALEN];
    struct in_addr if_ip;
    int ifindex;
    pid_t pid;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <iface> <host>\n", argv[0]);
        return 1;
    }

    iface = argv[1];
    host = argv[2];

    if (get_iface_info(iface, &ifindex, if_mac, &if_ip) < 0) {
        fprintf(stderr, "Failed to get iface info.\n");
        return 1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    if (getaddrinfo(host, NULL, &hints, &res) != 0) {
        perror("getaddrinfo");
        return 1;
    }

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sockfd < 0) {
        perror("socket(AF_PACKET)");
        freeaddrinfo(res);
        return 1;
    }

    printf("PACKET PING %s (%s) on iface %s\n", host,
           inet_ntoa(((struct sockaddr_in *)res->ai_addr)->sin_addr), iface);

    pid = getpid() & 0xFFFF;

    for (int i = 1; i <= NUM_PINGS_PACKET; i++) {
        char sendbuf[ETH_FRAME_SIZE];
        struct ethhdr *eth = (struct ethhdr *)sendbuf;
        char ip_icmp[IP_PACKET_SIZE];
        struct sockaddr_ll addr = {0};

        /* Build IP+ICMP */
        build_icmp_packet(ip_icmp, sizeof(ip_icmp),
                          if_ip,
                          ((struct sockaddr_in *)res->ai_addr)->sin_addr,
                          (uint16_t)pid, (uint16_t)i);

        /* Eth header */
        memset(sendbuf, 0, sizeof(sendbuf));
        memset(eth->h_dest, 0xFF, ETH_ALEN); /* broadcast for simplicity */
        memcpy(eth->h_source, if_mac, ETH_ALEN);
        eth->h_proto = htons(ETH_P_IP);

        /* Copy IP+ICMP */
        memcpy(sendbuf + ETH_HLEN, ip_icmp, IP_PACKET_SIZE);

        addr.sll_family = AF_PACKET;
        addr.sll_protocol = htons(ETH_P_IP);
        addr.sll_ifindex = ifindex;
        addr.sll_halen = ETH_ALEN;
        memset(addr.sll_addr, 0xFF, ETH_ALEN);

        if (sendto(sockfd, sendbuf, ETH_FRAME_SIZE, 0,
                   (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("sendto");
            continue;
        }

        /* Receive */
        {
            char recvbuf[RECV_BUF_SIZE];
            ssize_t n;
            struct sockaddr_ll from;
            socklen_t fromlen = sizeof(from);
            struct ethhdr *reth;
            struct iphdr *riph;
            struct icmphdr *ricmp;

            n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0,
                         (struct sockaddr *)&from, &fromlen);
            if (n < 0) {
                perror("recvfrom");
                continue;
            }

            if ((size_t)n < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr))
                continue;

            reth = (struct ethhdr *)recvbuf;
            if (ntohs(reth->h_proto) != ETH_P_IP)
                continue;

            riph = (struct iphdr *)(recvbuf + ETH_HLEN);
            if (riph->protocol != IPPROTO_ICMP)
                continue;

            ricmp = (struct icmphdr *)(recvbuf + ETH_HLEN + (riph->ihl * 4));
            if (ricmp->type == ICMP_ECHOREPLY &&
                ntohs(ricmp->un.echo.id) == (uint16_t)pid) {
                printf("Reply from %s: icmp_seq=%d\n",
                       inet_ntoa(((struct sockaddr_in *)res->ai_addr)->sin_addr), i);
            }
        }

        sleep(1);
    }

    freeaddrinfo(res);
    close(sockfd);
    return 0;
}

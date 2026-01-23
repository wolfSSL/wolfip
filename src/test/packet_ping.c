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
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close(fd);
        return -1;
    }
    *ifindex = ifr.ifr_ifindex;

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(fd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(fd);
        return -1;
    }
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip = sin->sin_addr;

    close(fd);
    return 0;
}

/* Query MAC via SIOCGARP (wolfIP ioctl will serve from its ARP table) */
static int get_dest_mac_via_ioctl(const char *ifname, const struct in_addr *ip, unsigned char *mac)
{
    int fd;
    struct arpreq ar;
    struct sockaddr_in *pa;
    int ret = -1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket(AF_INET,SOCK_DGRAM) for ARP");
        return -1;
    }
    memset(&ar, 0, sizeof(ar));
    pa = (struct sockaddr_in *)&ar.arp_pa;
    pa->sin_family = AF_INET;
    pa->sin_addr = *ip;
    strncpy(ar.arp_dev, ifname, sizeof(ar.arp_dev) - 1);
    ar.arp_dev[sizeof(ar.arp_dev) - 1] = '\0';

    if (ioctl(fd, SIOCGARP, &ar) == 0) {
        memcpy(mac, ar.arp_ha.sa_data, ETH_ALEN);
        ret = 0;
    } else {
        perror("ioctl(SIOCGARP)");
    }
    close(fd);
    return ret;
}

/* Simple ICMP ping via AF_INET, SOCK_DGRAM, IPPROTO_ICMP */
static int do_inet_ping(const char *host,
                        const struct in_addr *dst_ip,
                        int count)
{
    int fd;
    struct sockaddr_in dst;
    struct timeval tv;
    char ipbuf[INET_ADDRSTRLEN];
    pid_t pid;
    int seq;
    int ret;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (fd < 0) {
        perror("socket(AF_INET,SOCK_DGRAM,IPPROTO_ICMP)");
        return -1;
    }

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                   (char *)&tv, sizeof(tv)) < 0) {
        perror("setsockopt(SO_RCVTIMEO) inet ping");
        /* not fatal */
    }

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr = *dst_ip;
    dst.sin_port = 0;

    strncpy(ipbuf, inet_ntoa(*dst_ip), sizeof(ipbuf) - 1);
    ipbuf[sizeof(ipbuf) - 1] = '\0';

    printf("INET_PING %s (%s): %d bytes ICMP data, %d probes\n",
           host,
           ipbuf,
           ICMP_DATA_SIZE,
           count);

    pid = getpid() & 0xFFFF;

    ret = 0;
    for (seq = 1; seq <= count; ++seq) {
        unsigned char packet[ICMP_PACKET_SIZE];
        unsigned char recvbuf[RECV_BUF_SIZE];
        struct icmphdr *icmp;
        struct icmphdr *ricmp;
        struct timeval t0;
        struct timeval t1;
        struct sockaddr_in from;
        socklen_t fromlen;
        ssize_t sent;
        ssize_t recvd;
        int i;
        long sec;
        long usec;
        double rtt;

        memset(packet, 0, sizeof(packet));

        icmp = (struct icmphdr *)packet;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons((unsigned short)pid);
        icmp->un.echo.sequence = htons((unsigned short)seq);

        for (i = 0; i < ICMP_DATA_SIZE; ++i) {
            packet[ICMP_HEADER_SIZE + i] =
                (unsigned char)('a' + (i % 26));
        }

        icmp->checksum = 0;
        icmp->checksum = checksum(packet, ICMP_PACKET_SIZE);

        gettimeofday(&t0, NULL);

        sent = sendto(fd, packet, ICMP_PACKET_SIZE, 0,
                      (struct sockaddr *)&dst, sizeof(dst));
        if (sent < 0) {
            perror("sendto inet ping");
            ret = -1;
            break;
        }

        fromlen = sizeof(from);
        recvd = recvfrom(fd, recvbuf, sizeof(recvbuf), 0,
                         (struct sockaddr *)&from, &fromlen);
        if (recvd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("INET_PING: Request timeout for icmp_seq %d\n", seq);
                continue;
            } else {
                perror("recvfrom inet ping");
                ret = -1;
                break;
            }
        }

        gettimeofday(&t1, NULL);

        if (recvd < (ssize_t)sizeof(struct icmphdr)) {
            printf("INET_PING: short ICMP reply\n");
            continue;
        }

        ricmp = (struct icmphdr *)recvbuf;

        if (ricmp->type == ICMP_ECHOREPLY && ricmp->code == 0) {

            sec = t1.tv_sec - t0.tv_sec;
            usec = t1.tv_usec - t0.tv_usec;
            if (usec < 0) {
                --sec;
                usec += 1000000;
            }
            rtt = sec * 1000.0 + usec / 1000.0;

            printf("%ld bytes from %s: icmp_seq=%d time=%.3f ms\n",
                   (long)(recvd - (long)sizeof(struct icmphdr)),
                   inet_ntoa(from.sin_addr),
                   seq,
                   rtt);
        } else {
            printf("INET_PING: unexpected ICMP type=%d code=%d\n",
                   ricmp->type, ricmp->code);
        }
    }

    close(fd);
    return ret;
}

int main(int argc, char *argv[])
{
    const char *ifname;
    const char *host;
    struct addrinfo hints;
    struct addrinfo *res;
    int ret;
    struct in_addr dst_ip;
    struct in_addr src_ip;
    unsigned char src_mac[ETH_ALEN];
    unsigned char dst_mac[ETH_ALEN];
    int ifindex;
    int sockfd;
    struct timeval tv;
    struct sockaddr_ll bind_addr;
    struct sockaddr_ll send_addr;
    pid_t pid;
    int seq;
    char ip_str[INET_ADDRSTRLEN];

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <iface> <host>\n", argv[0]);
        return 1;
    }

    ifname = argv[1];
    host   = argv[2];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    ret = getaddrinfo(host, NULL, &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return 1;
    }

    dst_ip = ((struct sockaddr_in *)res->ai_addr)->sin_addr;

    if (get_iface_info(ifname, &ifindex, src_mac, &src_ip) < 0) {
        freeaddrinfo(res);
        return 1;
    }

    /* Step 1–2: normal ICMP ping via AF_INET to trigger ARP */
    if (do_inet_ping(host, &dst_ip, NUM_PINGS_INET) < 0) {
        /* we still try ARP lookup; maybe some packets got out anyway */
    }

    /* Step 3: get dest MAC from ARP cache */
    strncpy(ip_str, inet_ntoa(dst_ip), sizeof(ip_str) - 1);
    ip_str[sizeof(ip_str) - 1] = '\0';

    if (get_dest_mac_via_ioctl(ifname, &dst_ip, dst_mac) < 0)
        memset(dst_mac, 0xFF, ETH_ALEN); /* broadcast fallback */

    /* Step 4: AF_PACKET raw socket ping */
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sockfd < 0) {
        perror("socket(AF_PACKET,SOCK_RAW,ETH_P_IP)");
        freeaddrinfo(res);
        return 1;
    }

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                   (char *)&tv, sizeof(tv)) < 0) {
        perror("setsockopt(SO_RCVTIMEO) packet ping");
        /* not fatal */
    }

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sll_family   = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_IP);
    bind_addr.sll_ifindex  = ifindex;

    if (bind(sockfd, (struct sockaddr *)&bind_addr,
             sizeof(bind_addr)) < 0) {
        perror("bind(AF_PACKET, IP)");
        freeaddrinfo(res);
        close(sockfd);
        return 1;
    }

    memset(&send_addr, 0, sizeof(send_addr));
    send_addr.sll_family   = AF_PACKET;
    send_addr.sll_protocol = htons(ETH_P_IP);
    send_addr.sll_ifindex  = ifindex;
    send_addr.sll_halen    = ETH_ALEN;
    memcpy(send_addr.sll_addr, dst_mac, ETH_ALEN);

    printf("PACKET_PING %s (%s) via %s: %d bytes ICMP data, %d probes\n",
           host,
           ip_str,
           ifname,
           ICMP_DATA_SIZE,
           NUM_PINGS_PACKET);

    pid = getpid() & 0xFFFF;

    for (seq = 1; seq <= NUM_PINGS_PACKET; ++seq) {
        unsigned char frame[ETH_FRAME_SIZE];
        struct ether_header *eth;
        struct iphdr *ip;
        struct icmphdr *icmp;
        unsigned char *data;
        int i;
        struct timeval send_time;
        struct timeval recv_time;
        ssize_t sent;
        unsigned char buf[RECV_BUF_SIZE];
        struct sockaddr_ll recv_addr;
        socklen_t recv_addrlen;
        ssize_t n;
        struct ether_header *reth;
        struct iphdr *rip;
        int iphdr_len;
        struct icmphdr *ricmp;
        long sec;
        long usec;
        double rtt;

        memset(frame, 0, sizeof(frame));

        /* Ethernet header */
        eth = (struct ether_header *)frame;
        memcpy(eth->ether_dhost, dst_mac, ETH_ALEN);
        memcpy(eth->ether_shost, src_mac, ETH_ALEN);
        eth->ether_type = htons(ETH_P_IP);

        /* IPv4 header */
        ip = (struct iphdr *)(frame + ETH_HLEN);
        ip->version  = 4;
        ip->ihl      = IP_HEADER_SIZE / 4;
        ip->tos      = 0;
        ip->tot_len  = htons(IP_PACKET_SIZE);
        ip->id       = htons((unsigned short)seq);
        ip->frag_off = htons(0);
        ip->ttl      = 64;
        ip->protocol = IPPROTO_ICMP;
        ip->check    = 0;
        ip->saddr    = src_ip.s_addr;
        ip->daddr    = dst_ip.s_addr;
        ip->check    = checksum(ip, IP_HEADER_SIZE);

        /* ICMP header + data */
        icmp = (struct icmphdr *)(frame + ETH_HLEN + IP_HEADER_SIZE);
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons((unsigned short)pid);
        icmp->un.echo.sequence = htons((unsigned short)seq);

        data = (unsigned char *)icmp + ICMP_HEADER_SIZE;
        for (i = 0; i < ICMP_DATA_SIZE; ++i) {
            data[i] = (unsigned char)('A' + (i % 26));
        }

        icmp->checksum = 0;
        icmp->checksum = checksum(icmp, ICMP_PACKET_SIZE);

        gettimeofday(&send_time, NULL);

        sent = sendto(sockfd, frame, ETH_FRAME_SIZE, 0,
                      (struct sockaddr *)&send_addr,
                      sizeof(send_addr));
        if (sent < 0) {
            perror("sendto packet ping");
            break;
        }

        recv_addrlen = sizeof(recv_addr);
        n = recvfrom(sockfd, buf, sizeof(buf), 0,
                     (struct sockaddr *)&recv_addr,
                     &recv_addrlen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("PACKET_PING: Request timeout for icmp_seq %d\n", seq);
                sleep(1);
                continue;
            } else {
                perror("recvfrom packet ping");
                break;
            }
        }

        gettimeofday(&recv_time, NULL);

        if (recv_addr.sll_ifindex != ifindex) {
            sleep(1);
            continue;
        }

        if (n < (ssize_t)(ETH_HLEN + IP_HEADER_SIZE + ICMP_HEADER_SIZE)) {
            printf("PACKET_PING: short frame\n");
            sleep(1);
            continue;
        }

        reth = (struct ether_header *)buf;
        if (ntohs(reth->ether_type) != ETH_P_IP) {
            sleep(1);
            continue;
        }

        rip = (struct iphdr *)(buf + ETH_HLEN);
        if (rip->protocol != IPPROTO_ICMP) {
            sleep(1);
            continue;
        }

        if (rip->daddr != src_ip.s_addr) {
            sleep(1);
            continue;
        }

        iphdr_len = rip->ihl * 4;
        if (n < (ssize_t)(ETH_HLEN + iphdr_len + ICMP_HEADER_SIZE)) {
            sleep(1);
            continue;
        }

        ricmp = (struct icmphdr *)(buf + ETH_HLEN + iphdr_len);

        if (ricmp->type == ICMP_ECHOREPLY &&
            ricmp->code == 0 &&
            ricmp->un.echo.id == htons((unsigned short)pid) &&
            ricmp->un.echo.sequence == htons((unsigned short)seq)) {

            sec = recv_time.tv_sec - send_time.tv_sec;
            usec = recv_time.tv_usec - send_time.tv_usec;
            if (usec < 0) {
                --sec;
                usec += 1000000;
            }
            rtt = sec * 1000.0 + usec / 1000.0;

            printf("%ld bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
                   (long)(n - ETH_HLEN - iphdr_len),
                   inet_ntoa(*(struct in_addr *)&rip->saddr),
                   seq,
                   rip->ttl,
                   rtt);
        } else {
            printf("PACKET_PING: unexpected ICMP type=%d code=%d\n",
                   ricmp->type, ricmp->code);
        }

        sleep(1);
    }

    freeaddrinfo(res);
    close(sockfd);
    return 0;
}

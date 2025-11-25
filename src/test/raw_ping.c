/* raw_ping.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>

#define PACKET_SIZE 64
#define NUM_PINGS   3

static unsigned short icmp_checksum(void *b, int len)
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

int main(int argc, char *argv[])
{
    int sockfd;
    struct addrinfo hints;
    struct addrinfo *res;
    int ret;
    const char *host;
    struct sockaddr_in *addr_in;
    pid_t pid;
    int seq;
    int replies = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <host>\n", argv[0]);
        return 1;
    }

    host = argv[1];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;      /* IPv4 */
    hints.ai_socktype = SOCK_RAW;     /* raw socket */
    hints.ai_protocol = IPPROTO_ICMP; /* ICMP */

    ret = getaddrinfo(host, NULL, &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return 1;
    }

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket (need root / CAP_NET_RAW)");
        freeaddrinfo(res);
        return 1;
    }

    addr_in = (struct sockaddr_in *)res->ai_addr;

    printf("PING %s (%s): %d bytes ICMP data, %d probes\n",
           host,
           inet_ntoa(addr_in->sin_addr),
           PACKET_SIZE - (int)sizeof(struct icmphdr),
           NUM_PINGS);

    pid = getpid() & 0xFFFF;

    for (seq = 1; seq <= NUM_PINGS; ++seq) {
        unsigned char packet[PACKET_SIZE];
        struct icmphdr *icmp;
        int payload_size;
        unsigned char *data;
        struct timeval send_time;
        struct timeval recv_time;
        ssize_t sent;
        unsigned char recvbuf[1024];
        struct sockaddr_in src;
        socklen_t srclen;
        ssize_t n;
        struct ip *ip_hdr;
        int ip_hdr_len;
        struct icmphdr *icmp_reply;
        long sec;
        long usec;
        double rtt;
        int i;

        memset(packet, 0, sizeof(packet));

        icmp = (struct icmphdr *)packet;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons((unsigned short)pid);
        icmp->un.echo.sequence = htons((unsigned short)seq);

        /* Simple payload pattern */
        payload_size = PACKET_SIZE - (int)sizeof(struct icmphdr);
        data = packet + sizeof(struct icmphdr);
        for (i = 0; i < payload_size; ++i) {
            data[i] = (unsigned char)('A' + (i % 26));
        }

        icmp->checksum = 0;
        icmp->checksum = icmp_checksum(packet, PACKET_SIZE);

        gettimeofday(&send_time, NULL);

        sent = sendto(sockfd, packet, PACKET_SIZE, 0,
                      res->ai_addr, res->ai_addrlen);
        if (sent < 0) {
            perror("sendto");
            break;
        }

        srclen = sizeof(src);
        n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0,
                     (struct sockaddr *)&src, &srclen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("Request timeout for icmp_seq %d\n", seq);
                sleep(1);
                continue;
            } else {
                perror("recvfrom");
                break;
            }
        }

        gettimeofday(&recv_time, NULL);

        /* Received packet: IP header + ICMP */
        ip_hdr = (struct ip *)recvbuf;
        ip_hdr_len = ip_hdr->ip_hl * 4;

        if (n < ip_hdr_len + (int)sizeof(struct icmphdr)) {
            printf("Short packet\n");
            sleep(1);
            continue;
        }

        icmp_reply = (struct icmphdr *)(recvbuf + ip_hdr_len);

        if (icmp_reply->type == ICMP_ECHOREPLY &&
            icmp_reply->code == 0 &&
            icmp_reply->un.echo.id == htons((unsigned short)pid) &&
            icmp_reply->un.echo.sequence == htons((unsigned short)seq)) {

            sec = recv_time.tv_sec - send_time.tv_sec;
            usec = recv_time.tv_usec - send_time.tv_usec;
            if (usec < 0) {
                --sec;
                usec += 1000000;
            }
            rtt = sec * 1000.0 + usec / 1000.0;

            printf("%ld bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
                   (long)(n - ip_hdr_len),
                   inet_ntoa(src.sin_addr),
                   seq,
                   ip_hdr->ip_ttl,
                   rtt);
            replies++;
        } else {
            printf("Got unexpected ICMP packet (type=%d code=%d)\n",
                   icmp_reply->type, icmp_reply->code);
        }

        sleep(1);
    }

    freeaddrinfo(res);
    close(sockfd);
    return (replies > 0) ? 0 : 1;
}

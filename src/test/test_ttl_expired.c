/* test_ttl_expired.c
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
 * Validate that wolfIP emits an ICMP TTL Expired message when forwarding
 * a packet whose TTL reaches zero.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "wolfip.h"

#ifndef WOLFIP_MAX_INTERFACES
#define WOLFIP_MAX_INTERFACES 2
#endif

#ifndef WOLFIP_ENABLE_FORWARDING
#define WOLFIP_ENABLE_FORWARDING 1
#endif

#ifndef IP4
#define IP4(a,b,c,d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | \
                      ((uint32_t)(c) << 8) | (uint32_t)(d))
#endif

#define HOST_IP     IP4(10,0,1,10)
#define ROUTER_IF0  IP4(10,0,1,1)
#define ROUTER_GW   IP4(10,0,1,254)
#define ROUTER_IF1  IP4(10,0,2,1)
#define DEST_IP     IP4(10,0,2,200)
#define TTL_EXCEEDED_DATA_LEN 28

#define PACKED __attribute__((packed))

struct eth_hdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
} PACKED;

struct ipv4_hdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t csum;
    uint32_t src;
    uint32_t dst;
} PACKED;

struct icmp_echo {
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    uint16_t id;
    uint16_t seq;
} PACKED;

struct icmp_ttl_exceeded {
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    uint8_t unused[4];
    uint8_t data[TTL_EXCEEDED_DATA_LEN];
} PACKED;

static uint16_t ones_csum(const void *buf, size_t len)
{
    const uint16_t *p = buf;
    uint32_t acc = 0;
    while (len > 1) {
        acc += *p++;
        len -= 2;
    }
    if (len)
        acc += *((const uint8_t *)p);
    while (acc >> 16)
        acc = (acc & 0xFFFF) + (acc >> 16);
    return (uint16_t)~acc;
}

uint32_t wolfIP_getrandom(void)
{
    return (uint32_t)rand();
}

struct mem_link {
    pthread_mutex_t lock;
    pthread_cond_t cond[2];
    int ready[2];
    size_t len[2];
    uint8_t buf[2][LINK_MTU];
};

struct mem_ep {
    struct wolfIP_ll_dev *ll;
    struct mem_link *link;
    int idx;
};

static struct mem_ep mem_eps[2];

static void mem_link_init(struct mem_link *link)
{
    pthread_mutex_init(&link->lock, NULL);
    pthread_cond_init(&link->cond[0], NULL);
    pthread_cond_init(&link->cond[1], NULL);
    link->ready[0] = link->ready[1] = 0;
    link->len[0] = link->len[1] = 0;
}

static struct mem_ep *mem_ep_lookup(struct wolfIP_ll_dev *ll)
{
    for (size_t i = 0; i < 2; i++)
        if (mem_eps[i].ll == ll)
            return &mem_eps[i];
    return NULL;
}

static int mem_ll_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct mem_ep *ep = mem_ep_lookup(ll);
    struct mem_link *link;
    int idx;
    int ret = 0;

    if (!ep)
        return -1;
    link = ep->link;
    idx = ep->idx;

    pthread_mutex_lock(&link->lock);
    if (link->ready[idx]) {
        size_t copy = link->len[idx];
        if (copy > len)
            copy = len;
        memcpy(buf, link->buf[idx], copy);
        link->ready[idx] = 0;
        pthread_cond_signal(&link->cond[idx]);
        ret = (int)copy;
    }
    pthread_mutex_unlock(&link->lock);
    return ret;
}

static int mem_ll_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct mem_ep *ep = mem_ep_lookup(ll);
    struct mem_link *link;
    int dst;

    if (!ep)
        return -1;
    link = ep->link;
    dst = 1 - ep->idx;

    pthread_mutex_lock(&link->lock);
    while (link->ready[dst])
        pthread_cond_wait(&link->cond[dst], &link->lock);
    if (len > LINK_MTU)
        len = LINK_MTU;
    memcpy(link->buf[dst], buf, len);
    link->len[dst] = len;
    link->ready[dst] = 1;
    pthread_cond_signal(&link->cond[dst]);
    pthread_mutex_unlock(&link->lock);
    return (int)len;
}

static void mem_attach(struct wolfIP_ll_dev *ll, struct mem_link *link, int idx, const uint8_t *mac)
{
    ll->poll = mem_ll_poll;
    ll->send = mem_ll_send;
    memcpy(ll->mac, mac, 6);
    snprintf(ll->ifname, sizeof(ll->ifname), "mem%d", idx);
    mem_eps[idx].ll = ll;
    mem_eps[idx].link = link;
    mem_eps[idx].idx = idx;
}

static void mem_host_send(struct mem_link *link, const uint8_t *frame, size_t len)
{
    pthread_mutex_lock(&link->lock);
    while (link->ready[1])
        pthread_cond_wait(&link->cond[1], &link->lock);
    if (len > LINK_MTU)
        len = LINK_MTU;
    memcpy(link->buf[1], frame, len);
    link->len[1] = len;
    link->ready[1] = 1;
    pthread_cond_signal(&link->cond[1]);
    pthread_mutex_unlock(&link->lock);
}

static int mem_host_recv(struct mem_link *link, uint8_t *frame, size_t cap, int timeout_ms)
{
    int ret = -1;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&link->lock);
    while (!link->ready[0]) {
        int rc = pthread_cond_timedwait(&link->cond[0], &link->lock, &ts);
        if (rc == ETIMEDOUT)
            goto out;
    }
    if (link->len[0] > cap)
        cap = link->len[0];
    memcpy(frame, link->buf[0], link->len[0]);
    ret = (int)link->len[0];
    link->ready[0] = 0;
    pthread_cond_signal(&link->cond[0]);
out:
    pthread_mutex_unlock(&link->lock);
    return ret;
}

static void build_ttl_frame(uint8_t *frame, const uint8_t *src_mac, const uint8_t *dst_mac,
        uint32_t src_ip, uint32_t dst_ip)
{
    struct eth_hdr *eth = (struct eth_hdr *)frame;
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(frame + sizeof(*eth));
    struct icmp_echo *icmp = (struct icmp_echo *)(frame + sizeof(*eth) + sizeof(*ip));

    memcpy(eth->dst, dst_mac, 6);
    memcpy(eth->src, src_mac, 6);
    eth->type = htons(ETH_P_IP);

    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl = 0x45;
    ip->ttl = 1;
    ip->proto = 1;
    ip->len = htons(sizeof(*ip) + sizeof(*icmp));
    ip->id = htons(0x1234);
    ip->src = htonl(src_ip);
    ip->dst = htonl(dst_ip);
    ip->csum = ones_csum(ip, sizeof(*ip));

    memset(icmp, 0, sizeof(*icmp));
    icmp->type = 8;
    icmp->id = htons(0x0101);
    icmp->seq = htons(1);
    icmp->csum = ones_csum(icmp, sizeof(*icmp));
}

static int dummy_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    (void)buf;
    return (int)len;
}

static int dummy_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    (void)buf;
    (void)len;
    return 0;
}

static volatile int running = 1;

static void *poll_thread(void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    while (running) {
        struct timespec ts;
        uint64_t now;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        now = (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
        wolfIP_poll(s, now);
        usleep(1000);
    }
    return NULL;
}

int main(void)
{
    struct wolfIP *router;
    struct wolfIP_ll_dev *iface0;
    struct wolfIP_ll_dev *iface1;
    struct mem_link link;
    pthread_t th;
    uint8_t host_mac[6] = {0x02,0x00,0x00,0x00,0xAA,0x01};
    uint8_t router0_mac[6] = {0x02,0x00,0x00,0x00,0xBB,0x01};
    uint8_t router1_mac[6] = {0x02,0x00,0x00,0x00,0xCC,0x01};
    uint8_t frame[LINK_MTU];
    int rc = EXIT_FAILURE;
    int n;

    setvbuf(stdout, NULL, _IONBF, 0);

    mem_link_init(&link);
    wolfIP_init_static(&router);

    iface0 = wolfIP_getdev(router);
    iface1 = wolfIP_getdev_ex(router, 1);
    if (!iface0 || !iface1) {
        fprintf(stderr, "missing interfaces\n");
        return EXIT_FAILURE;
    }

    mem_attach(iface0, &link, 1, router0_mac);

    iface1->send = dummy_send;
    iface1->poll = dummy_poll;
    memcpy(iface1->mac, router1_mac, 6);

    wolfIP_ipconfig_set(router, ROUTER_IF0, IP4(255,255,255,0), ROUTER_GW);
    wolfIP_ipconfig_set_ex(router, 1, ROUTER_IF1, IP4(255,255,255,0), IP4(0,0,0,0));

    running = 1;
    if (pthread_create(&th, NULL, poll_thread, router) != 0) {
        perror("pthread_create");
        return EXIT_FAILURE;
    }

    build_ttl_frame(frame, host_mac, router0_mac, HOST_IP, DEST_IP);
    mem_host_send(&link, frame, sizeof(struct eth_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct icmp_echo));

    n = mem_host_recv(&link, frame, sizeof(frame), 1000);
    if (n <= 0) {
        fprintf(stderr, "No TTL expired response\n");
        goto cleanup;
    }

    {
        struct eth_hdr *eth = (struct eth_hdr *)frame;
        struct ipv4_hdr *ip = (struct ipv4_hdr *)(frame + sizeof(*eth));
        struct icmp_ttl_exceeded *icmp = (struct icmp_ttl_exceeded *)(frame + sizeof(*eth) + sizeof(*ip));
        struct ipv4_hdr *orig_ip = (struct ipv4_hdr *)icmp->data;
        struct icmp_echo *orig_icmp = (struct icmp_echo *)(icmp->data + sizeof(*orig_ip));
        size_t expected_len = sizeof(*eth) + sizeof(*ip) + sizeof(*icmp);
        uint16_t ip_len = ntohs(ip->len);
        uint16_t expected_ip_len = (uint16_t)(sizeof(*ip) + sizeof(*icmp));

        if ((size_t)n != expected_len) {
            fprintf(stderr, "Unexpected frame length: got %d expected %zu\n", n, expected_len);
            goto mismatch;
        }
        if (ntohs(eth->type) != ETH_P_IP ||
                memcmp(eth->dst, host_mac, sizeof(host_mac)) != 0 ||
                memcmp(eth->src, router0_mac, sizeof(router0_mac)) != 0) {
            fprintf(stderr, "Ethernet header mismatch\n");
            goto mismatch;
        }
        if (ip->ver_ihl != 0x45 || ip->proto != 1 || ip->ttl != 64 ||
                ip_len != expected_ip_len ||
                ntohl(ip->src) != ROUTER_IF0 || ntohl(ip->dst) != HOST_IP) {
            fprintf(stderr, "IPv4 header mismatch\n");
            goto mismatch;
        }
        if (icmp->type != 11 || icmp->code != 0 ||
                memcmp(icmp->unused, "\x00\x00\x00\x00", sizeof(icmp->unused)) != 0) {
            fprintf(stderr, "ICMP header mismatch\n");
            goto mismatch;
        }
        if (orig_ip->ver_ihl != 0x45 || orig_ip->proto != 1 ||
                ntohl(orig_ip->src) != HOST_IP || ntohl(orig_ip->dst) != DEST_IP ||
                ntohs(orig_ip->len) != sizeof(*orig_ip) + sizeof(struct icmp_echo) ||
                ntohs(orig_ip->id) != 0x1234 || orig_ip->ttl != 1) {
            fprintf(stderr, "Embedded IPv4 header mismatch\n");
            goto mismatch;
        }
        if (orig_icmp->type != 8 || orig_icmp->code != 0 ||
                ntohs(orig_icmp->id) != 0x0101 || ntohs(orig_icmp->seq) != 1) {
            fprintf(stderr, "Embedded ICMP header mismatch\n");
            goto mismatch;
        }
        printf("TTL expired response received\n");
        rc = EXIT_SUCCESS;
        goto cleanup;
    }

mismatch:
    fprintf(stderr, "TTL expired response mismatch\n");

cleanup:
    running = 0;
    pthread_join(th, NULL);
    return rc;
}

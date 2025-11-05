/* wolfip.c
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

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include "wolfip.h"
#include "config.h"

#if WOLFIP_ENABLE_LOOPBACK
#define WOLFIP_LOOPBACK_IF_IDX 0U
#define WOLFIP_PRIMARY_IF_IDX 1U
#define WOLFIP_LOOPBACK_IP 0x7F000001U
#define WOLFIP_LOOPBACK_MASK 0xFF000000U
static inline int wolfIP_is_loopback_if(unsigned int if_idx)
{
    return if_idx == WOLFIP_LOOPBACK_IF_IDX;
}
#else
#define WOLFIP_LOOPBACK_IF_IDX 0U
#define WOLFIP_PRIMARY_IF_IDX 0U
static inline int wolfIP_is_loopback_if(unsigned int if_idx)
{
    (void)if_idx;
    return 0;
}
#endif

#define WOLFIP_CONTAINER_OF(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

#if WOLFIP_ENABLE_LOOPBACK
static int wolfIP_loopback_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len);
#endif
static void wolfIP_recv_on(struct wolfIP *s, unsigned int if_idx, void *buf, uint32_t len);

/* Fixed size binary heap: each element is a timer. */
#define MAX_TIMERS MAX_TCPSOCKETS * 3

/* Constants */
#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO_REQUEST 8
#define ICMP_TTL_EXCEEDED 11

#define WI_IPPROTO_ICMP 0x01
#define WI_IPPROTO_TCP 0x06
#define WI_IPPROTO_UDP 0x11
#define IPADDR_ANY 0x00000000

#define TCP_OPTION_MSS 0x02
#define TCP_OPTION_MSS_LEN 4
#define TCP_OPTION_TS 0x08
#define TCP_OPTION_TS_LEN 10
#define TCP_OPTIONS_LEN 12
#define TCP_OPTION_NOP 0x01
#define TCP_OPTION_EOO 0x00

#define TCP_HEADER_LEN 20
#define IP_HEADER_LEN 20
#define UDP_HEADER_LEN 8
#define ICMP_HEADER_LEN 8
#define ARP_HEADER_LEN 28

#ifdef ETHERNET
#define ETH_HEADER_LEN 14
#else
#define ETH_HEADER_LEN 0
#endif

#define ETH_TYPE_IP 0x0800
#define ETH_TYPE_ARP 0x0806

#define NO_TIMER 0

#define WI_IP_MTU 1500
#define TCP_MSS (WI_IP_MTU - (IP_HEADER_LEN + TCP_HEADER_LEN))

/* Macros */
#define IS_IP_BCAST(ip) (ip == 0xFFFFFFFF)

#define PKT_FLAG_SENT 0x01
#define PKT_FLAG_ACKED 0x02
#define PKT_FLAG_FIN 0x04


/* Random number generator, provided by the user */
//extern uint32_t wolfIP_getrandom(void);

struct PACKED pkt_desc {
    uint32_t pos, len;
    uint16_t flags, time_sent;
};

struct fifo {
    uint32_t head, tail, size, h_wrap;
    uint8_t *data;
};

/* TCP TX is a circular buffer and contains an array of full packets */
/* TCP RX only contains application data */

/* FIFO functions
 * head: next empty slot
 * tail: oldest populated slot
 *
 * */

/* Initialize a FIFO */
static void fifo_init(struct fifo *f, uint8_t *data, uint32_t size)
{
    f->head = 0;
    f->tail = 0;
    f->h_wrap = 0;
    f->size = size;
    f->data = data;
}

/* Return the number of bytes available */
static uint32_t fifo_space(struct fifo *f)
{
    int ret = 0;
    if (f->head == f->tail) {
        f->head = 0;
        f->tail = 0;
        return f->size;
    }
    if (f->tail == f->h_wrap) {
        f->tail = 0;
        f->h_wrap = 0;
    }
    if (f->h_wrap == 0) {
        if (f->head >= f->tail) {
            ret = f->size - (f->head - f->tail);
        } else {
            ret = f->tail - f->head;
        }
        /* Take into account the wraparound to always keep the segment contiguous */
        if ((f->size - f->head) < (sizeof(struct pkt_desc) + LINK_MTU)) {
            if (f->tail > (sizeof(struct pkt_desc) + LINK_MTU)) {
                f->h_wrap = f->head;
                f->head = 0;
                return f->tail - f->head;
            } else return 0;
        }
    } else {
        ret = f->size - (f->tail - f->head);
    }
    return ret;
}

/* Check the descriptor of the next packet */
static struct pkt_desc *fifo_peek(struct fifo *f)
{
    if (f->tail == f->h_wrap) {
        f->tail = 0;
        f->h_wrap = 0;
    }
    if (f->tail == f->head)
        return NULL;
    while (f->tail % 4)
        f->tail++;
    if ((f->head < f->tail) && ((f->tail + sizeof(struct pkt_desc) + LINK_MTU > f->size)))
        f->tail = 0;
    return (struct pkt_desc *)((uint8_t *)f->data + f->tail);
}

/* Continue reading starting from a descriptor returned by fifo_peek */
static struct pkt_desc *fifo_next(struct fifo *f, struct pkt_desc *desc)
{
    uint32_t len;
    if (desc == NULL)
        return NULL;
    len = sizeof(struct pkt_desc) + desc->len;
    if ((desc->pos + len) == f->head)
        return NULL;
    while ((desc->pos + len) % 4)
        len++;
    if ((desc->pos + len + sizeof(struct pkt_desc) + LINK_MTU ) >= f->size)
        desc = (struct pkt_desc *)((uint8_t *)f->data);
    else
        desc = (struct pkt_desc *)((uint8_t *)f->data + desc->pos + len);
    if ((desc->pos + len) == f->h_wrap) {
        desc = (struct pkt_desc *)((uint8_t *)f->data);
    }
    return desc;
}

/* Return the number of bytes used */
static uint32_t fifo_len(struct fifo *f)
{
    while (f->tail % 4)
        f->tail++;
    f->tail %= f->size;
    if (f->tail == f->head)
        return 0;
    if (f->tail > f->head) {
        if (f->h_wrap > 0)
            return f->h_wrap - f->tail + f->head;
        else
            return f->size - (f->tail - f->head);
    } else {
        return f->head - f->tail;
    }
}

/* Insert data into the FIFO */
static int fifo_push(struct fifo *f, void *data, uint32_t len)
{
    struct pkt_desc desc;
    memset(&desc, 0, sizeof(struct pkt_desc));
    /* Ensure 4-byte alignment in the buffer */
    if (f->head % 4)
        f->head += 4 - (f->head % 4);
    if (fifo_space(f) < (sizeof(struct pkt_desc) + len))
        return -1;
    desc.pos = f->head;
    desc.len = len;
    memcpy((uint8_t *)f->data + f->head, &desc, sizeof(struct pkt_desc));
    f->head += sizeof(struct pkt_desc);
    memcpy((uint8_t *)f->data + f->head, data, len);
    f->head += len;
    return 0;
}

/* Grab the tail packet and advance the tail pointer */
static struct pkt_desc *fifo_pop(struct fifo *f)
{
    struct pkt_desc *desc;
    if (f->tail == f->head)
        return NULL;
    while (f->tail % 4)
        f->tail++;
    f->tail %= f->size;
    if (f->tail == f->head)
        return NULL;
    if ((f->head < f->tail) && ((f->tail + sizeof(struct pkt_desc) + LINK_MTU > f->size)))
        f->tail = 0;
    desc = (struct pkt_desc *)((uint8_t *)f->data + f->tail);
    f->tail += sizeof(struct pkt_desc) + desc->len;
    f->tail %= f->size;
    return desc;
}

/* Simple queue structure for TCP RX, keeping only the data in the buffer */
struct queue {
    uint32_t seq_base, head, tail, size;
    uint8_t *data;
};

/* Initialize a queue */
/* head: next empty slot
 * tail: oldest populated slot
 */
static void queue_init(struct queue *q, uint8_t *data, uint32_t size, uint32_t seq_base)
{
    q->seq_base = seq_base;
    q->tail = 0;
    q->head = 0;
    q->size = size;
    q->data = data;
}

/* Return the number of bytes available */
static uint32_t queue_space(struct queue *q)
{
    if (q->head >= q->tail) {
        return q->size - (q->head - q->tail);
    } else {
        return q->tail - q->head;
    }
}

/* Return the number of bytes used */
static uint32_t queue_len(struct queue *q)
{
    return q->size - queue_space(q);
}

/* Insert data into the queue */
static int queue_insert(struct queue *q, void *data, uint32_t seq, uint32_t len)
{
    uint32_t pos;
    int diff;
    if ((len > queue_space(q)) || (len > q->size)) {
        return -1;
    }
    if (queue_len(q) == 0) {
        q->tail = q->head = 0;
        memcpy(q->data, data, len);
        q->head = len;
        q->seq_base = seq;
    } else {
        diff = seq - q->seq_base;
        if (diff < 0)
            return -1;
        pos = (uint32_t)diff;
        if (pos > q->size)
            return -1;
        /* Check if the data is ancient */
        if (pos < q->tail)
            return 0;
        /* Write in two steps: consider wrapping */
        if (pos + len > q->size) {
            memcpy((uint8_t *)q->data + pos, data, q->size - pos);
            memcpy((uint8_t *)q->data, (const uint8_t *)data + q->size - pos, len - (q->size - pos));
        } else {
            memcpy((uint8_t *)q->data + pos, data, len);
        }
        if (pos + len > q->head)
            q->head = (pos + len) % q->size;
    }
    return 0;
}

/* Grab the tail packet and advance the tail pointer */
static int queue_pop(struct queue *q, void *data, uint32_t len)
{
    uint32_t q_len = queue_len(q);
    if (q_len == 0)
        return -WOLFIP_EAGAIN;
    if (len > q_len)
        len = q_len;
    memcpy(data, (const uint8_t *)q->data + q->tail, len);
    q->tail += len;
    q->tail %= q->size;
    q->seq_base += len;
    return len;
}

/* ARP */

#define ARP_REQUEST 1
#define ARP_REPLY 2

#ifdef ETHERNET
/* Struct to contain an ethernet frame with its header */
struct PACKED wolfIP_eth_frame {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
    uint8_t data[0];
};
#endif

/* Struct to contain a IPv4 packet with its header */
struct PACKED wolfIP_ip_packet {
#ifdef ETHERNET
    struct wolfIP_eth_frame eth;
#endif
    uint8_t ver_ihl, tos;
    uint16_t len, id, flags_fo;
    uint8_t ttl, proto;
    uint16_t csum;
    ip4 src, dst;
    uint8_t data[0];
};

/* Describe a TCP segment down to the datalink layer */
struct PACKED wolfIP_tcp_seg {
    struct wolfIP_ip_packet ip;
    uint16_t src_port, dst_port;
    uint32_t seq, ack;
    uint8_t hlen, flags;
    uint16_t win, csum, urg;
    uint8_t data[0];
};

struct PACKED tcp_opt_ts {
    /* Timestamp option (10 extra bytes) */
    uint8_t opt, len;
    uint32_t val, ecr;
    uint8_t  pad, eoo;
};

struct PACKED tcp_opt_mss {
    /* MSS option (4 extra bytes) */
    uint8_t opt, len;
    uint16_t mss;
};

/* UDP datagram */
struct PACKED wolfIP_udp_datagram {
    struct wolfIP_ip_packet ip;
    uint16_t src_port, dst_port, len, csum;
    uint8_t data[0];
};

/* For Checksums */
union transport_pseudo_header {
    struct PACKED ph {
        ip4 src, dst;
        uint8_t zero, proto;
        uint16_t len;
    } ph;
    uint16_t buf[6];
};

/* ICMP */
struct PACKED wolfIP_icmp_packet {
    struct wolfIP_ip_packet ip;
    uint8_t type, code;
    uint16_t csum;
    uint8_t data[0];
};

/* DHCP */
#define BOOT_REQUEST 1
#define BOOT_REPLY   2

#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_ACK 5

#define DHCP_MAGIC 0x63825363
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_OPTION_MSG_TYPE 53
#define DHCP_OPTION_SUBNET_MASK 1
#define DHCP_OPTION_ROUTER 3
#define DHCP_OPTION_DNS 6
#define DHCP_OPTION_SERVER_ID 54
#define DHCP_OPTION_PARAM_REQ 55
#define DHCP_OPTION_OFFER_IP 50
#define DHCP_OPTION_END 0xFF
#define DHCP_DISCOVER_TIMEOUT 2000
#define DHCP_DISCOVER_RETRIES 3
#define DHCP_REQUEST_TIMEOUT 2000
#define DHCP_REQUEST_RETRIES 3

enum dhcp_state {
    DHCP_OFF = 0,
    DHCP_DISCOVER_SENT,
    DHCP_REQUEST_SENT,
    DHCP_BOUND,
};

#define DHCP_IS_RUNNING(s) \
    ((s->dhcp_state != DHCP_OFF) && (s->dhcp_state != DHCP_BOUND))

struct PACKED dhcp_msg {
    uint8_t op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t chaddr[16], sname[64], file[128];
    uint32_t magic;
    uint8_t options[312];
};

#define DHCP_HEADER_LEN 240

struct PACKED dhcp_option {
    uint8_t code, len, data[0];
};

/* Sockets */

/* TCP socket */
enum tcp_state {
    TCP_CLOSED = 0,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RCVD,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSING,
    TCP_TIME_WAIT,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK
};

struct tcpsocket {
    enum tcp_state state;
    uint32_t last_ts, rtt, rto, cwnd, cwnd_count, ssthresh, tmr_rto, rto_backoff,
             seq, ack, last_ack, last;
    ip4 local_ip, remote_ip;
    struct fifo txbuf;
    struct queue rxbuf;
};

/* UDP socket */
struct udpsocket {
    struct fifo rxbuf, txbuf;
};

struct tsocket {
    union tsocket_sock {
        struct tcpsocket tcp;
        struct udpsocket udp;
    } sock;
    uint16_t proto, events;
    ip4 local_ip, remote_ip;
    uint16_t src_port, dst_port;
    struct wolfIP *S;
#ifdef ETHERNET
    uint8_t nexthop_mac[6];
#endif
    uint8_t if_idx;
    uint8_t rxmem[RXBUF_SIZE];
    uint8_t txmem[TXBUF_SIZE];
    void (*callback)(int sock_fd, uint16_t events, void *arg);
    void *callback_arg;
};
static void close_socket(struct tsocket *ts);

#ifdef ETHERNET
struct PACKED arp_packet {
    struct wolfIP_eth_frame eth;
    uint16_t htype, ptype;
    uint8_t hlen, plen;
    uint16_t opcode;
    uint8_t sma[6];
    uint32_t sip;
    uint8_t tma[6];
    uint32_t tip;
};
struct arp_neighbor {
    ip4 ip;
    uint8_t mac[6];
    uint8_t if_idx;
};

#ifndef WOLFIP_ARP_PENDING_MAX
#define WOLFIP_ARP_PENDING_MAX 4
#endif

struct arp_pending_entry {
    ip4 dest;
    uint32_t len;
    uint8_t if_idx;
    uint8_t frame[LINK_MTU];
};

static int arp_lookup(struct wolfIP *s, unsigned int if_idx, ip4 ip, uint8_t *mac);
#if WOLFIP_ENABLE_FORWARDING
static void wolfIP_forward_packet(struct wolfIP *s, unsigned int out_if, struct wolfIP_ip_packet *ip,
        uint32_t len, const uint8_t *mac, int broadcast);
#endif

#endif

struct wolfIP;

struct wolfIP_timer {
    uint32_t id;
    uint64_t expires;
    void *arg;
    void (*cb)(void *arg);
};

/* Timer binary heap */
struct timers_binheap {
    struct wolfIP_timer timers[MAX_TIMERS];
    uint32_t size;
};

struct wolfIP
{
    struct wolfIP_ll_dev ll_dev[WOLFIP_MAX_INTERFACES];
    struct ipconf ipconf[WOLFIP_MAX_INTERFACES];
    unsigned int if_count;
    enum   dhcp_state dhcp_state; /* State machine for DHCP */
    uint32_t dhcp_xid;  /* DHCP transaction ID while DORA */
    int dhcp_udp_sd; /* DHCP socket descriptor. DHCP uses an UDP socket */
    uint32_t dhcp_timer; /* Timer for DHCP */
    uint32_t dhcp_timeout_count; /* DHCP timeout counter */
    ip4 dhcp_server_ip; /* DHCP server IP */
    ip4 dhcp_ip; /* IP address assigned by DHCP */
    ip4 dns_server;
    uint16_t dns_id;
    int dns_udp_sd;
    void (*dns_lookup_cb)(ip4 ip);
    struct timers_binheap timers;
    struct tsocket tcpsockets[MAX_TCPSOCKETS];
    struct tsocket udpsockets[MAX_UDPSOCKETS];
    uint16_t ipcounter;
    uint64_t last_tick;
#ifdef ETHERNET
    struct wolfIP_arp {
        uint64_t last_arp[WOLFIP_MAX_INTERFACES];
        struct arp_neighbor neighbors[MAX_NEIGHBORS];
    } arp;
    struct arp_pending_entry arp_pending[WOLFIP_ARP_PENDING_MAX];
#endif
};

#if WOLFIP_ENABLE_LOOPBACK

static int wolfIP_loopback_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct wolfIP *s;
    uint32_t copy = len;
    uint8_t frame[LINK_MTU];
    if (!ll || !buf)
        return -1;
    s = WOLFIP_CONTAINER_OF(ll, struct wolfIP, ll_dev);
    if (!s)
        return -1;
    if (copy > LINK_MTU)
        copy = LINK_MTU;
    memcpy(frame, buf, copy);
    wolfIP_recv_on(s, WOLFIP_LOOPBACK_IF_IDX, frame, copy);
    return (int)copy;
}
#endif

/* ***************************** */
/* Implementation */

static inline struct wolfIP_ll_dev *wolfIP_ll_at(struct wolfIP *s, unsigned int if_idx)
{
    if (!s || if_idx >= s->if_count)
        return NULL;
    return &s->ll_dev[if_idx];
}

static inline struct ipconf *wolfIP_ipconf_at(struct wolfIP *s, unsigned int if_idx)
{
    if (!s || if_idx >= s->if_count)
        return NULL;
    return &s->ipconf[if_idx];
}

static inline struct ipconf *wolfIP_primary_ipconf(struct wolfIP *s)
{
    return wolfIP_ipconf_at(s, WOLFIP_PRIMARY_IF_IDX);
}

static inline int ip_is_local_conf(const struct ipconf *conf, ip4 addr)
{
    if (!conf)
        return 0;
    if (conf->mask == 0)
        return conf->ip == addr;
    return ((addr & conf->mask) == (conf->ip & conf->mask));
}

#if WOLFIP_ENABLE_FORWARDING
static int wolfIP_forward_interface(struct wolfIP *s, unsigned int in_if, ip4 dest)
{
    int i;
    if (!s || s->if_count < 2)
        return s ? s->if_count : 0;
    for (i = 0; i < (int)s->if_count; i++) {
        struct ipconf *conf = &s->ipconf[i];
        if (i == (int)in_if)
            continue;
        if (!conf || conf->ip == IPADDR_ANY)
            continue;
        if (dest == conf->ip)
            return -1;
        if (ip_is_local_conf(conf, dest)) {
            return i;
        }
    }
    return -1;
}
#endif

static inline ip4 wolfIP_select_nexthop(const struct ipconf *conf, ip4 dest)
{
    if (IS_IP_BCAST(dest))
        return dest;
    if (!conf)
        return dest;
    if (ip_is_local_conf(conf, dest))
        return dest;
    if (conf->gw != IPADDR_ANY)
        return conf->gw;
    return dest;
}

static unsigned int wolfIP_route_for_ip(struct wolfIP *s, ip4 dest)
{
    unsigned int default_if = 0;
    unsigned int gw_fallback = 0;
    unsigned int first_non_loop = 0;
    int has_gw_fallback = 0;
    int has_non_loop = 0;
    unsigned int i;

    if (!s || s->if_count == 0)
        return 0;

    if (WOLFIP_PRIMARY_IF_IDX < s->if_count)
        default_if = WOLFIP_PRIMARY_IF_IDX;

    if (dest == IPADDR_ANY || IS_IP_BCAST(dest))
        return default_if;

    for (i = 0; i < s->if_count; i++) {
        struct ipconf *conf = &s->ipconf[i];
        if (conf->ip == IPADDR_ANY && conf->gw == IPADDR_ANY)
            continue;
        if (ip_is_local_conf(conf, dest) || conf->ip == dest) {
            return i;
        }
        if (!wolfIP_is_loopback_if(i) && !has_non_loop) {
            first_non_loop = i;
            has_non_loop = 1;
        }
        if (!wolfIP_is_loopback_if(i) && !has_gw_fallback && conf->gw != IPADDR_ANY) {
            gw_fallback = i;
            has_gw_fallback = 1;
        }
    }
    if (has_gw_fallback) {
        return gw_fallback;
    }
    if (has_non_loop) {
        return first_non_loop;
    }
    return default_if;
}

static inline unsigned int wolfIP_socket_if_idx(const struct tsocket *t)
{
    if (!t || !t->S || t->if_idx >= t->S->if_count)
        return 0;
    return t->if_idx;
}

static unsigned int wolfIP_if_for_local_ip(struct wolfIP *s, ip4 local_ip, int *found)
{
    unsigned int primary = 0;
    unsigned int i;
    if (found)
        *found = 0;
    if (!s || s->if_count == 0)
        return 0;
    if (WOLFIP_PRIMARY_IF_IDX < s->if_count)
        primary = WOLFIP_PRIMARY_IF_IDX;
    if (local_ip == IPADDR_ANY)
        return primary;
    for (i = 0; i < s->if_count; i++) {
        struct ipconf *conf = &s->ipconf[i];
        if (conf->ip == local_ip) {
            if (found)
                *found = 1;
            return i;
        }
    }
    return primary;
}

#ifdef ETHERNET
static uint16_t icmp_checksum(struct wolfIP_icmp_packet *icmp);
static void iphdr_set_checksum(struct wolfIP_ip_packet *ip);
static int eth_output_add_header(struct wolfIP *S, unsigned int if_idx, const uint8_t *dst, struct wolfIP_eth_frame *eth,
        uint16_t type);
#endif
#if WOLFIP_ENABLE_FORWARDING && defined(ETHERNET)
static void arp_request(struct wolfIP *s, unsigned int if_idx, ip4 tip);
static int arp_lookup(struct wolfIP *s, unsigned int if_idx, ip4 ip, uint8_t *mac);
#endif

#ifdef ETHERNET
static void wolfIP_send_ttl_exceeded(struct wolfIP *s, unsigned int if_idx, struct wolfIP_ip_packet *orig)
{
    struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, if_idx);
    struct wolfIP_icmp_packet icmp;
    if (!ll || !ll->send)
        return;
    memset(&icmp, 0, sizeof(icmp));
    icmp.type = ICMP_TTL_EXCEEDED;
    icmp.csum = ee16(icmp_checksum(&icmp));
    icmp.ip.ver_ihl = 0x45;
    icmp.ip.ttl = 64;
    icmp.ip.proto = WI_IPPROTO_ICMP;
    icmp.ip.id = ee16(s->ipcounter++);
    icmp.ip.len = ee16(IP_HEADER_LEN + ICMP_HEADER_LEN);
    icmp.ip.src = orig->dst;
    icmp.ip.dst = orig->src;
    icmp.ip.csum = 0;
    iphdr_set_checksum(&icmp.ip);
    eth_output_add_header(s, if_idx, orig->eth.src, &icmp.ip.eth, ETH_TYPE_IP);
    ll->send(ll, &icmp, sizeof(struct wolfIP_icmp_packet));
}
#else
static void wolfIP_send_ttl_exceeded(struct wolfIP *s, unsigned int if_idx, struct wolfIP_ip_packet *orig)
{
    (void)s;
    (void)if_idx;
    (void)orig;
}
#endif

/* User Callbacks */
void wolfIP_register_callback(struct wolfIP *s, int sock_fd, void (*cb)(int sock_fd, uint16_t events, void *arg), void *arg)
{
    struct tsocket *t;
    if (sock_fd < 0)
        return;
    if (sock_fd & MARK_TCP_SOCKET) {
        if ((sock_fd & (~MARK_TCP_SOCKET)) >= MAX_TCPSOCKETS)
            return;
        t = &s->tcpsockets[sock_fd & ~MARK_TCP_SOCKET];
        t->callback = cb;
        t->callback_arg = arg;
    } else if (sock_fd & MARK_UDP_SOCKET) {
        if ((sock_fd &(~MARK_UDP_SOCKET)) >= MAX_UDPSOCKETS)
            return;
        t = &s->udpsockets[sock_fd & ~MARK_UDP_SOCKET];
        t->callback = cb;
        t->callback_arg = arg;
    }
}

/* Timers */
static struct wolfIP_timer timers_binheap_pop(struct timers_binheap *heap)
{
    uint32_t i = 0;
    struct wolfIP_timer tmr = {0};
    do {
        tmr = heap->timers[0];
        heap->size--;
        heap->timers[0] = heap->timers[heap->size];
        while (2*i+1 < heap->size) {
            struct wolfIP_timer tmp;
            uint32_t j = 2*i+1;
            if (j+1 < heap->size && heap->timers[j+1].expires < heap->timers[j].expires) {
                j++;
            }
            if (heap->timers[i].expires <= heap->timers[j].expires) {
                break;
            }
            tmp = heap->timers[i];
            heap->timers[i] = heap->timers[j];
            heap->timers[j] = tmp;
            i = j;
        }
    } while ((tmr.expires == 0) && (heap->size > 0));
    return tmr;
}

static int timers_binheap_insert(struct timers_binheap *heap, struct wolfIP_timer tmr)
{
    static uint32_t timer_id = 1;
    int i;
    if (timer_id == 0)
        timer_id = 1;
    while (heap->size > 0 && heap->timers[0].expires == 0)
        timers_binheap_pop(heap);
    tmr.id = timer_id++;
    /* Insert at the end */
    heap->timers[heap->size] = tmr;
    heap->size++;
    i = heap->size - 1;
    while (i > 0 && heap->timers[i].expires < heap->timers[(i-1)/2].expires) {
        struct wolfIP_timer tmp = heap->timers[i];
        heap->timers[i] = heap->timers[(i-1)/2];
        heap->timers[(i-1)/2] = tmp;
        i = (i-1)/2;
    }
    return tmr.id;
}

static int is_timer_expired(struct timers_binheap *heap, uint64_t now)
{
    while (heap->size > 0 && heap->timers[0].expires == 0) {
        timers_binheap_pop(heap);
    }
    if (heap->size == 0) {
        return 0;
    }
    return (heap->timers[0].expires <= now)?1:0;
}

static void timer_binheap_cancel(struct timers_binheap *heap, uint32_t id)
{
    uint32_t i;
    for (i = 0; i < heap->size; i++) {
        if (heap->timers[i].id == id) {
            heap->timers[i].expires = 0;
            break;
        }
    }
}

/* UDP */
static struct tsocket *udp_new_socket(struct wolfIP *s)
{
    struct tsocket *t;
    int i;

    for (i = 0; i < MAX_UDPSOCKETS; i++) {
        t = &s->udpsockets[i];
        if (t->proto == 0) {
            t->proto = WI_IPPROTO_UDP;
            t->S = s;
            t->if_idx = 0;
            fifo_init(&t->sock.udp.rxbuf, t->rxmem, RXBUF_SIZE);
            fifo_init(&t->sock.udp.txbuf, t->txmem, TXBUF_SIZE);
            t->events |= CB_EVENT_WRITABLE;
            return t;
        }
    }
    return NULL;
}

static void udp_try_recv(struct wolfIP *s, unsigned int if_idx, struct wolfIP_udp_datagram *udp, uint32_t frame_len)
{
    struct ipconf *conf = wolfIP_ipconf_at(s, if_idx);
    int i;
    ip4 local_ip = conf ? conf->ip : IPADDR_ANY;
    ip4 dst_ip = ee32(udp->ip.dst);
    for (i = 0; i < MAX_UDPSOCKETS; i++) {
        struct tsocket *t = &s->udpsockets[i];
        if (t->src_port == ee16(udp->dst_port) && t->dst_port == ee16(udp->src_port) &&
                (((t->local_ip == 0) && DHCP_IS_RUNNING(s)) ||
                 (t->local_ip == dst_ip && t->remote_ip != local_ip)) ) {

            if (t->local_ip == 0)
                t->if_idx = (uint8_t)if_idx;

            /* UDP datagram sanity checks */
            if ((int)frame_len != ee16(udp->len) + IP_HEADER_LEN + ETH_HEADER_LEN)
                return;
            /* Insert into socket buffer */
            fifo_push(&t->sock.udp.rxbuf, udp, frame_len);
            t->events |= CB_EVENT_READABLE;
        }
    }
}

/* TCP */
static struct tsocket *tcp_new_socket(struct wolfIP *s)
{
    struct tsocket *t;
    int i;
    for (i = 0; i < MAX_TCPSOCKETS; i++) {
        t = &s->tcpsockets[i];
        if (t->proto == 0) {
            t->proto = WI_IPPROTO_TCP;
            t->S = s;
            t->if_idx = 0;
            t->sock.tcp.state = TCP_CLOSED;
            t->sock.tcp.rto = 1000;
            t->sock.tcp.cwnd = 2 * TCP_MSS;
            t->sock.tcp.ssthresh = 64 * TCP_MSS;
            t->sock.tcp.rtt = 0;
            t->sock.tcp.rto_backoff = 0;

            queue_init(&t->sock.tcp.rxbuf, t->rxmem, RXBUF_SIZE, 0);
            fifo_init(&t->sock.tcp.txbuf, t->txmem, TXBUF_SIZE);
            return t;
        }
    }
    return NULL;
}

static void tcp_send_empty(struct tsocket *t, uint8_t flags)
{
    struct wolfIP_tcp_seg *tcp;
    struct tcp_opt_ts *ts;
    uint8_t buffer[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN];
    tcp = (struct wolfIP_tcp_seg *)buffer;
    memset(tcp, 0, sizeof(buffer));
    tcp->src_port = ee16(t->src_port);
    tcp->dst_port = ee16(t->dst_port);
    tcp->seq = ee32(t->sock.tcp.seq);
    tcp->ack = ee32(t->sock.tcp.ack);
    tcp->hlen = ((20 + TCP_OPTIONS_LEN) << 2) & 0xF0;
    tcp->flags = flags;
    tcp->win = ee16((uint16_t)queue_space(&t->sock.tcp.rxbuf));
    tcp->csum = 0;
    tcp->urg = 0;
    ts = (struct tcp_opt_ts *)tcp->data;
    ts->opt = TCP_OPTION_TS;
    ts->len = TCP_OPTION_TS_LEN;
    ts->val = ee32(t->S->last_tick & 0xFFFFFFFFU);
    ts->ecr = t->sock.tcp.last_ts;
    ts->pad = 0x01;
    ts->eoo = 0x00;
    fifo_push(&t->sock.tcp.txbuf, tcp, sizeof(struct wolfIP_tcp_seg) + \
            TCP_OPTIONS_LEN);
}

static void tcp_send_ack(struct tsocket *t)
{
    return tcp_send_empty(t, 0x10);
}

static void tcp_send_finack(struct tsocket *t)
{
    tcp_send_empty(t, 0x11);
    t->sock.tcp.last = t->sock.tcp.seq;
}

static void tcp_send_syn(struct tsocket *t, uint8_t flags)
{
    struct wolfIP_tcp_seg *tcp;
    struct tcp_opt_ts *ts;
    struct tcp_opt_mss *mss;
    uint8_t buffer[sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN + TCP_OPTION_MSS_LEN];
    tcp = (struct wolfIP_tcp_seg *)buffer;
    memset(tcp, 0, sizeof(buffer));
    tcp->src_port = ee16(t->src_port);
    tcp->dst_port = ee16(t->dst_port);
    tcp->seq = ee32(t->sock.tcp.seq);
    tcp->ack = ee32(t->sock.tcp.ack);
    tcp->hlen = ((20 + TCP_OPTIONS_LEN + TCP_OPTION_MSS_LEN) << 2) & 0xF0;
    tcp->flags = flags;
    tcp->win = ee16((uint16_t)queue_space(&t->sock.tcp.rxbuf));
    tcp->csum = 0;
    tcp->urg = 0;
    ts = (struct tcp_opt_ts *)tcp->data;
    ts->opt = TCP_OPTION_TS;
    ts->len = TCP_OPTION_TS_LEN;
    ts->val = ee32(t->S->last_tick & 0xFFFFFFFFU);
    ts->ecr = t->sock.tcp.last_ts;
    ts->pad = 0x01;
    ts->eoo = 0x01;
    mss = (struct tcp_opt_mss *)((uint8_t *)tcp->data + sizeof(struct tcp_opt_ts));
    mss->opt = TCP_OPTION_MSS;
    mss->len = TCP_OPTION_MSS_LEN;
    mss->mss = ee16(TCP_MSS);
    fifo_push(&t->sock.tcp.txbuf, tcp, sizeof(struct wolfIP_tcp_seg) + \
            TCP_OPTIONS_LEN + TCP_OPTION_MSS_LEN);
}

static void tcp_send_synack(struct tsocket *t)
{
    return tcp_send_syn(t, 0x12);
}

/* Add a segment to the rx buffer for the application to consume */
static void tcp_recv(struct tsocket *t, struct wolfIP_tcp_seg *seg)
{
    uint32_t seg_len = ee16(seg->ip.len) - (IP_HEADER_LEN + (seg->hlen >> 2));
    uint32_t seq = ee32(seg->seq);
    if ((t->sock.tcp.state != TCP_ESTABLISHED) && (t->sock.tcp.state != TCP_CLOSE_WAIT)) {
        return;
    }
    if (t->sock.tcp.ack == seq) {
        /* push into queue */
        if (queue_insert(&t->sock.tcp.rxbuf, (uint8_t *)seg->ip.data + (seg->hlen >> 2),
                    seq, seg_len) < 0) {
            /* Buffer full, dropped. This will send a duplicate ack. */
        } else {
            /* Advance ack counter */
            t->sock.tcp.ack = seq + seg_len;
            timer_binheap_cancel(&t->S->timers, t->sock.tcp.tmr_rto);
            t->sock.tcp.tmr_rto = NO_TIMER;
            t->events |= CB_EVENT_READABLE;
        }
        tcp_send_ack(t);
    }
}

static uint16_t transport_checksum(union transport_pseudo_header *ph, void *_data)
{
    uint32_t sum = 0;
    uint32_t i = 0;
    uint16_t *ptr = (uint16_t *)ph->buf;
    uint16_t *data = (uint16_t *)_data;
    uint8_t *data8 = (uint8_t *)_data;
    uint16_t len = ee16(ph->ph.len);
    for (i = 0; i < 6; i++) {
        sum += ee16(ptr[i]);
    }
    for (i = 0; i < (len / 2); i++) {
        sum += ee16(data[i]);
    }
    if (len & 0x01) {
        uint16_t spare = 0;
        spare |= (data8[len - 1]) << 8;
        sum += spare;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}

static uint16_t icmp_checksum(struct wolfIP_icmp_packet *icmp)
{
    uint32_t sum = 0;
    uint32_t i = 0;
    uint16_t *ptr = (uint16_t *)(&icmp->type);
    for (i = 0; i < ICMP_HEADER_LEN / 2; i++) {
        sum += ee16(ptr[i]);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}

static void iphdr_set_checksum(struct wolfIP_ip_packet *ip)
{
    uint32_t sum = 0;
    uint32_t i = 0;
    uint16_t *ptr = (uint16_t *)(&ip->ver_ihl);
    for (i = 0; i < IP_HEADER_LEN / 2; i++) {
        sum += ee16(ptr[i]);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    ip->csum = ee16(~sum);
}

#ifdef ETHERNET
static int eth_output_add_header(struct wolfIP *S, unsigned int if_idx, const uint8_t *dst, struct wolfIP_eth_frame *eth,
        uint16_t type)
{
    struct wolfIP_ll_dev *ll = wolfIP_ll_at(S, if_idx);
    if (!ll)
        return -1;
    if (!dst) {
        /* Arp request, broadcast */
        memset(eth->dst, 0xff, 6);
    } else {
        /* Send to nexthop */
        memcpy(eth->dst, dst, 6);
    }
    memcpy(eth->src, ll->mac, 6);
    eth->type = ee16(type);
    return 0;
}
#endif

#if WOLFIP_ENABLE_FORWARDING
static int wolfIP_forward_prepare(struct wolfIP *s, unsigned int out_if, ip4 dest, uint8_t *mac, int *broadcast)
{
#ifdef ETHERNET
    if (!broadcast || !mac)
        return 0;
    if (wolfIP_is_loopback_if(out_if)) {
        struct wolfIP_ll_dev *loop = wolfIP_ll_at(s, out_if);
        if (loop)
            memcpy(mac, loop->mac, 6);
        *broadcast = 0;
        return 1;
    }
    if (IS_IP_BCAST(dest)) {
        *broadcast = 1;
        return 1;
    }
    *broadcast = 0;
    if (arp_lookup(s, out_if, dest, mac) == 0)
        return 1;
    arp_request(s, out_if, dest);
    return 0;
#else
    (void)s;
    (void)out_if;
    (void)dest;
    (void)mac;
    (void)broadcast;
    return 0;
#endif
}

static void wolfIP_forward_packet(struct wolfIP *s, unsigned int out_if, struct wolfIP_ip_packet *ip, uint32_t len, const uint8_t *mac, int broadcast)
{
#ifdef ETHERNET
    struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, out_if);
    if (!ll || !ll->send)
        return;
    if (broadcast)
        eth_output_add_header(s, out_if, NULL, &ip->eth, ETH_TYPE_IP);
    else
        eth_output_add_header(s, out_if, mac, &ip->eth, ETH_TYPE_IP);
    ll->send(ll, ip, len);
#else
    (void)s;
    (void)out_if;
    (void)ip;
    (void)len;
    (void)mac;
    (void)broadcast;
#endif
}
#endif

static int ip_output_add_header(struct tsocket *t, struct wolfIP_ip_packet *ip, uint8_t proto, uint16_t len)
{
    union transport_pseudo_header ph;
    unsigned int if_idx;
    memset(&ph, 0, sizeof(ph));
    memset(ip, 0, sizeof(struct wolfIP_ip_packet));
    ip->src = ee32(t->local_ip);
    ip->dst = ee32(t->remote_ip);
    ip->ver_ihl = 0x45;
    ip->tos = 0;
    ip->len = ee16(len);
    ip->flags_fo = 0;
    ip->ttl = 64;
    ip->proto = proto;
    ip->id = ee16(t->S->ipcounter++);
    ip->csum = 0;
    iphdr_set_checksum(ip);

    ph.ph.src = ip->src;
    ph.ph.dst = ip->dst;
    ph.ph.zero = 0;
    ph.ph.proto = proto;
    ph.ph.len = ee16(len - IP_HEADER_LEN);
    if (proto == WI_IPPROTO_TCP) {
        struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)ip;
        tcp->csum = 0;
        tcp->csum = ee16(transport_checksum(&ph, &tcp->src_port));
    } else if (proto == WI_IPPROTO_UDP) {
        struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)ip;
        udp->csum = 0;
        udp->csum = ee16(transport_checksum(&ph, &udp->src_port));
    }
#ifdef ETHERNET
    if_idx = wolfIP_socket_if_idx(t);
    eth_output_add_header(t->S, if_idx, t->nexthop_mac, (struct wolfIP_eth_frame *)ip, ETH_TYPE_IP);
#else
    (void)if_idx;
#endif
    return 0;
}

/* Process timestamp option, calculate RTT */
static int tcp_process_ts(struct tsocket *t, const struct wolfIP_tcp_seg *tcp)
{
    const struct tcp_opt_ts *ts;
    const uint8_t *opt = tcp->data;
    while (opt < ((const uint8_t *)tcp->data + (tcp->hlen >> 2))) {
        if (*opt == TCP_OPTION_NOP)
            opt++;
        else if (*opt == TCP_OPTION_EOO)
            break;
        else {
            ts = (const struct tcp_opt_ts *)opt;
            if (ts->opt == TCP_OPTION_TS) {
                t->sock.tcp.last_ts = ts->val;
                if (ts->ecr != 0)
                    return -1;
                if (t->sock.tcp.rtt == 0)
                    t->sock.tcp.rtt = (uint32_t)(t->S->last_tick - ee32(ts->ecr));
                else {
                    t->sock.tcp.rtt = (uint32_t)(7 * (t->sock.tcp.rtt << 3)) +
                        ((t->S->last_tick - ee32(ts->ecr)) << 3);
                }
                return 0;
            } else {
                opt += ts->len;
            }
        }
    }
    return -1;
}

#define SEQ_DIFF(a,b) ((a - b) > 0x7FFFFFFF) ? (b - a) : (a - b)

/* Receive an ack */
static void tcp_ack(struct tsocket *t, const struct wolfIP_tcp_seg *tcp)
{
    uint32_t ack = ee32(tcp->ack);
    struct pkt_desc *desc;
    int ack_count = 0;
    desc = fifo_peek(&t->sock.tcp.txbuf);
    while ((desc) && (desc->flags & PKT_FLAG_SENT)) {
        struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)(t->txmem + desc->pos + sizeof(*desc));
        uint32_t seg_len = ee16(seg->ip.len) - (IP_HEADER_LEN + (seg->hlen >> 2));
        if (seg_len == 0) {
            /* Advance the tail and discard */
            desc = fifo_pop(&t->sock.tcp.txbuf);
            (void)desc;
            desc = fifo_peek(&t->sock.tcp.txbuf);
            continue;
        }
        if (ee32(seg->seq) == t->sock.tcp.last && ee32(seg->seq) == ack) {
            if (t->sock.tcp.state == TCP_LAST_ACK) {
                t->sock.tcp.state = TCP_CLOSED;
                close_socket(t);
                return;
            }
        }
        if (SEQ_DIFF(ee32(seg->seq) + seg_len, ack) < fifo_len(&t->sock.tcp.txbuf)) {
            desc->flags |= PKT_FLAG_ACKED;
            desc = fifo_next(&t->sock.tcp.txbuf, desc);
            ack_count++;
        } else {
            break;
        }
    }
    if (ack_count > 0) {
        struct pkt_desc *fresh_desc = NULL;
        struct wolfIP_tcp_seg *seg;
        /* This ACK ackwnowledged some data. */
        desc = fifo_peek(&t->sock.tcp.txbuf);
        while (desc && (desc->flags & PKT_FLAG_ACKED)) {
            fresh_desc = fifo_pop(&t->sock.tcp.txbuf);
            desc = fifo_peek(&t->sock.tcp.txbuf);
        }
        if (fresh_desc) {
            seg = (struct wolfIP_tcp_seg *)(t->txmem + fresh_desc->pos + sizeof(*fresh_desc));
            /* Update rtt */
            if (tcp_process_ts(t, seg) < 0) {
                /* No timestamp option, use coarse RTT estimation */
                int rtt = t->S->last_tick - fresh_desc->time_sent;
                if (t->sock.tcp.rtt == 0) {
                    t->sock.tcp.rtt = rtt;
                } else {
                    t->sock.tcp.rtt = (7 * (t->sock.tcp.rtt << 3)) + (rtt << 3);
                }
            }
            /* Update cwnd */
            if (t->sock.tcp.cwnd < t->sock.tcp.ssthresh) {
                t->sock.tcp.cwnd += TCP_MSS;
            } else {
                t->sock.tcp.cwnd_count++;
                if (t->sock.tcp.cwnd_count == t->sock.tcp.cwnd) {
                    t->sock.tcp.cwnd_count = 0;
                    t->sock.tcp.cwnd += TCP_MSS;
                }
            }
            if (fifo_space(&t->sock.tcp.txbuf) > 0)
                t->events |= CB_EVENT_WRITABLE;
        }
    } else {
        /* Duplicate ack */
        t->sock.tcp.ssthresh = t->sock.tcp.cwnd / 2;
        if (t->sock.tcp.ssthresh < 2 * TCP_MSS) {
            t->sock.tcp.ssthresh = 2 * TCP_MSS;
        }
        t->sock.tcp.cwnd = t->sock.tcp.ssthresh + TCP_MSS;
        t->sock.tcp.cwnd_count = 0;
        desc = fifo_peek(&t->sock.tcp.txbuf);
        while (desc && (desc->flags & PKT_FLAG_SENT)) {
            struct wolfIP_tcp_seg *seg = (struct wolfIP_tcp_seg *)(t->txmem + desc->pos + sizeof(*desc));
            uint32_t seg_len = ee16(seg->ip.len) - (IP_HEADER_LEN + (seg->hlen >> 2));
            if (seg_len == 0) {
                /* Advance the tail and discard */
                desc = fifo_pop(&t->sock.tcp.txbuf);
                (void)desc;
                desc = fifo_peek(&t->sock.tcp.txbuf);
                continue;
            }
            if (ee32(seg->seq) == ack) {
                desc->flags &= ~PKT_FLAG_SENT; /* Resend */
                break;
            }
            desc = fifo_next(&t->sock.tcp.txbuf, desc);
        }
    }
}

/* Preselect socket, parse options, manage handshakes, pass to application */
static void tcp_input(struct wolfIP *S, unsigned int if_idx, struct wolfIP_tcp_seg *tcp, uint32_t frame_len)
{
    struct ipconf *conf = wolfIP_ipconf_at(S, if_idx);
    ip4 local_ip = conf ? conf->ip : IPADDR_ANY;
    int i;
    for (i = 0; i < MAX_TCPSOCKETS; i++) {
        uint32_t tcplen;
        uint32_t iplen;
        struct tsocket *t = &S->tcpsockets[i];
        if (t->src_port == ee16(tcp->dst_port) &&
                t->local_ip == ee32(tcp->ip.dst) && t->remote_ip != local_ip) {
            t->if_idx = (uint8_t)if_idx;
            /* TCP segment sanity checks */
            iplen = ee16(tcp->ip.len);
            if (iplen > frame_len - sizeof(struct wolfIP_eth_frame)) {
                return; /* discard */
            }

            if (t->sock.tcp.state > TCP_LISTEN) {
                if (t->dst_port != ee16(tcp->src_port) || t->remote_ip != ee32(tcp->ip.src)) {
                    /* Not the right socket */
                    continue;
                }
            }
            /* Check IP ttl */
            if (tcp->ip.ttl == 0) {
                wolfIP_send_ttl_exceeded(S, if_idx, &tcp->ip);
                return;
            }
            tcplen = iplen - (IP_HEADER_LEN + (tcp->hlen >> 2));
            /* Check if RST, close socket only if in SYN_SENT */
            if ((tcp->flags & 0x04) && (t->sock.tcp.state == TCP_SYN_SENT)) {
                close_socket(t);
            }

            /* Check if FIN */
            if (tcp->flags & 0x01) {
                if (t->sock.tcp.state == TCP_ESTABLISHED) {
                    t->sock.tcp.state = TCP_CLOSE_WAIT;
                    t->sock.tcp.ack = ee32(tcp->seq) + 1;
                    tcp_send_ack(t);
                    t->events |= CB_EVENT_CLOSED | CB_EVENT_READABLE;
                }
                else if (t->sock.tcp.state == TCP_FIN_WAIT_1) {
                    t->sock.tcp.state = TCP_CLOSING;
                    t->sock.tcp.ack = ee32(tcp->seq) + 1;
                    tcp_send_ack(t);
                    t->events |= CB_EVENT_CLOSED | CB_EVENT_READABLE;
                }
            }
            /* Check if SYN */
            if (tcp->flags & 0x02) {
                if (t->sock.tcp.state == TCP_LISTEN) {
                    t->sock.tcp.state = TCP_SYN_RCVD;
                    t->sock.tcp.ack = ee32(tcp->seq) + 1;
                    t->sock.tcp.seq = wolfIP_getrandom();
                    t->dst_port = ee16(tcp->src_port);
                    t->remote_ip = ee32(tcp->ip.src);
                    t->events |= CB_EVENT_READABLE; /* Keep flag until application calls accept */
                    tcp_process_ts(t, tcp);
                    break;
                } else if (t->sock.tcp.state == TCP_SYN_SENT) {
                    if (tcp->flags == 0x12) {
                        t->sock.tcp.state = TCP_ESTABLISHED;
                        t->sock.tcp.ack = ee32(tcp->seq) + 1;
                        t->sock.tcp.seq = ee32(tcp->ack);
                        t->events |= CB_EVENT_WRITABLE;
                        tcp_process_ts(t, tcp);
                        tcp_send_ack(t);
                    }
                }
            }
            /* Check if pure ACK to SYN-ACK */
            if ((tcplen == 0) && (t->sock.tcp.state == TCP_SYN_RCVD)) {
                if (tcp->flags == 0x10)  {
                    t->sock.tcp.state = TCP_ESTABLISHED;
                    t->sock.tcp.ack = ee32(tcp->seq);
                    t->sock.tcp.seq = ee32(tcp->ack);
                    t->events |= CB_EVENT_WRITABLE;
                }
            } else if (t->sock.tcp.state == TCP_LAST_ACK) {
                tcp_send_ack(t);
                close_socket(t);
            }
            else if ((t->sock.tcp.state == TCP_ESTABLISHED) ||
                    (t->sock.tcp.state == TCP_FIN_WAIT_1) ||
                    (t->sock.tcp.state == TCP_FIN_WAIT_2)) {

                if (tcp->flags & 0x01) {
                    /* FIN */
                    if (t->sock.tcp.state == TCP_ESTABLISHED) {
                        t->sock.tcp.state = TCP_CLOSE_WAIT;
                        t->events &= ~CB_EVENT_READABLE;
                    } else if (t->sock.tcp.state == TCP_FIN_WAIT_1) {
                        t->sock.tcp.state = TCP_CLOSING;
                    }
                    t->sock.tcp.ack = ee32(tcp->seq) + 1;
                    t->events |= CB_EVENT_CLOSED | CB_EVENT_READABLE;
                    tcp_send_ack(t);
                }
                if (tcp->flags & 0x10) {
                    tcp_ack(t, tcp);
                    tcp_process_ts(t, tcp);
                }
                if (tcplen == 0)
                    return;
                if ((t->sock.tcp.state == TCP_LAST_ACK) || (t->sock.tcp.state == TCP_CLOSING) || (t->sock.tcp.state == TCP_CLOSED))
                    return;
                tcp_recv(t, tcp);
            }
        }
    }
}

static void tcp_rto_cb(void *arg)
{
    struct tsocket *ts = (struct tsocket *)arg;
    struct pkt_desc *desc;
    struct wolfIP_timer tmr = { };
    struct wolfIP_timer *ptmr = NULL;
    int pending = 0;
    if ((ts->proto != WI_IPPROTO_TCP) || (ts->sock.tcp.state != TCP_ESTABLISHED))
        return;
    desc = fifo_peek(&ts->sock.tcp.txbuf);
    while (desc) {
        if (desc->flags & PKT_FLAG_SENT) {
            desc->flags &= ~PKT_FLAG_SENT;
            pending++;
        }
        desc = fifo_next(&ts->sock.tcp.txbuf, desc);
    }

    if (ts->sock.tcp.tmr_rto != NO_TIMER) {
        timer_binheap_cancel(&ts->S->timers, ts->sock.tcp.tmr_rto);
        ts->sock.tcp.tmr_rto = NO_TIMER;
    }
    if (pending) {
        ts->sock.tcp.rto_backoff++;
        ts->sock.tcp.cwnd = TCP_MSS;
        ts->sock.tcp.ssthresh = ts->sock.tcp.cwnd / 2;

        ptmr = &tmr;
        ptmr->expires = ts->S->last_tick + (ts->sock.tcp.rto << ts->sock.tcp.rto_backoff);
        ptmr->arg = ts;
        ptmr->cb = tcp_rto_cb;
        ts->sock.tcp.tmr_rto = timers_binheap_insert(&ts->S->timers, *ptmr);
    } else {
        ts->sock.tcp.rto_backoff = 0;
    }
}

static void close_socket(struct tsocket *ts)
{
    memset(ts, 0, sizeof(struct tsocket));
}


int wolfIP_sock_socket(struct wolfIP *s, int domain, int type, int protocol)
{
    struct tsocket *ts;
    if (domain != AF_INET)
        return -1;
    (void)protocol;
    if (type == IPSTACK_SOCK_STREAM) {
        ts = tcp_new_socket(s);
        if (!ts)
            return -1;
        return (ts - s->tcpsockets) | MARK_TCP_SOCKET;
    } else if (type == IPSTACK_SOCK_DGRAM) {
        ts = udp_new_socket(s);
        if (!ts)
            return -1;
        return (ts - s->udpsockets) | MARK_UDP_SOCKET;
    }
    return -1;
}

int wolfIP_sock_connect(struct wolfIP *s, int sockfd, const struct wolfIP_sockaddr *addr, socklen_t addrlen)
{
    struct tsocket *ts;
    const struct wolfIP_sockaddr_in *sin;
    unsigned int if_idx;
    if (!addr)
        return -WOLFIP_EINVAL;
    sin = (const struct wolfIP_sockaddr_in *)addr;
    if (sockfd & MARK_UDP_SOCKET) {
        struct ipconf *conf;
        ts = &s->udpsockets[sockfd & ~MARK_UDP_SOCKET];
        ts->dst_port = ee16(sin->sin_port);
        ts->remote_ip = ee32(sin->sin_addr.s_addr);
        if_idx = wolfIP_route_for_ip(s, ts->remote_ip);
        conf = wolfIP_ipconf_at(s, if_idx);
        ts->if_idx = (uint8_t)if_idx;
        if (ts->local_ip == 0 && conf && conf->ip != IPADDR_ANY)
            ts->local_ip = conf->ip;
        else if (ts->local_ip == 0) {
            struct ipconf *primary = wolfIP_primary_ipconf(s);
            if (primary && primary->ip != IPADDR_ANY)
                ts->local_ip = primary->ip;
        }
        return 0;
    }
    if ((sockfd & MARK_TCP_SOCKET) == 0)
        return -1;
    ts = &s->tcpsockets[sockfd & ~MARK_TCP_SOCKET];
    if (ts->sock.tcp.state == TCP_ESTABLISHED)
        return 0;
    if (ts->sock.tcp.state == TCP_SYN_SENT)
        return -WOLFIP_EAGAIN; /* Call again */
    if ((sin->sin_family != AF_INET) || (addrlen < sizeof(struct wolfIP_sockaddr_in)))
        return -WOLFIP_EINVAL;
    if (ts->sock.tcp.state == TCP_CLOSED) {
        struct ipconf *conf;
        ts->sock.tcp.state = TCP_SYN_SENT;
        ts->remote_ip = ee32(sin->sin_addr.s_addr);
        if_idx = wolfIP_route_for_ip(s, ts->remote_ip);
        conf = wolfIP_ipconf_at(s, if_idx);
        ts->if_idx = (uint8_t)if_idx;
        if (conf && conf->ip != IPADDR_ANY)
            ts->local_ip = conf->ip;
        else {
            struct ipconf *primary = wolfIP_primary_ipconf(s);
            if (primary && primary->ip != IPADDR_ANY)
                ts->local_ip = primary->ip;
            else
                ts->local_ip = 0;
        }
        if (!ts->src_port)
            ts->src_port = (uint16_t)(wolfIP_getrandom() & 0xFFFF);
        if (ts->src_port < 1024)
            ts->src_port += 1024;
        ts->dst_port = ee16(sin->sin_port);
        tcp_send_syn(ts, 0x02);
        return -WOLFIP_EAGAIN;
    }
    return -WOLFIP_EINVAL;
}

int wolfIP_sock_accept(struct wolfIP *s, int sockfd, struct wolfIP_sockaddr *addr, socklen_t *addrlen)
{
    struct tsocket *ts;
    struct wolfIP_sockaddr_in *sin = (struct wolfIP_sockaddr_in *)addr;
    struct tsocket *newts;

    if ((addr) && (!(addrlen) || (*addrlen < sizeof(struct wolfIP_sockaddr_in))))
        return -1;

    if (addr && addrlen)
        *addrlen = sizeof(struct wolfIP_sockaddr_in);

    if (sockfd & MARK_TCP_SOCKET) {
        ts = &s->tcpsockets[sockfd & ~MARK_TCP_SOCKET];
        if ((ts->sock.tcp.state != TCP_SYN_RCVD) && (ts->sock.tcp.state != TCP_LISTEN))
            return -1;

        if (ts->sock.tcp.state == TCP_SYN_RCVD) {
            tcp_send_synack(ts);
            newts = tcp_new_socket(s);
            if (!newts)
                return -1;
            ts->events &= ~CB_EVENT_READABLE;
            newts->events |= CB_EVENT_WRITABLE;
            newts->callback = ts->callback;
            newts->callback_arg = ts->callback_arg;
            newts->local_ip = ts->local_ip;
            newts->if_idx = ts->if_idx;
            newts->remote_ip = ts->remote_ip;
            newts->src_port = ts->src_port;
            newts->dst_port = ts->dst_port;
            newts->sock.tcp.ack = ts->sock.tcp.ack;
            newts->sock.tcp.seq = ts->sock.tcp.seq + 1;
            newts->sock.tcp.state = TCP_ESTABLISHED;
            if (sin) {
                sin->sin_family = AF_INET;
                sin->sin_port = ee16(ts->dst_port);
                sin->sin_addr.s_addr = ee32(ts->remote_ip);
            }
            ts->sock.tcp.state = TCP_LISTEN;
            ts->sock.tcp.seq = wolfIP_getrandom();
            return (newts - s->tcpsockets) | MARK_TCP_SOCKET;
        } else if (ts->sock.tcp.state == TCP_LISTEN) {
            return -WOLFIP_EAGAIN;
        }
    }
    return -1;;
}

int wolfIP_sock_sendto(struct wolfIP *s, int sockfd, const void *buf, size_t len, int flags,
        const struct wolfIP_sockaddr *dest_addr, socklen_t addrlen)
{
    uint8_t frame[LINK_MTU];
    struct tsocket *ts;
    struct wolfIP_tcp_seg *tcp;
    struct wolfIP_udp_datagram *udp;
    tcp = (struct wolfIP_tcp_seg *)frame;
    udp = (struct wolfIP_udp_datagram *)frame;
    (void)flags;

    if (sockfd < 0)
        return -1;

    if ((!buf) || (len == 0))
        return -1;

    if (sockfd & MARK_TCP_SOCKET) {
        size_t sent = 0;
        struct tcp_opt_ts *tsopt = (struct tcp_opt_ts *)tcp->data;
        ts = &s->tcpsockets[sockfd & ~MARK_TCP_SOCKET];
        if (ts->sock.tcp.state != TCP_ESTABLISHED)
            return -1;
        while (sent < len) {
            uint32_t payload_len = len - sent;
            if (payload_len > (TCP_MSS - TCP_OPTIONS_LEN))
                payload_len = (TCP_MSS - TCP_OPTIONS_LEN);
            if (fifo_space(&ts->sock.tcp.txbuf) < payload_len + sizeof(struct pkt_desc) + IP_HEADER_LEN + TCP_HEADER_LEN + TCP_OPTIONS_LEN) {
                break;
            }
            memset(tcp, 0, sizeof(struct wolfIP_tcp_seg));
            tcp->src_port = ee16(ts->src_port);
            tcp->dst_port = ee16(ts->dst_port);
            tcp->seq = ee32(ts->sock.tcp.seq);
            tcp->ack = ee32(ts->sock.tcp.ack);
            tcp->hlen = (TCP_HEADER_LEN + TCP_OPTIONS_LEN) << 2;
            tcp->flags = 0x10 | ((sent == 0)? 0x08 : 0); /* ACK; PSH only on first */
            tcp->win = ee16(queue_space(&ts->sock.tcp.rxbuf));
            tcp->csum = 0;
            tcp->urg = 0;
            tsopt->opt = TCP_OPTION_TS;
            tsopt->len = TCP_OPTION_TS_LEN;
            tsopt->val = ee32(s->last_tick & 0xFFFFFFFF);
            tsopt->ecr = ts->sock.tcp.last_ts;
            tsopt->pad = 0x01;
            tsopt->eoo = 0x00;
            memcpy((uint8_t *)tcp->data + TCP_OPTIONS_LEN, (const uint8_t *)buf + sent, payload_len);
            fifo_push(&ts->sock.tcp.txbuf, tcp, sizeof(struct wolfIP_tcp_seg) + TCP_OPTIONS_LEN + payload_len);
            sent += payload_len;
            ts->sock.tcp.seq += payload_len;
        }
        if (sent == 0)
            return -WOLFIP_EAGAIN;
        else
            return sent;
    } else if (sockfd & MARK_UDP_SOCKET) {
        const struct wolfIP_sockaddr_in *sin = (const struct wolfIP_sockaddr_in *)dest_addr;
        unsigned int if_idx;
        struct ipconf *conf;
        ts = &s->udpsockets[sockfd & ~MARK_UDP_SOCKET];
        if ((ts->dst_port == 0) && (dest_addr == NULL))
            return -1;
        memset(udp, 0, sizeof(struct wolfIP_udp_datagram));
        if (sin) {
            if (addrlen < sizeof(struct wolfIP_sockaddr_in))
                return -1;
            ts->dst_port = ee16(sin->sin_port);
            ts->remote_ip = ee32(sin->sin_addr.s_addr);
        }
        if ((ts->dst_port==0) || (ts->remote_ip==0))
            return -1;
        if (len > WI_IP_MTU - IP_HEADER_LEN - UDP_HEADER_LEN)
            return -1; /* Fragmentation not supported */
        if (fifo_space(&ts->sock.udp.txbuf) < len)
            return -WOLFIP_EAGAIN;
        if (ts->src_port == 0) {
            ts->src_port = (uint16_t)(wolfIP_getrandom() & 0xFFFF);
            if (ts->src_port < 1024)
                ts->src_port += 1024;
        }
        if_idx = wolfIP_route_for_ip(s, ts->remote_ip);
        conf = wolfIP_ipconf_at(s, if_idx);
        ts->if_idx = (uint8_t)if_idx;
        if (ts->local_ip == 0) {
            if (conf && conf->ip != IPADDR_ANY)
                ts->local_ip = conf->ip;
            else {
                struct ipconf *primary = wolfIP_primary_ipconf(s);
                if (primary && primary->ip != IPADDR_ANY)
                    ts->local_ip = primary->ip;
            }
        }

        udp->src_port = ee16(ts->src_port);
        udp->dst_port = ee16(ts->dst_port);
        udp->len = ee16(len + UDP_HEADER_LEN);
        udp->csum = 0;
        memcpy(udp->data, buf, len);
        fifo_push(&ts->sock.udp.txbuf, udp, sizeof(struct wolfIP_udp_datagram) + len);
        return len;
    } else return -1;
}

int wolfIP_sock_send(struct wolfIP *s, int sockfd, const void *buf, size_t len, int flags)
{
    return wolfIP_sock_sendto(s, sockfd, buf, len, flags, NULL, 0);
} 

int wolfIP_sock_write(struct wolfIP *s, int sockfd, const void *buf, size_t len)
{
    return wolfIP_sock_sendto(s, sockfd, buf, len, 0, NULL, 0);
}

int wolfIP_sock_recvfrom(struct wolfIP *s, int sockfd, void *buf, size_t len, int flags,
        struct wolfIP_sockaddr *src_addr, socklen_t *addrlen)
{
    uint32_t seg_len;
    struct pkt_desc *desc;
    struct wolfIP_udp_datagram *udp;
    struct tsocket *ts;
    (void)flags;

    if (sockfd & MARK_TCP_SOCKET) {
        ts = &s->tcpsockets[sockfd & ~MARK_TCP_SOCKET];
        if (ts->sock.tcp.state == TCP_CLOSE_WAIT)
        {
            /* In close-wait, return 0 if the queue is empty */
            if (queue_len(&ts->sock.tcp.rxbuf) == 0)
                return 0;
            return queue_pop(&ts->sock.tcp.rxbuf, buf, len);
        } else if (ts->sock.tcp.state == TCP_ESTABLISHED) {
            int ret = queue_pop(&ts->sock.tcp.rxbuf, buf, len);
            if ((ret > 0) && (queue_len(&ts->sock.tcp.rxbuf) > 0))
                ts->events |= CB_EVENT_READABLE;
            return ret;
        } else { /* Not established */
            return -1;
        }
    } else if (sockfd & MARK_UDP_SOCKET) {
        struct wolfIP_sockaddr_in *sin = (struct wolfIP_sockaddr_in *)src_addr;
        ts = &s->udpsockets[sockfd & ~MARK_UDP_SOCKET];
        if (sin && *addrlen < sizeof(struct wolfIP_sockaddr_in))
            return -1;
        if (addrlen) *addrlen = sizeof(struct wolfIP_sockaddr_in);
        if (fifo_len(&ts->sock.udp.rxbuf) == 0)
            return -WOLFIP_EAGAIN;
        desc = fifo_peek(&ts->sock.udp.rxbuf);
        udp = (struct wolfIP_udp_datagram *)(ts->rxmem + desc->pos + sizeof(*desc));
        if (sin) {
            sin->sin_family = AF_INET;
            sin->sin_port = ee16(udp->src_port);
            sin->sin_addr.s_addr = ee32(ts->remote_ip);
        }
        seg_len = ee16(udp->len) - UDP_HEADER_LEN;
        if (seg_len > len)
            return -1;
        memcpy(buf, udp->data, seg_len);
        fifo_pop(&ts->sock.udp.rxbuf);
        return seg_len;
    } else return -1;
}

int wolfIP_sock_recv(struct wolfIP *s, int sockfd, void *buf, size_t len, int flags)
{
    return wolfIP_sock_recvfrom(s, sockfd, buf, len, flags, NULL, 0);
}

int wolfIP_sock_read(struct wolfIP *s, int sockfd, void *buf, size_t len)
{
    return wolfIP_sock_recvfrom(s, sockfd, buf, len, 0, NULL, 0);
}

int wolfIP_sock_close(struct wolfIP *s, int sockfd)
{
    if (sockfd & MARK_TCP_SOCKET) {
        struct tsocket *ts = &s->tcpsockets[sockfd & ~MARK_TCP_SOCKET];
        if (ts->sock.tcp.state == TCP_ESTABLISHED) {
            ts->sock.tcp.state = TCP_FIN_WAIT_1;
            tcp_send_finack(ts);
            return -WOLFIP_EAGAIN;
        } else if (ts->sock.tcp.state == TCP_CLOSE_WAIT) {
            ts->sock.tcp.state = TCP_LAST_ACK;
            tcp_send_finack(ts);
            return -WOLFIP_EAGAIN;
        } else if (ts->sock.tcp.state == TCP_CLOSING) {
            ts->sock.tcp.state = TCP_TIME_WAIT;
            return -WOLFIP_EAGAIN;
        } else if (ts->sock.tcp.state == TCP_FIN_WAIT_1) {
            ts->sock.tcp.state = TCP_CLOSING;
            return -WOLFIP_EAGAIN;
        } else if (ts->sock.tcp.state == TCP_FIN_WAIT_2) {
            ts->sock.tcp.state = TCP_TIME_WAIT;
            return -WOLFIP_EAGAIN;
        } else if (ts->sock.tcp.state != TCP_CLOSED) {
            ts->sock.tcp.state = TCP_CLOSED;
            close_socket(ts);
            return 0;
        } else return -1;
    } else if (sockfd & MARK_UDP_SOCKET) {
        struct tsocket *ts = &s->udpsockets[sockfd & ~MARK_UDP_SOCKET];
        close_socket(ts);
        return 0;
    } else return -1;
    return 0;
}

int wolfIP_sock_getsockname(struct wolfIP *s, int sockfd, struct wolfIP_sockaddr *addr, const socklen_t *addrlen)
{
    struct tsocket *ts = &s->tcpsockets[sockfd];
    struct wolfIP_sockaddr_in *sin = (struct wolfIP_sockaddr_in *)addr;
    if (!sin || *addrlen < sizeof(struct wolfIP_sockaddr_in))
        return -1;
    sin->sin_family = AF_INET;
    sin->sin_port = ts->src_port;
    sin->sin_addr.s_addr = ts->local_ip;
    return 0;
}

int wolfIP_sock_bind(struct wolfIP *s, int sockfd, const struct wolfIP_sockaddr *addr, socklen_t addrlen)
{
    struct tsocket *ts;
    ip4 bind_ip;
    struct ipconf *conf;
    const struct wolfIP_sockaddr_in *sin = (const struct wolfIP_sockaddr_in *)addr;
    int match = 0;
    unsigned int if_idx;

    if (!sin || addrlen < sizeof(struct wolfIP_sockaddr_in))
        return -1;
    bind_ip = ee32(sin->sin_addr.s_addr);
    if_idx = wolfIP_if_for_local_ip(s, bind_ip, &match);
    conf = wolfIP_ipconf_at(s, if_idx);
    if ((bind_ip != IPADDR_ANY) && !match)
        return -1;

    if (sockfd & MARK_TCP_SOCKET) {
        ts = &s->tcpsockets[sockfd & ~MARK_TCP_SOCKET];
        if (ts->sock.tcp.state != TCP_CLOSED)
            return -1;
        if ((sin->sin_family != AF_INET) || (addrlen < sizeof(struct wolfIP_sockaddr_in)))
            return -1;
        ts->if_idx = (uint8_t)if_idx;
        if (bind_ip != IPADDR_ANY)
            ts->local_ip = bind_ip;
        else if (conf && conf->ip != IPADDR_ANY)
            ts->local_ip = conf->ip;
        else {
            struct ipconf *primary = wolfIP_primary_ipconf(s);
            if (primary && primary->ip != IPADDR_ANY)
                ts->local_ip = primary->ip;
        }
        ts->src_port = ee16(sin->sin_port);
        return 0;
    } else if (sockfd & MARK_UDP_SOCKET) {
        ts = &s->udpsockets[sockfd & ~MARK_UDP_SOCKET];
        if (ts->src_port != 0)
            return -1;
        if ((sin->sin_family != AF_INET) || (addrlen < sizeof(struct wolfIP_sockaddr_in)))
            return -1;
        ts->if_idx = (uint8_t)if_idx;
        if (bind_ip != IPADDR_ANY)
            ts->local_ip = bind_ip;
        else if (conf && conf->ip != IPADDR_ANY)
            ts->local_ip = conf->ip;
        else {
            struct ipconf *primary = wolfIP_primary_ipconf(s);
            if (primary && primary->ip != IPADDR_ANY)
                ts->local_ip = primary->ip;
        }
        ts->src_port = ee16(sin->sin_port);
        return 0;
    } else return -1;

}

int wolfIP_sock_listen(struct wolfIP *s, int sockfd, int backlog)
{
    struct tsocket *ts;
    (void)backlog;
    if (sockfd & MARK_TCP_SOCKET) {
        ts = &s->tcpsockets[sockfd & ~MARK_TCP_SOCKET];
    } else return -1;
    if (ts->sock.tcp.state != TCP_CLOSED)
        return -1;
    ts->sock.tcp.state = TCP_LISTEN;
    return 0;
}

int wolfIP_sock_getpeername(struct wolfIP *s, int sockfd, struct wolfIP_sockaddr *addr, const socklen_t *addrlen)
{
    struct tsocket *ts = &s->tcpsockets[sockfd];
    struct wolfIP_sockaddr_in *sin = (struct wolfIP_sockaddr_in *)addr;
    if (!sin || *addrlen < sizeof(struct wolfIP_sockaddr_in))
        return -1;
    sin->sin_family = AF_INET;
    sin->sin_port = ee16(ts->dst_port);
    sin->sin_addr.s_addr = ee32(ts->remote_ip);
    return 0;
}


/* Reply to ICecho requests */
static void icmp_input(struct wolfIP *s, unsigned int if_idx, struct wolfIP_ip_packet *ip, uint32_t len)
{
    struct wolfIP_icmp_packet *icmp = (struct wolfIP_icmp_packet *)ip;
    uint32_t tmp;
    struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, if_idx);
    if (!DHCP_IS_RUNNING(s) && (icmp->type == ICMP_ECHO_REQUEST)) {
        icmp->type = ICMP_ECHO_REPLY;
        icmp->csum += 8;
        tmp = ip->src;
        ip->src = ip->dst;
        ip->dst = tmp;
        ip->id = ee16(s->ipcounter++);
        ip->csum = 0;
        iphdr_set_checksum(ip);
        eth_output_add_header(s, if_idx, ip->eth.src, &ip->eth, ETH_TYPE_IP);
        if (ll && ll->send)
            ll->send(ll, ip, len);
    }
}

static int dhcp_send_discover(struct wolfIP *s);
static int dhcp_send_request(struct wolfIP *s);
static void dhcp_timer_cb(void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    LOG("dhcp timeout\n");
    if (!s)
        return;
    switch(s->dhcp_state) {
        case DHCP_DISCOVER_SENT:
            if (s->dhcp_timeout_count < DHCP_DISCOVER_RETRIES) {
                dhcp_send_discover(s);
                s->dhcp_timeout_count++;
            } else
                s->dhcp_state = DHCP_OFF;
            break;
        case DHCP_REQUEST_SENT:
            if (s->dhcp_timeout_count < DHCP_REQUEST_RETRIES) {
                dhcp_send_request(s);
                s->dhcp_timeout_count++;
            } else
                s->dhcp_state = DHCP_OFF;
            break;
        default:
            break;
    }
}

static void dhcp_cancel_timer(struct wolfIP *s)
{
    if (s->dhcp_timer != NO_TIMER) {
        timer_binheap_cancel(&s->timers, s->dhcp_timer);
        s->dhcp_timer = NO_TIMER;
        s->dhcp_timeout_count = 0;
    }
}

static int dhcp_parse_offer(struct wolfIP *s, struct dhcp_msg *msg)
{
    struct dhcp_option *opt = (struct dhcp_option *)(msg->options);
    uint32_t ip;
    uint32_t netmask = 0xFFFFFF00;
    struct ipconf *primary = wolfIP_primary_ipconf(s);
    while (opt->code != 0xFF) {
        if (opt->code == DHCP_OPTION_MSG_TYPE) {
            if (opt->data[0] == DHCP_OFFER) {
                opt = (struct dhcp_option *)((uint8_t *)opt + 3);
                while (opt->code != 0xFF) {
                    if (opt->code == DHCP_OPTION_SERVER_ID) {
                        uint32_t data = opt->data[0] | (opt->data[1] << 8) | (opt->data[2] << 16) | (opt->data[3] << 24);
                        s->dhcp_server_ip = ee32(data);
                    }
                    if (opt->code == DHCP_OPTION_SUBNET_MASK) {
                        netmask = opt->data[0] | (opt->data[1] << 8) | (opt->data[2] << 16) | (opt->data[3] << 24);
                    }

                    opt = (struct dhcp_option *)((uint8_t *)opt + 2 + opt->len);
                }
                ip = ee32(msg->yiaddr);
                if (primary) {
                    primary->ip = ip;
                    primary->mask = ee32(netmask);
                }
                s->dhcp_ip = ip;
                dhcp_cancel_timer(s);
                s->dhcp_state = DHCP_REQUEST_SENT;
                return 0;
            }
        }
        opt = (struct dhcp_option *)((uint8_t *)opt + 2 + opt->len);
    }
    if ((s->dhcp_server_ip != 0) && (s->dhcp_ip != 0)) {
        s->dhcp_state = DHCP_REQUEST_SENT;
        return 0;
    }
    return -1;
}


static int dhcp_parse_ack(struct wolfIP *s, struct dhcp_msg *msg)
{
    struct dhcp_option *opt = (struct dhcp_option *)(msg->options);
    struct ipconf *primary = wolfIP_primary_ipconf(s);
    while (opt->code != 0xFF) {
        if (opt->code == DHCP_OPTION_MSG_TYPE) {
            if (opt->data[0] == DHCP_ACK) {
                uint32_t data;
                opt = (struct dhcp_option *)((uint8_t *)opt + 3);
                data = opt->data[0] | (opt->data[1] << 8) | (opt->data[2] << 16) | (opt->data[3] << 24);
                while (opt->code != 0xFF) {
                    if (opt->code == DHCP_OPTION_SERVER_ID)
                        s->dhcp_server_ip = ee32(data);
                    if (primary) {
                        if (opt->code == DHCP_OPTION_OFFER_IP)
                            primary->ip = ee32(data);
                        if (opt->code == DHCP_OPTION_SUBNET_MASK)
                            primary->mask = ee32(data);
                        if (opt->code == DHCP_OPTION_ROUTER)
                            primary->gw = ee32(data);
                    }
                    if ((opt->code == DHCP_OPTION_DNS) && (s->dns_server == 0))
                        s->dns_server = ee32(data);
                    opt = (struct dhcp_option *)((uint8_t *)opt + 2 + opt->len);
                }
                if (primary && (primary->ip != 0) && (primary->mask != 0)) {
                    dhcp_cancel_timer(s);
                    s->dhcp_state = DHCP_BOUND;
                    return 0;
                }
            } else break;
        } else break;
    }
    return -1;
}

static int dhcp_poll(struct wolfIP *s)
{
    struct wolfIP_sockaddr_in sin;
    socklen_t sl = sizeof(struct wolfIP_sockaddr_in);
    struct dhcp_msg msg;
    int len;
    memset(&msg, 0xBB, sizeof(msg));
    len = wolfIP_sock_recvfrom(s, s->dhcp_udp_sd, &msg, sizeof(struct dhcp_msg), 0, (struct wolfIP_sockaddr *)&sin, &sl);
    if (len < 0)
        return -1;
    if ((s->dhcp_state == DHCP_DISCOVER_SENT) && (dhcp_parse_offer(s, &msg) == 0))
        dhcp_send_request(s);
    else if ((s->dhcp_state == DHCP_REQUEST_SENT) && (dhcp_parse_ack(s, &msg) == 0)) {
        struct ipconf *primary = wolfIP_primary_ipconf(s);
        LOG("DHCP configuration received.\n");
        if (primary) {
            LOG("IP Address: %u.%u.%u.%u\n", (primary->ip >> 24) & 0xFF, (primary->ip >> 16) & 0xFF, (primary->ip >> 8) & 0xFF, (primary->ip >> 0) & 0xFF);
            LOG("Subnet Mask: %u.%u.%u.%u\n", (primary->mask >> 24) & 0xFF, (primary->mask >> 16) & 0xFF, (primary->mask >> 8) & 0xFF, (primary->mask >> 0) & 0xFF);
            LOG("Gateway: %u.%u.%u.%u\n", (primary->gw >> 24) & 0xFF, (primary->gw >> 16) & 0xFF, (primary->gw >> 8) & 0xFF, (primary->gw >> 0) & 0xFF);
        }
        if (s->dns_server)
            LOG("DNS Server: %u.%u.%u.%u\n", (s->dns_server >> 24) & 0xFF, (s->dns_server >> 16) & 0xFF, (s->dns_server >> 8) & 0xFF, (s->dns_server >> 0) & 0xFF);
    }
    return 0;
}

static int dhcp_send_request(struct wolfIP *s)
{
    struct dhcp_msg req;
    struct dhcp_option *opt = (struct dhcp_option *)(req.options);
    struct wolfIP_timer tmr = { };
    struct wolfIP_sockaddr_in sin;
    uint32_t opt_sz = 0;
    /* Prepare DHCP request */
    memset(&req, 0, sizeof(struct dhcp_msg));
    req.op = BOOT_REQUEST;
    s->dhcp_state = DHCP_REQUEST_SENT;
    req.htype = 1; /* Ethernet */
    req.hlen = 6; /* MAC */
    req.xid = ee32(s->dhcp_xid);
    req.magic = ee32(DHCP_MAGIC);
    {
        struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, WOLFIP_PRIMARY_IF_IDX);
        if (ll)
            memcpy(req.chaddr, ll->mac, 6);
        else
            memset(req.chaddr, 0, 6);
    }

    /* Set options */
    memset(req.options, 0xFF, sizeof(req.options));
    opt->code = DHCP_OPTION_MSG_TYPE; /* DHCP message type */
    opt->len = 1;
    opt->data[0] = DHCP_REQUEST;
    opt_sz += 3;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = DHCP_OPTION_PARAM_REQ; /* Parameter request list */
    opt->len = 3;
    opt->data[0] = 1; /* Subnet mask */
    opt->data[1] = 3; /* Router */
    opt->data[2] = 6; /* DNS */
    opt_sz += 5;
    opt = (struct dhcp_option *)((uint8_t *)opt + 5);
    opt->code = DHCP_OPTION_SERVER_ID; /* Server ID */
    opt->len = 4;
    opt->data[0] = (s->dhcp_server_ip >> 24) & 0xFF;
    opt->data[1] = (s->dhcp_server_ip >> 16) & 0xFF;
    opt->data[2] = (s->dhcp_server_ip >> 8) & 0xFF;
    opt->data[3] = (s->dhcp_server_ip >> 0) & 0xFF;
    opt_sz += 6;
    opt = (struct dhcp_option *)((uint8_t *)opt + 6);
    opt->code = DHCP_OPTION_OFFER_IP; /* Requested IP */
    opt->len = 4;
    opt->data[0] = (s->dhcp_ip >> 24) & 0xFF;
    opt->data[1] = (s->dhcp_ip >> 16) & 0xFF;
    opt->data[2] = (s->dhcp_ip >> 8) & 0xFF;
    opt->data[3] = (s->dhcp_ip >> 0) & 0xFF;
    opt_sz += 6;

    opt_sz++;
    memset(&sin, 0, sizeof(struct wolfIP_sockaddr_in));
    sin.sin_port = ee16(DHCP_SERVER_PORT);
    sin.sin_addr.s_addr = ee32(0xFFFFFFFF); /* Broadcast */
    sin.sin_family = AF_INET;
    wolfIP_sock_sendto(s, s->dhcp_udp_sd, &req, DHCP_HEADER_LEN + opt_sz, 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(struct wolfIP_sockaddr_in));
    tmr.expires = s->last_tick + DHCP_REQUEST_TIMEOUT + (wolfIP_getrandom() % 200);
    tmr.arg = s;
    tmr.cb = dhcp_timer_cb;
    s->dhcp_timer = timers_binheap_insert(&s->timers, tmr);
    return 0;
}

static void dhcp_callback(int sockfd, uint16_t ev, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    (void)sockfd;
    (void)ev;
    if (!s)
        return;
    dhcp_poll(s);
}

static int dhcp_send_discover(struct wolfIP *s)
{
    struct dhcp_msg disc;
    struct dhcp_option *opt = (struct dhcp_option *)(disc.options);
    struct wolfIP_timer tmr = { };
    struct wolfIP_sockaddr_in sin;
    uint32_t opt_sz = 0;
    /* Prepare DHCP discover */
    memset(&disc, 0, sizeof(struct dhcp_msg));
    disc.op = BOOT_REQUEST;
    disc.htype = 1; /* Ethernet */
    disc.hlen = 6; /* MAC */
    disc.xid = ee32(s->dhcp_xid);
    disc.magic = ee32(DHCP_MAGIC);
    {
        struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, WOLFIP_PRIMARY_IF_IDX);
        if (ll)
            memcpy(disc.chaddr, ll->mac, 6);
        else
            memset(disc.chaddr, 0, 6);
    }

    /* Set options */
    memset(disc.options, 0xFF, sizeof(disc.options));
    opt->code = DHCP_OPTION_MSG_TYPE; /* DHCP message type */
    opt->len = 1;
    opt->data[0] = DHCP_DISCOVER;
    opt_sz += 3;
    opt = (struct dhcp_option *)((uint8_t *)opt + 3);
    opt->code = 55; /* Parameter request list */
    opt->len = 3;
    opt->data[0] = 1; /* Subnet mask */
    opt->data[1] = 3; /* Router */
    opt->data[2] = 6; /* DNS */
    opt_sz += 5;
    opt_sz ++;

    memset(&sin, 0, sizeof(struct wolfIP_sockaddr_in));
    sin.sin_port = ee16(DHCP_SERVER_PORT);
    sin.sin_addr.s_addr = ee32(0xFFFFFFFF); /* Broadcast */
    sin.sin_family = AF_INET;
    wolfIP_sock_sendto(s, s->dhcp_udp_sd, &disc, DHCP_HEADER_LEN + opt_sz, 0,
            (struct wolfIP_sockaddr *)&sin, sizeof(struct wolfIP_sockaddr_in));
    tmr.expires = s->last_tick + DHCP_DISCOVER_TIMEOUT + (wolfIP_getrandom() % 200);
    tmr.arg = s;
    tmr.cb = dhcp_timer_cb;
    s->dhcp_state = DHCP_DISCOVER_SENT;

    s->dhcp_timer = timers_binheap_insert(&s->timers, tmr);
    return 0;
}

int dhcp_bound(struct wolfIP *s)
{
    return (s->dhcp_state == DHCP_BOUND);
}

int dhcp_client_init(struct wolfIP *s)
{
    struct wolfIP_sockaddr_in sin;
    if (s->dhcp_state != DHCP_OFF)
        return -1;
    s->dhcp_xid = wolfIP_getrandom();

    if (s->dhcp_udp_sd > 0) {
        wolfIP_sock_close(s, s->dhcp_udp_sd);
    }

    s->dhcp_udp_sd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    if (s->dhcp_udp_sd < 0) {
        s->dhcp_state = DHCP_OFF;
        return -1;
    }
    memset(&sin, 0, sizeof(struct wolfIP_sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_port = ee16(DHCP_CLIENT_PORT);
    if (wolfIP_sock_bind(s, s->dhcp_udp_sd, (struct wolfIP_sockaddr *)&sin, sizeof(struct wolfIP_sockaddr_in)) < 0) {
        s->dhcp_state = DHCP_OFF;
        return -1;
    }
    wolfIP_register_callback(s, s->dhcp_udp_sd, dhcp_callback, s);
    return dhcp_send_discover(s);
}

/* ARP */
#ifdef ETHERNET

#if WOLFIP_ENABLE_FORWARDING
static void arp_queue_packet(struct wolfIP *s, unsigned int if_idx, ip4 dest,
        const struct wolfIP_ip_packet *ip, uint32_t len)
{
    int slot = -1;
    int i;

    if (!s || len == 0)
        return;
    if (len > LINK_MTU)
        len = LINK_MTU;

    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++) {
        if (s->arp_pending[i].dest == dest && s->arp_pending[i].if_idx == if_idx) {
            slot = i;
            break;
        }
        if (slot < 0 && s->arp_pending[i].dest == IPADDR_ANY)
            slot = i;
    }
    if (slot < 0)
        slot = 0;

    memcpy(s->arp_pending[slot].frame, ip, len);
    s->arp_pending[slot].len = len;
    s->arp_pending[slot].dest = dest;
    s->arp_pending[slot].if_idx = (uint8_t)if_idx;
}

static void arp_flush_pending(struct wolfIP *s, unsigned int if_idx, ip4 ip)
{
    uint8_t mac[6];
    int i;

    if (!s)
        return;
    if (arp_lookup(s, if_idx, ip, mac) != 0)
        return;

    for (i = 0; i < WOLFIP_ARP_PENDING_MAX; i++) {
        struct arp_pending_entry *pending = &s->arp_pending[i];
        if (pending->dest != ip || pending->if_idx != if_idx)
            continue;
        if (pending->len == 0) {
            pending->dest = IPADDR_ANY;
            continue;
        }
        if (pending->len > LINK_MTU)
            pending->len = LINK_MTU;
        {
            struct wolfIP_ip_packet *pkt =
                (struct wolfIP_ip_packet *)pending->frame;

            if (pkt->ttl <= 1) {
                pending->dest = IPADDR_ANY;
                pending->len = 0;
                continue;
            }
            pkt->ttl--;
            pkt->csum = 0;
            iphdr_set_checksum(pkt);
            wolfIP_forward_packet(s, if_idx, pkt, pending->len, mac, 0);
        }
        pending->dest = IPADDR_ANY;
        pending->len = 0;
    }
}
#endif /* WOLFIP_ENABLE_FORWARDING */

static void arp_store_neighbor(struct wolfIP *s, unsigned int if_idx, ip4 ip, const uint8_t *mac)
{
    int i;
    int stored = 0;
    if (!s)
        return;
    for (i = 0; i < MAX_NEIGHBORS; i++) {
        if (s->arp.neighbors[i].ip == ip && s->arp.neighbors[i].if_idx == if_idx) {
            memcpy(s->arp.neighbors[i].mac, mac, 6);
            stored = 1;
            break;
        }
    }
    if (!stored) {
        for (i = 0; i < MAX_NEIGHBORS; i++) {
            if (s->arp.neighbors[i].ip == IPADDR_ANY) {
                s->arp.neighbors[i].ip = ip;
                s->arp.neighbors[i].if_idx = (uint8_t)if_idx;
                memcpy(s->arp.neighbors[i].mac, mac, 6);
                stored = 1;
                break;
            }
        }
    }
    if (stored) {
#if WOLFIP_ENABLE_FORWARDING
        arp_flush_pending(s, if_idx, ip);
#endif
    }
}

static void arp_request(struct wolfIP *s, unsigned int if_idx, ip4 tip)
{
    struct arp_packet arp;
    struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, if_idx);
    struct ipconf *conf = wolfIP_ipconf_at(s, if_idx);

    if (!ll || !conf)
        return;

    if (s->arp.last_arp[if_idx] + 1000 > s->last_tick) {
        return;
    }
    s->arp.last_arp[if_idx] = s->last_tick;
    memset(&arp, 0, sizeof(struct arp_packet));
    eth_output_add_header(s, if_idx, NULL, &arp.eth, ETH_TYPE_ARP);
    arp.htype = ee16(1); /* Ethernet */
    arp.ptype = ee16(0x0800);
    arp.hlen = 6;
    arp.plen = 4;
    arp.opcode = ee16(ARP_REQUEST);
    memcpy(arp.sma, ll->mac, 6);
    arp.sip = ee32(conf->ip);
    memset(arp.tma, 0, 6);
    arp.tip = ee32(tip);
    if (ll->send)
        ll->send(ll, &arp, sizeof(struct arp_packet));
}

static void arp_recv(struct wolfIP *s, unsigned int if_idx, void *buf, int len)
{
    struct arp_packet *arp = (struct arp_packet *)buf;
    struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, if_idx);
    struct ipconf *conf = wolfIP_ipconf_at(s, if_idx);

    if (!ll || !conf)
        return;

    if (arp->opcode == ee16(ARP_REQUEST) && arp->tip == ee32(conf->ip)) {
        arp->opcode = ee16(ARP_REPLY);
        memcpy(arp->tma, arp->sma, 6);
        memcpy(arp->sma, ll->mac, 6);
        arp->tip = arp->sip;
        arp->sip = ee32(conf->ip);
        arp_store_neighbor(s, if_idx, ee32(arp->sip), arp->sma);
        eth_output_add_header(s, if_idx, arp->tma, &arp->eth, ETH_TYPE_ARP);
        if (ll->send)
            ll->send(ll, buf, len);
    }
    if (arp->opcode == ee16(ARP_REPLY)) {
        arp_store_neighbor(s, if_idx, ee32(arp->sip), arp->sma);
    }
}

static int arp_lookup(struct wolfIP *s, unsigned int if_idx, ip4 ip, uint8_t *mac)
{
    int i;
    memset(mac, 0, 6);
    for (i = 0; i < MAX_NEIGHBORS; i++) {
        if (s->arp.neighbors[i].ip == ip && s->arp.neighbors[i].if_idx == if_idx) {
            memcpy(mac, s->arp.neighbors[i].mac, 6);
            return 0;
        }
    }
    return -1;
}

#endif

/* Initialize the IP stack */
void wolfIP_init(struct wolfIP *s)
{
    unsigned int i;
    if (!s)
        return;
    memset(s, 0, sizeof(struct wolfIP));
    s->if_count = WOLFIP_MAX_INTERFACES;
    for (i = 0; i < s->if_count; i++) {
        s->ipconf[i].ll = wolfIP_ll_at(s, i);
    }
#if WOLFIP_ENABLE_LOOPBACK
    if (s->if_count > WOLFIP_LOOPBACK_IF_IDX) {
        struct wolfIP_ll_dev *loop = wolfIP_ll_at(s, WOLFIP_LOOPBACK_IF_IDX);
        struct ipconf *loop_conf = wolfIP_ipconf_at(s, WOLFIP_LOOPBACK_IF_IDX);
        static const uint8_t loop_mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
        if (loop) {
            memcpy(loop->mac, loop_mac, sizeof(loop_mac));
            strncpy(loop->ifname, "lo", sizeof(loop->ifname) - 1);
            loop->ifname[sizeof(loop->ifname) - 1] = '\0';
            loop->poll = NULL;
            loop->send = wolfIP_loopback_send;
        }
        if (loop_conf) {
            loop_conf->ll = loop;
            loop_conf->ip = WOLFIP_LOOPBACK_IP;
            loop_conf->mask = WOLFIP_LOOPBACK_MASK;
            loop_conf->gw = IPADDR_ANY;
        }
    }
#endif
}

struct wolfIP_ll_dev *wolfIP_getdev(struct wolfIP *s)
{
    return wolfIP_getdev_ex(s, WOLFIP_PRIMARY_IF_IDX);
}

struct wolfIP_ll_dev *wolfIP_getdev_ex(struct wolfIP *s, unsigned int if_idx)
{
    return wolfIP_ll_at(s, if_idx);
}

static struct wolfIP wolfIP_static;
void wolfIP_init_static(struct wolfIP **s)
{
    if (!s)
        return;
    wolfIP_init(&wolfIP_static);
    *s = &wolfIP_static;
}

size_t wolfIP_instance_size(void)
{
    return sizeof(struct wolfIP);
}

static inline void ip_recv(struct wolfIP *s, unsigned int if_idx, struct wolfIP_ip_packet *ip,
        uint32_t len)
{
#if WOLFIP_ENABLE_FORWARDING
    unsigned int i;
#endif
#if WOLFIP_ENABLE_LOOPBACK
    if (!wolfIP_is_loopback_if(if_idx)) {
        ip4 dest = ee32(ip->dst);
        if ((dest & WOLFIP_LOOPBACK_MASK) == (WOLFIP_LOOPBACK_IP & WOLFIP_LOOPBACK_MASK)) {
            return;
        }
    }
#endif
#if WOLFIP_ENABLE_FORWARDING
    if (ip->ver_ihl == 0x45) {
        ip4 dest = ee32(ip->dst);
        int is_local = 0;
        if (dest == IPADDR_ANY || IS_IP_BCAST(dest)) {
            is_local = 1;
        } else {
            for (i = 0; i < s->if_count; i++) {
                struct ipconf *conf = &s->ipconf[i];
                if (!conf || conf->ip == IPADDR_ANY)
                    continue;
                if (conf->ip == dest) {
                    is_local = 1;
                    break;
                }
            }
        }
        if (!is_local) {
            int out_if = wolfIP_forward_interface(s, if_idx, dest);
            if (out_if >= 0) {
                uint8_t mac[6];
                int broadcast = 0;

                if (ip->ttl <= 1) {
                    wolfIP_send_ttl_exceeded(s, if_idx, ip);
                    return;
                }
                if (!wolfIP_forward_prepare(s, out_if, dest, mac, &broadcast)) {
                    arp_queue_packet(s, out_if, dest, ip, len);
                    return;
                }
                ip->ttl--;
                ip->csum = 0;
                iphdr_set_checksum(ip);
                wolfIP_forward_packet(s, out_if, ip, len, broadcast ? NULL : mac, broadcast);
                return;
            }
        }
    }
#endif
    if (ip->ver_ihl == 0x45 && ip->proto == 0x06) {
        struct wolfIP_tcp_seg *tcp = (struct wolfIP_tcp_seg *)ip;
        tcp_input(s, if_idx, tcp, len);
    }
    else if (ip->ver_ihl == 0x45 && ip->proto == 0x11) {
        struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)ip;
        udp_try_recv(s, if_idx, udp, len);
    } else if (ip->ver_ihl == 0x45 && ip->proto == 0x01) {
        icmp_input(s, if_idx, ip, len);
    }
}

static void wolfIP_recv_on(struct wolfIP *s, unsigned int if_idx, void *buf, uint32_t len)
{
#ifdef ETHERNET
    struct wolfIP_ll_dev *ll;
    struct wolfIP_eth_frame *eth;
#else
    struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)buf;
#endif
    if (!s)
        return;

#ifdef ETHERNET
    ll = wolfIP_ll_at(s, if_idx);
    if (!ll)
        return;
    eth = (struct wolfIP_eth_frame *)buf;
    if (eth->type == ee16(ETH_TYPE_IP)) {
        struct wolfIP_ip_packet *ip = (struct wolfIP_ip_packet *)eth;
        if ((memcmp(eth->dst, ll->mac, 6) != 0) && (memcmp(eth->dst, "\xff\xff\xff\xff\xff\xff", 6) != 0)) {
            return; /* Not for us */
        }
        ip_recv(s, if_idx, ip, len);
    } else if (eth->type == ee16(ETH_TYPE_ARP)) {
        arp_recv(s, if_idx, buf, len);
    }
#else
    /* No ethernet, assume IP */
    ip = (struct wolfIP_ip_packet *)buf;
    ip_recv(s, if_idx, ip, len);
#endif
}

/* Try to receive a packet from the network interface.
 *
 * This function is called either after polling the device driver
 * in the loop, or in the device driver dsr callback.
 */
void wolfIP_recv(struct wolfIP *s, void *buf, uint32_t len)
{
    wolfIP_recv_on(s, WOLFIP_PRIMARY_IF_IDX, buf, len);
}

void wolfIP_recv_ex(struct wolfIP *s, unsigned int if_idx, void *buf, uint32_t len)
{
    wolfIP_recv_on(s, if_idx, buf, len);
}

/* DNS Client */
#define DNS_PORT 53
#define DNS_QUERY 0x00
#define DNS_RESPONSE 0x80
#define DNS_A 0x01 /* A record only */
#define DNS_RD 0x0100 /* Recursion desired */

struct PACKED dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct PACKED dns_question {
    uint16_t qtype;
    uint16_t qclass;
};
#define MAX_DNS_RESPONSE 512

void dns_callback(int dns_sd, uint16_t ev, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    char buf[MAX_DNS_RESPONSE];
    struct dns_header *hdr = (struct dns_header *)buf;
    struct dns_question *q;
    int dns_len;
    if (!s)
        return;
    if (ev & CB_EVENT_READABLE) {
        dns_len = wolfIP_sock_recvfrom(s, dns_sd, buf, MAX_DNS_RESPONSE, 0, NULL, 0);
        if (dns_len < 0) {
            wolfIP_sock_close(s, dns_sd);
            s->dns_udp_sd = -1;
            s->dns_id = 0;
            return;
        }
        /* Parse DNS response */
        if ((ee16(hdr->flags) & 0x8100) == 0x8100) {
            /* Skip the question */
            char *q_name = buf + sizeof(struct dns_header);
            uint32_t ip;
            while (*q_name) q_name++;
            if (q_name - buf > dns_len) {
                s->dns_id = 0;
                return;
            }
            q_name++; /* Skip the null terminator */
            q = (struct dns_question *)q_name;
            if (ee16(q->qtype) == DNS_A) {
                uint8_t *ip_ptr = (uint8_t *)(buf + dns_len - 4);
                ip = ip_ptr[3] | (ip_ptr[2] << 8) | (ip_ptr[1] << 16) | (ip_ptr[0] << 24);
                if(s->dns_lookup_cb)
                    s->dns_lookup_cb(ee32(ip));
                LOG("DNS response: %u.%u.%u.%u\n", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
                s->dns_id = 0;
            }
        }
    }
}

int nslookup(struct wolfIP *s, const char *dname, uint16_t *id, void (*lookup_cb)(uint32_t ip))
{
    uint8_t buf[512];
    struct dns_header *hdr;
    struct dns_question *q;
    char *q_name, *tok_start, *tok_end;
    struct wolfIP_sockaddr_in dns_srv;
    uint32_t tok_len = 0;
    if (!dname || !id || !lookup_cb) return -22; /* Invalid arguments */
    if (strlen(dname) > 256) return -22; /* Invalid arguments */
    if (s->dns_server == 0) return -101; /* Network unreachable: No DNS server configured */
    if (s->dns_id != 0) return -16; /* DNS query already in progress */
    if (s->dns_udp_sd <= 0) {
        s->dns_udp_sd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
        if (s->dns_udp_sd < 0)
            return -1;
        wolfIP_register_callback(s, s->dns_udp_sd, dns_callback, s);
    }
    s->dns_lookup_cb = lookup_cb;
    s->dns_id = wolfIP_getrandom();
    *id = s->dns_id;
    memset(buf, 0, 512);
    hdr = (struct dns_header *)buf;
    hdr->id = ee16(s->dns_id);
    hdr->flags = ee16(DNS_QUERY);
    hdr->qdcount = ee16(1);
    hdr->flags = ee16(DNS_RD);
    /* Prepare the DNS query name */
    q_name = (char *)(buf + sizeof(struct dns_header));
    tok_start = (char *)dname;
    while(*tok_start) {
        tok_end = tok_start;
        while ((*tok_end != '.') && (*tok_end != 0)) {
            tok_end++;
        }
        *q_name = tok_end - tok_start;
        q_name++;
        memcpy(q_name, tok_start, tok_end - tok_start);
        q_name += tok_end - tok_start;
        tok_len += (tok_end - tok_start) + 1;
        if (*tok_end == 0)
            break;
        tok_start = tok_end + 1;
    }
    *q_name = 0;
    tok_len++;
    q = (struct dns_question *)(buf + sizeof(struct dns_header) + tok_len);
    q->qtype = ee16(DNS_A);
    q->qclass = ee16(1);
    memset(&dns_srv, 0, sizeof(struct wolfIP_sockaddr_in));
    dns_srv.sin_family = AF_INET;
    dns_srv.sin_port = ee16(DNS_PORT);
    dns_srv.sin_addr.s_addr = ee32(s->dns_server);
    wolfIP_sock_sendto(s, s->dns_udp_sd, buf, sizeof(struct dns_header) + tok_len + sizeof(struct dns_question), 0, (struct wolfIP_sockaddr *)&dns_srv, sizeof(struct wolfIP_sockaddr_in));
    return 0;
}

/* wolfIP_poll: poll the network stack for incoming packets
 * This function should be called in a loop to process incoming packets.
 * It will call the poll function of the device driver and process the
 * received packets.
 *
 * This function also handles timers for all supported protocols.
 *
 * It returns the number of milliseconds to wait before
 * calling it again (TODO).
 */
int wolfIP_poll(struct wolfIP *s, uint64_t now)
{
    int len = 0;
    int i = 0;
    uint8_t buf[LINK_MTU];
    unsigned int if_idx;
    struct wolfIP_timer tmr;
    memset(buf, 0, LINK_MTU);

    s->last_tick = now;

    /* Step 1: Poll the device */
    for (if_idx = 0; if_idx < s->if_count; if_idx++) {
        struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, if_idx);
        if (!ll || !ll->poll)
            continue;
        do {
            len = ll->poll(ll, buf, LINK_MTU);
            if (len > 0) {
                /* Process packet */
                wolfIP_recv_on(s, if_idx, buf, len);
            }
        } while (len > 0);
    }
    /* Step 2: Handle timers */
    while(is_timer_expired(&s->timers, now)) {
        tmr = timers_binheap_pop(&s->timers);
        tmr.cb(tmr.arg);
    }
    /* Step 3: handle DHCP and application callbacks */
    for (i = 0; i < MAX_TCPSOCKETS; i++) {
        struct tsocket *ts = &s->tcpsockets[i];
        if ((ts->sock.tcp.state != TCP_CLOSED) && (ts->callback) && (ts->events)) {
            ts->callback(i | MARK_TCP_SOCKET, ts->events, ts->callback_arg);
            ts->events = 0;
        }
    }
    for (i = 0; i < MAX_UDPSOCKETS; i++) {
        struct tsocket *ts = &s->udpsockets[i];
        if ((ts->callback) && (ts->events)) {
            ts->callback(i | MARK_UDP_SOCKET, ts->events, ts->callback_arg);
            ts->events = 0;
        }
    }

    /* Step 4: attempt to write any pending data */
    for (i = 0; i < MAX_TCPSOCKETS; i++) {
        struct tsocket *ts = &s->tcpsockets[i];
        uint32_t in_flight = 0;
        uint32_t size = 0;
        struct pkt_desc *desc;
        struct wolfIP_tcp_seg *tcp;
        desc = fifo_peek(&ts->sock.tcp.txbuf);
        while (desc) {
            tcp = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
            if (desc->flags & PKT_FLAG_SENT) {
                in_flight += ee16(tcp->ip.len) - (IP_HEADER_LEN + (tcp->hlen >> 2));
                desc = fifo_next(&ts->sock.tcp.txbuf, desc);
                continue;
            } else {
#ifdef ETHERNET
                unsigned int if_idx = wolfIP_socket_if_idx(ts);
                struct ipconf *conf = wolfIP_ipconf_at(s, if_idx);
                ip4 nexthop = wolfIP_select_nexthop(conf, ts->remote_ip);
                if (wolfIP_is_loopback_if(if_idx)) {
                    struct wolfIP_ll_dev *loop = wolfIP_ll_at(s, if_idx);
                    if (loop)
                        memcpy(ts->nexthop_mac, loop->mac, 6);
                } else if (arp_lookup(s, if_idx, nexthop, ts->nexthop_mac) < 0) {
                    /* Send ARP request */
                    arp_request(s, if_idx, nexthop);
                    break;
                }
#endif
                    if (in_flight <= ts->sock.tcp.cwnd) {
                        struct wolfIP_timer new_tmr = {};
                        size = desc->len - ETH_HEADER_LEN;
                        tcp = (struct wolfIP_tcp_seg *)(ts->txmem + desc->pos + sizeof(*desc));
                        if ((ts->sock.tcp.ack == ts->sock.tcp.last_ack) &&
                                (size == IP_HEADER_LEN + (uint32_t)(tcp->hlen >> 2)) &&
                                (tcp->flags == 0x10)) {
                            desc->flags |= PKT_FLAG_SENT;
                            fifo_pop(&ts->sock.tcp.txbuf);
                            desc = fifo_peek(&ts->sock.tcp.txbuf);
                            continue;
                        }
                        /* Refresh ack counter */
                        ts->sock.tcp.last_ack = ts->sock.tcp.ack;
                        tcp->ack = ee32(ts->sock.tcp.ack);
                        tcp->win = ee16(queue_space(&ts->sock.tcp.rxbuf));
                        ip_output_add_header(ts, (struct wolfIP_ip_packet *)tcp, WI_IPPROTO_TCP, size);
                        {
                            struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, wolfIP_socket_if_idx(ts));
                            if (ll && ll->send)
                                ll->send(ll, tcp, desc->len);
                        }
                        desc->flags |= PKT_FLAG_SENT;
                        desc->time_sent = now;
                        if (size == IP_HEADER_LEN + (uint32_t)(tcp->hlen >> 2)) {
                            desc = fifo_pop(&ts->sock.tcp.txbuf);
                        } else {
                            uint32_t payload_len = size - (IP_HEADER_LEN + (tcp->hlen >> 2));
                            if (ts->sock.tcp.tmr_rto != NO_TIMER) {
                                timer_binheap_cancel(&s->timers, ts->sock.tcp.tmr_rto);
                                ts->sock.tcp.tmr_rto = NO_TIMER;
                            }
                            new_tmr.cb = tcp_rto_cb;
                            new_tmr.expires = now + (ts->sock.tcp.rto << ts->sock.tcp.rto_backoff);
                            new_tmr.arg = ts;
                            ts->sock.tcp.tmr_rto = timers_binheap_insert(&s->timers, new_tmr);
                            in_flight += payload_len;
                            desc = fifo_next(&ts->sock.tcp.txbuf, desc);
                        }
                    } else {
                        break;
                    }
            }
        }
    }
    for (i = 0; i < MAX_UDPSOCKETS; i++) {
        struct tsocket *t = &s->udpsockets[i];
        struct pkt_desc *desc = fifo_peek(&t->sock.udp.txbuf);
        while (desc) {
            struct wolfIP_udp_datagram *udp = (struct wolfIP_udp_datagram *)(t->txmem + desc->pos + sizeof(*desc));
#ifdef ETHERNET
            unsigned int if_idx = wolfIP_socket_if_idx(t);
            struct ipconf *conf = wolfIP_ipconf_at(s, if_idx);
            ip4 nexthop = wolfIP_select_nexthop(conf, t->remote_ip);
            if (wolfIP_is_loopback_if(if_idx)) {
                struct wolfIP_ll_dev *loop = wolfIP_ll_at(s, if_idx);
                if (loop)
                    memcpy(t->nexthop_mac, loop->mac, 6);
            } else {
                if ((!IS_IP_BCAST(nexthop) && (arp_lookup(s, if_idx, nexthop, t->nexthop_mac) < 0))) {
                    /* Send ARP request */
                    arp_request(s, if_idx, nexthop);
                    break;
                }
                if (IS_IP_BCAST(nexthop)) memset(t->nexthop_mac, 0xFF, 6);
            }
#endif
            len = desc->len - ETH_HEADER_LEN;
            ip_output_add_header(t, (struct wolfIP_ip_packet *)udp, WI_IPPROTO_UDP, len);
            {
                struct wolfIP_ll_dev *ll = wolfIP_ll_at(s, wolfIP_socket_if_idx(t));
                if (ll && ll->send)
                    ll->send(ll, udp, desc->len);
            }
            fifo_pop(&t->sock.udp.txbuf);
            desc = fifo_peek(&t->sock.udp.txbuf);
        }
    }
    return 0;
}

void wolfIP_ipconfig_set(struct wolfIP *s, ip4 ip, ip4 mask, ip4 gw)
{
    wolfIP_ipconfig_set_ex(s, WOLFIP_PRIMARY_IF_IDX, ip, mask, gw);
}

void wolfIP_ipconfig_get(struct wolfIP *s, ip4 *ip, ip4 *mask, ip4 *gw)
{
    wolfIP_ipconfig_get_ex(s, WOLFIP_PRIMARY_IF_IDX, ip, mask, gw);
}

void wolfIP_ipconfig_set_ex(struct wolfIP *s, unsigned int if_idx, ip4 ip, ip4 mask, ip4 gw)
{
    struct ipconf *conf = wolfIP_ipconf_at(s, if_idx);
    if (!conf)
        return;
    conf->ip = ip;
    conf->mask = mask;
    conf->gw = gw;
}

void wolfIP_ipconfig_get_ex(struct wolfIP *s, unsigned int if_idx, ip4 *ip, ip4 *mask, ip4 *gw)
{
    struct ipconf *conf = wolfIP_ipconf_at(s, if_idx);
    if (!conf)
        return;
    if (ip)
        *ip = conf->ip;
    if (mask)
        *mask = conf->mask;
    if (gw)
        *gw = conf->gw;
}

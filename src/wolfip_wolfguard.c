/* wolfip_wolfguard.c
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

#ifdef WOLFIP_WOLFGUARD

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define WOLF_POSIX
#include "config.h"
#include "wolfip.h"
#undef WOLF_POSIX

#include "wolfip_wolfguard.h"

/*
 * WolfGuard Generic Netlink constants (from wolfguard uapi header)
 * */
#define WG_CMD_GET_DEVICE  0
#define WG_CMD_SET_DEVICE  1

/* wgdevice_attribute */
#define WGDEVICE_A_IFINDEX    1
#define WGDEVICE_A_IFNAME     2
#define WGDEVICE_A_PRIVATE_KEY 3
#define WGDEVICE_A_PUBLIC_KEY  4
#define WGDEVICE_A_FLAGS       5
#define WGDEVICE_A_LISTEN_PORT 6
#define WGDEVICE_A_FWMARK      7
#define WGDEVICE_A_PEERS       8

/* wgpeer_flag */
#define WGPEER_F_REPLACE_ALLOWEDIPS (1U << 1)

/* wgpeer_attribute */
#define WGPEER_A_PUBLIC_KEY                      1
#define WGPEER_A_PRESHARED_KEY                   2
#define WGPEER_A_FLAGS                           3
#define WGPEER_A_ENDPOINT                        4
#define WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL   5
#define WGPEER_A_ALLOWEDIPS                      9

/* wgallowedip_attribute */
#define WGALLOWEDIP_A_FAMILY    1
#define WGALLOWEDIP_A_IPADDR    2
#define WGALLOWEDIP_A_CIDR_MASK 3

/* ethernet / arp constants */
#define WG_ETH_HDR_LEN   14
/* 14-byte eth hdr + 28-byte ARP payload */
#define WG_ARP_PKT_LEN   42

#define WG_ETH_TYPE_IP   0x0800
#define WG_ETH_TYPE_ARP  0x0806

#define WG_ARP_REQUEST   1
#define WG_ARP_REPLY     2

/*
 * Fixed dummy MAC addresses used to satisfy wolfip's Ethernet layer.
 * The wolfguard TUN interface is Layer-3; these MACs have no meaning on
 * the wire, they are technically only seen by the wolfip stack.
 *
 * local_mac: assigned to ll->mac (wolfip's own MAC on this interface).
 * peer_mac:  returned in synthetic ARP replies as the "peer's" MAC.
 */
static const uint8_t wg_local_mac[6] = {0x02, 0x00, 0x57, 0x47, 0x00, 0x01};
static const uint8_t wg_peer_mac[6]  = {0x02, 0x00, 0x57, 0x47, 0x00, 0x02};

/*
 * Driver state
 * */
struct wg_dev {
    int     tun_fd;    /* AF_PACKET/SOCK_DGRAM socket (or pipe fd in unit tests) */
    int     ifindex;   /* interface index — 0 only in unit tests */
    char    ifname[16];
    /* Pending synthetic ARP reply to return on next wg_poll() call */
    uint8_t arp_reply[WG_ARP_PKT_LEN];
    int     arp_reply_pending;
};

/* One global instance, mirrors tap_linux.c's pattern of a single static fd */
static struct wg_dev wg_state;

/*
 * Minimal netlink attribute helpers
 */

#ifndef NLA_ALIGNTO
# define NLA_ALIGNTO 4
#endif
#ifndef NLA_ALIGN
# define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif
#ifndef NLA_HDRLEN
# define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif

static void nla_put_raw(uint8_t *buf, size_t *off, uint16_t type,
                        const void *data, uint16_t dlen)
{
    struct nlattr *nla = (struct nlattr *)(buf + *off);
    nla->nla_type = type;
    nla->nla_len  = (uint16_t)(NLA_HDRLEN + dlen);
    if (data && dlen)
        memcpy((uint8_t *)nla + NLA_HDRLEN, data, dlen);
    *off += (size_t)NLA_ALIGN(nla->nla_len);
}

static void nla_put_u8(uint8_t *buf, size_t *off, uint16_t type, uint8_t v)
{
    nla_put_raw(buf, off, type, &v, sizeof(v));
}

static void nla_put_u16(uint8_t *buf, size_t *off, uint16_t type, uint16_t v)
{
    nla_put_raw(buf, off, type, &v, sizeof(v));
}

static void nla_put_u32(uint8_t *buf, size_t *off, uint16_t type, uint32_t v)
{
    nla_put_raw(buf, off, type, &v, sizeof(v));
}

static void nla_put_str(uint8_t *buf, size_t *off, uint16_t type,
                        const char *str)
{
    nla_put_raw(buf, off, type, str, (uint16_t)(strlen(str) + 1));
}

/* Begin a nested attribute; returns the offset of the attribute header so
 * nla_nested_end() can fill in the final length. */
static size_t nla_nested_start(uint8_t *buf, size_t *off, uint16_t type)
{
    size_t start = *off;
    struct nlattr *nla = (struct nlattr *)(buf + start);
    nla->nla_type = (uint16_t)(type | NLA_F_NESTED);
    *off += (size_t)NLA_HDRLEN;
    return start;
}

static void nla_nested_end(uint8_t *buf, size_t start, size_t *off)
{
    struct nlattr *nla = (struct nlattr *)(buf + start);
    nla->nla_len = (uint16_t)(*off - start);
    /* Pad to 4-byte boundary */
    if (*off % NLA_ALIGNTO)
        *off += NLA_ALIGNTO - (*off % NLA_ALIGNTO);
}

/*
 * Generic Netlink: resolve family ID for "wolfguard"
 * */

/* These are standard kernel genetlink controller definitions. They are part
 * of the stable kernel ABI and safe to define here if not provided by the
 * system headers. */
#ifndef GENL_ID_CTRL
# define GENL_ID_CTRL 0x10
#endif
#ifndef CTRL_CMD_GETFAMILY
# define CTRL_CMD_GETFAMILY 3
#endif
#ifndef CTRL_ATTR_FAMILY_NAME
# define CTRL_ATTR_FAMILY_NAME 2
#endif
#ifndef CTRL_ATTR_FAMILY_ID
# define CTRL_ATTR_FAMILY_ID 1
#endif

static int wg_get_genl_family_id(uint16_t *family_id)
{
    uint8_t buf[512];
    struct nlmsghdr *nlh;
    struct genlmsghdr *genl;
    struct sockaddr_nl sa;
    struct nlattr *nla;
    int sock, ret, rem;
    size_t off = 0;

    memset(buf, 0, sizeof(buf));
    memset(&sa, 0, sizeof(sa));

    sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (sock < 0)
        return -errno;

    sa.nl_family = AF_NETLINK;
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(sock);
        return -errno;
    }

    /* Build CTRL_CMD_GETFAMILY request */
    nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type  = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq   = 1;
    off += NLMSG_HDRLEN;

    genl = (struct genlmsghdr *)(buf + off);
    genl->cmd     = CTRL_CMD_GETFAMILY;
    genl->version = 1;
    off += NLMSG_ALIGN(sizeof(*genl));

    nla_put_str(buf, &off, CTRL_ATTR_FAMILY_NAME, WG_GENL_NAME);
    nlh->nlmsg_len = (uint32_t)off;

    ret = (int)send(sock, buf, off, 0);
    if (ret < 0) {
        close(sock);
        return -errno;
    }

    ret = (int)recv(sock, buf, sizeof(buf), 0);
    close(sock);
    if (ret < 0)
        return -errno;

    nlh = (struct nlmsghdr *)buf;
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        return err->error;
    }

    /* Walk attributes to find CTRL_ATTR_FAMILY_ID */
    nla = (struct nlattr *)(buf + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*genl)));
    rem = (int)nlh->nlmsg_len - NLMSG_HDRLEN - (int)NLMSG_ALIGN(sizeof(*genl));

    while (rem >= NLA_HDRLEN) {
        if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
            memcpy(family_id, (uint8_t *)nla + NLA_HDRLEN, sizeof(*family_id));
            return 0;
        }
        rem -= NLA_ALIGN(nla->nla_len);
        nla  = (struct nlattr *)((uint8_t *)nla + NLA_ALIGN(nla->nla_len));
    }

    return -ENOENT;
}

/*
 * Interface creation / deletion via NETLINK_ROUTE
 * */

static int wg_iface_create(const char *ifname)
{
    uint8_t buf[512];
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifi;
    struct sockaddr_nl sa;
    int sock, ret;
    size_t off = 0, li_start;

    memset(buf, 0, sizeof(buf));
    memset(&sa, 0, sizeof(sa));

    sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (sock < 0)
        return -errno;

    sa.nl_family = AF_NETLINK;
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(sock);
        return -errno;
    }

    /* Build RTM_NEWLINK */
    nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type  = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq   = 1;
    off += NLMSG_HDRLEN;

    ifi = (struct ifinfomsg *)(buf + off);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    off += NLMSG_ALIGN(sizeof(*ifi));

    nla_put_str(buf, &off, IFLA_IFNAME, ifname);

    /* IFLA_LINKINFO -> IFLA_INFO_KIND = "wolfguard" */
    li_start = nla_nested_start(buf, &off, IFLA_LINKINFO);
    nla_put_str(buf, &off, IFLA_INFO_KIND, WG_GENL_NAME);
    nla_nested_end(buf, li_start, &off);

    nlh->nlmsg_len = (uint32_t)off;

    ret = (int)send(sock, buf, off, 0);
    if (ret < 0) {
        close(sock);
        return -errno;
    }

    ret = (int)recv(sock, buf, sizeof(buf), 0);
    close(sock);
    if (ret < 0)
        return -errno;

    nlh = (struct nlmsghdr *)buf;
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        if (err->error == 0)
            return 0;  /* ACK */
        if (err->error == -EEXIST)
            return 0;  /* Interface already exists — reuse it */
        return err->error;
    }
    return 0;
}

static void wg_iface_delete(const char *ifname)
{
    uint8_t buf[256];
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifi;
    struct sockaddr_nl sa;
    int sock;
    size_t off = 0;

    memset(buf, 0, sizeof(buf));
    memset(&sa, 0, sizeof(sa));

    sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (sock < 0)
        return;

    sa.nl_family = AF_NETLINK;
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(sock);
        return;
    }

    nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type  = RTM_DELLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq   = 1;
    off += NLMSG_HDRLEN;

    ifi = (struct ifinfomsg *)(buf + off);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    off += NLMSG_ALIGN(sizeof(*ifi));

    nla_put_str(buf, &off, IFLA_IFNAME, ifname);
    nlh->nlmsg_len = (uint32_t)off;

    (void)send(sock, buf, off, 0);
    (void)recv(sock, buf, sizeof(buf), 0);
    close(sock);
}

/*
 * wolfguard device configuration via Generic Netlink (WG_CMD_SET_DEVICE)
 * */

static int wg_configure(const struct wolfIP_wg_config *cfg, uint16_t family_id)
{
    uint8_t buf[4096];
    struct nlmsghdr *nlh;
    struct genlmsghdr *genl;
    struct sockaddr_nl sa;
    int sock, ret, i;
    size_t off = 0, peers_start, peer_start, aips_start, aip_start;

    memset(buf, 0, sizeof(buf));
    memset(&sa, 0, sizeof(sa));

    sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (sock < 0)
        return -errno;

    sa.nl_family = AF_NETLINK;
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(sock);
        return -errno;
    }

    nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type  = family_id;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq   = 2;
    off += NLMSG_HDRLEN;

    genl = (struct genlmsghdr *)(buf + off);
    genl->cmd     = WG_CMD_SET_DEVICE;
    genl->version = WG_GENL_VERSION;
    off += NLMSG_ALIGN(sizeof(*genl));

    /* Device-level attributes */
    nla_put_str(buf, &off, WGDEVICE_A_IFNAME, cfg->ifname);
    nla_put_raw(buf, &off, WGDEVICE_A_PRIVATE_KEY,
                cfg->private_key, WG_PRIVATE_KEY_LEN);
    nla_put_u16(buf, &off, WGDEVICE_A_LISTEN_PORT, cfg->listen_port);

    /* Peers */
    if (cfg->num_peers > 0) {
        peers_start = nla_nested_start(buf, &off, WGDEVICE_A_PEERS);

        for (i = 0; i < cfg->num_peers; i++) {
            const struct wolfIP_wg_peer *p = &cfg->peers[i];
            uint32_t pflags;
            int ep_len;
            struct in_addr addr4;

            peer_start = nla_nested_start(buf, &off, 0);

            nla_put_raw(buf, &off, WGPEER_A_PUBLIC_KEY,
                        p->public_key, WG_PUBLIC_KEY_LEN);

            /* Replace any existing allowed IPs for this peer */
            pflags = WGPEER_F_REPLACE_ALLOWEDIPS;
            nla_put_u32(buf, &off, WGPEER_A_FLAGS, pflags);

            /* Endpoint (sockaddr_in or sockaddr_in6 in network byte order) */
            ep_len = (p->endpoint.ss_family == AF_INET6)
                     ? (int)sizeof(struct sockaddr_in6)
                     : (int)sizeof(struct sockaddr_in);
            nla_put_raw(buf, &off, WGPEER_A_ENDPOINT, &p->endpoint,
                        (uint16_t)ep_len);

            /* Optional persistent keep-alive */
            if (p->keepalive_interval > 0)
                nla_put_u16(buf, &off, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
                            p->keepalive_interval);

            /* Allowed IPs (one IPv4 entry per peer for now) */
            aips_start = nla_nested_start(buf, &off, WGPEER_A_ALLOWEDIPS);
            aip_start  = nla_nested_start(buf, &off, 0);

            nla_put_u16(buf, &off, WGALLOWEDIP_A_FAMILY,
                        (uint16_t)AF_INET);
            /* ip4 is host byte order; convert to network byte order */
            addr4.s_addr = htonl(p->allowed_ip);
            nla_put_raw(buf, &off, WGALLOWEDIP_A_IPADDR,
                        &addr4, (uint16_t)sizeof(addr4));
            nla_put_u8(buf, &off, WGALLOWEDIP_A_CIDR_MASK,
                       p->allowed_cidr);

            nla_nested_end(buf, aip_start,  &off);
            nla_nested_end(buf, aips_start, &off);
            nla_nested_end(buf, peer_start, &off);
        }

        nla_nested_end(buf, peers_start, &off);
    }

    nlh->nlmsg_len = (uint32_t)off;

    ret = (int)send(sock, buf, off, 0);
    if (ret < 0) {
        close(sock);
        return -errno;
    }

    ret = (int)recv(sock, buf, sizeof(buf), 0);
    close(sock);
    if (ret < 0)
        return -errno;

    nlh = (struct nlmsghdr *)buf;
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        return err->error;
    }
    return 0;
}

/*
 * Interface bring-up (ioctl)
 * */

static int wg_iface_up(const char *ifname)
{
    struct ifreq ifr;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0)
        return -errno;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        close(sock);
        return -errno;
    }
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        close(sock);
        return -errno;
    }
    close(sock);
    return 0;
}

/*
 * AF_PACKET/SOCK_DGRAM socket bound to the wolfguard interface.
 *
 * wolfguard (like WireGuard) is an ARPHRD_NONE netdev — it is NOT a TUN/TAP
 * device and cannot be opened via /dev/net/tun.  An AF_PACKET/SOCK_DGRAM
 * socket bound to the interface lets us inject and receive raw IP packets
 * directly through the kernel interface, which the wolfguard module then
 * encrypts/decrypts transparently.
 * */

static int wg_open_packet_socket(const char *ifname)
{
    struct sockaddr_ll sll;
    int sock, ifidx, flags;

    sock = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IP));
    if (sock < 0)
        return -errno;

    ifidx = (int)if_nametoindex(ifname);
    if (ifidx == 0) {
        close(sock);
        return -ENODEV;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex  = ifidx;
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(sock);
        return -errno;
    }

    flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0)
        (void)fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    wg_state.ifindex = ifidx;
    return sock;
}

/*
 * ARP proxy helpers
 *
 * wolfip sends Ethernet frames (L2).  The wolfguard TUN interface is L3.
 * When wolfip tries to resolve an IP via ARP, wg_send() intercepts the ARP
 * request and queues a synthetic ARP reply in wg_state.arp_reply[].
 * The next wg_poll() call returns that reply to wolfip before checking the
 * TUN fd.  This satisfies wolfip's ARP machinery without kernel involvement.
 * */

/*
 * Build a synthetic ARP reply frame.
 *
 * @req:  The 42-byte ARP request received from wolfip via wg_send().
 * @out:  Buffer for the 42-byte ARP reply to be returned via wg_poll().
 *
 * The reply tells wolfip that every IP is reachable at wg_peer_mac,
 * so wolfip can forward outbound traffic to the wolfguard TUN fd.
 */
static void build_arp_reply(const uint8_t *req, uint8_t *out)
{
    /*
     * ARP packet layout (42 bytes):
     *   [0..5]   Ethernet dst MAC
     *   [6..11]  Ethernet src MAC
     *   [12..13] Ethertype (0x0806)
     *   [14..15] htype (0x0001 = Ethernet)
     *   [16..17] ptype (0x0800 = IPv4)
     *   [18]     hlen  (6)
     *   [19]     plen  (4)
     *   [20..21] opcode (1=request, 2=reply)
     *   [22..27] sender MAC
     *   [28..31] sender IP
     *   [32..37] target MAC
     *   [38..41] target IP
     */
    memcpy(out, req, WG_ARP_PKT_LEN);

    /* Ethernet header: reply goes back to whoever sent the request */
    memcpy(out + 0,  req + 6,  6);   /* dst = request's src MAC */
    memcpy(out + 6,  wg_peer_mac, 6); /* src = peer's dummy MAC  */
    /* ethertype [12..13] stays 0x0806 */

    /* ARP opcode: reply */
    out[20] = 0x00;
    out[21] = WG_ARP_REPLY;

    /* Sender: we claim to be the peer answering for the requested IP */
    memcpy(out + 22, wg_peer_mac, 6);  /* sender MAC = peer's dummy MAC */
    memcpy(out + 28, req + 38,   4);   /* sender IP  = target IP from request */

    /* Target: original requester */
    memcpy(out + 32, req + 22, 6);  /* target MAC = sender MAC from request */
    memcpy(out + 38, req + 28, 4);  /* target IP  = sender IP from request  */
}

/*
 * wolfIP_ll_dev callbacks
 * */

/*
 * wg_poll() - Receive a packet from the wolfguard interface.
 *
 * Priority 1: If a synthetic ARP reply is pending, return it immediately.
 * Priority 2: Poll the TUN fd for an incoming (decrypted) IP packet from
 *             a peer and prepend a 14-byte Ethernet header so that wolfip
 *             can process it normally.
 */
static int wg_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct wg_dev *dev = &wg_state;
    struct pollfd pfd;
    int ret;
    uint8_t *b = (uint8_t *)buf;
    (void)ll;

    /* Return any pending ARP reply first */
    if (dev->arp_reply_pending) {
        if (len < WG_ARP_PKT_LEN)
            return -1;
        memcpy(b, dev->arp_reply, WG_ARP_PKT_LEN);
        dev->arp_reply_pending = 0;
        return WG_ARP_PKT_LEN;
    }

    /* Poll the TUN fd with a short timeout */
    pfd.fd     = dev->tun_fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, 2);
    if (ret <= 0)
        return ret;  /* 0 = timeout, <0 = error */

    if (len < WG_ETH_HDR_LEN)
        return -1;

    /* Read the raw IP packet — recvfrom for packet socket, read for unit tests */
    if (dev->ifindex != 0)
        ret = (int)recvfrom(dev->tun_fd, b + WG_ETH_HDR_LEN,
                            len - WG_ETH_HDR_LEN, 0, NULL, NULL);
    else
        ret = (int)read(dev->tun_fd, b + WG_ETH_HDR_LEN,
                        len - WG_ETH_HDR_LEN);
    if (ret <= 0)
        return ret;

    /* Prepend a synthetic Ethernet header (IPv4) */
    memcpy(b + 0, wg_local_mac,  6);  /* dst = our own MAC   */
    memcpy(b + 6, wg_peer_mac,   6);  /* src = peer's MAC    */
    b[12] = 0x08;                      /* ethertype = 0x0800  */
    b[13] = 0x00;

    return ret + WG_ETH_HDR_LEN;
}

/*
 * wg_send() - Transmit a packet from wolfip onto the wolfguard interface.
 *
 * Ethernet frames from wolfip are handled as follows:
 *   - IPv4 (0x0800): strip the 14-byte Ethernet header and write the raw
 *                    IP packet to the TUN fd.  wolfguard encrypts and sends.
 *   - ARP  (0x0806, op=1): synthesize a reply and queue it for wg_poll().
 *   - Other: silently dropped (no ARP6, no RARP, etc. on a VPN TUN link).
 */
static int wg_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct wg_dev *dev = &wg_state;
    uint8_t *b = (uint8_t *)buf;
    uint16_t etype;
    (void)ll;

    if (len < WG_ETH_HDR_LEN)
        return -1;

    etype = (uint16_t)((b[12] << 8) | b[13]);

    if (etype == WG_ETH_TYPE_IP) {
        int written;
        if (dev->ifindex != 0) {
            /* Production: inject raw IP via AF_PACKET/SOCK_DGRAM sendto */
            struct sockaddr_ll sll;
            memset(&sll, 0, sizeof(sll));
            sll.sll_family   = AF_PACKET;
            sll.sll_ifindex  = dev->ifindex;
            sll.sll_protocol = htons(WG_ETH_TYPE_IP);
            sll.sll_halen    = 0;
            written = (int)sendto(dev->tun_fd, b + WG_ETH_HDR_LEN,
                                  len - WG_ETH_HDR_LEN, 0,
                                  (struct sockaddr *)&sll, sizeof(sll));
        } else {
            /* Unit test: mock fd is a pipe — use plain write */
            written = (int)write(dev->tun_fd, b + WG_ETH_HDR_LEN,
                                 len - WG_ETH_HDR_LEN);
        }
        return (written < 0) ? -1 : 0;
    }

    if (etype == WG_ETH_TYPE_ARP) {
        /* Only handle ARP requests (op == 1) */
        if (len < WG_ARP_PKT_LEN)
            return -1;
        if (b[20] == 0x00 && b[21] == WG_ARP_REQUEST) {
            build_arp_reply(b, dev->arp_reply);
            dev->arp_reply_pending = 1;
        }
        return 0;
    }

    /* Unknown ethertype — drop */
    return 0;
}

/*
 * Public API
 * */

int wolfIP_wg_init(struct wolfIP_wg_config *cfg, struct wolfIP_ll_dev *ll)
{
    uint16_t family_id = 0;
    int ret;

    if (!cfg || !ll)
        return -EINVAL;

    if (cfg->num_peers < 0 || cfg->num_peers > WOLFIP_WG_MAX_PEERS) {
        fprintf(stderr, "wolfIP_wg_init: num_peers %d out of range (max %d)\n",
                cfg->num_peers, WOLFIP_WG_MAX_PEERS);
        return -EINVAL;
    }

    memset(&wg_state, 0, sizeof(wg_state));
    wg_state.tun_fd = -1;
    strncpy(wg_state.ifname, cfg->ifname, sizeof(wg_state.ifname) - 1);

    /* Create the wolfguard network interface */
    ret = wg_iface_create(cfg->ifname);
    if (ret < 0) {
        fprintf(stderr, "wolfIP_wg_init: failed to create interface '%s': %d\n",
                cfg->ifname, ret);
        return ret;
    }

    /* Resolve the wolfguard Generic Netlink family ID */
    ret = wg_get_genl_family_id(&family_id);
    if (ret < 0) {
        fprintf(stderr, "wolfIP_wg_init: wolfguard genl family not found "
                "(is wolfguard.ko loaded?): %d\n", ret);
        wg_iface_delete(cfg->ifname);
        return ret;
    }

    /* Configure keys and peers */
    ret = wg_configure(cfg, family_id);
    if (ret < 0) {
        fprintf(stderr, "wolfIP_wg_init: WG_CMD_SET_DEVICE failed: %d\n", ret);
        wg_iface_delete(cfg->ifname);
        return ret;
    }

    /* Bring the interface UP */
    ret = wg_iface_up(cfg->ifname);
    if (ret < 0) {
        fprintf(stderr, "wolfIP_wg_init: failed to bring up '%s': %d\n",
                cfg->ifname, ret);
        wg_iface_delete(cfg->ifname);
        return ret;
    }

    /* Open AF_PACKET socket bound to the wolfguard interface */
    ret = wg_open_packet_socket(cfg->ifname);
    if (ret < 0) {
        fprintf(stderr, "wolfIP_wg_init: failed to open packet socket for '%s': %d\n",
                cfg->ifname, ret);
        wg_iface_delete(cfg->ifname);
        return ret;
    }
    wg_state.tun_fd = ret;

    /* Populate the wolfIP_ll_dev */
    memset(ll, 0, sizeof(*ll));
    memcpy(ll->mac, wg_local_mac, 6);
    strncpy(ll->ifname, cfg->ifname, sizeof(ll->ifname) - 1);
    ll->poll = wg_poll;
    ll->send = wg_send;

    return 0;
}

void wolfIP_wg_teardown(const char *ifname)
{
    if (wg_state.tun_fd >= 0) {
        close(wg_state.tun_fd);
        wg_state.tun_fd = -1;
    }
    if (ifname && *ifname)
        wg_iface_delete(ifname);
    memset(&wg_state, 0, sizeof(wg_state));
    wg_state.tun_fd = -1;
}

#endif /* WOLFIP_WOLFGUARD */

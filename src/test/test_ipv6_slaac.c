/* test_ipv6_slaac.c
 *
 * End-to-end check that wolfIP configures itself by SLAAC and is then
 * reachable from a real Linux host: link-local formation, duplicate address
 * detection, router discovery, global address formation, and Neighbor
 * Discovery driven by the host's own stack.
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

/*
 * Needs root, for the TAP device and for configuring the host end.
 *
 *   sudo ./build/test-ipv6-slaac            # run, print what happened, wait
 *   sudo ./build/test-ipv6-slaac --selftest # assert it all worked, then exit
 *
 * What is actually being tested, end to end against the Linux stack:
 *
 *   1. wolfIP forms its link-local address from the interface MAC and runs
 *      duplicate address detection on it (RFC 4862 sections 5.3 and 5.4).
 *   2. It solicits routers (RFC 4861 section 6.3.7).
 *   3. A Router Advertisement carrying a Prefix Information option arrives,
 *      and wolfIP forms a global address from the prefix plus its interface
 *      identifier, again verifying it with duplicate address detection
 *      (RFC 4862 section 5.5.3).
 *   4. Linux pings that global address. Its stack does not know wolfIP's
 *      link-layer address, so it sends a Neighbor Solicitation first, and
 *      wolfIP has to answer it before any ping can succeed.
 *
 * Step 4 is the part that distinguishes this from test_ipv6_ping.c, which
 * configures addresses by hand and needs a static neighbour entry because it
 * predates Neighbor Discovery. Here nothing is configured on the wolfIP side
 * and no neighbour entry is installed: address resolution happens for real,
 * in both directions.
 *
 * Where the Router Advertisement comes from
 *
 * By default the test injects it itself, over an AF_PACKET socket bound to
 * the host end of the TAP device. That keeps the test self-contained and
 * deterministic, and the frame is a real frame on a real link - but its
 * contents are ours, so it does not prove interoperability with a real
 * router implementation. With radvd installed and WOLFIP_SLAAC_USE_RADVD=1
 * in the environment, radvd is used instead, which does.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#endif

#include "config.h"
#include "wolfip.h"

#if !WOLFIP_IPV6
#error "test_ipv6_slaac requires -DWOLFIP_IPV6=1"
#endif

extern int tap_init(struct wolfIP_ll_dev *dev, const char *name,
                    uint32_t host_ip);

#define SLAAC_IFNAME  "wtcp0"
/* RFC 3849 documentation prefix. */
#define SLAAC_PREFIX  "2001:db8:1:2::"
#define SLAAC_HOSTADDR "2001:db8:1:2::1"
#define SLAAC_ROUTER_LL "fe80::1"

static const uint8_t slaac_router_mac[6] = {0x02, 0xBB, 0x00, 0x00, 0x00, 0x01};

/* Spawn tcpdump on the TAP interface, the same way the IPv4 interop tests
 * do, so the exchange can be opened in wireshark straight afterwards. The
 * pid is kept so the capture is stopped on the way out rather than left
 * running. Set WOLFIP_NO_PCAP to skip it. */
static pid_t pcap_pid;

static void pcap_start(const char *ifname, const char *file)
{
    if (getenv("WOLFIP_NO_PCAP") != NULL)
        return;
    pcap_pid = fork();
    if (pcap_pid < 0) {
        pcap_pid = 0;
        return;
    }
    if (pcap_pid == 0) {
        /* -U so frames hit the file as they arrive: if the test aborts, the
         * capture up to that point is still readable. */
        execlp("tcpdump", "tcpdump", "-i", ifname, "-w", file, "-U",
               "-s", "0", (char *)NULL);
        _exit(127);
    }
    /* Let tcpdump attach before any traffic is generated. */
    usleep(500000);
    printf("capturing to %s (pid %d)\n", file, (int)pcap_pid);
}

static void radvd_stop_if_started(int started, const char *ifname)
{
    char cmd[160];

    if (!started)
        return;
    snprintf(cmd, sizeof(cmd), "tools/scripts/wolfip-radvd.sh stop %s", ifname);
    (void)system(cmd);
}

static void pcap_stop(void)
{
    if (pcap_pid > 0) {
        int status;

        kill(pcap_pid, SIGTERM);
        waitpid(pcap_pid, &status, 0);
        pcap_pid = 0;
    }
}

static volatile sig_atomic_t stop_requested;

static void on_sigint(int sig)
{
    (void)sig;
    stop_requested = 1;
}

static uint64_t now_ms(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return ((uint64_t)tv.tv_sec * 1000u) + ((uint64_t)tv.tv_usec / 1000u);
}

static void run_for(struct wolfIP *s, uint64_t ms)
{
    uint64_t until = now_ms() + ms;

    while (!stop_requested && (now_ms() < until)) {
        wolfIP_poll(s, now_ms());
        usleep(1000);
    }
}

/* One's complement sum, for the ICMPv6 checksum over the pseudo-header. */
static uint16_t slaac_csum(const uint8_t *a, size_t alen,
                           const uint8_t *b, size_t blen)
{
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i + 1 < alen; i += 2)
        sum += (uint32_t)((a[i] << 8) | a[i + 1]);
    if (alen & 1u)
        sum += (uint32_t)(a[alen - 1] << 8);
    for (i = 0; i + 1 < blen; i += 2)
        sum += (uint32_t)((b[i] << 8) | b[i + 1]);
    if (blen & 1u)
        sum += (uint32_t)(b[blen - 1] << 8);
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

#ifdef __linux__
/* Send a Router Advertisement onto the link from the host end of the TAP,
 * advertising SLAAC_PREFIX as on-link and autonomous. */
static int slaac_send_ra(const char *ifname)
{
    uint8_t frame[128];
    uint8_t pseudo[40];
    uint8_t dst_mac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
    struct sockaddr_ll sll;
    struct ifreq ifr;
    ip6 src;
    ip6 dst;
    ip6 prefix;
    int fd;
    int rc;
    size_t icmp_off = 14 + 40;
    size_t icmp_len = 16 + 32; /* RA header + one prefix option */
    uint16_t csum;

    if ((atoip6(SLAAC_ROUTER_LL, &src) != 0) ||
            (atoip6(SLAAC_PREFIX, &prefix) != 0))
        return -1;
    ip6_set_all_nodes(&dst);

    memset(frame, 0, sizeof(frame));
    /* Ethernet */
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, slaac_router_mac, 6);
    frame[12] = 0x86;
    frame[13] = 0xDD;
    /* IPv6 */
    frame[14] = 0x60;
    frame[18] = (uint8_t)(icmp_len >> 8);
    frame[19] = (uint8_t)(icmp_len & 0xFFu);
    frame[20] = 58;  /* ICMPv6 */
    frame[21] = 255; /* hop limit, mandatory for Neighbor Discovery */
    memcpy(frame + 22, src.addr, 16);
    memcpy(frame + 38, dst.addr, 16);
    /* Router Advertisement */
    frame[icmp_off + 0] = 134;  /* type */
    frame[icmp_off + 4] = 64;   /* cur hop limit */
    frame[icmp_off + 6] = 0x07; /* router lifetime 1800s */
    frame[icmp_off + 7] = 0x08;
    /* Prefix Information option */
    frame[icmp_off + 16] = 3;    /* type */
    frame[icmp_off + 17] = 4;    /* length, 32 octets */
    frame[icmp_off + 18] = 64;   /* prefix length */
    frame[icmp_off + 19] = 0xC0; /* on-link + autonomous */
    frame[icmp_off + 20] = 0x00; /* valid lifetime 7200s */
    frame[icmp_off + 21] = 0x00;
    frame[icmp_off + 22] = 0x1C;
    frame[icmp_off + 23] = 0x20;
    frame[icmp_off + 24] = 0x00; /* preferred lifetime 7200s */
    frame[icmp_off + 25] = 0x00;
    frame[icmp_off + 26] = 0x1C;
    frame[icmp_off + 27] = 0x20;
    memcpy(&frame[icmp_off + 32], prefix.addr, 16);

    /* IPv6 pseudo-header, RFC 8200 section 8.1 */
    memset(pseudo, 0, sizeof(pseudo));
    memcpy(pseudo, src.addr, 16);
    memcpy(pseudo + 16, dst.addr, 16);
    pseudo[34] = (uint8_t)(icmp_len >> 8);
    pseudo[35] = (uint8_t)(icmp_len & 0xFFu);
    pseudo[39] = 58;
    csum = slaac_csum(pseudo, sizeof(pseudo), &frame[icmp_off], icmp_len);
    frame[icmp_off + 2] = (uint8_t)(csum >> 8);
    frame[icmp_off + 3] = (uint8_t)(csum & 0xFFu);

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(fd);
        return -1;
    }
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, dst_mac, 6);
    rc = (int)sendto(fd, frame, icmp_off + icmp_len, 0,
                     (struct sockaddr *)&sll, sizeof(sll));
    close(fd);
    return (rc > 0) ? 0 : -1;
}
#else
static int slaac_send_ra(const char *ifname)
{
    (void)ifname;
    fprintf(stderr, "Router Advertisement injection is Linux-only\n");
    return -1;
}
#endif

#ifdef __linux__
/* Send a Neighbor Advertisement claiming `target`, from the host end of the
 * TAP. Used to provoke a duplicate address collision at a precise moment:
 * wolfIP must abandon an address somebody else advertises while it is still
 * tentative (RFC 4862 section 5.4.4). */
static int slaac_send_na(const char *ifname, const ip6 *target)
{
    uint8_t frame[128];
    uint8_t pseudo[40];
    uint8_t dst_mac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
    struct sockaddr_ll sll;
    struct ifreq ifr;
    ip6 dst;
    int fd;
    int rc;
    size_t icmp_off = 14 + 40;
    size_t icmp_len = 24 + 8; /* NA header + target link-layer address */
    uint16_t csum;

    ip6_set_all_nodes(&dst);
    memset(frame, 0, sizeof(frame));
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, slaac_router_mac, 6);
    frame[12] = 0x86;
    frame[13] = 0xDD;
    frame[14] = 0x60;
    frame[18] = (uint8_t)(icmp_len >> 8);
    frame[19] = (uint8_t)(icmp_len & 0xFFu);
    frame[20] = 58;
    frame[21] = 255;
    /* Source is the address being claimed, which is what a node defending
     * its own address does. */
    memcpy(frame + 22, target->addr, 16);
    memcpy(frame + 38, dst.addr, 16);
    frame[icmp_off + 0] = 136;  /* Neighbor Advertisement */
    frame[icmp_off + 4] = 0x20; /* Override */
    memcpy(&frame[icmp_off + 8], target->addr, 16);
    frame[icmp_off + 24] = 2;   /* target link-layer address option */
    frame[icmp_off + 25] = 1;
    memcpy(&frame[icmp_off + 26], slaac_router_mac, 6);

    memset(pseudo, 0, sizeof(pseudo));
    memcpy(pseudo, target->addr, 16);
    memcpy(pseudo + 16, dst.addr, 16);
    pseudo[34] = (uint8_t)(icmp_len >> 8);
    pseudo[35] = (uint8_t)(icmp_len & 0xFFu);
    pseudo[39] = 58;
    csum = slaac_csum(pseudo, sizeof(pseudo), &frame[icmp_off], icmp_len);
    frame[icmp_off + 2] = (uint8_t)(csum >> 8);
    frame[icmp_off + 3] = (uint8_t)(csum & 0xFFu);

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
        return -1;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        close(fd);
        return -1;
    }
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, dst_mac, 6);
    rc = (int)sendto(fd, frame, icmp_off + icmp_len, 0,
                     (struct sockaddr *)&sll, sizeof(sll));
    close(fd);
    return (rc > 0) ? 0 : -1;
}
#else
static int slaac_send_na(const char *ifname, const ip6 *target)
{
    (void)ifname; (void)target;
    return -1;
}
#endif

/* First non-link-local IPv6 address that has completed duplicate address
 * detection, or -1 if there is none yet. */
static int slaac_global_addr(struct wolfIP *s, ip6 *out)
{
    struct wolfIP_ifaddr_info info;
    unsigned int n = wolfIP_ifaddr_count(s, 0, AF_INET6);
    unsigned int i;

    for (i = 0; i < n; i++) {
        if (wolfIP_ifaddr_get(s, 0, AF_INET6, i, &info) != 0)
            continue;
        if (ip6_is_link_local(&info.v6))
            continue;
        if (info.state != WOLFIP_IFADDR_PREFERRED)
            continue;
        ip6_copy(out, &info.v6);
        return 0;
    }
    return -1;
}

static void report_addresses(struct wolfIP *s)
{
    struct wolfIP_ifaddr_info info;
    unsigned int n = wolfIP_ifaddr_count(s, 0, AF_INET6);
    unsigned int i;
    char buf[WOLFIP_IP6_ADDRSTRLEN];

    printf("wolfIP has %u IPv6 address(es):\n", n);
    for (i = 0; i < n; i++) {
        const char *state;

        if (wolfIP_ifaddr_get(s, 0, AF_INET6, i, &info) != 0)
            continue;
        switch (info.state) {
            case WOLFIP_IFADDR_TENTATIVE:  state = "tentative"; break;
            case WOLFIP_IFADDR_DEPRECATED: state = "deprecated"; break;
            default:                       state = "preferred"; break;
        }
        ip6toa(&info.v6, buf);
        printf("  %-40s /%u  %s%s\n", buf, info.prefix_len, state,
               ip6_is_link_local(&info.v6) ? "  (link-local)" : "");
    }
}

int main(int argc, char **argv)
{
    struct wolfIP *s = NULL;
    struct wolfIP_ll_dev *dev;
    char cmd[256];
    char addr_str[WOLFIP_IP6_ADDRSTRLEN];
    ip6 global;
    int selftest = 0;
    int dad_collision = 0;
    int use_radvd = (getenv("WOLFIP_SLAAC_USE_RADVD") != NULL);
    int radvd_started = 0;
    int i;
    int rc = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--selftest") == 0)
            selftest = 1;
        if (strcmp(argv[i], "--dad-collision") == 0)
            dad_collision = 1;
        if (strcmp(argv[i], "--with-radvd") == 0)
            use_radvd = 1;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    wolfIP_init_static(&s);
    dev = wolfIP_getdev(s);
    if (!dev) {
        fprintf(stderr, "no device\n");
        return 1;
    }
    {
        struct in_addr host_ip;

        inet_aton(HOST_STACK_IP, &host_ip);
        if (tap_init(dev, SLAAC_IFNAME, host_ip.s_addr) < 0) {
            perror("tap_init (are you root?)");
            return 2;
        }
    }

    pcap_start(dev->ifname, "ipv6-slaac.pcap");

    /* Give the host end an address in the prefix we are about to advertise,
     * so it can reach whatever wolfIP configures for itself. */
    snprintf(cmd, sizeof(cmd),
             "ip -6 addr replace %s/64 dev %s nodad >/dev/null 2>&1",
             SLAAC_HOSTADDR, dev->ifname);
    if (system(cmd) != 0)
        fprintf(stderr, "warning: could not add host address\n");

    /* Nothing is configured on the wolfIP side: this is the whole point. */
    if (wolfIP_ipv6_start(s, 0) != 0) {
        fprintf(stderr, "wolfIP_ipv6_start failed\n");
        return 3;
    }
    printf("IPv6 started on %s, running duplicate address detection...\n",
           dev->ifname);

    if (dad_collision) {
        struct wolfIP_ifaddr_info info;
        ip6 claimed;

        /* Punctual: claim the link-local address while it is still
         * tentative, before the detection window closes. */
        run_for(s, 300);
        if (wolfIP_ifaddr_get(s, 0, AF_INET6, 0, &info) != 0) {
            fprintf(stderr, "FAIL: no tentative address to collide with\n");
            return 7;
        }
        ip6_copy(&claimed, &info.v6);
        ip6toa(&claimed, addr_str);
        printf("claiming %s from the host while it is %s...\n", addr_str,
               (info.state == WOLFIP_IFADDR_TENTATIVE) ? "tentative"
                                                       : "already assigned");
        if (slaac_send_na(dev->ifname, &claimed) != 0) {
            fprintf(stderr, "could not send the Neighbor Advertisement\n");
            return 8;
        }
        run_for(s, 2000);
        report_addresses(s);
        if (wolfIP_ifaddr_count(s, 0, AF_INET6) != 0) {
            pcap_stop();
            printf("\nDAD collision test: FAIL (address was kept)\n");
            return 1;
        }
        pcap_stop();
        printf("\nDAD collision test: PASS (address abandoned)\n");
        return 0;
    }

    run_for(s, 2000);
    report_addresses(s);

    if (use_radvd) {
        /* radvd does not autostart, and should not: the script spawns it
         * directly against a generated config for this interface only. */
        snprintf(cmd, sizeof(cmd),
                 "tools/scripts/wolfip-radvd.sh start %s", dev->ifname);
        printf("\nStarting radvd: %s\n", cmd);
        if (system(cmd) != 0) {
            fprintf(stderr, "could not start radvd\n");
            return 4;
        }
        radvd_started = 1;
    } else {
        printf("\nInjecting a Router Advertisement for %s/64...\n",
               SLAAC_PREFIX);
        if (slaac_send_ra(dev->ifname) != 0) {
            fprintf(stderr, "could not send the Router Advertisement\n");
            return 4;
        }
    }

    /* Forming the address and verifying it takes another detection cycle.
     * radvd answers our Router Solicitation, but the solicitation itself is
     * only sent once the link-local address is usable. */
    run_for(s, use_radvd ? 9000 : 3000);
    printf("\n");
    report_addresses(s);

    if (slaac_global_addr(s, &global) != 0) {
        fprintf(stderr, "\nFAIL: no global address was configured by SLAAC\n");
        return 5;
    }
    ip6toa(&global, addr_str);
    printf("\nSLAAC configured: %s\n", addr_str);

    if (!selftest) {
        printf("\nNeighbor Discovery is implemented, so no static neighbour\n"
               "entry is needed. From another terminal:\n\n"
               "  ping -6 -c 3 %s\n\n", addr_str);
        printf("Running. Ctrl-C to stop.\n");
        run_for(s, 3600u * 1000u);
        pcap_stop();
        return 0;
    }

    {
        pid_t child = fork();
        int status = 0;

        if (child < 0) {
            perror("fork");
            return 6;
        }
        if (child == 0) {
            char pingcmd[256];

            usleep(300000);
            /* No neighbour entry is installed: the host has to resolve
             * wolfIP's link-layer address with a Neighbor Solicitation, and
             * wolfIP has to answer it. */
            snprintf(pingcmd, sizeof(pingcmd),
                     "ping -6 -c 3 -W 2 %s", addr_str);
            printf("+ %s\n", pingcmd);
            fflush(stdout);
            _exit(system(pingcmd) == 0 ? 0 : 1);
        }
        {
            uint64_t until = now_ms() + (20u * 1000u);

            while (!stop_requested && (now_ms() < until)) {
                pid_t r;

                wolfIP_poll(s, now_ms());
                usleep(1000);
                r = waitpid(child, &status, WNOHANG);
                if (r == child) {
                    rc = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
                    break;
                }
            }
        }
    }

    /* The host resolved us, so we should have it in our own cache too. */
    {
        uint8_t mac[6];
        ip6 host;

        if ((atoip6(SLAAC_HOSTADDR, &host) == 0) &&
                (wolfIP_nd6_lookup(s, 0, &host, mac) == 0)) {
            printf("neighbour cache: %s is at %02x:%02x:%02x:%02x:%02x:%02x\n",
                   SLAAC_HOSTADDR, mac[0], mac[1], mac[2], mac[3], mac[4],
                   mac[5]);
        }
    }

    radvd_stop_if_started(radvd_started, dev->ifname);
    pcap_stop();
    printf("\nSLAAC end-to-end test: %s\n", (rc == 0) ? "PASS" : "FAIL");
    return rc;
}

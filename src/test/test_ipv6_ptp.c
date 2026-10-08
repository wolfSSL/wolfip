/* test_ipv6_ptp.c
 *
 * End-to-end check that wolfIP carries IPv6 over a point-to-point link - a
 * Linux tun device, the same shape of link as macOS utun - against the host
 * stack on the other end of it.
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
 * Needs root, for the tun device.
 *
 *   sudo ./build/test-ipv6-ptp            # run and wait, ping it yourself
 *   sudo ./build/test-ipv6-ptp --selftest # run ping(8) against it and exit
 *
 * What makes this different from test_ipv6_ping.c, which does the same thing
 * over a TAP device:
 *
 *   - There is no Ethernet header and no ethertype. The stack demuxes on the
 *     version nibble alone, and the driver never sees the link headroom.
 *   - There is no link-layer address, so the interface identifier cannot be
 *     a modified EUI-64. wolfIP generates one; with
 *     WOLFIP_IPV6_IID_OVERRIDE the test pins it instead, which is also what
 *     makes the link-local address printed below reproducible.
 *   - Neighbor Discovery performs no address resolution (RFC 4861 s3). The
 *     host reaches us because the link has exactly one other end.
 *
 * Both scopes are exercised, because they fail differently: the global
 * address is reached through the on-link prefix, the link-local one through
 * the interface scope, and the second is the one that depends on the
 * interface identifier being what we said it was.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include "config.h"
#include "wolfip.h"

#if !WOLFIP_IPV6
#error "test_ipv6_ptp requires -DWOLFIP_IPV6=1"
#endif

extern int tun_init(struct wolfIP_ll_dev *dev, const char *name,
                    uint32_t host_ip, uint32_t peer_ip);

/* linux_tun.c is a pure driver and leaves this to the application, unlike
 * the TAP ports. The interface identifier is drawn from it when the
 * override is not in use, so it has to be seeded rather than constant. */
uint32_t wolfIP_getrandom(void)
{
    return (uint32_t)random();
}

#define PTP_IFNAME   "wtun6"
/* Documentation prefix, RFC 3849. The host takes ::1, wolfIP ::2. */
#define PTP_HOST_GLOBAL "2001:db8:6::1"
#define PTP_OUR_GLOBAL  "2001:db8:6::2"
#define PTP_HOST_LL     "fe80::1"

/* A fixed interface identifier, so the address the host is told to ping is
 * known before the stack has formed it. This is exactly the case
 * WOLFIP_IPV6_IID_OVERRIDE exists for - an application supplying a stable
 * identifier - and with the option off the test falls back to reading
 * whichever one was generated. */
static const uint8_t ptp_iid[8] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x42};

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

static int run_cmd(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

static int run_cmd(const char *fmt, ...)
{
    char cmd[256];
    va_list ap;
    int rc;

    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);
    printf("+ %s\n", cmd);
    fflush(stdout);
    rc = system(cmd);
    return (rc == 0) ? 0 : -1;
}

/* Poll the stack until `until_ms`, or until `child` exits. Returns the
 * child's exit status, or 0 when there is no child. */
static int run_stack(struct wolfIP *s, uint64_t until_ms, pid_t child)
{
    int status = 0;

    while (!stop_requested && (now_ms() < until_ms)) {
        wolfIP_poll(s, now_ms());
        usleep(1000);
        if (child > 0) {
            pid_t r = waitpid(child, &status, WNOHANG);

            if (r == child)
                return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
        }
    }
    if (child > 0) {
        kill(child, SIGTERM);
        waitpid(child, &status, 0);
    }
    return (child > 0) ? 1 : 0;
}

/* Wait for every address on the interface to leave TENTATIVE, so a ping is
 * not sent at an address duplicate address detection has not cleared. */
static int wait_for_dad(struct wolfIP *s, unsigned int if_idx)
{
    uint64_t deadline = now_ms() + 5000u;

    while (now_ms() < deadline) {
        unsigned int n = wolfIP_ifaddr_count(s, if_idx, AF_INET6);
        unsigned int i;
        int tentative = 0;

        wolfIP_poll(s, now_ms());
        usleep(1000);
        for (i = 0; i < n; i++) {
            struct wolfIP_ifaddr_info info;

            if (wolfIP_ifaddr_get(s, if_idx, AF_INET6, i, &info) != 0)
                continue;
            if (info.state == WOLFIP_IFADDR_TENTATIVE)
                tentative = 1;
        }
        if (!tentative && (n > 0))
            return 0;
    }
    return -1;
}

/* The link-local address the stack ended up with. */
static int our_link_local(struct wolfIP *s, unsigned int if_idx, ip6 *out)
{
    unsigned int n = wolfIP_ifaddr_count(s, if_idx, AF_INET6);
    unsigned int i;

    for (i = 0; i < n; i++) {
        struct wolfIP_ifaddr_info info;

        if (wolfIP_ifaddr_get(s, if_idx, AF_INET6, i, &info) != 0)
            continue;
        if (ip6_is_link_local(&info.v6)) {
            ip6_copy(out, &info.v6);
            return 0;
        }
    }
    return -1;
}

int main(int argc, char **argv)
{
    struct wolfIP *s = NULL;
    struct wolfIP_ll_dev *dev;
    char ll_str[WOLFIP_IP6_ADDRSTRLEN];
    ip6 link_local;
    ip6 global;
    struct in_addr host_ip;
    struct in_addr peer_ip;
    int selftest = 0;
    int i;
    int rc;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--selftest") == 0)
            selftest = 1;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    srandom((unsigned int)(now_ms() ^ (uint64_t)getpid()));

    wolfIP_init_static(&s);
    dev = wolfIP_getdev(s);
    if (!dev) {
        fprintf(stderr, "no device\n");
        return 1;
    }

    /* The IPv4 addresses only bring the interface up; nothing here uses
     * them. tun_init() marks the device non_ethernet, which is what puts
     * the stack on the point-to-point path. */
    inet_aton(HOST_STACK_IP, &host_ip);
    inet_aton(WOLFIP_IP, &peer_ip);
    if (tun_init(dev, PTP_IFNAME, host_ip.s_addr, peer_ip.s_addr) < 0) {
        perror("tun_init (are you root?)");
        return 2;
    }
    if (!dev->non_ethernet) {
        fprintf(stderr, "tun device did not come up as point-to-point\n");
        return 2;
    }

    /* The host end of the link. A /64 makes our global address on-link, so
     * the kernel routes to it without a static neighbour entry - which it
     * could not create anyway, the link having no addresses. */
    if (run_cmd("ip -6 addr add %s/64 dev %s", PTP_HOST_GLOBAL, dev->ifname) != 0)
        return 3;
    if (run_cmd("ip -6 addr add %s/64 dev %s", PTP_HOST_LL, dev->ifname) != 0)
        return 3;

    if (wolfIP_ipv6_set_iid(s, 0, ptp_iid) != 0) {
        /* Built without WOLFIP_IPV6_IID_OVERRIDE: the identifier is
         * generated, and the address is read back below rather than known
         * in advance. */
        printf("interface identifier: generated (override not compiled in)\n");
    } else {
        printf("interface identifier: fixed by the application\n");
    }

    if (wolfIP_ipv6_start(s, 0) != 0) {
        fprintf(stderr, "wolfIP_ipv6_start failed\n");
        return 3;
    }
    if (atoip6(PTP_OUR_GLOBAL, &global) != 0)
        return 3;
    if (wolfIP_ipv6_addr_add(s, 0, &global, 64) != 0) {
        fprintf(stderr, "could not add the global address\n");
        return 3;
    }

    if (wait_for_dad(s, 0) != 0) {
        fprintf(stderr, "duplicate address detection did not settle\n");
        return 4;
    }
    if (our_link_local(s, 0, &link_local) != 0) {
        fprintf(stderr, "no link-local address was formed\n");
        return 4;
    }
    ip6toa(&link_local, ll_str);

    printf("interface : %s (point-to-point, no link-layer address)\n",
           dev->ifname);
    printf("link-local: %s\n", ll_str);
    printf("global    : %s\n", PTP_OUR_GLOBAL);
    printf("host      : %s and %s\n", PTP_HOST_GLOBAL, PTP_HOST_LL);
    printf("\n");

    if (!selftest) {
        printf("From another terminal:\n\n"
               "  ping -6 -c 3 %s\n"
               "  ping -6 -c 3 %s%%%s\n\n",
               PTP_OUR_GLOBAL, ll_str, dev->ifname);
        printf("Running. Ctrl-C to stop.\n");
        return run_stack(s, now_ms() + (3600u * 1000u), 0);
    }

    {
        pid_t child;

        /* Drain first: anything still buffered would be duplicated by the
         * child when it exits. */
        fflush(stdout);
        child = fork();
        if (child < 0) {
            perror("fork");
            return 5;
        }
        if (child == 0) {
            int failed = 0;

            /* Give the parent a moment to start polling. */
            usleep(300000);
            /* Global scope: reached through the on-link prefix. */
            if (run_cmd("ping -6 -c 3 -W 2 %s", PTP_OUR_GLOBAL) != 0)
                failed = 1;
            /* Link-local scope: reached through the interface, and only
             * correct if the interface identifier is the one we set. */
            if (run_cmd("ping -6 -c 3 -W 2 %s%%%s", ll_str, dev->ifname) != 0)
                failed = 1;
            _exit(failed);
        }
        rc = run_stack(s, now_ms() + (30u * 1000u), child);
    }

    printf("\nIPv6 point-to-point echo self-test: %s\n",
           (rc == 0) ? "PASS" : "FAIL");
    return rc;
}

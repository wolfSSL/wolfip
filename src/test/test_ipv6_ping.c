/* test_ipv6_ping.c
 *
 * End-to-end check that wolfIP answers ICMPv6 Echo Requests from a real
 * host stack, over a TAP device or a VDE switch.
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
 * Needs root, for the TAP device and for the neighbour entry described
 * below. With a VDE switch, build with BUILD_VDE=1 and point
 * VDE_SOCKET_PATH at the switch's control socket.
 *
 *   sudo ./build/test-ipv6-ping            # run and wait, ping it yourself
 *   sudo ./build/test-ipv6-ping --selftest # run ping(8) against it and exit
 *
 * IMPORTANT - why a static neighbour entry is needed
 *
 * Neighbor Discovery is not implemented yet. Before the host can send us an
 * Echo Request it has to learn our link-layer address, and it would normally
 * do that with a Neighbor Solicitation that this stack cannot yet answer. So
 * the neighbour entry is installed by hand:
 *
 *   ip -6 neigh replace <our-link-local> lladdr <our-mac> dev <iface> \
 *       nud permanent
 *
 * --selftest does this for you. Once NDP lands the entry becomes
 * unnecessary and this comment, and the code that installs it, should go.
 *
 * Answering the ping itself needs nothing further: the reply goes back to
 * the source MAC of the request, so no address resolution happens on our
 * side. That is exactly why Echo Reply is implementable before NDP.
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

#include "config.h"
#include "wolfip.h"

#if !WOLFIP_IPV6
#error "test_ipv6_ping requires -DWOLFIP_IPV6=1"
#endif

extern int tap_init(struct wolfIP_ll_dev *dev, const char *name,
                    uint32_t host_ip);
#if WOLFIP_USE_VDE
extern int vde_init(struct wolfIP_ll_dev *ll, const char *socket_path,
                    const char *port, const uint8_t *mac);
#endif

#define PING_IFNAME "wtcp0"
/* Documentation prefix, RFC 3849. Handy for watching global-scope traffic
 * alongside the link-local address. */
#define PING_GLOBAL "2001:db8::1"

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

/* Run the stack until `until_ms`, or until interrupted, or until `child`
 * (when non-zero) exits. Returns the child's exit status, or 0. */
static int run_stack(struct wolfIP *s, uint64_t until_ms, pid_t child)
{
    int status = 0;

    while (!stop_requested && (now_ms() < until_ms)) {
        wolfIP_poll(s, now_ms());
        usleep(1000);
        if (child != 0) {
            pid_t r = waitpid(child, &status, WNOHANG);

            if (r == child)
                return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
        }
    }
    if (child != 0) {
        kill(child, SIGTERM);
        waitpid(child, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct wolfIP *s = NULL;
    struct wolfIP_ll_dev *dev;
    char ll_str[WOLFIP_IP6_ADDRSTRLEN];
    char cmd[256];
    ip6 link_local;
    ip6 prefix;
    ip6 iid;
    ip6 global;
    int selftest = 0;
    int i;
    int rc;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--selftest") == 0)
            selftest = 1;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    wolfIP_init_static(&s);
    dev = wolfIP_getdev(s);
    if (!dev) {
        fprintf(stderr, "no device\n");
        return 1;
    }

#if WOLFIP_USE_VDE
    {
        const char *sock = getenv("VDE_SOCKET_PATH");

        if (!sock)
            sock = "/tmp/vde_switch.ctl";
        if (vde_init(dev, sock, NULL, NULL) < 0) {
            perror("vde_init");
            return 2;
        }
        printf("VDE switch socket: %s\n", sock);
    }
#else
    {
        struct in_addr host_ip;

        /* The IPv4 address is only there to get the interface configured
         * and up; nothing in this test uses it. */
        inet_aton(HOST_STACK_IP, &host_ip);
        if (tap_init(dev, PING_IFNAME, host_ip.s_addr) < 0) {
            perror("tap_init (are you root?)");
            return 2;
        }
    }
#endif

    /* Link-local address from the interface MAC, the way RFC 4862 section
     * 5.3 forms it: fe80::/64 plus a modified EUI-64 interface identifier.
     * SLAAC will do this by itself later; here it is done explicitly. */
    if (atoip6("fe80::", &prefix) != 0)
        return 3;
    ip6_iid_from_mac(&iid, dev->mac);
    ip6_make_addr(&link_local, &prefix, 64, &iid);
    if (wolfIP_ifaddr_add6(s, 0, &link_local, 64) != 0) {
        fprintf(stderr, "could not add link-local address\n");
        return 3;
    }
    if (atoip6(PING_GLOBAL, &global) == 0)
        (void)wolfIP_ifaddr_add6(s, 0, &global, 64);

    ip6toa(&link_local, ll_str);
    printf("interface : %s\n", dev->ifname);
    printf("mac       : %02x:%02x:%02x:%02x:%02x:%02x\n",
           dev->mac[0], dev->mac[1], dev->mac[2],
           dev->mac[3], dev->mac[4], dev->mac[5]);
    printf("link-local: %s\n", ll_str);
    printf("global    : %s\n", PING_GLOBAL);
    printf("\n");

    /* Neighbor Discovery is not implemented, so the host cannot resolve our
     * MAC on its own. Install the mapping by hand. */
    snprintf(cmd, sizeof(cmd),
             "ip -6 neigh replace %s lladdr %02x:%02x:%02x:%02x:%02x:%02x "
             "dev %s nud permanent",
             ll_str, dev->mac[0], dev->mac[1], dev->mac[2],
             dev->mac[3], dev->mac[4], dev->mac[5], dev->ifname);

    if (!selftest) {
        printf("Neighbor Discovery is not implemented yet, so run this\n"
               "once before pinging:\n\n  sudo %s\n\n", cmd);
        printf("then, from another terminal:\n\n"
               "  ping -6 -c 3 %s%%%s\n\n", ll_str, dev->ifname);
        printf("Running. Ctrl-C to stop.\n");
        return run_stack(s, now_ms() + (3600u * 1000u), 0);
    }

    if (system(cmd) != 0)
        fprintf(stderr, "warning: could not install neighbour entry\n");

    {
        pid_t child = fork();

        if (child < 0) {
            perror("fork");
            return 4;
        }
        if (child == 0) {
            char pingcmd[256];

            /* Give the parent a moment to start polling. */
            usleep(300000);
            snprintf(pingcmd, sizeof(pingcmd),
                     "ping -6 -c 3 -W 2 %s%%%s", ll_str, dev->ifname);
            printf("+ %s\n", pingcmd);
            fflush(stdout);
            _exit(system(pingcmd) == 0 ? 0 : 1);
        }
        rc = run_stack(s, now_ms() + (20u * 1000u), child);
    }

    printf("\nICMPv6 echo self-test: %s\n", (rc == 0) ? "PASS" : "FAIL");
    return rc;
}

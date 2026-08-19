/* macsec_sta.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfIP.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfIP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* macsec_sta - a host harness that runs the wolfDen wolfMKA control plane
 * (via the wolfIP adapter) over an AF_PACKET raw socket, driving wolfIP's
 * software SecY, for interop against Linux wpa_supplicant's MKA. It carries
 * EAPOL-MKA frames (EtherType 0x888E to the PAE group address), and prints
 * SAK-INSTALLED once a SAK is agreed. With MACSEC_KERNEL_DEV set it also
 * programs the SAK into that kernel macsec device for a data-plane test.
 *
 *   macsec_sta <ifname> <cak_hex> <ckn_hex> <priority> [timeout_s]
 *
 * Linux only; built with WOLFMKA_DIR. Used by the run_macsec_mka_*.sh tests.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "mka_wolfmka.h"

static int g_fd = -1;
static int g_ifindex;

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)(ts.tv_nsec / 1000000U);
}

static size_t unhex(const char *h, uint8_t *o, size_t cap)
{
    size_t   n = 0;
    unsigned v;
    while (h[0] && h[1] && n < cap) {
        if (sscanf(h, "%2x", &v) != 1) {   /* stop on the first non-hex pair */
            break;
        }
        o[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

/* Accept only characters valid in a Linux interface name; MACSEC_KERNEL_DEV is
 * spliced into an "ip macsec" command line, so reject anything a shell could
 * treat specially. */
static int iface_name_ok(const char *s)
{
    size_t i, n;
    char   c;
    if (s == NULL) {
        return 0;
    }
    n = strlen(s);
    if (n == 0 || n >= IFNAMSIZ) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-')) {
            return 0;
        }
    }
    return 1;
}

static void run_ip(const char *cmd)
{
    if (system(cmd) != 0) {
        fprintf(stderr, "warning: command failed: %s\n", cmd);
    }
}

static int cb_send(void *ctx, const uint8_t *frame, size_t len)
{
    struct sockaddr_ll sll;
    (void)ctx;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family  = AF_PACKET;
    sll.sll_ifindex = g_ifindex;
    sll.sll_halen   = 6;
    memcpy(sll.sll_addr, frame, 6);            /* destination MAC */
    if (sendto(g_fd, frame, len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "sendto: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static void print_sak(size_t sak_len, uint8_t an, const uint8_t *sak,
                      const uint8_t sci[8])
{
    size_t i;
    printf("SAK-INSTALLED len=%zu an=%u sak=", sak_len, an);
    for (i = 0; i < sak_len; i++) printf("%02x", sak[i]);
    printf(" sci=");
    for (i = 0; i < 8; i++) printf("%02x", sci[i]);
    printf("\n");
    fflush(stdout);
}

/* ---- backend glue (wolfMKA) ---- */

static struct mka_wolfmka  g_m;
static struct macsec_tx_sc g_tx;
static struct macsec_rx_sc g_rx;

/* Program the agreed SAK into a kernel macsec device (data-plane demo). The
 * adapter already installed the SAK into the software SecY channels, so we
 * read it back from there. The device must already exist (ip link add ...
 * type macsec). Returns 0 on success. */
static void hexenc(char *out, const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) { sprintf(out + 2 * i, "%02x", b[i]); }
    out[2 * n] = '\0';
}

static void backend_program_kernel(const char *dev)
{
    char cmd[600], txsak[65], rxsak[65], rxsci[17];
    if (!iface_name_ok(dev)) {
        fprintf(stderr, "refusing unsafe MACSEC_KERNEL_DEV '%s'\n",
                dev != NULL ? dev : "(null)");
        return;
    }
    hexenc(txsak, g_tx.sak, g_tx.sak_len);
    hexenc(rxsak, g_rx.sak, g_rx.sak_len);
    hexenc(rxsci, g_rx.sci, 8);
    snprintf(cmd, sizeof cmd,
             "ip macsec add %s tx sa %u pn 1 on key 01 %s", dev, g_tx.an, txsak);
    run_ip(cmd);
    snprintf(cmd, sizeof cmd, "ip macsec add %s rx sci %s on", dev, rxsci);
    run_ip(cmd);
    snprintf(cmd, sizeof cmd,
             "ip macsec add %s rx sci %s sa %u pn 1 on key 02 %s",
             dev, rxsci, g_rx.an, rxsak);
    run_ip(cmd);
    printf("MACSEC-UP dev=%s\n", dev);
    fflush(stdout);
}

static int backend_init(const uint8_t *cak, size_t cak_len,
                        const uint8_t *ckn, size_t ckn_len,
                        const uint8_t sci[8], uint8_t prio)
{
    memset(&g_tx, 0, sizeof(g_tx));
    memset(&g_rx, 0, sizeof(g_rx));
    return mka_wolfmka_init_psk(&g_m, cb_send, NULL, cak, cak_len, ckn, ckn_len,
                                sci, prio, 1 /* key_server_capable */,
                                16 /* GCM-AES-128 */, &g_tx, &g_rx);
}
static void backend_rx(const uint8_t *f, size_t n, uint64_t t)
{ (void)mka_wolfmka_rx(&g_m, f, n, (uint32_t)t); }
static void backend_tick(uint64_t t) { (void)mka_wolfmka_tick(&g_m, (uint32_t)t); }
static int  backend_installed(void) { return mka_wolfmka_installed(&g_m); }
static void backend_report(void)
{ print_sak(g_tx.sak_len, g_tx.an, g_tx.sak, g_tx.sci); }
static void backend_free(void) { mka_wolfmka_free(&g_m); }

static void pump(uint8_t *buf, size_t cap)
{
    struct pollfd pfd;
    pfd.fd = g_fd; pfd.events = POLLIN; pfd.revents = 0;
    if (poll(&pfd, 1, 200) > 0 && (pfd.revents & POLLIN)) {
        ssize_t n = recv(g_fd, buf, cap, 0);
        /* EAPOL-MKA only: EtherType 0x888E, packet type 5. */
        if (n >= 18 && buf[12] == 0x88 && buf[13] == 0x8E && buf[15] == 5) {
            backend_rx(buf, (size_t)n, now_ms());
        }
    }
    backend_tick(now_ms());
}

int main(int argc, char **argv)
{
    struct ifreq ifr;
    struct sockaddr_ll sll;
    uint8_t cak[32], ckn[32], sci[8], mac[6], buf[2048];
    size_t  cak_len, ckn_len;
    uint64_t deadline;
    int      timeout_s = 15;
    int      prio;

    if (argc < 5) {
        fprintf(stderr, "usage: %s ifname cak_hex ckn_hex priority [timeout_s]\n",
                argv[0]);
        return 2;
    }
    cak_len = unhex(argv[2], cak, sizeof(cak));
    ckn_len = unhex(argv[3], ckn, sizeof(ckn));
    prio    = atoi(argv[4]);
    if (argc >= 6) timeout_s = atoi(argv[5]);

    /* CAK must be a full 16- or 32-byte hex string; CKN 1..32 bytes. Require
     * the whole argument to be consumed so a bad hex tail is not silently
     * accepted with unintended key bytes. */
    if ((cak_len != 16 && cak_len != 32) || strlen(argv[2]) != cak_len * 2) {
        fprintf(stderr, "cak must be 16 or 32 bytes of hex\n");
        return 2;
    }
    if (ckn_len == 0 || strlen(argv[3]) != ckn_len * 2) {
        fprintf(stderr, "ckn must be 1..32 bytes of hex\n");
        return 2;
    }

    g_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_fd < 0) { perror("socket"); return 1; }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
    if (ioctl(g_fd, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return 1; }
    g_ifindex = ifr.ifr_ifindex;
    if (ioctl(g_fd, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return 1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = g_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(g_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); return 1;
    }

    memcpy(sci, mac, 6); sci[6] = 0x00; sci[7] = 0x01;   /* SCI = MAC || port 1 */

    if (backend_init(cak, cak_len, ckn, ckn_len, sci, (uint8_t)prio) != 0) {
        fprintf(stderr, "backend init failed\n"); close(g_fd); return 1;
    }
    printf("macsec_sta: if=%s prio=%d mac=%02x%02x%02x%02x%02x%02x backend=wolfmka\n",
           argv[1], prio, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    fflush(stdout);
    backend_tick(now_ms());                              /* emit the first MKPDU */

    deadline = now_ms() + (uint64_t)timeout_s * 1000U;
    {
        const char *kdev = getenv("MACSEC_KERNEL_DEV");
        while (now_ms() < deadline) {
            pump(buf, sizeof(buf));
            if (backend_installed()) {
                /* In kernel mode program the SAK into the macsec device and
                 * keep MKA alive to the deadline so a ping can flow; otherwise
                 * just let the peer finish and exit. */
                uint64_t until = (kdev != NULL) ? deadline : (now_ms() + 1500U);
                backend_report();
                if (kdev != NULL) {
                    backend_program_kernel(kdev);
                }
                while (now_ms() < until) {
                    pump(buf, sizeof(buf));
                }
                backend_free();
                close(g_fd);
                return 0;
            }
        }
    }
    fprintf(stderr, "macsec_sta: no SAK agreed within %ds\n", timeout_s);
    backend_free();
    close(g_fd);
    return 1;
}

/* wolfsta.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfIP.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* wolfsta - host STA app: wolfIP + wolfSupplicant on a real netdev.
 *
 * Joins a Wi-Fi network through the wolfSupplicant (WPA2-PSK or WPA3-SAE)
 * over the SoftMAC nl80211 path (tools/hostapd/nl80211_sta.c), then runs
 * the wolfIP stack over the radio's netdev via an AF_PACKET link device:
 * once the negotiated keys are installed in the kernel, the kernel
 * decrypts inbound frames and encrypts outbound ones, so wolfIP owns L3
 * over plaintext Ethernet.
 *
 *   join (supplicant) -> AUTHENTICATED -> DHCP -> [optional UDP echo]
 *
 * The kernel must NOT also run IP on the interface, or the two stacks
 * fight over ARP/ICMP. Before running:
 *     ip addr flush dev <ifname>
 *     ip link set <ifname> up
 * (kept out of this binary so it does not silently reconfigure the host).
 * An external host can verify reachability with `ping <leased-ip>`.
 *
 * Usage:
 *   wolfsta <ifname> <ssid> psk|sae <passphrase> <bssid> [freq_mhz] [group]
 *
 * Requires root, libnl-genl-3, and (for SAE) wolfSSL built with
 * WOLFSSL_PUBLIC_MP.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <sys/random.h>

#include "config.h"
#include "wolfip.h"

#include "supplicant.h"
#include "nl80211_sta.h"

#define JOIN_TIMEOUT_MS 20000
#define DHCP_TIMEOUT_MS 15000

/* AF_PACKET link device (ETH_P_ALL) bound to the radio netdev. */
static int     g_data_sock = -1;
static int     g_data_ifindex = -1;
static uint8_t g_data_mac[6];

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

/* Optional post-DHCP UDP echo probe (WOLFSTA_ECHO="ip:port"): proves
 * wolfIP UDP TX/RX over the encrypted link end to end. */
static int g_echo_ok = 0;
static void udp_echo_cb(int fd, uint16_t ev, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    uint8_t b[64];
    if ((ev & CB_EVENT_READABLE) != 0) {
        if (wolfIP_sock_recvfrom(s, fd, b, sizeof(b), 0, NULL, NULL) > 0) {
            g_echo_ok = 1;
        }
    }
}

/* Entropy hook required by the wolfIP core (normally supplied by the
 * netdev port; wolfsta brings its own AF_PACKET link device). */
uint32_t wolfIP_getrandom(void)
{
    uint32_t v = 0;
    if (getrandom(&v, sizeof(v), 0) != (ssize_t)sizeof(v)) {
        /* Fall back to a time-seeded value; entropy here is not
         * security-critical (TCP ISN / ephemeral ports for a test STA). */
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        v = (uint32_t)(ts.tv_nsec ^ (ts.tv_sec << 16));
    }
    return v;
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

static int parse_mac(const char *str, uint8_t out[6])
{
    unsigned int v[6];
    int i;
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return -1;
    for (i = 0; i < 6; i++) {
        if (v[i] > 0xFF) return -1;   /* reject out-of-range octets */
        out[i] = (uint8_t)v[i];
    }
    return 0;
}

/* ---- AF_PACKET link device for the wolfIP data path ---- */

static int data_sock_open(const char *ifname)
{
    struct ifreq       ifr;
    struct sockaddr_ll sll;
    int s, flags;

    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) { perror("socket(AF_PACKET data)"); return -1; }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX"); close(s); return -1;
    }
    g_data_ifindex = ifr.ifr_ifindex;
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR"); close(s); return -1;
    }
    memcpy(g_data_mac, ifr.ifr_hwaddr.sa_data, 6);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = g_data_ifindex;
    if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind(AF_PACKET data)"); close(s); return -1;
    }
    flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0) fcntl(s, F_SETFL, flags | O_NONBLOCK);
    g_data_sock = s;
    return 0;
}

static int data_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct sockaddr_ll sll;
    socklen_t slen = sizeof(sll);
    ssize_t n;
    (void)ll;

    if (g_data_sock < 0) return -1;
    n = recvfrom(g_data_sock, buf, len, 0, (struct sockaddr *)&sll, &slen);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    /* Skip our own outbound copies (AF_PACKET sees PACKET_OUTGOING). */
    if (sll.sll_pkttype == PACKET_OUTGOING) return 0;
    return (int)n;
}

static int data_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct sockaddr_ll sll;
    ssize_t n;
    (void)ll;

    if (g_data_sock < 0) return -1;
    if (len < 14U) return -1;       /* need a full Ethernet header to read dst MAC */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family  = AF_PACKET;
    sll.sll_ifindex = g_data_ifindex;
    sll.sll_halen   = 6;
    memcpy(sll.sll_addr, buf, 6);   /* dst MAC from the Ethernet header */
    n = sendto(g_data_sock, buf, len, 0,
               (struct sockaddr *)&sll, sizeof(sll));
    if (n < 0) { perror("sendto(data)"); return -1; }
    return (int)n;
}

/* ---- main ---- */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s <ifname> <ssid> psk|sae <passphrase> <bssid> "
        "[freq_mhz] [sae_group]\n", argv0);
}

int main(int argc, char **argv)
{
    const char *ifname, *ssid, *mode, *secret, *bssid_s;
    uint32_t freq = 2412;
    int      sae_group = SAE_GROUP_19;
    struct nl80211_sta            sta;
    struct wolfip_supplicant      supp;
    struct wolfip_supplicant_cfg  cfg;
    enum nl80211_sta_akm akm;
    enum nl80211_sta_mfp mfp;
    uint8_t  bssid[6];
    uint64_t deadline;
    int      state, authed = 0;
    struct wolfIP        *ipstack = NULL;
    struct wolfIP_ll_dev *dev;
    ip4 ip = 0, nm = 0, gw = 0;
    int  rc = 1;
    const char *echo_spec;
    struct wolfIP_sockaddr_in echo_dst;
    int  echo_fd = -1, echo_probes = 0, echo_reported = 0;
    long hold_secs = 0;
    uint64_t hold_deadline = 0, next_probe = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    if (argc < 6) { usage(argv[0]); return 2; }
    ifname  = argv[1];
    ssid    = argv[2];
    mode    = argv[3];
    secret  = argv[4];
    bssid_s = argv[5];
    if (argc > 6) freq = (uint32_t)atoi(argv[6]);
    if (argc > 7) sae_group = atoi(argv[7]);
    if (parse_mac(bssid_s, bssid) != 0) {
        fprintf(stderr, "bad bssid: %s\n", bssid_s);
        return 2;
    }

    if (strcmp(mode, "sae") == 0) {
        akm = NL80211_STA_AKM_SAE;
        mfp = NL80211_STA_MFP_REQUIRED;     /* WPA3 mandates MFP */
    }
    else if (strcmp(mode, "psk") == 0) {
        akm = NL80211_STA_AKM_PSK;
        mfp = NL80211_STA_MFP_NONE;
    }
    else {
        fprintf(stderr, "mode must be psk or sae\n");
        return 2;
    }

    /* ---- phase 1: join via the supplicant ---- */
    if (nl80211_sta_init(&sta, ifname) != 0) {
        fprintf(stderr, "nl80211_sta_init(%s) failed\n", ifname);
        return 1;
    }
    sta.verbose = 1;
    if (nl80211_sta_set_target(&sta, ssid, bssid, freq, akm, mfp) != 0) {
        fprintf(stderr, "set_target failed\n");
        goto out_radio;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.ssid           = ssid;
    cfg.ssid_len       = strlen(ssid);
    cfg.passphrase     = secret;
    cfg.passphrase_len = strlen(secret);
    memcpy(cfg.ap_mac,  bssid,        6);
    memcpy(cfg.sta_mac, sta.sta_mac,  6);
    nl80211_sta_supplicant_ops(&sta, &cfg.ops);
    if (akm == NL80211_STA_AKM_SAE) {
        cfg.auth_mode    = WOLFIP_AUTH_SAE;
        cfg.sae_group    = sae_group;
        cfg.mfp_capable  = 1;
        cfg.mfp_required = 1;
    }
    else {
        cfg.auth_mode = WOLFIP_AUTH_PSK;
    }

    if (wolfip_supplicant_init(&supp, &cfg) != 0) {
        fprintf(stderr, "supplicant_init failed\n");
        goto out_radio;
    }
    nl80211_sta_attach(&sta, &supp);
    printf("[wolfsta] joining ssid='%s' (%s) bssid=%s freq=%uMHz\n",
           ssid, mode, bssid_s, freq);

    if (nl80211_sta_start(&sta, now_ms()) != 0) {
        fprintf(stderr, "nl80211_sta_start failed\n");
        goto out_supp;
    }

    deadline = now_ms() + JOIN_TIMEOUT_MS;
    while (now_ms() < deadline && !g_stop) {
        state = nl80211_sta_poll(&sta, 200, now_ms());
        if (state < 0) break;
        if (state == (int)SUPP_STATE_AUTHENTICATED) { authed = 1; break; }
    }
    if (!authed) {
        fprintf(stderr, "[wolfsta] join failed (supp_state=%d failed=%d)\n",
                (int)wolfip_supplicant_state(&supp), sta.failed);
        goto out_supp;
    }
    printf("[wolfsta] AUTHENTICATED; keys installed - starting wolfIP\n");

    /* ---- phase 2: wolfIP over the radio netdev ---- */
    if (data_sock_open(ifname) != 0) goto out_supp;

    wolfIP_init_static(&ipstack);
    dev = wolfIP_getdev(ipstack);
    if (dev == NULL) { fprintf(stderr, "wolfIP_getdev failed\n"); goto out_data; }
    memcpy(dev->mac, sta.sta_mac, 6);
    snprintf(dev->ifname, sizeof(dev->ifname), "%s", ifname);
    dev->poll = data_poll;
    dev->send = data_send;

    printf("[wolfsta] DHCP: requesting a lease...\n");
    wolfIP_poll(ipstack, now_ms());
    dhcp_client_init(ipstack);
    deadline = now_ms() + DHCP_TIMEOUT_MS;
    do {
        wolfIP_poll(ipstack, now_ms());
        usleep(1000);
    } while (!dhcp_bound(ipstack) && now_ms() < deadline && !g_stop);

    if (!dhcp_bound(ipstack)) {
        fprintf(stderr, "[wolfsta] DHCP timed out\n");
        goto out_data;
    }
    wolfIP_ipconfig_get(ipstack, &ip, &nm, &gw);
    printf("[wolfsta] DHCP bound: ip=%u.%u.%u.%u nm=%u.%u.%u.%u gw=%u.%u.%u.%u\n",
           (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
           (nm >> 24) & 0xFF, (nm >> 16) & 0xFF, (nm >> 8) & 0xFF, nm & 0xFF,
           (gw >> 24) & 0xFF, (gw >> 16) & 0xFF, (gw >> 8) & 0xFF, gw & 0xFF);
    rc = 0;

    /* Optional UDP echo probe to <ip>:<port> (WOLFSTA_ECHO). Run e.g.
     * `socat UDP4-RECVFROM:7777,fork EXEC:/bin/cat` on the AP side. */
    echo_spec = getenv("WOLFSTA_ECHO");
    if (echo_spec != NULL) {
        char ipbuf[64];
        const char *colon = strchr(echo_spec, ':');
        if (colon != NULL && (size_t)(colon - echo_spec) < sizeof(ipbuf)) {
            memcpy(ipbuf, echo_spec, (size_t)(colon - echo_spec));
            ipbuf[colon - echo_spec] = '\0';
            echo_fd = wolfIP_sock_socket(ipstack, AF_INET,
                                         IPSTACK_SOCK_DGRAM, IPPROTO_UDP);
            if (echo_fd >= 0) {
                memset(&echo_dst, 0, sizeof(echo_dst));
                echo_dst.sin_family      = AF_INET;
                echo_dst.sin_port        = htons((uint16_t)atoi(colon + 1));
                echo_dst.sin_addr.s_addr = inet_addr(ipbuf);
                wolfIP_register_callback(ipstack, echo_fd, udp_echo_cb,
                                         ipstack);
                printf("[wolfsta] UDP echo probe -> %s\n", echo_spec);
            }
        }
    }

    /* Hold the link up so the lease can be exercised externally (e.g.
     * `ping <leased-ip>` from another host). WOLFSTA_HOLD_SECS bounds the
     * hold for scripted tests (0 = until Ctrl-C). */
    {
        const char *hs = getenv("WOLFSTA_HOLD_SECS");
        if (hs != NULL) hold_secs = atol(hs);
    }
    if (hold_secs > 0) hold_deadline = now_ms() + (uint64_t)hold_secs * 1000ULL;
    printf("[wolfsta] link up - polling%s\n",
           hold_secs > 0 ? "" : " (Ctrl-C to quit)");
    while (!g_stop && (hold_secs == 0 || now_ms() < hold_deadline)) {
        wolfIP_poll(ipstack, now_ms());
        if (echo_fd >= 0 && !g_echo_ok && echo_probes < 20
            && now_ms() >= next_probe) {
            wolfIP_sock_sendto(ipstack, echo_fd, "wolfsta-probe", 13, 0,
                               (struct wolfIP_sockaddr *)&echo_dst,
                               sizeof(echo_dst));
            next_probe = now_ms() + 400;
            echo_probes++;
        }
        if (echo_fd >= 0 && g_echo_ok && !echo_reported) {
            printf("[wolfsta] UDP echo OK\n");
            echo_reported = 1;
        }
        usleep(2000);
    }
    if (echo_spec != NULL && echo_fd >= 0 && !g_echo_ok) {
        printf("[wolfsta] UDP echo: no reply (informational)\n");
    }

out_data:
    if (echo_fd >= 0) wolfIP_sock_close(ipstack, echo_fd);
    if (g_data_sock >= 0) close(g_data_sock);
out_supp:
    wolfip_supplicant_deinit(&supp);
out_radio:
    nl80211_sta_cleanup(&sta);
    return rc;
}

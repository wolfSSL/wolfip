/* test_supplicant_hostapd_psk.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Real-authenticator 4-way handshake test. Hostapd is configured for
 * wired+WPA2-PSK; on first EAPOL frame from us, hostapd's wpa_auth
 * state machine creates a STA entry and emits EAPOL-Key M1. Our
 * supplicant then runs M1->M2->M3->M4 against the real implementation.
 *
 * Success: supplicant reaches SUPP_STATE_AUTHENTICATED and hostapd
 * reports the supplicant as connected.
 *
 * Usage: sudo ./test-supplicant-hostapd-psk <ifname> <ssid> <psk> <ap_mac>
 *
 *   ifname   veth peer on the supplicant side (e.g. wolfip-supp)
 *   ssid     SSID hostapd was configured with (used in PMK derivation)
 *   psk      passphrase (>=8 chars), must match hostapd's wpa_passphrase
 *   ap_mac   MAC address of hostapd's interface (xx:xx:xx:xx:xx:xx),
 *            used as Authenticator Address in PTK derivation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "supplicant.h"
#include "eapol.h"
#include "rsn_ie.h"
#include "wpa_crypto.h"

/* Path hostapd's PSK config writes its ctrl socket to. */
#define HOSTAPD_CTRL_DIR "/tmp/wolfip_hostapd_ctrl"
#define HOSTAPD_CTRL_IF  "wolfip-auth"

#define EAPOL_ETH_TYPE 0x888EU

struct host_ctx {
    int     sock;
    int     ifindex;
    uint8_t local_mac[6];
    uint8_t peer_mac[6];   /* hostapd interface MAC: where to unicast    */
};
static struct host_ctx HCTX;

static int psk_send_eapol(void *ctx, const uint8_t *frame, size_t len)
{
    struct host_ctx *h = (struct host_ctx *)ctx;
    uint8_t eth[1600];
    struct sockaddr_ll sll;

    if (len + 14 > sizeof(eth)) return -1;
    /* For PSK on wired we unicast to the authenticator's MAC. PAE
     * multicast also works, but unicast keeps frames off the local
     * loopback path and matches what a real STA does post-association. */
    memcpy(&eth[0], h->peer_mac,  6);
    memcpy(&eth[6], h->local_mac, 6);
    eth[12] = (uint8_t)(EAPOL_ETH_TYPE >> 8);
    eth[13] = (uint8_t)(EAPOL_ETH_TYPE & 0xFFU);
    memcpy(&eth[14], frame, len);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = h->ifindex;
    sll.sll_halen    = 6;
    memcpy(sll.sll_addr, h->peer_mac, 6);
    if (sendto(h->sock, eth, len + 14, 0,
               (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "sendto: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

struct install_rec {
    int      pairwise_set;
    int      group_set;
    uint8_t  tk[WPA_TK_LEN];
    uint8_t  gtk[WPA_GTK_MAX_LEN];
    size_t   gtk_len;
};
static struct install_rec installs;

static int psk_install_key(void *ctx, wolfip_supplicant_keytype_t kt,
                           uint8_t idx, const uint8_t *k, size_t l)
{
    (void)ctx; (void)idx;
    if (kt == SUPP_KEY_PAIRWISE) {
        if (l != WPA_TK_LEN) return -1;
        memcpy(installs.tk, k, l);
        installs.pairwise_set = 1;
        printf("install_key PAIRWISE (TK 16B) from real hostapd\n");
    }
    else {
        if (l == 0 || l > WPA_GTK_MAX_LEN) return -1;
        memcpy(installs.gtk, k, l);
        installs.gtk_len = l;
        installs.group_set = 1;
        printf("install_key GROUP (GTK %zuB) from real hostapd\n", l);
    }
    return 0;
}

static int open_raw_socket(const char *ifname, struct host_ctx *h)
{
    struct ifreq ifr;
    struct sockaddr_ll sll;
    int s;

    s = socket(AF_PACKET, SOCK_RAW, htons(EAPOL_ETH_TYPE));
    if (s < 0) {
        fprintf(stderr, "socket(AF_PACKET): %s (need root)\n", strerror(errno));
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "SIOCGIFINDEX(%s): %s\n", ifname, strerror(errno));
        close(s); return -1;
    }
    h->ifindex = ifr.ifr_ifindex;

    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "SIOCGIFHWADDR(%s): %s\n", ifname, strerror(errno));
        close(s); return -1;
    }
    memcpy(h->local_mac, ifr.ifr_hwaddr.sa_data, 6);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(EAPOL_ETH_TYPE);
    sll.sll_ifindex  = h->ifindex;
    if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        close(s); return -1;
    }
    h->sock = s;
    return 0;
}

static int parse_mac(const char *s, uint8_t out[6])
{
    unsigned int v[6];
    int i;
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return -1;
    for (i = 0; i < 6; i++) {
        if (v[i] > 0xFF) return -1;
        out[i] = (uint8_t)v[i];
    }
    return 0;
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

/* PMKID = trunc-128( HMAC-SHA1( PMK, "PMK Name" || AA || SPA ) ).
 * Per IEEE 802.11-2020 12.7.1.3. Hostapd uses this to key its PMKSA
 * cache entries; pre-installing one lets the 4-way handshake skip EAP. */
static int derive_pmkid(const uint8_t pmk[32],
                        const uint8_t aa[6],
                        const uint8_t spa[6],
                        uint8_t out_pmkid[16])
{
    static const char *label = "PMK Name";
    Hmac hmac;
    uint8_t digest[WC_SHA_DIGEST_SIZE];
    int ret;

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) return ret;
    ret = wc_HmacSetKey(&hmac, WC_SHA, pmk, 32);
    if (ret == 0) ret = wc_HmacUpdate(&hmac, (const byte *)label, 8);
    if (ret == 0) ret = wc_HmacUpdate(&hmac, aa, 6);
    if (ret == 0) ret = wc_HmacUpdate(&hmac, spa, 6);
    if (ret == 0) ret = wc_HmacFinal(&hmac, digest);
    wc_HmacFree(&hmac);
    if (ret != 0) return ret;
    memcpy(out_pmkid, digest, 16);
    return 0;
}

static void hex_print(char *out, const uint8_t *in, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) sprintf(out + i * 2, "%02x", in[i]);
    out[n * 2] = '\0';
}

/* Send a single command to hostapd via its AF_UNIX SOCK_DGRAM control
 * interface, return its reply text. */
static int hostapd_ctrl(const char *cmd, char *reply, size_t reply_cap)
{
    struct sockaddr_un local, remote;
    struct timeval tv;
    int s;
    ssize_t n;
    char local_path[64];

    s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    snprintf(local_path, sizeof(local_path),
             "/tmp/wolfip_supp_cli_%d", (int)getpid());
    unlink(local_path);
    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    strncpy(local.sun_path, local_path, sizeof(local.sun_path) - 1);
    if (bind(s, (struct sockaddr *)&local, sizeof(local)) < 0) {
        close(s); return -1;
    }
    memset(&remote, 0, sizeof(remote));
    remote.sun_family = AF_UNIX;
    snprintf(remote.sun_path, sizeof(remote.sun_path),
             "%s/%s", HOSTAPD_CTRL_DIR, HOSTAPD_CTRL_IF);
    if (sendto(s, cmd, strlen(cmd), 0,
               (struct sockaddr *)&remote, sizeof(remote)) < 0) {
        close(s); unlink(local_path); return -1;
    }
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    n = recv(s, reply, reply_cap - 1, 0);
    close(s); unlink(local_path);
    if (n < 0) return -1;
    reply[n] = '\0';
    return 0;
}

/* Hand-craft an EAPOL-Start frame so hostapd notices we're here even
 * if it doesn't poll. */
static int send_eapol_start(struct host_ctx *h)
{
    uint8_t pkt[4];
    pkt[0] = 0x02;                        /* version 2                */
    pkt[1] = 0x01;                        /* type = EAPOL-Start       */
    pkt[2] = 0x00; pkt[3] = 0x00;         /* body length = 0          */
    return psk_send_eapol(h, pkt, sizeof(pkt));
}

int main(int argc, char **argv)
{
    const char *ifname;
    const char *ssid;
    const char *psk;
    uint8_t ap_mac[6];
    struct wolfip_supplicant_cfg cfg;
    struct wolfip_supplicant *supp = NULL;
    uint8_t rsn[64]; size_t rsn_len;
    uint8_t rxbuf[1600];
    uint64_t deadline;
    int rc = 1;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 5) {
        fprintf(stderr,
            "Usage: %s <ifname> <ssid> <psk> <ap_mac>\n", argv[0]);
        return 2;
    }
    ifname = argv[1]; ssid = argv[2]; psk = argv[3];
    if (parse_mac(argv[4], ap_mac) != 0) {
        fprintf(stderr, "bad ap_mac: %s\n", argv[4]);
        return 2;
    }

    printf("wolfIP supplicant <-> hostapd WPA2-PSK 4-way on '%s'\n", ifname);
    printf("ssid='%s' ap_mac=%s\n", ssid, argv[4]);

    if (open_raw_socket(ifname, &HCTX) != 0) return 1;
    memcpy(HCTX.peer_mac, ap_mac, 6);
    printf("AF_PACKET bound (ifindex=%d, STA=%02x:%02x:%02x:%02x:%02x:%02x)\n",
           HCTX.ifindex,
           HCTX.local_mac[0], HCTX.local_mac[1], HCTX.local_mac[2],
           HCTX.local_mac[3], HCTX.local_mac[4], HCTX.local_mac[5]);

    if (rsn_ie_build_wpa2_psk(rsn, sizeof(rsn), &rsn_len) != 0) {
        fprintf(stderr, "rsn_ie_build\n"); close(HCTX.sock); return 1;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.auth_mode = WOLFIP_AUTH_PSK;
    cfg.ssid = ssid; cfg.ssid_len = strlen(ssid);
    cfg.passphrase = psk; cfg.passphrase_len = strlen(psk);
    memcpy(cfg.ap_mac,  HCTX.peer_mac,  6);
    memcpy(cfg.sta_mac, HCTX.local_mac, 6);
    cfg.ap_rsn_ie = rsn; cfg.ap_rsn_ie_len = rsn_len;
    cfg.ops.send_eapol  = psk_send_eapol;
    cfg.ops.install_key = psk_install_key;
    cfg.ops.ctx         = &HCTX;

    supp = wolfip_supplicant_new(&cfg);
    if (supp == NULL) {
        fprintf(stderr, "supplicant_new\n"); close(HCTX.sock); return 1;
    }
    if (wolfip_supplicant_kick(supp, now_ms()) != 0) {
        fprintf(stderr, "kick\n"); goto out;
    }

    /* Pre-install our PMK + PMKID into hostapd's PMKSA cache so the
     * new_sta event below skips EAP entirely and triggers the 4-way
     * straight away. Without this, hostapd's wired path forces every
     * station through EAP-Request/Identity even when wpa_key_mgmt is
     * WPA-PSK.
     *
     * On the mac80211_hwsim path (real wireless association), hostapd
     * already has a properly associated station and runs the 4-way on
     * its own; the in-binary trigger is unnecessary and can confuse
     * hostapd. Skip when WOLFIP_SUPP_SKIP_HOSTAPD_CLI=1. */
    if (getenv("WOLFIP_SUPP_SKIP_HOSTAPD_CLI") != NULL) {
        printf("WOLFIP_SUPP_SKIP_HOSTAPD_CLI set; awaiting M1 from kernel\n");
    } else {

        uint8_t pmk[WPA_PMK_LEN];
        uint8_t pmkid[16];
        char    pmk_hex[65], pmkid_hex[33], cmd[256], reply[128];
        int     r;

        if (wpa_pmk_from_passphrase(psk, strlen(psk),
                                    (const uint8_t *)ssid, strlen(ssid),
                                    pmk) != 0) {
            fprintf(stderr, "pmk derive\n"); goto out;
        }
        if (derive_pmkid(pmk, HCTX.peer_mac, HCTX.local_mac, pmkid) != 0) {
            fprintf(stderr, "pmkid derive\n"); goto out;
        }
        hex_print(pmk_hex,   pmk,   WPA_PMK_LEN);
        hex_print(pmkid_hex, pmkid, 16);

        snprintf(cmd, sizeof(cmd),
                 "PMKSA_ADD %02x:%02x:%02x:%02x:%02x:%02x %s %s 3600 0",
                 HCTX.local_mac[0], HCTX.local_mac[1], HCTX.local_mac[2],
                 HCTX.local_mac[3], HCTX.local_mac[4], HCTX.local_mac[5],
                 pmkid_hex, pmk_hex);
        r = hostapd_ctrl(cmd, reply, sizeof(reply));
        printf("PMKSA_ADD reply: %s (ret=%d)\n",
               r == 0 ? reply : "(no reply)", r);

        snprintf(cmd, sizeof(cmd),
                 "NEW_STA %02x:%02x:%02x:%02x:%02x:%02x",
                 HCTX.local_mac[0], HCTX.local_mac[1], HCTX.local_mac[2],
                 HCTX.local_mac[3], HCTX.local_mac[4], HCTX.local_mac[5]);
        r = hostapd_ctrl(cmd, reply, sizeof(reply));
        printf("NEW_STA reply:    %s (ret=%d)\n",
               r == 0 ? reply : "(no reply)", r);
    }
    /* Self-EAPOL-Start as a safety nudge on the wired path; harmless
     * on hwsim. */
    (void)send_eapol_start(&HCTX);
    printf("supplicant kicked; awaiting M1\n");

    deadline = now_ms() + 10000;
    while (now_ms() < deadline) {
        struct timeval tv = {0, 100000};
        fd_set rfds;
        int sel;
        FD_ZERO(&rfds);
        FD_SET(HCTX.sock, &rfds);
        sel = select(HCTX.sock + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) { if (errno == EINTR) continue; break; }
        if (sel > 0 && FD_ISSET(HCTX.sock, &rfds)) {
            ssize_t n = recv(HCTX.sock, rxbuf, sizeof(rxbuf), 0);
            if (n < 14) continue;
            if (memcmp(&rxbuf[6], HCTX.local_mac, 6) == 0) continue;
            (void)wolfip_supplicant_rx(supp, rxbuf + 14,
                                       (size_t)(n - 14), now_ms());
        }
        wolfip_supplicant_tick(supp, now_ms());

        if (wolfip_supplicant_state(supp) == SUPP_STATE_AUTHENTICATED) {
            printf("AUTHENTICATED against real hostapd "
                   "(pairwise=%d group=%d)\n",
                   installs.pairwise_set, installs.group_set);
            rc = (installs.pairwise_set && installs.group_set) ? 0 : 1;
            break;
        }
        if (wolfip_supplicant_state(supp) == SUPP_STATE_FAILED) {
            fprintf(stderr, "supplicant entered FAILED state\n");
            break;
        }
    }
    if (rc != 0
        && wolfip_supplicant_state(supp) != SUPP_STATE_AUTHENTICATED) {
        fprintf(stderr, "timeout: supp_state=%d\n",
                (int)wolfip_supplicant_state(supp));
    }
out:
    wolfip_supplicant_free(supp);
    close(HCTX.sock);
    return rc;
}

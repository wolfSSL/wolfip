/* test_supplicant_hostapd.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Real-authenticator interop test. Drives the wolfIP supplicant over a
 * Linux TAP device against a hostapd-in-wired-mode EAP server. Validates
 * EAP-TLS framing, identity exchange, TLS handshake, fragmentation, and
 * EAP-Success against a non-wolfSSL implementation of the authenticator.
 *
 * Usage:
 *   sudo ./test-supplicant-hostapd <ifname>
 *
 * The TAP is expected to be already created and brought up
 * (tools/hostapd/run_hostapd_test.sh does this). The hostapd EAP server
 * is also expected to be running and bound to the same TAP.
 *
 * Success criterion: the supplicant transitions to SUPP_STATE_4WAY_M1_WAIT
 * (i.e. EAP-Success was received and the MSK-derived PMK is installed).
 * Wired hostapd does NOT perform the 4-way handshake - that's already
 * validated against the in-process AP in test-supplicant-eap-tls.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include "supplicant.h"
#include "eapol.h"
#include "rsn_ie.h"
#include "test_eap_certs.h"

#define EAPOL_ETH_TYPE      0x888EU

/* PAE group address: where the supplicant addresses outgoing EAPOL
 * frames in wired/bridge environments per IEEE 802.1X-2010 7.8. */
static const uint8_t PAE_GROUP_MAC[6] = {0x01,0x80,0xC2,0x00,0x00,0x03};

struct host_ctx {
    int     sock;
    int     ifindex;
    uint8_t local_mac[6];
};

static struct host_ctx HCTX;

/* ---- transport callbacks bridging supplicant to the raw socket ---- */

static int hostapd_send_eapol(void *ctx, const uint8_t *frame, size_t len)
{
    struct host_ctx *h = (struct host_ctx *)ctx;
    uint8_t eth[1600];
    struct sockaddr_ll sll;
    ssize_t sent;

    if (len + 14 > sizeof(eth)) return -1;
    memcpy(&eth[0],  PAE_GROUP_MAC, 6);
    memcpy(&eth[6],  h->local_mac,  6);
    eth[12] = (uint8_t)(EAPOL_ETH_TYPE >> 8);
    eth[13] = (uint8_t)(EAPOL_ETH_TYPE & 0xFFU);
    memcpy(&eth[14], frame, len);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = h->ifindex;
    sll.sll_halen    = 6;
    memcpy(sll.sll_addr, PAE_GROUP_MAC, 6);

    sent = sendto(h->sock, eth, len + 14, 0,
                  (struct sockaddr *)&sll, sizeof(sll));
    if (sent < 0) {
        fprintf(stderr, "sendto: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int hostapd_install_key(void *ctx, wolfip_supplicant_keytype_t kt,
                               uint8_t idx, const uint8_t *k, size_t l)
{
    (void)ctx; (void)kt; (void)idx; (void)k; (void)l;
    /* No 4-way runs against wired hostapd, so install_key isn't expected
     * to fire here. Accept defensively. */
    return 0;
}

/* ---- raw socket open + interface lookup ---- */

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
        close(s);
        return -1;
    }
    h->ifindex = ifr.ifr_ifindex;

    /* Use a fixed locally-administered MAC for the supplicant. The
     * actual TAP MAC is irrelevant since we build the Ethernet header
     * ourselves with SOCK_RAW. */
    h->local_mac[0] = 0x02; h->local_mac[1] = 0x00; h->local_mac[2] = 0x00;
    h->local_mac[3] = 0x00; h->local_mac[4] = 0x00; h->local_mac[5] = 0x22;

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(EAPOL_ETH_TYPE);
    sll.sll_ifindex  = h->ifindex;
    if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        close(s);
        return -1;
    }
    h->sock = s;
    return 0;
}

/* ---- main test driver ---- */

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

int main(int argc, char **argv)
{
    const char *ifname = (argc > 1) ? argv[1] : "wolfip-eap0";
    struct eap_test_creds creds;
    struct wolfip_supplicant_cfg cfg;
    struct wolfip_supplicant *supp = NULL;
    uint8_t rsn[64]; size_t rsn_len;
    uint8_t rxbuf[1600];
    uint64_t deadline;
    int rc = 1;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wolfIP supplicant <-> hostapd interop on '%s'\n", ifname);

    if (eap_test_load_creds(&creds) != 0) {
        fprintf(stderr, "failed to load test certs\n");
        return 1;
    }
    if (rsn_ie_build_wpa2_psk(rsn, sizeof(rsn), &rsn_len) != 0) {
        fprintf(stderr, "rsn_ie_build\n");
        return 1;
    }

    if (open_raw_socket(ifname, &HCTX) != 0) {
        return 1;
    }
    printf("AF_PACKET bound to %s (ifindex=%d, SA=%02x:%02x:%02x:%02x:%02x:%02x)\n",
           ifname, HCTX.ifindex,
           HCTX.local_mac[0], HCTX.local_mac[1], HCTX.local_mac[2],
           HCTX.local_mac[3], HCTX.local_mac[4], HCTX.local_mac[5]);

    /* Configure supplicant for EAP-TLS, identity matching eap_users. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.ssid = "wolfIP-Interop"; cfg.ssid_len = strlen(cfg.ssid);
    cfg.auth_mode = WOLFIP_AUTH_EAP_TLS;
    cfg.identity = "alice@wolfip.local";
    cfg.identity_len = strlen(cfg.identity);
    /* AP MAC = PAE group; STA MAC = our raw-socket MAC. Used only in PTK
     * derivation; wired hostapd never runs the 4-way so values are
     * effectively unused, but the supplicant still requires them. */
    memcpy(cfg.ap_mac,  PAE_GROUP_MAC, 6);
    memcpy(cfg.sta_mac, HCTX.local_mac, 6);
    cfg.ap_rsn_ie = rsn; cfg.ap_rsn_ie_len = rsn_len;
    cfg.eap_tls.ca = creds.ca; cfg.eap_tls.ca_len = creds.ca_len;
    cfg.eap_tls.ca_format = WOLFIP_EAP_TLS_FMT_DER;
    cfg.eap_tls.client_cert = creds.cli_cert;
    cfg.eap_tls.client_cert_len = creds.cli_cert_len;
    cfg.eap_tls.client_cert_format = WOLFIP_EAP_TLS_FMT_DER;
    cfg.eap_tls.client_key = creds.cli_key;
    cfg.eap_tls.client_key_len = creds.cli_key_len;
    cfg.eap_tls.client_key_format = WOLFIP_EAP_TLS_FMT_DER;
    cfg.eap_tls.tls_version_pin = 1;   /* hostapd's default is TLS 1.2 */
    cfg.eap_tls.server_name_pin = NULL;/* hostapd cert CN = test issuer
                                        * dependent; skip pinning */
    cfg.ops.send_eapol  = hostapd_send_eapol;
    cfg.ops.install_key = hostapd_install_key;
    cfg.ops.ctx         = &HCTX;

    supp = wolfip_supplicant_new(&cfg);
    if (supp == NULL) {
        fprintf(stderr, "supplicant_new failed\n");
        close(HCTX.sock); return 1;
    }
    if (wolfip_supplicant_kick(supp, now_ms()) != 0) {
        fprintf(stderr, "kick failed\n");
        wolfip_supplicant_free(supp); close(HCTX.sock); return 1;
    }
    printf("supplicant kicked, awaiting hostapd EAP-Request/Identity\n");

    /* Drive for up to 10 seconds. */
    deadline = now_ms() + 10000;
    while (now_ms() < deadline) {
        struct timeval tv = {0, 100000};   /* 100 ms */
        fd_set rfds;
        int sel;
        FD_ZERO(&rfds);
        FD_SET(HCTX.sock, &rfds);
        sel = select(HCTX.sock + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "select: %s\n", strerror(errno));
            break;
        }
        if (sel > 0 && FD_ISSET(HCTX.sock, &rfds)) {
            ssize_t n = recv(HCTX.sock, rxbuf, sizeof(rxbuf), 0);
            if (n < 14) continue;
            /* Skip our own outbound echo (some kernels deliver). */
            if (memcmp(&rxbuf[6], HCTX.local_mac, 6) == 0) continue;
            /* Hand 802.1X body up to supplicant. */
            (void)wolfip_supplicant_rx(supp, rxbuf + 14, (size_t)(n - 14),
                                       now_ms());
        }
        wolfip_supplicant_tick(supp, now_ms());

        if (wolfip_supplicant_state(supp) == SUPP_STATE_4WAY_M1_WAIT) {
            printf("EAP-Success received from hostapd; supplicant has PMK\n");
            rc = 0;
            break;
        }
        if (wolfip_supplicant_state(supp) == SUPP_STATE_FAILED) {
            fprintf(stderr, "supplicant entered FAILED state\n");
            rc = 1;
            break;
        }
    }
    if (rc != 0
        && wolfip_supplicant_state(supp) != SUPP_STATE_4WAY_M1_WAIT) {
        fprintf(stderr, "timeout: state=%d after %lums (no EAP-Success)\n",
                (int)wolfip_supplicant_state(supp),
                (unsigned long)(now_ms() - (deadline - 10000)));
    }

    wolfip_supplicant_free(supp);
    close(HCTX.sock);
    return rc;
}

/* test_supplicant_hostapd_peap.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Real-authenticator interop test for PEAPv0/MSCHAPv2. Drives the
 * wolfIP supplicant over a Linux veth + AF_PACKET against a hostapd
 * EAP server configured for PEAP+MSCHAPv2. Validates the full inner
 * exchange (Identity, MSCHAPv2 Challenge/Response/Success) against a
 * non-wolfSSL implementation.
 *
 * Success: supplicant transitions to SUPP_STATE_4WAY_M1_WAIT (i.e.
 * outer EAP-Success received, MSK-derived PMK installed).
 *
 * Only built when WOLFIP_ENABLE_PEAP_MSCHAPV2=1.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(WOLFIP_ENABLE_PEAP_MSCHAPV2) && WOLFIP_ENABLE_PEAP_MSCHAPV2

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

#define EAPOL_ETH_TYPE 0x888EU
static const uint8_t PAE_GROUP_MAC[6] = {0x01,0x80,0xC2,0x00,0x00,0x03};

struct host_ctx {
    int     sock;
    int     ifindex;
    uint8_t local_mac[6];
};
static struct host_ctx HCTX;

static int peap_send_eapol(void *ctx, const uint8_t *frame, size_t len)
{
    struct host_ctx *h = (struct host_ctx *)ctx;
    uint8_t eth[1600];
    struct sockaddr_ll sll;
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
    if (sendto(h->sock, eth, len + 14, 0,
               (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "sendto: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int peap_install_key(void *ctx, wolfip_supplicant_keytype_t kt,
                            uint8_t idx, const uint8_t *k, size_t l)
{
    (void)ctx; (void)kt; (void)idx; (void)k; (void)l;
    return 0;
}

static int open_raw_socket(const char *ifname, struct host_ctx *h)
{
    struct ifreq ifr;
    struct sockaddr_ll sll;
    int s;
    s = socket(AF_PACKET, SOCK_RAW, htons(EAPOL_ETH_TYPE));
    if (s < 0) { fprintf(stderr,"socket: %s\n",strerror(errno)); return -1; }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) { close(s); return -1; }
    h->ifindex = ifr.ifr_ifindex;
    h->local_mac[0] = 0x02; h->local_mac[1] = 0x00; h->local_mac[2] = 0x00;
    h->local_mac[3] = 0x00; h->local_mac[4] = 0x00; h->local_mac[5] = 0x33;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(EAPOL_ETH_TYPE);
    sll.sll_ifindex  = h->ifindex;
    if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(s); return -1;
    }
    h->sock = s;
    return 0;
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

int main(int argc, char **argv)
{
    const char *ifname = (argc > 1) ? argv[1] : "wolfip-supp";
    struct eap_test_creds creds;
    struct wolfip_supplicant_cfg cfg;
    struct wolfip_supplicant *supp = NULL;
    uint8_t rsn[64]; size_t rsn_len;
    uint8_t rxbuf[1600];
    uint64_t deadline;
    int rc = 1;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wolfIP supplicant <-> hostapd PEAP/MSCHAPv2 on '%s'\n", ifname);

    if (eap_test_load_creds(&creds) != 0) {
        fprintf(stderr, "failed to load test certs\n");
        return 1;
    }
    if (rsn_ie_build_wpa2_psk(rsn, sizeof(rsn), &rsn_len) != 0) return 1;

    if (open_raw_socket(ifname, &HCTX) != 0) return 1;
    printf("AF_PACKET bound to %s (ifindex=%d, SA=%02x:%02x:%02x:%02x:%02x:%02x)\n",
           ifname, HCTX.ifindex,
           HCTX.local_mac[0], HCTX.local_mac[1], HCTX.local_mac[2],
           HCTX.local_mac[3], HCTX.local_mac[4], HCTX.local_mac[5]);

    memset(&cfg, 0, sizeof(cfg));
    cfg.ssid = "wolfIP-PEAPNet"; cfg.ssid_len = strlen(cfg.ssid);
    cfg.auth_mode = WOLFIP_AUTH_PEAP_MSCHAPV2;
    cfg.identity       = "anonymous@wolfip.local";
    cfg.identity_len   = strlen(cfg.identity);
    cfg.inner_identity = "alice@wolfip.local";
    cfg.inner_identity_len = strlen(cfg.inner_identity);
    cfg.password       = "clientPass";
    cfg.password_len   = strlen(cfg.password);
    memcpy(cfg.ap_mac,  PAE_GROUP_MAC, 6);
    memcpy(cfg.sta_mac, HCTX.local_mac, 6);
    cfg.ap_rsn_ie = rsn; cfg.ap_rsn_ie_len = rsn_len;
    cfg.eap_tls.ca = creds.ca; cfg.eap_tls.ca_len = creds.ca_len;
    cfg.eap_tls.ca_format = WOLFIP_EAP_TLS_FMT_DER;
    /* No client cert/key for PEAP. */
    cfg.eap_tls.tls_version_pin = 1;     /* hostapd default = TLS 1.2 */
    cfg.eap_tls.server_name_pin = NULL;  /* skip pinning */
    cfg.ops.send_eapol  = peap_send_eapol;
    cfg.ops.install_key = peap_install_key;
    cfg.ops.ctx         = &HCTX;

    supp = wolfip_supplicant_new(&cfg);
    if (supp == NULL) { fprintf(stderr,"supplicant_new\n"); return 1; }
    if (wolfip_supplicant_kick(supp, now_ms()) != 0) {
        fprintf(stderr,"kick\n"); wolfip_supplicant_free(supp); return 1;
    }
    printf("supplicant kicked; awaiting EAP-Request/Identity\n");

    deadline = now_ms() + 15000;
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

        if (wolfip_supplicant_state(supp) == SUPP_STATE_4WAY_M1_WAIT) {
            printf("PEAP+MSCHAPv2 complete; PMK installed; awaiting M1\n");
            rc = 0; break;
        }
        if (wolfip_supplicant_state(supp) == SUPP_STATE_FAILED) {
            fprintf(stderr,"supplicant entered FAILED\n");
            break;
        }
    }
    if (rc != 0) {
        fprintf(stderr,"timeout: state=%d\n",
                (int)wolfip_supplicant_state(supp));
    }
    wolfip_supplicant_free(supp);
    close(HCTX.sock);
    return rc;
}

#else  /* !WOLFIP_ENABLE_PEAP_MSCHAPV2 */

int main(void)
{
    printf("PEAP not built (WOLFIP_ENABLE_PEAP_MSCHAPV2=0)\n");
    return 0;
}

#endif

/* test_supplicant_hwsim_eap_softmac.c
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

/* WPA2-Enterprise (EAP-TLS) interop test over a mac80211_hwsim SoftMAC
 * radio. Unlike the wired veth test (test_supplicant_hostapd.c), which
 * stops at EAP-Success because hostapd's wired driver does no 4-way, this
 * drives the FULL enterprise join over a real 802.11 radio:
 *
 *   NL80211_CMD_CONNECT (AKM 802.1X) -> EAP-Request/Identity -> EAP-TLS
 *   handshake -> EAP-Success -> 4-way handshake (PMK from the EAP MSK) ->
 *   PTK/GTK install -> AUTHENTICATED.
 *
 * Transport is the shared SoftMAC glue (tools/hostapd/nl80211_sta.c); the
 * EAP-TLS credentials are the same throwaway PKI used by the other EAP
 * tests (test_eap_certs.h, /tmp/wolfip_eap_certs).
 *
 * Only built when WOLFIP_ENABLE_EAP_TLS=1.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(WOLFIP_ENABLE_EAP_TLS) && WOLFIP_ENABLE_EAP_TLS

#include <time.h>
#include <signal.h>
#include <sys/stat.h>

#include "supplicant.h"
#include "test_eap_certs.h"
#include "../../tools/hostapd/nl80211_sta.h"

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

static int parse_mac(const char *s, uint8_t out[6])
{
    unsigned int v[6];
    int i;
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return -1;
    for (i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname = (argc > 1) ? argv[1] : "wlan1";
    const char *ssid   = (argc > 2) ? argv[2] : "wolfIP-EAP";
    const char *ident  = (argc > 3) ? argv[3] : "alice@wolfip.local";
    const char *bssid  = (argc > 4) ? argv[4] : "02:00:00:00:00:00";
    uint32_t    freq   = (argc > 5) ? (uint32_t)atoi(argv[5]) : 2412;
    struct nl80211_sta            sta;
    struct wolfip_supplicant      supp;
    struct wolfip_supplicant_cfg  cfg;
    struct eap_test_creds        *creds;
    uint8_t  bssid_b[6];
    uint64_t deadline;
    int      state, done = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    if (parse_mac(bssid, bssid_b) != 0) {
        fprintf(stderr, "bad bssid: %s\n", bssid);
        return 2;
    }

    creds = (struct eap_test_creds *)calloc(1, sizeof(*creds));
    if (creds == NULL || eap_test_load_creds(creds) != 0) {
        fprintf(stderr, "failed to load test EAP certs\n");
        free(creds);
        return 1;
    }

    if (nl80211_sta_init(&sta, ifname) != 0) {
        fprintf(stderr, "nl80211_sta_init(%s) failed\n", ifname);
        free(creds);
        return 1;
    }
    sta.verbose = 1;
    /* WPA2-Enterprise: AKM 802.1X, MFP optional (off here to match the
     * default hostapd EAP config). */
    if (nl80211_sta_set_target(&sta, ssid, bssid_b, freq,
                               NL80211_STA_AKM_8021X,
                               NL80211_STA_MFP_NONE) != 0) {
        fprintf(stderr, "set_target failed\n");
        nl80211_sta_cleanup(&sta);
        free(creds);
        return 1;
    }
    printf("[init] iface=%s ifindex=%d sta_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           ifname, sta.ifindex,
           sta.sta_mac[0], sta.sta_mac[1], sta.sta_mac[2],
           sta.sta_mac[3], sta.sta_mac[4], sta.sta_mac[5]);

    memset(&supp, 0, sizeof(supp));  /* zero before first init (PMKSA snapshot) */
    memset(&cfg, 0, sizeof(cfg));
    cfg.ssid         = ssid;
    cfg.ssid_len     = strlen(ssid);
    cfg.auth_mode    = WOLFIP_AUTH_EAP_TLS;
    cfg.identity     = ident;
    cfg.identity_len = strlen(ident);
    cfg.eap_tls.ca                 = creds->ca;
    cfg.eap_tls.ca_len             = creds->ca_len;
    cfg.eap_tls.ca_format          = WOLFIP_EAP_TLS_FMT_DER;
    cfg.eap_tls.client_cert        = creds->cli_cert;
    cfg.eap_tls.client_cert_len    = creds->cli_cert_len;
    cfg.eap_tls.client_cert_format = WOLFIP_EAP_TLS_FMT_DER;
    cfg.eap_tls.client_key         = creds->cli_key;
    cfg.eap_tls.client_key_len     = creds->cli_key_len;
    cfg.eap_tls.client_key_format  = WOLFIP_EAP_TLS_FMT_DER;
    cfg.eap_tls.tls_version_pin    = 1;   /* hostapd default TLS 1.2 */
    memcpy(cfg.ap_mac,  bssid_b,     6);
    memcpy(cfg.sta_mac, sta.sta_mac, 6);
    nl80211_sta_supplicant_ops(&sta, &cfg.ops);

    if (wolfip_supplicant_init(&supp, &cfg) != 0) {
        fprintf(stderr, "supplicant_init failed\n");
        nl80211_sta_cleanup(&sta);
        free(creds);
        return 1;
    }
    nl80211_sta_attach(&sta, &supp);
    printf("[init] supplicant ready (EAP-TLS, identity=%s)\n", ident);

    if (nl80211_sta_start(&sta, now_ms()) != 0) {
        fprintf(stderr, "nl80211_sta_start failed\n");
        wolfip_supplicant_deinit(&supp);
        nl80211_sta_cleanup(&sta);
        free(creds);
        return 1;
    }
    printf("[init] CONNECT (802.1X) submitted ssid='%s' freq=%uMHz\n",
           ssid, freq);

    deadline = now_ms() + 25000;
    while (now_ms() < deadline && !g_stop) {
        state = nl80211_sta_poll(&sta, 200, now_ms());
        if (state < 0) break;
        if (state == (int)SUPP_STATE_AUTHENTICATED) { done = 1; break; }
    }

    printf("[final] supp_state=%d associated=%d failed=%d done=%d\n",
           (int)wolfip_supplicant_state(&supp), sta.associated,
           sta.failed, done);

    wolfip_supplicant_deinit(&supp);
    nl80211_sta_cleanup(&sta);
    free(creds);
    return done ? 0 : 1;
}

#else  /* !WOLFIP_ENABLE_EAP_TLS */

int main(void)
{
    printf("EAP-TLS not built (WOLFIP_ENABLE_EAP_TLS=0)\n");
    return 0;
}

#endif

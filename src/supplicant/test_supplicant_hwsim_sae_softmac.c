/* test_supplicant_hwsim_sae_softmac.c
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

/* WPA3-Personal (SAE) interop test over the SoftMAC nl80211 path.
 *
 * Unlike test_supplicant_hostapd_sae.c (which uses the FullMAC
 * CONNECT + EXTERNAL_AUTH_SUPPORT surface that mac80211_hwsim ignores),
 * this binary drives SAE through NL80211_CMD_AUTHENTICATE + SAE_DATA and
 * NL80211_CMD_ASSOCIATE via tools/hostapd/nl80211_sta.c - the SoftMAC SAE
 * path that mac80211_hwsim DOES support. It is therefore the variant that
 * goes green under hwsim with no hardware, and the same code drives a
 * real SoftMAC USB radio (e.g. TP-Link ath9k_htc / rtl8xxxu / mt76).
 *
 * Flow:
 *   1. scan so cfg80211 has the target BSS
 *   2. NL80211_CMD_AUTHENTICATE (SAE Commit, then Confirm) via SAE_DATA
 *   3. NL80211_CMD_ASSOCIATE once SAE completes (supplicant -> M1_WAIT)
 *   4. 4-way handshake over AF_PACKET; PTK/GTK installed via NEW_KEY
 *   5. supplicant reaches AUTHENTICATED -> exit 0
 *
 * Env: WOLFIP_SAE_H2E=1 selects RFC 9380 Hash-to-Element PWE (interop
 * against hostapd sae_pwe=2); default is hunt-and-peck.
 *
 * Only built when WOLFIP_ENABLE_SAE=1.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE

#include <time.h>
#include <signal.h>

#include "supplicant.h"
#include "sae_crypto.h"
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
    const char *ssid   = (argc > 2) ? argv[2] : "wolfIP-SAE";
    const char *pw     = (argc > 3) ? argv[3] : "ThisIsAPassword!";
    const char *bssid  = (argc > 4) ? argv[4] : "02:00:00:00:00:00";
    uint32_t    freq   = (argc > 5) ? (uint32_t)atoi(argv[5]) : 2412;
    struct nl80211_sta            sta;
    struct wolfip_supplicant      supp;
    struct wolfip_supplicant_cfg  cfg;
    uint8_t  bssid_b[6];
    uint64_t deadline;
    int      state;
    int      done = 0;
    int      h2e  = 0;
    int      group = SAE_GROUP_19;
    const char *env;

    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    if (parse_mac(bssid, bssid_b) != 0) {
        fprintf(stderr, "bad bssid: %s\n", bssid);
        return 2;
    }
#if defined(WOLFIP_ENABLE_SAE_H2E) && WOLFIP_ENABLE_SAE_H2E
    env = getenv("WOLFIP_SAE_H2E");
    h2e = (env != NULL && env[0] == '1') ? 1 : 0;
#endif
    env = getenv("WOLFIP_SAE_GROUP");
    if (env != NULL) {
        int gv = atoi(env);
        if (gv == 19 || gv == 20 || gv == 21) group = gv;
    }

    if (nl80211_sta_init(&sta, ifname) != 0) {
        fprintf(stderr, "nl80211_sta_init(%s) failed\n", ifname);
        return 1;
    }
    sta.verbose = 1;
    if (nl80211_sta_set_target(&sta, ssid, bssid_b, freq,
                               NL80211_STA_AKM_SAE,
                               NL80211_STA_MFP_REQUIRED) != 0) {
        fprintf(stderr, "set_target failed\n");
        nl80211_sta_cleanup(&sta);
        return 1;
    }
    printf("[init] iface=%s ifindex=%d sta_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           ifname, sta.ifindex,
           sta.sta_mac[0], sta.sta_mac[1], sta.sta_mac[2],
           sta.sta_mac[3], sta.sta_mac[4], sta.sta_mac[5]);

    memset(&supp, 0, sizeof(supp));  /* zero before first init (PMKSA snapshot) */
    memset(&cfg, 0, sizeof(cfg));
    cfg.ssid           = ssid;
    cfg.ssid_len       = strlen(ssid);
    cfg.auth_mode      = WOLFIP_AUTH_SAE;
    cfg.passphrase     = pw;
    cfg.passphrase_len = strlen(pw);
    cfg.sae_group      = group;
    cfg.sae_h2e        = h2e;
    cfg.mfp_capable    = 1;
    cfg.mfp_required   = 1;
    memcpy(cfg.ap_mac,  bssid_b,     6);
    memcpy(cfg.sta_mac, sta.sta_mac, 6);
    nl80211_sta_supplicant_ops(&sta, &cfg.ops);

    if (wolfip_supplicant_init(&supp, &cfg) != 0) {
        fprintf(stderr, "supplicant_init failed\n");
        nl80211_sta_cleanup(&sta);
        return 1;
    }
    nl80211_sta_attach(&sta, &supp);
    printf("[init] supplicant ready (SAE, group %d, %s)\n",
           group, h2e ? "H2E" : "H&P");

    if (nl80211_sta_start(&sta, now_ms()) != 0) {
        fprintf(stderr, "nl80211_sta_start failed\n");
        wolfip_supplicant_deinit(&supp);
        nl80211_sta_cleanup(&sta);
        return 1;
    }
    printf("[init] SAE commit submitted ssid='%s' freq=%uMHz\n", ssid, freq);

    deadline = now_ms() + 20000;
    while (now_ms() < deadline && !g_stop) {
        state = nl80211_sta_poll(&sta, 200, now_ms());
        if (state < 0) break;
        if (state == (int)SUPP_STATE_AUTHENTICATED) { done = 1; break; }
        if (state == (int)SUPP_STATE_FAILED) break; /* e.g. wrong password */
    }

    printf("[final] supp_state=%d associated=%d sae_auth=%d failed=%d done=%d\n",
           (int)wolfip_supplicant_state(&supp), sta.associated,
           sta.sae_authenticated, sta.failed, done);
    if (!done && !sta.started) {
        printf("[note] SAE never started - check the radio is in managed "
               "mode and the BSS scan found the AP.\n");
    }

    wolfip_supplicant_deinit(&supp);
    nl80211_sta_cleanup(&sta);
    return done ? 0 : 1;
}

#else  /* !WOLFIP_ENABLE_SAE */

int main(void)
{
    printf("SAE not built (WOLFIP_ENABLE_SAE=0)\n");
    return 0;
}

#endif

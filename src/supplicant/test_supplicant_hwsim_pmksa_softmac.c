/* test_supplicant_hwsim_pmksa_softmac.c
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

/* WPA3-SAE PMKSA fast-reconnect over a mac80211_hwsim radio.
 *
 *   Pass 1: full SAE (AUTHENTICATE/SAE_DATA + ASSOCIATE) -> 4-way ->
 *           AUTHENTICATED. The supplicant caches the PMK + PMKID.
 *   Pass 2: arm wolfip_supplicant_pmksa_reconnect() (reuse cached PMK,
 *           PMKID in the RSN IE, skip the dragonfly), then open-auth
 *           (NL80211_CMD_AUTHENTICATE, AUTH_TYPE=OPEN) + ASSOCIATE with the
 *           PMKID-bearing RSN IE. hostapd matches the PMKID, skips SAE, and
 *           runs the 4-way directly -> AUTHENTICATED with no SAE exchange.
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

/* Drive the supplicant to AUTHENTICATED (or FAILED/timeout). */
static int run_until_auth(struct nl80211_sta *sta, int timeout_ms)
{
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    while (now_ms() < deadline && !g_stop) {
        int state = nl80211_sta_poll(sta, 200, now_ms());
        if (state < 0) return -1;
        if (state == (int)SUPP_STATE_AUTHENTICATED) return 0;
        if (state == (int)SUPP_STATE_FAILED) return -1;
    }
    return -1;
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
    uint8_t  pmk[WPA_PMK_LEN];
    uint8_t  pmkid[16];

    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    if (parse_mac(bssid, bssid_b) != 0) {
        fprintf(stderr, "bad bssid: %s\n", bssid);
        return 2;
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

    memset(&supp, 0, sizeof(supp));  /* zero before first init (PMKSA snapshot) */
    memset(&cfg, 0, sizeof(cfg));
    cfg.ssid = ssid; cfg.ssid_len = strlen(ssid);
    cfg.auth_mode = WOLFIP_AUTH_SAE;
    cfg.passphrase = pw; cfg.passphrase_len = strlen(pw);
    cfg.sae_group = SAE_GROUP_19;
    cfg.mfp_capable = 1; cfg.mfp_required = 1;
    memcpy(cfg.ap_mac,  bssid_b,     6);
    memcpy(cfg.sta_mac, sta.sta_mac, 6);
    nl80211_sta_supplicant_ops(&sta, &cfg.ops);
    if (wolfip_supplicant_init(&supp, &cfg) != 0) {
        fprintf(stderr, "supplicant_init failed\n");
        nl80211_sta_cleanup(&sta);
        return 1;
    }
    nl80211_sta_attach(&sta, &supp);

    /* ---- Pass 1: full SAE ---- */
    printf("[pmksa] pass 1: full SAE join\n");
    if (nl80211_sta_start(&sta, now_ms()) != 0
        || run_until_auth(&sta, 20000) != 0) {
        fprintf(stderr, "[pmksa] FAIL: initial SAE join did not authenticate\n");
        wolfip_supplicant_deinit(&supp);
        nl80211_sta_cleanup(&sta);
        return 1;
    }
    printf("[pmksa] pass 1 AUTHENTICATED\n");

    if (wolfip_supplicant_get_pmk(&supp, pmk) != 0
        || wolfip_supplicant_get_pmkid(&supp, pmkid) != 0) {
        fprintf(stderr, "[pmksa] FAIL: no cached PMK/PMKID after SAE\n");
        wolfip_supplicant_deinit(&supp);
        nl80211_sta_cleanup(&sta);
        return 1;
    }

    /* ---- Pass 2: PMKSA fast reconnect (no SAE) ---- */
    printf("[pmksa] pass 2: PMKSA fast reconnect (no SAE)\n");
    if (wolfip_supplicant_pmksa_reconnect(&supp) != 0) {
        fprintf(stderr, "[pmksa] FAIL: pmksa_reconnect arm failed\n");
        wolfip_supplicant_deinit(&supp);
        nl80211_sta_cleanup(&sta);
        return 1;
    }
    nl80211_sta_reset(&sta);
    if (nl80211_sta_set_pmksa(&sta, pmkid, pmk, WPA_PMK_LEN,
                              supp.own_rsn_ie, supp.own_rsn_ie_len) != 0) {
        fprintf(stderr, "[pmksa] FAIL: set_pmksa failed\n");
        wolfip_supplicant_deinit(&supp);
        nl80211_sta_cleanup(&sta);
        return 1;
    }
    if (nl80211_sta_start(&sta, now_ms()) != 0
        || run_until_auth(&sta, 20000) != 0) {
        fprintf(stderr, "[pmksa] FAIL: PMKSA reconnect did not authenticate\n");
        wolfip_supplicant_deinit(&supp);
        nl80211_sta_cleanup(&sta);
        return 1;
    }
    printf("[pmksa] pass 2 AUTHENTICATED (PMKSA fast reconnect)\n");
    printf("[pmksa] PASS\n");

    wolfip_supplicant_deinit(&supp);
    nl80211_sta_cleanup(&sta);
    return 0;
}

#else  /* !WOLFIP_ENABLE_SAE */

int main(void)
{
    printf("SAE not built (WOLFIP_ENABLE_SAE=0)\n");
    return 0;
}

#endif

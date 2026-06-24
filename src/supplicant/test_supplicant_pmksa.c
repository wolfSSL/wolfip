/* test_supplicant_pmksa.c
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

/* Hermetic (no kernel / no hostapd) tests for the PMKSA logic in
 * src/supplicant/supplicant.c:
 *   A. get_pmkid / pmksa_clear lifecycle.
 *   B. wolfip_supplicant_pmksa_reconnect idempotency - a second call must
 *      NOT append a second PMKID block to own_rsn_ie (MEDIUM-2).
 *   C. PSK cached-PMK fast path is bound to the passphrase - a re-init with
 *      a changed passphrase for the same SSID must re-run PBKDF2 instead of
 *      reusing the stale cached PMK (LOW-11).
 *
 * These exercise the snapshot-before-memset / restore path in _init by
 * seeding the pmksa_* cache fields directly (the struct is public so a
 * caller can allocate it statically), simulating a prior session.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "supplicant.h"
#include "wpa_crypto.h"

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hash.h>     /* wc_Sha256Hash (absent from the SAE=0 include chain) */

static int dummy_send(void *c, const uint8_t *f, size_t n)
{ (void)c; (void)f; (void)n; return 0; }
static int dummy_key(void *c, wolfip_supplicant_keytype_t k, uint8_t i,
                     const uint8_t *key, size_t kl)
{ (void)c; (void)k; (void)i; (void)key; (void)kl; return 0; }

static void base_cfg(struct wolfip_supplicant_cfg *cfg, const char *ssid,
                     const char *pass)
{
    static const uint8_t ap[6]  = {0x02,0x00,0x00,0x00,0x11,0x00};
    static const uint8_t sta[6] = {0x02,0x00,0x00,0x00,0x22,0x00};
    memset(cfg, 0, sizeof(*cfg));
    cfg->ssid = ssid; cfg->ssid_len = strlen(ssid);
    cfg->auth_mode = WOLFIP_AUTH_PSK;
    cfg->passphrase = pass; cfg->passphrase_len = strlen(pass);
    memcpy(cfg->ap_mac,  ap,  6);
    memcpy(cfg->sta_mac, sta, 6);
    cfg->ops.send_eapol  = dummy_send;
    cfg->ops.install_key = dummy_key;
}

/* A. get_pmkid / pmksa_clear lifecycle. */
static int test_pmkid_lifecycle(void)
{
    struct wolfip_supplicant s;
    struct wolfip_supplicant_cfg cfg;
    uint8_t pmkid[16];
    int fails = 0;
    size_t i;

    printf("Test A: get_pmkid / pmksa_clear lifecycle\n");
    memset(&s, 0, sizeof(s));
    base_cfg(&cfg, "pmksanet", "ThisIsAPassword!");
    if (wolfip_supplicant_init(&s, &cfg) != 0) {
        printf("  [FAIL] init\n"); return 1;
    }
    if (wolfip_supplicant_get_pmkid(&s, pmkid) == 0) {
        printf("  [FAIL] get_pmkid succeeded with no cached PMKID\n"); fails++;
    }
    else { printf("  [OK]   get_pmkid fails before any PMKID is cached\n"); }

    /* Simulate a cached PMKID (as AUTHENTICATED would set for SAE). */
    s.pmksa_magic = WOLFIP_PMKSA_MAGIC;
    for (i = 0; i < 16; i++) s.pmksa_pmkid[i] = (uint8_t)(0xA0 + i);
    s.pmksa_have_pmkid = 1;
    if (wolfip_supplicant_get_pmkid(&s, pmkid) != 0
        || memcmp(pmkid, s.pmksa_pmkid, 16) != 0) {
        printf("  [FAIL] get_pmkid did not return the cached PMKID\n"); fails++;
    }
    else { printf("  [OK]   get_pmkid returns the cached PMKID\n"); }

    wolfip_supplicant_pmksa_clear(&s);
    if (wolfip_supplicant_get_pmkid(&s, pmkid) == 0) {
        printf("  [FAIL] get_pmkid succeeded after pmksa_clear\n"); fails++;
    }
    else { printf("  [OK]   get_pmkid fails after pmksa_clear\n"); }

    wolfip_supplicant_deinit(&s);
    return fails;
}

/* B. pmksa_reconnect idempotency: a second arm must not grow own_rsn_ie. */
static int test_pmksa_reconnect_idempotent(void)
{
    struct wolfip_supplicant s;
    struct wolfip_supplicant_cfg cfg;
    size_t len_after_first;
    uint8_t saved_ie[64];
    int fails = 0;

    printf("Test B: pmksa_reconnect idempotency (MEDIUM-2)\n");
    memset(&s, 0, sizeof(s));
    base_cfg(&cfg, "pmksanet", "ThisIsAPassword!");
    if (wolfip_supplicant_init(&s, &cfg) != 0) {
        printf("  [FAIL] init\n"); return 1;
    }
    /* Seed a cached PMKSA matching this SSID + BSSID with a PMKID. */
    s.pmksa_magic = WOLFIP_PMKSA_MAGIC;
    s.pmksa_have_pmkid = 1;
    memset(s.pmksa_pmkid, 0x5A, 16);
    memcpy(s.pmksa_ssid, s.ssid, s.ssid_len);
    s.pmksa_ssid_len = (uint8_t)s.ssid_len;
    memcpy(s.pmksa_bssid, s.ap_mac, WPA_MAC_LEN);
    memset(s.pmksa_pmk, 0x33, WPA_PMK_LEN);

    if (wolfip_supplicant_pmksa_reconnect(&s) != 0) {
        printf("  [FAIL] first pmksa_reconnect\n");
        wolfip_supplicant_deinit(&s); return 1;
    }
    len_after_first = s.own_rsn_ie_len;
    memcpy(saved_ie, s.own_rsn_ie, len_after_first);
    /* IE length byte must equal (total - 2). */
    if (s.own_rsn_ie[1] != (uint8_t)(len_after_first - 2U)) {
        printf("  [FAIL] IE length byte inconsistent after first arm\n");
        fails++;
    }

    /* Second arm: must be a no-op for the IE (no second PMKID appended). */
    if (wolfip_supplicant_pmksa_reconnect(&s) != 0) {
        printf("  [FAIL] second pmksa_reconnect\n");
        wolfip_supplicant_deinit(&s); return 1;
    }
    if (s.own_rsn_ie_len != len_after_first
        || memcmp(s.own_rsn_ie, saved_ie, len_after_first) != 0) {
        printf("  [FAIL] second arm mutated own_rsn_ie (double PMKID)\n");
        fails++;
    }
    else {
        printf("  [OK]   second pmksa_reconnect left the RSN IE unchanged\n");
    }
    if (fails == 0) {
        printf("  [OK]   RSN IE length byte consistent (single PMKID block)\n");
    }
    wolfip_supplicant_deinit(&s);
    return fails;
}

/* C. PSK cached PMK is bound to the passphrase. */
static int test_psk_pmk_passphrase_bound(void)
{
    struct wolfip_supplicant s;
    struct wolfip_supplicant_cfg cfg;
    uint8_t known_pmk[WPA_PMK_LEN];
    uint8_t got[WPA_PMK_LEN];
    uint8_t pbkdf2_two[WPA_PMK_LEN];
    int fails = 0;

    printf("Test C: PSK cached-PMK fast path is passphrase-bound (LOW-11)\n");

    /* A distinctive cached PMK that no PBKDF2 would produce. */
    memset(known_pmk, 0xC7, sizeof(known_pmk));
    /* Reference PMK for the *changed* passphrase. */
    if (wpa_pmk_from_passphrase("passTwo!!", 9,
                                (const uint8_t *)"pmksanet", 8,
                                pbkdf2_two) != 0) {
        printf("  [FAIL] reference PBKDF2\n"); return 1;
    }

    /* Seed the cache as if a prior session authenticated with "passOne!!". */
    memset(&s, 0, sizeof(s));
    s.pmksa_magic = WOLFIP_PMKSA_MAGIC;
    memcpy(s.pmksa_ssid, "pmksanet", 8);
    s.pmksa_ssid_len = 8;
    memcpy(s.pmksa_pmk, known_pmk, WPA_PMK_LEN);
    if (wc_Sha256Hash((const byte *)"passOne!!", 9, s.pmksa_pp_hash) != 0) {
        printf("  [FAIL] seed pp hash\n"); return 1;
    }
    s.pmksa_have_pp = 1;

    /* Re-init with the SAME passphrase -> fast path, PMK == cached. */
    base_cfg(&cfg, "pmksanet", "passOne!!");
    if (wolfip_supplicant_init(&s, &cfg) != 0) {
        printf("  [FAIL] init (same pass)\n"); return 1;
    }
    if (wolfip_supplicant_get_pmk(&s, got) != 0
        || memcmp(got, known_pmk, WPA_PMK_LEN) != 0) {
        printf("  [FAIL] same passphrase did not reuse the cached PMK\n");
        fails++;
    }
    else {
        printf("  [OK]   same passphrase reuses the cached PMK (fast path)\n");
    }

    /* Re-init the SAME context with a DIFFERENT passphrase, same SSID ->
     * the stale cached PMK must be rejected and PBKDF2 re-run. */
    base_cfg(&cfg, "pmksanet", "passTwo!!");
    if (wolfip_supplicant_init(&s, &cfg) != 0) {
        printf("  [FAIL] init (changed pass)\n"); return 1;
    }
    if (wolfip_supplicant_get_pmk(&s, got) != 0) {
        printf("  [FAIL] get_pmk after changed pass\n"); fails++;
    }
    else if (memcmp(got, known_pmk, WPA_PMK_LEN) == 0) {
        printf("  [FAIL] changed passphrase still reused the stale PMK\n");
        fails++;
    }
    else if (memcmp(got, pbkdf2_two, WPA_PMK_LEN) != 0) {
        printf("  [FAIL] changed passphrase PMK != PBKDF2(new passphrase)\n");
        fails++;
    }
    else {
        printf("  [OK]   changed passphrase re-runs PBKDF2 (no stale reuse)\n");
    }

    wolfip_supplicant_deinit(&s);
    return fails;
}

int main(void)
{
    int fails = 0;
    fails += test_pmkid_lifecycle();
    fails += test_pmksa_reconnect_idempotent();
    fails += test_psk_pmk_passphrase_bound();

    if (fails == 0) {
        printf("\nAll PMKSA tests passed.\n");
        return 0;
    }
    printf("\n%d PMKSA test failure(s).\n", fails);
    return 1;
}

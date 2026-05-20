/* test_supplicant_4way.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * In-process Phase B integration test:
 *   - Instantiates a wolfIP supplicant.
 *   - Instantiates a tiny "fake AP" peer that drives M1 then M3 of a
 *     WPA2-Personal 4-way handshake.
 *   - Cross-checks PTK derivation, MIC verification on M2/M4, and GTK
 *     install via the install_key() callback.
 *
 * No sockets, no kernel TAP; the two peers talk through in-memory
 * function-pointer transports so the test is hermetic.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "wpa_crypto.h"
#include "eapol.h"
#include "rsn_ie.h"
#include "supplicant.h"

/* ---- Test bus: a single-slot mailbox per direction ---- */

struct mailbox {
    uint8_t buf[1024];
    size_t  len;
    int     has;
};

static struct mailbox supp_inbox;   /* AP -> supplicant */
static struct mailbox ap_inbox;     /* supplicant -> AP */
static int            drop_next_to_supp; /* one-shot drop injector */

/* ---- Fake AP context ---- */

struct fake_ap {
    uint8_t pmk[WPA_PMK_LEN];
    uint8_t aa[WPA_MAC_LEN];
    uint8_t sa[WPA_MAC_LEN];
    uint8_t anonce[WPA_NONCE_LEN];
    uint8_t snonce[WPA_NONCE_LEN];        /* learned from M2 */
    uint8_t replay[WPA_REPLAY_CTR_LEN];
    uint8_t gtk[16];
    uint8_t rsn_ie[64];
    size_t  rsn_ie_len;
    int     m2_rsn_ok;                    /* set when M2 echoed our RSN IE */
    struct wpa_ptk ptk;
    int     have_ptk;
};

static int ap_send(struct fake_ap *ap,
                   const uint8_t *frame, size_t len, int compute_mic)
{
    uint8_t mic[WPA_MIC_LEN];
    uint8_t local[1024];
    int     ret;

    if (len > sizeof(local)) {
        return -1;
    }
    memcpy(local, frame, len);
    if (compute_mic) {
        ret = wpa_eapol_mic(ap->ptk.kck, local, len, mic);
        if (ret != 0) {
            return ret;
        }
        memcpy(local + EAPOL_HEADER_LEN + KEYBODY_OFF_MIC, mic, WPA_MIC_LEN);
    }
    if (drop_next_to_supp) {
        drop_next_to_supp = 0;
        printf("    [test] simulated drop of one AP->supp frame\n");
        return 0;
    }
    if (supp_inbox.has) {
        return -1; /* mailbox busy */
    }
    memcpy(supp_inbox.buf, local, len);
    supp_inbox.len = len;
    supp_inbox.has = 1;
    return 0;
}

static int ap_send_m1(struct fake_ap *ap)
{
    uint8_t frame[EAPOL_KEY_FIXED_LEN];
    size_t  total;
    int     ret;
    uint16_t ki;

    /* Generate ANonce - deterministic for test reproducibility. */
    memset(ap->anonce, 0xA1, sizeof(ap->anonce));
    /* Replay counter increments per pairwise message. */
    memset(ap->replay, 0, WPA_REPLAY_CTR_LEN);
    ap->replay[WPA_REPLAY_CTR_LEN - 1] = 1;

    ki = (uint16_t)(KEY_INFO_VER_AES_HMAC | KEY_INFO_KEY_TYPE
                    | KEY_INFO_KEY_ACK);
    ret = eapol_key_build(frame, sizeof(frame), ki,
                          16, ap->replay, ap->anonce, NULL, 0, &total);
    if (ret != 0) return ret;
    return ap_send(ap, frame, total, 0);
}

/* Build a Group-Key M1 carrying a fresh GTK. Like M3 but with Key Type
 * = 0 (Group) and no RSN IE. */
static int ap_send_group_m1(struct fake_ap *ap, const uint8_t *new_gtk)
{
    uint8_t  frame[EAPOL_KEY_FIXED_LEN + 64];
    uint8_t  kde_plain[40];
    uint8_t  kde_wrapped[48];
    size_t   plain_len;
    size_t   total;
    int      ret;
    uint16_t ki;
    uint8_t  zero_nonce[WPA_NONCE_LEN];

    memset(kde_plain, 0, sizeof(kde_plain));
    /* GTK KDE: type=0xDD len=22 OUI=00:0F:AC dt=01 keyid=02 res=00 + GTK[16]. */
    kde_plain[0] = KDE_TYPE;
    kde_plain[1] = 22;
    kde_plain[2] = KDE_OUI_0;
    kde_plain[3] = KDE_OUI_1;
    kde_plain[4] = KDE_OUI_2;
    kde_plain[5] = KDE_DATATYPE_GTK;
    kde_plain[6] = 0x02;
    kde_plain[7] = 0x00;
    memcpy(&kde_plain[8], new_gtk, 16);
    plain_len = 24U;

    ret = wpa_aes_keywrap(ap->ptk.kek, WPA_KEK_LEN,
                          kde_plain, plain_len, kde_wrapped);
    if (ret != 0) return ret;

    ap->replay[WPA_REPLAY_CTR_LEN - 1]++;
    memset(zero_nonce, 0, sizeof(zero_nonce));

    ki = (uint16_t)(KEY_INFO_VER_AES_HMAC
                    | KEY_INFO_KEY_MIC | KEY_INFO_KEY_ACK
                    | KEY_INFO_SECURE  | KEY_INFO_ENCR_KEY_DATA);
    ret = eapol_key_build(frame, sizeof(frame), ki,
                          16, ap->replay, zero_nonce,
                          kde_wrapped, (uint16_t)(plain_len + 8U), &total);
    if (ret != 0) return ret;
    return ap_send(ap, frame, total, 1);
}

static int ap_send_m3(struct fake_ap *ap)
{
    uint8_t  frame[EAPOL_KEY_FIXED_LEN + 128];
    uint8_t  kde_plain[96];
    uint8_t  kde_wrapped[104];
    size_t   plain_len;
    size_t   total;
    size_t   wrap_in;
    int      ret;
    uint16_t ki;

    /* Real M3 Key Data carries the AP's RSN IE (raw, type 0x30) AND a
     * GTK KDE (type 0xDD, OUI 00:0F:AC, datatype 0x01). The whole
     * thing is then AES-Key-Wrapped with KEK. */
    plain_len = 0;
    memset(kde_plain, 0, sizeof(kde_plain));
    /* RSN IE first. */
    if (plain_len + ap->rsn_ie_len > sizeof(kde_plain)) return -1;
    memcpy(&kde_plain[plain_len], ap->rsn_ie, ap->rsn_ie_len);
    plain_len += ap->rsn_ie_len;
    /* GTK KDE. */
    if (plain_len + 24U > sizeof(kde_plain)) return -1;
    kde_plain[plain_len + 0] = KDE_TYPE;
    kde_plain[plain_len + 1] = 22;
    kde_plain[plain_len + 2] = KDE_OUI_0;
    kde_plain[plain_len + 3] = KDE_OUI_1;
    kde_plain[plain_len + 4] = KDE_OUI_2;
    kde_plain[plain_len + 5] = KDE_DATATYPE_GTK;
    kde_plain[plain_len + 6] = 0x01;
    kde_plain[plain_len + 7] = 0x00;
    memset(ap->gtk, 0xC1, sizeof(ap->gtk));
    memcpy(&kde_plain[plain_len + 8], ap->gtk, sizeof(ap->gtk));
    plain_len += 24U;
    /* AES Key Wrap requires multiple-of-8 input. IEEE pad rule
     * (12.7.2): if padding is needed, the first pad byte is 0xDD and
     * remaining pad bytes are 0x00. */
    if ((plain_len % 8U) != 0U) {
        kde_plain[plain_len++] = 0xDDU;
        while ((plain_len % 8U) != 0U) {
            kde_plain[plain_len++] = 0x00U;
        }
    }
    wrap_in = plain_len;
    if (wrap_in + 8U > sizeof(kde_wrapped)) return -1;

    ret = wpa_aes_keywrap(ap->ptk.kek, WPA_KEK_LEN,
                          kde_plain, wrap_in, kde_wrapped);
    if (ret != 0) return ret;

    /* Advance replay counter. */
    ap->replay[WPA_REPLAY_CTR_LEN - 1]++;

    ki = (uint16_t)(KEY_INFO_VER_AES_HMAC | KEY_INFO_KEY_TYPE
                    | KEY_INFO_KEY_MIC   | KEY_INFO_KEY_ACK
                    | KEY_INFO_INSTALL   | KEY_INFO_SECURE
                    | KEY_INFO_ENCR_KEY_DATA);
    ret = eapol_key_build(frame, sizeof(frame), ki,
                          16, ap->replay, ap->anonce,
                          kde_wrapped, (uint16_t)(wrap_in + 8U), &total);
    if (ret != 0) return ret;
    return ap_send(ap, frame, total, 1);
}

static int ap_handle_m2_m4(struct fake_ap *ap,
                           const uint8_t *frame, size_t len,
                           int *out_was_m2)
{
    struct eapol_key_view kv;
    uint8_t local[1024];
    int     ret;

    if (eapol_key_parse(frame, len, &kv) != 0) return -1;

    /* M2 is the first MIC-bearing pairwise frame from the supplicant.
     * If we don't have PTK yet, derive it from this frame's SNonce. */
    if (!ap->have_ptk) {
        memcpy(ap->snonce, kv.nonce, WPA_NONCE_LEN);
        ret = wpa_ptk_derive(ap->pmk, ap->aa, ap->sa,
                             ap->anonce, ap->snonce, &ap->ptk);
        if (ret != 0) return ret;
        ap->have_ptk = 1;
        *out_was_m2 = 1;

        /* M2 must carry the supplicant's RSN IE in Key Data. Compare to
         * what we'd have seen in (Re)Assoc Request - in this test the
         * AP and supplicant negotiate the same default WPA2-PSK IE. */
        if (kv.key_data_len < 2U || kv.key_data[0] != RSN_IE_ELEMENT_ID) {
            printf("    [ap] M2 Key Data missing RSN IE\n");
            return -1;
        }
        if (rsn_ie_equal(kv.key_data, kv.key_data_len,
                         ap->rsn_ie, ap->rsn_ie_len) == 0) {
            ap->m2_rsn_ok = 1;
        }
        else {
            printf("    [ap] M2 RSN IE does not match advertised IE\n");
        }
    }
    else {
        *out_was_m2 = 0;
    }
    /* Verify MIC over copy with MIC zeroed. */
    if (len > sizeof(local)) return -1;
    memcpy(local, frame, len);
    memset(local + EAPOL_HEADER_LEN + KEYBODY_OFF_MIC, 0, WPA_MIC_LEN);
    ret = wpa_eapol_mic_verify(ap->ptk.kck, local, len, kv.mic);
    if (ret != 0) {
        printf("    [ap] MIC verify FAILED on inbound frame\n");
        return -1;
    }
    return 0;
}

/* ---- Supplicant transport hooks ---- */

static int supp_send_cb(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    if (ap_inbox.has) {
        return -1;
    }
    if (len > sizeof(ap_inbox.buf)) {
        return -1;
    }
    memcpy(ap_inbox.buf, frame, len);
    ap_inbox.len = len;
    ap_inbox.has = 1;
    return 0;
}

struct install_record {
    int      pairwise_set;
    int      group_set;
    uint8_t  tk[WPA_TK_LEN];
    uint8_t  gtk[WPA_GTK_MAX_LEN];
    size_t   gtk_len;
    uint8_t  gtk_idx;
};
static struct install_record installs;

static int supp_install_cb(void *ctx,
                           wolfip_supplicant_keytype_t kt,
                           uint8_t key_idx,
                           const uint8_t *key, size_t key_len)
{
    (void)ctx;
    if (kt == SUPP_KEY_PAIRWISE) {
        if (key_len != WPA_TK_LEN) return -1;
        memcpy(installs.tk, key, key_len);
        installs.pairwise_set = 1;
    }
    else if (kt == SUPP_KEY_GROUP) {
        if (key_len == 0 || key_len > WPA_GTK_MAX_LEN) return -1;
        memcpy(installs.gtk, key, key_len);
        installs.gtk_len = key_len;
        installs.gtk_idx = key_idx;
        installs.group_set = 1;
    }
    return 0;
}

/* ---- Test driver ---- */

static int run_handshake(int with_drop)
{
    struct fake_ap ap;
    struct wolfip_supplicant_cfg cfg;
    struct wolfip_supplicant *supp;
    int    pass = 0;
    int    fails = 0;
    int    iter;

    static const char ssid[] = "wolfIP-TestNet";
    static const char pass_text[] = "ThisIsAPassword!";

    memset(&supp_inbox, 0, sizeof(supp_inbox));
    memset(&ap_inbox,   0, sizeof(ap_inbox));
    memset(&installs,   0, sizeof(installs));
    drop_next_to_supp = with_drop;

    memset(&ap, 0, sizeof(ap));
    ap.aa[5] = 0x11; ap.sa[5] = 0x22;
    if (wpa_pmk_from_passphrase(pass_text, strlen(pass_text),
                                (const uint8_t *)ssid, strlen(ssid),
                                ap.pmk) != 0) {
        printf("  [FAIL] AP PMK derive\n");
        return 1;
    }
    if (rsn_ie_build_wpa2_psk(ap.rsn_ie, sizeof(ap.rsn_ie),
                              &ap.rsn_ie_len) != 0) {
        printf("  [FAIL] AP rsn_ie_build\n");
        return 1;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.ssid = ssid; cfg.ssid_len = strlen(ssid);
    cfg.passphrase = pass_text; cfg.passphrase_len = strlen(pass_text);
    memcpy(cfg.ap_mac,  ap.aa, WPA_MAC_LEN);
    memcpy(cfg.sta_mac, ap.sa, WPA_MAC_LEN);
    cfg.ap_rsn_ie     = ap.rsn_ie;
    cfg.ap_rsn_ie_len = ap.rsn_ie_len;
    cfg.ops.send_eapol  = supp_send_cb;
    cfg.ops.install_key = supp_install_cb;

    supp = wolfip_supplicant_new(&cfg);
    if (supp == NULL) {
        printf("  [FAIL] wolfip_supplicant_new\n");
        return 1;
    }
    if (wolfip_supplicant_kick(supp, 0) != 0) {
        printf("  [FAIL] kick\n");
        wolfip_supplicant_free(supp);
        return 1;
    }

    /* AP transmits M1. */
    if (ap_send_m1(&ap) != 0) {
        printf("  [FAIL] AP send M1\n");
        wolfip_supplicant_free(supp);
        return 1;
    }
    /* If dropping was requested, resend M1 now (mimics AP retransmit). */
    if (with_drop) {
        if (ap_send_m1(&ap) != 0) {
            printf("  [FAIL] AP resend M1\n");
            wolfip_supplicant_free(supp);
            return 1;
        }
    }

    /* Drive the loop until we reach AUTHENTICATED or stall. */
    for (iter = 0; iter < 8; iter++) {
        if (supp_inbox.has) {
            int ret = wolfip_supplicant_rx(supp,
                                           supp_inbox.buf, supp_inbox.len, 0);
            supp_inbox.has = 0;
            if (ret != 0
                && wolfip_supplicant_state(supp) != SUPP_STATE_FAILED) {
                /* benign error (e.g. duplicate after drop) */
            }
            if (wolfip_supplicant_state(supp) == SUPP_STATE_FAILED) {
                printf("  [FAIL] supplicant entered FAILED state\n");
                wolfip_supplicant_free(supp);
                return 1;
            }
        }
        if (ap_inbox.has) {
            int was_m2 = 0;
            int ret = ap_handle_m2_m4(&ap,
                                      ap_inbox.buf, ap_inbox.len, &was_m2);
            ap_inbox.has = 0;
            if (ret != 0) {
                printf("  [FAIL] AP rejected supplicant frame\n");
                wolfip_supplicant_free(supp);
                return 1;
            }
            if (was_m2) {
                if (ap_send_m3(&ap) != 0) {
                    printf("  [FAIL] AP send M3\n");
                    wolfip_supplicant_free(supp);
                    return 1;
                }
            }
            else {
                /* This was M4 - handshake done from AP side. */
            }
        }
        if (wolfip_supplicant_state(supp) == SUPP_STATE_AUTHENTICATED
            && !supp_inbox.has && !ap_inbox.has) {
            pass = 1;
            break;
        }
    }
    if (!pass) {
        printf("  [FAIL] handshake stalled, supp state=%d\n",
               (int)wolfip_supplicant_state(supp));
        wolfip_supplicant_free(supp);
        return 1;
    }

    /* Cross-check the keys both sides derived. */
    if (memcmp(wolfip_supplicant_tk(supp), ap.ptk.tk, WPA_TK_LEN) != 0) {
        printf("  [FAIL] TK mismatch between supplicant and AP\n");
        fails++;
    }
    else {
        printf("  [OK]   TK matches between supplicant and AP\n");
    }
    if (memcmp(wolfip_supplicant_kck(supp), ap.ptk.kck, WPA_KCK_LEN) != 0) {
        printf("  [FAIL] KCK mismatch\n");
        fails++;
    }
    else {
        printf("  [OK]   KCK matches\n");
    }
    if (!installs.pairwise_set || !installs.group_set) {
        printf("  [FAIL] install_key not called for both PTK and GTK\n");
        fails++;
    }
    else {
        printf("  [OK]   install_key invoked for PTK and GTK (idx=%u)\n",
               installs.gtk_idx);
    }
    if (installs.gtk_len != sizeof(ap.gtk)
        || memcmp(installs.gtk, ap.gtk, sizeof(ap.gtk)) != 0) {
        printf("  [FAIL] GTK delivered to driver does not match AP-side GTK\n");
        fails++;
    }
    else {
        printf("  [OK]   GTK delivered intact through M3 AES-Key-Wrap\n");
    }
    if (!ap.m2_rsn_ok) {
        printf("  [FAIL] AP did not see RSN IE in M2 Key Data\n");
        fails++;
    }
    else {
        printf("  [OK]   M2 Key Data carried matching RSN IE\n");
    }
    wolfip_supplicant_free(supp);
    return fails;
}

/* Test C: after 4-way completes, drive a Group Key rekey. Verify that
 * a fresh GTK with a new index reaches the driver via install_key, and
 * that the supplicant emits Group-M2 back. */
static int run_group_rekey(void)
{
    struct fake_ap ap;
    struct wolfip_supplicant_cfg cfg;
    struct wolfip_supplicant *supp;
    int    iter;
    int    fails = 0;
    int    pass = 0;

    static const char ssid[] = "wolfIP-TestNet";
    static const char pass_text[] = "ThisIsAPassword!";

    memset(&supp_inbox, 0, sizeof(supp_inbox));
    memset(&ap_inbox,   0, sizeof(ap_inbox));
    memset(&installs,   0, sizeof(installs));
    drop_next_to_supp = 0;

    memset(&ap, 0, sizeof(ap));
    ap.aa[5] = 0x11; ap.sa[5] = 0x22;
    if (wpa_pmk_from_passphrase(pass_text, strlen(pass_text),
                                (const uint8_t *)ssid, strlen(ssid),
                                ap.pmk) != 0) return 1;
    if (rsn_ie_build_wpa2_psk(ap.rsn_ie, sizeof(ap.rsn_ie),
                              &ap.rsn_ie_len) != 0) return 1;

    memset(&cfg, 0, sizeof(cfg));
    cfg.ssid = ssid; cfg.ssid_len = strlen(ssid);
    cfg.passphrase = pass_text; cfg.passphrase_len = strlen(pass_text);
    memcpy(cfg.ap_mac,  ap.aa, WPA_MAC_LEN);
    memcpy(cfg.sta_mac, ap.sa, WPA_MAC_LEN);
    cfg.ap_rsn_ie     = ap.rsn_ie;
    cfg.ap_rsn_ie_len = ap.rsn_ie_len;
    cfg.ops.send_eapol  = supp_send_cb;
    cfg.ops.install_key = supp_install_cb;

    supp = wolfip_supplicant_new(&cfg);
    if (supp == NULL || wolfip_supplicant_kick(supp, 0) != 0) {
        printf("  [FAIL] init/kick\n");
        if (supp) wolfip_supplicant_free(supp);
        return 1;
    }
    if (ap_send_m1(&ap) != 0) { printf("  [FAIL] m1\n"); return 1; }

    /* Run 4-way to AUTHENTICATED. */
    for (iter = 0; iter < 8; iter++) {
        if (supp_inbox.has) {
            (void)wolfip_supplicant_rx(supp, supp_inbox.buf, supp_inbox.len, 0);
            supp_inbox.has = 0;
        }
        if (ap_inbox.has) {
            int was_m2 = 0;
            if (ap_handle_m2_m4(&ap, ap_inbox.buf, ap_inbox.len,
                                &was_m2) != 0) {
                printf("  [FAIL] AP reject\n");
                wolfip_supplicant_free(supp);
                return 1;
            }
            ap_inbox.has = 0;
            if (was_m2) {
                if (ap_send_m3(&ap) != 0) {
                    printf("  [FAIL] m3\n");
                    wolfip_supplicant_free(supp);
                    return 1;
                }
            }
        }
        if (wolfip_supplicant_state(supp) == SUPP_STATE_AUTHENTICATED
            && !supp_inbox.has && !ap_inbox.has) {
            break;
        }
    }
    if (wolfip_supplicant_state(supp) != SUPP_STATE_AUTHENTICATED) {
        printf("  [FAIL] 4-way did not complete\n");
        wolfip_supplicant_free(supp);
        return 1;
    }

    /* Now rekey GTK. */
    {
        uint8_t new_gtk[16];
        memset(new_gtk, 0xF7, sizeof(new_gtk));
        installs.group_set = 0;
        installs.gtk_idx   = 0;
        if (ap_send_group_m1(&ap, new_gtk) != 0) {
            printf("  [FAIL] AP group-m1\n");
            wolfip_supplicant_free(supp);
            return 1;
        }
        for (iter = 0; iter < 4; iter++) {
            if (supp_inbox.has) {
                (void)wolfip_supplicant_rx(supp,
                                           supp_inbox.buf, supp_inbox.len, 0);
                supp_inbox.has = 0;
            }
            if (ap_inbox.has) {
                /* Group M2 from supplicant: just MIC-verify. */
                int was_m2 = 0;
                if (ap_handle_m2_m4(&ap, ap_inbox.buf, ap_inbox.len,
                                    &was_m2) != 0) {
                    printf("  [FAIL] AP rejected Group M2\n");
                    wolfip_supplicant_free(supp);
                    return 1;
                }
                ap_inbox.has = 0;
                pass = 1;
                break;
            }
        }
        if (!pass) {
            printf("  [FAIL] no Group M2 emitted\n");
            wolfip_supplicant_free(supp);
            return 1;
        }
        if (!installs.group_set || installs.gtk_idx != 2) {
            printf("  [FAIL] new GTK not installed (group_set=%d idx=%u)\n",
                   installs.group_set, installs.gtk_idx);
            fails++;
        }
        else if (memcmp(installs.gtk, new_gtk, sizeof(new_gtk)) != 0) {
            printf("  [FAIL] installed GTK does not match rekeyed value\n");
            fails++;
        }
        else {
            printf("  [OK]   Group rekey: new GTK[16] installed at idx 2\n");
            printf("  [OK]   Group M2 emitted and MIC-verified by AP\n");
        }
    }
    wolfip_supplicant_free(supp);
    return fails;
}

/* Test D: drop M3, advance the clock, expect supplicant-side M2 retx
 * via tick(). After AP gets the duplicate M2 it resends M3 and the
 * handshake completes. */
static int run_m3_drop_with_tick_retx(void)
{
    struct fake_ap ap;
    struct wolfip_supplicant_cfg cfg;
    struct wolfip_supplicant *supp;
    int    fails = 0;
    int    saw_retx = 0;
    int    iter;

    static const char ssid[] = "wolfIP-TestNet";
    static const char pass_text[] = "ThisIsAPassword!";

    memset(&supp_inbox, 0, sizeof(supp_inbox));
    memset(&ap_inbox,   0, sizeof(ap_inbox));
    memset(&installs,   0, sizeof(installs));
    drop_next_to_supp = 0;

    memset(&ap, 0, sizeof(ap));
    ap.aa[5] = 0x11; ap.sa[5] = 0x22;
    if (wpa_pmk_from_passphrase(pass_text, strlen(pass_text),
                                (const uint8_t *)ssid, strlen(ssid),
                                ap.pmk) != 0) return 1;
    if (rsn_ie_build_wpa2_psk(ap.rsn_ie, sizeof(ap.rsn_ie),
                              &ap.rsn_ie_len) != 0) return 1;

    memset(&cfg, 0, sizeof(cfg));
    cfg.ssid = ssid; cfg.ssid_len = strlen(ssid);
    cfg.passphrase = pass_text; cfg.passphrase_len = strlen(pass_text);
    memcpy(cfg.ap_mac,  ap.aa, WPA_MAC_LEN);
    memcpy(cfg.sta_mac, ap.sa, WPA_MAC_LEN);
    cfg.ap_rsn_ie     = ap.rsn_ie;
    cfg.ap_rsn_ie_len = ap.rsn_ie_len;
    cfg.ops.send_eapol  = supp_send_cb;
    cfg.ops.install_key = supp_install_cb;

    supp = wolfip_supplicant_new(&cfg);
    if (supp == NULL || wolfip_supplicant_kick(supp, 0) != 0) {
        printf("  [FAIL] init/kick\n");
        if (supp) wolfip_supplicant_free(supp);
        return 1;
    }

    if (ap_send_m1(&ap) != 0) {
        printf("  [FAIL] m1\n");
        wolfip_supplicant_free(supp);
        return 1;
    }
    /* Deliver M1 to supp; supp emits M2. */
    if (!supp_inbox.has) { printf("  [FAIL] no M1 to supp\n"); return 1; }
    (void)wolfip_supplicant_rx(supp, supp_inbox.buf, supp_inbox.len, 0);
    supp_inbox.has = 0;
    if (!ap_inbox.has) { printf("  [FAIL] no M2 from supp\n"); return 1; }

    /* AP processes M2, prepares M3 - but we drop the next AP->supp frame. */
    {
        int was_m2 = 0;
        if (ap_handle_m2_m4(&ap, ap_inbox.buf, ap_inbox.len, &was_m2) != 0
            || !was_m2) {
            printf("  [FAIL] AP rejected first M2\n");
            wolfip_supplicant_free(supp);
            return 1;
        }
        ap_inbox.has = 0;
    }
    drop_next_to_supp = 1;
    if (ap_send_m3(&ap) != 0) {
        printf("  [FAIL] AP send M3 (dropped)\n");
        wolfip_supplicant_free(supp);
        return 1;
    }
    /* M3 was dropped. supp should still be in 4WAY_M3_WAIT and has not
     * advanced. tick() before the retry interval should not retransmit. */
    wolfip_supplicant_tick(supp, 500);
    if (ap_inbox.has) {
        printf("  [FAIL] supp retransmitted M2 too early\n");
        wolfip_supplicant_free(supp);
        return 1;
    }
    /* Now advance past the retry interval. */
    wolfip_supplicant_tick(supp, 1500);
    if (!ap_inbox.has) {
        printf("  [FAIL] supp did not retransmit M2 after timeout\n");
        wolfip_supplicant_free(supp);
        return 1;
    }
    saw_retx = 1;

    /* AP receives the duplicate M2 and resends M3. */
    {
        int was_m2 = 0;
        if (ap_handle_m2_m4(&ap, ap_inbox.buf, ap_inbox.len, &was_m2) != 0) {
            printf("  [FAIL] AP rejected retx M2\n");
            wolfip_supplicant_free(supp);
            return 1;
        }
        ap_inbox.has = 0;
        /* Reset have_ptk-keyed-once flag: we already have PTK; on a
         * duplicate M2 the AP code path treats it as 'not M2'. That's
         * fine - we just need to re-emit M3 manually. */
        if (ap_send_m3(&ap) != 0) {
            printf("  [FAIL] AP resend M3\n");
            wolfip_supplicant_free(supp);
            return 1;
        }
    }
    /* Drive to AUTHENTICATED. */
    for (iter = 0; iter < 6; iter++) {
        if (supp_inbox.has) {
            (void)wolfip_supplicant_rx(supp, supp_inbox.buf,
                                       supp_inbox.len, 1500);
            supp_inbox.has = 0;
        }
        if (ap_inbox.has) {
            int was_m2 = 0;
            (void)ap_handle_m2_m4(&ap, ap_inbox.buf, ap_inbox.len, &was_m2);
            ap_inbox.has = 0;
        }
        if (wolfip_supplicant_state(supp) == SUPP_STATE_AUTHENTICATED) {
            break;
        }
    }
    if (wolfip_supplicant_state(supp) != SUPP_STATE_AUTHENTICATED) {
        printf("  [FAIL] handshake never reached AUTHENTICATED\n");
        fails++;
    }
    else if (!saw_retx) {
        printf("  [FAIL] retx path not exercised\n");
        fails++;
    }
    else {
        printf("  [OK]   tick(t<1s) suppressed retx, tick(t>=1s) retx'd M2\n");
        printf("  [OK]   handshake completed after one M3 drop + retx\n");
    }
    wolfip_supplicant_free(supp);
    return fails;
}

int main(void)
{
    int fails = 0;
    printf("Test A: clean 4-way handshake\n");
    fails += run_handshake(0);
    printf("\nTest B: 4-way handshake with one dropped M1 (AP retransmits)\n");
    fails += run_handshake(1);
    printf("\nTest C: Group Key rekey after 4-way completes\n");
    fails += run_group_rekey();
    printf("\nTest D: M3 drop + tick()-driven M2 retransmit\n");
    fails += run_m3_drop_with_tick_retx();

    if (fails == 0) {
        printf("\nAll supplicant 4-way tests passed.\n");
        return 0;
    }
    printf("\n%d supplicant test failure(s).\n", fails);
    return 1;
}

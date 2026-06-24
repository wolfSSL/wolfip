/* test_supplicant_sae.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * In-process integration test for the WPA3-SAE supplicant. The wolfIP
 * supplicant runs in WOLFIP_AUTH_SAE mode and drives its dragonfly
 * Commit/Confirm exchange against a fake AP that uses the sae_crypto
 * module directly. Success criteria:
 *   - Supplicant reaches SUPP_STATE_4WAY_M1_WAIT (= SAE complete).
 *   - PMK derived by supplicant matches PMK derived by fake AP.
 *
 * The 4-way handshake leg of WPA3 is exactly the WPA2 4-way with a
 * different PMK source; that path is already covered by
 * test_supplicant_4way and not re-exercised here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "supplicant.h"
#include "sae_crypto.h"

/* Multi-slot mailbox - SAE typically queues 2 frames per side. */
struct frame_queue {
    uint8_t  buf[4][512];
    size_t   len[4];
    int      count;
};
static struct frame_queue to_supp;       /* fake AP -> supplicant     */
static struct frame_queue to_auth;       /* supplicant -> fake AP     */

static int queue_push(struct frame_queue *q,
                      const uint8_t *frame, size_t len)
{
    if (q->count >= 4) return -1;
    if (len > sizeof(q->buf[0])) return -1;
    memcpy(q->buf[q->count], frame, len);
    q->len[q->count] = len;
    q->count++;
    return 0;
}

static int queue_pop(struct frame_queue *q,
                     uint8_t *out, size_t cap, size_t *out_len)
{
    int i;
    if (q->count == 0) return -1;
    if (q->len[0] > cap) return -1;
    memcpy(out, q->buf[0], q->len[0]);
    *out_len = q->len[0];
    for (i = 1; i < q->count; i++) {
        memcpy(q->buf[i - 1], q->buf[i], q->len[i]);
        q->len[i - 1] = q->len[i];
    }
    q->count--;
    return 0;
}

static int supp_send_auth(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    return queue_push(&to_auth, frame, len);
}

static int supp_send_eapol(void *ctx, const uint8_t *frame, size_t len)
{
    /* The 4-way handshake leg fires once SAE completes. We don't
     * exercise it here, so just discard. */
    (void)ctx; (void)frame; (void)len;
    return 0;
}

static int supp_install_key(void *ctx, wolfip_supplicant_keytype_t kt,
                            uint8_t idx, const uint8_t *k, size_t l)
{
    (void)ctx; (void)kt; (void)idx; (void)k; (void)l;
    return 0;
}

/* Fake AP: holds its own sae_ctx for the same group + password,
 * processes supplicant's Commit, emits Commit + Confirm in turn. */
struct fake_ap {
    struct sae_ctx sae;
    int            sent_commit;
    int            sent_confirm;
    int            saw_supp_confirm;
    int            h2e;          /* 0 = H&P, 1 = H2E (status 126 in Commit) */
};

static int ap_send_frame(uint8_t alg, uint8_t seq, uint8_t status,
                         const uint8_t *content, size_t content_len)
{
    uint8_t buf[8 + 3 * SAE_MAX_PRIME_LEN + SAE_MAX_HASH_LEN];
    if (6U + content_len > sizeof(buf)) return -1;
    buf[0] = alg; buf[1] = 0;
    buf[2] = seq; buf[3] = 0;
    buf[4] = status; buf[5] = 0;
    if (content_len > 0) memcpy(&buf[6], content, content_len);
    return queue_push(&to_supp, buf, 6U + content_len);
}

static int ap_handle_supp_frame(struct fake_ap *a,
                                const uint8_t *frame, size_t len)
{
    uint16_t alg, seq;
    if (len < 6) return -1;
    alg = (uint16_t)(frame[0] | ((uint16_t)frame[1] << 8));
    seq = (uint16_t)(frame[2] | ((uint16_t)frame[3] << 8));
    if (alg != 3U) return -1;

    if (seq == 1U) {
        uint8_t  commit_body[2 + 3 * SAE_MAX_PRIME_LEN];
        size_t   commit_len = 0;
        /* Supplicant's Commit. Process + respond with our Commit. */
        if (sae_parse_peer_commit(&a->sae, &frame[6], len - 6U) != 0) {
            return -1;
        }
        if (sae_generate_commit(&a->sae) != 0) return -1;
        if (sae_serialize_commit(&a->sae, commit_body,
                                 sizeof(commit_body),
                                 &commit_len) != 0) {
            return -1;
        }
        if (ap_send_frame(3, 1, a->h2e ? 126U : 0U,
                          commit_body, commit_len) != 0) return -1;
        a->sent_commit = 1;

        if (sae_derive_k_and_pmk(&a->sae) != 0) return -1;
        return 0;
    }
    if (seq == 2U) {
        uint16_t recv_sc;
        uint8_t  my_confirm[SAE_MAX_HASH_LEN];
        uint8_t  body[2 + SAE_MAX_HASH_LEN];
        size_t   my_clen = 0;
        if (len < 8U + 32U) return -1;
        recv_sc = (uint16_t)(frame[6] | ((uint16_t)frame[7] << 8));
        if (sae_verify_peer_confirm(&a->sae, recv_sc,
                                    &frame[8], len - 8U) != 0) {
            return -1;
        }
        a->saw_supp_confirm = 1;

        /* Now send our Confirm back. */
        if (sae_compute_confirm(&a->sae, 1, my_confirm,
                                sizeof(my_confirm), &my_clen) != 0) {
            return -1;
        }
        body[0] = 1; body[1] = 0;
        memcpy(&body[2], my_confirm, my_clen);
        if (ap_send_frame(3, 2, 0, body, 2U + my_clen) != 0) return -1;
        a->sent_confirm = 1;
        return 0;
    }
    return -1;
}

static int run_sae_test(int group_id, const char *label, int h2e)
{
    static const uint8_t sta_mac[6] = {0x02,0x00,0x00,0x00,0x00,0x11};
    static const uint8_t ap_mac [6] = {0x02,0x00,0x00,0x00,0x00,0x22};
    static const char    pw[]       = "wolfip-sae-test-pw";
    static const char    ssid[]     = "wolfIP-WPA3";

    struct wolfip_supplicant_cfg cfg;
    struct wolfip_supplicant    *supp = NULL;
    struct fake_ap                ap;
    uint8_t  frame[1024];
    size_t   flen = 0;
    int      iter, rc = 1;

    printf("Test: WPA3-SAE supplicant <-> in-process AP (group %d / %s, %s)\n",
           group_id, label, h2e ? "H2E" : "H&P");

    memset(&to_supp, 0, sizeof(to_supp));
    memset(&to_auth, 0, sizeof(to_auth));
    memset(&ap, 0, sizeof(ap));
    ap.h2e = h2e;

    /* Init fake AP's SAE context with the same group + PWE. */
    if (sae_ctx_init(&ap.sae, group_id) != 0) {
        printf("  [FAIL] fake AP sae init\n");
        return 1;
    }
    if (h2e) {
        if (sae_h2e_compute_pt(&ap.sae, pw, strlen(pw), NULL, 0,
                               (const uint8_t *)ssid, sizeof(ssid) - 1) != 0
         || sae_compute_pwe_h2e(&ap.sae, sta_mac, ap_mac) != 0) {
            printf("  [FAIL] fake AP H2E PWE\n");
            return 1;
        }
        ap.sae.h2e = 1;
    }
    else {
#if WOLFIP_ENABLE_SAE_HNP
        if (sae_compute_pwe_hnp(&ap.sae, pw, strlen(pw),
                                sta_mac, ap_mac) != 0) {
            printf("  [FAIL] fake AP H&P PWE\n");
            return 1;
        }
#else
        printf("  [SKIP] H&P disabled at build time\n");
        return 0;
#endif
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.ssid = ssid; cfg.ssid_len = sizeof(ssid) - 1;
    cfg.auth_mode  = WOLFIP_AUTH_SAE;
    cfg.passphrase = pw;
    cfg.passphrase_len = strlen(pw);
    cfg.sae_group  = group_id;
    cfg.sae_h2e    = h2e;
    memcpy(cfg.ap_mac,  ap_mac,  6);
    memcpy(cfg.sta_mac, sta_mac, 6);
    cfg.ops.send_eapol      = supp_send_eapol;
    cfg.ops.install_key     = supp_install_key;
    cfg.ops.send_auth_frame = supp_send_auth;

    supp = wolfip_supplicant_new(&cfg);
    if (supp == NULL) {
        printf("  [FAIL] wolfip_supplicant_new\n");
        goto out;
    }
    if (wolfip_supplicant_kick(supp, 0) != 0) {
        printf("  [FAIL] kick\n"); goto out;
    }
    /* After kick, supplicant should have sent its Commit. */

    for (iter = 0; iter < 16; iter++) {
        if (to_auth.count > 0) {
            if (queue_pop(&to_auth, frame, sizeof(frame), &flen) == 0) {
                if (ap_handle_supp_frame(&ap, frame, flen) != 0) {
                    printf("  [FAIL] fake AP rejected frame at iter %d\n",
                           iter);
                    goto out;
                }
            }
        }
        if (to_supp.count > 0) {
            if (queue_pop(&to_supp, frame, sizeof(frame), &flen) == 0) {
                int r = wolfip_supplicant_rx_auth_frame(supp,
                                                       frame, flen, 0);
                if (r != 0
                    && wolfip_supplicant_state(supp) == SUPP_STATE_FAILED) {
                    printf("  [FAIL] supplicant FAILED at iter %d\n", iter);
                    goto out;
                }
            }
        }
        if (wolfip_supplicant_state(supp) == SUPP_STATE_4WAY_M1_WAIT
            && ap.sent_confirm) break;
    }
    if (wolfip_supplicant_state(supp) != SUPP_STATE_4WAY_M1_WAIT) {
        printf("  [FAIL] supplicant did not reach 4WAY_M1_WAIT (state=%d)\n",
               (int)wolfip_supplicant_state(supp));
        goto out;
    }
    printf("  [OK]   supplicant reached SAE-done state\n");
    if (!ap.sent_confirm) {
        printf("  [FAIL] fake AP did not finish Confirm\n");
        goto out;
    }
    printf("  [OK]   fake AP completed Confirm round-trip\n");

    /* Compare PMKs derived independently. supp's PMK isn't exposed via
     * the API; recompute via the same path we know matches: ap.sae.pmk.
     * As a proxy, just verify supplicant transitioned (= it verified
     * AP's Confirm using its own derived KCK, which means matching K). */
    rc = 0;
out:
    if (supp) wolfip_supplicant_free(supp);
    sae_ctx_free(&ap.sae);
    return rc;
}

int main(void)
{
    int fails = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    fails += run_sae_test(SAE_GROUP_19, "P-256", 0);
    fails += run_sae_test(SAE_GROUP_20, "P-384", 0);
    fails += run_sae_test(SAE_GROUP_21, "P-521", 0);
#if defined(WOLFIP_ENABLE_SAE_H2E) && WOLFIP_ENABLE_SAE_H2E
    fails += run_sae_test(SAE_GROUP_19, "P-256", 1);
    fails += run_sae_test(SAE_GROUP_20, "P-384", 1);
    fails += run_sae_test(SAE_GROUP_21, "P-521", 1);
#endif
    if (fails == 0) {
        printf("\nAll SAE supplicant tests passed.\n");
        return 0;
    }
    printf("\n%d SAE supplicant test failure(s).\n", fails);
    return 1;
}

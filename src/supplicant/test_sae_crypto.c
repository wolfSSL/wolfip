/* test_sae_crypto.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * SAE crypto unit tests. Phase A covers the hunt-and-peck PWE
 * derivation: produce a PWE for the test MACs+password and verify
 * the resulting (x, y) point satisfies the curve equation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sae_crypto.h"

#include <wolfssl/wolfcrypt/error-crypt.h>

#if WOLFIP_ENABLE_SAE_HNP
static int test_pwe_group_19(void)
{
    /* Arbitrary test MACs and password. The PWE depends on both. */
    static const uint8_t mac_a[6] = {0x02,0x00,0x00,0x00,0x00,0x11};
    static const uint8_t mac_b[6] = {0x02,0x00,0x00,0x00,0x00,0x22};
    static const char     pw[]    = "wolfip-sae-test-pw";
    struct sae_ctx c;
    struct sae_ctx c2;
    struct sae_ctx c3;
    int rc = 1;

    printf("Test 1: SAE PWE hunt-and-peck (group 19, P-256)\n");
    if (sae_ctx_init(&c, SAE_GROUP_19) != 0) {
        printf("  [FAIL] sae_ctx_init\n");
        return 1;
    }
    if (sae_compute_pwe_hnp(&c, pw, strlen(pw), mac_a, mac_b) != 0) {
        printf("  [FAIL] sae_compute_pwe_hnp returned non-zero\n");
        goto out;
    }
    if (!c.have_pwe) {
        printf("  [FAIL] have_pwe not set\n");
        goto out;
    }
    if (sae_pwe_is_on_curve(&c) != 0) {
        printf("  [FAIL] PWE point does not satisfy y^2 = x^3 + ax + b\n");
        goto out;
    }
    printf("  [OK]   PWE derived and lies on P-256 curve\n");

    /* Determinism: re-derive with same inputs and verify same x/y. */
    if (sae_ctx_init(&c2, SAE_GROUP_19) != 0) {
        printf("  [FAIL] ctx2 init\n"); goto out;
    }
    if (sae_compute_pwe_hnp(&c2, pw, strlen(pw), mac_a, mac_b) != 0) {
        printf("  [FAIL] ctx2 pwe\n");
        sae_ctx_free(&c2); goto out;
    }
    if (!sae_pwe_equal(&c, &c2)) {
        printf("  [FAIL] PWE not deterministic\n");
        sae_ctx_free(&c2); goto out;
    }
    sae_ctx_free(&c2);
    printf("  [OK]   PWE deterministic across calls\n");

    /* Symmetry: PWE(mac_a, mac_b) == PWE(mac_b, mac_a). */
    if (sae_ctx_init(&c3, SAE_GROUP_19) != 0) goto out;
    if (sae_compute_pwe_hnp(&c3, pw, strlen(pw), mac_b, mac_a) != 0) {
        sae_ctx_free(&c3); goto out;
    }
    if (!sae_pwe_equal(&c, &c3)) {
        printf("  [FAIL] PWE not symmetric in MAC order\n");
        sae_ctx_free(&c3); goto out;
    }
    sae_ctx_free(&c3);
    printf("  [OK]   PWE symmetric (max||min canonicalisation works)\n");
    rc = 0;
out:
    sae_ctx_free(&c);
    return rc;
}

/* Two-peer in-process test: both sides derive PWE from the same
 * password+MACs, exchange Commit, derive K + KCK + PMK, and verify each
 * other's Confirm. Both PMKs must match. */
static int test_two_peer_handshake_group(int group_id, const char *label)
{
    static const uint8_t mac_sta[6] = {0x02,0x00,0x00,0x00,0x00,0x11};
    static const uint8_t mac_ap [6] = {0x02,0x00,0x00,0x00,0x00,0x22};
    static const char    pw[]       = "wolfip-sae-test-pw";
    struct sae_ctx a, b;
    uint8_t        a_commit[2 + 3 * 66];   /* sized for P-521          */
    uint8_t        b_commit[2 + 3 * 66];
    size_t         a_clen = 0, b_clen = 0;
    uint8_t        a_confirm[64], b_confirm[64];
    size_t         a_mlen = 0, b_mlen = 0;
    int            rc = 1;

    printf("Test 2: SAE two-peer handshake (group %d / %s)\n",
           group_id, label);
    if (sae_ctx_init(&a, group_id) != 0
        || sae_ctx_init(&b, group_id) != 0) {
        printf("  [FAIL] ctx init\n");
        goto out;
    }
    if (sae_compute_pwe_hnp(&a, pw, strlen(pw), mac_sta, mac_ap) != 0
        || sae_compute_pwe_hnp(&b, pw, strlen(pw), mac_sta, mac_ap) != 0) {
        printf("  [FAIL] PWE derivation\n");
        goto out;
    }
    if (sae_generate_commit(&a) != 0 || sae_generate_commit(&b) != 0) {
        printf("  [FAIL] generate_commit\n");
        goto out;
    }
    if (sae_serialize_commit(&a, a_commit, sizeof(a_commit), &a_clen) != 0
        || sae_serialize_commit(&b, b_commit, sizeof(b_commit), &b_clen) != 0) {
        printf("  [FAIL] serialize_commit\n");
        goto out;
    }
    /* Exchange. */
    if (sae_parse_peer_commit(&a, b_commit, b_clen) != 0
        || sae_parse_peer_commit(&b, a_commit, a_clen) != 0) {
        printf("  [FAIL] parse_peer_commit\n");
        goto out;
    }
    if (sae_derive_k_and_pmk(&a) != 0 || sae_derive_k_and_pmk(&b) != 0) {
        printf("  [FAIL] derive_k_and_pmk\n");
        goto out;
    }
    if (memcmp(a.pmk, b.pmk, sizeof(a.pmk)) != 0) {
        printf("  [FAIL] PMK mismatch between peers\n");
        goto out;
    }
    printf("  [OK]   both peers derived identical PMK (32 B)\n");

    if (memcmp(a.pmkid, b.pmkid, sizeof(a.pmkid)) != 0) {
        printf("  [FAIL] PMKID mismatch\n");
        goto out;
    }
    printf("  [OK]   PMKID matches\n");

    /* Confirm round. */
    if (sae_compute_confirm(&a, 1, a_confirm, sizeof(a_confirm), &a_mlen) != 0
        || sae_compute_confirm(&b, 1, b_confirm, sizeof(b_confirm), &b_mlen)
           != 0) {
        printf("  [FAIL] compute_confirm\n");
        goto out;
    }
    if (sae_verify_peer_confirm(&a, 1, b_confirm, b_mlen) != 0) {
        printf("  [FAIL] a rejected b's confirm\n");
        goto out;
    }
    if (sae_verify_peer_confirm(&b, 1, a_confirm, a_mlen) != 0) {
        printf("  [FAIL] b rejected a's confirm\n");
        goto out;
    }
    printf("  [OK]   confirm MACs verified on both sides\n");

    /* Tamper test. */
    a_confirm[0] ^= 0x01;
    if (sae_verify_peer_confirm(&b, 1, a_confirm, a_mlen) == 0) {
        printf("  [FAIL] tampered confirm wrongly accepted\n");
        goto out;
    }
    printf("  [OK]   tampered confirm rejected\n");
    rc = 0;
out:
    sae_ctx_free(&a);
    sae_ctx_free(&b);
    return rc;
}

/* MEDIUM-3: the four security-critical rejection paths in sae_parse_peer_commit
 * (scalar out of [2,q-1], coord >= prime, element off-curve, and the IEEE
 * 802.11-2020 12.4.5.4 reflection check) that the happy-path tests never hit. */
static int test_parse_peer_commit_negatives(void)
{
    static const uint8_t mac_sta[6] = {0x02,0x00,0x00,0x00,0x00,0x11};
    static const uint8_t mac_ap [6] = {0x02,0x00,0x00,0x00,0x00,0x22};
    static const char    pw[]       = "wolfip-sae-test-pw";
    const size_t   pl = 32;                 /* P-256 field/scalar length    */
    const size_t   sc_off = 2;              /* group_id(2) || scalar || x||y */
    const size_t   ex_off = 2 + 32;
    const size_t   ey_off = 2 + 64;
    struct sae_ctx a, b;
    uint8_t        a_commit[2 + 3 * 66], b_commit[2 + 3 * 66];
    uint8_t        bad[2 + 3 * 66];
    size_t         a_clen = 0, b_clen = 0;
    int            fails = 0;
    int            rc = 1;

    printf("Test 3b: SAE parse_peer_commit reject paths (group 19 / P-256)\n");
    if (sae_ctx_init(&a, SAE_GROUP_19) != 0
        || sae_ctx_init(&b, SAE_GROUP_19) != 0) {
        printf("  [FAIL] ctx init\n"); goto out;
    }
    if (sae_compute_pwe_hnp(&a, pw, strlen(pw), mac_sta, mac_ap) != 0
        || sae_compute_pwe_hnp(&b, pw, strlen(pw), mac_sta, mac_ap) != 0) {
        printf("  [FAIL] PWE\n"); goto out;
    }
    if (sae_generate_commit(&a) != 0 || sae_generate_commit(&b) != 0) {
        printf("  [FAIL] commit\n"); goto out;
    }
    if (sae_serialize_commit(&a, a_commit, sizeof(a_commit), &a_clen) != 0
        || sae_serialize_commit(&b, b_commit, sizeof(b_commit), &b_clen) != 0) {
        printf("  [FAIL] serialize\n"); goto out;
    }
    if (a_clen != 2 + 3 * pl) {
        printf("  [FAIL] unexpected commit length %u\n", (unsigned)a_clen);
        goto out;
    }

    /* Baseline: the unmodified peer commit parses. */
    if (sae_parse_peer_commit(&b, a_commit, a_clen) != 0) {
        printf("  [FAIL] valid peer commit rejected\n"); fails++;
    }
    else printf("  [OK]   valid peer commit accepted\n");

    /* (a) element y bumped off-curve. */
    memcpy(bad, a_commit, a_clen);
    bad[ey_off + pl - 1] ^= 0x01;
    if (sae_parse_peer_commit(&b, bad, a_clen) == 0) {
        printf("  [FAIL] off-curve element accepted\n"); fails++;
    }
    else printf("  [OK]   off-curve element rejected\n");

    /* (b) element x out of range (>= prime). */
    memcpy(bad, a_commit, a_clen);
    memset(&bad[ex_off], 0xFF, pl);
    if (sae_parse_peer_commit(&b, bad, a_clen) == 0) {
        printf("  [FAIL] coord >= prime accepted\n"); fails++;
    }
    else printf("  [OK]   coord >= prime rejected\n");

    /* (c) scalar below range (== 1). */
    memcpy(bad, a_commit, a_clen);
    memset(&bad[sc_off], 0, pl);
    bad[sc_off + pl - 1] = 1;
    if (sae_parse_peer_commit(&b, bad, a_clen) == 0) {
        printf("  [FAIL] scalar == 1 accepted\n"); fails++;
    }
    else printf("  [OK]   scalar < 2 rejected\n");

    /* (c2) scalar above range (all 0xFF >= q). */
    memcpy(bad, a_commit, a_clen);
    memset(&bad[sc_off], 0xFF, pl);
    if (sae_parse_peer_commit(&b, bad, a_clen) == 0) {
        printf("  [FAIL] scalar >= q accepted\n"); fails++;
    }
    else printf("  [OK]   scalar >= q rejected\n");

    /* (d) reflection: feed b its OWN commit. */
    if (sae_parse_peer_commit(&b, b_commit, b_clen) == 0) {
        printf("  [FAIL] reflected (own) commit accepted\n"); fails++;
    }
    else printf("  [OK]   reflected commit rejected\n");

    rc = fails;
out:
    sae_ctx_free(&a);
    sae_ctx_free(&b);
    return rc;
}
#endif /* WOLFIP_ENABLE_SAE_HNP */

/* Decode an ASCII hex string into a byte buffer. Returns bytes written,
 * or -1 on bad input. No spaces / 0x prefixes - tight unit-test helper. */
static int hex_decode(const char *hex, uint8_t *out, size_t out_cap)
{
    size_t len = strlen(hex), i;
    if ((len & 1) != 0 || (len / 2) > out_cap) return -1;
    for (i = 0; i < len; i += 2) {
        unsigned int v;
        if (sscanf(hex + i, "%2x", &v) != 1) return -1;
        out[i / 2] = (uint8_t)v;
    }
    return (int)(len / 2);
}

/* RFC 9380 J.1.1 - P256_XMD:SHA-256_SSWU_RO_, msg = "". The standard
 * publishes both the reduced field elements u[0]/u[1] AND the SSWU
 * outputs Q0/Q1 (before clear_cofactor; for P-256 cofactor=1 so
 * Q == clear_cofactor(Q)). We feed the published u directly into our
 * sswu_map and check the resulting (x, y) matches Q. This validates
 * the SSWU primitive standalone (without depending on RFC 9380's
 * expand_message_xmd, which SAE-H2E does not use). */
static int test_sswu_rfc9380_p256(void)
{
    struct sae_ctx c;
    int            rc = -1, n;
    uint8_t        u[32], qx[32], qy[32];
    uint8_t        exp_qx[32], exp_qy[32];

    static const struct {
        const char *u, *qx, *qy;
    } kVecs[] = {
        { "ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009",
          "ab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967934d5",
          "dccb558863804a881d4fff3455716c836cef230e5209594ddd33d85c565b19b1" },
        { "8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a",
          "51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d980ef5",
          "b45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699e5a1b66aac" }
    };
    int i;

    printf("RFC 9380 J.1.1 SSWU P-256 known-answer\n");
    memset(&c, 0, sizeof(c));
    if (sae_ctx_init(&c, SAE_GROUP_19) != 0) {
        printf("  [FAIL] sae_ctx_init group 19\n"); goto out;
    }
    for (i = 0; i < (int)(sizeof(kVecs) / sizeof(kVecs[0])); i++) {
        n = hex_decode(kVecs[i].u, u, sizeof(u));
        if (n != 32) { printf("  [FAIL] hex u\n"); goto out; }
        if (hex_decode(kVecs[i].qx, exp_qx, sizeof(exp_qx)) != 32
         || hex_decode(kVecs[i].qy, exp_qy, sizeof(exp_qy)) != 32) {
            printf("  [FAIL] hex q\n"); goto out;
        }
        if (sae_h2e_sswu(&c, u, sizeof(u), qx, qy) != 0) {
            printf("  [FAIL] sae_h2e_sswu u[%d]\n", i); goto out;
        }
        if (memcmp(qx, exp_qx, 32) != 0 || memcmp(qy, exp_qy, 32) != 0) {
            printf("  [FAIL] vector %d mismatch\n", i);
            goto out;
        }
        printf("  [OK]   vector %d (Q%d)\n", i, i);
    }
    rc = 0;
out:
    sae_ctx_free(&c);
    return rc;
}

/* H2E PT determinism + sensitivity + on-curve. */
static int test_h2e_pt_group(int group_id, const char *label)
{
    struct sae_ctx a, b, c, t;
    const uint8_t ssid[]  = "wolfIP-SAE";
    const uint8_t ssid2[] = "wolfIP-OTHER";
    const char   *pw      = "ThisIsAPassword!";
    const char   *pw2     = "DifferentPassword!";
    uint8_t       xa[SAE_MAX_PRIME_LEN], ya[SAE_MAX_PRIME_LEN];
    uint8_t       xb[SAE_MAX_PRIME_LEN], yb[SAE_MAX_PRIME_LEN];
    uint8_t       xc[SAE_MAX_PRIME_LEN], yc[SAE_MAX_PRIME_LEN];
    int           rc = -1;
    size_t        plen;

    printf("H2E PT (group %d / %s)\n", group_id, label);
    memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b)); memset(&c, 0, sizeof(c));
    if (sae_ctx_init(&a, group_id) != 0 || sae_ctx_init(&b, group_id) != 0
     || sae_ctx_init(&c, group_id) != 0) {
        printf("  [FAIL] sae_ctx_init\n"); goto out;
    }
    plen = a.grp->prime_len;

    if (sae_h2e_compute_pt(&a, pw,  strlen(pw),  NULL, 0,
                           ssid,  sizeof(ssid)  - 1) != 0
     || sae_h2e_compute_pt(&b, pw,  strlen(pw),  NULL, 0,
                           ssid,  sizeof(ssid)  - 1) != 0
     || sae_h2e_compute_pt(&c, pw2, strlen(pw2), NULL, 0,
                           ssid2, sizeof(ssid2) - 1) != 0) {
        printf("  [FAIL] sae_h2e_compute_pt\n"); goto out;
    }
    if (sae_h2e_get_pt(&a, xa, ya) != 0
     || sae_h2e_get_pt(&b, xb, yb) != 0
     || sae_h2e_get_pt(&c, xc, yc) != 0) {
        printf("  [FAIL] sae_h2e_get_pt\n"); goto out;
    }
    if (memcmp(xa, xb, plen) != 0 || memcmp(ya, yb, plen) != 0) {
        printf("  [FAIL] PT not deterministic for same (pw, SSID)\n");
        goto out;
    }
    printf("  [OK]   PT deterministic across two contexts\n");
    if (memcmp(xa, xc, plen) == 0 && memcmp(ya, yc, plen) == 0) {
        printf("  [FAIL] PT identical for different (pw, SSID)\n");
        goto out;
    }
    printf("  [OK]   PT differs for different (pw, SSID)\n");

    /* Swap PT into PWE slot and reuse the existing on-curve check. */
    memset(&t, 0, sizeof(t));
    if (sae_ctx_init(&t, group_id) != 0) {
        printf("  [FAIL] tmp ctx\n"); goto out;
    }
    if (mp_copy(&a.pt_x, &t.pwe_x) != 0
     || mp_copy(&a.pt_y, &t.pwe_y) != 0) {
        sae_ctx_free(&t); printf("  [FAIL] copy\n"); goto out;
    }
    t.have_pwe = 1;
    if (sae_pwe_is_on_curve(&t) != 0) {
        sae_ctx_free(&t);
        printf("  [FAIL] PT not on curve\n");
        goto out;
    }
    sae_ctx_free(&t);
    printf("  [OK]   PT lies on the curve\n");
    rc = 0;
out:
    sae_ctx_free(&a); sae_ctx_free(&b); sae_ctx_free(&c);
    return rc;
}

/* H2E two-peer end-to-end: both sides derive PT, then PWE, then run
 * the Commit/Confirm dragonfly and compare PMKs. */
static int test_h2e_handshake_group(int group_id, const char *label)
{
    struct sae_ctx a, b;
    const uint8_t  mac_a[6]  = {0x02,0x00,0x00,0x00,0x00,0xAA};
    const uint8_t  mac_b[6]  = {0x02,0x00,0x00,0x00,0x00,0xBB};
    const uint8_t  ssid[]    = "wolfIP-SAE";
    const char    *pw        = "ThisIsAPassword!";
    uint8_t        wire_a[1024], wire_b[1024];
    uint8_t        a_confirm[SAE_MAX_HASH_LEN], b_confirm[SAE_MAX_HASH_LEN];
    size_t         la, lb, a_mlen, b_mlen;
    int            rc = -1;

    printf("H2E full handshake (group %d / %s)\n", group_id, label);
    memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b));
    if (sae_ctx_init(&a, group_id) != 0 || sae_ctx_init(&b, group_id) != 0) {
        printf("  [FAIL] sae_ctx_init\n"); goto out;
    }
    if (sae_h2e_compute_pt(&a, pw, strlen(pw), NULL, 0,
                           ssid, sizeof(ssid) - 1) != 0
     || sae_h2e_compute_pt(&b, pw, strlen(pw), NULL, 0,
                           ssid, sizeof(ssid) - 1) != 0) {
        printf("  [FAIL] sae_h2e_compute_pt\n"); goto out;
    }
    if (sae_compute_pwe_h2e(&a, mac_a, mac_b) != 0
     || sae_compute_pwe_h2e(&b, mac_a, mac_b) != 0) {
        printf("  [FAIL] sae_compute_pwe_h2e\n"); goto out;
    }
    if (!sae_pwe_equal(&a, &b)) {
        printf("  [FAIL] PWE mismatch between peers\n"); goto out;
    }
    printf("  [OK]   PWE matches across peers\n");
    if (sae_generate_commit(&a) != 0 || sae_generate_commit(&b) != 0) {
        printf("  [FAIL] generate_commit\n"); goto out;
    }
    if (sae_serialize_commit(&a, wire_a, sizeof(wire_a), &la) != 0
     || sae_serialize_commit(&b, wire_b, sizeof(wire_b), &lb) != 0) {
        printf("  [FAIL] serialize_commit\n"); goto out;
    }
    if (sae_parse_peer_commit(&a, wire_b, lb) != 0
     || sae_parse_peer_commit(&b, wire_a, la) != 0) {
        printf("  [FAIL] parse_peer_commit\n"); goto out;
    }
    if (sae_derive_k_and_pmk(&a) != 0 || sae_derive_k_and_pmk(&b) != 0) {
        printf("  [FAIL] derive_k_and_pmk\n"); goto out;
    }
    if (memcmp(a.pmk, b.pmk, SAE_PMK_LEN) != 0) {
        printf("  [FAIL] PMK mismatch\n"); goto out;
    }
    printf("  [OK]   PMK matches (%d B)\n", SAE_PMK_LEN);

    if (sae_compute_confirm(&a, 1, a_confirm, sizeof(a_confirm), &a_mlen) != 0
     || sae_compute_confirm(&b, 1, b_confirm, sizeof(b_confirm), &b_mlen) != 0) {
        printf("  [FAIL] compute_confirm\n"); goto out;
    }
    if (sae_verify_peer_confirm(&a, 1, b_confirm, b_mlen) != 0
     || sae_verify_peer_confirm(&b, 1, a_confirm, a_mlen) != 0) {
        printf("  [FAIL] verify_peer_confirm\n"); goto out;
    }
    printf("  [OK]   confirm MACs verified on both sides\n");
    rc = 0;
out:
    sae_ctx_free(&a); sae_ctx_free(&b);
    return rc;
}

int main(void)
{
    int fails = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
#if WOLFIP_ENABLE_SAE_HNP
    fails += test_pwe_group_19();
    fails += test_two_peer_handshake_group(SAE_GROUP_19, "P-256 / SHA-256");
    fails += test_two_peer_handshake_group(SAE_GROUP_20, "P-384");
    fails += test_two_peer_handshake_group(SAE_GROUP_21, "P-521");
    fails += test_parse_peer_commit_negatives();
#endif
    fails += test_sswu_rfc9380_p256();
    fails += test_h2e_pt_group(SAE_GROUP_19, "P-256");
    fails += test_h2e_pt_group(SAE_GROUP_20, "P-384");
    fails += test_h2e_pt_group(SAE_GROUP_21, "P-521");
    fails += test_h2e_handshake_group(SAE_GROUP_19, "P-256 / SHA-256");
    fails += test_h2e_handshake_group(SAE_GROUP_20, "P-384");
    fails += test_h2e_handshake_group(SAE_GROUP_21, "P-521");
    if (fails == 0) {
        printf("\nAll SAE crypto tests passed.\n");
        return 0;
    }
    printf("\n%d SAE crypto test failure(s).\n", fails);
    return 1;
}

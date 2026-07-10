/* test_macsec_sa.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Stand-alone loopback test for src/macsec/macsec_sa.c (the stateful SecY SA
 * layer). A transmit SC and a receive SC share a SAK; frames are protected by
 * the TX SC and validated by the RX SC. Verifies:
 *   1. In-order delivery of a burst (PN increments, all accepted).
 *   2. Replay window: reorder within the window accepted, below-window
 *      rejected as replay.
 *   3. Strict mode (window 0): duplicates / old PNs rejected.
 *   4. Integrity-only loopback.
 *   5. Tamper -> authentication failure.
 *   6. PN exhaustion -> transmit refused (rekey needed).
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "macsec_sa.h"
#include "macsec_test.h"

#define BURST      8
#define FRAME_CAP  256

static const uint8_t DA[6]  = { 0x02,0,0,0,0,0xbb };
static const uint8_t SA[6]  = { 0x02,0,0,0,0,0xaa };
static const uint8_t SCI[8] = { 0x02,0,0,0,0,0xaa,0x00,0x01 };
static const uint8_t SAK[16] = {
    0xad,0x7a,0x2b,0xd0,0x3e,0xac,0x83,0x5a,
    0x6f,0x62,0x0f,0xdc,0xb5,0x06,0xb3,0x45
};

/* Protect a burst of frames (PN 1..BURST) into frames[]/lens[]. */
static int make_burst(struct macsec_tx_sc *tx,
                      uint8_t frames[BURST][FRAME_CAP], size_t lens[BURST])
{
    uint8_t payload[48];
    int i;
    for (i = 0; i < BURST; i++) {
        fill_payload(payload, sizeof(payload), (uint8_t)i);
        if (macsec_tx(tx, DA, SA, payload, sizeof(payload),
                      frames[i], FRAME_CAP, &lens[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static int test_in_order(void)
{
    struct macsec_tx_sc tx;
    struct macsec_rx_sc rx;
    uint8_t frames[BURST][FRAME_CAP];
    size_t  lens[BURST];
    uint8_t rec[FRAME_CAP];
    size_t  rlen;
    int     i, fails = 0, ok = 1;

    printf("Test 1: in-order burst loopback\n");
    macsec_tx_sc_set_key(&tx, SAK, 16, SCI, 0, 1 /*encrypt*/, 0, 1, 1);
    macsec_rx_sc_set_key(&rx, SAK, 16, SCI, 0, 1 /*replay*/, 4, 0);
    if (make_burst(&tx, frames, lens) != 0) {
        printf("  [FAIL] burst protect error\n"); return 1;
    }
    for (i = 0; i < BURST; i++) {
        if (macsec_rx(&rx, frames[i], lens[i], rec, sizeof(rec), &rlen)
            != MACSEC_RX_OK) {
            ok = 0;
        }
    }
    fails += expect_true(ok, "all in-order frames accepted");
    fails += expect_true(tx.next_pn == (uint32_t)(BURST + 1),
                         "TX PN advanced past the burst");
    return fails;
}

static int test_replay_window(void)
{
    struct macsec_tx_sc tx;
    struct macsec_rx_sc rx;
    uint8_t frames[BURST][FRAME_CAP];
    size_t  lens[BURST];
    uint8_t rec[FRAME_CAP];
    size_t  rlen;
    int     fails = 0;

    printf("Test 2: replay window (reorder in, old out)\n");
    macsec_tx_sc_set_key(&tx, SAK, 16, SCI, 0, 1, 0, 1, 1);
    macsec_rx_sc_set_key(&rx, SAK, 16, SCI, 0, 1 /*replay*/, 4 /*window*/, 0);
    make_burst(&tx, frames, lens);   /* frames[i] carries PN i+1 */

    /* Accept PN 5 first (index 4). */
    fails += expect_true(
        macsec_rx(&rx, frames[4], lens[4], rec, sizeof(rec), &rlen)
            == MACSEC_RX_OK, "PN 5 accepted");
    /* PN 3 is within window (5-4+1=2 .. ) -> accepted. */
    fails += expect_true(
        macsec_rx(&rx, frames[2], lens[2], rec, sizeof(rec), &rlen)
            == MACSEC_RX_OK, "PN 3 within window accepted");
    /* PN 1 is below the window lower bound -> replay. */
    fails += expect_true(
        macsec_rx(&rx, frames[0], lens[0], rec, sizeof(rec), &rlen)
            == MACSEC_RX_REPLAY, "PN 1 below window rejected");
    return fails;
}

static int test_strict_mode(void)
{
    struct macsec_tx_sc tx;
    struct macsec_rx_sc rx;
    uint8_t frames[BURST][FRAME_CAP];
    size_t  lens[BURST];
    uint8_t rec[FRAME_CAP];
    size_t  rlen;
    int     fails = 0;

    printf("Test 3: strict mode (window 0) duplicate rejection\n");
    macsec_tx_sc_set_key(&tx, SAK, 16, SCI, 0, 1, 0, 1, 1);
    macsec_rx_sc_set_key(&rx, SAK, 16, SCI, 0, 1, 0 /*window=0*/, 0);
    make_burst(&tx, frames, lens);

    fails += expect_true(
        macsec_rx(&rx, frames[2], lens[2], rec, sizeof(rec), &rlen)
            == MACSEC_RX_OK, "PN 3 accepted");
    fails += expect_true(
        macsec_rx(&rx, frames[2], lens[2], rec, sizeof(rec), &rlen)
            == MACSEC_RX_REPLAY, "duplicate PN 3 rejected");
    fails += expect_true(
        macsec_rx(&rx, frames[1], lens[1], rec, sizeof(rec), &rlen)
            == MACSEC_RX_REPLAY, "older PN 2 rejected");
    fails += expect_true(
        macsec_rx(&rx, frames[3], lens[3], rec, sizeof(rec), &rlen)
            == MACSEC_RX_OK, "newer PN 4 accepted");
    return fails;
}

static int test_integrity_only(void)
{
    struct macsec_tx_sc tx;
    struct macsec_rx_sc rx;
    uint8_t payload[48];
    uint8_t frame[FRAME_CAP];
    uint8_t rec[FRAME_CAP];
    size_t  flen, rlen;
    int     fails = 0;

    printf("Test 4: integrity-only loopback\n");
    fill_payload(payload, sizeof(payload), 0x40);
    macsec_tx_sc_set_key(&tx, SAK, 16, SCI, 0, 0 /*integrity*/, 0, 1, 1);
    macsec_rx_sc_set_key(&rx, SAK, 16, SCI, 0, 1, 4, 0);
    if (macsec_tx(&tx, DA, SA, payload, sizeof(payload), frame,
                  sizeof(frame), &flen) != 0) {
        printf("  [FAIL] tx error\n"); return 1;
    }
    fails += expect_true(
        macsec_rx(&rx, frame, flen, rec, sizeof(rec), &rlen) == MACSEC_RX_OK
        && rlen == sizeof(payload)
        && memcmp(rec, payload, sizeof(payload)) == 0,
        "integrity-only frame recovered");
    return fails;
}

static int test_tamper(void)
{
    struct macsec_tx_sc tx;
    struct macsec_rx_sc rx;
    uint8_t payload[48];
    uint8_t frame[FRAME_CAP];
    uint8_t rec[FRAME_CAP];
    size_t  flen, rlen;
    int     fails = 0;

    printf("Test 5: tamper -> auth fail\n");
    fill_payload(payload, sizeof(payload), 0x20);
    macsec_tx_sc_set_key(&tx, SAK, 16, SCI, 0, 1, 0, 1, 1);
    macsec_rx_sc_set_key(&rx, SAK, 16, SCI, 0, 1, 4, 0);
    macsec_tx(&tx, DA, SA, payload, sizeof(payload), frame, sizeof(frame),
              &flen);
    frame[flen - 2] ^= 0x01;         /* corrupt the ICV */
    fails += expect_true(
        macsec_rx(&rx, frame, flen, rec, sizeof(rec), &rlen)
            == MACSEC_RX_AUTH_FAIL, "tampered frame -> AUTH_FAIL");
    return fails;
}

static int test_pn_exhaustion(void)
{
    struct macsec_tx_sc tx;
    uint8_t payload[48];
    uint8_t frame[FRAME_CAP];
    size_t  flen;
    int     fails = 0;

    printf("Test 6: PN exhaustion\n");
    fill_payload(payload, sizeof(payload), 0x10);
    macsec_tx_sc_set_key(&tx, SAK, 16, SCI, 0, 1, 0, 1, MACSEC_PN_MAX);
    fails += expect_true(
        macsec_tx(&tx, DA, SA, payload, sizeof(payload), frame,
                  sizeof(frame), &flen) == 0, "last PN transmitted");
    fails += expect_true(
        macsec_tx(&tx, DA, SA, payload, sizeof(payload), frame,
                  sizeof(frame), &flen) == MACSEC_RX_BAD_ARG,
        "transmit refused after PN exhaustion");
    return fails;
}

int main(void)
{
    int fails = 0;
    setvbuf(stdout, NULL, _IONBF, 0);

    fails += test_in_order();
    fails += test_replay_window();
    fails += test_strict_mode();
    fails += test_integrity_only();
    fails += test_tamper();
    fails += test_pn_exhaustion();

    printf("\n%s: macsec_sa (%d failure%s)\n",
           fails == 0 ? "PASS" : "FAIL", fails, fails == 1 ? "" : "s");
    return fails == 0 ? 0 : 1;
}

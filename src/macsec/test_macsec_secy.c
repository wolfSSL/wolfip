/* test_macsec_secy.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Stand-alone test for src/macsec/macsec_secy.c. Verifies:
 *   1. SecTAG build/parse field round-trip (TCI bits, AN, PN, SL, SCI).
 *   2. protect/validate round-trip: encrypt (GCM-AES-128 and -256), with and
 *      without an in-tag SCI.
 *   3. Integrity-only round-trip (secure data left in cleartext on the wire).
 *   4. Confidentiality offset 30 / 50 (prefix cleartext, remainder encrypted).
 *   5. Tamper rejection: ciphertext, ICV, DA (AAD), PN, and wrong SAK.
 *
 * Exact 802.1AE frame KATs are locked against captured Linux `ip macsec`
 * output in the M4 interop tests.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "macsec_secy.h"
#include "macsec_test.h"

static const uint8_t g_da[6]  = { 0x01,0x80,0xc2,0x00,0x00,0x03 };
static const uint8_t g_sa[6]  = { 0x02,0x00,0x00,0x00,0x00,0x22 };
static const uint8_t g_sci[8] = { 0x02,0x00,0x00,0x00,0x00,0x22,0x00,0x01 };
static const uint8_t g_sak128[16] = {
    0xad,0x7a,0x2b,0xd0,0x3e,0xac,0x83,0x5a,
    0x6f,0x62,0x0f,0xdc,0xb5,0x06,0xb3,0x45
};
static const uint8_t g_sak256[32] = {
    0xe3,0xc0,0x8a,0x8f,0x06,0xc6,0xe3,0xad,
    0x95,0xa7,0x05,0x57,0xb2,0x3f,0x75,0x48,
    0x3c,0xe3,0x30,0x21,0xa9,0xc7,0x2b,0x70,
    0x25,0x66,0x62,0x04,0xc6,0x9c,0x0b,0x72
};

static void base_protect_params(struct macsec_protect_params *pp,
                                const uint8_t *sak, size_t sak_len,
                                int encrypt, size_t offset, int include_sci)
{
    memset(pp, 0, sizeof(*pp));
    pp->da          = g_da;
    pp->sa          = g_sa;
    pp->sci         = g_sci;
    pp->sak         = sak;
    pp->sak_len     = sak_len;
    pp->conf_offset = offset;
    pp->pn          = 0x00000001U;
    pp->an          = 1;
    pp->encrypt     = (uint8_t)encrypt;
    pp->include_sci = (uint8_t)include_sci;
}

static int roundtrip(const uint8_t *sak, size_t sak_len, int encrypt,
                     size_t offset, int include_sci, const char *what)
{
    struct macsec_protect_params  pp;
    struct macsec_validate_params vp;
    struct macsec_sectag          tag;
    uint8_t payload[64];
    uint8_t frame[128];
    uint8_t recovered[128];
    size_t  frame_len = 0, rec_len = 0;
    int     fails = 0;

    fill_payload(payload, sizeof(payload), 0);
    base_protect_params(&pp, sak, sak_len, encrypt, offset, include_sci);

    if (macsec_protect(&pp, payload, sizeof(payload), frame, sizeof(frame),
                       &frame_len) != 0) {
        printf("  [FAIL] %s: protect error\n", what);
        return 1;
    }

    memset(&vp, 0, sizeof(vp));
    vp.sak         = sak;
    vp.sak_len     = sak_len;
    vp.sci         = g_sci;              /* fallback when tag omits SCI */
    vp.conf_offset = offset;

    if (macsec_validate(&vp, frame, frame_len, recovered, sizeof(recovered),
                        &rec_len, &tag) != 0) {
        printf("  [FAIL] %s: validate error\n", what);
        return 1;
    }
    fails += expect_true(rec_len == sizeof(payload)
                         && memcmp(recovered, payload, sizeof(payload)) == 0,
                         what);
    return fails;
}

static int test_sectag(void)
{
    struct macsec_protect_params pp;
    struct macsec_sectag         tag;
    uint8_t buf[MACSEC_SECTAG_MAX_LEN];
    int     built;
    int     fails = 0;

    printf("Test 1: SecTAG build/parse\n");
    base_protect_params(&pp, g_sak128, 16, 1 /*encrypt*/, 0, 1 /*sci*/);
    pp.pn = 0x11223344U;
    pp.an = 2;

    built = macsec_sectag_build(buf, sizeof(buf), &pp, 40 /* < 48 -> SL */);
    fails += expect_true(built == (int)MACSEC_SECTAG_MAX_LEN, "SCI tag len 16");
    if (macsec_sectag_parse(buf, sizeof(buf), &tag) != 0) {
        printf("  [FAIL] parse error\n");
        return fails + 1;
    }
    fails += expect_true(tag.pn == 0x11223344U, "PN round-trip");
    fails += expect_true((tag.tci_an & MACSEC_AN_MASK) == 2, "AN round-trip");
    fails += expect_true(tag.sci_present
                         && memcmp(tag.sci, g_sci, 8) == 0, "SCI round-trip");
    fails += expect_true((tag.tci_an & MACSEC_TCI_E) && (tag.tci_an & MACSEC_TCI_C),
                         "E and C set for encrypt");
    fails += expect_true(tag.sl == 40, "SL carries short length");
    return fails;
}

static int test_roundtrips(void)
{
    int fails = 0;
    printf("Test 2: protect/validate round-trips\n");
    fails += roundtrip(g_sak128, 16, 1, 0, 1, "encrypt-128 with SCI");
    fails += roundtrip(g_sak256, 32, 1, 0, 1, "encrypt-256 with SCI");
    fails += roundtrip(g_sak128, 16, 1, 0, 0, "encrypt-128 no SCI");
    fails += roundtrip(g_sak128, 16, 0, 0, 1, "integrity-only-128");
    fails += roundtrip(g_sak128, 16, 1, 30, 1, "encrypt offset 30");
    fails += roundtrip(g_sak128, 16, 1, 50, 1, "encrypt offset 50");
    return fails;
}

static int test_onwire_semantics(void)
{
    struct macsec_protect_params pp;
    uint8_t payload[64];
    uint8_t frame[128];
    size_t  frame_len = 0;
    size_t  hdr_len;
    int     fails = 0;

    printf("Test 3: on-wire cleartext/ciphertext placement\n");
    fill_payload(payload, sizeof(payload), 0);

    /* Integrity-only: secure data must equal the plaintext on the wire. */
    base_protect_params(&pp, g_sak128, 16, 0, 0, 1);
    macsec_protect(&pp, payload, sizeof(payload), frame, sizeof(frame),
                   &frame_len);
    hdr_len = 12 + MACSEC_SECTAG_MAX_LEN;
    fails += expect_true(memcmp(frame + hdr_len, payload, sizeof(payload)) == 0,
                         "integrity-only leaves data in clear");

    /* Offset 30: first 30 octets cleartext, remainder encrypted. */
    base_protect_params(&pp, g_sak128, 16, 1, 30, 1);
    macsec_protect(&pp, payload, sizeof(payload), frame, sizeof(frame),
                   &frame_len);
    fails += expect_true(memcmp(frame + hdr_len, payload, 30) == 0,
                         "offset prefix stays cleartext");
    fails += expect_true(memcmp(frame + hdr_len + 30, payload + 30,
                                sizeof(payload) - 30) != 0,
                         "offset remainder is encrypted");
    return fails;
}

static int test_tamper(void)
{
    struct macsec_protect_params  pp;
    struct macsec_validate_params vp;
    struct macsec_sectag          tag;
    uint8_t payload[64];
    uint8_t frame[128];
    uint8_t good[128];
    uint8_t recovered[128];
    size_t  frame_len = 0, rec_len = 0;
    size_t  hdr_len = 12 + MACSEC_SECTAG_MAX_LEN;
    int     fails = 0;

    printf("Test 4: tamper / wrong-key rejection\n");
    fill_payload(payload, sizeof(payload), 0);
    base_protect_params(&pp, g_sak128, 16, 1, 0, 1);
    macsec_protect(&pp, payload, sizeof(payload), frame, sizeof(frame),
                   &frame_len);
    memcpy(good, frame, frame_len);

    memset(&vp, 0, sizeof(vp));
    vp.sak = g_sak128; vp.sak_len = 16; vp.sci = g_sci; vp.conf_offset = 0;

    /* Sanity: unmodified frame validates. */
    fails += expect_true(macsec_validate(&vp, good, frame_len, recovered,
                         sizeof(recovered), &rec_len, &tag) == 0,
                         "clean frame validates");

    /* Ciphertext bit flip. */
    memcpy(frame, good, frame_len); frame[hdr_len + 4] ^= 0x01;
    fails += expect_true(macsec_validate(&vp, frame, frame_len, recovered,
                         sizeof(recovered), &rec_len, &tag) != 0,
                         "ciphertext tamper rejected");
    /* ICV bit flip. */
    memcpy(frame, good, frame_len); frame[frame_len - 1] ^= 0x80;
    fails += expect_true(macsec_validate(&vp, frame, frame_len, recovered,
                         sizeof(recovered), &rec_len, &tag) != 0,
                         "ICV tamper rejected");
    /* DA (AAD) change. */
    memcpy(frame, good, frame_len); frame[0] ^= 0x01;
    fails += expect_true(macsec_validate(&vp, frame, frame_len, recovered,
                         sizeof(recovered), &rec_len, &tag) != 0,
                         "DA (AAD) tamper rejected");
    /* PN change (alters GCM nonce). */
    memcpy(frame, good, frame_len); frame[12 + 7] ^= 0x01;
    fails += expect_true(macsec_validate(&vp, frame, frame_len, recovered,
                         sizeof(recovered), &rec_len, &tag) != 0,
                         "PN tamper rejected");
    /* Wrong SAK. */
    memcpy(frame, good, frame_len); vp.sak = g_sak256; vp.sak_len = 32;
    fails += expect_true(macsec_validate(&vp, frame, frame_len, recovered,
                         sizeof(recovered), &rec_len, &tag) != 0,
                         "wrong SAK rejected");
    return fails;
}

int main(void)
{
    int fails = 0;
    setvbuf(stdout, NULL, _IONBF, 0);

    fails += test_sectag();
    fails += test_roundtrips();
    fails += test_onwire_semantics();
    fails += test_tamper();

    printf("\n%s: macsec_secy (%d failure%s)\n",
           fails == 0 ? "PASS" : "FAIL", fails, fails == 1 ? "" : "s");
    return fails == 0 ? 0 : 1;
}

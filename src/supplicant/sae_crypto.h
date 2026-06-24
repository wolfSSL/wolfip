/* sae_crypto.h
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

/* WPA3-SAE (Simultaneous Authentication of Equals) cryptography per
 * IEEE 802.11-2020 clause 12.4. Implements the dragonfly handshake:
 *
 *   1. PWE (Password Element) derivation via hunt-and-peck (v1) or
 *      hash-to-element (v2).
 *   2. Per-session ephemeral scalar/element generation (Commit phase).
 *   3. Shared-secret K computation from peer's Commit.
 *   4. KCK / PMK derivation via HKDF over k.
 *   5. Confirm MAC over the exchanged scalars + elements.
 *
 * Group 19 (NIST P-256) is implemented in v1; groups 20 (P-384) and 21
 * (P-521) follow the same code path with curve parameters from the
 * `sae_group_info` table.
 *
 * Side-channel notes: the hunt-and-peck PWE loop always runs the
 * configured minimum iteration count, even after a valid PWE is found,
 * to keep observation-channel timing flat. Computation of the secret
 * scalar/element uses RNG output; intermediate mp_int values are
 * cleared with mp_forcezero on return paths.
 */

#ifndef WOLFIP_SUPPLICANT_SAE_CRYPTO_H
#define WOLFIP_SUPPLICANT_SAE_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#include "supplicant_features.h"  /* wolfSSL config + may auto-disable SAE */
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/ecc.h>

#define SAE_GROUP_19    19      /* P-256 + SHA-256                       */
#define SAE_GROUP_20    20      /* P-384 + SHA-384                       */
#define SAE_GROUP_21    21      /* P-521 + SHA-512                       */

/* SAE Commit status code signalling Hash-to-Element (IEEE 802.11-2020
 * Table 9-50, "SAE_HASH_TO_ELEMENT"). */
#define SAE_STATUS_H2E  126

/* Compile out the legacy hunt-and-peck PWE code when only H2E is needed
 * (Wi-Fi Alliance is deprecating H&P; WPA3 R3 mandates H2E support).
 * Defaults to 1 for compatibility with existing deployments and tests.
 * Setting it to 0 saves ~600 B of text from sae_compute_pwe_hnp() and
 * makes a non-H2E SAE handshake fail at init. */
#ifndef WOLFIP_ENABLE_SAE_HNP
#define WOLFIP_ENABLE_SAE_HNP 1
#endif

#define SAE_MAX_PRIME_LEN   66  /* P-521 = 521/8 = 65, round up to 66    */
#define SAE_MAX_HASH_LEN    64  /* SHA-512                               */
#define SAE_PMK_LEN         32  /* Always 32 bytes per IEEE              */
#define SAE_MIN_HNP_ITERS   40  /* Minimum hunt-and-peck loop count      */

struct sae_group_info {
    int      group_id;       /* 19 / 20 / 21                              */
    int      wc_curve_id;    /* ECC_SECP256R1 / ...                       */
    int      hash_type;      /* WC_SHA256 / WC_SHA384 / WC_SHA512         */
    size_t   prime_len;      /* bytes to encode field elements (x/y/scalar)*/
    size_t   hash_len;       /* output bytes from hash_type               */
    size_t   h2e_field_len;  /* hash-to-field L = prime_len*3/2 (the value
                              * hostapd uses): 48 (P-256), 72 (P-384),
                              * 99 (P-521)                                 */
};

/* Per-session SAE state. */
struct sae_ctx {
    const struct sae_group_info *grp;

    /* Curve + PWE. */
    int      curve_idx;      /* index into wc_ecc_sets[]                  */
    mp_int   prime;
    mp_int   order;
    mp_int   a_coef;         /* curve a (-3 for NIST primes)              */
    mp_int   b_coef;
    mp_int   pwe_x;
    mp_int   pwe_y;

    /* H2E precomputed point: per (password, SSID), can outlive a single
     * handshake; PWE = val * PT is per-handshake. */
    mp_int   pt_x;
    mp_int   pt_y;
    int      have_pt;

    /* Commit phase. */
    mp_int   rand;
    mp_int   mask;
    mp_int   my_scalar;
    ecc_point *my_element;

    /* Peer Commit (filled by sae_parse_peer_commit). */
    mp_int   peer_scalar;
    ecc_point *peer_element;

    /* Shared. */
    mp_int   k_x;            /* x-coord of K = rand*(peer_scalar*PWE + peer_element) */

    /* Derived keys. */
    uint8_t  kck[SAE_MAX_HASH_LEN];
    uint8_t  pmk[SAE_PMK_LEN];
    uint8_t  pmkid[16];
    size_t   kck_len;

    int      have_pwe;
    int      have_commit;
    int      have_keys;

    /* PWE method selector. 0 = hunt-and-peck (all groups forced to SHA-256
     * keying). 1 = H2E (RFC 9380) - hash type follows the group. */
    int      h2e;
    /* Hash type chosen for keying (filled by sae_derive_k_and_pmk). */
    int      mac_hash_type;

    /* Pre-allocated scratch for HMAC mp_int encode in Confirm build.
     * Kept in the ctx so it doesn't land on the call stack of every
     * sae_compute_confirm / sae_verify_peer_confirm invocation. */
    uint8_t  confirm_scratch[SAE_MAX_PRIME_LEN];
};

#ifdef __cplusplus
extern "C" {
#endif

/* Look up curve parameters for a SAE group id. Returns NULL if
 * unsupported. */
const struct sae_group_info *sae_group(int group_id);

/* Initialize a SAE context for the requested group. Loads curve
 * parameters into the context's mp_ints. Returns 0 on success.
 * Caller must call sae_ctx_free regardless of return value. */
int  sae_ctx_init(struct sae_ctx *c, int group_id);

/* Free all resources. Safe to call on a partially-initialized context. */
void sae_ctx_free(struct sae_ctx *c);

#if WOLFIP_ENABLE_SAE_HNP
/* Compute the PWE via hunt-and-peck per IEEE 802.11-2020 12.4.4.2.3.
 * mac_a / mac_b are the two endpoint MAC addresses; ordering is
 * canonicalised internally (max || min). password is the SAE
 * passphrase (8..63 chars conventionally).
 *
 * The loop runs at least SAE_MIN_HNP_ITERS iterations regardless of
 * when a valid PWE is found.
 */
int  sae_compute_pwe_hnp(struct sae_ctx *c,
                         const char    *password, size_t pw_len,
                         const uint8_t  mac_a[6], const uint8_t mac_b[6]);
#endif

/* Generate this peer's Commit: rand + mask + my_scalar + my_element. */
int  sae_generate_commit(struct sae_ctx *c);

/* Serialize/parse SAE Commit body content (NO 802.11 auth header):
 *   group_id (LE u16) || scalar (prime_len) || element_x (prime_len) ||
 *   element_y (prime_len)
 */
int  sae_serialize_commit(const struct sae_ctx *c,
                          uint8_t *out, size_t out_cap, size_t *out_len);
int  sae_parse_peer_commit(struct sae_ctx *c,
                           const uint8_t *in, size_t in_len);

/* Compute the shared K (k_x stored in ctx) and derive KCK + PMK +
 * PMKID. Must be called after BOTH sae_generate_commit() AND
 * sae_parse_peer_commit() have succeeded. */
int  sae_derive_k_and_pmk(struct sae_ctx *c);

/* Test/inspection helpers. These do not depend on wolfSSL's MP_API
 * being exported (sae_crypto.c is linked alongside the test binary
 * and can use mp_* internally). */

/* Verify the PWE point in the context satisfies y^2 = x^3 + a*x + b
 * mod p. Returns 0 on match, -1 otherwise. */
int sae_pwe_is_on_curve(const struct sae_ctx *c);

/* Return 1 if the two contexts' PWE (x and y) match, 0 otherwise. */
int sae_pwe_equal(const struct sae_ctx *a, const struct sae_ctx *b);

/* WPA3-SAE H2E (Hash-to-Element) primitives. */

/* Apply the RFC 9380 6.6.2 simplified-SWU map_to_curve to a single
 * field element. u_be is big-endian (any length; reduced mod p
 * internally). x_out / y_out receive prime_len big-endian bytes of
 * the resulting affine point. */
int sae_h2e_sswu(const struct sae_ctx *c, const uint8_t *u_be, size_t u_len,
                 uint8_t *x_out, uint8_t *y_out);

/* Compute PT = SSWU(u1) + SSWU(u2) per IEEE 802.11-2020 12.4.4.2.3
 * H2E. PT is stored in c->pt_x / c->pt_y and is per (password, SSID).
 * Test wrappers can retrieve PT via sae_h2e_get_pt().
 *
 *   pwd_seed = HKDF-Extract(salt = SSID, IKM = password [|| identifier])
 *   L        = ceil((bits(q) + 64) / 8)
 *   u_i      = HKDF-Expand(pwd_seed, "SAE Hash to Element u(i) P(i)", L)
 *              mod p
 *   PT       = SSWU(u1) + SSWU(u2)
 *
 * identifier may be NULL (id_len = 0) when not used by the WPA3 deployment.
 */
int sae_h2e_compute_pt(struct sae_ctx *c,
                       const char *password, size_t pw_len,
                       const char *identifier, size_t id_len,
                       const uint8_t *ssid, size_t ssid_len);

/* Inspect the H2E PT for test/debug. Returns 0 + writes prime_len bytes
 * to x_out and y_out (big-endian), or -1 if PT is not computed. */
int sae_h2e_get_pt(const struct sae_ctx *c, uint8_t *x_out, uint8_t *y_out);

/* Compute the per-handshake H2E PWE = val * PT, where
 *   val = (HMAC-H(zero, MAX(MAC_A,MAC_B) || MIN(MAC_A,MAC_B))
 *           mod (q-1)) + 1
 * H is the group's hash function and q is the curve order. PT must
 * already be populated via sae_h2e_compute_pt(). Stores the resulting
 * PWE in c->pwe_x / c->pwe_y and sets c->have_pwe so the rest of the
 * dragonfly handshake (sae_generate_commit etc.) works unchanged. */
int sae_compute_pwe_h2e(struct sae_ctx *c,
                        const uint8_t mac_a[6], const uint8_t mac_b[6]);

/* Compute / verify the SAE Confirm MAC. The MAC is taken over:
 *   send_confirm (LE u16) || my_scalar || my_elem.x || my_elem.y ||
 *   peer_scalar || peer_elem.x || peer_elem.y
 *
 * out_mac receives hash_len bytes. For verify, peer_mac is the
 * verifier provided by the peer.
 */
int  sae_compute_confirm(const struct sae_ctx *c, uint16_t send_confirm,
                         uint8_t *out_mac, size_t mac_cap, size_t *out_len);
int  sae_verify_peer_confirm(const struct sae_ctx *c, uint16_t recv_confirm,
                             const uint8_t *peer_mac, size_t peer_mac_len);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_SUPPLICANT_SAE_CRYPTO_H */

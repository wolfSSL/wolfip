/* sae_crypto.c
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

#include "sae_crypto.h"

#include <string.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/kdf.h>

/* Body-gated so an auto-disabled SAE (see supplicant_features.h) compiles
 * to an empty object instead of referencing unavailable ECC/HKDF. */
#if defined(WOLFIP_ENABLE_SAE) && WOLFIP_ENABLE_SAE

/* SAE group lookup table. Maps a SAE group id to the wolfCrypt curve
 * id, hash type for HKDF/HMAC, and field/order/element byte lengths.
 *
 * Groups are sized in bytes per IEEE 802.11-2020 (P-521's 521-bit
 * field uses 66 bytes per element with leading zero padding).
 */
static const struct sae_group_info SAE_GROUPS[] = {
    /* h2e_field_len = prime_len * 3/2 (the L hostapd uses): 48, 72, 99. */
    /* { group, curve, hash, prime_len, hash_len, h2e_field_len }; prime_len
     * and h2e_field_len are curve-defined byte counts (kept numeric). */
    { SAE_GROUP_19, ECC_SECP256R1, WC_SHA256, 32, WC_SHA256_DIGEST_SIZE, 48 },
    { SAE_GROUP_20, ECC_SECP384R1, WC_SHA384, 48, WC_SHA384_DIGEST_SIZE, 72 },
    { SAE_GROUP_21, ECC_SECP521R1, WC_SHA512, 66, WC_SHA512_DIGEST_SIZE, 99 },
};

const struct sae_group_info *sae_group(int group_id)
{
    size_t i;
    for (i = 0; i < sizeof(SAE_GROUPS) / sizeof(SAE_GROUPS[0]); i++) {
        if (SAE_GROUPS[i].group_id == group_id) {
            return &SAE_GROUPS[i];
        }
    }
    return NULL;
}

/* ---- helpers ---- */

/* Parse a hex string from wc_ecc_sets[].prime/Af/... into an mp_int. */
static int parse_hex_mp(mp_int *out, const char *hex_str)
{
    int ret;
    ret = mp_init(out);
    if (ret != MP_OKAY) return ret;
    return mp_read_radix(out, hex_str, MP_RADIX_HEX);
}

/* Lexicographic max(a, b) || min(a, b) where a, b are 6-byte MACs.
 * Used as the HKDF salt for PWE derivation. */
static void mac_concat_max_min(const uint8_t a[6], const uint8_t b[6],
                               uint8_t out[12])
{
    int cmp = memcmp(a, b, 6);
    if (cmp >= 0) {
        memcpy(out, a, 6);
        memcpy(out + 6, b, 6);
    }
    else {
        memcpy(out, b, 6);
        memcpy(out + 6, a, 6);
    }
}

/* Compute v = (x^3 + a*x + b) mod p. Output into v_out (pre-initialized). */
static int curve_rhs(const mp_int *x,
                     const mp_int *a, const mp_int *b, const mp_int *p,
                     mp_int *v_out)
{
    mp_int t1, t2;
    int    ret;

    ret = mp_init_multi(&t1, &t2, NULL, NULL, NULL, NULL);
    if (ret != MP_OKAY) return ret;

    /* t1 = x^2 mod p */
    ret = mp_sqrmod((mp_int *)x, (mp_int *)p, &t1);
    if (ret != MP_OKAY) goto out;
    /* t1 = x^3 mod p */
    ret = mp_mulmod(&t1, (mp_int *)x, (mp_int *)p, &t1);
    if (ret != MP_OKAY) goto out;
    /* t2 = a*x mod p */
    ret = mp_mulmod((mp_int *)a, (mp_int *)x, (mp_int *)p, &t2);
    if (ret != MP_OKAY) goto out;
    /* v = t1 + t2 + b mod p */
    ret = mp_addmod(&t1, &t2, (mp_int *)p, v_out);
    if (ret != MP_OKAY) goto out;
    ret = mp_addmod(v_out, (mp_int *)b, (mp_int *)p, v_out);

out:
    mp_clear(&t1);
    mp_clear(&t2);
    return ret;
}

/* Compute sqrt(v) mod p assuming p mod 4 == 3 (true for NIST P-256/384/521):
 *   sqrt(v) = v^((p+1)/4) mod p
 * Returns 0 on success and verifies by squaring.
 * Caller must pre-init y_out. */
static int sqrt_mod_p(const mp_int *v, const mp_int *p, mp_int *y_out)
{
    mp_int exp, check;
    int    ret;

    ret = mp_init_multi(&exp, &check, NULL, NULL, NULL, NULL);
    if (ret != MP_OKAY) return ret;

    /* exp = (p+1)/4 */
    ret = mp_add_d((mp_int *)p, 1, &exp);
    if (ret != MP_OKAY) goto out;
    ret = mp_div_2d(&exp, 2, &exp, NULL);
    if (ret != MP_OKAY) goto out;

    ret = mp_exptmod((mp_int *)v, &exp, (mp_int *)p, y_out);
    if (ret != MP_OKAY) goto out;

    /* Verify: y^2 mod p == v */
    ret = mp_sqrmod(y_out, (mp_int *)p, &check);
    if (ret != MP_OKAY) goto out;
    if (mp_cmp(&check, (mp_int *)v) != MP_EQ) {
        ret = -1; /* not a QR */
    }
out:
    mp_clear(&exp);
    mp_clear(&check);
    return ret;
}

/* Quadratic-residue test: return 1 if v is a QR mod p, 0 otherwise.
 * Uses Euler's criterion: v^((p-1)/2) == 1 (mod p). */
static int is_quadratic_residue(const mp_int *v, const mp_int *p)
{
    mp_int exp, r;
    int    ret, qr = 0;

    if (mp_init_multi(&exp, &r, NULL, NULL, NULL, NULL) != MP_OKAY) {
        return 0;
    }
    /* exp = (p-1)/2 */
    if (mp_sub_d((mp_int *)p, 1, &exp) != MP_OKAY) goto out;
    if (mp_div_2d(&exp, 1, &exp, NULL) != MP_OKAY) goto out;

    ret = mp_exptmod((mp_int *)v, &exp, (mp_int *)p, &r);
    if (ret == MP_OKAY) {
        qr = (mp_cmp_d(&r, 1) == MP_EQ) ? 1 : 0;
    }
out:
    mp_clear(&exp);
    mp_clear(&r);
    return qr;
}

/* ---- init / free ---- */

int sae_ctx_init(struct sae_ctx *c, int group_id)
{
    const ecc_set_type *dp;
    int                  idx;
    int                  ret;

    if (c == NULL) return BAD_FUNC_ARG;
    memset(c, 0, sizeof(*c));

    c->grp = sae_group(group_id);
    if (c->grp == NULL) {
        return BAD_FUNC_ARG;
    }

    idx = wc_ecc_get_curve_idx(c->grp->wc_curve_id);
    if (idx < 0) {
        return idx;
    }
    c->curve_idx = idx;
    dp = wc_ecc_get_curve_params(idx);
    if (dp == NULL) {
        return -1;
    }

    ret = parse_hex_mp(&c->prime,  dp->prime);
    if (ret == MP_OKAY) ret = parse_hex_mp(&c->order, dp->order);
    if (ret == MP_OKAY) ret = parse_hex_mp(&c->a_coef, dp->Af);
    if (ret == MP_OKAY) ret = parse_hex_mp(&c->b_coef, dp->Bf);
    if (ret == MP_OKAY) ret = mp_init_multi(&c->pwe_x, &c->pwe_y,
                                            &c->rand, &c->mask,
                                            &c->my_scalar, &c->peer_scalar);
    if (ret == MP_OKAY) ret = mp_init(&c->k_x);
    if (ret == MP_OKAY) ret = mp_init_multi(&c->pt_x, &c->pt_y,
                                            NULL, NULL, NULL, NULL);
    if (ret != MP_OKAY) {
        return ret;
    }

    c->my_element   = wc_ecc_new_point();
    c->peer_element = wc_ecc_new_point();
    if (c->my_element == NULL || c->peer_element == NULL) {
        return MEMORY_E;
    }
    c->kck_len = c->grp->hash_len;
    return 0;
}

void sae_ctx_free(struct sae_ctx *c)
{
    if (c == NULL) return;
    if (c->my_element)   wc_ecc_del_point(c->my_element);
    if (c->peer_element) wc_ecc_del_point(c->peer_element);

    mp_forcezero(&c->rand);
    mp_forcezero(&c->mask);
    mp_forcezero(&c->my_scalar);
    mp_forcezero(&c->peer_scalar);
    mp_forcezero(&c->k_x);
    mp_forcezero(&c->pwe_x);
    mp_forcezero(&c->pwe_y);
    mp_clear(&c->pt_x);
    mp_clear(&c->pt_y);
    mp_clear(&c->prime);
    mp_clear(&c->order);
    mp_clear(&c->a_coef);
    mp_clear(&c->b_coef);
    if (c->kck_len > 0) wc_ForceZero(c->kck, c->kck_len);
    wc_ForceZero(c->pmk, sizeof(c->pmk));
    wc_ForceZero(c->pmkid, sizeof(c->pmkid));
    memset(c, 0, sizeof(*c));
}

/* ---- PWE via hunt-and-peck ---- */

/* IEEE 802.11 KDF-Hash-Length; full definition further below. */
static int ieee80211_kdf(int hash_type,
                         const uint8_t *key, size_t key_len,
                         const char    *label,
                         const uint8_t *context, size_t context_len,
                         uint8_t *out, size_t bits_out);

#if WOLFIP_ENABLE_SAE_HNP
/* Shift a big-endian octet buffer right by `bits` (1..7) in place. Matches
 * hostapd's buf_shift_right(): the IEEE 802.11 KDF emits a bit string whose
 * valid bits are left-aligned, so for a field whose prime is not a multiple
 * of 8 bits (P-521 = 521 bits) the SAE pwd-value must be right-shifted by
 * (8 - prime_bits % 8) to become a right-aligned integer before the < p
 * compare. The garbage low bits in the last octet are discarded by the
 * shift. P-256/P-384 are byte-aligned (bits == 0) and skip this. */
static void sae_buf_shift_right(uint8_t *buf, size_t len, size_t bits)
{
    size_t i;
    if (bits == 0 || len == 0) {
        return;
    }
    for (i = len - 1; i > 0; i--) {
        buf[i] = (uint8_t)((buf[i] >> bits) | (buf[i - 1] << (8 - bits)));
    }
    buf[0] = (uint8_t)(buf[0] >> bits);
}

/* Find a small quadratic non-residue mod p, used to blind the per-iteration
 * QR test below. The search probes the constants 2,3,5,... (independent of
 * the password), so its variable timing leaks nothing secret. */
static int sae_find_qnr(const mp_int *p, mp_int *qnr)
{
    mp_int cand;
    int    ret = -1;
    int    i;

    if (mp_init(&cand) != MP_OKAY) {
        return -1;
    }
    for (i = 2; i < 1000; i++) {
        if (mp_set(&cand, (mp_digit)i) != MP_OKAY) {
            break;
        }
        if (!is_quadratic_residue(&cand, p)) {
            ret = (mp_copy(&cand, qnr) == MP_OKAY) ? 0 : -1;
            break;
        }
    }
    mp_clear(&cand);
    return ret;
}

/* Blinded quadratic-residue test (RFC 7664 12.4.4.2.2 / "Dragonfly"
 * CVE-2019-9494 mitigation). Sets *is_qr to 1 iff v is a QR mod p, with the
 * value handed to the modular exponentiation randomized (v * r^2, optionally
 * times a known non-residue) so the exptmod timing does not correlate with
 * v - i.e. it does not leak which hunt-and-peck counter produced the PWE.
 * qnr is a known quadratic non-residue mod p. Returns 0 on success. */
static int sae_qr_blind(const mp_int *v, const mp_int *p, const mp_int *qnr,
                        WC_RNG *rng, size_t prime_len, int *is_qr)
{
    mp_int  r, num, exp, res;
    uint8_t rb[SAE_MAX_PRIME_LEN];
    uint8_t bit = 0;
    int     leg_one;
    int     ret;

    *is_qr = 0;
    if (mp_init_multi(&r, &num, &exp, &res, NULL, NULL) != MP_OKAY) {
        return -1;
    }
    /* r uniform in [1, p-1]. */
    do {
        ret = wc_RNG_GenerateBlock(rng, rb, (word32)prime_len);
        if (ret != 0) goto out;
        ret = mp_read_unsigned_bin(&r, rb, (int)prime_len);
        if (ret != MP_OKAY) goto out;
        ret = mp_mod(&r, (mp_int *)p, &r);
        if (ret != MP_OKAY) goto out;
    } while (mp_iszero(&r) == MP_YES);

    /* num = v * r^2 mod p (r^2 is a QR, so QR(num) == QR(v)). */
    ret = mp_sqrmod(&r, (mp_int *)p, &num);
    if (ret == MP_OKAY) ret = mp_mulmod((mp_int *)v, &num, (mp_int *)p, &num);
    if (ret != MP_OKAY) goto out;

    /* With probability 1/2 multiply by the known non-residue, flipping the
     * class, and adjust the expected Legendre symbol accordingly - so the
     * raw exptmod output is equally likely 1 or p-1 regardless of QR(v). */
    ret = wc_RNG_GenerateBlock(rng, &bit, 1);
    if (ret != 0) goto out;
    bit &= 1U;
    if (bit) {
        ret = mp_mulmod(&num, (mp_int *)qnr, (mp_int *)p, &num);
        if (ret != MP_OKAY) goto out;
    }
    /* Legendre symbol: num^((p-1)/2) mod p (1 = residue, p-1 = non-residue). */
    ret = mp_sub_d((mp_int *)p, 1, &exp);
    if (ret == MP_OKAY) ret = mp_div_2d(&exp, 1, &exp, NULL);
    if (ret == MP_OKAY) ret = mp_exptmod(&num, &exp, (mp_int *)p, &res);
    if (ret != MP_OKAY) goto out;
    leg_one = (mp_cmp_d(&res, 1) == MP_EQ) ? 1 : 0;
    *is_qr = bit ? (leg_one ? 0 : 1) : (leg_one ? 1 : 0);
    ret = 0;
out:
    mp_forcezero(&r);
    mp_clear(&num);
    mp_clear(&exp);
    mp_clear(&res);
    wc_ForceZero(rb, sizeof(rb));
    return ret;
}

int sae_compute_pwe_hnp(struct sae_ctx *c,
                        const char    *password, size_t pw_len,
                        const uint8_t  mac_a[6], const uint8_t mac_b[6])
{
    /* IEEE 802.11-2020 12.4.4.3.2: pwd-value = KDF-Hash-Length(pwd-seed,
     * "SAE Hunting and Pecking", p). The KDF is the IEEE 802.11 KDF (the
     * i||label||context||L construction in ieee80211_kdf), NOT RFC 5869
     * HKDF-Expand. Label and KDF both verified byte-for-byte against
     * hostapd's SAE (-K key dump). */
    static const char LABEL[] = "SAE Hunting and Pecking";
    uint8_t  salt[12];
    uint8_t  ikm[128];      /* password || counter byte               */
    uint8_t  pwd_seed[SAE_MAX_HASH_LEN];
    uint8_t  pwd_value[SAE_MAX_PRIME_LEN];
    uint8_t  prime_be[SAE_MAX_PRIME_LEN]; /* KDF context = p (BE, padded) */
    uint8_t  save_x_be[SAE_MAX_PRIME_LEN]; /* CT-selected PWE x (BE)      */
    mp_int   x_candidate, v, save_x, save_y, qnr;
    WC_RNG   rng;
    int      rng_ok = 0;
    int      ret;
    int      found = 0;
    uint8_t  save_parity = 0;
    uint8_t  counter;
    size_t   prime_len;
    size_t   i_size;
    int      hash_type;

    if (c == NULL || c->grp == NULL || password == NULL
        || pw_len == 0 || pw_len > 64) {
        return BAD_FUNC_ARG;
    }
    prime_len = c->grp->prime_len;
    /* Hunt-and-peck uses a FIXED SHA-256 for pwd-seed/pwd-value across all
     * groups (legacy IEEE 802.11-2016 behavior that hostapd keeps), unlike
     * H2E which uses the per-group hash. The keyseed/KCK (sae_derive_k_and_
     * pmk) likewise forces SHA-256 in H&P mode, so the two stay consistent. */
    hash_type = WC_SHA256;

    /* salt = max(mac_a, mac_b) || min(...) */
    mac_concat_max_min(mac_a, mac_b, salt);

    /* KDF context = big-endian prime bytes (padded to prime_len). */
    i_size = mp_unsigned_bin_size(&c->prime);
    if (i_size > prime_len) {
        return BUFFER_E;
    }
    memset(prime_be, 0, prime_len - i_size);
    ret = mp_to_unsigned_bin(&c->prime, prime_be + prime_len - i_size);
    if (ret != MP_OKAY) return ret;

    ret = mp_init_multi(&x_candidate, &v, &save_x, &save_y, &qnr, NULL);
    if (ret != MP_OKAY) return ret;

    /* Dragonfly (CVE-2019-9494) constant-time mitigation: run ALL
     * SAE_MIN_HNP_ITERS iterations unconditionally, test each candidate with
     * a blinded QR test, and constant-time-select the FIRST valid (x,
     * parity) into save_x_be/save_parity. No early break and no
     * data-dependent save branch, so the timing does not reveal which
     * counter produced the PWE. The QNR is derived from public constants. */
    ret = sae_find_qnr(&c->prime, &qnr);
    if (ret != 0) goto out;
    if (wc_InitRng(&rng) != 0) { ret = -1; goto out; }
    rng_ok = 1;
    memset(save_x_be, 0, sizeof(save_x_be));

    for (counter = 1; counter <= SAE_MIN_HNP_ITERS; counter++) {
        size_t  ikm_len, i;
        int     in_range, is_qr, valid, is_first;
        int     prime_bits, rem;
        uint8_t mask, pbit, mbit, xb[SAE_MAX_PRIME_LEN];
        mp_int  xr;

        /* ikm = password || counter (single byte) */
        if (pw_len + 1U > sizeof(ikm)) { ret = BUFFER_E; goto out; }
        memcpy(ikm, password, pw_len);
        ikm[pw_len] = counter;
        ikm_len = pw_len + 1U;

        /* pwd_seed = HKDF-Extract(salt, ikm); pwd_value = IEEE KDF. */
        ret = wc_HKDF_Extract(hash_type, salt, sizeof(salt),
                              ikm, (word32)ikm_len, pwd_seed);
        if (ret != 0) goto out;
        ret = ieee80211_kdf(hash_type, pwd_seed, WC_SHA256_DIGEST_SIZE,
                            LABEL, prime_be, prime_len,
                            pwd_value, (size_t)mp_count_bits(&c->prime));
        if (ret != 0) goto out;
        /* Right-align the left-aligned KDF bits for non-byte-aligned primes
         * (P-521); no-op for P-256/P-384 (see sae_buf_shift_right). */
        prime_bits = mp_count_bits(&c->prime);
        rem        = prime_bits % 8;
        if (rem != 0) {
            sae_buf_shift_right(pwd_value, prime_len, (size_t)(8 - rem));
        }
        ret = mp_read_unsigned_bin(&x_candidate, pwd_value, (int)prime_len);
        if (ret != MP_OKAY) goto out;

        in_range = (mp_cmp(&x_candidate, &c->prime) == MP_LT) ? 1 : 0;
        /* v = x^3 + a*x + b mod p. Reduce x mod p first so curve_rhs is
         * well-defined even for an out-of-range candidate (its result is
         * discarded by the constant-time select below when in_range == 0). */
        if (mp_init(&xr) != MP_OKAY) { ret = -1; goto out; }
        ret = mp_mod(&x_candidate, &c->prime, &xr);
        if (ret == MP_OKAY) {
            ret = curve_rhs(&xr, &c->a_coef, &c->b_coef, &c->prime, &v);
        }
        mp_clear(&xr);
        if (ret != 0) goto out;

        is_qr = 0;
        ret = sae_qr_blind(&v, &c->prime, &qnr, &rng, prime_len, &is_qr);
        if (ret != 0) goto out;

        valid    = in_range & is_qr;
        is_first = valid & (found ^ 1);
        found   |= valid;

        /* Constant-time select of x (big-endian) + the SHA-256 parity bit
         * (pwd_seed byte 31) on the first valid counter only. */
        if (mp_to_unsigned_bin_len(&x_candidate, xb, (int)prime_len)
                != MP_OKAY) { ret = -1; goto out; }
        mask = (uint8_t)(0U - (uint8_t)is_first);   /* 0xFF if first else 0 */
        for (i = 0; i < prime_len; i++) {
            save_x_be[i] = (uint8_t)((save_x_be[i] & (uint8_t)~mask)
                                     | (xb[i] & mask));
        }
        pbit = (uint8_t)(pwd_seed[WC_SHA256_DIGEST_SIZE - 1] & 1U);
        mbit = (uint8_t)(mask & 1U);
        save_parity = (uint8_t)((save_parity & (uint8_t)~mbit)
                                | (pbit & mbit));
        wc_ForceZero(xb, sizeof(xb));
        wc_ForceZero(pwd_seed, sizeof(pwd_seed));
        wc_ForceZero(pwd_value, sizeof(pwd_value));
    }
    if (!found) { ret = -1; goto out; }

    /* Recover the chosen PWE: x = save_x_be, y = sqrt(x^3+ax+b) with the
     * saved parity. */
    ret = mp_read_unsigned_bin(&save_x, save_x_be, (int)prime_len);
    if (ret != MP_OKAY) goto out;
    ret = curve_rhs(&save_x, &c->a_coef, &c->b_coef, &c->prime, &v);
    if (ret != 0) goto out;
    ret = sqrt_mod_p(&v, &c->prime, &save_y);
    if (ret != 0) goto out;
    if ((int)(save_parity & 1U) != mp_isodd(&save_y)) {
        mp_int neg;
        if (mp_init(&neg) != MP_OKAY) { ret = -1; goto out; }
        if (mp_sub(&c->prime, &save_y, &neg) != MP_OKAY
            || mp_copy(&neg, &save_y) != MP_OKAY) {
            mp_clear(&neg); ret = -1; goto out;
        }
        mp_clear(&neg);
    }
    if (mp_copy(&save_x, &c->pwe_x) != MP_OKAY
        || mp_copy(&save_y, &c->pwe_y) != MP_OKAY) {
        ret = -1; goto out;
    }
    c->have_pwe = 1;
    ret = 0;

out:
    if (rng_ok) wc_FreeRng(&rng);
    wc_ForceZero(ikm, sizeof(ikm));
    wc_ForceZero(pwd_seed, sizeof(pwd_seed));
    wc_ForceZero(pwd_value, sizeof(pwd_value));
    wc_ForceZero(save_x_be, sizeof(save_x_be));
    mp_forcezero(&x_candidate);
    mp_forcezero(&v);
    mp_forcezero(&save_x);
    mp_forcezero(&save_y);
    mp_forcezero(&qnr);
    return ret;
}
#endif /* WOLFIP_ENABLE_SAE_HNP */

/* ---- test/inspection helpers (avoid forcing WOLFSSL_PUBLIC_MP on
 *      consumers of the test binary) ---- */

int sae_pwe_is_on_curve(const struct sae_ctx *c)
{
    mp_int lhs, rhs, t1;
    int    rv = -1;

    if (c == NULL || !c->have_pwe) return -1;
    if (mp_init_multi(&lhs, &rhs, &t1, NULL, NULL, NULL) != MP_OKAY) {
        return -1;
    }
    if (mp_sqrmod((mp_int *)&c->pwe_y, (mp_int *)&c->prime, &lhs) != MP_OKAY)
        goto out;
    if (mp_sqrmod((mp_int *)&c->pwe_x, (mp_int *)&c->prime, &t1)  != MP_OKAY)
        goto out;
    if (mp_mulmod(&t1, (mp_int *)&c->pwe_x,
                  (mp_int *)&c->prime, &t1) != MP_OKAY) goto out;
    if (mp_mulmod((mp_int *)&c->a_coef, (mp_int *)&c->pwe_x,
                  (mp_int *)&c->prime, &rhs) != MP_OKAY) goto out;
    if (mp_addmod(&t1, &rhs, (mp_int *)&c->prime, &rhs) != MP_OKAY) goto out;
    if (mp_addmod(&rhs, (mp_int *)&c->b_coef,
                  (mp_int *)&c->prime, &rhs) != MP_OKAY) goto out;
    rv = (mp_cmp(&lhs, &rhs) == MP_EQ) ? 0 : -1;
out:
    mp_clear(&lhs); mp_clear(&rhs); mp_clear(&t1);
    return rv;
}

int sae_pwe_equal(const struct sae_ctx *a, const struct sae_ctx *b)
{
    if (a == NULL || b == NULL || !a->have_pwe || !b->have_pwe) return 0;
    return (mp_cmp((mp_int *)&a->pwe_x, (mp_int *)&b->pwe_x) == MP_EQ
         && mp_cmp((mp_int *)&a->pwe_y, (mp_int *)&b->pwe_y) == MP_EQ) ? 1 : 0;
}

/* ---- affine point arithmetic over y^2 = x^3 + a*x + b mod p ----
 *
 * wolfCrypt's internal ecc_projective_add_point is not exported by the
 * shared library on this build; we implement the (relatively simple)
 * affine formulas directly. Identity is encoded by storing 0 in P.z.
 */

static int ec_pt_is_identity(const ecc_point *P)
{
    return mp_iszero((mp_int *)P->z);
}

static int ec_pt_set_identity(ecc_point *P)
{
    mp_zero(P->x);
    mp_zero(P->y);
    mp_zero(P->z);
    return 0;
}

static int ec_pt_set_affine(ecc_point *P, const mp_int *x, const mp_int *y)
{
    int ret;
    ret = mp_copy((mp_int *)x, P->x);
    if (ret == MP_OKAY) ret = mp_copy((mp_int *)y, P->y);
    if (ret == MP_OKAY) ret = mp_set(P->z, 1);
    return ret;
}

/* Negate an affine point: (x, y) -> (x, p - y). */
static int ec_pt_neg(ecc_point *P, const mp_int *p)
{
    mp_int neg_y;
    int ret;
    if (mp_iszero(P->y)) return 0; /* y == 0: -P == P */
    ret = mp_init(&neg_y);
    if (ret != MP_OKAY) return ret;
    ret = mp_sub((mp_int *)p, P->y, &neg_y);
    if (ret == MP_OKAY) ret = mp_copy(&neg_y, P->y);
    mp_clear(&neg_y);
    return ret;
}

/* R = 2P on the curve y^2 = x^3 + a*x + b mod p. R may alias P. */
static int ec_pt_dbl(const ecc_point *P, ecc_point *R,
                     const mp_int *a, const mp_int *p)
{
    mp_int slope, t1, t2, x3;
    int    ret;

    if (ec_pt_is_identity(P) || mp_iszero(P->y)) {
        return ec_pt_set_identity(R);
    }
    ret = mp_init_multi(&slope, &t1, &t2, &x3, NULL, NULL);
    if (ret != MP_OKAY) return ret;

    /* slope = (3*x^2 + a) * (2*y)^(-1) mod p */
    ret = mp_sqrmod((mp_int *)P->x, (mp_int *)p, &t1);
    if (ret == MP_OKAY) ret = mp_addmod(&t1, &t1, (mp_int *)p, &t2);
    if (ret == MP_OKAY) ret = mp_addmod(&t2, &t1, (mp_int *)p, &t1);
    if (ret == MP_OKAY) ret = mp_addmod(&t1, (mp_int *)a, (mp_int *)p, &t1);
    if (ret == MP_OKAY) ret = mp_addmod((mp_int *)P->y, (mp_int *)P->y,
                                        (mp_int *)p, &t2);
    if (ret == MP_OKAY) ret = mp_invmod(&t2, (mp_int *)p, &t2);
    if (ret == MP_OKAY) ret = mp_mulmod(&t1, &t2, (mp_int *)p, &slope);
    if (ret != MP_OKAY) goto out;

    /* x3 = slope^2 - 2*x mod p */
    ret = mp_sqrmod(&slope, (mp_int *)p, &x3);
    if (ret == MP_OKAY) ret = mp_submod(&x3, (mp_int *)P->x,
                                        (mp_int *)p, &x3);
    if (ret == MP_OKAY) ret = mp_submod(&x3, (mp_int *)P->x,
                                        (mp_int *)p, &x3);
    /* y3 = slope * (x - x3) - y mod p */
    if (ret == MP_OKAY) ret = mp_submod((mp_int *)P->x, &x3,
                                        (mp_int *)p, &t1);
    if (ret == MP_OKAY) ret = mp_mulmod(&slope, &t1, (mp_int *)p, &t1);
    if (ret == MP_OKAY) ret = mp_submod(&t1, (mp_int *)P->y,
                                        (mp_int *)p, &t2);
    if (ret == MP_OKAY) ret = mp_copy(&x3, R->x);
    if (ret == MP_OKAY) ret = mp_copy(&t2, R->y);
    if (ret == MP_OKAY) ret = mp_set(R->z, 1);
out:
    mp_clear(&slope); mp_clear(&t1); mp_clear(&t2); mp_clear(&x3);
    return ret;
}

/* R = P + Q on the curve. R may alias P or Q. Handles identity + 2P case. */
static int ec_pt_add(const ecc_point *P, const ecc_point *Q, ecc_point *R,
                     const mp_int *a, const mp_int *p)
{
    mp_int slope, t1, t2, x3;
    int    ret;

    if (ec_pt_is_identity(P)) {
        ret = mp_copy((mp_int *)Q->x, R->x);
        if (ret == MP_OKAY) ret = mp_copy((mp_int *)Q->y, R->y);
        if (ret == MP_OKAY) ret = mp_copy((mp_int *)Q->z, R->z);
        return ret;
    }
    if (ec_pt_is_identity(Q)) {
        ret = mp_copy((mp_int *)P->x, R->x);
        if (ret == MP_OKAY) ret = mp_copy((mp_int *)P->y, R->y);
        if (ret == MP_OKAY) ret = mp_copy((mp_int *)P->z, R->z);
        return ret;
    }
    if (mp_cmp((mp_int *)P->x, (mp_int *)Q->x) == MP_EQ) {
        mp_int sum_y;
        if (mp_cmp((mp_int *)P->y, (mp_int *)Q->y) == MP_EQ) {
            return ec_pt_dbl(P, R, a, p);
        }
        /* P == -Q -> identity */
        ret = mp_init(&sum_y);
        if (ret == MP_OKAY) ret = mp_addmod((mp_int *)P->y, (mp_int *)Q->y,
                                            (mp_int *)p, &sum_y);
        if (ret == MP_OKAY && mp_iszero(&sum_y)) {
            mp_clear(&sum_y);
            return ec_pt_set_identity(R);
        }
        mp_clear(&sum_y);
        return -1;
    }
    ret = mp_init_multi(&slope, &t1, &t2, &x3, NULL, NULL);
    if (ret != MP_OKAY) return ret;

    /* slope = (Qy - Py) * (Qx - Px)^-1 mod p */
    ret = mp_submod((mp_int *)Q->y, (mp_int *)P->y, (mp_int *)p, &t1);
    if (ret == MP_OKAY) ret = mp_submod((mp_int *)Q->x, (mp_int *)P->x,
                                        (mp_int *)p, &t2);
    if (ret == MP_OKAY) ret = mp_invmod(&t2, (mp_int *)p, &t2);
    if (ret == MP_OKAY) ret = mp_mulmod(&t1, &t2, (mp_int *)p, &slope);
    if (ret != MP_OKAY) goto out;

    ret = mp_sqrmod(&slope, (mp_int *)p, &x3);
    if (ret == MP_OKAY) ret = mp_submod(&x3, (mp_int *)P->x,
                                        (mp_int *)p, &x3);
    if (ret == MP_OKAY) ret = mp_submod(&x3, (mp_int *)Q->x,
                                        (mp_int *)p, &x3);
    if (ret == MP_OKAY) ret = mp_submod((mp_int *)P->x, &x3,
                                        (mp_int *)p, &t1);
    if (ret == MP_OKAY) ret = mp_mulmod(&slope, &t1, (mp_int *)p, &t1);
    if (ret == MP_OKAY) ret = mp_submod(&t1, (mp_int *)P->y,
                                        (mp_int *)p, &t2);
    if (ret == MP_OKAY) ret = mp_copy(&x3, R->x);
    if (ret == MP_OKAY) ret = mp_copy(&t2, R->y);
    if (ret == MP_OKAY) ret = mp_set(R->z, 1);
out:
    mp_clear(&slope); mp_clear(&t1); mp_clear(&t2); mp_clear(&x3);
    return ret;
}

/* Convenience: mp_int random in [2, q-1]. Masks high byte to the order's
 * bit length when it's not a multiple of 8 (e.g., P-521 / 521 bits). */
static int rand_mpz_in_range(mp_int *out, const mp_int *q,
                             size_t qlen_bytes)
{
    WC_RNG  rng;
    uint8_t buf[SAE_MAX_PRIME_LEN];
    int     ret;
    int     i;
    int     q_bits;
    int     rem;

    if (qlen_bytes > sizeof(buf)) return BUFFER_E;
    ret = wc_InitRng(&rng);
    if (ret != 0) return ret;

    q_bits = mp_count_bits((mp_int *)q);
    rem    = q_bits % 8;

    for (i = 0; i < 64; i++) {
        ret = wc_RNG_GenerateBlock(&rng, buf, (word32)qlen_bytes);
        if (ret != 0) break;
        if (rem != 0) {
            buf[0] = (uint8_t)(buf[0] & (0xFF >> (8 - rem)));
        }
        ret = mp_read_unsigned_bin(out, buf, (int)qlen_bytes);
        if (ret != MP_OKAY) break;
        if (mp_cmp(out, (mp_int *)q) == MP_LT && mp_cmp_d(out, 1) == MP_GT) {
            wc_FreeRng(&rng);
            wc_ForceZero(buf, sizeof(buf));
            return 0;
        }
    }
    wc_FreeRng(&rng);
    wc_ForceZero(buf, sizeof(buf));
    return -1;
}

int sae_generate_commit(struct sae_ctx *c)
{
    ecc_point *PWE = NULL;
    ecc_point *elem_pos = NULL;
    int      ret;

    if (c == NULL || !c->have_pwe) return BAD_FUNC_ARG;

    /* Pick rand and mask in [2, q-1]. */
    ret = rand_mpz_in_range(&c->rand, &c->order, c->grp->prime_len);
    if (ret != 0) goto out;
    ret = rand_mpz_in_range(&c->mask, &c->order, c->grp->prime_len);
    if (ret != 0) goto out;

    /* my_scalar = (rand + mask) mod q. Verify > 1. */
    ret = mp_addmod(&c->rand, &c->mask, &c->order, &c->my_scalar);
    if (ret != MP_OKAY) goto out;
    if (mp_cmp_d(&c->my_scalar, 1) != MP_GT) {
        ret = -1; goto out;
    }

    /* my_element = -mask * PWE = mask*PWE then negate y. */
    PWE = wc_ecc_new_point();
    elem_pos = wc_ecc_new_point();
    if (PWE == NULL || elem_pos == NULL) { ret = MEMORY_E; goto out; }
    ret = ec_pt_set_affine(PWE, &c->pwe_x, &c->pwe_y);
    if (ret != MP_OKAY) goto out;
    ret = wc_ecc_mulmod(&c->mask, PWE, elem_pos,
                        &c->a_coef, &c->prime, 1);
    if (ret != MP_OKAY) goto out;
    ret = wc_ecc_copy_point(elem_pos, c->my_element);
    if (ret != MP_OKAY) goto out;
    ret = ec_pt_neg(c->my_element, &c->prime);
    if (ret != MP_OKAY) goto out;

    c->have_commit = 1;
    ret = 0;
out:
    if (PWE) wc_ecc_del_point(PWE);
    if (elem_pos) wc_ecc_del_point(elem_pos);
    return ret;
}

/* Serialize Commit body: group_id (LE u16) || scalar (prime_len BE) ||
 * element_x (prime_len BE) || element_y (prime_len BE). */
int sae_serialize_commit(const struct sae_ctx *c,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t need;
    size_t pl;
    int    ret;

    if (c == NULL || out == NULL || out_len == NULL || !c->have_commit) {
        return BAD_FUNC_ARG;
    }
    pl = c->grp->prime_len;
    need = 2U + pl + 2U * pl;
    if (need > out_cap) return BUFFER_E;

    out[0] = (uint8_t)(c->grp->group_id & 0xFFU);
    out[1] = (uint8_t)((c->grp->group_id >> 8) & 0xFFU);

    /* my_scalar || my_element.x || my_element.y, each fixed-width prime_len,
     * left-zero-padded. mp_to_unsigned_bin_len() pads and bounds-checks in
     * one call (it errors if a value exceeds pl bytes), avoiding the
     * pl - sz underflow an unguarded mp_unsigned_bin_size diff would cause. */
    ret = mp_to_unsigned_bin_len((mp_int *)&c->my_scalar, out + 2, (int)pl);
    if (ret != MP_OKAY) return ret;
    ret = mp_to_unsigned_bin_len((mp_int *)c->my_element->x,
                                 out + 2 + pl, (int)pl);
    if (ret != MP_OKAY) return ret;
    ret = mp_to_unsigned_bin_len((mp_int *)c->my_element->y,
                                 out + 2 + 2 * pl, (int)pl);
    if (ret != MP_OKAY) return ret;
    *out_len = need;
    return 0;
}

int sae_parse_peer_commit(struct sae_ctx *c, const uint8_t *in, size_t in_len)
{
    size_t pl;
    int    ret;
    uint16_t group_id;
    mp_int ex, ey;
    mp_int v_check;
    mp_int y2;

    if (c == NULL || in == NULL || c->grp == NULL) return BAD_FUNC_ARG;
    pl = c->grp->prime_len;
    if (in_len < 2U + 3U * pl) return BUFFER_E;

    group_id = (uint16_t)(in[0] | ((uint16_t)in[1] << 8));
    if (group_id != c->grp->group_id) return -1;

    ret = mp_read_unsigned_bin(&c->peer_scalar, in + 2, (int)pl);
    if (ret != MP_OKAY) return ret;
    /* peer_scalar must be in [2, q-1]. */
    if (mp_cmp_d(&c->peer_scalar, 1) != MP_GT
        || mp_cmp(&c->peer_scalar, &c->order) != MP_LT) {
        return -1;
    }
    ret = mp_init_multi(&ex, &ey, &v_check, &y2, NULL, NULL);
    if (ret != MP_OKAY) return ret;

    ret = mp_read_unsigned_bin(&ex, in + 2 + pl, (int)pl);
    if (ret == MP_OKAY) ret = mp_read_unsigned_bin(&ey,
                                                  in + 2 + 2 * pl, (int)pl);
    if (ret != MP_OKAY) goto out;

    /* Both coords must be in [0, prime). */
    if (mp_cmp(&ex, &c->prime) != MP_LT
        || mp_cmp(&ey, &c->prime) != MP_LT) {
        ret = -1; goto out;
    }
    /* Element must satisfy y^2 = x^3 + a*x + b mod p. */
    ret = curve_rhs(&ex, &c->a_coef, &c->b_coef, &c->prime, &v_check);
    if (ret != MP_OKAY) goto out;
    ret = mp_sqrmod(&ey, &c->prime, &y2);
    if (ret == MP_OKAY) {
        if (mp_cmp(&y2, &v_check) != MP_EQ) ret = -1;
    }
    if (ret != MP_OKAY) goto out;
    ret = ec_pt_set_affine(c->peer_element, &ex, &ey);
    if (ret != MP_OKAY) goto out;

    /* IEEE 802.11-2020 12.4.5.4: silently reject a REFLECTED commit whose
     * scalar AND element both equal our own. A reflection makes the Confirm
     * hash inputs symmetric (H(K||s||e||s||e) identical both ways), so the
     * reflected Confirm would verify and let a peer with no knowledge of the
     * password reach the keyed state. Only meaningful once our own commit
     * exists (have_commit); the STA always sends its commit first. */
    if (c->have_commit
        && mp_cmp(&c->peer_scalar, &c->my_scalar) == MP_EQ
        && c->my_element != NULL
        && mp_cmp(&ex, c->my_element->x) == MP_EQ
        && mp_cmp(&ey, c->my_element->y) == MP_EQ) {
        ret = -1;
        goto out;
    }
out:
    mp_clear(&ex); mp_clear(&ey); mp_clear(&v_check); mp_clear(&y2);
    return ret;
}

static int sae_hash_len(int hash_type);

/* IEEE 802.11 KDF (PRF) per 802.11r 8.5.1.5.2.
 *   Block_i = HMAC-Hash(key, i_LE16 || label || context || L_LE16)
 *   where L = requested output length in BITS (the L field is hashed in,
 *   so it must be the exact bit length the spec asks for - e.g. 521 for
 *   P-521, not the rounded-up byte count).
 * Concatenate blocks, truncate to ceil(bits_out/8) bytes. */
static int ieee80211_kdf(int hash_type,
                         const uint8_t *key, size_t key_len,
                         const char    *label,
                         const uint8_t *context, size_t context_len,
                         uint8_t *out, size_t bits_out)
{
    uint8_t  digest[SAE_MAX_HASH_LEN];
    uint8_t  counter_le[2], length_le[2];
    size_t   label_len = strlen(label);
    size_t   produced = 0;
    uint16_t counter = 1;
    size_t   bytes_out = (bits_out + 7U) / 8U;
    size_t   block_len = (size_t)sae_hash_len(hash_type);
    Hmac     hmac;
    int      ret;

    if (block_len == 0) {
        return BAD_FUNC_ARG;
    }
    length_le[0] = (uint8_t)(bits_out & 0xFFU);
    length_le[1] = (uint8_t)((bits_out >> 8) & 0xFFU);

    while (produced < bytes_out) {
        size_t take;
        counter_le[0] = (uint8_t)(counter & 0xFFU);
        counter_le[1] = (uint8_t)((counter >> 8) & 0xFFU);

        ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
        if (ret != 0) return ret;
        ret = wc_HmacSetKey(&hmac, hash_type, key, (word32)key_len);
        if (ret == 0) ret = wc_HmacUpdate(&hmac, counter_le, 2);
        if (ret == 0) ret = wc_HmacUpdate(&hmac, (const byte *)label,
                                          (word32)label_len);
        if (ret == 0 && context_len > 0) ret = wc_HmacUpdate(&hmac, context,
                                          (word32)context_len);
        if (ret == 0) ret = wc_HmacUpdate(&hmac, length_le, 2);
        if (ret == 0) ret = wc_HmacFinal(&hmac, digest);
        wc_HmacFree(&hmac);
        if (ret != 0) return ret;

        take = bytes_out - produced;
        if (take > block_len) take = block_len;
        memcpy(out + produced, digest, take);
        produced += take;
        counter++;
    }
    wc_ForceZero(digest, sizeof(digest));
    return 0;
}

int sae_derive_k_and_pmk(struct sae_ctx *c)
{
    ecc_point *tmpP = NULL;     /* peer_scalar * PWE                   */
    ecc_point *tmpQ = NULL;     /* tmpP + peer_element                 */
    ecc_point *K    = NULL;     /* rand * tmpQ                         */
    ecc_point *PWE  = NULL;
    uint8_t   k_bytes[SAE_MAX_PRIME_LEN];
    uint8_t   keyseed[SAE_MAX_HASH_LEN];
    uint8_t   keys[SAE_MAX_HASH_LEN + SAE_PMK_LEN];
    uint8_t   ctx_bytes[SAE_MAX_PRIME_LEN];
    mp_int    sum_scalars;
    Hmac      hmac;
    size_t    pl;
    size_t    hl;
    int       ret;
    static const uint8_t zero_salt[SAE_MAX_HASH_LEN] = {0};

    /* Top-of-function NULL guard before any c->grp deref, matching every other
     * public entry point in this module. */
    if (c == NULL || c->grp == NULL) return BAD_FUNC_ARG;
    pl = c->grp->prime_len;
    hl = c->grp->hash_len;
    if (!c->have_pwe || !c->have_commit) return BAD_FUNC_ARG;
    /* In hunt-and-peck mode, hostapd forces hash_len to SHA-256 size
     * regardless of group. H2E follows the group's hash. */
    if (!c->h2e) {
        hl = 32;
        c->kck_len = 32;
        c->mac_hash_type = WC_SHA256;
    }
    else {
        c->kck_len = hl;
        c->mac_hash_type = c->grp->hash_type;
    }

    ret = mp_init(&sum_scalars);
    if (ret != MP_OKAY) return ret;

    PWE  = wc_ecc_new_point();
    tmpP = wc_ecc_new_point();
    tmpQ = wc_ecc_new_point();
    K    = wc_ecc_new_point();
    if (!PWE || !tmpP || !tmpQ || !K) { ret = MEMORY_E; goto out; }

    ret = ec_pt_set_affine(PWE, &c->pwe_x, &c->pwe_y);
    if (ret != MP_OKAY) goto out;

    /* tmpP = peer_scalar * PWE. */
    ret = wc_ecc_mulmod(&c->peer_scalar, PWE, tmpP,
                        &c->a_coef, &c->prime, 1);
    if (ret != MP_OKAY) goto out;
    /* tmpQ = tmpP + peer_element. */
    ret = ec_pt_add(tmpP, c->peer_element, tmpQ, &c->a_coef, &c->prime);
    if (ret != 0) goto out;
    if (ec_pt_is_identity(tmpQ)) { ret = -1; goto out; }
    /* K = rand * tmpQ. */
    ret = wc_ecc_mulmod(&c->rand, tmpQ, K, &c->a_coef, &c->prime, 1);
    if (ret != MP_OKAY) goto out;
    if (ec_pt_is_identity(K)) { ret = -1; goto out; }

    /* k = K.x (prime_len BE bytes). Store. */
    ret = mp_to_unsigned_bin_len(K->x, k_bytes, (int)pl);
    if (ret != MP_OKAY) goto out;
    ret = mp_copy(K->x, &c->k_x);
    if (ret != MP_OKAY) goto out;

    /* keyseed = HMAC-Hash(zero_salt, k) with the selected mac hash. */
    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) goto out;
    ret = wc_HmacSetKey(&hmac, c->mac_hash_type, zero_salt, (word32)hl);
    if (ret == 0) ret = wc_HmacUpdate(&hmac, k_bytes, (word32)pl);
    if (ret == 0) ret = wc_HmacFinal(&hmac, keyseed);
    wc_HmacFree(&hmac);
    if (ret != 0) goto out;

    /* context = (my_scalar + peer_scalar) mod q, encoded prime_len BE. */
    ret = mp_addmod(&c->my_scalar, &c->peer_scalar, &c->order, &sum_scalars);
    if (ret != MP_OKAY) goto out;
    ret = mp_to_unsigned_bin_len(&sum_scalars, ctx_bytes, (int)pl);
    if (ret != MP_OKAY) goto out;

    /* PMKID = first 16 bytes of (sum_scalars BE). */
    memcpy(c->pmkid, ctx_bytes, 16);

    /* KCK || PMK = ieee80211_kdf(keyseed, "SAE KCK and PMK", ctx, KCK_len + PMK_len). */
    ret = ieee80211_kdf(c->mac_hash_type, keyseed, hl,
                        "SAE KCK and PMK",
                        ctx_bytes, pl,
                        keys, (c->kck_len + SAE_PMK_LEN) * 8U);
    if (ret != 0) goto out;
    memcpy(c->kck, keys, c->kck_len);
    memcpy(c->pmk, keys + c->kck_len, SAE_PMK_LEN);
    c->have_keys = 1;
    ret = 0;
out:
    if (PWE)  wc_ecc_del_point(PWE);
    if (tmpP) wc_ecc_del_point(tmpP);
    if (tmpQ) wc_ecc_del_point(tmpQ);
    if (K)    wc_ecc_del_point(K);
    mp_forcezero(&sum_scalars);
    wc_ForceZero(k_bytes,   sizeof(k_bytes));
    wc_ForceZero(keyseed,   sizeof(keyseed));
    wc_ForceZero(keys,      sizeof(keys));
    wc_ForceZero(ctx_bytes, sizeof(ctx_bytes));
    return ret;
}

/* HMAC over send_confirm || my_scalar || my_elem || peer_scalar || peer_elem. */
static int build_confirm_input(const struct sae_ctx *c, uint16_t send_confirm,
                               int use_peer_scalar_first,
                               Hmac *h)
{
    /* scratch lives in the ctx (preallocated) to keep this function's
     * stack frame small. Cast away const for the scratch field only -
     * confirm_scratch is genuinely mutable; the rest of *c is not
     * touched. */
    uint8_t *scratch = ((struct sae_ctx *)c)->confirm_scratch;
    uint8_t  sc_le[2];
    size_t   pl = c->grp->prime_len;
    int      ret;

    sc_le[0] = (uint8_t)(send_confirm & 0xFFU);
    sc_le[1] = (uint8_t)((send_confirm >> 8) & 0xFFU);
    ret = wc_HmacUpdate(h, sc_le, 2);
    if (ret != 0) return ret;

    /* Encode an mp_int as prime_len BE bytes into scratch + update HMAC. */
    #define UP(mp_ptr) do { \
        ret = mp_to_unsigned_bin_len((mp_int *)(mp_ptr), scratch, (int)pl); \
        if (ret != MP_OKAY) return ret; \
        ret = wc_HmacUpdate(h, scratch, (word32)pl); \
        if (ret != 0) return ret; \
    } while (0)

    if (!use_peer_scalar_first) {
        UP(&c->my_scalar);
        UP(c->my_element->x);
        UP(c->my_element->y);
        UP(&c->peer_scalar);
        UP(c->peer_element->x);
        UP(c->peer_element->y);
    }
    else {
        UP(&c->peer_scalar);
        UP(c->peer_element->x);
        UP(c->peer_element->y);
        UP(&c->my_scalar);
        UP(c->my_element->x);
        UP(c->my_element->y);
    }
    #undef UP
    wc_ForceZero(scratch, pl);
    return 0;
}

int sae_compute_confirm(const struct sae_ctx *c, uint16_t send_confirm,
                        uint8_t *out_mac, size_t mac_cap, size_t *out_len)
{
    Hmac    h;
    uint8_t digest[SAE_MAX_HASH_LEN];
    int     ret;

    if (c == NULL || !c->have_keys || out_mac == NULL || out_len == NULL) {
        return BAD_FUNC_ARG;
    }
    if (mac_cap < c->kck_len) return BUFFER_E;

    ret = wc_HmacInit(&h, NULL, INVALID_DEVID);
    if (ret != 0) return ret;
    ret = wc_HmacSetKey(&h, c->mac_hash_type, c->kck, (word32)c->kck_len);
    if (ret == 0) ret = build_confirm_input(c, send_confirm, 0, &h);
    if (ret == 0) ret = wc_HmacFinal(&h, digest);
    wc_HmacFree(&h);
    if (ret != 0) return ret;

    memcpy(out_mac, digest, c->kck_len);
    *out_len = c->kck_len;
    wc_ForceZero(digest, sizeof(digest));
    return 0;
}

int sae_verify_peer_confirm(const struct sae_ctx *c, uint16_t recv_confirm,
                            const uint8_t *peer_mac, size_t peer_mac_len)
{
    Hmac    h;
    uint8_t digest[SAE_MAX_HASH_LEN];
    uint8_t diff = 0;
    size_t  i;
    int     ret;

    if (c == NULL || !c->have_keys || peer_mac == NULL) return BAD_FUNC_ARG;
    if (peer_mac_len != c->kck_len) return BUFFER_E;

    ret = wc_HmacInit(&h, NULL, INVALID_DEVID);
    if (ret != 0) return ret;
    ret = wc_HmacSetKey(&h, c->mac_hash_type, c->kck, (word32)c->kck_len);
    if (ret == 0) ret = build_confirm_input(c, recv_confirm, 1, &h);
    if (ret == 0) ret = wc_HmacFinal(&h, digest);
    wc_HmacFree(&h);
    if (ret != 0) return ret;

    for (i = 0; i < c->kck_len; i++) {
        diff |= (uint8_t)(digest[i] ^ peer_mac[i]);
    }
    wc_ForceZero(digest, sizeof(digest));
    return (diff == 0) ? 0 : -1;
}

/* WPA3-SAE H2E (Hash-to-Element), IEEE 802.11-2020 12.4.4.2.3 + RFC 9380
 * simplified-SWU (6.6.2). Deterministic, constant-time PWE:
 *   pwd_seed   = HKDF-Extract(salt = SSID, IKM = password [|| ident])
 *   pwd_value1 = HKDF-Expand(pwd_seed, "SAE Hash to Element u1 P1", L)
 *   pwd_value2 = HKDF-Expand(pwd_seed, "SAE Hash to Element u2 P2", L)
 *   u1 = pwd_value1 mod p ; u2 = pwd_value2 mod p
 *   P1 = SSWU(u1)         ; P2 = SSWU(u2) ; PT = P1 + P2 (per password,SSID)
 *   val = HMAC-SHA256(zero_32, max(MAC_A,MAC_B) || min(MAC_A,MAC_B))
 *   val = (val mod (q-1)) + 1 ; PWE = val * PT
 */

/* sgn0(x) per RFC 9380 4.1: parity (LSB) of the canonical big-int. */
static int sswu_sgn0(const mp_int *x)
{
    return mp_isodd((mp_int *)x) ? 1 : 0;
}

/* inv0(x) per RFC 9380 4.1: invmod(x), with 0 -> 0. */
static int sswu_inv0(const mp_int *x, const mp_int *p, mp_int *out)
{
    if (mp_iszero((mp_int *)x)) {
        mp_zero(out);
        return 0;
    }
    return mp_invmod((mp_int *)x, (mp_int *)p, out);
}

/* RFC 9380 8.2 - Z constant per suite. Returned as a fresh mp_int. */
static int sswu_z_for_group(int group_id, const mp_int *p, mp_int *z_out)
{
    int neg_z;
    int ret = mp_init(z_out);
    if (ret != MP_OKAY) return ret;
    switch (group_id) {
    case SAE_GROUP_19: neg_z = 10; break; /* P-256: Z = -10 */
    case SAE_GROUP_20: neg_z = 12; break; /* P-384: Z = -12 */
    case SAE_GROUP_21: neg_z = 4;  break; /* P-521: Z =  -4 */
    default:
        mp_clear(z_out);
        return BAD_FUNC_ARG;
    }
    /* z = p - neg_z (mod p). */
    ret = mp_sub_d((mp_int *)p, (mp_digit)neg_z, z_out);
    if (ret != MP_OKAY) { mp_clear(z_out); return ret; }
    return 0;
}

/* RFC 9380 6.6.2 simplified-SWU, affine form. Curve: y^2 = x^3+a*x+b mod p.
 *
 *   tv1 = inv0(Z^2 u^4 + Z u^2)
 *   x1  = (-B / A) * (1 + tv1)         ; if tv1 == 0: x1 = B / (Z * A)
 *   gx1 = x1^3 + A*x1 + B
 *   if is_square(gx1): x = x1, y = sqrt(gx1)
 *   else:              x2 = Z*u^2*x1 ; gx2 = x2^3 + A*x2 + B
 *                      x = x2, y = sqrt(gx2)
 *   if sgn0(u) != sgn0(y): y = -y
 *   return (x, y)
 */
static int sswu_map(const mp_int *u, const mp_int *a, const mp_int *b,
                    const mp_int *p, const mp_int *z,
                    mp_int *x_out, mp_int *y_out)
{
    mp_int u2, zu2, z2u4, denom, denom_inv, x1;
    mp_int x2, gx1, gx2, t;
    mp_int neg_b, a_inv, neg_b_over_a, one_plus_inv;
    int    ret;

    ret = mp_init_multi(&u2, &zu2, &z2u4, &denom, &denom_inv, &x1);
    if (ret != MP_OKAY) return ret;
    ret = mp_init_multi(&x2, &gx1, &gx2, &t, NULL, NULL);
    if (ret != MP_OKAY) goto out_part1;
    ret = mp_init_multi(&neg_b, &a_inv, &neg_b_over_a, &one_plus_inv,
                        NULL, NULL);
    if (ret != MP_OKAY) goto out_part2;

    if ((ret = mp_sqrmod((mp_int *)u, (mp_int *)p, &u2))               != MP_OKAY
     || (ret = mp_mulmod(&u2, (mp_int *)z, (mp_int *)p, &zu2))         != MP_OKAY
     || (ret = mp_sqrmod(&zu2, (mp_int *)p, &z2u4))                    != MP_OKAY
     || (ret = mp_addmod(&z2u4, &zu2, (mp_int *)p, &denom))            != MP_OKAY) {
        goto out;
    }
    ret = sswu_inv0(&denom, p, &denom_inv);
    if (ret != MP_OKAY) goto out;

    /* x1 = (-B/A) * (1 + denom_inv). */
    if ((ret = mp_sub((mp_int *)p, (mp_int *)b, &neg_b))              != MP_OKAY
     || (ret = mp_invmod((mp_int *)a, (mp_int *)p, &a_inv))           != MP_OKAY
     || (ret = mp_mulmod(&neg_b, &a_inv, (mp_int *)p, &neg_b_over_a)) != MP_OKAY
     || (ret = mp_add_d(&denom_inv, 1, &one_plus_inv))                != MP_OKAY
     || (ret = mp_mod(&one_plus_inv, (mp_int *)p, &one_plus_inv))     != MP_OKAY
     || (ret = mp_mulmod(&neg_b_over_a, &one_plus_inv,
                         (mp_int *)p, &x1))                           != MP_OKAY) {
        goto out;
    }
    /* If denom was 0, override: x1 = B / (Z*A). */
    if (mp_iszero(&denom)) {
        mp_int za, za_inv;
        ret = mp_init_multi(&za, &za_inv, NULL, NULL, NULL, NULL);
        if (ret == MP_OKAY) {
            ret = mp_mulmod((mp_int *)z, (mp_int *)a, (mp_int *)p, &za);
            if (ret == MP_OKAY) ret = mp_invmod(&za, (mp_int *)p, &za_inv);
            if (ret == MP_OKAY) ret = mp_mulmod((mp_int *)b, &za_inv,
                                                (mp_int *)p, &x1);
            mp_clear(&za); mp_clear(&za_inv);
        }
        if (ret != MP_OKAY) goto out;
    }

    /* gx1 = x1^3 + a*x1 + b. */
    ret = curve_rhs(&x1, a, b, p, &gx1);
    if (ret != 0) goto out;

    if (is_quadratic_residue(&gx1, p)) {
        if ((ret = mp_copy(&x1, x_out))              != MP_OKAY
         || (ret = sqrt_mod_p(&gx1, p, y_out))       != 0) {
            goto out;
        }
    } else {
        if ((ret = mp_mulmod(&zu2, &x1, (mp_int *)p, &x2))    != MP_OKAY
         || (ret = curve_rhs(&x2, a, b, p, &gx2))             != 0
         || (ret = mp_copy(&x2, x_out))                       != MP_OKAY
         || (ret = sqrt_mod_p(&gx2, p, y_out))                != 0) {
            goto out;
        }
    }

    /* sgn0(u) != sgn0(y) -> y = -y. */
    if (sswu_sgn0(u) != sswu_sgn0(y_out)) {
        if ((ret = mp_sub((mp_int *)p, y_out, &t)) != MP_OKAY
         || (ret = mp_copy(&t, y_out))             != MP_OKAY) {
            goto out;
        }
    }
    ret = 0;
out:
    mp_clear(&neg_b); mp_clear(&a_inv);
    mp_clear(&neg_b_over_a); mp_clear(&one_plus_inv);
out_part2:
    mp_clear(&x2); mp_clear(&gx1); mp_clear(&gx2); mp_clear(&t);
out_part1:
    mp_clear(&u2); mp_clear(&zu2); mp_clear(&z2u4);
    mp_clear(&denom); mp_clear(&denom_inv); mp_clear(&x1);
    return ret;
}

/* Hash output length for the SAE group's chosen hash type. */
static int sae_hash_len(int hash_type)
{
    switch (hash_type) {
    case WC_SHA256: return WC_SHA256_DIGEST_SIZE;
    case WC_SHA384: return WC_SHA384_DIGEST_SIZE;
    case WC_SHA512: return WC_SHA512_DIGEST_SIZE;
    default:        return 0;
    }
}

/* Public test wrapper: apply SSWU to a big-endian field element u and
 * return (x, y) as big-endian prime_len bytes. */
int sae_h2e_sswu(const struct sae_ctx *c, const uint8_t *u_be, size_t u_len,
                 uint8_t *x_out, uint8_t *y_out)
{
    mp_int u, x, y, z;
    int    ret;
    size_t plen;

    if (c == NULL || c->grp == NULL || u_be == NULL || x_out == NULL
        || y_out == NULL) {
        return BAD_FUNC_ARG;
    }
    plen = c->grp->prime_len;

    ret = mp_init_multi(&u, &x, &y, NULL, NULL, NULL);
    if (ret != MP_OKAY) return ret;
    ret = mp_read_unsigned_bin(&u, u_be, (word32)u_len);
    if (ret != MP_OKAY) goto out_uxy;
    ret = mp_mod(&u, (mp_int *)&c->prime, &u);
    if (ret != MP_OKAY) goto out_uxy;

    ret = sswu_z_for_group(c->grp->group_id, &c->prime, &z);
    if (ret != 0) goto out_uxy;

    ret = sswu_map(&u, &c->a_coef, &c->b_coef, &c->prime, &z, &x, &y);
    if (ret != 0) goto out_z;

    XMEMSET(x_out, 0, plen);
    XMEMSET(y_out, 0, plen);
    ret = mp_to_unsigned_bin_len(&x, x_out, (int)plen);
    if (ret == MP_OKAY) ret = mp_to_unsigned_bin_len(&y, y_out, (int)plen);
out_z:
    mp_clear(&z);
out_uxy:
    mp_clear(&u); mp_clear(&x); mp_clear(&y);
    return ret;
}

/* HKDF-Extract + HKDF-Expand per the group's hash, producing one
 * pwd_value of `L` bytes from `info`. Caller-provided prk is reused. */
static int sae_h2e_pwd_value(int hash_type,
                             const uint8_t *prk, int prk_len,
                             const char *info, size_t info_len,
                             uint8_t *out, size_t L)
{
    return wc_HKDF_Expand(hash_type, prk, (word32)prk_len,
                          (const byte *)info, (word32)info_len,
                          out, (word32)L);
}

int sae_h2e_compute_pt(struct sae_ctx *c,
                       const char *password, size_t pw_len,
                       const char *identifier, size_t id_len,
                       const uint8_t *ssid, size_t ssid_len)
{
    static const char LBL_U1[] = "SAE Hash to Element u1 P1";
    static const char LBL_U2[] = "SAE Hash to Element u2 P2";
    uint8_t   prk[SAE_MAX_HASH_LEN];
    uint8_t   pwd_value[128];   /* >= max hash-to-field L (99 for P-521) */
    uint8_t   ikm[128];
    mp_int    u1, u2, z, p1x, p1y, p2x, p2y;
    ecc_point *p1 = NULL, *p2 = NULL, *pt = NULL;
    int       hash_type, hlen;
    size_t    L, ikm_len;
    int       ret;

    if (c == NULL || c->grp == NULL || password == NULL || ssid == NULL) {
        return BAD_FUNC_ARG;
    }
    if (pw_len + id_len > sizeof(ikm)) return BUFFER_E;

    hash_type = c->grp->hash_type;
    hlen      = sae_hash_len(hash_type);
    if (hlen <= 0 || (size_t)hlen > sizeof(prk)) return BAD_FUNC_ARG;
    /* RFC 9380 hash_to_field length L = ceil((ceil(log2 p) + k)/8) where k
     * is the curve security level (128/192/256), i.e. 48/72/98 bytes for
     * P-256/P-384/P-521 - NOT a fixed prime_len+16. (P-256 happens to be
     * prime_len+16=48, which is why only the larger groups were wrong.) */
    L = c->grp->h2e_field_len;
    if (L == 0 || L > sizeof(pwd_value)) return BAD_FUNC_ARG;

    ikm_len = pw_len;
    memcpy(ikm, password, pw_len);
    if (id_len > 0 && identifier != NULL) {
        memcpy(ikm + pw_len, identifier, id_len);
        ikm_len += id_len;
    }

    ret = mp_init_multi(&u1, &u2, &p1x, &p1y, &p2x, NULL);
    if (ret != MP_OKAY) return ret;
    /* z is initialized by sswu_z_for_group() below (matching sae_h2e_sswu, which
     * does not pre-init it). Zero its struct now so the early-error mp_clear(&z)
     * in cleanup is a safe no-op and a heap mp backend cannot leak a first
     * allocation that sswu_z_for_group's mp_init would otherwise overwrite. */
    XMEMSET(&z, 0, sizeof(z));
    ret = mp_init(&p2y);
    if (ret != MP_OKAY) goto out_mp_part;

    ret = wc_HKDF_Extract(hash_type, ssid, (word32)ssid_len,
                          ikm, (word32)ikm_len, prk);
    if (ret != 0) goto out;
    ret = sae_h2e_pwd_value(hash_type, prk, hlen, LBL_U1, sizeof(LBL_U1) - 1,
                            pwd_value, L);
    if (ret != 0) goto out;
    ret = mp_read_unsigned_bin(&u1, pwd_value, (word32)L);
    if (ret == MP_OKAY) ret = mp_mod(&u1, &c->prime, &u1);
    if (ret != MP_OKAY) goto out;
    ret = sae_h2e_pwd_value(hash_type, prk, hlen, LBL_U2, sizeof(LBL_U2) - 1,
                            pwd_value, L);
    if (ret != 0) goto out;
    ret = mp_read_unsigned_bin(&u2, pwd_value, (word32)L);
    if (ret == MP_OKAY) ret = mp_mod(&u2, &c->prime, &u2);
    if (ret != MP_OKAY) goto out;

    ret = sswu_z_for_group(c->grp->group_id, &c->prime, &z);
    if (ret != 0) goto out;
    ret = sswu_map(&u1, &c->a_coef, &c->b_coef, &c->prime, &z, &p1x, &p1y);
    if (ret != 0) goto out;
    ret = sswu_map(&u2, &c->a_coef, &c->b_coef, &c->prime, &z, &p2x, &p2y);
    if (ret != 0) goto out;

    p1 = wc_ecc_new_point();
    p2 = wc_ecc_new_point();
    pt = wc_ecc_new_point();
    if (p1 == NULL || p2 == NULL || pt == NULL) {
        ret = MEMORY_E; goto out;
    }
    ret = ec_pt_set_affine(p1, &p1x, &p1y);
    if (ret == 0) ret = ec_pt_set_affine(p2, &p2x, &p2y);
    if (ret == 0) ret = ec_pt_add(p1, p2, pt, &c->a_coef, &c->prime);
    if (ret != 0) goto out;

    if (ec_pt_is_identity(pt)) { ret = -1; goto out; }

    ret = mp_copy(pt->x, &c->pt_x);
    if (ret == MP_OKAY) ret = mp_copy(pt->y, &c->pt_y);
    if (ret == MP_OKAY) c->have_pt = 1;

out:
    mp_clear(&p2y);
out_mp_part:
    mp_clear(&u1); mp_clear(&u2); mp_clear(&z);
    mp_clear(&p1x); mp_clear(&p1y); mp_clear(&p2x);
    if (p1) wc_ecc_del_point(p1);
    if (p2) wc_ecc_del_point(p2);
    if (pt) wc_ecc_del_point(pt);
    wc_ForceZero(prk, sizeof(prk));
    wc_ForceZero(pwd_value, sizeof(pwd_value));
    wc_ForceZero(ikm, sizeof(ikm));
    return ret;
}

int sae_h2e_get_pt(const struct sae_ctx *c, uint8_t *x_out, uint8_t *y_out)
{
    size_t plen;
    int    ret;
    if (c == NULL || !c->have_pt || x_out == NULL || y_out == NULL) {
        return -1;
    }
    plen = c->grp->prime_len;
    XMEMSET(x_out, 0, plen);
    XMEMSET(y_out, 0, plen);
    ret = mp_to_unsigned_bin_len((mp_int *)&c->pt_x, x_out, (int)plen);
    if (ret == MP_OKAY) ret = mp_to_unsigned_bin_len((mp_int *)&c->pt_y,
                                                     y_out, (int)plen);
    return ret == MP_OKAY ? 0 : -1;
}

int sae_compute_pwe_h2e(struct sae_ctx *c,
                        const uint8_t mac_a[6], const uint8_t mac_b[6])
{
    uint8_t  zero_key[SAE_MAX_HASH_LEN];
    uint8_t  mac_pair[12];
    uint8_t  val_seed[SAE_MAX_HASH_LEN];
    mp_int   val, q_minus_one;
    ecc_point *pt = NULL, *pwe = NULL;
    Hmac     h;
    int      ret;
    int      hash_type, hlen;

    if (c == NULL || c->grp == NULL || mac_a == NULL || mac_b == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!c->have_pt) return -1;  /* PT must be precomputed. */

    hash_type = c->grp->hash_type;
    hlen      = sae_hash_len(hash_type);
    if (hlen <= 0 || (size_t)hlen > sizeof(val_seed)) return BAD_FUNC_ARG;

    /* val_seed = HMAC(zero_hlen, MAX(MAC_A,MAC_B) || MIN(MAC_A,MAC_B)). */
    memset(zero_key, 0, (size_t)hlen);
    mac_concat_max_min(mac_a, mac_b, mac_pair);
    ret = wc_HmacInit(&h, NULL, INVALID_DEVID);
    if (ret != 0) return ret;
    ret = wc_HmacSetKey(&h, hash_type, zero_key, (word32)hlen);
    if (ret == 0) ret = wc_HmacUpdate(&h, mac_pair, sizeof(mac_pair));
    if (ret == 0) ret = wc_HmacFinal(&h, val_seed);
    wc_HmacFree(&h);
    if (ret != 0) return ret;

    /* val = (val_seed mod (q - 1)) + 1   in [1, q-1]. */
    ret = mp_init_multi(&val, &q_minus_one, NULL, NULL, NULL, NULL);
    if (ret != MP_OKAY) return ret;
    if ((ret = mp_read_unsigned_bin(&val, val_seed, (word32)hlen)) != MP_OKAY
     || (ret = mp_sub_d(&c->order, 1, &q_minus_one))               != MP_OKAY
     || (ret = mp_mod(&val, &q_minus_one, &val))                   != MP_OKAY
     || (ret = mp_add_d(&val, 1, &val))                            != MP_OKAY) {
        goto out;
    }

    /* PWE = val * PT via wc_ecc_mulmod. Build PT as an ecc_point first. */
    pt  = wc_ecc_new_point();
    pwe = wc_ecc_new_point();
    if (pt == NULL || pwe == NULL) { ret = MEMORY_E; goto out; }
    ret = ec_pt_set_affine(pt, &c->pt_x, &c->pt_y);
    if (ret != 0) goto out;

    ret = wc_ecc_mulmod(&val, pt, pwe, &c->a_coef, &c->prime, 1);
    if (ret != MP_OKAY) goto out;

    /* Extract affine x,y into c->pwe_x / c->pwe_y. wc_ecc_mulmod with
     * map=1 returns affine; pwe->z == 1. */
    ret = mp_copy(pwe->x, &c->pwe_x);
    if (ret == MP_OKAY) ret = mp_copy(pwe->y, &c->pwe_y);
    if (ret == MP_OKAY) c->have_pwe = 1;

out:
    if (pt)  wc_ecc_del_point(pt);
    if (pwe) wc_ecc_del_point(pwe);
    mp_forcezero(&val);
    mp_clear(&q_minus_one);
    wc_ForceZero(val_seed, sizeof(val_seed));
    wc_ForceZero(zero_key, sizeof(zero_key));
    return ret == MP_OKAY ? 0 : ret;
}

#endif /* WOLFIP_ENABLE_SAE */

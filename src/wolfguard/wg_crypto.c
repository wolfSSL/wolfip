/* wg_crypto.c
 *
 * wolfGuard crypto abstraction, wraps wolfCrypt FIPS compliant APIs
 * (P-256 ECDH, AES-256-GCM, SHA-256, HMAC-SHA256)
 *
 * Copyright (C) 2026 wolfSSL Inc.
 */

#ifdef WOLFGUARD

#include "wolfguard.h"
#include <string.h>

/*
 * DH (ECDH with SECP256R1 / P-256)
 * */

int wg_dh_generate(uint8_t *private_key, uint8_t *public_key, WC_RNG *rng)
{
    ecc_key key;
    word32 pub_len = WG_PUBLIC_KEY_LEN;
    word32 priv_len = WG_PRIVATE_KEY_LEN;
    int ret;

    ret = wc_ecc_init(&key);
    if (ret != 0)
        return -1;

    ret = wc_ecc_make_key_ex(rng, 32, &key, ECC_SECP256R1);
    if (ret != 0) {
        wc_ecc_free(&key);
        return -1;
    }

    PRIVATE_KEY_UNLOCK();
    ret = wc_ecc_export_x963(&key, public_key, &pub_len);
    PRIVATE_KEY_LOCK();
    if (ret != 0) {
        wc_ecc_free(&key);
        return -1;
    }

    PRIVATE_KEY_UNLOCK();
    ret = wc_ecc_export_private_only(&key, private_key, &priv_len);
    PRIVATE_KEY_LOCK();
    if (ret != 0) {
        wc_ecc_free(&key);
        return -1;
    }

    wc_ecc_free(&key);
    return 0;
}

int wg_dh(uint8_t *shared_out, const uint8_t *private_key,
          const uint8_t *public_key, WC_RNG *rng)
{
    ecc_key priv, pub;
    word32 out_len = WG_SYMMETRIC_KEY_LEN;
    int ret;

    ret = wc_ecc_init(&priv);
    if (ret != 0)
        return -1;
    ret = wc_ecc_init(&pub);
    if (ret != 0) {
        wc_ecc_free(&priv);
        return -1;
    }

    /* Set RNG on private key for side-channel blinding */
    ret = wc_ecc_set_rng(&priv, rng);
    if (ret != 0)
        goto cleanup;

    /* Import private key WITHOUT public key, matches kernel wolfGuard's
     * wc_ecc_shared_secret_exim() which passes NULL, 0 for public part */
    ret = wc_ecc_import_private_key_ex(private_key, WG_PRIVATE_KEY_LEN,
                                       NULL, 0, &priv, ECC_SECP256R1);
    if (ret != 0)
        goto cleanup;

    /* Import the remote public key (uncompressed point) */
    ret = wc_ecc_import_x963_ex(public_key, WG_PUBLIC_KEY_LEN, &pub,
                                ECC_SECP256R1);
    if (ret != 0)
        goto cleanup;

    /* Compute shared secret */
    PRIVATE_KEY_UNLOCK();
    ret = wc_ecc_shared_secret(&priv, &pub, shared_out, &out_len);
    PRIVATE_KEY_LOCK();
    if (ret != 0)
        goto cleanup;

    wc_ecc_free(&pub);
    wc_ecc_free(&priv);
    return 0;

cleanup:
    wc_ecc_free(&pub);
    wc_ecc_free(&priv);
    return -1;
}

int wg_pubkey_from_private(uint8_t *public_key, const uint8_t *private_key)
{
    ecc_key key;
    word32 pub_len = WG_PUBLIC_KEY_LEN;
    int ret;

    ret = wc_ecc_init(&key);
    if (ret != 0)
        return -1;

    ret = wc_ecc_import_private_key_ex(private_key, WG_PRIVATE_KEY_LEN,
                                       NULL, 0, &key, ECC_SECP256R1);
    if (ret != 0) {
        wc_ecc_free(&key);
        return -1;
    }

    /* Derive public key from private */
    PRIVATE_KEY_UNLOCK();
    ret = wc_ecc_make_pub(&key, NULL);
    PRIVATE_KEY_LOCK();
    if (ret != 0) {
        wc_ecc_free(&key);
        return -1;
    }

    PRIVATE_KEY_UNLOCK();
    ret = wc_ecc_export_x963(&key, public_key, &pub_len);
    PRIVATE_KEY_LOCK();
    wc_ecc_free(&key);
    return (ret == 0) ? 0 : -1;
}

/*
 * AEAD (AES-256-GCM)
 *
 * Nonce construction:
 *   16-byte nonce = 4 bytes zero || 8 bytes LE counter || 4 bytes zero
 *
 * The kernel wolfGuard uses AES_IV_SIZE (16) for all AES-GCM IVs.
 * Per NIST SP 800-38D, a 16-byte IV is processed via GHASH (unlike
 * 12-byte IVs which are used directly). Both are valid, but we must
 * match the kernel to interoperate properly and correctly.
 *
 * Output: ciphertext || 16-byte auth tag
 * */

static void wg_aead_make_nonce(uint8_t nonce[WG_AEAD_NONCE_LEN],
                               uint64_t counter)
{
    memset(nonce, 0, WG_AEAD_NONCE_LEN);
    nonce[4]  = (uint8_t)(counter);
    nonce[5]  = (uint8_t)(counter >> 8);
    nonce[6]  = (uint8_t)(counter >> 16);
    nonce[7]  = (uint8_t)(counter >> 24);
    nonce[8]  = (uint8_t)(counter >> 32);
    nonce[9]  = (uint8_t)(counter >> 40);
    nonce[10] = (uint8_t)(counter >> 48);
    nonce[11] = (uint8_t)(counter >> 56);
}

int wg_aead_encrypt(uint8_t *dst, const uint8_t *key, uint64_t counter,
                    const uint8_t *plaintext, size_t plaintext_len,
                    const uint8_t *aad, size_t aad_len)
{
    Aes aes;
    uint8_t nonce[WG_AEAD_NONCE_LEN];
    int ret;

    wg_aead_make_nonce(nonce, counter);

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0)
        return -1;

    ret = wc_AesGcmSetKey(&aes, key, WG_SYMMETRIC_KEY_LEN);
    if (ret != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    /* dst layout: [ciphertext (plaintext_len)] [tag (16)] */
    ret = wc_AesGcmEncrypt(&aes, dst, plaintext, (word32)plaintext_len,
                           nonce, WG_AEAD_NONCE_LEN,
                           dst + plaintext_len, WG_AUTHTAG_LEN,
                           aad, (word32)aad_len);

    wc_AesFree(&aes);
    return (ret == 0) ? 0 : -1;
}

int wg_aead_decrypt(uint8_t *dst, const uint8_t *key, uint64_t counter,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    const uint8_t *aad, size_t aad_len)
{
    Aes aes;
    uint8_t nonce[WG_AEAD_NONCE_LEN];
    int ret;
    size_t ct_only;

    if (ciphertext_len < WG_AUTHTAG_LEN)
        return -1;

    ct_only = ciphertext_len - WG_AUTHTAG_LEN;
    wg_aead_make_nonce(nonce, counter);

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0)
        return -1;

    ret = wc_AesGcmSetKey(&aes, key, WG_SYMMETRIC_KEY_LEN);
    if (ret != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    ret = wc_AesGcmDecrypt(&aes, dst, ciphertext, (word32)ct_only,
                           nonce, WG_AEAD_NONCE_LEN,
                           ciphertext + ct_only, WG_AUTHTAG_LEN,
                           aad, (word32)aad_len);

    wc_AesFree(&aes);
    return (ret == 0) ? 0 : -1;
}

/*
 * XAEAD (AES-256-GCM with explicit nonce for cookies)
 *
 * Uses caller-provided 16-byte nonce as the AES-GCM IV.
 * */

int wg_xaead_encrypt(uint8_t *dst, const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *aad, size_t aad_len)
{
    Aes aes;
    int ret;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0)
        return -1;

    ret = wc_AesGcmSetKey(&aes, key, WG_SYMMETRIC_KEY_LEN);
    if (ret != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    /* Use the full 16-byte nonce as the AES-GCM IV */
    ret = wc_AesGcmEncrypt(&aes, dst, plaintext, (word32)plaintext_len,
                           nonce, WG_AEAD_NONCE_LEN,
                           dst + plaintext_len, WG_AUTHTAG_LEN,
                           aad, (word32)aad_len);

    wc_AesFree(&aes);
    return (ret == 0) ? 0 : -1;
}

int wg_xaead_decrypt(uint8_t *dst, const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *ciphertext, size_t ciphertext_len,
                     const uint8_t *aad, size_t aad_len)
{
    Aes aes;
    int ret;
    size_t ct_only;

    if (ciphertext_len < WG_AUTHTAG_LEN)
        return -1;

    ct_only = ciphertext_len - WG_AUTHTAG_LEN;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0)
        return -1;

    ret = wc_AesGcmSetKey(&aes, key, WG_SYMMETRIC_KEY_LEN);
    if (ret != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    ret = wc_AesGcmDecrypt(&aes, dst, ciphertext, (word32)ct_only,
                           nonce, WG_AEAD_NONCE_LEN,
                           ciphertext + ct_only, WG_AUTHTAG_LEN,
                           aad, (word32)aad_len);

    wc_AesFree(&aes);
    return (ret == 0) ? 0 : -1;
}

/*
 * Hash (SHA-256)
 * */

int wg_hash(uint8_t *out, const uint8_t *input, size_t len)
{
    wc_Sha256 sha;
    int ret;

    ret = wc_InitSha256(&sha);
    if (ret != 0)
        return -1;

    ret = wc_Sha256Update(&sha, input, (word32)len);
    if (ret != 0) {
        wc_Sha256Free(&sha);
        return -1;
    }

    ret = wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
    return (ret == 0) ? 0 : -1;
}

int wg_hash2(uint8_t *out, const uint8_t *a, size_t a_len,
             const uint8_t *b, size_t b_len)
{
    wc_Sha256 sha;
    int ret;

    ret = wc_InitSha256(&sha);
    if (ret != 0)
        return -1;

    ret = wc_Sha256Update(&sha, a, (word32)a_len);
    if (ret != 0) {
        wc_Sha256Free(&sha);
        return -1;
    }

    ret = wc_Sha256Update(&sha, b, (word32)b_len);
    if (ret != 0) {
        wc_Sha256Free(&sha);
        return -1;
    }

    ret = wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
    return (ret == 0) ? 0 : -1;
}

/*
 * MAC (HMAC-SHA256, full 32-byte output)
 * */

int wg_mac(uint8_t *out, const uint8_t *key, size_t key_len,
           const uint8_t *input, size_t input_len)
{
    uint8_t full[WG_HASH_LEN];
    int ret;

    ret = wg_hmac(full, key, key_len, input, input_len);
    if (ret != 0)
        return -1;

    memcpy(out, full, WG_COOKIE_LEN);
    wg_memzero(full, sizeof(full));
    return 0;
}

/*
 * HMAC (HMAC-SHA256, full 32-byte output)
 * */

int wg_hmac(uint8_t *out, const uint8_t *key, size_t key_len,
            const uint8_t *input, size_t input_len)
{
    Hmac hmac;
    int ret;

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) {
        return -1;
    }

    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, (word32)key_len);
    if (ret != 0) {
        goto out;
    }

    ret = wc_HmacUpdate(&hmac, input, (word32)input_len);
    if (ret != 0) {
        goto out;
    }

    ret = wc_HmacFinal(&hmac, out);

out:
    wc_HmacFree(&hmac);
    return (ret == 0) ? 0 : -1;
}

/*
 * KDF (HKDF-extract + expand with HMAC-SHA256)
 *
 * WireGuard spec KDF:
 *   prk = HMAC(key, input)
 *   t0  = empty
 *   t1  = HMAC(prk, t0 || 0x01)
 *   t2  = HMAC(prk, t1 || 0x02)
 *   t3  = HMAC(prk, t2 || 0x03)
 * */

int wg_kdf1(uint8_t *t1, const uint8_t *key, const uint8_t *input,
            size_t input_len)
{
    uint8_t prk[WG_HASH_LEN];
    uint8_t tmp[WG_HASH_LEN + 1];
    int ret;

    /* Extract */
    ret = wg_hmac(prk, key, WG_HASH_LEN, input, input_len);
    if (ret != 0)
        return -1;

    /* Expand: t1 = HMAC(prk, 0x01) */
    tmp[0] = 0x01;
    ret = wg_hmac(t1, prk, WG_HASH_LEN, tmp, 1);

    wg_memzero(prk, sizeof(prk));
    return ret;
}

int wg_kdf2(uint8_t *t1, uint8_t *t2, const uint8_t *key,
            const uint8_t *input, size_t input_len)
{
    uint8_t prk[WG_HASH_LEN];
    uint8_t tmp[WG_HASH_LEN + 1];
    int ret;

    /* Extract */
    ret = wg_hmac(prk, key, WG_HASH_LEN, input, input_len);
    if (ret != 0)
        return -1;

    /* t1 = HMAC(prk, 0x01) */
    tmp[0] = 0x01;
    ret = wg_hmac(t1, prk, WG_HASH_LEN, tmp, 1);
    if (ret != 0)
        goto done;

    /* t2 = HMAC(prk, t1 || 0x02) */
    memcpy(tmp, t1, WG_HASH_LEN);
    tmp[WG_HASH_LEN] = 0x02;
    ret = wg_hmac(t2, prk, WG_HASH_LEN, tmp, WG_HASH_LEN + 1);

done:
    wg_memzero(prk, sizeof(prk));
    wg_memzero(tmp, sizeof(tmp));
    return ret;
}

int wg_kdf3(uint8_t *t1, uint8_t *t2, uint8_t *t3, const uint8_t *key,
            const uint8_t *input, size_t input_len)
{
    uint8_t prk[WG_HASH_LEN];
    uint8_t tmp[WG_HASH_LEN + 1];
    int ret;

    /* Extract */
    ret = wg_hmac(prk, key, WG_HASH_LEN, input, input_len);
    if (ret != 0)
        return -1;

    /* t1 = HMAC(prk, 0x01) */
    tmp[0] = 0x01;
    ret = wg_hmac(t1, prk, WG_HASH_LEN, tmp, 1);
    if (ret != 0)
        goto done;

    /* t2 = HMAC(prk, t1 || 0x02) */
    memcpy(tmp, t1, WG_HASH_LEN);
    tmp[WG_HASH_LEN] = 0x02;
    ret = wg_hmac(t2, prk, WG_HASH_LEN, tmp, WG_HASH_LEN + 1);
    if (ret != 0)
        goto done;

    /* t3 = HMAC(prk, t2 || 0x03) */
    memcpy(tmp, t2, WG_HASH_LEN);
    tmp[WG_HASH_LEN] = 0x03;
    ret = wg_hmac(t3, prk, WG_HASH_LEN, tmp, WG_HASH_LEN + 1);

done:
    wg_memzero(prk, sizeof(prk));
    wg_memzero(tmp, sizeof(tmp));
    return ret;
}

/*
 * Monotonic timestamp for replay protection (WG_TIMESTAMP_LEN = 12 bytes)
 *
 * The WireGuard spec (Section 5.1) requires a per-peer monotonically
 * increasing 96-bit value, encoded big-endian so that memcmp() gives
 * chronological ordering.
 * TAI64N format (https://cr.yp.to/libtai/tai64.html):
 *   8 bytes: big-endian seconds since TAI epoch (2^62 + 10 + unix_seconds)
 *   4 bytes: big-endian nanoseconds
 *
 * The 0x400000000000000a offset is the TAI64 label (2^62) plus the
 * TAI-UTC leap second offset (10 at the Unix epoch).
 */

void wg_timestamp_now(uint8_t *out, uint64_t now_ms)
{
    uint64_t secs = now_ms / 1000;
    uint32_t nsec = (uint32_t)((now_ms % 1000) * 1000000);
    uint64_t tai64_secs = 0x400000000000000aULL + secs;

    /* 8-byte big-endian TAI64 seconds */
    out[0] = (uint8_t)(tai64_secs >> 56);
    out[1] = (uint8_t)(tai64_secs >> 48);
    out[2] = (uint8_t)(tai64_secs >> 40);
    out[3] = (uint8_t)(tai64_secs >> 32);
    out[4] = (uint8_t)(tai64_secs >> 24);
    out[5] = (uint8_t)(tai64_secs >> 16);
    out[6] = (uint8_t)(tai64_secs >> 8);
    out[7] = (uint8_t)(tai64_secs);

    /* 4-byte big-endian nanoseconds */
    out[8]  = (uint8_t)(nsec >> 24);
    out[9]  = (uint8_t)(nsec >> 16);
    out[10] = (uint8_t)(nsec >> 8);
    out[11] = (uint8_t)(nsec);
}

/*
 * Slightly touched version from the ConstantCompare implementation
 * of wolfguard:
 *
 * ref: https://github.com/wolfSSL/wolfGuard/blob/3f7dea395caa30df0fbabbf27752fbedf78cd91b/kernel-src/wolfcrypt_glue.h#L92
 *
 * the key (and only) difference is that we return 0 on match and -1 on mismatch,
 * while ConstantCompare returns the raw difference on mismatch between the two buffers.
 * */

int wg_memcmp(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t diff = 0;
    size_t i;

    for (i = 0; i < len; i++)
        diff |= a[i] ^ b[i];

    return (diff == 0) ? 0 : -1;
}

/*
 * wrapper that calls the public exported version of ForceZero().
 *
 * which, as documented, fills the first len bytes of the memory area pointed by mem
 * with zeros. It ensures compiler optimization doesn't skip it.
 * */

void wg_memzero(void *ptr, size_t len)
{
    wc_ForceZero(ptr, len);
}

#endif /* WOLFGUARD */

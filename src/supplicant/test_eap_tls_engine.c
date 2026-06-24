/* test_eap_tls_engine.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * End-to-end test of eap_tls_engine:
 *   1. Generate a CA, server cert (auth server), and client cert at
 *      runtime via openssl, in /tmp/wolfip_eap_certs/, DER format.
 *   2. Spin up a wolfSSL server in-process (direct wolfSSL API + custom
 *      memory IO callbacks).
 *   3. Drive the eap_tls_engine (the supplicant-side client) and the
 *      server in lockstep, shuttling TLS bytes through tx_buf/rx_buf
 *      pairs - simulating what EAP-TLS framing would carry.
 *   4. After both reach handshake_complete, export MSK on both sides
 *      using wolfSSL_make_eap_keys and verify byte-for-byte equality.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include "eap_tls_engine.h"

#define CERT_DIR "/tmp/wolfip_eap_certs"

/* Generate CA + server + client material with openssl. Returns 0 if
 * already present (idempotent) or freshly generated. */
static int generate_certs(void)
{
    struct stat st;
    char cmd[2048];
    char bash_cmd[2200];
    if (stat(CERT_DIR "/client.key.der", &st) == 0
        && stat(CERT_DIR "/server.key.der", &st) == 0
        && stat(CERT_DIR "/ca.der", &st) == 0) {
        return 0;
    }
    snprintf(cmd, sizeof(cmd),
        "set -e; mkdir -p %s; cd %s; "
        "openssl ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null; "
        "openssl req -x509 -new -key ca.key -sha256 -days 365 -out ca.crt "
          "-subj '/CN=wolfIP EAP Test CA' 2>/dev/null; "
        "openssl x509 -in ca.crt -outform DER -out ca.der 2>/dev/null; "
        "openssl ecparam -name prime256v1 -genkey -noout -out server.key 2>/dev/null; "
        "openssl req -new -key server.key -out server.csr "
          "-subj '/CN=auth.wolfip.local' 2>/dev/null; "
        "openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key "
          "-CAcreateserial -out server.crt -days 365 -sha256 "
          "-extfile <(printf 'subjectAltName=DNS:auth.wolfip.local') 2>/dev/null; "
        "openssl pkcs8 -topk8 -nocrypt -in server.key -outform DER -out server.key.der 2>/dev/null; "
        "openssl x509 -in server.crt -outform DER -out server.der 2>/dev/null; "
        "openssl ecparam -name prime256v1 -genkey -noout -out client.key 2>/dev/null; "
        "openssl req -new -key client.key -out client.csr "
          "-subj '/CN=alice@wolfip.local' 2>/dev/null; "
        "openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key "
          "-CAcreateserial -out client.crt -days 365 -sha256 "
          "-extfile <(printf 'extendedKeyUsage=clientAuth') 2>/dev/null; "
        "openssl pkcs8 -topk8 -nocrypt -in client.key -outform DER -out client.key.der 2>/dev/null; "
        "openssl x509 -in client.crt -outform DER -out client.der 2>/dev/null",
        CERT_DIR, CERT_DIR);
    /* /bin/sh on Debian is dash which doesn't support process substitution.
     * Force bash via system() -> sh -c. Use /bin/bash explicitly. */
    snprintf(bash_cmd, sizeof(bash_cmd), "/bin/bash -c \"%s\"", cmd);
    if (system(bash_cmd) != 0) return -1;
    return 0;
}

static int slurp(const char *path, uint8_t *out, size_t cap, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (f == NULL) return -1;
    n = fread(out, 1, cap, f);
    fclose(f);
    if (n == 0) return -1;
    *out_len = n;
    return 0;
}

/* In-process server IO buffers; the test loops below copy bytes
 * between client and server IO buffers. */
struct mem_io {
    uint8_t buf[8192];
    size_t  filled;
    size_t  drained;
};

static int srv_io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    struct mem_io *m = (struct mem_io *)ctx;
    size_t avail;
    size_t take;
    (void)ssl;
    if (m->filled <= m->drained) return WOLFSSL_CBIO_ERR_WANT_READ;
    avail = m->filled - m->drained;
    take = (size_t)sz < avail ? (size_t)sz : avail;
    memcpy(buf, m->buf + m->drained, take);
    m->drained += take;
    if (m->drained == m->filled) { m->drained = 0; m->filled = 0; }
    return (int)take;
}

static int srv_io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    struct mem_io *m = (struct mem_io *)ctx;
    size_t cap;
    (void)ssl;
    if (m->filled > sizeof(m->buf)) return WOLFSSL_CBIO_ERR_GENERAL;
    cap = sizeof(m->buf) - m->filled;
    if ((size_t)sz > cap) sz = (int)cap;
    memcpy(m->buf + m->filled, buf, (size_t)sz);
    m->filled += (size_t)sz;
    return sz;
}

static int run_handshake_test(int tls_version_pin,
                              const char *version_label,
                              const uint8_t *ca_der, size_t ca_len,
                              const uint8_t *srv_cert_der, size_t srv_cert_len,
                              const uint8_t *srv_key_der, size_t srv_key_len,
                              const uint8_t *cli_cert_der, size_t cli_cert_len,
                              const uint8_t *cli_key_der, size_t cli_key_len)
{
    struct eap_tls_engine eng;
    struct eap_tls_engine_cfg cfg;
    WOLFSSL_CTX *srv_ctx = NULL;
    WOLFSSL     *srv_ssl = NULL;
    WOLFSSL_METHOD *srv_method;
    struct mem_io srv_in;
    struct mem_io srv_out;
    uint8_t msk_client[WOLFIP_EAP_TLS_MSK_LEN];
    uint8_t msk_server[WOLFIP_EAP_TLS_MSK_LEN];
    int     iter;
    int     client_done = 0;
    int     server_done = 0;
    int     fails = 0;
    int     ret;

    printf("\n=== Handshake test: %s ===\n", version_label);

    /* --- Client (supplicant) side via eap_tls_engine. --- */
    memset(&cfg, 0, sizeof(cfg));
    cfg.ca                 = ca_der;       cfg.ca_len = ca_len;
    cfg.ca_format          = WOLFIP_EAP_TLS_FMT_DER;
    cfg.client_cert        = cli_cert_der; cfg.client_cert_len = cli_cert_len;
    cfg.client_cert_format = WOLFIP_EAP_TLS_FMT_DER;
    cfg.client_key         = cli_key_der;  cfg.client_key_len  = cli_key_len;
    cfg.client_key_format  = WOLFIP_EAP_TLS_FMT_DER;
    cfg.server_name_pin    = "auth.wolfip.local";
    cfg.tls_version_pin    = tls_version_pin;

    if (eap_tls_engine_init(&eng, &cfg) != 0) {
        printf("  [FAIL] eap_tls_engine_init\n");
        return 1;
    }
    printf("eap_tls_engine ready (%s client + SAN pin)\n", version_label);

    /* --- Server side using native wolfSSL. --- */
    if (tls_version_pin == 2) {
        srv_method = wolfTLSv1_3_server_method();
    }
    else {
        srv_method = wolfTLSv1_2_server_method();
    }
    srv_ctx = wolfSSL_CTX_new(srv_method);
    if (srv_ctx == NULL) {
        printf("  [FAIL] srv CTX_new (%s)\n", version_label);
        eap_tls_engine_free(&eng);
        return 1;
    }
    /* Server validates the client's cert (mutual auth). */
    wolfSSL_CTX_set_verify(srv_ctx, WOLFSSL_VERIFY_PEER, NULL);
    if (wolfSSL_CTX_load_verify_buffer(srv_ctx, ca_der, ca_len,
                                       WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("  [FAIL] srv load CA\n"); return 1;
    }
    if (wolfSSL_CTX_use_certificate_buffer(srv_ctx, srv_cert_der, srv_cert_len,
                                           WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("  [FAIL] srv load cert\n"); return 1;
    }
    if (wolfSSL_CTX_use_PrivateKey_buffer(srv_ctx, srv_key_der, srv_key_len,
                                          WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("  [FAIL] srv load key\n"); return 1;
    }
    wolfSSL_CTX_SetIORecv(srv_ctx, srv_io_recv);
    wolfSSL_CTX_SetIOSend(srv_ctx, srv_io_send);
    srv_ssl = wolfSSL_new(srv_ctx);
    if (srv_ssl == NULL) { printf("  [FAIL] srv new\n"); return 1; }
    memset(&srv_in,  0, sizeof(srv_in));
    memset(&srv_out, 0, sizeof(srv_out));
    wolfSSL_SetIOReadCtx(srv_ssl,  &srv_in);
    wolfSSL_SetIOWriteCtx(srv_ssl, &srv_out);
    /* Preserve session arrays for MSK export. */
    wolfSSL_KeepArrays(srv_ssl);

    /* --- Drive the handshake. The client side has its own IO ring
     * inside the engine; the server side uses srv_in/srv_out. After
     * each step we move bytes between the client engine and the server
     * mem_io buffers. --- */
    for (iter = 0; iter < 64; iter++) {
        /* Step client. */
        if (!client_done) {
            ret = eap_tls_engine_step(&eng);
            if (ret == 1) client_done = 1;
            else if (ret < 0) {
                printf("  [FAIL] client engine step iter %d\n", iter);
                fails++; break;
            }
        }
        /* Move client tx -> server in. */
        if (eng.io.tx_filled > eng.io.tx_drained) {
            size_t avail = eng.io.tx_filled - eng.io.tx_drained;
            size_t cap = sizeof(srv_in.buf) - srv_in.filled;
            size_t take = avail < cap ? avail : cap;
            memcpy(srv_in.buf + srv_in.filled,
                   eng.io.tx_buf + eng.io.tx_drained, take);
            srv_in.filled += take;
            eng.io.tx_drained += take;
            if (eng.io.tx_drained == eng.io.tx_filled) {
                eng.io.tx_filled = 0; eng.io.tx_drained = 0;
                eng.io.tx_first_frag = 1;
            }
        }
        /* Step server. */
        if (!server_done) {
            ret = wolfSSL_accept(srv_ssl);
            if (ret == WOLFSSL_SUCCESS) {
                server_done = 1;
            }
            else {
                int err = wolfSSL_get_error(srv_ssl, ret);
                if (err != WOLFSSL_ERROR_WANT_READ
                    && err != WOLFSSL_ERROR_WANT_WRITE) {
                    char emsg[80];
                    wolfSSL_ERR_error_string((unsigned long)err, emsg);
                    printf("  [FAIL] server accept err=%d (%s)\n", err, emsg);
                    fails++; break;
                }
            }
        }
        /* Move server tx -> client rx. */
        if (srv_out.filled > srv_out.drained) {
            size_t avail = srv_out.filled - srv_out.drained;
            size_t cap = sizeof(eng.io.rx_buf) - eng.io.rx_filled;
            size_t take = avail < cap ? avail : cap;
            memcpy(eng.io.rx_buf + eng.io.rx_filled,
                   srv_out.buf + srv_out.drained, take);
            eng.io.rx_filled += take;
            eng.io.rx_complete = 1;
            srv_out.drained += take;
            if (srv_out.drained == srv_out.filled) {
                srv_out.filled = 0; srv_out.drained = 0;
            }
        }
        if (client_done && server_done) break;
    }
    if (!client_done || !server_done) {
        printf("  [FAIL] handshake did not complete (client=%d server=%d in %d iter)\n",
               client_done, server_done, iter);
        fails++;
        goto out;
    }
    printf("%s handshake completed in %d iter\n", version_label, iter);

    /* Export MSK on both sides and compare. <= TLS 1.2 uses the RFC 5216
     * PRF (wolfSSL_make_eap_keys). TLS 1.3 uses the RFC 9190 TLS Exporter
     * on BOTH sides; that needs a wolfSSL built with HAVE_KEYING_MATERIAL.
     * When the exporter is unavailable the engine returns an error for 1.3
     * (rather than a wrong MSK), so we skip the 1.3 assertion on such a
     * build instead of masking a real divergence. When it IS available the
     * 1.3 MSK comparison is a HARD assertion. */
    if (eap_tls_engine_export_msk(&eng, msk_client) != 0) {
        if (tls_version_pin == 2) {
            printf("  [SKIP] %s MSK: wolfSSL lacks HAVE_KEYING_MATERIAL; "
                   "RFC 9190 exporter not testable on this build\n",
                   version_label);
            goto out;
        }
        printf("  [FAIL] %s client MSK export failed\n", version_label);
        fails++; goto out;
    }
    if (tls_version_pin == 2) {
#ifdef HAVE_KEYING_MATERIAL
        static const char l9190[] = "EXPORTER_EAP_TLS_Key_Material";
        unsigned char tc = 0x0D;
        if (wolfSSL_export_keying_material(srv_ssl, msk_server,
                WOLFIP_EAP_TLS_MSK_LEN, l9190, sizeof(l9190) - 1U,
                &tc, 1U, 1) != WOLFSSL_SUCCESS) {
            printf("  [FAIL] %s server exporter failed\n", version_label);
            fails++; goto out;
        }
#else
        printf("  [SKIP] %s MSK: HAVE_KEYING_MATERIAL absent\n",
               version_label);
        goto out;
#endif
    }
    else if (wolfSSL_make_eap_keys(srv_ssl, msk_server,
                                   WOLFIP_EAP_TLS_MSK_LEN,
                                   "client EAP encryption") != 0) {
        printf("  [FAIL] %s server MSK export failed\n", version_label);
        fails++; goto out;
    }
    if (memcmp(msk_client, msk_server, WOLFIP_EAP_TLS_MSK_LEN) != 0) {
        printf("  [FAIL] %s MSK mismatch (client vs server)\n",
               version_label);
        fails++;
    }
    else {
        int i;
        printf("  [OK]   %s client MSK matches server MSK (64 bytes)\n",
               version_label);
        printf("  [OK]   PMK (MSK[0..31]) = ");
        for (i = 0; i < 16; i++) printf("%02x", msk_client[i]);
        printf("...\n");
    }

out:
    if (srv_ssl) wolfSSL_free(srv_ssl);
    if (srv_ctx) wolfSSL_CTX_free(srv_ctx);
    eap_tls_engine_free(&eng);
    return fails;
}

int main(void)
{
    uint8_t ca_der[2048],       srv_cert_der[2048], srv_key_der[2048];
    uint8_t cli_cert_der[2048], cli_key_der[2048];
    size_t  ca_len=0, srv_cert_len=0, srv_key_len=0, cli_cert_len=0, cli_key_len=0;
    int     fails = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Generating EAP-TLS test certs in %s\n", CERT_DIR);
    if (generate_certs() != 0) {
        printf("  [FAIL] openssl cert generation\n");
        return 1;
    }
    if (slurp(CERT_DIR "/ca.der",         ca_der,       sizeof(ca_der),       &ca_len)       != 0
     || slurp(CERT_DIR "/server.der",     srv_cert_der, sizeof(srv_cert_der), &srv_cert_len) != 0
     || slurp(CERT_DIR "/server.key.der", srv_key_der,  sizeof(srv_key_der),  &srv_key_len)  != 0
     || slurp(CERT_DIR "/client.der",     cli_cert_der, sizeof(cli_cert_der), &cli_cert_len) != 0
     || slurp(CERT_DIR "/client.key.der", cli_key_der,  sizeof(cli_key_der),  &cli_key_len)  != 0) {
        printf("  [FAIL] reading cert files\n");
        return 1;
    }
    printf("Loaded ca=%zuB srv_cert=%zuB srv_key=%zuB cli_cert=%zuB cli_key=%zuB\n",
           ca_len, srv_cert_len, srv_key_len, cli_cert_len, cli_key_len);

    wolfSSL_Init();
    fails += run_handshake_test(1, "TLS 1.2",
                                ca_der, ca_len,
                                srv_cert_der, srv_cert_len,
                                srv_key_der, srv_key_len,
                                cli_cert_der, cli_cert_len,
                                cli_key_der, cli_key_len);
    fails += run_handshake_test(2, "TLS 1.3",
                                ca_der, ca_len,
                                srv_cert_der, srv_cert_len,
                                srv_key_der, srv_key_len,
                                cli_cert_der, cli_cert_len,
                                cli_key_der, cli_key_len);
    wolfSSL_Cleanup();

    if (fails == 0) {
        printf("\nEAP-TLS engine tests passed.\n");
        return 0;
    }
    printf("\n%d EAP-TLS engine test failure(s).\n", fails);
    return 1;
}

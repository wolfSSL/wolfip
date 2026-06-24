/* test_eap_certs.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Inline helpers shared by EAP-TLS tests: one-shot openssl cert
 * generation into /tmp/wolfip_eap_certs/ and a tiny file slurp.
 * Single-include header (no separate .c).
 */

#ifndef WOLFIP_TEST_EAP_CERTS_H
#define WOLFIP_TEST_EAP_CERTS_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define EAP_TEST_CERT_DIR "/tmp/wolfip_eap_certs"

static int eap_test_generate_certs(void)
{
    struct stat st;
    char cmd[2400];
    char bash_cmd[2600];
    int n;
    if (stat(EAP_TEST_CERT_DIR "/client.key.der", &st) == 0
        && stat(EAP_TEST_CERT_DIR "/server.key.der", &st) == 0
        && stat(EAP_TEST_CERT_DIR "/ca.der", &st) == 0) {
        return 0;
    }
    n = snprintf(cmd, sizeof(cmd),
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
        EAP_TEST_CERT_DIR, EAP_TEST_CERT_DIR);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        return -1; /* command string truncated */
    }
    n = snprintf(bash_cmd, sizeof(bash_cmd), "/bin/bash -c \"%s\"", cmd);
    if (n < 0 || (size_t)n >= sizeof(bash_cmd)) {
        return -1; /* command string truncated */
    }
    return (system(bash_cmd) == 0) ? 0 : -1;
}

static int eap_test_slurp(const char *path, uint8_t *out, size_t cap,
                          size_t *out_len)
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

struct eap_test_creds {
    uint8_t ca[2048];        size_t ca_len;
    uint8_t srv_cert[2048];  size_t srv_cert_len;
    uint8_t srv_key[2048];   size_t srv_key_len;
    uint8_t cli_cert[2048];  size_t cli_cert_len;
    uint8_t cli_key[2048];   size_t cli_key_len;
};

static int eap_test_load_creds(struct eap_test_creds *c)
{
    if (eap_test_generate_certs() != 0) return -1;
    if (eap_test_slurp(EAP_TEST_CERT_DIR "/ca.der",
                       c->ca, sizeof(c->ca), &c->ca_len) != 0) return -1;
    if (eap_test_slurp(EAP_TEST_CERT_DIR "/server.der",
                       c->srv_cert, sizeof(c->srv_cert),
                       &c->srv_cert_len) != 0) return -1;
    if (eap_test_slurp(EAP_TEST_CERT_DIR "/server.key.der",
                       c->srv_key, sizeof(c->srv_key),
                       &c->srv_key_len) != 0) return -1;
    if (eap_test_slurp(EAP_TEST_CERT_DIR "/client.der",
                       c->cli_cert, sizeof(c->cli_cert),
                       &c->cli_cert_len) != 0) return -1;
    if (eap_test_slurp(EAP_TEST_CERT_DIR "/client.key.der",
                       c->cli_key, sizeof(c->cli_key),
                       &c->cli_key_len) != 0) return -1;
    return 0;
}

#endif /* WOLFIP_TEST_EAP_CERTS_H */

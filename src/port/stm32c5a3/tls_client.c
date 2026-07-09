/* tls_client.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfIP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Milestone 3A.0: TLS 1.3 mutual-auth client for the STM32C5A3ZG wolfIP port.
 *
 * The device presents a client certificate (mutual auth) and completes a
 * TLS 1.3 handshake with TLS_AES_128_GCM_SHA256 against an openssl s_server.
 * The identity private key is loaded here as an ordinary SEC1 EC key (software
 * / direct-HW crypto). The DHUK-wrapped callback key swap is a later step;
 * this build proves the TLS-over-wolfIP + mTLS + cert-chain plumbing works.
 */

#include "tls_client.h"
#include "tls_certs.h"
#include "wolfip.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <string.h>

#ifdef ENABLE_DHUK_KEY
/* Milestone 3A.1: the identity private key is a DHUK-wrapped scalar. The
 * CertificateVerify signature is produced by a PK (EccSign) callback that
 * routes wc_ecc_sign_hash through the STM32 crypto callback: the scalar is
 * unwrapped inside SAES and signed on the HW PKA, so it never appears in
 * software. */
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/port/st/stm32.h>
#include "st_p256_vec.h"

static ecc_key g_dhuk_key;
static WC_RNG  g_dhuk_rng;
static int     g_dhuk_ready;

/* DHUK derivation seed used to wrap the identity scalar (matches the crypto
 * self-test provisioning). In production the wrapped blob is provisioned
 * off-device and the plaintext scalar never exists here. */
static const byte g_dhuk_seed[32] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
    0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01
};
#endif /* ENABLE_DHUK_KEY */

/* Configuration */
#ifndef TLS_CLIENT_BUF_SIZE
#define TLS_CLIENT_BUF_SIZE 2048
#endif

/* Forced cipher suite for the 3A.0 mutual-auth test. */
#ifndef TLS_CLIENT_CIPHER
#define TLS_CLIENT_CIPHER "TLS_AES_128_GCM_SHA256"
#endif

/* Client state */
typedef enum {
    TLS_CLIENT_STATE_IDLE = 0,
    TLS_CLIENT_STATE_DNS_LOOKUP,
    TLS_CLIENT_STATE_CONNECTING,
    TLS_CLIENT_STATE_HANDSHAKE,
    TLS_CLIENT_STATE_CONNECTED,
    TLS_CLIENT_STATE_DONE,
    TLS_CLIENT_STATE_ERROR
} tls_client_state_t;

/* Client context */
static struct {
    struct wolfIP *stack;
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    int fd;
    tls_client_state_t state;
    tls_client_debug_cb debug_cb;
    tls_client_response_cb response_cb;
    void *user_ctx;
    uint8_t rx_buf[TLS_CLIENT_BUF_SIZE];
    ip4 server_ip;
    uint16_t server_port;
    char sni_host[64];
    int got_response;
    int connect_ready_count;
    unsigned int hs_polls;
    int hs_last_err;
} client;

/* External functions from wolfssl_io.c */
extern int wolfSSL_SetIO_wolfIP_CTX(WOLFSSL_CTX *ctx, struct wolfIP *s);
extern int wolfSSL_SetIO_wolfIP(WOLFSSL *ssl, int fd);

/* Debug output helper */
static void debug_print(const char *msg)
{
    if (client.debug_cb) {
        client.debug_cb(msg);
    }
}

#ifdef DEBUG_WOLFSSL
/* wolfSSL internal logging -> UART. */
static void tls_wolfssl_log(const int logLevel, const char *const logMessage)
{
    (void)logLevel;
    if (client.debug_cb && logMessage) {
        client.debug_cb("[ssl] ");
        client.debug_cb(logMessage);
        client.debug_cb("\n");
    }
}
#endif

/* Print "<key> = <val>\n" (val in decimal, handles negatives). */
static void debug_print_kv(const char *key, int val)
{
    char buf[16];
    int i = 0;
    unsigned int u;
    int neg = 0;

    if (!client.debug_cb) {
        return;
    }
    client.debug_cb(key);
    client.debug_cb(" = ");
    if (val < 0) {
        neg = 1;
        u = (unsigned int)(-val);
    } else {
        u = (unsigned int)val;
    }
    if (u == 0u) {
        buf[i++] = '0';
    }
    while (u > 0u && i < (int)sizeof(buf) - 1) {
        buf[i++] = (char)('0' + (u % 10u));
        u /= 10u;
    }
    if (neg && i < (int)sizeof(buf) - 1) {
        buf[i++] = '-';
    }
    {
        char rev[16];
        int j;
        for (j = 0; j < i; j++) {
            rev[j] = buf[i - 1 - j];
        }
        rev[i] = '\0';
        client.debug_cb(rev);
    }
    client.debug_cb("\n");
}

#ifdef ENABLE_DHUK_KEY
/* PK (EccSign) callback: sign the CertificateVerify hash with the DHUK-wrapped
 * identity key. wc_ecc_sign_hash on a WC_DHUK_DEVID key dispatches to the STM32
 * crypto callback (SAES unwrap -> HW PKA). The loaded placeholder key (keyDer)
 * is intentionally ignored. */
static int dhuk_ecc_sign_cb(WOLFSSL *ssl, const byte *in, word32 inSz,
    byte *out, word32 *outSz, const byte *keyDer, word32 keySz, void *ctx)
{
    int ret;
    (void)ssl;
    (void)keyDer;
    (void)keySz;
    (void)ctx;
    debug_print("TLS Client: CertificateVerify -> DHUK sign callback (SAES unwrap -> HW PKA)\n");
    ret = wc_ecc_sign_hash(in, inSz, out, outSz, &g_dhuk_rng, &g_dhuk_key);
    debug_print_kv("TLS Client: DHUK sign ret", ret);
    return ret;
}

/* Register the DHUK device and provision the wrapped identity key. */
static int dhuk_provision_key(void)
{
    Aes  aes;
    byte wrapped[32];
    int  ret;

    ret = wc_Stm32_DhukRegister(WC_DHUK_DEVID);
    if (ret != 0) {
        debug_print_kv("TLS Client: DHUK register err", ret);
        return ret;
    }
    ret = wc_InitRng(&g_dhuk_rng);
    if (ret != 0) {
        debug_print_kv("TLS Client: DHUK rng err", ret);
        return ret;
    }
    ret = wc_ecc_init_ex(&g_dhuk_key, NULL, WC_DHUK_DEVID);
    if (ret != 0) {
        debug_print_kv("TLS Client: DHUK ecc init err", ret);
        return ret;
    }
    /* Curve + public point from the identity vector (public, for verify). */
    ret = wc_ecc_import_unsigned(&g_dhuk_key, (byte *)SigGen_Qx,
        (byte *)SigGen_Qy, NULL, ECC_SECP256R1);
    if (ret != 0) {
        debug_print_kv("TLS Client: DHUK import pub err", ret);
        return ret;
    }
    /* Wrap the identity scalar with the DHUK-derived AES key (SAES). */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, g_dhuk_seed, 32, NULL, AES_ENCRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesEcbEncrypt(&aes, wrapped, (byte *)SigGen_D, 32);
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        debug_print_kv("TLS Client: DHUK wrap err", ret);
        return ret;
    }
    ret = wc_ecc_import_wrapped_private(&g_dhuk_key, g_dhuk_seed, 32,
        wrapped, 32, 32);
    if (ret != 0) {
        debug_print_kv("TLS Client: DHUK import wrapped err", ret);
        return ret;
    }
    g_dhuk_ready = 1;
    debug_print("TLS Client: DHUK identity key provisioned (devId)\n");
    return 0;
}
#endif /* ENABLE_DHUK_KEY */

int tls_client_init(struct wolfIP *stack, tls_client_debug_cb debug)
{
    int ret;

    memset(&client, 0, sizeof(client));
    client.stack = stack;
    client.debug_cb = debug;
    client.fd = -1;
    client.state = TLS_CLIENT_STATE_IDLE;

    debug_print("TLS Client: Initializing wolfSSL\n");

#ifdef DEBUG_WOLFSSL
    /* Route wolfSSL's internal trace to the UART so we can see exactly
     * where a hang occurs during wolfSSL_new / wolfSSL_connect. */
    wolfSSL_SetLoggingCb(tls_wolfssl_log);
    wolfSSL_Debugging_ON();
#endif

    /* Initialize wolfSSL library (may already be done elsewhere) */
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        debug_print("TLS Client: wolfSSL_Init failed\n");
        return -1;
    }

    /* Create TLS 1.3 client context */
    client.ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (client.ctx == NULL) {
        debug_print("TLS Client: CTX_new failed\n");
        return -1;
    }

    /* Mutual auth: load the device client certificate (binds the P-256
     * identity public key). DER / ASN.1 encoded in tls_certs.h. */
    ret = wolfSSL_CTX_use_certificate_buffer(client.ctx,
        client_cert_der, (long)client_cert_der_len, WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        debug_print("TLS Client: Failed! load client certificate\n");
        return -1;
    }

    /* Mutual auth: load the SEC1 EC identity private key (raw scalar, for
     * this software bring-up only; the DHUK build will sign via callback).
     * SEC1 EC keys are ASN.1 (FILETYPE_ASN1); if the loader rejects it that
     * is a real finding, not something to paper over. */
    ret = wolfSSL_CTX_use_PrivateKey_buffer(client.ctx,
        client_key_der, (long)client_key_der_len, WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        debug_print("TLS Client: Failed! load client private key\n");
        return -1;
    }

    /* Server verification OFF for 3A.0: the SERVER verifies US. Server auth
     * is not the point of this test. */
    wolfSSL_CTX_set_verify(client.ctx, WOLFSSL_VERIFY_NONE, NULL);

    /* Force the TLS 1.3 suite under test. */
    ret = wolfSSL_CTX_set_cipher_list(client.ctx, TLS_CLIENT_CIPHER);
    if (ret != WOLFSSL_SUCCESS) {
        debug_print("TLS Client: Failed! set cipher list\n");
        return -1;
    }

#ifdef ENABLE_DHUK_KEY
    /* 3A.1: provision the DHUK-wrapped identity key and route the
     * CertificateVerify signature through the crypto callback (HW PKA).
     * The placeholder key loaded above satisfies wolfSSL's cert/key
     * association; the PK callback overrides the actual signing so the
     * identity scalar is only ever unwrapped inside SAES. */
    ret = dhuk_provision_key();
    if (ret != 0) {
        debug_print("TLS Client: Failed! DHUK key provisioning\n");
        return -1;
    }
    wolfSSL_CTX_SetEccSignCb(client.ctx, dhuk_ecc_sign_cb);
#endif

    /* Register wolfIP I/O callbacks */
    wolfSSL_SetIO_wolfIP_CTX(client.ctx, stack);

    debug_print("TLS Client: Initialized (mutual auth)\n");
    return 0;
}

void tls_client_set_sni(const char *hostname)
{
    if (hostname) {
        strncpy(client.sni_host, hostname, sizeof(client.sni_host) - 1);
        client.sni_host[sizeof(client.sni_host) - 1] = '\0';
    } else {
        client.sni_host[0] = '\0';
    }
}

int tls_client_connect(const char *host, uint16_t port,
                       tls_client_response_cb response_cb, void *user_ctx)
{
    struct wolfIP_sockaddr_in addr;
    int ret;

    if (client.state != TLS_CLIENT_STATE_IDLE) {
        debug_print("TLS Client: Already busy\n");
        return -1;
    }

    client.response_cb = response_cb;
    client.user_ctx = user_ctx;
    client.server_port = port;

    /* Try to parse as IP address first */
    client.server_ip = atoip4(host);
    if (client.server_ip == 0) {
        /* DNS lookup not implemented - require IP address */
        debug_print("TLS Client: DNS not implemented, use IP address\n");
        return -1;
    }

    /* Create socket */
    client.fd = wolfIP_sock_socket(client.stack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (client.fd < 0) {
        debug_print("TLS Client: Failed! socket() error\n");
        return -1;
    }

    /* Connect to server */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(port);
    addr.sin_addr.s_addr = ee32(client.server_ip);

    ret = wolfIP_sock_connect(client.stack, client.fd,
                              (struct wolfIP_sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && ret != -WOLFIP_EAGAIN) {
        debug_print("TLS Client: Failed! connect() error\n");
        wolfIP_sock_close(client.stack, client.fd);
        client.fd = -1;
        return -1;
    }

    client.state = TLS_CLIENT_STATE_CONNECTING;
    debug_print("TLS Client: Connecting...\n");
    return 0;
}

/* Print negotiated protocol version and cipher after a successful handshake. */
static void tls_client_report_handshake(void)
{
    const char *ver;
    const char *cipher;

    ver = wolfSSL_get_version(client.ssl);
    cipher = wolfSSL_get_cipher(client.ssl);

    debug_print("TLS Client: version = ");
    debug_print(ver ? ver : "(null)");
    debug_print("\n");
    debug_print("TLS Client: cipher  = ");
    debug_print(cipher ? cipher : "(null)");
    debug_print("\n");
}

/* Call this from main loop to drive the TLS client state machine */
int tls_client_poll(void)
{
    int ret;
    int err;

    switch (client.state) {
        case TLS_CLIENT_STATE_IDLE:
        case TLS_CLIENT_STATE_DONE:
        case TLS_CLIENT_STATE_ERROR:
            return 0;

        case TLS_CLIENT_STATE_CONNECTING:
            /* Check if TCP connection is established by calling connect again */
            {
                struct wolfIP_sockaddr_in addr;

                memset(&addr, 0, sizeof(addr));
                addr.sin_family = AF_INET;
                addr.sin_port = ee16(client.server_port);
                addr.sin_addr.s_addr = ee32(client.server_ip);

                ret = wolfIP_sock_connect(client.stack, client.fd,
                                          (struct wolfIP_sockaddr *)&addr, sizeof(addr));
                if (ret == -WOLFIP_EAGAIN) {
                    /* Still connecting, keep polling */
                    client.connect_ready_count = 0;
                    return 0;
                }
                if (ret < 0) {
                    debug_print("TLS Client: Failed! TCP connect error\n");
                    client.state = TLS_CLIENT_STATE_ERROR;
                    return -1;
                }
                /* Connection established - wait a few poll cycles to settle */
                client.connect_ready_count++;
                if (client.connect_ready_count < 10) {
                    return 0;
                }
                client.connect_ready_count = 0;
            }
            debug_print("TLS Client: TLS handshake...\n");

            /* Create SSL object */
            client.ssl = wolfSSL_new(client.ctx);
            if (client.ssl == NULL) {
                debug_print("TLS Client: Failed! SSL context error\n");
                client.state = TLS_CLIENT_STATE_ERROR;
                return -1;
            }

            /* Set SNI (Server Name Indication) if configured */
            if (client.sni_host[0]) {
                wolfSSL_UseSNI(client.ssl, WOLFSSL_SNI_HOST_NAME,
                    client.sni_host, (word16)strlen(client.sni_host));
            }

            /* Associate SSL with socket */
            ret = wolfSSL_SetIO_wolfIP(client.ssl, client.fd);
            if (ret != 0) {
                debug_print("TLS Client: Failed! I/O setup error\n");
                client.state = TLS_CLIENT_STATE_ERROR;
                return -1;
            }
            client.state = TLS_CLIENT_STATE_HANDSHAKE;
            __attribute__((fallthrough));

        case TLS_CLIENT_STATE_HANDSHAKE:
            /* Heartbeat: if this count keeps rising, wolfSSL_connect is
             * returning each poll (stuck WANT_READ/WRITE); if it freezes,
             * a crypto op is hung inside wolfSSL_connect. */
            client.hs_polls++;
            if (client.hs_polls == 1u || (client.hs_polls % 50u) == 0u) {
                debug_print_kv("TLS hs poll", (int)client.hs_polls);
                debug_print_kv("  last err", client.hs_last_err);
            }
            ret = wolfSSL_connect(client.ssl);
            if (ret == WOLFSSL_SUCCESS) {
                debug_print("TLS Client: Connected!\n");
                tls_client_report_handshake();
                client.state = TLS_CLIENT_STATE_CONNECTED;
            } else {
                err = wolfSSL_get_error(client.ssl, ret);
                client.hs_last_err = err;
                if (err == WOLFSSL_ERROR_WANT_READ ||
                    err == WOLFSSL_ERROR_WANT_WRITE) {
                    /* Handshake in progress, continue polling */
                    return 0;
                }
                debug_print_kv("TLS Client: Failed! Handshake err", err);
                client.state = TLS_CLIENT_STATE_ERROR;
                return -1;
            }
            break;

        case TLS_CLIENT_STATE_CONNECTED:
            /* Try to read any response */
            ret = wolfSSL_read(client.ssl, client.rx_buf,
                               sizeof(client.rx_buf) - 1);
            if (ret > 0) {
                client.rx_buf[ret] = '\0';
                client.got_response = 1;
                if (client.response_cb) {
                    client.response_cb((char *)client.rx_buf, ret, client.user_ctx);
                }
            } else {
                err = wolfSSL_get_error(client.ssl, ret);
                if (err == WOLFSSL_ERROR_ZERO_RETURN) {
                    /* Server closed connection - normal after response */
                    if (client.got_response) {
                        debug_print("TLS Client: Passed! Received response from server\n");
                    } else {
                        debug_print("TLS Client: Failed! Server closed connection (no data received)\n");
                    }
                    client.state = TLS_CLIENT_STATE_DONE;
                } else if (err != WOLFSSL_ERROR_WANT_READ) {
                    /* Connection closed/reset - check if we got data first */
                    if (client.got_response) {
                        debug_print("TLS Client: Passed! Connection closed after response\n");
                        client.state = TLS_CLIENT_STATE_DONE;
                    } else {
                        debug_print("TLS Client: Failed! Read error (no response received)\n");
                        client.state = TLS_CLIENT_STATE_ERROR;
                    }
                }
            }
            break;

        default:
            break;
    }

    return 0;
}

int tls_client_send(const void *data, int len)
{
    int ret;
    int err;

    if (client.state != TLS_CLIENT_STATE_CONNECTED) {
        return -1;
    }

    ret = wolfSSL_write(client.ssl, data, len);
    if (ret <= 0) {
        err = wolfSSL_get_error(client.ssl, ret);
        if (err != WOLFSSL_ERROR_WANT_WRITE) {
            debug_print("TLS Client: Write failed\n");
            return -1;
        }
    }

    return ret;
}

void tls_client_close(void)
{
    if (client.ssl) {
        wolfSSL_shutdown(client.ssl);
        wolfSSL_free(client.ssl);
        client.ssl = NULL;
    }
    if (client.fd >= 0 && client.stack) {
        wolfIP_sock_close(client.stack, client.fd);
        client.fd = -1;
    }
    client.got_response = 0;
    client.connect_ready_count = 0;
    client.state = TLS_CLIENT_STATE_IDLE;
}

int tls_client_is_connected(void)
{
    return (client.state == TLS_CLIENT_STATE_CONNECTED);
}

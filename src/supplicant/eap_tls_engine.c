/* eap_tls_engine.c
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

#include "eap_tls_engine.h"

#include <string.h>

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

/* Translate our format flag to wolfSSL's value. */
static int xlate_fmt(int f)
{
    if (f == WOLFIP_EAP_TLS_FMT_PEM) return WOLFSSL_FILETYPE_PEM;
    return WOLFSSL_FILETYPE_ASN1;   /* default DER */
}

/* IORecv: pull buffered TLS bytes (already extracted from EAP-TLS
 * fragments) into wolfSSL's read path. */
static int eap_tls_io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    struct eap_tls_engine *e = (struct eap_tls_engine *)ctx;
    size_t available;
    size_t take;
    (void)ssl;

    if (e == NULL || buf == NULL || sz <= 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    if (e->io.rx_filled < e->io.rx_drained) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    available = e->io.rx_filled - e->io.rx_drained;
    if (available == 0U) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    take = (size_t)sz;
    if (take > available) {
        take = available;
    }
    memcpy(buf, e->io.rx_buf + e->io.rx_drained, take);
    e->io.rx_drained += take;

    /* When wolfSSL drains the current fragment fully and the EAP layer
     * has marked rx_complete, reset for the next inbound message so
     * subsequent IORecv calls return WANT_READ instead of stale data. */
    if (e->io.rx_complete && e->io.rx_drained == e->io.rx_filled) {
        e->io.rx_drained = 0;
        e->io.rx_filled  = 0;
        e->io.rx_total   = 0;
        e->io.rx_complete = 0;
    }
    return (int)take;
}

/* IOSend: append wolfSSL's TLS output to the outbound buffer. The
 * supplicant later drains tx_buf into one or more EAP-TLS fragments. */
static int eap_tls_io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    struct eap_tls_engine *e = (struct eap_tls_engine *)ctx;
    size_t capacity;
    (void)ssl;

    if (e == NULL || buf == NULL || sz <= 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    if (e->io.tx_filled > sizeof(e->io.tx_buf)) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    capacity = sizeof(e->io.tx_buf) - e->io.tx_filled;
    if (capacity == 0U) {
        /* TLS handshake too large to buffer in one round. The EAP layer
         * should drain tx_buf via eap_tls_tx_fragment() between IOSend
         * calls; if we hit this it means the engine produced more than
         * one full buffer at once. */
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    if ((size_t)sz > capacity) {
        sz = (int)capacity;
    }
    memcpy(e->io.tx_buf + e->io.tx_filled, buf, (size_t)sz);
    e->io.tx_filled += (size_t)sz;
    return sz;
}

static WOLFSSL_METHOD *pick_method(int tls_version_pin)
{
    if (tls_version_pin == 1) {
        return wolfTLSv1_2_client_method();
    }
    if (tls_version_pin == 2) {
        return wolfTLSv1_3_client_method();
    }
    /* Default: SSLv23 client method auto-negotiates the highest
     * supported version (1.2 or 1.3). */
    return wolfSSLv23_client_method();
}

int eap_tls_engine_init(struct eap_tls_engine *e,
                        const struct eap_tls_engine_cfg *cfg)
{
    WOLFSSL_METHOD *method;
    int ret;

    if (e == NULL || cfg == NULL) {
        return -1;
    }
    if (cfg->ca == NULL || cfg->ca_len == 0) {
        return -1;
    }
    /* Client cert + key are optional. Required for mutual EAP-TLS, not
     * for PEAP (where the client authenticates inside the tunnel via
     * MSCHAPv2 etc.). Both must be supplied together or both NULL. */
    if ((cfg->client_cert != NULL) != (cfg->client_key != NULL)) {
        return -1;
    }

    memset(e, 0, sizeof(*e));
    eap_tls_io_reset(&e->io);

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        return -1;
    }
    e->wolfssl_inited = 1;   /* _free() will balance this with _Cleanup() */

    method = pick_method(cfg->tls_version_pin);
    if (method == NULL) {
        eap_tls_engine_free(e);
        return -1;
    }
    e->ctx = wolfSSL_CTX_new(method);
    if (e->ctx == NULL) {
        eap_tls_engine_free(e);
        return -1;
    }

    /* Hard-fail on bad server certs - the default verify mode is already
     * SSL_VERIFY_PEER for a client method, but make it explicit. */
    wolfSSL_CTX_set_verify(e->ctx, WOLFSSL_VERIFY_PEER, NULL);

    /* Wire custom IO at the context level; per-session ctx pointer is
     * set after wolfSSL_new(). */
    wolfSSL_CTX_SetIORecv(e->ctx, eap_tls_io_recv);
    wolfSSL_CTX_SetIOSend(e->ctx, eap_tls_io_send);

    /* Load trusted CA(s). */
    ret = wolfSSL_CTX_load_verify_buffer(e->ctx,
                                         cfg->ca, (long)cfg->ca_len,
                                         xlate_fmt(cfg->ca_format));
    if (ret != WOLFSSL_SUCCESS) {
        eap_tls_engine_free(e);
        return -1;
    }

    /* Load client cert chain if supplied. PEAP supplicants skip this. */
    if (cfg->client_cert != NULL && cfg->client_cert_len > 0) {
        ret = wolfSSL_CTX_use_certificate_buffer(e->ctx,
                                                 cfg->client_cert,
                                                 (long)cfg->client_cert_len,
                                                 xlate_fmt(cfg->client_cert_format));
        if (ret != WOLFSSL_SUCCESS) {
            eap_tls_engine_free(e);
            return -1;
        }
        ret = wolfSSL_CTX_use_PrivateKey_buffer(e->ctx,
                                                cfg->client_key,
                                                (long)cfg->client_key_len,
                                                xlate_fmt(cfg->client_key_format));
        if (ret != WOLFSSL_SUCCESS) {
            eap_tls_engine_free(e);
            return -1;
        }
    }

    e->ssl = wolfSSL_new(e->ctx);
    if (e->ssl == NULL) {
        eap_tls_engine_free(e);
        return -1;
    }
    wolfSSL_SetIOReadCtx(e->ssl, e);
    wolfSSL_SetIOWriteCtx(e->ssl, e);

    /* Preserve master_secret + client/server randoms past handshake so
     * wolfSSL_make_eap_keys can synthesize the MSK afterwards. Must be
     * set before wolfSSL_connect runs. */
    wolfSSL_KeepArrays(e->ssl);

    /* Optional server name pinning. wolfSSL_check_domain_name extends
     * peer-cert validation to require the name appear in SAN/CN. */
    if (cfg->server_name_pin != NULL) {
        ret = wolfSSL_check_domain_name(e->ssl, cfg->server_name_pin);
        if (ret != WOLFSSL_SUCCESS) {
            eap_tls_engine_free(e);
            return -1;
        }
    }
    return 0;
}

void eap_tls_engine_free(struct eap_tls_engine *e)
{
    if (e == NULL) {
        return;
    }
    if (e->ssl != NULL) {
        wolfSSL_free(e->ssl);
        e->ssl = NULL;
    }
    if (e->ctx != NULL) {
        wolfSSL_CTX_free(e->ctx);
        e->ctx = NULL;
    }
    /* Balance the wolfSSL_Init() done in eap_tls_engine_init so the global
     * refcount does not grow across re-inits (LOW-17). Only when this engine
     * actually initialized wolfSSL. */
    if (e->wolfssl_inited) {
        wolfSSL_Cleanup();
        e->wolfssl_inited = 0;
    }
    memset(&e->io, 0, sizeof(e->io));
    e->io.tx_first_frag = 1;
}

int eap_tls_engine_step(struct eap_tls_engine *e)
{
    int ret;
    int err;

    if (e == NULL || e->ssl == NULL) {
        return -1;
    }
    if (e->failed) {
        return -1;
    }
    if (e->handshake_complete) {
        return 1;
    }

    ret = wolfSSL_connect(e->ssl);
    if (ret == WOLFSSL_SUCCESS) {
        e->handshake_complete = 1;
        return 1;
    }
    err = wolfSSL_get_error(e->ssl, ret);
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
        /* Need more inbound data (next EAP-Request) or to drain our
         * outbound buffer (caller will fragment). Either way, not
         * fatal - keep stepping. */
        return 0;
    }
    e->failed = 1;
    return -1;
}

int eap_tls_engine_export_msk(struct eap_tls_engine *e,
                              uint8_t msk[WOLFIP_EAP_TLS_MSK_LEN])
{
    int ret;
    if (e == NULL || msk == NULL || e->ssl == NULL) {
        return -1;
    }
    if (!e->handshake_complete) {
        return -1;
    }
    /* The MSK derivation differs by TLS version:
     *   TLS <= 1.2 (RFC 5216): TLS-PRF over the master secret with the
     *     "client EAP encryption" label (wolfSSL_make_eap_keys).
     *   TLS 1.3 (RFC 9190): the master secret no longer exists; the MSK is
     *     the first 64 bytes of the TLS Exporter output for the label
     *     "EXPORTER_EAP_TLS_Key_Material" with the 1-octet EAP-TLS Type-Code
     *     (0x0D) as the exporter context. wolfSSL_make_eap_keys would
     *     silently compute the (nonexistent) 1.2 PRF here, producing an MSK
     *     that does not match the authenticator. */
    if (wolfSSL_GetVersion(e->ssl) == WOLFSSL_TLSV1_3) {
#ifdef HAVE_KEYING_MATERIAL
        static const char label[] = "EXPORTER_EAP_TLS_Key_Material";
        unsigned char     type_code = 0x0D;   /* EAP-TLS */
        ret = (wolfSSL_export_keying_material(e->ssl, msk,
                   (size_t)WOLFIP_EAP_TLS_MSK_LEN,
                   label, sizeof(label) - 1U, &type_code, 1U, 1)
               == WOLFSSL_SUCCESS) ? 0 : -1;
#else
        /* RFC 9190 MSK needs the TLS Exporter (build wolfSSL with
         * --enable-keying-material). Fail loudly rather than derive a
         * wrong MSK from the absent 1.2 PRF. */
        ret = -1;
#endif
    }
    else {
        ret = (wolfSSL_make_eap_keys(e->ssl, msk,
                                     (unsigned int)WOLFIP_EAP_TLS_MSK_LEN,
                                     "client EAP encryption") == 0) ? 0 : -1;
    }
    /* The MSK has been derived; release the master_secret + client/server
     * randoms that wolfSSL_KeepArrays (in _init) preserved past the
     * handshake so the key material does not linger in the WOLFSSL object. */
    wolfSSL_FreeArrays(e->ssl);
    return ret;
}

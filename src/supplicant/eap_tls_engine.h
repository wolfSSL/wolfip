/* eap_tls_engine.h
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

/* Glue between EAP-TLS framing and wolfSSL. Drives the wolfSSL client
 * handshake using custom IO callbacks (WOLFSSL_USER_IO), with TLS
 * record bytes shuttled through eap_tls_io ring buffers. No OpenSSL
 * compatibility layer; native wolfSSL API only.
 */

#ifndef WOLFIP_SUPPLICANT_EAP_TLS_ENGINE_H
#define WOLFIP_SUPPLICANT_EAP_TLS_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#include "eap_tls.h"

/* Forward declarations - keep wolfSSL types out of the header surface so
 * non-EAP-TLS builds don't drag wolfssl/ssl.h transitively. */
struct WOLFSSL_CTX;
struct WOLFSSL;

#define WOLFIP_EAP_TLS_MSK_LEN 64U

/* Certificate / key format flags passed through to wolfSSL. */
#define WOLFIP_EAP_TLS_FMT_DER 1
#define WOLFIP_EAP_TLS_FMT_PEM 2

struct eap_tls_engine_cfg {
    /* Required: CA cert(s) the supplicant uses to verify the EAP
     * authentication server's certificate. */
    const uint8_t *ca;
    size_t         ca_len;
    int            ca_format;     /* WOLFIP_EAP_TLS_FMT_* */

    /* Required for EAP-TLS (mutual): client certificate + private key. */
    const uint8_t *client_cert;
    size_t         client_cert_len;
    int            client_cert_format;

    const uint8_t *client_key;
    size_t         client_key_len;
    int            client_key_format;

    /* Optional: TLS protocol cap. 0 = allow any (recommended); the
     * engine negotiates the highest version both peers support.
     *   1 = force TLS 1.2 only
     *   2 = force TLS 1.3 only
     */
    int            tls_version_pin;

    /* Optional: expected server hostname for SAN/CN pinning. NULL means
     * "trust any name signed by a configured CA". */
    const char    *server_name_pin;
};

struct eap_tls_engine {
    struct WOLFSSL_CTX *ctx;
    struct WOLFSSL     *ssl;
    struct eap_tls_io   io;
    int                 handshake_complete;
    int                 failed;
    int                 wolfssl_inited;  /* 1 if wolfSSL_Init() succeeded;
                                          * _free() calls wolfSSL_Cleanup()
                                          * only then, balancing the refcount */
};

#ifdef __cplusplus
extern "C" {
#endif

int  eap_tls_engine_init(struct eap_tls_engine *e,
                         const struct eap_tls_engine_cfg *cfg);

void eap_tls_engine_free(struct eap_tls_engine *e);

/* Drive the wolfSSL handshake. Call after a new TLS fragment has been
 * appended to e->io.rx_buf (or for the very first step where wolfSSL
 * needs to emit ClientHello with no inbound data).
 *
 * Returns:
 *    1 - handshake complete; engine ready for MSK export
 *    0 - in progress; outbound bytes (if any) are now in e->io.tx_buf
 *   -1 - fatal error; engine is in failed state
 */
int  eap_tls_engine_step(struct eap_tls_engine *e);

/* After eap_tls_engine_step returns 1, export the 64-byte MSK. The
 * derivation is version-specific: TLS <= 1.2 uses the RFC 5216 PRF
 * (wolfSSL_make_eap_keys, label "client EAP encryption"); TLS 1.3 uses the
 * RFC 9190 TLS Exporter (label "EXPORTER_EAP_TLS_Key_Material",
 * EAP-TLS Type-Code context), which requires a wolfSSL built with
 * --enable-keying-material (else the 1.3 export fails rather than returning
 * a wrong MSK). Caller takes msk[0..31] as the PMK for the subsequent 4-way
 * handshake; msk[32..63] becomes the EMSK (currently unused).
 *
 * Returns 0 on success.
 */
int  eap_tls_engine_export_msk(struct eap_tls_engine *e,
                               uint8_t msk[WOLFIP_EAP_TLS_MSK_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_SUPPLICANT_EAP_TLS_ENGINE_H */

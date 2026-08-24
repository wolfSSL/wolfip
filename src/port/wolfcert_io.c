/* wolfcert_io.c
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
 *
 * wolfIP <-> wolfCert glue: a WolfCertTransport over wolfIP sockets.
 * Carries TLS records and plain HTTP alike, so it holds no TLS code of its
 * own - wolfCert bridges wolfSSL's CBIO onto these same callbacks.
 */
#include "wolfip.h"
#include <wolfcert/types.h>
#include <wolfcert/errors.h>
#include <string.h>
#include <limits.h>

#ifndef MAX_WOLFCERT_CTX
    #define MAX_WOLFCERT_CTX 2
#endif

/* Cap on a blocking transfer; wolfIP has no timeout of its own. */
#ifndef WOLFCERT_WOLFIP_IO_TIMEOUT_MS
    #define WOLFCERT_WOLFIP_IO_TIMEOUT_MS 30000
#endif

/* Cap on a connect the caller left unbounded; wolfIP has none of its own. */
#ifndef WOLFCERT_WOLFIP_CONNECT_TIMEOUT_MS
    #define WOLFCERT_WOLFIP_CONNECT_TIMEOUT_MS 30000
#endif

/* nslookup() reports this while another query is in flight. */
#define WOLFCERT_WOLFIP_DNS_BUSY (-16)

/* Per-transport state; a connection is just its wolfIP descriptor. */
struct wolfcert_io_ctx {
    struct wolfIP *stack;
    uint64_t (*now_ms)(void);
    int in_use;
};

static struct wolfcert_io_ctx io_ctxs[MAX_WOLFCERT_CTX];

/* nslookup()'s callback carries no user pointer, so the answer lands here.
 * One slot serves every context: only one resolution runs at a time. */
static uint32_t dns_result_ip;
static int dns_result_ready;

/* Claim a free slot; stack and now_ms are filled in by the caller. */
static struct wolfcert_io_ctx *io_ctx_alloc(void)
{
    int i;

    for (i = 0; i < MAX_WOLFCERT_CTX; i++) {
        if (io_ctxs[i].in_use == 0) {
            io_ctxs[i].in_use = 1;
            return &io_ctxs[i];
        }
    }
    return NULL;
}

static void io_ctx_free(struct wolfcert_io_ctx *c)
{
    if (c != NULL) {
        c->stack = NULL;
        c->now_ms = NULL;
        c->in_use = 0;
    }
}

/* Elapsed against timeout_ms, or against dflt when the caller gave none. */
static int deadline_expired(struct wolfcert_io_ctx *c, uint64_t start,
                            int timeout_ms, uint64_t dflt)
{
    uint64_t budget = (timeout_ms > 0) ? (uint64_t)timeout_ms : dflt;

    return ((c->now_ms() - start) >= budget);
}

/* Decide whether the host is a dotted quad or a name for the resolver.
 * Rejects anything atoip4() would silently turn into a wrong address. */
static int is_ipv4_literal(const char *host)
{
    int octet = 0;
    int digits = 0;
    int dots = 0;
    int i;

    for (i = 0; host[i] != '\0'; i++) {
        if (host[i] == '.') {
            if (digits == 0)
                return 0;
            octet = 0;
            digits = 0;
            dots++;
        }
        else if ((host[i] >= '0') && (host[i] <= '9')) {
            octet = (octet * 10) + (host[i] - '0');
            digits++;
            if ((digits > 3) || (octet > 255))
                return 0;
        }
        else {
            return 0;
        }
    }
    return ((dots == 3) && (digits > 0));
}

static void dns_result_cb(uint32_t ip)
{
    dns_result_ip = ip;
    dns_result_ready = 1;
}

static int resolve_host(struct wolfcert_io_ctx *c, const char *host,
                        uint64_t start, int timeout_ms, ip4 *out)
{
    uint16_t id = 0;
    int rc = -1;

    if (is_ipv4_literal(host)) {
        *out = atoip4(host);
        if (*out == 0)
            return WOLFCERT_ERR_BAD_ARG;
        return WOLFCERT_OK;
    }

    for (;;) {
        rc = nslookup(c->stack, host, &id, dns_result_cb);
        if (rc == 0)
            break;
        /* Both codes are transient; the query is not armed either way. */
        if ((rc != WOLFCERT_WOLFIP_DNS_BUSY) && (rc != -WOLFIP_EAGAIN))
            return WOLFCERT_ERR_IO;
        if (deadline_expired(c, start, timeout_ms,
                             WOLFCERT_WOLFIP_CONNECT_TIMEOUT_MS))
            return WOLFCERT_ERR_IO;
        (void)wolfIP_poll(c->stack, c->now_ms());
    }

    /* Clear once our own query is armed */
    dns_result_ip = 0;
    dns_result_ready = 0;

    for (;;) {
        if (dns_result_ready != 0) {
            if (dns_result_ip == 0)
                return WOLFCERT_ERR_NOT_FOUND;
            *out = (ip4)dns_result_ip;
            return WOLFCERT_OK;
        }
        if (deadline_expired(c, start, timeout_ms,
                             WOLFCERT_WOLFIP_CONNECT_TIMEOUT_MS))
            return WOLFCERT_ERR_IO;
        (void)wolfIP_poll(c->stack, c->now_ms());
    }
}

/* -WOLFIP_EAGAIN is the only retryable code; a bare -1 is a dead socket and
 * reporting it as would-block would spin the caller forever. */
static int map_io_error(int rc, int want)
{
    if (rc == -WOLFIP_EAGAIN)
        return want;
    if (rc == -1)
        return WOLFCERT_ERR_CONN_CLOSED;
    if (rc == -WOLFIP_EINVAL)
        return WOLFCERT_ERR_BAD_ARG;
    return WOLFCERT_ERR_IO;
}

static int wolfcert_wolfip_connect(void *ctx, const char *host, int port,
                                   int timeout_ms, void **conn)
{
    struct wolfcert_io_ctx *c = (struct wolfcert_io_ctx *)ctx;
    struct wolfIP_sockaddr_in addr;
    uint64_t start;
    ip4 ip = 0;
    int ret;
    int fd;
    int rc;

    if ((c == NULL) || (host == NULL) || (host[0] == '\0') || (conn == NULL))
        return WOLFCERT_ERR_BAD_ARG;
    if ((port <= 0) || (port > 65535))
        return WOLFCERT_ERR_BAD_ARG;

    start = c->now_ms();

    ret = resolve_host(c, host, start, timeout_ms, &ip);
    if (ret != WOLFCERT_OK)
        return ret;

    fd = wolfIP_sock_socket(c->stack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (fd < 0)
        return WOLFCERT_ERR_IO;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16((uint16_t)port);
    addr.sin_addr.s_addr = ee32(ip);

    /* Re-issue with the same address each tick until it reports success. */
    ret = WOLFCERT_ERR_IO;
    for (;;) {
        rc = wolfIP_sock_connect(c->stack, fd,
                                 (struct wolfIP_sockaddr *)&addr,
                                 sizeof(addr));
        if (rc == 0) {
            ret = WOLFCERT_OK;
            break;
        }
        if (rc != -WOLFIP_EAGAIN) {
            ret = WOLFCERT_ERR_IO;
            break;
        }
        if (deadline_expired(c, start, timeout_ms,
                             WOLFCERT_WOLFIP_CONNECT_TIMEOUT_MS)) {
            ret = WOLFCERT_ERR_IO;
            break;
        }
        (void)wolfIP_poll(c->stack, c->now_ms());
    }

    if (ret != WOLFCERT_OK) {
        (void)wolfIP_sock_close(c->stack, fd);
        return ret;
    }

    *conn = (void *)(intptr_t)fd;
    return WOLFCERT_OK;
}

static int wolfcert_wolfip_read(void *ctx, void *conn, uint8_t *buf,
                                size_t len, int timeout_ms)
{
    struct wolfcert_io_ctx *c = (struct wolfcert_io_ctx *)ctx;
    int fd = (int)(intptr_t)conn;
    uint64_t start;
    int mapped;
    int rc;

    if ((c == NULL) || (buf == NULL) || (len == 0))
        return WOLFCERT_ERR_BAD_ARG;
    if (len > (size_t)INT_MAX)
        len = (size_t)INT_MAX;

    start = c->now_ms();

    for (;;) {
        rc = wolfIP_sock_recv(c->stack, fd, buf, len, 0);
        if (rc > 0)
            return rc;
        if (rc == 0)
            return WOLFCERT_ERR_CONN_CLOSED;

        mapped = map_io_error(rc, WOLFCERT_ERR_WANT_READ);
        if (mapped != WOLFCERT_ERR_WANT_READ)
            return mapped;

        /* Only a zero timeout reports would-block; the rest pump. */
        if (timeout_ms == 0)
            return WOLFCERT_ERR_WANT_READ;
        (void)wolfIP_poll(c->stack, c->now_ms());
        if (deadline_expired(c, start, timeout_ms,
                             WOLFCERT_WOLFIP_IO_TIMEOUT_MS))
            return WOLFCERT_ERR_IO;
    }
}

static int wolfcert_wolfip_write(void *ctx, void *conn, const uint8_t *buf,
                                 size_t len, int timeout_ms)
{
    struct wolfcert_io_ctx *c = (struct wolfcert_io_ctx *)ctx;
    int fd = (int)(intptr_t)conn;
    uint64_t start;
    int mapped;
    int rc;

    if ((c == NULL) || (buf == NULL) || (len == 0))
        return WOLFCERT_ERR_BAD_ARG;
    if (len > (size_t)INT_MAX)
        len = (size_t)INT_MAX;

    start = c->now_ms();

    for (;;) {
        rc = wolfIP_sock_send(c->stack, fd, buf, len, 0);
        if (rc > 0)
            return rc;
        mapped = map_io_error(rc, WOLFCERT_ERR_WANT_WRITE);
        if (mapped != WOLFCERT_ERR_WANT_WRITE)
            return mapped;

        if (timeout_ms == 0)
            return WOLFCERT_ERR_WANT_WRITE;
        (void)wolfIP_poll(c->stack, c->now_ms());
        if (deadline_expired(c, start, timeout_ms,
                             WOLFCERT_WOLFIP_IO_TIMEOUT_MS))
            return WOLFCERT_ERR_IO;
    }
}

/* Closing an established socket starts a FIN handshake and reports
 * -WOLFIP_EAGAIN until it finishes. Drive to complete the handshake. */
static int wolfcert_wolfip_disconnect(void *ctx, void *conn)
{
    struct wolfcert_io_ctx *c = (struct wolfcert_io_ctx *)ctx;
    uint64_t start;
    int rc;

    if (c == NULL)
        return WOLFCERT_ERR_BAD_ARG;

    start = c->now_ms();

    for (;;) {
        rc = wolfIP_sock_close(c->stack, (int)(intptr_t)conn);
        if (rc == 0)
            return WOLFCERT_OK;
        if (rc != -WOLFIP_EAGAIN)
            return WOLFCERT_ERR_IO;
        if (deadline_expired(c, start, 0, WOLFCERT_WOLFIP_IO_TIMEOUT_MS))
            return WOLFCERT_ERR_IO;
        (void)wolfIP_poll(c->stack, c->now_ms());
    }
}

/* Opens nothing: fills t, and returns the context */
void *wolfCert_Init_wolfIP(WolfCertTransport *t, struct wolfIP *stack,
                           uint64_t (*now_ms)(void))
{
    struct wolfcert_io_ctx *c;

    if ((t == NULL) || (stack == NULL) || (now_ms == NULL))
        return NULL;

    c = io_ctx_alloc();
    if (c == NULL)
        return NULL;

    c->stack = stack;
    c->now_ms = now_ms;

    t->connect = wolfcert_wolfip_connect;
    t->read = wolfcert_wolfip_read;
    t->write = wolfcert_wolfip_write;
    t->disconnect = wolfcert_wolfip_disconnect;
    t->ctx = c;

    return c;
}

/* Releases the context slot; closes no socket. */
void wolfCert_Cleanup_wolfIP(void *context)
{
    io_ctx_free((struct wolfcert_io_ctx *)context);
}

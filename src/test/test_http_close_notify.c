/* test_http_close_notify.c
 *
 * Copyright (C) 2024 wolfSSL Inc.
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
 *
 * Regression test for F-5732: every TLS connection-close path in httpd.c must
 * send the close_notify alert (wolfSSL_shutdown) before tearing the session
 * down (wolfSSL_CleanupIO_wolfIP / wolfSSL_free).  Skipping close_notify lets a
 * network-adjacent attacker truncate an HTTPS response indistinguishably from a
 * legitimate close (RFC 5246 7.2.1 / CWE-325).  These stubs record call order so
 * the test fails if any close site frees the session without a prior shutdown.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Pull in the unit under test directly; the close paths are not exported. */
#include "httpd.c"

/* --- ordered call tracking ----------------------------------------------- */
static int seq;
static int shutdown_seq;
static int cleanup_seq;
static int free_seq;
static int tls_teardown_calls;
static int sock_send_result;

static void reset_tracking(void)
{
    seq = 0;
    shutdown_seq = 0;
    cleanup_seq = 0;
    free_seq = 0;
    tls_teardown_calls = 0;
    sock_send_result = -1;
}

/* --- stubs for the wolfIP symbols referenced by httpd.c ------------------ */
int wolfIP_sock_socket(struct wolfIP *s, int d, int t, int p)
{ (void)s; (void)d; (void)t; (void)p; return -1; }
int wolfIP_sock_bind(struct wolfIP *s, int fd, const struct wolfIP_sockaddr *a, socklen_t l)
{ (void)s; (void)fd; (void)a; (void)l; return -1; }
int wolfIP_sock_listen(struct wolfIP *s, int fd, int b)
{ (void)s; (void)fd; (void)b; return -1; }
int wolfIP_sock_accept(struct wolfIP *s, int fd, struct wolfIP_sockaddr *a, socklen_t *l)
{ (void)s; (void)fd; (void)a; (void)l; return -1; }
int wolfIP_sock_send(struct wolfIP *s, int fd, const void *b, size_t l, int f)
{ (void)s; (void)fd; (void)b; (void)l; (void)f; return sock_send_result; }
int wolfIP_sock_recv(struct wolfIP *s, int fd, void *b, size_t l, int f)
{ (void)s; (void)fd; (void)b; (void)l; (void)f; return -1; }
int wolfIP_sock_close(struct wolfIP *s, int fd)
{ (void)s; (void)fd; return 0; }
void wolfIP_register_callback(struct wolfIP *s, int fd, tsocket_cb cb, void *arg)
{ (void)s; (void)fd; (void)cb; (void)arg; }

/* --- stubs for the wolfSSL symbols referenced by httpd.c ----------------- */
WOLFSSL *wolfSSL_new(WOLFSSL_CTX *ctx)
{ (void)ctx; return NULL; }
int wolfSSL_SetIO_wolfIP(WOLFSSL *ssl, int fd)
{ (void)ssl; (void)fd; return 0; }
int wolfSSL_SetIO_wolfIP_CTX(WOLFSSL_CTX *ctx, struct wolfIP *s)
{ (void)ctx; (void)s; return 0; }
/* All I/O fails, forcing every send/recv onto its error-close path. */
int wolfSSL_write(WOLFSSL *ssl, const void *data, int sz)
{ (void)ssl; (void)data; (void)sz; return -1; }
int wolfSSL_read(WOLFSSL *ssl, void *data, int sz)
{ (void)ssl; (void)data; (void)sz; return -1; }
int wolfSSL_get_error(WOLFSSL *ssl, int ret)
{ (void)ssl; (void)ret; return 0; /* not WANT_READ -> close */ }
int wolfSSL_shutdown(WOLFSSL *ssl)
{ (void)ssl; tls_teardown_calls++; shutdown_seq = ++seq; return 0; }
void wolfSSL_CleanupIO_wolfIP(WOLFSSL *ssl)
{ (void)ssl; tls_teardown_calls++; cleanup_seq = ++seq; }
void wolfSSL_free(WOLFSSL *ssl)
{ (void)ssl; tls_teardown_calls++; free_seq = ++seq; }

/* --- test harness -------------------------------------------------------- */
#define CHECK(cond) do { if (!(cond)) { \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static int failures;
static int ssl_marker; /* opaque non-NULL session handle */

static void check_close_emitted_close_notify(const char *site)
{
    /* close_notify must precede session/IO teardown on every close path. */
    if (shutdown_seq == 0) {
        printf("FAIL %s: wolfSSL_shutdown (close_notify) never called\n", site);
        failures++;
        return;
    }
    CHECK(shutdown_seq < cleanup_seq); /* shutdown before IO cleanup */
    CHECK(shutdown_seq < free_seq);    /* shutdown before free */
}

static void check_plain_http_close_skips_tls(const char *site,
    struct http_client *hc)
{
    if (tls_teardown_calls != 0) {
        printf("FAIL %s: plain HTTP close called wolfSSL teardown\n", site);
        failures++;
    }
    CHECK(hc->ssl == NULL);
    CHECK(hc->client_sd == 0);
}

int main(void)
{
    struct httpd httpd;
    struct http_client hc;

    failures = 0;
    memset(&httpd, 0, sizeof(httpd));

    /* http_send_response_headers error close */
    reset_tracking();
    memset(&hc, 0, sizeof(hc));
    hc.httpd = &httpd; hc.client_sd = 1; hc.ssl = (WOLFSSL *)&ssl_marker;
    http_send_response_headers(&hc, 200, "OK", "text/plain", 0);
    check_close_emitted_close_notify("http_send_response_headers");

    /* http_send_response_body error close */
    reset_tracking();
    memset(&hc, 0, sizeof(hc));
    hc.httpd = &httpd; hc.client_sd = 1; hc.ssl = (WOLFSSL *)&ssl_marker;
    http_send_response_body(&hc, "x", 1);
    check_close_emitted_close_notify("http_send_response_body");

    /* http_send_response_chunk error close */
    reset_tracking();
    memset(&hc, 0, sizeof(hc));
    hc.httpd = &httpd; hc.client_sd = 1; hc.ssl = (WOLFSSL *)&ssl_marker;
    http_send_response_chunk(&hc, "x", 1);
    check_close_emitted_close_notify("http_send_response_chunk");

    /* http_send_response_chunk_end error close */
    reset_tracking();
    memset(&hc, 0, sizeof(hc));
    hc.httpd = &httpd; hc.client_sd = 1; hc.ssl = (WOLFSSL *)&ssl_marker;
    http_send_response_chunk_end(&hc);
    check_close_emitted_close_notify("http_send_response_chunk_end");

    /* http_recv_cb fail_close (read error) */
    reset_tracking();
    memset(&hc, 0, sizeof(hc));
    hc.httpd = &httpd; hc.client_sd = 1; hc.ssl = (WOLFSSL *)&ssl_marker;
    http_recv_cb(1, 0, &hc);
    check_close_emitted_close_notify("http_recv_cb fail_close");

    /* http_send_response_headers plain HTTP close must not touch wolfSSL */
    reset_tracking();
    memset(&hc, 0, sizeof(hc));
    hc.httpd = &httpd; hc.client_sd = 1; hc.ssl = NULL;
    http_send_response_headers(&hc, 200, "OK", "text/plain", 0);
    check_plain_http_close_skips_tls("http_send_response_headers plain", &hc);

    /* http_send_response_body plain HTTP close must not touch wolfSSL */
    reset_tracking();
    memset(&hc, 0, sizeof(hc));
    hc.httpd = &httpd; hc.client_sd = 1; hc.ssl = NULL;
    http_send_response_body(&hc, "x", 1);
    check_plain_http_close_skips_tls("http_send_response_body plain", &hc);

    /* http_send_response_chunk plain HTTP close must not touch wolfSSL */
    reset_tracking();
    memset(&hc, 0, sizeof(hc));
    hc.httpd = &httpd; hc.client_sd = 1; hc.ssl = NULL;
    http_send_response_chunk(&hc, "x", 1);
    check_plain_http_close_skips_tls("http_send_response_chunk plain", &hc);

    /* http_send_response_chunk_end plain HTTP close must not touch wolfSSL */
    reset_tracking();
    memset(&hc, 0, sizeof(hc));
    hc.httpd = &httpd; hc.client_sd = 1; hc.ssl = NULL;
    http_send_response_chunk_end(&hc);
    check_plain_http_close_skips_tls("http_send_response_chunk_end plain", &hc);

    /* http_recv_cb plain HTTP close must not touch wolfSSL */
    reset_tracking();
    memset(&hc, 0, sizeof(hc));
    hc.httpd = &httpd; hc.client_sd = 1; hc.ssl = NULL;
    http_recv_cb(1, 0, &hc);
    check_plain_http_close_skips_tls("http_recv_cb fail_close plain", &hc);

    if (failures == 0)
        printf("test_http_close_notify: all checks passed\n");
    else
        printf("test_http_close_notify: %d check(s) failed\n", failures);
    return failures ? 1 : 0;
}

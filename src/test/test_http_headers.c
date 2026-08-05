/* test_http_headers.c
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
 * Regression test for the header-accumulation defect in parse_http_request.
 * The header loop copies every header line to req.headers at a fixed offset of
 * zero, so each line overwrites the previous one and only the last header of
 * the request survives.  struct http_request.headers is documented as "HTTP
 * headers" and is the only API a handler has for reading them, so a handler
 * that inspects it sees a single line rather than the request's headers.
 *
 * The accumulated lines are separated by CRLF, the delimiter they arrived with
 * on the wire, so a handler can re-split req.headers on "\r\n".
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Pull in the unit under test, parse_http_request is static. */
#include "httpd.c"

/* stubs for the wolfIP / wolfSSL symbols referenced by httpd.c */
int wolfIP_sock_socket(struct wolfIP *s, int d, int t, int p)
{ (void)s; (void)d; (void)t; (void)p; return -1; }
int wolfIP_sock_bind(struct wolfIP *s, int fd, const struct wolfIP_sockaddr *a, socklen_t l)
{ (void)s; (void)fd; (void)a; (void)l; return -1; }
int wolfIP_sock_listen(struct wolfIP *s, int fd, int b)
{ (void)s; (void)fd; (void)b; return -1; }
int wolfIP_sock_accept(struct wolfIP *s, int fd, struct wolfIP_sockaddr *a, socklen_t *l)
{ (void)s; (void)fd; (void)a; (void)l; return -1; }
int wolfIP_sock_send(struct wolfIP *s, int fd, const void *b, size_t l, int f)
{ (void)s; (void)fd; (void)b; (void)f; return (int)l; }
int wolfIP_sock_recv(struct wolfIP *s, int fd, void *b, size_t l, int f)
{ (void)s; (void)fd; (void)b; (void)l; (void)f; return -1; }
int wolfIP_sock_close(struct wolfIP *s, int fd)
{ (void)s; (void)fd; return 0; }
void wolfIP_register_callback(struct wolfIP *s, int fd, tsocket_cb cb, void *arg)
{ (void)s; (void)fd; (void)cb; (void)arg; }
int wolfSSL_SetIO_wolfIP(WOLFSSL *ssl, int fd)
{ (void)ssl; (void)fd; return 0; }
int wolfSSL_SetIO_wolfIP_CTX(WOLFSSL_CTX *ctx, struct wolfIP *s)
{ (void)ctx; (void)s; return 0; }
void wolfSSL_CleanupIO_wolfIP(WOLFSSL *ssl)
{ (void)ssl; }

/* test harness */
static int handler_calls;
/* One byte of headroom: strnlen() can return the full field width if the
 * parser ever leaves req.headers unterminated, and the capture must still be
 * able to terminate its own copy without running off the end. */
static char seen_headers[HTTP_HEADERS_LEN + 1];
static size_t seen_headers_len;

/* Records what a real consumer of the documented API would observe. */
static int probe_handler(struct httpd *httpd, struct http_client *hc, struct http_request *req)
{
    (void)httpd; (void)hc;
    handler_calls++;
    seen_headers_len = strnlen(req->headers, sizeof(req->headers));
    memcpy(seen_headers, req->headers, seen_headers_len);
    seen_headers[seen_headers_len] = '\0';
    return 0;
}

static int run(struct httpd *httpd, const char *raw, size_t len)
{
    struct http_client hc;
    /* Copy into a writable scratch buffer that mirrors the production recv
     * buffer, so the test never hands a read-only string literal to the
     * parser - safe even if parse_http_request ever normalizes in-place. */
    uint8_t buf[HTTP_RECV_BUF_LEN];
    if (len > sizeof(buf))
        len = sizeof(buf);
    memcpy(buf, raw, len);
    memset(&hc, 0, sizeof(hc));
    hc.httpd = httpd;
    hc.client_sd = 1;
    hc.ssl = NULL;
    handler_calls = 0;
    seen_headers[0] = '\0';
    seen_headers_len = 0;
    return parse_http_request(&hc, buf, len);
}

#define CHECK(cond) do { if (!(cond)) { \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

int main(void)
{
    struct httpd httpd;
    int failures = 0;
    int r;

    memset(&httpd, 0, sizeof(httpd));
    httpd_register_handler(&httpd, "/probe", probe_handler);

    /* 1. Every header line sent must be visible through req.headers. */
    {
        const char *req =
            "GET /probe HTTP/1.1\r\n"
            "Host: victim.local\r\n"
            "Authorization: Bearer valid_token\r\n"
            "X-Foo: bar\r\n"
            "X-Last: last\r\n"
            "\r\n";
        r = run(&httpd, req, strlen(req));
        CHECK(r == 0);
        CHECK(handler_calls == 1);
        CHECK(strstr(seen_headers, "Host: victim.local") != NULL);
        CHECK(strstr(seen_headers, "Authorization: Bearer valid_token") != NULL);
        CHECK(strstr(seen_headers, "X-Foo: bar") != NULL);
        CHECK(strstr(seen_headers, "X-Last: last") != NULL);
    }

    /* 2. A request carrying an Authorization header and one
     *    carrying none must not present an identical req.headers, or the two
     *    are indistinguishable to any handler that authorizes on it. */
    {
        char with_auth[sizeof(seen_headers)];
        size_t with_auth_len;
        const char *authed =
            "GET /probe HTTP/1.1\r\n"
            "Authorization: Bearer valid_token\r\n"
            "X-Foo: bar\r\n"
            "\r\n";
        const char *anon =
            "GET /probe HTTP/1.1\r\n"
            "X-Foo: bar\r\n"
            "\r\n";

        r = run(&httpd, authed, strlen(authed));
        CHECK(r == 0);
        CHECK(handler_calls == 1);
        with_auth_len = seen_headers_len;
        memcpy(with_auth, seen_headers, with_auth_len + 1);

        r = run(&httpd, anon, strlen(anon));
        CHECK(r == 0);
        CHECK(handler_calls == 1);
        CHECK(strcmp(with_auth, seen_headers) != 0);
        CHECK(with_auth_len > seen_headers_len);
    }

    /* 3. Accumulated lines are joined with the CRLF they arrived with, so a
     *    handler re-splitting req.headers on "\r\n" recovers them. */
    {
        const char *req =
            "GET /probe HTTP/1.1\r\n"
            "Host: victim.local\r\n"
            "X-Foo: bar\r\n"
            "\r\n";
        r = run(&httpd, req, strlen(req));
        CHECK(r == 0);
        CHECK(handler_calls == 1);
        CHECK(strcmp(seen_headers, "Host: victim.local\r\nX-Foo: bar") == 0);
    }

    /* 4. A single header still round-trips exactly, with no separator or
     *    padding bolted on. */
    {
        const char *req =
            "GET /probe HTTP/1.1\r\n"
            "Host: victim.local\r\n"
            "\r\n";
        r = run(&httpd, req, strlen(req));
        CHECK(r == 0);
        CHECK(handler_calls == 1);
        CHECK(strcmp(seen_headers, "Host: victim.local") == 0);
    }

    /* 5. A request with no headers at all leaves the field empty. */
    {
        const char *req =
            "GET /probe HTTP/1.1\r\n"
            "\r\n";
        r = run(&httpd, req, strlen(req));
        CHECK(r == 0);
        CHECK(handler_calls == 1);
        CHECK(seen_headers[0] == '\0');
    }

    /* 6. Headers whose total exceeds HTTP_HEADERS_LEN while each individual
     *    line stays under it.  The existing length check bounds a single line,
     *    not the running total, so accumulating without a total bound would
     *    overflow req.headers here.  Either outcome is acceptable - reject the
     *    request, or truncate - as long as the field stays NUL-terminated
     *    within its own storage and the parser does not run off the end. */
    {
        char req[HTTP_RECV_BUF_LEN];
        size_t off = 0;
        int i;
        off += (size_t)snprintf(req + off, sizeof(req) - off,
                                "GET /probe HTTP/1.1\r\n");
        for (i = 0; i < 12; i++) {
            /* ~60 bytes per line * 12 = ~720 bytes total, each line well
             * under the 512-byte HTTP_HEADERS_LEN cap. */
            off += (size_t)snprintf(req + off, sizeof(req) - off,
                                    "X-Filler-%02d: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n",
                                    i);
        }
        off += (size_t)snprintf(req + off, sizeof(req) - off, "\r\n");
        r = run(&httpd, req, off);
        if (r == 0) {
            CHECK(handler_calls == 1);
            CHECK(seen_headers_len < HTTP_HEADERS_LEN);
        } else {
            CHECK(handler_calls == 0);
        }
    }

    if (failures == 0)
        printf("test_http_headers: all checks passed\n");
    else
        printf("test_http_headers: %d check(s) failed\n", failures);
    return failures ? 1 : 0;
}

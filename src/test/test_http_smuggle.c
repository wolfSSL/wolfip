/* test_http_smuggle.c
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
 * Regression test for F-5259: parse_http_request must derive the body length
 * from the declared Content-Length, not from the recv buffer tail.  A request
 * declaring Content-Length: 0 with a second request appended in the same
 * segment (a CL.0 request-smuggling primitive) must be rejected instead of
 * delivering the trailing bytes to the handler as a body.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Pull in the unit under test - parse_http_request is static. */
#include "httpd.c"

/* --- stubs for the wolfIP / wolfSSL symbols referenced by httpd.c --------- */
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

/* --- test harness --------------------------------------------------------- */
static int handler_calls;
static size_t handler_body_len;

static int upload_handler(struct httpd *httpd, struct http_client *hc, struct http_request *req)
{
    (void)httpd; (void)hc;
    handler_calls++;
    handler_body_len = req->body_len;
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
    handler_body_len = 0;
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
    httpd_register_handler(&httpd, "/upload", upload_handler);

    /* 1. CL.0 smuggling: declared Content-Length 0 but a whole second request
     *    appended in the same segment.  Must be rejected; handler must not run
     *    and must never observe the smuggled bytes as a body. */
    {
        const char *req =
            "POST /upload HTTP/1.1\r\n"
            "Host: victim.local\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
            "GET /admin HTTP/1.1\r\n"
            "Host: victim.local\r\n"
            "X-Evil: injected\r\n"
            "\r\n";
        r = run(&httpd, req, strlen(req));
        CHECK(r < 0);                 /* rejected as bad request */
        CHECK(handler_calls == 0);    /* handler never reached */
    }

    /* 2. Well-formed POST: body matches Content-Length, delivered verbatim. */
    {
        const char *req =
            "POST /upload HTTP/1.1\r\n"
            "Host: victim.local\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello";
        r = run(&httpd, req, strlen(req));
        CHECK(r == 0);
        CHECK(handler_calls == 1);
        CHECK(handler_body_len == 5);
    }

    /* 3. Body larger than Content-Length (CL shorter than data) is rejected. */
    {
        const char *req =
            "POST /upload HTTP/1.1\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "hello";
        r = run(&httpd, req, strlen(req));
        CHECK(r < 0);
        CHECK(handler_calls == 0);
    }

    /* 4. Body present without Content-Length is malformed and rejected. */
    {
        const char *req =
            "POST /upload HTTP/1.1\r\n"
            "Host: victim.local\r\n"
            "\r\n"
            "smuggled";
        r = run(&httpd, req, strlen(req));
        CHECK(r < 0);
        CHECK(handler_calls == 0);
    }

    /* 5. Plain GET with no body still works. */
    {
        const char *req =
            "GET /upload HTTP/1.1\r\n"
            "Host: victim.local\r\n"
            "\r\n";
        r = run(&httpd, req, strlen(req));
        CHECK(r == 0);
        CHECK(handler_calls == 1);
        CHECK(handler_body_len == 0);
    }

    if (failures == 0)
        printf("test_http_smuggle: all checks passed\n");
    else
        printf("test_http_smuggle: %d check(s) failed\n", failures);
    return failures ? 1 : 0;
}

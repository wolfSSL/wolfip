/* test_http_arg_oob.c
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
 * Regression test for F-5258: httpd_get_request_arg must not walk past the end
 * of the query/body buffer.  When the buffer is exactly full the terminating
 * NUL lands on the last byte of the array; the old "p = q + 1" idiom then
 * advanced one byte past the array into the adjacent struct member (headers for
 * GET, body_len for POST), causing it to interpret that memory as further
 * key=value pairs.  The parser must instead stop at the NUL and report the key
 * as not found.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Pull in the unit under test. */
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
void wolfSSL_CleanupIO_wolfIP(WOLFSSL *ssl)
{ (void)ssl; }

#define CHECK(cond) do { if (!(cond)) { \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

int main(void)
{
    int failures = 0;
    char value[64];
    int r;

    /* 1. GET with a query that exactly fills the buffer (255 bytes, NUL at
     *    query[HTTP_QUERY_LEN-1]) and no '=' anywhere.  A header-shaped
     *    "target=INJECTED" string sits in the adjacent headers field.  The key
     *    must NOT be found: the parser must stop at the NUL rather than reading
     *    headers as a continuation of the query. */
    {
        struct http_request req;
        memset(&req, 0, sizeof(req));
        strcpy(req.method, "GET");
        memset(req.query, 'A', HTTP_QUERY_LEN - 1);
        req.query[HTTP_QUERY_LEN - 1] = '\0';
        strcpy(req.headers, "target=INJECTED");

        memset(value, 0, sizeof(value));
        r = httpd_get_request_arg(&req, "target", value, sizeof(value));
        CHECK(r == -1);                 /* key not found */
        CHECK(value[0] == '\0');        /* nothing copied out of headers */
    }

    /* 2. POST with a body that exactly fills the buffer (1023 bytes, NUL at
     *    body[HTTP_BODY_LEN-1]) and no '='.  Must not walk into body_len. */
    {
        struct http_request req;
        memset(&req, 0, sizeof(req));
        strcpy(req.method, "POST");
        memset(req.body, 'B', HTTP_BODY_LEN - 1);
        req.body[HTTP_BODY_LEN - 1] = '\0';
        req.body_len = HTTP_BODY_LEN - 1;

        memset(value, 0, sizeof(value));
        r = httpd_get_request_arg(&req, "x", value, sizeof(value));
        CHECK(r == -1);
        CHECK(value[0] == '\0');
    }

    /* 3. Normal lookups still work: a real query argument is returned. */
    {
        struct http_request req;
        memset(&req, 0, sizeof(req));
        strcpy(req.method, "GET");
        strcpy(req.query, "a=1&target=ok&b=2");

        memset(value, 0, sizeof(value));
        r = httpd_get_request_arg(&req, "target", value, sizeof(value));
        CHECK(r == 0);
        CHECK(strcmp(value, "ok") == 0);
    }

    /* 4. Last argument (no trailing '&') still resolves correctly. */
    {
        struct http_request req;
        memset(&req, 0, sizeof(req));
        strcpy(req.method, "GET");
        strcpy(req.query, "a=1&last=end");

        memset(value, 0, sizeof(value));
        r = httpd_get_request_arg(&req, "last", value, sizeof(value));
        CHECK(r == 0);
        CHECK(strcmp(value, "end") == 0);
    }

    if (failures == 0)
        printf("test_http_arg_oob: all checks passed\n");
    else
        printf("test_http_arg_oob: %d check(s) failed\n", failures);
    return failures ? 1 : 0;
}

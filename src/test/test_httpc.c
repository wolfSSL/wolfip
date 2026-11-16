/* test_httpc.c
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
 * Host unit test for the HTTP GET client: canned responses delivered in
 * fragments of varying size through the recv callback.
 */
#include <stdio.h>
#include <string.h>
#include "httpc.h"

static const char *resp;
static uint32_t resp_pos;
static uint32_t resp_chunk;
static char sent[512];
static int failures;

#define CHECK(expr) do { \
        if (!(expr)) { \
            printf("FAIL line %d: %s\n", __LINE__, #expr); \
            failures++; \
        } \
    } while (0)

static int test_send(void *ctx, const uint8_t *buf, uint32_t len)
{
    (void)ctx;
    if (strlen(sent) + len >= sizeof(sent))
        return -1;
    strncat(sent, (const char *)buf, len);
    return 0;
}

static int test_recv(void *ctx, uint8_t *buf, uint32_t len)
{
    uint32_t n = (uint32_t)strlen(resp) - resp_pos;

    (void)ctx;
    if (n > len)
        n = len;
    if (n > resp_chunk)
        n = resp_chunk;
    memcpy(buf, resp + resp_pos, n);
    resp_pos += n;
    return (int)n;
}

static int run(const char *response, uint32_t chunk, uint32_t body_max,
    char *body, uint32_t *body_len)
{
    struct httpc_io io;

    io.send = test_send;
    io.recv = test_recv;
    io.ctx = NULL;
    resp = response;
    resp_pos = 0;
    resp_chunk = chunk;
    sent[0] = '\0';
    return httpc_get(&io, "host", "/v", (uint8_t *)body, body_max, body_len);
}

int main(void)
{
    char body[64];
    uint32_t len = 0;
    uint32_t chunk;

    /* Good response, delivered in every fragment size. */
    for (chunk = 1; chunk < 80; chunk++) {
        CHECK(run("HTTP/1.1 200 OK\r\nContent-Type: x\r\n"
            "content-LENGTH:  5\r\n\r\nhello", chunk, sizeof(body), body,
            &len) == 200);
        CHECK(len == 5 && memcmp(body, "hello", 5) == 0);
    }
    CHECK(strcmp(sent, "GET /v HTTP/1.1\r\nHost: host\r\n"
        "Connection: close\r\n\r\n") == 0);

    /* A header that only ends in the wanted name must not match. */
    CHECK(run("HTTP/1.1 200 OK\r\nX-Content-Length: 9\r\n"
        "Content-Length: 5\r\n\r\nhello", 3, sizeof(body), body, &len)
        == 200 && len == 5);
    CHECK(run("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", 99,
        sizeof(body), body, &len) == 200 && len == 0);

    /* Non-200 status is returned and no body is read. */
    CHECK(run("HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nabc", 99,
        sizeof(body), body, &len) == 404 && len == 0);

    /* Length errors. */
    CHECK(run("HTTP/1.1 200 OK\r\n\r\nhello", 99, sizeof(body), body, &len)
        == HTTPC_ERR_LENGTH);
    CHECK(run("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5\r\nhello", 99, sizeof(body), body, &len) == HTTPC_ERR_LENGTH);
    CHECK(run("HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n", 99,
        sizeof(body), body, &len) == HTTPC_ERR_LENGTH);
    CHECK(run("HTTP/1.1 200 OK\r\nContent-Length: 5x\r\n\r\nhello", 99,
        sizeof(body), body, &len) == HTTPC_ERR_LENGTH);
    CHECK(run("HTTP/1.1 200 OK\r\nContent-Length: 5, 9\r\n\r\nhello", 99,
        sizeof(body), body, &len) == HTTPC_ERR_LENGTH);
    CHECK(run("HTTP/1.1 200 OK\r\nContent-Length: 5 \r\n\r\nhello", 99,
        sizeof(body), body, &len) == 200 && len == 5);
    CHECK(run("HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n\r\n", 99,
        sizeof(body), body, &len) == HTTPC_ERR_LENGTH);
    CHECK(run("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello", 99,
        sizeof(body), body, &len) == HTTPC_ERR_SIZE);

    /* Peer closes before the whole body arrived. */
    CHECK(run("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello", 99,
        sizeof(body), body, &len) == HTTPC_ERR_IO);
    CHECK(run("HTTP/1.1 200 OK\r\nContent-Le", 99, sizeof(body), body, &len)
        == HTTPC_ERR_IO);

    /* Malformed head. */
    CHECK(run("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhello", 99,
        sizeof(body), body, &len) == HTTPC_ERR_HEADER);
    CHECK(run("garbage\r\n\r\n", 99, sizeof(body), body, &len)
        == HTTPC_ERR_HEADER);
    CHECK(run("HTTP/1.1 2x0 OK\r\n\r\n", 99, sizeof(body), body, &len)
        == HTTPC_ERR_HEADER);

    /* Bad arguments. */
    CHECK(httpc_get(NULL, "h", "/", (uint8_t *)body, sizeof(body), &len)
        == HTTPC_ERR_ARG);

    if (failures != 0) {
        printf("test_httpc: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_httpc: all tests passed\n");
    return 0;
}

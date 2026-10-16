/* test_ipv6_bsd.c
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

/*
 * AF_INET6 through the POSIX port, which is the API an application actually
 * calls. Needs no network: the shim is reached in-process, the way
 * test_posix_errno.c reaches it, and the addresses are configured on the
 * stack directly.
 *
 * Most of the port is a pass-through - bind(), connect(), sendto() and the
 * rest hand the sockaddr to wolfIP unchanged, so they work for AF_INET6 the
 * moment the stack does. getaddrinfo() is the exception: it builds the
 * sockaddr itself, and had no IPv6 in it at all.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Pull in the shim so its file-static state (in_the_stack / IPSTACK) is
 * reachable, as test_posix_errno.c does. The library constructor's TAP
 * setup fails without CAP_NET_ADMIN, which is fine: nothing here transmits. */
#include "../port/posix/bsd_socket.c"

#if !WOLFIP_IPV6
#error "test_ipv6_bsd requires -DWOLFIP_IPV6=1"
#endif

#define BSD6_ADDR "2001:db8:b5d::1"
#define BSD6_IF   0

static int failures;

#define CHECK(cond, ...)                                                \
    do {                                                               \
        if (!(cond)) {                                                 \
            printf("FAIL %s:%d: ", __func__, __LINE__);                \
            printf(__VA_ARGS__);                                       \
            printf("\n");                                              \
            failures++;                                                \
        }                                                              \
    } while (0)

static void gai_free(struct addrinfo *res)
{
    if (res)
        freeaddrinfo(res);
}

/* An IPv6 literal needs no resolver and must come back as a sockaddr_in6
 * carrying exactly the address that was asked for. */
static void test_gai_ipv6_literal(void)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct sockaddr_in6 *sin6;
    struct in6_addr expect;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(BSD6_ADDR, "8080", &hints, &res);
    CHECK(rc == 0, "getaddrinfo returned %d", rc);
    if (rc != 0)
        return;
    CHECK(res->ai_family == AF_INET6, "family %d", res->ai_family);
    CHECK(res->ai_addrlen == sizeof(struct sockaddr_in6),
          "addrlen %u", (unsigned)res->ai_addrlen);
    sin6 = (struct sockaddr_in6 *)res->ai_addr;
    CHECK(sin6->sin6_family == AF_INET6, "sin6_family %d", sin6->sin6_family);
    CHECK(ntohs(sin6->sin6_port) == 8080, "port %d", ntohs(sin6->sin6_port));
    assert(inet_pton(AF_INET6, BSD6_ADDR, &expect) == 1);
    CHECK(memcmp(&sin6->sin6_addr, &expect, sizeof(expect)) == 0,
          "address mismatch");
    gai_free(res);

    /* AF_UNSPEC must recognise it too, rather than falling through to the
     * resolver and failing. */
    res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    rc = getaddrinfo(BSD6_ADDR, "80", &hints, &res);
    CHECK(rc == 0, "AF_UNSPEC returned %d", rc);
    if (rc == 0) {
        CHECK(res->ai_family == AF_INET6, "AF_UNSPEC family %d",
              res->ai_family);
        gai_free(res);
    }

    /* And an AF_INET request must refuse it rather than return nonsense. */
    res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    rc = getaddrinfo(BSD6_ADDR, "80", &hints, &res);
    CHECK(rc == EAI_FAMILY, "AF_INET on a v6 literal returned %d", rc);
    gai_free(res);
}

/* A passive AF_INET6 lookup with no node is what a server calls to bind the
 * wildcard. */
static void test_gai_ipv6_passive(void)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct sockaddr_in6 *sin6;
    struct in6_addr any6;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    rc = getaddrinfo(NULL, "9000", &hints, &res);
    CHECK(rc == 0, "passive getaddrinfo returned %d", rc);
    if (rc != 0)
        return;
    CHECK(res->ai_family == AF_INET6, "family %d", res->ai_family);
    sin6 = (struct sockaddr_in6 *)res->ai_addr;
    CHECK(ntohs(sin6->sin6_port) == 9000, "port %d", ntohs(sin6->sin6_port));
    memset(&any6, 0, sizeof(any6));
    CHECK(memcmp(&sin6->sin6_addr, &any6, sizeof(any6)) == 0,
          "passive address is not the wildcard");
    gai_free(res);
}

/* An IPv4 literal asked for as AF_INET6. POSIX answers with the mapped form
 * when AI_V4MAPPED is set and refuses otherwise; both halves matter,
 * because guessing either way silently gives the caller the wrong family. */
static void test_gai_v4mapped(void)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct sockaddr_in6 *sin6;
    const uint8_t *b;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    rc = getaddrinfo("10.0.0.7", "1234", &hints, &res);
    CHECK(rc == EAI_FAMILY, "v4 literal without AI_V4MAPPED returned %d", rc);
    gai_free(res);

    res = NULL;
    hints.ai_flags = AI_V4MAPPED;
    rc = getaddrinfo("10.0.0.7", "1234", &hints, &res);
    CHECK(rc == 0, "v4 literal with AI_V4MAPPED returned %d", rc);
    if (rc != 0)
        return;
    CHECK(res->ai_family == AF_INET6, "family %d", res->ai_family);
    sin6 = (struct sockaddr_in6 *)res->ai_addr;
    b = (const uint8_t *)&sin6->sin6_addr;
    CHECK(b[10] == 0xFF && b[11] == 0xFF, "not a v4-mapped address");
    CHECK(b[12] == 10 && b[13] == 0 && b[14] == 0 && b[15] == 7,
          "mapped address is %u.%u.%u.%u", b[12], b[13], b[14], b[15]);
    gai_free(res);
}

/* The IPv4 path must be exactly as it was. */
static void test_gai_ipv4_unchanged(void)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct sockaddr_in *sin;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo("10.10.10.2", "4433", &hints, &res);
    CHECK(rc == 0, "IPv4 getaddrinfo returned %d", rc);
    if (rc != 0)
        return;
    CHECK(res->ai_family == AF_INET, "family %d", res->ai_family);
    CHECK(res->ai_addrlen == sizeof(struct sockaddr_in),
          "addrlen %u", (unsigned)res->ai_addrlen);
    sin = (struct sockaddr_in *)res->ai_addr;
    CHECK(ntohs(sin->sin_port) == 4433, "port %d", ntohs(sin->sin_port));
    CHECK(sin->sin_addr.s_addr == inet_addr("10.10.10.2"), "address mismatch");
    gai_free(res);
}

/* socket(), bind() and getsockname() over AF_INET6 through the shim. */
static void test_socket_bind_getsockname(void)
{
    struct sockaddr_in6 addr;
    struct sockaddr_in6 got;
    socklen_t len = sizeof(got);
    struct in6_addr expect;
    int fd;

    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    CHECK(fd >= 0, "socket(AF_INET6, SOCK_DGRAM) returned %d errno=%d", fd,
          errno);
    if (fd < 0)
        return;

    assert(inet_pton(AF_INET6, BSD6_ADDR, &expect) == 1);
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(7777);
    memcpy(&addr.sin6_addr, &expect, sizeof(expect));
    CHECK(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0,
          "bind failed, errno=%d", errno);

    memset(&got, 0, sizeof(got));
    CHECK(getsockname(fd, (struct sockaddr *)&got, &len) == 0,
          "getsockname failed, errno=%d", errno);
    CHECK(got.sin6_family == AF_INET6, "getsockname family %d",
          got.sin6_family);
    CHECK(ntohs(got.sin6_port) == 7777, "getsockname port %d",
          ntohs(got.sin6_port));
    CHECK(memcmp(&got.sin6_addr, &expect, sizeof(expect)) == 0,
          "getsockname address mismatch");
    CHECK(close(fd) == 0, "close failed");
}

/* A TCP socket, and IPV6_V6ONLY through the shim's setsockopt/getsockopt -
 * which pass level and optname straight through, so this is really a check
 * that nothing in the port intercepts them. */
static void test_stream_socket_and_v6only(void)
{
    int fd;
    int on = 1;
    int value = -1;
    socklen_t len = sizeof(value);

    fd = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(fd >= 0, "socket(AF_INET6, SOCK_STREAM) returned %d", fd);
    if (fd < 0)
        return;

    value = -1;
    CHECK(getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, &len) == 0,
          "getsockopt IPV6_V6ONLY failed, errno=%d", errno);
    CHECK(value == 0, "IPV6_V6ONLY defaults to %d", value);

    CHECK(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == 0,
          "setsockopt IPV6_V6ONLY failed, errno=%d", errno);
    value = -1;
    len = sizeof(value);
    CHECK(getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, &len) == 0,
          "getsockopt after set failed, errno=%d", errno);
    CHECK(value == 1, "IPV6_V6ONLY reads back as %d", value);
    CHECK(close(fd) == 0, "close failed");
}

/* An ICMPv6 socket, which is AF_INET6 paired with IPPROTO_ICMPV6 and
 * nothing else. */
static void test_icmpv6_socket(void)
{
    int fd;
    int bad;

    fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    CHECK(fd >= 0, "socket(AF_INET6, IPPROTO_ICMPV6) returned %d", fd);
    if (fd >= 0)
        CHECK(close(fd) == 0, "close failed");

    /* The other pairing is a socket that could never match anything. */
    bad = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMP);
    CHECK(bad < 0, "AF_INET6 with IPPROTO_ICMP was accepted (%d)", bad);
    if (bad >= 0)
        close(bad);
}

/* An AF_INET socket must be untouched by any of this. */
static void test_ipv4_socket_unchanged(void)
{
    struct sockaddr_in addr;
    struct sockaddr_in got;
    socklen_t len = sizeof(got);
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0, "socket(AF_INET) returned %d", fd);
    if (fd < 0)
        return;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(7778);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    CHECK(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0,
          "IPv4 bind failed, errno=%d", errno);
    memset(&got, 0, sizeof(got));
    CHECK(getsockname(fd, (struct sockaddr *)&got, &len) == 0,
          "IPv4 getsockname failed");
    CHECK(got.sin_family == AF_INET, "IPv4 getsockname family %d",
          got.sin_family);
    CHECK(ntohs(got.sin_port) == 7778, "IPv4 getsockname port %d",
          ntohs(got.sin_port));
    CHECK(close(fd) == 0, "close failed");
}

int main(void)
{
    ip6 addr6;

    if (!IPSTACK)
        wolfIP_init_static(&IPSTACK);
    /* Take over the shim path, so socket() and friends are served by wolfIP
     * rather than by libc. */
    in_the_stack = 0;

    if (atoip6(BSD6_ADDR, &addr6) != 0) {
        printf("FAIL: atoip6\n");
        return 1;
    }
    if (wolfIP_ifaddr_add6(IPSTACK, BSD6_IF, &addr6, 64) != 0) {
        printf("FAIL: could not configure %s\n", BSD6_ADDR);
        return 1;
    }

    test_gai_ipv6_literal();
    test_gai_ipv6_passive();
    test_gai_v4mapped();
    test_gai_ipv4_unchanged();
    test_socket_bind_getsockname();
    test_stream_socket_and_v6only();
    test_icmpv6_socket();
    test_ipv4_socket_unchanged();

    printf("IPv6 BSD socket port test: %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}

/* test_freertos_ipv6.c
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
 * AF_INET6 through the FreeRTOS BSD socket port.
 *
 * That port is a pass-through: every call but socket() takes a
 * struct wolfIP_sockaddr and hands it to wolfIP unchanged, so IPv6 works
 * there the moment the stack does. What can still go wrong is the port
 * rejecting the family, or truncating the larger sockaddr on the way
 * through, and those are what this pins down.
 *
 * The wolfIP side is mocked, as in test_freertos_close_last_ack.c: the point
 * is what the shim forwards, not what the stack then does with it. Its
 * close() mock is a scripted one-shot for a LAST_ACK regression, which is
 * why this has its own copy rather than sharing that fixture.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"
#include "wolfip.h"

struct MockSemaphore {
    int count;
};

static int sem_allocs;
static int sem_frees;
static tsocket_cb registered_cb;
static void *registered_arg;
static int fake_internal_fd = MARK_TCP_SOCKET;
static int close_calls;
static int last_socket_domain;
static uint16_t last_bind_family;
static socklen_t last_bind_len;
static uint8_t last_bind_addr[28];
static int last_setsockopt_level;
static int last_setsockopt_optname;

SemaphoreHandle_t xSemaphoreCreateBinary(void)
{
    struct MockSemaphore *sem = calloc(1, sizeof(*sem));
    if (sem != NULL)
        sem_allocs++;
    return sem;
}

SemaphoreHandle_t xSemaphoreCreateMutex(void)
{
    return xSemaphoreCreateBinary();
}

BaseType_t xSemaphoreTake(SemaphoreHandle_t sem, TickType_t ticks)
{
    (void)ticks;
    if (sem == NULL)
        return pdFALSE;
    if (sem->count > 0) {
        sem->count--;
        return pdTRUE;
    }
    return pdFALSE;
}

BaseType_t xSemaphoreGive(SemaphoreHandle_t sem)
{
    if (sem == NULL)
        return pdFALSE;
    sem->count++;
    return pdTRUE;
}

void vSemaphoreDelete(SemaphoreHandle_t sem)
{
    if (sem != NULL) {
        sem_frees++;
        free(sem);
    }
}

BaseType_t xTaskCreate(TaskFunction_t task, const char *name,
    uint16_t stack_words, void *arg, UBaseType_t priority, TaskHandle_t *handle)
{
    (void)task;
    (void)name;
    (void)stack_words;
    (void)arg;
    (void)priority;
    (void)handle;
    return pdPASS;
}

void vTaskDelay(TickType_t ticks)
{
    (void)ticks;
}

TickType_t xTaskGetTickCount(void)
{
    return 0;
}

void vTaskDelete(TaskHandle_t handle)
{
    (void)handle;
}

int wolfIP_poll(struct wolfIP *ipstack, uint64_t now_ms)
{
    (void)ipstack;
    (void)now_ms;
    return 10;
}

int wolfIP_sock_socket(struct wolfIP *s, int domain, int type, int protocol)
{
    (void)s;
    (void)type;
    (void)protocol;
    last_socket_domain = domain;
    return fake_internal_fd;
}

int wolfIP_sock_bind(struct wolfIP *s, int fd, const struct wolfIP_sockaddr *addr, socklen_t len)
{
    (void)s; (void)fd;
    last_bind_family = addr ? addr->sa_family : 0;
    last_bind_len = len;
    if (addr && (len >= 28))
        memcpy(last_bind_addr, addr, 28);
    return 0;
}

int wolfIP_sock_listen(struct wolfIP *s, int fd, int backlog)
{
    (void)s; (void)fd; (void)backlog;
    return 0;
}

int wolfIP_sock_accept(struct wolfIP *s, int fd, struct wolfIP_sockaddr *addr, socklen_t *len)
{
    (void)s; (void)fd; (void)addr; (void)len;
    return -WOLFIP_EAGAIN;
}

int wolfIP_sock_connect(struct wolfIP *s, int fd, const struct wolfIP_sockaddr *addr, socklen_t len)
{
    (void)s; (void)fd; (void)addr; (void)len;
    return -WOLFIP_EAGAIN;
}

int wolfIP_sock_send(struct wolfIP *s, int fd, const void *buf, size_t len, int flags)
{
    (void)s; (void)fd; (void)buf; (void)len; (void)flags;
    return -WOLFIP_EAGAIN;
}

int wolfIP_sock_sendto(struct wolfIP *s, int fd, const void *buf, size_t len, int flags,
    const struct wolfIP_sockaddr *dest_addr, socklen_t len2)
{
    (void)s; (void)fd; (void)buf; (void)len; (void)flags; (void)dest_addr; (void)len2;
    return -WOLFIP_EAGAIN;
}

int wolfIP_sock_recv(struct wolfIP *s, int fd, void *buf, size_t len, int flags)
{
    (void)s; (void)fd; (void)buf; (void)len; (void)flags;
    return -WOLFIP_EAGAIN;
}

int wolfIP_sock_recvfrom(struct wolfIP *s, int fd, void *buf, size_t len, int flags,
    struct wolfIP_sockaddr *src_addr, socklen_t *len2)
{
    (void)s; (void)fd; (void)buf; (void)len; (void)flags; (void)src_addr; (void)len2;
    return -WOLFIP_EAGAIN;
}

int wolfIP_sock_setsockopt(struct wolfIP *s, int fd, int level, int optname,
    const void *optval, socklen_t optlen)
{
    (void)s; (void)fd; (void)optval; (void)optlen;
    last_setsockopt_level = level;
    last_setsockopt_optname = optname;
    return 0;
}

int wolfIP_sock_getsockopt(struct wolfIP *s, int fd, int level, int optname,
    void *optval, socklen_t *optlen)
{
    (void)s; (void)fd; (void)level; (void)optname; (void)optval; (void)optlen;
    return 0;
}

int wolfIP_sock_getsockname(struct wolfIP *s, int fd, struct wolfIP_sockaddr *addr, socklen_t *len)
{
    (void)s; (void)fd;
    /* Answer with the address bind() was given, so the test can see the
     * shim carry a 28-byte sockaddr back out again. */
    if (addr && len && (*len >= 28)) {
        memcpy(addr, last_bind_addr, 28);
        *len = 28;
    }
    return 0;
}

int wolfIP_sock_getpeername(struct wolfIP *s, int fd, struct wolfIP_sockaddr *addr, socklen_t *len)
{
    (void)s; (void)fd; (void)addr; (void)len;
    return 0;
}

int wolfIP_sock_can_write(struct wolfIP *s, int fd)
{
    (void)s; (void)fd;
    return 0;
}

int wolfIP_sock_can_read(struct wolfIP *s, int fd)
{
    (void)s; (void)fd;
    return 0;
}

int wolfIP_sock_close(struct wolfIP *s, int fd)
{
    (void)s;
    if (fd != fake_internal_fd)
        return -WOLFIP_EINVAL;
    close_calls++;
    return 0;
}

void wolfIP_register_callback(struct wolfIP *s, int fd, tsocket_cb cb, void *arg)
{
    (void)s;
    (void)fd;
    registered_cb = cb;
    registered_arg = arg;
}

#include "../port/freeRTOS/bsd_socket.c"

/* Laid out as RFC 3493 defines sockaddr_in6, which is what an application
 * on this port passes in. */
struct test_sockaddr_in6 {
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t sin6_addr[16];
    uint32_t sin6_scope_id;
};

static int failures;

#define CHECK(cond, ...)                                                \
    do {                                                               \
        if (!(cond)) {                                                 \
            printf("FAIL %d: ", __LINE__);                             \
            printf(__VA_ARGS__);                                       \
            printf("\n");                                              \
            failures++;                                                \
        }                                                              \
    } while (0)

int main(void)
{
    struct wolfIP stack;
    struct test_sockaddr_in6 a6;
    struct test_sockaddr_in6 got;
    socklen_t len;
    int fd;
    int on = 1;
    static const uint8_t addr6[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x0f, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };

    memset(&stack, 0, sizeof(stack));
    if (wolfip_freertos_socket_init(&stack, 1, 128) != 0) {
        printf("init failed\n");
        return 1;
    }

    last_socket_domain = -1;
    fd = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(fd >= 0, "socket(AF_INET6) returned %d", fd);
    if (fd < 0)
        return 1;
    CHECK(last_socket_domain == AF_INET6, "socket() forwarded domain %d",
          last_socket_domain);

    /* bind() must carry the whole 28-byte address through, address bytes
     * included: a shim that assumed sockaddr_in would truncate it to 16 and
     * the destination would be silently wrong. */
    memset(&a6, 0, sizeof(a6));
    a6.sin6_family = AF_INET6;
    a6.sin6_port = 0x3930;
    memcpy(a6.sin6_addr, addr6, sizeof(addr6));
    last_bind_family = 0;
    last_bind_len = 0;
    CHECK(bind(fd, (const struct wolfIP_sockaddr *)&a6, sizeof(a6)) == 0,
          "AF_INET6 bind failed");
    CHECK(last_bind_family == AF_INET6, "bind() forwarded family %u",
          (unsigned)last_bind_family);
    CHECK(last_bind_len == sizeof(a6), "bind() forwarded len %u",
          (unsigned)last_bind_len);
    CHECK(memcmp(last_bind_addr + 8, addr6, sizeof(addr6)) == 0,
          "bind() did not carry the address bytes through");

    /* ...and back out again. */
    memset(&got, 0, sizeof(got));
    len = sizeof(got);
    CHECK(getsockname(fd, (struct wolfIP_sockaddr *)&got, &len) == 0,
          "getsockname failed");
    CHECK(len == sizeof(got), "getsockname reported len %u", (unsigned)len);
    CHECK(got.sin6_family == AF_INET6, "getsockname family %u",
          (unsigned)got.sin6_family);
    CHECK(memcmp(got.sin6_addr, addr6, sizeof(addr6)) == 0,
          "getsockname address mismatch");

    /* IPV6_V6ONLY is level 41 option 26. The shim must forward both rather
     * than filtering on levels it happens to recognise. */
    last_setsockopt_level = -1;
    last_setsockopt_optname = -1;
    CHECK(setsockopt(fd, 41, 26, &on, sizeof(on)) == 0,
          "IPV6_V6ONLY setsockopt failed");
    CHECK(last_setsockopt_level == 41 && last_setsockopt_optname == 26,
          "setsockopt forwarded level %d optname %d", last_setsockopt_level,
          last_setsockopt_optname);

    CHECK(close(fd) == 0, "close failed");

    printf("test_freertos_ipv6: %s\n", failures ? "FAIL" : "passed");
    return failures ? 1 : 0;
}

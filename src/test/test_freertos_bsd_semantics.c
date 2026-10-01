/* test_freertos_bsd_semantics.c
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

/* Blocking semantics of the FreeRTOS BSD wrapper: timeouts, accept() and
 * close(), against a scripted wolfIP core. */

#include <limits.h>
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

#define LISTEN_FD (MARK_TCP_SOCKET | 0)
#define CHILD_FD  (MARK_TCP_SOCKET | 1)

static int next_socket_fd = LISTEN_FD;
static TickType_t last_wait_ticks;
static int recv_ret = -WOLFIP_EAGAIN;
static int can_read_ret;
static TickType_t now_ticks;
static tsocket_cb registered_cb;
static void *registered_arg;
/* Runs once, in place of another task, when a caller first blocks. */
static void (*wait_hook)(void);

SemaphoreHandle_t xSemaphoreCreateBinary(void)
{
    return calloc(1, sizeof(struct MockSemaphore));
}

SemaphoreHandle_t xSemaphoreCreateMutex(void)
{
    struct MockSemaphore *sem = calloc(1, sizeof(*sem));

    if (sem != NULL)
        sem->count = 1;
    return sem;
}

/* Nothing else runs, so a wait that is not already satisfied times out. */
BaseType_t xSemaphoreTake(SemaphoreHandle_t sem, TickType_t ticks)
{
    if (sem == NULL)
        return pdFALSE;
    if (sem->count == 0 && ticks != 0 && wait_hook != NULL) {
        void (*hook)(void) = wait_hook;

        wait_hook = NULL;
        hook();
    }
    if (sem->count > 0) {
        sem->count--;
        return pdTRUE;
    }
    last_wait_ticks = ticks;
    if (ticks != 0 && ticks != portMAX_DELAY)
        now_ticks += ticks;
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
    free(sem);
}

BaseType_t xTaskCreate(TaskFunction_t task, const char *name,
    uint16_t stack_words, void *arg, UBaseType_t priority, TaskHandle_t *handle)
{
    (void)task; (void)name; (void)stack_words; (void)arg; (void)priority;
    (void)handle;
    return pdPASS;
}

void vTaskDelay(TickType_t ticks)
{
    now_ticks += ticks;
}

TickType_t xTaskGetTickCount(void)
{
    return now_ticks;
}

void vTaskDelete(TaskHandle_t handle)
{
    (void)handle;
}

int wolfIP_poll(struct wolfIP *ipstack, uint64_t now_ms)
{
    (void)ipstack; (void)now_ms;
    return 0;
}

int wolfIP_sock_socket(struct wolfIP *s, int domain, int type, int protocol)
{
    (void)s; (void)domain; (void)type; (void)protocol;
    return next_socket_fd++;
}

int wolfIP_sock_bind(struct wolfIP *s, int fd, const struct wolfIP_sockaddr *addr, socklen_t len)
{
    (void)s; (void)fd; (void)addr; (void)len;
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
    return recv_ret;
}

int wolfIP_sock_recvfrom(struct wolfIP *s, int fd, void *buf, size_t len, int flags,
    struct wolfIP_sockaddr *src_addr, socklen_t *len2)
{
    (void)s; (void)fd; (void)buf; (void)len; (void)flags; (void)src_addr; (void)len2;
    return recv_ret;
}

int wolfIP_sock_setsockopt(struct wolfIP *s, int fd, int level, int optname,
    const void *optval, socklen_t optlen)
{
    (void)s; (void)fd; (void)level; (void)optname; (void)optval; (void)optlen;
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
    (void)s; (void)fd; (void)addr; (void)len;
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
    return can_read_ret;
}

int wolfIP_sock_close(struct wolfIP *s, int fd)
{
    (void)s; (void)fd;
    return 0;
}

void wolfIP_register_callback(struct wolfIP *s, int fd, tsocket_cb cb, void *arg)
{
    (void)s; (void)fd;
    registered_cb = cb;
    registered_arg = arg;
}

void wolfIP_set_wake_cb(struct wolfIP *s, wolfIP_wake_cb cb, void *arg)
{
    (void)s; (void)cb; (void)arg;
}

#include "../port/freeRTOS/bsd_socket.c"

static int failures;

#define CHECK(cond) do { \
        if (!(cond)) { \
            printf("%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

static int spurious_wakes;

/* Another task's activity: time passes and a non-completing event fires. */
static void spurious_wake(void)
{
    now_ticks += pdMS_TO_TICKS(100);
    spurious_wakes++;
    registered_cb(0, CB_EVENT_WRITABLE, registered_arg);
    if (spurious_wakes < 10)
        wait_hook = spurious_wake;
}

static void test_timeouts(void)
{
    struct wolfIP_timeval tv;
    struct wolfIP_timeval out;
    socklen_t outlen;
    char wide[2 * sizeof(struct wolfIP_timeval)];
    char buf[8];
    TickType_t start;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    recv_ret = -WOLFIP_EAGAIN;

    /* Default: the wait is unbounded. */
    CHECK(recv(fd, buf, sizeof(buf), 0) == -1);
    CHECK(last_wait_ticks == portMAX_DELAY);

    tv.tv_sec = 1;
    tv.tv_usec = 500000;
    CHECK(setsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_RCVTIMEO, &tv,
        sizeof(tv)) == 0);
    CHECK(recv(fd, buf, sizeof(buf), 0) == -1);
    CHECK(last_wait_ticks == pdMS_TO_TICKS(1500));
    CHECK(socket_last_error() == WOLFIP_EAGAIN);

    /* A sub-millisecond timeout still waits, rather than meaning "none". */
    tv.tv_sec = 0;
    tv.tv_usec = 1;
    CHECK(setsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_SNDTIMEO, &tv,
        sizeof(tv)) == 0);
    CHECK(send(fd, buf, sizeof(buf), 0) == -1);
    CHECK(last_wait_ticks == 1);

    /* Zero restores "no timeout". */
    tv.tv_usec = 0;
    CHECK(setsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_RCVTIMEO, &tv,
        sizeof(tv)) == 0);
    CHECK(recv(fd, buf, sizeof(buf), 0) == -1);
    CHECK(last_wait_ticks == portMAX_DELAY);

    /* Every blocking call honours its timeout. */
    tv.tv_sec = 0;
    tv.tv_usec = 250000;
    CHECK(setsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_SNDTIMEO, &tv,
        sizeof(tv)) == 0);
    CHECK(setsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_RCVTIMEO, &tv,
        sizeof(tv)) == 0);
    last_wait_ticks = 0;
    CHECK(connect(fd, NULL, 0) == -1);
    CHECK(last_wait_ticks == pdMS_TO_TICKS(250));
    /* The handshake goes on: connect() reports it as in progress. */
    CHECK(socket_last_error() == WOLFIP_EINPROGRESS);
    last_wait_ticks = 0;
    CHECK(sendto(fd, buf, sizeof(buf), 0, NULL, 0) == -1);
    CHECK(last_wait_ticks == pdMS_TO_TICKS(250));
    last_wait_ticks = 0;
    CHECK(recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL) == -1);
    CHECK(last_wait_ticks == pdMS_TO_TICKS(250));

    /* Wakes that do not complete the call spend its timeout, not restart it. */
    spurious_wakes = 0;
    wait_hook = spurious_wake;
    start = now_ticks;
    CHECK(send(fd, buf, sizeof(buf), 0) == -1);
    CHECK(socket_last_error() == WOLFIP_EAGAIN);
    CHECK((TickType_t)(now_ticks - start) <= pdMS_TO_TICKS(300));
    CHECK(spurious_wakes == 3);
    wait_hook = NULL;

    /* getsockopt() reads back what setsockopt() stored. */
    tv.tv_sec = 1;
    tv.tv_usec = 500000;
    CHECK(setsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_RCVTIMEO, &tv,
        sizeof(tv)) == 0);
    memset(&out, 0xff, sizeof(out));
    outlen = sizeof(out);
    CHECK(getsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_RCVTIMEO, &out,
        &outlen) == 0);
    CHECK(outlen == sizeof(out));
    CHECK(out.tv_sec == 1 && out.tv_usec == 500000);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    CHECK(setsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_SNDTIMEO, &tv,
        sizeof(tv)) == 0);
    memset(&out, 0xff, sizeof(out));
    CHECK(getsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_SNDTIMEO, &out,
        &outlen) == 0);
    CHECK(out.tv_sec == 0 && out.tv_usec == 0);
    outlen = sizeof(out) - 1;
    CHECK(getsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_SNDTIMEO, &out,
        &outlen) == -1);

    /* A timeout too long for TickType_t waits forever, as on Linux. */
    tv.tv_sec = LONG_MAX;
    tv.tv_usec = 999999;
    CHECK(setsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_RCVTIMEO, &tv,
        sizeof(tv)) == 0);
    CHECK(recv(fd, buf, sizeof(buf), 0) == -1);
    CHECK(last_wait_ticks == portMAX_DELAY);

    /* A negative timeout does not wait. */
    tv.tv_sec = -1;
    tv.tv_usec = 0;
    CHECK(setsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_RCVTIMEO, &tv,
        sizeof(tv)) == 0);
    last_wait_ticks = 1234;
    CHECK(recv(fd, buf, sizeof(buf), 0) == -1);
    CHECK(last_wait_ticks == 0);
    CHECK(socket_last_error() == WOLFIP_EAGAIN);

    tv.tv_sec = 0;
    tv.tv_usec = 1000000;
    CHECK(setsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_RCVTIMEO, &tv,
        sizeof(tv)) == -1);
    CHECK(socket_last_error() == WOLFIP_EDOM);
    tv.tv_usec = -1;
    CHECK(setsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_RCVTIMEO, &tv,
        sizeof(tv)) == -1);
    CHECK(socket_last_error() == WOLFIP_EDOM);
    /* A larger struct timeval (64-bit time_t on a 32-bit target) is refused. */
    memset(wide, 0, sizeof(wide));
    CHECK(setsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_RCVTIMEO, wide,
        sizeof(wide)) == -1);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    CHECK(setsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_RCVTIMEO, &tv,
        sizeof(tv) - 1) == -1);

    CHECK(close(fd) == 0);
}

int main(void)
{
    struct wolfIP stack;

    memset(&stack, 0, sizeof(stack));
    if (wolfip_freertos_socket_init(&stack, 1, 128) != 0) {
        printf("init failed\n");
        return 1;
    }

    test_timeouts();

    if (failures != 0) {
        printf("test_freertos_bsd_semantics: %d FAILED\n", failures);
        return 1;
    }
    printf("test_freertos_bsd_semantics: passed\n");
    return 0;
}

/* bsd_socket.c
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
 * FreeRTOS POSIX-style socket wrappers for wolfIP.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

#include "config.h"
#include "wolfip.h"
#include "bsd_socket.h"

#ifndef WOLFIP_FREERTOS_BSD_MAX_FDS
#define WOLFIP_FREERTOS_BSD_MAX_FDS 16
#endif

#ifndef WOLFIP_FREERTOS_POLL_MAX_MS
#define WOLFIP_FREERTOS_POLL_MAX_MS 20u
#endif

#ifndef WOLFIP_FREERTOS_POLL_MIN_MS
#define WOLFIP_FREERTOS_POLL_MIN_MS 5u
#endif

typedef struct {
    int in_use;
    int internal_fd;
    SemaphoreHandle_t ready_sem;
    volatile uint16_t seen_events;
    volatile uint16_t wait_events;
} wolfip_bsd_fd_entry;

static struct wolfIP *g_ipstack;
static SemaphoreHandle_t g_lock;
static wolfip_bsd_fd_entry g_fds[WOLFIP_FREERTOS_BSD_MAX_FDS];
static int g_last_error;
static volatile uint32_t g_cb_log_count;

static void wolfip_bsd_poll_task(void *arg)
{
    struct wolfIP *ipstack = (struct wolfIP *)arg;
    TickType_t next_heartbeat = xTaskGetTickCount() + pdMS_TO_TICKS(5000);

    for (;;) {
        uint32_t next_ms;
        TickType_t delay_ticks;
        TickType_t now_ticks;
        uint64_t now_ms = (uint64_t)xTaskGetTickCount() * (uint64_t)portTICK_PERIOD_MS;

        xSemaphoreTake(g_lock, portMAX_DELAY);
        next_ms = (uint32_t)wolfIP_poll(ipstack, now_ms);
        xSemaphoreGive(g_lock);
        if (next_ms < WOLFIP_FREERTOS_POLL_MIN_MS) {
            next_ms = WOLFIP_FREERTOS_POLL_MIN_MS;
        }
        if (next_ms > WOLFIP_FREERTOS_POLL_MAX_MS) {
            next_ms = WOLFIP_FREERTOS_POLL_MAX_MS;
        }

        delay_ticks = pdMS_TO_TICKS(next_ms);
        if (delay_ticks == 0) {
            delay_ticks = 1;
        }
        while (delay_ticks > 0) {
            TickType_t chunk = delay_ticks;
            TickType_t max_chunk = pdMS_TO_TICKS(500);
            if (max_chunk == 0) {
                max_chunk = 1;
            }
            if (chunk > max_chunk) {
                chunk = max_chunk;
            }
            vTaskDelay(chunk);
            delay_ticks -= chunk;

            now_ticks = xTaskGetTickCount();
            if ((int32_t)(now_ticks - next_heartbeat) >= 0) {
                uint64_t virt_ms = (uint64_t)now_ticks * (uint64_t)portTICK_PERIOD_MS;
                printf("[wolfip_poll] virt_ms=%lu virt_s=%lu next_ms=%lu\n",
                    (unsigned long)virt_ms,
                    (unsigned long)(virt_ms / 1000u),
                    (unsigned long)next_ms);
                next_heartbeat = now_ticks + pdMS_TO_TICKS(5000);
            }
        }
    }
}

static void wolfip_bsd_set_error(int err)
{
    if (err < 0) {
        g_last_error = -err;
    }
    else {
        g_last_error = err;
    }
}

int socket_last_error(void)
{
    return g_last_error;
}

static int wolfip_bsd_fd_valid(int public_fd)
{
    if (public_fd < 0 || public_fd >= WOLFIP_FREERTOS_BSD_MAX_FDS) {
        return 0;
    }
    if (!g_fds[public_fd].in_use) {
        return 0;
    }
    return 1;
}

static int wolfip_bsd_fd_alloc(int internal_fd)
{
    int i;
    for (i = 0; i < WOLFIP_FREERTOS_BSD_MAX_FDS; i++) {
        if (!g_fds[i].in_use) {
            SemaphoreHandle_t sem = xSemaphoreCreateBinary();
            if (sem == NULL) {
                return -WOLFIP_ENOMEM;
            }
            g_fds[i].in_use = 1;
            g_fds[i].internal_fd = internal_fd;
            g_fds[i].ready_sem = sem;
            g_fds[i].seen_events = 0;
            g_fds[i].wait_events = 0;
            return i;
        }
    }
    return -WOLFIP_ENOMEM;
}

static void wolfip_bsd_fd_free(int public_fd)
{
    if (!wolfip_bsd_fd_valid(public_fd)) {
        return;
    }

    vSemaphoreDelete(g_fds[public_fd].ready_sem);
    g_fds[public_fd].in_use = 0;
    g_fds[public_fd].internal_fd = -1;
    g_fds[public_fd].ready_sem = NULL;
    g_fds[public_fd].seen_events = 0;
    g_fds[public_fd].wait_events = 0;
}

static void wolfip_bsd_socket_cb(int internal_fd, uint16_t events, void *arg)
{
    wolfip_bsd_fd_entry *entry = (wolfip_bsd_fd_entry *)arg;

    (void)internal_fd;
    if (entry == NULL) {
        return;
    }
    g_cb_log_count++;
    if ((events & CB_EVENT_CLOSED) != 0u || (g_cb_log_count & 0x1Fu) == 0u) {
        printf("[sock_cb] ifd=%d events=0x%04x wait=0x%04x cb_count=%lu\n",
            internal_fd,
            (unsigned)events,
            (unsigned)entry->wait_events,
            (unsigned long)g_cb_log_count);
    }
    entry->seen_events |= events;
    if ((events & entry->wait_events) != 0) {
        (void)xSemaphoreGive(entry->ready_sem);
    }
}

static void wolfip_bsd_prepare_wait_locked(wolfip_bsd_fd_entry *entry, uint16_t wait_events)
{
    entry->seen_events = 0;
    entry->wait_events = wait_events;
    while (xSemaphoreTake(entry->ready_sem, 0) == pdTRUE) {
    }
    wolfIP_register_callback(g_ipstack, entry->internal_fd, wolfip_bsd_socket_cb, entry);
}

static int wolfip_bsd_wait_unlocked(wolfip_bsd_fd_entry *entry)
{
    if (xSemaphoreTake(entry->ready_sem, portMAX_DELAY) != pdTRUE) {
        return -1;
    }
    return 0;
}

int wolfip_freertos_socket_init(struct wolfIP *ipstack,
    UBaseType_t poll_task_priority,
    uint16_t poll_task_stack_words)
{
    int i;

    if (ipstack == NULL) {
        return -WOLFIP_EINVAL;
    }
    if (g_ipstack != NULL) {
        return 0;
    }

    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) {
        return -WOLFIP_ENOMEM;
    }

    for (i = 0; i < WOLFIP_FREERTOS_BSD_MAX_FDS; i++) {
        g_fds[i].in_use = 0;
        g_fds[i].internal_fd = -1;
        g_fds[i].ready_sem = NULL;
        g_fds[i].seen_events = 0;
        g_fds[i].wait_events = 0;
    }

    g_ipstack = ipstack;
    g_last_error = 0;
    g_cb_log_count = 0;

    if (xTaskCreate(wolfip_bsd_poll_task, "wolfip_poll", poll_task_stack_words,
            g_ipstack, poll_task_priority, NULL) != pdPASS) {
        g_ipstack = NULL;
        vSemaphoreDelete(g_lock);
        g_lock = NULL;
        return -WOLFIP_ENOMEM;
    }

    return 0;
}

int socket(int domain, int type, int protocol)
{
    int ret;
    int public_fd;

    if (g_ipstack == NULL) {
        return -1;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    ret = wolfIP_sock_socket(g_ipstack, domain, type, protocol);
    if (ret < 0) {
        wolfip_bsd_set_error(ret);
        xSemaphoreGive(g_lock);
        return -1;
    }

    public_fd = wolfip_bsd_fd_alloc(ret);
    if (public_fd < 0) {
        (void)wolfIP_sock_close(g_ipstack, ret);
        wolfip_bsd_set_error(public_fd);
        xSemaphoreGive(g_lock);
        return -1;
    }

    xSemaphoreGive(g_lock);
    return public_fd;
}

int bind(int sockfd, const struct wolfIP_sockaddr *addr, socklen_t addrlen)
{
    int ret;
    if (!wolfip_bsd_fd_valid(sockfd)) {
        return -1;
    }
    xSemaphoreTake(g_lock, portMAX_DELAY);
    ret = wolfIP_sock_bind(g_ipstack, g_fds[sockfd].internal_fd, addr, addrlen);
    xSemaphoreGive(g_lock);
    if (ret < 0) {
        wolfip_bsd_set_error(ret);
        return -1;
    }
    return ret;
}

int listen(int sockfd, int backlog)
{
    int ret;
    if (!wolfip_bsd_fd_valid(sockfd)) {
        return -1;
    }
    xSemaphoreTake(g_lock, portMAX_DELAY);
    ret = wolfIP_sock_listen(g_ipstack, g_fds[sockfd].internal_fd, backlog);
    xSemaphoreGive(g_lock);
    if (ret < 0) {
        wolfip_bsd_set_error(ret);
        return -1;
    }
    return ret;
}

int accept(int sockfd, struct wolfIP_sockaddr *addr, socklen_t *addrlen)
{
    int ret;
    int public_fd;
    wolfip_bsd_fd_entry *entry;

    if (!wolfip_bsd_fd_valid(sockfd)) {
        return -1;
    }
    entry = &g_fds[sockfd];

    for (;;) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        ret = wolfIP_sock_accept(g_ipstack, entry->internal_fd, addr, addrlen);
        if (ret >= 0) {
            public_fd = wolfip_bsd_fd_alloc(ret);
            xSemaphoreGive(g_lock);
            if (public_fd < 0) {
                xSemaphoreTake(g_lock, portMAX_DELAY);
                (void)wolfIP_sock_close(g_ipstack, ret);
                xSemaphoreGive(g_lock);
                wolfip_bsd_set_error(public_fd);
                return -1;
            }
            return public_fd;
        }
        if (ret != -WOLFIP_EAGAIN) {
            xSemaphoreGive(g_lock);
            wolfip_bsd_set_error(ret);
            return -1;
        }

        wolfip_bsd_prepare_wait_locked(entry, (uint16_t)(CB_EVENT_READABLE | CB_EVENT_CLOSED));
        xSemaphoreGive(g_lock);
        if (wolfip_bsd_wait_unlocked(entry) < 0) {
            wolfip_bsd_set_error(WOLFIP_EAGAIN);
            return -1;
        }
    }
}

int connect(int sockfd, const struct wolfIP_sockaddr *addr, socklen_t addrlen)
{
    int ret;
    wolfip_bsd_fd_entry *entry;

    if (!wolfip_bsd_fd_valid(sockfd)) {
        return -1;
    }
    entry = &g_fds[sockfd];

    for (;;) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        ret = wolfIP_sock_connect(g_ipstack, entry->internal_fd, addr, addrlen);
        if (ret == 0) {
            xSemaphoreGive(g_lock);
            return 0;
        }
        if (ret != -WOLFIP_EAGAIN) {
            xSemaphoreGive(g_lock);
            wolfip_bsd_set_error(ret);
            return -1;
        }

        wolfip_bsd_prepare_wait_locked(entry, (uint16_t)(CB_EVENT_WRITABLE | CB_EVENT_CLOSED));
        xSemaphoreGive(g_lock);
        if (wolfip_bsd_wait_unlocked(entry) < 0) {
            wolfip_bsd_set_error(WOLFIP_EAGAIN);
            return -1;
        }
    }
}

int send(int sockfd, const void *buf, size_t len, int flags)
{
    int ret;
    wolfip_bsd_fd_entry *entry;

    if (!wolfip_bsd_fd_valid(sockfd)) {
        return -1;
    }
    entry = &g_fds[sockfd];

    for (;;) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        ret = wolfIP_sock_send(g_ipstack, entry->internal_fd, buf, len, flags);
        if (ret >= 0) {
            xSemaphoreGive(g_lock);
            return ret;
        }
        if (ret != -WOLFIP_EAGAIN) {
            xSemaphoreGive(g_lock);
            wolfip_bsd_set_error(ret);
            return -1;
        }

        wolfip_bsd_prepare_wait_locked(entry, (uint16_t)(CB_EVENT_WRITABLE | CB_EVENT_CLOSED));
        xSemaphoreGive(g_lock);
        if (wolfip_bsd_wait_unlocked(entry) < 0) {
            wolfip_bsd_set_error(WOLFIP_EAGAIN);
            return -1;
        }
    }
}

int sendto(int sockfd, const void *buf, size_t len, int flags,
    const struct wolfIP_sockaddr *dest_addr, socklen_t addrlen)
{
    int ret;
    wolfip_bsd_fd_entry *entry;

    if (!wolfip_bsd_fd_valid(sockfd)) {
        return -1;
    }
    entry = &g_fds[sockfd];

    for (;;) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        ret = wolfIP_sock_sendto(g_ipstack, entry->internal_fd, buf, len, flags, dest_addr, addrlen);
        if (ret >= 0) {
            xSemaphoreGive(g_lock);
            return ret;
        }
        if (ret != -WOLFIP_EAGAIN) {
            xSemaphoreGive(g_lock);
            wolfip_bsd_set_error(ret);
            return -1;
        }

        wolfip_bsd_prepare_wait_locked(entry, (uint16_t)(CB_EVENT_WRITABLE | CB_EVENT_CLOSED));
        xSemaphoreGive(g_lock);
        if (wolfip_bsd_wait_unlocked(entry) < 0) {
            wolfip_bsd_set_error(WOLFIP_EAGAIN);
            return -1;
        }
    }
}

int recv(int sockfd, void *buf, size_t len, int flags)
{
    int ret;
    wolfip_bsd_fd_entry *entry;

    if (!wolfip_bsd_fd_valid(sockfd)) {
        return -1;
    }
    entry = &g_fds[sockfd];

    for (;;) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        ret = wolfIP_sock_recv(g_ipstack, entry->internal_fd, buf, len, flags);
        if (ret >= 0) {
            xSemaphoreGive(g_lock);
            return ret;
        }
        if (ret != -WOLFIP_EAGAIN) {
            xSemaphoreGive(g_lock);
            wolfip_bsd_set_error(ret);
            return -1;
        }

        wolfip_bsd_prepare_wait_locked(entry, (uint16_t)(CB_EVENT_READABLE | CB_EVENT_CLOSED));
        xSemaphoreGive(g_lock);
        if (wolfip_bsd_wait_unlocked(entry) < 0) {
            wolfip_bsd_set_error(WOLFIP_EAGAIN);
            return -1;
        }
    }
}

int recvfrom(int sockfd, void *buf, size_t len, int flags,
    struct wolfIP_sockaddr *src_addr, socklen_t *addrlen)
{
    int ret;
    wolfip_bsd_fd_entry *entry;

    if (!wolfip_bsd_fd_valid(sockfd)) {
        return -1;
    }
    entry = &g_fds[sockfd];

    for (;;) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        ret = wolfIP_sock_recvfrom(g_ipstack, entry->internal_fd, buf, len, flags, src_addr, addrlen);
        if (ret >= 0) {
            xSemaphoreGive(g_lock);
            return ret;
        }
        if (ret != -WOLFIP_EAGAIN) {
            xSemaphoreGive(g_lock);
            wolfip_bsd_set_error(ret);
            return -1;
        }

        wolfip_bsd_prepare_wait_locked(entry, (uint16_t)(CB_EVENT_READABLE | CB_EVENT_CLOSED));
        xSemaphoreGive(g_lock);
        if (wolfip_bsd_wait_unlocked(entry) < 0) {
            wolfip_bsd_set_error(WOLFIP_EAGAIN);
            return -1;
        }
    }
}

int setsockopt(int sockfd, int level, int optname,
    const void *optval, socklen_t optlen)
{
    int ret;
    if (!wolfip_bsd_fd_valid(sockfd)) {
        return -1;
    }
    xSemaphoreTake(g_lock, portMAX_DELAY);
    ret = wolfIP_sock_setsockopt(g_ipstack, g_fds[sockfd].internal_fd,
        level, optname, optval, optlen);
    xSemaphoreGive(g_lock);
    if (ret < 0) {
        wolfip_bsd_set_error(ret);
        return -1;
    }
    return ret;
}

int getsockopt(int sockfd, int level, int optname,
    void *optval, socklen_t *optlen)
{
    int ret;
    if (!wolfip_bsd_fd_valid(sockfd)) {
        return -1;
    }
    xSemaphoreTake(g_lock, portMAX_DELAY);
    ret = wolfIP_sock_getsockopt(g_ipstack, g_fds[sockfd].internal_fd,
        level, optname, optval, optlen);
    xSemaphoreGive(g_lock);
    if (ret < 0) {
        wolfip_bsd_set_error(ret);
        return -1;
    }
    return ret;
}

int getsockname(int sockfd, struct wolfIP_sockaddr *addr, socklen_t *addrlen)
{
    int ret;
    if (!wolfip_bsd_fd_valid(sockfd)) {
        return -1;
    }
    xSemaphoreTake(g_lock, portMAX_DELAY);
    ret = wolfIP_sock_getsockname(g_ipstack, g_fds[sockfd].internal_fd, addr, addrlen);
    xSemaphoreGive(g_lock);
    if (ret < 0) {
        wolfip_bsd_set_error(ret);
        return -1;
    }
    return ret;
}

int getpeername(int sockfd, struct wolfIP_sockaddr *addr, socklen_t *addrlen)
{
    int ret;
    if (!wolfip_bsd_fd_valid(sockfd)) {
        return -1;
    }
    xSemaphoreTake(g_lock, portMAX_DELAY);
    ret = wolfIP_sock_getpeername(g_ipstack, g_fds[sockfd].internal_fd, addr, addrlen);
    xSemaphoreGive(g_lock);
    if (ret < 0) {
        wolfip_bsd_set_error(ret);
        return -1;
    }
    return ret;
}

int close(int sockfd)
{
    int ret;
    wolfip_bsd_fd_entry *entry;

    if (!wolfip_bsd_fd_valid(sockfd)) {
        return -1;
    }
    entry = &g_fds[sockfd];

    for (;;) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        ret = wolfIP_sock_close(g_ipstack, entry->internal_fd);
        if (ret >= 0) {
            wolfIP_register_callback(g_ipstack, entry->internal_fd, NULL, NULL);
            wolfip_bsd_fd_free(sockfd);
            xSemaphoreGive(g_lock);
            return ret;
        }
        if (ret != -WOLFIP_EAGAIN) {
            xSemaphoreGive(g_lock);
            wolfip_bsd_set_error(ret);
            return -1;
        }

        wolfip_bsd_prepare_wait_locked(entry, CB_EVENT_CLOSED);
        xSemaphoreGive(g_lock);
        if (wolfip_bsd_wait_unlocked(entry) < 0) {
            wolfip_bsd_set_error(WOLFIP_EAGAIN);
            return -1;
        }
    }
}

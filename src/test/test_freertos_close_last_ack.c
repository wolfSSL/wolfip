/* Regression test for the FreeRTOS BSD close() wrapper when the core delivers
 * CB_EVENT_CLOSED synchronously during LAST_ACK teardown. */

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
    if (sem == NULL)
        return pdFALSE;
    if (ticks == portMAX_DELAY && sem->count == 0 && registered_cb != NULL) {
        tsocket_cb cb = registered_cb;
        void *arg = registered_arg;

        registered_cb = NULL;
        registered_arg = NULL;
        cb(fake_internal_fd, CB_EVENT_CLOSED, arg);
    }
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
    (void)domain;
    (void)type;
    (void)protocol;
    return fake_internal_fd;
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
    return 0;
}

int wolfIP_sock_close(struct wolfIP *s, int fd)
{
    (void)s;
    if (fd != fake_internal_fd)
        return -WOLFIP_EINVAL;
    close_calls++;
    if (close_calls == 1)
        return -WOLFIP_EAGAIN;
    return -1;
}

void wolfIP_register_callback(struct wolfIP *s, int fd, tsocket_cb cb, void *arg)
{
    (void)s;
    (void)fd;
    registered_cb = cb;
    registered_arg = arg;
}

#include "../port/freeRTOS/bsd_socket.c"

int main(void)
{
    struct wolfIP stack;
    int fd;
    int rc;

    memset(&stack, 0, sizeof(stack));
    if (wolfip_freertos_socket_init(&stack, 1, 128) != 0) {
        printf("init failed\n");
        return 1;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("socket failed\n");
        return 1;
    }

    rc = close(fd);
    if (rc != 0) {
        printf("close failed rc=%d close_calls=%d sem_allocs=%d sem_frees=%d\n",
            rc, close_calls, sem_allocs, sem_frees);
        return 1;
    }
    if (close_calls != 2 || sem_frees != 1) {
        printf("unexpected state close_calls=%d sem_allocs=%d sem_frees=%d\n",
            close_calls, sem_allocs, sem_frees);
        return 1;
    }

    printf("test_freertos_close_last_ack: passed\n");
    return 0;
}

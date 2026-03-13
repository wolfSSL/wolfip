#include "echo_server_freertos.h"

#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "bsd_socket.h"
#include "wolfip.h"

#define FREERTOS_ECHO_TASK_NAME        "echo"
#define FREERTOS_ECHO_TASK_STACK_WORDS 2048
#define FREERTOS_ECHO_TASK_PRIORITY    3
#define FREERTOS_ECHO_BACKLOG          2

typedef struct {
    struct wolfIP *stack;
    uint16_t port;
    echo_server_freertos_debug_cb debug_cb;
} freertos_echo_task_ctx;

static freertos_echo_task_ctx g_echo_task_ctx;
static char g_echo_rxbuf[512];

static void echo_debug(const char *msg)
{
    if (g_echo_task_ctx.debug_cb != NULL) {
        g_echo_task_ctx.debug_cb(msg);
    }
}

static void echo_debug_port(const char *prefix, uint16_t port)
{
    char msg[96];

    (void)snprintf(msg, sizeof(msg), "%s %u\n", prefix, (unsigned)port);
    echo_debug(msg);
}

static void echo_debug_error(const char *prefix, int ret, int sock_err)
{
    char msg[96];

    (void)snprintf(msg, sizeof(msg), "%s ret=%d sock_err=%d\n",
        prefix, ret, sock_err);
    echo_debug(msg);
}

static int echo_send_all(int client_fd, const char *buf, int len)
{
    int sent = 0;

    while (sent < len) {
        int ret = send(client_fd, buf + sent, (size_t)(len - sent), 0);
        if (ret <= 0) {
            echo_debug_error("Echo/FreeRTOS: send failed", ret, socket_last_error());
            return -1;
        }
        sent += ret;
    }

    return 0;
}

static void echo_serve_client(int client_fd)
{
    int ret;

    for (;;) {
        ret = recv(client_fd, g_echo_rxbuf, sizeof(g_echo_rxbuf), 0);
        if (ret <= 0) {
            echo_debug_error("Echo/FreeRTOS: recv failed", ret, socket_last_error());
            break;
        }
        if (echo_send_all(client_fd, g_echo_rxbuf, ret) < 0) {
            break;
        }
    }
    (void)close(client_fd);
}

static void echo_server_task(void *arg)
{
    freertos_echo_task_ctx *task_ctx = (freertos_echo_task_ctx *)arg;
    struct wolfIP_sockaddr_in addr;
    int listen_fd;

    (void)task_ctx->stack;
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        echo_debug("Echo/FreeRTOS: socket failed\n");
        vTaskDelete(NULL);
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(task_ctx->port);
    addr.sin_addr.s_addr = 0;

    if (bind(listen_fd, (const struct wolfIP_sockaddr *)&addr, sizeof(addr)) < 0) {
        echo_debug("Echo/FreeRTOS: bind failed\n");
        (void)close(listen_fd);
        vTaskDelete(NULL);
        return;
    }

    if (listen(listen_fd, FREERTOS_ECHO_BACKLOG) < 0) {
        echo_debug("Echo/FreeRTOS: listen failed\n");
        (void)close(listen_fd);
        vTaskDelete(NULL);
        return;
    }

    echo_debug_port("Echo/FreeRTOS: Server ready on port", task_ctx->port);

    for (;;) {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            echo_debug("Echo/FreeRTOS: accept failed\n");
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
        echo_serve_client(client_fd);
    }
}

int echo_server_freertos_start(struct wolfIP *stack, uint16_t port,
    echo_server_freertos_debug_cb debug_cb)
{
    g_echo_task_ctx.stack = stack;
    g_echo_task_ctx.port = port;
    g_echo_task_ctx.debug_cb = debug_cb;

    if (xTaskCreate(echo_server_task, FREERTOS_ECHO_TASK_NAME,
            FREERTOS_ECHO_TASK_STACK_WORDS, &g_echo_task_ctx,
            FREERTOS_ECHO_TASK_PRIORITY, NULL) != pdPASS) {
        return -1;
    }

    return 0;
}

#include "https_server_freertos.h"

#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "portable.h"
#include "task.h"

#include "bsd_socket.h"
#include "certs.h"
#include "config.h"
#include "wolfip.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#define FREERTOS_HTTPS_TASK_NAME        "https"
#define FREERTOS_HTTPS_TASK_STACK_WORDS 4096
#define FREERTOS_HTTPS_TASK_PRIORITY    3
#define FREERTOS_HTTPS_BACKLOG          2

typedef struct {
    struct wolfIP *stack;
    uint16_t port;
    https_server_freertos_debug_cb debug_cb;
} freertos_https_task_ctx;

static freertos_https_task_ctx g_https_task_ctx;
static char g_https_request[512];
static char g_https_response[768];

int custom_rand_gen_block(unsigned char *output, unsigned int sz)
{
    unsigned int i;

    for (i = 0; i < sz; i++) {
        output[i] = (unsigned char)(wolfIP_getrandom() & 0xFFu);
    }
    return 0;
}

static void https_debug(const char *msg)
{
    if (g_https_task_ctx.debug_cb != NULL) {
        g_https_task_ctx.debug_cb(msg);
    }
}

static void https_debug_error(const char *prefix, int wolfssl_err, int sock_err)
{
    char msg[96];

    (void)snprintf(msg, sizeof(msg), "%s err=%d sock_err=%d\n",
        prefix, wolfssl_err, sock_err);
    https_debug(msg);
}

static void https_debug_port(const char *prefix, uint16_t port)
{
    char msg[96];

    (void)snprintf(msg, sizeof(msg), "%s %u\n", prefix, (unsigned)port);
    https_debug(msg);
}

static void https_debug_diag(const char *phase)
{
    char msg[128];
    UBaseType_t high_water;
    size_t free_heap;
    size_t min_heap;

    high_water = uxTaskGetStackHighWaterMark(NULL);
    free_heap = xPortGetFreeHeapSize();
    min_heap = xPortGetMinimumEverFreeHeapSize();

    (void)snprintf(msg, sizeof(msg),
        "HTTPS/FreeRTOS: %s stack_hw=%lu free_heap=%lu min_heap=%lu\n",
        phase,
        (unsigned long)high_water,
        (unsigned long)free_heap,
        (unsigned long)min_heap);
    https_debug(msg);
}

static int https_tls_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int fd;
    int err;
    int ret;

    (void)ssl;
    if (ctx == NULL) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    fd = *(const int *)ctx;
    ret = recv(fd, buf, (size_t)sz, 0);
    if (ret < 0) {
        err = socket_last_error();
        if (err == WOLFIP_EAGAIN) {
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
        https_debug_error("HTTPS/FreeRTOS: recv failed", ret, err);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    if (ret == 0) {
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    return ret;
}

static int https_tls_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int fd;
    int err;
    int ret;

    (void)ssl;
    if (ctx == NULL) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    fd = *(const int *)ctx;
    ret = send(fd, buf, (size_t)sz, 0);
    if (ret <= 0) {
        err = socket_last_error();
        if (err == WOLFIP_EAGAIN) {
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }
        https_debug_error("HTTPS/FreeRTOS: send failed", ret, err);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    return ret;
}

static void format_ip4(ip4 ip, char *buf, size_t buf_len)
{
    uint32_t host_ip = (uint32_t)ip;

    (void)snprintf(buf, buf_len, "%u.%u.%u.%u",
        (unsigned)((host_ip >> 24) & 0xFFu),
        (unsigned)((host_ip >> 16) & 0xFFu),
        (unsigned)((host_ip >> 8) & 0xFFu),
        (unsigned)(host_ip & 0xFFu));
}

static void https_serve_client(WOLFSSL_CTX *ctx, struct wolfIP *stack, int client_fd)
{
    WOLFSSL *ssl;
    char ip_str[16];
    int err;
    int ret;
    ip4 ip = 0;
    uint32_t uptime_sec;
    int response_len;

    (void)stack;
    https_debug_diag("client start");
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        https_debug("HTTPS/FreeRTOS: wolfSSL_new failed\n");
        (void)close(client_fd);
        return;
    }
    https_debug_diag("after wolfSSL_new");

    wolfSSL_SetIOReadCtx(ssl, &client_fd);
    wolfSSL_SetIOWriteCtx(ssl, &client_fd);

    ret = wolfSSL_accept(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        https_debug_diag("accept failed");
        https_debug_error("HTTPS/FreeRTOS: TLS handshake failed",
            err, socket_last_error());
        wolfSSL_free(ssl);
        (void)close(client_fd);
        return;
    }
    https_debug_diag("after wolfSSL_accept");

    ret = wolfSSL_read(ssl, g_https_request, (int)sizeof(g_https_request) - 1);
    if (ret <= 0) {
        err = wolfSSL_get_error(ssl, ret);
        https_debug_diag("read failed");
        https_debug_error("HTTPS/FreeRTOS: request read failed",
            err, socket_last_error());
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        (void)close(client_fd);
        return;
    }
    g_https_request[ret] = '\0';
    https_debug_diag("after request read");

    wolfIP_ipconfig_get(stack, &ip, NULL, NULL);
    format_ip4(ip, ip_str, sizeof(ip_str));
    uptime_sec = (uint32_t)(xTaskGetTickCount() / configTICK_RATE_HZ);

    response_len = snprintf(g_https_response, sizeof(g_https_response),
        "HTTP/1.1 200 OK\r\n"
        "Connection: close\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<!DOCTYPE html><html><head><title>wolfIP STM32H563 FreeRTOS</title>"
        "<style>body{font-family:sans-serif;margin:40px;}table{border-collapse:collapse;}"
        "td{padding:8px 16px;border:1px solid #ddd;}</style></head>"
        "<body><h1>wolfIP Status</h1><table>"
        "<tr><td>Device</td><td>STM32H563</td></tr>"
        "<tr><td>Mode</td><td>FreeRTOS BSD sockets</td></tr>"
        "<tr><td>IP Address</td><td>%s</td></tr>"
        "<tr><td>Uptime</td><td>%lu sec</td></tr>"
        "<tr><td>TLS</td><td>TLS 1.3</td></tr>"
        "</table></body></html>",
        ip_str, (unsigned long)uptime_sec);
    if (response_len > 0) {
        if ((size_t)response_len >= sizeof(g_https_response)) {
            response_len = (int)sizeof(g_https_response) - 1;
        }
        (void)wolfSSL_write(ssl, g_https_response, response_len);
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    (void)close(client_fd);
    https_debug_diag("client done");
}

static void https_server_task(void *arg)
{
    freertos_https_task_ctx *task_ctx = (freertos_https_task_ctx *)arg;
    struct wolfIP_sockaddr_in addr;
    WOLFSSL_CTX *ctx;
    int listen_fd;

    https_debug("HTTPS/FreeRTOS: Initializing wolfSSL\n");
    https_debug_diag("task start");
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        https_debug("HTTPS/FreeRTOS: wolfSSL_Init failed\n");
        vTaskDelete(NULL);
        return;
    }

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL) {
        https_debug("HTTPS/FreeRTOS: CTX_new failed\n");
        vTaskDelete(NULL);
        return;
    }
    https_debug_diag("after CTX_new");

    wolfSSL_SetIORecv(ctx, https_tls_recv);
    wolfSSL_SetIOSend(ctx, https_tls_send);

    if (wolfSSL_CTX_use_certificate_buffer(ctx,
            (const unsigned char *)server_cert_pem,
            server_cert_pem_len - 1,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        https_debug("HTTPS/FreeRTOS: certificate load failed\n");
        wolfSSL_CTX_free(ctx);
        vTaskDelete(NULL);
        return;
    }

    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx,
            (const unsigned char *)server_key_pem,
            server_key_pem_len - 1,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        https_debug("HTTPS/FreeRTOS: private key load failed\n");
        wolfSSL_CTX_free(ctx);
        vTaskDelete(NULL);
        return;
    }

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        https_debug("HTTPS/FreeRTOS: socket failed\n");
        wolfSSL_CTX_free(ctx);
        vTaskDelete(NULL);
        return;
    }
    https_debug_diag("after socket");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(task_ctx->port);
    addr.sin_addr.s_addr = 0;

    if (bind(listen_fd, (const struct wolfIP_sockaddr *)&addr, sizeof(addr)) < 0) {
        https_debug("HTTPS/FreeRTOS: bind failed\n");
        (void)close(listen_fd);
        wolfSSL_CTX_free(ctx);
        vTaskDelete(NULL);
        return;
    }

    if (listen(listen_fd, FREERTOS_HTTPS_BACKLOG) < 0) {
        https_debug("HTTPS/FreeRTOS: listen failed\n");
        (void)close(listen_fd);
        wolfSSL_CTX_free(ctx);
        vTaskDelete(NULL);
        return;
    }

    https_debug_port("HTTPS/FreeRTOS: Server ready on port", task_ctx->port);
    https_debug_diag("server ready");

    for (;;) {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            https_debug("HTTPS/FreeRTOS: accept failed\n");
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
        https_serve_client(ctx, task_ctx->stack, client_fd);
    }
}

int https_server_freertos_start(struct wolfIP *stack, uint16_t port,
    https_server_freertos_debug_cb debug_cb)
{
    g_https_task_ctx.stack = stack;
    g_https_task_ctx.port = port;
    g_https_task_ctx.debug_cb = debug_cb;

    if (xTaskCreate(https_server_task, FREERTOS_HTTPS_TASK_NAME,
            FREERTOS_HTTPS_TASK_STACK_WORDS, &g_https_task_ctx,
            FREERTOS_HTTPS_TASK_PRIORITY, NULL) != pdPASS) {
        return -1;
    }

    return 0;
}

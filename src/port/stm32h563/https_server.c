/* https_server.c
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

#include "https_server.h"
#include "certs.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <string.h>

/* Configuration */
#define HTTPS_RX_BUF_SIZE 1024
#define HTTPS_TX_BUF_SIZE 2048

/* Server state */
typedef enum {
    HTTPS_STATE_LISTENING,
    HTTPS_STATE_ACCEPTING,
    HTTPS_STATE_HANDSHAKE,
    HTTPS_STATE_READ_REQUEST,
    HTTPS_STATE_SEND_RESPONSE,
    HTTPS_STATE_CLOSING
} https_state_t;

/* Server context */
static struct {
    struct wolfIP *stack;
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    int listen_fd;
    int client_fd;
    https_state_t state;
    https_debug_cb debug_cb;
    uint8_t rx_buf[HTTPS_RX_BUF_SIZE];
    uint8_t tx_buf[HTTPS_TX_BUF_SIZE];
    int rx_len;
    int tx_len;
    int tx_sent;
    uint32_t device_ip;
    uint32_t uptime_sec;
} server;

/* External functions from wolfssl_io.c */
extern int wolfSSL_SetIO_wolfIP_CTX(WOLFSSL_CTX *ctx, struct wolfIP *s);
extern int wolfSSL_SetIO_wolfIP(WOLFSSL *ssl, int fd);

/* Forward declarations */
static void https_listen_cb(int fd, uint16_t event, void *arg);
static void https_client_cb(int fd, uint16_t event, void *arg);

/* Debug output helper */
static void debug_print(const char *msg)
{
    if (server.debug_cb) {
        server.debug_cb(msg);
    }
}

/* Format IP address to string (portable, works on any endianness) */
static void ip_to_str(uint32_t ip, char *buf)
{
    int i = 0;
    uint8_t octets[4];

    /* Extract octets using shifts - portable across all architectures */
    octets[0] = (ip >> 24) & 0xFF;
    octets[1] = (ip >> 16) & 0xFF;
    octets[2] = (ip >> 8) & 0xFF;
    octets[3] = ip & 0xFF;

    for (int octet = 0; octet < 4; octet++) {
        uint8_t val = octets[octet];
        if (val >= 100) {
            buf[i++] = '0' + (val / 100);
            val %= 100;
            buf[i++] = '0' + (val / 10);
            buf[i++] = '0' + (val % 10);
        } else if (val >= 10) {
            buf[i++] = '0' + (val / 10);
            buf[i++] = '0' + (val % 10);
        } else {
            buf[i++] = '0' + val;
        }
        if (octet < 3) buf[i++] = '.';
    }
    buf[i] = '\0';
}

/* Format number to string */
static void uint_to_str(uint32_t val, char *buf)
{
    char tmp[12];
    int i = 0;

    if (val == 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return;
    }

    while (val > 0) {
        tmp[i++] = '0' + (val % 10);
        val /= 10;
    }

    int j = 0;
    while (i > 0) {
        buf[j++] = tmp[--i];
    }
    buf[j] = '\0';
}

/* Check if request starts with a method */
static int starts_with(const char *str, const char *prefix)
{
    while (*prefix) {
        if (*str++ != *prefix++) return 0;
    }
    return 1;
}

/* Build HTTP response for status page */
static int build_status_response(void)
{
    char ip_str[16];
    char uptime_str[12];
    char *p = (char *)server.tx_buf;

    ip_to_str(server.device_ip, ip_str);
    uint_to_str(server.uptime_sec, uptime_str);

    /* Build HTML page */
    const char *html_start =
        "<!DOCTYPE html><html><head>"
        "<title>wolfIP STM32H563</title>"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<style>"
        "body{font-family:sans-serif;margin:40px;background:#f5f5f5}"
        ".card{background:white;padding:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1);max-width:400px}"
        "h1{color:#333;margin-top:0}table{width:100%}td{padding:8px 0}"
        ".label{color:#666}.value{font-weight:bold;text-align:right}"
        "</style></head><body><div class=\"card\">"
        "<h1>wolfIP Status</h1>"
        "<table>"
        "<tr><td class=\"label\">Device</td><td class=\"value\">STM32H563</td></tr>"
        "<tr><td class=\"label\">IP Address</td><td class=\"value\">";

    const char *html_mid1 = "</td></tr>"
        "<tr><td class=\"label\">Uptime</td><td class=\"value\">";

    const char *html_mid2 = " sec</td></tr>"
        "<tr><td class=\"label\">TLS</td><td class=\"value\">TLS 1.3</td></tr>"
        "<tr><td class=\"label\">Cipher</td><td class=\"value\">ECC P-256</td></tr>"
        "</table></div>"
        "<p style=\"color:#999;font-size:12px\">Powered by wolfSSL + wolfIP</p>"
        "</body></html>";

    /* Calculate content length */
    int content_len = strlen(html_start) + strlen(ip_str) + strlen(html_mid1) +
                      strlen(uptime_str) + strlen(html_mid2);

    /* HTTP header */
    strcpy(p, "HTTP/1.1 200 OK\r\n");
    p += strlen(p);
    strcpy(p, "Content-Type: text/html\r\n");
    p += strlen(p);
    strcpy(p, "Connection: close\r\n");
    p += strlen(p);
    strcpy(p, "Content-Length: ");
    p += strlen(p);

    char len_str[12];
    uint_to_str(content_len, len_str);
    strcpy(p, len_str);
    p += strlen(p);
    strcpy(p, "\r\n\r\n");
    p += strlen(p);

    /* HTML body */
    strcpy(p, html_start);
    p += strlen(p);
    strcpy(p, ip_str);
    p += strlen(p);
    strcpy(p, html_mid1);
    p += strlen(p);
    strcpy(p, uptime_str);
    p += strlen(p);
    strcpy(p, html_mid2);
    p += strlen(p);

    return (int)(p - (char *)server.tx_buf);
}

/* Build 404 response */
static int build_404_response(void)
{
    const char *response =
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n"
        "Content-Length: 44\r\n\r\n"
        "<html><body><h1>404 Not Found</h1></body></html>";

    strcpy((char *)server.tx_buf, response);
    return strlen(response);
}

/* Parse HTTP request and build response */
static void process_request(void)
{
    server.rx_buf[server.rx_len] = '\0';

    if (starts_with((char *)server.rx_buf, "GET / ") ||
        starts_with((char *)server.rx_buf, "GET /index")) {
        server.tx_len = build_status_response();
    } else {
        server.tx_len = build_404_response();
    }
    server.tx_sent = 0;
}

int https_server_init(struct wolfIP *stack, uint16_t port, https_debug_cb debug)
{
    struct wolfIP_sockaddr_in addr;
    int ret;

    memset(&server, 0, sizeof(server));
    server.stack = stack;
    server.debug_cb = debug;
    server.listen_fd = -1;
    server.client_fd = -1;
    server.state = HTTPS_STATE_LISTENING;

    debug_print("HTTPS: Initializing wolfSSL\n");

    /* Initialize wolfSSL (may already be done) */
    wolfSSL_Init();

    /* Create TLS 1.3 server context */
    server.ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (server.ctx == NULL) {
        debug_print("HTTPS: CTX_new failed\n");
        return -1;
    }

    /* Load certificate */
    debug_print("HTTPS: Loading certificate\n");
    ret = wolfSSL_CTX_use_certificate_buffer(server.ctx,
        (const unsigned char *)server_cert_pem, server_cert_pem_len,
        WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        debug_print("HTTPS: Certificate load failed\n");
        return -1;
    }

    /* Load private key */
    debug_print("HTTPS: Loading private key\n");
    ret = wolfSSL_CTX_use_PrivateKey_buffer(server.ctx,
        (const unsigned char *)server_key_pem, server_key_pem_len,
        WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        debug_print("HTTPS: Private key load failed\n");
        return -1;
    }

    /* Register wolfIP I/O callbacks */
    wolfSSL_SetIO_wolfIP_CTX(server.ctx, stack);

    /* Create listen socket */
    debug_print("HTTPS: Creating listen socket\n");
    server.listen_fd = wolfIP_sock_socket(stack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (server.listen_fd < 0) {
        debug_print("HTTPS: socket() failed\n");
        return -1;
    }

    /* Bind to port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(port);
    addr.sin_addr.s_addr = 0;

    ret = wolfIP_sock_bind(stack, server.listen_fd,
        (struct wolfIP_sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        debug_print("HTTPS: bind() failed\n");
        return -1;
    }

    /* Listen */
    ret = wolfIP_sock_listen(stack, server.listen_fd, 1);
    if (ret < 0) {
        debug_print("HTTPS: listen() failed\n");
        return -1;
    }

    /* Register callback for incoming connections */
    wolfIP_register_callback(stack, server.listen_fd, https_listen_cb, NULL);

    debug_print("HTTPS: Server ready\n");
    return 0;
}

/* Callback for listen socket - handles incoming connections */
static void https_listen_cb(int fd, uint16_t event, void *arg)
{
    struct wolfIP_sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd;
    (void)arg;

    if (fd != server.listen_fd) {
        return;
    }

    if (!(event & CB_EVENT_READABLE)) {
        return;
    }

    /* Only accept if we're in listening state */
    if (server.state != HTTPS_STATE_LISTENING) {
        return;
    }

    /* Accept new connection */
    client_fd = wolfIP_sock_accept(server.stack, server.listen_fd,
        (struct wolfIP_sockaddr *)&client_addr, &addr_len);
    if (client_fd < 0) {
        return;
    }

    debug_print("HTTPS: Client connected!\n");
    server.client_fd = client_fd;
    server.state = HTTPS_STATE_ACCEPTING;

    /* Register callback for client socket */
    wolfIP_register_callback(server.stack, client_fd, https_client_cb, NULL);
}

/* Callback for client socket - handles data events */
static void https_client_cb(int fd, uint16_t event, void *arg)
{
    (void)arg;

    if (fd != server.client_fd) {
        return;
    }

    /* Handle connection closed */
    if (event & CB_EVENT_CLOSED) {
        debug_print("HTTPS: Client disconnected\n");
        server.state = HTTPS_STATE_CLOSING;
    }
}

int https_server_poll(void)
{
    int ret;
    int err;

    switch (server.state) {
        case HTTPS_STATE_LISTENING:
            /* Accept is handled by https_listen_cb callback */
            break;

        case HTTPS_STATE_ACCEPTING:
            /* Create SSL object */
            server.ssl = wolfSSL_new(server.ctx);
            if (server.ssl == NULL) {
                debug_print("HTTPS: wolfSSL_new failed\n");
                server.state = HTTPS_STATE_CLOSING;
                break;
            }

            ret = wolfSSL_SetIO_wolfIP(server.ssl, server.client_fd);
            if (ret != 0) {
                debug_print("HTTPS: SetIO failed\n");
                server.state = HTTPS_STATE_CLOSING;
                break;
            }

            server.state = HTTPS_STATE_HANDSHAKE;
            break;

        case HTTPS_STATE_HANDSHAKE:
            ret = wolfSSL_accept(server.ssl);
            if (ret == WOLFSSL_SUCCESS) {
                debug_print("HTTPS: TLS handshake complete\n");
                server.rx_len = 0;
                server.state = HTTPS_STATE_READ_REQUEST;
            } else {
                err = wolfSSL_get_error(server.ssl, ret);
                if (err != WOLFSSL_ERROR_WANT_READ &&
                    err != WOLFSSL_ERROR_WANT_WRITE) {
                    debug_print("HTTPS: Handshake failed\n");
                    server.state = HTTPS_STATE_CLOSING;
                }
            }
            break;

        case HTTPS_STATE_READ_REQUEST:
            ret = wolfSSL_read(server.ssl,
                server.rx_buf + server.rx_len,
                HTTPS_RX_BUF_SIZE - server.rx_len - 1);
            if (ret > 0) {
                server.rx_len += ret;
                /* Check for end of HTTP request */
                server.rx_buf[server.rx_len] = '\0';
                if (strstr((char *)server.rx_buf, "\r\n\r\n") != NULL) {
                    process_request();
                    server.state = HTTPS_STATE_SEND_RESPONSE;
                }
            } else {
                err = wolfSSL_get_error(server.ssl, ret);
                if (err != WOLFSSL_ERROR_WANT_READ) {
                    server.state = HTTPS_STATE_CLOSING;
                }
            }
            break;

        case HTTPS_STATE_SEND_RESPONSE:
            ret = wolfSSL_write(server.ssl,
                server.tx_buf + server.tx_sent,
                server.tx_len - server.tx_sent);
            if (ret > 0) {
                server.tx_sent += ret;
                if (server.tx_sent >= server.tx_len) {
                    debug_print("HTTPS: Response sent\n");
                    server.state = HTTPS_STATE_CLOSING;
                }
            } else {
                err = wolfSSL_get_error(server.ssl, ret);
                if (err != WOLFSSL_ERROR_WANT_WRITE) {
                    server.state = HTTPS_STATE_CLOSING;
                }
            }
            break;

        case HTTPS_STATE_CLOSING:
            if (server.ssl) {
                wolfSSL_shutdown(server.ssl);
                wolfSSL_free(server.ssl);
                server.ssl = NULL;
            }
            if (server.client_fd >= 0) {
                wolfIP_sock_close(server.stack, server.client_fd);
                server.client_fd = -1;
            }
            server.rx_len = 0;
            server.tx_len = 0;
            server.tx_sent = 0;
            server.state = HTTPS_STATE_LISTENING;
            break;
    }

    return 0;
}

void https_server_set_info(uint32_t ip_addr, uint32_t uptime_sec)
{
    server.device_ip = ip_addr;
    server.uptime_sec = uptime_sec;
}

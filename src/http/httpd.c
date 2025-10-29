/* httpd.c
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
 */
#include "wolfip.h"
#include "httpd.h"

static const char *http_status_text(int status_code) {
    switch (status_code) {
        case HTTP_STATUS_OK:
            return "OK";
        case HTTP_STATUS_BAD_REQUEST:
            return "Bad Request";
        case HTTP_STATUS_NOT_FOUND:
            return "Not Found";
        case HTTP_STATUS_TEAPOT:
            return "I'm a teapot";
        case HTTP_STATUS_TOO_MANY_REQUESTS:
            return "Too Many Requests";
        case HTTP_STATUS_INTERNAL_SERVER_ERROR:
            return "Internal Server Error";
        case HTTP_STATUS_SERVICE_UNAVAILABLE:
            return "Service Unavailable";
        default:
            return "Unknown";
    }
}
/*
static struct http_client *http_client_find(struct httpd *httpd, int sd) {
    for (int i = 0; i < HTTPD_MAX_CLIENTS; i++) {
        if (httpd->clients[i].client_sd == sd) {
            return &httpd->clients[i];
        }
    }
    return NULL;
}
*/

int httpd_register_handler(struct httpd *httpd, const char *path, int (*handler)(struct httpd *httpd, struct http_client *hc, struct http_request *req)) {
    for (int i = 0; i < HTTPD_MAX_URLS; i++) {
        if (httpd->urls[i].handler == NULL) {
            strncpy(httpd->urls[i].path, path, HTTP_PATH_LEN);
            httpd->urls[i].handler = handler;
            return 0;
        }
    }
    return -1;
}

int httpd_register_static_page(struct httpd *httpd, const char *path, const char *content) {
    for (int i = 0; i < HTTPD_MAX_URLS; i++) {
        if (httpd->urls[i].handler == NULL) {
            strncpy(httpd->urls[i].path, path, HTTP_PATH_LEN);
            httpd->urls[i].handler = NULL;
            httpd->urls[i].static_content = content;
            return 0;
        }
    }
    return -1;
}

static struct http_url *http_find_url(struct httpd *httpd, const char *path) {
    for (int i = 0; i < HTTPD_MAX_URLS; i++) {
        if (strcmp(httpd->urls[i].path, path) == 0) {
            return &httpd->urls[i];
        }
    }
    return NULL;
}

void http_send_response_headers(struct http_client *hc, int status_code, const char *status_text, const char *content_type, size_t content_length)
{
    char txt_response[HTTP_TX_BUF_LEN];
    memset(txt_response, 0, sizeof(txt_response));
    if (!hc) return;
    /* If content_lenght is 0, assume chunked encoding */
    if (content_length == 0) {
        snprintf(txt_response, sizeof(txt_response), "HTTP/1.1 %d %s\r\n"
            "Content-Type: %s\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n",
            status_code, status_text, content_type);
    } else {
        snprintf(txt_response, sizeof(txt_response), "HTTP/1.1 %d %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %zu\r\n"
            "\r\n",
            status_code, status_text, content_type, content_length);
    }
    if (hc->ssl) {
        wolfSSL_write(hc->ssl, txt_response, strlen(txt_response));
    } else {
        wolfIP_sock_send(hc->httpd->ipstack, hc->client_sd, txt_response, strlen(txt_response), 0);
    }
}

void http_send_response_body(struct http_client *hc, const void *body, size_t len) {
    if (!hc) return;
    if (hc->ssl) {
        wolfSSL_write(hc->ssl, body, len);
    } else {
        wolfIP_sock_send(hc->httpd->ipstack, hc->client_sd, body, len, 0);
    }
}

void http_send_response_chunk(struct http_client *hc, const void *chunk, size_t len) {
    char txt_chunk[8];
    memset(txt_chunk, 0, sizeof(txt_chunk));
    if (!hc) return;
    snprintf(txt_chunk, sizeof(txt_chunk), "%zx\r\n", len);
    if (hc->ssl) {
        wolfSSL_write(hc->ssl, txt_chunk, strlen(txt_chunk));
        wolfSSL_write(hc->ssl, chunk, len);
        wolfSSL_write(hc->ssl, "\r\n", 2);
    } else {
        struct wolfIP *s = hc->httpd->ipstack;
        wolfIP_sock_send(s, hc->client_sd, txt_chunk, strlen(txt_chunk), 0);
        wolfIP_sock_send(s, hc->client_sd, chunk, len, 0);
        wolfIP_sock_send(s, hc->client_sd, "\r\n", 2, 0);
    }
}

void http_send_response_chunk_end(struct http_client *hc) {
    if (!hc) return;
    if (hc->ssl) {
        wolfSSL_write(hc->ssl, "0\r\n\r\n", 5);
    } else {
        wolfIP_sock_send(hc->httpd->ipstack, hc->client_sd, "0\r\n\r\n", 5, 0);
    }
}

void http_send_200_OK(struct http_client *hc) {
    http_send_response_headers(hc, HTTP_STATUS_OK,
            http_status_text(HTTP_STATUS_OK), "text/plain", 0);
}

void http_send_500_server_error(struct http_client *hc) {
    http_send_response_headers(hc, HTTP_STATUS_INTERNAL_SERVER_ERROR,
            http_status_text(HTTP_STATUS_INTERNAL_SERVER_ERROR), "text/plain", 0);
}

void http_send_503_service_unavailable(struct http_client *hc) {
    http_send_response_headers(hc, HTTP_STATUS_SERVICE_UNAVAILABLE,
            http_status_text(HTTP_STATUS_SERVICE_UNAVAILABLE), "text/plain", 0);
}

void http_send_418_teapot(struct http_client *hc) {
    http_send_response_headers(hc, HTTP_STATUS_TEAPOT,
            http_status_text(HTTP_STATUS_TEAPOT), "text/plain", 0);
}

int http_url_decode(char *buf, size_t len) {
    char *p = buf;
    char *q;
    while (p < buf + len) {
        q = strchr(p, '%');
        if (!q) {
            break;
        }
        if (q + 2 >= buf + len) {
            break;
        }
        *q = (char) strtol(q + 1, NULL, 16);
        memmove(q + 1, q + 3, len - (q + 3 - buf));
        len -= 2;
    }
    return len;
}

int http_url_encode(char *buf, size_t len, size_t max_len) {
    char *p = buf;
    char *q = NULL;
    while (p < buf + len) {
        q = strchr(p, ' ');
        if (!q) {
            break;
        }
        if (len + 2 >= max_len) {
            return -1; /* Not enough space */
        }
        memmove(q + 3, q + 1, len - (q + 1 - buf));
        *q = '%';
        *(q + 1) = '2';
        *(q + 2) = '0';
        len += 2;
    }
    if (q)
        q[len] = '\0';
    return len;
}

static int parse_http_request(struct http_client *hc, uint8_t *buf, size_t len) {
    char *p = (char *) buf;
    char *end = p + len;
    char *q;
    size_t n;
    int ret;
    struct http_request req;
    struct http_url *url = NULL;
    memset(&req, 0, sizeof(struct http_request));
    http_url_decode(p, len); /* Decode can be done in place */
    if (len < 4) goto bad_request;
    /* Parse the request line */
    q = strchr(p, ' ');
    if (!q) goto bad_request;
    n = q - p;
    if (n >= sizeof(req.method)) goto bad_request;
    memcpy(req.method, p, n);
    req.method[n] = '\0';
    p = q + 1;
    q = strchr(p, ' ');
    if (!q) goto bad_request;
    n = q - p;
    if (n >= sizeof(req.path)) goto bad_request;
    memcpy(req.path, p, n);
    req.path[n] = '\0';
    p = q + 1;
    q = strchr(p, '\r');
    if (!q) goto bad_request;
    n = q - p;
    if (n >= sizeof(req.query)) goto bad_request;
    memcpy(req.query, p, n);
    req.query[n] = '\0';
    p = q + 2;

    /* Parse the headers */
    while (p < end) {
        q = strstr(p, "\r\n");
        if (!q) goto bad_request;
        n = q - p;
        if (n == 0) {
            break;
        }
        if (n >= sizeof(req.headers)) goto bad_request;
        memcpy(req.headers, p, n);
        req.headers[n] = '\0';
        p = q + 2;
    }
    /* Parse the body */
    if (p < end) {
        n = end - p;
        if (n >= sizeof(req.body)) {
            return -1;
        }
        memcpy(req.body, p, n);
        req.body[n] = '\0';
        req.body_len = n;
    }

    if ((strcmp(req.method, "GET") != 0) && (strcmp(req.method, "POST") != 0))
        goto bad_request;
    url = http_find_url(hc->httpd, req.path);
    if (!url) goto not_found;

    if ((url->handler == NULL) && (url->static_content == NULL))
        goto service_unavailable;
    if (url->handler == NULL) {
        http_send_response_headers(hc, HTTP_STATUS_OK, http_status_text(HTTP_STATUS_OK), "text/html", strlen(url->static_content));
        http_send_response_body(hc, url->static_content, strlen(url->static_content));
        ret = 0;
    } else {
        ret = url->handler(hc->httpd, hc, &req);
    }
    return ret;
bad_request:
    http_send_response_headers(hc, HTTP_STATUS_BAD_REQUEST, http_status_text(HTTP_STATUS_BAD_REQUEST), "text/plain", 0);
    return -1;
not_found:
    http_send_response_headers(hc, HTTP_STATUS_NOT_FOUND, http_status_text(HTTP_STATUS_NOT_FOUND), "text/plain", 0);
    return -1;
service_unavailable:
    http_send_response_headers(hc, HTTP_STATUS_SERVICE_UNAVAILABLE, http_status_text(HTTP_STATUS_SERVICE_UNAVAILABLE), "text/plain", 0);
    return -1;
}

static void http_recv_cb(int sd, uint16_t event, void *arg) {
    struct http_client *hc = (struct http_client *) arg;
    int parse_r;
    uint8_t buf[HTTP_RECV_BUF_LEN];
    int ret;
    if (!hc) return;
    (void) event;
    if (hc->ssl) {
        ret = wolfSSL_read(hc->ssl, buf, sizeof(buf));
        if (ret < 0) {
            if (wolfSSL_get_error(hc->ssl, ret) == WOLFSSL_ERROR_WANT_READ) {
                return;
            } else {
                goto fail_close;
            }
        }
    } else {
        ret = wolfIP_sock_recv(hc->httpd->ipstack, sd, buf, sizeof(buf), 0);
        if (ret == -11)
            return;
    }
    if (ret <= 0)
        goto fail_close;
    parse_r = parse_http_request(hc, buf, ret);
    if (parse_r < 0)
        goto fail_close;

    return;

fail_close:
    if (hc->ssl) {
        wolfSSL_free(hc->ssl);
        hc->ssl = NULL;
    }
    wolfIP_sock_close(hc->httpd->ipstack, sd);
    hc->client_sd = 0;
}

static void http_accept_cb(int sd, uint16_t event, void *arg) {
    struct httpd *httpd = (struct httpd *) arg;
    struct wolfIP_sockaddr_in addr;
    socklen_t addr_len = sizeof(struct wolfIP_sockaddr_in);
    int client_sd = wolfIP_sock_accept(httpd->ipstack, sd, (struct wolfIP_sockaddr *) &addr, &addr_len);
    if (client_sd < 0) {
        return;
    }
    (void) event;
    for (int i = 0; i < HTTPD_MAX_CLIENTS; i++) {
        if (httpd->clients[i].client_sd == 0) {
            httpd->clients[i].client_sd = client_sd;
            httpd->clients[i].httpd = httpd;
            memcpy(&httpd->clients[i].addr, &addr, sizeof(addr));
            if (httpd->ssl_ctx) {
                httpd->clients[i].ssl = wolfSSL_new(httpd->ssl_ctx);
                if (httpd->clients[i].ssl) {
                    wolfSSL_SetIO_FT(httpd->clients[i].ssl, client_sd);
                } else {
                    /* Failed to create SSL object */
                    wolfIP_sock_close(httpd->ipstack, client_sd);
                    httpd->clients[i].client_sd = 0;
                    return;
                }
            }
            wolfIP_register_callback(httpd->ipstack, client_sd, http_recv_cb, &httpd->clients[i]);
            break;
        }
    }
}

/* Extra utility to extract requests arguments */
int httpd_get_request_arg(struct http_request *req, const char *name, char *value, size_t value_len) {
    char *p;
    char *q;
    char *sep;

    if (strcmp(req->method, "GET") == 0)
        p = req->query;
    else if (strcmp(req->method, "POST") == 0)
        p = req->body;
    else
        return -1; // Unsupported method

    while (*p) {
        q = strchr(p, '&');
        if (!q) {
            q = p + strlen(p); // End of key-value pair
        }
        sep = strchr(p, '=');
        if (sep && sep < q) { // Ensure '=' is within bounds
            size_t key_len = sep - p;
            if (key_len == strlen(name) && strncmp(p, name, key_len) == 0) {
                size_t value_len_actual = q - (sep + 1);
                if (value_len_actual >= value_len) {
                    return -1; // Insufficient buffer size
                }
                memcpy(value, sep + 1, value_len_actual);
                value[value_len_actual] = '\0';
                return 0;
            }
        }
        p = q + 1; // Move to next key-value pair
    }
    return -1; // Key not found
}

int httpd_init(struct httpd *httpd, struct wolfIP *s, uint16_t port, void *ssl_ctx) {
    struct wolfIP_sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (!httpd) {
        return -1;
    }
    memset(httpd, 0, sizeof(struct httpd));
    httpd->ipstack = s;
    httpd->port = port;
    httpd->listen_sd = wolfIP_sock_socket(s, AF_INET, SOCK_STREAM, 0);
    if (httpd->listen_sd < 0) {
        return -1;
    }
    if (wolfIP_sock_bind(s, httpd->listen_sd, (struct wolfIP_sockaddr *) &addr, sizeof(addr)) < 0) {
        return -1;
    }
    if (wolfIP_sock_listen(s, httpd->listen_sd, 5) < 0) {
        return -1;
    }
    if (ssl_ctx) {
        httpd->ssl_ctx = (WOLFSSL_CTX *) ssl_ctx;
        wolfSSL_SetIO_FT_CTX(httpd->ssl_ctx, httpd->ipstack);
    }
    wolfIP_register_callback(s, httpd->listen_sd, http_accept_cb, httpd);
    return 0;
}






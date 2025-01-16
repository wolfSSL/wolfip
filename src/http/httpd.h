#ifndef WOLF_HTTPD_H
#define WOLF_HTTPD_H
#ifdef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#else
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <stdint.h>

#define HTTP_METHOD_LEN 8
#define HTTP_PATH_LEN 128
#define HTTP_QUERY_LEN 256
#define HTTP_HEADERS_LEN 512
#define HTTP_BODY_LEN 1024


/* Config */
#define HTTP_RECV_BUF_LEN 1460
#define HTTP_TX_BUF_LEN 1460

#define HTTPD_MAX_URLS 16
#define HTTPD_MAX_CLIENTS 4

/* Constants for HTTP status codes */
#define HTTP_STATUS_OK 200
#define HTTP_STATUS_BAD_REQUEST 400
#define HTTP_STATUS_NOT_FOUND 404
#define HTTP_STATUS_TEAPOT 418
#define HTTP_STATUS_TOO_MANY_REQUESTS 429
#define HTTP_STATUS_INTERNAL_SERVER_ERROR 500
#define HTTP_STATUS_SERVICE_UNAVAILABLE 503

struct httpd;

struct http_request {
    char method[HTTP_METHOD_LEN];      // "GET", "POST", etc.
    char path[HTTP_PATH_LEN];          // URL path
    char query[HTTP_QUERY_LEN];        // URL query string (for GET requests)
    char headers[HTTP_HEADERS_LEN];    // HTTP headers
    char body[HTTP_BODY_LEN];          // HTTP body (for POST requests)
    size_t body_len;
};

struct http_client {
    struct httpd *httpd;
    int client_sd;
    struct wolfIP_sockaddr_in addr;
    WOLFSSL *ssl;   /* NULL if not using SSL */
};

struct http_url {
    char path[HTTP_PATH_LEN];
    int (*handler)(struct httpd *httpd, struct http_client *hc, struct http_request *req);
    const char *static_content;
};

struct httpd {
    struct http_url urls[HTTPD_MAX_URLS];
    struct http_client clients[HTTPD_MAX_CLIENTS];
    struct wolfIP *ipstack;
    int listen_sd;
    uint16_t port;
    WOLFSSL_CTX *ssl_ctx;
};

int httpd_init(struct httpd *httpd, struct wolfIP *s, uint16_t port, void *ssl_ctx);
int httpd_register_handler(struct httpd *httpd, const char *path, int (*handler)(struct httpd *httpd, struct http_client *hc, struct http_request *req));
int httpd_register_static_page(struct httpd *httpd, const char *path, const char *content);
int httpd_get_request_arg(struct http_request *req, const char *name, char *value, size_t value_len);
void http_send_response_headers(struct http_client *hc, int status_code, const char *status_text, const char *content_type, size_t content_length);
void http_send_response_body(struct http_client *hc, const void *body, size_t len);
void http_send_response_chunk(struct http_client *hc, const void *chunk, size_t len);
void http_send_response_chunk_end(struct http_client *hc);
void http_send_200_OK(struct http_client *hc);
void http_send_500_server_error(struct http_client *hc);
void http_send_503_service_unavailable(struct http_client *hc);
void http_send_418_teapot(struct http_client *hc);

int http_url_decode(char *buf, size_t len);
int http_url_encode(char *buf, size_t len, size_t max_len);


#endif

# HTTP/HTTPS Server How-To

This guide shows how to use the wolfIP **HTTP server** module (`src/http/`): how
to build it, how to bring up a server on a TCP port, how to register static
pages and dynamic handlers, and how to layer TLS on top of it to serve HTTPS.

It is a getting-started document. The authoritative API is `src/http/httpd.h`;
the worked examples come from `src/test/test_httpd.c` (a TLS server serving a
static page) and `src/port/stm32h563/main.c` (an HTTPS status page served by a
dynamic handler on an STM32H5).

## Table of Contents

- [1. What the HTTP module is](#1-what-the-http-module-is)
- [2. Building with HTTP](#2-building-with-http)
- [3. Architecture: event callbacks, no threads](#3-architecture-event-callbacks-no-threads)
- [4. The server lifecycle](#4-the-server-lifecycle)
- [5. Registering content: static pages and handlers](#5-registering-content-static-pages-and-handlers)
- [6. The handler/callback API](#6-the-handlercallback-api)
- [7. Reading the request: methods, query and form args](#7-reading-the-request-methods-query-and-form-args)
- [8. Building the response](#8-building-the-response)
- [9. Serving a page: a minimal example](#9-serving-a-page-a-minimal-example)
- [10. Enabling HTTPS (TLS layering)](#10-enabling-https-tls-layering)
- [11. URL encoding/decoding helpers](#11-url-encodingdecoding-helpers)
- [12. Troubleshooting](#12-troubleshooting)

---

## 1. What the HTTP module is

`src/http/` is a small, self-contained HTTP/1.1 server (`httpd.c`/`httpd.h`)
built directly on the wolfIP socket API. Like the rest of wolfIP it performs
**zero dynamic allocation**: the server, its client slots, and the routing table
all live inside a single caller-provided `struct httpd`. Request and response
buffers are fixed-size and stack-allocated per call.

The server is **event-driven**. It registers wolfIP socket callbacks and is
driven entirely from inside `wolfIP_poll()` on a single thread — there is no
accept loop or per-connection thread to manage. When data arrives on a client
socket, wolfIP calls back into the module, which parses one request and emits a
response synchronously.

It supports:

- **GET** and **POST** requests (any other method is rejected as
  `400 Bad Request`).
- **Static pages** registered by path, served with `Content-Type: text/html`.
- **Dynamic handlers** registered by path, which build the response themselves.
- **HTTPS** by handing the server a `WOLFSSL_CTX`, in which case every client
  connection is wrapped in a TLS session via the wolfSSL-over-wolfIP I/O layer.

The module is deliberately minimal. Responses are sent immediately as they are
generated, with no buffering; if the output socket is congested the write fails
and the connection is closed (see the header comment in `httpd.c`).

## 2. Building with HTTP

The HTTP server is gated by the `WOLFIP_ENABLE_HTTP` macro. The default POSIX
`config.h` enables it:

```c
/* config.h */
/* Enable HTTP server for POSIX builds */
#ifndef WOLFIP_ENABLE_HTTP
#define WOLFIP_ENABLE_HTTP
#endif
```

Unlike the TFTP module, `src/http/httpd.c` is **not** globbed into the main
wolfIP library. It is compiled and linked per target, and it always depends on
wolfSSL (the header pulls in `<wolfssl/ssl.h>` unconditionally, even for plain
HTTP). The relevant flags, from the top-level `Makefile`, are:

| Flag | Purpose |
|------|---------|
| `-DWOLFIP_ENABLE_HTTP` | Compiles the module in (everything in `httpd.c`/`httpd.h` is `#ifdef`-guarded by it). |
| `-DWOLFSSL_WOLFIP` | Selects the wolfSSL-over-wolfIP I/O backend used for HTTPS. |
| `-Isrc/http` | Lets sources `#include "httpd.h"`. |

To build and run the bundled HTTP/TLS server test:

```sh
make build/test-httpd
```

That target links `build/http/httpd.o`, the wolfSSL I/O glue
(`build/port/wolfssl_io.o`), and a test certificate/key against `-lwolfssl`
(`Makefile`). The CMake build defines an equivalent `test-httpd` target /
`add_test(NAME httpd ...)`.

To use the module in your own build, compile `src/http/httpd.c` with the flags
above, add `src/http` to the include path, and link wolfSSL.

## 3. Architecture: event callbacks, no threads

The module installs two kinds of wolfIP callback and never blocks:

```text
   wolfIP_poll(s, now_ms)
        │
        ├─ listen socket readable ─▶ http_accept_cb()
        │        │
        │        ├─ wolfIP_sock_accept() ─▶ new client_sd
        │        ├─ claim a free clients[] slot (max HTTPD_MAX_CLIENTS)
        │        ├─ if ssl_ctx: wolfSSL_new() + wolfSSL_SetIO_wolfIP()
        │        └─ wolfIP_register_callback(client_sd, http_recv_cb, &client)
        │
        └─ client socket readable ─▶ http_recv_cb()
                 │
                 ├─ read   : wolfSSL_read()  (HTTPS)  or  wolfIP_sock_recv()
                 ├─ parse  : parse_http_request()  ── one request, in place
                 ├─ route  : http_find_url(path)
                 │             ├─ static_content ─▶ headers + body
                 │             └─ handler(...)    ─▶ app builds the response
                 └─ write  : wolfSSL_write() (HTTPS) or wolfIP_sock_send()
```

All you do at the application level is: create a `wolfIP` stack, call
`httpd_init()`, register your routes, and keep calling `wolfIP_poll()` from your
main loop. Everything above happens inside `poll`.

## 4. The server lifecycle

A server is one `struct httpd` plus a call to `httpd_init()`
(`src/http/httpd.h`):

```c
int httpd_init(struct httpd *httpd, struct wolfIP *s, uint16_t port, void *ssl_ctx);
```

`httpd_init()` zeroes the `struct httpd`, then creates a TCP socket, binds it to
`port`, calls `listen()` with a backlog of 5, and registers the accept callback
(`httpd.c`). Pass `ssl_ctx = NULL` for plain HTTP, or a configured
`WOLFSSL_CTX *` for HTTPS (see [section 10](#10-enabling-https-tls-layering)).
It returns `0` on success or `-1` if any socket step fails.

The lifecycle is:

1. Bring up the wolfIP stack and configure its IP (DHCP or static).
2. `httpd_init(&httpd, s, port, ssl_ctx)`.
3. Register one or more routes with `httpd_register_static_page()` and/or
   `httpd_register_handler()`.
4. Drive the stack: call `wolfIP_poll(s, now_ms)` in your main loop forever.

There is no explicit teardown call; individual client connections are closed
automatically by the module on error or after a response. `struct httpd` holds
its own listen socket, so its lifetime must match the server's.

## 5. Registering content: static pages and handlers

Routes are matched by **exact path** (`strcmp`), up to `HTTPD_MAX_URLS` (16)
entries. There are two registration calls (`src/http/httpd.h`):

```c
int httpd_register_static_page(struct httpd *httpd, const char *path,
                               const char *content);
int httpd_register_handler(struct httpd *httpd, const char *path,
        int (*handler)(struct httpd *httpd, struct http_client *hc,
                       struct http_request *req));
```

- **Static page** — `content` is a NUL-terminated string the module serves
  verbatim with status `200 OK` and `Content-Type: text/html`. The string is
  referenced by pointer, not copied, so it must outlive the server.
- **Handler** — for any request to `path`, the module calls your function and
  lets it build the entire response.

Both copy the path into the route table (truncated to `HTTP_PATH_LEN`, 128) and
return `0`, or `-1` if all 16 slots are taken. Each successful registration
consumes one slot; there is no public deregistration API. A registered route with
neither a handler nor static content yields `503 Service Unavailable`; an
unmatched path yields `404 Not Found` (`parse_http_request()` in `httpd.c`).

## 6. The handler/callback API

A handler has this exact signature (`src/http/httpd.h`):

```c
int my_handler(struct httpd *httpd, struct http_client *hc,
               struct http_request *req);
```

- `httpd` — the server instance (often unused; cast to `(void)`).
- `hc` — the opaque per-client context. You pass it back to the response
  helpers; you do not write its fields directly.
- `req` — the parsed request (see below). The struct is stack-allocated for the
  duration of the call, so copy out anything you need to keep.

The parsed request (`struct http_request`, `httpd.h`) is fixed-size:

```c
struct http_request {
    char method[HTTP_METHOD_LEN];   /* "GET", "POST"            (max 8)   */
    char path[HTTP_PATH_LEN];       /* URL path, percent-decoded (max 128) */
    char query[HTTP_QUERY_LEN];     /* raw query string         (max 256) */
    char headers[HTTP_HEADERS_LEN]; /* header block, CRLF-joined (max 1024) */
    char body[HTTP_BODY_LEN];       /* request body             (max 1024) */
    size_t body_len;
};
```

The return value is propagated by the module: return `0` after you have sent a
response. A negative return from your handler causes the module to close the
client connection (`http_recv_cb()` treats a negative parse/handler result as a
failure and tears the connection down).

> **Note.** `req->headers` holds the request's header lines joined with the CRLF
> they arrived with, so a handler can re-split it on `"\r\n"`. A request whose
> header block does not fit is rejected; framing headers (`Content-Length`,
> `Transfer-Encoding`) are consumed internally and are not meant to be re-read
> here.

## 7. Reading the request: methods, query and form args

Only `GET` and `POST` reach a route; anything else is rejected before dispatch.
To pull a named argument out of a GET query string or a POST form body, use the
helper (`src/http/httpd.h`):

```c
int httpd_get_request_arg(struct http_request *req, const char *name,
                          char *value, size_t value_len);
```

It searches `req->query` for a `GET` and `req->body` for a `POST`, looking for
`name=value` pairs separated by `&`. On a match it copies the value (NUL
terminated) into `value` and returns `0`; it returns `-1` if the key is not
found, the method is unsupported, or `value_len` is too small
(`httpd_get_request_arg()` in `httpd.c`).

```c
char user[32];
if (httpd_get_request_arg(req, "user", user, sizeof(user)) == 0) {
    /* user now holds the value of ?user=... or user=... */
}
```

The body parser derives the body length from the declared `Content-Length` and
rejects `Transfer-Encoding` (chunked) request bodies, as well as a body with no
`Content-Length`, to avoid request-smuggling ambiguity (see the comment in
`parse_http_request()`).

## 8. Building the response

The response helpers all take the `struct http_client *hc` from your handler and
write straight to the socket (plain or TLS). From `src/http/httpd.h`:

| Function | Purpose |
|----------|---------|
| `http_send_response_headers(hc, code, status_text, content_type, content_length)` | Emit the status line + headers. `content_length == 0` switches to `Transfer-Encoding: chunked`. |
| `http_send_response_body(hc, body, len)` | Send a response body (after fixed-length headers). |
| `http_send_response_chunk(hc, chunk, len)` | Send one chunk (after chunked headers). |
| `http_send_response_chunk_end(hc)` | Terminate a chunked response. |
| `http_send_200_OK(hc)` | Shorthand: 200 headers, `text/plain`, chunked. |
| `http_send_500_server_error(hc)` | Shorthand: `500 Internal Server Error`. |
| `http_send_503_service_unavailable(hc)` | Shorthand: `503 Service Unavailable`. |
| `http_send_418_teapot(hc)` | Shorthand: `418 I'm a teapot`. |

The common fixed-length pattern is **headers then body**:

```c
http_send_response_headers(hc, HTTP_STATUS_OK, "OK", "text/html", len);
http_send_response_body(hc, response, len);
return 0;
```

For a response whose size is not known up front, send chunked headers
(`content_length == 0`), then any number of `http_send_response_chunk()` calls,
and finish with `http_send_response_chunk_end()`. Any write failure inside these
helpers closes the client connection automatically.

Status code constants are defined in `httpd.h`: `HTTP_STATUS_OK` (200),
`HTTP_STATUS_BAD_REQUEST` (400), `HTTP_STATUS_NOT_FOUND` (404),
`HTTP_STATUS_TEAPOT` (418), `HTTP_STATUS_TOO_MANY_REQUESTS` (429),
`HTTP_STATUS_INTERNAL_SERVER_ERROR` (500), `HTTP_STATUS_SERVICE_UNAVAILABLE`
(503).

## 9. Serving a page: a minimal example

A complete dynamic handler that builds an HTML page and returns it, condensed
from `src/port/stm32h563/main.c` (`https_status_handler`):

```c
static int status_handler(struct httpd *httpd, struct http_client *hc,
    struct http_request *req)
{
    char response[512];
    int len;
    (void)httpd;

    /* Build the page (req->method / req->path are available if needed) */
    len = snprintf(response, sizeof(response),
        "<!DOCTYPE html><html><head><title>wolfIP</title></head>"
        "<body><h1>wolfIP Status</h1>"
        "<p>You asked for: %s</p></body></html>",
        req->path);

    http_send_response_headers(hc, HTTP_STATUS_OK, "OK", "text/html", len);
    http_send_response_body(hc, response, len);
    return 0;
}
```

Wiring it up (the static-page variant is even shorter, from
`src/test/test_httpd.c`):

```c
struct httpd httpd;
const char homepage[] = "<html><body><h1>Hello, world!</h1></body></html>";

/* Plain HTTP on port 80; pass NULL for the ssl_ctx argument. */
if (httpd_init(&httpd, s, 80, NULL) < 0)
    return -1;

httpd_register_static_page(&httpd, "/", homepage);   /* serves homepage */
httpd_register_handler(&httpd, "/status", status_handler);

/* Main loop: the server runs entirely inside wolfIP_poll(). */
for (;;) {
    uint32_t ms_next = wolfIP_poll(s, now_ms());
    /* sleep up to ms_next, service other work, then loop */
}
```

That is the whole server. `httpd_register_static_page(&httpd, "/", homepage)`
is exactly what `test_httpd.c` does (over TLS, on port 443).

## 10. Enabling HTTPS (TLS layering)

HTTPS is enabled by passing a configured `WOLFSSL_CTX *` as the fourth argument
to `httpd_init()` instead of `NULL`. The module then:

- calls `wolfSSL_SetIO_wolfIP_CTX(ssl_ctx, ipstack)` in `httpd_init()` to bind
  the TLS context to the wolfIP I/O backend, and
- for every accepted connection creates a `WOLFSSL` with `wolfSSL_new()` and
  attaches it to the client socket with `wolfSSL_SetIO_wolfIP()`
  (`http_accept_cb()`).

After that, every read uses `wolfSSL_read()` and every write
`wolfSSL_write()` transparently — the same handlers and response helpers work
for HTTP and HTTPS unchanged. The wolfSSL-over-wolfIP I/O glue
(`wolfSSL_SetIO_wolfIP*`, `wolfSSL_CleanupIO_wolfIP`) lives in
`src/port/wolfssl_io.c` and must be linked in.

Setting up the context is ordinary wolfSSL. From `src/test/test_httpd.c`:

```c
WOLFSSL_CTX *server_ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());

wolfSSL_CTX_use_certificate_buffer(server_ctx, server_der, server_der_len,
        SSL_FILETYPE_ASN1);
wolfSSL_CTX_use_PrivateKey_buffer(server_ctx, server_key_der, server_key_der_len,
        SSL_FILETYPE_ASN1);

httpd_init(&httpd, s, 443, server_ctx);          /* HTTPS on 443 */
httpd_register_static_page(&httpd, "/", homepage);
```

`src/port/stm32h563/main.c` does the same with `wolfTLSv1_3_server_method()` and
PEM certificate/key buffers, then registers a dynamic handler. Either TLS
version works; the choice is entirely in how you build the `WOLFSSL_CTX`.

On the read path, a `WOLFSSL_ERROR_WANT_READ` from `wolfSSL_read()` is handled
internally (the callback simply returns and waits for more data), so partial TLS
records do not break the connection.

## 11. URL encoding/decoding helpers

The module exposes its in-place percent-codec (`src/http/httpd.h`); the request
parser already uses `http_url_decode()` on `req->path`, but the functions are
public if you need them:

```c
/* Returns the decoded length, or a negative error code. */
int http_url_decode(char *buf, size_t len);
int http_url_encode(char *buf, size_t len, size_t max_len);
```

`http_url_decode()` rewrites `%XX` escapes in place and returns the new length,
or `HTTP_URL_DECODE_ERR_TRUNCATED` (-1) / `HTTP_URL_DECODE_ERR_BAD_ESCAPE` (-2).
`http_url_encode()` escapes spaces as `%20`, growing the buffer up to `max_len`,
and returns the new length or `-1` if there is not enough room.

## 12. Troubleshooting

- **Server never accepts connections.** `httpd_init()` returned `-1` (socket,
  bind, or listen failed) — check the port is free and the stack has an IP
  configured before `httpd_init()`. Also confirm you are calling
  `wolfIP_poll()` continuously; nothing happens between polls.
- **All requests get `404`.** Routes are matched by **exact** path with
  `strcmp`. `/status` and `/status/` are different, and there is no prefix or
  wildcard matching. Register the exact path the client requests.
- **A registered route returns `503`.** The route exists but has neither a
  handler nor static content (e.g. a handler registered as `NULL`).
- **POST body is empty or the request is `400`.** The parser requires a valid
  `Content-Length` matching the body length and rejects chunked
  (`Transfer-Encoding`) request bodies. The body is also capped at
  `HTTP_BODY_LEN` (1024); larger bodies are rejected.
- **HTTPS connection resets at handshake.** Confirm `WOLFSSL_WOLFIP` is defined,
  `src/port/wolfssl_io.c` is linked, the certificate/key loaded into the
  `WOLFSSL_CTX` without error, and `wolfSSL_Init()` was called at startup.
- **Connections drop under load / large responses truncated.** Responses are
  written immediately with no buffering; a congested or full TX window makes the
  send fail and the module closes the connection. Keep responses within a TX
  window, or send incrementally with the chunked helpers.
- **Fifth concurrent client is refused.** Only `HTTPD_MAX_CLIENTS` (4) client
  slots exist; a new accept with no free slot is dropped.

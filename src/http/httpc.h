/* httpc.h
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
 * Minimal HTTP/1.1 GET client. It is transport-agnostic: the caller supplies
 * blocking send/recv callbacks (a wolfSSL session, a plain socket, a test
 * buffer). One request per connection.
 */
#ifndef WOLFIP_HTTPC_H
#define WOLFIP_HTTPC_H

#include <stdint.h>

#define HTTPC_ERR_ARG       (-1)
#define HTTPC_ERR_IO        (-2)    /* send/recv failed or closed early */
#define HTTPC_ERR_HEADER    (-3)    /* malformed or oversized response head */
#define HTTPC_ERR_LENGTH    (-4)    /* no Content-Length, or chunked */
#define HTTPC_ERR_SIZE      (-5)    /* body larger than the caller's buffer */

#ifndef HTTPC_HEAD_MAX
#define HTTPC_HEAD_MAX 1024
#endif

struct httpc_io {
    /* Send all len bytes. Returns 0, or negative on error. */
    int (*send)(void *ctx, const uint8_t *buf, uint32_t len);
    /* Block until at least one byte is read. Returns the count, 0 when the
     * peer closed, negative on error or timeout. */
    int (*recv)(void *ctx, uint8_t *buf, uint32_t len);
    void *ctx;
};

/* GET path from host. On return *body_len holds the body bytes stored in
 * body (at most body_max). Returns the HTTP status code (for example 200),
 * or a negative HTTPC_ERR_ value. The body is only read for a 200. */
int httpc_get(const struct httpc_io *io, const char *host, const char *path,
    uint8_t *body, uint32_t body_max, uint32_t *body_len);

#endif /* WOLFIP_HTTPC_H */

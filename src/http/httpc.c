/* httpc.c
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
 * Minimal HTTP/1.1 GET client over caller-supplied send/recv callbacks.
 */
#include <stdint.h>
#include <string.h>
#include "httpc.h"

static int httpc_send_str(const struct httpc_io *io, const char *s)
{
    return io->send(io->ctx, (const uint8_t *)s, (uint32_t)strlen(s));
}

static char httpc_lower(char c)
{
    if (c >= 'A' && c <= 'Z')
        c = (char)(c - 'A' + 'a');
    return c;
}

/* Find header `name` (lower case, with the colon) in the NUL-terminated
 * response head and return a pointer to its value, or NULL. */
static const char *httpc_header(const char *head, const char *name)
{
    const char *line = head;
    const char *p;
    uint32_t i;

    while ((line = strstr(line, "\r\n")) != NULL) {
        line += 2;
        p = line;
        for (i = 0; name[i] != '\0'; i++) {
            if (httpc_lower(p[i]) != name[i])
                break;
        }
        if (name[i] == '\0') {
            p += i;
            while (*p == ' ' || *p == '\t')
                p++;
            return p;
        }
    }
    return NULL;
}

int httpc_get(const struct httpc_io *io, const char *host, const char *path,
    uint8_t *body, uint32_t body_max, uint32_t *body_len)
{
    char head[HTTPC_HEAD_MAX];
    const char *val;
    char *end = NULL;
    uint32_t fill = 0;
    uint32_t have;
    uint32_t content_len = 0;
    uint32_t got;
    int status;
    int n;

    if (io == NULL || io->send == NULL || io->recv == NULL || host == NULL ||
            path == NULL || body == NULL || body_len == NULL)
        return HTTPC_ERR_ARG;
    *body_len = 0;

    if (httpc_send_str(io, "GET ") != 0 || httpc_send_str(io, path) != 0 ||
            httpc_send_str(io, " HTTP/1.1\r\nHost: ") != 0 ||
            httpc_send_str(io, host) != 0 ||
            httpc_send_str(io, "\r\nConnection: close\r\n\r\n") != 0)
        return HTTPC_ERR_IO;

    /* Response head, up to the blank line. Bytes past it are body. */
    while (end == NULL) {
        if (fill >= sizeof(head) - 1)
            return HTTPC_ERR_HEADER;
        n = io->recv(io->ctx, (uint8_t *)head + fill,
            (uint32_t)(sizeof(head) - 1 - fill));
        if (n <= 0)
            return HTTPC_ERR_IO;
        fill += (uint32_t)n;
        head[fill] = '\0';
        end = strstr(head, "\r\n\r\n");
    }
    end[2] = '\0';
    have = fill - (uint32_t)(end + 4 - head);

    /* "HTTP/1.x NNN" */
    if (strncmp(head, "HTTP/1.", 7) != 0 || head[8] != ' ' ||
            head[9] < '1' || head[9] > '9' || head[10] < '0' ||
            head[10] > '9' || head[11] < '0' || head[11] > '9')
        return HTTPC_ERR_HEADER;
    status = (head[9] - '0') * 100 + (head[10] - '0') * 10 + (head[11] - '0');
    if (status != 200)
        return status;

    if (httpc_header(head, "transfer-encoding:") != NULL)
        return HTTPC_ERR_LENGTH;
    val = httpc_header(head, "content-length:");
    if (val == NULL || *val < '0' || *val > '9')
        return HTTPC_ERR_LENGTH;
    while (*val >= '0' && *val <= '9') {
        if (content_len > (0xFFFFFFFFU - 9U) / 10U)
            return HTTPC_ERR_LENGTH;
        content_len = content_len * 10U + (uint32_t)(*val - '0');
        val++;
    }
    while (*val == ' ' || *val == '\t')
        val++;
    if (*val != '\r')
        return HTTPC_ERR_LENGTH;
    if (content_len > body_max)
        return HTTPC_ERR_SIZE;
    if (have > content_len)
        return HTTPC_ERR_HEADER;

    memcpy(body, end + 4, have);
    got = have;
    while (got < content_len) {
        n = io->recv(io->ctx, body + got, content_len - got);
        if (n <= 0)
            return HTTPC_ERR_IO;
        got += (uint32_t)n;
    }
    *body_len = got;
    return status;
}

/* wolftftp.c
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
#include "wolftftp.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define WOLFTFTP_PKT_MAX (4U + WOLFTFTP_MAX_BLKSIZE)
#define WOLFTFTP_OPT_BLKSIZE   0x01U
#define WOLFTFTP_OPT_TIMEOUT   0x02U
#define WOLFTFTP_OPT_TSIZE     0x04U
#define WOLFTFTP_OPT_WINDOWSIZE 0x08U

struct wolftftp_parsed_req {
    uint16_t opcode;
    char filename[WOLFTFTP_MAX_FILENAME];
    uint16_t blksize;
    uint16_t timeout_s;
    uint16_t windowsize;
    uint32_t tsize;
    uint8_t opts;
};

struct wolftftp_parsed_data {
    uint16_t block;
    const uint8_t *data;
    uint16_t data_len;
};

static size_t wolftftp_strnlen_local(const char *s, size_t max_len)
{
    size_t i;

    if (s == NULL)
        return 0;
    for (i = 0; i < max_len; i++) {
        if (s[i] == '\0')
            return i;
    }
    return max_len;
}

static int wolftftp_stricmp_local(const char *a, const char *b)
{
    unsigned char ca;
    unsigned char cb;

    if (a == NULL || b == NULL)
        return -1;
    while (*a != '\0' || *b != '\0') {
        ca = (unsigned char)tolower((unsigned char)*a);
        cb = (unsigned char)tolower((unsigned char)*b);
        if (ca != cb)
            return (int)ca - (int)cb;
        if (*a != '\0')
            a++;
        if (*b != '\0')
            b++;
    }
    return 0;
}

static uint16_t wolftftp_read_u16(const uint8_t *buf)
{
    return (uint16_t)(((uint16_t)buf[0] << 8) | buf[1]);
}

static void wolftftp_write_u16(uint8_t *buf, uint16_t value)
{
    buf[0] = (uint8_t)(value >> 8);
    buf[1] = (uint8_t)(value & 0xFFU);
}

static int wolftftp_parse_u32(const char *value, uint32_t max_value,
    uint32_t *out)
{
    uint32_t v = 0;
    uint32_t digit;

    if (value == NULL || out == NULL || *value == '\0')
        return -1;
    while (*value != '\0') {
        if (*value < '0' || *value > '9')
            return -1;
        digit = (uint32_t)(*value - '0');
        if (v > (0xFFFFFFFFU - digit) / 10U)
            return -1;
        v = (v * 10U) + digit;
        if (v > max_value)
            return -1;
        value++;
    }
    *out = v;
    return 0;
}

static int wolftftp_copy_string(char *dst, size_t dst_len, const char *src)
{
    size_t len;

    if (dst == NULL || dst_len == 0 || src == NULL)
        return -WOLFIP_EINVAL;
    len = wolftftp_strnlen_local(src, dst_len);
    if (len == 0 || len >= dst_len)
        return -WOLFIP_EINVAL;
    memcpy(dst, src, len);
    dst[len] = '\0';
    return 0;
}

static void wolftftp_cfg_defaults(struct wolftftp_transfer_cfg *cfg)
{
    if (cfg->blksize == 0)
        cfg->blksize = WOLFTFTP_DEFAULT_BLKSIZE;
    if (cfg->timeout_s == 0)
        cfg->timeout_s = WOLFTFTP_DEFAULT_TIMEOUT_S;
    if (cfg->windowsize == 0)
        cfg->windowsize = 1;
    if (cfg->max_retries == 0)
        cfg->max_retries = WOLFTFTP_MAX_RETRIES;
    if (cfg->blksize > WOLFTFTP_MAX_BLKSIZE)
        cfg->blksize = WOLFTFTP_MAX_BLKSIZE;
    if (cfg->windowsize > WOLFTFTP_MAX_WINDOWSIZE)
        cfg->windowsize = WOLFTFTP_MAX_WINDOWSIZE;
}

static void wolftftp_neg_defaults(struct wolftftp_negotiated *neg,
    const struct wolftftp_transfer_cfg *cfg)
{
    memset(neg, 0, sizeof(*neg));
    neg->blksize = cfg->blksize;
    neg->timeout_s = cfg->timeout_s;
    neg->windowsize = cfg->windowsize;
}

static int wolftftp_send(struct wolftftp_transport_ops *transport,
    uint16_t local_port, const struct wolftftp_endpoint *remote,
    const uint8_t *buf, uint16_t len)
{
    if (transport == NULL || transport->send == NULL || remote == NULL ||
            buf == NULL || len == 0)
        return -WOLFIP_EINVAL;
    return transport->send(transport->arg, local_port, remote, buf, len);
}

static void wolftftp_client_finish(struct wolftftp_client *client, int status)
{
    if (client == NULL)
        return;
    client->last_status = status;
    if (client->io.close != NULL && client->handle != NULL)
        client->io.close(client->io.arg, client->handle, status);
    client->handle = NULL;
    client->deadline_ms = 0;
    client->last_tx_len = 0;
    if (status == 0)
        client->state = WOLFTFTP_CLIENT_COMPLETE;
    else
        client->state = WOLFTFTP_CLIENT_ERROR;
}

static void wolftftp_server_finish(struct wolftftp_server *server,
    struct wolftftp_server_session *session, int status)
{
    if (session == NULL)
        return;
    session->last_status = status;
    if (status == 0) {
        if (session->state != WOLFTFTP_SESSION_FREE)
            session->state = WOLFTFTP_SESSION_COMPLETE;
    } else {
        session->state = WOLFTFTP_SESSION_ERROR;
    }
    if (server != NULL && server->io.close != NULL && session->handle != NULL)
        server->io.close(server->io.arg, session->handle, status);
    session->handle = NULL;
    /* Reap the slot in both success and failure paths so that further
     * transfers can be accepted; we have no public API that observes
     * COMPLETE state. */
    memset(session, 0, sizeof(*session));
}

static int wolftftp_append_opt(uint8_t *buf, uint16_t *off, uint16_t max_len,
    const char *key, const char *value)
{
    size_t klen;
    size_t vlen;

    klen = strlen(key) + 1U;
    vlen = strlen(value) + 1U;
    if ((uint32_t)(*off) + klen + vlen > max_len)
        return WOLFTFTP_ERR_PACKET;
    memcpy(buf + *off, key, klen);
    *off = (uint16_t)(*off + klen);
    memcpy(buf + *off, value, vlen);
    *off = (uint16_t)(*off + vlen);
    return 0;
}

static int wolftftp_build_request(uint8_t *buf, uint16_t max_len, uint16_t opcode,
    const char *filename, const struct wolftftp_transfer_cfg *cfg, uint32_t tsize,
    uint8_t *requested_opts, uint16_t *out_len)
{
    uint16_t off = 0;
    char value[16];
    int ret;
    size_t name_len;

    if (buf == NULL || filename == NULL || cfg == NULL || requested_opts == NULL ||
            out_len == NULL)
        return -WOLFIP_EINVAL;

    name_len = wolftftp_strnlen_local(filename, WOLFTFTP_MAX_FILENAME);
    if (name_len == 0 || name_len >= WOLFTFTP_MAX_FILENAME)
        return -WOLFIP_EINVAL;
    if (max_len < (uint16_t)(4U + name_len + 6U))
        return WOLFTFTP_ERR_PACKET;

    wolftftp_write_u16(buf, opcode);
    off = 2;
    memcpy(buf + off, filename, name_len + 1U);
    off = (uint16_t)(off + name_len + 1U);
    memcpy(buf + off, "octet", 6);
    off = (uint16_t)(off + 6U);
    *requested_opts = 0;

    if (cfg->blksize != WOLFTFTP_DEFAULT_BLKSIZE) {
        (void)snprintf(value, sizeof(value), "%u", cfg->blksize);
        ret = wolftftp_append_opt(buf, &off, max_len, "blksize", value);
        if (ret != 0)
            return ret;
        *requested_opts |= WOLFTFTP_OPT_BLKSIZE;
    }
    if (cfg->timeout_s != WOLFTFTP_DEFAULT_TIMEOUT_S) {
        (void)snprintf(value, sizeof(value), "%u", cfg->timeout_s);
        ret = wolftftp_append_opt(buf, &off, max_len, "timeout", value);
        if (ret != 0)
            return ret;
        *requested_opts |= WOLFTFTP_OPT_TIMEOUT;
    }
    if (cfg->windowsize > 1U) {
        (void)snprintf(value, sizeof(value), "%u", cfg->windowsize);
        ret = wolftftp_append_opt(buf, &off, max_len, "windowsize", value);
        if (ret != 0)
            return ret;
        *requested_opts |= WOLFTFTP_OPT_WINDOWSIZE;
    }
    if (tsize != 0U || cfg->max_image_size != 0U) {
        (void)snprintf(value, sizeof(value), "%lu", (unsigned long)tsize);
        ret = wolftftp_append_opt(buf, &off, max_len, "tsize", value);
        if (ret != 0)
            return ret;
        *requested_opts |= WOLFTFTP_OPT_TSIZE;
    }

    *out_len = off;
    return 0;
}

/* Reject filenames that could escape the integrator's namespace: any absolute
 * path (leading '/' or '\', or a Windows drive specifier like "C:\...") and any
 * ".." path component. The library hands the name straight to io.open(), and
 * TFTP is unauthenticated, so a naive filesystem-backed open() would otherwise
 * be exposed to traversal. The check is component-aware: a ".." segment between
 * separators (or as the whole name) is rejected, but dots inside a name
 * ("fw..bin") are fine. */
static int wolftftp_filename_is_safe(const char *name)
{
    const char *seg = name;
    const char *c;

    if (name[0] == '\0')
        return 0;
    if (name[0] == '/' || name[0] == '\\')
        return 0;
    /* ':' is never valid in a portable filename; on Windows it introduces a
     * drive specifier ("C:\windows", "C:foo") or an NTFS alternate data stream
     * ("name:stream"), either of which would sidestep the leading-separator
     * check above. Reject it wherever it appears. */
    for (c = name; *c != '\0'; c++) {
        if (*c == ':')
            return 0;
    }
    for (c = name; ; c++) {
        if (*c == '/' || *c == '\\' || *c == '\0') {
            size_t seglen = (size_t)(c - seg);
            if (seglen == 2U && seg[0] == '.' && seg[1] == '.')
                return 0;
            if (*c == '\0')
                break;
            seg = c + 1;
        }
    }
    return 1;
}

static int wolftftp_parse_request(const uint8_t *buf, uint16_t len,
    struct wolftftp_parsed_req *req)
{
    const char *p;
    size_t slen;
    const char *key;
    const char *value;
    uint32_t number;

    if (buf == NULL || req == NULL || len < 4)
        return WOLFTFTP_ERR_PACKET;
    memset(req, 0, sizeof(*req));
    req->opcode = wolftftp_read_u16(buf);
    if (req->opcode != WOLFTFTP_OP_RRQ && req->opcode != WOLFTFTP_OP_WRQ)
        return WOLFTFTP_ERR_PACKET;

    p = (const char *)(buf + 2);
    slen = wolftftp_strnlen_local(p, len - 2U);
    if (slen == 0 || slen >= WOLFTFTP_MAX_FILENAME || (uint16_t)(2U + slen) >= len)
        return WOLFTFTP_ERR_PACKET;
    memcpy(req->filename, p, slen);
    req->filename[slen] = '\0';
    if (!wolftftp_filename_is_safe(req->filename))
        return WOLFTFTP_ERR_PACKET;
    p += slen + 1U;
    slen = wolftftp_strnlen_local(p, (size_t)(buf + len - (const uint8_t *)p));
    if (slen == 0 || (const uint8_t *)(p + slen) >= buf + len ||
            wolftftp_stricmp_local(p, "octet") != 0)
        return WOLFTFTP_ERR_UNSUPPORTED;
    p += slen + 1U;

    while ((const uint8_t *)p < buf + len) {
        key = p;
        slen = wolftftp_strnlen_local(key,
            (size_t)(buf + len - (const uint8_t *)key));
        if (slen == 0 || (const uint8_t *)(key + slen) >= buf + len)
            return WOLFTFTP_ERR_PACKET;
        value = key + slen + 1U;
        slen = wolftftp_strnlen_local(value,
            (size_t)(buf + len - (const uint8_t *)value));
        /* Same `>=` check as the key side: when strnlen_local saturates
         * to max_len there is no NUL inside the buffer, so passing the
         * unterminated value through to parse_u32 / stricmp would walk
         * past buf+len. */
        if (slen == 0 || (const uint8_t *)(value + slen) >= buf + len)
            return WOLFTFTP_ERR_PACKET;
        if (wolftftp_stricmp_local(key, "blksize") == 0) {
            if (wolftftp_parse_u32(value, WOLFTFTP_MAX_BLKSIZE, &number) != 0 ||
                    number < 8U)
                return WOLFTFTP_ERR_UNSUPPORTED;
            req->blksize = (uint16_t)number;
            req->opts |= WOLFTFTP_OPT_BLKSIZE;
        } else if (wolftftp_stricmp_local(key, "timeout") == 0) {
            if (wolftftp_parse_u32(value, 255U, &number) != 0 || number == 0U)
                return WOLFTFTP_ERR_UNSUPPORTED;
            req->timeout_s = (uint16_t)number;
            req->opts |= WOLFTFTP_OPT_TIMEOUT;
        } else if (wolftftp_stricmp_local(key, "tsize") == 0) {
            if (wolftftp_parse_u32(value, 0xFFFFFFFFUL, &number) != 0)
                return WOLFTFTP_ERR_UNSUPPORTED;
            req->tsize = number;
            req->opts |= WOLFTFTP_OPT_TSIZE;
        } else if (wolftftp_stricmp_local(key, "windowsize") == 0) {
            if (wolftftp_parse_u32(value, WOLFTFTP_MAX_WINDOWSIZE, &number) != 0 ||
                    number == 0U)
                return WOLFTFTP_ERR_UNSUPPORTED;
            req->windowsize = (uint16_t)number;
            req->opts |= WOLFTFTP_OPT_WINDOWSIZE;
        } else {
            return WOLFTFTP_ERR_UNSUPPORTED;
        }
        p = value + slen + 1U;
    }

    return 0;
}

static int wolftftp_build_ack(uint8_t *buf, uint16_t block)
{
    wolftftp_write_u16(buf, WOLFTFTP_OP_ACK);
    wolftftp_write_u16(buf + 2, block);
    return 4;
}

static int wolftftp_build_error(uint8_t *buf, uint16_t max_len, uint16_t code,
    const char *msg)
{
    size_t mlen;

    if (buf == NULL || msg == NULL || max_len < 5)
        return WOLFTFTP_ERR_PACKET;
    mlen = strlen(msg) + 1U;
    if ((uint32_t)mlen + 4U > max_len)
        return WOLFTFTP_ERR_PACKET;
    wolftftp_write_u16(buf, WOLFTFTP_OP_ERROR);
    wolftftp_write_u16(buf + 2, code);
    memcpy(buf + 4, msg, mlen);
    return (int)(4U + mlen);
}

static int wolftftp_build_data(uint8_t *buf, uint16_t max_len, uint16_t block,
    const uint8_t *data, uint16_t data_len)
{
    if (buf == NULL || data == NULL || max_len < (uint16_t)(4U + data_len))
        return WOLFTFTP_ERR_PACKET;
    wolftftp_write_u16(buf, WOLFTFTP_OP_DATA);
    wolftftp_write_u16(buf + 2, block);
    if (data_len > 0)
        memcpy(buf + 4, data, data_len);
    return (int)(4U + data_len);
}

static int wolftftp_build_oack(uint8_t *buf, uint16_t max_len,
    const struct wolftftp_negotiated *neg, uint8_t opts)
{
    uint16_t off = 2;
    char value[16];
    int ret;

    if (buf == NULL || neg == NULL)
        return -WOLFIP_EINVAL;
    wolftftp_write_u16(buf, WOLFTFTP_OP_OACK);
    if ((opts & WOLFTFTP_OPT_BLKSIZE) != 0U) {
        (void)snprintf(value, sizeof(value), "%u", neg->blksize);
        ret = wolftftp_append_opt(buf, &off, max_len, "blksize", value);
        if (ret != 0)
            return ret;
    }
    if ((opts & WOLFTFTP_OPT_TIMEOUT) != 0U) {
        (void)snprintf(value, sizeof(value), "%u", neg->timeout_s);
        ret = wolftftp_append_opt(buf, &off, max_len, "timeout", value);
        if (ret != 0)
            return ret;
    }
    if ((opts & WOLFTFTP_OPT_TSIZE) != 0U) {
        (void)snprintf(value, sizeof(value), "%lu", (unsigned long)neg->tsize);
        ret = wolftftp_append_opt(buf, &off, max_len, "tsize", value);
        if (ret != 0)
            return ret;
    }
    if ((opts & WOLFTFTP_OPT_WINDOWSIZE) != 0U) {
        (void)snprintf(value, sizeof(value), "%u", neg->windowsize);
        ret = wolftftp_append_opt(buf, &off, max_len, "windowsize", value);
        if (ret != 0)
            return ret;
    }
    return off;
}

static int wolftftp_parse_oack(const uint8_t *buf, uint16_t len,
    struct wolftftp_negotiated *neg, uint8_t requested_opts)
{
    const char *p;
    size_t slen;
    const char *key;
    const char *value;
    uint32_t number;

    if (buf == NULL || neg == NULL || len < 2)
        return WOLFTFTP_ERR_PACKET;
    if (wolftftp_read_u16(buf) != WOLFTFTP_OP_OACK)
        return WOLFTFTP_ERR_PACKET;
    p = (const char *)(buf + 2);
    while ((const uint8_t *)p < buf + len) {
        key = p;
        slen = wolftftp_strnlen_local(key,
            (size_t)(buf + len - (const uint8_t *)key));
        if (slen == 0 || (const uint8_t *)(key + slen) >= buf + len)
            return WOLFTFTP_ERR_PACKET;
        value = key + slen + 1U;
        slen = wolftftp_strnlen_local(value,
            (size_t)(buf + len - (const uint8_t *)value));
        /* Same `>=` check as the key side: when strnlen_local saturates
         * to max_len there is no NUL inside the buffer, so passing the
         * unterminated value through to parse_u32 / stricmp would walk
         * past buf+len. */
        if (slen == 0 || (const uint8_t *)(value + slen) >= buf + len)
            return WOLFTFTP_ERR_PACKET;
        /* RFC 2347 §2: an OACK may only acknowledge options the client
         * actually sent. Reject any option absent from requested_opts so a
         * malicious server cannot install unsolicited timeout/windowsize/
         * tsize values that were never negotiated. */
        if (wolftftp_stricmp_local(key, "blksize") == 0) {
            if ((requested_opts & WOLFTFTP_OPT_BLKSIZE) == 0U)
                return WOLFTFTP_ERR_UNSUPPORTED;
            if (wolftftp_parse_u32(value, WOLFTFTP_MAX_BLKSIZE, &number) != 0 ||
                    number < 8U)
                return WOLFTFTP_ERR_UNSUPPORTED;
            neg->blksize = (uint16_t)number;
        } else if (wolftftp_stricmp_local(key, "timeout") == 0) {
            if ((requested_opts & WOLFTFTP_OPT_TIMEOUT) == 0U)
                return WOLFTFTP_ERR_UNSUPPORTED;
            if (wolftftp_parse_u32(value, 255U, &number) != 0 || number == 0U)
                return WOLFTFTP_ERR_UNSUPPORTED;
            neg->timeout_s = (uint16_t)number;
        } else if (wolftftp_stricmp_local(key, "tsize") == 0) {
            if ((requested_opts & WOLFTFTP_OPT_TSIZE) == 0U)
                return WOLFTFTP_ERR_UNSUPPORTED;
            if (wolftftp_parse_u32(value, 0xFFFFFFFFUL, &number) != 0)
                return WOLFTFTP_ERR_UNSUPPORTED;
            neg->tsize = number;
            neg->have_tsize = 1;
        } else if (wolftftp_stricmp_local(key, "windowsize") == 0) {
            if ((requested_opts & WOLFTFTP_OPT_WINDOWSIZE) == 0U)
                return WOLFTFTP_ERR_UNSUPPORTED;
            if (wolftftp_parse_u32(value, WOLFTFTP_MAX_WINDOWSIZE, &number) != 0 ||
                    number == 0U)
                return WOLFTFTP_ERR_UNSUPPORTED;
            neg->windowsize = (uint16_t)number;
        } else {
            return WOLFTFTP_ERR_UNSUPPORTED;
        }
        p = value + slen + 1U;
    }
    return 0;
}

static int wolftftp_parse_data(const uint8_t *buf, uint16_t len,
    struct wolftftp_parsed_data *data)
{
    if (buf == NULL || data == NULL || len < 4)
        return WOLFTFTP_ERR_PACKET;
    if (wolftftp_read_u16(buf) != WOLFTFTP_OP_DATA)
        return WOLFTFTP_ERR_PACKET;
    data->block = wolftftp_read_u16(buf + 2);
    data->data = buf + 4;
    data->data_len = (uint16_t)(len - 4U);
    return 0;
}

static int wolftftp_packet_opcode(const uint8_t *buf, uint16_t len)
{
    if (buf == NULL || len < 2)
        return -1;
    return wolftftp_read_u16(buf);
}

static uint32_t wolftftp_deadline(const struct wolftftp_negotiated *neg,
    uint32_t now_ms)
{
    uint32_t d = now_ms + ((uint32_t)neg->timeout_s * 1000U);
    /* 0 is reserved as the "not armed" sentinel; nudge past it. */
    if (d == 0U)
        d = 1U;
    return d;
}

static int wolftftp_send_client_error(struct wolftftp_client *client,
    const struct wolftftp_endpoint *remote, uint16_t code, const char *msg)
{
    int len;
    uint8_t buf[64];

    len = wolftftp_build_error(buf, sizeof(buf), code, msg);
    if (len < 0)
        return len;
    return wolftftp_send(&client->transport, client->cfg.local_port, remote, buf,
        (uint16_t)len);
}

static int wolftftp_send_server_error(struct wolftftp_server *server,
    uint16_t local_port, const struct wolftftp_endpoint *remote, uint16_t code,
    const char *msg)
{
    int len;
    uint8_t buf[64];

    len = wolftftp_build_error(buf, sizeof(buf), code, msg);
    if (len < 0)
        return len;
    return wolftftp_send(&server->transport, local_port, remote, buf, (uint16_t)len);
}

void wolftftp_client_init(struct wolftftp_client *client,
    const struct wolftftp_transport_ops *transport,
    const struct wolftftp_io_ops *io,
    const struct wolftftp_transfer_cfg *cfg)
{
    memset(client, 0, sizeof(*client));
    if (transport != NULL)
        client->transport = *transport;
    if (io != NULL)
        client->io = *io;
    if (cfg != NULL)
        client->cfg = *cfg;
    wolftftp_cfg_defaults(&client->cfg);
    wolftftp_neg_defaults(&client->neg, &client->cfg);
    client->state = WOLFTFTP_CLIENT_IDLE;
}

static int wolftftp_client_open_sink(struct wolftftp_client *client)
{
    uint32_t size_hint = client->advertised_size;

    if (client->io.open == NULL || client->io.write == NULL)
        return WOLFTFTP_ERR_IO;
    return client->io.open(client->io.arg, client->filename, 1, &size_hint,
        &client->handle);
}

int wolftftp_client_start_rrq(struct wolftftp_client *client,
    const struct wolftftp_endpoint *server, const char *filename)
{
    int ret;

    if (client == NULL || server == NULL)
        return -WOLFIP_EINVAL;
    if (client->state != WOLFTFTP_CLIENT_IDLE && client->state != WOLFTFTP_CLIENT_COMPLETE &&
            client->state != WOLFTFTP_CLIENT_ERROR)
        return WOLFTFTP_ERR_STATE;
    ret = wolftftp_copy_string(client->filename, sizeof(client->filename), filename);
    if (ret != 0)
        return ret;
    client->server = *server;
    if (client->server.port == 0U)
        client->server.port = WOLFTFTP_PORT;
    client->tid_locked = 0;
    client->expected_block = 1;
    client->last_acked_block = 0;
    client->window_count = 0;
    client->next_offset = 0;
    client->total_size = 0;
    client->advertised_size = 0;
    client->final_seen = 0;
    client->handle = NULL;
    client->retries = 0;
    wolftftp_neg_defaults(&client->neg, &client->cfg);
    ret = wolftftp_build_request(client->last_tx, sizeof(client->last_tx),
        WOLFTFTP_OP_RRQ, filename, &client->cfg, 0, &client->requested_opts,
        &client->last_tx_len);
    if (ret != 0)
        return ret;
    ret = wolftftp_send(&client->transport, client->cfg.local_port, &client->server,
        client->last_tx, client->last_tx_len);
    if (ret != 0)
        return ret;
    client->request_sent = 1;
    client->state = WOLFTFTP_CLIENT_WAIT_FIRST;
    client->last_status = 0;
    client->deadline_ms = 0;
    return 0;
}

static int wolftftp_client_accept_data(struct wolftftp_client *client,
    const struct wolftftp_parsed_data *data)
{
    int ret;

    if (data->block == client->expected_block) {
        if (client->total_size > (uint32_t)(UINT32_MAX - data->data_len) ||
                (client->cfg.max_image_size != 0U &&
                data->data_len > client->cfg.max_image_size - client->total_size)) {
            (void)wolftftp_send_client_error(client, &client->server,
                WOLFTFTP_ENOSPACE, "image too large");
            wolftftp_client_finish(client, WOLFTFTP_ERR_SIZE);
            return WOLFTFTP_ERR_SIZE;
        }
        if (client->handle == NULL) {
            ret = wolftftp_client_open_sink(client);
            if (ret != 0) {
                (void)wolftftp_send_client_error(client, &client->server,
                    WOLFTFTP_EACCESS, "open failed");
                wolftftp_client_finish(client, WOLFTFTP_ERR_IO);
                return WOLFTFTP_ERR_IO;
            }
        }
        ret = client->io.write(client->io.arg, client->handle, client->next_offset,
            data->data, data->data_len);
        if (ret != 0) {
            (void)wolftftp_send_client_error(client, &client->server,
                WOLFTFTP_EACCESS, "write failed");
            wolftftp_client_finish(client, WOLFTFTP_ERR_IO);
            return WOLFTFTP_ERR_IO;
        }
        if (client->io.hash_update != NULL && data->data_len > 0) {
            ret = client->io.hash_update(client->io.arg, client->handle, data->data,
                data->data_len);
            if (ret != 0) {
                (void)wolftftp_send_client_error(client, &client->server,
                    WOLFTFTP_EUNDEF, "hash failed");
                wolftftp_client_finish(client, WOLFTFTP_ERR_VERIFY);
                return WOLFTFTP_ERR_VERIFY;
            }
        }
        client->next_offset += data->data_len;
        client->total_size += data->data_len;
        client->expected_block++;
        client->window_count++;
        client->final_seen = (uint8_t)(data->data_len < client->neg.blksize);
        if (client->window_count >= client->neg.windowsize || client->final_seen) {
            client->last_tx_len = (uint16_t)wolftftp_build_ack(client->last_tx,
                data->block);
            ret = wolftftp_send(&client->transport, client->cfg.local_port,
                &client->server, client->last_tx, client->last_tx_len);
            if (ret != 0)
                return ret;
            client->last_acked_block = data->block;
            client->window_count = 0;
        }
        if (client->final_seen != 0U) {
            if (client->io.verify != NULL) {
                ret = client->io.verify(client->io.arg, client->handle,
                    client->total_size);
                if (ret != 0) {
                    wolftftp_client_finish(client, WOLFTFTP_ERR_VERIFY);
                    return WOLFTFTP_ERR_VERIFY;
                }
            }
            wolftftp_client_finish(client, 0);
        } else {
            client->state = WOLFTFTP_CLIENT_RECV_DATA;
        }
        return 0;
    }
    if (data->block == client->last_acked_block || data->block == (uint16_t)(client->expected_block - 1U)) {
        if (client->last_tx_len != 0U) {
            return wolftftp_send(&client->transport, client->cfg.local_port,
                &client->server, client->last_tx, client->last_tx_len);
        }
        return 0;
    }
    return 0;
}

int wolftftp_client_receive(struct wolftftp_client *client, uint16_t local_port,
    const struct wolftftp_endpoint *remote, const uint8_t *buf, uint16_t len)
{
    int opcode;
    struct wolftftp_parsed_data data;
    struct wolftftp_negotiated neg;
    int ret;

    if (client == NULL || remote == NULL || buf == NULL)
        return -WOLFIP_EINVAL;
    if (local_port != client->cfg.local_port)
        return 0;
    if (client->state != WOLFTFTP_CLIENT_WAIT_FIRST &&
            client->state != WOLFTFTP_CLIENT_RECV_DATA)
        return WOLFTFTP_ERR_STATE;
    if (remote->ip != client->server.ip)
        return 0;
    if (client->tid_locked != 0U && remote->port != client->server.port) {
        (void)wolftftp_send_client_error(client, remote, WOLFTFTP_EBADTID,
            "unknown tid");
        return WOLFTFTP_ERR_TID;
    }

    opcode = wolftftp_packet_opcode(buf, len);
    if (opcode == WOLFTFTP_OP_OACK) {
        client->server.port = remote->port;
        client->tid_locked = 1;
        wolftftp_neg_defaults(&neg, &client->cfg);
        ret = wolftftp_parse_oack(buf, len, &neg, client->requested_opts);
        if (ret != 0) {
            wolftftp_client_finish(client, ret);
            return ret;
        }
        if (neg.have_tsize != 0U) {
            client->advertised_size = neg.tsize;
            if (client->cfg.max_image_size != 0U && neg.tsize > client->cfg.max_image_size) {
                (void)wolftftp_send_client_error(client, &client->server,
                    WOLFTFTP_ENOSPACE, "image too large");
                wolftftp_client_finish(client, WOLFTFTP_ERR_SIZE);
                return WOLFTFTP_ERR_SIZE;
            }
        }
        client->neg = neg;
        client->last_tx_len = (uint16_t)wolftftp_build_ack(client->last_tx, 0);
        ret = wolftftp_send(&client->transport, client->cfg.local_port, &client->server,
            client->last_tx, client->last_tx_len);
        if (ret != 0)
            return ret;
        client->last_acked_block = 0;
        client->state = WOLFTFTP_CLIENT_RECV_DATA;
        client->deadline_ms = 0;
        client->retries = 0;
        return 0;
    }
    if (opcode == WOLFTFTP_OP_ERROR) {
        wolftftp_client_finish(client, WOLFTFTP_ERR_IO);
        return WOLFTFTP_ERR_IO;
    }
    if (opcode != WOLFTFTP_OP_DATA)
        return WOLFTFTP_ERR_PACKET;

    ret = wolftftp_parse_data(buf, len, &data);
    if (ret != 0)
        return ret;

    if (client->tid_locked == 0U) {
        client->server.port = remote->port;
        client->tid_locked = 1;
    } else if (remote->port != client->server.port) {
        (void)wolftftp_send_client_error(client, remote, WOLFTFTP_EBADTID,
            "unknown tid");
        return WOLFTFTP_ERR_TID;
    }
    if (client->state == WOLFTFTP_CLIENT_WAIT_FIRST) {
        wolftftp_neg_defaults(&client->neg, &client->cfg);
        client->advertised_size = 0;
        client->state = WOLFTFTP_CLIENT_RECV_DATA;
    }
    client->deadline_ms = 0;
    client->retries = 0;
    return wolftftp_client_accept_data(client, &data);
}

int wolftftp_client_poll(struct wolftftp_client *client, uint32_t now_ms)
{
    int ret;

    if (client == NULL)
        return -WOLFIP_EINVAL;
    if (client->state != WOLFTFTP_CLIENT_WAIT_FIRST &&
            client->state != WOLFTFTP_CLIENT_RECV_DATA)
        return 0;
    if (client->last_tx_len == 0U)
        return 0;
    if (client->deadline_ms == 0U) {
        client->deadline_ms = wolftftp_deadline(&client->neg, now_ms);
        return 0;
    }
    if (client->deadline_ms != 0U &&
            (int32_t)(now_ms - client->deadline_ms) < 0)
        return 0;
    if (client->retries >= client->cfg.max_retries) {
        wolftftp_client_finish(client, WOLFTFTP_ERR_TIMEOUT);
        return WOLFTFTP_ERR_TIMEOUT;
    }
    ret = wolftftp_send(&client->transport, client->cfg.local_port, &client->server,
        client->last_tx, client->last_tx_len);
    if (ret == 0)
        client->retries++;
    client->deadline_ms = wolftftp_deadline(&client->neg, now_ms);
    return ret;
}

int wolftftp_client_status(const struct wolftftp_client *client)
{
    if (client == NULL)
        return -WOLFIP_EINVAL;
    return client->last_status;
}

void wolftftp_server_init(struct wolftftp_server *server,
    const struct wolftftp_transport_ops *transport,
    const struct wolftftp_io_ops *io,
    const struct wolftftp_transfer_cfg *cfg)
{
    memset(server, 0, sizeof(*server));
    if (transport != NULL)
        server->transport = *transport;
    if (io != NULL)
        server->io = *io;
    if (cfg != NULL)
        server->cfg = *cfg;
    wolftftp_cfg_defaults(&server->cfg);
    server->listen_port = WOLFTFTP_PORT;
    server->transfer_port_base = WOLFTFTP_SERVER_PORT_BASE;
}

static struct wolftftp_server_session *wolftftp_server_find_session(
    struct wolftftp_server *server, uint16_t local_port,
    const struct wolftftp_endpoint *remote)
{
    unsigned int i;

    for (i = 0; i < WOLFTFTP_SERVER_MAX_SESSIONS; i++) {
        if (server->sessions[i].state != WOLFTFTP_SESSION_FREE &&
                server->sessions[i].local_port == local_port &&
                server->sessions[i].remote.ip == remote->ip &&
                server->sessions[i].remote.port == remote->port) {
            return &server->sessions[i];
        }
    }
    return NULL;
}

static struct wolftftp_server_session *wolftftp_server_find_by_remote(
    struct wolftftp_server *server, const struct wolftftp_endpoint *remote)
{
    unsigned int i;

    for (i = 0; i < WOLFTFTP_SERVER_MAX_SESSIONS; i++) {
        if (server->sessions[i].state != WOLFTFTP_SESSION_FREE &&
                server->sessions[i].remote.ip == remote->ip &&
                server->sessions[i].remote.port == remote->port) {
            return &server->sessions[i];
        }
    }
    return NULL;
}

static struct wolftftp_server_session *wolftftp_server_alloc_session(
    struct wolftftp_server *server)
{
    unsigned int i;

    for (i = 0; i < WOLFTFTP_SERVER_MAX_SESSIONS; i++) {
        if (server->sessions[i].state == WOLFTFTP_SESSION_FREE) {
            memset(&server->sessions[i], 0, sizeof(server->sessions[i]));
            server->sessions[i].local_port = (uint16_t)(server->transfer_port_base + i);
            return &server->sessions[i];
        }
    }
    return NULL;
}

static int wolftftp_server_send_last(struct wolftftp_server *server,
    struct wolftftp_server_session *session, const uint8_t *buf, uint16_t len)
{
    return wolftftp_send(&server->transport, session->local_port, &session->remote,
        buf, len);
}

static int wolftftp_server_send_window(struct wolftftp_server *server,
    struct wolftftp_server_session *session)
{
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t out_len;
    int is_last;
    int ret;
    uint16_t i;
    uint16_t data_len;

    if (server->io.read == NULL)
        return WOLFTFTP_ERR_IO;
    /* Snapshot the pre-send state so a retransmit can replay the same
     * window instead of advancing into already-sent-but-unacked blocks. */
    session->window_start_offset = session->next_offset;
    session->window_start_total = session->total_size;
    session->window_start_block = session->next_block;
    session->window_start_final = session->final_seen;
    for (i = 0; i < session->neg.windowsize; i++) {
        out_len = 0;
        is_last = 0;
        ret = server->io.read(server->io.arg, session->handle, session->next_offset,
            pkt + 4, session->neg.blksize, &out_len, &is_last);
        if (ret != 0)
            return WOLFTFTP_ERR_IO;
        data_len = out_len;
        /* Refuse to advance past the configured limit or wrap the
         * uint32_t offset/total accumulators. io.read takes a uint32_t
         * offset, so a transfer beyond 4 GiB would silently wrap and
         * re-read near-start data; terminate instead. Mirrors the WRQ
         * per-DATA guard in wolftftp_server_accept_wrq_data. */
        if (session->total_size > (uint32_t)(UINT32_MAX - data_len) ||
                (server->cfg.max_image_size != 0U &&
                data_len > server->cfg.max_image_size - session->total_size)) {
            (void)wolftftp_send_server_error(server, session->local_port,
                &session->remote, WOLFTFTP_ENOSPACE, "image too large");
            wolftftp_server_finish(server, session, WOLFTFTP_ERR_SIZE);
            return WOLFTFTP_ERR_SIZE;
        }
        ret = wolftftp_build_data(pkt, sizeof(pkt), session->next_block, pkt + 4,
            data_len);
        if (ret < 0)
            return ret;
        ret = wolftftp_server_send_last(server, session, pkt, (uint16_t)ret);
        if (ret != 0)
            return ret;
        session->next_offset += data_len;
        session->total_size += data_len;
        session->window_count++;
        session->next_block++;
        if (data_len < session->neg.blksize) {
            /* A short (possibly 0-byte) DATA is the EOF marker per
             * RFC 1350. */
            session->final_seen = 1;
            break;
        }
        if (is_last != 0) {
            /* Reader claims no more bytes but the last read filled an
             * entire block; we still owe the peer an explicit 0-byte
             * DATA so EOF is unambiguous. Break the window now so the
             * next ACK triggers another send_window that picks up the
             * trailing short/empty read and finalizes the transfer. */
            break;
        }
    }
    session->state = WOLFTFTP_SESSION_SEND_WAIT_ACK;
    return 0;
}

static int wolftftp_server_start_request(struct wolftftp_server *server,
    const struct wolftftp_endpoint *remote, const struct wolftftp_parsed_req *req)
{
    struct wolftftp_server_session *session;
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    int ret;
    uint32_t size_hint;

    session = wolftftp_server_alloc_session(server);
    if (session == NULL)
        return wolftftp_send_server_error(server, server->listen_port, remote,
            WOLFTFTP_EUNDEF, "no slots");

    session->remote = *remote;
    session->is_write = (uint8_t)(req->opcode == WOLFTFTP_OP_WRQ);
    session->state = session->is_write ? WOLFTFTP_SESSION_RECV_DATA :
        WOLFTFTP_SESSION_SEND_WAIT_ACK;
    session->next_block = 1;
    session->last_acked_block = 0;
    wolftftp_neg_defaults(&session->neg, &server->cfg);
    if ((req->opts & WOLFTFTP_OPT_BLKSIZE) != 0U)
        session->neg.blksize = req->blksize;
    if ((req->opts & WOLFTFTP_OPT_TIMEOUT) != 0U)
        session->neg.timeout_s = req->timeout_s;
    if ((req->opts & WOLFTFTP_OPT_WINDOWSIZE) != 0U)
        session->neg.windowsize = req->windowsize;
    session->neg.have_tsize = (uint8_t)((req->opts & WOLFTFTP_OPT_TSIZE) != 0U);
    session->neg.tsize = req->tsize;
    /* Reject an advertised tsize that already exceeds the configured limit
     * before io.open is handed the hint, so a single WRQ cannot force a
     * 4 GiB pre-allocation. This mirrors the client OACK check and the
     * later per-DATA enforcement in wolftftp_server_accept_wrq_data. */
    if (session->neg.have_tsize != 0U && server->cfg.max_image_size != 0U &&
            session->neg.tsize > server->cfg.max_image_size) {
        (void)wolftftp_send_server_error(server, session->local_port, remote,
            WOLFTFTP_ENOSPACE, "image too large");
        wolftftp_server_finish(server, session, WOLFTFTP_ERR_SIZE);
        return WOLFTFTP_ERR_SIZE;
    }
    (void)wolftftp_copy_string(session->filename, sizeof(session->filename),
        req->filename);

    if (server->io.open == NULL ||
            (!session->is_write && server->io.read == NULL) ||
            (session->is_write && server->io.write == NULL)) {
        memset(session, 0, sizeof(*session));
        return wolftftp_send_server_error(server, server->listen_port, remote,
            WOLFTFTP_EACCESS, "io unavailable");
    }
    size_hint = session->neg.have_tsize != 0U ? session->neg.tsize : 0U;
    ret = server->io.open(server->io.arg, req->filename, session->is_write,
        &size_hint, &session->handle);
    if (ret != 0) {
        memset(session, 0, sizeof(*session));
        return wolftftp_send_server_error(server, server->listen_port, remote,
            WOLFTFTP_ENOTFOUND, "open failed");
    }
    if (!session->is_write) {
        session->file_size = size_hint;
        if ((req->opts & WOLFTFTP_OPT_TSIZE) != 0U) {
            session->neg.have_tsize = 1;
            session->neg.tsize = size_hint;
        }
    }
    if (req->opts != 0U) {
        ret = wolftftp_build_oack(pkt, sizeof(pkt), &session->neg, req->opts);
        if (ret < 0) {
            wolftftp_server_finish(server, session, ret);
            return ret;
        }
        session->options_sent = 1;
        /* Remember which options the OACK actually carried so the
         * timeout retransmit can rebuild the same OACK byte-for-byte
         * if it gets lost in flight. */
        session->oack_opts = req->opts;
        ret = wolftftp_server_send_last(server, session, pkt, (uint16_t)ret);
        if (ret == 0)
            session->deadline_ms = 0;
        return ret;
    }
    if (session->is_write) {
        ret = wolftftp_build_ack(pkt, 0);
        if (ret < 0) {
            wolftftp_server_finish(server, session, ret);
            return ret;
        }
        ret = wolftftp_server_send_last(server, session, pkt, (uint16_t)ret);
        if (ret == 0)
            session->deadline_ms = 0;
        return ret;
    }
    ret = wolftftp_server_send_window(server, session);
    if (ret == 0)
        session->deadline_ms = 0;
    return ret;
}

static int wolftftp_server_accept_wrq_data(struct wolftftp_server *server,
    struct wolftftp_server_session *session, const struct wolftftp_parsed_data *data)
{
    uint8_t pkt[8];
    int ret;

    if (data->block == session->next_block) {
        /* First DATA block on a WRQ-with-options is the implicit ACK
         * of the OACK; clear options_sent so the timeout path stops
         * trying to replay the OACK now that we have entered the
         * data phase. */
        session->options_sent = 0;
        if (session->total_size > (uint32_t)(UINT32_MAX - data->data_len) ||
                (server->cfg.max_image_size != 0U &&
                data->data_len > server->cfg.max_image_size - session->total_size)) {
            (void)wolftftp_send_server_error(server, session->local_port,
                &session->remote, WOLFTFTP_ENOSPACE, "image too large");
            wolftftp_server_finish(server, session, WOLFTFTP_ERR_SIZE);
            return WOLFTFTP_ERR_SIZE;
        }
        ret = server->io.write(server->io.arg, session->handle, session->next_offset,
            data->data, data->data_len);
        if (ret != 0) {
            wolftftp_server_finish(server, session, WOLFTFTP_ERR_IO);
            return WOLFTFTP_ERR_IO;
        }
        if (server->io.hash_update != NULL && data->data_len > 0) {
            ret = server->io.hash_update(server->io.arg, session->handle, data->data,
                data->data_len);
            if (ret != 0) {
                wolftftp_server_finish(server, session, WOLFTFTP_ERR_VERIFY);
                return WOLFTFTP_ERR_VERIFY;
            }
        }
        session->next_offset += data->data_len;
        session->total_size += data->data_len;
        session->window_count++;
        session->next_block++;
        session->final_seen = (uint8_t)(data->data_len < session->neg.blksize);
        if (session->window_count >= session->neg.windowsize || session->final_seen != 0U) {
            ret = wolftftp_build_ack(pkt, data->block);
            if (ret < 0)
                return ret;
            ret = wolftftp_server_send_last(server, session, pkt, (uint16_t)ret);
            if (ret != 0)
                return ret;
            session->last_acked_block = data->block;
            session->window_count = 0;
            session->deadline_ms = 0;
            session->retries = 0;
        }
        if (session->final_seen != 0U) {
            if (server->io.verify != NULL) {
                ret = server->io.verify(server->io.arg, session->handle,
                    session->total_size);
                if (ret != 0) {
                    wolftftp_server_finish(server, session, WOLFTFTP_ERR_VERIFY);
                    return WOLFTFTP_ERR_VERIFY;
                }
            }
            wolftftp_server_finish(server, session, 0);
        }
        return 0;
    }
    if (data->block == session->last_acked_block || data->block == (uint16_t)(session->next_block - 1U)) {
        ret = wolftftp_build_ack(pkt, data->block);
        if (ret < 0)
            return ret;
        return wolftftp_server_send_last(server, session, pkt, (uint16_t)ret);
    }
    return 0;
}

int wolftftp_server_receive(struct wolftftp_server *server, uint16_t local_port,
    const struct wolftftp_endpoint *remote, const uint8_t *buf, uint16_t len)
{
    struct wolftftp_server_session *session;
    struct wolftftp_parsed_req req;
    struct wolftftp_parsed_data data;
    int opcode;
    int ret;

    if (server == NULL || remote == NULL || buf == NULL)
        return -WOLFIP_EINVAL;
    opcode = wolftftp_packet_opcode(buf, len);
    if (local_port == server->listen_port) {
        ret = wolftftp_parse_request(buf, len, &req);
        if (ret == WOLFTFTP_ERR_UNSUPPORTED) {
            return wolftftp_send_server_error(server, server->listen_port, remote,
                WOLFTFTP_EBADOPT, "unsupported");
        }
        if (ret != 0)
            return wolftftp_send_server_error(server, server->listen_port, remote,
                WOLFTFTP_EBADOP, "bad request");
        /* A retransmitted request (the client has not yet seen our reply)
         * lands back on the listen port while a session for the same remote
         * endpoint is already active. Coalesce it onto that session instead
         * of allocating a fresh slot, so a single source cannot pin the whole
         * pool and a lossy client's retries do not leak slots. The in-progress
         * session's poll-driven retransmit redelivers the pending reply. */
        if (wolftftp_server_find_by_remote(server, remote) != NULL)
            return 0;
        return wolftftp_server_start_request(server, remote, &req);
    }

    session = wolftftp_server_find_session(server, local_port, remote);
    if (session == NULL) {
        return wolftftp_send_server_error(server, local_port, remote,
            WOLFTFTP_EBADTID, "unknown tid");
    }
    if (session->is_write != 0U) {
        if (opcode == WOLFTFTP_OP_ERROR) {
            wolftftp_server_finish(server, session, WOLFTFTP_ERR_IO);
            return WOLFTFTP_ERR_IO;
        }
        ret = wolftftp_parse_data(buf, len, &data);
        if (ret != 0)
            return ret;
        return wolftftp_server_accept_wrq_data(server, session, &data);
    }

    if (opcode == WOLFTFTP_OP_ERROR) {
        wolftftp_server_finish(server, session, WOLFTFTP_ERR_IO);
        return WOLFTFTP_ERR_IO;
    }
    if (opcode != WOLFTFTP_OP_ACK || len < 4)
        return WOLFTFTP_ERR_PACKET;
    if (wolftftp_read_u16(buf + 2) != session->last_acked_block &&
            wolftftp_read_u16(buf + 2) != (uint16_t)(session->next_block - 1U) &&
            !(session->options_sent != 0U && wolftftp_read_u16(buf + 2) == 0U)) {
        return 0;
    }
    session->last_acked_block = wolftftp_read_u16(buf + 2);
    session->window_count = 0;
    session->options_sent = 0;
    session->deadline_ms = 0;
    session->retries = 0;
    if (session->final_seen != 0U && session->last_acked_block == (uint16_t)(session->next_block - 1U)) {
        wolftftp_server_finish(server, session, 0);
        return 0;
    }
    ret = wolftftp_server_send_window(server, session);
    if (ret == 0)
        session->deadline_ms = 0;
    return ret;
}

int wolftftp_server_poll(struct wolftftp_server *server, uint32_t now_ms)
{
    unsigned int i;
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    int ret;

    if (server == NULL)
        return -WOLFIP_EINVAL;
    for (i = 0; i < WOLFTFTP_SERVER_MAX_SESSIONS; i++) {
        struct wolftftp_server_session *session = &server->sessions[i];
        if (session->state == WOLFTFTP_SESSION_FREE ||
                session->state == WOLFTFTP_SESSION_COMPLETE)
            continue;
        if (session->deadline_ms == 0U) {
            session->deadline_ms = wolftftp_deadline(&session->neg, now_ms);
            continue;
        }
        if ((int32_t)(now_ms - session->deadline_ms) < 0)
            continue;
        if (session->retries >= server->cfg.max_retries) {
            wolftftp_server_finish(server, session, WOLFTFTP_ERR_TIMEOUT);
            continue;
        }
        if (session->options_sent != 0U) {
            /* OACK was the last packet on the wire and has not been
             * acked. RFC 2347: when option negotiation was used the
             * server MUST replay the OACK on timeout — not a bare
             * ACK(0) / ACK(last_acked_block), which the client would
             * either ignore or treat as a fatal "illegal operation"
             * and abort with EBADOP. */
            ret = wolftftp_build_oack(pkt, sizeof(pkt), &session->neg,
                session->oack_opts);
            if (ret > 0) {
                (void)wolftftp_server_send_last(server, session, pkt,
                    (uint16_t)ret);
            }
        } else if (session->is_write != 0U) {
            ret = wolftftp_build_ack(pkt, session->last_acked_block);
            if (ret >= 0) {
                (void)wolftftp_server_send_last(server, session, pkt, (uint16_t)ret);
            }
        } else {
            /* Replay the last unacked window verbatim instead of
             * sending fresh blocks. */
            session->next_offset = session->window_start_offset;
            session->total_size = session->window_start_total;
            session->next_block = session->window_start_block;
            session->final_seen = session->window_start_final;
            (void)wolftftp_server_send_window(server, session);
        }
        session->retries++;
        session->deadline_ms = wolftftp_deadline(&session->neg, now_ms);
    }
    return 0;
}

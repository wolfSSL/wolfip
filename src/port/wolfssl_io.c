/* wolfssl_io.c
 * Copyright (C) 2025 wolfSSL Inc.
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
 * wolfIP <-> wolfSSL glue for custom IO callbacks.
 */
#include "wolfip.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/memory.h>

#define MAX_WOLFIP_CTX 8

struct ctx_entry {
    WOLFSSL_CTX *ctx;
    struct wolfIP *stack;
};

struct wolfip_io_desc {
    int fd;
    struct wolfIP *stack;
};

static struct ctx_entry ctx_map[MAX_WOLFIP_CTX];
static struct wolfip_io_desc io_descs[MAX_WOLFIP_CTX];

static struct wolfIP *wolfIP_lookup_stack(WOLFSSL_CTX *ctx)
{
    for (int i = 0; i < MAX_WOLFIP_CTX; i++) {
        if (ctx_map[i].ctx == ctx)
            return ctx_map[i].stack;
    }
    return NULL;
}

static void wolfIP_register_stack(WOLFSSL_CTX *ctx, struct wolfIP *stack)
{
    for (int i = 0; i < MAX_WOLFIP_CTX; i++) {
        if (ctx_map[i].ctx == ctx || ctx_map[i].ctx == NULL) {
            ctx_map[i].ctx = ctx;
            ctx_map[i].stack = stack;
            return;
        }
    }
}

static int wolfIP_io_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    struct wolfip_io_desc *desc = (struct wolfip_io_desc *)ctx;
    (void)ssl;

    if (!desc || !desc->stack)
        return WOLFSSL_CBIO_ERR_GENERAL;

    int ret = wolfIP_sock_recv(desc->stack, desc->fd, buf, sz, 0);
    if (ret == -11 || ret == -1)
        return WOLFSSL_CBIO_ERR_WANT_READ;
    if (ret <= 0)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return ret;
}

static int wolfIP_io_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    struct wolfip_io_desc *desc = (struct wolfip_io_desc *)ctx;
    (void)ssl;

    if (!desc || !desc->stack)
        return WOLFSSL_CBIO_ERR_GENERAL;

    int ret = wolfIP_sock_send(desc->stack, desc->fd, buf, sz, 0);
    if (ret == -11 || ret == -1)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    if (ret <= 0)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return ret;
}

int wolfSSL_SetIO_wolfIP_CTX(WOLFSSL_CTX* ctx, struct wolfIP *s)
{
    wolfSSL_SetIORecv(ctx, wolfIP_io_recv);
    wolfSSL_SetIOSend(ctx, wolfIP_io_send);
    wolfIP_register_stack(ctx, s);
    return 0;
}

int wolfSSL_SetIO_wolfIP(WOLFSSL* ssl, int fd)
{
    WOLFSSL_CTX *ctx = wolfSSL_get_SSL_CTX(ssl);
    struct wolfIP *stack = wolfIP_lookup_stack(ctx);

    if (!stack)
        return WOLFSSL_CBIO_ERR_GENERAL;

    for (int i = 0; i < MAX_WOLFIP_CTX; i++) {
        if (io_descs[i].stack == NULL) {
            io_descs[i].fd = fd;
            io_descs[i].stack = stack;
            wolfSSL_SetIOReadCtx(ssl, &io_descs[i]);
            wolfSSL_SetIOWriteCtx(ssl, &io_descs[i]);
            return 0;
        }
    }

    return -1;
}

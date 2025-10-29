/* wolfssl_io.c
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
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

static struct wolfIP *ref_ipstack = NULL;

static int wolfIP_io_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int ret = 0;
    int fd = (intptr_t)ctx;
    (void)ssl;
    if (!ref_ipstack)
        return -1;
    ret = wolfIP_sock_recv(ref_ipstack, fd, buf, sz, 0);
    if (ret == -11)
        return WOLFSSL_CBIO_ERR_WANT_READ;
    else if (ret <= 0)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return ret;
}

static int wolfIP_io_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int ret = 0;
    int fd = (intptr_t)ctx;
    (void)ssl;
    if (!ref_ipstack)
        return -1;
    ret = wolfIP_sock_send(ref_ipstack, fd, buf, sz, 0);
    if (ret == -11)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    else if (ret <= 0)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return ret;
}

int wolfSSL_SetIO_FT_CTX(WOLFSSL_CTX* ctx, struct wolfIP *s)
{
    wolfSSL_SetIORecv(ctx, wolfIP_io_recv);
    wolfSSL_SetIOSend(ctx, wolfIP_io_send);
    ref_ipstack = s;
    return 0;
}

int wolfSSL_SetIO_FT(WOLFSSL* ssl, int fd)
{
    wolfSSL_SetIOReadCtx(ssl, (void*)(intptr_t)fd);
    wolfSSL_SetIOWriteCtx(ssl, (void*)(intptr_t)fd);
    return 0;
}


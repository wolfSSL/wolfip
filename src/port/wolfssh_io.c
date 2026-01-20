/* wolfssh_io.c
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
 * wolfIP <-> wolfSSH glue for custom IO callbacks.
 */
#include "wolfip.h"
#include <wolfssh/ssh.h>

#ifndef MAX_WOLFSSH_CTX
    #define MAX_WOLFSSH_CTX 4
#endif

/* I/O descriptor for wolfSSH sessions */
struct wolfssh_io_desc {
    struct wolfIP *stack;
    int fd;
    int in_use;
};

static struct wolfssh_io_desc io_descs[MAX_WOLFSSH_CTX];

/* Find or allocate an I/O descriptor */
static struct wolfssh_io_desc *io_desc_alloc(void)
{
    for (int i = 0; i < MAX_WOLFSSH_CTX; i++) {
        if (!io_descs[i].in_use) {
            io_descs[i].in_use = 1;
            return &io_descs[i];
        }
    }
    return NULL;
}

/* Free an I/O descriptor */
static void io_desc_free(struct wolfssh_io_desc *desc)
{
    if (desc) {
        desc->stack = NULL;
        desc->fd = -1;
        desc->in_use = 0;
    }
}

/* wolfSSH receive callback */
static int wolfssh_io_recv(WOLFSSH *ssh, void *buf, word32 sz, void *ctx)
{
    struct wolfssh_io_desc *desc = (struct wolfssh_io_desc *)ctx;
    int ret;
    (void)ssh;

    if (!desc || !desc->stack || desc->fd < 0) {
        return WS_CBIO_ERR_GENERAL;
    }

    ret = wolfIP_sock_recv(desc->stack, desc->fd, buf, (int)sz, 0);
    if (ret == -WOLFIP_EAGAIN || ret == -1) {
        return WS_CBIO_ERR_WANT_READ;
    }
    if (ret == 0) {
        return WS_CBIO_ERR_CONN_CLOSE;
    }
    if (ret < 0) {
        return WS_CBIO_ERR_GENERAL;
    }
    return ret;
}

/* wolfSSH send callback */
static int wolfssh_io_send(WOLFSSH *ssh, void *buf, word32 sz, void *ctx)
{
    struct wolfssh_io_desc *desc = (struct wolfssh_io_desc *)ctx;
    int ret;
    (void)ssh;

    if (!desc || !desc->stack || desc->fd < 0) {
        return WS_CBIO_ERR_GENERAL;
    }

    ret = wolfIP_sock_send(desc->stack, desc->fd, buf, (int)sz, 0);
    if (ret == -WOLFIP_EAGAIN || ret == -1) {
        return WS_CBIO_ERR_WANT_WRITE;
    }
    if (ret == 0) {
        return WS_CBIO_ERR_CONN_CLOSE;
    }
    if (ret < 0) {
        return WS_CBIO_ERR_GENERAL;
    }
    return ret;
}

/* Set up wolfSSH I/O callbacks for a wolfIP socket */
int wolfSSH_SetIO_wolfIP(WOLFSSH *ssh, struct wolfIP *stack, int fd)
{
    struct wolfssh_io_desc *desc;

    if (!ssh || !stack || fd < 0) {
        return WS_BAD_ARGUMENT;
    }

    desc = io_desc_alloc();
    if (!desc) {
        return WS_MEMORY_E;
    }

    desc->stack = stack;
    desc->fd = fd;

    wolfSSH_SetIORecv(ssh, wolfssh_io_recv);
    wolfSSH_SetIOSend(ssh, wolfssh_io_send);
    wolfSSH_SetIOReadCtx(ssh, desc);
    wolfSSH_SetIOWriteCtx(ssh, desc);

    return WS_SUCCESS;
}

/* Clean up I/O descriptor when SSH session is done */
void wolfSSH_CleanupIO_wolfIP(WOLFSSH *ssh)
{
    void *ctx;

    if (!ssh) {
        return;
    }

    ctx = wolfSSH_GetIOReadCtx(ssh);
    if (ctx) {
        io_desc_free((struct wolfssh_io_desc *)ctx);
    }
}

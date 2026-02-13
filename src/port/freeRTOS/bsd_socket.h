/* bsd_socket.h
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
 * FreeRTOS POSIX-style socket wrappers for wolfIP.
 */
#ifndef WOLFIP_FREERTOS_SOCKET_H
#define WOLFIP_FREERTOS_SOCKET_H

#include "FreeRTOS.h"
#include "task.h"
#include "wolfip.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SOCK_STREAM IPSTACK_SOCK_STREAM
#define SOCK_DGRAM  IPSTACK_SOCK_DGRAM

int wolfip_freertos_socket_init(struct wolfIP *ipstack,
    UBaseType_t poll_task_priority,
    uint16_t poll_task_stack_words);

int socket_last_error(void);

int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct wolfIP_sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct wolfIP_sockaddr *addr, socklen_t *addrlen);
int connect(int sockfd, const struct wolfIP_sockaddr *addr, socklen_t addrlen);
int close(int sockfd);

int send(int sockfd, const void *buf, size_t len, int flags);
int sendto(int sockfd, const void *buf, size_t len, int flags,
    const struct wolfIP_sockaddr *dest_addr, socklen_t addrlen);
int recv(int sockfd, void *buf, size_t len, int flags);
int recvfrom(int sockfd, void *buf, size_t len, int flags,
    struct wolfIP_sockaddr *src_addr, socklen_t *addrlen);

int setsockopt(int sockfd, int level, int optname,
    const void *optval, socklen_t optlen);
int getsockopt(int sockfd, int level, int optname,
    void *optval, socklen_t *optlen);
int getsockname(int sockfd, struct wolfIP_sockaddr *addr, socklen_t *addrlen);
int getpeername(int sockfd, struct wolfIP_sockaddr *addr, socklen_t *addrlen);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_FREERTOS_SOCKET_H */

/* bsd_socket.c
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
/* POSIX socket calls wrapper for wolfIP */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <pthread.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <poll.h>
#include <string.h>
#define WOLF_POSIX
#include "config.h"
#include "wolfip.h"

static __thread int in_the_stack = 1;
static struct wolfIP *IPSTACK = NULL;
pthread_mutex_t wolfIP_mutex;

/* host_ functions are the original functions from the libc */
static int (*host_socket  ) (int domain, int type, int protocol) = NULL;
static int (*host_bind    ) (int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int (*host_connect ) (int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int (*host_accept  ) (int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static int (*host_listen  ) (int sockfd, int backlog);
static ssize_t (*host_recvfrom) (int sockfd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *addrlen);
static ssize_t (*host_recv    ) (int sockfd, void *buf, size_t len, int flags);
static ssize_t (*host_read    ) (int sockfd, void *buf, size_t len);
static ssize_t (*host_sendto  ) (int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen);
static ssize_t (*host_send    ) (int sockfd, const void *buf, size_t len, int flags);
static ssize_t (*host_write   ) (int sockfd, const void *buf, size_t len);
static int (*host_close   ) (int sockfd);
static int (*host_setsockopt) (int sockfd, int level, int optname, const void *optval, socklen_t optlen);
static int (*host_getsockopt) (int sockfd, int level, int optname, void *optval, socklen_t *optlen);
static int (*host_getsockname) (int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static int (*host_getpeername) (int sockfd, struct sockaddr *addr, socklen_t *addrlen);

static int (*host_poll) (struct pollfd *fds, nfds_t nfds, int timeout);
static int (*host_select) (int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
static int (*host_fcntl) (int fd, int cmd, ...);

#define swap_socketcall(call, name) \
{ \
    const char *msg; \
    if (host_##call == NULL) { \
        *(void **)(&host_##call) = dlsym(RTLD_NEXT, name); \
        if ((msg = dlerror()) != NULL) \
        fprintf (stderr, "%s: dlsym(%s): %s\n", "wolfIP", name, msg); \
    } \
}


#define conditional_steal_call(call, fd, ...) \
    if(in_the_stack) { \
        return host_##call(fd, ## __VA_ARGS__); \
    } else { \
        pthread_mutex_lock(&wolfIP_mutex); \
        if ((fd & (MARK_TCP_SOCKET | MARK_UDP_SOCKET)) != 0) { \
            int __wolfip_retval = wolfIP_sock_##call(IPSTACK, fd, ## __VA_ARGS__); \
            if (__wolfip_retval < 0) { \
                errno = __wolfip_retval; \
                pthread_mutex_unlock(&wolfIP_mutex); \
                return -1; \
            } \
            pthread_mutex_unlock(&wolfIP_mutex); \
            return __wolfip_retval; \
        }else { \
            pthread_mutex_unlock(&wolfIP_mutex); \
            return host_##call(fd, ## __VA_ARGS__); \
        } \
    }

#define conditional_steal_blocking_call(call, fd, ...) \
    if(in_the_stack) { \
        return host_##call(fd, ## __VA_ARGS__); \
    } else { \
        pthread_mutex_lock(&wolfIP_mutex); \
        if ((fd & (MARK_TCP_SOCKET | MARK_UDP_SOCKET)) != 0) { \
            int __wolfip_retval; \
            do { \
                __wolfip_retval = wolfIP_sock_##call(IPSTACK, fd, ## __VA_ARGS__); \
                if (__wolfip_retval == -11) { \
                    usleep(1000); \
                } \
            } while (__wolfip_retval == -11); \
            if (__wolfip_retval < 0) { \
                errno = __wolfip_retval; \
                pthread_mutex_unlock(&wolfIP_mutex); \
                return -1; \
            } \
            pthread_mutex_unlock(&wolfIP_mutex); \
            return __wolfip_retval; \
        }else { \
            pthread_mutex_unlock(&wolfIP_mutex); \
            return host_##call(fd, ## __VA_ARGS__); \
        } \
    }


int wolfIP_sock_setsockopt(struct wolfIP *ipstack, int fd, int level, int optname, const void *optval, socklen_t optlen) {
    printf("Intercepted setsockopt\n");
    (void)ipstack;
    (void)fd;
    (void)level;
    (void)optname;
    (void)optval;
    (void)optlen;
    return 0;
}

int wolfIP_sock_getsockopt(struct wolfIP *ipstack, int fd, int level, int optname, void *optval, socklen_t *optlen) {
    printf("Intercepted getsockopt\n");
    (void)ipstack;
    (void)fd;
    (void)level;
    (void)optname;
    (void)optval;
    (void)optlen;
    return 0;
}

int wolfIP_sock_fcntl(struct wolfIP *ipstack, int fd, int cmd, int arg) {
    printf("Intercepted fcntl\n");
    (void)ipstack;
    (void)fd;
    (void)cmd;
    (void)arg;
    return 0;
}

int fcntl(int fd, int cmd, ...) {
    va_list ap;
    int arg;
    va_start(ap, cmd);
    arg = va_arg(ap, int);
    va_end(ap);
    int ret;
    if (in_the_stack) {
        return host_fcntl(fd, cmd, arg);
    } else {
        pthread_mutex_lock(&wolfIP_mutex);
        ret = wolfIP_sock_fcntl(IPSTACK, fd, cmd, arg);
        pthread_mutex_unlock(&wolfIP_mutex);
        return ret;
    }
}


struct bsd_poll_helper {
    int fd;               /* Original fd */
    int events;           /* Original events */
    int pipefds[2];       /* Pipe for triggering events */
};

/* Static arrays for poll helpers */
static struct bsd_poll_helper tcp_pollers[MAX_TCPSOCKETS] = {{0}};
static struct bsd_poll_helper udp_pollers[MAX_UDPSOCKETS] = {{0}};

void poller_callback(int fd, uint16_t event, void *arg)
{
    struct bsd_poll_helper *poller;
    char c;
    (void)arg;
    if ((fd & MARK_TCP_SOCKET) != 0)
        poller = &tcp_pollers[fd & ~MARK_TCP_SOCKET];
    else if ((fd & MARK_UDP_SOCKET) != 0)
        poller = &udp_pollers[fd & ~MARK_UDP_SOCKET];
    else
        return;
    if (poller->fd != fd)
        return;
    if (event & CB_EVENT_READABLE)
        c = 'r';
    else if (event & CB_EVENT_WRITABLE)
        c = 'w';
    else if (event & CB_EVENT_CLOSED)
        c = 'h';
    else
        return;
    write(poller->pipefds[1], &c, 1);
}

int wolfIP_sock_poll(struct wolfIP *ipstack, struct pollfd *fds, nfds_t nfds, int timeout) {
    nfds_t i;
    int fd;
    int ret;
    int miss = 0;
    if (in_the_stack) {
        return host_poll(fds, nfds, timeout);
    }
    memset(tcp_pollers, 0, sizeof(tcp_pollers));
    memset(udp_pollers, 0, sizeof(udp_pollers));
    for (i = 0; i < nfds; i++) {
        struct bsd_poll_helper *poller = NULL;
        fd = fds[i].fd;

        if ((fd & MARK_TCP_SOCKET) != 0)
            poller = &tcp_pollers[fd & ~MARK_TCP_SOCKET];
        else if ((fd & MARK_UDP_SOCKET) != 0)
            poller = &udp_pollers[fd & ~MARK_UDP_SOCKET];
        else
            continue;
        if (pipe(poller->pipefds) < 0) {
            perror("pipe");
            return -1;
        }
        poller->fd = fd;
        poller->events = fds[i].events;
        /* Replace the original fd with the read end of the pipe */
        fds[i].fd = poller->pipefds[0];
        fds[i].events = POLLIN;
        fds[i].revents = 0;
        /* Assign the callback */
        wolfIP_register_callback(ipstack, fd, poller_callback, ipstack);
    }
    /* Call the original poll */
repeat:
    miss = 0;
    pthread_mutex_unlock(&wolfIP_mutex);
    ret = host_poll(fds, nfds, timeout);
    pthread_mutex_lock(&wolfIP_mutex);
    if (ret <= 0)
        return ret;
    for (i = 0; i < nfds; i++) {
        struct bsd_poll_helper *poller = NULL;
        int j;
        char c = 0;
        fd = fds[i].fd;
        for (j = 0; j < MAX_TCPSOCKETS; j++) {
            if (tcp_pollers[j].fd == 0)
                continue;
            if (tcp_pollers[j].pipefds[0] == fd) {
                poller = &tcp_pollers[j];
                break;
            }
        }
        if (!poller) {
            for (j = 0; j < MAX_UDPSOCKETS; j++) {
                if (udp_pollers[j].fd == 0)
                    continue;
                if (udp_pollers[j].pipefds[0] == fd) {
                    poller = &udp_pollers[j];
                    break;
                }
            }
        }
        if (poller) {
            if ((fds[i].revents & POLLIN) != 0) {
                fds[i].revents = 0;
                host_read(poller->pipefds[0], &c, 1);
                switch(c) {
                    case 'r':
                        fds[i].revents |= POLLIN;
                        break;
                    case 'w':
                        fds[i].revents |= POLLOUT;
                        break;
                    case 'e':
                        fds[i].revents |= POLLERR;
                        break;
                    case 'h':
                        fds[i].revents |= POLLHUP;
                        break;
                }
                if ((fds[i].revents != 0) && (fds[i].revents & (poller->events | POLLHUP | POLLERR)) == 0) {
                    miss++;
                    ret--;
                    continue;
                }
                fds[i].revents &= (POLLHUP | POLLERR | poller->events);
            } else {
                fds[i].revents = 0;
            }
            fds[i].fd = poller->fd;
            fds[i].events = poller->events;
            host_close(poller->pipefds[0]);
            host_close(poller->pipefds[1]);
            poller->fd = 0;
            wolfIP_register_callback(ipstack, poller->fd, NULL, NULL);
        }
    }
    if ((miss != 0) && (ret == 0))
        goto repeat;
    return ret;
}

int wolfIP_sock_select(struct wolfIP *ipstack, int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    int i;
    int maxfd;
    int ret;
    fd_set readfds_local;
    /* Assume MARK_TCP_SOCKET < MARK_UDP_SOCKET */
    if (nfds < MARK_TCP_SOCKET + 1) {
        return host_select(nfds, readfds, writefds, exceptfds, timeout);
    }
    memset(tcp_pollers, 0, sizeof(tcp_pollers));
    memset(udp_pollers, 0, sizeof(udp_pollers));
    for (i = 0; (i < MARK_TCP_SOCKET) && (i < nfds); i++) {
        if ((readfds && FD_ISSET(i, readfds)) ||
                (writefds && FD_ISSET(i, writefds)) ||
                (exceptfds && FD_ISSET(i, exceptfds))) {
            maxfd = i;
        }
    }
    /* At this point, we do need a fd_set to read from pipes */
    if (!readfds) {
        FD_ZERO(&readfds_local);
        readfds = &readfds_local;
    }
    for (i = MARK_TCP_SOCKET; i < nfds && i < (MARK_TCP_SOCKET | MAX_TCPSOCKETS); i++) {
        int tcp_pos = i & (~MARK_TCP_SOCKET);
        if ((readfds && (FD_ISSET(i, readfds))) || (writefds && (FD_ISSET(i, writefds))) || (exceptfds && (FD_ISSET(i, exceptfds)))) {
            if (pipe(tcp_pollers[tcp_pos].pipefds) < 0)
                return -1;
            tcp_pollers[tcp_pos].fd = i;
            tcp_pollers[tcp_pos].events = 0;
            wolfIP_register_callback(ipstack, i, poller_callback, ipstack);
            if (readfds && (FD_ISSET(i, readfds))) {
                tcp_pollers[tcp_pos].events |= POLLIN;
                FD_CLR(i, readfds);
                FD_SET(tcp_pollers[tcp_pos].pipefds[0], readfds);
            }
            if (writefds && (FD_ISSET(i, writefds))) {
                tcp_pollers[tcp_pos].events |= POLLOUT;
                FD_CLR(i, writefds);
                FD_SET(tcp_pollers[tcp_pos].pipefds[0], writefds);
            }
            if (exceptfds && (FD_ISSET(i, exceptfds))) {
                tcp_pollers[tcp_pos].events |= POLLERR | POLLHUP;
                FD_CLR(i, exceptfds);
                FD_SET(tcp_pollers[tcp_pos].pipefds[0], exceptfds);
            }
            if (maxfd < tcp_pollers[tcp_pos].pipefds[0]) {
                maxfd = tcp_pollers[tcp_pos].pipefds[0];
            }
        } else {
        }
    }
    for (i = MARK_UDP_SOCKET; i < nfds && i < (MARK_UDP_SOCKET | MAX_UDPSOCKETS); i++) {
        int udp_pos = i & (~MARK_UDP_SOCKET);
        if (FD_ISSET(i, readfds) || FD_ISSET(i, writefds) || FD_ISSET(i, exceptfds)) {
            pipe(udp_pollers[udp_pos].pipefds);
            udp_pollers[udp_pos].fd = i;
            udp_pollers[udp_pos].events = 0;
            wolfIP_register_callback(ipstack, i, poller_callback, ipstack);
            if (readfds && FD_ISSET(i, readfds)) {
                udp_pollers[udp_pos].events |= POLLIN;
                FD_CLR(i, readfds);
                FD_SET(udp_pollers[udp_pos].pipefds[0], readfds);
            }
            if (writefds && FD_ISSET(i, writefds)) {
                udp_pollers[udp_pos].events |= POLLOUT;
                FD_CLR(i, writefds);
                FD_SET(udp_pollers[udp_pos].pipefds[0], writefds);
            }
            if (exceptfds && FD_ISSET(i, exceptfds)) {
                udp_pollers[udp_pos].events |= POLLERR | POLLHUP;
                FD_CLR(i, exceptfds);
                FD_SET(udp_pollers[udp_pos].pipefds[0], exceptfds);
            }
            if (maxfd < udp_pollers[udp_pos].pipefds[0]) {
                maxfd = udp_pollers[udp_pos].pipefds[0];
            }
        }
    }
    /* Call the original select */
    pthread_mutex_unlock(&wolfIP_mutex);
    ret = host_select(maxfd + 1, readfds, writefds, exceptfds, timeout);
    pthread_mutex_lock(&wolfIP_mutex);
    if (ret <= 0) {
        return ret;
    }

    for (i = 0; i < MAX_TCPSOCKETS; i++) {
        if (tcp_pollers[i].fd == 0) {
            continue;
        }
        if (FD_ISSET(tcp_pollers[i].pipefds[0], readfds)) {
            char c;
            host_read(tcp_pollers[i].pipefds[0], &c, 1);
            if (readfds && (c == 'r')) {
                FD_SET(tcp_pollers[i].fd, readfds);
            } else if (writefds && (c == 'w')) {
                FD_SET(tcp_pollers[i].fd, writefds);
            } else if (exceptfds && (c == 'e')) {
                FD_SET(tcp_pollers[i].fd, exceptfds);
            }
        }
        wolfIP_register_callback(ipstack, tcp_pollers[i].fd, NULL, NULL);
        host_close(tcp_pollers[i].pipefds[0]);
        host_close(tcp_pollers[i].pipefds[1]);
        tcp_pollers[i].fd = 0;
    }
    for (i = 0; i < MAX_UDPSOCKETS; i++) {
        if (udp_pollers[i].fd == 0) {
            continue;
        }
        if (FD_ISSET(udp_pollers[i].pipefds[0], readfds)) {
            char c;
            read(udp_pollers[i].pipefds[0], &c, 1);
            if (readfds && (c == 'r')) {
                FD_SET(udp_pollers[i].fd, readfds);
            } else if (writefds && (c == 'w')) {
                FD_SET(udp_pollers[i].fd, writefds);
            } else if (exceptfds && (c == 'e')) {
                FD_SET(udp_pollers[i].fd, exceptfds);
            }
        }
        host_close(udp_pollers[i].pipefds[0]);
        host_close(udp_pollers[i].pipefds[1]);
        wolfIP_register_callback(ipstack, tcp_pollers[i].fd, NULL, NULL);
        udp_pollers[i].fd = 0;
    }
    return ret;
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    int ret;
    if (in_the_stack) {
        return host_select(nfds, readfds, writefds, exceptfds, timeout);
    } else {
        pthread_mutex_lock(&wolfIP_mutex);
        ret = wolfIP_sock_select(IPSTACK, nfds, readfds, writefds, exceptfds, timeout);
        pthread_mutex_unlock(&wolfIP_mutex);
        return ret;
    }
}

int socket(int domain, int type, int protocol) {
    if (in_the_stack) {
        return host_socket(domain, type, protocol);
    } else {
        return wolfIP_sock_socket(IPSTACK, domain, type, protocol);
    }
}

int listen(int sockfd, int backlog) {
    conditional_steal_call(listen, sockfd, backlog);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    conditional_steal_call(bind, sockfd, addr, addrlen);
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
    conditional_steal_call(getsockopt, sockfd, level, optname, optval, optlen);
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    conditional_steal_call(getpeername, sockfd, addr, addrlen);
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    conditional_steal_call(getsockname, sockfd, addr, addrlen);
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    conditional_steal_call(setsockopt, sockfd, level, optname, optval, optlen);
}

int close(int sockfd) {
    conditional_steal_call(close, sockfd);
}

/* Blocking calls */
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    conditional_steal_blocking_call(accept, sockfd, addr, addrlen);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    conditional_steal_blocking_call(connect, sockfd, addr, addrlen);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *addrlen) {
    conditional_steal_blocking_call(recvfrom, sockfd, buf, len, flags, addr, addrlen);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    conditional_steal_blocking_call(recv, sockfd, buf, len, flags);
}

ssize_t read(int sockfd, void *buf, size_t len) {
    conditional_steal_blocking_call(read, sockfd, buf, len);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen) {
    conditional_steal_blocking_call(sendto, sockfd, buf, len, flags, addr, addrlen);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    conditional_steal_blocking_call(send, sockfd, buf, len, flags);
}

ssize_t write(int sockfd, const void *buf, size_t len) {
    conditional_steal_blocking_call(write, sockfd, buf, len);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    int ret;
    if (in_the_stack) {
        return host_poll(fds, nfds, timeout);
    } else {
        pthread_mutex_lock(&wolfIP_mutex);
        ret = wolfIP_sock_poll(IPSTACK, fds, nfds, timeout);
        pthread_mutex_unlock(&wolfIP_mutex);
        return ret;
    }
}



/* Catch-all function to initialize a new tap device as the network interface.
 * This is defined in port/linux.c
 * */
extern int tap_init(struct ll *dev, const char *name, uint32_t host_ip);

void *wolfIP_sock_posix_ip_loop(void *arg) {
    struct wolfIP *ipstack = (struct wolfIP *)arg;
    uint32_t ms_next;
    struct timeval tv;
    while (1) {
        pthread_mutex_lock(&wolfIP_mutex);
        gettimeofday(&tv, NULL);
        ms_next = wolfIP_poll(ipstack, tv.tv_sec * 1000 + tv.tv_usec / 1000);
        pthread_mutex_unlock(&wolfIP_mutex);
        usleep(ms_next * 1000);
        in_the_stack = 1;
    }
    return NULL;
}

void __attribute__((constructor)) init_wolfip_posix() {
    struct in_addr linux_ip;
    struct ll *tapdev;
    pthread_t wolfIP_thread;
    if (IPSTACK)
        return;
    inet_aton(LINUX_IP, &linux_ip);
    swap_socketcall(socket, "socket");
    swap_socketcall(bind, "bind");
    swap_socketcall(listen, "listen");
    swap_socketcall(accept, "accept");
    swap_socketcall(connect, "connect");
    swap_socketcall(sendto, "sendto");
    swap_socketcall(recvfrom, "recvfrom");
    swap_socketcall(recv, "recv");
    swap_socketcall(send, "send");
    swap_socketcall(close, "close");
    swap_socketcall(write, "write");
    swap_socketcall(read, "read");
    swap_socketcall(getsockname, "getsockname");
    swap_socketcall(getpeername, "getpeername");
    swap_socketcall(setsockopt, "getaddrinfo");
    swap_socketcall(getsockopt, "freeaddrinfo");
    swap_socketcall(poll, "poll");
    swap_socketcall(select, "select");
    swap_socketcall(fcntl, "fcntl");

    pthread_mutex_init(&wolfIP_mutex, NULL);
    wolfIP_init_static(&IPSTACK);
    tapdev = wolfIP_getdev(IPSTACK);
    if (tap_init(tapdev, "wtcp0", linux_ip.s_addr) < 0) {
        perror("tap init");
    }
    wolfIP_ipconfig_set(IPSTACK, atoip4(WOLFIP_IP), atoip4("255.255.255.0"),
            atoip4(LINUX_IP));
    printf("IP: manually configured - %s\n", WOLFIP_IP);
    sleep(1);
    pthread_create(&wolfIP_thread, NULL, wolfIP_sock_posix_ip_loop, IPSTACK);
    in_the_stack = 0;
}


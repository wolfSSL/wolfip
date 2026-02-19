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
#include <time.h>
#include <poll.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/uio.h>
#include <limits.h>
#include <fcntl.h>
#include <stdio.h>
#define WOLF_POSIX
#include "config.h"
#include "wolfip.h"

static __thread int in_the_stack = 1;
static struct wolfIP *IPSTACK = NULL;
pthread_mutex_t wolfIP_mutex;

struct wolfip_fd_entry;
int wolfIP_sock_poll(struct wolfIP *ipstack, struct pollfd *fds, nfds_t nfds, int timeout);
void poller_callback(int fd, uint16_t event, void *arg);

#if WOLFIP_POSIX_TCPDUMP
static pid_t tcpdump_pid = -1;

static void wolfIP_stop_tcpdump(void);

static void wolfIP_start_tcpdump(const char *ifname)
{
    if (tcpdump_pid > 0 || !ifname || ifname[0] == '\0')
        return;
    tcpdump_pid = fork();
    if (tcpdump_pid == 0) {
        execlp("tcpdump", "tcpdump", "-i", ifname,
                "-w", "/tmp/wolfip.pcap", "-U", "-n", NULL);
        _exit(127);
    } else if (tcpdump_pid < 0) {
        perror("tcpdump fork");
    }
}

static void wolfIP_stop_tcpdump(void)
{
    if (tcpdump_pid > 0) {
        kill(tcpdump_pid, SIGINT);
        tcpdump_pid = -1;
    }
}

static void wolfIP_stop_tcpdump_atexit(void)
{
    wolfIP_stop_tcpdump();
}
#endif

/* host_ functions are the original functions from the libc */
static int (*host_socket  ) (int domain, int type, int protocol) = NULL;
static int (*host_bind    ) (int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int (*host_connect ) (int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int (*host_accept  ) (int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static int (*host_accept4 ) (int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
static int (*host_listen  ) (int sockfd, int backlog);
static ssize_t (*host_recvfrom) (int sockfd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *addrlen);
static ssize_t (*host_recv    ) (int sockfd, void *buf, size_t len, int flags);
static ssize_t (*host_read    ) (int sockfd, void *buf, size_t len);
static ssize_t (*host_sendto  ) (int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen);
static ssize_t (*host_send    ) (int sockfd, const void *buf, size_t len, int flags);
static ssize_t (*host_write   ) (int sockfd, const void *buf, size_t len);
static ssize_t (*host_sendmsg ) (int sockfd, const struct msghdr *msg, int flags);
static ssize_t (*host_recvmsg ) (int sockfd, struct msghdr *msg, int flags);
static int (*host_getaddrinfo) (const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
static void (*host_freeaddrinfo) (struct addrinfo *res);
static int (*host_close   ) (int sockfd);
static int (*host_setsockopt) (int sockfd, int level, int optname, const void *optval, socklen_t optlen);
static int (*host_getsockopt) (int sockfd, int level, int optname, void *optval, socklen_t *optlen);
static int (*host_getsockname) (int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static int (*host_getpeername) (int sockfd, struct sockaddr *addr, socklen_t *addrlen);

static int (*host_poll) (struct pollfd *fds, nfds_t nfds, int timeout);
static int (*host_select) (int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
static int (*host_fcntl) (int fd, int cmd, ...);

#define WOLFIP_MAX_PUBLIC_FDS 256

struct wolfip_fd_entry {
    int internal_fd;   /* MARK_* encoded */
    int public_fd;     /* Returned to user; read end of pipe */
    int pipe_write;    /* Write end used for wakeups */
    int snd_timeout_ms; /* SO_SNDTIMEO; -1 means infinite */
    int rcv_timeout_ms; /* SO_RCVTIMEO; -1 means infinite */
    uint8_t nonblock;
    uint8_t in_use;
    uint8_t pending_tokens; /* Bitset of queued event bytes in the pipe */
    uint16_t events;   /* Events armed for current poll/select */
};

#define WOLFIP_TOKEN_R (1u << 0)
#define WOLFIP_TOKEN_W (1u << 1)
#define WOLFIP_TOKEN_E (1u << 2)
#define WOLFIP_TOKEN_H (1u << 3)

static uint8_t wolfip_token_mask(char c)
{
    switch (c) {
        case 'r': return WOLFIP_TOKEN_R;
        case 'w': return WOLFIP_TOKEN_W;
        case 'e': return WOLFIP_TOKEN_E;
        case 'h': return WOLFIP_TOKEN_H;
        default: return 0;
    }
}

static void wolfip_consume_token_locked(struct wolfip_fd_entry *entry, char c)
{
    uint8_t mask = wolfip_token_mask(c);
    if (entry && mask)
        entry->pending_tokens &= (uint8_t)~mask;
}

static void wolfip_drain_pipe_locked(struct wolfip_fd_entry *entry)
{
    char c;
    if (!entry)
        return;
    while (host_read(entry->public_fd, &c, 1) > 0)
        wolfip_consume_token_locked(entry, c);
}

static struct wolfip_fd_entry wolfip_fd_entries[WOLFIP_MAX_PUBLIC_FDS];
static int tcp_entry_for_slot[MAX_TCPSOCKETS];
static int udp_entry_for_slot[MAX_UDPSOCKETS];
static int icmp_entry_for_slot[MAX_ICMPSOCKETS];

enum wolfip_dns_wait_type {
    DNS_WAIT_NONE = 0,
    DNS_WAIT_FORWARD,
    DNS_WAIT_PTR
};

struct wolfip_dns_wait_ctx {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int pending;
    enum wolfip_dns_wait_type type;
    int status;
    uint32_t ip;
    char name[256];
};

static struct wolfip_dns_wait_ctx dns_wait_ctx = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
    0,
    DNS_WAIT_NONE,
    0,
    0,
    {0}
};

struct wolfip_gai_alloc {
    struct addrinfo *res;
    struct wolfip_gai_alloc *next;
};

static pthread_mutex_t wolfip_gai_alloc_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct wolfip_gai_alloc *wolfip_gai_alloc_head;

static void wolfip_fd_pool_init(void)
{
    int i;
    static int init_done;
    if (init_done)
        return;
    for (i = 0; i < WOLFIP_MAX_PUBLIC_FDS; i++)
        wolfip_fd_entries[i].in_use = 0;
    for (i = 0; i < MAX_TCPSOCKETS; i++)
        tcp_entry_for_slot[i] = -1;
    for (i = 0; i < MAX_UDPSOCKETS; i++)
        udp_entry_for_slot[i] = -1;
    for (i = 0; i < MAX_ICMPSOCKETS; i++)
        icmp_entry_for_slot[i] = -1;
    init_done = 1;
}

static struct wolfip_fd_entry *wolfip_entry_from_internal(int internal_fd)
{
    int idx;
    if (IS_SOCKET_TCP(internal_fd)) {
        int pos = SOCKET_UNMARK(internal_fd);
        if (pos < 0 || pos >= MAX_TCPSOCKETS)
            return NULL;
        idx = tcp_entry_for_slot[pos];
    } else if (IS_SOCKET_UDP(internal_fd)) {
        int pos = SOCKET_UNMARK(internal_fd);
        if (pos < 0 || pos >= MAX_UDPSOCKETS)
            return NULL;
        idx = udp_entry_for_slot[pos];
    } else if (IS_SOCKET_ICMP(internal_fd)) {
        int pos = SOCKET_UNMARK(internal_fd);
        if (pos < 0 || pos >= MAX_ICMPSOCKETS)
            return NULL;
        idx = icmp_entry_for_slot[pos];
    } else {
        return NULL;
    }
    if (idx < 0 || idx >= WOLFIP_MAX_PUBLIC_FDS)
        return NULL;
    if (!wolfip_fd_entries[idx].in_use)
        return NULL;
    return &wolfip_fd_entries[idx];
}

static struct wolfip_fd_entry *wolfip_entry_from_public(int public_fd)
{
    if (public_fd < 0 || public_fd >= WOLFIP_MAX_PUBLIC_FDS)
        return NULL;
    if (!wolfip_fd_entries[public_fd].in_use)
        return NULL;
    return &wolfip_fd_entries[public_fd];
}

static void wolfip_fd_detach_internal(int internal_fd)
{
    if (IS_SOCKET_TCP(internal_fd)) {
        int pos = SOCKET_UNMARK(internal_fd);
        if (pos >= 0 && pos < MAX_TCPSOCKETS)
            tcp_entry_for_slot[pos] = -1;
    } else if (IS_SOCKET_UDP(internal_fd)) {
        int pos = SOCKET_UNMARK(internal_fd);
        if (pos >= 0 && pos < MAX_UDPSOCKETS)
            udp_entry_for_slot[pos] = -1;
    } else if (IS_SOCKET_ICMP(internal_fd)) {
        int pos = SOCKET_UNMARK(internal_fd);
        if (pos >= 0 && pos < MAX_ICMPSOCKETS)
            icmp_entry_for_slot[pos] = -1;
    }
}

static void wolfip_fd_attach_internal(int internal_fd, int entry_idx)
{
    if (IS_SOCKET_TCP(internal_fd)) {
        int pos = SOCKET_UNMARK(internal_fd);
        if (pos >= 0 && pos < MAX_TCPSOCKETS)
            tcp_entry_for_slot[pos] = entry_idx;
    } else if (IS_SOCKET_UDP(internal_fd)) {
        int pos = SOCKET_UNMARK(internal_fd);
        if (pos >= 0 && pos < MAX_UDPSOCKETS)
            udp_entry_for_slot[pos] = entry_idx;
    } else if (IS_SOCKET_ICMP(internal_fd)) {
        int pos = SOCKET_UNMARK(internal_fd);
        if (pos >= 0 && pos < MAX_ICMPSOCKETS)
            icmp_entry_for_slot[pos] = entry_idx;
    }
}

static int wolfip_fd_alloc(int internal_fd, int nonblock)
{
    int pipefds[2];
    int idx;
    wolfip_fd_pool_init();
    if (pipe(pipefds) < 0) {
        return -errno;
    }
    if (host_fcntl) {
        host_fcntl(pipefds[0], F_SETFD, FD_CLOEXEC);
        host_fcntl(pipefds[1], F_SETFD, FD_CLOEXEC);
        host_fcntl(pipefds[0], F_SETFL, O_NONBLOCK);
        host_fcntl(pipefds[1], F_SETFL, O_NONBLOCK);
    } else {
        fcntl(pipefds[0], F_SETFD, FD_CLOEXEC);
        fcntl(pipefds[1], F_SETFD, FD_CLOEXEC);
        fcntl(pipefds[0], F_SETFL, O_NONBLOCK);
        fcntl(pipefds[1], F_SETFL, O_NONBLOCK);
    }
    if (pipefds[0] < 0 || pipefds[0] >= WOLFIP_MAX_PUBLIC_FDS || wolfip_fd_entries[pipefds[0]].in_use) {
        if (host_close) {
            host_close(pipefds[0]);
            host_close(pipefds[1]);
        }
        return -EMFILE;
    }
    idx = pipefds[0];
    memset(&wolfip_fd_entries[idx], 0, sizeof(wolfip_fd_entries[idx]));
    wolfip_fd_entries[idx].internal_fd = internal_fd;
    wolfip_fd_entries[idx].public_fd = pipefds[0];
    wolfip_fd_entries[idx].pipe_write = pipefds[1];
    wolfip_fd_entries[idx].snd_timeout_ms = -1;
    wolfip_fd_entries[idx].rcv_timeout_ms = -1;
    wolfip_fd_entries[idx].nonblock = nonblock ? 1 : 0;
    wolfip_fd_entries[idx].pending_tokens = 0;
    wolfip_fd_entries[idx].events = 0;
    wolfip_fd_entries[idx].in_use = 1;
    wolfip_fd_attach_internal(internal_fd, idx);
    return pipefds[0];
}

static void wolfip_fd_release(int public_fd)
{
    if (public_fd < 0 || public_fd >= WOLFIP_MAX_PUBLIC_FDS)
        return;
    if (wolfip_fd_entries[public_fd].in_use) {
        if (host_close) {
            host_close(wolfip_fd_entries[public_fd].public_fd);
            host_close(wolfip_fd_entries[public_fd].pipe_write);
        }
        wolfip_fd_detach_internal(wolfip_fd_entries[public_fd].internal_fd);
    }
    wolfip_fd_entries[public_fd].in_use = 0;
    wolfip_fd_entries[public_fd].pending_tokens = 0;
    wolfip_fd_entries[public_fd].events = 0;
}

static int wolfip_fd_internal_from_public(int public_fd)
{
    struct wolfip_fd_entry *e = wolfip_entry_from_public(public_fd);
    if (!e)
        return -1;
    return e->internal_fd;
}

static int wolfip_fd_set_nonblock_flag(int public_fd, int nonblock)
{
    struct wolfip_fd_entry *e = wolfip_entry_from_public(public_fd);
    if (!e)
        return -WOLFIP_EINVAL;
    e->nonblock = nonblock ? 1 : 0;
    return 0;
}

static int wolfip_fd_is_nonblock(int public_fd)
{
    struct wolfip_fd_entry *e = wolfip_entry_from_public(public_fd);
    return e ? (e->nonblock != 0) : 0;
}

static int wolfip_wait_for_event_locked(struct wolfip_fd_entry *entry, short wait_events, int timeout_ms)
{
    struct pollfd pfd;
    char want;

    if (!entry)
        return -EINVAL;
    want = (wait_events & POLLOUT) ? 'w' : 'r';
    entry->events = (uint16_t)wait_events;
    wolfIP_register_callback(IPSTACK, entry->internal_fd, poller_callback, IPSTACK);
    pfd.fd = entry->public_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    while (1) {
        int poll_ret;
        int wake = 0;
        int ready = 0;
        char c;

        if (wait_events & POLLOUT)
            ready = wolfIP_sock_can_write(IPSTACK, entry->internal_fd);
        else if (wait_events & POLLIN)
            ready = wolfIP_sock_can_read(IPSTACK, entry->internal_fd);
        if (ready < 0)
            return ready;
        if (ready > 0) {
            break;
        }

        pthread_mutex_unlock(&wolfIP_mutex);
        poll_ret = host_poll(&pfd, 1, timeout_ms);
        if (poll_ret < 0 && errno == EINTR) {
            pthread_mutex_lock(&wolfIP_mutex);
            return -EINTR;
        }
        pthread_mutex_lock(&wolfIP_mutex);
        if (poll_ret < 0) {
            return -errno;
        }
        if (poll_ret == 0) {
            return -ETIMEDOUT;
        }
        while (host_read(entry->public_fd, &c, 1) > 0) {
            wolfip_consume_token_locked(entry, c);
            if (c == want || c == 'h' || c == 'e')
                wake = 1;
        }
        if (wake)
            break;
    }
    return 0;
}

#define swap_socketcall(call, name) \
{ \
    const char *msg; \
    if (host_##call == NULL) { \
        *(void **)(&host_##call) = dlsym(RTLD_NEXT, name); \
        if ((msg = dlerror()) != NULL) \
        fprintf (stderr, "%s: dlsym(%s): %s\n", "wolfIP", name, msg); \
    } \
}


#define conditional_steal_call(call, user_fd, ...) \
    if(in_the_stack) { \
        return host_##call(user_fd, ## __VA_ARGS__); \
    } else { \
        int __wolfip_internal = wolfip_fd_internal_from_public(user_fd); \
        pthread_mutex_lock(&wolfIP_mutex); \
        if (__wolfip_internal >= 0) { \
            int __wolfip_retval = wolfIP_sock_##call(IPSTACK, __wolfip_internal, ## __VA_ARGS__); \
            if (__wolfip_retval < 0) { \
                errno = __wolfip_retval; \
                pthread_mutex_unlock(&wolfIP_mutex); \
                return -1; \
            } \
            pthread_mutex_unlock(&wolfIP_mutex); \
            errno = 0; \
            return __wolfip_retval; \
        } else { \
            pthread_mutex_unlock(&wolfIP_mutex); \
            return host_##call(user_fd, ## __VA_ARGS__); \
        } \
    }

#define conditional_steal_blocking_call(call, user_fd, wait_events, ...) \
    if(in_the_stack) { \
        return host_##call(user_fd, ## __VA_ARGS__); \
    } else { \
        int __wolfip_internal = wolfip_fd_internal_from_public(user_fd); \
        pthread_mutex_lock(&wolfIP_mutex); \
        if (__wolfip_internal >= 0) { \
            int __wolfip_retval; \
            int __wolfip_nonblock = wolfip_fd_is_nonblock(user_fd); \
            struct wolfip_fd_entry *__entry = wolfip_entry_from_public(user_fd); \
            do { \
                __wolfip_retval = wolfIP_sock_##call(IPSTACK, __wolfip_internal, ## __VA_ARGS__); \
                if (__wolfip_retval == -EAGAIN) { \
                    if (__wolfip_nonblock) { \
                        errno = EAGAIN; \
                        pthread_mutex_unlock(&wolfIP_mutex); \
                        return -1; \
                    } \
                    if (__entry) { \
                        int __wait_timeout = ((wait_events) & POLLOUT) ? __entry->snd_timeout_ms : __entry->rcv_timeout_ms; \
                        int __wait_ret = wolfip_wait_for_event_locked(__entry, (wait_events), __wait_timeout); \
                        if (__wait_ret < 0) { \
                            errno = -__wait_ret; \
                            pthread_mutex_unlock(&wolfIP_mutex); \
                            return -1; \
                        } \
                    } else { \
                        pthread_mutex_unlock(&wolfIP_mutex); \
                        usleep(1000); \
                        pthread_mutex_lock(&wolfIP_mutex); \
                    } \
                } \
            } while (__wolfip_retval == -EAGAIN); \
            if (__wolfip_retval < 0) { \
                errno = __wolfip_retval; \
                pthread_mutex_unlock(&wolfIP_mutex); \
                return -1; \
            } \
            pthread_mutex_unlock(&wolfIP_mutex); \
            errno = 0; \
            return __wolfip_retval; \
        }else { \
            pthread_mutex_unlock(&wolfIP_mutex); \
            return host_##call(user_fd, ## __VA_ARGS__); \
        } \
    }



int wolfIP_sock_fcntl(struct wolfIP *ipstack, int fd, int cmd, int arg) {
    (void)ipstack;
    switch (cmd) {
        case F_SETFL:
            return wolfip_fd_set_nonblock_flag(fd, (arg & O_NONBLOCK) ? 1 : 0);
        case F_GETFL: {
            int flags = wolfip_fd_is_nonblock(fd) ? O_NONBLOCK : 0;
            return flags;
        }
        default:
            return -WOLFIP_EINVAL;
    }
}

#define WOLFIP_IOV_STACK_BUF 2048

static int wolfip_calc_msghdr_len(const struct msghdr *msg, size_t *total_len)
{
    size_t len = 0;
    size_t i;

    if (!msg || msg->msg_iovlen == 0 || !msg->msg_iov)
        return -WOLFIP_EINVAL;
    for (i = 0; i < msg->msg_iovlen; i++) {
        const struct iovec *iov = &msg->msg_iov[i];
        if (!iov)
            return -WOLFIP_EINVAL;
        if (!iov->iov_base && iov->iov_len != 0)
            return -WOLFIP_EINVAL;
        if (SIZE_MAX - len < iov->iov_len)
            return -WOLFIP_EINVAL;
        len += iov->iov_len;
    }
    if (total_len)
        *total_len = len;
    return 0;
}

static void wolfip_flatten_iov(uint8_t *dst, const struct msghdr *msg)
{
    size_t offset = 0;
    size_t i;

    if (!dst || !msg)
        return;
    for (i = 0; i < msg->msg_iovlen; i++) {
        const struct iovec *iov = &msg->msg_iov[i];
        if (!iov || !iov->iov_base || iov->iov_len == 0)
            continue;
        memcpy(dst + offset, iov->iov_base, iov->iov_len);
        offset += iov->iov_len;
    }
}

static void wolfip_scatter_iov(const struct msghdr *msg, const uint8_t *src, size_t len)
{
    size_t offset = 0;
    size_t i;

    if (!msg || !msg->msg_iov || !src)
        return;
    for (i = 0; i < msg->msg_iovlen && offset < len; i++) {
        const struct iovec *iov = &msg->msg_iov[i];
        size_t chunk;

        if (!iov || !iov->iov_base || iov->iov_len == 0)
            continue;
        chunk = iov->iov_len;
        if (chunk > len - offset)
            chunk = len - offset;
        memcpy(iov->iov_base, src + offset, chunk);
        offset += chunk;
    }
}

static void wolfip_fill_ttl_control(struct wolfIP *ipstack, int sockfd, struct msghdr *msg)
{
    int ttl;
    int ttl_status;
    struct cmsghdr *cmsg;
    socklen_t ctrl_len;

    if (!msg)
        return;
    ctrl_len = msg->msg_controllen;
    msg->msg_controllen = 0;
    ttl_status = wolfIP_sock_get_recv_ttl(ipstack, sockfd, &ttl);
    if (ttl_status <= 0)
        return;
    if (!msg->msg_control || ctrl_len < (socklen_t)CMSG_SPACE(sizeof(int)))
        return;
    cmsg = (struct cmsghdr *)msg->msg_control;
    cmsg->cmsg_level = SOL_IP;
    cmsg->cmsg_type = IP_TTL;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *)CMSG_DATA(cmsg)) = ttl;
    msg->msg_controllen = cmsg->cmsg_len;
}

static size_t wolfip_strlcpy(char *dst, const char *src, size_t size)
{
    size_t len = 0;
    if (!dst || size == 0)
        return 0;
    if (src) {
        while (src[len] && len + 1 < size) {
            dst[len] = src[len];
            len++;
        }
        dst[len] = '\0';
        while (src[len])
            len++;
    } else {
        dst[0] = '\0';
    }
    return len;
}

static int wolfip_dns_error_to_eai(int err)
{
    switch (err) {
        case 0:
            return 0;
        case -16:
            return EAI_AGAIN;
        case -22:
            return EAI_NONAME;
        case -101:
            return EAI_FAIL;
        default:
            return EAI_FAIL;
    }
}

static int wolfip_dns_begin_wait(enum wolfip_dns_wait_type type)
{
    pthread_mutex_lock(&dns_wait_ctx.mutex);
    if (dns_wait_ctx.pending) {
        pthread_mutex_unlock(&dns_wait_ctx.mutex);
        return EAI_AGAIN;
    }
    dns_wait_ctx.pending = 1;
    dns_wait_ctx.type = type;
    dns_wait_ctx.status = EAI_FAIL;
    dns_wait_ctx.name[0] = '\0';
    pthread_mutex_unlock(&dns_wait_ctx.mutex);
    return 0;
}

static void wolfip_dns_abort_wait(int status)
{
    pthread_mutex_lock(&dns_wait_ctx.mutex);
    dns_wait_ctx.pending = 0;
    dns_wait_ctx.type = DNS_WAIT_NONE;
    dns_wait_ctx.status = status;
    pthread_cond_signal(&dns_wait_ctx.cond);
    pthread_mutex_unlock(&dns_wait_ctx.mutex);
}

static int wolfip_dns_wait(enum wolfip_dns_wait_type type, uint32_t *ip_out, char *name_out, size_t name_len)
{
    struct timespec ts;
    int status;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;
    pthread_mutex_lock(&dns_wait_ctx.mutex);
    while (dns_wait_ctx.pending && dns_wait_ctx.type == type) {
        int err = pthread_cond_timedwait(&dns_wait_ctx.cond, &dns_wait_ctx.mutex, &ts);
        if (err == ETIMEDOUT) {
            dns_wait_ctx.pending = 0;
            dns_wait_ctx.type = DNS_WAIT_NONE;
            pthread_mutex_unlock(&dns_wait_ctx.mutex);
            return EAI_AGAIN;
        }
    }
    if (dns_wait_ctx.type != type) {
        int status = dns_wait_ctx.status ? dns_wait_ctx.status : EAI_FAIL;
        pthread_mutex_unlock(&dns_wait_ctx.mutex);
        return status;
    }
    status = dns_wait_ctx.status;
    if (status == 0) {
        if (ip_out)
            *ip_out = dns_wait_ctx.ip;
        if (name_out && name_len)
            wolfip_strlcpy(name_out, dns_wait_ctx.name, name_len);
    }
    dns_wait_ctx.type = DNS_WAIT_NONE;
    pthread_mutex_unlock(&dns_wait_ctx.mutex);
    return status;
}

static void wolfip_dns_forward_cb(ip4 ip)
{
    pthread_mutex_lock(&dns_wait_ctx.mutex);
    if (dns_wait_ctx.pending && dns_wait_ctx.type == DNS_WAIT_FORWARD) {
        dns_wait_ctx.ip = ip;
        dns_wait_ctx.status = 0;
        dns_wait_ctx.pending = 0;
        pthread_cond_signal(&dns_wait_ctx.cond);
    }
    pthread_mutex_unlock(&dns_wait_ctx.mutex);
}

static void wolfip_dns_reverse_cb(const char *name)
{
    pthread_mutex_lock(&dns_wait_ctx.mutex);
    if (dns_wait_ctx.pending && dns_wait_ctx.type == DNS_WAIT_PTR) {
        wolfip_strlcpy(dns_wait_ctx.name, name, sizeof(dns_wait_ctx.name));
        dns_wait_ctx.status = 0;
        dns_wait_ctx.pending = 0;
        pthread_cond_signal(&dns_wait_ctx.cond);
    }
    pthread_mutex_unlock(&dns_wait_ctx.mutex);
}

static int wolfip_dns_forward_query(const char *node, uint32_t *ip_out)
{
    uint16_t dns_id;
    int err = wolfip_dns_begin_wait(DNS_WAIT_FORWARD);
    if (err != 0)
        return err;
    pthread_mutex_lock(&wolfIP_mutex);
    err = nslookup(IPSTACK, node, &dns_id, wolfip_dns_forward_cb);
    pthread_mutex_unlock(&wolfIP_mutex);
    if (err < 0) {
        int eai = wolfip_dns_error_to_eai(err);
        wolfip_dns_abort_wait(eai);
        return eai;
    }
    return wolfip_dns_wait(DNS_WAIT_FORWARD, ip_out, NULL, 0);
}

static int wolfip_dns_reverse_query(uint32_t ip, char *name, size_t name_len)
{
    uint16_t dns_id;
    int err = wolfip_dns_begin_wait(DNS_WAIT_PTR);
    if (err != 0)
        return err;
    pthread_mutex_lock(&wolfIP_mutex);
    err = wolfIP_dns_ptr_lookup(IPSTACK, ip, &dns_id, wolfip_dns_reverse_cb);
    pthread_mutex_unlock(&wolfIP_mutex);
    if (err < 0) {
        int eai = wolfip_dns_error_to_eai(err);
        wolfip_dns_abort_wait(eai);
        return eai;
    }
    return wolfip_dns_wait(DNS_WAIT_PTR, NULL, name, name_len);
}

static int wolfip_parse_service(const char *service, uint16_t *port)
{
    char *end;
    long value;
    if (!port)
        return EAI_FAIL;
    if (!service) {
        *port = 0;
        return 0;
    }
    value = strtol(service, &end, 10);
    if (*end != '\0' || value < 0 || value > 65535)
        return EAI_SERVICE;
    *port = (uint16_t)value;
    return 0;
}

static struct addrinfo *wolfip_alloc_addrinfo(void)
{
    return (struct addrinfo *)calloc(1, sizeof(struct addrinfo));
}

static int wolfip_build_addrinfo(uint32_t ip, uint16_t port, const char *canon,
        const struct addrinfo *hints, struct addrinfo **res)
{
    struct addrinfo *ai = wolfip_alloc_addrinfo();
    struct sockaddr_in *sa = (struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in));
    if (!ai || !sa) {
        free(ai);
        free(sa);
        return EAI_MEMORY;
    }
    ai->ai_family = AF_INET;
    ai->ai_socktype = hints ? hints->ai_socktype : 0;
    ai->ai_protocol = hints ? hints->ai_protocol : 0;
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_flags = hints ? hints->ai_flags : 0;
    sa->sin_family = AF_INET;
    sa->sin_port = htons(port);
    sa->sin_addr.s_addr = htonl(ip);
    ai->ai_addr = (struct sockaddr *)sa;
    if (canon) {
        ai->ai_canonname = strdup(canon);
        if (!ai->ai_canonname) {
            free(sa);
            free(ai);
            return EAI_MEMORY;
        }
    }
    *res = ai;
    return 0;
}

static void wolfip_free_addrinfo_list(struct addrinfo *res)
{
    while (res) {
        struct addrinfo *next = res->ai_next;
        free(res->ai_canonname);
        free(res->ai_addr);
        free(res);
        res = next;
    }
}

static int wolfip_register_gai_alloc(struct addrinfo *res)
{
    struct wolfip_gai_alloc *node = (struct wolfip_gai_alloc *)malloc(sizeof(struct wolfip_gai_alloc));
    if (!node) {
        wolfip_free_addrinfo_list(res);
        return EAI_MEMORY;
    }
    node->res = res;
    pthread_mutex_lock(&wolfip_gai_alloc_mutex);
    node->next = wolfip_gai_alloc_head;
    wolfip_gai_alloc_head = node;
    pthread_mutex_unlock(&wolfip_gai_alloc_mutex);
    return 0;
}

static int wolfip_take_gai_alloc(struct addrinfo *res)
{
    struct wolfip_gai_alloc **pp;
    struct wolfip_gai_alloc *cur;
    pthread_mutex_lock(&wolfip_gai_alloc_mutex);
    pp = &wolfip_gai_alloc_head;
    while ((cur = *pp) != NULL) {
        if (cur->res == res) {
            *pp = cur->next;
            pthread_mutex_unlock(&wolfip_gai_alloc_mutex);
            free(cur);
            return 1;
        }
        pp = &cur->next;
    }
    pthread_mutex_unlock(&wolfip_gai_alloc_mutex);
    return 0;
}

int wolfIP_sock_sendmsg(struct wolfIP *ipstack, int sockfd, const struct msghdr *msg, int flags)
{
    const struct wolfIP_sockaddr *dest = NULL;
    socklen_t addrlen = 0;
    size_t total_len = 0;
    int ret;
    uint8_t stack_buf[WOLFIP_IOV_STACK_BUF];
    uint8_t *heap_buf = NULL;
    const void *payload = NULL;

    if (wolfip_calc_msghdr_len(msg, &total_len) < 0)
        return -WOLFIP_EINVAL;
    if (msg->msg_name && msg->msg_namelen > 0) {
        dest = (const struct wolfIP_sockaddr *)msg->msg_name;
        addrlen = msg->msg_namelen;
    }
    if (msg->msg_iovlen == 1) {
        payload = msg->msg_iov[0].iov_base;
    } else if (total_len > 0) {
        uint8_t *tmp = stack_buf;
        if (total_len > sizeof(stack_buf)) {
            heap_buf = (uint8_t *)malloc(total_len);
            if (!heap_buf)
                return -WOLFIP_ENOMEM;
            tmp = heap_buf;
        }
        wolfip_flatten_iov(tmp, msg);
        payload = tmp;
    }

    ret = wolfIP_sock_sendto(ipstack, sockfd, payload, total_len, flags, dest, addrlen);
    if (heap_buf)
        free(heap_buf);
    if (ret == -WOLFIP_EAGAIN)
        return -EWOULDBLOCK;
    return ret;
}

int wolfIP_sock_recvmsg(struct wolfIP *ipstack, int sockfd, struct msghdr *msg, int flags)
{
    struct wolfIP_sockaddr *src = NULL;
    socklen_t addrlen = 0;
    size_t total_len = 0;
    int ret;
    uint8_t stack_buf[WOLFIP_IOV_STACK_BUF];
    uint8_t *heap_buf = NULL;
    uint8_t *buf = NULL;
    struct pollfd pfd;

    if (wolfip_calc_msghdr_len(msg, &total_len) < 0)
        return -WOLFIP_EINVAL;
    if (msg->msg_name && msg->msg_namelen > 0) {
        src = (struct wolfIP_sockaddr *)msg->msg_name;
        addrlen = msg->msg_namelen;
    }
    if (msg->msg_iovlen == 1) {
        buf = (uint8_t *)msg->msg_iov[0].iov_base;
    } else if (total_len > 0) {
        if (total_len > sizeof(stack_buf)) {
            heap_buf = (uint8_t *)malloc(total_len);
            if (!heap_buf)
                return -WOLFIP_ENOMEM;
            buf = heap_buf;
        } else {
            buf = stack_buf;
        }
    }

    pfd.fd = sockfd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    while (1) {
        ret = wolfIP_sock_recvfrom(ipstack, sockfd, buf ? buf : msg->msg_iov[0].iov_base,
                total_len, flags, src, src ? &addrlen : NULL);
        if (ret != -WOLFIP_EAGAIN)
            break;
        (void)wolfIP_sock_poll(ipstack, &pfd, 1, -1);
    }
    if (ret >= 0 && msg->msg_iovlen > 1) {
        wolfip_scatter_iov(msg, buf, (size_t)ret);
    }
    if (heap_buf)
        free(heap_buf);
    if (ret >= 0) {
        if (src)
            msg->msg_namelen = addrlen;
        msg->msg_flags = 0;
        wolfip_fill_ttl_control(ipstack, sockfd, msg);
    }
    if (ret == -WOLFIP_EAGAIN)
        return -EWOULDBLOCK;
    return ret;
}

int fcntl(int fd, int cmd, ...) {
    va_list ap;
    int arg = 0;
    int ret;
    va_start(ap, cmd);
    if (cmd != F_GETFD && cmd != F_GETFL) {
        arg = va_arg(ap, int);
    }
    va_end(ap);
    if (in_the_stack) {
        return host_fcntl(fd, cmd, arg);
    } else {
        pthread_mutex_lock(&wolfIP_mutex);
        ret = wolfIP_sock_fcntl(IPSTACK, fd, cmd, arg);
        if (ret == -WOLFIP_EINVAL) {
            pthread_mutex_unlock(&wolfIP_mutex);
            return host_fcntl(fd, cmd, arg);
        }
        pthread_mutex_unlock(&wolfIP_mutex);
        if (ret < 0) {
            errno = -ret;
            return -1;
        }
        return ret;
    }
}


void poller_callback(int fd, uint16_t event, void *arg)
{
    struct wolfip_fd_entry *entry;
    char c;
    char discard;
    ssize_t wr;
    (void)arg;
    entry = wolfip_entry_from_internal(fd);
    if (!entry)
        return;
    if ((event & CB_EVENT_WRITABLE) && (entry->events & POLLOUT)) {
        c = 'w';
    } else if ((event & CB_EVENT_READABLE) && (entry->events & POLLIN)) {
        c = 'r';
    } else if (event & CB_EVENT_CLOSED) {
        c = 'h';
    } else {
        return;
    }
    {
        uint8_t mask = wolfip_token_mask(c);
        if (mask && (entry->pending_tokens & mask)) {
            return;
        }
    }
    if (host_write)
        wr = host_write(entry->pipe_write, &c, 1);
    else
        wr = write(entry->pipe_write, &c, 1);
    if (wr > 0) {
        entry->pending_tokens |= wolfip_token_mask(c);
        return;
    }
    if (wr < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        /* Keep at least one token in the pipe: drop one stale byte then retry. */
        if (host_read(entry->public_fd, &discard, 1) > 0)
            wolfip_consume_token_locked(entry, discard);
        if (host_write)
            wr = host_write(entry->pipe_write, &c, 1);
        else
            wr = write(entry->pipe_write, &c, 1);
        if (wr > 0)
            entry->pending_tokens |= wolfip_token_mask(c);
    }
    if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        /* Best-effort wakeup only: close/teardown races can invalidate the
         * pipe while callbacks are still in flight, so hard errors are
         * intentionally ignored here. */
    }
}

int wolfIP_sock_poll(struct wolfIP *ipstack, struct pollfd *fds, nfds_t nfds, int timeout) {
    nfds_t i;
    int ret;
    if (in_the_stack) {
        return host_poll(fds, nfds, timeout);
    }
    for (i = 0; i < nfds; i++) {
        struct wolfip_fd_entry *entry = wolfip_entry_from_public(fds[i].fd);
        if (!entry)
            continue;
        entry->events = fds[i].events;
        /* Drain any stale notifications */
        wolfip_drain_pipe_locked(entry);
        wolfIP_register_callback(ipstack, entry->internal_fd, poller_callback, ipstack);
        fds[i].revents = 0;
        fds[i].fd = entry->public_fd;
    }
    pthread_mutex_unlock(&wolfIP_mutex);
    ret = host_poll(fds, nfds, timeout);
    pthread_mutex_lock(&wolfIP_mutex);
    if (ret > 0) {
        for (i = 0; i < nfds; i++) {
            struct wolfip_fd_entry *entry = wolfip_entry_from_public(fds[i].fd);
            short revents = 0;
            char c;
            if (!entry)
                continue;
            if (fds[i].revents & POLLIN) {
                while (host_read(entry->public_fd, &c, 1) > 0) {
                    wolfip_consume_token_locked(entry, c);
                    if (c == 'r')
                        revents |= POLLIN;
                    else if (c == 'w')
                        revents |= POLLOUT;
                    else if (c == 'e')
                        revents |= POLLERR;
                    else if (c == 'h')
                        revents |= POLLHUP;
                }
                if (revents == 0) {
                    wolfIP_register_callback(ipstack, entry->internal_fd, NULL, NULL);
                    entry->events = 0;
                }
            }
            fds[i].revents = revents & (entry->events | POLLERR | POLLHUP);
            fds[i].events = entry->events;
        }
    }
    return ret;
}

int wolfIP_sock_select(struct wolfIP *ipstack, int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    int i;
    int ret;
    int maxfd = nfds - 1;
    if (in_the_stack) {
        return host_select(nfds, readfds, writefds, exceptfds, timeout);
    }
    /* Arm callbacks for sockets present in fd_sets */
    for (i = 0; i < WOLFIP_MAX_PUBLIC_FDS; i++) {
        struct wolfip_fd_entry *entry;
        if (!wolfip_fd_entries[i].in_use)
            continue;
        entry = &wolfip_fd_entries[i];
        entry->events = 0;
        if (readfds && FD_ISSET(entry->public_fd, readfds))
            entry->events |= POLLIN;
        if (writefds && FD_ISSET(entry->public_fd, writefds))
            entry->events |= POLLOUT;
        if (exceptfds && FD_ISSET(entry->public_fd, exceptfds))
            entry->events |= POLLERR | POLLHUP;
        if (entry->events == 0)
            continue;
        wolfip_drain_pipe_locked(entry);
        wolfIP_register_callback(ipstack, entry->internal_fd, poller_callback, ipstack);
        if (entry->public_fd > maxfd)
            maxfd = entry->public_fd;
    }
    pthread_mutex_unlock(&wolfIP_mutex);
    ret = host_select(maxfd + 1, readfds, writefds, exceptfds, timeout);
    pthread_mutex_lock(&wolfIP_mutex);
    if (ret > 0) {
        int idx;
        for (idx = 0; idx < WOLFIP_MAX_PUBLIC_FDS; idx++) {
            struct wolfip_fd_entry *entry;
            char c;
            int saw_r = 0, saw_w = 0, saw_e = 0;
            if (!wolfip_fd_entries[idx].in_use)
                continue;
            entry = &wolfip_fd_entries[idx];
        if (entry->events == 0)
            continue;
        if ((readfds && FD_ISSET(entry->public_fd, readfds)) ||
            (writefds && FD_ISSET(entry->public_fd, writefds)) ||
            (exceptfds && FD_ISSET(entry->public_fd, exceptfds))) {
                while (host_read(entry->public_fd, &c, 1) > 0) {
                    wolfip_consume_token_locked(entry, c);
                    if (c == 'r')
                        saw_r = 1;
                    else if (c == 'w')
                        saw_w = 1;
                    else if (c == 'e' || c == 'h')
                        saw_e = 1;
                }
                if (!saw_r && !saw_w && !saw_e) {
                    /* No payload left; clear events to avoid busy wakeups */
                    wolfIP_register_callback(ipstack, entry->internal_fd, NULL, NULL);
                    entry->events = 0;
                }
                if (readfds && FD_ISSET(entry->public_fd, readfds) && !saw_r)
                    FD_CLR(entry->public_fd, readfds);
                if (writefds && FD_ISSET(entry->public_fd, writefds) && !saw_w)
                    FD_CLR(entry->public_fd, writefds);
                if (exceptfds && FD_ISSET(entry->public_fd, exceptfds) && !saw_e)
                    FD_CLR(entry->public_fd, exceptfds);
            }
        }
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
    int base_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    int internal_fd;
    int public_fd;
    if (in_the_stack) {
        return host_socket(domain, type, protocol);
    }
    internal_fd = wolfIP_sock_socket(IPSTACK, domain, base_type, protocol);
    if (internal_fd < 0) {
        errno = -internal_fd;
        return -1;
    }
    public_fd = wolfip_fd_alloc(internal_fd, (type & SOCK_NONBLOCK) ? 1 : 0);
    if (public_fd < 0) {
        wolfIP_sock_close(IPSTACK, internal_fd);
        errno = -public_fd;
        return -1;
    }
    return public_fd;
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
    int ret;
    struct wolfip_fd_entry *entry;
    if (in_the_stack) {
        return host_close(sockfd);
    }
    pthread_mutex_lock(&wolfIP_mutex);
    entry = wolfip_entry_from_public(sockfd);
    if (entry) {
        int internal_fd = entry->internal_fd;
        wolfip_fd_release(sockfd);
        ret = wolfIP_sock_close(IPSTACK, internal_fd);
        if (ret < 0) {
            errno = ret;
            pthread_mutex_unlock(&wolfIP_mutex);
            return -1;
        }
        pthread_mutex_unlock(&wolfIP_mutex);
        return ret;
    }
    pthread_mutex_unlock(&wolfIP_mutex);
    return host_close(sockfd);
}

/* Blocking calls */
static int wolfip_accept_common(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    int want_nonblock = (flags & SOCK_NONBLOCK) ? 1 : 0;
    struct wolfip_fd_entry *entry;
    struct pollfd pfd;

    if (in_the_stack) {
        if (flags)
            return host_accept4(sockfd, addr, addrlen, flags);
        return host_accept(sockfd, addr, addrlen);
    }
    pthread_mutex_lock(&wolfIP_mutex);
    entry = wolfip_entry_from_public(sockfd);
    if (entry) {
        int internal_ret;
        int public_fd;
        if (!want_nonblock)
            want_nonblock = wolfip_fd_is_nonblock(sockfd);
        do {
            internal_ret = wolfIP_sock_accept(IPSTACK, entry->internal_fd, addr, addrlen);
            if (internal_ret == -EAGAIN) {
                if (want_nonblock) {
                    errno = EAGAIN;
                    pthread_mutex_unlock(&wolfIP_mutex);
                    return -1;
                }
                entry->events = POLLIN;
                wolfIP_register_callback(IPSTACK, entry->internal_fd, poller_callback, IPSTACK);
                pfd.fd = entry->public_fd;
                pfd.events = POLLIN;
                pfd.revents = 0;
                pthread_mutex_unlock(&wolfIP_mutex);
                host_poll(&pfd, 1, -1);
                pthread_mutex_lock(&wolfIP_mutex);
                wolfip_drain_pipe_locked(entry);
            }
        } while (internal_ret == -EAGAIN);
        if (internal_ret < 0) {
            errno = internal_ret;
            pthread_mutex_unlock(&wolfIP_mutex);
            return -1;
        }
        public_fd = wolfip_fd_alloc(internal_ret, want_nonblock);
        if (public_fd < 0) {
            wolfIP_sock_close(IPSTACK, internal_ret);
            errno = -public_fd;
            pthread_mutex_unlock(&wolfIP_mutex);
            return -1;
        }
        pthread_mutex_unlock(&wolfIP_mutex);
        return public_fd;
    }
    pthread_mutex_unlock(&wolfIP_mutex);
    if (flags)
        return host_accept4(sockfd, addr, addrlen, flags);
    return host_accept(sockfd, addr, addrlen);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    return wolfip_accept_common(sockfd, addr, addrlen, 0);
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    return wolfip_accept_common(sockfd, addr, addrlen, flags);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    conditional_steal_blocking_call(connect, sockfd, POLLOUT, addr, addrlen);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *addrlen) {
    conditional_steal_blocking_call(recvfrom, sockfd, POLLIN, buf, len, flags, addr, addrlen);
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
    conditional_steal_blocking_call(recvmsg, sockfd, POLLIN, msg, flags);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    conditional_steal_blocking_call(recv, sockfd, POLLIN, buf, len, flags);
}

ssize_t read(int sockfd, void *buf, size_t len) {
    conditional_steal_blocking_call(read, sockfd, POLLIN, buf, len);
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    uint16_t port;
    struct addrinfo *ai;
    int ret;
    struct in_addr ipv4;
    char canon[256];
    if (in_the_stack || !res) {
        return host_getaddrinfo(node, service, hints, res);
    }
    if (!node) {
        struct in_addr local_ip;
        uint32_t ip_host;
        if (hints && (hints->ai_family != AF_UNSPEC) && (hints->ai_family != AF_INET))
            return EAI_FAMILY;
        ret = wolfip_parse_service(service, &port);
        if (ret != 0)
            return ret;
        if (hints && (hints->ai_flags & AI_PASSIVE)) {
            ip_host = 0; /* INADDR_ANY */
            canon[0] = '\0';
        } else {
            inet_aton(WOLFIP_IP, &local_ip);
            ip_host = ntohl(local_ip.s_addr);
            wolfip_strlcpy(canon, WOLFIP_IP, sizeof(canon));
        }
        ret = wolfip_build_addrinfo(ip_host, port, canon[0] ? canon : NULL, hints, &ai);
        if (ret != 0)
            return ret;
        ret = wolfip_register_gai_alloc(ai);
        if (ret != 0)
            return ret;
        *res = ai;
        return 0;
    }
    ret = wolfip_parse_service(service, &port);
    if (ret != 0)
        return ret;
    if (hints && (hints->ai_family != AF_UNSPEC) && (hints->ai_family != AF_INET))
        return EAI_FAMILY;
    if (inet_pton(AF_INET, node, &ipv4) == 1) {
        uint32_t ip_host = ntohl(ipv4.s_addr);
        canon[0] = '\0';
        if (hints && (hints->ai_flags & AI_CANONNAME) && !(hints->ai_flags & AI_NUMERICHOST)) {
            if (wolfip_dns_reverse_query(ip_host, canon, sizeof(canon)) != 0)
                wolfip_strlcpy(canon, node, sizeof(canon));
        } else if (hints && (hints->ai_flags & AI_CANONNAME)) {
            wolfip_strlcpy(canon, node, sizeof(canon));
        }
        ret = wolfip_build_addrinfo(ip_host, port, canon[0] ? canon : NULL, hints, &ai);
        if (ret != 0)
            return ret;
        ret = wolfip_register_gai_alloc(ai);
        if (ret != 0)
            return ret;
        *res = ai;
        return 0;
    } else if (hints && (hints->ai_flags & AI_NUMERICHOST)) {
        return EAI_NONAME;
    }
    {
        uint32_t ip_host;
        ret = wolfip_dns_forward_query(node, &ip_host);
        if (ret != 0)
            return ret;
        if (hints && (hints->ai_flags & AI_CANONNAME))
            wolfip_strlcpy(canon, node, sizeof(canon));
        else
            canon[0] = '\0';
        ret = wolfip_build_addrinfo(ip_host, port,
                (hints && (hints->ai_flags & AI_CANONNAME)) ? canon : NULL,
                hints, &ai);
        if (ret != 0)
            return ret;
        ret = wolfip_register_gai_alloc(ai);
        if (ret != 0)
            return ret;
        *res = ai;
        return 0;
    }
}

void freeaddrinfo(struct addrinfo *res) {
    if (!res) {
        return;
    }
    if (wolfip_take_gai_alloc(res)) {
        wolfip_free_addrinfo_list(res);
    } else {
        host_freeaddrinfo(res);
    }
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen) {
    int internal_fd;
    int nonblock;
    int is_stream;
    int ret;
    int wait_ret;
    struct wolfip_fd_entry *entry;
    size_t sent = 0;

    if (in_the_stack) {
        return host_sendto(sockfd, buf, len, flags, addr, addrlen);
    }
    pthread_mutex_lock(&wolfIP_mutex);
    internal_fd = wolfip_fd_internal_from_public(sockfd);
    if (internal_fd < 0) {
        pthread_mutex_unlock(&wolfIP_mutex);
        return host_sendto(sockfd, buf, len, flags, addr, addrlen);
    }
    nonblock = wolfip_fd_is_nonblock(sockfd);
    is_stream = IS_SOCKET_TCP(internal_fd) ? 1 : 0;
    entry = wolfip_entry_from_public(sockfd);
    while (sent < len) {
        ret = wolfIP_sock_sendto(IPSTACK, internal_fd, (const uint8_t *)buf + sent,
                len - sent, flags,
                (const struct wolfIP_sockaddr *)addr, addrlen);
        if (ret > 0) {
            sent += (size_t)ret;
            if (nonblock || !is_stream)
                break;
            continue;
        }
        if (ret == -EAGAIN) {
            if (nonblock) {
                if (sent == 0)
                    errno = EAGAIN;
                else
                    errno = 0;
                pthread_mutex_unlock(&wolfIP_mutex);
                return (sent == 0) ? -1 : (ssize_t)sent;
            }
            if (entry) {
                wait_ret = wolfip_wait_for_event_locked(entry, POLLOUT, entry->snd_timeout_ms);
                if (wait_ret < 0) {
                    errno = -wait_ret;
                    pthread_mutex_unlock(&wolfIP_mutex);
                    return -1;
                }
            } else {
                pthread_mutex_unlock(&wolfIP_mutex);
                usleep(1000);
                pthread_mutex_lock(&wolfIP_mutex);
            }
            continue;
        }
        if (ret < 0) {
            errno = -ret;
            pthread_mutex_unlock(&wolfIP_mutex);
            return -1;
        }
    }
    pthread_mutex_unlock(&wolfIP_mutex);
    errno = 0;
    return (ssize_t)sent;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    conditional_steal_blocking_call(sendmsg, sockfd, POLLOUT, msg, flags);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    int internal_fd;
    int nonblock;
    int ret;
    int wait_ret;
    struct wolfip_fd_entry *entry;
    size_t sent = 0;

    if (in_the_stack) {
        return host_send(sockfd, buf, len, flags);
    }
    pthread_mutex_lock(&wolfIP_mutex);
    internal_fd = wolfip_fd_internal_from_public(sockfd);
    if (internal_fd < 0) {
        pthread_mutex_unlock(&wolfIP_mutex);
        return host_send(sockfd, buf, len, flags);
    }
    nonblock = wolfip_fd_is_nonblock(sockfd);
    entry = wolfip_entry_from_public(sockfd);
    while (sent < len) {
        ret = wolfIP_sock_send(IPSTACK, internal_fd, (const uint8_t *)buf + sent, len - sent, flags);
        if (ret > 0) {
            sent += (size_t)ret;
            if (nonblock)
                break;
            continue;
        }
        if (ret == -EAGAIN) {
            if (nonblock) {
                if (sent == 0) {
                    errno = EAGAIN;
                    pthread_mutex_unlock(&wolfIP_mutex);
                    return -1;
                }
                pthread_mutex_unlock(&wolfIP_mutex);
                errno = 0;
                return (ssize_t)sent;
            }
            if (entry) {
                wait_ret = wolfip_wait_for_event_locked(entry, POLLOUT, entry->snd_timeout_ms);
                if (wait_ret < 0) {
                    errno = -wait_ret;
                    pthread_mutex_unlock(&wolfIP_mutex);
                    return -1;
                }
            } else {
                pthread_mutex_unlock(&wolfIP_mutex);
                usleep(1000);
                pthread_mutex_lock(&wolfIP_mutex);
            }
            continue;
        }
        errno = -ret;
        pthread_mutex_unlock(&wolfIP_mutex);
        return -1;
    }
    pthread_mutex_unlock(&wolfIP_mutex);
    errno = 0;
    return (ssize_t)sent;
}

ssize_t write(int sockfd, const void *buf, size_t len) {
    int internal_fd;
    int nonblock;
    int ret;
    int wait_ret;
    struct wolfip_fd_entry *entry;
    size_t sent = 0;

    if (in_the_stack) {
        return host_write(sockfd, buf, len);
    }
    pthread_mutex_lock(&wolfIP_mutex);
    internal_fd = wolfip_fd_internal_from_public(sockfd);
    if (internal_fd < 0) {
        pthread_mutex_unlock(&wolfIP_mutex);
        return host_write(sockfd, buf, len);
    }
    nonblock = wolfip_fd_is_nonblock(sockfd);
    entry = wolfip_entry_from_public(sockfd);
    while (sent < len) {
        ret = wolfIP_sock_write(IPSTACK, internal_fd, (const uint8_t *)buf + sent, len - sent);
        if (ret > 0) {
            sent += (size_t)ret;
            if (nonblock)
                break;
            continue;
        }
        if (ret == -EAGAIN) {
            if (nonblock) {
                if (sent == 0) {
                    errno = EAGAIN;
                    pthread_mutex_unlock(&wolfIP_mutex);
                    return -1;
                }
                pthread_mutex_unlock(&wolfIP_mutex);
                errno = 0;
                return (ssize_t)sent;
            }
            if (entry) {
                wait_ret = wolfip_wait_for_event_locked(entry, POLLOUT, entry->snd_timeout_ms);
                if (wait_ret < 0) {
                    errno = -wait_ret;
                    pthread_mutex_unlock(&wolfIP_mutex);
                    return -1;
                }
            } else {
                pthread_mutex_unlock(&wolfIP_mutex);
                usleep(1000);
                pthread_mutex_lock(&wolfIP_mutex);
            }
            continue;
        }
        errno = -ret;
        pthread_mutex_unlock(&wolfIP_mutex);
        return -1;
    }
    pthread_mutex_unlock(&wolfIP_mutex);
    errno = 0;
    return (ssize_t)sent;
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



/* Network device initialization: VDE or TAP */
#if WOLFIP_USE_VDE
#include "src/port/vde2/vde_device.h"
#else
/* Catch-all function to initialize a new tap device as the network interface.
 * Implemented in port/posix/tap_*.c
 */
extern int tap_init(struct wolfIP_ll_dev *dev, const char *name, uint32_t host_ip);
#endif

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
    struct in_addr host_stack_ip;
    const char *host_stack_ip_str;
    const char *wolfip_ip_str;
    const char *wolfip_mask_str;
    struct wolfIP_ll_dev *tapdev;
    pthread_t wolfIP_thread;
#if WOLFIP_POSIX_TCPDUMP
    static int tcpdump_atexit_registered;
#endif
    if (IPSTACK)
        return;
    host_stack_ip_str = getenv("WOLFIP_HOST_IP");
    if (!host_stack_ip_str || host_stack_ip_str[0] == '\0') {
        host_stack_ip_str = HOST_STACK_IP;
    }
    wolfip_ip_str = getenv("WOLFIP_IP_ADDR");
    if (!wolfip_ip_str || wolfip_ip_str[0] == '\0') {
        wolfip_ip_str = WOLFIP_IP;
    }
    wolfip_mask_str = getenv("WOLFIP_NETMASK");
    if (!wolfip_mask_str || wolfip_mask_str[0] == '\0') {
        wolfip_mask_str = "255.255.255.0";
    }
    fprintf(stderr, "wolfIP: Serving process PID=%hu, TID=%x\n", getpid(), (unsigned short)pthread_self());
    inet_aton(host_stack_ip_str, &host_stack_ip);
    swap_socketcall(socket, "socket");
    swap_socketcall(bind, "bind");
    swap_socketcall(listen, "listen");
    swap_socketcall(accept, "accept");
    swap_socketcall(accept4, "accept4");
    swap_socketcall(connect, "connect");
    swap_socketcall(sendto, "sendto");
    swap_socketcall(sendmsg, "sendmsg");
    swap_socketcall(recvfrom, "recvfrom");
    swap_socketcall(recvmsg, "recvmsg");
    swap_socketcall(recv, "recv");
    swap_socketcall(send, "send");
    swap_socketcall(close, "close");
    swap_socketcall(write, "write");
    swap_socketcall(read, "read");
    swap_socketcall(getsockname, "getsockname");
    swap_socketcall(getpeername, "getpeername");
    swap_socketcall(setsockopt, "setsockopt");
    swap_socketcall(getsockopt, "getsockopt");
    swap_socketcall(getaddrinfo, "getaddrinfo");
    swap_socketcall(freeaddrinfo, "freeaddrinfo");
    swap_socketcall(poll, "poll");
    swap_socketcall(select, "select");
    swap_socketcall(fcntl, "fcntl");

    pthread_mutex_init(&wolfIP_mutex, NULL);
    wolfIP_init_static(&IPSTACK);
    tapdev = wolfIP_getdev(IPSTACK);
#if WOLFIP_USE_VDE
    {
        const char *vde_socket = getenv("VDE_SOCKET_PATH");
        if (!vde_socket) {
            vde_socket = "/tmp/vde_switch.ctl";
        }
        if (vde_init(tapdev, vde_socket, NULL, NULL) < 0) {
            perror("vde init");
            return;
        }
    }
#else
    if (tap_init(tapdev, "wtcp0", host_stack_ip.s_addr) < 0) {
        perror("tap init");
        return;
    }
#endif
#if WOLFIP_POSIX_TCPDUMP
    if (!tcpdump_atexit_registered) {
        atexit(wolfIP_stop_tcpdump_atexit);
        tcpdump_atexit_registered = 1;
    }
    wolfIP_start_tcpdump((tapdev && tapdev->ifname[0]) ? tapdev->ifname : "wtcp0");
#endif
    wolfIP_ipconfig_set(IPSTACK, atoip4(wolfip_ip_str), atoip4(wolfip_mask_str),
            atoip4(host_stack_ip_str));
    fprintf(stderr, "IP: manually configured - %s\n", wolfip_ip_str);
    /* Avoid penalizing startup fairness across stacks: once init is done,
     * hand control to the poll thread immediately. */
    pthread_create(&wolfIP_thread, NULL, wolfIP_sock_posix_ip_loop, IPSTACK);
    in_the_stack = 0;
}

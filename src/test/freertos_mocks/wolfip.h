#ifndef TEST_FREERTOS_WOLFIP_H
#define TEST_FREERTOS_WOLFIP_H

#include <stddef.h>
#include <stdint.h>

typedef uint32_t socklen_t;

struct wolfIP {
    int dummy;
};

struct wolfIP_sockaddr {
    uint16_t sa_family;
    char sa_data[14];
};

typedef void (*tsocket_cb)(int fd, uint16_t event, void *arg);

#define AF_INET 2
#define IPSTACK_SOCK_STREAM 1
#define IPSTACK_SOCK_DGRAM 2

#define WOLFIP_EAGAIN 11
#define WOLFIP_EINVAL 22
#define WOLFIP_ENOMEM 12

#define MARK_TCP_SOCKET 0x100
#define IS_SOCKET_TCP(fd) (((fd) & MARK_TCP_SOCKET) == MARK_TCP_SOCKET)

#define CB_EVENT_READABLE 0x0001
#define CB_EVENT_WRITABLE 0x0002
#define CB_EVENT_CLOSED   0x0004

int wolfIP_poll(struct wolfIP *ipstack, uint64_t now_ms);
int wolfIP_sock_socket(struct wolfIP *s, int domain, int type, int protocol);
int wolfIP_sock_bind(struct wolfIP *s, int fd, const struct wolfIP_sockaddr *addr, socklen_t len);
int wolfIP_sock_listen(struct wolfIP *s, int fd, int backlog);
int wolfIP_sock_accept(struct wolfIP *s, int fd, struct wolfIP_sockaddr *addr, socklen_t *len);
int wolfIP_sock_connect(struct wolfIP *s, int fd, const struct wolfIP_sockaddr *addr, socklen_t len);
int wolfIP_sock_send(struct wolfIP *s, int fd, const void *buf, size_t len, int flags);
int wolfIP_sock_sendto(struct wolfIP *s, int fd, const void *buf, size_t len, int flags,
    const struct wolfIP_sockaddr *dest_addr, socklen_t len2);
int wolfIP_sock_recv(struct wolfIP *s, int fd, void *buf, size_t len, int flags);
int wolfIP_sock_recvfrom(struct wolfIP *s, int fd, void *buf, size_t len, int flags,
    struct wolfIP_sockaddr *src_addr, socklen_t *len2);
int wolfIP_sock_setsockopt(struct wolfIP *s, int fd, int level, int optname,
    const void *optval, socklen_t optlen);
int wolfIP_sock_getsockopt(struct wolfIP *s, int fd, int level, int optname,
    void *optval, socklen_t *optlen);
int wolfIP_sock_getsockname(struct wolfIP *s, int fd, struct wolfIP_sockaddr *addr, socklen_t *len);
int wolfIP_sock_getpeername(struct wolfIP *s, int fd, struct wolfIP_sockaddr *addr, socklen_t *len);
int wolfIP_sock_can_write(struct wolfIP *s, int fd);
int wolfIP_sock_can_read(struct wolfIP *s, int fd);
int wolfIP_sock_close(struct wolfIP *s, int fd);
void wolfIP_register_callback(struct wolfIP *s, int fd, tsocket_cb cb, void *arg);

#endif

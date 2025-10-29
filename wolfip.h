#ifndef WOLFIP_H
#define WOLFIP_H
#include <stdint.h>

/* Types */
struct wolfIP;
typedef uint32_t ip4;

/* Macros, compiler specific. */
#define PACKED __attribute__((packed))
#define ee16(x) __builtin_bswap16(x)
#define ee32(x) __builtin_bswap32(x)
#define DEBUG


#ifdef DEBUG
    #include <stdio.h>
    #define LOG(fmt, ...) printf(fmt, ##__VA_ARGS__)
    #else
    #define LOG(fmt, ...) do{}while(0)
#endif /* DEBUG */

/* Device driver interface */
/* Struct to contain a hw device description */
struct ll {
    uint8_t mac[6];
    char ifname[16];
    /* poll function */
    int (*poll)(struct ll *ll, void *buf, uint32_t len);
    /* send function */
    int (*send)(struct ll *ll, void *buf, uint32_t len);
};

/* Struct to contain an IP device configuration */
struct ipconf {
    struct ll *ll;
    ip4 ip;
    ip4 mask;
    ip4 gw;
};

/* Socket interface */
#define MARK_TCP_SOCKET 0x100 /* Mark a socket as TCP */
#define MARK_UDP_SOCKET 0x200 /* Mark a socket as UDP */
#if (MARK_TCP_SOCKET >= MARK_UDP_SOCKET)
    #error "MARK_TCP_SOCKET must be less than MARK_UDP_SOCKET"
#endif /* MARK_TCP_SOCKET >= MARK_UDP_SOCKET */


#ifndef WOLF_POSIX
    #define IPSTACK_SOCK_STREAM 1
    #define IPSTACK_SOCK_DGRAM 2

    struct wolfIP_sockaddr_in {
        uint16_t sin_family;
        uint16_t sin_port;
        struct sin_addr { uint32_t s_addr; } sin_addr;
    };
    struct wolfIP_sockaddr { uint16_t sa_family; };
    typedef uint32_t socklen_t;
    #ifndef AF_INET
        #define AF_INET 2
    #endif /* !AF_INET */
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define wolfIP_sockaddr_in sockaddr_in
    #define wolfIP_sockaddr sockaddr
#endif /* !WOLF_POSIX */

int wolfIP_sock_socket(struct wolfIP *s, int domain, int type, int protocol);
int wolfIP_sock_bind(struct wolfIP *s, int sockfd,
                     const struct wolfIP_sockaddr *addr, socklen_t addrlen);
int wolfIP_sock_listen(struct wolfIP *s, int sockfd, int backlog);
int wolfIP_sock_accept(struct wolfIP *s, int sockfd,
                       struct wolfIP_sockaddr *addr, socklen_t *addrlen);
int wolfIP_sock_connect(struct wolfIP *s, int sockfd,
                        const struct wolfIP_sockaddr *addr, socklen_t addrlen);
int wolfIP_sock_sendto(struct wolfIP *s, int sockfd, const void *buf,
                       size_t len, int flags, const struct wolfIP_sockaddr *dest_addr,
                       socklen_t addrlen);
int wolfIP_sock_send(struct wolfIP *s, int sockfd, const void *buf, size_t len,
                     int flags);
int wolfIP_sock_write(struct wolfIP *s, int sockfd, const void *buf, size_t len);
int wolfIP_sock_recvfrom(struct wolfIP *s, int sockfd, void *buf, size_t len,
                         int flags, struct wolfIP_sockaddr *src_addr, socklen_t *addrlen);
int wolfIP_sock_recv(struct wolfIP *s, int sockfd, void *buf, size_t len, int flags);
int wolfIP_sock_read(struct wolfIP *s, int sockfd, void *buf, size_t len);
int wolfIP_sock_close(struct wolfIP *s, int sockfd);
int wolfIP_sock_getpeername(struct wolfIP *s, int sockfd, struct wolfIP_sockaddr *addr,
                            const socklen_t *addrlen);
int wolfIP_sock_getsockname(struct wolfIP *s, int sockfd, struct wolfIP_sockaddr *addr,
                            const socklen_t *addrlen);

int dhcp_client_init(struct wolfIP *s);
int dhcp_bound(struct wolfIP *s);

/* DNS client */
int nslookup(struct wolfIP *s, const char *name, uint16_t *id,
             void (*lookup_cb)(uint32_t ip));

/* IP stack interface */
void wolfIP_init(struct wolfIP *s);
void wolfIP_init_static(struct wolfIP **s);
int wolfIP_poll(struct wolfIP *s, uint64_t now);
void wolfIP_recv(struct wolfIP *s, void *buf, uint32_t len);
void wolfIP_ipconfig_set(struct wolfIP *s, ip4 ip, ip4 mask, ip4 gw);
void wolfIP_ipconfig_get(struct wolfIP *s, ip4 *ip, ip4 *mask, ip4 *gw);

struct ll *wolfIP_getdev(struct wolfIP *s);

/* Callback flags */
#define CB_EVENT_READABLE 0x01 /* Accepted connection or data available */
#define CB_EVENT_TIMEOUT 0x02  /* Timeout */
#define CB_EVENT_WRITABLE 0x04 /* Connected or space available to send */
#define CB_EVENT_CLOSED 0x10   /* Connection closed by peer */
void wolfIP_register_callback(struct wolfIP *s, int sock_fd,
                              void (*cb)(int sock_fd, uint16_t events, void *arg),
                              void *arg);

/* External requirements */
uint32_t wolfIP_getrandom(void);

/* Inline utility functions */
static inline uint32_t atou(const char *s)
{
    uint32_t ret = 0;
    while (*s >= '0' && *s <= '9') {
        ret = ret * 10 + (*s - '0');
        s++;
    }
    return ret;
}

static inline ip4 atoip4(const char *ip)
{
    ip4 ret = 0;
    int i = 0;
    int j = 0;
    for (i = 0; i < 4; i++) {
        ret |= (atou(ip + j) << (24 - i * 8));
        while (ip[j] != '.' && ip[j] != '\0') j++;
        if (ip[j] == '\0') break;
        j++;
    }
    return ret;
}

static inline void iptoa(ip4 ip, char *buf)
{
    int i, j = 0;
    buf[0] = 0;
    for (i = 0; i < 4; i++) {
        uint8_t x = (ip >> (24 - i * 8)) & 0xFF;
        if (x > 99) buf[j++] = x / 100 + '0';
        if (x > 9) buf[j++] = (x / 10) % 10 + '0';
        buf[j++] = x % 10 + '0';
        if (i < 3) buf[j++] = '.';
    }
    buf[j] = 0;
}

#ifdef WOLFSSL_WOLFIP
    #ifdef WOLFSSL_USER_SETTINGS
        #include "user_settings.h"
        #else
        #include <wolfssl/options.h>
    #endif /* WOLFSSL_USER_SETTINGS */
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/ssl.h>
    /* Defined in wolfssl_io.c */
    int wolfSSL_SetIO_FT(WOLFSSL* ssl, int fd);
    int wolfSSL_SetIO_FT_CTX(WOLFSSL_CTX *ctx, struct wolfIP *s);

    #ifdef  WOLFIP_ESP
        #include <wolfssl/wolfcrypt/aes.h>
        #include <wolfssl/wolfcrypt/des3.h>
        #include <wolfssl/wolfcrypt/hmac.h>
    #endif /* WOLFIP_ESP */
#endif /* WOLFSSL_WOLFIP */

#endif /* !WOLFIP_H */

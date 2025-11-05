/* test_wolfssl_forwarding.c
 *
 * Simplified forwarding test that exercises a wolfIP TLS echo server
 * reachable through a wolfIP router while the client runs on the host
 * using the Linux TCP/IP stack.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

#include "config.h"

#ifndef WOLFIP_MAX_INTERFACES
#define WOLFIP_MAX_INTERFACES 2
#endif

#ifndef WOLFIP_ENABLE_FORWARDING
#define WOLFIP_ENABLE_FORWARDING 1
#endif

#include "wolfip.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/memory.h>

extern const unsigned char ca_der[];
extern const unsigned long ca_der_len;
extern const unsigned char server_der[];
extern const unsigned long server_der_len;
extern const unsigned char server_key_der[];
extern const unsigned long server_key_der_len;

extern int tap_init(struct wolfIP_ll_dev *dev, const char *name, uint32_t host_ip);

#define IP4(a,b,c,d) (((ip4)(a) << 24) | ((ip4)(b) << 16) | ((ip4)(c) << 8) | (ip4)(d))

#define TEST_PAYLOAD 1024
#define TAP_IFNAME   "wtls0"
#define HOST_ROUTE   "10.20.2.0/24"

static const ip4 host_ip4          = IP4(10,20,1,2);
static const ip4 router_lan_ip4    = IP4(10,20,1,254);
static const ip4 router_wan_ip4    = IP4(10,20,2,1);
static const ip4 server_ip4        = IP4(10,20,2,2);

static pthread_t th_server;
static pthread_t th_router;

static struct wolfIP *router_stack;
static struct wolfIP *server_stack;

static int server_listen_fd = -1;
static int server_client_fd = -1;
static WOLFSSL_CTX *server_ctx = NULL;
static WOLFSSL *server_ssl = NULL;
static uint8_t server_buf[TEST_PAYLOAD];
static int server_bytes_recv = 0;
static int server_bytes_sent = 0;
static volatile int server_done = 0;
static int server_handshake_done = 0;

static volatile int router_running = 1;

static void ip4_to_str(ip4 addr, char *buf, size_t len)
{
    snprintf(buf, len, "%u.%u.%u.%u",
            (unsigned)((addr >> 24) & 0xFF),
            (unsigned)((addr >> 16) & 0xFF),
            (unsigned)((addr >> 8) & 0xFF),
            (unsigned)(addr & 0xFF));
}

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

static void wolfip_reset_io(WOLFSSL *ssl)
{
    void *ctx;
    if (!ssl)
        return;
    ctx = wolfSSL_GetIOReadCtx(ssl);
    if (ctx) {
        wolfSSL_SetIOReadCtx(ssl, NULL);
        wolfSSL_SetIOWriteCtx(ssl, NULL);
    }
}

/* ------------------------------------------------------------------------- */
/* In-memory link layer                                                      */
/* ------------------------------------------------------------------------- */

struct mem_link {
    pthread_mutex_t lock;
    pthread_cond_t cond[2];
    uint8_t buf[2][LINK_MTU];
    uint32_t len[2];
    int ready[2];
    const char *name[2];
};

struct mem_ep {
    struct wolfIP_ll_dev *ll;
    struct mem_link *link;
    int idx;
};

static struct mem_ep mem_eps[8];
static size_t mem_ep_count;

static void mem_link_init(struct mem_link *link)
{
    pthread_mutex_init(&link->lock, NULL);
    pthread_cond_init(&link->cond[0], NULL);
    pthread_cond_init(&link->cond[1], NULL);
    link->ready[0] = link->ready[1] = 0;
    link->len[0] = link->len[1] = 0;
    link->name[0] = link->name[1] = "";
}

static struct mem_ep *mem_ep_lookup(struct wolfIP_ll_dev *ll)
{
    for (size_t i = 0; i < mem_ep_count; i++) {
        if (mem_eps[i].ll == ll)
            return &mem_eps[i];
    }
    return NULL;
}

static int mem_ll_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct mem_ep *ep = mem_ep_lookup(ll);
    struct mem_link *link;
    int idx;
    int ret = 0;

    if (!ep)
        return -1;
    link = ep->link;
    idx = ep->idx;

    pthread_mutex_lock(&link->lock);
    if (link->ready[idx]) {
        uint32_t copy = link->len[idx];
        if (copy > len)
            copy = len;
        memcpy(buf, link->buf[idx], copy);
        link->ready[idx] = 0;
        pthread_cond_signal(&link->cond[idx]);
        ret = (int)copy;
    }
    pthread_mutex_unlock(&link->lock);
    return ret;
}

static int mem_ll_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct mem_ep *ep = mem_ep_lookup(ll);
    struct mem_link *link;
    int dst;

    if (!ep)
        return -1;
    link = ep->link;
    dst = 1 - ep->idx;

    pthread_mutex_lock(&link->lock);
    while (link->ready[dst])
        pthread_cond_wait(&link->cond[dst], &link->lock);
    if (len > LINK_MTU)
        len = LINK_MTU;
    memcpy(link->buf[dst], buf, len);
    link->len[dst] = len;
    link->ready[dst] = 1;
    pthread_cond_signal(&link->cond[dst]);
    pthread_mutex_unlock(&link->lock);
    return (int)len;
}

static void mem_link_attach(struct wolfIP_ll_dev *ll, struct mem_link *link, int idx,
        const char *ifname, const uint8_t mac[6])
{
    ll->poll = mem_ll_poll;
    ll->send = mem_ll_send;
    snprintf(ll->ifname, sizeof(ll->ifname), "%s", ifname);
    memcpy(ll->mac, mac, 6);
    link->name[idx] = ifname;
    mem_eps[mem_ep_count++] = (struct mem_ep){ .ll = ll, .link = link, .idx = idx };
}

/* ------------------------------------------------------------------------- */
/* TLS echo server (wolfIP stack)                                           */
/* ------------------------------------------------------------------------- */

static void server_cb(int fd, uint16_t events, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    (void)events;
    if (fd == server_listen_fd && (events & CB_EVENT_READABLE) && server_client_fd == -1) {
        server_client_fd = wolfIP_sock_accept(s, server_listen_fd, NULL, NULL);
        if (server_client_fd > 0) {
            wolfIP_register_callback(s, server_client_fd, server_cb, s);
            server_ssl = wolfSSL_new(server_ctx);
            wolfSSL_SetIO_wolfIP(server_ssl, server_client_fd);
            server_handshake_done = 0;
            server_bytes_recv = 0;
            server_bytes_sent = 0;
            printf("TLS server: accepted client (fd 0x%04x)\n", server_client_fd);
        }
        return;
    }

    if (fd != server_client_fd || server_ssl == NULL)
        return;

    if (!server_handshake_done) {
        int ret = wolfSSL_accept(server_ssl);
        if (ret == SSL_SUCCESS) {
            server_handshake_done = 1;
            printf("TLS server: handshake complete\n");
        } else {
            int err = wolfSSL_get_error(server_ssl, ret);
            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE)
                return;
            fprintf(stderr, "TLS server: handshake failed (%d)\n", err);
            wolfIP_sock_close(s, server_client_fd);
            server_client_fd = -1;
            wolfip_reset_io(server_ssl);
            wolfSSL_free(server_ssl);
            server_ssl = NULL;
            server_done = 1;
            return;
        }
    }

    if (events & (CB_EVENT_READABLE | CB_EVENT_WRITABLE)) {
        if (server_bytes_recv < TEST_PAYLOAD) {
            int ret = wolfSSL_read(server_ssl, server_buf + server_bytes_recv,
                    TEST_PAYLOAD - server_bytes_recv);
            if (ret > 0) {
                server_bytes_recv += ret;
            }
        }
        if (server_bytes_recv == TEST_PAYLOAD && server_bytes_sent < TEST_PAYLOAD) {
            int ret = wolfSSL_write(server_ssl, server_buf + server_bytes_sent,
                    TEST_PAYLOAD - server_bytes_sent);
            if (ret > 0) {
                server_bytes_sent += ret;
            }
        }
        if (server_bytes_sent == TEST_PAYLOAD) {
            wolfIP_sock_close(s, server_client_fd);
            server_client_fd = -1;
            wolfip_reset_io(server_ssl);
            wolfSSL_free(server_ssl);
            server_ssl = NULL;
            server_handshake_done = 0;
            server_done = 1;
            printf("TLS server: echoed %d bytes\n", TEST_PAYLOAD);
        }
    }

    if (events & CB_EVENT_CLOSED) {
        if (server_ssl) {
            wolfip_reset_io(server_ssl);
            wolfSSL_free(server_ssl);
            server_ssl = NULL;
        }
        server_client_fd = -1;
        server_handshake_done = 0;
        server_done = 1;
    }
}

static int server_setup(struct wolfIP *s)
{
    struct wolfIP_sockaddr_in local = {
        .sin_family = AF_INET,
        .sin_port = ee16(4433),
        .sin_addr.s_addr = 0,
    };

    server_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!server_ctx)
        return -1;
    wolfSSL_SetIO_wolfIP_CTX(server_ctx, s);

    if (wolfSSL_CTX_use_certificate_buffer(server_ctx, server_der,
                server_der_len, SSL_FILETYPE_ASN1) != SSL_SUCCESS)
        return -1;
    if (wolfSSL_CTX_use_PrivateKey_buffer(server_ctx, server_key_der,
                server_key_der_len, SSL_FILETYPE_ASN1) != SSL_SUCCESS)
        return -1;

    server_listen_fd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (server_listen_fd < 0)
        return -1;
    wolfIP_register_callback(s, server_listen_fd, server_cb, s);
    if (wolfIP_sock_bind(s, server_listen_fd, (struct wolfIP_sockaddr *)&local,
                sizeof(local)) < 0)
        return -1;
    if (wolfIP_sock_listen(s, server_listen_fd, 1) < 0)
        return -1;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Stack polling                                                             */
/* ------------------------------------------------------------------------- */

static void *poll_thread(void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    while (1) {
        uint64_t now = monotonic_ms();
        wolfIP_poll(s, now);
        usleep(1000);
        if (s == router_stack) {
            if (!router_running)
                break;
        } else if (s == server_stack) {
            if (server_done)
                break;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Linux TLS client                                                          */
/* ------------------------------------------------------------------------- */

static int run_linux_tls_client(ip4 server_ip)
{
    struct sockaddr_in remote = {
        .sin_family = AF_INET,
        .sin_port = htons(4433),
        .sin_addr.s_addr = htonl(server_ip),
    };
    uint8_t tx[TEST_PAYLOAD];
    uint8_t rx[TEST_PAYLOAD];
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    int fd = -1;
    int ret = -1;
    int err = 0;
    size_t sent = 0;
    size_t received = 0;
    int connected = 0;
    char remote_str[16];

    sleep(1);
    ip4_to_str(server_ip, remote_str, sizeof(remote_str));
    printf("TLS client: connecting to %s:%u\n", remote_str, 4433);

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) {
        fprintf(stderr, "linux client: failed to init context\n");
        goto out;
    }
    wolfSSL_CTX_load_verify_buffer(ctx, ca_der, ca_der_len, SSL_FILETYPE_ASN1);

    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "linux client: failed to allocate ssl object\n");
        goto out;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        goto out;
    }
    wolfSSL_set_fd(ssl, fd);

    for (int attempt = 0; attempt < 50; attempt++) {
        int cret;
        cret = connect(fd, (struct sockaddr *)&remote, sizeof(remote));
        if (cret == 0) {
            connected = 1;
            printf("TLS client: TCP connected\n");
            break;
        }
        if (errno == EINPROGRESS) {
            if (wolfSSL_get_using_nonblock(ssl) == 0)
                wolfSSL_set_using_nonblock(ssl, 1);
            if (poll(&(struct pollfd){ .fd = fd, .events = POLLOUT }, 1, 100) > 0) {
                socklen_t errlen = sizeof(err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == 0 && err == 0) {
                    connected = 1;
                    printf("TLS client: TCP connect completed after wait\n");
                    break;
                }
            }
            continue;
        }
        if (errno == ECONNREFUSED || errno == ENETUNREACH || errno == ETIMEDOUT) {
            usleep(100000);
            continue;
        }
        perror("connect");
        goto out;
    }

    if (!connected) {
        fprintf(stderr, "linux client: unable to connect after retries\n");
        goto out;
    }

    while (1) {
        int hret = wolfSSL_connect(ssl);
        if (hret == SSL_SUCCESS) {
            printf("TLS client: TLS handshake complete\n");
            break;
        }
        err = wolfSSL_get_error(ssl, hret);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            usleep(1000);
            continue;
        }
        fprintf(stderr, "linux client: handshake failed (%d)\n", err);
        goto out;
    }

    for (size_t i = 0; i < sizeof(tx); i += 16)
        memcpy(tx + i, "Test pattern - -", 16);

    while (sent < sizeof(tx)) {
        int wrote = wolfSSL_write(ssl, tx + sent, (int)(sizeof(tx) - sent));
        if (wrote > 0) {
            sent += (size_t)wrote;
            continue;
        }
        err = wolfSSL_get_error(ssl, wrote);
        if (err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ) {
            usleep(1000);
            continue;
        }
        fprintf(stderr, "linux client: write failed (%d)\n", err);
        goto out;
    }
    printf("TLS client: wrote %d bytes\n", TEST_PAYLOAD);

    while (received < sizeof(rx)) {
        int got = wolfSSL_read(ssl, rx + received, (int)(sizeof(rx) - received));
        if (got > 0) {
            received += (size_t)got;
            continue;
        }
        if (got == 0) {
            fprintf(stderr, "linux client: unexpected eof\n");
            goto out;
        }
        err = wolfSSL_get_error(ssl, got);
        if (err == WOLFSSL_ERROR_WANT_READ) {
            usleep(1000);
            continue;
        }
        fprintf(stderr, "linux client: read failed (%d)\n", err);
        goto out;
    }
    printf("TLS client: read %d bytes\n", TEST_PAYLOAD);

    if (memcmp(tx, rx, sizeof(tx)) != 0) {
        fprintf(stderr, "linux client: payload mismatch\n");
        goto out;
    }

    printf("TLS client: verified %d-byte echo\n", TEST_PAYLOAD);
    ret = 0;

out:
    if (ssl) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }
    if (ctx)
        wolfSSL_CTX_free(ctx);
    if (fd >= 0)
        close(fd);
    return ret;
}

/* ------------------------------------------------------------------------- */
/* ARP helper                                                                */
/* ------------------------------------------------------------------------- */

#define TEST_PACKED __attribute__((packed))

struct TEST_PACKED test_arp_packet {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sma[6];
    uint32_t sip;
    uint8_t tma[6];
    uint32_t tip;
};

/* ------------------------------------------------------------------------- */
/* Main                                                                      */
/* ------------------------------------------------------------------------- */

int main(void)
{
    static const uint8_t mac_router1[6] = {0x02, 0x00, 0x00, 0x00, 0x02, 0xFE};
    static const uint8_t mac_server[6] = {0x02, 0x00, 0x00, 0x00, 0x02, 0x10};
    struct mem_link link_router_server;
    struct wolfIP_ll_dev *tap_dev = NULL;
    size_t stack_sz;
    int ret = 0;
    int router_started = 0;
    int server_started = 0;
    char route_cmd[128] = {0};
    char route_del_cmd[128] = {0};
    struct in_addr host_addr = { .s_addr = htonl(host_ip4) };
    uint8_t host_mac[6];
    char host_str[16];
    char lan_str[16];
    char wan_str[16];
    char srv_str[16];

    setvbuf(stdout, NULL, _IONBF, 0);

    mem_link_init(&link_router_server);

    wolfSSL_Init();
    wolfSSL_Debugging_OFF();

    ip4_to_str(host_ip4, host_str, sizeof(host_str));
    ip4_to_str(router_lan_ip4, lan_str, sizeof(lan_str));
    ip4_to_str(router_wan_ip4, wan_str, sizeof(wan_str));
    ip4_to_str(server_ip4, srv_str, sizeof(srv_str));
    printf("Configuration: host=%s router_lan=%s router_wan=%s server=%s\n",
            host_str, lan_str, wan_str, srv_str);

    stack_sz = wolfIP_instance_size();
    router_stack = (struct wolfIP *)XMALLOC(stack_sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    server_stack = (struct wolfIP *)XMALLOC(stack_sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!router_stack || !server_stack) {
        fprintf(stderr, "failed to allocate stacks\n");
        ret = 1;
        goto cleanup;
    }
    XMEMSET(router_stack, 0, stack_sz);
    XMEMSET(server_stack, 0, stack_sz);
    wolfIP_init(router_stack);
    wolfIP_init(server_stack);

    tap_dev = wolfIP_getdev(router_stack);
    if (!tap_dev) {
        fprintf(stderr, "failed to obtain router interface 0\n");
        ret = 1;
        goto cleanup;
    }
    if (tap_init(tap_dev, TAP_IFNAME, host_addr.s_addr) < 0) {
        perror("tap_init");
        ret = 1;
        goto cleanup;
    }
    memcpy(host_mac, tap_dev->mac, sizeof(host_mac));
    host_mac[5] ^= 1;

    mem_link_attach(wolfIP_getdev_ex(router_stack, 1), &link_router_server, 0,
            "rt1", mac_router1);
    mem_link_attach(wolfIP_getdev(server_stack), &link_router_server, 1,
            "srv0", mac_server);

    wolfIP_ipconfig_set_ex(router_stack, 0, router_lan_ip4, IP4(255,255,255,0), IP4(0,0,0,0));
    wolfIP_ipconfig_set_ex(router_stack, 1, router_wan_ip4, IP4(255,255,255,0), IP4(0,0,0,0));
    wolfIP_ipconfig_set(server_stack, server_ip4, IP4(255,255,255,0), router_wan_ip4);

    if (server_setup(server_stack) < 0) {
        fprintf(stderr, "failed to set up server\n");
        ret = 1;
        goto cleanup;
    }

    router_running = 1;
    server_done = 0;

    if (pthread_create(&th_router, NULL, poll_thread, router_stack) != 0) {
        fprintf(stderr, "failed to start router thread\n");
        ret = 1;
        goto cleanup;
    }
    router_started = 1;

    if (pthread_create(&th_server, NULL, poll_thread, server_stack) != 0) {
        fprintf(stderr, "failed to start server thread\n");
        ret = 1;
        goto cleanup;
    }
    server_started = 1;

    snprintf(route_cmd, sizeof(route_cmd),
            "ip route add %s dev %s via %u.%u.%u.%u 2>/dev/null",
            HOST_ROUTE, TAP_IFNAME,
            (router_lan_ip4 >> 24) & 0xFF,
            (router_lan_ip4 >> 16) & 0xFF,
            (router_lan_ip4 >> 8) & 0xFF,
            router_lan_ip4 & 0xFF);
    snprintf(route_del_cmd, sizeof(route_del_cmd),
            "ip route del %s dev %s 2>/dev/null",
            HOST_ROUTE, TAP_IFNAME);
    if (route_cmd[0])
        system(route_cmd);

    if (run_linux_tls_client(server_ip4) < 0) {
        fprintf(stderr, "linux client: test failed\n");
        ret = 1;
    }

cleanup:
    router_running = 0;
    server_done = 1;

    if (server_started)
        pthread_join(th_server, NULL);
    if (router_started)
        pthread_join(th_router, NULL);

    if (route_del_cmd[0])
        system(route_del_cmd);

    if (server_ssl) {
        wolfip_reset_io(server_ssl);
        wolfSSL_free(server_ssl);
        server_ssl = NULL;
    }
    if (server_ctx) {
        wolfSSL_CTX_free(server_ctx);
        server_ctx = NULL;
    }
    if (server_listen_fd >= 0 && server_stack)
        wolfIP_sock_close(server_stack, server_listen_fd);
    if (router_stack)
        XFREE(router_stack, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (server_stack)
        XFREE(server_stack, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    printf("Test result: %s\n", ret == 0 ? "SUCCESS" : "FAIL");
    return ret;
}

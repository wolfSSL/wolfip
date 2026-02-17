#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include "config.h"
#include "wolfip.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#if !CONFIG_IPFILTER
#error "ipfilter_logger requires CONFIG_IPFILTER=1"
#endif

#define TEST_SIZE (8 * 1024)
#define BUFFER_SIZE TEST_SIZE

#define WI_IPPROTO_ICMP 0x01
#define WI_IPPROTO_TCP 0x06
#define WI_IPPROTO_UDP 0x11

static int listen_fd = -1, client_fd = -1;
static int exit_ok = 0, exit_count = 0;
static uint8_t buf[TEST_SIZE];
static int tot_sent = 0;
static int tot_recv = 0;
static int wolfIP_closing = 0;
static int closed = 0;
/* "Test pattern - -" 16 chars without trailing null. */
static const uint8_t test_pattern[16] = {0x54, 0x65, 0x73, 0x74, 0x20, 0x70,
                                         0x61, 0x74, 0x74, 0x65, 0x72, 0x6e,
                                         0x20, 0x2d, 0x20, 0x2d};

static WOLFSSL_CTX *server_ctx = NULL; /* Used by wolfIP */
static WOLFSSL_CTX *client_ctx = NULL; /* Used by Linux */
static WOLFSSL *client_ssl = NULL;
static WOLFSSL *server_ssl = NULL;

extern int wolfSSL_SetIO_wolfIP(WOLFSSL* ssl, int fd);
extern int wolfSSL_SetIO_wolfIP_CTX(WOLFSSL_CTX *ctx, struct wolfIP *s);

extern const unsigned char ca_der[];
extern const unsigned long ca_der_len;
extern const unsigned char server_der[];
extern const unsigned long server_der_len;
extern const unsigned char server_key_der[];
extern const unsigned long server_key_der_len;

/* Network device initialization: VDE or TAP */
#if WOLFIP_USE_VDE
#include "src/port/vde2/vde_device.h"
#else
extern int tap_init(struct wolfIP_ll_dev *dev, const char *name, uint32_t host_ip);
#endif

static const char *filter_reason_str(enum wolfIP_filter_reason reason)
{
    static const char *names[] = {
        "BINDING", "DISSOCIATE", "LISTENING", "STOP_LISTENING",
        "CONNECTING", "ACCEPTING", "CLOSED", "REMOTE_RESET",
        "RECEIVING", "SENDING", "ADDR_UNREACHABLE", "PORT_UNREACHABLE",
        "INBOUND_ERR", "OUTBOUND_ERR", "CLOSE_WAIT"
    };
    if ((unsigned)reason < (sizeof(names) / sizeof(names[0])))
        return names[reason];
    return "UNKNOWN";
}

static void mac_to_str(const uint8_t mac[6], char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void ip_to_str(uint32_t net_ip, char *buf, size_t len)
{
    ip4 host_ip = ee32(net_ip);
    iptoa(host_ip, buf);
    buf[len - 1] = '\0';
}

static const char *proto_to_name(uint16_t proto)
{
    switch (proto) {
    case WOLFIP_FILTER_PROTO_ETH:
        return "ETH";
    case WOLFIP_FILTER_PROTO_IP:
        return "IP";
    case WOLFIP_FILTER_PROTO_TCP:
        return "TCP";
    case WOLFIP_FILTER_PROTO_UDP:
        return "UDP";
    case WOLFIP_FILTER_PROTO_ICMP:
        return "ICMP";
    default:
        return "UNKNOWN";
    }
}

static void log_ports(uint16_t proto, const struct wolfIP_filter_metadata *meta)
{
    if (proto == 0)
        return;
    if (proto == WOLFIP_FILTER_PROTO_TCP) {
        printf(" tcp=%u->%u flags=0x%02x",
               ntohs(meta->l4.tcp.src_port),
               ntohs(meta->l4.tcp.dst_port),
               meta->l4.tcp.flags);
    } else if (proto == WOLFIP_FILTER_PROTO_UDP) {
        printf(" udp=%u->%u",
               ntohs(meta->l4.udp.src_port),
               ntohs(meta->l4.udp.dst_port));
    } else if (proto == WOLFIP_FILTER_PROTO_ICMP) {
        printf(" icmp type=%u code=%u",
               meta->l4.icmp.type,
               meta->l4.icmp.code);
    }
}

static int filter_logger_cb(void *arg, const struct wolfIP_filter_event *event)
{
    char src_ip[16], dst_ip[16], src_mac[18], dst_mac[18];
    (void)arg;
    ip_to_str(event->meta.src_ip, src_ip, sizeof(src_ip));
    ip_to_str(event->meta.dst_ip, dst_ip, sizeof(dst_ip));
    mac_to_str(event->meta.src_mac, src_mac, sizeof(src_mac));
    mac_to_str(event->meta.dst_mac, dst_mac, sizeof(dst_mac));

    printf("[ipfilter] %s reason=%s if=%u len=%" PRIu32
           " ip=%s->%s mac=%s->%s",
           proto_to_name(event->meta.ip_proto),
           filter_reason_str(event->reason),
           event->if_idx,
           event->length,
           src_ip,
           dst_ip,
           src_mac,
           dst_mac);
    log_ports(event->meta.ip_proto, &event->meta);
    printf("\n");

    fflush(stdout);
    return 0;
}

static void register_filter_logger(void)
{
    wolfIP_filter_set_callback(filter_logger_cb, NULL);
    wolfIP_filter_set_mask(~0U);
}

static void server_cb(int fd, uint16_t event, void *arg)
{
    int ret = 0;
    if ((fd == listen_fd) && (event & CB_EVENT_READABLE) && (client_fd == -1)) {
        client_fd = wolfIP_sock_accept((struct wolfIP *)arg, listen_fd, NULL, NULL);
        if (client_fd > 0) {
            printf("accept: Client FD is 0x%04x\n", client_fd);
            server_ssl = wolfSSL_new(server_ctx);
            if (!server_ssl) {
                printf("Failed to create server SSL object\n");
                return;
            }
            wolfSSL_SetIO_wolfIP(server_ssl, client_fd);
            printf("Server: TCP connection established\n");
        }
    } else if ((fd == client_fd) && (event & CB_EVENT_READABLE)) {
        ret = wolfSSL_read(server_ssl, buf, sizeof(buf));
        if (ret < 0) {
            ret = wolfSSL_get_error(server_ssl, 0);
            if (ret != WOLFSSL_ERROR_WANT_READ) {
                printf("Recv error: %d\n", ret);
                wolfIP_sock_close((struct wolfIP *)arg, client_fd);
            }
        } else if (ret == 0) {
            printf("Client side closed the connection.\n");
            wolfIP_sock_close((struct wolfIP *)arg, client_fd);
            printf("Server: Exiting.\n");
            exit_ok = 1;
        } else {
            printf("recv: %d, echoing back\n", ret);
            tot_recv += ret;
        }
    }
    if ((event & CB_EVENT_WRITABLE) || ((ret > 0) && !closed)) {
        int snd_ret;
        if ((tot_sent >= 4096) && wolfIP_closing) {
            wolfIP_sock_close((struct wolfIP *)arg, client_fd);
            printf("Server: I closed the connection.\n");
            closed = 1;
            exit_ok = 1;
        }
        if ((!closed) && (tot_sent < tot_recv)) {
            snd_ret = wolfSSL_write(server_ssl, buf + tot_sent, tot_recv - tot_sent);
            if (snd_ret != WANT_WRITE) {
                if (snd_ret < 0) {
                    printf("Send error: %d\n", snd_ret);
                    wolfSSL_free(server_ssl);
                    wolfIP_sock_close((struct wolfIP *)arg, client_fd);
                } else {
                    tot_sent += snd_ret;
                    printf("sent %d bytes\n", snd_ret);
                    if (tot_recv == tot_sent) {
                        tot_sent = 0;
                        tot_recv = 0;
                    }
                }
            }
        }
    }
    if (event & CB_EVENT_CLOSED) {
        printf("Closing %d, client fd: %d\n", fd, client_fd);
        wolfSSL_free(server_ssl);
        server_ssl = NULL;
    }
    if ((fd == client_fd) && (event & CB_EVENT_CLOSED)) {
        printf("Client side closed the connection (EVENT_CLOSED)\n");
        wolfSSL_free(server_ssl);
        wolfIP_sock_close((struct wolfIP *)arg, client_fd);
        client_fd = -1;
        printf("Server: Exiting.\n");
        exit_ok = 1;
    }
}

static int test_loop(struct wolfIP *s, int active_close)
{
    exit_ok = 0;
    exit_count = 0;
    tot_sent = 0;
    wolfIP_closing = active_close;
    closed = 0;

    while (1) {
        uint32_t ms_next;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        ms_next = wolfIP_poll(s, tv.tv_sec * 1000 + tv.tv_usec / 1000);
        usleep(ms_next * 1000);
        if (exit_ok > 0) {
            if (exit_count++ < 10)
                continue;
            else
                break;
        }
    }
    return 0;
}

static void *pt_echoclient(void *arg)
{
    int fd, ret;
    unsigned total_r = 0;
    unsigned i;
    uint8_t local_buf[BUFFER_SIZE];
    uint32_t *srv_addr = (uint32_t *)arg;
    struct sockaddr_in remote_sock = {
        .sin_family = AF_INET,
        .sin_port = ntohs(8), /* Echo */
    };

    client_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!client_ctx) {
        printf("Failed to create client context\n");
        return (void *)-1;
    }

    client_ssl = wolfSSL_new(client_ctx);
    if (!client_ssl) {
        printf("Failed to create client SSL object\n");
        return (void *)-1;
    }

    wolfSSL_CTX_load_verify_buffer(client_ctx, ca_der, ca_der_len, SSL_FILETYPE_ASN1);

    remote_sock.sin_addr.s_addr = *srv_addr;
    fd = socket(AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (fd < 0) {
        perror("test client socket");
        return (void *)-1;
    }
    wolfSSL_set_fd(client_ssl, fd);
    sleep(1);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    printf("Connecting to echo server\n");
    ret = connect(fd, (struct sockaddr *)&remote_sock, sizeof(remote_sock));
    if (ret < 0) {
        perror("test client connect");
        return (void *)-1;
    }
    printf("Linux client: TCP connection established\n");
    ret = wolfSSL_connect(client_ssl);
    if (ret != SSL_SUCCESS) {
        printf("Linux client: Failed to connect to TLS server, err: %d\n", ret);
        return (void *)-1;
    }
    for (i = 0; i < sizeof(local_buf); i += sizeof(test_pattern)) {
        memcpy(local_buf + i, test_pattern, sizeof(test_pattern));
    }
    ret = wolfSSL_write(client_ssl, local_buf, sizeof(local_buf));
    if (ret < 0) {
        printf("test client write: %d\n", ret);
        return (void *)-1;
    }
    while (total_r < sizeof(local_buf)) {
        ret = wolfSSL_read(client_ssl, local_buf + total_r, sizeof(local_buf) - total_r);
        if (ret <= 0) {
            printf("test client read error: %d\n", ret);
            return (void *)-1;
        }
        total_r += ret;
    }
    for (i = 0; i < sizeof(local_buf); i += sizeof(test_pattern)) {
        if (memcmp(local_buf + i, test_pattern, sizeof(test_pattern))) {
            printf("test client: pattern mismatch at %u\n", i);
            return (void *)-1;
        }
    }
    client_ssl = NULL;
    close(fd);
    printf("Test client: success\n");
    wolfSSL_free(client_ssl);
    return (void *)0;
}

static void run_ipfilter_logger(struct wolfIP *s, uint32_t srv_ip)
{
    int ret, test_ret = 0;
    pthread_t pt;
    struct wolfIP_sockaddr_in local_sock = {
        .sin_family = AF_INET,
        .sin_port = ee16(8), /* Echo */
        .sin_addr.s_addr = 0
    };
    printf("Starting TLS echo server with filter logger\n");

    server_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!server_ctx) {
        printf("Failed to create server context\n");
        return;
    }
    wolfSSL_SetIO_wolfIP_CTX(server_ctx, s);

    wolfSSL_CTX_use_certificate_buffer(server_ctx, server_der, server_der_len, SSL_FILETYPE_ASN1);
    wolfSSL_CTX_use_PrivateKey_buffer(server_ctx, server_key_der, server_key_der_len, SSL_FILETYPE_ASN1);

    listen_fd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    wolfIP_register_callback(s, listen_fd, server_cb, s);

    ret = wolfIP_sock_bind(s, listen_fd, (struct wolfIP_sockaddr *)&local_sock, sizeof(local_sock));
    printf("bind: %d\n", ret);
    ret = wolfIP_sock_listen(s, listen_fd, 1);
    printf("listen: %d\n", ret);

    pthread_create(&pt, NULL, pt_echoclient, &srv_ip);
    ret = test_loop(s, 0);
    pthread_join(pt, (void **)&test_ret);
    printf("ipfilter logger server ret=%d client=%d\n", ret, test_ret);

    wolfIP_sock_close(s, listen_fd);
}

int main(int argc, char **argv)
{
    struct wolfIP *s;
    struct wolfIP_ll_dev *tapdev;
    struct in_addr host_stack_ip;
    uint32_t srv_ip;
#ifdef DHCP
    ip4 ip = 0, nm = 0, gw = 0;
    struct timeval tv = {0, 0};
#endif

    (void)argc;
    (void)argv;
    wolfSSL_Init();
    wolfSSL_Debugging_OFF();

    wolfIP_init_static(&s);
    register_filter_logger();

    tapdev = wolfIP_getdev(s);
    if (!tapdev)
        return 1;
    inet_aton(HOST_STACK_IP, &host_stack_ip);
#if WOLFIP_USE_VDE
    {
        const char *vde_socket = getenv("VDE_SOCKET_PATH");
        if (!vde_socket) {
            vde_socket = "/tmp/vde_switch.ctl";
        }
        if (vde_init(tapdev, vde_socket, NULL, NULL) < 0) {
            perror("vde init");
            return 2;
        }
    }
#else
    if (tap_init(tapdev, "wtcp0", host_stack_ip.s_addr) < 0) {
        perror("tap init");
        return 2;
    }
#endif
#ifdef DHCP
    gettimeofday(&tv, NULL);
    wolfIP_poll(s, tv.tv_sec * 1000 + tv.tv_usec / 1000);
    dhcp_client_init(s);
    do {
        gettimeofday(&tv, NULL);
        wolfIP_poll(s, tv.tv_sec * 1000 + tv.tv_usec / 1000);
        usleep(1000);
        wolfIP_ipconfig_get(s, &ip, &nm, &gw);
    } while (!dhcp_bound(s));
    wolfIP_ipconfig_get(s, &ip, &nm, &gw);
    srv_ip = htonl(ip);
#else
    wolfIP_ipconfig_set(s, atoip4(WOLFIP_IP), atoip4("255.255.255.0"),
            atoip4(HOST_STACK_IP));
    inet_pton(AF_INET, WOLFIP_IP, &srv_ip);
#endif

    run_ipfilter_logger(s, srv_ip);
    sleep(1);
    return 0;
}

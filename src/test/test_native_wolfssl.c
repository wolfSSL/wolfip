/* test_native_wolfssl.c
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
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "config.h"
#include "wolfip.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#define TEST_SIZE (8 * 1024)

#define BUFFER_SIZE TEST_SIZE

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


/* Defined in wolfssl_io.c */
int wolfSSL_SetIO_FT(WOLFSSL* ssl, int fd);
int wolfSSL_SetIO_FT_CTX(WOLFSSL_CTX *ctx, struct wolfIP *s);

/* wolfIP: server side callback. */
static void server_cb(int fd, uint16_t event, void *arg)
{
    int ret = 0;
    if ((fd == listen_fd) && (event & CB_EVENT_READABLE) && (client_fd == -1)) {
        client_fd = wolfIP_sock_accept((struct wolfIP *)arg, listen_fd, NULL, NULL);
        if (client_fd > 0) {
            printf("accept: Client FD is 0x%04x\n", client_fd);
            /* Create the wolfSSL object */
            server_ssl = wolfSSL_new(server_ctx);
            if (!server_ssl) {
                printf("Failed to create server SSL object\n");
                return;
            }
            wolfSSL_SetIO_FT(server_ssl, client_fd);
            /* Accepting the TLS session is not necessary here, as the
             * first read will trigger the handshake.
             */
            printf("Server: TCP connection established\n");
        }
    } else if ((fd == client_fd) && (event & CB_EVENT_READABLE  )) {
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
        } else  /* ret > 0 */ {
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


/* wolfIP side: main loop of the stack under test. */
static int test_loop(struct wolfIP *s, int active_close)
{
    exit_ok = 0;
    exit_count = 0;
    tot_sent = 0;
    wolfIP_closing = active_close;
    closed = 0;

    while(1) {
        uint32_t ms_next;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        ms_next = wolfIP_poll(s, tv.tv_sec * 1000 + tv.tv_usec / 1000);
        usleep(ms_next * 1000);
        if (exit_ok > 0) {
            if (exit_count++ < 10)
                continue;
            else break;
        }
    }
    return 0;
}

/* Test code (Linux side).
 * Thread with client to test the echoserver.
 */
extern const unsigned char ca_der[];
extern const unsigned long ca_der_len;

void *pt_echoclient(void *arg)
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
        printf("test client socket: %d\n", fd);
        return (void *)-1;
    }
    wolfSSL_set_fd(client_ssl, fd);
    sleep(1);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    printf("Connecting to echo server\n");
    ret = connect(fd, (struct sockaddr *)&remote_sock, sizeof(remote_sock));
    if (ret < 0) {
        printf("test client connect: %d\n", ret);
        perror("connect");
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
        if (ret < 0) {
            printf("failed test client read: %d\n", ret);
            return (void *)-1;
        }
        if (ret == 0) {
            printf("test client read: server has closed the connection.\n");
            if (wolfIP_closing)
                return (void *)0;
            else
                return (void *)-1;
        }
        total_r += ret;
    }
    for (i = 0; i < sizeof(local_buf); i += sizeof(test_pattern)) {
        if (memcmp(local_buf + i, test_pattern, sizeof(test_pattern))) {
            printf("test client: pattern mismatch\n");
            printf("at position %u\n", i);
            local_buf[i + 16] = 0;
            printf("%s\n", &local_buf[i]);
            return (void *)-1;
        }
    }
    client_ssl = NULL;
    close(fd);
    printf("Test client: success\n");
    wolfSSL_free(client_ssl);
    return (void *)0;
}


/* Catch-all function to initialize a new tap device as the network interface.
 * This is defined in port/linux.c
 * */
extern int tap_init(struct ll *dev, const char *name, uint32_t host_ip);

/* Test cases */

extern const unsigned char server_der[];
extern const unsigned long server_der_len;
extern const unsigned char server_key_der[];
extern const unsigned long server_key_der_len;


void test_wolfip_echoserver(struct wolfIP *s, uint32_t srv_ip)
{
    int ret, test_ret = 0;
    pthread_t pt;
    struct wolfIP_sockaddr_in local_sock = {
        .sin_family = AF_INET,
        .sin_port = ee16(8), /* Echo */
        .sin_addr.s_addr = 0
    };
    printf("TCP server tests\n");

    printf("Creating TLS server context\n");
    server_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!server_ctx) {
        printf("Failed to create server context\n");
        return;
    }
    printf("Associating server context with wolfIP\n");
    wolfSSL_SetIO_FT_CTX(server_ctx, s);

    printf("Importing server certificate\n");
    ret = wolfSSL_CTX_use_certificate_buffer(server_ctx, server_der,
            server_der_len, SSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
        printf("Failed to import server certificate\n");
        return;
    }
    printf("Importing server private key\n");
    ret = wolfSSL_CTX_use_PrivateKey_buffer(server_ctx, server_key_der,
            server_key_der_len, SSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
        printf("Failed to import server private key\n");
        return;
    }

    listen_fd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    printf("socket: %04x\n", listen_fd);
    wolfIP_register_callback(s, listen_fd, server_cb, s);

    pthread_create(&pt, NULL, pt_echoclient, &srv_ip);
    printf("Starting test: echo server close-wait\n");
    ret = wolfIP_sock_bind(s, listen_fd, (struct wolfIP_sockaddr *)&local_sock, sizeof(local_sock));
    printf("bind: %d\n", ret);
    ret = wolfIP_sock_listen(s, listen_fd, 1);
    printf("listen: %d\n", ret);
    ret = test_loop(s, 0);
    pthread_join(pt, (void **)&test_ret);
    printf("Test echo server close-wait: %d\n", ret);
    printf("Test linux client: %d\n", test_ret);
    sleep(1);

    pthread_create(&pt, NULL, pt_echoclient, &srv_ip);
    printf("Starting test: echo server active close\n");
    ret = test_loop(s, 1);
    printf("Test echo server close-wait: %d\n", ret);
    pthread_join(pt, (void **)&test_ret);
    printf("Test linux client: %d\n", test_ret);
    sleep(1);

    wolfIP_sock_close(s, listen_fd);
}

/* Main test function. */
int main(int argc, char **argv)
{
    struct wolfIP *s;
    struct ll *tapdev;
    struct timeval tv = {0, 0};
    struct in_addr linux_ip;
    uint32_t srv_ip;
    ip4 ip = 0, nm = 0, gw = 0;

    wolfSSL_Init();
    wolfSSL_Debugging_OFF();

    (void)argc;
    (void)argv;
    (void)ip;
    (void)nm;
    (void)gw;
    (void)tv;
    wolfIP_init_static(&s);
    tapdev = wolfIP_getdev(s);
    if (!tapdev)
        return 1;
    inet_aton(LINUX_IP, &linux_ip);
    if (tap_init(tapdev, "wtcp0", linux_ip.s_addr) < 0) {
        perror("tap init");
        return 2;
    }
    system("tcpdump -i wtcp0 -w test.pcap &");

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
    printf("DHCP: obtained IP address.\n");
    wolfIP_ipconfig_get(s, &ip, &nm, &gw);
    srv_ip = htonl(ip);
#else
    wolfIP_ipconfig_set(s, atoip4(WOLFIP_IP), atoip4("255.255.255.0"),
            atoip4(LINUX_IP));
    printf("IP: manually configured\n");
    inet_pton(AF_INET, WOLFIP_IP, &srv_ip);
#endif

    /* Server side test */
    test_wolfip_echoserver(s, srv_ip);
    sleep(2);
    sync();
    system("killall tcpdump");
    return 0;
}


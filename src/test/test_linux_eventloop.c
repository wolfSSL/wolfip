/* test_linux_eventloop.c
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

#if defined(WOLFIP_ESP)
    #include "wolfesp.h"
    #include "esp_sa_list.c"
#endif

#define TEST_SIZE (4 * 1024)

#define BUFFER_SIZE TEST_SIZE

static int listen_fd = -1, client_fd = -1;
static int exit_ok = 0, exit_count = 0;
static uint8_t buf[TEST_SIZE];
static int tot_sent = 0;
static int tot_recv = 0;
static int wolfIP_closing = 0;
static int closed = 0;
static int conn_fd = -1;
static int client_connected = 0;
/* "Test pattern - -" 16 chars without trailing null. */
static const uint8_t test_pattern[16] = {0x54, 0x65, 0x73, 0x74, 0x20, 0x70,
                                         0x61, 0x74, 0x74, 0x65, 0x72, 0x6e,
                                         0x20, 0x2d, 0x20, 0x2d};


/* wolfIP: server side callback. */
static void server_cb(int fd, uint16_t event, void *arg)
{
    int ret = 0;
    if ((fd == listen_fd) && (event & CB_EVENT_READABLE) && (client_fd == -1)) {
        client_fd = wolfIP_sock_accept((struct wolfIP *)arg, listen_fd, NULL, NULL);
        if (client_fd > 0) {
            printf("accept: %04x\n", client_fd);
        }
    } else if ((fd == client_fd) && (event & CB_EVENT_READABLE  )) {
        ret = wolfIP_sock_recvfrom((struct wolfIP *)arg, client_fd, buf, sizeof(buf), 0, NULL, NULL);
        if (ret != -11) {
            if (ret < 0) {
                printf("Recv error: %d\n", ret);
                wolfIP_sock_close((struct wolfIP *)arg, client_fd);
            } else if (ret == 0) {
                printf("Client side closed the connection.\n");
                wolfIP_sock_close((struct wolfIP *)arg, client_fd);
                printf("Server: Exiting.\n");
                exit_ok = 1;
            } else if (ret > 0) {
                printf("recv: %d, echoing back\n", ret);
                tot_recv += ret;
            }
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
            snd_ret = wolfIP_sock_sendto((struct wolfIP *)arg, client_fd, buf + tot_sent, tot_recv - tot_sent, 0, NULL, 0);
            if (snd_ret != -11) {
                if (snd_ret < 0) {
                    printf("Send error: %d\n", snd_ret);
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
    }
    if ((fd == client_fd) && (event & CB_EVENT_CLOSED)) {
        printf("Client side closed the connection (EVENT_CLOSED)\n");
        wolfIP_sock_close((struct wolfIP *)arg, client_fd);
        client_fd = -1;
        printf("Server: Exiting.\n");
        exit_ok = 1;
    }
    (void)arg;
}

/* Client-side callback. */
static void client_cb(int fd, uint16_t event, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    uint32_t i;
    int ret;
    static unsigned int total_r = 0, total_w = 0;
    if (fd == conn_fd) {
        if ((event & CB_EVENT_WRITABLE) && (client_connected == 0)) {
            printf("Client: connected\n");
            client_connected = 1;
        }
    }
    if (total_w == 0) {
        for (i = 0; i < sizeof(buf); i += sizeof(test_pattern)) {
            memcpy(buf + i, test_pattern, sizeof(test_pattern));
        }
    }
    if (client_connected && (event & CB_EVENT_WRITABLE) && (total_w < sizeof(buf))) {
        ret = wolfIP_sock_sendto(s, fd, buf + total_w, sizeof(buf) - total_w, 0, NULL, 0);
        if (ret <= 0) {
            printf("Test client write: %d\n", ret);
            return;
        }
        total_w += ret;
    }

    while ((total_r < total_w) && (event & CB_EVENT_READABLE)) {
        ret = wolfIP_sock_recvfrom(s, fd, buf + total_r, sizeof(buf) - total_r, 0, NULL, NULL);
        if (ret < 0){
            if (ret != -11) {
                printf("Client read: %d\n", ret);
            }
            return;
        }
        if (ret == 0) {
            printf("Client read: server has closed the connection.\n");
            return;
        }
        total_r += ret;
        printf("Client RX total: %u\n", total_r);
    }
    if (total_r == sizeof(buf)) {
        exit_ok = 1;
        for (i = 0; i < sizeof(buf); i += sizeof(test_pattern)) {
            if (memcmp(buf + i, test_pattern, sizeof(test_pattern))) {
                printf("test client: pattern mismatch\n");
                printf("at position %u\n", i);
                buf[i + 16] = 0;
                printf("%s\n", &buf[i]);
                return;
            }
        }
        if (wolfIP_closing) {
            wolfIP_sock_close(s, fd);
            conn_fd = -1;
        }
        printf("Test client: success\n");
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
    remote_sock.sin_addr.s_addr = *srv_addr;
    fd = socket(AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (fd < 0) {
        printf("test client socket: %d\n", fd);
        return (void *)-1;
    }
    sleep(1);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    printf("Connecting to echo server\n");
    ret = connect(fd, (struct sockaddr *)&remote_sock, sizeof(remote_sock));
    if (ret < 0) {
        printf("test client connect: %d\n", ret);
        perror("connect");
        return (void *)-1;
    }
    for (i = 0; i < sizeof(local_buf); i += sizeof(test_pattern)) {
        memcpy(local_buf + i, test_pattern, sizeof(test_pattern));
    }
    ret = write(fd, local_buf, sizeof(local_buf));
    if (ret < 0) {
        printf("test client write: %d\n", ret);
        return (void *)-1;
    }
    while (total_r < sizeof(local_buf)) {
        ret = read(fd, local_buf + total_r, sizeof(local_buf) - total_r);
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
    close(fd);
    printf("Test client: success\n");
    return (void *)0;
}

/* Test code (Linux side).
 * Thread with echo server to test the client.
 */
static void *pt_echoserver(void *arg)
{
    int fd, ret;
    unsigned total_r = 0;
    uint8_t local_buf[BUFFER_SIZE];
    struct sockaddr_in local_sock = {
        .sin_family = AF_INET,
        .sin_port = ntohs(8), /* Echo */
        .sin_addr.s_addr = 0
    };
    wolfIP_closing = (uintptr_t)arg;
    fd = socket(AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (fd < 0) {
        printf("test server socket: %d\n", fd);
        return (void *)-1;
    }
    local_sock.sin_addr.s_addr = inet_addr(LINUX_IP);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    ret = bind(fd, (struct sockaddr *)&local_sock, sizeof(local_sock));
    if (ret < 0) {
        printf("test server bind: %d (%s)\n", ret, strerror(errno));
        return (void *)-1;
    }
    ret = listen(fd, 1);
    if (ret < 0) {
        printf("test server listen: %d\n", ret);
        return (void *)-1;
    }
    printf("Waiting for client\n");
    ret = accept(fd, NULL, NULL);
    if (ret < 0) {
        printf("test server accept: %d\n", ret);
        return (void *)-1;
    }
    printf("test server: client %d connected\n", ret);
    fd = ret;
    while (1) {
        ret = read(fd, local_buf + total_r, sizeof(local_buf) - total_r);
        if (ret < 0) {
            printf("failed test server read: %d (%s) \n", ret, strerror(errno));
            return (void *)-1;
        }
        if (ret == 0) {
            printf("test server read: client has closed the connection.\n");
            if (wolfIP_closing)
                return (void *)0;
            else
                return (void *)-1;
        }
        total_r += ret;
        write(fd, local_buf + total_r - ret, ret);
    }
}


/* Catch-all function to initialize a new tap device as the network interface.
 * This is defined in port/linux.c
 * */
extern int tap_init(struct ll *dev, const char *name, uint32_t host_ip);

/* Test cases */

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

void test_wolfip_echoclient(struct wolfIP *s)
{
    int ret, test_ret = 0;
    pthread_t pt;
    struct wolfIP_sockaddr_in remote_sock;
    /* Client side test: client is closing the connection */
    remote_sock.sin_family = AF_INET;
    remote_sock.sin_port = ee16(8);
    remote_sock.sin_addr.s_addr = inet_addr(LINUX_IP);
    printf("TCP client tests\n");
    conn_fd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    printf("client socket: %04x\n", conn_fd);
    wolfIP_register_callback(s, conn_fd, client_cb, s);
    printf("Connecting to %s:8\n", LINUX_IP);
    wolfIP_sock_connect(s, conn_fd, (struct wolfIP_sockaddr *)&remote_sock, sizeof(remote_sock));
    pthread_create(&pt, NULL, pt_echoserver, (void*)1);
    printf("Starting test: echo client active close\n");
    ret = test_loop(s, 1);
    printf("Test echo client active close: %d\n", ret);
    pthread_join(pt, (void **)&test_ret);
    printf("Test linux server: %d\n", test_ret);

    if (conn_fd >= 0) {
        wolfIP_sock_close(s, conn_fd);
        conn_fd = -1;
    }

    /* Client side test: server is closing the connection */
    /* Excluded for now as linux cannot bind twice on port 8 */
#if 0
    conn_fd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (conn_fd < 0) {
        printf("cannot create socket: %d\n", conn_fd);
    }
    printf("client socket: %04x\n", conn_fd);
    wolfIP_register_callback(s, conn_fd, client_cb, s);
    printf("Connecting to %s:8\n", LINUX_IP);
    wolfIP_sock_connect(s, conn_fd, (struct wolfIP_sockaddr *)&remote_sock, sizeof(remote_sock));
    pthread_create(&pt, NULL, pt_echoserver, (void*)0);
    printf("Starting test: echo client passive close\n");
    ret = test_loop(s, 0);
    printf("Test echo client, server closing: %d\n", ret);
    pthread_join(pt, (void **)&test_ret);
    printf("Test linux server: %d\n", test_ret);
#endif



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

#if defined(WOLFIP_ESP)
    esp_load_sa_list(test_in_sa_list, 2, 1);
    esp_load_sa_list(test_out_sa_list, 2, 0);
#endif

    /* Server side test */
    test_wolfip_echoserver(s, srv_ip);

    /* Client side test */
    test_wolfip_echoclient(s);

    system("killall tcpdump");
    return 0;
}


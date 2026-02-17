/* test_eventloop.c
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
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "config.h"
#include "wolfip.h"

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
static const uint8_t test_pattern[16] = "Test pattern - -";



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
        if (ret != -EAGAIN) {
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
            if (snd_ret != -EAGAIN) {
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
            if (ret != -EAGAIN) {
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

/* Test code (host side).
 * Thread with client to test the echoserver.
 */
void *pt_echoclient(void *arg)
{
    int fd, ret;
    unsigned total_r = 0;
    unsigned i;
    uint8_t local_buf[BUFFER_SIZE];
    uint32_t *srv_addr = (uint32_t *)arg;
    int old_flags = -1;
    fd_set wfds, rfds;
    struct timeval tv;
    socklen_t errlen;
    int err;
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
    old_flags = fcntl(fd, F_GETFL, 0);
    if (old_flags < 0) {
        perror("fcntl(F_GETFL)");
        close(fd);
        return (void *)-1;
    }
    if (fcntl(fd, F_SETFL, old_flags | O_NONBLOCK) < 0) {
        perror("fcntl(F_SETFL)");
        close(fd);
        return (void *)-1;
    }
    ret = connect(fd, (struct sockaddr *)&remote_sock, sizeof(remote_sock));
    if (ret < 0) {
        err = errno;
        printf("test client connect returned %d, errno=%d (%s)\n", ret, err, strerror(err));
        if (err != EINPROGRESS) {
            perror("connect");
            close(fd);
            return (void *)-1;
        }
        printf("Waiting for connect to complete...\n");
        while (1) {
            tv.tv_sec = 5;
            tv.tv_usec = 0;
            FD_ZERO(&rfds);
            FD_ZERO(&wfds);
            FD_SET(fd, &rfds);
            FD_SET(fd, &wfds);
            ret = select(fd + 1, &rfds, &wfds, NULL, &tv);
            if (ret <= 0) {
                printf("select returned %d (timeout or error)\n", ret);
                if (ret < 0) {
                    perror("select");
                    close(fd);
                    return (void *)-1;
                }
            }
            errlen = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0) {
                perror("getsockopt(SO_ERROR)");
                close(fd);
                return (void *)-1;
            }
            if (err == 0) {
                printf("connect completed after select()\n");
                break;
            }
            if (ret == 0) {
                printf("connect still in progress after timeout\n");
                continue;
            }
            if (err != EINPROGRESS && err != EALREADY && err != EWOULDBLOCK && err != EAGAIN) {
                printf("connect completed with error: %d (%s)\n", err, strerror(err));
                close(fd);
                return (void *)-1;
            }
        }
    } else {
        printf("connect returned immediately\n");
    }
    if (fcntl(fd, F_SETFL, old_flags) < 0)
        perror("fcntl(restore)");
    printf("test client: connect succeeded\n");
    for (i = 0; i < sizeof(local_buf); i += sizeof(test_pattern)) {
        memcpy(local_buf + i, test_pattern, sizeof(test_pattern));
    }
    ret = write(fd, local_buf, sizeof(local_buf));
    if (ret < 0) {
        int werr = errno;
        printf("test client write: %d (errno=%d: %s)\n", ret, werr, strerror(werr));
        perror("write");
        return (void *)-1;
    }
    printf("test client: wrote %d bytes\n", ret);
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
        printf("test client: read %d bytes (total %u)\n", ret, total_r);
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

/* Test code (host side).
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
    local_sock.sin_addr.s_addr = inet_addr(HOST_STACK_IP);
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


/* Network device initialization: VDE or TAP */
#if WOLFIP_USE_VDE
#include "src/port/vde2/vde_device.h"
#else
extern int tap_init(struct wolfIP_ll_dev *dev, const char *name, uint32_t host_ip);
#endif

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
    printf("Test host client: %d\n", test_ret);
    sleep(1);

    pthread_create(&pt, NULL, pt_echoclient, &srv_ip);
    printf("Starting test: echo server active close\n");
    ret = test_loop(s, 1);
    printf("Test echo server close-wait: %d\n", ret);
    pthread_join(pt, (void **)&test_ret);
    printf("Test host client: %d\n", test_ret);
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
    remote_sock.sin_addr.s_addr = inet_addr(HOST_STACK_IP);
    printf("TCP client tests\n");
    conn_fd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    printf("client socket: %04x\n", conn_fd);
    wolfIP_register_callback(s, conn_fd, client_cb, s);
    printf("Connecting to %s:8\n", HOST_STACK_IP);
    wolfIP_sock_connect(s, conn_fd, (struct wolfIP_sockaddr *)&remote_sock, sizeof(remote_sock));
    pthread_create(&pt, NULL, pt_echoserver, (void*)1);
    printf("Starting test: echo client active close\n");
    ret = test_loop(s, 1);
    printf("Test echo client active close: %d\n", ret);
    pthread_join(pt, (void **)&test_ret);
    printf("Test host server: %d\n", test_ret);

    if (conn_fd >= 0) {
        wolfIP_sock_close(s, conn_fd);
        conn_fd = -1;
    }

    /* Client side test: server is closing the connection */
    /* Excluded for now because binding twice on port 8 is not supported */
#if 0
    conn_fd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (conn_fd < 0) {
        printf("cannot create socket: %d\n", conn_fd);
    }
    printf("client socket: %04x\n", conn_fd);
    wolfIP_register_callback(s, conn_fd, client_cb, s);
    printf("Connecting to %s:8\n", HOST_STACK_IP);
    wolfIP_sock_connect(s, conn_fd, (struct wolfIP_sockaddr *)&remote_sock, sizeof(remote_sock));
    pthread_create(&pt, NULL, pt_echoserver, (void*)0);
    printf("Starting test: echo client passive close\n");
    ret = test_loop(s, 0);
    printf("Test echo client, server closing: %d\n", ret);
    pthread_join(pt, (void **)&test_ret);
    printf("Test host server: %d\n", test_ret);
#endif



}

/* Main test function. */
int main(int argc, char **argv)
{
    struct wolfIP *s;
    struct wolfIP_ll_dev *tapdev;
    struct timeval tv = {0, 0};
    struct in_addr host_stack_ip;
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
    {
#if !defined(__FreeBSD__) && !defined(__APPLE__)
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "tcpdump -i %s -w test.pcap &", tapdev->ifname);
        system(cmd);
#else
        (void)tapdev;
#endif
    }

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
            atoip4(HOST_STACK_IP));
    printf("IP: manually configured\n");
    inet_pton(AF_INET, WOLFIP_IP, &srv_ip);
#endif

    /* Server side test */
    test_wolfip_echoserver(s, srv_ip);

    /* Client side test */
    test_wolfip_echoclient(s);

#if !defined(__FreeBSD__) && !defined(__APPLE__)
    system("killall tcpdump");
#endif
    return 0;
}

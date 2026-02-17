/* test_dhcp_dns.c
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
#include <sys/socket.h>
#include <sys/types.h>
#include "config.h"
#include "wolfip.h"

#define DHCP
#define TEST_SIZE (8 * 1024)

#define BUFFER_SIZE TEST_SIZE

static int conn_fd = -1;
static int exit_ok = 0, exit_count = 0;
static uint8_t buf[TEST_SIZE];
static int tot_sent = 0;
static int wolfIP_closing = 0;
static int closed = 0;
static int client_connected = 0;
/* "Test pattern - -" 16 chars without trailing null. */
static const uint8_t test_pattern[16] = {0x54, 0x65, 0x73, 0x74, 0x20, 0x70,
                                         0x61, 0x74, 0x74, 0x65, 0x72, 0x6e,
                                         0x20, 0x2d, 0x20, 0x2d};

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
 * Provide an echo server to exercise the client path.
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

}

static int example_com_resolved = 0;


void ns_cb(uint32_t ip)
{
    printf("Obtained ip address for example.com: %s\n", inet_ntoa(*(struct in_addr *)&ip));
    example_com_resolved = 1;
}


/* Main test function. */
int main(int argc, char **argv)
{
    struct wolfIP *s;
    struct wolfIP_ll_dev *tapdev;
    struct timeval tv;
    struct in_addr host_stack_ip;
    uint32_t srv_ip;
    uint16_t dns_id = 0;
    ip4 ip = 0, nm = 0, gw = 0;
#ifdef __FreeBSD__
    char dnsmasq_pid_file[64] = {0};
#endif

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
#elif defined(__FreeBSD__)
        char cmd[256];
        char addr_buf[INET_ADDRSTRLEN];
        char start_buf[INET_ADDRSTRLEN];
        char end_buf[INET_ADDRSTRLEN];
        uint32_t host_ip = ntohl(host_stack_ip.s_addr);
        uint32_t net = host_ip & 0xFFFFFF00U;
        uint32_t start = net | 0x14U;
        uint32_t end = net | 0x28U;
        struct in_addr tmp;

        inet_ntop(AF_INET, &host_stack_ip, addr_buf, sizeof(addr_buf));
        tmp.s_addr = htonl(start);
        inet_ntop(AF_INET, &tmp, start_buf, sizeof(start_buf));
        tmp.s_addr = htonl(end);
        inet_ntop(AF_INET, &tmp, end_buf, sizeof(end_buf));

        snprintf(dnsmasq_pid_file, sizeof(dnsmasq_pid_file),
                "/tmp/dnsmasq-%s.pid", tapdev->ifname);
        snprintf(cmd, sizeof(cmd),
                "dnsmasq --interface=%s "
                "--bind-interfaces "
                "--listen-address=%s "
                "--conf-file=/dev/null "
                "--dhcp-range=%s,%s,255.255.255.0,1h "
                "--dhcp-option=3,%s "
                "--dhcp-option=6,%s "
                "--dhcp-authoritative "
                "--address=/example.com/%s "
                "--log-facility=/dev/null "
                "--pid-file=%s >/dev/null 2>&1 &",
                tapdev->ifname,
                addr_buf,
                start_buf,
                end_buf,
                addr_buf,
                addr_buf,
                addr_buf,
                dnsmasq_pid_file);
        printf("Starting dnsmasq: %s\n", cmd);
        system(cmd);
#else
        (void)tapdev;
#endif
    }

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
    (void)srv_ip;

    nslookup(s, "example.com", &dns_id, ns_cb);

    while(!example_com_resolved) {
        gettimeofday(&tv, NULL);
        wolfIP_poll(s, tv.tv_sec * 1000 + tv.tv_usec / 1000);
        usleep(1000);
    }

    /* Client side test */
    test_wolfip_echoclient(s);

    sleep(2);
    sync();
#if !defined(__FreeBSD__) && !defined(__APPLE__)
    system("killall tcpdump");
#elif defined(__FreeBSD__)
    if (dnsmasq_pid_file[0] != '\0') {
        char stop_cmd[160];
        snprintf(stop_cmd, sizeof(stop_cmd),
                "if [ -f %s ]; then kill $(cat %s) >/dev/null 2>&1; rm -f %s; fi",
                dnsmasq_pid_file, dnsmasq_pid_file, dnsmasq_pid_file);
        system(stop_cmd);
    }
#endif
    return 0;
}

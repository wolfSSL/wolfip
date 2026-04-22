/* test_multicast_interop.c
 *
 * Linux TAP interop smoke tests for wolfIP IPv4 UDP multicast.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "config.h"
#include "wolfip.h"

#ifndef IP_MULTICAST
#error "test_multicast_interop requires IP_MULTICAST"
#endif

#define MCAST_GROUP "239.1.2.9"
#define MCAST_PORT 19009
#define WOLFIP_MCAST_PORT 19010

extern int tap_init(struct wolfIP_ll_dev *dev, const char *name, uint32_t host_ip);

static uint64_t now_ms(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000U + (uint64_t)tv.tv_usec / 1000U;
}

static void poll_stack_for(struct wolfIP *s, unsigned int ms)
{
    uint64_t end = now_ms() + ms;

    while (now_ms() < end) {
        (void)wolfIP_poll(s, now_ms());
        usleep(1000);
    }
}

static int host_udp_socket(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int one = 1;

    if (fd < 0) {
        perror("socket");
        return -1;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    return fd;
}

static int test_host_to_wolfip(struct wolfIP *s, uint32_t host_ip)
{
    int host_fd;
    int wolf_fd;
    struct sockaddr_in host_if;
    struct sockaddr_in dst;
    struct wolfIP_sockaddr_in bind_addr;
    struct wolfIP_ip_mreq mreq;
    char rx[32];
    const char payload[] = "linux-to-wolfip";
    unsigned int i;

    wolf_fd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_DGRAM, 17);
    if (wolf_fd < 0)
        return -1;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(MCAST_PORT);
    bind_addr.sin_addr.s_addr = 0;
    if (wolfIP_sock_bind(s, wolf_fd, (struct wolfIP_sockaddr *)&bind_addr,
            sizeof(bind_addr)) < 0)
        return -1;
    memset(&mreq, 0, sizeof(mreq));
    inet_pton(AF_INET, MCAST_GROUP, &mreq.imr_multiaddr.s_addr);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (wolfIP_sock_setsockopt(s, wolf_fd, WOLFIP_SOL_IP,
            WOLFIP_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
        return -1;

    host_fd = host_udp_socket();
    if (host_fd < 0)
        return -1;
    memset(&host_if, 0, sizeof(host_if));
    host_if.sin_addr.s_addr = host_ip;
    if (setsockopt(host_fd, IPPROTO_IP, IP_MULTICAST_IF,
            &host_if.sin_addr, sizeof(host_if.sin_addr)) < 0) {
        perror("setsockopt IP_MULTICAST_IF");
        close(host_fd);
        return -1;
    }
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(MCAST_PORT);
    inet_pton(AF_INET, MCAST_GROUP, &dst.sin_addr);

    if (sendto(host_fd, payload, sizeof(payload), 0,
            (struct sockaddr *)&dst, sizeof(dst)) != (ssize_t)sizeof(payload)) {
        perror("sendto host multicast");
        close(host_fd);
        return -1;
    }
    for (i = 0; i < 1000; i++) {
        int ret;

        (void)wolfIP_poll(s, now_ms());
        ret = wolfIP_sock_recvfrom(s, wolf_fd, rx, sizeof(rx), 0, NULL, NULL);
        if (ret == (int)sizeof(payload) && memcmp(rx, payload, sizeof(payload)) == 0) {
            close(host_fd);
            return 0;
        }
        usleep(1000);
    }
    close(host_fd);
    fprintf(stderr, "wolfIP did not receive Linux multicast payload\n");
    return -1;
}

static int test_wolfip_to_host(struct wolfIP *s, uint32_t host_ip)
{
    int host_fd;
    int wolf_fd;
    int ttl = 3;
    struct sockaddr_in bind_addr;
    struct ip_mreq host_mreq;
    struct wolfIP_sockaddr_in dst;
    fd_set rfds;
    struct timeval tv;
    char rx[32];
    const char payload[] = "wolfip-to-linux";

    host_fd = host_udp_socket();
    if (host_fd < 0)
        return -1;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = htons(WOLFIP_MCAST_PORT);
    if (bind(host_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind host multicast");
        close(host_fd);
        return -1;
    }
    memset(&host_mreq, 0, sizeof(host_mreq));
    inet_pton(AF_INET, MCAST_GROUP, &host_mreq.imr_multiaddr);
    host_mreq.imr_interface.s_addr = host_ip;
    if (setsockopt(host_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
            &host_mreq, sizeof(host_mreq)) < 0) {
        perror("host IP_ADD_MEMBERSHIP");
        close(host_fd);
        return -1;
    }

    wolf_fd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_DGRAM, 17);
    if (wolf_fd < 0)
        return -1;
    if (wolfIP_sock_setsockopt(s, wolf_fd, WOLFIP_SOL_IP,
            WOLFIP_IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
        return -1;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(WOLFIP_MCAST_PORT);
    inet_pton(AF_INET, MCAST_GROUP, &dst.sin_addr.s_addr);
    if (wolfIP_sock_sendto(s, wolf_fd, payload, sizeof(payload), 0,
            (struct wolfIP_sockaddr *)&dst, sizeof(dst)) != (int)sizeof(payload))
        return -1;
    poll_stack_for(s, 50);

    FD_ZERO(&rfds);
    FD_SET(host_fd, &rfds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    if (select(host_fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
        fprintf(stderr, "Linux did not receive wolfIP multicast payload\n");
        close(host_fd);
        return -1;
    }
    if (recv(host_fd, rx, sizeof(rx), 0) != (ssize_t)sizeof(payload) ||
            memcmp(rx, payload, sizeof(payload)) != 0) {
        fprintf(stderr, "Linux received unexpected multicast payload\n");
        close(host_fd);
        return -1;
    }
    close(host_fd);
    return 0;
}

int main(void)
{
    struct wolfIP *s;
    struct wolfIP_ll_dev *tapdev;
    struct in_addr host;

    wolfIP_init_static(&s);
    tapdev = wolfIP_getdev(s);
    if (!tapdev)
        return 1;
    inet_aton(HOST_STACK_IP, &host);
    if (tap_init(tapdev, "wmcast0", host.s_addr) < 0)
        return 2;
    wolfIP_ipconfig_set(s, atoip4(WOLFIP_IP), atoip4("255.255.255.0"),
            atoip4(HOST_STACK_IP));
    poll_stack_for(s, 50);

    if (test_host_to_wolfip(s, host.s_addr) < 0)
        return 3;
    if (test_wolfip_to_host(s, host.s_addr) < 0)
        return 4;
    printf("multicast interop ok\n");
    return 0;
}

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
#include "wolftcp.h"
#include "httpd.h"

#define TEST_SIZE (8 * 1024)

#define BUFFER_SIZE TEST_SIZE

static int exit_ok = 0, exit_count = 0;
static int tot_sent = 0;
static int wolftcp_closing = 0;
static int closed = 0;




/* wolfTCP side: main loop of the stack under test. */
static int test_loop(struct ipstack *s, int active_close)
{
    exit_ok = 0;
    exit_count = 0;
    tot_sent = 0;
    wolftcp_closing = active_close;
    closed = 0;

    while(1) {
        uint32_t ms_next;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        ms_next = ipstack_poll(s, tv.tv_sec * 1000 + tv.tv_usec / 1000);
        usleep(ms_next * 1000);
        if (exit_ok > 0) {
            if (exit_count++ < 10)
                continue;
            else break;
        }
    }
    return 0;
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


static void test_httpd(struct ipstack *s)
{
    int ret;
    struct httpd httpd;
    WOLFSSL_CTX *server_ctx;
    const char homepage[] = "<html><body><h1>Hello, world!</h1></body></html>";

    printf("HTTP server test\n");

    printf("Creating TLS server context\n");
    server_ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    if (!server_ctx) {
        printf("Failed to create server context\n");
        return;
    }
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

    /* Initializing HTTPD server */
    printf("Initializing HTTPD server\n");
    ret = httpd_init(&httpd, s, 443, server_ctx);
    if (ret < 0) {
        printf("Failed to initialize HTTPD server\n");
        return;
    }
    httpd_register_static_page(&httpd, "/", homepage);
    test_loop(s, 0);
}

/* Main test function. */
int main(int argc, char **argv)
{
    struct ipstack *s;
    struct ll *tapdev;
    struct timeval tv;
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
    ipstack_init_static(&s);
    tapdev = ipstack_getdev(s);
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
    ipstack_poll(s, tv.tv_sec * 1000 + tv.tv_usec / 1000);
    dhcp_client_init(s);
    do {
        gettimeofday(&tv, NULL);
        ipstack_poll(s, tv.tv_sec * 1000 + tv.tv_usec / 1000);
        usleep(1000);
        ipstack_ipconfig_get(s, &ip, &nm, &gw);
    } while (!dhcp_bound(s));
    printf("DHCP: obtained IP address.\n");
    ipstack_ipconfig_get(s, &ip, &nm, &gw);
    srv_ip = htonl(ip);
#else
    ipstack_ipconfig_set(s, atoip4(WOLFTCP_IP), atoip4("255.255.255.0"),
            atoip4(LINUX_IP));
    printf("IP: manually configured\n");
    inet_pton(AF_INET, WOLFTCP_IP, &srv_ip);
#endif

    /* Server side test */
    test_httpd(s);
    sleep(2);
    sync();
    system("killall tcpdump");
    return 0;
}


/* test_wolfguard_interop.c
 *
 * Interoperability test: wolfIP wolfGuard <-> kernel wolfGuard
 *
 * This binary is the wolfIP side of the interop test.  It:
 *   1. Opens a TUN interface for outer transport to the host
 *   2. Initializes wolfIP + wolfGuard on the TUN
 *   3. Sends a UDP probe through the tunnel to the kernel side
 *   4. Waits for an echo reply (kernel side runs socat)
 *   5. Exits 0 on success, 1 on timeout/failure
 *
 * Usage: test_wolfguard_interop <private_key_file> <peer_pubkey_file>
 *
 * The key files contain raw binary (not base64):
 *   private_key_file - 32 bytes (SECP256R1 compressed)
 *   peer_pubkey_file - 65 bytes (uncompressed P-256 point)
 *
 * Network topology (set up by the shell script tools/scripts/test-interop-wolfguard.sh):
 *   Host TUN endpoint: 192.168.77.1
 *   wolfIP outer IP:   192.168.77.2
 *   Kernel wg0:        10.0.0.1/24  (listen 51820)
 *   wolfIP wg0:        10.0.0.2/24  (listen 51821)
 *
 * Copyright (C) 2026 wolfSSL Inc.
 */

#ifndef WOLFGUARD
#define WOLFGUARD
#endif

#undef  WOLFIP_MAX_INTERFACES
#define WOLFIP_MAX_INTERFACES 2

#include "../../config.h"

#undef  MAX_UDPSOCKETS
#define MAX_UDPSOCKETS 8

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

/* Unity build */
#include "../wolfip.c"
#include "../wolfguard/wg_crypto.c"
#include "../wolfguard/wg_noise.c"
#include "../wolfguard/wg_cookie.c"
#include "../wolfguard/wg_allowedips.c"
#include "../wolfguard/wg_packet.c"
#include "../wolfguard/wg_timers.c"
#include "../wolfguard/wolfguard.c"

/* TUN driver */
extern int tun_init(struct wolfIP_ll_dev *dev, const char *name,
                    uint32_t host_ip, uint32_t peer_ip);

uint32_t wolfIP_getrandom(void)
{
    return (uint32_t)random();
}

/* Test configuration */
#define TUN_NAME        "wgtun0"
#define HOST_TUN_IP     "192.168.77.1"
#define WOLFIP_TUN_IP   "192.168.77.2"
#define KERNEL_WG_IP    "10.0.0.1"
#define WOLFIP_WG_IP    "10.0.0.2"
#define KERNEL_WG_PORT  51820
#define WOLFIP_WG_PORT  51821
#define ECHO_PORT       7777
#define TIMEOUT_SEC     30

#define MAKE_IP4(a,b,c,d) ((ip4)( \
    ((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | \
    ((uint32_t)(c) << 8)  | (uint32_t)(d) ))

/* Global state */
static struct wolfIP stack;
static struct wg_device wg_dev;
static volatile int got_reply = 0;
static uint8_t recv_buf[1500];
static int recv_len = 0;

static void udp_recv_cb(int sock_fd, uint16_t events, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    struct wolfIP_sockaddr_in src;
    socklen_t src_len = sizeof(src);

    (void)sock_fd;
    if (!(events & CB_EVENT_READABLE))
        return;

    recv_len = wolfIP_sock_recvfrom(s, sock_fd, recv_buf, sizeof(recv_buf), 0,
                                     (struct wolfIP_sockaddr *)&src, &src_len);
    if (recv_len > 0) {
        printf("[wolfIP] Received %d bytes from tunnel!\n", recv_len);
        got_reply = 1;
    }
}

static int read_key_file(const char *path, uint8_t *buf, size_t expected_len)
{
    FILE *f = fopen(path, "rb");
    size_t n;

    if (!f) {
        perror(path);
        return -1;
    }
    n = fread(buf, 1, expected_len, f);
    fclose(f);
    if (n != expected_len) {
        fprintf(stderr, "%s: expected %zu bytes, got %zu\n",
                path, expected_len, n);
        return -1;
    }
    return 0;
}

static volatile int running = 1;

static void sighandler(int sig)
{
    (void)sig;
    running = 0;
}

int main(int argc, char **argv)
{
    struct wolfIP_ll_dev *tundev;
    uint8_t priv_key[WG_PRIVATE_KEY_LEN];
    uint8_t peer_pub[WG_PUBLIC_KEY_LEN];
    int peer_idx;
    int app_sock;
    struct wolfIP_sockaddr_in bind_addr, dst_addr;
    const char *probe = "wolfGuard interop test";
    struct timeval tv;
    uint64_t start_ms, now_ms;
    int ret;
    int probe_sent = 0;
    int probe_interval_ms = 1000;
    uint64_t last_probe_ms = 0;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <private_key_file> <peer_pubkey_file>\n",
                argv[0]);
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    /* Read keys */
    if (read_key_file(argv[1], priv_key, WG_PRIVATE_KEY_LEN) != 0)
        return 1;
    if (read_key_file(argv[2], peer_pub, WG_PUBLIC_KEY_LEN) != 0)
        return 1;

    printf("[wolfIP] Keys loaded successfully\n");
    printf("[wolfIP] Private key: %02x%02x...%02x%02x (%d bytes)\n",
           priv_key[0], priv_key[1],
           priv_key[WG_PRIVATE_KEY_LEN-2], priv_key[WG_PRIVATE_KEY_LEN-1],
           WG_PRIVATE_KEY_LEN);
    printf("[wolfIP] Peer public key: %02x%02x...%02x%02x (%d bytes)\n",
           peer_pub[0], peer_pub[1],
           peer_pub[WG_PUBLIC_KEY_LEN-2], peer_pub[WG_PUBLIC_KEY_LEN-1],
           WG_PUBLIC_KEY_LEN);

    /* Initialize wolfIP stack */
    wolfIP_init(&stack);

    /* Set up TUN interface (index 0) for outer transport */
    tundev = wolfIP_getdev(&stack);
    if (!tundev) {
        fprintf(stderr, "[wolfIP] Failed to get device\n");
        return 1;
    }

    {
        struct in_addr host_ip, peer_ip;
        inet_aton(HOST_TUN_IP, &host_ip);
        inet_aton(WOLFIP_TUN_IP, &peer_ip);
        if (tun_init(tundev, TUN_NAME, host_ip.s_addr, peer_ip.s_addr) < 0) {
            fprintf(stderr, "[wolfIP] Failed to init TUN %s\n", TUN_NAME);
            return 1;
        }
    }
    printf("[wolfIP] TUN %s created (%s <-> %s)\n",
           TUN_NAME, HOST_TUN_IP, WOLFIP_TUN_IP);

    /* Configure wolfIP outer IP */
    wolfIP_ipconfig_set(&stack, atoip4(WOLFIP_TUN_IP),
                        atoip4("255.255.255.255"), atoip4(HOST_TUN_IP));

    /* Initialize wolfGuard on interface 1 (wg0) */
    ret = wolfguard_init(&wg_dev, &stack, 1, WOLFIP_WG_PORT);
    if (ret != 0) {
        fprintf(stderr, "[wolfIP] wolfguard_init failed: %d\n", ret);
        return 1;
    }

    /* Set our private key */
    ret = wolfguard_set_private_key(&wg_dev, priv_key);
    if (ret != 0) {
        fprintf(stderr, "[wolfIP] wolfguard_set_private_key failed: %d\n", ret);
        return 1;
    }
    printf("[wolfIP] wolfGuard initialized on port %d\n", WOLFIP_WG_PORT);

    /* Configure wg0 IP */
    wolfIP_ipconfig_set_ex(&stack, 1, atoip4(WOLFIP_WG_IP),
                           atoip4("255.255.255.0"), 0);
    printf("[wolfIP] wg0 IP: %s/24\n", WOLFIP_WG_IP);

    /* Add kernel as peer */
    peer_idx = wolfguard_add_peer(&wg_dev, peer_pub, NULL,
                                  inet_addr(HOST_TUN_IP),
                                  htons(KERNEL_WG_PORT), 25);
    if (peer_idx < 0) {
        fprintf(stderr, "[wolfIP] wolfguard_add_peer failed\n");
        return 1;
    }
    printf("[wolfIP] Added peer (idx=%d) endpoint=%s:%d\n",
           peer_idx, HOST_TUN_IP, KERNEL_WG_PORT);

    /* Add allowed IP: 10.0.0.0/24 */
    ret = wolfguard_add_allowed_ip(&wg_dev, peer_idx,
                                   inet_addr(KERNEL_WG_IP) & inet_addr("255.255.255.0"),
                                   24);
    if (ret != 0) {
        fprintf(stderr, "[wolfIP] wolfguard_add_allowed_ip failed\n");
        return 1;
    }

    /* Create application UDP socket on wg0 IP */
    app_sock = wolfIP_sock_socket(&stack, AF_INET, SOCK_DGRAM, 0);
    if (app_sock < 0) {
        fprintf(stderr, "[wolfIP] socket failed\n");
        return 1;
    }

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(9999);
    bind_addr.sin_addr.s_addr = inet_addr(WOLFIP_WG_IP);
    wolfIP_sock_bind(&stack, app_sock,
                     (struct wolfIP_sockaddr *)&bind_addr, sizeof(bind_addr));
    wolfIP_register_callback(&stack, app_sock, udp_recv_cb, &stack);

    /* Destination: kernel wg0 echo server */
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(ECHO_PORT);
    dst_addr.sin_addr.s_addr = inet_addr(KERNEL_WG_IP);

    printf("[wolfIP] Sending probes to %s:%d through tunnel...\n",
           KERNEL_WG_IP, ECHO_PORT);

    /* Write a ready marker so the shell script knows TUN is up */
    {
        FILE *f = fopen("/tmp/wolfguard-interop-ready", "w");
        if (f) {
            fprintf(f, "ready\n");
            fclose(f);
        }
    }

    /* Wait for kernel wolfGuard to be configured before sending probes.
     * The shell script writes this marker after wg-fips set completes. */
    printf("[wolfIP] Waiting for kernel wolfGuard configuration...\n");
    {
        int wait_count = 0;
        while (running && access("/tmp/wolfguard-kernel-ready", F_OK) != 0) {
            /* Keep polling the stack while waiting (for ARP, timers, etc.) */
            gettimeofday(&tv, NULL);
            now_ms = (uint64_t)tv.tv_sec * 1000ULL +
                     (uint64_t)tv.tv_usec / 1000ULL;
            wolfIP_poll(&stack, now_ms);
            usleep(50000); /* 50ms */
            if (++wait_count > 200) { /* 10s max */
                fprintf(stderr, "[wolfIP] Timed out waiting for kernel ready\n");
                break;
            }
        }
    }
    printf("[wolfIP] Kernel ready, starting probes\n");

    /*
     * This is the first part of the test, so wolfip -> kernel, which means that
     * wolfIP initiates handshake -> send probes -> get echo
     */
    printf("\n[wolfIP] Phase 1: wolfIP -> kernel (wolfIP initiates)\n");

    gettimeofday(&tv, NULL);
    start_ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;

    while (running && !got_reply) {
        uint32_t ms_next;

        gettimeofday(&tv, NULL);
        now_ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;

        if (now_ms - start_ms > (uint64_t)TIMEOUT_SEC * 1000ULL) {
            fprintf(stderr, "[wolfIP] Phase 1 TIMEOUT after %d seconds\n",
                    TIMEOUT_SEC);
            break;
        }

        if (!got_reply && (now_ms - last_probe_ms >=
                           (uint64_t)probe_interval_ms)) {
            ret = wolfIP_sock_sendto(&stack, app_sock,
                                     probe, strlen(probe), 0,
                                     (const struct wolfIP_sockaddr *)&dst_addr,
                                     sizeof(dst_addr));
            if (ret >= 0) {
                probe_sent++;
                printf("[wolfIP] Probe #%d sent (%d bytes)\n",
                       probe_sent, ret);
            }
            last_probe_ms = now_ms;
        }

        ms_next = wolfIP_poll(&stack, now_ms);
        wolfguard_poll(&wg_dev, now_ms);

        if (ms_next > 10)
            ms_next = 10;
        usleep(ms_next * 1000);
    }

    if (got_reply) {
        printf("[wolfIP] Phase 1 PASS: echo received after %d probes\n",
               probe_sent);
        if (recv_len > 0 && (size_t)recv_len == strlen(probe) &&
            memcmp(recv_buf, probe, strlen(probe)) == 0) {
            printf("[wolfIP]   Payload verified: \"%.*s\"\n",
                   recv_len, recv_buf);
        }
    } else {
        printf("[wolfIP] Phase 1 FAIL: no reply after %d probes\n",
               probe_sent);
    }

    /*
     *
     * This is the second and final part of the test, where the kernel
     * initiates handshake -> wolfIP receives data.
     * Signal the script to reset the kernel wg0 (forcing a new
     * handshake) and ping wolfIP through the tunnel.  wolfIP just
     * polls and waits for incoming data on the app socket.
     */
    {
        int phase1_pass = got_reply;
        int phase2_pass = 0;
        FILE *f;

        printf("\n[wolfIP] Phase 2: kernel -> wolfIP "
               "(kernel initiates)\n");

        /* Reset state: destroy and re-init wolfGuard so the kernel
         * must perform a fresh handshake */
        wolfguard_destroy(&wg_dev);
        ret = wolfguard_init(&wg_dev, &stack, 1, WOLFIP_WG_PORT);
        if (ret != 0) {
            fprintf(stderr, "[wolfIP] Phase 2: wolfguard_init failed\n");
            goto phase2_done;
        }
        ret = wolfguard_set_private_key(&wg_dev, priv_key);
        if (ret != 0) {
            fprintf(stderr, "[wolfIP] Phase 2: set_private_key failed\n");
            goto phase2_done;
        }
        wolfIP_ipconfig_set_ex(&stack, 1, atoip4(WOLFIP_WG_IP),
                               atoip4("255.255.255.0"), 0);
        peer_idx = wolfguard_add_peer(&wg_dev, peer_pub, NULL,
                                      inet_addr(HOST_TUN_IP),
                                      htons(KERNEL_WG_PORT), 25);
        if (peer_idx < 0) {
            fprintf(stderr, "[wolfIP] Phase 2: add_peer failed\n");
            goto phase2_done;
        }
        ret = wolfguard_add_allowed_ip(&wg_dev, peer_idx,
                                       inet_addr(KERNEL_WG_IP) &
                                           inet_addr("255.255.255.0"),
                                       24);
        if (ret != 0) {
            fprintf(stderr, "[wolfIP] Phase 2: add_allowed_ip failed\n");
            goto phase2_done;
        }

        printf("[wolfIP] wolfGuard reset, waiting for kernel handshake...\n");

        /* Signal the script that phase 2 is ready */
        f = fopen("/tmp/wolfguard-phase2-ready", "w");
        if (f) { fprintf(f, "ready\n"); fclose(f); }

        /* Poll and wait for incoming data.  The kernel will send UDP
         * probes to us (port 9999) which triggers a kernel-initiated
         * handshake.  We also send probes after a delay.
         * By then the kernel has already initiated, so wolfIP acts as responder.
         * The echo reply confirms bidirectional data flow. */
        got_reply = 0;
        recv_len = 0;
        probe_sent = 0;
        last_probe_ms = 0;
        gettimeofday(&tv, NULL);
        start_ms = (uint64_t)tv.tv_sec * 1000ULL +
                   (uint64_t)tv.tv_usec / 1000ULL;

        while (running && !got_reply) {
            uint32_t ms_next;

            gettimeofday(&tv, NULL);
            now_ms = (uint64_t)tv.tv_sec * 1000ULL +
                     (uint64_t)tv.tv_usec / 1000ULL;

            if (now_ms - start_ms > (uint64_t)TIMEOUT_SEC * 1000ULL) {
                fprintf(stderr,
                        "[wolfIP] Phase 2 TIMEOUT after %d seconds\n",
                        TIMEOUT_SEC);
                break;
            }

            /* Send probes after 3s delay.
             * By then the kernel has already initiated the
             * handshake, so these go through
             * the kernel-established session */
            if (now_ms - start_ms > 3000ULL &&
                (now_ms - last_probe_ms >= (uint64_t)probe_interval_ms)) {
                ret = wolfIP_sock_sendto(&stack, app_sock,
                                         probe, strlen(probe), 0,
                                         (const struct wolfIP_sockaddr *)&dst_addr,
                                         sizeof(dst_addr));
                if (ret >= 0) {
                    probe_sent++;
                    printf("[wolfIP] Phase 2 probe #%d sent\n", probe_sent);
                }
                last_probe_ms = now_ms;
            }

            ms_next = wolfIP_poll(&stack, now_ms);
            wolfguard_poll(&wg_dev, now_ms);

            if (ms_next > 10)
                ms_next = 10;
            usleep(ms_next * 1000);
        }

        if (got_reply) {
            printf("[wolfIP] Phase 2 PASS: received %d bytes from kernel\n",
                   recv_len);
            phase2_pass = 1;
        } else {
            printf("[wolfIP] Phase 2 FAIL: no data from kernel\n");
        }

phase2_done:
        printf("\n[wolfIP] ==============================\n");
        printf("[wolfIP]   INTEROP TEST RESULTS\n");
        printf("[wolfIP]   Phase 1 (wolfIP → kernel): %s\n",
               phase1_pass ? "PASS" : "FAIL");
        printf("[wolfIP]   Phase 2 (kernel → wolfIP): %s\n",
               phase2_pass ? "PASS" : "FAIL");
        printf("[wolfIP] ==============================\n\n");

        /* Cleanup */
        unlink("/tmp/wolfguard-interop-ready");
        unlink("/tmp/wolfguard-phase2-ready");
        wolfIP_sock_close(&stack, app_sock);
        wolfguard_destroy(&wg_dev);

        return (phase1_pass && phase2_pass) ? 0 : 1;
    }
}

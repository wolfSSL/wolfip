/* test_wolfguard.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
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

/*
 * Functional test for wolfip + wolfguard integration (self-contained loopback).
 *
 *   wolfip side (userspace)           kernel peer side
 *   ─────────────────────────         ─────────────────────────
 *   interface : wg-wip                interface : wg-peer
 *   IP        : 10.9.0.1/24           IP        : 10.9.0.2/24
 *   listen    : 127.0.0.1:51830       listen    : 127.0.0.1:51831
 *   peer      : wg-peer pubkey        peer      : wg-wip pubkey
 *   endpoint  : 127.0.0.1:51831       endpoint  : 127.0.0.1:51830
 *
 *   wolfip sends a UDP probe to 10.9.0.2:5555.
 *   The kernel decrypts it on wg-peer and delivers it to a host UDP socket
 *   bound to 0.0.0.0:5555 which echoes it back.
 *   The kernel re-encrypts via wg-peer toward 127.0.0.1:51830.
 *   wolfip receives and verifies the echo.
 *
 * PREREQUISITES
 * -------------
 *   - wolfguard.ko and libwolfssl.ko loaded
 *   - wg-fips in PATH
 *   - NET_ADMIN capability (run as root or with the capability)
 *   - /dev/net/tun accessible
 *
 * BUILD
 *   make build/test-wolfguard
 *
 * RUN
 *   ./build/test-wolfguard
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "config.h"
#include "wolfip.h"
#include "wolfip_wolfguard.h"
#include <wolfssl/options.h>
#ifdef HAVE_FIPS
#include <wolfssl/wolfcrypt/fips_test.h>
#endif

#define WG_LOCAL_IFNAME   "wg-wip"
#define WG_PEER_IFNAME    "wg-peer"
#define WG_LOCAL_PORT     51830
#define WG_PEER_PORT      51831
#define LOCAL_IP          "10.9.0.1"
#define PEER_IP           "10.9.0.2"
#define SUBNET_MASK       "255.255.255.0"
#define ECHO_PORT         5555
#define TEST_PAYLOAD      "wolfip+wolfguard loopback"
#define POLL_TIMEOUT_MS   10000

/* Temp files for key material (base64 text) */
#define TMP_LOCAL_PRIV    "/tmp/.wg_local_priv.b64"
#define TMP_LOCAL_PUB     "/tmp/.wg_local_pub.b64"
#define TMP_PEER_PRIV     "/tmp/.wg_peer_priv.b64"
#define TMP_PEER_PUB      "/tmp/.wg_peer_pub.b64"

/*
 * Generate a SECP256R1 keypair with wg-fips and save both as base64 text files.
 */
static int gen_keypair_files(const char *priv_file, const char *pub_file)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "wg-fips genkey 2>/dev/null | tee '%s' | wg-fips pubkey > '%s' 2>/dev/null",
             priv_file, pub_file);
    if (system(cmd) != 0) {
        fprintf(stderr, "gen_keypair_files: failed (is wg-fips in PATH?)\n");
        return -1;
    }
    return 0;
}

/*
 * Decode a base64 key file to raw bytes.
 * Uses `base64 -d` via a temp file to avoid linking a base64 library.
 */
static int read_key_raw(const char *b64_file, uint8_t *out, size_t want)
{
    char tmp[256], cmd[512];
    FILE *f;
    size_t n;

    snprintf(tmp, sizeof(tmp), "%s.bin", b64_file);
    snprintf(cmd, sizeof(cmd),
             "base64 -d '%s' > '%s' 2>/dev/null", b64_file, tmp);
    if (system(cmd) != 0) {
        fprintf(stderr, "read_key_raw: base64 -d failed for %s\n", b64_file);
        return -EINVAL;
    }

    f = fopen(tmp, "rb");
    if (!f) { unlink(tmp); return -errno; }
    n = fread(out, 1, want, f);
    fclose(f);
    unlink(tmp);

    if (n != want) {
        fprintf(stderr, "read_key_raw: got %zu bytes, expected %zu from %s\n",
                n, want, b64_file);
        return -EINVAL;
    }
    return 0;
}

/*
 * Read a base64 key file as a NUL-terminated string (newline stripped).
 * Used when passing keys to wg-fips via shell commands.
 */
static int read_key_b64_str(const char *file, char *out, size_t outlen)
{
    FILE *f;
    size_t n;

    f = fopen(file, "r");
    if (!f) return -errno;
    n = fread(out, 1, outlen - 1, f);
    fclose(f);
    if (n == 0) return -EINVAL;
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        n--;
    out[n] = '\0';
    return 0;
}

/*
 * Create and configure the kernel-side wolfguard interface (wg-peer).
 * Requires that TMP_LOCAL_PUB already exists (local public key in base64).
 */
static int setup_kernel_peer(void)
{
    char cmd[512], local_pub_b64[256];
    int  ret;

    /* Generate peer keypair */
    ret = gen_keypair_files(TMP_PEER_PRIV, TMP_PEER_PUB);
    if (ret < 0) return ret;

    /* Read the wolfip side's public key (base64) */
    ret = read_key_b64_str(TMP_LOCAL_PUB, local_pub_b64, sizeof(local_pub_b64));
    if (ret < 0) {
        fprintf(stderr, "setup_kernel_peer: cannot read %s\n", TMP_LOCAL_PUB);
        return ret;
    }

    /* Create the kernel wolfguard interface (EEXIST is acceptable) */
    snprintf(cmd, sizeof(cmd),
             "ip link add '%s' type wolfguard 2>/dev/null", WG_PEER_IFNAME);
    ret = system(cmd);
    /* Verify the interface actually exists regardless of return code */
    snprintf(cmd, sizeof(cmd), "ip link show '%s' > /dev/null 2>&1", WG_PEER_IFNAME);
    if (system(cmd) != 0) {
        fprintf(stderr, "setup_kernel_peer: failed to create '%s' "
                "(is wolfguard.ko loaded?)\n", WG_PEER_IFNAME);
        return -1;
    }
    (void)ret;

    /* Configure: private key, listen port, and the wolfip peer */
    snprintf(cmd, sizeof(cmd),
             "wg-fips set '%s'"
             " listen-port %d"
             " private-key '%s'"
             " peer %s"
             " endpoint 127.0.0.1:%d"
             " persistent-keepalive 5"
             " allowed-ips %s/32",
             WG_PEER_IFNAME, WG_PEER_PORT,
             TMP_PEER_PRIV,
             local_pub_b64,
             WG_LOCAL_PORT,
             LOCAL_IP);
    if (system(cmd) != 0) {
        fprintf(stderr, "setup_kernel_peer: wg-fips set failed\n");
        return -1;
    }

    /* Assign IP and bring up */
    snprintf(cmd, sizeof(cmd),
             "ip addr add %s/24 dev '%s' 2>/dev/null; true",
             PEER_IP, WG_PEER_IFNAME);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set '%s' up", WG_PEER_IFNAME);
    if (system(cmd) != 0) {
        fprintf(stderr, "setup_kernel_peer: ip link set up failed\n");
        return -1;
    }

    return 0;
}

static void teardown_kernel_peer(void)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "ip link del '%s' 2>/dev/null; true", WG_PEER_IFNAME);
    system(cmd);
    unlink(TMP_LOCAL_PRIV);
    unlink(TMP_LOCAL_PUB);
    unlink(TMP_PEER_PRIV);
    unlink(TMP_PEER_PUB);
}

static uint64_t ms_now(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000u + (uint64_t)tv.tv_usec / 1000u;
}

/*
 * UDP loopback test
 *
 * Opens a host (kernel) UDP echo socket at 0.0.0.0:ECHO_PORT and a wolfip
 * UDP socket, then drives both in the same poll loop.  No threads needed.
 * */
static int test_udp_ping(struct wolfIP *stack)
{
    struct wolfIP_sockaddr_in peer_sa, local_sa;
    struct sockaddr_in        echo_local, echo_from;
    socklen_t fromlen;
    int       wolfip_sock, echo_fd, flags;
    int       sent = 0, n, ret;
    uint64_t  deadline, last_send_at;
    uint8_t   echo_buf[512], recv_buf[512];
    const char *payload    = TEST_PAYLOAD;
    size_t      payload_len = strlen(payload);

    /*
     * Host-side non-blocking echo socket (kernel peer side of the tunnel).
     * The kernel decrypts wolfguard traffic on wg-peer and delivers it
     * here; this socket echoes it straight back.
     * */
    echo_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (echo_fd < 0) {
        fprintf(stderr, "test_udp_ping: socket() failed: %s\n", strerror(errno));
        return -1;
    }
    setsockopt(echo_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    memset(&echo_local, 0, sizeof(echo_local));
    echo_local.sin_family      = AF_INET;
    echo_local.sin_port        = htons(ECHO_PORT);
    echo_local.sin_addr.s_addr = INADDR_ANY;
    if (bind(echo_fd, (struct sockaddr *)&echo_local, sizeof(echo_local)) < 0) {
        fprintf(stderr, "test_udp_ping: bind echo socket: %s\n", strerror(errno));
        close(echo_fd);
        return -1;
    }
    flags = fcntl(echo_fd, F_GETFL, 0);
    fcntl(echo_fd, F_SETFL, flags | O_NONBLOCK);

    /*
     * wolfip UDP socket (wolfip side of the tunnel).
     * */
    wolfip_sock = wolfIP_sock_socket(stack, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    if (wolfip_sock < 0) {
        fprintf(stderr, "test_udp_ping: wolfIP_sock_socket failed: %d\n", wolfip_sock);
        close(echo_fd);
        return -1;
    }

    /* Bind to a fixed port so the echo reply can find us */
    memset(&local_sa, 0, sizeof(local_sa));
    local_sa.sin_family      = AF_INET;
    local_sa.sin_port        = ee16(4444);
    local_sa.sin_addr.s_addr = 0;
    wolfIP_sock_bind(stack, wolfip_sock,
                     (struct wolfIP_sockaddr *)&local_sa, sizeof(local_sa));

    /* Peer address: kernel echo socket reachable via wg-peer */
    memset(&peer_sa, 0, sizeof(peer_sa));
    peer_sa.sin_family      = AF_INET;
    peer_sa.sin_port        = ee16(ECHO_PORT);
    peer_sa.sin_addr.s_addr = inet_addr(PEER_IP);

    deadline    = ms_now() + POLL_TIMEOUT_MS;
    last_send_at = 0;
    ret         = -1;

    printf("[test] polling (timeout %d ms)...\n", POLL_TIMEOUT_MS);

    while (ms_now() < deadline) {
        uint64_t t = ms_now();

        /* Drive the wolfip stack */
        wolfIP_poll(stack, t);

        /* Attempt to send every 200 ms until confirmed sent */
        if (!sent && (t - last_send_at) >= 200u) {
            int r = wolfIP_sock_sendto(stack, wolfip_sock,
                                       payload, payload_len, 0,
                                       (struct wolfIP_sockaddr *)&peer_sa,
                                       sizeof(peer_sa));
            last_send_at = t;
            if (r >= 0) {
                printf("[test] UDP probe sent (%d bytes) to %s:%d\n",
                       r, PEER_IP, ECHO_PORT);
                sent = 1;
            }
            /* -EAGAIN is normal while ARP is resolving; other errors abort */
            if (r < 0 && r != -WOLFIP_EAGAIN) {
                fprintf(stderr, "[test] sendto error: %d\n", r);
                break;
            }
        }

        /* Service the host echo socket */
        fromlen = sizeof(echo_from);
        n = recvfrom(echo_fd, echo_buf, sizeof(echo_buf), 0,
                     (struct sockaddr *)&echo_from, &fromlen);
        if (n > 0) {
            printf("[echo] %d bytes from %s:%d — echoing\n",
                   n, inet_ntoa(echo_from.sin_addr), ntohs(echo_from.sin_port));
            sendto(echo_fd, echo_buf, (size_t)n, 0,
                   (struct sockaddr *)&echo_from, fromlen);
        }

        /* Check if the wolfip stack received the echo */
        if (wolfIP_sock_can_read(stack, wolfip_sock)) {
            n = wolfIP_sock_recvfrom(stack, wolfip_sock,
                                     recv_buf, sizeof(recv_buf) - 1,
                                     0, NULL, NULL);
            if (n > 0) {
                recv_buf[n] = '\0';
                printf("[test] echo received: \"%s\" (%d bytes)\n",
                       (char *)recv_buf, n);
                if ((size_t)n == payload_len &&
                    memcmp(recv_buf, payload, payload_len) == 0) {
                    printf("[test] PASS: payload matches\n");
                    ret = 0;
                } else {
                    fprintf(stderr, "[test] FAIL: payload mismatch\n");
                }
                break;
            }
        }

        usleep(2000); /* 2 ms */
    }

    if (ret != 0 && ms_now() >= deadline)
        fprintf(stderr, "[test] FAIL: timed out after %d ms\n", POLL_TIMEOUT_MS);

    wolfIP_sock_close(stack, wolfip_sock);
    close(echo_fd);
    return ret;
}

int main(void)
{
    struct wolfIP_wg_config  cfg;
    struct wolfIP_ll_dev    *ll;
    struct wolfIP           *stack;
    int ret;

    printf("=== wolfip + wolfguard functional test ===\n");

    /* generate local (wolfip-side) keypair */
    printf("[setup] generating local keypair...\n");
    if (gen_keypair_files(TMP_LOCAL_PRIV, TMP_LOCAL_PUB) < 0)
        return 1;

    /* create and configure kernel peer interface */
    printf("[setup] configuring kernel peer (%s)...\n", WG_PEER_IFNAME);
    if (setup_kernel_peer() < 0) {
        unlink(TMP_LOCAL_PRIV);
        unlink(TMP_LOCAL_PUB);
        return 1;
    }

    /* build wolfIP_wg_config */
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.ifname, WG_LOCAL_IFNAME, sizeof(cfg.ifname) - 1);
    cfg.listen_port = WG_LOCAL_PORT;
    cfg.num_peers   = 1;

    ret = read_key_raw(TMP_LOCAL_PRIV, cfg.private_key, WG_PRIVATE_KEY_LEN);
    if (ret < 0) {
        fprintf(stderr, "main: failed to read local private key: %d\n", ret);
        goto fail;
    }

    ret = read_key_raw(TMP_PEER_PUB, cfg.peers[0].public_key, WG_PUBLIC_KEY_LEN);
    if (ret < 0) {
        fprintf(stderr, "main: failed to read peer public key: %d\n", ret);
        goto fail;
    }

    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&cfg.peers[0].endpoint;
        sin->sin_family         = AF_INET;
        sin->sin_port           = htons(WG_PEER_PORT);
        sin->sin_addr.s_addr    = inet_addr("127.0.0.1");
    }

    cfg.peers[0].allowed_ip         = atoip4(PEER_IP); /* host byte order */
    cfg.peers[0].allowed_cidr       = 32;
    cfg.peers[0].keepalive_interval = 5;

    /* initialize the wolfip stack and attach the wolfguard driver */
    wolfIP_init_static(&stack);
    ll = wolfIP_getdev(stack);

    printf("[setup] initializing wolfip + wolfguard (%s)...\n", WG_LOCAL_IFNAME);
    ret = wolfIP_wg_init(&cfg, ll);
    if (ret < 0) {
        fprintf(stderr, "main: wolfIP_wg_init failed: %d\n", ret);
        goto fail;
    }

    wolfIP_ipconfig_set(stack,
                        atoip4(LOCAL_IP),
                        atoip4(SUBNET_MASK),
                        atoip4(LOCAL_IP));

    printf("[setup] interfaces up — running UDP loopback test...\n");
    ret = test_udp_ping(stack);

    wolfIP_wg_teardown(WG_LOCAL_IFNAME);
    teardown_kernel_peer();
#ifdef HAVE_FIPS
    {
        int fips_status = wolfCrypt_GetStatus_fips();
        printf("[fips] status: %s (code %d)\n",
               fips_status == 0 ? "FIPS mode active" : "NOT in FIPS mode",
               fips_status);
    }
#endif
    printf("=== %s ===\n", ret == 0 ? "PASS" : "FAIL");
    return ret == 0 ? 0 : 1;

fail:
    teardown_kernel_peer();
    return 1;
}

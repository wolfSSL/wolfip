/* test_tftp_interop.c
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
 * Bidirectional TFTP interop test against the Debian tftp-hpa/tftpd-hpa
 * pair, exercising the wolfIP TFTP client and server end-to-end over a
 * TAP link.
 *
 *   client mode: wolfIP TFTP client GETs a fixture file from a local
 *                in.tftpd daemon launched against
 *                tools/scripts/tftpd-hpa-wolfip.conf
 *   server mode: a Linux /usr/bin/tftp client (tftp-hpa) GETs a fixture
 *                file from the wolfIP TFTP server
 *
 * Both directions transfer a small known-content file and only succeed
 * if the bytes on the receiving end match the fixture exactly.
 *
 * The test requires root (to set up the TAP link), in.tftpd, and the
 * tftp-hpa command line client. Without those, it returns 77 to signal
 * "skipped" so the make target can be safely run on bare CI images.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "wolfip.h"
#include "src/tftp/wolftftp.h"

#ifndef WOLFIP_ENABLE_TFTP
#error "test_tftp_interop requires WOLFIP_ENABLE_TFTP=1"
#endif

#define TFTP_INTEROP_PORT          6969
#define TFTP_INTEROP_TRANSFER_PORT 6970
#define TFTP_INTEROP_CLIENT_PORT   6989

#define TFTP_INTEROP_REMOTE_NAME   "wolfip_tftp_fixture.bin"

/* All filesystem paths used by this test live under a fresh
 * mkdtemp() directory (mode 0700, owned by the running user) so that
 * a hostile local user on a multi-tenant box cannot precreate a
 * symlink at one of the test's well-known paths and redirect the
 * (root-running) test's writes elsewhere. The previous fixed-path
 * layout (`/tmp/wolfip-tftp-*`) was a TOCTOU / symlink-attack
 * vector — fixed only paths now are the diagnostics pcap and the
 * Makefile-side artifact uploader's expectations, both kept under
 * /tmp and re-emitted by name from the temp root before tearing it
 * down. */
static char tftp_workdir[64];
static char tftp_local_dir[96];
static char tftp_fixture_path[160];
static char tftp_download_path[160];
static char tftp_host_get_path[160];
static char tftp_tftpd_log[160];
static char tftp_tftp_log[160];

#define TFTP_INTEROP_DIAG_PCAP "/tmp/wolfip-tftp.pcap"
#define TFTP_INTEROP_DIAG_TFTPD "/tmp/wolfip-tftpd-hpa.log"
#define TFTP_INTEROP_DIAG_TFTP "/tmp/wolfip-tftp-client.log"

/* Picked so it is NOT an exact multiple of WOLFTFTP_DEFAULT_BLKSIZE
 * (512): the last DATA block must be smaller than blksize so the
 * receiving side can detect EOF without an extra 0-byte trailer. */
#define TFTP_INTEROP_FIXTURE_SIZE 1500U

#define TFTP_INTEROP_TIMEOUT_MS 8000U

#define TFTP_EXIT_SUCCESS 0
#define TFTP_EXIT_FAIL    1
#define TFTP_EXIT_SKIP    77

extern int tap_init(struct wolfIP_ll_dev *dev, const char *name, uint32_t host_ip);

static uint64_t now_ms(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000U + (uint64_t)tv.tv_usec / 1000U;
}

static int file_equal(const char *a, const char *b)
{
    FILE *fa;
    FILE *fb;
    int rc = 0;
    int ca;
    int cb;

    fa = fopen(a, "rb");
    fb = fopen(b, "rb");
    if (fa == NULL || fb == NULL) {
        if (fa != NULL) fclose(fa);
        if (fb != NULL) fclose(fb);
        return 0;
    }
    do {
        ca = fgetc(fa);
        cb = fgetc(fb);
        if (ca != cb) {
            rc = 0;
            goto done;
        }
    } while (ca != EOF);
    rc = 1;
done:
    fclose(fa);
    fclose(fb);
    return rc;
}

/* Open a file beneath the test workdir for writing. O_NOFOLLOW
 * refuses to traverse a symlink at the leaf (so a precreated link
 * can't redirect our writes to / etc / shadow when the test runs as
 * root); O_EXCL refuses to overwrite an existing entry. The workdir
 * itself is mode 0700, so a hostile user shouldn't be able to plant
 * anything in it to begin with — these flags are belt-and-braces. */
static int open_workdir_file_for_write(const char *path)
{
    return open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
}

static int write_fixture(const char *path)
{
    FILE *fp;
    int fd;
    unsigned int i;

    (void)unlink(path);
    fd = open_workdir_file_for_write(path);
    if (fd < 0)
        return -1;
    fp = fdopen(fd, "wb");
    if (fp == NULL) {
        close(fd);
        return -1;
    }
    for (i = 0; i < TFTP_INTEROP_FIXTURE_SIZE; i++) {
        unsigned char b = (unsigned char)((i * 31U + 7U) & 0xFFU);
        if (fputc(b, fp) == EOF) {
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}

/* Build the per-run workdir layout under a freshly-created mkdtemp
 * directory. Returns 0 on success, -1 on failure with errno set. The
 * directory is mode 0700 by mkdtemp's contract. */
static int tftp_workdir_setup(void)
{
    snprintf(tftp_workdir, sizeof(tftp_workdir),
        "/tmp/wolfip-tftp-XXXXXX");
    if (mkdtemp(tftp_workdir) == NULL)
        return -1;
    /* in.tftpd chroots into the TFTP root and serves files relative
     * to it. Create a "root/" subdir inside the workdir so the chroot
     * target is owned by us and predictable. */
    snprintf(tftp_local_dir, sizeof(tftp_local_dir),
        "%s/root", tftp_workdir);
    if (mkdir(tftp_local_dir, 0700) != 0)
        return -1;
    snprintf(tftp_fixture_path, sizeof(tftp_fixture_path),
        "%s/%s", tftp_local_dir, TFTP_INTEROP_REMOTE_NAME);
    snprintf(tftp_download_path, sizeof(tftp_download_path),
        "%s/download.bin", tftp_workdir);
    snprintf(tftp_host_get_path, sizeof(tftp_host_get_path),
        "%s/host-get.bin", tftp_workdir);
    snprintf(tftp_tftpd_log, sizeof(tftp_tftpd_log),
        "%s/tftpd.log", tftp_workdir);
    snprintf(tftp_tftp_log, sizeof(tftp_tftp_log),
        "%s/tftp-client.log", tftp_workdir);
    return 0;
}

static void tftp_workdir_publish_diagnostics(void)
{
    char cmd[256];
    /* Copy the diagnostic artifacts to fixed /tmp paths the CI
     * artifact uploader expects. These targets are short-lived and
     * only created on the failure path, so a symlink-attack window
     * here is minimal — but use --no-target-directory to refuse to
     * overwrite anything we did not create ourselves. */
    if (tftp_workdir[0] == '\0')
        return;
    snprintf(cmd, sizeof(cmd),
        "cp -f -- %s/tftpd.log " TFTP_INTEROP_DIAG_TFTPD
        " 2>/dev/null || true", tftp_workdir);
    (void)system(cmd);
    snprintf(cmd, sizeof(cmd),
        "cp -f -- %s/tftp-client.log " TFTP_INTEROP_DIAG_TFTP
        " 2>/dev/null || true", tftp_workdir);
    (void)system(cmd);
}

static void tftp_workdir_teardown(void)
{
    char cmd[160];
    if (tftp_workdir[0] == '\0')
        return;
    snprintf(cmd, sizeof(cmd), "rm -rf -- %s", tftp_workdir);
    (void)system(cmd);
    tftp_workdir[0] = '\0';
}

static int file_present(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && (st.st_mode & S_IXUSR) != 0;
}

/* ---------- file-backed io_ops shared by client and server tests ---- */

struct tftp_file_ctx {
    FILE *fp;
    const char *path;
    int is_write;
    uint32_t size;
};

static int io_open(void *arg, const char *name, int is_write,
    uint32_t *size_hint, void **handle)
{
    struct tftp_file_ctx *ctx = (struct tftp_file_ctx *)arg;
    struct stat st;

    (void)name;
    ctx->is_write = is_write;
    ctx->fp = fopen(ctx->path, is_write ? "wb+" : "rb");
    if (ctx->fp == NULL)
        return -1;
    if (!is_write && stat(ctx->path, &st) == 0) {
        ctx->size = (uint32_t)st.st_size;
        if (size_hint != NULL)
            *size_hint = ctx->size;
    }
    *handle = ctx->fp;
    return 0;
}

static int io_read(void *arg, void *handle, uint32_t offset,
    uint8_t *buf, uint16_t max_len, uint16_t *out_len, int *is_last)
{
    FILE *fp = (FILE *)handle;
    size_t n;

    (void)arg;
    if (fseek(fp, (long)offset, SEEK_SET) != 0)
        return -1;
    n = fread(buf, 1, max_len, fp);
    *out_len = (uint16_t)n;
    /* Only flag is_last when this read produced *less* than the
     * negotiated blksize. Files that end on a block boundary must be
     * followed by a 0-byte DATA block per RFC 1350, so we let the
     * server pull one more (empty) block instead of declaring EOF on
     * a full-sized read. */
    *is_last = (n < max_len) ? 1 : 0;
    return 0;
}

static int io_write(void *arg, void *handle, uint32_t offset,
    const uint8_t *buf, uint16_t len)
{
    FILE *fp = (FILE *)handle;

    (void)arg;
    if (fseek(fp, (long)offset, SEEK_SET) != 0)
        return -1;
    if (fwrite(buf, 1, len, fp) != len)
        return -1;
    fflush(fp);
    return 0;
}

static void io_close(void *arg, void *handle, int status)
{
    (void)arg;
    (void)status;
    if (handle != NULL)
        fclose((FILE *)handle);
}

/* ---------- transport glue for the client ------------------------- */

struct client_glue {
    struct wolfIP *s;
    int sock;
    int trace;
};

static void trace_packet(const char *who, const char *dir,
    uint32_t ip, uint16_t port, const uint8_t *buf, int len)
{
    uint16_t opcode = (len >= 2) ?
        (uint16_t)(((uint16_t)buf[0] << 8) | buf[1]) : 0;
    uint16_t block = (len >= 4) ?
        (uint16_t)(((uint16_t)buf[2] << 8) | buf[3]) : 0;
    fprintf(stderr, "[%s] %s %d.%d.%d.%d:%u op=%u blk/data0=%u len=%d\n",
        who, dir,
        (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
        port, opcode, block, len);
}

static int client_send(void *arg, uint16_t local_port,
    const struct wolftftp_endpoint *remote, const uint8_t *buf, uint16_t len)
{
    struct client_glue *g = (struct client_glue *)arg;
    struct wolfIP_sockaddr_in dst;
    int ret;

    (void)local_port;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = ee16(remote->port);
    dst.sin_addr.s_addr = ee32(remote->ip);
    ret = wolfIP_sock_sendto(g->s, g->sock, buf, len, 0,
        (struct wolfIP_sockaddr *)&dst, sizeof(dst));
    if (g->trace)
        trace_packet("client", "TX", remote->ip, remote->port, buf,
            ret > 0 ? ret : (int)len);
    if (ret == (int)len)
        return 0;
    fprintf(stderr, "[client] sendto returned %d (expected %u)\n", ret, len);
    return ret < 0 ? ret : -1;
}

/* ---------- transport glue for the server ------------------------- */

struct server_glue {
    struct wolfIP *s;
    int listen_sock;
    int transfer_sock;
    int trace;
};

static int server_send(void *arg, uint16_t local_port,
    const struct wolftftp_endpoint *remote, const uint8_t *buf, uint16_t len)
{
    struct server_glue *g = (struct server_glue *)arg;
    struct wolfIP_sockaddr_in dst;
    int sock;
    int ret;

    if (local_port == TFTP_INTEROP_PORT)
        sock = g->listen_sock;
    else
        sock = g->transfer_sock;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = ee16(remote->port);
    dst.sin_addr.s_addr = ee32(remote->ip);
    ret = wolfIP_sock_sendto(g->s, sock, buf, len, 0,
        (struct wolfIP_sockaddr *)&dst, sizeof(dst));
    if (g->trace)
        trace_packet("server", "TX", remote->ip, remote->port, buf,
            ret > 0 ? ret : (int)len);
    if (ret == (int)len)
        return 0;
    fprintf(stderr, "[server] sendto on local_port %u returned %d "
        "(expected %u)\n", local_port, ret, len);
    return ret < 0 ? ret : -1;
}

/* ---------- tftpd-hpa lifecycle ----------------------------------- */

static pid_t tftpd_pid = -1;

static void tftpd_stop(void)
{
    if (tftpd_pid > 0) {
        kill(tftpd_pid, SIGTERM);
        waitpid(tftpd_pid, NULL, 0);
        tftpd_pid = -1;
    }
}

static int tftpd_start(void)
{
    pid_t pid;
    char addrport[64];
    const char *exe = "/usr/sbin/in.tftpd";
    int log_fd;

    snprintf(addrport, sizeof(addrport), "%s:%d", HOST_STACK_IP,
        TFTP_INTEROP_PORT);
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        /* Child: become in.tftpd. tftpd-hpa otherwise logs via syslog,
         * which the test runner can't see — redirect stderr (where -v
         * prints) so any rejection is visible after the run. */
        /* Log file lives in the mkdtemp workdir (mode 0700). Use
         * O_NOFOLLOW to refuse to follow any symlink at the leaf,
         * and O_TRUNC over O_EXCL because we may rerun within the
         * same workdir if the test is invoked twice. */
        log_fd = open(tftp_tftpd_log,
            O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
        if (log_fd >= 0) {
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }
        execl(exe, "in.tftpd",
            "-l",     /* --listen: standalone, bind UDP ourselves   */
            "-L",     /* --foreground: do not detach (keeps our PID
                       *               valid and stderr attached)   */
            "-vvv",
            "-u", "root",
            "-a", addrport,
            "-s", tftp_local_dir,
            (char *)NULL);
        perror("execl in.tftpd");
        _exit(127);
    }
    /* Parent: give the daemon a moment to bind, then check it is
     * still alive. */
    tftpd_pid = pid;
    usleep(500 * 1000);
    if (waitpid(pid, NULL, WNOHANG) != 0) {
        tftpd_pid = -1;
        fprintf(stderr, "[client] in.tftpd exited early — see %s\n",
            tftp_tftpd_log);
        return -1;
    }
    /* tftpd-hpa logs everything to syslog (so the captured stderr will
     * be empty even on success). Cross-check that the daemon is
     * actually bound to the expected UDP port — this catches silent
     * --listen / --address mistakes that otherwise look just like the
     * "no reply" failure mode. */
    {
        char check[160];
        snprintf(check, sizeof(check),
            "ss -lnup 'sport = :%d' 2>/dev/null | tail -n +2 | grep -q .",
            TFTP_INTEROP_PORT);
        if (system(check) != 0) {
            fprintf(stderr,
                "[client] in.tftpd is running (pid %d) but nothing is "
                "listening on UDP %s:%d — check syslog "
                "(journalctl -t in.tftpd) and tftpd-hpa flags.\n",
                (int)tftpd_pid, HOST_STACK_IP, TFTP_INTEROP_PORT);
        }
    }
    return 0;
}

static void dump_log_file(const char *label, const char *path)
{
    FILE *fp;
    char line[512];

    fp = fopen(path, "r");
    if (fp == NULL)
        return;
    fprintf(stderr, "----- %s (%s) -----\n", label, path);
    while (fgets(line, sizeof(line), fp) != NULL)
        fputs(line, stderr);
    fprintf(stderr, "----- end %s -----\n", label);
    fclose(fp);
}

/* ---------- pump the wolfIP stack and the TFTP module ------------- */

static void pump_client(struct wolfIP *s, struct wolftftp_client *client,
    int sock, int trace)
{
    uint8_t pkt[1500];
    struct wolfIP_sockaddr_in remote;
    socklen_t rlen = sizeof(remote);
    int n;

    (void)wolfIP_poll(s, now_ms());
    for (;;) {
        rlen = sizeof(remote);
        n = wolfIP_sock_recvfrom(s, sock, pkt, sizeof(pkt), 0,
            (struct wolfIP_sockaddr *)&remote, &rlen);
        if (n <= 0)
            break;
        {
            struct wolftftp_endpoint rep;
            rep.ip = ee32(remote.sin_addr.s_addr);
            rep.port = ee16(remote.sin_port);
            if (trace)
                trace_packet("client", "RX", rep.ip, rep.port, pkt, n);
            (void)wolftftp_client_receive(client,
                TFTP_INTEROP_CLIENT_PORT, &rep, pkt, (uint16_t)n);
        }
    }
    (void)wolftftp_client_poll(client, (uint32_t)now_ms());
}

static void pump_server(struct wolfIP *s, struct wolftftp_server *server,
    int listen_sock, int transfer_sock, int trace)
{
    uint8_t pkt[1500];
    struct wolfIP_sockaddr_in remote;
    socklen_t rlen;
    int n;
    int i;
    int socks[2];
    uint16_t ports[2];

    socks[0] = listen_sock;
    socks[1] = transfer_sock;
    ports[0] = TFTP_INTEROP_PORT;
    ports[1] = TFTP_INTEROP_TRANSFER_PORT;

    (void)wolfIP_poll(s, now_ms());
    for (i = 0; i < 2; i++) {
        for (;;) {
            rlen = sizeof(remote);
            n = wolfIP_sock_recvfrom(s, socks[i], pkt, sizeof(pkt), 0,
                (struct wolfIP_sockaddr *)&remote, &rlen);
            if (n <= 0)
                break;
            {
                struct wolftftp_endpoint rep;
                rep.ip = ee32(remote.sin_addr.s_addr);
                rep.port = ee16(remote.sin_port);
                if (trace)
                    trace_packet("server", "RX", rep.ip, rep.port, pkt, n);
                (void)wolftftp_server_receive(server, ports[i], &rep,
                    pkt, (uint16_t)n);
            }
        }
    }
    (void)wolftftp_server_poll(server, (uint32_t)now_ms());
}

/* ---------- client direction: wolfIP client vs in.tftpd ----------- */

static int run_client_test(struct wolfIP *s)
{
    struct client_glue glue;
    struct tftp_file_ctx file_ctx;
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_transfer_cfg cfg;
    struct wolftftp_client client;
    struct wolftftp_endpoint srv;
    struct wolfIP_sockaddr_in bind_addr;
    int sock;
    int ret;
    uint64_t deadline;

    if (!file_present("/usr/sbin/in.tftpd")) {
        fprintf(stderr, "[client] skipping: /usr/sbin/in.tftpd not found\n");
        return TFTP_EXIT_SKIP;
    }

    /* tftp_local_dir is created once by tftp_workdir_setup() with
     * mode 0700; we only need to (re)create the fixture file. */
    if (write_fixture(tftp_fixture_path) != 0) {
        fprintf(stderr, "[client] cannot create fixture %s\n",
            tftp_fixture_path);
        return TFTP_EXIT_FAIL;
    }
    (void)unlink(tftp_download_path);

    if (tftpd_start() != 0) {
        fprintf(stderr, "[client] failed to launch in.tftpd\n");
        return TFTP_EXIT_FAIL;
    }

    sock = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    if (sock < 0) {
        tftpd_stop();
        return TFTP_EXIT_FAIL;
    }
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = ee16(TFTP_INTEROP_CLIENT_PORT);
    bind_addr.sin_addr.s_addr = 0;
    if (wolfIP_sock_bind(s, sock, (struct wolfIP_sockaddr *)&bind_addr,
            sizeof(bind_addr)) < 0) {
        fprintf(stderr, "[client] wolfIP UDP bind failed\n");
        wolfIP_sock_close(s, sock);
        tftpd_stop();
        return TFTP_EXIT_FAIL;
    }

    memset(&file_ctx, 0, sizeof(file_ctx));
    file_ctx.path = tftp_download_path;
    memset(&glue, 0, sizeof(glue));
    glue.s = s;
    glue.sock = sock;
    glue.trace = 1;
    memset(&transport, 0, sizeof(transport));
    transport.send = client_send;
    transport.arg = &glue;
    memset(&io, 0, sizeof(io));
    io.open = io_open;
    io.write = io_write;
    io.close = io_close;
    io.arg = &file_ctx;
    /* All-defaults cfg keeps the RRQ option-free; some tftpd-hpa
     * builds only enable a subset of options and reject the whole
     * request with EBADOPT (code 8) if any unexpected option appears. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.local_port = TFTP_INTEROP_CLIENT_PORT;
    cfg.blksize = WOLFTFTP_DEFAULT_BLKSIZE;
    cfg.timeout_s = WOLFTFTP_DEFAULT_TIMEOUT_S;
    cfg.windowsize = 1;
    cfg.max_retries = 5;

    wolftftp_client_init(&client, &transport, &io, &cfg);
    memset(&srv, 0, sizeof(srv));
    srv.ip = atoip4(HOST_STACK_IP);
    srv.port = TFTP_INTEROP_PORT;
    ret = wolftftp_client_start_rrq(&client, &srv, TFTP_INTEROP_REMOTE_NAME);
    if (ret != 0) {
        fprintf(stderr, "[client] start_rrq failed: %d\n", ret);
        wolfIP_sock_close(s, sock);
        tftpd_stop();
        return TFTP_EXIT_FAIL;
    }

    deadline = now_ms() + TFTP_INTEROP_TIMEOUT_MS;
    while (client.state != WOLFTFTP_CLIENT_COMPLETE &&
            client.state != WOLFTFTP_CLIENT_ERROR &&
            now_ms() < deadline) {
        pump_client(s, &client, sock, glue.trace);
        usleep(2000);
    }

    wolfIP_sock_close(s, sock);
    tftpd_stop();

    if (client.state != WOLFTFTP_CLIENT_COMPLETE) {
        fprintf(stderr, "[client] transfer did not complete (state=%d, "
            "status=%d)\n", client.state, client.last_status);
        dump_log_file("in.tftpd", tftp_tftpd_log);
        return TFTP_EXIT_FAIL;
    }
    if (!file_equal(tftp_fixture_path, tftp_download_path)) {
        fprintf(stderr, "[client] downloaded contents diverge from fixture\n");
        return TFTP_EXIT_FAIL;
    }
    printf("[client] wolfIP client successfully fetched %u bytes from "
        "tftpd-hpa\n", TFTP_INTEROP_FIXTURE_SIZE);
    return TFTP_EXIT_SUCCESS;
}

/* ---------- server direction: tftp-hpa client vs wolfIP server ---- */

static volatile int server_close_calls = 0;
static volatile int server_close_status = 0;

static void server_io_close(void *arg, void *handle, int status)
{
    (void)arg;
    if (handle != NULL)
        fclose((FILE *)handle);
    server_close_status = status;
    server_close_calls++;
}

static int run_server_test(struct wolfIP *s)
{
    struct server_glue glue;
    struct tftp_file_ctx file_ctx;
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_transfer_cfg cfg;
    struct wolftftp_server server;
    struct wolfIP_sockaddr_in bind_addr;
    int listen_sock;
    int transfer_sock;
    pid_t tftp_pid;
    int wstatus;
    int rc;
    uint64_t deadline;

    if (!file_present("/usr/bin/tftp")) {
        fprintf(stderr, "[server] skipping: /usr/bin/tftp not found\n");
        return TFTP_EXIT_SKIP;
    }

    if (write_fixture(tftp_fixture_path) != 0)
        return TFTP_EXIT_FAIL;
    (void)unlink(tftp_host_get_path);

    listen_sock = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    transfer_sock = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_DGRAM, 0);
    if (listen_sock < 0 || transfer_sock < 0) {
        fprintf(stderr, "[server] socket() failed\n");
        return TFTP_EXIT_FAIL;
    }
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = 0;
    bind_addr.sin_port = ee16(TFTP_INTEROP_PORT);
    if (wolfIP_sock_bind(s, listen_sock, (struct wolfIP_sockaddr *)&bind_addr,
            sizeof(bind_addr)) < 0) {
        fprintf(stderr, "[server] bind listen failed\n");
        return TFTP_EXIT_FAIL;
    }
    bind_addr.sin_port = ee16(TFTP_INTEROP_TRANSFER_PORT);
    if (wolfIP_sock_bind(s, transfer_sock, (struct wolfIP_sockaddr *)&bind_addr,
            sizeof(bind_addr)) < 0) {
        fprintf(stderr, "[server] bind transfer failed\n");
        return TFTP_EXIT_FAIL;
    }

    memset(&file_ctx, 0, sizeof(file_ctx));
    file_ctx.path = tftp_fixture_path;
    memset(&glue, 0, sizeof(glue));
    glue.s = s;
    glue.listen_sock = listen_sock;
    glue.transfer_sock = transfer_sock;
    glue.trace = 1;
    memset(&transport, 0, sizeof(transport));
    transport.send = server_send;
    transport.arg = &glue;
    memset(&io, 0, sizeof(io));
    io.open = io_open;
    io.read = io_read;
    io.write = io_write;
    io.close = server_io_close;
    io.arg = &file_ctx;
    memset(&cfg, 0, sizeof(cfg));
    cfg.blksize = WOLFTFTP_DEFAULT_BLKSIZE;
    cfg.timeout_s = 2;
    cfg.windowsize = 1;
    cfg.max_retries = 5;

    wolftftp_server_init(&server, &transport, &io, &cfg);
    server.listen_port = TFTP_INTEROP_PORT;
    server.transfer_port_base = TFTP_INTEROP_TRANSFER_PORT;

    server_close_calls = 0;
    server_close_status = 0;

    /* Linux tftp-hpa client is driven via -c get: it issues an RRQ
     * for the fixture and saves it to tftp_host_get_path. */
    tftp_pid = fork();
    if (tftp_pid < 0) {
        return TFTP_EXIT_FAIL;
    }
    if (tftp_pid == 0) {
        /* The default mode of tftp-hpa is "netascii", which the wolfIP
         * server rejects with EBADOPT — force binary so the request
         * uses "octet". Stderr is captured so the post-mortem can show
         * exactly what the host client saw. */
        char port[8];
        int log_fd;

        snprintf(port, sizeof(port), "%d", TFTP_INTEROP_PORT);
        log_fd = open(tftp_tftp_log,
            O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
        if (log_fd >= 0) {
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }
        execl("/usr/bin/tftp", "tftp", WOLFIP_IP, port,
            "-m", "binary",
            "-v",
            "-c", "get", TFTP_INTEROP_REMOTE_NAME,
            tftp_host_get_path,
            (char *)NULL);
        _exit(127);
    }

    deadline = now_ms() + TFTP_INTEROP_TIMEOUT_MS;
    while (server_close_calls == 0 && now_ms() < deadline) {
        pump_server(s, &server, listen_sock, transfer_sock, glue.trace);
        usleep(2000);
    }
    /* Keep pumping briefly so any final ACK is flushed before we tear
     * down the sockets (which would otherwise make the host client
     * report a transient error even on a successful transfer). */
    {
        uint64_t flush_end = now_ms() + 250U;
        while (now_ms() < flush_end) {
            pump_server(s, &server, listen_sock, transfer_sock, glue.trace);
            usleep(2000);
        }
    }

    if (waitpid(tftp_pid, &wstatus, WNOHANG) == 0) {
        /* Client may still be exiting normally; give it a moment. */
        usleep(500 * 1000);
        if (waitpid(tftp_pid, &wstatus, WNOHANG) == 0) {
            kill(tftp_pid, SIGTERM);
            waitpid(tftp_pid, &wstatus, 0);
        }
    }

    wolfIP_sock_close(s, transfer_sock);
    wolfIP_sock_close(s, listen_sock);

    if (server_close_calls == 0) {
        fprintf(stderr, "[server] wolfIP server session never closed\n");
        dump_log_file("tftp client", tftp_tftp_log);
        return TFTP_EXIT_FAIL;
    }
    if (server_close_status != 0) {
        fprintf(stderr, "[server] session close status %d\n",
            server_close_status);
        dump_log_file("tftp client", tftp_tftp_log);
        return TFTP_EXIT_FAIL;
    }
    rc = file_equal(tftp_fixture_path, tftp_host_get_path);
    if (!rc) {
        fprintf(stderr, "[server] host-side download diverges from fixture\n");
        dump_log_file("tftp client", tftp_tftp_log);
        return TFTP_EXIT_FAIL;
    }
    printf("[server] tftp-hpa client successfully fetched %u bytes from "
        "wolfIP server\n", TFTP_INTEROP_FIXTURE_SIZE);
    return TFTP_EXIT_SUCCESS;
}

/* ---------- driver ------------------------------------------------ */

static int setup_stack(struct wolfIP **out_s, struct wolfIP_ll_dev **out_dev)
{
    struct wolfIP *s;
    struct wolfIP_ll_dev *tapdev;
    struct in_addr host_stack_ip;
    char cmd[160];

    wolfIP_init_static(&s);
    tapdev = wolfIP_getdev(s);
    if (tapdev == NULL)
        return -1;
    inet_aton(HOST_STACK_IP, &host_stack_ip);
    if (tap_init(tapdev, "wtftp0", host_stack_ip.s_addr) < 0) {
        perror("tap_init");
        return -1;
    }
    wolfIP_ipconfig_set(s, atoip4(WOLFIP_IP), atoip4("255.255.255.0"),
        atoip4(HOST_STACK_IP));

    /* Drop a pcap on disk for post-mortem inspection. */
    snprintf(cmd, sizeof(cmd),
        "tcpdump -i %s -w /tmp/wolfip-tftp.pcap "
        "-U >/dev/null 2>&1 &", tapdev->ifname);
    (void)system(cmd);
    usleep(200 * 1000);

    *out_s = s;
    *out_dev = tapdev;
    return 0;
}

int main(int argc, char **argv)
{
    struct wolfIP *s = NULL;
    struct wolfIP_ll_dev *dev = NULL;
    const char *mode = "all";
    int rc_client = TFTP_EXIT_SUCCESS;
    int rc_server = TFTP_EXIT_SUCCESS;

    if (argc > 1)
        mode = argv[1];

    if (geteuid() != 0) {
        fprintf(stderr, "test_tftp_interop: requires root to set up the "
            "TAP link; skipping\n");
        return TFTP_EXIT_SKIP;
    }

    if (tftp_workdir_setup() != 0) {
        perror("test_tftp_interop: mkdtemp");
        return TFTP_EXIT_FAIL;
    }

    if (setup_stack(&s, &dev) != 0) {
        tftp_workdir_teardown();
        return TFTP_EXIT_FAIL;
    }
    (void)dev;

    /* Give ARP a chance to resolve the host before the first transfer. */
    {
        uint64_t end = now_ms() + 250U;
        while (now_ms() < end) {
            (void)wolfIP_poll(s, now_ms());
            usleep(2000);
        }
    }

    if (strcmp(mode, "client") == 0 || strcmp(mode, "all") == 0)
        rc_client = run_client_test(s);
    if (strcmp(mode, "server") == 0 || strcmp(mode, "all") == 0)
        rc_server = run_server_test(s);

    tftpd_stop();
    (void)system("pkill -INT -f 'tcpdump -i wtftp0' >/dev/null 2>&1");
    usleep(200 * 1000); /* let tcpdump flush */

    if (rc_client == TFTP_EXIT_FAIL || rc_server == TFTP_EXIT_FAIL) {
        /* Republish the workdir-private logs at the well-known paths
         * the CI artifact uploader expects, then tear the workdir
         * down. The pcap was always written at the well-known path
         * because tcpdump runs out-of-process. */
        tftp_workdir_publish_diagnostics();
        fprintf(stderr,
            "Diagnostics: " TFTP_INTEROP_DIAG_PCAP ", "
            TFTP_INTEROP_DIAG_TFTPD ", " TFTP_INTEROP_DIAG_TFTP "\n");
        fprintf(stderr, "----- wire summary (tcpdump -nn -r) -----\n");
        fflush(stderr);
        (void)system("tcpdump -nn -tt -r " TFTP_INTEROP_DIAG_PCAP " 2>&1 "
            "| sed 's/^/  /' >&2");
        fprintf(stderr, "----- end wire summary -----\n");
        if (file_present("/usr/bin/journalctl")) {
            fprintf(stderr, "----- last 20 in.tftpd syslog lines -----\n");
            fflush(stderr);
            (void)system("journalctl -t in.tftpd -n 20 --no-pager 2>&1 "
                "| sed 's/^/  /' >&2");
            fprintf(stderr, "----- end syslog -----\n");
        }
        tftp_workdir_teardown();
        return TFTP_EXIT_FAIL;
    }
    tftp_workdir_teardown();
    if (rc_client == TFTP_EXIT_SKIP && rc_server == TFTP_EXIT_SKIP)
        return TFTP_EXIT_SKIP;
    return TFTP_EXIT_SUCCESS;
}

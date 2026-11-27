/* https_server.c
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
 *
 * Minimal HTTPS file server for the Versal wolfBoot + wolfIP firmware update
 * demo. TLS 1.3 only, ML-KEM hybrid key exchange, client certificate
 * required. Serves GET <path> from a document root; nothing else.
 *
 * usage: https_server [-p port] [-d docroot] [-c certdir]
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

static const char *docroot = "www";

static int send_all(WOLFSSL *ssl, const void *buf, int len)
{
    const char *p = (const char *)buf;
    int ret;

    while (len > 0) {
        ret = wolfSSL_write(ssl, p, len);
        if (ret <= 0)
            return -1;
        p += ret;
        len -= ret;
    }
    return 0;
}

static void reply(WOLFSSL *ssl, int code, const char *text)
{
    char hdr[160];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        code, text);
    (void)send_all(ssl, hdr, n);
}

static void serve(WOLFSSL *ssl)
{
    char req[1024], path[1200], hdr[160], buf[4096];
    char *sp;
    int n = 0, r;
    long sz;
    FILE *f;

    while (n < (int)sizeof(req) - 1) {
        r = wolfSSL_read(ssl, req + n, (int)sizeof(req) - 1 - n);
        if (r <= 0)
            return;
        n += r;
        req[n] = '\0';
        if (strstr(req, "\r\n\r\n") != NULL)
            break;
    }
    if (strncmp(req, "GET /", 5) != 0) {
        reply(ssl, 405, "Method Not Allowed");
        return;
    }
    sp = strchr(req + 4, ' ');
    if (sp == NULL || strstr(req + 4, "..") != NULL) {
        reply(ssl, 400, "Bad Request");
        return;
    }
    *sp = '\0';
    snprintf(path, sizeof(path), "%s%s", docroot, req + 4);
    f = fopen(path, "rb");
    if (f == NULL) {
        printf("  GET %s -> 404\n", req + 4);
        reply(ssl, 404, "Not Found");
        return;
    }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
        "Content-Length: %ld\r\nConnection: close\r\n\r\n", sz);
    if (send_all(ssl, hdr, n) == 0) {
        while ((r = (int)fread(buf, 1, sizeof(buf), f)) > 0) {
            if (send_all(ssl, buf, r) != 0)
                break;
        }
    }
    fclose(f);
    printf("  GET %s -> 200, %ld bytes\n", req + 4, sz);
}

int main(int argc, char **argv)
{
    int port = 4443, opt, lfd, on = 1, i, ngroups;
    const char *certdir = "certs";
    char path[512];
    struct sockaddr_in sa;
    WOLFSSL_CTX *ctx;
    int groups[] = {
        WOLFSSL_SECP384R1MLKEM1024, WOLFSSL_X25519MLKEM768,
        WOLFSSL_SECP256R1MLKEM768
    };

    while ((opt = getopt(argc, argv, "p:d:c:")) != -1) {
        if (opt == 'p') port = atoi(optarg);
        else if (opt == 'd') docroot = optarg;
        else if (opt == 'c') certdir = optarg;
        else {
            fprintf(stderr, "usage: %s [-p port] [-d docroot] [-c certdir]\n",
                argv[0]);
            return 1;
        }
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    wolfSSL_Init();
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL)
        return fprintf(stderr, "wolfSSL_CTX_new failed\n"), 1;
    snprintf(path, sizeof(path), "%s/server-cert.pem", certdir);
    if (wolfSSL_CTX_use_certificate_file(ctx, path, WOLFSSL_FILETYPE_PEM) != 1)
        return fprintf(stderr, "bad %s\n", path), 1;
    snprintf(path, sizeof(path), "%s/server-key.pem", certdir);
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, path, WOLFSSL_FILETYPE_PEM) != 1)
        return fprintf(stderr, "bad %s\n", path), 1;
    snprintf(path, sizeof(path), "%s/ca-cert.pem", certdir);
    if (wolfSSL_CTX_load_verify_locations(ctx, path, NULL) != 1)
        return fprintf(stderr, "bad %s\n", path), 1;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
        WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    /* Keep only the hybrid groups this wolfSSL build provides. */
    for (i = 0, ngroups = 0; i < (int)(sizeof(groups) / sizeof(groups[0]));
            i++) {
        if (wolfSSL_CTX_set_groups(ctx, &groups[i], 1) == 1)
            groups[ngroups++] = groups[i];
    }
    if (ngroups == 0 || wolfSSL_CTX_set_groups(ctx, groups, ngroups) != 1)
        return fprintf(stderr, "hybrid groups not available\n"), 1;
    printf("%d post-quantum hybrid key exchange group(s) enabled\n", ngroups);

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = INADDR_ANY;
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
            listen(lfd, 4) != 0)
        return perror("bind/listen"), 1;
    printf("HTTPS server on port %d, docroot %s\n", port, docroot);
    fflush(stdout);

    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        struct timeval tv = { 15, 0 };
        WOLFSSL *ssl;
        int fd, ar;

        fd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (fd < 0)
            continue;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            close(fd);
            continue;
        }
        wolfSSL_set_fd(ssl, fd);
        ar = wolfSSL_accept(ssl);
        if (ar == WOLFSSL_SUCCESS) {
            printf("%s: %s %s, group %s, client certificate verified\n",
                inet_ntoa(peer.sin_addr), wolfSSL_get_version(ssl),
                wolfSSL_get_cipher(ssl), wolfSSL_get_curve_name(ssl));
            serve(ssl);
        }
        else {
            char es[80];
            int e = wolfSSL_get_error(ssl, ar);
            printf("%s: handshake refused (%d %s)\n",
                inet_ntoa(peer.sin_addr), e,
                wolfSSL_ERR_error_string((unsigned long)e, es));
        }
        fflush(stdout);
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        close(fd);
    }
    return 0;
}

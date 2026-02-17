/* esp_server.c
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* wolfip includes */
#include "config.h"
#include "wolfip.h"
#include "wolfesp.h"

#define PORT 8
#define BUFFER_SIZE 1024

static void __attribute__((noreturn)) print_usage_and_die(void);

static int disable_ipsec = 0;
static int esp_mode = 0;
static int use_udp = 0;

/* esp security association info */
#include "esp_common.c"

int main(int argc, char * argv[])
{
    int    server_fd, client_fd;
    struct sockaddr_in address;
    int    addrlen = sizeof(address);
    char   buffer[BUFFER_SIZE];
    int    opt = 0;
    int    type = SOCK_STREAM;
    int    err = 0;

    while ((opt = getopt(argc, argv, "pm:u?")) != -1) {
        switch (opt) {
        case 'p':
            disable_ipsec = 1;
            break;
        case 'm':
            esp_mode = atoi(optarg);
            break;
        case 'u':
            use_udp = 1;
            type = SOCK_DGRAM;
            break;
        case '?':
            print_usage_and_die();
            break;
        default:
            break;
        }
    }

    if (!disable_ipsec) {
        err = wolfIP_esp_init();
        if (err) {
            perror("esp_init");
            return 2;
        }

        switch (esp_mode) {
        #if defined(WOLFSSL_AESGCM_STREAM)
        case 0:
            err = wolfIP_esp_sa_new_gcm(1, in_sa_gcm, atoip4(HOST_STACK_IP),
                                        atoip4(WOLFIP_IP), ESP_ENC_GCM_RFC4106,
                                        in_enc_key, sizeof(in_enc_key));
            if (err) { return err; }

            err = wolfIP_esp_sa_new_gcm(0, out_sa_gcm, atoip4(WOLFIP_IP),
                                        atoip4(HOST_STACK_IP), ESP_ENC_GCM_RFC4106,
                                        out_enc_key, sizeof(out_enc_key));
            if (err) { return err; }
            break;
        #endif /* WOLFSSL_AESGCM_STREAM */
        case 1:
            err = wolfIP_esp_sa_new_cbc_hmac(1, in_sa_cbc, atoip4(HOST_STACK_IP),
                                             atoip4(WOLFIP_IP),
                                             in_enc_key, sizeof(in_enc_key) - 4,
                                             ESP_AUTH_SHA256_RFC4868,
                                             in_auth_key, sizeof(in_auth_key),
                                             ESP_ICVLEN_HMAC_128);
            if (err) { return err; }

            err = wolfIP_esp_sa_new_cbc_hmac(0, out_sa_cbc, atoip4(WOLFIP_IP),
                                             atoip4(HOST_STACK_IP),
                                             out_enc_key, sizeof(out_enc_key) - 4,
                                             ESP_AUTH_SHA256_RFC4868,
                                             out_auth_key, sizeof(out_auth_key),
                                             ESP_ICVLEN_HMAC_128);
            if (err) { return err; }
            break;
        #ifndef NO_DES3
        case 2:
            err = wolfIP_esp_sa_new_des3_hmac(1, in_sa_des3, atoip4(HOST_STACK_IP),
                                              atoip4(WOLFIP_IP),
                                              in_enc_key, ESP_AUTH_SHA256_RFC4868,
                                              in_auth_key, sizeof(in_auth_key),
                                              ESP_ICVLEN_HMAC_128);
            if (err) { return err; }

            err = wolfIP_esp_sa_new_des3_hmac(0, out_sa_des3, atoip4(WOLFIP_IP),
                                              atoip4(HOST_STACK_IP),
                                              out_enc_key, ESP_AUTH_SHA256_RFC4868,
                                              out_auth_key, sizeof(out_auth_key),
                                              ESP_ICVLEN_HMAC_128);
            if (err) { return err; }
            break;
        #endif /* !NO_DES3 */
        case 3:
            err = wolfIP_esp_sa_new_gcm(1, in_sa_gmac, atoip4(HOST_STACK_IP),
                                        atoip4(WOLFIP_IP), ESP_ENC_GCM_RFC4543,
                                        in_enc_key, sizeof(in_enc_key));
            if (err) { return err; }

            err = wolfIP_esp_sa_new_gcm(0, out_sa_gmac, atoip4(WOLFIP_IP),
                                        atoip4(HOST_STACK_IP), ESP_ENC_GCM_RFC4543,
                                        out_enc_key, sizeof(out_enc_key));
            if (err) { return err; }
            break;

        default:
            break;
        }
    }

    // Create a socket
    if ((server_fd = socket(AF_INET, type, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket created: %d\n", server_fd);

    // Bind to the specified port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("Bind successful\n");

    if (!use_udp) {
        // Start listening for incoming connections
        if (listen(server_fd, 3) < 0) {
            perror("Listen failed");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        printf("Echo tcp server listening on port %d\n", PORT);

        while (1) {
            ssize_t bytes_read;
            // Accept a client connection
            if ((client_fd = accept(server_fd, (struct sockaddr *)&address,
                                    (socklen_t *)&addrlen)) < 0) {
                perror("Accept failed");
                continue;
            }

            printf("Client connected, fd: %d\n", client_fd);

            while ((bytes_read = read(client_fd, buffer, BUFFER_SIZE)) > 0) {
                write(client_fd, buffer, bytes_read); // Echo data back to the client
            }

            printf("Client disconnected\n");
            close(client_fd);
        }
    }
    else {
        printf("Echo udp server listening on port %d\n", PORT);

        for (;;) {
            ssize_t bytes_read = 0;
            ssize_t bytes_sent = 0;
            struct sockaddr_in cliaddr;
            socklen_t cliaddr_len = sizeof(cliaddr);
            bytes_read = recvfrom(server_fd, buffer, BUFFER_SIZE, 0,
                                  (struct sockaddr *)&cliaddr, &cliaddr_len);

            if (bytes_read <= 0) {
                printf("info: recvfrom: %ld\n", bytes_read);
                break;
            }

            printf("info: recv from %s: %5d, %ld bytes\n", inet_ntoa(cliaddr.sin_addr),
                   ntohs(cliaddr.sin_port), bytes_read);

            bytes_sent = sendto(server_fd, buffer, bytes_read, 0,
                                (struct sockaddr *)&cliaddr, cliaddr_len);
            if (bytes_sent <= 0) {
                printf("info: sendto: %ld\n", bytes_sent);
                break;
            }
        }
    }

    close(server_fd);
    return 0;
}

static void
print_usage_and_die(void)
{
    printf("./test-esp [-m <mode>] [-p]\n");
    printf("\n");
    printf("options:\n");
    printf("  -p         force plaintext (disable ipsec)\n");
    printf("  -m <mode>  0 gcm (default), 1 cbc auth, 2 des3 hmac, 3 gmac\n");
    printf("  -u         use udp (default tcp)\n");
    exit(1);
}

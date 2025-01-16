/* tcp_netcat_select.c
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>

#define PORT 12346

int main() {
    int server_fd, new_socket = -1;
    struct sockaddr_in server_addr;
    fd_set readfds;
    int max_fd;

    // Create a TCP socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("server socket: %d\n", server_fd);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind the socket to the address
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) == -1) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Initialize file descriptor sets
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);  // Monitor stdin
    FD_SET(server_fd, &readfds);      // Monitor the server socket
    max_fd = server_fd;

    while (1) {
        fd_set tempfds = readfds;
        int activity = select(max_fd + 1, &tempfds, NULL, NULL, NULL);
        if (activity == -1) {
            perror("Select error");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(STDIN_FILENO, &tempfds)) {
            // Data available on stdin
            char buffer[1024];
            ssize_t bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (bytes_read > 0 && new_socket != -1) {
                // Write stdin data to the socket
                send(new_socket, buffer, bytes_read, 0);
            }
        }

        if ((new_socket == -1) && FD_ISSET(server_fd, &tempfds)) {
            printf("Server socket activity\n");
            // New connection on the socket
            if (new_socket == -1) {
                new_socket = accept(server_fd, NULL, NULL);
                if (new_socket == -1) {
                    perror("Accept failed");
                    continue;
                }
                printf("New connection established\n");
                FD_SET(new_socket, &readfds);  // Monitor the new socket
                max_fd = (new_socket > max_fd) ? new_socket : max_fd;
                continue;
            }
        }
        if ((new_socket != -1) && FD_ISSET(new_socket, &tempfds)) {
            // Data available on the socket
            char buffer[1024];
            ssize_t bytes_received = recv(new_socket, buffer, sizeof(buffer), 0);
            if (bytes_received > 0) {
                write(STDOUT_FILENO, buffer, bytes_received);
            } else if (bytes_received == 0) {
                // Connection closed by the client
                close(new_socket);
                FD_CLR(new_socket, &readfds);  // Stop monitoring the socket
                new_socket = -1;
                printf("Connection closed\n");
            }
        }
    }

    close(server_fd);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>

#define PORT 12345

int main() {
    int server_fd, new_socket = -1, nfds;
    struct sockaddr_in server_addr;
    struct pollfd fds[2];

    // Create a TCP socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

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

    // Set up poll to monitor stdin and the socket
    fds[0].fd = STDIN_FILENO;  // Monitor stdin
    fds[1].fd = server_fd;  // Monitor the server socket

    while (1) {
        fds[0].events = POLLIN;
        fds[1].events = POLLIN;
        // Poll for events
        nfds = poll(fds, 2, -1);  // -1 means wait indefinitely
        if (nfds == -1) {
            perror("Poll error");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        if (fds[0].revents & POLLIN) {
            // Data available on stdin
            char buffer[1024];
            ssize_t bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (bytes_read > 0) {
                // Write stdin data to the socket
                if (new_socket != -1) {
                    send(new_socket, buffer, bytes_read, 0);
                }
            }
        }

        if (fds[1].revents & POLLIN) {
            // New connection on the socket
            if (new_socket == -1) {
                printf("Calling accept()\n");
                new_socket = accept(server_fd, NULL, NULL);
                if (new_socket == -1) {
                    perror("Accept failed");
                    continue;
                }
                fds[1].fd = new_socket;
                printf("New connection established\n");
                continue;
            } else {
                // Data available on the socket
                char buffer[1024];
                ssize_t bytes_received = recv(new_socket, buffer, sizeof(buffer), 0);
                if (bytes_received > 0) {
                    // Write socket data to stdout
                    write(STDOUT_FILENO, buffer, bytes_received);
                } else if (bytes_received == 0) {
                    // Connection closed by the client
                    close(new_socket);
                    new_socket = -1;
                    fds[1].fd = server_fd;
                    printf("Connection closed\n");
                }
            }
        }
    }

    close(server_fd);
    return 0;
}

/* ssh_server.c
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

#include "ssh_server.h"
#include "ssh_keys.h"

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <string.h>

/* Configuration */
#define SSH_RX_BUF_SIZE 512
#define SSH_TX_BUF_SIZE 512

/* Default credentials (change for production!) */
#define SSH_USERNAME "admin"
#define SSH_PASSWORD "wolfip"

/* SSH server state */
typedef enum {
    SSH_STATE_LISTENING,
    SSH_STATE_ACCEPTING,
    SSH_STATE_KEY_EXCHANGE,
    SSH_STATE_AUTH,
    SSH_STATE_CHANNEL_OPEN,
    SSH_STATE_CONNECTED,
    SSH_STATE_CLOSING
} ssh_state_t;

/* Server context */
static struct {
    struct wolfIP *stack;
    WOLFSSH_CTX *ctx;
    WOLFSSH *ssh;
    int listen_fd;
    int client_fd;
    ssh_state_t state;
    ssh_debug_cb debug_cb;
    uint8_t rx_buf[SSH_RX_BUF_SIZE];
    uint8_t tx_buf[SSH_TX_BUF_SIZE];
    int rx_len;
    uint32_t start_tick;
    int channel_open;
} server;

/* External functions from wolfssh_io.c */
extern void wolfSSH_CTX_SetIO_wolfIP(WOLFSSH_CTX *ctx);
extern int wolfSSH_SetIO_wolfIP(WOLFSSH *ssh, struct wolfIP *stack, int fd);

#ifdef DEBUG_WOLFSSH
/* wolfSSH logging callback */
static void ssh_log_cb(enum wolfSSH_LogLevel level, const char *msg)
{
    (void)level;
    if (server.debug_cb && msg) {
        server.debug_cb(msg);
        server.debug_cb("\n");
    }
}
#endif

/* Debug output helper */
static void debug_print(const char *msg)
{
    if (server.debug_cb) {
        server.debug_cb(msg);
    }
}

/* Password authentication callback */
static int ssh_userauth_cb(byte authType, WS_UserAuthData *authData, void *ctx)
{
    (void)ctx;

    if (authType != WOLFSSH_USERAUTH_PASSWORD) {
        return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
    }

    /* Check username */
    if (authData->usernameSz != strlen(SSH_USERNAME) ||
        memcmp(authData->username, SSH_USERNAME, authData->usernameSz) != 0) {
        debug_print("SSH: Invalid username\n");
        return WOLFSSH_USERAUTH_INVALID_USER;
    }

    /* Check password */
    if (authData->sf.password.passwordSz != strlen(SSH_PASSWORD) ||
        memcmp(authData->sf.password.password, SSH_PASSWORD,
               authData->sf.password.passwordSz) != 0) {
        debug_print("SSH: Invalid password\n");
        return WOLFSSH_USERAUTH_INVALID_PASSWORD;
    }

    debug_print("SSH: Authentication successful\n");
    return WOLFSSH_USERAUTH_SUCCESS;
}

/* Format number to string */
static void uint_to_str(uint32_t val, char *buf)
{
    char tmp[12];
    int i = 0;

    if (val == 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return;
    }

    while (val > 0) {
        tmp[i++] = '0' + (val % 10);
        val /= 10;
    }

    int j = 0;
    while (i > 0) {
        buf[j++] = tmp[--i];
    }
    buf[j] = '\0';
}

/* Shell command handler */
static int handle_command(const char *cmd, char *response, int max_len)
{
    char num_buf[12];
    int len = 0;

    /* Skip leading whitespace */
    while (*cmd == ' ' || *cmd == '\t') cmd++;

    if (strncmp(cmd, "help", 4) == 0) {
        const char *help =
            "\r\nAvailable commands:\r\n"
            "  help    - Show this help\r\n"
            "  info    - Show device information\r\n"
            "  uptime  - Show uptime in seconds\r\n"
            "  exit    - Close SSH session\r\n\r\n";
        len = strlen(help);
        if (len < max_len) {
            memcpy(response, help, len);
        }
    }
    else if (strncmp(cmd, "info", 4) == 0) {
        const char *info =
            "\r\nDevice: STM32H563\r\n"
            "Stack:  wolfIP\r\n"
            "SSH:    wolfSSH\r\n"
            "TLS:    wolfSSL TLS 1.3\r\n\r\n";
        len = strlen(info);
        if (len < max_len) {
            memcpy(response, info, len);
        }
    }
    else if (strncmp(cmd, "uptime", 6) == 0) {
        uint32_t uptime = ssh_server_get_uptime();
        uint_to_str(uptime, num_buf);
        const char *prefix = "\r\nUptime: ";
        const char *suffix = " seconds\r\n\r\n";
        len = strlen(prefix) + strlen(num_buf) + strlen(suffix);
        if (len < max_len) {
            strcpy(response, prefix);
            strcat(response, num_buf);
            strcat(response, suffix);
        }
    }
    else if (strncmp(cmd, "exit", 4) == 0 || strncmp(cmd, "quit", 4) == 0) {
        const char *bye = "\r\nGoodbye!\r\n";
        len = strlen(bye);
        if (len < max_len) {
            memcpy(response, bye, len);
        }
        return -1; /* Signal to close connection */
    }
    else if (cmd[0] != '\0' && cmd[0] != '\r' && cmd[0] != '\n') {
        const char *unknown = "\r\nUnknown command. Type 'help' for available commands.\r\n\r\n";
        len = strlen(unknown);
        if (len < max_len) {
            memcpy(response, unknown, len);
        }
    }
    else {
        /* Empty command - just return prompt */
        len = 0;
    }

    return len;
}

int ssh_server_init(struct wolfIP *stack, uint16_t port, ssh_debug_cb debug)
{
    struct wolfIP_sockaddr_in addr;
    int ret;

    memset(&server, 0, sizeof(server));
    server.stack = stack;
    server.debug_cb = debug;
    server.listen_fd = -1;
    server.client_fd = -1;
    server.state = SSH_STATE_LISTENING;

    debug_print("SSH: Initializing wolfSSH\n");

    /* Initialize wolfSSH library */
    ret = wolfSSH_Init();
    if (ret != WS_SUCCESS) {
        debug_print("SSH: wolfSSH_Init failed\n");
        return -1;
    }

#ifdef DEBUG_WOLFSSH
    /* Enable wolfSSH debug logging */
    wolfSSH_Debugging_ON();
    wolfSSH_SetLoggingCb(ssh_log_cb);
#endif

    /* Create SSH server context */
    server.ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (server.ctx == NULL) {
        debug_print("SSH: CTX_new failed\n");
        return -1;
    }

    /* Set I/O callbacks on context */
    wolfSSH_CTX_SetIO_wolfIP(server.ctx);

    /* Set user authentication callback */
    wolfSSH_SetUserAuth(server.ctx, ssh_userauth_cb);

    /* Load host key (ECC P-256) */
    debug_print("SSH: Loading host key\n");
    ret = wolfSSH_CTX_UsePrivateKey_buffer(server.ctx,
        ssh_host_key_der, ssh_host_key_der_len,
        WOLFSSH_FORMAT_ASN1);
    if (ret != WS_SUCCESS) {
        debug_print("SSH: Failed to load host key\n");
        wolfSSH_CTX_free(server.ctx);
        server.ctx = NULL;
        return -1;
    }

    /* Create listen socket */
    server.listen_fd = wolfIP_sock_socket(stack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (server.listen_fd < 0) {
        debug_print("SSH: socket() failed\n");
        wolfSSH_CTX_free(server.ctx);
        server.ctx = NULL;
        return -1;
    }

    /* Bind to port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(port);
    addr.sin_addr.s_addr = 0;

    ret = wolfIP_sock_bind(stack, server.listen_fd,
        (struct wolfIP_sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        debug_print("SSH: bind() failed\n");
        wolfIP_sock_close(stack, server.listen_fd);
        wolfSSH_CTX_free(server.ctx);
        server.ctx = NULL;
        return -1;
    }

    /* Listen */
    ret = wolfIP_sock_listen(stack, server.listen_fd, 1);
    if (ret < 0) {
        debug_print("SSH: listen() failed\n");
        wolfIP_sock_close(stack, server.listen_fd);
        wolfSSH_CTX_free(server.ctx);
        server.ctx = NULL;
        return -1;
    }

    debug_print("SSH: Server ready on port 22\n");
    return 0;
}

int ssh_server_poll(void)
{
    int ret;
    struct wolfIP_sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    switch (server.state) {
        case SSH_STATE_LISTENING:
            /* Try to accept a connection */
            ret = wolfIP_sock_accept(server.stack, server.listen_fd,
                (struct wolfIP_sockaddr *)&client_addr, &addr_len);
            if (ret >= 0) {
                server.client_fd = ret;
                debug_print("SSH: Client connected\n");
                server.state = SSH_STATE_ACCEPTING;
            }
            break;

        case SSH_STATE_ACCEPTING:
            /* Create SSH session */
            server.ssh = wolfSSH_new(server.ctx);
            if (server.ssh == NULL) {
                debug_print("SSH: wolfSSH_new failed\n");
                server.state = SSH_STATE_CLOSING;
                break;
            }

            /* Set I/O callbacks for wolfIP */
            ret = wolfSSH_SetIO_wolfIP(server.ssh, server.stack, server.client_fd);
            if (ret != WS_SUCCESS) {
                debug_print("SSH: SetIO failed\n");
                server.state = SSH_STATE_CLOSING;
                break;
            }

            server.channel_open = 0;
            server.state = SSH_STATE_KEY_EXCHANGE;
            break;

        case SSH_STATE_KEY_EXCHANGE:
            /* Perform SSH handshake (key exchange + auth) */
            ret = wolfSSH_accept(server.ssh);
            if (ret == WS_SUCCESS) {
                debug_print("SSH: Handshake complete\n");
                server.state = SSH_STATE_CONNECTED;
                server.rx_len = 0;

                /* Send welcome banner and prompt */
                const char *welcome =
                    "\r\n=== wolfIP SSH Shell ===\r\n"
                    "Type 'help' for available commands.\r\n\r\n"
                    "wolfip> ";
                wolfSSH_stream_send(server.ssh, (byte *)welcome, strlen(welcome));
            } else {
                int err = wolfSSH_get_error(server.ssh);
                if (err != WS_WANT_READ && err != WS_WANT_WRITE) {
                    debug_print("SSH: Handshake failed\n");
                    server.state = SSH_STATE_CLOSING;
                }
            }
            break;

        case SSH_STATE_CONNECTED:
            /* Read data from SSH channel */
            ret = wolfSSH_stream_read(server.ssh,
                server.rx_buf + server.rx_len,
                SSH_RX_BUF_SIZE - server.rx_len - 1);
            if (ret > 0) {
                server.rx_len += ret;
                server.rx_buf[server.rx_len] = '\0';

                /* Echo input character by character */
                wolfSSH_stream_send(server.ssh, server.rx_buf + server.rx_len - ret, ret);

                /* Check for complete command (newline) */
                char *newline = strchr((char *)server.rx_buf, '\r');
                if (newline == NULL) {
                    newline = strchr((char *)server.rx_buf, '\n');
                }

                if (newline != NULL) {
                    *newline = '\0';

                    /* Process command */
                    char response[256];
                    int resp_len = handle_command((char *)server.rx_buf,
                                                  response, sizeof(response));

                    if (resp_len < 0) {
                        /* Exit requested */
                        wolfSSH_stream_send(server.ssh, (byte *)response, strlen(response));
                        server.state = SSH_STATE_CLOSING;
                        break;
                    }

                    /* Send response */
                    if (resp_len > 0) {
                        wolfSSH_stream_send(server.ssh, (byte *)response, resp_len);
                    }

                    /* Send prompt */
                    const char *prompt = "wolfip> ";
                    wolfSSH_stream_send(server.ssh, (byte *)prompt, strlen(prompt));

                    /* Reset buffer */
                    server.rx_len = 0;
                }
            } else if (ret < 0) {
                int err = wolfSSH_get_error(server.ssh);
                if (err != WS_WANT_READ && err != WS_WANT_WRITE) {
                    debug_print("SSH: Connection closed\n");
                    server.state = SSH_STATE_CLOSING;
                }
            }
            break;

        case SSH_STATE_CLOSING:
            if (server.ssh) {
                wolfSSH_shutdown(server.ssh);
                wolfSSH_free(server.ssh);
                server.ssh = NULL;
            }
            if (server.client_fd >= 0) {
                wolfIP_sock_close(server.stack, server.client_fd);
                server.client_fd = -1;
            }
            server.rx_len = 0;
            server.channel_open = 0;
            server.state = SSH_STATE_LISTENING;
            debug_print("SSH: Ready for new connection\n");
            break;

        default:
            break;
    }

    return 0;
}

uint32_t ssh_server_get_uptime(void)
{
    /* This would need integration with the main tick counter */
    /* For now, return a placeholder */
    return 0;
}

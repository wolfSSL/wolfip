/* wolftftp.h
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
#ifndef WOLFTFTP_H
#define WOLFTFTP_H

#include "wolfip.h"

#include <stdint.h>

#ifndef WOLFIP_ENABLE_TFTP
#define WOLFIP_ENABLE_TFTP 0
#endif

#ifndef WOLFTFTP_PORT
#define WOLFTFTP_PORT 69U
#endif

#ifndef WOLFTFTP_DEFAULT_TIMEOUT_S
#define WOLFTFTP_DEFAULT_TIMEOUT_S 1U
#endif

#ifndef WOLFTFTP_MAX_RETRIES
#define WOLFTFTP_MAX_RETRIES 5U
#endif

#ifndef WOLFTFTP_MAX_FILENAME
#define WOLFTFTP_MAX_FILENAME 128U
#endif

#ifndef WOLFTFTP_MAX_BLKSIZE
#define WOLFTFTP_MAX_BLKSIZE 1428U
#endif

#ifndef WOLFTFTP_DEFAULT_BLKSIZE
#define WOLFTFTP_DEFAULT_BLKSIZE 512U
#endif

#ifndef WOLFTFTP_MAX_WINDOWSIZE
#define WOLFTFTP_MAX_WINDOWSIZE 8U
#endif

#ifndef WOLFTFTP_SERVER_MAX_SESSIONS
#define WOLFTFTP_SERVER_MAX_SESSIONS 4U
#endif

#ifndef WOLFTFTP_SERVER_PORT_BASE
#define WOLFTFTP_SERVER_PORT_BASE 20000U
#endif

/* Worst-case RRQ/WRQ on the wire:
 *   opcode(2) + filename(MAX_FILENAME, null-terminated) + "octet\0"(6)
 *   + blksize/value(13) + timeout/value(12) + windowsize/value(13)
 *   + tsize/value(17) = 63 + MAX_FILENAME. The constant below adds a
 *   generous margin so future options do not silently truncate. */
#define WOLFTFTP_REQ_BUF_MAX (WOLFTFTP_MAX_FILENAME + 128U)

#define WOLFTFTP_ERR_IO          (-1000)
#define WOLFTFTP_ERR_STATE       (-1001)
#define WOLFTFTP_ERR_PACKET      (-1002)
#define WOLFTFTP_ERR_TIMEOUT     (-1003)
#define WOLFTFTP_ERR_SIZE        (-1004)
#define WOLFTFTP_ERR_VERIFY      (-1005)
#define WOLFTFTP_ERR_UNSUPPORTED (-1006)
#define WOLFTFTP_ERR_TID         (-1007)
#define WOLFTFTP_ERR_NO_SLOT     (-1008)

enum wolftftp_opcode {
    WOLFTFTP_OP_RRQ   = 1,
    WOLFTFTP_OP_WRQ   = 2,
    WOLFTFTP_OP_DATA  = 3,
    WOLFTFTP_OP_ACK   = 4,
    WOLFTFTP_OP_ERROR = 5,
    WOLFTFTP_OP_OACK  = 6
};

enum wolftftp_error_code {
    WOLFTFTP_EUNDEF   = 0,
    WOLFTFTP_ENOTFOUND = 1,
    WOLFTFTP_EACCESS   = 2,
    WOLFTFTP_ENOSPACE  = 3,
    WOLFTFTP_EBADOP    = 4,
    WOLFTFTP_EBADTID   = 5,
    WOLFTFTP_EEXISTS   = 6,
    WOLFTFTP_ENOUSER   = 7,
    WOLFTFTP_EBADOPT   = 8
};

enum wolftftp_client_state {
    WOLFTFTP_CLIENT_IDLE = 0,
    WOLFTFTP_CLIENT_WAIT_FIRST,
    WOLFTFTP_CLIENT_RECV_DATA,
    WOLFTFTP_CLIENT_COMPLETE,
    WOLFTFTP_CLIENT_ERROR
};

enum wolftftp_session_state {
    WOLFTFTP_SESSION_FREE = 0,
    WOLFTFTP_SESSION_SEND_WAIT_ACK,
    WOLFTFTP_SESSION_RECV_DATA,
    WOLFTFTP_SESSION_COMPLETE,
    WOLFTFTP_SESSION_ERROR
};

struct wolftftp_endpoint {
    uint32_t ip;
    uint16_t port;
};

struct wolftftp_transfer_cfg {
    uint16_t local_port;
    uint16_t blksize;
    uint16_t timeout_s;
    uint16_t windowsize;
    uint16_t max_retries;
    uint32_t max_image_size;
};

struct wolftftp_negotiated {
    uint16_t blksize;
    uint16_t timeout_s;
    uint16_t windowsize;
    uint32_t tsize;
    uint8_t  have_tsize;
};

typedef int (*wolftftp_udp_send_cb)(void *arg, uint16_t local_port,
    const struct wolftftp_endpoint *remote, const uint8_t *buf, uint16_t len);
typedef int (*wolftftp_open_cb)(void *arg, const char *name, int is_write,
    uint32_t *size_hint, void **handle);
typedef int (*wolftftp_read_cb)(void *arg, void *handle, uint32_t offset,
    uint8_t *buf, uint16_t max_len, uint16_t *out_len, int *is_last);
typedef int (*wolftftp_write_cb)(void *arg, void *handle, uint32_t offset,
    const uint8_t *buf, uint16_t len);
typedef int (*wolftftp_hash_update_cb)(void *arg, void *handle,
    const uint8_t *buf, uint16_t len);
typedef int (*wolftftp_verify_cb)(void *arg, void *handle, uint32_t total_size);
typedef void (*wolftftp_close_cb)(void *arg, void *handle, int status);

struct wolftftp_io_ops {
    wolftftp_open_cb open;
    wolftftp_read_cb read;
    wolftftp_write_cb write;
    wolftftp_hash_update_cb hash_update;
    wolftftp_verify_cb verify;
    wolftftp_close_cb close;
    void *arg;
};

struct wolftftp_transport_ops {
    wolftftp_udp_send_cb send;
    void *arg;
};

struct wolftftp_client {
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_transfer_cfg cfg;
    struct wolftftp_negotiated neg;
    struct wolftftp_endpoint server;
    void *handle;
    uint8_t last_tx[WOLFTFTP_REQ_BUF_MAX];
    uint16_t last_tx_len;
    uint32_t next_offset;
    uint32_t total_size;
    uint32_t advertised_size;
    uint32_t deadline_ms;
    uint16_t expected_block;
    uint16_t last_acked_block;
    uint16_t window_count;
    uint16_t retries;
    int last_status;
    enum wolftftp_client_state state;
    uint8_t requested_opts;
    uint8_t final_seen;
    uint8_t request_sent;
    uint8_t tid_locked;
    char filename[WOLFTFTP_MAX_FILENAME];
};

struct wolftftp_server_session {
    struct wolftftp_endpoint remote;
    struct wolftftp_negotiated neg;
    void *handle;
    uint32_t next_offset;
    uint32_t total_size;
    uint32_t file_size;
    uint32_t deadline_ms;
    /* Snapshot of next_offset/total_size/next_block at the start of the
     * last RRQ window send, used to replay the window on a retransmit
     * instead of advancing into unacknowledged territory. */
    uint32_t window_start_offset;
    uint32_t window_start_total;
    uint16_t window_start_block;
    uint8_t  window_start_final;
    uint16_t local_port;
    uint16_t next_block;
    uint16_t last_acked_block;
    uint16_t window_count;
    uint16_t retries;
    uint8_t is_write;
    uint8_t options_sent;
    uint8_t final_seen;
    int last_status;
    enum wolftftp_session_state state;
    char filename[WOLFTFTP_MAX_FILENAME];
};

struct wolftftp_server {
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_transfer_cfg cfg;
    uint16_t listen_port;
    uint16_t transfer_port_base;
    struct wolftftp_server_session sessions[WOLFTFTP_SERVER_MAX_SESSIONS];
};

void wolftftp_client_init(struct wolftftp_client *client,
    const struct wolftftp_transport_ops *transport,
    const struct wolftftp_io_ops *io,
    const struct wolftftp_transfer_cfg *cfg);
int wolftftp_client_start_rrq(struct wolftftp_client *client,
    const struct wolftftp_endpoint *server, const char *filename);
int wolftftp_client_receive(struct wolftftp_client *client, uint16_t local_port,
    const struct wolftftp_endpoint *remote, const uint8_t *buf, uint16_t len);
int wolftftp_client_poll(struct wolftftp_client *client, uint32_t now_ms);
int wolftftp_client_status(const struct wolftftp_client *client);

void wolftftp_server_init(struct wolftftp_server *server,
    const struct wolftftp_transport_ops *transport,
    const struct wolftftp_io_ops *io,
    const struct wolftftp_transfer_cfg *cfg);
int wolftftp_server_receive(struct wolftftp_server *server, uint16_t local_port,
    const struct wolftftp_endpoint *remote, const uint8_t *buf, uint16_t len);
int wolftftp_server_poll(struct wolftftp_server *server, uint32_t now_ms);

#endif

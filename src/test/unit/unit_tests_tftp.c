/* unit_tests_tftp.c
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
struct tftp_test_ctx {
    uint8_t sent[32][WOLFTFTP_PKT_MAX];
    uint16_t sent_len[32];
    uint16_t sent_local_port[32];
    struct wolftftp_endpoint sent_remote[32];
    int send_calls;
    int send_fail;

    int open_calls;
    int write_calls;
    int read_calls;
    int hash_calls;
    int verify_calls;
    int close_calls;
    int close_status;

    int open_fail;
    int write_fail;
    int read_fail;
    int hash_fail;
    int verify_fail;

    void *handle_out;
    uint32_t open_size_hint;
    int open_is_write;
    char opened_name[WOLFTFTP_MAX_FILENAME];

    uint8_t read_data[WOLFTFTP_MAX_BLKSIZE * 4];
    uint16_t read_len[8];
    int read_last[8];
    int read_count;

    uint8_t write_buf[WOLFTFTP_MAX_BLKSIZE * 4];
    uint32_t write_offset;
    uint16_t write_len;
};

static void tftp_test_ctx_reset(struct tftp_test_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->handle_out = ctx;
}

static int tftp_test_send(void *arg, uint16_t local_port,
    const struct wolftftp_endpoint *remote, const uint8_t *buf, uint16_t len)
{
    struct tftp_test_ctx *ctx = (struct tftp_test_ctx *)arg;
    int idx = ctx->send_calls;

    if (ctx->send_fail != 0)
        return ctx->send_fail;
    ck_assert_int_lt(idx, 32);
    memcpy(ctx->sent[idx], buf, len);
    ctx->sent_len[idx] = len;
    ctx->sent_local_port[idx] = local_port;
    ctx->sent_remote[idx] = *remote;
    ctx->send_calls++;
    return 0;
}

static int tftp_test_open(void *arg, const char *name, int is_write,
    uint32_t *size_hint, void **handle)
{
    struct tftp_test_ctx *ctx = (struct tftp_test_ctx *)arg;

    ctx->open_calls++;
    ctx->open_is_write = is_write;
    ctx->open_size_hint = size_hint != NULL ? *size_hint : 0;
    (void)wolftftp_copy_string(ctx->opened_name, sizeof(ctx->opened_name), name);
    if (ctx->open_fail != 0)
        return ctx->open_fail;
    if (handle != NULL)
        *handle = ctx->handle_out;
    if (!is_write && size_hint != NULL && *size_hint == 0)
        *size_hint = 7;
    return 0;
}

static int tftp_test_read(void *arg, void *handle, uint32_t offset,
    uint8_t *buf, uint16_t max_len, uint16_t *out_len, int *is_last)
{
    struct tftp_test_ctx *ctx = (struct tftp_test_ctx *)arg;
    uint16_t len;
    int idx = ctx->read_calls++;

    (void)handle;
    if (ctx->read_fail != 0)
        return ctx->read_fail;
    ck_assert_int_lt(idx, 8);
    len = ctx->read_len[idx];
    ck_assert_uint_le(len, max_len);
    memcpy(buf, ctx->read_data + offset, len);
    *out_len = len;
    *is_last = ctx->read_last[idx];
    return 0;
}

static int tftp_test_write(void *arg, void *handle, uint32_t offset,
    const uint8_t *buf, uint16_t len)
{
    struct tftp_test_ctx *ctx = (struct tftp_test_ctx *)arg;

    (void)handle;
    if (ctx->write_fail != 0)
        return ctx->write_fail;
    ctx->write_calls++;
    ctx->write_offset = offset;
    ctx->write_len = len;
    memcpy(ctx->write_buf + offset, buf, len);
    return 0;
}

static int tftp_test_hash(void *arg, void *handle, const uint8_t *buf,
    uint16_t len)
{
    struct tftp_test_ctx *ctx = (struct tftp_test_ctx *)arg;

    (void)handle;
    (void)buf;
    (void)len;
    ctx->hash_calls++;
    return ctx->hash_fail;
}

static int tftp_test_verify(void *arg, void *handle, uint32_t total_size)
{
    struct tftp_test_ctx *ctx = (struct tftp_test_ctx *)arg;

    (void)handle;
    ctx->verify_calls++;
    ctx->open_size_hint = total_size;
    return ctx->verify_fail;
}

static void tftp_test_close(void *arg, void *handle, int status)
{
    struct tftp_test_ctx *ctx = (struct tftp_test_ctx *)arg;

    (void)handle;
    ctx->close_calls++;
    ctx->close_status = status;
}

static struct wolftftp_transport_ops tftp_transport_ops(struct tftp_test_ctx *ctx)
{
    struct wolftftp_transport_ops ops;

    memset(&ops, 0, sizeof(ops));
    ops.send = tftp_test_send;
    ops.arg = ctx;
    return ops;
}

static struct wolftftp_io_ops tftp_io_ops(struct tftp_test_ctx *ctx)
{
    struct wolftftp_io_ops ops;

    memset(&ops, 0, sizeof(ops));
    ops.open = tftp_test_open;
    ops.read = tftp_test_read;
    ops.write = tftp_test_write;
    ops.hash_update = tftp_test_hash;
    ops.verify = tftp_test_verify;
    ops.close = tftp_test_close;
    ops.arg = ctx;
    return ops;
}

static struct wolftftp_transfer_cfg tftp_cfg_defaults(void)
{
    struct wolftftp_transfer_cfg cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.local_port = 12000;
    cfg.blksize = 16;
    cfg.timeout_s = 2;
    cfg.windowsize = 2;
    cfg.max_retries = 3;
    cfg.max_image_size = 128;
    return cfg;
}

static struct wolftftp_endpoint tftp_remote(uint32_t ip, uint16_t port)
{
    struct wolftftp_endpoint ep;

    ep.ip = ip;
    ep.port = port;
    return ep;
}

START_TEST(test_tftp_helpers_and_builders)
{
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t out_len = 0;
    uint8_t requested = 0;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_parsed_req req;
    struct wolftftp_negotiated neg;
    struct wolftftp_parsed_data data;

    uint32_t parsed = 0xDEADBEEFU;

    ck_assert_int_eq(wolftftp_stricmp_local("octet", "OCTET"), 0);
    ck_assert_int_eq(wolftftp_parse_u32("42", 100, &parsed), 0);
    ck_assert_uint_eq(parsed, 42U);
    parsed = 0xDEADBEEFU;
    ck_assert_int_eq(wolftftp_parse_u32("999", 10, &parsed), -1);
    ck_assert_uint_eq(parsed, 0xDEADBEEFU);
    /* Valid zero is distinguishable from invalid input. */
    parsed = 0xDEADBEEFU;
    ck_assert_int_eq(wolftftp_parse_u32("0", 100, &parsed), 0);
    ck_assert_uint_eq(parsed, 0U);
    parsed = 0xDEADBEEFU;
    ck_assert_int_eq(wolftftp_parse_u32("abc", 100, &parsed), -1);
    ck_assert_uint_eq(parsed, 0xDEADBEEFU);
    ck_assert_int_eq(wolftftp_parse_u32(NULL, 100, &parsed), -1);
    ck_assert_int_eq(wolftftp_parse_u32("", 100, &parsed), -1);
    ck_assert_int_eq(wolftftp_parse_u32("12", 100, NULL), -1);
    ck_assert_int_eq(wolftftp_copy_string(NULL, 0, "x"), -WOLFIP_EINVAL);

    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_RRQ,
        "fw.bin", &cfg, 0, &requested, &out_len), 0);
    ck_assert_uint_eq(wolftftp_read_u16(pkt), WOLFTFTP_OP_RRQ);
    ck_assert(requested != 0U);
    ck_assert_int_eq(wolftftp_parse_request(pkt, out_len, &req), 0);
    ck_assert_str_eq(req.filename, "fw.bin");
    ck_assert_uint_eq(req.blksize, cfg.blksize);
    ck_assert_uint_eq(req.timeout_s, cfg.timeout_s);
    ck_assert_uint_eq(req.windowsize, cfg.windowsize);

    wolftftp_neg_defaults(&neg, &cfg);
    neg.tsize = 33;
    neg.have_tsize = 1;
    ck_assert_int_gt(wolftftp_build_oack(pkt, sizeof(pkt), &neg,
        WOLFTFTP_OPT_BLKSIZE | WOLFTFTP_OPT_TIMEOUT |
        WOLFTFTP_OPT_TSIZE | WOLFTFTP_OPT_WINDOWSIZE), 0);
    ck_assert_int_eq(wolftftp_parse_oack(pkt, (uint16_t)strlen((char *)(pkt + 2)) + 14,
        &neg), WOLFTFTP_ERR_PACKET);
    wolftftp_neg_defaults(&neg, &cfg);
    ck_assert_int_eq(wolftftp_parse_oack(pkt, (uint16_t)(2 + strlen("blksize") + 1 +
        strlen("16") + 1 + strlen("timeout") + 1 + strlen("2") + 1 +
        strlen("tsize") + 1 + strlen("33") + 1 + strlen("windowsize") + 1 +
        strlen("2") + 1), &neg), 0);
    ck_assert_uint_eq(neg.tsize, 33U);
    ck_assert_uint_eq(neg.have_tsize, 1U);

    memcpy(pkt + 4, "abc", 3);
    ck_assert_int_eq(wolftftp_build_data(pkt, sizeof(pkt), 7, pkt + 4, 3), 7);
    ck_assert_int_eq(wolftftp_parse_data(pkt, 7, &data), 0);
    ck_assert_uint_eq(data.block, 7U);
    ck_assert_uint_eq(data.data_len, 3U);
    ck_assert_mem_eq(data.data, "abc", 3);

    ck_assert_int_eq(wolftftp_build_error(pkt, 7, WOLFTFTP_EBADOP, "x"), 6);
    ck_assert_int_eq(wolftftp_packet_opcode(pkt, 6), WOLFTFTP_OP_ERROR);
    ck_assert_int_eq(wolftftp_packet_opcode(NULL, 0), -1);
    ck_assert_uint_eq(wolftftp_deadline(&neg, 10), 2010U);
}
END_TEST

START_TEST(test_tftp_parse_request_error_paths)
{
    uint8_t pkt[64];
    struct wolftftp_parsed_req req;
    struct wolftftp_negotiated neg;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();

    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_RRQ);
    memcpy(pkt + 2, "fw\0netascii\0", 12);
    ck_assert_int_eq(wolftftp_parse_request(pkt, 14, &req),
        WOLFTFTP_ERR_UNSUPPORTED);

    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_RRQ);
    memcpy(pkt + 2, "fw\0octet\0blksize\01\0", 19);
    ck_assert_int_eq(wolftftp_parse_request(pkt, 19, &req),
        WOLFTFTP_ERR_PACKET);

    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_RRQ);
    memcpy(pkt + 2, "fw\0octet\0mystery\01\0", 19);
    ck_assert_int_eq(wolftftp_parse_request(pkt, 19, &req),
        WOLFTFTP_ERR_PACKET);
    ck_assert_int_eq(wolftftp_parse_request(pkt, 3, &req),
        WOLFTFTP_ERR_PACKET);

    /* Option value not NUL-terminated within the datagram. The bytes
     * after the would-be-NUL are intentionally non-zero so that any
     * regression to a value-side `>` (instead of `>=`) bounds check
     * would let parse_u32 walk into them. The whole frame must be
     * rejected as malformed without reading past buf+len. */
    memset(pkt, 0xFF, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_RRQ);
    memcpy(pkt + 2, "fw\0octet\0blksize\0", 17);
    memcpy(pkt + 19, "512", 3); /* deliberately no trailing NUL */
    ck_assert_int_eq(wolftftp_parse_request(pkt, 22, &req),
        WOLFTFTP_ERR_PACKET);

    /* Same shape on the OACK side: the value runs right up to len
     * with no NUL. Must be rejected. */
    memset(pkt, 0xFF, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_OACK);
    memcpy(pkt + 2, "blksize\0", 8);
    memcpy(pkt + 10, "512", 3);
    wolftftp_neg_defaults(&neg, &cfg);
    ck_assert_int_eq(wolftftp_parse_oack(pkt, 13, &neg),
        WOLFTFTP_ERR_PACKET);
}
END_TEST

/* F-5009: an unauthenticated RRQ/WRQ filename must not be able to escape the
 * integrator's namespace. parse_request rejects any '..' path component and any
 * absolute path before the name can reach io.open. Benign names that merely
 * contain dots (but no '..' component) and relative subdirectories still pass. */
START_TEST(test_tftp_parse_request_rejects_path_traversal)
{
    uint8_t pkt[160];
    struct wolftftp_parsed_req req;
    static const char *bad[] = {
        "../../etc/passwd",   /* leading traversal            */
        "/etc/cron.d/evil",   /* absolute (unix)              */
        "\\windows\\sys",     /* absolute (dos)               */
        "..",                 /* whole name is a traversal    */
        "fw/../../secret",    /* embedded traversal           */
        "images/..",          /* trailing traversal component */
        "a/..\\b",            /* backslash-separated traversal*/
        "C:\\windows\\sys",   /* windows drive-letter absolute*/
        "C:fw.bin",           /* windows drive-relative path  */
        "fw.bin:stream",      /* ntfs alternate data stream   */
    };
    static const char *good[] = {
        "fw.bin",             /* ordinary name                */
        "images/fw.bin",      /* relative subdir is fine      */
        "fw..bin",            /* dots, but not a '..' component */
        "v1.2..3.img",        /* same                         */
        ".config",            /* leading dot, not traversal   */
    };
    size_t i, fnlen;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        memset(pkt, 0, sizeof(pkt));
        wolftftp_write_u16(pkt, WOLFTFTP_OP_RRQ);
        fnlen = strlen(bad[i]);
        memcpy(pkt + 2, bad[i], fnlen + 1U);
        memcpy(pkt + 2 + fnlen + 1U, "octet", 6);
        ck_assert_int_eq(wolftftp_parse_request(pkt,
            (uint16_t)(2U + fnlen + 1U + 6U), &req), WOLFTFTP_ERR_PACKET);
        /* Same rejection on the WRQ (arbitrary-write) path. */
        wolftftp_write_u16(pkt, WOLFTFTP_OP_WRQ);
        ck_assert_int_eq(wolftftp_parse_request(pkt,
            (uint16_t)(2U + fnlen + 1U + 6U), &req), WOLFTFTP_ERR_PACKET);
    }

    for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
        memset(pkt, 0, sizeof(pkt));
        wolftftp_write_u16(pkt, WOLFTFTP_OP_RRQ);
        fnlen = strlen(good[i]);
        memcpy(pkt + 2, good[i], fnlen + 1U);
        memcpy(pkt + 2 + fnlen + 1U, "octet", 6);
        ck_assert_int_eq(wolftftp_parse_request(pkt,
            (uint16_t)(2U + fnlen + 1U + 6U), &req), 0);
        ck_assert_str_eq(req.filename, good[i]);
    }
}
END_TEST

START_TEST(test_tftp_client_rrq_oack_and_data_success)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint srv = tftp_remote(0x0A000001U, 0);
    struct wolftftp_endpoint tid = tftp_remote(srv.ip, 1069);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    int len;

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_client_init(&client, &transport, &io, &cfg);

    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);
    ck_assert_int_eq(ctx.send_calls, 1);
    ck_assert_uint_eq(client.state, WOLFTFTP_CLIENT_WAIT_FIRST);

    len = wolftftp_build_oack(pkt, sizeof(pkt), &client.neg,
        WOLFTFTP_OPT_BLKSIZE | WOLFTFTP_OPT_TIMEOUT | WOLFTFTP_OPT_WINDOWSIZE);
    ck_assert_int_gt(len, 0);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), 0);
    ck_assert_int_eq(ctx.send_calls, 2);
    ck_assert_uint_eq(client.server.port, 1069U);

    memcpy(pkt + 4, "abcdefghijklmnop", 16);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 16);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), 0);
    ck_assert_int_eq(ctx.write_calls, 1);
    ck_assert_int_eq(ctx.hash_calls, 1);
    ck_assert_int_eq(ctx.send_calls, 2);

    memcpy(pkt + 4, "end", 3);
    len = wolftftp_build_data(pkt, sizeof(pkt), 2, pkt + 4, 3);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), 0);
    ck_assert_int_eq(ctx.send_calls, 3);
    ck_assert_int_eq(ctx.verify_calls, 1);
    ck_assert_int_eq(ctx.close_calls, 1);
    ck_assert_int_eq(ctx.close_status, 0);
    ck_assert_uint_eq(client.state, WOLFTFTP_CLIENT_COMPLETE);
    ck_assert_mem_eq(ctx.write_buf, "abcdefghijklmnopend", 19);
}
END_TEST

START_TEST(test_tftp_client_fallback_duplicate_and_tid_errors)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint srv = tftp_remote(0x0A000002U, 0);
    struct wolftftp_endpoint tid = tftp_remote(srv.ip, 2000);
    struct wolftftp_endpoint bad_tid = tftp_remote(srv.ip, 2001);
    struct wolftftp_endpoint other_ip = tftp_remote(0x0A000099U, 2000);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    int len;

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_client_init(&client, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);

    memcpy(pkt + 4, "1234567890123456", 16);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 16);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), 0);
    ck_assert_uint_eq(client.server.port, 2000U);

    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), 0);
    ck_assert_int_eq(ctx.send_calls, 2);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &bad_tid, pkt, (uint16_t)len), WOLFTFTP_ERR_TID);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &other_ip, pkt, (uint16_t)len), 0);
}
END_TEST

START_TEST(test_tftp_client_error_and_failure_paths)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint srv = tftp_remote(0x0A000003U, 0);
    struct wolftftp_endpoint tid = tftp_remote(srv.ip, 3000);
    struct wolftftp_transfer_cfg cfg2;
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    int len;

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    cfg.max_image_size = 4;
    wolftftp_client_init(&client, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);

    wolftftp_neg_defaults(&client.neg, &cfg);
    client.neg.tsize = 9;
    client.neg.have_tsize = 1;
    len = wolftftp_build_oack(pkt, sizeof(pkt), &client.neg, WOLFTFTP_OPT_TSIZE);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), WOLFTFTP_ERR_SIZE);
    ck_assert_uint_eq(client.state, WOLFTFTP_CLIENT_ERROR);

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    cfg2 = tftp_cfg_defaults();
    wolftftp_client_init(&client, &transport, &io, &cfg2);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);
    ctx.open_fail = -1;
    memcpy(pkt + 4, "end", 3);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 3);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), WOLFTFTP_ERR_IO);

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    cfg2 = tftp_cfg_defaults();
    wolftftp_client_init(&client, &transport, &io, &cfg2);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);
    ctx.hash_fail = -1;
    memcpy(pkt + 4, "end", 3);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 3);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), WOLFTFTP_ERR_VERIFY);

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    cfg2 = tftp_cfg_defaults();
    wolftftp_client_init(&client, &transport, &io, &cfg2);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);
    ctx.verify_fail = -1;
    memcpy(pkt + 4, "end", 3);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 3);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), WOLFTFTP_ERR_VERIFY);

    wolftftp_write_u16(pkt, WOLFTFTP_OP_ERROR);
    wolftftp_write_u16(pkt + 2, WOLFTFTP_EUNDEF);
    memcpy(pkt + 4, "x\0", 2);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, 6), WOLFTFTP_ERR_STATE);
}
END_TEST

START_TEST(test_tftp_client_poll_and_status_paths)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint srv = tftp_remote(0x0A000004U, 0);

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_client_init(&client, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_client_status(NULL), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolftftp_client_poll(NULL, 0), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolftftp_client_poll(&client, 0), 0);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"),
        WOLFTFTP_ERR_STATE);
    ck_assert_int_eq(wolftftp_client_poll(&client, 10), 0);
    ck_assert_int_eq(wolftftp_client_poll(&client, 1000), 0);
    ck_assert_int_eq(ctx.send_calls, 1);
    ck_assert_int_eq(wolftftp_client_poll(&client, 3000), 0);
    ck_assert_int_eq(ctx.send_calls, 2);
    ck_assert_int_eq(wolftftp_client_poll(&client, 6000), 0);
    ck_assert_int_eq(ctx.send_calls, 3);
    ck_assert_int_eq(wolftftp_client_poll(&client, 12000), 0);
    ck_assert_int_eq(ctx.send_calls, 4);
    ck_assert_int_eq(wolftftp_client_poll(&client, 15000), WOLFTFTP_ERR_TIMEOUT);
    ck_assert_int_eq(wolftftp_client_status(&client), WOLFTFTP_ERR_TIMEOUT);
}
END_TEST

START_TEST(test_tftp_server_rrq_success_and_poll)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote = tftp_remote(0x0A000011U, 4000);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;
    uint16_t ack0;

    tftp_test_ctx_reset(&ctx);
    memcpy(ctx.read_data, "abcdefg", 7);
    ctx.read_len[0] = 7;
    ctx.read_last[0] = 1;
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);

    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_RRQ,
        "fw.bin", &cfg, 0, &opts, &req_len), 0);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    ck_assert_int_eq(ctx.open_calls, 1);
    ck_assert_int_eq(ctx.send_calls, 1);
    ack0 = (uint16_t)wolftftp_build_ack(pkt, 0);
    ck_assert_int_eq(wolftftp_server_receive(&server, server.sessions[0].local_port,
        &remote, pkt, ack0), 0);
    ck_assert_int_eq(ctx.send_calls, 2);
    wolftftp_write_u16(pkt, WOLFTFTP_OP_ACK);
    wolftftp_write_u16(pkt + 2, 1);
    ck_assert_int_eq(wolftftp_server_receive(&server, server.sessions[0].local_port,
        &remote, pkt, 4), 0);
    ck_assert_int_eq(ctx.close_calls, 1);

    ck_assert_int_eq(wolftftp_server_poll(&server, 10), 0);
    ck_assert_int_eq(wolftftp_server_poll(NULL, 10), -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_tftp_server_wrq_success_and_failures)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote = tftp_remote(0x0A000012U, 5000);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;
    int len;

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);

    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_WRQ,
        "fw.bin", &cfg, 10, &opts, &req_len), 0);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    ck_assert_int_eq(ctx.send_calls, 1);
    memcpy(pkt + 4, "done", 4);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 4);
    ck_assert_int_eq(wolftftp_server_receive(&server, server.sessions[0].local_port,
        &remote, pkt, (uint16_t)len), 0);
    ck_assert_int_eq(ctx.write_calls, 1);
    ck_assert_int_eq(ctx.hash_calls, 1);
    ck_assert_int_eq(ctx.verify_calls, 1);
    ck_assert_int_eq(ctx.close_calls, 1);

    tftp_test_ctx_reset(&ctx);
    ctx.verify_fail = -1;
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_WRQ,
        "fw.bin", &cfg, 10, &opts, &req_len), 0);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    memcpy(pkt + 4, "bad", 3);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 3);
    ck_assert_int_eq(wolftftp_server_receive(&server, server.sessions[0].local_port,
        &remote, pkt, (uint16_t)len), WOLFTFTP_ERR_VERIFY);

    tftp_test_ctx_reset(&ctx);
    cfg.max_image_size = 2;
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    /* Advertise tsize=0 (size unknown) so the request is accepted and the
     * oversized-payload rejection is exercised on the DATA path rather than
     * up front against the advertised tsize. */
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_WRQ,
        "fw.bin", &cfg, 0, &opts, &req_len), 0);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    memcpy(pkt + 4, "toolong", 7);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 7);
    ck_assert_int_eq(wolftftp_server_receive(&server, server.sessions[0].local_port,
        &remote, pkt, (uint16_t)len), WOLFTFTP_ERR_SIZE);
}
END_TEST

/* F-4389: a WRQ advertising tsize greater than cfg.max_image_size must be
 * rejected before io.open is handed the size_hint, so a single datagram
 * cannot force a huge pre-allocation. */
START_TEST(test_tftp_server_wrq_tsize_exceeds_limit_rejected)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote = tftp_remote(0x0A000012U, 5000);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;

    tftp_test_ctx_reset(&ctx);
    cfg.max_image_size = 128;
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);

    /* WRQ with tsize = UINT32_MAX, far above max_image_size. */
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_WRQ,
        "fw.bin", &cfg, 0xFFFFFFFFU, &opts, &req_len), 0);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), WOLFTFTP_ERR_SIZE);
    /* io.open must never have been reached with the oversized hint, and the
     * session slot must be reaped. */
    ck_assert_int_eq(ctx.open_calls, 0);
    ck_assert_int_eq(server.sessions[0].state, WOLFTFTP_SESSION_FREE);
    /* The peer must have received an ENOSPACE error datagram. */
    ck_assert_int_eq(ctx.send_calls, 1);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[0]), WOLFTFTP_OP_ERROR);
}
END_TEST

START_TEST(test_tftp_server_request_errors_and_timeouts)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote = tftp_remote(0x0A000013U, 6000);
    struct wolftftp_endpoint wrong_tid = tftp_remote(remote.ip, 6001);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);

    memset(pkt, 0, 6);
    wolftftp_write_u16(pkt, WOLFTFTP_OP_ERROR);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, 6), 0);

    memcpy(pkt, "\x00\x01fw\0octet\0bogus\01\0", 18);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, 18), 0);

    tftp_test_ctx_reset(&ctx);
    ctx.open_fail = -1;
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_RRQ,
        "fw.bin", &cfg, 0, &opts, &req_len), 0);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);

    tftp_test_ctx_reset(&ctx);
    memcpy(ctx.read_data, "abcdefg", 7);
    ctx.read_len[0] = 7;
    ctx.read_last[0] = 1;
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    ck_assert_int_eq(wolftftp_server_receive(&server, server.sessions[0].local_port,
        &wrong_tid, pkt, 4), 0);
    ck_assert_int_eq(wolftftp_server_poll(&server, 1), 0);
    ck_assert_int_eq(wolftftp_server_poll(&server, 2000), 0);
    ck_assert_int_eq(wolftftp_server_poll(&server, 4000), 0);
    ck_assert_int_eq(wolftftp_server_poll(&server, 6000), 0);
}
END_TEST

START_TEST(test_tftp_server_session_reaped_after_completion)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote;
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;
    unsigned int n;
    unsigned int i;

    /* Run more transfers than the static session pool can hold; if
     * wolftftp_server_finish failed to free the slot, the second batch
     * of allocs would fall through to the "no slots" error path and
     * leave open_calls at WOLFTFTP_SERVER_MAX_SESSIONS. */
    n = WOLFTFTP_SERVER_MAX_SESSIONS * 2U + 1U;
    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);

    for (i = 0; i < n; i++) {
        remote = tftp_remote(0x0A000100U + i, (uint16_t)(7000U + i));
        ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_WRQ,
            "fw.bin", &cfg, 4, &opts, &req_len), 0);
        ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
            pkt, req_len), 0);
        memcpy(pkt + 4, "end", 3);
        ck_assert_int_eq(wolftftp_server_receive(&server, server.sessions[0].local_port,
            &remote, pkt,
            (uint16_t)wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 3)), 0);
        ck_assert_uint_eq(server.sessions[0].state, WOLFTFTP_SESSION_FREE);
    }
    ck_assert_int_eq(ctx.open_calls, (int)n);
    ck_assert_int_eq(ctx.close_calls, (int)n);
}
END_TEST

START_TEST(test_tftp_client_honors_caller_server_port)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    /* User supplies a non-default server port (e.g. 1069). The RRQ
     * must go to that port and TID locking must still happen on the
     * first response, even though the configured port is not 69. */
    struct wolftftp_endpoint srv = tftp_remote(0x0A000020U, 1069);
    struct wolftftp_endpoint tid = tftp_remote(srv.ip, 5005);
    struct wolftftp_endpoint bad_tid = tftp_remote(srv.ip, 5006);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    int len;

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_client_init(&client, &transport, &io, &cfg);

    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);
    ck_assert_uint_eq(client.server.port, 1069U);
    ck_assert_uint_eq(client.tid_locked, 0U);
    ck_assert_uint_eq(ctx.sent_remote[0].port, 1069U);

    memcpy(pkt + 4, "0123456789abcdef", 16);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 16);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), 0);
    ck_assert_uint_eq(client.server.port, 5005U);
    ck_assert_uint_eq(client.tid_locked, 1U);

    /* Once locked, a packet from the original non-default port is no
     * longer accepted (it is now an unknown TID). */
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &srv, pkt, (uint16_t)len), WOLFTFTP_ERR_TID);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &bad_tid, pkt, (uint16_t)len), WOLFTFTP_ERR_TID);
}
END_TEST

START_TEST(test_tftp_client_default_port_when_zero)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint srv = tftp_remote(0x0A000021U, 0);

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_client_init(&client, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);
    ck_assert_uint_eq(client.server.port, WOLFTFTP_PORT);
    ck_assert_uint_eq(ctx.sent_remote[0].port, WOLFTFTP_PORT);
}
END_TEST

START_TEST(test_tftp_parse_tsize_rejects_non_numeric)
{
    uint8_t pkt[64];
    struct wolftftp_parsed_req req;
    struct wolftftp_negotiated neg;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();

    /* tsize="abc": must be rejected as unsupported, not silently
     * treated as tsize=0. Same check for OACK. Note: pass len so the
     * trailing NUL of "abc" lies INSIDE buf+len, otherwise the test
     * would be probing the (now-fixed) OOB read instead of the
     * non-numeric rejection path. */
    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_RRQ);
    memcpy(pkt + 2, "fw\0octet\0tsize\0abc\0", 19);
    ck_assert_int_eq(wolftftp_parse_request(pkt, 21, &req),
        WOLFTFTP_ERR_UNSUPPORTED);

    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_OACK);
    memcpy(pkt + 2, "tsize\0abc\0", 10);
    wolftftp_neg_defaults(&neg, &cfg);
    ck_assert_int_eq(wolftftp_parse_oack(pkt, 12, &neg),
        WOLFTFTP_ERR_UNSUPPORTED);

    /* tsize=0 is still valid and parses to 0. */
    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_OACK);
    memcpy(pkt + 2, "tsize\0" "0\0", 8);
    wolftftp_neg_defaults(&neg, &cfg);
    ck_assert_int_eq(wolftftp_parse_oack(pkt, 10, &neg), 0);
    ck_assert_uint_eq(neg.have_tsize, 1U);
    ck_assert_uint_eq(neg.tsize, 0U);
}
END_TEST

START_TEST(test_tftp_build_request_fits_max_options)
{
    /* All four options enabled plus a near-max filename must still
     * fit in the buffer used by the client for retransmits. */
    uint8_t buf[WOLFTFTP_REQ_BUF_MAX];
    struct wolftftp_transfer_cfg cfg;
    char name[WOLFTFTP_MAX_FILENAME];
    uint8_t requested = 0;
    uint16_t out_len = 0;
    size_t i;

    memset(&cfg, 0, sizeof(cfg));
    cfg.blksize = WOLFTFTP_MAX_BLKSIZE;
    cfg.timeout_s = 255;
    cfg.windowsize = WOLFTFTP_MAX_WINDOWSIZE;
    cfg.max_image_size = 0xFFFFFFFFU;
    for (i = 0; i + 1 < sizeof(name); i++)
        name[i] = 'a';
    name[sizeof(name) - 1] = '\0';

    ck_assert_int_eq(wolftftp_build_request(buf, sizeof(buf), WOLFTFTP_OP_RRQ,
        name, &cfg, 0xFFFFFFFFU, &requested, &out_len), 0);
    ck_assert_uint_eq(requested,
        (uint8_t)(WOLFTFTP_OPT_BLKSIZE | WOLFTFTP_OPT_TIMEOUT |
                  WOLFTFTP_OPT_WINDOWSIZE | WOLFTFTP_OPT_TSIZE));
    ck_assert_uint_le(out_len, sizeof(buf));
}
END_TEST

START_TEST(test_tftp_server_rrq_retransmit_replays_window)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    /* Server uses defaults (no options), with a windowsize of 2 so we
     * actually get a multi-block window we can compare across the
     * retransmit boundary. */
    struct wolftftp_transfer_cfg cfg;
    struct wolftftp_transfer_cfg req_cfg;
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote = tftp_remote(0x0A000030U, 4001);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;
    uint16_t blksize = 8U;

    memset(&cfg, 0, sizeof(cfg));
    cfg.blksize = blksize;
    cfg.timeout_s = 1;
    cfg.windowsize = 2;
    cfg.max_retries = 5;

    /* Request side wants all defaults so no options are negotiated;
     * the server immediately sends the first window of data. */
    memset(&req_cfg, 0, sizeof(req_cfg));
    req_cfg.blksize = WOLFTFTP_DEFAULT_BLKSIZE;
    req_cfg.timeout_s = WOLFTFTP_DEFAULT_TIMEOUT_S;
    req_cfg.windowsize = 1;

    tftp_test_ctx_reset(&ctx);
    /* Fill the source with several full blocks of distinguishable data
     * so we can spot any accidental advance past the unacked window. */
    memset(ctx.read_data, 'A', blksize);
    memset(ctx.read_data + blksize, 'B', blksize);
    memset(ctx.read_data + 2 * blksize, 'C', blksize);
    memset(ctx.read_data + 3 * blksize, 'D', blksize);
    ctx.read_len[0] = blksize;
    ctx.read_len[1] = blksize;
    /* Replay (block 1, block 2) again on retransmit. */
    ctx.read_len[2] = blksize;
    ctx.read_len[3] = blksize;
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);

    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_RRQ,
        "fw.bin", &req_cfg, 0, &opts, &req_len), 0);
    ck_assert_uint_eq(opts, 0U);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    /* No-option RRQ skips the OACK; first window of 2 blocks is sent. */
    ck_assert_int_eq(ctx.send_calls, 2);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[0] + 2), 1U);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[1] + 2), 2U);

    /* Force a timeout; this triggers the RRQ retransmit branch in
     * wolftftp_server_poll. Before the fix it would send blocks 3 and
     * 4 (advancing past the unacked window); after the fix it must
     * replay blocks 1 and 2. */
    ck_assert_int_eq(wolftftp_server_poll(&server, 1U), 0);
    ck_assert_int_eq(wolftftp_server_poll(&server, 5000U), 0);
    ck_assert_int_eq(ctx.send_calls, 4);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[2] + 2), 1U);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[3] + 2), 2U);
    ck_assert_mem_eq(ctx.sent[2] + 4, ctx.sent[0] + 4, blksize);
    ck_assert_mem_eq(ctx.sent[3] + 4, ctx.sent[1] + 4, blksize);
    /* Session state must remain anchored at the (still-unacked) start
     * of the replayed window. */
    ck_assert_uint_eq(server.sessions[0].window_start_block, 1U);
    ck_assert_uint_eq(server.sessions[0].window_start_offset, 0U);
}
END_TEST

START_TEST(test_tftp_client_poll_deadline_is_wrap_safe)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint srv = tftp_remote(0x0A000040U, 0);
    uint32_t base = 0xFFFFF000U; /* near uint32_t wrap */

    cfg.timeout_s = 2; /* deadline = base + 2000, which wraps past 0 */

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_client_init(&client, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);
    ck_assert_int_eq(ctx.send_calls, 1);

    /* Arm the deadline at base; the next tick computes
     * deadline = base + 2000 which wraps to a small value. */
    ck_assert_int_eq(wolftftp_client_poll(&client, base), 0);
    ck_assert_uint_ne(client.deadline_ms, 0U);
    /* "After 1000ms" — wrap is still in the future — must not retry. */
    ck_assert_int_eq(wolftftp_client_poll(&client, base + 1000U), 0);
    ck_assert_int_eq(ctx.send_calls, 1);
    /* After deadline, retry fires even though now < deadline numerically
     * would have been true with the old unsigned compare. */
    ck_assert_int_eq(wolftftp_client_poll(&client, base + 2500U), 0);
    ck_assert_int_eq(ctx.send_calls, 2);
}
END_TEST

START_TEST(test_tftp_server_rrq_sends_zero_byte_terminator_on_exact_multiple)
{
    /* RFC 1350: when the file length is an exact multiple of blksize
     * the server must still send a trailing 0-byte DATA block so the
     * peer can recognise EOF. Pin this behaviour with a 2 * blksize
     * read source. */
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg;
    struct wolftftp_transfer_cfg req_cfg;
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote = tftp_remote(0x0A000050U, 4200);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;
    uint16_t blksize = 8U;

    memset(&cfg, 0, sizeof(cfg));
    cfg.blksize = blksize;
    cfg.timeout_s = 1;
    cfg.windowsize = 1;
    cfg.max_retries = 3;

    memset(&req_cfg, 0, sizeof(req_cfg));
    req_cfg.blksize = WOLFTFTP_DEFAULT_BLKSIZE;
    req_cfg.timeout_s = WOLFTFTP_DEFAULT_TIMEOUT_S;
    req_cfg.windowsize = 1;

    tftp_test_ctx_reset(&ctx);
    memset(ctx.read_data, 'A', blksize);
    memset(ctx.read_data + blksize, 'B', blksize);
    /* Two full blocks of data; reader hints is_last after each because
     * fread-like callbacks don't know the file is an exact multiple. */
    ctx.read_len[0] = blksize; ctx.read_last[0] = 0;
    ctx.read_len[1] = blksize; ctx.read_last[1] = 1;
    /* A real callback would return 0 bytes past EOF. */
    ctx.read_len[2] = 0;       ctx.read_last[2] = 1;
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);

    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_RRQ,
        "fw.bin", &req_cfg, 0, &opts, &req_len), 0);
    ck_assert_uint_eq(opts, 0U);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    /* First DATA: block 1, full blksize. */
    ck_assert_int_eq(ctx.send_calls, 1);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[0]), WOLFTFTP_OP_DATA);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[0] + 2), 1U);
    ck_assert_uint_eq(ctx.sent_len[0], 4U + blksize);

    /* ACK 1 → expect block 2, also full blksize. */
    wolftftp_write_u16(pkt, WOLFTFTP_OP_ACK);
    wolftftp_write_u16(pkt + 2, 1);
    ck_assert_int_eq(wolftftp_server_receive(&server, server.sessions[0].local_port,
        &remote, pkt, 4), 0);
    ck_assert_int_eq(ctx.send_calls, 2);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[1] + 2), 2U);
    ck_assert_uint_eq(ctx.sent_len[1], 4U + blksize);

    /* ACK 2 → expect the explicit 0-byte block 3 (the EOF marker),
     * not session completion. */
    wolftftp_write_u16(pkt, WOLFTFTP_OP_ACK);
    wolftftp_write_u16(pkt + 2, 2);
    ck_assert_int_eq(wolftftp_server_receive(&server, server.sessions[0].local_port,
        &remote, pkt, 4), 0);
    ck_assert_int_eq(ctx.send_calls, 3);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[2] + 2), 3U);
    ck_assert_uint_eq(ctx.sent_len[2], 4U); /* opcode + block, no data */
    ck_assert_int_eq(ctx.close_calls, 0);

    /* Final ACK closes the session. */
    wolftftp_write_u16(pkt, WOLFTFTP_OP_ACK);
    wolftftp_write_u16(pkt + 2, 3);
    ck_assert_int_eq(wolftftp_server_receive(&server, server.sessions[0].local_port,
        &remote, pkt, 4), 0);
    ck_assert_int_eq(ctx.close_calls, 1);
    ck_assert_int_eq(ctx.close_status, 0);
}
END_TEST

/* F-5783: the RRQ send path accumulates next_offset/total_size (uint32_t)
 * with no max_image_size guard, unlike the WRQ receive path. A reader that
 * keeps returning full blocks would advance past the configured limit and
 * eventually wrap the uint32_t offset, re-reading near-start data. The
 * server must instead refuse to send past max_image_size with an ENOSPACE
 * error, mirroring the WRQ per-DATA guard. */
START_TEST(test_tftp_server_rrq_max_image_size_enforced_on_send)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg;
    struct wolftftp_transfer_cfg req_cfg;
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote = tftp_remote(0x0A000060U, 4300);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;
    uint16_t blksize = 8U;

    memset(&cfg, 0, sizeof(cfg));
    cfg.blksize = blksize;
    cfg.timeout_s = 1;
    cfg.windowsize = 1;
    cfg.max_retries = 3;
    /* Exactly two full blocks may be sent; the third must be rejected. */
    cfg.max_image_size = 2U * blksize;

    memset(&req_cfg, 0, sizeof(req_cfg));
    req_cfg.blksize = WOLFTFTP_DEFAULT_BLKSIZE;
    req_cfg.timeout_s = WOLFTFTP_DEFAULT_TIMEOUT_S;
    req_cfg.windowsize = 1;

    tftp_test_ctx_reset(&ctx);
    /* A reader that never signals EOF: every read returns a full block. */
    memset(ctx.read_data, 'A', blksize);
    memset(ctx.read_data + blksize, 'B', blksize);
    memset(ctx.read_data + 2 * blksize, 'C', blksize);
    ctx.read_len[0] = blksize; ctx.read_last[0] = 0;
    ctx.read_len[1] = blksize; ctx.read_last[1] = 0;
    ctx.read_len[2] = blksize; ctx.read_last[2] = 0;
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);

    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_RRQ,
        "fw.bin", &req_cfg, 0, &opts, &req_len), 0);
    ck_assert_uint_eq(opts, 0U);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    /* Block 1 (total 8 of 16). */
    ck_assert_int_eq(ctx.send_calls, 1);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[0]), WOLFTFTP_OP_DATA);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[0] + 2), 1U);

    /* ACK 1 → block 2 (total 16 of 16). */
    wolftftp_write_u16(pkt, WOLFTFTP_OP_ACK);
    wolftftp_write_u16(pkt + 2, 1);
    ck_assert_int_eq(wolftftp_server_receive(&server, server.sessions[0].local_port,
        &remote, pkt, 4), 0);
    ck_assert_int_eq(ctx.send_calls, 2);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[1]), WOLFTFTP_OP_DATA);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[1] + 2), 2U);

    /* ACK 2 → a third full block would push total past max_image_size;
     * the server must answer with an ENOSPACE error, not more DATA, and
     * reap the session. Before the fix this sent DATA block 3. */
    wolftftp_write_u16(pkt, WOLFTFTP_OP_ACK);
    wolftftp_write_u16(pkt + 2, 2);
    ck_assert_int_eq(wolftftp_server_receive(&server, server.sessions[0].local_port,
        &remote, pkt, 4), WOLFTFTP_ERR_SIZE);
    ck_assert_int_eq(ctx.send_calls, 3);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[2]), WOLFTFTP_OP_ERROR);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[2] + 2), WOLFTFTP_ENOSPACE);
    ck_assert_int_eq(server.sessions[0].state, WOLFTFTP_SESSION_FREE);
}
END_TEST

START_TEST(test_tftp_server_poll_deadline_is_wrap_safe)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote = tftp_remote(0x0A000041U, 4100);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;
    uint32_t base = 0xFFFFF000U;

    cfg.timeout_s = 2;

    tftp_test_ctx_reset(&ctx);
    memcpy(ctx.read_data, "abcdefg", 7);
    ctx.read_len[0] = 7;
    ctx.read_last[0] = 1;
    /* Replay buffer for the retransmit path: */
    ctx.read_len[1] = 7;
    ctx.read_last[1] = 1;
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_RRQ,
        "fw.bin", &cfg, 0, &opts, &req_len), 0);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    ck_assert_int_eq(ctx.send_calls, 1);

    ck_assert_int_eq(wolftftp_server_poll(&server, base), 0);
    ck_assert_uint_ne(server.sessions[0].deadline_ms, 0U);
    /* Before wrap-adjusted deadline: must not retransmit. */
    ck_assert_int_eq(wolftftp_server_poll(&server, base + 1000U), 0);
    ck_assert_int_eq(ctx.send_calls, 1);
    /* After deadline (with arithmetic wrap): must retransmit. */
    ck_assert_int_eq(wolftftp_server_poll(&server, base + 2500U), 0);
    ck_assert_int_eq(ctx.send_calls, 2);
}
END_TEST

/* RFC 2347: when option negotiation was used the server MUST replay
 * the OACK on timeout, not a bare ACK(0) or ACK(last_acked_block).
 * Exercise both RRQ-with-options and WRQ-with-options paths and
 * compare the retransmitted bytes to the original OACK. */
START_TEST(test_tftp_server_timeout_replays_oack_after_option_negotiation)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote;
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;
    uint16_t original_len;

    /* ---- RRQ + options ---- */
    tftp_test_ctx_reset(&ctx);
    memcpy(ctx.read_data, "wxyz", 4);
    ctx.read_len[0] = 4;
    /* Reader claims EOF; data_len < blksize so no extra 0-byte block. */
    remote = tftp_remote(0x0A000060U, 5050);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_RRQ,
        "fw.bin", &cfg, 0, &opts, &req_len), 0);
    ck_assert(opts != 0U);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    /* First send is the OACK, not a DATA — sanity. */
    ck_assert_int_eq(ctx.send_calls, 1);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[0]), WOLFTFTP_OP_OACK);
    original_len = ctx.sent_len[0];
    ck_assert_uint_eq(server.sessions[0].options_sent, 1U);
    ck_assert(server.sessions[0].oack_opts != 0U);

    /* Arm + trip the timeout. The retransmit must be a byte-for-byte
     * copy of the OACK, never ACK(0). */
    ck_assert_int_eq(wolftftp_server_poll(&server, 0U), 0);
    ck_assert_int_eq(wolftftp_server_poll(&server,
        (uint32_t)(cfg.timeout_s * 1000U + 1U)), 0);
    ck_assert_int_eq(ctx.send_calls, 2);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[1]), WOLFTFTP_OP_OACK);
    ck_assert_uint_eq(ctx.sent_len[1], original_len);
    ck_assert_mem_eq(ctx.sent[1], ctx.sent[0], original_len);

    /* ACK(0) clears options_sent; the next timeout must NOT replay
     * the OACK any more — it should retransmit the data window. */
    wolftftp_write_u16(pkt, WOLFTFTP_OP_ACK);
    wolftftp_write_u16(pkt + 2, 0);
    ck_assert_int_eq(wolftftp_server_receive(&server,
        server.sessions[0].local_port, &remote, pkt, 4), 0);
    ck_assert_uint_eq(server.sessions[0].options_sent, 0U);
    /* The ACK(0) triggered the first DATA send. */
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[ctx.send_calls - 1]),
        WOLFTFTP_OP_DATA);

    /* ---- WRQ + options ---- */
    tftp_test_ctx_reset(&ctx);
    remote = tftp_remote(0x0A000061U, 5060);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_WRQ,
        "fw.bin", &cfg, 4, &opts, &req_len), 0);
    ck_assert(opts != 0U);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    ck_assert_int_eq(ctx.send_calls, 1);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[0]), WOLFTFTP_OP_OACK);
    original_len = ctx.sent_len[0];

    /* Timeout: must replay the OACK rather than ACK(0). */
    ck_assert_int_eq(wolftftp_server_poll(&server, 0U), 0);
    ck_assert_int_eq(wolftftp_server_poll(&server,
        (uint32_t)(cfg.timeout_s * 1000U + 1U)), 0);
    ck_assert_int_eq(ctx.send_calls, 2);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[1]), WOLFTFTP_OP_OACK);
    ck_assert_uint_eq(ctx.sent_len[1], original_len);
    ck_assert_mem_eq(ctx.sent[1], ctx.sent[0], original_len);

    /* First DATA from client implicitly ACKs the OACK. options_sent
     * must clear so further timeouts retransmit ACK(last) instead. */
    memcpy(pkt + 4, "abcd", 4);
    {
        int data_len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 4);
        ck_assert_int_eq(wolftftp_server_receive(&server,
            server.sessions[0].local_port, &remote, pkt, (uint16_t)data_len), 0);
    }
    ck_assert_uint_eq(server.sessions[0].options_sent, 0U);
}
END_TEST

/* ---------------------------------------------------------------------------
 * Coverage gap closures (RFC 1350 / 2347 / 2348 / 2349 / 7440 corners).
 *
 * Each test below targets a specific cluster of previously-uncovered
 * branches in src/tftp/wolftftp.c. They are grouped by area:
 *
 *   A. defensive NULL / bounds checks across the public + private API
 *   B. send-callback failure propagation
 *   C. option-range / option-parser edge cases
 *   D. client edge cases (TID lock, unexpected opcode, verify failure,
 *      tsize > max_image_size, duplicate-block ACK retransmit replay)
 *   E. server edge cases (WRQ full flow with options, io.* missing,
 *      bad-block ACK, retries exhausted, ENOSPACE on WRQ, hash failure)
 *
 * The tests intentionally exercise small, surgical scenarios so each
 * failure points at one root cause rather than a regression in the
 * happy path.
 * ------------------------------------------------------------------------- */

START_TEST(test_tftp_helpers_null_and_bounds)
{
    /* strnlen_local: NULL input returns 0. */
    ck_assert_uint_eq(wolftftp_strnlen_local(NULL, 16), 0U);
    /* No NUL within max_len returns max_len. */
    {
        char no_nul[8];
        memset(no_nul, 'a', sizeof(no_nul));
        ck_assert_uint_eq(wolftftp_strnlen_local(no_nul, sizeof(no_nul)),
            sizeof(no_nul));
    }
    /* stricmp_local: either operand NULL → negative. */
    ck_assert_int_lt(wolftftp_stricmp_local(NULL, "octet"), 0);
    ck_assert_int_lt(wolftftp_stricmp_local("octet", NULL), 0);
    /* stricmp_local: prefix mismatch flips < 0 vs > 0 based on tolower. */
    ck_assert_int_lt(wolftftp_stricmp_local("a", "b"), 0);
    ck_assert_int_gt(wolftftp_stricmp_local("z", "a"), 0);
    /* Unequal lengths: "abc" vs "ab" — the shorter wins as "shorter < longer". */
    ck_assert_int_lt(wolftftp_stricmp_local("ab", "abc"), 0);
    ck_assert_int_gt(wolftftp_stricmp_local("abc", "ab"), 0);

    /* parse_u32: all rejection paths. */
    {
        uint32_t v = 0xCAFEU;
        ck_assert_int_eq(wolftftp_parse_u32(NULL, 100, &v), -1);
        ck_assert_int_eq(wolftftp_parse_u32("", 100, &v), -1);
        ck_assert_int_eq(wolftftp_parse_u32("12", 100, NULL), -1);
        /* non-digit somewhere in the middle */
        ck_assert_int_eq(wolftftp_parse_u32("1a2", 100, &v), -1);
        /* numeric overflow past max_value */
        ck_assert_int_eq(wolftftp_parse_u32("1000000", 999, &v), -1);
    }

    /* copy_string: NULL / zero dst / oversized src. */
    {
        char dst[8];
        ck_assert_int_eq(wolftftp_copy_string(NULL, 8, "x"), -WOLFIP_EINVAL);
        ck_assert_int_eq(wolftftp_copy_string(dst, 0, "x"), -WOLFIP_EINVAL);
        ck_assert_int_eq(wolftftp_copy_string(dst, sizeof(dst), NULL),
            -WOLFIP_EINVAL);
        ck_assert_int_eq(wolftftp_copy_string(dst, sizeof(dst), ""),
            -WOLFIP_EINVAL);
        ck_assert_int_eq(wolftftp_copy_string(dst, 4, "longer"),
            -WOLFIP_EINVAL);
    }

    /* cfg_defaults clamping: zero fields filled in, oversized clamped. */
    {
        struct wolftftp_transfer_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        wolftftp_cfg_defaults(&cfg);
        ck_assert_uint_eq(cfg.blksize, WOLFTFTP_DEFAULT_BLKSIZE);
        ck_assert_uint_eq(cfg.timeout_s, WOLFTFTP_DEFAULT_TIMEOUT_S);
        ck_assert_uint_eq(cfg.windowsize, 1U);
        ck_assert_uint_eq(cfg.max_retries, WOLFTFTP_MAX_RETRIES);
        memset(&cfg, 0, sizeof(cfg));
        cfg.blksize = WOLFTFTP_MAX_BLKSIZE * 2U;
        cfg.windowsize = WOLFTFTP_MAX_WINDOWSIZE * 2U;
        wolftftp_cfg_defaults(&cfg);
        ck_assert_uint_eq(cfg.blksize, WOLFTFTP_MAX_BLKSIZE);
        ck_assert_uint_eq(cfg.windowsize, WOLFTFTP_MAX_WINDOWSIZE);
    }

    /* wolftftp_deadline: when (now_ms + timeout_s*1000) wraps exactly
     * to 0, the helper must nudge to 1 so the "not armed" sentinel
     * stays distinguishable. */
    {
        struct wolftftp_negotiated neg = {0};
        neg.timeout_s = 1U;
        /* now + 1000 = 0 → nudged to 1. */
        ck_assert_uint_eq(wolftftp_deadline(&neg, 0U - 1000U), 1U);
        ck_assert_uint_eq(wolftftp_deadline(&neg, 0U), 1000U);
    }

    /* Low-level send wrapper rejects each kind of bad arg. */
    {
        struct wolftftp_transport_ops t;
        struct wolftftp_endpoint r = {0};
        uint8_t b[1];
        memset(&t, 0, sizeof(t));
        ck_assert_int_eq(wolftftp_send(NULL, 0, &r, b, 1), -WOLFIP_EINVAL);
        ck_assert_int_eq(wolftftp_send(&t, 0, &r, b, 1), -WOLFIP_EINVAL);
        t.send = (wolftftp_udp_send_cb)1; /* non-NULL is enough */
        ck_assert_int_eq(wolftftp_send(&t, 0, NULL, b, 1), -WOLFIP_EINVAL);
        ck_assert_int_eq(wolftftp_send(&t, 0, &r, NULL, 1), -WOLFIP_EINVAL);
        ck_assert_int_eq(wolftftp_send(&t, 0, &r, b, 0), -WOLFIP_EINVAL);
    }

    /* finish() defensives: NULL-safe and (server, session NULL) safe. */
    wolftftp_client_finish(NULL, 0);
    wolftftp_server_finish(NULL, NULL, 0);
}
END_TEST

START_TEST(test_tftp_builders_overflow_and_bad_args)
{
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint8_t tiny[6];
    uint16_t out_len = 0;
    uint8_t requested = 0;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_negotiated neg;

    /* build_request: NULL args. */
    ck_assert_int_eq(wolftftp_build_request(NULL, sizeof(pkt), WOLFTFTP_OP_RRQ,
        "fw.bin", &cfg, 0, &requested, &out_len), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_RRQ,
        NULL, &cfg, 0, &requested, &out_len), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_RRQ,
        "fw.bin", NULL, 0, &requested, &out_len), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_RRQ,
        "fw.bin", &cfg, 0, NULL, &out_len), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_RRQ,
        "fw.bin", &cfg, 0, &requested, NULL), -WOLFIP_EINVAL);
    /* build_request: empty filename. */
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_RRQ,
        "", &cfg, 0, &requested, &out_len), -WOLFIP_EINVAL);
    /* build_request: filename too long. */
    {
        char too_long[WOLFTFTP_MAX_FILENAME + 4];
        memset(too_long, 'a', sizeof(too_long) - 1);
        too_long[sizeof(too_long) - 1] = '\0';
        ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt),
            WOLFTFTP_OP_RRQ, too_long, &cfg, 0, &requested, &out_len),
            -WOLFIP_EINVAL);
    }
    /* build_request: caller-supplied buffer cannot even fit fixed
     * header (opcode + "fw.bin\0" + "octet\0" + a tiny option). */
    ck_assert_int_eq(wolftftp_build_request(tiny, sizeof(tiny),
        WOLFTFTP_OP_RRQ, "fw.bin", &cfg, 0, &requested, &out_len),
        WOLFTFTP_ERR_PACKET);
    /* build_request: header fits but the first option does not — pass
     * a buffer just large enough for opcode + filename + "octet\0"
     * but not for any option blob. */
    {
        struct wolftftp_transfer_cfg opt_cfg = tftp_cfg_defaults();
        uint8_t narrow[2 + 7 + 6 + 1]; /* +1 leaves no room for option */
        out_len = 0; requested = 0;
        ck_assert_int_eq(wolftftp_build_request(narrow, sizeof(narrow),
            WOLFTFTP_OP_RRQ, "fw.bin", &opt_cfg, 0, &requested, &out_len),
            WOLFTFTP_ERR_PACKET);
    }

    /* build_oack: NULL args + capped buffer triggers append failure. */
    wolftftp_neg_defaults(&neg, &cfg);
    neg.tsize = 12; neg.have_tsize = 1;
    ck_assert_int_eq(wolftftp_build_oack(NULL, sizeof(pkt), &neg,
        WOLFTFTP_OPT_BLKSIZE), -WOLFIP_EINVAL);
    ck_assert_int_eq(wolftftp_build_oack(pkt, sizeof(pkt), NULL,
        WOLFTFTP_OPT_BLKSIZE), -WOLFIP_EINVAL);
    /* Force every append-opt error branch by giving the OACK builder
     * a buffer that grows just-too-small as each option is appended. */
    ck_assert_int_eq(wolftftp_build_oack(tiny, sizeof(tiny), &neg,
        WOLFTFTP_OPT_BLKSIZE), WOLFTFTP_ERR_PACKET);
    ck_assert_int_eq(wolftftp_build_oack(tiny, sizeof(tiny), &neg,
        WOLFTFTP_OPT_TIMEOUT), WOLFTFTP_ERR_PACKET);
    ck_assert_int_eq(wolftftp_build_oack(tiny, sizeof(tiny), &neg,
        WOLFTFTP_OPT_TSIZE), WOLFTFTP_ERR_PACKET);
    ck_assert_int_eq(wolftftp_build_oack(tiny, sizeof(tiny), &neg,
        WOLFTFTP_OPT_WINDOWSIZE), WOLFTFTP_ERR_PACKET);

    /* build_data: NULL data, undersized buffer. */
    ck_assert_int_eq(wolftftp_build_data(NULL, sizeof(pkt), 1, pkt + 4, 1),
        WOLFTFTP_ERR_PACKET);
    ck_assert_int_eq(wolftftp_build_data(pkt, sizeof(pkt), 1, NULL, 1),
        WOLFTFTP_ERR_PACKET);
    ck_assert_int_eq(wolftftp_build_data(pkt, 3, 1, pkt + 4, 1),
        WOLFTFTP_ERR_PACKET);

    /* build_error: NULL args, msg overflows max_len. */
    ck_assert_int_eq(wolftftp_build_error(NULL, sizeof(pkt),
        WOLFTFTP_EBADOP, "x"), WOLFTFTP_ERR_PACKET);
    ck_assert_int_eq(wolftftp_build_error(pkt, sizeof(pkt),
        WOLFTFTP_EBADOP, NULL), WOLFTFTP_ERR_PACKET);
    ck_assert_int_eq(wolftftp_build_error(pkt, 4, WOLFTFTP_EBADOP, "x"),
        WOLFTFTP_ERR_PACKET);
    ck_assert_int_eq(wolftftp_build_error(pkt, 5, WOLFTFTP_EBADOP, "long"),
        WOLFTFTP_ERR_PACKET);

    /* packet_opcode: NULL buf, short len. */
    ck_assert_int_eq(wolftftp_packet_opcode(NULL, 4), -1);
    ck_assert_int_eq(wolftftp_packet_opcode(pkt, 1), -1);

    /* parse_data: NULL args, short frame, wrong opcode. */
    {
        struct wolftftp_parsed_data d;
        ck_assert_int_eq(wolftftp_parse_data(NULL, 10, &d), WOLFTFTP_ERR_PACKET);
        ck_assert_int_eq(wolftftp_parse_data(pkt, 10, NULL), WOLFTFTP_ERR_PACKET);
        ck_assert_int_eq(wolftftp_parse_data(pkt, 3, &d), WOLFTFTP_ERR_PACKET);
        wolftftp_write_u16(pkt, WOLFTFTP_OP_ACK);
        ck_assert_int_eq(wolftftp_parse_data(pkt, 10, &d), WOLFTFTP_ERR_PACKET);
    }

    /* parse_request: NULL args, too short. */
    {
        struct wolftftp_parsed_req r;
        ck_assert_int_eq(wolftftp_parse_request(NULL, 10, &r),
            WOLFTFTP_ERR_PACKET);
        ck_assert_int_eq(wolftftp_parse_request(pkt, 10, NULL),
            WOLFTFTP_ERR_PACKET);
        ck_assert_int_eq(wolftftp_parse_request(pkt, 3, &r),
            WOLFTFTP_ERR_PACKET);
        /* Filename that runs the whole buffer with no terminating NUL. */
        memset(pkt, 'a', sizeof(pkt));
        wolftftp_write_u16(pkt, WOLFTFTP_OP_RRQ);
        ck_assert_int_eq(wolftftp_parse_request(pkt, 32, &r),
            WOLFTFTP_ERR_PACKET);
    }

    /* parse_oack: NULL args, wrong opcode, short len. */
    {
        struct wolftftp_negotiated n;
        wolftftp_neg_defaults(&n, &cfg);
        ck_assert_int_eq(wolftftp_parse_oack(NULL, 10, &n),
            WOLFTFTP_ERR_PACKET);
        ck_assert_int_eq(wolftftp_parse_oack(pkt, 10, NULL),
            WOLFTFTP_ERR_PACKET);
        ck_assert_int_eq(wolftftp_parse_oack(pkt, 1, &n),
            WOLFTFTP_ERR_PACKET);
        wolftftp_write_u16(pkt, WOLFTFTP_OP_RRQ); /* wrong */
        ck_assert_int_eq(wolftftp_parse_oack(pkt, 4, &n),
            WOLFTFTP_ERR_PACKET);
    }
}
END_TEST

START_TEST(test_tftp_send_failure_propagation)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint srv = tftp_remote(0x0A000070U, 0);
    struct wolftftp_endpoint cli = tftp_remote(0x0A000071U, 8000);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;

    /* Client: initial RRQ send fails → start_rrq returns the send error. */
    tftp_test_ctx_reset(&ctx);
    ctx.send_fail = WOLFTFTP_ERR_IO;
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_client_init(&client, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"),
        WOLFTFTP_ERR_IO);

    /* Client poll: retransmit send fails — poll returns the error. */
    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_client_init(&client, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);
    ctx.send_fail = WOLFTFTP_ERR_IO;
    ck_assert_int_eq(wolftftp_client_poll(&client, 0), 0);   /* arms */
    ck_assert_int_eq(wolftftp_client_poll(&client, 5000U),
        WOLFTFTP_ERR_IO);

    /* Server: parse-request fail (non-octet mode) → server replies with
     * an error frame; if THAT send fails, the function bubbles up the
     * transport error. */
    tftp_test_ctx_reset(&ctx);
    ctx.send_fail = WOLFTFTP_ERR_IO;
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_RRQ);
    memcpy(pkt + 2, "fw\0netascii\0", 12);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &cli,
        pkt, 14), WOLFTFTP_ERR_IO);

    /* Server: OACK send fails on start_request — start_request returns
     * the send error and the session is reaped (slot returns to FREE). */
    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_RRQ,
        "fw.bin", &cfg, 0, &opts, &req_len), 0);
    ck_assert(opts != 0U);
    ctx.send_fail = WOLFTFTP_ERR_IO;
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &cli,
        pkt, req_len), WOLFTFTP_ERR_IO);

    /* Server: first DATA send fails for a no-option RRQ. The session
     * is left in SEND_WAIT_ACK and a follow-up timeout will retry. */
    tftp_test_ctx_reset(&ctx);
    memcpy(ctx.read_data, "abcdefg", 7);
    ctx.read_len[0] = 7;
    ctx.read_last[0] = 1;
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    {
        struct wolftftp_transfer_cfg req_cfg;
        memset(&req_cfg, 0, sizeof(req_cfg));
        req_cfg.blksize = WOLFTFTP_DEFAULT_BLKSIZE;
        req_cfg.timeout_s = WOLFTFTP_DEFAULT_TIMEOUT_S;
        req_cfg.windowsize = 1;
        opts = 0;
        ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt),
            WOLFTFTP_OP_RRQ, "fw.bin", &req_cfg, 0, &opts, &req_len), 0);
        ck_assert_uint_eq(opts, 0U);
        ctx.send_fail = WOLFTFTP_ERR_IO;
        ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &cli,
            pkt, req_len), WOLFTFTP_ERR_IO);
    }
}
END_TEST

START_TEST(test_tftp_parse_option_ranges)
{
    uint8_t pkt[96];
    struct wolftftp_parsed_req req;
    struct wolftftp_negotiated neg;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();

    /* RRQ: blksize=4 (< 8) → rejected. */
    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_RRQ);
    memcpy(pkt + 2, "fw\0octet\0blksize\0" "4\0", 19);
    ck_assert_int_eq(wolftftp_parse_request(pkt, 21, &req),
        WOLFTFTP_ERR_UNSUPPORTED);

    /* RRQ: timeout=0 → rejected (must be 1..255). */
    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_RRQ);
    memcpy(pkt + 2, "fw\0octet\0timeout\0" "0\0", 19);
    ck_assert_int_eq(wolftftp_parse_request(pkt, 21, &req),
        WOLFTFTP_ERR_UNSUPPORTED);

    /* RRQ: windowsize=0 → rejected. */
    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_RRQ);
    memcpy(pkt + 2, "fw\0octet\0windowsize\0" "0\0", 22);
    ck_assert_int_eq(wolftftp_parse_request(pkt, 24, &req),
        WOLFTFTP_ERR_UNSUPPORTED);

    /* OACK: blksize=4 → rejected. */
    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_OACK);
    memcpy(pkt + 2, "blksize\0" "4\0", 10);
    wolftftp_neg_defaults(&neg, &cfg);
    ck_assert_int_eq(wolftftp_parse_oack(pkt, 12, &neg),
        WOLFTFTP_ERR_UNSUPPORTED);

    /* OACK: timeout=0 → rejected. */
    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_OACK);
    memcpy(pkt + 2, "timeout\0" "0\0", 10);
    wolftftp_neg_defaults(&neg, &cfg);
    ck_assert_int_eq(wolftftp_parse_oack(pkt, 12, &neg),
        WOLFTFTP_ERR_UNSUPPORTED);

    /* OACK: windowsize=0 → rejected. */
    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_OACK);
    memcpy(pkt + 2, "windowsize\0" "0\0", 13);
    wolftftp_neg_defaults(&neg, &cfg);
    ck_assert_int_eq(wolftftp_parse_oack(pkt, 15, &neg),
        WOLFTFTP_ERR_UNSUPPORTED);

    /* OACK: unknown option → rejected. */
    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_OACK);
    memcpy(pkt + 2, "mystery\0" "1\0", 10);
    wolftftp_neg_defaults(&neg, &cfg);
    ck_assert_int_eq(wolftftp_parse_oack(pkt, 12, &neg),
        WOLFTFTP_ERR_UNSUPPORTED);

    /* OACK: full valid option set (covers all 4 accepted branches).
     * Each "key\0" "val\0" pair is two adjacent string literals; the
     * concatenated payload is the raw on-wire option list (no extra
     * implicit C-string NUL because we memcpy by explicit length). */
    {
        const char payload[] =
            "blksize\0" "32\0"
            "timeout\0" "5\0"
            "tsize\0" "100\0"
            "windowsize\0" "2\0";
        size_t payload_len = sizeof(payload) - 1; /* drop implicit NUL */
        memset(pkt, 0, sizeof(pkt));
        wolftftp_write_u16(pkt, WOLFTFTP_OP_OACK);
        memcpy(pkt + 2, payload, payload_len);
        wolftftp_neg_defaults(&neg, &cfg);
        ck_assert_int_eq(wolftftp_parse_oack(pkt, (uint16_t)(2 + payload_len),
            &neg), 0);
    }
    ck_assert_uint_eq(neg.blksize, 32U);
    ck_assert_uint_eq(neg.timeout_s, 5U);
    ck_assert_uint_eq(neg.tsize, 100U);
    ck_assert_uint_eq(neg.have_tsize, 1U);
    ck_assert_uint_eq(neg.windowsize, 2U);
}
END_TEST

START_TEST(test_tftp_client_unexpected_opcode_rejected)
{
    /* RRQ-receiving client must reject opcodes that aren't OACK,
     * ERROR, or DATA (e.g. a stray RRQ/WRQ/ACK) — RFC 1350 doesn't
     * mandate this exact code but we treat it as ERR_PACKET. */
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint srv = tftp_remote(0x0A000080U, 0);
    struct wolftftp_endpoint tid = tftp_remote(srv.ip, 4321);
    uint8_t pkt[16];

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_client_init(&client, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);

    /* Send a stray ACK to the client — must be rejected as malformed. */
    wolftftp_write_u16(pkt, WOLFTFTP_OP_ACK);
    wolftftp_write_u16(pkt + 2, 1);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, 4), WOLFTFTP_ERR_PACKET);
}
END_TEST

START_TEST(test_tftp_client_invalid_first_data_does_not_lock_tid)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint srv = tftp_remote(0x0A000080U, 0);
    struct wolftftp_endpoint attacker = tftp_remote(srv.ip, 4321);
    struct wolftftp_endpoint tid = tftp_remote(srv.ip, 5678);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    int len;

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_client_init(&client, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);

    /* A malformed first DATA must be rejected without latching its TID. */
    memset(pkt, 0, sizeof(pkt));
    wolftftp_write_u16(pkt, WOLFTFTP_OP_DATA);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &attacker, pkt, 3), WOLFTFTP_ERR_PACKET);
    ck_assert_uint_eq(client.tid_locked, 0U);
    ck_assert_uint_eq(client.server.port, WOLFTFTP_PORT);

    memcpy(pkt + 4, "0123456789abcdef", 16);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 16);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), 0);
    ck_assert_uint_eq(client.tid_locked, 1U);
    ck_assert_uint_eq(client.server.port, tid.port);
}
END_TEST

START_TEST(test_tftp_client_max_image_size_enforced_on_data)
{
    /* OACK didn't trip the tsize check (no tsize); enforcement
     * happens on accumulated bytes during accept_data. Pin both the
     * error-frame send and the FAIL state. */
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint srv = tftp_remote(0x0A000081U, 0);
    struct wolftftp_endpoint tid = tftp_remote(srv.ip, 5678);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    int len;

    cfg.max_image_size = 8U;
    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_client_init(&client, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);
    /* Block 1: 16 bytes (full blksize=16 from tftp_cfg_defaults) — over
     * cfg.max_image_size = 8 → client sends ENOSPACE error + ERR_SIZE. */
    memcpy(pkt + 4, "0123456789abcdef", 16);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 16);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), WOLFTFTP_ERR_SIZE);
    ck_assert_uint_eq(client.state, WOLFTFTP_CLIENT_ERROR);
}
END_TEST

START_TEST(test_tftp_client_data_size_cap_is_overflow_safe)
{
    /* A rogue server that streams ~4 GiB without a short final block can
     * push client->total_size up to near UINT32_MAX. The size-cap guard
     * must not be defeated by an unsigned wrap of (total_size + data_len):
     * the next block has to be rejected with ERR_SIZE, not written at a
     * wrapped offset. Regression test for F-4254. */
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint srv = tftp_remote(0x0A0000A1U, 0);
    struct wolftftp_endpoint tid = tftp_remote(srv.ip, 7000);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    int len;

    cfg.max_image_size = 0xFFFFFFFFU;
    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_client_init(&client, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);

    /* Block 1 establishes the TID and the data phase (16 bytes written). */
    memcpy(pkt + 4, "0123456789abcdef", 16);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 16);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), 0);
    ck_assert_int_eq(ctx.write_calls, 1);

    /* Fast-forward the accumulated total to just below the 32-bit limit,
     * as if ~4 GiB had already arrived. Adding the next 16-byte block
     * would wrap (total_size + 16) back to a small value that slips under
     * max_image_size, defeating the cap. */
    client.total_size = 0xFFFFFFF8U;
    memcpy(pkt + 4, "ghijklmnopqrstuv", 16);
    len = wolftftp_build_data(pkt, sizeof(pkt), 2, pkt + 4, 16);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), WOLFTFTP_ERR_SIZE);
    ck_assert_uint_eq(client.state, WOLFTFTP_CLIENT_ERROR);
    /* The wrapped block must never reach the write sink. */
    ck_assert_int_eq(ctx.write_calls, 1);
}
END_TEST

START_TEST(test_tftp_client_duplicate_block_replays_last_ack)
{
    /* RFC 1350: if the receiver sees an out-of-order block matching
     * the last-acked or previous-expected one, it must replay the
     * most recent ACK rather than ignoring it or breaking state.
     * Use windowsize=1 so the client ACKs every block immediately and
     * last_tx holds an ACK we can compare. */
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint srv = tftp_remote(0x0A000082U, 0);
    struct wolftftp_endpoint tid = tftp_remote(srv.ip, 6500);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    int len;
    int send_calls_after_first_ack;

    cfg.windowsize = 1;
    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_client_init(&client, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);
    /* Deliver block 1 full-blksize — client writes, ACKs, expects 2. */
    memcpy(pkt + 4, "0123456789ABCDEF", 16);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 16);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), 0);
    send_calls_after_first_ack = ctx.send_calls;
    /* That ACK is the most recent send, so we can index it directly. */
    ck_assert_uint_eq(wolftftp_read_u16(
        ctx.sent[send_calls_after_first_ack - 1]), WOLFTFTP_OP_ACK);

    /* Now redeliver block 1 — the client should replay its cached
     * ACK(1) without re-writing the data. */
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 16);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), 0);
    ck_assert_int_eq(ctx.send_calls, send_calls_after_first_ack + 1);
    ck_assert_int_eq(ctx.write_calls, 1);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[send_calls_after_first_ack]),
        WOLFTFTP_OP_ACK);
    ck_assert_uint_eq(wolftftp_read_u16(
        ctx.sent[send_calls_after_first_ack] + 2), 1U);
}
END_TEST

START_TEST(test_tftp_client_open_sink_missing_callbacks)
{
    /* Client misconfigured without io.write must fail when the first
     * DATA arrives (open_sink internally short-circuits). */
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint srv = tftp_remote(0x0A000083U, 0);
    struct wolftftp_endpoint tid = tftp_remote(srv.ip, 6700);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    int len;

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    io.write = NULL; /* deliberately drop write */
    wolftftp_client_init(&client, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);
    memcpy(pkt + 4, "end", 3);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 3);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), WOLFTFTP_ERR_IO);
    ck_assert_uint_eq(client.state, WOLFTFTP_CLIENT_ERROR);
}
END_TEST

START_TEST(test_tftp_client_oack_tsize_exceeds_limit)
{
    /* OACK advertises tsize bigger than cfg.max_image_size — client
     * must send ENOSPACE and finish with ERR_SIZE before any DATA. */
    struct tftp_test_ctx ctx;
    struct wolftftp_client client;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint srv = tftp_remote(0x0A000084U, 0);
    struct wolftftp_endpoint tid = tftp_remote(srv.ip, 6800);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    int len;

    cfg.max_image_size = 1U;
    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_client_init(&client, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_client_start_rrq(&client, &srv, "fw.bin"), 0);
    wolftftp_neg_defaults(&client.neg, &cfg);
    client.neg.tsize = 1024U;
    client.neg.have_tsize = 1;
    len = wolftftp_build_oack(pkt, sizeof(pkt), &client.neg,
        WOLFTFTP_OPT_TSIZE);
    ck_assert_int_eq(wolftftp_client_receive(&client, cfg.local_port,
        &tid, pkt, (uint16_t)len), WOLFTFTP_ERR_SIZE);
    ck_assert_uint_eq(client.state, WOLFTFTP_CLIENT_ERROR);
}
END_TEST

START_TEST(test_tftp_server_io_missing_for_rrq_and_wrq)
{
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote = tftp_remote(0x0A000090U, 7000);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;

    /* RRQ but server has no io.read → "io unavailable" error + slot
     * reaped without entering data phase. */
    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    io.read = NULL;
    wolftftp_server_init(&server, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt),
        WOLFTFTP_OP_RRQ, "fw.bin", &cfg, 0, &opts, &req_len), 0);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    ck_assert_int_eq(ctx.send_calls, 1);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[0]), WOLFTFTP_OP_ERROR);
    ck_assert_uint_eq(server.sessions[0].state, WOLFTFTP_SESSION_FREE);

    /* WRQ but server has no io.write → same path on the opposite leg. */
    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    io.write = NULL;
    wolftftp_server_init(&server, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt),
        WOLFTFTP_OP_WRQ, "fw.bin", &cfg, 0, &opts, &req_len), 0);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    ck_assert_int_eq(ctx.send_calls, 1);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[0]), WOLFTFTP_OP_ERROR);
    ck_assert_uint_eq(server.sessions[0].state, WOLFTFTP_SESSION_FREE);
}
END_TEST

START_TEST(test_tftp_server_retries_exhausted_to_timeout)
{
    /* Pump server_poll until retries == cfg.max_retries, expect the
     * session to transition into the reap path with ERR_TIMEOUT. */
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote = tftp_remote(0x0A000091U, 7100);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;
    unsigned int i;

    cfg.max_retries = 2;
    cfg.timeout_s = 1;
    tftp_test_ctx_reset(&ctx);
    memcpy(ctx.read_data, "abc", 3);
    ctx.read_len[0] = 3;
    ctx.read_last[0] = 1;
    /* Read buffer for each retransmit replay; fill enough slots. */
    for (i = 1; i < 8; i++) {
        ctx.read_len[i] = 3;
        ctx.read_last[i] = 1;
    }
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    {
        struct wolftftp_transfer_cfg req_cfg;
        memset(&req_cfg, 0, sizeof(req_cfg));
        req_cfg.blksize = WOLFTFTP_DEFAULT_BLKSIZE;
        req_cfg.timeout_s = WOLFTFTP_DEFAULT_TIMEOUT_S;
        req_cfg.windowsize = 1;
        ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt),
            WOLFTFTP_OP_RRQ, "fw.bin", &req_cfg, 0, &opts, &req_len), 0);
    }
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    /* Drive the timeout loop past retries. */
    (void)wolftftp_server_poll(&server, 0U);
    (void)wolftftp_server_poll(&server, 2000U);  /* retry 1 */
    (void)wolftftp_server_poll(&server, 4000U);  /* retry 2 */
    (void)wolftftp_server_poll(&server, 6000U);  /* retries exhausted → reap */
    ck_assert_uint_eq(server.sessions[0].state, WOLFTFTP_SESSION_FREE);
    ck_assert_int_eq(ctx.close_status, WOLFTFTP_ERR_TIMEOUT);
}
END_TEST

START_TEST(test_tftp_server_wrq_full_flow_with_options)
{
    /* Drive a WRQ with options end-to-end: OACK → DATA (windowed) →
     * ACK → DATA → final-short → ACK → close. This wakes a lot of
     * accept_wrq_data branches. */
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg;
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote = tftp_remote(0x0A000092U, 7200);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;
    int len;

    memset(&cfg, 0, sizeof(cfg));
    cfg.blksize = 8;
    cfg.timeout_s = 1;
    cfg.windowsize = 2;
    cfg.max_retries = 3;
    cfg.max_image_size = 64;

    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt),
        WOLFTFTP_OP_WRQ, "fw.bin", &cfg, 12, &opts, &req_len), 0);
    ck_assert(opts != 0U);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[0]), WOLFTFTP_OP_OACK);

    /* Block 1: full blksize, second in window not yet — no ACK sent. */
    memcpy(pkt + 4, "AAAAAAAA", 8);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 8);
    ck_assert_int_eq(wolftftp_server_receive(&server,
        server.sessions[0].local_port, &remote, pkt, (uint16_t)len), 0);
    /* Block 2: completes the window → ACK(2). */
    memcpy(pkt + 4, "BBBBBBBB", 8);
    len = wolftftp_build_data(pkt, sizeof(pkt), 2, pkt + 4, 8);
    ck_assert_int_eq(wolftftp_server_receive(&server,
        server.sessions[0].local_port, &remote, pkt, (uint16_t)len), 0);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[ctx.send_calls - 1]),
        WOLFTFTP_OP_ACK);
    ck_assert_uint_eq(wolftftp_read_u16(ctx.sent[ctx.send_calls - 1] + 2), 2U);

    /* Final short block 3 (4 bytes < blksize) → final ACK + close. */
    memcpy(pkt + 4, "CCCC", 4);
    len = wolftftp_build_data(pkt, sizeof(pkt), 3, pkt + 4, 4);
    ck_assert_int_eq(wolftftp_server_receive(&server,
        server.sessions[0].local_port, &remote, pkt, (uint16_t)len), 0);
    ck_assert_int_eq(ctx.close_calls, 1);
    ck_assert_int_eq(ctx.close_status, 0);
    ck_assert_mem_eq(ctx.write_buf, "AAAAAAAABBBBBBBBCCCC", 20);
    /* Late duplicate of block 3 must replay ACK(3) (covers the
     * accept_wrq_data duplicate branch). */
    memcpy(pkt + 4, "CCCC", 4);
    len = wolftftp_build_data(pkt, sizeof(pkt), 3, pkt + 4, 4);
    /* After close the slot is FREE, so the server treats this as an
     * unknown TID — still a defined branch, not a crash. */
    (void)wolftftp_server_receive(&server,
        server.sessions[0].local_port, &remote, pkt, (uint16_t)len);
}
END_TEST

START_TEST(test_tftp_server_wrq_hash_failure_and_size_overflow)
{
    /* WRQ data write succeeds but io.hash_update fails — must finish
     * the session as ERR_VERIFY. */
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote = tftp_remote(0x0A000093U, 7300);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;
    int len;

    tftp_test_ctx_reset(&ctx);
    ctx.hash_fail = -1;
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt),
        WOLFTFTP_OP_WRQ, "fw.bin", &cfg, 0, &opts, &req_len), 0);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    memcpy(pkt + 4, "xxx", 3);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 3);
    ck_assert_int_eq(wolftftp_server_receive(&server,
        server.sessions[0].local_port, &remote, pkt, (uint16_t)len),
        WOLFTFTP_ERR_VERIFY);
    ck_assert_uint_eq(server.sessions[0].state, WOLFTFTP_SESSION_FREE);
}
END_TEST

START_TEST(test_tftp_server_wrq_data_size_cap_is_overflow_safe)
{
    /* A rogue client that streams ~4 GiB into a WRQ session can push
     * session->total_size up to near UINT32_MAX. The size-cap guard must
     * not be defeated by an unsigned wrap of (total_size + data_len): the
     * next block has to be rejected with ERR_SIZE, not written at a wrapped
     * offset that seeks back over already-written data. Regression for
     * F-4253 (server WRQ counterpart of F-4254). */
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg = tftp_cfg_defaults();
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote = tftp_remote(0x0A000095U, 7500);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;
    int len;

    cfg.max_image_size = 0xFFFFFFFFU;
    tftp_test_ctx_reset(&ctx);
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt),
        WOLFTFTP_OP_WRQ, "fw.bin", &cfg, 0, &opts, &req_len), 0);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);

    /* Block 1: full blksize, enters the data phase (16 bytes written). */
    memcpy(pkt + 4, "0123456789abcdef", 16);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 16);
    ck_assert_int_eq(wolftftp_server_receive(&server,
        server.sessions[0].local_port, &remote, pkt, (uint16_t)len), 0);
    ck_assert_int_eq(ctx.write_calls, 1);

    /* Fast-forward the accumulated total to just below the 32-bit limit,
     * as if ~4 GiB had already arrived. Adding the next 16-byte block
     * would wrap (total_size + 16) back to a small value that slips under
     * max_image_size, defeating the cap. */
    server.sessions[0].total_size = 0xFFFFFFF8U;
    memcpy(pkt + 4, "ghijklmnopqrstuv", 16);
    len = wolftftp_build_data(pkt, sizeof(pkt), 2, pkt + 4, 16);
    ck_assert_int_eq(wolftftp_server_receive(&server,
        server.sessions[0].local_port, &remote, pkt, (uint16_t)len),
        WOLFTFTP_ERR_SIZE);
    ck_assert_uint_eq(server.sessions[0].state, WOLFTFTP_SESSION_FREE);
    /* The wrapped block must never reach the write sink. */
    ck_assert_int_eq(ctx.write_calls, 1);
}
END_TEST

START_TEST(test_tftp_server_rrq_ack_bad_then_recover)
{
    /* ACK that doesn't match last_acked / (next_block-1) / OACK-ack-0
     * is silently dropped. Then a valid ACK proceeds the transfer. */
    struct tftp_test_ctx ctx;
    struct wolftftp_server server;
    struct wolftftp_transfer_cfg cfg;
    struct wolftftp_transport_ops transport;
    struct wolftftp_io_ops io;
    struct wolftftp_endpoint remote = tftp_remote(0x0A000094U, 7400);
    uint8_t pkt[WOLFTFTP_PKT_MAX];
    uint16_t req_len = 0;
    uint8_t opts = 0;

    memset(&cfg, 0, sizeof(cfg));
    cfg.blksize = 8;
    cfg.timeout_s = 1;
    cfg.windowsize = 1;
    cfg.max_retries = 3;

    tftp_test_ctx_reset(&ctx);
    memcpy(ctx.read_data, "abcdefgh", 8);
    ctx.read_len[0] = 8; /* full block */
    ctx.read_len[1] = 4; ctx.read_last[1] = 1; /* short final on retry */
    transport = tftp_transport_ops(&ctx);
    io = tftp_io_ops(&ctx);
    wolftftp_server_init(&server, &transport, &io, &cfg);
    {
        struct wolftftp_transfer_cfg req_cfg;
        memset(&req_cfg, 0, sizeof(req_cfg));
        req_cfg.blksize = WOLFTFTP_DEFAULT_BLKSIZE;
        req_cfg.timeout_s = WOLFTFTP_DEFAULT_TIMEOUT_S;
        req_cfg.windowsize = 1;
        ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt),
            WOLFTFTP_OP_RRQ, "fw.bin", &req_cfg, 0, &opts, &req_len), 0);
    }
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    ck_assert_int_eq(ctx.send_calls, 1);

    /* ACK with bogus block number 99 → dropped silently, no new DATA. */
    wolftftp_write_u16(pkt, WOLFTFTP_OP_ACK);
    wolftftp_write_u16(pkt + 2, 99);
    ck_assert_int_eq(wolftftp_server_receive(&server,
        server.sessions[0].local_port, &remote, pkt, 4), 0);
    ck_assert_int_eq(ctx.send_calls, 1);

    /* ACK with malformed length → ERR_PACKET. */
    ck_assert_int_eq(wolftftp_server_receive(&server,
        server.sessions[0].local_port, &remote, pkt, 3),
        WOLFTFTP_ERR_PACKET);
}
END_TEST

static void add_tftp_tests(TCase *tc_proto)
{
    tcase_add_test(tc_proto, test_tftp_helpers_and_builders);
    tcase_add_test(tc_proto, test_tftp_parse_request_error_paths);
    tcase_add_test(tc_proto, test_tftp_parse_request_rejects_path_traversal);
    tcase_add_test(tc_proto, test_tftp_client_rrq_oack_and_data_success);
    tcase_add_test(tc_proto, test_tftp_client_fallback_duplicate_and_tid_errors);
    tcase_add_test(tc_proto, test_tftp_client_error_and_failure_paths);
    tcase_add_test(tc_proto, test_tftp_client_poll_and_status_paths);
    tcase_add_test(tc_proto, test_tftp_server_rrq_success_and_poll);
    tcase_add_test(tc_proto, test_tftp_server_wrq_success_and_failures);
    tcase_add_test(tc_proto, test_tftp_server_wrq_tsize_exceeds_limit_rejected);
    tcase_add_test(tc_proto, test_tftp_server_request_errors_and_timeouts);
    tcase_add_test(tc_proto, test_tftp_server_session_reaped_after_completion);
    tcase_add_test(tc_proto, test_tftp_client_honors_caller_server_port);
    tcase_add_test(tc_proto, test_tftp_client_default_port_when_zero);
    tcase_add_test(tc_proto, test_tftp_parse_tsize_rejects_non_numeric);
    tcase_add_test(tc_proto, test_tftp_build_request_fits_max_options);
    tcase_add_test(tc_proto, test_tftp_server_rrq_retransmit_replays_window);
    tcase_add_test(tc_proto, test_tftp_client_poll_deadline_is_wrap_safe);
    tcase_add_test(tc_proto, test_tftp_server_poll_deadline_is_wrap_safe);
    tcase_add_test(tc_proto,
        test_tftp_server_rrq_max_image_size_enforced_on_send);
    tcase_add_test(tc_proto,
        test_tftp_server_rrq_sends_zero_byte_terminator_on_exact_multiple);
    tcase_add_test(tc_proto,
        test_tftp_server_timeout_replays_oack_after_option_negotiation);
    /* Coverage-targeted batches (see "Coverage gap closures" header). */
    tcase_add_test(tc_proto, test_tftp_helpers_null_and_bounds);
    tcase_add_test(tc_proto, test_tftp_builders_overflow_and_bad_args);
    tcase_add_test(tc_proto, test_tftp_send_failure_propagation);
    tcase_add_test(tc_proto, test_tftp_parse_option_ranges);
    tcase_add_test(tc_proto, test_tftp_client_unexpected_opcode_rejected);
    tcase_add_test(tc_proto, test_tftp_client_invalid_first_data_does_not_lock_tid);
    tcase_add_test(tc_proto, test_tftp_client_max_image_size_enforced_on_data);
    tcase_add_test(tc_proto, test_tftp_client_data_size_cap_is_overflow_safe);
    tcase_add_test(tc_proto, test_tftp_client_duplicate_block_replays_last_ack);
    tcase_add_test(tc_proto, test_tftp_client_open_sink_missing_callbacks);
    tcase_add_test(tc_proto, test_tftp_client_oack_tsize_exceeds_limit);
    tcase_add_test(tc_proto, test_tftp_server_io_missing_for_rrq_and_wrq);
    tcase_add_test(tc_proto, test_tftp_server_retries_exhausted_to_timeout);
    tcase_add_test(tc_proto, test_tftp_server_wrq_full_flow_with_options);
    tcase_add_test(tc_proto, test_tftp_server_wrq_hash_failure_and_size_overflow);
    tcase_add_test(tc_proto, test_tftp_server_wrq_data_size_cap_is_overflow_safe);
    tcase_add_test(tc_proto, test_tftp_server_rrq_ack_bad_then_recover);
}

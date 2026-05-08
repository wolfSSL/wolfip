/* unit_tests_tftp.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
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

    ck_assert_int_eq(wolftftp_stricmp_local("octet", "OCTET"), 0);
    ck_assert_uint_eq(wolftftp_parse_u32("42", 100), 42);
    ck_assert_uint_eq(wolftftp_parse_u32("999", 10), 0);
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
    ck_assert_int_eq(wolftftp_build_request(pkt, sizeof(pkt), WOLFTFTP_OP_WRQ,
        "fw.bin", &cfg, 10, &opts, &req_len), 0);
    ck_assert_int_eq(wolftftp_server_receive(&server, WOLFTFTP_PORT, &remote,
        pkt, req_len), 0);
    memcpy(pkt + 4, "toolong", 7);
    len = wolftftp_build_data(pkt, sizeof(pkt), 1, pkt + 4, 7);
    ck_assert_int_eq(wolftftp_server_receive(&server, server.sessions[0].local_port,
        &remote, pkt, (uint16_t)len), WOLFTFTP_ERR_SIZE);
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

static void add_tftp_tests(TCase *tc_proto)
{
    tcase_add_test(tc_proto, test_tftp_helpers_and_builders);
    tcase_add_test(tc_proto, test_tftp_parse_request_error_paths);
    tcase_add_test(tc_proto, test_tftp_client_rrq_oack_and_data_success);
    tcase_add_test(tc_proto, test_tftp_client_fallback_duplicate_and_tid_errors);
    tcase_add_test(tc_proto, test_tftp_client_error_and_failure_paths);
    tcase_add_test(tc_proto, test_tftp_client_poll_and_status_paths);
    tcase_add_test(tc_proto, test_tftp_server_rrq_success_and_poll);
    tcase_add_test(tc_proto, test_tftp_server_wrq_success_and_failures);
    tcase_add_test(tc_proto, test_tftp_server_request_errors_and_timeouts);
}

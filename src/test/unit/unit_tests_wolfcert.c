/* unit_tests_wolfcert.c
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
 * Unit tests for the wolfIP <-> wolfCert transport glue.
 */

/* A stand-in for the caller's stack pointer; the mocks never dereference it. */
static struct wolfIP *wc_test_stack(void)
{
    static int dummy;
    return (struct wolfIP *)&dummy;
}

static void *wc_test_init(WolfCertTransport *t)
{
    return wolfCert_Init_wolfIP(t, wc_test_stack(), test_wc_now_ms);
}

START_TEST(test_wolfcert_io_init_populates_vtable)
{
    WolfCertTransport t;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));

    c = wc_test_init(&t);
    ck_assert_ptr_ne(c, NULL);
    ck_assert_ptr_eq(t.ctx, c);
    ck_assert(t.connect != NULL);
    ck_assert(t.read != NULL);
    ck_assert(t.write != NULL);
    ck_assert(t.disconnect != NULL);
    /* Pure wiring: no socket is opened and the stack is not driven. */
    ck_assert_int_eq(wc_socket_calls, 0);
    ck_assert_int_eq(wc_poll_calls, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_init_rejects_bad_args)
{
    WolfCertTransport t;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));

    ck_assert_ptr_eq(wolfCert_Init_wolfIP(NULL, wc_test_stack(),
                                          test_wc_now_ms), NULL);
    ck_assert_ptr_eq(wolfCert_Init_wolfIP(&t, NULL, test_wc_now_ms), NULL);
    ck_assert_ptr_eq(wolfCert_Init_wolfIP(&t, wc_test_stack(), NULL), NULL);
    wolfCert_Cleanup_wolfIP(NULL);
}
END_TEST

START_TEST(test_wolfcert_io_init_pool_exhaustion)
{
    WolfCertTransport t[MAX_WOLFCERT_CTX + 1];
    void *c[MAX_WOLFCERT_CTX];
    int i;

    reset_wolfcert_io_state();
    memset(t, 0, sizeof(t));

    for (i = 0; i < MAX_WOLFCERT_CTX; i++) {
        c[i] = wc_test_init(&t[i]);
        ck_assert_ptr_ne(c[i], NULL);
    }
    ck_assert_ptr_eq(wc_test_init(&t[MAX_WOLFCERT_CTX]), NULL);

    /* Cleanup returns the slot, so the next init succeeds again. */
    wolfCert_Cleanup_wolfIP(c[0]);
    ck_assert_ptr_ne(wc_test_init(&t[MAX_WOLFCERT_CTX]), NULL);
}
END_TEST

START_TEST(test_wolfcert_io_connect_ip_literal)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    wc_socket_ret = 0x105;
    wc_connect_steps[0] = 0;
    wc_connect_steps_len = 1;

    ck_assert_int_eq(t.connect(t.ctx, "10.0.0.1", 443, 5000, &conn),
                     WOLFCERT_OK);
    ck_assert_int_eq((int)(intptr_t)conn, 0x105);
    /* A dotted quad must not reach the resolver. */
    ck_assert_int_eq(dns_result_ready, 0);
    /* The stack receives the address and port we dialled. */
    ck_assert_uint_eq(wc_connect_last_ip, 0x0A000001);
    ck_assert_uint_eq(wc_connect_last_port, 443);

    /* The handle decodes back to the same descriptor on disconnect. */
    ck_assert_int_eq(t.disconnect(t.ctx, conn), WOLFCERT_OK);
    ck_assert_int_eq(wc_close_last_fd, 0x105);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_connect_waits_until_writable)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    wc_connect_steps[0] = -WOLFIP_EAGAIN;
    wc_connect_steps_len = 1;
    wc_ready_steps[0] = 0;
    wc_ready_steps[1] = 0;
    wc_ready_steps[2] = 1;
    wc_ready_steps_len = 3;

    ck_assert_int_eq(t.connect(t.ctx, "10.0.0.1", 443, 5000, &conn),
                     WOLFCERT_OK);
    /* The stack is driven while waiting, and the SYN is issued only once. */
    ck_assert_int_eq(wc_poll_calls, 2);
    ck_assert_int_eq(wc_connect_calls, 1);
    ck_assert_int_eq(wc_close_calls, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_connect_deadline_closes_socket)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    wc_connect_steps[0] = -WOLFIP_EAGAIN;
    wc_connect_steps_len = 1;
    wc_ready_steps[0] = 0;
    wc_ready_steps_len = 1;
    wc_now_step_ms = 100;

    ck_assert_int_eq(t.connect(t.ctx, "10.0.0.1", 443, 250, &conn),
                     WOLFCERT_ERR_IO);
    /* A failed connect owns its socket: wolfCert will not call disconnect. */
    ck_assert_int_eq(wc_close_calls, 1);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_connect_default_timeout_bounds_spin)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    /* A zero-initialised WolfCertServerCfg leaves timeout_ms at 0. wolfIP has
     * no kernel to abandon an unanswered SYN, so the transport's own default
     * must stop it well before the iteration backstop. */
    wc_connect_steps[0] = -WOLFIP_EAGAIN;
    wc_connect_steps_len = 1;
    wc_ready_steps[0] = 0;
    wc_ready_steps_len = 1;
    wc_now_step_ms = 1000;

    ck_assert_int_eq(t.connect(t.ctx, "10.0.0.1", 443, 0, &conn),
                     WOLFCERT_ERR_IO);
    ck_assert_int_eq(wc_close_calls, 1);
    ck_assert_int_lt(wc_poll_calls,
                     (int)(WOLFCERT_WOLFIP_CONNECT_TIMEOUT_MS / 1000) + 2);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

/* The slot reads as torn down after the first poll: connect must stop without
 * issuing the SYN again, and without closing it. */
START_TEST(test_wolfcert_io_connect_reset_is_not_rearmed)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    wc_connect_steps[0] = -WOLFIP_EAGAIN;
    wc_connect_steps_len = 1;
    wc_ready_steps[0] = 0;
    wc_ready_steps_len = 1;
    wc_peer_flip_at = 1;          /* the slot reads as 0.0.0.0:0 after it */

    ck_assert_int_eq(t.connect(t.ctx, "10.0.0.1", 443, 5000, &conn),
                     WOLFCERT_ERR_CONN_CLOSED);
    ck_assert_int_eq(wc_connect_calls, 1);
    ck_assert_int_eq(wc_close_calls, 0);
    ck_assert_int_lt(wc_poll_calls, 3);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

/* The slot reads as another caller's after the first poll: connect must
 * neither drive it nor close it. */
START_TEST(test_wolfcert_io_connect_reused_slot_is_left_alone)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    wc_connect_steps[0] = -WOLFIP_EAGAIN;
    wc_connect_steps_len = 1;
    wc_ready_steps[0] = 0;
    wc_ready_steps_len = 1;
    wc_peer_flip_at = 1;
    wc_peer_flip_ip = 0x0A000063;
    wc_peer_flip_port = 8080;

    ck_assert_int_eq(t.connect(t.ctx, "10.0.0.1", 443, 5000, &conn),
                     WOLFCERT_ERR_CONN_CLOSED);
    ck_assert_int_eq(wc_connect_calls, 1);
    ck_assert_int_eq(wc_close_calls, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_connect_hard_error_closes_socket)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    wc_connect_steps[0] = -WOLFIP_EINVAL;
    wc_connect_steps_len = 1;

    ck_assert_int_eq(t.connect(t.ctx, "10.0.0.1", 443, 5000, &conn),
                     WOLFCERT_ERR_IO);
    ck_assert_int_eq(wc_close_calls, 1);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_connect_resolves_name)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    ck_assert_int_eq(t.connect(t.ctx, "est.example.com", 443, 5000, &conn),
                     WOLFCERT_OK);
    ck_assert_int_eq(dns_result_ready, 1);
    ck_assert_uint_eq(dns_result_ip, 0x0A000001);
    ck_assert_uint_eq(wc_connect_last_ip, 0x0A000001);
    ck_assert_uint_eq(wc_connect_last_port, 443);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

/* resolve_host's error branches. All of them precede socket creation, so a
 * failure must leave no descriptor behind. */
START_TEST(test_wolfcert_io_connect_dns_busy_then_resolves)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    /* wolfIP answers -16 while another query is in flight; that is a retry,
     * not a failure. */
    wc_nslookup_steps[0] = -16;
    wc_nslookup_steps[1] = -16;
    wc_nslookup_steps[2] = 0;
    wc_nslookup_steps_len = 3;

    ck_assert_int_eq(t.connect(t.ctx, "est.example.com", 443, 5000, &conn),
                     WOLFCERT_OK);
    ck_assert_int_eq(dns_result_ready, 1);
    ck_assert_int_gt(wc_poll_calls, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

/* The one connect exit that returns before a socket exists: it must not
 * close anything. */
START_TEST(test_wolfcert_io_connect_socket_failure)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    wc_socket_ret = -1;

    ck_assert_int_eq(t.connect(t.ctx, "10.0.0.1", 443, 5000, &conn),
                     WOLFCERT_ERR_IO);
    ck_assert_int_eq(wc_socket_calls, 1);
    ck_assert_int_eq(wc_close_calls, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

/* A full UDP tx FIFO makes nslookup() report -WOLFIP_EAGAIN after rolling the
 * query back, so the next attempt can succeed. */
START_TEST(test_wolfcert_io_connect_dns_send_eagain_retries)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    wc_nslookup_steps[0] = -WOLFIP_EAGAIN;
    wc_nslookup_steps[1] = 0;
    wc_nslookup_steps_len = 2;

    ck_assert_int_eq(t.connect(t.ctx, "est.example.com", 443, 5000, &conn),
                     WOLFCERT_OK);
    ck_assert_int_eq(dns_result_ready, 1);
    ck_assert_int_gt(wc_poll_calls, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

/* An abandoned query can answer while we are still waiting to arm our own.
 * That answer belongs to the previous host and must not become this one's
 * address. */
START_TEST(test_wolfcert_io_connect_ignores_stale_dns_answer)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    /* A query is already armed from a previous, timed-out connect. */
    wc_dns_pending = 1;
    wc_dns_cb = dns_result_cb;
    wc_dns_ips[0] = 0x0A0000FE;   /* the stale answer, delivered first */
    wc_dns_ips[1] = 0x0A000001;   /* ours, once we manage to arm it */
    wc_dns_ips_len = 2;

    wc_nslookup_steps[0] = -16;   /* busy until the stale query clears */
    wc_nslookup_steps[1] = 0;
    wc_nslookup_steps_len = 2;

    ck_assert_int_eq(t.connect(t.ctx, "est.example.com", 443, 5000, &conn),
                     WOLFCERT_OK);
    ck_assert_uint_eq(wc_connect_last_ip, 0x0A000001);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

/* A blocking write retries through -WOLFIP_EAGAIN instead of reporting it. */
START_TEST(test_wolfcert_io_write_blocking_pumps)
{
    WolfCertTransport t;
    uint8_t buf[16];
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    memset(buf, 'a', sizeof(buf));
    c = wc_test_init(&t);

    wc_send_steps[0] = -WOLFIP_EAGAIN;
    wc_send_steps[1] = -WOLFIP_EAGAIN;
    wc_send_steps[2] = 6;
    wc_send_steps_len = 3;

    ck_assert_int_eq(t.write(t.ctx, (void *)(intptr_t)0x100, buf, sizeof(buf),
                             -1), 6);
    ck_assert_int_eq(wc_poll_calls, 2);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

/* A blocking write that never completes stops at the default budget. */
START_TEST(test_wolfcert_io_write_blocking_deadline)
{
    WolfCertTransport t;
    uint8_t buf[16];
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    memset(buf, 'a', sizeof(buf));
    c = wc_test_init(&t);

    wc_send_steps[0] = -WOLFIP_EAGAIN;
    wc_send_steps_len = 1;
    wc_now_step_ms = WOLFCERT_WOLFIP_IO_TIMEOUT_MS;

    ck_assert_int_eq(t.write(t.ctx, (void *)(intptr_t)0x100, buf, sizeof(buf),
                             -1), WOLFCERT_ERR_IO);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_connect_dns_busy_hits_deadline)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    wc_nslookup_ret = -16;
    wc_now_step_ms = 100;

    ck_assert_int_eq(t.connect(t.ctx, "est.example.com", 443, 250, &conn),
                     WOLFCERT_ERR_IO);
    ck_assert_int_eq(wc_socket_calls, 0);
    ck_assert_int_eq(wc_close_calls, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_connect_dns_hard_error)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    /* Anything other than the busy code is fatal and must not be retried. */
    wc_nslookup_ret = -22;

    ck_assert_int_eq(t.connect(t.ctx, "est.example.com", 443, 5000, &conn),
                     WOLFCERT_ERR_IO);
    ck_assert_int_eq(wc_poll_calls, 0);
    ck_assert_int_eq(wc_socket_calls, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_connect_dns_answer_is_zero)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    /* An A record of 0.0.0.0 reaches the callback like any other; it must
     * not be dialled. A name that does not exist never answers at all. */
    wc_nslookup_ip = 0;

    ck_assert_int_eq(t.connect(t.ctx, "est.example.com", 443, 5000, &conn),
                     WOLFCERT_ERR_NOT_FOUND);
    ck_assert_int_eq(wc_socket_calls, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_connect_dns_never_answers)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    /* Query accepted, callback never fires: the wait loop owns the deadline. */
    wc_nslookup_answer = 0;
    wc_now_step_ms = 100;

    ck_assert_int_eq(t.connect(t.ctx, "est.example.com", 443, 250, &conn),
                     WOLFCERT_ERR_IO);
    ck_assert_int_eq(dns_result_ready, 0);
    ck_assert_int_eq(wc_socket_calls, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_connect_unusable_ip_literal)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    /* Parses as a literal but yields no usable address; must not fall through
     * to the resolver, and must not open a socket. */
    ck_assert_int_eq(t.connect(t.ctx, "0.0.0.0", 443, 5000, &conn),
                     WOLFCERT_ERR_BAD_ARG);
    ck_assert_int_eq(dns_result_ready, 0);
    ck_assert_int_eq(wc_socket_calls, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_connect_rejects_bad_args)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    ck_assert_int_eq(t.connect(t.ctx, NULL, 443, 5000, &conn),
                     WOLFCERT_ERR_BAD_ARG);
    ck_assert_int_eq(t.connect(t.ctx, "10.0.0.1", 443, 5000, NULL),
                     WOLFCERT_ERR_BAD_ARG);
    ck_assert_int_eq(t.connect(t.ctx, "", 443, 5000, &conn),
                     WOLFCERT_ERR_BAD_ARG);
    ck_assert_int_eq(t.connect(t.ctx, "10.0.0.1", 0, 5000, &conn),
                     WOLFCERT_ERR_BAD_ARG);
    ck_assert_int_eq(t.connect(t.ctx, "10.0.0.1", 65536, 5000, &conn),
                     WOLFCERT_ERR_BAD_ARG);
    ck_assert_int_eq(t.connect(NULL, "10.0.0.1", 443, 5000, &conn),
                     WOLFCERT_ERR_BAD_ARG);
    ck_assert_int_eq(wc_socket_calls, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_read_nonblocking_maps_eagain)
{
    WolfCertTransport t;
    uint8_t buf[16];
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    wc_recv_steps[0] = -WOLFIP_EAGAIN;
    wc_recv_steps_len = 1;

    ck_assert_int_eq(t.read(t.ctx, (void *)(intptr_t)0x100, buf, sizeof(buf), 0),
                     WOLFCERT_ERR_WANT_READ);
    /* A non-blocking caller pumps the stack itself; the glue must not. */
    ck_assert_int_eq(wc_poll_calls, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_read_blocking_pumps_instead_of_want_read)
{
    WolfCertTransport t;
    uint8_t buf[16];
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    wc_recv_steps[0] = -WOLFIP_EAGAIN;
    wc_recv_steps[1] = -WOLFIP_EAGAIN;
    wc_recv_steps[2] = 4;
    wc_recv_steps_len = 3;

    /* wolfCert's blocking path turns any non-positive return into a generic
     * IO error, so WANT_READ here would break plain-HTTP SCEP. */
    ck_assert_int_eq(t.read(t.ctx, (void *)(intptr_t)0x100, buf, sizeof(buf),
                            -1), 4);
    ck_assert_int_eq(wc_poll_calls, 2);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_read_maps_close_and_reset)
{
    WolfCertTransport t;
    uint8_t buf[16];
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    /* An orderly close is a 0 from wolfIP; it must never reach wolfCert. */
    wc_recv_steps[0] = 0;
    wc_recv_steps_len = 1;
    ck_assert_int_eq(t.read(t.ctx, (void *)(intptr_t)0x100, buf, sizeof(buf),
                            -1), WOLFCERT_ERR_CONN_CLOSED);

    /* A bare -1 means the socket left ESTABLISHED/CLOSE_WAIT. Retrying it as
     * would-block would spin the caller and starve wolfIP_poll(). */
    wc_recv_step = 0;
    wc_recv_steps[0] = -1;
    ck_assert_int_eq(t.read(t.ctx, (void *)(intptr_t)0x100, buf, sizeof(buf),
                            -1), WOLFCERT_ERR_CONN_CLOSED);

    /* A rejected argument is neither a close nor would-block. */
    wc_recv_step = 0;
    wc_recv_steps[0] = -WOLFIP_EINVAL;
    ck_assert_int_eq(t.read(t.ctx, (void *)(intptr_t)0x100, buf, sizeof(buf),
                            -1), WOLFCERT_ERR_BAD_ARG);

    /* A length past INT_MAX is clamped before it reaches the stack, whose
     * transfer count is an int. */
    wc_recv_step = 0;
    wc_recv_steps[0] = 4;
    ck_assert_int_eq(t.read(t.ctx, (void *)(intptr_t)0x100, buf,
                            (size_t)INT_MAX + 1, -1), 4);
    ck_assert_uint_eq((unsigned long long)wc_recv_last_len,
                      (unsigned long long)INT_MAX);


    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_read_blocking_deadline)
{
    WolfCertTransport t;
    uint8_t buf[16];
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    wc_recv_steps[0] = -WOLFIP_EAGAIN;
    wc_recv_steps_len = 1;
    wc_now_step_ms = WOLFCERT_WOLFIP_IO_TIMEOUT_MS;

    ck_assert_int_eq(t.read(t.ctx, (void *)(intptr_t)0x100, buf, sizeof(buf),
                            -1), WOLFCERT_ERR_IO);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_write_short_write_and_eagain)
{
    WolfCertTransport t;
    uint8_t buf[16];
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    memset(buf, 'a', sizeof(buf));
    c = wc_test_init(&t);

    /* A short write is returned verbatim; wolfCert loops on the remainder. */
    wc_send_steps[0] = 6;
    wc_send_steps_len = 1;
    ck_assert_int_eq(t.write(t.ctx, (void *)(intptr_t)0x100, buf, sizeof(buf),
                             -1), 6);

    wc_send_step = 0;
    wc_send_steps[0] = -WOLFIP_EAGAIN;
    ck_assert_int_eq(t.write(t.ctx, (void *)(intptr_t)0x100, buf, sizeof(buf),
                             0), WOLFCERT_ERR_WANT_WRITE);

    wc_send_step = 0;
    wc_send_steps[0] = -WOLFIP_EINVAL;
    ck_assert_int_eq(t.write(t.ctx, (void *)(intptr_t)0x100, buf, sizeof(buf),
                             -1), WOLFCERT_ERR_BAD_ARG);

    wc_send_step = 0;
    wc_send_steps[0] = -1;
    ck_assert_int_eq(t.write(t.ctx, (void *)(intptr_t)0x100, buf, sizeof(buf),
                             -1), WOLFCERT_ERR_CONN_CLOSED);


    /* A length past INT_MAX is clamped before it reaches the stack. */
    wc_send_step = 0;
    wc_send_steps[0] = 4;
    ck_assert_int_eq(t.write(t.ctx, (void *)(intptr_t)0x100, buf,
                             (size_t)INT_MAX + 1, -1), 4);
    ck_assert_uint_eq((unsigned long long)wc_send_last_len,
                      (unsigned long long)INT_MAX);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_rw_reject_bad_args)
{
    WolfCertTransport t;
    uint8_t buf[16];
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    ck_assert_int_eq(t.read(t.ctx, (void *)(intptr_t)0x100, NULL, sizeof(buf),
                            0), WOLFCERT_ERR_BAD_ARG);
    ck_assert_int_eq(t.read(t.ctx, (void *)(intptr_t)0x100, buf, 0, 0),
                     WOLFCERT_ERR_BAD_ARG);
    ck_assert_int_eq(t.read(NULL, (void *)(intptr_t)0x100, buf, sizeof(buf), 0),
                     WOLFCERT_ERR_BAD_ARG);
    ck_assert_int_eq(t.write(t.ctx, (void *)(intptr_t)0x100, NULL, sizeof(buf),
                             0), WOLFCERT_ERR_BAD_ARG);
    ck_assert_int_eq(t.write(t.ctx, (void *)(intptr_t)0x100, buf, 0, 0),
                     WOLFCERT_ERR_BAD_ARG);
    ck_assert_int_eq(t.write(NULL, (void *)(intptr_t)0x100, buf, sizeof(buf),
                             0), WOLFCERT_ERR_BAD_ARG);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

/* An out-of-range octet is not a literal: it must reach the resolver rather
 * than reaching atoip4(), which does not validate and yields a wrong address. */
START_TEST(test_wolfcert_io_connect_rejects_out_of_range_octets)
{
    WolfCertTransport t;
    void *conn = NULL;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    ck_assert_int_eq(t.connect(t.ctx, "300.1.1.1", 443, 5000, &conn),
                     WOLFCERT_OK);
    ck_assert_int_eq(dns_result_ready, 1);

    dns_result_ready = 0;
    ck_assert_int_eq(t.connect(t.ctx, "1.2.3.256", 443, 5000, &conn),
                     WOLFCERT_OK);
    ck_assert_int_eq(dns_result_ready, 1);

    dns_result_ready = 0;
    ck_assert_int_eq(t.connect(t.ctx, "1.2.3", 443, 5000, &conn),
                     WOLFCERT_OK);
    ck_assert_int_eq(dns_result_ready, 1);

    dns_result_ready = 0;
    ck_assert_int_eq(t.connect(t.ctx, "1..2.3", 443, 5000, &conn),
                     WOLFCERT_OK);
    ck_assert_int_eq(dns_result_ready, 1);

    /* Four digits, but a value the octet bound would accept. */
    dns_result_ready = 0;
    ck_assert_int_eq(t.connect(t.ctx, "0001.1.1.1", 443, 5000, &conn),
                     WOLFCERT_OK);
    ck_assert_int_eq(dns_result_ready, 1);

    /* A valid literal still bypasses the resolver. */
    dns_result_ready = 0;
    ck_assert_int_eq(t.connect(t.ctx, "10.0.0.1", 443, 5000, &conn),
                     WOLFCERT_OK);
    ck_assert_int_eq(dns_result_ready, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

START_TEST(test_wolfcert_io_disconnect_closes_once)
{
    WolfCertTransport t;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    ck_assert_int_eq(t.disconnect(t.ctx, (void *)(intptr_t)0x100),
                     WOLFCERT_OK);
    ck_assert_int_eq(wc_close_calls, 1);
    ck_assert_int_eq(wc_poll_calls, 0);

    ck_assert_int_eq(t.disconnect(NULL, (void *)(intptr_t)0x100),
                     WOLFCERT_ERR_BAD_ARG);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST

/* Closing an established socket runs a FIN handshake, so close reports
 * -WOLFIP_EAGAIN. Nothing calls disconnect twice. */
START_TEST(test_wolfcert_io_disconnect_leaves_fin_to_stack)
{
    WolfCertTransport t;
    void *c;

    reset_wolfcert_io_state();
    memset(&t, 0, sizeof(t));
    c = wc_test_init(&t);

    wc_close_ret = -WOLFIP_EAGAIN;

    ck_assert_int_eq(t.disconnect(t.ctx, (void *)(intptr_t)0x100),
                     WOLFCERT_OK);
    ck_assert_int_eq(wc_close_calls, 1);
    ck_assert_int_eq(wc_poll_calls, 0);

    wolfCert_Cleanup_wolfIP(c);
}
END_TEST


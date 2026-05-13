/* unit_tests_dns_edges.c
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
/* ------------------------------------------------------------------ *
 * Helper: build a minimal valid DNS A-response header + question into
 * buf[], return the offset of the first answer NAME field so callers
 * can splice their own answer sections.
 * ------------------------------------------------------------------ */
static int build_dns_a_response_header(uint8_t *buf, size_t buf_sz,
                                       uint16_t id, uint16_t flags,
                                       uint16_t qdcount, uint16_t ancount,
                                       int *q_end_out)
{
    struct dns_header *hdr = (struct dns_header *)buf;
    struct dns_question *q;
    int pos;

    (void)buf_sz;
    memset(buf, 0, buf_sz);
    hdr->id      = ee16(id);
    hdr->flags   = ee16(flags);
    hdr->qdcount = ee16(qdcount);
    hdr->ancount = ee16(ancount);
    pos = (int)sizeof(struct dns_header);

    /* question: "example.com" */
    buf[pos++] = 7; memcpy(&buf[pos], "example", 7); pos += 7;
    buf[pos++] = 3; memcpy(&buf[pos], "com", 3);     pos += 3;
    buf[pos++] = 0;
    q = (struct dns_question *)(buf + pos);
    q->qtype  = ee16(DNS_A);
    q->qclass = ee16(DNS_CLASS_IN);
    pos += (int)sizeof(struct dns_question);

    if (q_end_out)
        *q_end_out = pos;
    return pos;
}

/* ------------------------------------------------------------------ *
 * dns_callback: recvfrom returns < 0 (empty socket → EAGAIN)
 * Exercises lines 8954-8957: close-socket + abort_query path.
 * ------------------------------------------------------------------ */
START_TEST(test_dns_callback_recvfrom_error_closes_socket)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_id     = 0x1234;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_lookup_cb  = test_dns_lookup_cb;

    /* Open a real UDP socket but put NO data in it so recvfrom → -EAGAIN */
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);

    /* Socket must have been closed and state cleared */
    ck_assert_int_eq(s.dns_udp_sd, -1);
    ck_assert_uint_eq(s.dns_id, 0);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_callback: RCODE != 0 (NXDOMAIN) → abort query
 * Exercises the DNS_RCODE_MASK branch inside the response path.
 * ------------------------------------------------------------------ */
START_TEST(test_dns_callback_rcode_nonzero_aborts_query)
{
    struct wolfIP s;
    uint8_t response[64];
    struct dns_header *hdr = (struct dns_header *)response;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_id     = 0x5678;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_lookup_cb  = test_dns_lookup_cb;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    memset(response, 0, sizeof(response));
    hdr->id      = ee16(s.dns_id);
    /* QR=1, RD=1, RCODE=3 (NXDOMAIN) */
    hdr->flags   = ee16(0x8103);
    hdr->qdcount = ee16(0);
    hdr->ancount = ee16(0);

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)],
                   response, sizeof(response), DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);

    ck_assert_uint_eq(s.dns_id, 0);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_callback: ancount == 0 → no callback, query left pending
 * ------------------------------------------------------------------ */
START_TEST(test_dns_callback_zero_ancount_no_delivery)
{
    struct wolfIP s;
    uint8_t response[64];
    int pos;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_id     = 0xABCD;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    dns_lookup_calls = 0;
    dns_lookup_ip    = 0;
    s.dns_lookup_cb  = test_dns_lookup_cb;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    pos = build_dns_a_response_header(response, sizeof(response),
                                      s.dns_id, 0x8100, 1, 0, NULL);

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)],
                   response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);

    /* No answer → callback never called, id still set */
    ck_assert_int_eq(dns_lookup_calls, 0);
    ck_assert_uint_eq(s.dns_id, 0xABCD);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_callback: answer rr->type == AAAA (28) while query_type == A
 * → neither branch fires, answer skipped, query stays pending.
 * ------------------------------------------------------------------ */
START_TEST(test_dns_callback_aaaa_answer_skipped_for_a_query)
{
    struct wolfIP s;
    uint8_t response[128];
    int pos;
    struct dns_rr *rr;
    uint8_t aaaa_rdata[16] = {0};

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_id     = 0x1111;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    dns_lookup_calls = 0;
    dns_lookup_ip    = 0;
    s.dns_lookup_cb  = test_dns_lookup_cb;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    pos = build_dns_a_response_header(response, sizeof(response),
                                      s.dns_id, 0x8100, 1, 1, NULL);
    /* Answer NAME: compressed pointer to question name at offset 12 */
    response[pos++] = 0xC0;
    response[pos++] = (uint8_t)sizeof(struct dns_header);
    rr = (struct dns_rr *)(response + pos);
    rr->type     = ee16(28);              /* AAAA */
    rr->class    = ee16(DNS_CLASS_IN);
    rr->ttl      = ee32(60);
    rr->rdlength = ee16((uint16_t)sizeof(aaaa_rdata));
    pos += (int)sizeof(struct dns_rr);
    memcpy(&response[pos], aaaa_rdata, sizeof(aaaa_rdata));
    pos += (int)sizeof(aaaa_rdata);

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)],
                   response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);

    ck_assert_int_eq(dns_lookup_calls, 0);
    ck_assert_uint_eq(s.dns_id, 0x1111);          /* still pending */
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_callback: answer rdlen advertised larger than remaining buffer
 * → abort query (line 8997-8999)
 * ------------------------------------------------------------------ */
START_TEST(test_dns_callback_rr_rdlen_truncated_aborts_query)
{
    struct wolfIP s;
    uint8_t response[80];
    int pos;
    struct dns_rr *rr;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_id     = 0x2222;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    dns_lookup_calls = 0;
    dns_lookup_ip    = 0;
    s.dns_lookup_cb  = test_dns_lookup_cb;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    pos = build_dns_a_response_header(response, sizeof(response),
                                      s.dns_id, 0x8100, 1, 1, NULL);
    response[pos++] = 0xC0;
    response[pos++] = (uint8_t)sizeof(struct dns_header);
    rr = (struct dns_rr *)(response + pos);
    rr->type     = ee16(DNS_A);
    rr->class    = ee16(DNS_CLASS_IN);
    rr->ttl      = ee32(60);
    /* rdlength says 100 bytes but we stop writing after 2 bytes of rdata */
    rr->rdlength = ee16(100);
    pos += (int)sizeof(struct dns_rr);
    response[pos++] = 0x0A;
    response[pos++] = 0x00;          /* only 2 bytes of rdata */

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)],
                   response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);

    ck_assert_int_eq(dns_lookup_calls, 0);
    ck_assert_uint_eq(s.dns_id, 0);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_callback: question section name is malformed (label goes past
 * end-of-packet) → dns_skip_name returns < 0 → abort query
 * ------------------------------------------------------------------ */
START_TEST(test_dns_callback_bad_question_name_aborts_query)
{
    struct wolfIP s;
    uint8_t response[32];
    struct dns_header *hdr = (struct dns_header *)response;
    int pos;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_id     = 0x3333;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_lookup_cb  = test_dns_lookup_cb;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    memset(response, 0, sizeof(response));
    hdr->id      = ee16(s.dns_id);
    hdr->flags   = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(1);
    pos = (int)sizeof(struct dns_header);
    /* Label length 20 but only 2 bytes of data before EOF */
    response[pos++] = 20;
    response[pos++] = 'a';
    response[pos++] = 'b';

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)],
                   response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);

    ck_assert_uint_eq(s.dns_id, 0);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_callback: answer NAME compressed ptr points forward (invalid)
 * → dns_skip_name returns -1 in answer section → abort query
 * ------------------------------------------------------------------ */
START_TEST(test_dns_callback_answer_forward_ptr_aborts_query)
{
    struct wolfIP s;
    uint8_t response[80];
    int pos;
    struct dns_question *q;
    struct dns_header *hdr = (struct dns_header *)response;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_id     = 0x4444;
    s.dns_query_type = DNS_QUERY_TYPE_A;
    s.dns_lookup_cb  = test_dns_lookup_cb;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    memset(response, 0, sizeof(response));
    hdr->id      = ee16(s.dns_id);
    hdr->flags   = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(1);
    pos = (int)sizeof(struct dns_header);
    response[pos++] = 1; response[pos++] = 'a'; response[pos++] = 0;
    q = (struct dns_question *)(response + pos);
    q->qtype  = ee16(DNS_A);
    q->qclass = ee16(DNS_CLASS_IN);
    pos += (int)sizeof(struct dns_question);

    /* Answer NAME: compression pointer pointing FORWARD (invalid) */
    response[pos] = 0xC0;
    response[pos + 1] = (uint8_t)(pos + 4);  /* forward reference */
    pos += 2;

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)],
                   response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);

    ck_assert_uint_eq(s.dns_id, 0);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_cancel_timer: NULL stack pointer is a no-op (line 8856)
 * ------------------------------------------------------------------ */
START_TEST(test_dns_cancel_timer_null_noop)
{
    dns_cancel_timer(NULL);   /* must not crash */
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_schedule_timer: NULL stack pointer is a no-op (line 8870)
 * ------------------------------------------------------------------ */
START_TEST(test_dns_schedule_timer_null_noop)
{
    dns_schedule_timer(NULL); /* must not crash */
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_timeout_cb: NULL arg is a no-op (line 8922)
 * ------------------------------------------------------------------ */
START_TEST(test_dns_timeout_cb_null_noop)
{
    dns_timeout_cb(NULL);     /* must not crash */
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_timeout_cb: dns_id == 0 → early return (line 8925)
 * ------------------------------------------------------------------ */
START_TEST(test_dns_timeout_cb_zero_id_noop)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_id = 0;  /* no outstanding query */
    s.dns_timer = NO_TIMER;

    dns_timeout_cb(&s);   /* must be silent: dns_id == 0 */
    ck_assert_uint_eq(s.dns_id, 0);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_timeout_cb: resend fails → abort (lines 8927-8929)
 * Trigger by setting dns_udp_sd = -1 so dns_resend_query() returns < 0.
 * ------------------------------------------------------------------ */
START_TEST(test_dns_timeout_cb_resend_failure_aborts_query)
{
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server   = 0x0A000001U;
    s.dns_id       = 0x9999;
    s.dns_timer    = NO_TIMER;
    s.dns_retry_count = 0;  /* still within retry budget */
    s.dns_query_type  = DNS_QUERY_TYPE_A;
    s.dns_lookup_cb   = test_dns_lookup_cb;
    /* Invalidate socket so resend fails */
    s.dns_udp_sd      = -1;

    dns_timeout_cb(&s);

    /* After failed resend the query must be aborted */
    ck_assert_uint_eq(s.dns_id, 0);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_NONE);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_copy_name: label does not fit in caller buffer.
 * Build: "ab" → label = [2,'a','b',0]. With out_len == 2 the
 * label-bound guard (o + c >= out_len) fires before the terminator
 * write — this exercises the label-copy capacity path, NOT the
 * terminator guard (see test_dns_copy_name_zero_out_len_... below).
 * ------------------------------------------------------------------ */
START_TEST(test_dns_copy_name_label_too_big_for_output)
{
    /* buf: [2,'a','b',0] */
    const uint8_t buf[4] = { 2, 'a', 'b', 0 };
    char out[2];   /* exactly "ab" with no room for NUL */
    int ret;

    /* out_len == 2: 0 + 2 >= 2 → label-bound guard fires → -1 */
    ret = dns_copy_name(buf, (int)sizeof(buf), 0, out, sizeof(out));
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_copy_name: terminator-write guard when out_len == 0.
 * Build: bare terminator [0] with out_len == 0. The label-copy guards
 * are not reached for an empty name, so this uniquely exercises the
 * 'o >= out_len' check at the NAME_TERMINATOR write site.
 * ------------------------------------------------------------------ */
START_TEST(test_dns_copy_name_zero_out_len_rejects_terminator_write)
{
    const uint8_t buf[1] = { 0 };
    char out[1]; /* not written; placeholder */
    int ret;

    ret = dns_copy_name(buf, (int)sizeof(buf), 0, out, 0);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_copy_name: compression pointer at the very last byte of buffer
 * (line 8823: pos + 1 >= len)
 * buf ends with 0xC0 at pos = len-1, no room for the second byte.
 * ------------------------------------------------------------------ */
START_TEST(test_dns_copy_name_ptr_at_end_of_buffer)
{
    /* Simple name "a." followed by a truncated 0xC0 ptr */
    const uint8_t buf[4] = { 1, 'a', 0xC0 /* no second byte */ };
    char out[32];
    int ret;

    ret = dns_copy_name(buf, 3, 2, out, sizeof(out));
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_copy_name: label extends past end of buffer (line 8836)
 * ------------------------------------------------------------------ */
START_TEST(test_dns_copy_name_label_past_end)
{
    /* Label length 10 but only 3 bytes follow before EOF */
    const uint8_t buf[5] = { 10, 'a', 'b', 'c', 'd' };
    char out[32];
    int ret;

    ret = dns_copy_name(buf, (int)sizeof(buf), 0, out, sizeof(out));
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_copy_name: separator write would overflow output buffer
 * (line 8839: o + 1 >= out_len when o != 0)
 * "ab.cd" needs out_len >= 6; give it 4 so separator fits but not "cd".
 * With out_len == 4: after "ab" o == 2; separator needs o+1 < 4 (ok,
 * so go further)... actually need out_len == 3 so o+1 == 3 >= 3.
 * ------------------------------------------------------------------ */
START_TEST(test_dns_copy_name_separator_overflow)
{
    /* "ab.cd" encoded as [2,'a','b',2,'c','d',0] */
    const uint8_t buf[8] = { 2, 'a', 'b', 2, 'c', 'd', 0 };
    /* out_len == 3: after copying "ab", o == 2; writing '.' needs o < 2
     * i.e. o + 1 = 3 >= out_len(3) → -1 */
    char out[3];
    int ret;

    ret = dns_copy_name(buf, (int)sizeof(buf), 0, out, sizeof(out));
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_copy_name: label itself would overflow output buffer (line 8843)
 * "abc" with out_len == 3: o + c == 3 >= 3 → -1.
 * ------------------------------------------------------------------ */
START_TEST(test_dns_copy_name_label_overflow_output)
{
    /* "abc" encoded as [3,'a','b','c',0] */
    const uint8_t buf[5] = { 3, 'a', 'b', 'c', 0 };
    /* out_len == 3: o + c == 3 >= 3 → overflow */
    char out[3];
    int ret;

    ret = dns_copy_name(buf, (int)sizeof(buf), 0, out, sizeof(out));
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_skip_name: pos overshoots len (label length field causes
 * pos > len → line 8795-8796 taken).
 * ------------------------------------------------------------------ */
START_TEST(test_dns_skip_name_label_past_end)
{
    /* [5, 'a', 'b'] — label says 5 bytes but only 2 follow */
    const uint8_t buf[3] = { 5, 'a', 'b' };
    int ret;

    ret = dns_skip_name(buf, (int)sizeof(buf), 0);
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_copy_name: compression pointer followed by second label that
 * overflows the output (separator + label together exceed out_len).
 * Covers the o + 1 >= out_len guard (line 8838-8839) where o != 0.
 * ------------------------------------------------------------------ */
START_TEST(test_dns_copy_name_second_label_separator_and_label_fit)
{
    /* "ab.cd" → [2,'a','b',2,'c','d',0] — verify success with
     * enough buffer and failure when truncated by exactly 1. */
    const uint8_t buf[8] = { 2, 'a', 'b', 2, 'c', 'd', 0 };
    char out_ok[7];   /* "ab.cd\0" = 6 chars + NUL → exactly fits */
    char out_small[5]; /* room for "ab." + 1, not enough for "cd\0" */
    int ret;

    /* Should succeed with enough room */
    ret = dns_copy_name(buf, (int)sizeof(buf), 0, out_ok, sizeof(out_ok));
    ck_assert_int_eq(ret, 0);
    ck_assert_str_eq(out_ok, "ab.cd");

    /* Should fail: out_len == 5, after "ab" o=2, need o+1 < 5 (ok),
     * then o+c = 2+1+2 = 5 >= 5 → overflow at label copy */
    ret = dns_copy_name(buf, (int)sizeof(buf), 0, out_small, sizeof(out_small));
    ck_assert_int_eq(ret, -1);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_callback: PTR response where dns_copy_name fails (bad rdata)
 * → the failure branch of dns_copy_name inside the PTR arm is taken,
 *   pos advances by rdlen, and the query stays pending.
 * ------------------------------------------------------------------ */
START_TEST(test_dns_callback_ptr_bad_copy_name_stays_pending)
{
    struct wolfIP s;
    uint8_t response[128];
    struct dns_header *hdr = (struct dns_header *)response;
    struct dns_question *q;
    struct dns_rr *rr;
    int pos;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dns_server = 0x0A000001U;
    s.dns_id     = 0xBBBB;
    s.dns_query_type = DNS_QUERY_TYPE_PTR;
    s.dns_ptr_cb     = test_dns_ptr_cb;
    s.dns_lookup_cb  = NULL;
    s.dns_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dns_udp_sd, 0);

    memset(response, 0, sizeof(response));
    hdr->id      = ee16(s.dns_id);
    hdr->flags   = ee16(0x8100);
    hdr->qdcount = ee16(1);
    hdr->ancount = ee16(1);
    pos = (int)sizeof(struct dns_header);
    response[pos++] = 1; response[pos++] = 'a'; response[pos++] = 0;
    q = (struct dns_question *)(response + pos);
    q->qtype  = ee16(DNS_PTR);
    q->qclass = ee16(DNS_CLASS_IN);
    pos += (int)sizeof(struct dns_question);

    /* Answer NAME: simple label */
    response[pos++] = 0xC0;
    response[pos++] = (uint8_t)sizeof(struct dns_header);

    /* RR header */
    rr = (struct dns_rr *)(response + pos);
    rr->type     = ee16(DNS_PTR);
    rr->class    = ee16(DNS_CLASS_IN);
    rr->ttl      = ee32(60);
    /* RDATA claims 4 bytes but contains a label [10,'a','b',0] that
     * overruns pos+c > len: the rdlength says 4 so only 4 bytes follow,
     * but the label length is 10 → dns_copy_name returns -1 */
    rr->rdlength = ee16(4);
    pos += (int)sizeof(struct dns_rr);
    response[pos++] = 10;    /* label length exceeds remaining rdata */
    response[pos++] = 'a';
    response[pos++] = 'b';
    response[pos++] = 0;

    enqueue_udp_rx(&s.udpsockets[SOCKET_UNMARK(s.dns_udp_sd)],
                   response, (uint16_t)pos, DNS_PORT);
    dns_callback(s.dns_udp_sd, CB_EVENT_READABLE, &s);

    /* copy failed → ptr_cb never called → query still pending */
    ck_assert_uint_eq(s.dns_id, 0xBBBB);
    ck_assert_int_eq(s.dns_query_type, DNS_QUERY_TYPE_PTR);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_copy_name: jumped == 1, so pos is NOT incremented after reading
 * the NUL terminator (line 8813-8814 true branch).
 * Use a valid compression pointer followed by the NUL terminator.
 * ------------------------------------------------------------------ */
START_TEST(test_dns_copy_name_jumped_no_pos_increment)
{
    /* buf layout:
     *  [0] = 0     ← NUL (empty name at offset 0)
     *  [1] = 0xC0
     *  [2] = 0x00  ← ptr to offset 0
     */
    const uint8_t buf[3] = { 0, 0xC0, 0x00 };
    char out[32];
    int ret;

    /* Start at the compression pointer (offset 1).
     * The pointer lands at offset 0 which is '\0', so jumped == 1 and
     * the NUL-terminator branch sets out[0]='\0' without touching pos. */
    ret = dns_copy_name(buf, (int)sizeof(buf), 1, out, sizeof(out));
    ck_assert_int_eq(ret, 0);
    ck_assert_uint_eq((uint8_t)out[0], 0);
}
END_TEST

/* ------------------------------------------------------------------ *
 * dns_send_query: socket allocation failure returns -1 (line 9050)
 * Exhaust all UDP sockets before calling dns_send_query so that
 * wolfIP_sock_socket returns < 0 inside it.
 * ------------------------------------------------------------------ */
START_TEST(test_dns_send_query_socket_alloc_failure)
{
    struct wolfIP s;
    uint16_t id;
    int i, sd;

    wolfIP_init(&s);
    mock_link_init(&s);
    wolfIP_ipconfig_set(&s, 0x0A000001U, 0xFFFFFF00U, 0x0A000001U);
    s.dns_server  = 0x08080808U;
    s.dns_id      = 0;            /* no outstanding query */
    s.dns_udp_sd  = -1;           /* force socket allocation path */

    /* Open all available UDP sockets to exhaust the pool */
    for (i = 0; i < MAX_UDPSOCKETS; i++) {
        sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
        /* Stop early if we run out (pool may be smaller than MAX_UDPSOCKETS) */
        if (sd < 0)
            break;
    }

    /* Now socket allocation inside dns_send_query must fail → -1 */
    ck_assert_int_eq(dns_send_query(&s, "example.com", &id, DNS_A), -1);
    /* Query state must not have been set */
    ck_assert_uint_eq(s.dns_id, 0);
}
END_TEST

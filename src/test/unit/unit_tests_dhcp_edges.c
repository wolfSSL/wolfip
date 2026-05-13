/* unit_tests_dhcp_edges.c
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
/* Helper: build a minimal valid ACK with required fields and place it in msg.
 * Sets xid from s->dhcp_xid.  Caller may append/override options before use.
 */
static void build_dhcp_msg_base(struct wolfIP *s, struct dhcp_msg *msg,
                                uint8_t msg_type)
{
    struct dhcp_option *opt;
    memset(msg, 0, sizeof(*msg));
    msg->op = BOOT_REPLY;
    msg->magic = ee32(DHCP_MAGIC);
    msg->xid = ee32(s->dhcp_xid);
    opt = (struct dhcp_option *)msg->options;
    opt->code = DHCP_OPTION_MSG_TYPE;
    opt->len = 1;
    opt->data[0] = msg_type;
}

/* Append a 4-byte TLV option at *ptr and advance it. */
static void append_opt4(uint8_t **ptr, uint8_t code, uint32_t val)
{
    struct dhcp_option *o = (struct dhcp_option *)*ptr;
    o->code = code;
    o->len = 4;
    o->data[0] = (val >> 24) & 0xFF;
    o->data[1] = (val >> 16) & 0xFF;
    o->data[2] = (val >>  8) & 0xFF;
    o->data[3] = (val >>  0) & 0xFF;
    *ptr += 6;
}

static void append_end(uint8_t **ptr)
{
    (*ptr)[0] = DHCP_OPTION_END;
    (*ptr)++;
}

/* Build a complete, valid ACK in msg with all required options. */
static void build_full_ack(struct wolfIP *s, struct dhcp_msg *msg,
                           uint32_t server_ip, uint32_t client_ip,
                           uint32_t mask, uint32_t router, uint32_t dns,
                           uint32_t lease_s)
{
    uint8_t *p;
    build_dhcp_msg_base(s, msg, DHCP_ACK);
    p = (uint8_t *)msg->options + 3; /* after MSG_TYPE TLV */
    append_opt4(&p, DHCP_OPTION_SERVER_ID, server_ip);
    append_opt4(&p, DHCP_OPTION_SUBNET_MASK, mask);
    append_opt4(&p, DHCP_OPTION_ROUTER, router);
    append_opt4(&p, DHCP_OPTION_DNS, dns);
    append_opt4(&p, DHCP_OPTION_LEASE_TIME, lease_s);
    if (client_ip)
        append_opt4(&p, DHCP_OPTION_OFFER_IP, client_ip);
    append_end(&p);
}

/* -------------------------------------------------------------------------
 * dhcp_schedule_lease_timer — uncovered branches
 * ---------------------------------------------------------------------- */

START_TEST(test_dhcp_schedule_lease_timer_zero_lease_noop)
{
    struct wolfIP s;

    wolfIP_init(&s);
    s.last_tick = 1000U;
    s.dhcp_timer = NO_TIMER;

    /* lease_s == 0 → early return; no timer should be scheduled */
    dhcp_schedule_lease_timer(&s, 0U, 0U, 0U);

    ck_assert_int_eq(s.dhcp_timer, NO_TIMER);
}
END_TEST

START_TEST(test_dhcp_schedule_lease_timer_null_noop)
{
    /* NULL pointer → early return, no crash */
    dhcp_schedule_lease_timer(NULL, 120U, 0U, 0U);
}
END_TEST

START_TEST(test_dhcp_schedule_lease_timer_renew_gt_lease_clamped)
{
    struct wolfIP s;

    wolfIP_init(&s);
    s.last_tick = 0U;

    /* renew_s > lease_s → clamp renew to lease/2 */
    dhcp_schedule_lease_timer(&s, 100U, 200U, 0U);

    /* renew_s should be 50 (100/2), rebind_s = 87 (100*7/8) */
    ck_assert_uint_eq(s.dhcp_renew_at,  50000U);
    ck_assert_uint_eq(s.dhcp_rebind_at, 87000U);
    ck_assert_uint_eq(s.dhcp_lease_expires, 100000U);
}
END_TEST

START_TEST(test_dhcp_schedule_lease_timer_rebind_lt_renew_fixed)
{
    struct wolfIP s;

    wolfIP_init(&s);
    s.last_tick = 0U;

    /* rebind_s < renew_s → set rebind = renew */
    dhcp_schedule_lease_timer(&s, 100U, 80U, 20U);

    /* rebind_s (20) < renew_s (80), so rebind becomes 80 */
    ck_assert_uint_eq(s.dhcp_renew_at,  80000U);
    ck_assert_uint_eq(s.dhcp_rebind_at, 80000U);
}
END_TEST

START_TEST(test_dhcp_schedule_lease_timer_rebind_gt_lease_clamped)
{
    struct wolfIP s;

    wolfIP_init(&s);
    s.last_tick = 0U;

    /* Provide explicit rebind > lease; per code the rebind branch resets it
     * to (lease*7)/8 = 87, then 87 > renew_s(50) OK, 87 <= lease_s(100) OK */
    dhcp_schedule_lease_timer(&s, 100U, 50U, 150U);

    /* rebind_s (150) > lease_s (100): reset to (100*7)/8 = 87 */
    ck_assert_uint_eq(s.dhcp_rebind_at, 87000U);
    ck_assert_uint_eq(s.dhcp_lease_expires, 100000U);
}
END_TEST

START_TEST(test_dhcp_schedule_lease_timer_explicit_t1_t2)
{
    struct wolfIP s;

    wolfIP_init(&s);
    s.last_tick = 2000U;

    /* All three values supplied and valid */
    dhcp_schedule_lease_timer(&s, 3600U, 1800U, 3150U);

    ck_assert_uint_eq(s.dhcp_renew_at,  2000U + 1800U * 1000U);
    ck_assert_uint_eq(s.dhcp_rebind_at, 2000U + 3150U * 1000U);
    ck_assert_uint_eq(s.dhcp_lease_expires, 2000U + 3600U * 1000U);
    ck_assert_int_ne(s.dhcp_timer, NO_TIMER);
}
END_TEST

/* -------------------------------------------------------------------------
 * dhcp_msg_type — return each message type and validate
 * ---------------------------------------------------------------------- */

START_TEST(test_dhcp_msg_type_returns_offer)
{
    struct wolfIP s;
    struct dhcp_msg msg;

    wolfIP_init(&s);
    s.dhcp_xid = 0xDEADBEEFU;

    build_dhcp_msg_base(&s, &msg, DHCP_OFFER);
    /* no further options needed for msg_type */
    ((uint8_t *)msg.options)[3] = DHCP_OPTION_END;

    ck_assert_int_eq(dhcp_msg_type(&s, &msg, sizeof(msg)), DHCP_OFFER);
}
END_TEST

START_TEST(test_dhcp_msg_type_returns_nak)
{
    struct wolfIP s;
    struct dhcp_msg msg;

    wolfIP_init(&s);
    s.dhcp_xid = 0xDEADBEEFU;

    build_dhcp_msg_base(&s, &msg, DHCP_NAK);
    ((uint8_t *)msg.options)[3] = DHCP_OPTION_END;

    ck_assert_int_eq(dhcp_msg_type(&s, &msg, sizeof(msg)), DHCP_NAK);
}
END_TEST

START_TEST(test_dhcp_msg_type_returns_ack)
{
    struct wolfIP s;
    struct dhcp_msg msg;

    wolfIP_init(&s);
    s.dhcp_xid = 0xABCD1234U;

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    ((uint8_t *)msg.options)[3] = DHCP_OPTION_END;

    ck_assert_int_eq(dhcp_msg_type(&s, &msg, sizeof(msg)), DHCP_ACK);
}
END_TEST

START_TEST(test_dhcp_msg_type_returns_request)
{
    struct wolfIP s;
    struct dhcp_msg msg;

    wolfIP_init(&s);
    s.dhcp_xid = 0x11223344U;

    build_dhcp_msg_base(&s, &msg, DHCP_REQUEST);
    ((uint8_t *)msg.options)[3] = DHCP_OPTION_END;

    ck_assert_int_eq(dhcp_msg_type(&s, &msg, sizeof(msg)), DHCP_REQUEST);
}
END_TEST

START_TEST(test_dhcp_msg_type_returns_discover)
{
    struct wolfIP s;
    struct dhcp_msg msg;

    wolfIP_init(&s);
    s.dhcp_xid = 0x55667788U;

    build_dhcp_msg_base(&s, &msg, DHCP_DISCOVER);
    ((uint8_t *)msg.options)[3] = DHCP_OPTION_END;

    ck_assert_int_eq(dhcp_msg_type(&s, &msg, sizeof(msg)), DHCP_DISCOVER);
}
END_TEST

START_TEST(test_dhcp_msg_type_bad_xid_returns_neg1)
{
    struct wolfIP s;
    struct dhcp_msg msg;

    wolfIP_init(&s);
    s.dhcp_xid = 0x11111111U;

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    msg.xid = ee32(0x22222222U); /* mismatch */
    ((uint8_t *)msg.options)[3] = DHCP_OPTION_END;

    ck_assert_int_eq(dhcp_msg_type(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_msg_type_bad_magic_returns_neg1)
{
    struct wolfIP s;
    struct dhcp_msg msg;

    wolfIP_init(&s);
    s.dhcp_xid = 0x11111111U;

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    msg.magic = ee32(0xDEADBEEFU); /* corrupt magic */
    ((uint8_t *)msg.options)[3] = DHCP_OPTION_END;

    ck_assert_int_eq(dhcp_msg_type(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_msg_type_boot_request_returns_neg1)
{
    struct wolfIP s;
    struct dhcp_msg msg;

    wolfIP_init(&s);
    s.dhcp_xid = 0x11111111U;

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    msg.op = BOOT_REQUEST; /* not a reply */

    ck_assert_int_eq(dhcp_msg_type(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_msg_type_len_ne_1_not_returned)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    uint8_t *p;

    wolfIP_init(&s);
    s.dhcp_xid = 0x12345678U;

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.xid = ee32(s.dhcp_xid);
    p = (uint8_t *)msg.options;
    /* MSG_TYPE with len=2 (not 1) — should NOT return the type */
    p[0] = DHCP_OPTION_MSG_TYPE;
    p[1] = 2;
    p[2] = DHCP_ACK;
    p[3] = 0x00;
    p += 4;
    p[0] = DHCP_OPTION_END;

    /* len != 1 means the branch `code == DHCP_OPTION_MSG_TYPE && len == 1`
     * is false; the option is skipped and -1 is returned */
    ck_assert_int_eq(dhcp_msg_type(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_msg_type_pad_bytes_skipped)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    uint8_t *p;

    wolfIP_init(&s);
    s.dhcp_xid = 0xBEEF0001U;

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.xid = ee32(s.dhcp_xid);
    p = (uint8_t *)msg.options;
    /* two pad bytes (code=0) then MSG_TYPE */
    p[0] = 0;
    p[1] = 0;
    p[2] = DHCP_OPTION_MSG_TYPE;
    p[3] = 1;
    p[4] = DHCP_NAK;
    p[5] = DHCP_OPTION_END;

    ck_assert_int_eq(dhcp_msg_type(&s, &msg, sizeof(msg)), DHCP_NAK);
}
END_TEST

START_TEST(test_dhcp_msg_type_truncated_option_returns_neg1)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    uint8_t *p;

    wolfIP_init(&s);
    s.dhcp_xid = 0x12340000U;

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.xid = ee32(s.dhcp_xid);
    p = (uint8_t *)msg.options;
    /* option says len=10 but we only give 3 bytes total → opt+2+len > opt_end */
    p[0] = DHCP_OPTION_SERVER_ID;
    p[1] = 10;
    p[2] = 0;

    /* only DHCP_HEADER_LEN + 3 bytes of options → truncated */
    ck_assert_int_eq(dhcp_msg_type(&s, &msg, DHCP_HEADER_LEN + 3), -1);
}
END_TEST

/* -------------------------------------------------------------------------
 * dhcp_parse_offer — additional branches
 * ---------------------------------------------------------------------- */

START_TEST(test_dhcp_parse_offer_type_ack_not_offer_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    uint8_t *p;

    wolfIP_init(&s);
    s.dhcp_xid = 0xCAFEBABEU;

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.xid = ee32(s.dhcp_xid);
    p = (uint8_t *)msg.options;
    /* Type = ACK (not OFFER) → inner body should not be entered.
     * After advancing past MSG_TYPE we have no DHCP_OFFER match, so
     * execution falls through to the outer saw_end check. */
    p[0] = DHCP_OPTION_MSG_TYPE;
    p[1] = 1;
    p[2] = DHCP_ACK;
    p += 3;
    p[0] = DHCP_OPTION_END;

    /* saw_end=1 after the END but no dhcp_ip/server set → -1 */
    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_offer_subnet_mask_len_lt4_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    uint8_t *p;

    wolfIP_init(&s);
    s.dhcp_xid = 0x1001U;

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.xid = ee32(s.dhcp_xid);
    msg.yiaddr = ee32(0x0A000064U);
    p = (uint8_t *)msg.options;
    p[0] = DHCP_OPTION_MSG_TYPE; p[1] = 1; p[2] = DHCP_OFFER; p += 3;
    /* SERVER_ID valid */
    p[0] = DHCP_OPTION_SERVER_ID; p[1] = 4;
    p[2] = 10; p[3] = 0; p[4] = 0; p[5] = 1;
    p += 6;
    /* SUBNET_MASK with len=2 < 4 → -1 */
    p[0] = DHCP_OPTION_SUBNET_MASK; p[1] = 2; p[2] = 0xFF; p[3] = 0xFF;
    p += 4;
    p[0] = DHCP_OPTION_END;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_offer_inner_truncated_opt2_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    uint8_t *p;
    uint32_t msg_used;

    wolfIP_init(&s);
    s.dhcp_xid = 0x2002U;

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.xid = ee32(s.dhcp_xid);
    msg.yiaddr = ee32(0x0A000064U);
    p = (uint8_t *)msg.options;
    p[0] = DHCP_OPTION_MSG_TYPE; p[1] = 1; p[2] = DHCP_OFFER; p += 3;
    /* One more byte: code only, no len byte → opt+2 > opt_end */
    p[0] = DHCP_OPTION_SERVER_ID;
    p += 1;
    msg_used = (uint32_t)(p - (uint8_t *)msg.options);

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, DHCP_HEADER_LEN + msg_used), -1);
}
END_TEST

START_TEST(test_dhcp_parse_offer_inner_truncated_data_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    uint8_t *p;
    uint32_t msg_used;

    wolfIP_init(&s);
    s.dhcp_xid = 0x3003U;

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.xid = ee32(s.dhcp_xid);
    msg.yiaddr = ee32(0x0A000064U);
    p = (uint8_t *)msg.options;
    p[0] = DHCP_OPTION_MSG_TYPE; p[1] = 1; p[2] = DHCP_OFFER; p += 3;
    /* SERVER_ID says len=4 but only 2 data bytes follow → opt+2+len > opt_end */
    p[0] = DHCP_OPTION_SERVER_ID; p[1] = 4; p[2] = 10; p[3] = 0;
    p += 4;
    msg_used = (uint32_t)(p - (uint8_t *)msg.options);

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, DHCP_HEADER_LEN + msg_used), -1);
}
END_TEST

START_TEST(test_dhcp_parse_offer_inner_pad_then_end)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;
    uint8_t *p;

    wolfIP_init(&s);
    s.dhcp_xid = 0x4004U;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.xid = ee32(s.dhcp_xid);
    msg.yiaddr = ee32(0x0A000064U);
    p = (uint8_t *)msg.options;
    p[0] = DHCP_OPTION_MSG_TYPE; p[1] = 1; p[2] = DHCP_OFFER; p += 3;
    /* Pad byte (code=0) inside inner OFFER loop */
    p[0] = 0; p += 1;
    /* SERVER_ID */
    p[0] = DHCP_OPTION_SERVER_ID; p[1] = 4;
    p[2] = 10; p[3] = 0; p[4] = 0; p[5] = 1;
    p += 6;
    p[0] = DHCP_OPTION_END;

    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, sizeof(msg)), 0);
    ck_assert_uint_eq(s.dhcp_server_ip, 0x0A000001U);
    ck_assert_uint_eq(s.dhcp_ip, 0x0A000064U);
}
END_TEST

START_TEST(test_dhcp_parse_offer_outer_end_with_state_already_set)
{
    /* Covers the branch at line ~7487:
     * saw_end=1 after outer END, dhcp_server_ip != 0 && dhcp_ip != 0 → 0 */
    struct wolfIP s;
    struct dhcp_msg msg;
    uint8_t *p;

    wolfIP_init(&s);
    s.dhcp_xid = 0x5005U;
    /* Pre-set as if an OFFER was already processed */
    s.dhcp_server_ip = 0x0A000001U;
    s.dhcp_ip = 0x0A000064U;

    memset(&msg, 0, sizeof(msg));
    msg.op = BOOT_REPLY;
    msg.magic = ee32(DHCP_MAGIC);
    msg.xid = ee32(s.dhcp_xid);
    p = (uint8_t *)msg.options;
    /* MSG_TYPE = ACK (not OFFER) so inner body not entered; outer loop sees END */
    p[0] = DHCP_OPTION_MSG_TYPE; p[1] = 1; p[2] = DHCP_ACK; p += 3;
    p[0] = DHCP_OPTION_END;

    /* outer saw_end=1, server_ip != 0, dhcp_ip != 0 → returns 0 */
    ck_assert_int_eq(dhcp_parse_offer(&s, &msg, sizeof(msg)), 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_REQUEST_SENT);
}
END_TEST

/* -------------------------------------------------------------------------
 * dhcp_parse_ack — additional branches
 * ---------------------------------------------------------------------- */

START_TEST(test_dhcp_parse_ack_mismatched_server_id_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;

    wolfIP_init(&s);
    s.dhcp_xid = 0x1234U;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    primary->ip = 0x0A000064U;
    s.dhcp_server_ip = 0x0A000001U; /* committed to this server */

    build_full_ack(&s, &msg, 0x0A000002U /* different server */,
                   0x0A000064U, 0xFFFFFF00U, 0x0A000001U, 0x08080808U, 120U);

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_server_id_len_lt4_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    uint8_t *p;

    wolfIP_init(&s);
    s.dhcp_xid = 0xABCDU;

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    p = (uint8_t *)msg.options + 3;
    /* SERVER_ID len=2 < 4 → -1 */
    p[0] = DHCP_OPTION_SERVER_ID; p[1] = 2; p[2] = 10; p[3] = 0;
    p += 4;
    p[0] = DHCP_OPTION_END;

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_offer_ip_len_lt4_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;
    uint8_t *p;
    uint32_t server_ip = 0x0A000001U;

    wolfIP_init(&s);
    s.dhcp_xid = 0xBEEFU;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    p = (uint8_t *)msg.options + 3;
    append_opt4(&p, DHCP_OPTION_SERVER_ID, server_ip);
    /* OFFER_IP with len=2 < 4 → -1 */
    p[0] = DHCP_OPTION_OFFER_IP; p[1] = 2; p[2] = 10; p[3] = 0;
    p += 4;
    append_end(&p);

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_subnet_mask_len_lt4_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;
    uint8_t *p;
    uint32_t server_ip = 0x0A000001U;

    wolfIP_init(&s);
    s.dhcp_xid = 0xCCCCU;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    p = (uint8_t *)msg.options + 3;
    append_opt4(&p, DHCP_OPTION_SERVER_ID, server_ip);
    /* SUBNET_MASK with len=2 < 4 → -1 */
    p[0] = DHCP_OPTION_SUBNET_MASK; p[1] = 2; p[2] = 0xFF; p[3] = 0xFF;
    p += 4;
    append_end(&p);

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_router_len_lt4_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;
    uint8_t *p;
    uint32_t server_ip = 0x0A000001U;

    wolfIP_init(&s);
    s.dhcp_xid = 0xDDDDU;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    p = (uint8_t *)msg.options + 3;
    append_opt4(&p, DHCP_OPTION_SERVER_ID, server_ip);
    append_opt4(&p, DHCP_OPTION_SUBNET_MASK, 0xFFFFFF00U);
    /* ROUTER with len=2 < 4 → -1 */
    p[0] = DHCP_OPTION_ROUTER; p[1] = 2; p[2] = 10; p[3] = 0;
    p += 4;
    append_end(&p);

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_dns_len_lt4_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;
    uint8_t *p;
    uint32_t server_ip = 0x0A000001U;

    wolfIP_init(&s);
    s.dhcp_xid = 0xEEEEU;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    s.dns_server = 0; /* allow DNS update */

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    p = (uint8_t *)msg.options + 3;
    append_opt4(&p, DHCP_OPTION_SERVER_ID, server_ip);
    append_opt4(&p, DHCP_OPTION_SUBNET_MASK, 0xFFFFFF00U);
    append_opt4(&p, DHCP_OPTION_ROUTER, 0x0A000001U);
    /* DNS with len=2 < 4 → -1 */
    p[0] = DHCP_OPTION_DNS; p[1] = 2; p[2] = 8; p[3] = 8;
    p += 4;
    append_end(&p);

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_lease_time_len_lt4_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;
    uint8_t *p;
    uint32_t server_ip = 0x0A000001U;

    wolfIP_init(&s);
    s.dhcp_xid = 0xFF00U;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    p = (uint8_t *)msg.options + 3;
    append_opt4(&p, DHCP_OPTION_SERVER_ID, server_ip);
    append_opt4(&p, DHCP_OPTION_SUBNET_MASK, 0xFFFFFF00U);
    append_opt4(&p, DHCP_OPTION_ROUTER, 0x0A000001U);
    /* LEASE_TIME with len=2 < 4 → -1 */
    p[0] = DHCP_OPTION_LEASE_TIME; p[1] = 2; p[2] = 0; p[3] = 60;
    p += 4;
    append_end(&p);

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_renewal_time_len_lt4_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;
    uint8_t *p;
    uint32_t server_ip = 0x0A000001U;

    wolfIP_init(&s);
    s.dhcp_xid = 0xAA11U;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    p = (uint8_t *)msg.options + 3;
    append_opt4(&p, DHCP_OPTION_SERVER_ID, server_ip);
    append_opt4(&p, DHCP_OPTION_SUBNET_MASK, 0xFFFFFF00U);
    append_opt4(&p, DHCP_OPTION_ROUTER, 0x0A000001U);
    append_opt4(&p, DHCP_OPTION_LEASE_TIME, 3600U);
    /* RENEWAL_TIME with len=2 < 4 → -1 */
    p[0] = DHCP_OPTION_RENEWAL_TIME; p[1] = 2; p[2] = 0; p[3] = 30;
    p += 4;
    append_end(&p);

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_rebind_time_len_lt4_rejected)
{
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;
    uint8_t *p;
    uint32_t server_ip = 0x0A000001U;

    wolfIP_init(&s);
    s.dhcp_xid = 0xBB22U;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    p = (uint8_t *)msg.options + 3;
    append_opt4(&p, DHCP_OPTION_SERVER_ID, server_ip);
    append_opt4(&p, DHCP_OPTION_SUBNET_MASK, 0xFFFFFF00U);
    append_opt4(&p, DHCP_OPTION_ROUTER, 0x0A000001U);
    append_opt4(&p, DHCP_OPTION_LEASE_TIME, 3600U);
    append_opt4(&p, DHCP_OPTION_RENEWAL_TIME, 1800U);
    /* REBIND_TIME with len=2 < 4 → -1 */
    p[0] = DHCP_OPTION_REBIND_TIME; p[1] = 2; p[2] = 0; p[3] = 45;
    p += 4;
    append_end(&p);

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_no_ip_after_ack_rejected)
{
    /* saw_server_id=1, mask set, but primary->ip == 0 → -1 */
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;
    uint8_t *p;
    uint32_t server_ip = 0x0A000001U;

    wolfIP_init(&s);
    s.dhcp_xid = 0xCC33U;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    primary->ip = 0U; /* no IP set */

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    p = (uint8_t *)msg.options + 3;
    append_opt4(&p, DHCP_OPTION_SERVER_ID, server_ip);
    append_opt4(&p, DHCP_OPTION_SUBNET_MASK, 0xFFFFFF00U);
    append_opt4(&p, DHCP_OPTION_ROUTER, 0x0A000001U);
    append_opt4(&p, DHCP_OPTION_LEASE_TIME, 120U);
    append_end(&p);

    /* primary->ip == 0 → condition fails → -1 */
    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_no_mask_after_ack_rejected)
{
    /* saw_server_id=1, ip set, but primary->mask == 0 → -1 */
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;
    uint8_t *p;
    uint32_t server_ip = 0x0A000001U;

    wolfIP_init(&s);
    s.dhcp_xid = 0xDD44U;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    primary->ip = 0x0A000064U;
    primary->mask = 0U; /* no mask */

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    p = (uint8_t *)msg.options + 3;
    append_opt4(&p, DHCP_OPTION_SERVER_ID, server_ip);
    /* deliberately omit SUBNET_MASK so primary->mask stays 0 */
    append_opt4(&p, DHCP_OPTION_ROUTER, 0x0A000001U);
    append_opt4(&p, DHCP_OPTION_LEASE_TIME, 120U);
    append_end(&p);

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), -1);
}
END_TEST

START_TEST(test_dhcp_parse_ack_with_renewal_and_rebind_times)
{
    /* Happy path: ACK with T1 (renewal) and T2 (rebind) options set. */
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;
    uint8_t *p;
    uint32_t server_ip = 0x0A000001U;
    uint32_t client_ip = 0x0A000064U;

    wolfIP_init(&s);
    s.dhcp_xid = 0xEE55U;
    s.last_tick = 0U;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    primary->ip = client_ip;

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    p = (uint8_t *)msg.options + 3;
    append_opt4(&p, DHCP_OPTION_SERVER_ID, server_ip);
    append_opt4(&p, DHCP_OPTION_SUBNET_MASK, 0xFFFFFF00U);
    append_opt4(&p, DHCP_OPTION_ROUTER, 0x0A000001U);
    append_opt4(&p, DHCP_OPTION_LEASE_TIME, 3600U);
    append_opt4(&p, DHCP_OPTION_RENEWAL_TIME, 1800U);
    append_opt4(&p, DHCP_OPTION_REBIND_TIME, 3150U);
    append_end(&p);

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_BOUND);
    ck_assert_uint_eq(s.dhcp_renew_at, 1800000U);
    ck_assert_uint_eq(s.dhcp_rebind_at, 3150000U);
    ck_assert_uint_eq(s.dhcp_lease_expires, 3600000U);
}
END_TEST

START_TEST(test_dhcp_parse_ack_dns_already_set_skipped)
{
    /* dns_server already set → DNS option branch not taken */
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;
    uint8_t *p;
    uint32_t server_ip = 0x0A000001U;
    uint32_t client_ip = 0x0A000064U;
    uint32_t old_dns = 0x01020304U;

    wolfIP_init(&s);
    s.dhcp_xid = 0xFF66U;
    s.dns_server = old_dns; /* already configured */
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    primary->ip = client_ip;

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    p = (uint8_t *)msg.options + 3;
    append_opt4(&p, DHCP_OPTION_SERVER_ID, server_ip);
    append_opt4(&p, DHCP_OPTION_SUBNET_MASK, 0xFFFFFF00U);
    append_opt4(&p, DHCP_OPTION_ROUTER, 0x0A000001U);
    append_opt4(&p, DHCP_OPTION_DNS, 0x08080808U); /* different DNS */
    append_opt4(&p, DHCP_OPTION_LEASE_TIME, 120U);
    append_end(&p);

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), 0);
    /* dns_server must not be overwritten */
    ck_assert_uint_eq(s.dns_server, old_dns);
}
END_TEST

START_TEST(test_dhcp_parse_ack_inner_pad_bytes_skipped)
{
    /* Pad bytes (code=0) inside the ACK inner loop are skipped. */
    struct wolfIP s;
    struct dhcp_msg msg;
    struct ipconf *primary;
    uint8_t *p;
    uint32_t server_ip = 0x0A000001U;
    uint32_t client_ip = 0x0A000064U;

    wolfIP_init(&s);
    s.dhcp_xid = 0x1122U;
    primary = wolfIP_primary_ipconf(&s);
    ck_assert_ptr_nonnull(primary);
    primary->ip = client_ip;

    build_dhcp_msg_base(&s, &msg, DHCP_ACK);
    p = (uint8_t *)msg.options + 3;
    /* pad byte */
    p[0] = 0; p += 1;
    append_opt4(&p, DHCP_OPTION_SERVER_ID, server_ip);
    append_opt4(&p, DHCP_OPTION_SUBNET_MASK, 0xFFFFFF00U);
    append_opt4(&p, DHCP_OPTION_ROUTER, 0x0A000002U);
    append_opt4(&p, DHCP_OPTION_LEASE_TIME, 120U);
    append_end(&p);

    ck_assert_int_eq(dhcp_parse_ack(&s, &msg, sizeof(msg)), 0);
    ck_assert_int_eq(s.dhcp_state, DHCP_BOUND);
}
END_TEST

/* -------------------------------------------------------------------------
 * dhcp_timer_cb — additional branches
 * ---------------------------------------------------------------------- */

START_TEST(test_dhcp_timer_cb_renewing_not_yet_rebind_sends_request)
{
    /* RENEWING but last_tick < dhcp_rebind_at → stays RENEWING, sends REQUEST */
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    s.dhcp_xid = 0xAAAA1234U;
    wolfIP_ipconfig_set(&s, 0x0A000064U, 0xFFFFFF00U, 0x0A000001U);
    s.dhcp_ip = 0x0A000064U;
    s.dhcp_server_ip = 0x0A000001U;
    s.last_tick = 1000U;
    s.dhcp_rebind_at = 9999999U; /* far future */
    s.dhcp_state = DHCP_RENEWING;
    s.dhcp_timeout_count = 0;

    last_frame_sent_size = 0;
    dhcp_timer_cb(&s);
    (void)wolfIP_poll(&s, s.last_tick);

    /* Must have sent a REQUEST and incremented counter */
    ck_assert_uint_gt(last_frame_sent_size, 0U);
    ck_assert_int_eq(s.dhcp_timeout_count, 1);
    ck_assert_int_eq(s.dhcp_state, DHCP_RENEWING);
}
END_TEST

START_TEST(test_dhcp_timer_cb_renewing_past_rebind_transitions_to_rebinding)
{
    /* RENEWING with last_tick >= rebind_at → transitions to REBINDING */
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    s.dhcp_xid = 0xBBBB5678U;
    wolfIP_ipconfig_set(&s, 0x0A000064U, 0xFFFFFF00U, 0x0A000001U);
    s.dhcp_ip = 0x0A000064U;
    s.dhcp_server_ip = 0x0A000001U;
    s.last_tick = 5000U;
    s.dhcp_rebind_at = 5000U; /* expired exactly */
    s.dhcp_state = DHCP_RENEWING;
    s.dhcp_timeout_count = 2;

    dhcp_timer_cb(&s);

    ck_assert_int_eq(s.dhcp_state, DHCP_REBINDING);
    ck_assert_uint_eq(s.dhcp_start_tick, 5000U);
    /* After transitioning to REBINDING, dhcp_send_request is also called
     * (count reset to 0 then incremented on success = 1) */
    ck_assert_uint_eq(s.dhcp_timeout_count, 1U);
}
END_TEST

START_TEST(test_dhcp_timer_cb_rebinding_not_expired_sends_request)
{
    /* REBINDING, lease not expired → sends REQUEST */
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    s.dhcp_xid = 0xCCCC9ABCU;
    wolfIP_ipconfig_set(&s, 0x0A000064U, 0xFFFFFF00U, 0x0A000001U);
    s.dhcp_ip = 0x0A000064U;
    s.dhcp_server_ip = 0x0A000001U;
    s.last_tick = 1000U;
    s.dhcp_lease_expires = 9999999U; /* far future */
    s.dhcp_state = DHCP_REBINDING;
    s.dhcp_timeout_count = 0;

    last_frame_sent_size = 0;
    dhcp_timer_cb(&s);
    (void)wolfIP_poll(&s, s.last_tick);

    ck_assert_uint_gt(last_frame_sent_size, 0U);
    ck_assert_int_eq(s.dhcp_timeout_count, 1);
    ck_assert_int_eq(s.dhcp_state, DHCP_REBINDING);
}
END_TEST

START_TEST(test_dhcp_timer_cb_bound_lease_not_expired_starts_renew)
{
    /* BOUND state, timer fires but lease has not expired → start RENEWING */
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_udp_sd = wolfIP_sock_socket(&s, AF_INET, IPSTACK_SOCK_DGRAM, WI_IPPROTO_UDP);
    ck_assert_int_gt(s.dhcp_udp_sd, 0);
    s.dhcp_xid = 0xDDDD0001U;
    wolfIP_ipconfig_set(&s, 0x0A000064U, 0xFFFFFF00U, 0x0A000001U);
    s.dhcp_ip = 0x0A000064U;
    s.dhcp_server_ip = 0x0A000001U;
    s.last_tick = 1000U;
    s.dhcp_lease_expires = 9999999U; /* not expired */
    s.dhcp_state = DHCP_BOUND;
    s.dhcp_timeout_count = 0;

    dhcp_timer_cb(&s);

    ck_assert_int_eq(s.dhcp_state, DHCP_RENEWING);
    ck_assert_uint_eq(s.dhcp_start_tick, 1000U);
    ck_assert_uint_eq(s.dhcp_timeout_count, 1U);
}
END_TEST

START_TEST(test_dhcp_timer_cb_default_state_noop)
{
    /* State not handled by any case → default branch (no-op) */
    struct wolfIP s;

    wolfIP_init(&s);
    mock_link_init(&s);
    s.dhcp_xid = 0x5678U;
    s.dhcp_state = DHCP_OFF; /* unhandled in switch */
    s.dhcp_timeout_count = 0;

    dhcp_timer_cb(&s);

    /* Timer must reset to NO_TIMER and state must stay DHCP_OFF */
    ck_assert_int_eq(s.dhcp_timer, NO_TIMER);
    ck_assert_int_eq(s.dhcp_state, DHCP_OFF);
}
END_TEST

START_TEST(test_dhcp_timer_cb_null_arg_noop)
{
    /* NULL arg → early return, no crash */
    dhcp_timer_cb(NULL);
}
END_TEST

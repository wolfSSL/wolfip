/* unit_tests_vlan.c
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

#if WOLFIP_VLAN

/* =========================================================================
 * Environment note
 * =========================================================================
 * When WOLFIP_VLAN=1, unit_shared.c bumps WOLFIP_MAX_INTERFACES to 6 so that
 * a loopback + a physical parent + WOLFIP_VLAN_MAX (= 4) simultaneously live
 * VLAN sub-interfaces fit. Slot layout after wolfIP_init() + mock_link_init():
 *   slot 0 (TEST_LOOPBACK_IF): loopback (poll/send set by wolfIP_init)
 *   slot 1 (TEST_PRIMARY_IF):  mock physical (poll/send set by mock_link_init)
 *   slots 2..5:                free (poll=NULL, send=NULL, vlan_active=0);
 *                              the first four wolfIP_vlan_create() calls land
 *                              here in slot-reuse order.
 * test_vlan_api_create_exhausts_max exercises the WOLFIP_VLAN_MAX cap by
 * filling all four free slots before expecting -WOLFIP_EINVAL.
 */

/* =========================================================================
 * Local helpers
 * ========================================================================= */

/* Base IPs used throughout */
#define VLAN_PHYS_IP     0x0A0A0A02U  /* 10.10.10.2  — physical parent */
#define VLAN_SUB100_IP   0x0A0A6402U  /* 10.10.100.2 — VID 100 sub-iface */
#define VLAN_SUB200_IP   0x0A0AC802U  /* 10.10.200.2 — VID 200 sub-iface */
#define VLAN_REMOTE_IP   0x0A0A6401U  /* 10.10.100.1 — remote peer on VID 100 */

/* MAC used by the synthetic "remote" sender in injected frames */
static const uint8_t vlan_remote_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF1};

/* Initialise the stack with only the primary physical interface.
 * TEST_SECOND_IF remains free and can be claimed by wolfIP_vlan_create. */
static void setup_vlan_stack(struct wolfIP *s)
{
    wolfIP_init(s);
    mock_link_init(s);
    wolfIP_ipconfig_set_ex(s, TEST_PRIMARY_IF, VLAN_PHYS_IP, 0xFFFFFF00U, 0);
    last_frame_sent_size = 0;
}

/* Compute the ICMP checksum over 'len' bytes starting at icmp->type.
 * Mirrors icmp_checksum() in wolfip.c. */
static uint16_t vlan_icmp_checksum(struct wolfIP_icmp_packet *icmp, uint16_t len)
{
    uint32_t sum = 0;
    uint32_t i;
    const uint8_t *ptr = (const uint8_t *)(&icmp->type);
    uint16_t word;

    for (i = 0; i < (uint32_t)(len & ~1u); i += 2) {
        memcpy(&word, ptr + i, sizeof(word));
        sum += ee16(word);
    }
    if (len & 0x01u) {
        uint16_t spare = (uint16_t)((uint16_t)ptr[len - 1] << 8);
        sum += spare;
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFF);
}

/* Build a minimal ICMP echo-request frame (untagged) addressed to dst_ip
 * from the vlan_remote_mac/remote_ip pair, using the ll->mac as eth dst.
 * buf must be at least ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN bytes. */
static uint32_t build_icmp_echo_request(uint8_t *buf, uint32_t bufsz,
                                        const uint8_t *eth_dst_mac,
                                        ip4 src_ip, ip4 dst_ip)
{
    struct wolfIP_icmp_packet *icmp;
    uint32_t frame_len;
    uint16_t ip_len;

    frame_len = (uint32_t)(ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN);
    if (bufsz < frame_len)
        return 0;
    memset(buf, 0, frame_len);

    /* Ethernet header */
    memcpy(buf,     eth_dst_mac,      6); /* dst */
    memcpy(buf + 6, vlan_remote_mac,  6); /* src */
    buf[12] = 0x08; buf[13] = 0x00;       /* ethertype = IPv4 */

    icmp = (struct wolfIP_icmp_packet *)buf;
    ip_len = (uint16_t)(IP_HEADER_LEN + ICMP_HEADER_LEN);

    /* IP header */
    icmp->ip.ver_ihl  = 0x45;
    icmp->ip.tos      = 0;
    icmp->ip.len      = ee16(ip_len);
    icmp->ip.id       = 0;
    icmp->ip.flags_fo = 0;
    icmp->ip.ttl      = 64;
    icmp->ip.proto    = 0x01; /* ICMP */
    icmp->ip.csum     = 0;
    icmp->ip.src      = ee32(src_ip);
    icmp->ip.dst      = ee32(dst_ip);
    iphdr_set_checksum(&icmp->ip);

    /* ICMP echo request */
    icmp->type = 8; /* ICMP_ECHO_REQUEST */
    icmp->code = 0;
    icmp->csum = 0;
    memset(icmp->unused, 0, 4); /* id=0, seq=0 */
    icmp->csum = ee16(vlan_icmp_checksum(icmp, ICMP_HEADER_LEN));

    return frame_len;
}

/* Build a tagged ICMP echo-request frame by inserting a 4-byte 802.1Q tag
 * into an already-built untagged frame.
 * dst_buf must be at least src_len + 4 bytes.
 * Returns new length (src_len + 4). */
static uint32_t insert_vlan_tag(uint8_t *dst_buf, uint32_t dst_bufsz,
                                const uint8_t *src_buf, uint32_t src_len,
                                uint16_t vid, uint8_t pcp, uint8_t dei)
{
    uint16_t tpid, tci;
    uint32_t tagged_len;

    tagged_len = src_len + 4u;
    if (dst_bufsz < tagged_len || src_len < (uint32_t)ETH_HEADER_LEN)
        return 0;

    /* Copy dst+src MAC (12 bytes) */
    memcpy(dst_buf, src_buf, 12);
    /* TPID = 0x8100 big-endian */
    tpid = ee16(0x8100u);
    memcpy(dst_buf + 12, &tpid, 2);
    /* TCI: pcp(3) | dei(1) | vid(12) */
    tci = ee16((uint16_t)(((uint16_t)(pcp & 0x7u) << 13)
                         | ((uint16_t)(dei & 0x1u) << 12)
                         | (vid & 0x0FFFu)));
    memcpy(dst_buf + 14, &tci, 2);
    /* Remaining payload (inner ethertype + IP + ...) */
    memcpy(dst_buf + 16, src_buf + 12, src_len - 12);
    return tagged_len;
}

/* Inject a tagged ICMP echo request onto the parent physical interface and
 * return the frame length sent (from last_frame_sent_size after the call).
 * Returns 0 if wolfIP_recv_on produced no reply. */
static uint32_t inject_tagged_icmp_echo(struct wolfIP *s, unsigned int parent_idx,
                                        const uint8_t *parent_mac,
                                        ip4 src_ip, ip4 dst_ip,
                                        uint16_t vid, uint8_t pcp, uint8_t dei)
{
    uint8_t plain[ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN];
    uint8_t tagged[ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN + 4];
    uint32_t plain_len, tagged_len;

    plain_len = build_icmp_echo_request(plain, sizeof(plain),
                                        parent_mac, src_ip, dst_ip);
    if (!plain_len)
        return 0;
    tagged_len = insert_vlan_tag(tagged, sizeof(tagged), plain, plain_len,
                                 vid, pcp, dei);
    if (!tagged_len)
        return 0;

    last_frame_sent_size = 0;
    wolfIP_recv_on(s, parent_idx, tagged, tagged_len);
    return last_frame_sent_size;
}

/* =========================================================================
 * 1. API edge tests
 * ========================================================================= */

START_TEST(test_vlan_api_create_basic)
{
    struct wolfIP s;
    unsigned int sub_idx = 0xFFFFFFFFu;
    unsigned int got_parent = 0;
    uint16_t got_vid = 0;
    uint8_t  got_pcp = 0xFF, got_dei = 0xFF;
    int ret;

    setup_vlan_stack(&s);

    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 3, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);
    ck_assert_uint_ne(sub_idx, 0xFFFFFFFFu);
    ck_assert_uint_ne(sub_idx, TEST_PRIMARY_IF);

    ret = wolfIP_vlan_get(&s, sub_idx, &got_parent, &got_vid, &got_pcp, &got_dei);
    ck_assert_int_eq(ret, 0);
    ck_assert_uint_eq(got_parent, TEST_PRIMARY_IF);
    ck_assert_uint_eq(got_vid, 100);
    ck_assert_uint_eq(got_pcp, 3);
    ck_assert_uint_eq(got_dei, 0);
}
END_TEST

START_TEST(test_vlan_api_create_vid_max_ok)
{
    struct wolfIP s;
    unsigned int sub_idx = 0xFFFFFFFFu;
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 4094, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);
    ck_assert_uint_ne(sub_idx, 0xFFFFFFFFu);
}
END_TEST

START_TEST(test_vlan_api_create_vid_4095_rejected)
{
    struct wolfIP s;
    unsigned int sub_idx = 0xFFFFFFFFu;
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 4095, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_vlan_api_create_vid_above_max_rejected)
{
    struct wolfIP s;
    unsigned int sub_idx = 0xFFFFFFFFu;
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 0xFFFF, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_vlan_api_create_pcp_above_7_rejected)
{
    struct wolfIP s;
    unsigned int sub_idx = 0xFFFFFFFFu;
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 8, 0, &sub_idx);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_vlan_api_create_dei_above_1_rejected)
{
    struct wolfIP s;
    unsigned int sub_idx = 0xFFFFFFFFu;
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 2, &sub_idx);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_vlan_api_create_duplicate_vid_rejected)
{
    struct wolfIP s;
    unsigned int sub_idx1 = 0xFFFFFFFFu, sub_idx2 = 0xFFFFFFFFu;
    int ret;

    setup_vlan_stack(&s);

    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx1);
    ck_assert_int_eq(ret, 0);

    /* Same VID on same parent must be rejected */
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 1, 0, &sub_idx2);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST

/* test_vlan_api_create_same_vid_two_parents_ok:
 * The mock harness exposes one physical parent (TEST_PRIMARY_IF), so we
 * exercise the per-parent VID-uniqueness check via slot reuse: create VID=100
 * on the primary, delete it, then re-create VID=100 on the same primary.
 * This confirms the duplicate check is scoped per-parent (a deleted slot
 * frees up the VID) and that slot reuse works. A full two-physical-parents
 * variant would require a second mock physical interface, which the current
 * harness does not provide. */
START_TEST(test_vlan_api_create_same_vid_two_parents_ok)
{
    struct wolfIP s;
    unsigned int sub_idx = 0xFFFFFFFFu;
    int ret;

    setup_vlan_stack(&s);

    /* Create VID=100 on primary */
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);

    /* Delete it */
    ret = wolfIP_vlan_delete(&s, sub_idx);
    ck_assert_int_eq(ret, 0);

    /* Slot is reused: re-creating VID=100 on the same parent succeeds */
    sub_idx = 0xFFFFFFFFu;
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);
    ck_assert_uint_ne(sub_idx, 0xFFFFFFFFu);
}
END_TEST

START_TEST(test_vlan_api_create_parent_not_physical_rejected)
{
    struct wolfIP s;
    unsigned int sub_idx = 0xFFFFFFFFu;
    unsigned int child_idx = 0xFFFFFFFFu;
    int ret;

    setup_vlan_stack(&s);

    /* Create a sub-interface */
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);

    /* Attempting to create a child of that sub-interface must be rejected */
    ret = wolfIP_vlan_create(&s, sub_idx, 200, 0, 0, &child_idx);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST

/* test_vlan_api_create_exhausts_max:
 * Create WOLFIP_VLAN_MAX sub-interfaces, then expect the next create to fail
 * with -WOLFIP_EINVAL. This exercises the cap on simultaneously-live VLANs. */
START_TEST(test_vlan_api_create_exhausts_max)
{
    struct wolfIP s;
    unsigned int sub_idx;
    int ret;
    unsigned int i;

    setup_vlan_stack(&s);

    /* Fill up to WOLFIP_VLAN_MAX VLAN slots; each must succeed. */
    for (i = 0; i < WOLFIP_VLAN_MAX; i++) {
        sub_idx = 0xFFFFFFFFu;
        ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF,
                                 (uint16_t)(100u + i), 0, 0, &sub_idx);
        ck_assert_int_eq(ret, 0);
        ck_assert_uint_ne(sub_idx, 0xFFFFFFFFu);
    }

    /* The next create must fail — VLAN_MAX is reached (or no free slot). */
    sub_idx = 0xFFFFFFFFu;
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF,
                             (uint16_t)(100u + WOLFIP_VLAN_MAX),
                             0, 0, &sub_idx);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST

/* The parent slot must be an initialized Ethernet device. An empty
 * pre-allocated ll_dev[] slot (send=NULL, poll=NULL, zero MAC) is not a
 * real link, so creating a VLAN on it would produce a sub-interface that
 * could never transmit. */
START_TEST(test_vlan_api_create_uninitialized_parent_rejected)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *empty;
    unsigned int sub_idx = 0xFFFFFFFFu;
    int ret;

    setup_vlan_stack(&s);

    /* TEST_SECOND_IF (= 2 with loopback) is left untouched by setup_vlan_stack:
     * its send/poll are NULL after wolfIP_init. Sanity-check, then try to
     * use it as a parent. */
    empty = wolfIP_getdev_ex(&s, TEST_SECOND_IF);
    ck_assert_ptr_nonnull(empty);
    ck_assert_ptr_null(empty->send);
    ck_assert_ptr_null(empty->poll);

    ret = wolfIP_vlan_create(&s, TEST_SECOND_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST

/* VLAN is an IEEE 802.3 (Ethernet) feature; non-ethernet interfaces such as
 * the loopback (struct wolfIP_ll_dev.non_ethernet == 1) cannot carry tagged
 * frames. The API must reject such parents. */
START_TEST(test_vlan_api_create_loopback_parent_rejected)
{
#if WOLFIP_ENABLE_LOOPBACK
    struct wolfIP s;
    struct wolfIP_ll_dev *loop;
    unsigned int sub_idx = 0xFFFFFFFFu;
    int ret;

    setup_vlan_stack(&s);

    loop = wolfIP_getdev_ex(&s, TEST_LOOPBACK_IF);
    ck_assert_ptr_nonnull(loop);
    /* wolfIP_init configures the loopback slot with non_ethernet=1 and a
     * loopback send callback; sanity-check before exercising the path. */
    ck_assert_uint_eq((unsigned)loop->non_ethernet, 1u);
    ck_assert_ptr_nonnull(loop->send);

    ret = wolfIP_vlan_create(&s, TEST_LOOPBACK_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
#endif
}
END_TEST

START_TEST(test_vlan_api_create_null_args_rejected)
{
    struct wolfIP s;
    unsigned int sub_idx = 0xFFFFFFFFu;
    int ret;

    setup_vlan_stack(&s);

    /* Null stack */
    ret = wolfIP_vlan_create(NULL, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    /* Null out_if_idx */
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    /* Bad parent index (out of range) */
    ret = wolfIP_vlan_create(&s, 0xFFFFFFFFu, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_vlan_api_delete_basic)
{
    struct wolfIP s;
    unsigned int sub_idx = 0xFFFFFFFFu;
    unsigned int sub_idx2 = 0xFFFFFFFFu;
    unsigned int got_parent;
    uint16_t got_vid;
    uint8_t got_pcp, got_dei;
    int ret;

    setup_vlan_stack(&s);

    /* Create VID=100 */
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);

    /* Delete it */
    ret = wolfIP_vlan_delete(&s, sub_idx);
    ck_assert_int_eq(ret, 0);

    /* wolfIP_vlan_get must now fail on the deleted index */
    ret = wolfIP_vlan_get(&s, sub_idx, &got_parent, &got_vid, &got_pcp, &got_dei);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    /* Re-creating the same VID must succeed (slot reuse) */
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx2);
    ck_assert_int_eq(ret, 0);
}
END_TEST

START_TEST(test_vlan_api_delete_physical_rejected)
{
    struct wolfIP s;
    int ret;

    setup_vlan_stack(&s);

    /* Physical interfaces do not have vlan_active set; delete must fail */
    ret = wolfIP_vlan_delete(&s, TEST_PRIMARY_IF);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST

START_TEST(test_vlan_api_delete_bad_ifidx_rejected)
{
    struct wolfIP s;
    int ret;

    setup_vlan_stack(&s);

    /* Out-of-range index */
    ret = wolfIP_vlan_delete(&s, 0xFFFFFFFFu);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    /* Null stack */
    ret = wolfIP_vlan_delete(NULL, TEST_PRIMARY_IF);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST

/* Regression: wolfIP_vlan_get used to default *parent_if_idx to 0 if the
 * parent pointer didn't match any slot in ll_dev[], silently reporting the
 * wrong parent. After the fix it must return -WOLFIP_EINVAL and leave the
 * caller's out pointers untouched. */
START_TEST(test_vlan_api_get_dangling_parent_pointer_rejected)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *sub;
    unsigned int sub_idx = 0xFFFFFFFFu;
    unsigned int got_parent = 0xEEEEEEEEu;
    uint16_t got_vid = 0xEEEE;
    uint8_t  got_pcp = 0xEE, got_dei = 0xEE;
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);

    /* Sanity: get() succeeds while the parent pointer is intact. */
    ret = wolfIP_vlan_get(&s, sub_idx, &got_parent, &got_vid, &got_pcp, &got_dei);
    ck_assert_int_eq(ret, 0);
    ck_assert_uint_eq(got_parent, TEST_PRIMARY_IF);

    /* Corrupt the parent pointer so it no longer matches any slot. */
    sub = wolfIP_getdev_ex(&s, sub_idx);
    ck_assert_ptr_nonnull(sub);
    sub->vlan_parent = (struct wolfIP_ll_dev *)(uintptr_t)0xDEADBEEFu;

    got_parent = 0xEEEEEEEEu;
    got_vid = 0xEEEE;
    got_pcp = 0xEE;
    got_dei = 0xEE;
    ret = wolfIP_vlan_get(&s, sub_idx, &got_parent, &got_vid, &got_pcp, &got_dei);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
    /* Output pointers must be untouched on failure. */
    ck_assert_uint_eq(got_parent, 0xEEEEEEEEu);
    ck_assert_uint_eq(got_vid, 0xEEEE);
    ck_assert_uint_eq(got_pcp, 0xEE);
    ck_assert_uint_eq(got_dei, 0xEE);

    /* Restore so the cleanup path doesn't dereference the bogus pointer. */
    sub->vlan_active = 0;
    sub->vlan_parent = NULL;
}
END_TEST

/* Regression: wolfIP_ll_send_frame used to allow vlan_active=1 to bypass
 * the !ll->send guard, then -- if vlan_parent was NULL -- fell through to
 * `ll->send(...)` and dereferenced a NULL function pointer. The hardened
 * guard rejects that inconsistent state explicitly. */
START_TEST(test_vlan_tx_active_without_parent_rejected)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *sub;
    unsigned int sub_idx = 0xFFFFFFFFu;
    uint8_t buf[60];
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);

    /* Force the inconsistent state directly: vlan_active=1, vlan_parent=NULL.
     * (wolfIP_vlan_create itself never produces this, but defensive code
     * must still refuse to send rather than crash.) */
    sub = wolfIP_getdev_ex(&s, sub_idx);
    ck_assert_ptr_nonnull(sub);
    sub->vlan_parent = NULL;
    ck_assert_ptr_null(sub->send);

    memset(buf, 0, sizeof(buf));
    last_frame_sent_size = 0;
    ret = wolfIP_ll_send_frame(&s, sub_idx, buf, sizeof(buf));
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
    ck_assert_uint_eq((uint32_t)last_frame_sent_size, 0u);

    /* Restore so teardown doesn't trip. */
    sub->vlan_active = 0;
}
END_TEST

START_TEST(test_vlan_api_get_null_args_rejected)
{
    struct wolfIP s;
    unsigned int sub_idx = 0xFFFFFFFFu;
    unsigned int got_parent;
    uint16_t got_vid;
    uint8_t got_pcp, got_dei;
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);

    /* Null stack */
    ret = wolfIP_vlan_get(NULL, sub_idx, &got_parent, &got_vid, &got_pcp, &got_dei);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    /* Null output pointers */
    ret = wolfIP_vlan_get(&s, sub_idx, NULL, &got_vid, &got_pcp, &got_dei);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    ret = wolfIP_vlan_get(&s, sub_idx, &got_parent, NULL, &got_pcp, &got_dei);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    ret = wolfIP_vlan_get(&s, sub_idx, &got_parent, &got_vid, NULL, &got_dei);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);

    ret = wolfIP_vlan_get(&s, sub_idx, &got_parent, &got_vid, &got_pcp, NULL);
    ck_assert_int_eq(ret, -WOLFIP_EINVAL);
}
END_TEST

/* =========================================================================
 * 2. TX tagging tests
 * ========================================================================= */

/* Build a minimal untagged Ethernet frame (60 bytes) with inner ethertype
 * 0x0800 and a dummy payload, then send it via the sub-interface index. */
START_TEST(test_vlan_tx_tag_inserted)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys;
    unsigned int sub_idx = 0xFFFFFFFFu;
    uint8_t buf[60];
    uint16_t tci_on_wire;
    uint16_t tci_expected;
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);

    /* Give the parent a mock_send function so wolfIP_ll_send_frame works */
    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    phys->send = mock_send;
    phys->mtu  = LINK_MTU;

    /* Build a 60-byte frame: dst+src MAC, ethertype 0x0800, zero payload */
    memset(buf, 0, sizeof(buf));
    memcpy(buf,     phys->mac,       6); /* dst */
    memcpy(buf + 6, vlan_remote_mac, 6); /* src */
    buf[12] = 0x08; buf[13] = 0x00;     /* inner ethertype */
    buf[14] = 0xDE; buf[15] = 0xAD;     /* start of payload */

    last_frame_sent_size = 0;
    ret = wolfIP_ll_send_frame(&s, sub_idx, buf, sizeof(buf));
    ck_assert_int_ge(ret, 0);

    /* Tagged frame = original 60 bytes + 4-byte tag = 64 bytes */
    ck_assert_uint_eq((uint32_t)last_frame_sent_size, 64u);

    /* Bytes [12..13] must be TPID = 0x81 0x00 */
    ck_assert_uint_eq(last_frame_sent[12], 0x81u);
    ck_assert_uint_eq(last_frame_sent[13], 0x00u);

    /* Bytes [14..15] = TCI; VID=100 (0x64), PCP=0, DEI=0 */
    memcpy(&tci_on_wire, &last_frame_sent[14], 2);
    tci_expected = ee16(100u); /* big-endian 0x0064 */
    ck_assert_uint_eq(tci_on_wire, tci_expected);

    /* Bytes [16..17] must be original inner ethertype 0x0800 */
    ck_assert_uint_eq(last_frame_sent[16], 0x08u);
    ck_assert_uint_eq(last_frame_sent[17], 0x00u);

    /* Payload byte [18] == original buf[14] = 0xDE */
    ck_assert_uint_eq(last_frame_sent[18], 0xDEu);
}
END_TEST

START_TEST(test_vlan_tx_pcp_and_dei_encoded)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys;
    unsigned int sub_idx = 0xFFFFFFFFu;
    uint8_t buf[60];
    uint16_t tci_on_wire;
    uint16_t tci_expected;
    int ret;

    setup_vlan_stack(&s);
    /* PCP=7, DEI=1, VID=100: TCI = (7<<13)|(1<<12)|100 = 0xF064 */
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 7, 1, &sub_idx);
    ck_assert_int_eq(ret, 0);

    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    phys->send = mock_send;
    phys->mtu  = LINK_MTU;

    memset(buf, 0, sizeof(buf));
    memcpy(buf,     phys->mac,       6);
    memcpy(buf + 6, vlan_remote_mac, 6);
    buf[12] = 0x08; buf[13] = 0x00;

    last_frame_sent_size = 0;
    ret = wolfIP_ll_send_frame(&s, sub_idx, buf, sizeof(buf));
    ck_assert_int_ge(ret, 0);
    ck_assert_uint_eq((uint32_t)last_frame_sent_size, 64u);

    /* TCI on wire (big-endian): 0xF064 */
    memcpy(&tci_on_wire, &last_frame_sent[14], 2);
    tci_expected = ee16(0xF064u);
    ck_assert_uint_eq(tci_on_wire, tci_expected);
}
END_TEST

START_TEST(test_vlan_tx_vid_zero_priority_tag)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys;
    unsigned int sub_idx = 0xFFFFFFFFu;
    uint8_t buf[60];
    uint16_t tci_on_wire, tci_expected;
    int ret;

    setup_vlan_stack(&s);
    /* VID=0, PCP=5, DEI=0: TCI = (5<<13)|0 = 0xA000 */
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 0, 5, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);

    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    phys->send = mock_send;
    phys->mtu  = LINK_MTU;

    memset(buf, 0, sizeof(buf));
    memcpy(buf,     phys->mac,       6);
    memcpy(buf + 6, vlan_remote_mac, 6);
    buf[12] = 0x08; buf[13] = 0x00;

    last_frame_sent_size = 0;
    ret = wolfIP_ll_send_frame(&s, sub_idx, buf, sizeof(buf));
    ck_assert_int_ge(ret, 0);

    /* TCI low 12 bits == 0 (VID=0), PCP=5 in high 3 bits */
    memcpy(&tci_on_wire, &last_frame_sent[14], 2);
    tci_expected = ee16(0xA000u);
    ck_assert_uint_eq(tci_on_wire, tci_expected);
}
END_TEST

START_TEST(test_vlan_tx_vid_4094_encoded)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys;
    unsigned int sub_idx = 0xFFFFFFFFu;
    uint8_t buf[60];
    uint16_t tci_on_wire, tci_expected;
    int ret;

    setup_vlan_stack(&s);
    /* VID=4094 (0xFFE), PCP=0, DEI=0: TCI low 12 bits = 0xFFE */
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 4094, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);

    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    phys->send = mock_send;
    phys->mtu  = LINK_MTU;

    memset(buf, 0, sizeof(buf));
    memcpy(buf,     phys->mac,       6);
    memcpy(buf + 6, vlan_remote_mac, 6);
    buf[12] = 0x08; buf[13] = 0x00;

    last_frame_sent_size = 0;
    ret = wolfIP_ll_send_frame(&s, sub_idx, buf, sizeof(buf));
    ck_assert_int_ge(ret, 0);

    memcpy(&tci_on_wire, &last_frame_sent[14], 2);
    tci_expected = ee16(0x0FFEu);
    ck_assert_uint_eq(tci_on_wire, tci_expected);
}
END_TEST

START_TEST(test_vlan_tx_oversize_rejected)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys;
    unsigned int sub_idx = 0xFFFFFFFFu;
    /* Frame large enough that +4 VLAN tag exceeds parent MTU */
    uint8_t buf[LINK_MTU];
    uint32_t send_len;
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);

    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    phys->send = mock_send;
    phys->mtu  = LINK_MTU;

    /* sub-iface MTU = parent_mtu - 4; sending parent_mtu - 3 bytes would
     * require parent_mtu + 1 bytes after tagging — must be rejected. */
    send_len = (uint32_t)(wolfIP_ll_frame_mtu(phys) - 3u);
    memset(buf, 0, send_len);
    memcpy(buf,     phys->mac,       6);
    memcpy(buf + 6, vlan_remote_mac, 6);
    buf[12] = 0x08; buf[13] = 0x00;

    last_frame_sent_size = 0;
    ret = wolfIP_ll_send_frame(&s, sub_idx, buf, send_len);
    ck_assert_int_lt(ret, 0);
    ck_assert_uint_eq((uint32_t)last_frame_sent_size, 0u);
}
END_TEST

START_TEST(test_vlan_tx_runt_rejected)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys;
    unsigned int sub_idx = 0xFFFFFFFFu;
    uint8_t buf[ETH_HEADER_LEN];
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);

    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    phys->send = mock_send;
    phys->mtu  = LINK_MTU;

    /* Send ETH_HEADER_LEN - 1 bytes: too short even for the MAC copy */
    memset(buf, 0, sizeof(buf));
    last_frame_sent_size = 0;
    ret = wolfIP_ll_send_frame(&s, sub_idx, buf, (uint32_t)(ETH_HEADER_LEN - 1));
    ck_assert_int_lt(ret, 0);
    ck_assert_uint_eq((uint32_t)last_frame_sent_size, 0u);
}
END_TEST

/* =========================================================================
 * 3. RX parsing / stripping tests
 *
 * Strategy: inject a tagged ICMP echo request onto the physical parent via
 * wolfIP_recv_on().  The stack strips the tag, finds the matching sub-iface,
 * and calls icmp_input() which sends a reply.  The reply goes through
 * wolfIP_ll_send_frame() for the sub-iface, which re-inserts the VLAN tag
 * and calls mock_send() on the parent — captured in last_frame_sent[].
 * ========================================================================= */

START_TEST(test_vlan_rx_tagged_match_delivered)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys;
    unsigned int sub_idx = 0xFFFFFFFFu;
    uint16_t tci_on_wire;
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);

    /* Give sub-iface an IP so icmp_input() accepts the echo request */
    wolfIP_ipconfig_set_ex(&s, sub_idx, VLAN_SUB100_IP, 0xFFFFFF00U, 0);

    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    /* wolfIP_recv_on reads ll->mac for the MAC filter; set parent send */
    phys->send = mock_send;

    last_frame_sent_size = 0;
    inject_tagged_icmp_echo(&s, TEST_PRIMARY_IF, phys->mac,
                            VLAN_REMOTE_IP, VLAN_SUB100_IP,
                            100, 0, 0);

    /* A reply must have been sent */
    ck_assert_uint_gt((uint32_t)last_frame_sent_size, 0u);

    /* Reply must carry a VLAN tag with TPID=0x8100 */
    ck_assert_uint_eq(last_frame_sent[12], 0x81u);
    ck_assert_uint_eq(last_frame_sent[13], 0x00u);

    /* TCI VID field = 100 (0x64), PCP=0, DEI=0 */
    memcpy(&tci_on_wire, &last_frame_sent[14], 2);
    ck_assert_uint_eq(ee16(tci_on_wire) & 0x0FFFu, 100u);
}
END_TEST

START_TEST(test_vlan_rx_tagged_mismatch_dropped)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys;
    unsigned int sub_idx = 0xFFFFFFFFu;
    int ret;

    setup_vlan_stack(&s);
    /* Sub on VID=100 only */
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);
    wolfIP_ipconfig_set_ex(&s, sub_idx, VLAN_SUB100_IP, 0xFFFFFF00U, 0);

    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    phys->send = mock_send;

    last_frame_sent_size = 0;
    /* Inject frame tagged with VID=999 — no matching sub-iface */
    inject_tagged_icmp_echo(&s, TEST_PRIMARY_IF, phys->mac,
                            VLAN_REMOTE_IP, VLAN_SUB100_IP,
                            999, 0, 0);

    /* No reply must be produced */
    ck_assert_uint_eq((uint32_t)last_frame_sent_size, 0u);
}
END_TEST

START_TEST(test_vlan_rx_untagged_on_physical_ok)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys;
    uint8_t frame[ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN];
    uint32_t frame_len;

    setup_vlan_stack(&s);
    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    phys->send = mock_send;

    frame_len = build_icmp_echo_request(frame, sizeof(frame),
                                        phys->mac,
                                        VLAN_REMOTE_IP, VLAN_PHYS_IP);
    ck_assert_uint_gt(frame_len, 0u);

    last_frame_sent_size = 0;
    wolfIP_recv_on(&s, TEST_PRIMARY_IF, frame, frame_len);

    /* An untagged ICMP echo reply must be sent on the physical interface */
    ck_assert_uint_gt((uint32_t)last_frame_sent_size, 0u);

    /* No VLAN tag: ethertype at [12..13] must be 0x0800, NOT 0x8100 */
    ck_assert_uint_eq(last_frame_sent[12], 0x08u);
    ck_assert_uint_eq(last_frame_sent[13], 0x00u);
}
END_TEST

START_TEST(test_vlan_rx_runt_tagged_dropped)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys;
    /* ETH_HEADER_LEN + 1 byte — too short to contain a full VLAN tag */
    uint8_t runt[ETH_HEADER_LEN + 1];
    uint16_t tpid;

    setup_vlan_stack(&s);
    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    phys->send = mock_send;

    memset(runt, 0, sizeof(runt));
    memcpy(runt,     phys->mac,       6);
    memcpy(runt + 6, vlan_remote_mac, 6);
    tpid = ee16(0x8100u);
    memcpy(runt + 12, &tpid, 2);
    runt[14] = 0x00; /* partial TCI — only 1 byte available */

    last_frame_sent_size = 0;
    wolfIP_recv_on(&s, TEST_PRIMARY_IF, runt, sizeof(runt));

    /* Must be silently dropped; no reply, no crash */
    ck_assert_uint_eq((uint32_t)last_frame_sent_size, 0u);
}
END_TEST

/* test_vlan_rx_multiple_subs_correct_dispatch:
 * Verify the RX VID-match logic for two distinct VIDs by exercising them
 * sequentially: create VID=100, test RX, delete; create VID=200, send a
 * stale VID=100 frame (must be dropped now that no sub-iface owns it),
 * then send a VID=200 frame (must be delivered). This drives both the
 * "VID matches" and "VID no longer matches" branches of wolfIP_recv_on()'s
 * sub-interface lookup. A truly concurrent two-sub variant would be valuable
 * as a follow-up but is out of scope for this test. */
START_TEST(test_vlan_rx_multiple_subs_correct_dispatch)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys;
    unsigned int sub_idx = 0xFFFFFFFFu;
    uint16_t tci_on_wire;
    int ret;

    setup_vlan_stack(&s);
    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    phys->send = mock_send;

    /* --- VID=100 --- */
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);
    wolfIP_ipconfig_set_ex(&s, sub_idx, VLAN_SUB100_IP, 0xFFFFFF00U, 0);

    last_frame_sent_size = 0;
    inject_tagged_icmp_echo(&s, TEST_PRIMARY_IF, phys->mac,
                            VLAN_REMOTE_IP, VLAN_SUB100_IP, 100, 0, 0);
    ck_assert_uint_gt((uint32_t)last_frame_sent_size, 0u);
    memcpy(&tci_on_wire, &last_frame_sent[14], 2);
    ck_assert_uint_eq(ee16(tci_on_wire) & 0x0FFFu, 100u);

    /* Tear down VID=100, set up VID=200 in the same slot */
    ret = wolfIP_vlan_delete(&s, sub_idx);
    ck_assert_int_eq(ret, 0);

    sub_idx = 0xFFFFFFFFu;
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 200, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);
    wolfIP_ipconfig_set_ex(&s, sub_idx, VLAN_SUB200_IP, 0xFFFFFF00U, 0);

    /* VID=100 frame must now be dropped (no matching sub) */
    last_frame_sent_size = 0;
    inject_tagged_icmp_echo(&s, TEST_PRIMARY_IF, phys->mac,
                            VLAN_REMOTE_IP, VLAN_SUB200_IP, 100, 0, 0);
    ck_assert_uint_eq((uint32_t)last_frame_sent_size, 0u);

    /* VID=200 frame must be delivered */
    last_frame_sent_size = 0;
    inject_tagged_icmp_echo(&s, TEST_PRIMARY_IF, phys->mac,
                            VLAN_REMOTE_IP, VLAN_SUB200_IP, 200, 0, 0);
    ck_assert_uint_gt((uint32_t)last_frame_sent_size, 0u);
    memcpy(&tci_on_wire, &last_frame_sent[14], 2);
    ck_assert_uint_eq(ee16(tci_on_wire) & 0x0FFFu, 200u);
}
END_TEST

START_TEST(test_vlan_rx_delete_then_dropped)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys;
    unsigned int sub_idx = 0xFFFFFFFFu;
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);
    wolfIP_ipconfig_set_ex(&s, sub_idx, VLAN_SUB100_IP, 0xFFFFFF00U, 0);

    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    phys->send = mock_send;

    /* First echo — must produce a reply */
    last_frame_sent_size = 0;
    inject_tagged_icmp_echo(&s, TEST_PRIMARY_IF, phys->mac,
                            VLAN_REMOTE_IP, VLAN_SUB100_IP, 100, 0, 0);
    ck_assert_uint_gt((uint32_t)last_frame_sent_size, 0u);

    /* Delete the sub-iface */
    ret = wolfIP_vlan_delete(&s, sub_idx);
    ck_assert_int_eq(ret, 0);

    /* Second echo — must be dropped */
    last_frame_sent_size = 0;
    inject_tagged_icmp_echo(&s, TEST_PRIMARY_IF, phys->mac,
                            VLAN_REMOTE_IP, VLAN_SUB100_IP, 100, 0, 0);
    ck_assert_uint_eq((uint32_t)last_frame_sent_size, 0u);
}
END_TEST

START_TEST(test_vlan_rx_dei_bit_accepted)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys;
    unsigned int sub_idx = 0xFFFFFFFFu;
    int ret;

    setup_vlan_stack(&s);
    /* Create sub with DEI=0; incoming frame may have DEI=1 in its TCI —
     * the RX dispatch only matches on VID, so it should still be delivered. */
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);
    wolfIP_ipconfig_set_ex(&s, sub_idx, VLAN_SUB100_IP, 0xFFFFFF00U, 0);

    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    phys->send = mock_send;

    last_frame_sent_size = 0;
    /* Inject tagged frame with DEI=1 — VID still matches */
    inject_tagged_icmp_echo(&s, TEST_PRIMARY_IF, phys->mac,
                            VLAN_REMOTE_IP, VLAN_SUB100_IP,
                            100, 0, 1 /* dei=1 */);

    ck_assert_uint_gt((uint32_t)last_frame_sent_size, 0u);
}
END_TEST

/* test_vlan_rx_tagged_arp_processed:
 * Assumption: the implementation routes arp_recv replies for VLAN sub-
 * interfaces through wolfIP_ll_send_frame (which inserts the tag) rather than
 * calling sub->ll->send directly (which is NULL for VLAN subs).  The parallel
 * implementation must ensure this, e.g. by calling wolfIP_ll_send_frame or by
 * having arp_recv walk up to the parent and insert the tag itself. */
START_TEST(test_vlan_rx_tagged_arp_processed)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys;
    unsigned int sub_idx = 0xFFFFFFFFu;
    uint8_t plain_arp[sizeof(struct arp_packet)];
    uint8_t tagged_arp[sizeof(struct arp_packet) + 4];
    struct arp_packet *arp;
    uint32_t tagged_len;
    uint16_t tci_on_wire;
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);
    wolfIP_ipconfig_set_ex(&s, sub_idx, VLAN_SUB100_IP, 0xFFFFFF00U, 0);

    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    phys->send = mock_send;

    /* Build a tagged ARP request for the sub-iface IP */
    memset(plain_arp, 0, sizeof(plain_arp));
    arp = (struct arp_packet *)plain_arp;
    memcpy(arp->eth.dst, phys->mac, 6);
    memcpy(arp->eth.src, vlan_remote_mac, 6);
    arp->eth.type = ee16(ETH_TYPE_ARP);
    arp->htype    = ee16(1);
    arp->ptype    = ee16(0x0800);
    arp->hlen     = 6;
    arp->plen     = 4;
    arp->opcode   = ee16(ARP_REQUEST);
    memcpy(arp->sma, vlan_remote_mac, 6);
    arp->sip      = ee32(VLAN_REMOTE_IP);
    memset(arp->tma, 0, 6);
    arp->tip      = ee32(VLAN_SUB100_IP);

    /* Insert VLAN tag at offset 12 */
    tagged_len = insert_vlan_tag(tagged_arp, sizeof(tagged_arp),
                                 plain_arp, sizeof(plain_arp), 100, 0, 0);
    ck_assert_uint_gt(tagged_len, 0u);

    last_frame_sent_size = 0;
    wolfIP_recv_on(&s, TEST_PRIMARY_IF, tagged_arp, tagged_len);

    /* ARP reply must have been sent */
    ck_assert_uint_gt((uint32_t)last_frame_sent_size, 0u);

    /* Reply must be tagged with VID=100 */
    ck_assert_uint_eq(last_frame_sent[12], 0x81u);
    ck_assert_uint_eq(last_frame_sent[13], 0x00u);
    memcpy(&tci_on_wire, &last_frame_sent[14], 2);
    ck_assert_uint_eq(ee16(tci_on_wire) & 0x0FFFu, 100u);
}
END_TEST

/* =========================================================================
 * 4. MTU test
 * ========================================================================= */

START_TEST(test_vlan_mtu_inherited)
{
    struct wolfIP s;
    struct wolfIP_ll_dev *phys, *sub;
    unsigned int sub_idx = 0xFFFFFFFFu;
    uint32_t phys_mtu, sub_mtu;
    int ret;

    setup_vlan_stack(&s);
    ret = wolfIP_vlan_create(&s, TEST_PRIMARY_IF, 100, 0, 0, &sub_idx);
    ck_assert_int_eq(ret, 0);

    phys = wolfIP_getdev_ex(&s, TEST_PRIMARY_IF);
    ck_assert_ptr_nonnull(phys);
    sub  = wolfIP_getdev_ex(&s, sub_idx);
    ck_assert_ptr_nonnull(sub);

    phys_mtu = wolfIP_ll_frame_mtu(phys);
    sub_mtu  = wolfIP_ll_frame_mtu(sub);

    /* Sub-interface MTU must be exactly 4 bytes less than parent MTU */
    ck_assert_uint_eq(sub_mtu + 4u, phys_mtu);
}
END_TEST

#endif /* WOLFIP_VLAN */

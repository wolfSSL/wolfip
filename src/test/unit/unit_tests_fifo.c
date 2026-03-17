START_TEST(test_fifo_init)
{
    struct fifo f;
    fifo_init(&f, mem, memsz);
    ck_assert_int_eq(fifo_len(&f), 0);
    ck_assert_int_eq(fifo_space(&f), memsz);
    ck_assert_int_eq(fifo_len(&f), 0);
}
END_TEST

START_TEST(test_fifo_peek_wraps_tail_when_head_lt_tail)
{
    struct fifo f;
    uint8_t data[64];
    struct pkt_desc *desc;

    fifo_init(&f, data, sizeof(data));
    f.head = 0;
    f.tail = 4;
    f.h_wrap = 0;

    /* With head at 0 and tail aligned, peek should return the current tail
     * descriptor without altering tail or wrap state. */
    desc = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(f.tail, 4);
}
END_TEST

START_TEST(test_fifo_peek_no_wrap_when_space_available)
{
    struct fifo f;
    uint8_t data[4096];
    struct pkt_desc *desc;

    fifo_init(&f, data, sizeof(data));
    f.head = 0;
    f.tail = 4;
    f.h_wrap = 0;

    /* When no wrap boundary is set, peek must not change tail. */
    desc = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(f.tail, 4);
}
END_TEST

START_TEST(test_fifo_next_wraps_on_hwrap)
{
    struct fifo f;
    uint8_t data[4096];
    struct pkt_desc *desc0;
    struct pkt_desc *desc1;
    struct pkt_desc *next;
    uint32_t len;

    fifo_init(&f, data, sizeof(data));

    desc0 = (struct pkt_desc *)data;
    desc0->pos = 0;
    desc0->len = 4;
    len = sizeof(struct pkt_desc) + desc0->len;
    while (len % 4)
        len++;

    desc1 = (struct pkt_desc *)(data + len);
    desc1->pos = 0;
    desc1->len = 0;
    f.h_wrap = len;
    f.head = len + 8;

    next = fifo_next(&f, desc0);
    ck_assert_ptr_eq(next, (struct pkt_desc *)data);
}
END_TEST

START_TEST(test_fifo_pop_aligns_tail_to_head_returns_null)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    f.head = 4;
    f.tail = 1;

    /* Aligning tail to head means the FIFO is empty; pop should return NULL. */
    ck_assert_ptr_eq(fifo_pop(&f), NULL);
}
END_TEST

START_TEST(test_fifo_pop_wraps_tail_when_head_lt_tail)
{
    struct fifo f;
    uint8_t data[64];
    struct pkt_desc *desc;

    fifo_init(&f, data, sizeof(data));
    f.head = 0;
    f.tail = 4;
    f.h_wrap = 0;

    desc = (struct pkt_desc *)(data + 4);
    desc->pos = 4;
    desc->len = 0;

    /* Popping a zero-length packet should advance tail past the descriptor. */
    ck_assert_ptr_nonnull(fifo_pop(&f));
    ck_assert_uint_eq(f.tail, 4 + sizeof(struct pkt_desc));
}
END_TEST

START_TEST(test_fifo_pop_no_wrap_when_space_available)
{
    struct fifo f;
    uint8_t data[4096];
    struct pkt_desc *desc;
    uint32_t expected_tail;

    fifo_init(&f, data, sizeof(data));
    f.head = 0;
    f.tail = 4;
    f.h_wrap = 0;

    desc = (struct pkt_desc *)(data + 4);
    desc->pos = 4;
    desc->len = 0;
    expected_tail = 4 + sizeof(struct pkt_desc);

    /* With no wrap, pop should advance tail to the next descriptor. */
    ck_assert_ptr_nonnull(fifo_pop(&f));
    ck_assert_uint_eq(f.tail, expected_tail);
}
END_TEST

START_TEST(test_fifo_peek_empty_unaligned_tail)
{
    struct fifo f;
    uint8_t data[64];
    struct pkt_desc *desc;

    fifo_init(&f, data, sizeof(data));
    f.head = 3;
    f.tail = 3;
    f.h_wrap = 0;

    desc = fifo_peek(&f);
    ck_assert_ptr_eq(desc, NULL);
    ck_assert_uint_eq(f.tail, 3);
    ck_assert_uint_eq(f.h_wrap, 0);
}
END_TEST

START_TEST(test_fifo_len_empty_unaligned_tail)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    f.head = 3;
    f.tail = 3;
    f.h_wrap = 0;

    ck_assert_uint_eq(fifo_len(&f), 0);
    ck_assert_uint_eq(f.tail, 3);
}
END_TEST

START_TEST(test_fifo_pop_empty_unaligned_tail)
{
    struct fifo f;
    uint8_t data[64];

    fifo_init(&f, data, sizeof(data));
    f.head = 3;
    f.tail = 3;
    f.h_wrap = 0;

    ck_assert_ptr_eq(fifo_pop(&f), NULL);
    ck_assert_uint_eq(f.tail, 3);
}
END_TEST

START_TEST(test_fifo_push_pop_odd_sizes_drains_cleanly)
{
    struct fifo f;
    uint8_t data[256];
    struct pkt_desc *desc;
    uint8_t p1[3] = {0x01, 0x02, 0x03};
    uint8_t p2[5] = {0x11, 0x12, 0x13, 0x14, 0x15};
    uint8_t p3[7] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27};

    fifo_init(&f, data, sizeof(data));
    ck_assert_int_eq(fifo_push(&f, p1, sizeof(p1)), 0);
    ck_assert_int_eq(fifo_push(&f, p2, sizeof(p2)), 0);
    ck_assert_int_eq(fifo_push(&f, p3, sizeof(p3)), 0);

    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), p1, sizeof(p1));
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), p2, sizeof(p2));
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_mem_eq((const uint8_t *)f.data + desc->pos + sizeof(struct pkt_desc), p3, sizeof(p3));

    ck_assert_uint_eq(fifo_len(&f), 0);
    ck_assert_ptr_eq(fifo_peek(&f), NULL);
}
END_TEST

START_TEST(test_fifo_full_wrap_does_not_appear_empty_or_discard_packets)
{
    struct fifo f;
    uint8_t data[120];
    uint8_t payload[8];
    struct pkt_desc *desc;
    int i;

    memset(payload, 0xAB, sizeof(payload));
    fifo_init(&f, data, sizeof(data));

    /* 5 * (sizeof(pkt_desc)=16 + payload=8) == 120: fills FIFO exactly and
     * forces head == tail with wrap marker set (full, not empty). */
    for (i = 0; i < 5; i++) {
        payload[0] = (uint8_t)i;
        ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    }

    ck_assert_uint_eq(fifo_space(&f), 0);
    ck_assert_uint_eq(f.head, f.tail);
    ck_assert_uint_eq(f.h_wrap, sizeof(data));

    /* Full FIFO must still expose packets. */
    desc = fifo_peek(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(desc->len, sizeof(payload));
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 0);

    for (i = 0; i < 5; i++) {
        desc = fifo_pop(&f);
        ck_assert_ptr_nonnull(desc);
        ck_assert_uint_eq(desc->len, sizeof(payload));
        ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), (uint8_t)i);
    }

    ck_assert_ptr_eq(fifo_peek(&f), NULL);
    ck_assert_uint_eq(fifo_len(&f), 0);
}
END_TEST

START_TEST(test_fifo_next_stops_at_aligned_head_when_head_unaligned)
{
    struct fifo f;
    uint8_t data[128];
    uint8_t p1[3] = {0x11, 0x12, 0x13};
    uint8_t p2[5] = {0x21, 0x22, 0x23, 0x24, 0x25};
    struct pkt_desc *d1;
    struct pkt_desc *d2;
    struct pkt_desc *d3;

    fifo_init(&f, data, sizeof(data));
    ck_assert_int_eq(fifo_push(&f, p1, sizeof(p1)), 0);
    ck_assert_int_eq(fifo_push(&f, p2, sizeof(p2)), 0);

    /* fifo_push aligns only on insertion boundaries; head can stay unaligned. */
    ck_assert_uint_ne(f.head % 4, 0);

    d1 = fifo_peek(&f);
    ck_assert_ptr_nonnull(d1);
    ck_assert_uint_eq(d1->len, sizeof(p1));
    ck_assert_uint_eq(*((uint8_t *)f.data + d1->pos + sizeof(*d1)), p1[0]);

    d2 = fifo_next(&f, d1);
    ck_assert_ptr_nonnull(d2);
    ck_assert_uint_eq(d2->len, sizeof(p2));
    ck_assert_uint_eq(*((uint8_t *)f.data + d2->pos + sizeof(*d2)), p2[0]);

    /* Must stop at aligned insertion cursor, not scan padding as descriptors. */
    d3 = fifo_next(&f, d2);
    ck_assert_ptr_eq(d3, NULL);
}
END_TEST

START_TEST(test_fifo_full_wrap_next_iterates_all_entries_without_loss)
{
    struct fifo f;
    uint8_t data[120];
    uint8_t payload[8];
    struct pkt_desc *desc;
    int i;

    memset(payload, 0xCD, sizeof(payload));
    fifo_init(&f, data, sizeof(data));

    for (i = 0; i < 5; i++) {
        payload[0] = (uint8_t)i;
        ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    }

    ck_assert_uint_eq(f.head, f.tail);
    ck_assert_uint_eq(f.h_wrap, sizeof(data));
    ck_assert_uint_eq(fifo_space(&f), 0);

    desc = fifo_peek(&f);
    for (i = 0; i < 5; i++) {
        ck_assert_ptr_nonnull(desc);
        ck_assert_uint_eq(desc->len, sizeof(payload));
        ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), (uint8_t)i);
        desc = fifo_next(&f, desc);
    }
    ck_assert_ptr_eq(desc, NULL);
}
END_TEST

START_TEST(test_fifo_wrap_full_pop_then_refill_keeps_order_without_drops)
{
    struct fifo f;
    uint8_t data[120];
    uint8_t payload[8];
    struct pkt_desc *desc;
    int i;

    memset(payload, 0xEF, sizeof(payload));
    fifo_init(&f, data, sizeof(data));

    for (i = 0; i < 5; i++) {
        payload[0] = (uint8_t)i;
        ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    }
    ck_assert_uint_eq(f.head, f.tail);
    ck_assert_uint_eq(f.h_wrap, sizeof(data));

    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 0);

    payload[0] = 5;
    ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    ck_assert_uint_eq(f.head, f.tail);
    ck_assert_uint_eq(f.h_wrap, sizeof(data));

    for (i = 1; i <= 5; i++) {
        desc = fifo_pop(&f);
        ck_assert_ptr_nonnull(desc);
        ck_assert_uint_eq(desc->len, sizeof(payload));
        ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), (uint8_t)i);
    }

    ck_assert_ptr_eq(fifo_peek(&f), NULL);
    ck_assert_uint_eq(fifo_len(&f), 0);
}
END_TEST

START_TEST(test_fifo_wrap_flag_transitions_push_pop_around_boundary)
{
    struct fifo f;
    uint8_t data[100];
    uint8_t payload[8];
    struct pkt_desc *desc;
    int i;

    fifo_init(&f, data, sizeof(data));
    memset(payload, 0, sizeof(payload));

    /* Fill descriptors at offsets 0,24,48,72 (head=96, no wrap yet). */
    for (i = 0; i < 4; i++) {
        payload[0] = (uint8_t)i;
        ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    }
    ck_assert_uint_eq(f.h_wrap, 0);
    ck_assert_uint_eq(f.head, 96);
    ck_assert_uint_eq(f.tail, 0);

    /* Drain first two packets so tail moves past "needed". */
    for (i = 0; i < 2; i++) {
        desc = fifo_pop(&f);
        ck_assert_ptr_nonnull(desc);
        ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), (uint8_t)i);
    }
    ck_assert_uint_eq(f.tail, 48);
    ck_assert_uint_eq(f.h_wrap, 0);

    /* Next push must wrap head to start and set h_wrap to old head (96). */
    payload[0] = 4;
    ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    ck_assert_uint_eq(f.h_wrap, 96);
    ck_assert_uint_eq(f.head, 24);
    ck_assert_uint_eq(f.tail, 48);

    /* Pop packet at 48: still before wrap marker, flag remains set. */
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 2);
    ck_assert_uint_eq(f.h_wrap, 96);
    ck_assert_uint_eq(f.tail, 72);

    /* Pop packet at 72 crosses wrap marker: tail wraps and h_wrap clears. */
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 3);
    ck_assert_uint_eq(f.h_wrap, 0);
    ck_assert_uint_eq(f.tail, 0);

    /* Wrapped packet remains readable after flag clear. */
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 4);
    ck_assert_ptr_eq(fifo_peek(&f), NULL);
}
END_TEST

START_TEST(test_fifo_wrap_flag_repeated_flips_keep_data_consistent)
{
    struct fifo f;
    uint8_t data[100];
    uint8_t payload[8];
    struct pkt_desc *desc;
    int i;

    fifo_init(&f, data, sizeof(data));
    memset(payload, 0, sizeof(payload));

    for (i = 0; i < 4; i++) {
        payload[0] = (uint8_t)i;
        ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    }
    for (i = 0; i < 2; i++) {
        desc = fifo_pop(&f);
        ck_assert_ptr_nonnull(desc);
        ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), (uint8_t)i);
    }

    payload[0] = 4;
    ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    ck_assert_uint_eq(f.h_wrap, 96);

    desc = fifo_pop(&f); /* 2 */
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 2);
    desc = fifo_pop(&f); /* 3, clears wrap */
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 3);
    ck_assert_uint_eq(f.h_wrap, 0);
    desc = fifo_pop(&f); /* 4 */
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 4);

    /* Build another wrap cycle with new packets 5,6,7,8. */
    for (i = 5; i <= 7; i++) {
        payload[0] = (uint8_t)i;
        ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    }
    desc = fifo_pop(&f); /* 5 */
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 5);

    payload[0] = 8;
    ck_assert_int_eq(fifo_push(&f, payload, sizeof(payload)), 0);
    ck_assert_uint_eq(f.h_wrap, 96);

    desc = fifo_pop(&f); /* 6 */
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 6);
    desc = fifo_pop(&f); /* 7, crosses wrap => clear */
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 7);
    ck_assert_uint_eq(f.h_wrap, 0);
    desc = fifo_pop(&f); /* 8 */
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 8);

    ck_assert_ptr_eq(fifo_peek(&f), NULL);
    ck_assert_uint_eq(fifo_len(&f), 0);
}
END_TEST

START_TEST(test_fifo_wrap_flag_transitions_with_odd_payload_sizes)
{
    struct fifo f;
    uint8_t data[80];
    uint8_t p3[3] = {0};
    uint8_t p5[5] = {0};
    struct pkt_desc *desc;

    fifo_init(&f, data, sizeof(data));

    p3[0] = 1; ck_assert_int_eq(fifo_push(&f, p3, sizeof(p3)), 0); /* pos 0 */
    p5[0] = 2; ck_assert_int_eq(fifo_push(&f, p5, sizeof(p5)), 0); /* pos 20 */
    p3[0] = 3; ck_assert_int_eq(fifo_push(&f, p3, sizeof(p3)), 0); /* pos 44 */

    /* Drain first two; leave packet 3 in pre-wrap region. */
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(desc->len, sizeof(p3));
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 1);
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(desc->len, sizeof(p5));
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 2);

    /* Force wrap with odd-size payload and verify wrap marker set. */
    p5[0] = 4;
    ck_assert_int_eq(fifo_push(&f, p5, sizeof(p5)), 0);
    ck_assert_uint_eq(f.h_wrap, 64);
    ck_assert_uint_ne(f.head % 4, 0);

    /* Pop remaining pre-wrap packet; marker stays until boundary crossing. */
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(desc->len, sizeof(p3));
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 3);
    ck_assert_uint_eq(f.h_wrap, 64);

    /* Next pop crosses wrap and clears marker; wrapped payload remains valid. */
    desc = fifo_pop(&f);
    ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(desc->len, sizeof(p5));
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 4);
    ck_assert_uint_eq(f.h_wrap, 0);
    ck_assert_ptr_eq(fifo_peek(&f), NULL);
}
END_TEST

START_TEST(test_fifo_wrap_flag_repeated_flips_with_odd_payload_sizes)
{
    struct fifo f;
    uint8_t data[80];
    uint8_t p3[3] = {0};
    uint8_t p5[5] = {0};
    uint8_t p7[7] = {0};
    struct pkt_desc *desc;

    fifo_init(&f, data, sizeof(data));

    p7[0] = 5; ck_assert_int_eq(fifo_push(&f, p7, sizeof(p7)), 0); /* pos 0 */
    p3[0] = 6; ck_assert_int_eq(fifo_push(&f, p3, sizeof(p3)), 0); /* pos 24 */
    p5[0] = 7; ck_assert_int_eq(fifo_push(&f, p5, sizeof(p5)), 0); /* pos 44 */

    /* Pop two, then wrap once with odd payload. */
    desc = fifo_pop(&f); ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 5);
    desc = fifo_pop(&f); ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 6);

    p7[0] = 8;
    ck_assert_int_eq(fifo_push(&f, p7, sizeof(p7)), 0);
    ck_assert_uint_eq(f.h_wrap, 68);

    /* Drain remaining in-order, including wrapped element; wrap clears. */
    desc = fifo_pop(&f); ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 7);
    ck_assert_uint_eq(f.h_wrap, 68);
    desc = fifo_pop(&f); ck_assert_ptr_nonnull(desc);
    ck_assert_uint_eq(*((uint8_t *)f.data + desc->pos + sizeof(*desc)), 8);
    ck_assert_uint_eq(f.h_wrap, 0);
    ck_assert_ptr_eq(fifo_peek(&f), NULL);
}
END_TEST

START_TEST(test_queue_insert_len_gt_space)
{
    struct queue q;
    uint8_t data[8];
    uint8_t payload[6] = {0};

    queue_init(&q, data, sizeof(data), 0);
    ck_assert_int_eq(queue_insert(&q, payload, 0, 6), 0);
    ck_assert_int_eq(queue_insert(&q, payload, 6, 4), -1);
}
END_TEST

START_TEST(test_queue_insert_len_gt_size_returns_error)
{
    struct queue q;
    uint8_t data[8];
    uint8_t payload[12] = {0};

    queue_init(&q, data, sizeof(data), 0);
    ck_assert_int_eq(queue_insert(&q, payload, 0, sizeof(payload)), -1);
}
END_TEST

START_TEST(test_queue_insert_updates_head_when_pos_plus_len_gt_head)
{
    struct queue q;
    uint8_t data[16];
    uint8_t payload[4] = {1,2,3,4};

    queue_init(&q, data, sizeof(data), 0);
    ck_assert_int_eq(queue_insert(&q, payload, 0, 4), 0);
    ck_assert_uint_eq(q.head, 4);
    ck_assert_int_eq(queue_insert(&q, payload, 4, 4), 0);
    ck_assert_uint_eq(q.head, 8);
}
END_TEST

START_TEST(test_queue_insert_no_head_update_when_pos_plus_len_le_head)
{
    struct queue q;
    uint8_t data[16];
    uint8_t payload[8] = {1,2,3,4,5,6,7,8};
    uint32_t head_before;

    queue_init(&q, data, sizeof(data), 0);
    ck_assert_int_eq(queue_insert(&q, payload, 0, 8), 0);
    head_before = q.head;
    ck_assert_int_eq(queue_insert(&q, payload, 2, 2), 0);
    ck_assert_uint_eq(q.head, head_before);
}
END_TEST


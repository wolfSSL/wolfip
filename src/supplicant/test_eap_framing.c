/* test_eap_framing.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Unit tests for EAP and EAP-TLS framing.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "eap.h"
#include "eap_tls.h"
#include "eapol.h"

static int test_eap_parse_identity_request(void)
{
    /* Code=Request(1), Id=42, Length=5, Type=Identity(1). */
    static const uint8_t pkt[] = { 0x01, 0x2A, 0x00, 0x05, 0x01 };
    struct eap_view v;
    int fails = 0;

    printf("Test 1: parse EAP-Request/Identity\n");
    if (eap_parse(pkt, sizeof(pkt), &v) != 0) {
        printf("  [FAIL] eap_parse rejected valid packet\n");
        return 1;
    }
    if (v.code != EAP_CODE_REQUEST) { printf("  [FAIL] code\n"); fails++; }
    if (v.id   != 0x2A) { printf("  [FAIL] id\n"); fails++; }
    if (v.length != 5)  { printf("  [FAIL] length\n"); fails++; }
    if (v.type != EAP_TYPE_IDENTITY) { printf("  [FAIL] type\n"); fails++; }
    if (v.type_data_len != 0) { printf("  [FAIL] type_data_len\n"); fails++; }
    if (fails == 0) printf("  [OK]   all header fields match\n");
    return fails;
}

static int test_eap_parse_short_rejected(void)
{
    /* Truncated header. */
    static const uint8_t pkt[] = { 0x01, 0x00, 0x00 };
    struct eap_view v;
    printf("Test 2: parse rejects truncated EAP\n");
    if (eap_parse(pkt, sizeof(pkt), &v) == 0) {
        printf("  [FAIL] accepted short packet\n");
        return 1;
    }
    printf("  [OK]   rejected\n");
    return 0;
}

static int test_eap_build_identity_response(void)
{
    /* Identity "alice@example.com" -> 17 bytes. */
    static const char id[] = "alice@example.com";
    uint8_t out[64];
    size_t  total;
    int     fails = 0;

    printf("Test 3: build EAP-Response/Identity\n");
    if (eap_build_identity_response(out, sizeof(out), 0x05,
                                    (const uint8_t *)id, strlen(id),
                                    &total) != 0) {
        printf("  [FAIL] build returned error\n");
        return 1;
    }
    if (total != EAP_HEADER_LEN + 1U + strlen(id)) {
        printf("  [FAIL] total len %zu\n", total);
        fails++;
    }
    if (out[0] != EAP_CODE_RESPONSE) { printf("  [FAIL] code\n"); fails++; }
    if (out[1] != 0x05)              { printf("  [FAIL] id\n");   fails++; }
    if (((out[2] << 8) | out[3]) != (int)total) {
        printf("  [FAIL] length field\n"); fails++;
    }
    if (out[4] != EAP_TYPE_IDENTITY) { printf("  [FAIL] type\n"); fails++; }
    if (memcmp(&out[5], id, strlen(id)) != 0) {
        printf("  [FAIL] identity bytes\n"); fails++;
    }
    if (fails == 0) printf("  [OK]   built packet round-trips structure\n");
    return fails;
}

static int test_eap_tls_rx_single_fragment(void)
{
    /* Single inbound fragment with neither L nor M set. */
    static const uint8_t payload[] = {
        0x00,                            /* Flags = 0                 */
        'h','e','l','l','o','-','t','l','s'   /* fake TLS bytes        */
    };
    struct eap_tls_io io;
    uint8_t flags;
    int     fails = 0;

    printf("Test 4: EAP-TLS receive (single fragment)\n");
    eap_tls_io_reset(&io);
    if (eap_tls_rx_fragment(&io, payload, sizeof(payload), &flags) != 0) {
        printf("  [FAIL] rx_fragment\n"); return 1;
    }
    if (!io.rx_complete) { printf("  [FAIL] not marked complete\n"); fails++; }
    if (io.rx_filled != 9) { printf("  [FAIL] rx_filled=%zu\n", io.rx_filled); fails++; }
    if (memcmp(io.rx_buf, "hello-tls", 9) != 0) {
        printf("  [FAIL] payload bytes\n"); fails++;
    }
    if (fails == 0) printf("  [OK]   fragment buffered, complete flag set\n");
    return fails;
}

static int test_eap_tls_rx_multi_fragment(void)
{
    /* Three fragments: first with L+M, middle with M, last without M. */
    /* Total payload: 20 bytes "wolfssl-rocks-tls13!"
     * frag1: flags=L|M(0xC0), len=20 BE, 8 bytes
     * frag2: flags=M(0x40),  6 bytes
     * frag3: flags=0,         6 bytes
     */
    static const uint8_t f1[] = {
        0xC0, 0x00,0x00,0x00,0x14, 'w','o','l','f','s','s','l','-'
    };
    static const uint8_t f2[] = { 0x40, 'r','o','c','k','s','-' };
    static const uint8_t f3[] = { 0x00, 't','l','s','1','3','!' };
    struct eap_tls_io io;
    uint8_t fl;
    int fails = 0;

    printf("Test 5: EAP-TLS receive (3-fragment reassembly)\n");
    eap_tls_io_reset(&io);
    if (eap_tls_rx_fragment(&io, f1, sizeof(f1), &fl) != 0
        || (fl & EAP_TLS_FLAG_L) == 0
        || (fl & EAP_TLS_FLAG_M) == 0
        || io.rx_complete) {
        printf("  [FAIL] frag1\n"); return 1;
    }
    if (io.rx_total != 20) { printf("  [FAIL] declared total %zu\n", io.rx_total); fails++; }
    if (eap_tls_rx_fragment(&io, f2, sizeof(f2), &fl) != 0
        || (fl & EAP_TLS_FLAG_M) == 0 || io.rx_complete) {
        printf("  [FAIL] frag2\n"); return 1;
    }
    if (eap_tls_rx_fragment(&io, f3, sizeof(f3), &fl) != 0
        || !io.rx_complete) {
        printf("  [FAIL] frag3\n"); return 1;
    }
    if (io.rx_filled != 20 || memcmp(io.rx_buf,
                                     "wolfssl-rocks-tls13!", 20) != 0) {
        printf("  [FAIL] reassembled bytes\n"); fails++;
    }
    if (fails == 0) printf("  [OK]   reassembly complete and correct\n");
    return fails;
}

static int test_eap_tls_tx_fragmentation(void)
{
    /* Fill 1500 bytes of outbound TLS, fragment with 600-byte MTU. */
    struct eap_tls_io io;
    uint8_t out[800];
    size_t  payload_len;
    int     more;
    size_t  total_sent = 0;
    int     frag_count = 0;
    int     first_seen_L = -1;
    int     fails = 0;
    size_t  i;

    printf("Test 6: EAP-TLS transmit fragmentation\n");
    eap_tls_io_reset(&io);
    /* Synthesize 1500 bytes of pretend TLS output. */
    for (i = 0; i < 1500U; i++) {
        io.tx_buf[i] = (uint8_t)i;
    }
    io.tx_filled = 1500U;
    io.tx_drained = 0;
    io.tx_first_frag = 1;

    while (1) {
        if (eap_tls_tx_fragment(&io, out, 600U, &payload_len, &more) != 0) {
            printf("  [FAIL] tx_fragment\n"); return 1;
        }
        if (frag_count == 0) {
            first_seen_L = (out[0] & EAP_TLS_FLAG_L) ? 1 : 0;
        }
        /* Subtract framing overhead. */
        if (out[0] & EAP_TLS_FLAG_L) {
            total_sent += payload_len - 5U;
        }
        else {
            total_sent += payload_len - 1U;
        }
        frag_count++;
        if (!more) break;
        if (frag_count > 10) { printf("  [FAIL] runaway\n"); return 1; }
    }
    if (!first_seen_L) {
        printf("  [FAIL] first fragment must set L bit\n"); fails++;
    }
    if (total_sent != 1500U) {
        printf("  [FAIL] total bytes shipped %zu\n", total_sent); fails++;
    }
    if (frag_count < 3) {
        printf("  [FAIL] expected >=3 fragments for 1500B over 600B MTU\n");
        fails++;
    }
    if (fails == 0) {
        printf("  [OK]   1500B across %d fragments, L bit on first only\n",
               frag_count);
    }
    return fails;
}

int main(void)
{
    int fails = 0;
    fails += test_eap_parse_identity_request();
    fails += test_eap_parse_short_rejected();
    fails += test_eap_build_identity_response();
    fails += test_eap_tls_rx_single_fragment();
    fails += test_eap_tls_rx_multi_fragment();
    fails += test_eap_tls_tx_fragmentation();
    if (fails == 0) {
        printf("\nAll EAP framing tests passed.\n");
        return 0;
    }
    printf("\n%d EAP framing test failure(s).\n", fails);
    return 1;
}

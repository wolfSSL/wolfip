/* test_cyw43_sdpcm.c - host unit tests for the CYW43439 driver's
 * hardware-independent SDPCM/BDC framing and gSPI command packing.
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
 * Links only cyw43_sdpcm.o - no wolfSSL, no Pico. These exercise exactly the
 * bounds/packing logic where an off-by-one or modulo-256 wrap would cause a
 * silent OOB read on real silicon.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "cyw43_sdpcm.h"

#define CHECK(cond, name) do {                          \
        if (cond) { printf("  [OK]   %s\n", name); }    \
        else { printf("  [FAIL] %s\n", name); fails++; }\
    } while (0)

/* Build a valid SDPCM SW header (12 bytes) for a `total`-byte frame. */
static void put_swhdr(uint8_t *b, uint16_t total, uint8_t seq, uint8_t chan,
                      uint8_t flow, uint8_t credit)
{
    memset(b, 0, 12);
    b[0] = (uint8_t)total;
    b[1] = (uint8_t)(total >> 8);
    b[2] = (uint8_t)~b[0];
    b[3] = (uint8_t)~b[1];
    b[4] = seq;
    b[5] = chan;
    b[7] = 12U;          /* hlen */
    b[8] = flow;
    b[9] = credit;
}

static int test_gspi_cmd(void)
{
    int fails = 0;
    printf("Test 1: gspi_cmd packing\n");
    /* WRITE | INC | FUNC(2) | ADDR(0) | LEN(64) = 0xE0000040. */
    CHECK(cyw43_gspi_cmd(1, 2U, 0U, 64U) == 0xE0000040U, "write F2 len64");
    /* read (no WRITE) | INC | FUNC(2) | LEN(64) = 0x60000040. */
    CHECK(cyw43_gspi_cmd(0, 2U, 0U, 64U) == 0x60000040U, "read F2 len64");
    /* Field masks: fn&3, addr&0x1FFFF, len&0x7FF. */
    CHECK(cyw43_gspi_cmd(0, 7U, 0x1FFFFU, 0x7FFU)
          == (0x40000000U | (3U << 28) | (0x1FFFFU << 11) | 0x7FFU),
          "field masking");
    CHECK((cyw43_gspi_cmd(0, 0U, 0x20000U, 0x800U) & 0x7FFU) == 0U
          && ((cyw43_gspi_cmd(0, 0U, 0x20000U, 0x800U) >> 11) & 0x1FFFFU) == 0U,
          "addr/len overflow bits dropped");
    return fails;
}

static int test_sdpcm_hdr(void)
{
    uint8_t b[12];
    int fails = 0;
    printf("Test 2: sdpcm_hdr build\n");
    memset(b, 0xEE, sizeof(b));
    cyw43_sdpcm_hdr(b, 2U, 0x0123U, 0x55U);
    CHECK(b[0] == 0x23 && b[1] == 0x01, "size LE");
    CHECK(b[2] == (uint8_t)~b[0] && b[3] == (uint8_t)~b[1], "size complement");
    CHECK(b[4] == 0x55 && b[5] == 2U && b[7] == 12U, "seq/chan/hlen");
    return fails;
}

static int test_credit(void)
{
    uint8_t tx_max, flow;
    int fails = 0;
    printf("Test 3: sdpcm credit/flow + tx_ready\n");

    tx_max = 4U; flow = 0U;
    cyw43_sdpcm_credit_update(0U, 6U, &tx_max, &flow);   /* delta 2 <= 0x40 */
    CHECK(tx_max == 6U && flow == 0U, "sane credit advance accepted");

    tx_max = 4U; flow = 0U;
    cyw43_sdpcm_credit_update(0U, 200U, &tx_max, &flow); /* delta 196 > 0x40 */
    CHECK(tx_max == 4U, "garbage credit jump ignored");

    cyw43_sdpcm_credit_update(1U, 8U, &tx_max, &flow);   /* flow paused */
    CHECK(flow == 1U, "flow byte latched");

    /* tx_ready: window = tx_max - tx_seq (mod 256). */
    CHECK(cyw43_sdpcm_tx_ready(5U, 4U, 0U) == 1, "ready: window 1, not paused");
    CHECK(cyw43_sdpcm_tx_ready(4U, 4U, 0U) == 0, "not ready: window 0");
    CHECK(cyw43_sdpcm_tx_ready(5U, 4U, 1U) == 0, "not ready: flow paused");
    CHECK(cyw43_sdpcm_tx_ready(3U, 4U, 0U) == 0, "not ready: wrapped negative");
    /* modulo-256 wrap: tx_max=2, tx_seq=255 -> window=3, valid. */
    CHECK(cyw43_sdpcm_tx_ready(2U, 255U, 0U) == 1, "ready across mod-256 wrap");
    return fails;
}

static int test_iovar_build(void)
{
    uint8_t out[128];
    uint8_t val[4] = { 1, 2, 3, 4 };
    uint32_t outlen = 0;
    int fails = 0;
    printf("Test 4: iovar build + overflow guard\n");

    CHECK(cyw43_iovar_build("ampdu", val, 4U, out, sizeof(out), &outlen) == 0
          && outlen == 6U + 4U
          && memcmp(out, "ampdu", 6) == 0
          && memcmp(out + 6, val, 4) == 0, "name+value framed");

    CHECK(cyw43_iovar_build("x", NULL, 0U, out, sizeof(out), &outlen) == 0
          && outlen == 2U, "no-value iovar");

    /* Overflow: huge vlen must be rejected without wrapping. */
    CHECK(cyw43_iovar_build("k", val, 0xFFFFFFFFU, out, sizeof(out),
                            &outlen) == -1, "huge vlen rejected (no wrap)");
    /* value exactly fills / just overflows. */
    CHECK(cyw43_iovar_build("ab", val, 13U, out, 16U, &outlen) == 0,
          "fits exactly (3 name + 13 val = 16)");
    CHECK(cyw43_iovar_build("ab", val, 14U, out, 16U, &outlen) == -1,
          "one over capacity rejected");
    return fails;
}

static int test_rlen_validate_hlen(void)
{
    uint8_t b[64];
    uint32_t size = 0;
    uint8_t  chan = 0xFF;
    int fails = 0;
    printf("Test 5: rlen_ok / validate / hlen_ok\n");

    CHECK(cyw43_sdpcm_rlen_ok(12U, 2048U) == 1, "rlen 12 ok");
    CHECK(cyw43_sdpcm_rlen_ok(11U, 2048U) == 0, "rlen < 12 rejected");
    CHECK(cyw43_sdpcm_rlen_ok(2045U, 2048U) == 1, "rlen 2045 (pads to 2048) ok");
    CHECK(cyw43_sdpcm_rlen_ok(2049U, 2048U) == 0, "padded read overflow rejected");

    put_swhdr(b, 40U, 1U, 2U, 0U, 8U);
    CHECK(cyw43_sdpcm_validate(b, 40U, &size, &chan) == CYW43_RX_OK
          && size == 40U && chan == 2U, "valid header accepted");

    b[2] ^= 0x01;   /* break size complement */
    CHECK(cyw43_sdpcm_validate(b, 40U, &size, &chan) == CYW43_RX_ERR_SUM,
          "checksum mismatch rejected");

    put_swhdr(b, 0U, 1U, 2U, 0U, 8U);   /* size == 0 */
    CHECK(cyw43_sdpcm_validate(b, 40U, &size, &chan) == CYW43_RX_ERR_SUM,
          "size == 0 rejected");

    put_swhdr(b, 50U, 1U, 2U, 0U, 8U);  /* size 50 > rlen 40 */
    CHECK(cyw43_sdpcm_validate(b, 40U, &size, &chan) == CYW43_RX_ERR_OVER,
          "size > rlen rejected");

    CHECK(cyw43_sdpcm_hlen_ok(12U, 40U) == 1, "hlen 12 fits size 40");
    CHECK(cyw43_sdpcm_hlen_ok(12U, 15U) == 0, "hlen+4 > size rejected");
    return fails;
}

static int test_bdc_payload(void)
{
    uint8_t b[80];
    uint32_t off = 0, len = 0;
    uint16_t etype = 0;
    int fails = 0;
    printf("Test 6: BDC payload extract + bounds\n");

    /* size 50, hlen 12, BDC data_offset words = 0 -> doff 4, payload at 16. */
    put_swhdr(b, 50U, 1U, 2U, 0U, 8U);
    b[12 + 3] = 0U;                          /* BDC data_offset (words) */
    memset(&b[16], 0, 50U - 16U);
    b[16 + 12] = 0x08; b[16 + 13] = 0x00;    /* ethertype 0x0800 (IP)   */
    CHECK(cyw43_sdpcm_bdc_payload(b, 12U, 50U, &off, &len, &etype) == 0
          && off == 16U && len == 34U && etype == 0x0800U,
          "valid BDC payload extracted");

    /* Oversized data_offset that runs past size must be rejected. */
    put_swhdr(b, 30U, 1U, 2U, 0U, 8U);
    b[12 + 3] = 40U;   /* doff = 4 + 160 = 164, well past size 30 */
    CHECK(cyw43_sdpcm_bdc_payload(b, 12U, 30U, &off, &len, &etype) == -1,
          "oversized data_offset rejected");
    return fails;
}

int main(void)
{
    int fails = 0;
    fails += test_gspi_cmd();
    fails += test_sdpcm_hdr();
    fails += test_credit();
    fails += test_iovar_build();
    fails += test_rlen_validate_hlen();
    fails += test_bdc_payload();
    if (fails == 0) {
        printf("\nAll cyw43_sdpcm tests passed.\n");
        return 0;
    }
    printf("\n%d cyw43_sdpcm test failure(s).\n", fails);
    return 1;
}

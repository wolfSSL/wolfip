/* cyw43_sdpcm.c - hardware-independent SDPCM/BDC framing for the CYW43439.
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
 * Pure logic only (no MMIO, no static state). See cyw43_sdpcm.h.
 */
#include "cyw43_sdpcm.h"
#include <string.h>

/* gSPI command word fields (see cyw43439_driver.c GSPI_CMD_* for the source
 * definitions; reproduced here so this unit stays hardware-header-free). */
#define GSPI_CMD_WRITE   (1U << 31)
#define GSPI_CMD_INC     (1U << 30)

uint32_t cyw43_gspi_cmd(int write, uint32_t fn, uint32_t addr, uint32_t nbytes)
{
    return (write ? GSPI_CMD_WRITE : 0U) | GSPI_CMD_INC
         | ((uint32_t)(fn & 3U) << 28)
         | ((uint32_t)(addr & 0x1FFFFU) << 11)
         | (uint32_t)(nbytes & 0x7FFU);
}

void cyw43_sdpcm_hdr(uint8_t *buf, uint8_t chan, uint32_t total, uint8_t seq)
{
    buf[0] = (uint8_t)total;
    buf[1] = (uint8_t)(total >> 8);
    buf[2] = (uint8_t)~buf[0];
    buf[3] = (uint8_t)~buf[1];
    buf[4] = seq;
    buf[5] = chan;
    buf[7] = 12U;                       /* header length */
}

void cyw43_sdpcm_credit_update(uint8_t flow_byte, uint8_t credit_byte,
                               uint8_t *tx_max, uint8_t *flow_ctl)
{
    uint8_t delta = (uint8_t)(credit_byte - *tx_max);
    *flow_ctl = flow_byte;
    if (delta <= 0x40U) {
        *tx_max = credit_byte;
    }
}

int cyw43_sdpcm_tx_ready(uint8_t tx_max, uint8_t tx_seq, uint8_t flow_ctl)
{
    uint8_t window = (uint8_t)(tx_max - tx_seq);
    return (flow_ctl == 0U) && (window != 0U) && ((window & 0x80U) == 0U);
}

int cyw43_iovar_build(const char *name, const uint8_t *val, uint32_t vlen,
                      uint8_t *out, size_t outcap, uint32_t *outlen)
{
    uint32_t nlen = (uint32_t)strlen(name) + 1U;
    /* Overflow-safe bound: nlen + vlen could wrap 2^32 if vlen were huge,
     * bypassing a naive (nlen + vlen > outcap) check. */
    if ((size_t)nlen > outcap || (size_t)vlen > outcap - (size_t)nlen) {
        return -1;
    }
    memcpy(out, name, nlen);
    if (vlen != 0U) {
        memcpy(out + nlen, val, vlen);
    }
    *outlen = nlen + vlen;
    return 0;
}

int cyw43_sdpcm_rlen_ok(uint32_t rlen, uint32_t iobuf_sz)
{
    /* The PIO read rounds the length up to a 4-byte multiple; guard on that
     * padded size so the read can never write past the buffer even if the
     * buffer size or the F2 length mask change. */
    return (rlen >= 12U) && (((rlen + 3U) & ~3U) <= iobuf_sz);
}

int cyw43_sdpcm_validate(const uint8_t *buf, uint32_t rlen,
                         uint32_t *size, uint8_t *chan)
{
    uint32_t sz      = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8);
    uint32_t sz_com  = (uint32_t)buf[2] | ((uint32_t)buf[3] << 8);

    if ((uint16_t)(sz ^ sz_com) != 0xFFFFU || sz == 0U) {
        return CYW43_RX_ERR_SUM;
    }
    /* A corrupt-but-self-consistent header must not declare more than was
     * actually read, or a payload index could run past the buffer. */
    if (sz > rlen) {
        return CYW43_RX_ERR_OVER;
    }
    *size = sz;
    *chan = (uint8_t)(buf[5] & 0x0FU);
    return CYW43_RX_OK;
}

int cyw43_sdpcm_hlen_ok(uint8_t hlen, uint32_t size)
{
    return ((uint32_t)hlen + 4U) <= size;
}

int cyw43_sdpcm_bdc_payload(const uint8_t *buf, uint8_t hlen, uint32_t size,
                            uint32_t *pay_off, uint32_t *pay_len,
                            uint16_t *etype)
{
    /* BDC data_offset is in 4-byte words at buf[hlen + 3]; the 802.3 frame
     * (>= a 14-byte Ethernet header) follows it. */
    uint32_t doff = 4U + ((uint32_t)buf[hlen + 3U] << 2);
    uint32_t off;

    if ((uint32_t)hlen + doff + 14U > size) {
        return -1;
    }
    off = (uint32_t)hlen + doff;
    *pay_off = off;
    *pay_len = size - off;
    *etype   = (uint16_t)(((uint16_t)buf[off + 12U] << 8) | buf[off + 13U]);
    return 0;
}

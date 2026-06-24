/* cyw43_sdpcm.h - hardware-independent SDPCM/BDC framing + gSPI command
 * packing for the CYW43439 driver.
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
 * These helpers are pure logic - no MMIO, no static state - so they compile and
 * run on the host and are exercised by test_cyw43_sdpcm.c. cyw43439_driver.c
 * keeps the PIO/SPI transport and delegates the framing/bounds arithmetic
 * here, the same way the supplicant keeps its transport separate from the
 * eapol/eap/rsn_ie framing units.
 */
#ifndef CYW43_SDPCM_H
#define CYW43_SDPCM_H

#include <stdint.h>
#include <stddef.h>

/* gSPI command word: WRITE? | INC(always) | FUNC(fn&3) | ADDR(addr&0x1FFFF) |
 * LEN(nbytes&0x7FF). */
uint32_t cyw43_gspi_cmd(int write, uint32_t fn, uint32_t addr,
                        uint32_t nbytes);

/* Write the 12-byte SDPCM software header for a `total`-byte frame on channel
 * `chan` using sequence number `seq`. `buf` must be >= 12 bytes and is assumed
 * zeroed by the caller (bytes 6 and 8..11 are left untouched). */
void cyw43_sdpcm_hdr(uint8_t *buf, uint8_t chan, uint32_t total, uint8_t seq);

/* Update the TX credit/flow state from a received SDPCM header's flow byte
 * (hdr[8]) and credit byte (hdr[9]). *tx_max advances only on a sane (<= 0x40)
 * modulo-256 jump so a garbage credit cannot run the window away. */
void cyw43_sdpcm_credit_update(uint8_t flow_byte, uint8_t credit_byte,
                               uint8_t *tx_max, uint8_t *flow_ctl);

/* 1 if the host may transmit now: not flow-paused, and tx_seq is inside the
 * granted modulo-256 window (window != 0 and not wrapped negative). */
int cyw43_sdpcm_tx_ready(uint8_t tx_max, uint8_t tx_seq, uint8_t flow_ctl);

/* Build a CDC iovar request (NUL-terminated `name` then `vlen` value bytes)
 * into out[0..outcap). Overflow-safe (no nlen+vlen wrap). Returns 0 and sets
 * *outlen on success, -1 if it would not fit. */
int cyw43_iovar_build(const char *name, const uint8_t *val, uint32_t vlen,
                      uint8_t *out, size_t outcap, uint32_t *outlen);

/* 1 if an `rlen` taken from the F2 status word is safe to read into an
 * `iobuf_sz`-byte buffer: at least a 12-byte SDPCM header, and the 4-byte
 * padded read does not overflow the buffer. */
int cyw43_sdpcm_rlen_ok(uint32_t rlen, uint32_t iobuf_sz);

/* SDPCM header validation results. */
#define CYW43_RX_OK         (0)
#define CYW43_RX_ERR_SUM    (-2)   /* size ^ size_com mismatch or size == 0   */
#define CYW43_RX_ERR_OVER   (-3)   /* declared size > bytes actually read     */

/* Validate the SDPCM size/size_com checksum and that the declared size does
 * not exceed `rlen` (the bytes actually clocked into `buf`). On CYW43_RX_OK,
 * sets *size and *chan (buf[5] & 0x0F). Does NOT touch credit/flow or the
 * header-length field (the caller updates credit then checks hlen, preserving
 * the order in which a corrupt header is rejected). */
int cyw43_sdpcm_validate(const uint8_t *buf, uint32_t rlen,
                         uint32_t *size, uint8_t *chan);

/* 1 if the SDPCM header-length field leaves room for at least the 4-byte
 * BDC/CDC sub-header within `size`. */
int cyw43_sdpcm_hlen_ok(uint8_t hlen, uint32_t size);

/* For a DATA-channel frame, validate the BDC data_offset and extract the
 * 802.3 payload offset/length and ethertype. Returns 0 on success (the
 * payload is buf[*pay_off .. *pay_off + *pay_len), with *pay_len >= 14), or
 * -1 if the BDC offset + an Ethernet header would run past `size`. */
int cyw43_sdpcm_bdc_payload(const uint8_t *buf, uint8_t hlen, uint32_t size,
                            uint32_t *pay_off, uint32_t *pay_len,
                            uint16_t *etype);

#endif /* CYW43_SDPCM_H */

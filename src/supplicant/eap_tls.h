/* eap_tls.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfIP.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* EAP-TLS framing per RFC 5216 (TLS 1.0-1.2) and RFC 9190 (TLS 1.3).
 *
 * Each EAP-TLS packet's Type-Data starts with a 1-byte Flags field:
 *
 *   bit 7  L: Length included (next 4 bytes are total TLS message size BE)
 *   bit 6  M: More fragments follow
 *   bit 5  S: EAP-TLS Start (server's initial Request, no TLS data)
 *   bit 4  Reserved (RFC 9190 uses bit 4 for "Outer TLVs" in EAP-TEAP only)
 *   bits 0-2 Version. RFC 5216 = 0; RFC 9190 keeps 0 for compatibility.
 *
 * After Flags (and optional 4-byte length on the first fragment) come
 * the TLS handshake bytes, possibly fragmented across multiple EAP
 * packets.
 *
 * The supplicant treats inbound TLS fragments as a stream: it appends
 * each fragment's payload to an inbound buffer, then drives wolfSSL via
 * a custom IORecv callback that pulls from that buffer. The outbound
 * direction works in reverse: wolfSSL IOSend appends to an outbound
 * buffer; the supplicant drains it into one or more EAP-TLS Response
 * packets, fragmenting as needed for the MTU.
 */

#ifndef WOLFIP_SUPPLICANT_EAP_TLS_H
#define WOLFIP_SUPPLICANT_EAP_TLS_H

#include <stdint.h>
#include <stddef.h>

#define EAP_TLS_FLAG_L      0x80U   /* Length included          */
#define EAP_TLS_FLAG_M      0x40U   /* More fragments           */
#define EAP_TLS_FLAG_S      0x20U   /* EAP-TLS Start            */
#define EAP_TLS_VERSION_MASK 0x07U  /* bits 0..2                */

/* RFC 5216 requires an EAP-TLS Response to acknowledge a fragmented
 * inbound packet that has the M bit set. The ACK is an EAP-Response
 * with Type=EAP-TLS and a single Flags byte = 0. */
#define EAP_TLS_ACK_LEN     1U

#ifndef WOLFIP_SUPPLICANT_EAP_FRAG_SIZE
/* Reassembly buffer for EAP-TLS rx + tx. Each direction allocates one
 * buffer of this size inside struct eap_tls_io, so total cost is 2x
 * per supplicant context. The 2048 default suits an MCU port that pins
 * a single self-signed (or short-chain) cert; it keeps the per-context
 * RAM cost to 4 KB. Bump to 4096 for TLS 1.2 cert chains with one or
 * two intermediates, or 8192 if your CA chain is deeper. */
#define WOLFIP_SUPPLICANT_EAP_FRAG_SIZE 2048U
#endif

#ifndef WOLFIP_SUPPLICANT_EAP_MTU
/* Per-fragment payload byte budget. Conservative default to fit a
 * single EAPOL frame within a typical 1500-byte Ethernet MTU after
 * EAP/EAPOL/EAP-TLS overhead. */
#define WOLFIP_SUPPLICANT_EAP_MTU 1024U
#endif

/* Streaming reassembly + fragmentation state. The supplicant embeds
 * one of these inside its context when auth_mode = EAP-TLS. */
struct eap_tls_io {
    /* Inbound: TLS bytes received from the server, ready for wolfSSL
     * IORecv to consume. */
    uint8_t  rx_buf[WOLFIP_SUPPLICANT_EAP_FRAG_SIZE];
    size_t   rx_total;       /* declared total of current message (0=unknown) */
    size_t   rx_filled;      /* bytes received so far                         */
    size_t   rx_drained;     /* bytes already handed to wolfSSL IORecv        */
    int      rx_complete;    /* M bit cleared in the last fragment            */

    /* Outbound: TLS bytes produced by wolfSSL IOSend, waiting to be
     * sliced into EAP-TLS Response packets. */
    uint8_t  tx_buf[WOLFIP_SUPPLICANT_EAP_FRAG_SIZE];
    size_t   tx_filled;      /* total bytes wolfSSL produced this round     */
    size_t   tx_drained;     /* bytes already encapsulated and sent         */
    int      tx_first_frag;  /* 1 until the first fragment has been emitted */
};

#ifdef __cplusplus
extern "C" {
#endif

void eap_tls_io_reset(struct eap_tls_io *io);

/* Parse one inbound EAP-TLS payload (Type-Data of an EAP-Request,
 * Code=Request, Type=EAP-TLS). Appends TLS data into io->rx_buf and
 * updates rx_total / rx_complete based on the L/M flag bits.
 *
 * type_data points at the Flags byte. type_data_len is the length of
 * the EAP-TLS payload (Flags + optional length + TLS bytes).
 *
 * out_flags is set to the Flags byte for caller inspection.
 *
 * Returns:
 *   1  - this was a Start packet (S bit), no TLS data appended
 *   0  - TLS data appended (possibly completing a message)
 *  -1  - malformed input
 */
int eap_tls_rx_fragment(struct eap_tls_io *io,
                        const uint8_t *type_data, size_t type_data_len,
                        uint8_t *out_flags);

/* Pull one fragment of outbound TLS bytes from io->tx_buf, encapsulate
 * it as an EAP-TLS Response payload (Flags + optional length + bytes),
 * and write into out. Caller already reserved space for an EAP header
 * and is constructing the EAP packet body Type-Data area.
 *
 * mtu is the maximum bytes available for this Type-Data (1 Flags byte
 * + optional 4 length bytes + TLS bytes).
 *
 * On return:
 *   *out_payload_len = bytes written
 *   *out_more        = 1 if there are still TLS bytes pending after
 *                      this fragment (caller should expect another
 *                      Request from the server to ACK and pull the
 *                      next), 0 if this was the final fragment.
 *
 * Returns 0 on success, -1 if mtu too small.
 */
int eap_tls_tx_fragment(struct eap_tls_io *io,
                        uint8_t *out, size_t mtu,
                        size_t *out_payload_len, int *out_more);

/* Build an EAP-TLS ACK (single Flags=0 byte). */
int eap_tls_build_ack(uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_SUPPLICANT_EAP_TLS_H */

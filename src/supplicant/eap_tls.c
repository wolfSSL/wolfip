/* eap_tls.c
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

#include "eap_tls.h"

#include <string.h>

void eap_tls_io_reset(struct eap_tls_io *io)
{
    if (io == NULL) {
        return;
    }
    memset(io, 0, sizeof(*io));
    io->tx_first_frag = 1;
}

static uint32_t rd32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8)
         |  (uint32_t)p[3];
}

static void wr32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v      );
}

int eap_tls_rx_fragment(struct eap_tls_io *io,
                        const uint8_t *type_data, size_t type_data_len,
                        uint8_t *out_flags)
{
    size_t   off;
    uint8_t  flags;
    uint32_t declared_total;
    size_t   tls_len;

    if (io == NULL || type_data == NULL || out_flags == NULL) {
        return -1;
    }
    if (type_data_len < 1U) {
        return -1;
    }
    flags = type_data[0];
    *out_flags = flags;
    off = 1U;

    /* A previously completed message that the engine has not yet consumed
     * must not bleed into this one: a fresh inbound fragment begins a new
     * logical message, so drop the stale reassembly state first. */
    if (io->rx_complete) {
        io->rx_filled   = 0;
        io->rx_total    = 0;
        io->rx_complete = 0;
        /* rx_drained is otherwise only cleared by eap_tls_io_recv after a full
         * drain; if the engine left the completed message partially drained,
         * a stale offset here would desync (skip/abort) the next message. */
        io->rx_drained  = 0;
    }

    /* Start packet has no TLS data and no length field. */
    if ((flags & EAP_TLS_FLAG_S) != 0U) {
        /* Server-initiated Start. Spec mandates no TLS data, but some
         * implementations include version. Ignore any trailing bytes. */
        return 1;
    }

    if ((flags & EAP_TLS_FLAG_L) != 0U) {
        if (type_data_len < off + 4U) {
            return -1;
        }
        declared_total = rd32_be(&type_data[off]);
        off += 4U;
        /* Lock the declared total the first time the L bit is seen. A
         * conformant peer sets it on the first fragment, but accept it on a
         * later fragment too (rx_total still 0) so the over-long-stream bound
         * engages even for a non-conformant M-without-L-then-L stream. The
         * total must fit our buffer and cover what we have already buffered. */
        if (io->rx_total == 0U) {
            if (declared_total > sizeof(io->rx_buf)
                || declared_total < io->rx_filled) {
                /* Server intends to send more than we can buffer, or less
                 * than already received. */
                return -1;
            }
            io->rx_total = declared_total;
        }
    }
    tls_len = type_data_len - off;
    if (tls_len > 0U) {
        if (io->rx_filled + tls_len > sizeof(io->rx_buf)) {
            return -1;
        }
        /* Never accept more than the declared total once it is known
         * (reassembly desync / over-long fragment stream). */
        if (io->rx_total != 0U && io->rx_filled + tls_len > io->rx_total) {
            return -1;
        }
        memcpy(io->rx_buf + io->rx_filled, &type_data[off], tls_len);
        io->rx_filled += tls_len;
    }
    /* "More fragments" not set => last (or only) fragment. */
    if ((flags & EAP_TLS_FLAG_M) == 0U) {
        io->rx_complete = 1;
        /* If the L bit was never seen, retroactively set total. */
        if (io->rx_total == 0U) {
            io->rx_total = io->rx_filled;
        }
    }
    return 0;
}

int eap_tls_tx_fragment(struct eap_tls_io *io,
                        uint8_t *out, size_t mtu,
                        size_t *out_payload_len, int *out_more)
{
    size_t  remaining;
    size_t  payload_off;
    size_t  take;
    int     first;
    int     more;
    uint8_t flags;

    if (io == NULL || out == NULL || out_payload_len == NULL
        || out_more == NULL) {
        return -1;
    }
    if (mtu < 1U) {
        return -1;
    }
    if (io->tx_filled < io->tx_drained) {
        return -1;
    }
    remaining = io->tx_filled - io->tx_drained;
    first = io->tx_first_frag;

    /* Reserve 1 byte for Flags and (on first fragment of a multi-frag
     * message) 4 bytes for length. */
    payload_off = 1U;
    if (first && remaining + payload_off > mtu) {
        /* Need length field. */
        payload_off += 4U;
    }
    if (mtu < payload_off) {
        return -1;
    }
    take = mtu - payload_off;
    if (take > remaining) {
        take = remaining;
    }
    more = (take < remaining) ? 1 : 0;
    /* A non-final fragment carrying no payload (mtu == payload_off) makes no
     * forward progress; reject rather than emit a header-only fragment. */
    if (take == 0U && more) {
        return -1;
    }

    flags = 0U;
    if (first && more) {
        flags |= EAP_TLS_FLAG_L;
    }
    if (more) {
        flags |= EAP_TLS_FLAG_M;
    }
    out[0] = flags;
    if ((flags & EAP_TLS_FLAG_L) != 0U) {
        wr32_be(&out[1], (uint32_t)remaining);
    }
    if (take > 0U) {
        memcpy(out + payload_off,
               io->tx_buf + io->tx_drained, take);
    }
    io->tx_drained  += take;
    io->tx_first_frag = more ? 0 : 1;
    *out_payload_len = payload_off + take;
    *out_more        = more;

    /* When the message is fully drained, reset the outbound state so
     * the next wolfSSL write starts a fresh message. */
    if (!more) {
        io->tx_filled    = 0U;
        io->tx_drained   = 0U;
        io->tx_first_frag = 1;
    }
    return 0;
}

int eap_tls_build_ack(uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return -1;
    }
    if (out_cap < EAP_TLS_ACK_LEN) {
        return -1;
    }
    out[0] = 0U;
    *out_len = EAP_TLS_ACK_LEN;
    return 0;
}

/* macsec_sa.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfIP.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfIP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Stateful 802.1AE Secure Association layer. Wraps the stateless SecY
 * transform (macsec_secy.c) with the per-SA packet-number counter (transmit)
 * and the replay window (receive) that a real SecY maintains. This is the
 * seam the wolfIP datapath drives: outbound frames go through macsec_tx()
 * before ll->send, inbound MACsec frames (EtherType 0x88E5) through
 * macsec_rx() after the link-layer demux. The SAK is installed here by the
 * MKA install_sak callback (see mka.h).
 */

#ifndef WOLFIP_MACSEC_SA_H
#define WOLFIP_MACSEC_SA_H

#include <stdint.h>
#include <stddef.h>

#include "macsec_secy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes for macsec_rx(). */
#define MACSEC_RX_OK            0
#define MACSEC_RX_AUTH_FAIL   (-1)   /* ICV / GCM authentication failed     */
#define MACSEC_RX_REPLAY      (-2)   /* PN below the replay window          */
#define MACSEC_RX_BAD_ARG     (-3)

/* PN exhaustion: 0xFFFFFFFF is the last usable 32-bit packet number; a fresh
 * SAK must be installed before it wraps (XPN is out of scope). */
#define MACSEC_PN_MAX         0xFFFFFFFFUL

/* Transmit Secure Channel + its current Secure Association. */
struct macsec_tx_sc {
    uint8_t  sak[MACSEC_KEY_LEN_MAX];
    size_t   sak_len;                  /* 16 or 32; 0 = no key installed     */
    uint8_t  sci[MACSEC_SCI_LEN];      /* our SCI                            */
    uint32_t next_pn;                  /* next packet number to transmit     */
    size_t   conf_offset;              /* 0/30/50                            */
    uint8_t  an;                       /* Association Number                 */
    uint8_t  encrypt;                  /* 1 = confidentiality, 0 = integrity */
    uint8_t  include_sci;              /* set SC bit / include SCI in SecTAG */
    uint8_t  in_use;
};

/* Receive Secure Channel + its current Secure Association. */
struct macsec_rx_sc {
    uint8_t  sak[MACSEC_KEY_LEN_MAX];
    size_t   sak_len;
    uint8_t  sci[MACSEC_SCI_LEN];      /* peer SCI (nonce fallback)          */
    uint32_t lowest_pn;                /* replay window lower bound          */
    uint32_t replay_window;            /* frames of reorder tolerated        */
    size_t   conf_offset;
    uint8_t  an;
    uint8_t  replay_protect;
    uint8_t  in_use;
};

/* Install a SAK on the transmit SC. initial_pn is normally 1 (PN 0 is
 * invalid). encrypt selects confidentiality vs integrity-only; conf_offset is
 * 0/30/50. Returns 0 on success. */
int macsec_tx_sc_set_key(struct macsec_tx_sc *sc,
                         const uint8_t *sak, size_t sak_len,
                         const uint8_t sci[MACSEC_SCI_LEN], uint8_t an,
                         uint8_t encrypt, size_t conf_offset,
                         uint8_t include_sci, uint32_t initial_pn);

/* Install a SAK on the receive SC. replay_protect enables the window;
 * replay_window is the number of out-of-order frames tolerated below the
 * highest accepted PN. Returns 0 on success. */
int macsec_rx_sc_set_key(struct macsec_rx_sc *sc,
                         const uint8_t *sak, size_t sak_len,
                         const uint8_t peer_sci[MACSEC_SCI_LEN], uint8_t an,
                         uint8_t replay_protect, uint32_t replay_window,
                         size_t conf_offset);

/* Protect payload (a user MSDU starting at its EtherType) into a MACsec frame
 * using the SC's next PN, then advance the counter. Returns 0 on success,
 * MACSEC_RX_* / negative on error (including PN exhaustion -> rekey needed). */
int macsec_tx(struct macsec_tx_sc *sc,
              const uint8_t da[MACSEC_MAC_LEN],
              const uint8_t sa[MACSEC_MAC_LEN],
              const uint8_t *payload, size_t payload_len,
              uint8_t *out, size_t out_cap, size_t *out_len);

/* Validate a received MACsec frame and enforce the replay window. On success
 * the recovered MSDU is written to out and *out_len set. Returns
 * MACSEC_RX_OK, MACSEC_RX_AUTH_FAIL, MACSEC_RX_REPLAY, or MACSEC_RX_BAD_ARG. */
int macsec_rx(struct macsec_rx_sc *sc,
              const uint8_t *frame, size_t frame_len,
              uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_MACSEC_SA_H */

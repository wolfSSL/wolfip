/* macsec_sa.c
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

#include "macsec_sa.h"
#include "supplicant_features.h"
#include "wpa_crypto.h"          /* wpa_secure_zero */

#include <string.h>

static int macsec_sa_key_ok(size_t sak_len)
{
    return (sak_len == MACSEC_KEY_LEN_128 || sak_len == MACSEC_KEY_LEN_256);
}

int macsec_tx_sc_set_key(struct macsec_tx_sc *sc,
                         const uint8_t *sak, size_t sak_len,
                         const uint8_t sci[MACSEC_SCI_LEN], uint8_t an,
                         uint8_t encrypt, size_t conf_offset,
                         uint8_t include_sci, uint32_t initial_pn)
{
    if (sc == NULL || sak == NULL || sci == NULL || !macsec_sa_key_ok(sak_len)) {
        return MACSEC_RX_BAD_ARG;
    }
    if (an > MACSEC_AN_MASK || initial_pn == 0
        || (conf_offset != 0 && conf_offset != 30 && conf_offset != 50)) {
        return MACSEC_RX_BAD_ARG;
    }
    memset(sc, 0, sizeof(*sc));
    memcpy(sc->sak, sak, sak_len);
    sc->sak_len     = sak_len;
    memcpy(sc->sci, sci, MACSEC_SCI_LEN);
    sc->an          = an;
    sc->next_pn     = initial_pn;
    sc->conf_offset = conf_offset;
    sc->encrypt     = encrypt ? 1U : 0U;
    sc->include_sci = include_sci ? 1U : 0U;
    sc->in_use      = 1U;
    return 0;
}

int macsec_rx_sc_set_key(struct macsec_rx_sc *sc,
                         const uint8_t *sak, size_t sak_len,
                         const uint8_t peer_sci[MACSEC_SCI_LEN], uint8_t an,
                         uint8_t replay_protect, uint32_t replay_window,
                         size_t conf_offset)
{
    if (sc == NULL || sak == NULL || peer_sci == NULL
        || !macsec_sa_key_ok(sak_len)) {
        return MACSEC_RX_BAD_ARG;
    }
    if (an > MACSEC_AN_MASK
        || (conf_offset != 0 && conf_offset != 30 && conf_offset != 50)) {
        return MACSEC_RX_BAD_ARG;
    }
    memset(sc, 0, sizeof(*sc));
    memcpy(sc->sak, sak, sak_len);
    sc->sak_len        = sak_len;
    memcpy(sc->sci, peer_sci, MACSEC_SCI_LEN);
    sc->an             = an;
    sc->lowest_pn      = 1U;            /* PN 0 is invalid */
    sc->replay_window  = replay_window;
    sc->conf_offset    = conf_offset;
    sc->replay_protect = replay_protect ? 1U : 0U;
    sc->in_use         = 1U;
    return 0;
}

int macsec_tx(struct macsec_tx_sc *sc,
              const uint8_t da[MACSEC_MAC_LEN],
              const uint8_t sa[MACSEC_MAC_LEN],
              const uint8_t *payload, size_t payload_len,
              uint8_t *out, size_t out_cap, size_t *out_len)
{
    struct macsec_protect_params p;
    int ret;

    if (sc == NULL || !sc->in_use) {
        return MACSEC_RX_BAD_ARG;
    }
    /* PN exhausted: next_pn is parked at 0 once the ceiling has been used
     * (see below); a fresh SAK is required before it can wrap (802.1AE). */
    if (sc->next_pn == 0U) {
        return MACSEC_RX_BAD_ARG;
    }

    memset(&p, 0, sizeof(p));
    p.da          = da;
    p.sa          = sa;
    p.sci         = sc->sci;
    p.sak         = sc->sak;
    p.sak_len     = sc->sak_len;
    p.conf_offset = sc->conf_offset;
    p.pn          = sc->next_pn;
    p.an          = sc->an;
    p.encrypt     = sc->encrypt;
    p.include_sci = sc->include_sci;

    ret = macsec_protect(&p, payload, payload_len, out, out_cap, out_len);
    if (ret != 0) {
        return ret;
    }
    /* Advance only after a successful protect; stop at the ceiling so the
     * next call reports exhaustion rather than wrapping to 0. */
    if (sc->next_pn == MACSEC_PN_MAX) {
        sc->next_pn = 0U;              /* mark exhausted */
    }
    else {
        sc->next_pn++;
    }
    return 0;
}

int macsec_rx(struct macsec_rx_sc *sc,
              const uint8_t *frame, size_t frame_len,
              uint8_t *out, size_t out_cap, size_t *out_len)
{
    struct macsec_validate_params vp;
    struct macsec_sectag          tag;
    int ret;

    if (sc == NULL || !sc->in_use || frame == NULL || out == NULL
        || out_len == NULL) {
        return MACSEC_RX_BAD_ARG;
    }

    memset(&vp, 0, sizeof(vp));
    vp.sak         = sc->sak;
    vp.sak_len     = sc->sak_len;
    vp.sci         = sc->sci;
    vp.conf_offset = sc->conf_offset;

    /* Authenticate first: the replay window must only ever be tested and
     * advanced on an authenticated PN, so a forged PN cannot move it. */
    ret = macsec_validate(&vp, frame, frame_len, out, out_cap, out_len, &tag);
    if (ret != 0) {
        /* macsec_validate() returns -1 for an ICV/GCM authentication failure
         * and a distinct negative (BAD_FUNC_ARG) for a malformed/truncated
         * frame; keep them separate so callers can tell a forged frame from a
         * parse error. */
        return (ret == -1) ? MACSEC_RX_AUTH_FAIL : MACSEC_RX_BAD_ARG;
    }
    if (sc->replay_protect && tag.pn < sc->lowest_pn) {
        wpa_secure_zero(out, *out_len);
        *out_len = 0;
        return MACSEC_RX_REPLAY;
    }

    /* Advance the window: lowest acceptable PN becomes pn + 1 - window,
     * floored at 1, and never moves backwards. */
    if (sc->replay_protect) {
        uint32_t new_low;
        if (tag.pn >= sc->replay_window) {
            new_low = tag.pn - sc->replay_window + 1U;
        }
        else {
            new_low = 1U;
        }
        if (new_low > sc->lowest_pn) {
            sc->lowest_pn = new_low;
        }
    }
    return MACSEC_RX_OK;
}

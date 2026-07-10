/* fuzz_macsec_secy.c
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

/* libFuzzer harness for the 802.1AE SecY receive path. Feeds arbitrary bytes
 * to macsec_sectag_parse and macsec_validate: GCM authentication rejects
 * random frames, but the SecTAG parse and the length / header / offset bounds
 * math that run before decryption are fully exercised. Each confidentiality
 * offset (0/30/50) is tried. Build: make WOLFIP_ENABLE_MACSEC=1 build/fuzz-macsec-secy */

#include <stdint.h>
#include <string.h>

#include "macsec_secy.h"

static const uint8_t FZ_SAK[16] = {
    0xad,0x7a,0x2b,0xd0,0x3e,0xac,0x83,0x5a,
    0x6f,0x62,0x0f,0xdc,0xb5,0x06,0xb3,0x45
};
static const uint8_t FZ_SCI[8] = { 0x02,0,0,0,0,0x22,0x00,0x01 };

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct macsec_sectag          tag;
    struct macsec_validate_params vp;
    uint8_t out[2048];
    size_t  out_len;
    size_t  i;
    static const size_t offsets[3] = { 0U, 30U, 50U };

    if (size > 1600) {
        return 0;
    }

    /* SecTAG parser on the raw bytes (starting at the MACsec EtherType). */
    (void)macsec_sectag_parse(data, size, &tag);

    /* Full validate path for each configured confidentiality offset. */
    for (i = 0; i < 3; i++) {
        memset(&vp, 0, sizeof(vp));
        vp.sak         = FZ_SAK;
        vp.sak_len     = sizeof(FZ_SAK);
        vp.sci         = FZ_SCI;
        vp.conf_offset = offsets[i];
        out_len = 0;
        (void)macsec_validate(&vp, data, size, out, sizeof(out), &out_len,
                              &tag);
    }
    return 0;
}

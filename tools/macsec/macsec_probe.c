/* macsec_probe.c
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

/* macsec_probe - a byte-level cross-check tool for the wolfIP SecY against the
 * Linux kernel MACsec module. It applies the wolfIP 802.1AE transform to a
 * single frame:
 *
 *   macsec_probe protect  <sak_hex> <sci_hex> <an> <pn> <enc> <off> \
 *                         <da_hex> <sa_hex> <payload_hex>
 *       -> prints the resulting MACsec frame (DA||SA||SecTAG||data||ICV) hex.
 *
 *   macsec_probe validate <sak_hex> <peer_sci_hex> <off> <frame_hex>
 *       -> decrypts/authenticates a MACsec frame and prints the recovered
 *          MSDU hex, or "FAIL" on ICV/replay error.
 *
 * The interop scripts capture a frame the kernel produced (tcpdump) and feed
 * it to "validate", and feed a "protect" frame back into the kernel, to lock
 * the wolfIP framing (SecTAG layout, SCI||PN nonce, DA||SA||SecTAG AAD) to the
 * kernel byte for byte. include_sci is always set (the kernel default).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "macsec_secy.h"

#define MAX_BUF 2048

static int hex2bin(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t hl = strlen(hex);
    size_t i;
    if ((hl & 1U) != 0 || (hl / 2U) > out_cap) {
        return -1;
    }
    for (i = 0; i < hl; i += 2) {
        unsigned v;
        if (sscanf(hex + i, "%2x", &v) != 1) {
            return -1;
        }
        out[i / 2] = (uint8_t)v;
    }
    *out_len = hl / 2U;
    return 0;
}

static void print_hex(const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

static int do_protect(int argc, char **argv)
{
    struct macsec_protect_params p;
    uint8_t sak[32], sci[8], da[6], sa[6];
    uint8_t payload[MAX_BUF], frame[MAX_BUF];
    size_t  sak_len, sci_len, da_len, sa_len, pl_len, frame_len = 0;

    if (argc != 11) {
        fprintf(stderr, "usage: protect sak sci an pn enc off da sa payload\n");
        return 2;
    }
    if (hex2bin(argv[2], sak, sizeof(sak), &sak_len)
        || hex2bin(argv[3], sci, sizeof(sci), &sci_len)
        || hex2bin(argv[8], da, sizeof(da), &da_len)
        || hex2bin(argv[9], sa, sizeof(sa), &sa_len)
        || hex2bin(argv[10], payload, sizeof(payload), &pl_len)
        || sci_len != 8 || da_len != 6 || sa_len != 6) {
        fprintf(stderr, "bad hex arg\n");
        return 2;
    }
    memset(&p, 0, sizeof(p));
    p.da          = da;
    p.sa          = sa;
    p.sci         = sci;
    p.sak         = sak;
    p.sak_len     = sak_len;
    p.an          = (uint8_t)atoi(argv[4]);
    p.pn          = (uint32_t)strtoul(argv[5], NULL, 10);
    p.encrypt     = (uint8_t)atoi(argv[6]);
    p.conf_offset = (size_t)atoi(argv[7]);
    p.include_sci = 1;

    if (macsec_protect(&p, payload, pl_len, frame, sizeof(frame),
                       &frame_len) != 0) {
        printf("FAIL\n");
        return 1;
    }
    print_hex(frame, frame_len);
    return 0;
}

static int do_validate(int argc, char **argv)
{
    struct macsec_validate_params vp;
    struct macsec_sectag          tag;
    uint8_t sak[32], sci[8], frame[MAX_BUF], out[MAX_BUF];
    size_t  sak_len, sci_len, frame_len, out_len = 0;

    if (argc != 6) {
        fprintf(stderr, "usage: validate sak peer_sci off frame\n");
        return 2;
    }
    if (hex2bin(argv[2], sak, sizeof(sak), &sak_len)
        || hex2bin(argv[3], sci, sizeof(sci), &sci_len)
        || hex2bin(argv[5], frame, sizeof(frame), &frame_len)
        || sci_len != 8) {
        fprintf(stderr, "bad hex arg\n");
        return 2;
    }
    memset(&vp, 0, sizeof(vp));
    vp.sak         = sak;
    vp.sak_len     = sak_len;
    vp.sci         = sci;
    vp.conf_offset = (size_t)atoi(argv[4]);

    if (macsec_validate(&vp, frame, frame_len, out, sizeof(out), &out_len,
                        &tag) != 0) {
        printf("FAIL\n");
        return 1;
    }
    print_hex(out, out_len);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s protect|validate ...\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "protect") == 0) {
        return do_protect(argc, argv);
    }
    if (strcmp(argv[1], "validate") == 0) {
        return do_validate(argc, argv);
    }
    fprintf(stderr, "unknown command '%s'\n", argv[1]);
    return 2;
}

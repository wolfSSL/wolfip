/* wolfip_debug.c
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
 * wolfIP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#if defined(ETHERNET) && defined(DEBUG_ETH)
static void wolfIP_print_eth(struct wolfIP_eth_frame * eth, uint32_t len)
{
    uint8_t * dst = eth->dst;
    uint8_t * src = eth->src;
    uint8_t * type = (uint8_t *) &eth->type;
    LOG("eth hdr:\n");
    LOG("+---------------------------------------+\n");
    LOG("| %02x:%02x:%02x:%02x:%02x:%02x "
        "| %02x:%02x:%02x:%02x:%02x:%02x | (dst, src) \n",
        dst[0], dst[1], dst[2], dst[3], dst[4], dst[5],
        src[0], src[1], src[2], src[3], src[4], src[5]);
    LOG("+---------------------------------------+\n");
    LOG("| 0x%02x%02x | %5lu bytes data             | (eth type, payload) \n",
        type[0], type[1], (unsigned long)len);
    LOG("+---------------------------------------+\n");
    LOG("\n");
}
#endif /* ETHERNET && DEBUG_ETH */

#ifdef DEBUG_IP
static void wolfIP_print_ip(struct wolfIP_ip_packet * ip)
{
    char src[32];
    char dst[32];
    memset(src, 0, sizeof(src));
    memset(dst, 0, sizeof(dst));
    iptoa(ee32(ip->src), src);
    iptoa(ee32(ip->dst), dst);

    LOG("ip hdr:\n");
    LOG("+-----------------------------+\n");
    LOG("| 0x%02x | 0x%02x | 0x%02x |   %4d | (ipv, hdr_len, tos, ip_len)\n",
        0x04, ip->ver_ihl, ip->tos, ee16(ip->len));
    LOG("+-----------------------------+\n");
    LOG("|    0x%04x    |    0x%04x    | (id, flags_fo)\n",
        ee16(ip->id), ee16(ip->flags_fo));
    LOG("+-----------------------------+\n");
    LOG("|  %3d  | 0x%02x |    0x%04x    | (ttl, proto, chksum)\n",
        ip->ttl, ip->proto, ee16(ip->csum));
    LOG("+-----------------------------+\n");
    LOG("|           %15s   | (src)\n", src);
    LOG("+-----------------------------+\n");
    LOG("|           %15s   | (dst)\n", dst);
    LOG("+-----------------------------+\n");
    LOG("\n");
}
#endif /* DEBUG_IP*/

#ifdef DEBUG_UDP
static inline int wolfip_isprint(int c)
{
    return (c >= ' ' && c <= '~');
}
static void wolfIP_print_udp(struct wolfIP_udp_datagram * udp)
{
    uint16_t len = ee16(udp->len);
    char     payload_str[32];
    LOG("udp hdr:\n");
    LOG("+-------------------+\n");
    LOG("|  %5d  |  %5d  | (src_port, dst_port)\n",
        ee16(udp->src_port), ee16(udp->dst_port));
    LOG("+-------------------+\n");
    LOG("|  %5u  |  0x%04x | (len, chksum)\n",
        len, ee16(udp->csum));
    LOG("+-------------------+\n");
    memset(payload_str, '\0', sizeof(payload_str));
    {
        /* show first 16 printable chars of payload */
        uint16_t max_len = 16;
        size_t   print_len = (len - 8) < max_len ? (len  - 8): max_len;
        size_t   i = 0;
        memset(payload_str, '\0', sizeof(payload_str));
        memcpy(payload_str, udp->data, print_len);
        for (i = 0; i < print_len; i++) {
            if (!wolfip_isprint(payload_str[i])) { payload_str[i] = '.'; }
        }
    }
    LOG("| %17s | (payload first 16 bytes)\n", payload_str);
    LOG("+-------------------+\n");
    LOG("\n");
}
#endif /* DEBUG_UDP */

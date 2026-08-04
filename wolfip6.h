/* wolfip6.h
 *
 * IPv6 addressing for the wolfIP TCP/IP stack: the 128-bit address type,
 * well-known addresses, scope and type predicates, prefix operations and
 * RFC 4291 section 3 / RFC 5952 text conversion.
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
#ifndef WOLFIP6_H
#define WOLFIP6_H
#include <stdint.h>
#include <stddef.h> /* NULL */

/* This header is included unconditionally from wolfip.h. Everything in it is
 * a type definition or a static inline function, so it costs nothing when
 * IPv6 is disabled and it cannot change the layout or ABI of any existing
 * structure. That matters because wolfip.c includes wolfip.h *before*
 * config.h, so a feature macro set only in config.h is not yet visible here;
 * anything that did affect layout would have to be driven from the command
 * line (-DWOLFIP_IPV6=1), exactly as WOLFIP_VLAN already is.
 *
 * No <string.h> dependency: the fixed 16-byte loops below are written out so
 * that freestanding builds without a libc still work.
 */

/* An IPv6 address, always stored in network byte order.
 *
 * A byte array rather than a word array: wolfIP targets big-endian (PowerPC
 * e5500) and strict-alignment (PIC32MZ, Cortex-M) machines, and IPv6
 * addresses sit at odd offsets in an Ethernet frame, so a word view would be
 * an unaligned access waiting to happen. Wrapped in a struct so it can be
 * assigned and passed by value and cannot silently decay to a pointer -
 * which also means it must be compared with ip6_cmp(), never with ==.
 */
typedef struct wolfIP_ip6_addr {
    uint8_t addr[16];
} ip6;

/* Longest textual form is "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
 * 45 characters plus the terminator. */
#define WOLFIP_IP6_ADDRSTRLEN 46

/* Brace initialisers. Deliberately macros rather than file-scope const
 * objects: an unused "static const" in a header trips -Wunused-const-variable
 * under -Werror. */
#define WOLFIP_IN6ADDR_ANY_INIT \
    {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }}
#define WOLFIP_IN6ADDR_LOOPBACK_INIT \
    {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }}

/* Multicast scope values (RFC 4291 section 2.7). */
#define WOLFIP_IP6_SCOPE_INTERFACE_LOCAL 0x1
#define WOLFIP_IP6_SCOPE_LINK_LOCAL      0x2
#define WOLFIP_IP6_SCOPE_ADMIN_LOCAL     0x4
#define WOLFIP_IP6_SCOPE_SITE_LOCAL      0x5
#define WOLFIP_IP6_SCOPE_ORG_LOCAL       0x8
#define WOLFIP_IP6_SCOPE_GLOBAL          0xE

/* ---------------------------------------------------------------------- */
/* Basic operations                                                       */
/* ---------------------------------------------------------------------- */

/* Ordering comparison. Returns 0 when equal, and otherwise the difference of
 * the first differing byte, so the sign gives a stable total order. */
static inline int ip6_cmp(const ip6 *a, const ip6 *b)
{
    int i;

    for (i = 0; i < 16; i++) {
        if (a->addr[i] != b->addr[i])
            return (int)a->addr[i] - (int)b->addr[i];
    }
    return 0;
}

static inline void ip6_copy(ip6 *dst, const ip6 *src)
{
    int i;

    for (i = 0; i < 16; i++)
        dst->addr[i] = src->addr[i];
}

static inline void ip6_set_unspecified(ip6 *a)
{
    int i;

    for (i = 0; i < 16; i++)
        a->addr[i] = 0;
}

static inline void ip6_set_loopback(ip6 *a)
{
    ip6_set_unspecified(a);
    a->addr[15] = 1;
}

/* ff02::1, all-nodes link-local multicast (RFC 4291 section 2.7.1). */
static inline void ip6_set_all_nodes(ip6 *a)
{
    ip6_set_unspecified(a);
    a->addr[0] = 0xFF;
    a->addr[1] = 0x02;
    a->addr[15] = 1;
}

/* ff02::2, all-routers link-local multicast (RFC 4291 section 2.7.1). */
static inline void ip6_set_all_routers(ip6 *a)
{
    ip6_set_unspecified(a);
    a->addr[0] = 0xFF;
    a->addr[1] = 0x02;
    a->addr[15] = 2;
}

/* Solicited-node multicast address for a target: ff02::1:ffXX:XXXX, formed
 * from the low 24 bits of the target (RFC 4291 section 2.7.1). */
static inline void ip6_set_solicited_node(ip6 *dst, const ip6 *target)
{
    ip6_set_unspecified(dst);
    dst->addr[0] = 0xFF;
    dst->addr[1] = 0x02;
    dst->addr[11] = 0x01;
    dst->addr[12] = 0xFF;
    dst->addr[13] = target->addr[13];
    dst->addr[14] = target->addr[14];
    dst->addr[15] = target->addr[15];
}

/* Build ::ffff:a.b.c.d from an IPv4 address. The IPv4 value is in host byte
 * order, matching the ip4 convention used throughout the public API. */
static inline void ip6_set_v4mapped(ip6 *dst, uint32_t v4)
{
    ip6_set_unspecified(dst);
    dst->addr[10] = 0xFF;
    dst->addr[11] = 0xFF;
    dst->addr[12] = (uint8_t)(v4 >> 24);
    dst->addr[13] = (uint8_t)(v4 >> 16);
    dst->addr[14] = (uint8_t)(v4 >> 8);
    dst->addr[15] = (uint8_t)(v4 & 0xFFu);
}

/* Recover the embedded IPv4 address, in host byte order. Only meaningful
 * when ip6_is_v4mapped() is true. */
static inline uint32_t ip6_get_v4mapped(const ip6 *a)
{
    return ((uint32_t)a->addr[12] << 24) | ((uint32_t)a->addr[13] << 16) |
           ((uint32_t)a->addr[14] << 8) | (uint32_t)a->addr[15];
}

/* ---------------------------------------------------------------------- */
/* Type and scope predicates                                              */
/* ---------------------------------------------------------------------- */

/* :: (RFC 4291 section 2.5.2) */
static inline int ip6_is_unspecified(const ip6 *a)
{
    int i;

    for (i = 0; i < 16; i++) {
        if (a->addr[i] != 0)
            return 0;
    }
    return 1;
}

/* ::1 (RFC 4291 section 2.5.3) */
static inline int ip6_is_loopback(const ip6 *a)
{
    int i;

    for (i = 0; i < 15; i++) {
        if (a->addr[i] != 0)
            return 0;
    }
    return (a->addr[15] == 1) ? 1 : 0;
}

/* ff00::/8 (RFC 4291 section 2.7) */
static inline int ip6_is_multicast(const ip6 *a)
{
    return (a->addr[0] == 0xFF) ? 1 : 0;
}

/* fe80::/10 (RFC 4291 section 2.5.6) */
static inline int ip6_is_link_local(const ip6 *a)
{
    return ((a->addr[0] == 0xFE) && ((a->addr[1] & 0xC0) == 0x80)) ? 1 : 0;
}

/* fc00::/7 unique local (RFC 4193) */
static inline int ip6_is_ula(const ip6 *a)
{
    return ((a->addr[0] & 0xFE) == 0xFC) ? 1 : 0;
}

/* 2000::/3 global unicast (RFC 3587) */
static inline int ip6_is_global(const ip6 *a)
{
    return ((a->addr[0] & 0xE0) == 0x20) ? 1 : 0;
}

/* ::ffff:0:0/96, the IPv4-mapped range (RFC 4291 section 2.5.5.2).
 *
 * These addresses represent an IPv4 node inside the IPv6 API. They must never
 * appear in an IPv6 packet on the wire, so the receive path drops any frame
 * carrying one in either address field. */
static inline int ip6_is_v4mapped(const ip6 *a)
{
    int i;

    for (i = 0; i < 10; i++) {
        if (a->addr[i] != 0)
            return 0;
    }
    return ((a->addr[10] == 0xFF) && (a->addr[11] == 0xFF)) ? 1 : 0;
}

/* ::a.b.c.d, the deprecated IPv4-compatible range (RFC 4291 section 2.5.5.1).
 * Deprecated by RFC 4291 and never valid on the wire; recognised so that the
 * receive path can drop it explicitly. :: and ::1 are excluded, being the
 * unspecified and loopback addresses rather than compatible addresses. */
static inline int ip6_is_v4compat(const ip6 *a)
{
    int i;

    for (i = 0; i < 12; i++) {
        if (a->addr[i] != 0)
            return 0;
    }
    if (ip6_is_unspecified(a) || ip6_is_loopback(a))
        return 0;
    return 1;
}

/* Multicast flags and scope nibbles (RFC 4291 section 2.7). Only meaningful
 * when ip6_is_multicast() is true. */
static inline uint8_t ip6_mcast_flags(const ip6 *a)
{
    return (uint8_t)((a->addr[1] >> 4) & 0x0F);
}

static inline uint8_t ip6_mcast_scope(const ip6 *a)
{
    return (uint8_t)(a->addr[1] & 0x0F);
}

/* ff02::/16 */
static inline int ip6_is_mcast_link_local(const ip6 *a)
{
    return (ip6_is_multicast(a) &&
            (ip6_mcast_scope(a) == WOLFIP_IP6_SCOPE_LINK_LOCAL)) ? 1 : 0;
}

/* ff02::1 */
static inline int ip6_is_all_nodes(const ip6 *a)
{
    ip6 ref;

    ip6_set_all_nodes(&ref);
    return (ip6_cmp(a, &ref) == 0) ? 1 : 0;
}

/* ff02::2 */
static inline int ip6_is_all_routers(const ip6 *a)
{
    ip6 ref;

    ip6_set_all_routers(&ref);
    return (ip6_cmp(a, &ref) == 0) ? 1 : 0;
}

/* ff02::1:ff00:0/104 */
static inline int ip6_is_solicited_node(const ip6 *a)
{
    if (!ip6_is_mcast_link_local(a))
        return 0;
    if (ip6_mcast_flags(a) != 0)
        return 0;
    if ((a->addr[2] != 0) || (a->addr[3] != 0) || (a->addr[4] != 0) ||
            (a->addr[5] != 0) || (a->addr[6] != 0) || (a->addr[7] != 0) ||
            (a->addr[8] != 0) || (a->addr[9] != 0) || (a->addr[10] != 0))
        return 0;
    return ((a->addr[11] == 0x01) && (a->addr[12] == 0xFF)) ? 1 : 0;
}

/* An address usable as a packet source or destination on the wire. */
static inline int ip6_is_unicast(const ip6 *a)
{
    return (!ip6_is_multicast(a) && !ip6_is_unspecified(a)) ? 1 : 0;
}

/* ---------------------------------------------------------------------- */
/* Prefix operations                                                      */
/* ---------------------------------------------------------------------- */

/* Compare the first prefix_len bits. Returns 0 when they match, non-zero
 * otherwise. A prefix_len above 128 is clamped, and 0 matches everything. */
static inline int ip6_prefix_cmp(const ip6 *a, const ip6 *b, uint8_t prefix_len)
{
    int full;
    int rem;
    int i;

    if (prefix_len > 128)
        prefix_len = 128;
    full = prefix_len / 8;
    rem = prefix_len % 8;
    for (i = 0; i < full; i++) {
        if (a->addr[i] != b->addr[i])
            return 1;
    }
    if (rem != 0) {
        uint8_t mask = (uint8_t)(0xFFu << (8 - rem));
        if ((a->addr[full] & mask) != (b->addr[full] & mask))
            return 1;
    }
    return 0;
}

/* Zero every bit beyond prefix_len, leaving the network part. */
static inline void ip6_prefix_mask(ip6 *a, uint8_t prefix_len)
{
    int full;
    int rem;
    int i;

    if (prefix_len > 128)
        prefix_len = 128;
    full = prefix_len / 8;
    rem = prefix_len % 8;
    if (rem != 0) {
        a->addr[full] = (uint8_t)(a->addr[full] & (uint8_t)(0xFFu << (8 - rem)));
        full++;
    }
    for (i = full; i < 16; i++)
        a->addr[i] = 0;
}

/* Combine a prefix with an interface identifier: the first prefix_len bits
 * come from prefix, the remainder from iid (RFC 4862 section 5.5.3). */
static inline void ip6_make_addr(ip6 *dst, const ip6 *prefix,
                                 uint8_t prefix_len, const ip6 *iid)
{
    int full;
    int rem;
    int i;

    if (prefix_len > 128)
        prefix_len = 128;
    full = prefix_len / 8;
    rem = prefix_len % 8;
    for (i = 0; i < 16; i++)
        dst->addr[i] = 0;
    for (i = 0; i < full; i++)
        dst->addr[i] = prefix->addr[i];
    if (rem != 0) {
        uint8_t mask = (uint8_t)(0xFFu << (8 - rem));
        dst->addr[full] = (uint8_t)((prefix->addr[full] & mask) |
                                    (iid->addr[full] & (uint8_t)~mask));
        full++;
    }
    for (i = full; i < 16; i++)
        dst->addr[i] = iid->addr[i];
}

/* ---------------------------------------------------------------------- */
/* Link layer mapping                                                     */
/* ---------------------------------------------------------------------- */

/* Ethernet multicast MAC for an IPv6 multicast address: 33:33 followed by
 * the last four bytes of the address (RFC 2464 section 7). */
static inline void ip6_mcast_to_eth(const ip6 *a, uint8_t *mac)
{
    mac[0] = 0x33;
    mac[1] = 0x33;
    mac[2] = a->addr[12];
    mac[3] = a->addr[13];
    mac[4] = a->addr[14];
    mac[5] = a->addr[15];
}

/* Modified EUI-64 interface identifier from a 48-bit MAC (RFC 4291 appendix
 * A): insert fffe in the middle and invert the universal/local bit. The
 * result is written into the low 64 bits of iid, the high 64 bits are zeroed
 * so it can be handed straight to ip6_make_addr(). */
static inline void ip6_iid_from_mac(ip6 *iid, const uint8_t *mac)
{
    int i;

    for (i = 0; i < 16; i++)
        iid->addr[i] = 0;
    iid->addr[8] = (uint8_t)(mac[0] ^ 0x02);
    iid->addr[9] = mac[1];
    iid->addr[10] = mac[2];
    iid->addr[11] = 0xFF;
    iid->addr[12] = 0xFE;
    iid->addr[13] = mac[3];
    iid->addr[14] = mac[4];
    iid->addr[15] = mac[5];
}

/* ---------------------------------------------------------------------- */
/* Text conversion                                                        */
/* ---------------------------------------------------------------------- */

/* Does the group starting at p contain a '.' before the next ':' or the end?
 * Used to spot the dotted-quad tail of an IPv4-mapped literal. */
static inline int wolfIP_ip6_group_has_dot(const char *p)
{
    while ((*p != '\0') && (*p != ':')) {
        if (*p == '.')
            return 1;
        p++;
    }
    return 0;
}

/* Parse 1..4 hex digits. Returns the count consumed, 0 when there are none. */
static inline int wolfIP_ip6_parse_group(const char *p, uint32_t *out)
{
    uint32_t v = 0;
    int n = 0;

    while (n < 4) {
        char c = p[n];
        int d;

        if ((c >= '0') && (c <= '9'))
            d = c - '0';
        else if ((c >= 'a') && (c <= 'f'))
            d = (c - 'a') + 10;
        else if ((c >= 'A') && (c <= 'F'))
            d = (c - 'A') + 10;
        else
            break;
        v = (v << 4) | (uint32_t)d;
        n++;
    }
    *out = v;
    return n;
}

/* Parse a trailing dotted quad. Returns 0 on success. The quad must run to
 * the end of the string. */
static inline int wolfIP_ip6_parse_v4tail(const char *p, uint8_t *out)
{
    int i;

    for (i = 0; i < 4; i++) {
        uint32_t oct = 0;
        int n = 0;

        while ((n < 3) && (p[n] >= '0') && (p[n] <= '9')) {
            oct = (oct * 10u) + (uint32_t)(p[n] - '0');
            n++;
        }
        if ((n == 0) || (oct > 255))
            return -1;
        out[i] = (uint8_t)oct;
        p += n;
        if (i < 3) {
            if (*p != '.')
                return -1;
            p++;
        }
    }
    return (*p == '\0') ? 0 : -1;
}

/* Parse an IPv6 literal (RFC 4291 section 2.2), including the "::" run and
 * the trailing dotted-quad form. Returns 0 on success, -1 on any malformed
 * input. Strict: rejects a lone ':', more than one "::", too many or too few
 * groups, and trailing garbage. */
static inline int atoip6(const char *s, ip6 *out)
{
    uint8_t buf[16];
    uint8_t quad[4];
    const char *p;
    int gap = -1;
    int filled = 0;
    int i;

    if ((s == NULL) || (out == NULL))
        return -1;
    for (i = 0; i < 16; i++)
        buf[i] = 0;
    p = s;
    if (p[0] == ':') {
        if (p[1] != ':')
            return -1;
        p += 2;
        gap = 0;
    }
    while (*p != '\0') {
        uint32_t v;
        int n;

        if (wolfIP_ip6_group_has_dot(p)) {
            if (filled > 12)
                return -1;
            if (wolfIP_ip6_parse_v4tail(p, quad) != 0)
                return -1;
            for (i = 0; i < 4; i++)
                buf[filled++] = quad[i];
            break;
        }
        n = wolfIP_ip6_parse_group(p, &v);
        if (n == 0)
            return -1;
        p += n;
        if (filled > 14)
            return -1;
        buf[filled++] = (uint8_t)(v >> 8);
        buf[filled++] = (uint8_t)(v & 0xFFu);
        if (*p == '\0')
            break;
        if (*p != ':')
            return -1;
        p++;
        if (*p == ':') {
            if (gap >= 0)
                return -1; /* only one "::" is allowed */
            gap = filled;
            p++;
            if (*p == '\0')
                break;
        }
    }
    if (gap >= 0) {
        int move = filled - gap;

        /* "::" must stand for at least one elided group. */
        if (filled >= 16)
            return -1;
        for (i = 0; i < move; i++)
            buf[15 - i] = buf[filled - 1 - i];
        for (i = gap; i < (16 - move); i++)
            buf[i] = 0;
    } else if (filled != 16) {
        return -1;
    }
    for (i = 0; i < 16; i++)
        out->addr[i] = buf[i];
    return 0;
}

/* Render an IPv6 address in the canonical form of RFC 5952: lowercase hex,
 * no leading zeros within a group, the longest run of zero groups replaced
 * by "::" (leftmost run on a tie, and never a run of only one group), and
 * IPv4-mapped addresses printed with a dotted-quad tail.
 *
 * buf must hold at least WOLFIP_IP6_ADDRSTRLEN bytes. */
static inline void ip6toa(const ip6 *a, char *buf)
{
    static const char hexd[] = "0123456789abcdef";
    uint16_t g[8];
    int best = -1;
    int bestlen = 0;
    int cur = -1;
    int curlen = 0;
    int i;
    int j = 0;

    if (buf == NULL)
        return;
    if (a == NULL) {
        buf[0] = '\0';
        return;
    }
    if (ip6_is_v4mapped(a)) {
        /* RFC 5952 section 5 */
        buf[j++] = ':';
        buf[j++] = ':';
        buf[j++] = 'f';
        buf[j++] = 'f';
        buf[j++] = 'f';
        buf[j++] = 'f';
        buf[j++] = ':';
        for (i = 12; i < 16; i++) {
            uint8_t o = a->addr[i];

            if (o > 99)
                buf[j++] = (char)('0' + (o / 100));
            if (o > 9)
                buf[j++] = (char)('0' + ((o / 10) % 10));
            buf[j++] = (char)('0' + (o % 10));
            if (i < 15)
                buf[j++] = '.';
        }
        buf[j] = '\0';
        return;
    }
    for (i = 0; i < 8; i++)
        g[i] = (uint16_t)(((uint16_t)a->addr[i * 2] << 8) | a->addr[(i * 2) + 1]);
    for (i = 0; i < 8; i++) {
        if (g[i] == 0) {
            if (cur < 0) {
                cur = i;
                curlen = 0;
            }
            curlen++;
            if (curlen > bestlen) {
                best = cur;
                bestlen = curlen;
            }
        } else {
            cur = -1;
            curlen = 0;
        }
    }
    /* A single zero group is written out, not compressed. */
    if (bestlen < 2) {
        best = -1;
        bestlen = 0;
    }
    i = 0;
    while (i < 8) {
        uint16_t v;
        int started = 0;
        int s;

        if (i == best) {
            buf[j++] = ':';
            if ((best + bestlen) >= 8)
                buf[j++] = ':';
            i += bestlen;
            continue;
        }
        if (i > 0)
            buf[j++] = ':';
        v = g[i];
        for (s = 12; s >= 0; s -= 4) {
            int nib = (v >> s) & 0xF;

            if ((nib != 0) || started || (s == 0)) {
                buf[j++] = hexd[nib];
                started = 1;
            }
        }
        i++;
    }
    buf[j] = '\0';
}

#endif /* !WOLFIP6_H */

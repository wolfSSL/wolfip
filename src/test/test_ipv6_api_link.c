/* test_ipv6_api_link.c
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

/*
 * A consumer of the library built without IPv6, calling every IPv6 entry
 * point wolfip.h declares.
 *
 * The unit tests cannot cover this. unit.c #includes src/wolfip.c, so every
 * function is in the same translation unit and a missing definition would
 * never be noticed. What broke was the other arrangement, and the only one
 * an application ever uses: include the header, link against the library.
 * The declarations are unconditional - wolfip.h is included before config.h
 * and cannot see WOLFIP_IPV6 - so without definitions to match, this program
 * failed to link.
 *
 * Building it is therefore most of the test. Running it checks the second
 * half: that the calls report the feature as absent rather than as a bad
 * argument, which a caller would try to correct and retry.
 */

#include <stdio.h>
#include <string.h>

#include "wolfip.h"

#define CHECK_ENOSYS(call)                                              \
    do {                                                               \
        int rc_ = (call);                                              \
                                                                       \
        if (rc_ != -WOLFIP_ENOSYS) {                                   \
            printf("FAIL: %s returned %d, expected %d\n",              \
                   #call, rc_, -WOLFIP_ENOSYS);                        \
            failures++;                                                \
        }                                                              \
    } while (0)

int main(void)
{
    struct wolfIP *s = NULL;
    uint8_t mac[6];
    uint8_t iid[8];
    ip6 addr;
    ip6 nexthop;
    int failures = 0;

    memset(mac, 0, sizeof(mac));
    memset(iid, 0, sizeof(iid));
    memset(&nexthop, 0, sizeof(nexthop));
    wolfIP_init_static(&s);
    if (!s) {
        printf("FAIL: no stack\n");
        return 1;
    }
    if (atoip6("2001:db8::1", &addr) != 0) {
        printf("FAIL: atoip6\n");
        return 1;
    }

    CHECK_ENOSYS(wolfIP_ipv6_start(s, 0));
    CHECK_ENOSYS(wolfIP_ipv6_stop(s, 0));
    CHECK_ENOSYS(wolfIP_ipv6_addr_add(s, 0, &addr, 64));
    CHECK_ENOSYS(wolfIP_ipv6_set_iid(s, 0, iid));
    CHECK_ENOSYS(wolfIP_ipv6_get_iid(s, 0, iid));
    CHECK_ENOSYS(wolfIP_nd6_neighbor_add(s, 0, &addr, mac));
    CHECK_ENOSYS(wolfIP_nd6_lookup(s, 0, &addr, mac));
    CHECK_ENOSYS(wolfIP_ipv6_nexthop(s, 0, &addr, &nexthop));
    CHECK_ENOSYS(wolfIP_ifaddr_add6(s, 0, &addr, 64));
    CHECK_ENOSYS(wolfIP_ifaddr_del6(s, 0, &addr));

    /* Declared in the same header and equally undefined until now. */
    CHECK_ENOSYS(wolfIP_register_l2_handler(s, 0x80E1, NULL, NULL, NULL, 0));

    /* An address list with no IPv6 in it reports empty rather than
     * failing, because counting is not an IPv6 operation. */
    if (wolfIP_ifaddr_count(s, 0, AF_INET6) != 0) {
        printf("FAIL: wolfIP_ifaddr_count(AF_INET6) is not zero\n");
        failures++;
    }

    printf("IPv6 API link check: %s\n", (failures == 0) ? "PASS" : "FAIL");
    return (failures == 0) ? 0 : 1;
}

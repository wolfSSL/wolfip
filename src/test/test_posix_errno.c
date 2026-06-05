/* test_posix_errno.c
 *
 * Copyright (C) 2024 wolfSSL Inc.
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

/* Regression test for F-4950: the POSIX shim macros must translate a negative
 * wolfIP return code into a positive errno, exactly as the hand-written paths
 * (bind/close/send/...) already do. Driving getpeername() through the
 * conditional_steal_call() macro on a wolfIP-managed fd exercises the
 * "errno = -ret" conversion: with the sign bug present errno is set to the raw
 * negative code and the assertion below fails. */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

/* Pull in the shim itself so we can reach its file-static state
 * (in_the_stack / IPSTACK). The library constructor runs at load; without
 * CAP_NET_ADMIN its TAP setup simply fails and returns, leaving the host_*
 * passthrough pointers populated, which is all this test needs. */
#include "../port/posix/bsd_socket.c"

int main(void)
{
    struct sockaddr_in peer;
    socklen_t peerlen = 0; /* deliberately too small -> internal error path */
    int fd;
    int ret;

    /* The library constructor already initialised the static stack via
     * wolfIP_init_static(); make sure it is present and take over the shim
     * path so socket()/getpeername() are served by wolfIP, not libc. */
    if (!IPSTACK)
        wolfIP_init_static(&IPSTACK);
    in_the_stack = 0;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);

    errno = 0;
    memset(&peer, 0, sizeof(peer));
    ret = getpeername(fd, (struct sockaddr *)&peer, &peerlen);

    printf("getpeername ret=%d errno=%d (%s)\n", ret, errno,
           errno > 0 ? strerror(errno) : "negative/raw");

    /* The call must fail... */
    assert(ret == -1);
    /* ...and errno must be a real positive errno value, never the raw negative
     * wolfIP code (the F-4950 defect). */
    assert(errno > 0);

    printf("F-4950 regression test passed\n");
    return 0;
}

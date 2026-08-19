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
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

/* Pull in the shim itself so we can reach its file-static state
 * (in_the_stack / IPSTACK). The library constructor runs at load; without
 * CAP_NET_ADMIN its TAP setup simply fails and returns, leaving the host_*
 * passthrough pointers populated, which is all this test needs. */
#include "../port/posix/bsd_socket.c"

enum {
    HOST_CALL_READERS = 4,
    HOST_CALL_RACE_ITERATIONS = 10000,
    FD_RACE_ITERATIONS = 1000
};

static int race_ready;
static int race_start;
static int host_call_observed;
static int fd_race_fd;
static int fd_race_failed;

static void race_wait_for_start(void)
{
    __atomic_add_fetch(&race_ready, 1, __ATOMIC_ACQ_REL);
    while (!__atomic_load_n(&race_start, __ATOMIC_ACQUIRE))
        sched_yield();
}

static void race_start_threads(int count)
{
    while (__atomic_load_n(&race_ready, __ATOMIC_ACQUIRE) != count)
        sched_yield();
    __atomic_store_n(&race_start, 1, __ATOMIC_RELEASE);
}

static void race_reset(void)
{
    __atomic_store_n(&race_ready, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&race_start, 0, __ATOMIC_RELEASE);
}

static void *host_call_publisher(void *arg)
{
    int i;

    (void)arg;
    race_wait_for_start();
    for (i = 0; i < HOST_CALL_RACE_ITERATIONS; i++) {
        __atomic_store_n(&host_getpeername, NULL, __ATOMIC_RELEASE);
        swap_socketcall(getpeername, "getpeername");
    }
    return NULL;
}

static void *host_call_reader(void *arg)
{
    int i;

    (void)arg;
    race_wait_for_start();
    for (i = 0; i < HOST_CALL_RACE_ITERATIONS; i++) {
        if (WOLFIP_HOST_CALL(getpeername) != NULL)
            __atomic_add_fetch(&host_call_observed, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

static void test_host_call_publication(void)
{
    pthread_t publisher;
    pthread_t readers[HOST_CALL_READERS];
    int i;

    race_reset();
    __atomic_store_n(&host_call_observed, 0, __ATOMIC_RELEASE);
    assert(pthread_create(&publisher, NULL, host_call_publisher, NULL) == 0);
    for (i = 0; i < HOST_CALL_READERS; i++)
        assert(pthread_create(&readers[i], NULL, host_call_reader, NULL) == 0);
    race_start_threads(HOST_CALL_READERS + 1);
    assert(pthread_join(publisher, NULL) == 0);
    for (i = 0; i < HOST_CALL_READERS; i++)
        assert(pthread_join(readers[i], NULL) == 0);
    assert(WOLFIP_HOST_CALL(getpeername) != NULL);
    assert(__atomic_load_n(&host_call_observed, __ATOMIC_ACQUIRE) > 0);
}

static void *fd_race_caller(void *arg)
{
    struct sockaddr_in peer;
    socklen_t peerlen;
    int fd;
    int i;

    (void)arg;
    in_the_stack = 0;
    race_wait_for_start();
    for (i = 0; i < FD_RACE_ITERATIONS; i++) {
        fd = __atomic_load_n(&fd_race_fd, __ATOMIC_ACQUIRE);
        peerlen = sizeof(peer);
        getpeername(fd, (struct sockaddr *)&peer, &peerlen);
    }
    return NULL;
}

static void *fd_race_reallocator(void *arg)
{
    int fd;
    int i;

    (void)arg;
    in_the_stack = 0;
    race_wait_for_start();
    for (i = 0; i < FD_RACE_ITERATIONS; i++) {
        fd = __atomic_load_n(&fd_race_fd, __ATOMIC_ACQUIRE);
        if (close(fd) != 0) {
            __atomic_store_n(&fd_race_failed, 1, __ATOMIC_RELEASE);
            break;
        }
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            __atomic_store_n(&fd_race_failed, 1, __ATOMIC_RELEASE);
            break;
        }
        __atomic_store_n(&fd_race_fd, fd, __ATOMIC_RELEASE);
    }
    return NULL;
}

static void test_fd_lookup_synchronization(void)
{
    pthread_t caller;
    pthread_t reallocator;
    int fd;

    race_reset();
    __atomic_store_n(&fd_race_failed, 0, __ATOMIC_RELEASE);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    __atomic_store_n(&fd_race_fd, fd, __ATOMIC_RELEASE);
    assert(pthread_create(&caller, NULL, fd_race_caller, NULL) == 0);
    assert(pthread_create(&reallocator, NULL, fd_race_reallocator, NULL) == 0);
    race_start_threads(2);
    assert(pthread_join(caller, NULL) == 0);
    assert(pthread_join(reallocator, NULL) == 0);
    assert(__atomic_load_n(&fd_race_failed, __ATOMIC_ACQUIRE) == 0);
    fd = __atomic_load_n(&fd_race_fd, __ATOMIC_ACQUIRE);
    assert(close(fd) == 0);
}

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
    assert(close(fd) == 0);

    printf("F-4950 regression test passed\n");
    test_host_call_publication();
    test_fd_lookup_synchronization();
    printf("POSIX concurrency regression tests passed\n");
    return 0;
}

/* syscalls.c - newlib stubs for the Pi Pico 2 W port
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

extern char _heap_start;
extern char _heap_limit;

/* Provided by rp2350_uart.c. Console output routes here. */
extern void rp2350_uart_tx(const char *buf, int len);

static char *heap_end;

int _write(int file, const char *ptr, int len)
{
    (void)file;
    rp2350_uart_tx(ptr, len);
    return len;
}

int _close(int file) { (void)file; return -1; }

int _fstat(int file, struct stat *st)
{
    (void)file;
    if (st == 0) { errno = EINVAL; return -1; }
    st->st_mode = S_IFCHR;
    return 0;
}

int _isatty(int file) { (void)file; return 1; }
int _lseek(int file, int ptr, int dir) { (void)file; (void)ptr; (void)dir; return 0; }
int _read(int file, char *ptr, int len) { (void)file; (void)ptr; (void)len; return 0; }

void *_sbrk(ptrdiff_t incr)
{
    char *prev;
    if (heap_end == 0) {
        heap_end = &_heap_start;
    }
    prev = heap_end;
    /* Reject growth past the reserved-stack limit, and a negative incr that
     * would drive the break below the heap base (e.g. a corrupt free list). */
    if ((heap_end + incr) >= &_heap_limit
        || (incr < 0 && (heap_end + incr) < &_heap_start)) {
        errno = ENOMEM;
        return (void *)-1;
    }
    heap_end += incr;
    return prev;
}

int _gettimeofday(struct timeval *tv, void *tzvp)
{
    (void)tzvp;
    if (tv == 0) { errno = EINVAL; return -1; }
    tv->tv_sec = 0;
    tv->tv_usec = 0;
    return 0;
}

time_t time(time_t *t)
{
    if (t != 0) { *t = 0; }
    return 0;
}

void _exit(int status)
{
    (void)status;
    while (1) { __asm volatile("wfi"); }
}

int _kill(int pid, int sig) { (void)pid; (void)sig; errno = EINVAL; return -1; }
int _getpid(void) { return 1; }
void _init(void) {}
void _fini(void) {}

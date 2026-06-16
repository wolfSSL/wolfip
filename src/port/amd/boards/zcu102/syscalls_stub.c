/* syscalls_stub.c
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
 *
 * Minimal newlib syscall stubs for the OTA build. The wolfIP TFTP client
 * uses snprintf(), which pulls in newlib's reent/stdio machinery; that in
 * turn references these POSIX hooks at link time even though the bounded
 * integer/string formatting the client does never actually calls them. The
 * lean (non-OTA) app avoids stdio entirely and so needs none of this.
 *
 * _sbrk hands out a small static heap so that any incidental allocation
 * succeeds rather than corrupting memory; the rest fail cleanly with ENOSYS.
 */
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

/* Static heap for _sbrk. snprintf's non-float conversions don't allocate,
 * so this is a safety margin, not a hot path. */
#ifndef OTA_HEAP_SIZE
#define OTA_HEAP_SIZE (64U * 1024U)
#endif
static char ota_heap[OTA_HEAP_SIZE];
static char *ota_brk = ota_heap;

void *_sbrk(ptrdiff_t incr)
{
    char *prev = ota_brk;

    if (incr < 0 || (size_t)(incr) > (size_t)(&ota_heap[OTA_HEAP_SIZE] - ota_brk)) {
        errno = ENOMEM;
        return (void *)-1;
    }
    ota_brk += incr;
    return prev;
}

int _close(int fd)
{
    (void)fd;
    errno = ENOSYS;
    return -1;
}

off_t _lseek(int fd, off_t off, int whence)
{
    (void)fd;
    (void)off;
    (void)whence;
    errno = ENOSYS;
    return (off_t)-1;
}

ssize_t _read(int fd, void *buf, size_t len)
{
    (void)fd;
    (void)buf;
    (void)len;
    errno = ENOSYS;
    return -1;
}

ssize_t _write(int fd, const void *buf, size_t len)
{
    (void)fd;
    (void)buf;
    (void)len;
    errno = ENOSYS;
    return -1;
}

int _fstat(int fd, struct stat *st)
{
    (void)fd;
    if (st != NULL)
        st->st_mode = S_IFCHR;
    return 0;
}

int _isatty(int fd)
{
    (void)fd;
    return 1;
}

int _kill(int pid, int sig)
{
    (void)pid;
    (void)sig;
    errno = ENOSYS;
    return -1;
}

int _getpid(void)
{
    return 1;
}

void _exit(int code)
{
    (void)code;
    for (;;)
        __asm__ volatile ("wfi");
}

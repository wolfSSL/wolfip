/* syscalls.c
 *
 * Copyright (C) 2024-2026 wolfSSL Inc.
 *
 * Minimal libc stubs and wolfIP platform hooks for bare-metal.
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
#include <sys/stat.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <wolfHAL/uart/uart.h>
extern uint32_t _ebss;
extern uint32_t _heap_limit;
extern whal_Uart g_whalUart;

static char *heap_end;

int _write(int file, const char *ptr, int len)
{
    (void)file;
    if (len > 0)
        whal_Uart_Send(&g_whalUart, ptr, (size_t)len);
    return len;
}

int _close(int file)
{
    (void)file;
    return -1;
}

int _fstat(int file, struct stat *st)
{
    (void)file;
    if (st == NULL) {
        errno = EINVAL;
        return -1;
    }
    st->st_mode = S_IFCHR;
    return 0;
}

int _isatty(int file)
{
    (void)file;
    return 1;
}

int _lseek(int file, int ptr, int dir)
{
    (void)file;
    (void)ptr;
    (void)dir;
    return 0;
}

int _read(int file, char *ptr, int len)
{
    (void)file;
    (void)ptr;
    (void)len;
    return 0;
}

void *_sbrk(ptrdiff_t incr)
{
    char *prev;
    if (heap_end == 0)
        heap_end = (char *)&_ebss;
    prev = heap_end;
    if ((heap_end + incr) >= (char *)&_heap_limit) {
        errno = ENOMEM;
        return (void *)-1;
    }
    heap_end += incr;
    return prev;
}

void _exit(int status)
{
    (void)status;
    while (1) { }
}

int _kill(int pid, int sig)
{
    (void)pid;
    (void)sig;
    errno = EINVAL;
    return -1;
}

int _getpid(void)
{
    return 1;
}

void _init(void)
{
}

void _fini(void)
{
}


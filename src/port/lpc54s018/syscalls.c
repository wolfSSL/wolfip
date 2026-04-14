/* syscalls.c
 *
 * Minimal newlib stubs for LPC54S018 bare-metal.
 * _write routes to Flexcomm0/USART0 FIFO for debug output.
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
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* Flexcomm0 / USART0 registers */
#define USART0_BASE     0x40086000UL
#define USART0_FIFOSTAT (*(volatile uint32_t *)(USART0_BASE + 0xE04U))
#define USART0_FIFOWR   (*(volatile uint32_t *)(USART0_BASE + 0xE20U))
/* FIFOSTAT bit 4 = TXNOTFULL (TX FIFO has space) */
#define USART0_FIFOSTAT_TXNOTFULL  (1U << 4)
#define USART0_FIFOSTAT_TXEMPTY    (1U << 3)
#define UART_TX_TIMEOUT            100000U

extern uint32_t _ebss;
extern uint32_t _estack;

static char *heap_end;

int _write(int file, const char *ptr, int len)
{
    int i;
    uint32_t timeout;
    (void)file;
    for (i = 0; i < len; i++) {
        timeout = UART_TX_TIMEOUT;
        while (!(USART0_FIFOSTAT & USART0_FIFOSTAT_TXNOTFULL) && --timeout) { }
        if (timeout == 0)
            return i;
        USART0_FIFOWR = (uint32_t)ptr[i];
    }
    /* Wait for transmit to complete */
    timeout = UART_TX_TIMEOUT;
    while (!(USART0_FIFOSTAT & USART0_FIFOSTAT_TXEMPTY) && --timeout) { }
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
    if (st == 0) {
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
    if (heap_end == 0) {
        heap_end = (char *)&_ebss;
    }
    prev = heap_end;
    if ((heap_end + incr) >= (char *)&_estack) {
        errno = ENOMEM;
        return (void *)-1;
    }
    heap_end += incr;
    return prev;
}

int _gettimeofday(struct timeval *tv, void *tzvp)
{
    (void)tzvp;
    if (tv == 0) {
        errno = EINVAL;
        return -1;
    }
    tv->tv_sec = 0;
    tv->tv_usec = 0;
    return 0;
}

time_t time(time_t *t)
{
    if (t != 0) {
        *t = 0;
    }
    return 0;
}

void _exit(int status)
{
    (void)status;
    while (1) {
        __asm volatile("wfi");
    }
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

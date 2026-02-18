/* syscalls.c
 *
 * Newlib system call stubs for STM32H753ZI bare-metal
 *
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 */
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

extern uint32_t _ebss;
extern uint32_t _estack;

static char *heap_end;

/* USART3 TX register for printf output */
#define USART3_BASE_ADDR    0x40004800UL
#define USART3_ISR_REG      (*(volatile uint32_t *)(USART3_BASE_ADDR + 0x1C))
#define USART3_TDR_REG      (*(volatile uint32_t *)(USART3_BASE_ADDR + 0x28))

int _write(int file, const char *ptr, int len)
{
    int i;
    (void)file;
    for (i = 0; i < len; i++) {
        if (ptr[i] == '\n') {
            while ((USART3_ISR_REG & (1u << 7)) == 0) { }
            USART3_TDR_REG = '\r';
        }
        while ((USART3_ISR_REG & (1u << 7)) == 0) { }
        USART3_TDR_REG = (uint32_t)ptr[i];
    }
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
    /* Fixed time: 2026-02-16 (epoch seconds) for certificate validation.
     * Without a real RTC, this ensures ASN time checks pass. */
    time_t now = 1771200000;  /* approx 2026-02-16 */
    if (t != 0) {
        *t = now;
    }
    return now;
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

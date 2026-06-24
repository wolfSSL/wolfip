/* syscalls.c
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

extern uint32_t _ebss;
extern uint32_t _heap_limit;

static char *heap_end;

int _write(int file, const char *ptr, int len)
{
    (void)file;
    (void)ptr;
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
    if ((heap_end + incr) >= (char *)&_heap_limit) {
        errno = ENOMEM;
        return (void *)-1;
    }
    heap_end += incr;
    return prev;
}

/* This board has no RTC, so derive a coarse wall-clock from the build date
 * (__DATE__ = "Mmm dd yyyy"). It only needs to be accurate enough that
 * wolfSSL X.509 notBefore/notAfter checks pass for certs minted around
 * build time (e.g. the 802.1X EAP-TLS demo). Resolution is one day; we add
 * two days of slack so a cert whose notBefore is later on the build day is
 * still considered valid. */
static time_t build_epoch(void)
{
    static const char mon_names[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    static const int  mdays[12] =
        { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    const char *bd = __DATE__;
    long  days;
    long  y;
    int   mon;
    int   day;
    int   year;
    int   leap;
    int   i;

    mon = 0;
    for (i = 0; i < 12; i++) {
        if (mon_names[i * 3] == bd[0] && mon_names[i * 3 + 1] == bd[1]
            && mon_names[i * 3 + 2] == bd[2]) {
            mon = i;
            break;
        }
    }
    day  = ((bd[4] == ' ') ? 0 : (bd[4] - '0')) * 10 + (bd[5] - '0');
    year = (bd[7] - '0') * 1000 + (bd[8] - '0') * 100
         + (bd[9] - '0') * 10 + (bd[10] - '0');

    days = 0;
    for (y = 1970; y < (long)year; y++) {
        days += (((y % 4 == 0) && (y % 100 != 0)) || (y % 400 == 0))
                ? 366 : 365;
    }
    leap = (((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0));
    for (i = 0; i < mon; i++) {
        days += mdays[i];
        if ((i == 1) && leap) {
            days += 1;
        }
    }
    days += (day - 1);
    /* NOTE: newlib time_t here is 32-bit signed, so this value overflows on
     * 2038-01-19; a build dated after that wraps negative and X.509
     * notBefore/notAfter checks fail. Also note _gettimeofday()/time() return
     * this same constant (frozen clock) - fine for the one-shot EAP-TLS cert
     * validity check it exists for, but not for measuring elapsed wall time
     * (layer a SysTick offset on top of build_epoch() if that is needed). */
    return (time_t)((days + 2) * 86400L);
}

int _gettimeofday(struct timeval *tv, void *tzvp)
{
    (void)tzvp;
    if (tv == 0) {
        errno = EINVAL;
        return -1;
    }
    tv->tv_sec = build_epoch();
    tv->tv_usec = 0;
    return 0;
}

time_t time(time_t *t)
{
    time_t now = build_epoch();
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

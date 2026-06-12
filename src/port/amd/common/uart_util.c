/* uart_util.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Hardware-independent UART formatting helpers shared by the UART drivers
 * (uart_cadence.c / uart_pl011.c). Each driver provides the hardware-
 * specific uart_init() and uart_putc(); these build on uart_putc().
 */
#include <stdint.h>
#include "uart.h"

void uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n')
            uart_putc('\r');
        uart_putc(*s++);
    }
}

void uart_puthex(uint32_t val)
{
    static const char hex[] = "0123456789ABCDEF";
    int i;
    uart_puts("0x");
    for (i = 28; i >= 0; i -= 4)
        uart_putc(hex[(val >> i) & 0xF]);
}

void uart_putdec(uint32_t val)
{
    char buf[11];
    int i = 0;
    if (val == 0) {
        uart_putc('0');
        return;
    }
    while (val > 0 && i < (int)sizeof(buf)) {
        buf[i++] = '0' + (char)(val % 10);
        val /= 10;
    }
    while (i > 0)
        uart_putc(buf[--i]);
}

void uart_putip4(ip4 ip)
{
    uart_putdec((ip >> 24) & 0xFF);
    uart_putc('.');
    uart_putdec((ip >> 16) & 0xFF);
    uart_putc('.');
    uart_putdec((ip >> 8) & 0xFF);
    uart_putc('.');
    uart_putdec(ip & 0xFF);
}

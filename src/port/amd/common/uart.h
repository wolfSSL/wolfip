/* uart.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 */
#ifndef AMD_UART_H
#define AMD_UART_H

#include <stdint.h>
#include "wolfip.h"   /* for ip4 */

void uart_init(void);
void uart_putc(char c);
void uart_puts(const char *s);
void uart_puthex(uint32_t val);
void uart_putdec(uint32_t val);
void uart_putip4(ip4 ip);

#endif /* AMD_UART_H */

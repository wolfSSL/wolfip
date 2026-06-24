/* board.h - Pi Pico 2 W (RP2350 + CYW43439) board definitions
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

#ifndef WOLFIP_RP2350_CYW43439_BOARD_H
#define WOLFIP_RP2350_CYW43439_BOARD_H

/* RP2350 base addresses (RP2350 datasheet 2.2). */
#define RP2350_ROM_BASE         0x00000000UL
#define RP2350_XIP_BASE         0x10000000UL
#define RP2350_SRAM_BASE        0x20000000UL
#define RP2350_SRAM_SIZE        0x00082000UL    /* 520 KB                 */
#define RP2350_APB_BASE         0x40000000UL
#define RP2350_AHB_BASE         0x50000000UL

/* SIO (single-cycle IO) - GPIO mailbox/atomic regs for both cores. */
#define RP2350_SIO_BASE         0xD0000000UL

/* Pi Pico W and Pico 2 W carrier: the CYW43439 is attached to RP2350 via
 * a constrained gSPI bus (1-bit data line, shared MOSI/MISO through a
 * 470 ohm series resistor). Pin assignment is fixed on the Pico 2 W
 * carrier - see datasheet "Raspberry Pi Pico 2 W" Schematic v0.4.
 *
 *   GP23 = WL_REG_ON       (power enable; active high)
 *   GP24 = SPI data         (shared MOSI/MISO via 470 R; doubles as the
 *                            host-wake IRQ from CYW43 when SPI is idle)
 *   GP25 = SPI CS           (active low)
 *   GP29 = SPI clock
 *
 * The clean-room driver polls GP24 for data-ready; an IRQ path can be
 * added once the polled bringup proves stable (RP2350 erratum E9: edge
 * IRQ on some pin modes can deadlock the core, prefer poll first).
 * These match the pico-sdk cyw43 pin config (WL_CLOCK=29, WL_DATA=24,
 * WL_CS=25, WL_REG_ON=23, WL_HOST_WAKE=24).
 */
#define CYW43_PIN_WL_REG_ON     23
#define CYW43_PIN_SPI_DATA      24
#define CYW43_PIN_SPI_CS        25
#define CYW43_PIN_SPI_CLK       29
#define CYW43_PIN_HOST_IRQ      24

/* UART0 for stdout console. Pi Pico 2 W exposes UART0 on GP0/GP1 by
 * default. The pico-sdk uses these and so do we. */
#define UART0_PIN_TX            0
#define UART0_PIN_RX            1
#define UART0_BAUD              115200

#endif /* WOLFIP_RP2350_CYW43439_BOARD_H */

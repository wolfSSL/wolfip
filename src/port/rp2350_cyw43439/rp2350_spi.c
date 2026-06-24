/* rp2350_spi.c - RP2350 host SPI driver for CYW43439 gSPI
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
 * The Pi Pico 2 W carrier wires the CYW43439 SDIO data line to RP2350
 * GP24 through a 470 ohm series resistor (also used as the host DATA_RDY
 * input from the radio when SPI is idle), with SPI CLK on GP29 and CS on
 * GP25 (see board.h: CYW43_PIN_SPI_DATA=24, CYW43_PIN_SPI_CLK=29). This
 * is the "gSPI" bus used by all known clean-room CYW43439 drivers
 * (PicoWi, Embassy, soypat/cyw43439).
 *
 * Implementation note: the first bring-up iteration uses bit-banged
 * SPI on the SIO (single-cycle IO) GPIO regs for deterministic timing
 * during the firmware load (~225 KB at ~10 Mbit/s). After the radio
 * is up, we switch to the SPI hardware peripheral for run-time
 * traffic. The hardware peripheral path is TODO(hardware): bring-up
 * lands in tasks #44/#45 against real silicon.
 */
#include <stdint.h>

#include "board.h"
#include "rp2350_spi.h"

/* RP2350 SIO (single-cycle IO) registers - per-bank GPIO control. */
#define SIO_BASE                0xD0000000UL
#define SIO_GPIO_OUT            (SIO_BASE + 0x010U)
#define SIO_GPIO_OUT_SET        (SIO_BASE + 0x018U)
#define SIO_GPIO_OUT_CLR        (SIO_BASE + 0x020U)
#define SIO_GPIO_OE             (SIO_BASE + 0x030U)
#define SIO_GPIO_OE_SET         (SIO_BASE + 0x038U)
#define SIO_GPIO_OE_CLR         (SIO_BASE + 0x040U)
#define SIO_GPIO_IN             (SIO_BASE + 0x004U)

/* IO_BANK0: pin function mux. Function 5 = SIO (software GPIO). */
#define IO_BANK0_BASE           0x40028000UL
#define IO_BANK0_GPIO_CTRL(n)   (IO_BANK0_BASE + 0x004U + (n) * 8U)
#define GPIO_FUNC_SIO           5U

/* PADS_BANK0: pad strength + pull. */
#define PADS_BANK0_BASE         0x40038000UL
#define PADS_BANK0_GPIO(n)      (PADS_BANK0_BASE + 0x004U + (n) * 4U)
#define PAD_OD                  (1U << 7)   /* output disable                */
#define PAD_IE                  (1U << 6)   /* input enable                  */
#define PAD_DRIVE_8MA           (0x2U << 4)
#define PAD_PULL_UP             (1U << 3)

#define MMIO(addr)              (*(volatile uint32_t *)(addr))

static void gpio_sio_init(uint32_t pin, int as_output, int pull_up)
{
    uint32_t pad = PAD_DRIVE_8MA | PAD_IE;
    if (pull_up) pad |= PAD_PULL_UP;
    MMIO(PADS_BANK0_GPIO(pin)) = pad;
    MMIO(IO_BANK0_GPIO_CTRL(pin)) = GPIO_FUNC_SIO;
    if (as_output) {
        MMIO(SIO_GPIO_OE_SET) = (1U << pin);
    }
    else {
        MMIO(SIO_GPIO_OE_CLR) = (1U << pin);   /* atomic, matches the SET path */
    }
}

static inline void gpio_set(uint32_t pin)   { MMIO(SIO_GPIO_OUT_SET) = (1U << pin); }
static inline void gpio_clr(uint32_t pin)   { MMIO(SIO_GPIO_OUT_CLR) = (1U << pin); }
static inline int  gpio_get(uint32_t pin)   { return (int)((MMIO(SIO_GPIO_IN) >> pin) & 1U); }

/* Short settle delay used around CS edges. */
#ifndef SPI_HALF_BIT
#define SPI_HALF_BIT 40U
#endif
static inline void spi_delay(void)
{
    volatile uint32_t n = SPI_HALF_BIT;
    while (n-- != 0U) { __asm volatile("nop"); }
}

void rp2350_spi_init(void)
{
    /* Only the CPU-driven control lines are set up here. CLK and DATA
     * are owned by the PIO state machine (rp2350_pio_init). */

    /* WL_REG_ON: output, drive low until power-up. */
    gpio_sio_init(CYW43_PIN_WL_REG_ON, 1, 0);
    gpio_clr(CYW43_PIN_WL_REG_ON);

    /* SPI CS: output, drive high (deasserted). */
    gpio_sio_init(CYW43_PIN_SPI_CS, 1, 0);
    gpio_set(CYW43_PIN_SPI_CS);
}

void rp2350_cyw43_power_up(void)
{
    gpio_set(CYW43_PIN_WL_REG_ON);
}

void rp2350_cyw43_power_down(void)
{
    gpio_clr(CYW43_PIN_WL_REG_ON);
}

void rp2350_spi_cs(int assert)
{
    /* CS is active low. */
    if (assert) {
        gpio_clr(CYW43_PIN_SPI_CS);
    }
    else {
        gpio_set(CYW43_PIN_SPI_CS);
    }
    spi_delay();
}

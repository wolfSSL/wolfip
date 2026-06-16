/* sdhci_shim.c
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
 * Platform glue that lets the ZCU102 wolfIP application consume wolfBoot's
 * SD-host-controller and disk drivers (src/sdhci.c, src/disk.c, src/gpt.c)
 * by compiling the SAME driver source into the app - no runtime hand-off.
 * The drivers call out to a handful of platform hooks; this file provides
 * them for the EL2 bare-metal app:
 *
 *   - sdhci_reg_read/write       MMIO at the ZynqMP SD1 controller
 *   - sdhci_platform_init        controller bring-up (FSBL already clocked
 *                                SD1 to boot us, so this is a no-op)
 *   - sdhci_platform_irq_init    polled - no IRQ
 *   - sdhci_platform_set_bus_mode SD (not eMMC) - no-op
 *   - hal_get_timer_us           bridged to the port generic-timer clock
 *   - sdhci_platform_dma_prepare/complete  D-cache maintenance so the
 *                                controller's SDMA sees coherent buffers
 *
 * The SDMA engine DMAs into the caller's buffer directly (sdhci.c writes
 * its address into SRS22), so every buffer handed to the disk layer - the
 * app's staging buffer AND disk.c's own MBR sector buffer - must be made
 * coherent. The clean/invalidate hooks below do that for buffers in the
 * normal write-back-cacheable DDR the app links into.
 */
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include "timer.h"
#include "uart.h"

/* ZynqMP SD1 (the ZCU102 carrier micro-SD slot, boot device for SW6=SD).
 * Matches wolfBoot hal/zynq.c ZYNQMP_SDHCI_BASE = ZYNQMP_SD1_BASE. */
#define ZYNQMP_SD1_BASE     0xFF170000UL

/* IOU_SLCR + CRL_APB registers needed to bring up the SD1 host controller,
 * mirrored from wolfBoot hal/zynq.h (IOU_SLCR_BASE 0xFF180000, CRL_APB_BASE
 * 0xFF5E0000). The SD1 slot type must be set to "Embedded" so the controller
 * reports the card as always present - the ZCU102 carrier does not wire the
 * card-detect pin to the controller, so without this the card-init busy-wait
 * never sees a card and hangs. */
#define IOU_SLCR_SD_CONFIG_REG2     (*(volatile uint32_t *)0xFF180320UL)
#define SD_CONFIG_REG2_SD1_SLOT_SH  28
#define SD_CONFIG_REG2_SD1_SLOT_MSK 0x30000000UL
#define RST_LPD_IOU2                (*(volatile uint32_t *)0xFF5E0238UL)
#define RST_LPD_IOU2_SDIO1          (1UL << 6)

/* The generic wolfBoot sdhci.c driver addresses a Cadence SD4HC controller
 * (HRS registers at 0x000-0x1FF, SRS registers at 0x200+), but ZynqMP has an
 * Arasan SDHCI controller with the standard SDHCI byte-offset register map and
 * width-specific access requirements. sdhci_reg_read/write below translate
 * between the two - this logic is copied verbatim from wolfBoot hal/zynq.c so
 * the app drives the controller identically to wolfBoot. Without it, e.g. the
 * HRS00 soft-reset write lands on the wrong register and the reset-poll hangs. */
#define CADENCE_SRS_OFFSET      0x200

#define STD_SDHCI_SDMA_ADDR     0x00  /* SDMA System Address (32-bit) */
#define STD_SDHCI_HOST_CTRL1    0x28  /* Host Control 1 (8-bit) */
#define STD_SDHCI_POWER_CTRL    0x29  /* Power Control (8-bit) */
#define STD_SDHCI_BLKGAP_CTRL   0x2A  /* Block Gap Control (8-bit) */
#define STD_SDHCI_WAKEUP_CTRL   0x2B  /* Wakeup Control (8-bit) */
#define STD_SDHCI_CLK_CTRL      0x2C  /* Clock Control (16-bit) */
#define STD_SDHCI_TIMEOUT_CTRL  0x2E  /* Timeout Control (8-bit) */
#define STD_SDHCI_SW_RESET      0x2F  /* Software Reset (8-bit) */
#define STD_SDHCI_HOST_CTRL2    0x3C  /* Host Control 2 (16-bit) */
#define STD_SDHCI_SRA           0x01  /* Software Reset for All */

#define SDHCI_SRS15_A64         (1U << 29)  /* 64-bit addressing */
#define SDHCI_SRS15_HV4E        (1U << 28)  /* Host version 4 enable */
#define SDHCI_SRS16_A64S        (1U << 28)  /* 64-bit system bus support */

/* Cortex-A53 data-cache line size. */
#define DCACHE_LINE         64UL

/* ZynqMP system soft reset: CRL_APB.RESET_CTRL, SOFT_RESET (bit 4). Writing
 * it resets the whole PS, so the BootROM re-runs FSBL -> ... -> wolfBoot,
 * which then picks the higher-version image (our freshly staged update). */
#define CRL_APB_RESET_CTRL          (*(volatile uint32_t *)0xFF5E0218UL)
#define CRL_APB_RESET_CTRL_SOFT_RST (1UL << 4)

/* ---- SDHCI register access (Cadence SD4HC -> Arasan translation) --- */
/* Handle reads from Cadence HRS registers (0x000-0x1FF). */
static uint32_t zynqmp_sdhci_hrs_read(uint32_t hrs_offset)
{
    volatile uint8_t *base = (volatile uint8_t *)ZYNQMP_SD1_BASE;

    switch (hrs_offset) {
    case 0x000: { /* HRS00 - Software Reset: map SRA (0x2F bit0) to SWR bit0 */
        uint8_t val = *((volatile uint8_t *)(base + STD_SDHCI_SW_RESET));
        return (val & STD_SDHCI_SRA) ? 1U : 0U;
    }
    case 0x010: /* HRS04 - PHY access: return ACK so wait loops don't hang */
        return (1U << 26); /* SDHCI_HRS04_UIS_ACK */
    default:
        return 0;
    }
}

/* Handle writes to Cadence HRS registers (0x000-0x1FF). */
static void zynqmp_sdhci_hrs_write(uint32_t hrs_offset, uint32_t val)
{
    volatile uint8_t *base = (volatile uint8_t *)ZYNQMP_SD1_BASE;

    switch (hrs_offset) {
    case 0x000: /* HRS00 - Software Reset: issue SRA via 8-bit write at 0x2F */
        if (val & 1U)
            *((volatile uint8_t *)(base + STD_SDHCI_SW_RESET)) = STD_SDHCI_SRA;
        break;
    default:
        break;
    }
}

uint32_t sdhci_reg_read(uint32_t offset)
{
    volatile uint8_t *base = (volatile uint8_t *)ZYNQMP_SD1_BASE;

    if (offset >= CADENCE_SRS_OFFSET) {
        uint32_t std_off = offset - CADENCE_SRS_OFFSET;

        if (std_off == 0x58) /* SRS22 -> SRS00 legacy SDMA address */
            return *((volatile uint32_t *)(base + STD_SDHCI_SDMA_ADDR));
        if (std_off == 0x5C) /* SRS23 -> 0 (no 64-bit addressing on v3.0) */
            return 0;
        {
            uint32_t val = *((volatile uint32_t *)(base + std_off));
            if (std_off == 0x40) /* SRS16 Capabilities: mask A64S */
                val &= ~SDHCI_SRS16_A64S;
            return val;
        }
    }
    return zynqmp_sdhci_hrs_read(offset);
}

void sdhci_reg_write(uint32_t offset, uint32_t val)
{
    volatile uint8_t *base = (volatile uint8_t *)ZYNQMP_SD1_BASE;

    if (offset >= CADENCE_SRS_OFFSET) {
        uint32_t std_off = offset - CADENCE_SRS_OFFSET;

        /* SRS10 (0x228) = standard 0x28-0x2B, byte-wide each. */
        if (std_off == 0x28) {
            *((volatile uint8_t *)(base + STD_SDHCI_HOST_CTRL1)) =
                (uint8_t)(val & 0xFF);
            *((volatile uint8_t *)(base + STD_SDHCI_POWER_CTRL)) =
                (uint8_t)((val >> 8) & 0xFF);
            *((volatile uint8_t *)(base + STD_SDHCI_BLKGAP_CTRL)) =
                (uint8_t)((val >> 16) & 0xFF);
            *((volatile uint8_t *)(base + STD_SDHCI_WAKEUP_CTRL)) =
                (uint8_t)((val >> 24) & 0xFF);
            return;
        }
        /* SRS11 (0x22C) = standard 0x2C (16-bit clk), 0x2E (8-bit timeout),
         * 0x2F (8-bit software reset). */
        if (std_off == 0x2C) {
            *((volatile uint16_t *)(base + STD_SDHCI_CLK_CTRL)) =
                (uint16_t)(val & 0xFFFF);
            *((volatile uint8_t *)(base + STD_SDHCI_TIMEOUT_CTRL)) =
                (uint8_t)((val >> 16) & 0xFF);
            *((volatile uint8_t *)(base + STD_SDHCI_SW_RESET)) =
                (uint8_t)((val >> 24) & 0xFF);
            return;
        }
        /* SRS22 (0x58) -> SRS00 legacy SDMA address (also restarts DMA). */
        if (std_off == 0x58) {
            *((volatile uint32_t *)(base + STD_SDHCI_SDMA_ADDR)) = val;
            return;
        }
        if (std_off == 0x5C) /* SRS23 -> no-op */
            return;
        /* SRS15 (0x3C): Arasan v3.0 lacks HV4E/A64 - mask them off. */
        if (std_off == STD_SDHCI_HOST_CTRL2)
            val &= ~(SDHCI_SRS15_HV4E | SDHCI_SRS15_A64);

        *((volatile uint32_t *)(base + std_off)) = val;
        return;
    }
    zynqmp_sdhci_hrs_write(offset, val);
}

/* ---- SDHCI platform bring-up -------------------------------------- */
/* The FSBL already configured the SD1 MIO pinmux and reference clock to
 * boot us, so the clock tree is live. But sdhci_init() soft-resets the
 * controller, and on that reset the Capabilities register re-latches the
 * IOU_SLCR slot type. We must (re)assert "Embedded slot" for SD1 and pulse
 * the SDIO1 controller reset so the capability is picked up - otherwise the
 * controller reports no card present (the CD pin is not wired on ZCU102)
 * and sdcard_card_init() busy-waits forever. This mirrors wolfBoot's own
 * hal/zynq.c sdhci_platform_init() exactly. */
void sdhci_platform_init(void)
{
    volatile int i;
    uint32_t reg;

    reg = IOU_SLCR_SD_CONFIG_REG2;
    reg &= ~SD_CONFIG_REG2_SD1_SLOT_MSK;
    reg |= (1UL << SD_CONFIG_REG2_SD1_SLOT_SH); /* 01 = Embedded */
    IOU_SLCR_SD_CONFIG_REG2 = reg;

    RST_LPD_IOU2 |= RST_LPD_IOU2_SDIO1;         /* assert SDIO1 reset */
    for (i = 0; i < 100; i++) {}
    RST_LPD_IOU2 &= ~RST_LPD_IOU2_SDIO1;        /* de-assert */
    for (i = 0; i < 1000; i++) {}

    /* Real settle time for the controller + slot-type/present-state to
     * stabilize after the reset. wolfBoot's busy-loop above is marginal when
     * re-initializing a controller wolfBoot already used; without this the
     * Card-State-Stable bit can read 0 on the fast (non-debug) path. */
    delay_us(10000); /* 10 ms */
}

void sdhci_platform_irq_init(void)
{
}

void sdhci_platform_set_bus_mode(int is_emmc)
{
    (void)is_emmc;
}

/* ---- Timer bridge -------------------------------------------------- */
/* wolfBoot's sdhci.c udelay() needs microseconds. timer_now() is a raw
 * up-counter at timer_freq() Hz. The seconds/remainder split avoids the
 * 64-bit overflow a plain (ticks * 1000000) would hit at long uptimes; it
 * equals (ticks * 1000000) / freq for all inputs. */
uint64_t hal_get_timer_us(void)
{
    uint64_t ticks = timer_now();
    uint64_t freq  = timer_freq();

    return (ticks / freq) * 1000000ULL + ((ticks % freq) * 1000000ULL) / freq;
}

/* ---- SDMA cache maintenance --------------------------------------- */
/* Clean+invalidate the data cache over [start, start+sz). dc civac writes
 * back any dirty line before invalidating, so it is safe even when the
 * buffer's first/last cache line is shared with unrelated data (a partial
 * dc ivac there would drop a neighbour's dirty bytes). Used for both
 * directions: before a transfer it pushes CPU writes to memory and drops
 * stale lines; after a read it drops the lines the DMA wrote underneath. */
static void dcache_civac_range(uintptr_t start, uint32_t sz)
{
    uintptr_t addr = start & ~(DCACHE_LINE - 1UL);
    uintptr_t end  = start + sz;

    __asm__ volatile ("dsb sy" ::: "memory");
    while (addr < end) {
        __asm__ volatile ("dc civac, %0" :: "r"(addr) : "memory");
        addr += DCACHE_LINE;
    }
    __asm__ volatile ("dsb sy" ::: "memory");
}

void sdhci_platform_dma_prepare(void *buf, uint32_t sz, int is_write)
{
    (void)is_write;
    dcache_civac_range((uintptr_t)buf, sz);
}

void sdhci_platform_dma_complete(void *buf, uint32_t sz, int is_write)
{
    /* After a card->memory read the DMA wrote memory directly; invalidate
     * (clean+invalidate) so the CPU reloads the fresh data. Nothing to do
     * after a memory->card write. */
    if (!is_write)
        dcache_civac_range((uintptr_t)buf, sz);
}

/* ---- System reset -------------------------------------------------- */
void ota_system_reset(void)
{
    /* Let the UART FIFO drain before the PS reset, otherwise the last log
     * lines ("...resetting to apply update") are truncated and the reset
     * looks like a crash. 50 ms is ample for a few lines at 115200. */
    delay_us(50000);
    __asm__ volatile ("dsb sy" ::: "memory");
    CRL_APB_RESET_CTRL = CRL_APB_RESET_CTRL_SOFT_RST;
    for (;;)
        __asm__ volatile ("wfi");
}

/* ---- Optional wolfBoot_printf backend (SDHCI_DEBUG=1) -------------- */
/* When the wolfBoot driver objects are built with -DDEBUG_UART, printf.h
 * routes wolfBoot_printf() to uart_printf()/uart_write(); supply minimal
 * implementations on top of the port's uart_putc(). Covers the format
 * specifiers the driver debug uses: %d %u %x %X (with 0-pad width) %p %llu
 * %s %c %%. Unreferenced (and dropped by -gc-sections) in non-debug builds. */
static void uart_put_u64(uint64_t v)
{
    char buf[20];
    int n = 0;

    if (v == 0) {
        uart_putc('0');
        return;
    }
    while (v != 0 && n < (int)sizeof(buf)) {
        buf[n++] = (char)('0' + (v % 10ULL));
        v /= 10ULL;
    }
    while (n > 0)
        uart_putc(buf[--n]);
}

static void uart_put_hex(uint64_t v, int upper, int width, int zero)
{
    const char *d = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char buf[16];
    int n = 0;

    if (v == 0)
        buf[n++] = '0';
    while (v != 0 && n < (int)sizeof(buf)) {
        buf[n++] = d[v & 0xFULL];
        v >>= 4;
    }
    while (n < width) {
        uart_putc(zero ? '0' : ' ');
        width--;
    }
    while (n > 0)
        uart_putc(buf[--n]);
}

void uart_write(const char *buf, unsigned int sz)
{
    unsigned int i;

    for (i = 0; i < sz; i++)
        uart_putc(buf[i]);
}

void uart_printf(const char *fmt, ...)
{
    va_list ap;
    int width;
    int zero;
    int lng;
    char c;

    va_start(ap, fmt);
    while (*fmt != '\0') {
        if (*fmt != '%') {
            uart_putc(*fmt++);
            continue;
        }
        fmt++;
        zero = 0;
        width = 0;
        lng = 0;
        if (*fmt == '0') {
            zero = 1;
            fmt++;
        }
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt - '0');
            fmt++;
        }
        while (*fmt == 'l') {
            lng++;
            fmt++;
        }
        c = *fmt++;
        switch (c) {
            case 'd': {
                int v = va_arg(ap, int);
                if (v < 0) {
                    uart_putc('-');
                    uart_put_u64((uint64_t)(-(int64_t)v));
                } else {
                    uart_put_u64((uint64_t)v);
                }
                break;
            }
            case 'u':
                uart_put_u64(lng >= 2 ? va_arg(ap, uint64_t)
                                      : (uint64_t)va_arg(ap, unsigned int));
                break;
            case 'x':
            case 'X':
                uart_put_hex(lng >= 2 ? va_arg(ap, uint64_t)
                                      : (uint64_t)va_arg(ap, unsigned int),
                             c == 'X', width, zero);
                break;
            case 'p':
                uart_putc('0');
                uart_putc('x');
                uart_put_hex((uint64_t)(uintptr_t)va_arg(ap, void *), 0, 0, 0);
                break;
            case 's': {
                const char *s = va_arg(ap, const char *);
                uart_puts(s != NULL ? s : "(null)");
                break;
            }
            case 'c':
                uart_putc((char)va_arg(ap, int));
                break;
            case '%':
                uart_putc('%');
                break;
            default:
                uart_putc('%');
                uart_putc(c);
                break;
        }
    }
    va_end(ap);
}

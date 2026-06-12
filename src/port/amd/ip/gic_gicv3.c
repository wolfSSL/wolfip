/* gic.c
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
 * GICv3 minimal driver for Cortex-A72 on Versal Gen 1. GICv3 differs
 * from the ZCU102's GIC-400 (GICv2) in three structural ways:
 *
 *   - The CPU interface is accessed via AArch64 system registers
 *     (ICC_*_EL1 / ICC_*_EL3) rather than memory-mapped GICC.
 *   - Each CPU has its own redistributor (GICR) memory map; SGI/PPI
 *     enable/priority/group regs live there instead of GICD.
 *   - Affinity routing is the default; legacy CPU-target byte fields
 *     do not exist for SPIs.
 *
 * BL31 (TF-A) on Versal normally initialises the GIC distributor and
 * the per-CPU redistributor for us; we only re-prime per-INTID config
 * for the SPIs we use and enable the CPU interface for our EL.
 *
 * Brought up on a VMK180 (Cortex-A72 EL3). Adapted from the GICv2
 * driver under src/port/zcu102/gic.c for GICv3 system registers and
 * the per-CPU redistributor.
 */
#include <stdint.h>
#include "board.h"
#include "gic.h"

/* Distributor registers */
#define GICD_CTLR           (*(volatile uint32_t *)(GICD_BASE + 0x000))
#define GICD_TYPER          (*(volatile uint32_t *)(GICD_BASE + 0x004))
#define GICD_IGROUPR(n)     (*(volatile uint32_t *)(GICD_BASE + 0x080 + 4*(n)))
#define GICD_ISENABLER(n)   (*(volatile uint32_t *)(GICD_BASE + 0x100 + 4*(n)))
#define GICD_ICENABLER(n)   (*(volatile uint32_t *)(GICD_BASE + 0x180 + 4*(n)))
#define GICD_ISPENDR(n)     (*(volatile uint32_t *)(GICD_BASE + 0x200 + 4*(n)))
#define GICD_ICPENDR(n)     (*(volatile uint32_t *)(GICD_BASE + 0x280 + 4*(n)))
#define GICD_IPRIORITYR(n)  (*(volatile uint32_t *)(GICD_BASE + 0x400 + 4*(n)))
#define GICD_ICFGR(n)       (*(volatile uint32_t *)(GICD_BASE + 0xC00 + 4*(n)))
#define GICD_IROUTER(n)     (*(volatile uint64_t *)(GICD_BASE + 0x6000 + 8*(n)))

#define GICD_CTLR_ARE_S     (1u << 4)
#define GICD_CTLR_ARE_NS    (1u << 5)
#define GICD_CTLR_ENG0      (1u << 0)
#define GICD_CTLR_ENG1S     (1u << 2)

/* Redistributor for CPU 0 */
#define GICR_CTLR           (*(volatile uint32_t *)(GICR_BASE + 0x000))
#define GICR_WAKER          (*(volatile uint32_t *)(GICR_BASE + 0x014))

#define GICR_SGI_BASE       (GICR_BASE + 0x10000)
#define GICR_IGROUPR0       (*(volatile uint32_t *)(GICR_SGI_BASE + 0x080))
#define GICR_ISENABLER0     (*(volatile uint32_t *)(GICR_SGI_BASE + 0x100))
#define GICR_ICENABLER0     (*(volatile uint32_t *)(GICR_SGI_BASE + 0x180))
#define GICR_IPRIORITYR(n)  (*(volatile uint32_t *)(GICR_SGI_BASE + 0x400 + 4*(n)))
#define GICR_ICFGR0         (*(volatile uint32_t *)(GICR_SGI_BASE + 0xC00))
#define GICR_ICFGR1         (*(volatile uint32_t *)(GICR_SGI_BASE + 0xC04))

#define GICR_WAKER_PS       (1u << 1)
#define GICR_WAKER_CA       (1u << 2)

#define GIC_NR_LINES        224
static gic_handler_t handlers[GIC_NR_LINES];
static volatile uint32_t g_irq_total;
static volatile uint32_t g_irq_last_intid;

void gic_register_handler(uint32_t intid, gic_handler_t fn)
{
    if (intid < GIC_NR_LINES)
        handlers[intid] = fn;
}

/* ICC_*_EL1 / ICC_*_EL3 system register accessors. The encoded
 * MSR/MRS forms below avoid relying on a particular assembler
 * version supporting the symbolic names. */
static inline void icc_sre_el3_set(uint64_t v)
{
    __asm__ volatile ("msr S3_6_C12_C12_5, %0" :: "r"(v));
    __asm__ volatile ("isb" ::: "memory");
}

static inline void icc_pmr_el1_set(uint64_t v)
{
    __asm__ volatile ("msr S3_0_C4_C6_0, %0" :: "r"(v));
}

static inline void icc_igrpen1_el1_set(uint64_t v)
{
    __asm__ volatile ("msr S3_0_C12_C12_7, %0" :: "r"(v));
}

static inline void icc_igrpen0_el1_set(uint64_t v)
{
    __asm__ volatile ("msr S3_0_C12_C12_6, %0" :: "r"(v));
}

static inline uint64_t icc_iar1_el1_read(void)
{
    uint64_t v;
    __asm__ volatile ("mrs %0, S3_0_C12_C12_0" : "=r"(v));
    return v;
}

static inline void icc_eoir1_el1_write(uint64_t v)
{
    __asm__ volatile ("msr S3_0_C12_C12_1, %0" :: "r"(v));
}

static inline void icc_ctlr_el1_set(uint64_t v)
{
    __asm__ volatile ("msr S3_0_C12_C12_4, %0" :: "r"(v));
}

static void gicr_wakeup(void)
{
    uint32_t waker = GICR_WAKER;
    waker &= ~GICR_WAKER_PS;
    GICR_WAKER = waker;
    while (GICR_WAKER & GICR_WAKER_CA)
        ;
}

void gic_init(void)
{
    uint32_t i;

    GICD_CTLR = GICD_CTLR_ARE_S | GICD_CTLR_ENG1S;

    for (i = 1; i < (GIC_NR_LINES / 32u); i++) {
        GICD_IGROUPR(i) = 0xFFFFFFFFu;
        GICD_ICENABLER(i) = 0xFFFFFFFFu;
    }
    for (i = 8u; i < (GIC_NR_LINES / 4u); i++)
        GICD_IPRIORITYR(i) = 0xA0A0A0A0u;
    for (i = 32; i < GIC_NR_LINES; i++)
        GICD_IROUTER(i) = 0;

    gicr_wakeup();
    GICR_IGROUPR0 = 0xFFFFFFFFu;
    GICR_ICENABLER0 = 0xFFFFFFFFu;
    for (i = 0; i < 8; i++)
        GICR_IPRIORITYR(i) = 0xA0A0A0A0u;

    icc_sre_el3_set(0xF);
    icc_pmr_el1_set(0xF8);
    icc_ctlr_el1_set(0);
    icc_igrpen1_el1_set(1);
    icc_igrpen0_el1_set(1);
}

/* NOTE: the GICv3 SPI-IRQ delivery path is intentionally UNUSED and
 * UNVERIFIED on these ports. Versal drives RX by polling gem_isr() from the
 * main loop (ip/gem_rx_swq_poll.c; gem_rx_install() is a no-op and never
 * calls gic_enable_spi()). The Group / IGROUPR programming here has not been
 * validated to deliver an SPI to the Secure EL3 context and would need
 * review (Group 0 Secure or Group 1 Secure via IGRPMODR, plus the EL3
 * ICC_* registers) before enabling IRQ-driven RX. */
void gic_enable_spi(uint32_t intid, uint32_t priority)
{
    uint32_t reg, shift;
    volatile uint8_t *prio_byte;

    prio_byte = (volatile uint8_t *)(GICD_BASE + 0x400);
    prio_byte[intid] = (uint8_t)(priority & 0xF8u);

    GICD_IGROUPR(intid >> 5) |= (1u << (intid & 31u));
    GICD_IROUTER(intid) = 0;

    shift = (intid & 15u) * 2u;
    reg = GICD_ICFGR(intid >> 4);
    reg &= ~(3u << shift);
    GICD_ICFGR(intid >> 4) = reg;

    GICD_ICPENDR(intid >> 5) = (1u << (intid & 31u));
    GICD_ISENABLER(intid >> 5) = (1u << (intid & 31u));
}

void irq_dispatch(void)
{
    uint64_t iar;
    uint32_t intid;

    iar   = icc_iar1_el1_read();
    intid = (uint32_t)(iar & 0xFFFFFFu);
    if (intid >= 1020u)               /* 1020-1023 spurious / no pending */
        return;                       /* do not EOI a spurious INTID */
    g_irq_total++;
    g_irq_last_intid = intid;
    if (intid < GIC_NR_LINES && handlers[intid] != 0)
        handlers[intid]();
    icc_eoir1_el1_write(iar);
}

uint32_t gic_total_irqs(void)      { return g_irq_total; }
uint32_t gic_last_intid(void)      { return g_irq_last_intid; }

uint32_t gic_is_pending(uint32_t intid)
{
    return (GICD_ISPENDR(intid >> 5) >> (intid & 31u)) & 1u;
}

void gic_disable_spi(uint32_t intid)
{
    GICD_ICENABLER(intid >> 5) = (1u << (intid & 31u));
}

void gic_self_test_sgi(uint32_t intid)
{
    /* GICv3 ICC_SGI1R_EL1: target self via target list 1 */
    uint64_t v = ((uint64_t)(intid & 0xF) << 24) | 1u;
    __asm__ volatile ("msr S3_0_C12_C11_5, %0" :: "r"(v));
    __asm__ volatile ("isb" ::: "memory");
}

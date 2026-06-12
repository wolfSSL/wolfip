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
 * GICv2 (mem-mapped distributor + CPU interface) minimal driver,
 * shared by the GICv2 boards (ZynqMP Cortex-A53 EL3 / Zynq-7000
 * Cortex-A9). Register bases come from board.h.
 * Configures all SPIs as Group 0 (IGROUPR bits cleared), level-
 * triggered, targeted at CPU0, priority 0xA0. With GICC_CTLR.FIQEn=0
 * a pending Group 0 interrupt is delivered as IRQ, not FIQ. Only
 * the SPIs explicitly enabled via gic_enable_spi() will fire. The
 * IRQ vector in startup.S funnels into irq_dispatch() here, which
 * reads IAR, routes to the registered C handler, and EOIs.
 *
 * No assumptions about a previous BSP - we initialize the distributor
 * and CPU interface from scratch.
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
#define GICD_ITARGETSR(n)   (*(volatile uint32_t *)(GICD_BASE + 0x800 + 4*(n)))
#define GICD_ICFGR(n)       (*(volatile uint32_t *)(GICD_BASE + 0xC00 + 4*(n)))
#define GICD_SGIR           (*(volatile uint32_t *)(GICD_BASE + 0xF00))

/* CPU interface registers */
#define GICC_CTLR           (*(volatile uint32_t *)(GICC_BASE + 0x000))
#define GICC_PMR            (*(volatile uint32_t *)(GICC_BASE + 0x004))
#define GICC_BPR            (*(volatile uint32_t *)(GICC_BASE + 0x008))
#define GICC_IAR            (*(volatile uint32_t *)(GICC_BASE + 0x00C))
#define GICC_EOIR           (*(volatile uint32_t *)(GICC_BASE + 0x010))

#define GIC_NR_LINES        192    /* GICv2 architecturally supports up to 192 SPIs */

static gic_handler_t handlers[GIC_NR_LINES];
static volatile uint32_t g_irq_total;
static volatile uint32_t g_irq_last_intid;

void gic_register_handler(uint32_t intid, gic_handler_t fn)
{
    if (intid < GIC_NR_LINES)
        handlers[intid] = fn;
}

static void byte_write(volatile uint32_t *reg, uint32_t intid, uint8_t val)
{
    uint32_t shift;
    uint32_t v;
    shift = (intid & 3u) * 8u;
    v = reg[intid >> 2];
    v &= ~(0xFFu << shift);
    v |= ((uint32_t)val << shift);
    reg[intid >> 2] = v;
}

void gic_enable_spi(uint32_t intid, uint32_t priority)
{
    /* Set priority (lower number = higher prio). */
    byte_write((volatile uint32_t *)(GICD_BASE + 0x400),
               intid, (uint8_t)(priority & 0xF8u));
    /* Target CPU0. */
    byte_write((volatile uint32_t *)(GICD_BASE + 0x800),
               intid, 0x01u);
    /* Group 0 (Secure) - we run at EL3 Secure, so Group 0 is the
     * correct choice. GICC.FIQEn=0 makes Group 0 route to IRQ, which
     * is what our vector table handles. */
    GICD_IGROUPR(intid >> 5) &= ~(1u << (intid & 31u));
    /* Level-triggered (ICFGR bits = 0b00 -> level, 0b10 -> edge). */
    {
        uint32_t reg;
        uint32_t shift;
        shift = (intid & 15u) * 2u;
        reg = GICD_ICFGR(intid >> 4);
        reg &= ~(3u << shift);
        GICD_ICFGR(intid >> 4) = reg;
    }
    /* Clear pending and enable. */
    GICD_ICPENDR(intid >> 5) = (1u << (intid & 31u));
    GICD_ISENABLER(intid >> 5) = (1u << (intid & 31u));
}

void gic_disable_spi(uint32_t intid)
{
    GICD_ICENABLER(intid >> 5) = (1u << (intid & 31u));
}

void gic_init(void)
{
    uint32_t i;

    /* Disable distributor while we reconfigure. */
    GICD_CTLR = 0;

    /* SGIs and PPIs (INTID 0..31): Group 0 Secure, but leave disabled
     * for now - enabling them lit up some pending PPI from CSU/PMU
     * that hung wolfIP_init when it occupied the CPU interface. */
    GICD_IGROUPR(0)   = 0;
    GICD_ICENABLER(0) = 0xFFFFFFFFu;
    GICD_ICPENDR(0)   = 0xFFFFFFFFu;
    /* SPIs (INTID 32+): disable all, mark all as Group 0. */
    for (i = 1; i < (GIC_NR_LINES / 32u); i++) {
        GICD_ICENABLER(i) = 0xFFFFFFFFu;
        GICD_ICPENDR(i)   = 0xFFFFFFFFu;
        GICD_IGROUPR(i)   = 0;
    }
    /* SGI/PPI priorities (lower 8 entries cover INTID 0..31). */
    for (i = 0; i < 8u; i++)
        GICD_IPRIORITYR(i) = 0xA0A0A0A0u;
    for (i = 8u; i < (GIC_NR_LINES / 4u); i++)
        GICD_IPRIORITYR(i) = 0xA0A0A0A0u;
    for (i = 8u; i < (GIC_NR_LINES / 4u); i++)
        GICD_ITARGETSR(i) = 0x01010101u;
    for (i = 2u; i < (GIC_NR_LINES / 16u); i++)
        GICD_ICFGR(i) = 0;

    /* Enable distributor: both groups (we are at EL3). */
    GICD_CTLR = 0x3u;

    /* CPU interface: priority mask wide open, both groups enabled,
     * FIQEn=0 so Group 0 (Secure) interrupts route to nIRQ output
     * (per GICv2 IHI 0048B 4.6.4: FIQEn=0 -> nIRQ, FIQEn=1 -> nFIQ).
     * AckCtl=1 so Secure reads of GICC_IAR can ack Group 1 too. */
    GICC_PMR = 0xF8u;
    GICC_BPR = 0;
    GICC_CTLR = 0x07u;    /* EnableGrp0 | EnableGrp1 | AckCtl, FIQEn=0 */
}

void irq_dispatch(void)
{
    uint32_t iar;
    uint32_t intid;

    iar   = GICC_IAR;
    intid = iar & 0x3FFu;
    if (intid >= 1020u)               /* 1020-1023 spurious / no pending */
        return;                       /* do not EOI a spurious INTID */
    g_irq_total++;
    g_irq_last_intid = intid;
    if (intid < GIC_NR_LINES && handlers[intid] != 0)
        handlers[intid]();
    GICC_EOIR = iar;
}

uint32_t gic_total_irqs(void)      { return g_irq_total; }
uint32_t gic_last_intid(void)      { return g_irq_last_intid; }

uint32_t gic_poll_dispatch(void)
{
    uint32_t n = 0;
    uint32_t iar;
    uint32_t intid;

    /* Drain up to 8 interrupts per poll to avoid live-locking the
     * main loop if a peripheral is hammering us. */
    while (n < 8) {
        iar   = GICC_IAR;
        intid = iar & 0x3FFu;
        if (intid >= 1020)            /* 1023 spurious / no pending */
            break;
        g_irq_total++;
        g_irq_last_intid = intid;
        if (intid < GIC_NR_LINES && handlers[intid] != 0)
            handlers[intid]();
        GICC_EOIR = iar;
        n++;
    }
    return n;
}

uint32_t gic_is_pending(uint32_t intid)
{
    return (GICD_ISPENDR(intid >> 5) >> (intid & 31u)) & 1u;
}

void gic_self_test_sgi(uint32_t intid)
{
    /* GICD_SGIR: TargetListFilter (bits 25:24) = 10 (self),
     * SGIINTID (bits 3:0) = intid. */
    GICD_SGIR = (2u << 24) | (intid & 0xFu);
}

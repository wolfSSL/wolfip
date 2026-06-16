/* mmu.c
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
 * ARMv7-A short-format L1 page tables (4 KB-aligned, 16 KB total,
 * 4096 1 MB section descriptors covering the whole 32-bit VA space).
 * Sufficient for a flat-mapped bare-metal app on Zynq-7000 PS.
 *
 *   0x00000000 - 0x3FFFFFFF  DDR (1 GB) - Normal WB cacheable
 *   0x40000000 - 0xDFFFFFFF  unmapped (PL interconnect / SMC ranges)
 *   0xE0000000 - 0xFFFFFFFF  PS peripherals (UART, GEM, SLCR, GIC, OCM)
 *                            mostly Device-nGnRnE, except the OCM
 *                            high-mapping (0xFFFC0000..0xFFFFFFFF)
 *                            which is Normal Non-Cacheable executable
 *                            (SEC_NORMAL_NC) for GEM DMA coherency.
 *
 * Short descriptor section format (1 MB, supersection ignored):
 *   bits [31:20] = section base
 *   bits [19:18] = NS, NS for non-secure (we are Secure -> 0)
 *   bit  [17]    = nG (global)
 *   bit  [16]    = S  (shareable)
 *   bits [14:12] = TEX
 *   bits [11:10] = AP[1:0]
 *   bit  [15]    = AP[2]
 *   bit  [9]     = IMPDEF
 *   bits [8:5]   = Domain
 *   bit  [4]     = XN (execute never)
 *   bit  [3]     = C
 *   bit  [2]     = B
 *   bits [1:0]   = 10 (section)
 *
 * TEX[2:0] + C + B encoding for Normal WB cacheable (TEX=001, C=1, B=1)
 * and Shareable Device (TEX=000, C=0, B=1) per ARMv7-A short descriptor.
 *
 * Brought up on a ZC702 (Cortex-A9).
 */
#include <stdint.h>
#include "mmu.h"

static volatile uint32_t L1[4096] __attribute__((aligned(16384),
                                                 section(".page_tables")));

#define SEC_NORMAL_WB(addr) \
    (((addr) & 0xFFF00000u) | \
     (1u << 12) |       /* TEX[0] = 1 */ \
     (1u << 10) |       /* AP[1] = 1 (RW PL1+) */ \
     (1u << 3)  |       /* C */ \
     (1u << 2)  |       /* B */ \
     0x2u)              /* section */

#define SEC_DEVICE(addr) \
    (((addr) & 0xFFF00000u) | \
     (1u << 10) |       /* AP[1] */ \
     (1u << 4)  |       /* XN */ \
     (1u << 2)  |       /* B (shareable device) */ \
     0x2u)

/* Normal, Non-cacheable, executable (TEX=001, C=0, B=0). Used for the
 * OCM section so the GEM DMA descriptor rings and frame buffers (which
 * live in OCM) are coherent with the Cortex-A9 without per-descriptor
 * cache maintenance. The 8-byte GEM BDs otherwise share 32-byte cache
 * lines (4 BDs per line), and cleaning one BD's line read-modify-writes
 * the MAC's OWN bits on the neighbours, stalling RX. Code still executes
 * from this region (not XN); it is just slower than cached. */
#define SEC_NORMAL_NC(addr) \
    (((addr) & 0xFFF00000u) | \
     (1u << 12) |       /* TEX[0] = 1 -> TEX=001 (Normal) */ \
     (1u << 10) |       /* AP[1] = 1 (RW PL1+) */ \
     0x2u)              /* C=0, B=0 -> non-cacheable; section */

#define SEC_INVALID         (0u)

extern uint8_t _dma_buffers_start[];
extern uint8_t _dma_buffers_end[];

static void mmu_build_tables(void)
{
    uint32_t i;
    uint32_t addr;
    uint32_t dma_lo = (uint32_t)(uintptr_t)_dma_buffers_start;
    uint32_t dma_hi = (uint32_t)(uintptr_t)_dma_buffers_end;

    for (i = 0; i < 4096; i++)
        L1[i] = SEC_INVALID;

    /* DDR 0x00000000 - 0x3FFFFFFF (1 GB) Normal WB cacheable, except any
     * 1 MB section overlapping the GEM DMA region, which is Normal-NC. In
     * the OCM layout the DMA buffers live in OCM (mapped NC below), so no
     * DDR section is carved and all of DDR stays cacheable. In the DDR
     * layout (the wolfBoot / cached-code path) the rings sit in DDR and
     * MUST be NC: the 8-byte GEM BDs share 32-byte cache lines, so a
     * cacheable ring lets a cache-line clean write stale neighbour BDs back
     * over MAC-set OWN bits and wedges RX under sustained load (HIGH-2). */
    for (i = 0; i < 1024; i++) {
        addr = i * 0x100000u;
        if (addr + 0x100000u <= dma_lo || addr >= dma_hi)
            L1[i] = SEC_NORMAL_WB(addr);
        else
            L1[i] = SEC_NORMAL_NC(addr);
    }

    /* PS peripherals at 0xE0000000 - 0xFEFFFFFF (Device). */
    for (i = 0xE00; i < 0xFF0; i++) {
        addr = i * 0x100000u;
        L1[i] = SEC_DEVICE(addr);
    }

    /* OCM high mapping 0xFFFC0000 - 0xFFFFFFFF (last 256 KB of 4 GB).
     * The section at 0xFFF00000 (1 MB) covers it. Mark Normal
     * NON-cacheable but executable: the whole app (code, data, stack and
     * the GEM DMA rings/buffers) lives in OCM, and the descriptors must be
     * non-cacheable for DMA coherency (see SEC_NORMAL_NC). */
    L1[0xFFF] = SEC_NORMAL_NC(0xFFF00000u);
}

void mmu_enable(void)
{
    uint32_t sctlr;

    mmu_build_tables();

    /* DACR: domain 0 = Client (check permissions). */
    __asm__ volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r"(0x55555555u));

    /* TTBR0 = L1 (low 32 bits of physical address). TTBR1 unused. */
    __asm__ volatile ("mcr p15, 0, %0, c2, c0, 0" :: "r"((uint32_t)L1));
    __asm__ volatile ("mcr p15, 0, %0, c2, c0, 2" :: "r"(0u));  /* TTBCR=0 */

    /* Invalidate TLB + I-cache. */
    __asm__ volatile ("mcr p15, 0, %0, c8, c7, 0" :: "r"(0u));  /* TLBIALL */
    __asm__ volatile ("mcr p15, 0, %0, c7, c5, 0" :: "r"(0u));  /* ICIALLU */
    __asm__ volatile ("dsb" ::: "memory");
    __asm__ volatile ("isb" ::: "memory");

    /* Enable MMU + I-cache + D-cache. */
    __asm__ volatile ("mrc p15, 0, %0, c1, c0, 0" : "=r"(sctlr));
    sctlr |= (1u << 0);   /* M */
    sctlr |= (1u << 2);   /* C */
    sctlr |= (1u << 12);  /* I */
    sctlr &= ~(1u << 1);  /* A off */
    __asm__ volatile ("mcr p15, 0, %0, c1, c0, 0" :: "r"(sctlr));
    __asm__ volatile ("isb" ::: "memory");
}

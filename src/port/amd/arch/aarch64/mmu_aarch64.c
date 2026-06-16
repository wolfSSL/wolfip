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
 * Minimal MMU bring-up for A53/A72 at EL3 with a 32-bit virtual address
 * space (T0SZ=32, start level L1). Static tables map the full 4 GB VA
 * range:
 *
 *   L1[0]  -> L2_DDR     (0x00000000 .. 0x3FFFFFFF, 1 GB, 2 MB granular)
 *   L1[1]  -> 0x40000000 .. 0x7FFFFFFF Normal WB IS (1 GB block)
 *   L1[2]  -> invalid    (0x80000000 .. 0xBFFFFFFF)
 *   L1[3]  -> L2_PERIPH  (0xC0000000 .. 0xFFFFFFFF, 1 GB, 2 MB granular)
 *
 * L2_DDR has a Normal-NC carve-out for any 2 MB block overlapping the
 * linker's [_dma_buffers_start, _dma_buffers_end) range. In the current
 * OCM-only layout the .dma_buffers section lives in OCM (mapped via
 * L2_PERIPH[511] Normal-WB), so this carve-out is effectively dormant -
 * GEM DMA coherency is handled with explicit DC CVAC / IVAC ops in
 * gem.c. The carve-out remains in the tables so a future DDR-resident
 * layout works without an MMU change.
 *
 * L2_PERIPH covers the PS peripheral aperture as Device-nGnRnE except
 * entry 511 (0xFFE00000..0xFFFFFFFF) which is Normal-WB executable so
 * code can be fetched from OCM (0xFFFC0000..0xFFFFFFFF) after the MMU
 * is enabled.
 *
 * MAIR_EL3:
 *   ATTR0 = 0xFF (Normal Inner+Outer WB Cacheable, Read+Write alloc)
 *   ATTR1 = 0x00 (Device-nGnRnE - PS peripherals)
 *   ATTR2 = 0x44 (Normal Inner+Outer Non-Cacheable - reserved for a
 *                 future DDR DMA carve-out)
 *
 * Block descriptor low attributes:
 *   bits[1:0]  = 0b01 block
 *   bits[5:2]  = AttrIndx
 *   bits[7:6]  = AP = 0 (RW at EL3)
 *   bits[9:8]  = SH = 0b11 inner-shareable (only meaningful for Normal)
 *   bit[10]    = AF = 1
 *   bit[54]    = UXN/XN = 1 for Device, 0 for Normal RX
 */
#include <stdint.h>
#include "mmu.h"

extern uint8_t _dma_buffers_start[];
extern uint8_t _dma_buffers_end[];

/* L1 has 4 entries (one per GB in our 4 GB VA). Section attribute keeps
 * it in the dedicated .page_tables area so it lives at a known DDR
 * address - the MMU walker still uses physical addresses to read it. */
static volatile uint64_t L1[512]
    __attribute__((aligned(4096), section(".page_tables")));
static volatile uint64_t L2_DDR[512]
    __attribute__((aligned(4096), section(".page_tables")));
/* L2 for the 3-4 GB region. Most blocks are Device (PS peripherals)
 * but the 2 MB block at 0xFFE00000 - 0xFFFFFFFF must be Normal+exec
 * because OCM (0xFFFC0000-0xFFFFFFFF) lives there and our code runs
 * from OCM. */
static volatile uint64_t L2_PERIPH[512]
    __attribute__((aligned(4096), section(".page_tables")));

#define DESC_VALID          (1ULL << 0)
#define DESC_TABLE          (1ULL << 1)
#define DESC_BLOCK          (0ULL << 1)
#define DESC_AF             (1ULL << 10)
#define DESC_SH_INNER       (3ULL << 8)
#define DESC_AP_RW_EL3      (0ULL << 6)
#define DESC_XN             (1ULL << 54)
#define DESC_ATTR(i)        (((uint64_t)(i) & 7ULL) << 2)

#define ATTR_NORMAL         0   /* AttrIndx 0 = MAIR ATTR0 (Normal WB) */
#define ATTR_DEVICE         1   /* AttrIndx 1 = MAIR ATTR1 (Device)    */
#define ATTR_NORMAL_NC      2   /* AttrIndx 2 = MAIR ATTR2 (Normal NC) */

#define BLOCK_NORMAL(pa) \
    (((uint64_t)(pa)) | DESC_BLOCK | DESC_VALID | DESC_AF | \
     DESC_SH_INNER | DESC_AP_RW_EL3 | DESC_ATTR(ATTR_NORMAL))

#define BLOCK_DEVICE(pa) \
    (((uint64_t)(pa)) | DESC_BLOCK | DESC_VALID | DESC_AF | \
     DESC_AP_RW_EL3 | DESC_ATTR(ATTR_DEVICE) | DESC_XN)

#define BLOCK_NORMAL_NC(pa) \
    (((uint64_t)(pa)) | DESC_BLOCK | DESC_VALID | DESC_AF | \
     DESC_SH_INNER | DESC_AP_RW_EL3 | DESC_ATTR(ATTR_NORMAL_NC) | DESC_XN)

/* Normal Non-Cacheable but executable (no XN) -- for the OCM block in the
 * OCM layout, where code, data and the GEM BD rings all share OCM. */
#define BLOCK_NORMAL_NC_EXEC(pa) \
    (((uint64_t)(pa)) | DESC_BLOCK | DESC_VALID | DESC_AF | \
     DESC_SH_INNER | DESC_AP_RW_EL3 | DESC_ATTR(ATTR_NORMAL_NC))

#define TABLE_DESC(pa) \
    (((uint64_t)(pa)) | DESC_TABLE | DESC_VALID)

#define L2_BLOCK_SIZE       (2ULL * 1024 * 1024)        /* 2 MB */
#define L1_BLOCK_SIZE       (1024ULL * 1024 * 1024)     /* 1 GB */

static void mmu_build_tables(void)
{
    uint64_t addr;
    uint64_t dma_lo;
    uint64_t dma_hi;
    int i;

    /* L2_DDR: 512 entries covering 0..1 GB at 2 MB each. */
    dma_lo = (uint64_t)(uintptr_t)_dma_buffers_start;
    dma_hi = (uint64_t)(uintptr_t)_dma_buffers_end;
    for (i = 0; i < 512; i++) {
        addr = (uint64_t)i * L2_BLOCK_SIZE;
        if ((addr + L2_BLOCK_SIZE) <= dma_lo || addr >= dma_hi) {
            L2_DDR[i] = BLOCK_NORMAL(addr);
        } else {
            /* Any 2 MB block overlapping the GEM DMA region is mapped
             * Normal-NC, in BOTH layouts. The 8-byte BDs share 64-byte
             * cache lines, so cleaning one BD's line writes neighbouring
             * BDs back over MAC-set OWN/USED bits (Skoll HIGH-2). A
             * cacheable ring with per-BD DC ops therefore corrupts the
             * ring under sustained RX (TCP-rate) and wedges it; NC makes
             * the rings DMA-coherent with no cache maintenance. NC also
             * keeps the wrapped word-wise memcpy/memset (aligned 64-bit +
             * byte tail) from faulting when staging frames. In the DDR
             * layout this block may also back part of the stack; the
             * uncached cost there is acceptable for correctness. */
            L2_DDR[i] = BLOCK_NORMAL_NC(addr);
        }
    }

    /* L2_PERIPH: 3..4 GB range. All Device-nGnRnE except the last
     * 2 MB block which contains OCM (0xFFFC0000..0xFFFFFFFF) and
     * must be Normal+executable so we can fetch our code from OCM. */
    for (i = 0; i < 511; i++) {
        addr = 3ULL * L1_BLOCK_SIZE + (uint64_t)i * L2_BLOCK_SIZE;
        L2_PERIPH[i] = BLOCK_DEVICE(addr);
    }
    /* Entry 511 covers 0xFFE00000..0xFFFFFFFF, containing OCM
     * (0xFFFC0000+). */
#ifdef AMD_LAYOUT_DDR
    /* DDR layout: code+data live in DDR; OCM here holds only the reset
     * vectors. Keep it Normal-WB cacheable, executable. */
    L2_PERIPH[511] = BLOCK_NORMAL(3ULL * L1_BLOCK_SIZE
                                 + 511ULL * L2_BLOCK_SIZE);
#else
    /* OCM layout: text, data and the GEM BD rings/buffers all live in OCM.
     * Map the OCM block Normal Non-Cacheable (still executable) so the
     * rings are DMA-coherent without per-descriptor cache maintenance --
     * and so a cache-line clean can never write back a stale neighbour BD
     * over a MAC-set OWN/USED bit (Skoll HIGH-2). Instruction fetch from
     * NC Normal memory is permitted; OCM is single-cycle SRAM so the lost
     * D-cache is not significant for this deterministic profile. */
    L2_PERIPH[511] = BLOCK_NORMAL_NC_EXEC(3ULL * L1_BLOCK_SIZE
                                 + 511ULL * L2_BLOCK_SIZE);
#endif

    /* L1 entries. */
    L1[0] = TABLE_DESC((uintptr_t)L2_DDR);
    L1[1] = BLOCK_NORMAL(L1_BLOCK_SIZE);            /* 1..2 GB DDR */
    L1[2] = 0;                                       /* 2..3 GB unused */
    L1[3] = TABLE_DESC((uintptr_t)L2_PERIPH);       /* 3..4 GB peri + OCM */

    for (i = 4; i < 512; i++)
        L1[i] = 0;
}

/* EL-specific system-register names. Default EL3; the wolfBoot demo build
 * passes -DWOLFIP_EL2 (the image is chain-loaded at EL2). TCR_EL2/MAIR_EL2
 * (E2H=0) share the single-range format of their EL3 counterparts, so the
 * same TCR/MAIR values apply. */
#ifdef WOLFIP_EL2
#define SR_MAIR  "mair_el2"
#define SR_TCR   "tcr_el2"
#define SR_TTBR0 "ttbr0_el2"
#define SR_SCTLR "sctlr_el2"
#define INS_TLBI "tlbi alle2"
#else
#define SR_MAIR  "mair_el3"
#define SR_TCR   "tcr_el3"
#define SR_TTBR0 "ttbr0_el3"
#define SR_SCTLR "sctlr_el3"
#define INS_TLBI "tlbi alle3"
#endif

void mmu_enable(void)
{
    uint64_t mair;
    uint64_t tcr;
    uint64_t sctlr;

    mmu_build_tables();

    /* Make sure the table writes are visible to the table walker
     * before we point TTBR at them. We are still running with the
     * D-cache off here, so a DSB SY is sufficient. */
    __asm__ volatile ("dsb sy" ::: "memory");

    /* MAIR_EL3:
     *   ATTR0 = 0xFF (Normal WB Inner+Outer Cacheable)
     *   ATTR1 = 0x00 (Device-nGnRnE)
     *   ATTR2 = 0x44 (Normal Inner+Outer Non-Cacheable, for DMA buffers) */
    mair = (0xFFULL << 0) | (0x00ULL << 8) | (0x44ULL << 16);
    __asm__ volatile ("msr " SR_MAIR ", %0" :: "r"(mair));

    /* TCR_EL3: 32-bit VA (T0SZ=32, start level L1), 4 KB granule,
     * IRGN0=WB-RA-WA, ORGN0=WB-RA-WA, SH0=Inner shareable, IPS=40 bit.
     * EL3 TCR has T0SZ at bits [5:0], IRGN0[9:8], ORGN0[11:10],
     * SH0[13:12], TG0[15:14], PS[18:16], TBI[20], RES1 at bit 23,31.
     */
    tcr = (uint64_t)32                /* T0SZ = 32 -> 4 GB VA */
        | ((uint64_t)1 << 8)          /* IRGN0 = WB RA-WA */
        | ((uint64_t)1 << 10)         /* ORGN0 = WB RA-WA */
        | ((uint64_t)3 << 12)         /* SH0   = Inner shareable */
        | ((uint64_t)0 << 14)         /* TG0   = 4 KB */
        | ((uint64_t)2 << 16)         /* PS    = 40 bit PA */
        | ((uint64_t)1 << 23)         /* RES1 */
        | ((uint64_t)1 << 31);        /* RES1 */
    __asm__ volatile ("msr " SR_TCR ", %0" :: "r"(tcr));

    /* TTBR0_ELx = &L1. */
    __asm__ volatile ("msr " SR_TTBR0 ", %0" :: "r"((uint64_t)(uintptr_t)L1));

    __asm__ volatile ("isb" ::: "memory");

    /* Invalidate TLBs and I-cache before turning the MMU on. */
    __asm__ volatile (INS_TLBI ::: "memory");
    __asm__ volatile ("ic iallu" ::: "memory");
    __asm__ volatile ("dsb sy" ::: "memory");
    __asm__ volatile ("isb" ::: "memory");

    /* Enable MMU + I-cache + D-cache. Cache coherency with GEM DMA
     * is handled with explicit DC CVAC / DC IVAC ops in eth_send and
     * eth_poll (see gem.c cache_*() helpers).
     *
     * DZE bit 14 = enable DC ZVA at EL0/EL1 (and EL3 since we are
     * here). Newlib aarch64 memset uses DC ZVA for fast bulk zero
     * writes; without DZE=1 the instruction traps UNDEF and the
     * exception loop wedges the CPU. */
    __asm__ volatile ("mrs %0, " SR_SCTLR : "=r"(sctlr));
    sctlr |= (1ULL << 0);   /* M */
    sctlr |= (1ULL << 2);   /* C */
    sctlr |= (1ULL << 12);  /* I */
#ifndef WOLFIP_EL2
    sctlr |= (1ULL << 14);  /* DZE - allow DC ZVA (EL3; RES0 in SCTLR_EL2) */
#endif
    sctlr &= ~(1ULL << 1);  /* A off */
    __asm__ volatile ("msr " SR_SCTLR ", %0" :: "r"(sctlr));
    __asm__ volatile ("isb" ::: "memory");
}

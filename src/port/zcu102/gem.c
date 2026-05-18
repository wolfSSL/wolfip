/* gem.c
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
 * Cadence GEM driver for ZynqMP GEM3 (on-board RJ45 on ZCU102).
 *
 * - 32-bit DMA addressing (OCM low bank, well under 4 GB).
 * - IRQ-driven RX (GIC-400 SPI 63 -> gem_isr) and polled TX. Note:
 *   the SCR_EL3.IRQ routing bit must be set on this A53 for the
 *   exception to actually be entered, despite the ARM ARM appearing
 *   to say SCR_EL3.IRQ only affects lower-EL routing. See
 *   startup.S for the explicit SCR_EL3 setup.
 * - BDs and frame buffers live in the .dma_buffers section, which the
 *   linker places in OCM (Normal-WB executable per L2_PERIPH[511]).
 *   Cache coherency between CPU L1 D-cache and the MAC DMA path is
 *   maintained explicitly via cache_clean() / cache_inval() at every
 *   BD hand-off.
 *
 * Register set per ZynqMP TRM (UG1085) chapter 34 / Cadence GEM.
 */
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "../../../wolfip.h"
#include "board.h"
#include "uart.h"
#include "gic.h"
#include "gem.h"
#include "phy_dp83867.h"

/* Cache maintenance helpers for GEM DMA coherency. Cortex-A53 cache
 * line is 64 bytes. With D-cache enabled and BD/buffers in normal
 * cacheable memory, CPU writes may sit in L1 D-cache and not be
 * visible to the MAC's DMA path. cache_clean() writes back dirty
 * lines to memory before DMA reads; cache_inval() invalidates lines
 * so subsequent CPU reads pull fresh DMA-written data. */
#define CACHE_LINE 64u

static inline void cache_clean(const void *p, uint32_t sz)
{
    uintptr_t start = (uintptr_t)p & ~(CACHE_LINE - 1u);
    uintptr_t end   = ((uintptr_t)p + sz + CACHE_LINE - 1u) & ~(CACHE_LINE - 1u);
    uintptr_t a;
    for (a = start; a < end; a += CACHE_LINE)
        __asm__ volatile ("dc cvac, %0" :: "r"(a) : "memory");
    __asm__ volatile ("dsb sy" ::: "memory");
}

static inline void cache_inval(const void *p, uint32_t sz)
{
    uintptr_t start = (uintptr_t)p & ~(CACHE_LINE - 1u);
    uintptr_t end   = ((uintptr_t)p + sz + CACHE_LINE - 1u) & ~(CACHE_LINE - 1u);
    uintptr_t a;
    for (a = start; a < end; a += CACHE_LINE)
        __asm__ volatile ("dc ivac, %0" :: "r"(a) : "memory");
    __asm__ volatile ("dsb sy" ::: "memory");
}

/* ---------------------------------------------------------------------
 * Register offsets and bit masks (subset we use)
 * ------------------------------------------------------------------- */
#define GEM_NWCTRL          (*(volatile uint32_t *)(GEM3_BASE + 0x000))
#define GEM_NWCFG           (*(volatile uint32_t *)(GEM3_BASE + 0x004))
#define GEM_NWSR            (*(volatile uint32_t *)(GEM3_BASE + 0x008))
#define GEM_DMACR           (*(volatile uint32_t *)(GEM3_BASE + 0x010))
#define GEM_TSR             (*(volatile uint32_t *)(GEM3_BASE + 0x014))
#define GEM_RXQBASE         (*(volatile uint32_t *)(GEM3_BASE + 0x018))
#define GEM_TXQBASE         (*(volatile uint32_t *)(GEM3_BASE + 0x01C))
#define GEM_RSR             (*(volatile uint32_t *)(GEM3_BASE + 0x020))
#define GEM_ISR             (*(volatile uint32_t *)(GEM3_BASE + 0x024))
#define GEM_IER             (*(volatile uint32_t *)(GEM3_BASE + 0x028))
#define GEM_IDR             (*(volatile uint32_t *)(GEM3_BASE + 0x02C))
#define GEM_PHYMNTNC        (*(volatile uint32_t *)(GEM3_BASE + 0x034))
#define GEM_HASHL           (*(volatile uint32_t *)(GEM3_BASE + 0x080))
#define GEM_HASHH           (*(volatile uint32_t *)(GEM3_BASE + 0x084))
#define GEM_LADDR1L         (*(volatile uint32_t *)(GEM3_BASE + 0x088))
#define GEM_LADDR1H         (*(volatile uint32_t *)(GEM3_BASE + 0x08C))
/* Priority queue base addresses (queues 1-3). Cadence GEM has 4 TX
 * and 4 RX priority queues; if we don't point unused ones at a safe
 * dummy BD, the MAC will eventually try to fetch from queue1+ at
 * power-on-random addresses and hang (TSR.TXGO sticks with no octets
 * transmitted). U-Boot's zynq_gem and Linux's macb both set these. */
#define GEM_TXQ1BASE        (*(volatile uint32_t *)(GEM3_BASE + 0x440))
#define GEM_TXQ2BASE        (*(volatile uint32_t *)(GEM3_BASE + 0x444))
#define GEM_TXQ3BASE        (*(volatile uint32_t *)(GEM3_BASE + 0x448))
#define GEM_RXQ1BASE        (*(volatile uint32_t *)(GEM3_BASE + 0x480))
#define GEM_RXQ2BASE        (*(volatile uint32_t *)(GEM3_BASE + 0x484))
#define GEM_RXQ3BASE        (*(volatile uint32_t *)(GEM3_BASE + 0x488))
#define GEM_OCTTXL          (*(volatile uint32_t *)(GEM3_BASE + 0x100))
#define GEM_TXCNT           (*(volatile uint32_t *)(GEM3_BASE + 0x108))
#define GEM_OCTRXL          (*(volatile uint32_t *)(GEM3_BASE + 0x150))
#define GEM_RXCNT           (*(volatile uint32_t *)(GEM3_BASE + 0x158))
#define GEM_RXFCSCNT        (*(volatile uint32_t *)(GEM3_BASE + 0x190))
#define GEM_RXORCNT         (*(volatile uint32_t *)(GEM3_BASE + 0x1A4))

#define NWCTRL_LOOPEN       (1u << 1)
#define NWCTRL_RXEN         (1u << 2)
#define NWCTRL_TXEN         (1u << 3)
#define NWCTRL_MDEN         (1u << 4)
#define NWCTRL_STATCLR      (1u << 5)
#define NWCTRL_STARTTX      (1u << 9)
#define NWCTRL_HALTTX       (1u << 10)

#define NWCFG_SPEED100      (1u << 0)
#define NWCFG_FDEN          (1u << 1)
#define NWCFG_COPYALL       (1u << 4)
#define NWCFG_BCASTDI       (1u << 5)
#define NWCFG_MCASTHASHEN   (1u << 6)
#define NWCFG_UCASTHASHEN   (1u << 7)
#define NWCFG_1536RXEN      (1u << 8)
#define NWCFG_1000          (1u << 10)
#define NWCFG_FCSREM        (1u << 17)
#define NWCFG_MDCDIV_SHIFT  18u
#define NWCFG_MDCDIV_MASK   (7u << 18)
#define NWCFG_DWIDTH_64     (1u << 21)  /* Data bus width = 64 bit (AArch64) */

#define NWSR_PHY_IDLE       (1u << 2)

#define RSR_BUFFNA          (1u << 0)
#define RSR_FRAMERX         (1u << 1)
#define RSR_RXOVR           (1u << 2)
#define RSR_HRESPNOK        (1u << 3)

#define IXR_MGMNT           (1u << 0)
#define IXR_FRAMERX         (1u << 1)
#define IXR_TXCOMPL         (1u << 7)
#define IXR_TXEXH           (1u << 6)
#define IXR_RXUSED          (1u << 2)
#define IXR_RXOVR           (1u << 10)
#define IXR_HRESPNOK        (1u << 11)

#define PHYMNTNC_CLAUSE22   0x40020000u
#define PHYMNTNC_OP_R       (2u << 28)
#define PHYMNTNC_OP_W       (1u << 28)

#define RXBUF_OWN_SW        (1u << 0)
#define RXBUF_WRAP          (1u << 1)
#define RXBUF_ADDR_MASK     0xFFFFFFFCu
#define RXBUF_LEN_MASK      0x00001FFFu

#define TXBUF_USED          (1u << 31)
#define TXBUF_WRAP          (1u << 30)
#define TXBUF_LAST          (1u << 15)
#define TXBUF_LEN_MASK      0x00003FFFu

/* ---------------------------------------------------------------------
 * BD ring and frame buffer sizing
 * ------------------------------------------------------------------- */
/* Ring sizes deliberately small to fit text + DMA buffers + BSS in
 * 256 KB OCM (we keep everything in OCM because DDR-via-JTAG isn't
 * reliable without PMU FW running). For higher throughput, bump
 * these once we move BSS back to DDR. */
#define RX_RING_LEN         16
#define TX_RING_LEN         8
#define BUF_LEN             1536    /* multiple of 64, per DMACR.RXBS */

/* GEM BD: two 32-bit words. */
struct gem_bd {
    uint32_t addr;
    uint32_t status;
};

/* All DMA-visible objects go in .dma_buffers (Device-nGnRnE per MMU). */
static struct gem_bd rx_ring[RX_RING_LEN]
    __attribute__((aligned(64), section(".dma_buffers")));
static struct gem_bd tx_ring[TX_RING_LEN]
    __attribute__((aligned(64), section(".dma_buffers")));
static uint8_t rx_buf_pool[RX_RING_LEN][BUF_LEN]
    __attribute__((aligned(64), section(".dma_buffers")));
static uint8_t tx_buf_pool[TX_RING_LEN][BUF_LEN]
    __attribute__((aligned(64), section(".dma_buffers")));

/* Dummy BD pair for disabling priority queues 1-3. The TX dummy has
 * USED=1 so the MAC ignores it (refuses to transmit). The RX dummy
 * has the SW-OWN/NEW bit set so MAC won't write into queue 1-3 RX. */
static struct gem_bd dummy_tx_bd
    __attribute__((aligned(8), section(".dma_buffers")));
static struct gem_bd dummy_rx_bd
    __attribute__((aligned(8), section(".dma_buffers")));

/* ---------------------------------------------------------------------
 * Software RX queue: filled by ISR, drained by eth_poll() in the main
 * loop. Single producer (ISR) / single consumer (main), so a lockless
 * head/tail pair is safe when we use DSB to publish writes.
 *
 * Each slot stores a pointer to one of rx_buf_pool[i] plus length;
 * the buffer's BD is recycled after the main loop hands the frame to
 * wolfIP.
 * ------------------------------------------------------------------- */
#define SWQ_DEPTH           16

struct swq_slot {
    uint8_t  *buf;
    uint16_t  len;
    uint16_t  ring_idx;     /* into rx_ring[] - recycle after consume */
};

static volatile struct swq_slot swq[SWQ_DEPTH];
static volatile uint32_t swq_head;    /* ISR writes */
static volatile uint32_t swq_tail;    /* main reads */
static volatile uint32_t rx_drops;    /* ISR-side counter */
static volatile uint32_t s_irq_count;
static volatile uint32_t s_rx_frames;
static volatile uint32_t s_tx_sent;

static uint32_t rx_next;              /* next BD the SW will look at */
static uint32_t tx_next;              /* next BD the SW will try to TX */

static uint8_t phy_addr_used;

/* ---------------------------------------------------------------------
 * MDIO
 * ------------------------------------------------------------------- */
static int mdio_wait_idle(void)
{
    int spin;
    for (spin = 0; spin < 100000; spin++) {
        if (GEM_NWSR & NWSR_PHY_IDLE)
            return 0;
    }
    return -1;
}

int gem_mdio_read(uint8_t phy_addr, uint8_t reg, uint16_t *out)
{
    uint32_t v;
    if (mdio_wait_idle() < 0)
        return -1;
    v = PHYMNTNC_CLAUSE22 | PHYMNTNC_OP_R
      | (((uint32_t)phy_addr & 0x1Fu) << 23)
      | (((uint32_t)reg      & 0x1Fu) << 18);
    GEM_PHYMNTNC = v;
    if (mdio_wait_idle() < 0)
        return -2;
    *out = (uint16_t)(GEM_PHYMNTNC & 0xFFFFu);
    return 0;
}

int gem_mdio_write(uint8_t phy_addr, uint8_t reg, uint16_t value)
{
    uint32_t v;
    if (mdio_wait_idle() < 0)
        return -1;
    v = PHYMNTNC_CLAUSE22 | PHYMNTNC_OP_W
      | (((uint32_t)phy_addr & 0x1Fu) << 23)
      | (((uint32_t)reg      & 0x1Fu) << 18)
      | (uint32_t)value;
    GEM_PHYMNTNC = v;
    if (mdio_wait_idle() < 0)
        return -2;
    return 0;
}

/* ---------------------------------------------------------------------
 * BD ring init
 * ------------------------------------------------------------------- */
static void rx_ring_init(void)
{
    uint32_t i;
    for (i = 0; i < RX_RING_LEN; i++) {
        uint32_t addr = (uint32_t)(uintptr_t)rx_buf_pool[i];
        addr &= RXBUF_ADDR_MASK;
        if (i == RX_RING_LEN - 1)
            addr |= RXBUF_WRAP;
        rx_ring[i].addr   = addr;          /* OWN=0 -> hardware can use */
        rx_ring[i].status = 0;
    }
    rx_next = 0;
}

static void tx_ring_init(void)
{
    uint32_t i;
    /* Match u-boot zynq_gem pattern: all BDs start as dummies with
     * USED|LAST|WRAP, addr=0. eth_send fills in addr + length + LAST
     * (and clears USED) when actually transmitting. The WRAP bit on
     * the last BD keeps the MAC walker in our ring. */
    for (i = 0; i < TX_RING_LEN; i++) {
        tx_ring[i].addr   = 0;
        tx_ring[i].status = TXBUF_USED | TXBUF_LAST
                          | ((i == TX_RING_LEN - 1) ? TXBUF_WRAP : 0);
    }
    tx_next = 0;
}

/* ---------------------------------------------------------------------
 * RX ISR
 * ------------------------------------------------------------------- */
static void gem_isr(void)
{
    uint32_t isr;

    s_irq_count++;
    isr = GEM_ISR;
    GEM_ISR = isr;          /* clear-on-write */

    /* Invalidate the WHOLE RX ring at entry - MAC may have written
     * to any BD, not just rx_next. Cheap (one cache line typically
     * since the ring is small). */
    cache_inval(rx_ring, sizeof(rx_ring));

    /* Walk RX BDs whose SW-OWN bit is set (frame ready for software). */
    while (rx_ring[rx_next].addr & RXBUF_OWN_SW) {
        s_rx_frames++;
        /* Also invalidate the buffer before we copy from it. */
        cache_inval(rx_buf_pool[rx_next],
                    rx_ring[rx_next].status & RXBUF_LEN_MASK);
        uint32_t status = rx_ring[rx_next].status;
        uint32_t next_head = swq_head;
        uint32_t slot = next_head % SWQ_DEPTH;
        uint32_t depth = next_head - swq_tail;

        if (depth >= SWQ_DEPTH) {
            /* SW queue full - drop and recycle the BD. */
            rx_drops++;
        } else {
            swq[slot].buf      = rx_buf_pool[rx_next];
            swq[slot].len      = (uint16_t)(status & RXBUF_LEN_MASK);
            swq[slot].ring_idx = (uint16_t)rx_next;
            __asm__ volatile ("dsb sy" ::: "memory");
            swq_head = next_head + 1;
        }

        /* If we have headroom in the SW queue we recycle the BD only
         * after main consumes the slot (see eth_poll); when dropping we
         * recycle here. */
        if (depth >= SWQ_DEPTH) {
            uint32_t addr = (uint32_t)(uintptr_t)rx_buf_pool[rx_next];
            addr &= RXBUF_ADDR_MASK;
            if (rx_next == RX_RING_LEN - 1)
                addr |= RXBUF_WRAP;
            rx_ring[rx_next].status = 0;
            __asm__ volatile ("dsb sy" ::: "memory");
            rx_ring[rx_next].addr = addr;          /* OWN=0 again */
            /* MAC reads BDs straight from memory; clean the line so it
             * sees OWN=0, otherwise it skips past this BD and walks the
             * ring leaving holes. */
            cache_clean(&rx_ring[rx_next], sizeof(rx_ring[rx_next]));
        }
        rx_next = (rx_next + 1) % RX_RING_LEN;
    }

    /* RXUSED recovery: clear BUFFNA. With cache_clean on the recycle
     * path, this should be rare; when it happens, also kick the RX
     * path so the MAC re-walks the ring. */
    if (isr & IXR_RXUSED) {
        GEM_RSR = RSR_BUFFNA;
    }
    if (isr & IXR_RXOVR) {
        GEM_RSR = RSR_RXOVR;
    }
}

/* ---------------------------------------------------------------------
 * eth_poll / eth_send (called from wolfIP_poll and stack TX path)
 * ------------------------------------------------------------------- */
static int eth_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    uint32_t tail;
    uint32_t slot;
    uint32_t copy;
    uint32_t addr;
    uint16_t idx;

    (void)ll;

    /* RX frames are delivered into swq[] by gem_isr() running off the
     * GIC-400 INTID 95 IRQ path (see startup.S SCR_EL3 setup and
     * board.h IRQ_GEM3). eth_poll just drains the SW queue here. */
    tail = swq_tail;
    if (tail == swq_head)
        return 0;             /* SW queue empty */

    slot = tail % SWQ_DEPTH;
    copy = swq[slot].len;
    if (copy > len)
        copy = len;
    memcpy(buf, swq[slot].buf, copy);

    /* Recycle the BD back to hardware. */
    idx  = swq[slot].ring_idx;
    addr = (uint32_t)(uintptr_t)rx_buf_pool[idx];
    addr &= RXBUF_ADDR_MASK;
    if (idx == RX_RING_LEN - 1)
        addr |= RXBUF_WRAP;
    rx_ring[idx].status = 0;
    __asm__ volatile ("dsb sy" ::: "memory");
    rx_ring[idx].addr   = addr;          /* OWN bit cleared = HW can write */
    /* MAC walks BDs from main memory (not coherent with CPU D-cache);
     * push the OWN=0 store out so the MAC will reuse this slot. */
    cache_clean(&rx_ring[idx], sizeof(rx_ring[idx]));

    __asm__ volatile ("dsb sy" ::: "memory");
    swq_tail = tail + 1;

    return (int)copy;
}

static int eth_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    uint32_t idx;
    uint32_t status;

    (void)ll;

    if (len > BUF_LEN)
        return -1;

    idx = tx_next;
    /* Wait briefly for the BD to be free (USED=1 means MAC done). The
     * USED bit is written back by MAC DMA - invalidate the cache line
     * so the CPU does not see the stale USED=0 we wrote when we last
     * armed this BD. */
    {
        int spin;
        for (spin = 0; spin < 100000; spin++) {
            cache_inval(&tx_ring[idx], sizeof(tx_ring[idx]));
            if (tx_ring[idx].status & TXBUF_USED)
                break;
        }
        if ((tx_ring[idx].status & TXBUF_USED) == 0)
            return -2;       /* TX ring backed up - tell caller to retry */
    }

    memcpy(tx_buf_pool[idx], buf, len);

    /* Pad to minimum Ethernet frame (60 bytes; MAC adds 4-byte FCS). */
    if (len < 60u) {
        memset(tx_buf_pool[idx] + len, 0, 60u - len);
        len = 60u;
    }

    /* Flush the frame buffer from D-cache so MAC DMA reads see it. */
    cache_clean(tx_buf_pool[idx], len);

    /* Re-arm BD: set buffer address, then clear USED with length+LAST
     * (preserve WRAP if this is the last BD). Buffer addr written
     * before status so MAC walking the ring sees a valid pair. */
    tx_ring[idx].addr = (uint32_t)(uintptr_t)tx_buf_pool[idx];
    status = (len & TXBUF_LEN_MASK) | TXBUF_LAST;
    if (idx == TX_RING_LEN - 1)
        status |= TXBUF_WRAP;
    tx_ring[idx].status = status;        /* USED=0 -> ready for MAC */

    /* Flush BD update so MAC sees USED=0. */
    cache_clean(&tx_ring[idx], sizeof(tx_ring[idx]));
    GEM_NWCTRL |= NWCTRL_STARTTX;

    s_tx_sent++;
    tx_next = (idx + 1) % TX_RING_LEN;
    return (int)len;
}

uint32_t gem_irq_count(void) { return s_irq_count; }
uint32_t gem_rx_frames(void) { return s_rx_frames; }
uint32_t gem_tx_sent(void)   { return s_tx_sent; }

void gem_dump_state(void)
{
    uint32_t i;
    cache_inval(rx_ring, sizeof(rx_ring));
    cache_inval(tx_ring, sizeof(tx_ring));
    uart_puts("GEM3 regs: NWCTRL="); uart_puthex(GEM_NWCTRL);
    uart_puts(" NWCFG=");           uart_puthex(GEM_NWCFG);
    uart_puts(" NWSR=");            uart_puthex(GEM_NWSR);
    uart_puts(" DMACR=");           uart_puthex(GEM_DMACR);
    uart_puts("\n           ISR="); uart_puthex(GEM_ISR);
    uart_puts(" RSR=");             uart_puthex(GEM_RSR);
    uart_puts(" TSR=");             uart_puthex(GEM_TSR);
    uart_puts(" IMR=");             uart_puthex(*(volatile uint32_t *)(GEM3_BASE + 0x030));
    uart_puts("\n           tx[0]="); uart_puthex(tx_ring[0].addr);
    uart_puts("/");                 uart_puthex(tx_ring[0].status);
    uart_puts(" rx[0]=");           uart_puthex(rx_ring[0].addr);
    uart_puts("/");                 uart_puthex(rx_ring[0].status);
    uart_puts("\n           irq=");             uart_putdec(s_irq_count);
    uart_puts(" rx_frm=");          uart_putdec(s_rx_frames);
    uart_puts(" tx_snt=");          uart_putdec(s_tx_sent);
    uart_puts(" drops=");           uart_putdec(rx_drops);
    uart_puts("\n           HW counters: txoct="); uart_putdec(GEM_OCTTXL);
    uart_puts(" txcnt=");           uart_putdec(GEM_TXCNT);
    uart_puts(" rxoct=");           uart_putdec(GEM_OCTRXL);
    uart_puts(" rxcnt=");           uart_putdec(GEM_RXCNT);
    uart_puts(" rxfcs=");           uart_putdec(GEM_RXFCSCNT);
    uart_puts(" rxor=");            uart_putdec(GEM_RXORCNT);
    {
        uint32_t filled = 0;
        uint32_t first_filled = 0xFFFF;
        for (i = 0; i < RX_RING_LEN; i++) {
            if (rx_ring[i].addr & RXBUF_OWN_SW) {
                filled++;
                if (first_filled == 0xFFFF) first_filled = i;
            }
        }
        uart_puts(" rx_filled="); uart_putdec(filled);
        uart_puts(" first=");     uart_putdec(first_filled);
        uart_puts(" rx_next=");   uart_putdec(rx_next);
    }
    uart_puts("\n");
}

/* ---------------------------------------------------------------------
 * Clock + reset for GEM3 via CRL_APB.
 *
 * For the stock ZCU102 boot flow, FSBL has already configured GEM3:
 *   - CRL_APB.GEM3_REF_CTRL  -> 125 MHz from IOPLL or RPLL
 *   - CRL_APB.RST_LPD_IOU0   -> GEM3 out of reset
 *   - IOU_SLCR MIO 64..77    -> GEM3 RGMII + MDIO pin muxing
 *
 * We pulse the GEM3 reset bit so the MAC starts from a known state
 * without touching the clock control (which would race with FSBL's
 * setup of PLLs).
 * ------------------------------------------------------------------- */
#define CRL_RST_GEM3        (1u << 3)

/* Configure CRL_APB.GEM3_REF_CTRL for the negotiated link speed. The
 * MAC sources TX_CLK to the PHY at this rate (RGMII): 125 MHz for
 * 1 Gbps, 25 MHz for 100 Mbps, 2.5 MHz for 10 Mbps. PetaLinux/FSBL
 * may pre-program this for a different speed than we want; both
 * U-Boot and Linux re-program it whenever PHY link speed changes.
 *
 * IOPLL = 1500 MHz on ZCU102 (FSBL default).
 *   1500 / 12 / 1 = 125 MHz  (1000)
 *   1500 / 12 / 5 = 25 MHz   (100)
 *   1500 / 12 / 50 = 2.5 MHz (10)
 *
 * Register layout (TRM): CLKACT bit26, CLKACT_RX bit25,
 *   DIVISOR1 bits[21:16], DIVISOR0 bits[13:8], SRCSEL bits[2:0]. */
static void gem3_set_ref_clk(int speed_mbps)
{
    volatile uint32_t *gem3_ref = (volatile uint32_t *)CRL_APB_GEM3_REF_CTRL;
    uint32_t div1;
    uint32_t val;

    switch (speed_mbps) {
    case 1000: div1 = 1;  break;
    case 100:  div1 = 5;  break;
    case 10:   div1 = 50; break;
    default:   div1 = 1;  break;
    }
    val = (1u << 26)               /* CLKACT */
        | (1u << 25)               /* CLKACT_RX */
        | ((div1 & 0x3Fu) << 16)   /* DIVISOR1 */
        | ((12u   & 0x3Fu) << 8)   /* DIVISOR0 */
        | (0u);                    /* SRCSEL = IOPLL */
    *gem3_ref = val;
}

static void gem3_hw_reset(void)
{
    volatile uint32_t *rst     = (volatile uint32_t *)CRL_APB_RST_LPD_IOU0;
    volatile uint32_t *gem3ref = (volatile uint32_t *)CRL_APB_GEM3_REF_CTRL;

    uart_puts("GEM3 clk before: GEM3_REF_CTRL=");
    uart_puthex(*gem3ref);
    uart_puts(" RST_LPD_IOU0=");
    uart_puthex(*rst);
    uart_puts("\n");

    *rst |= CRL_RST_GEM3;
    {
        volatile int d;
        for (d = 0; d < 10000; d++)
            ;
    }
    *rst &= ~CRL_RST_GEM3;
    {
        volatile int d;
        for (d = 0; d < 100000; d++)   /* ~10 ms post-reset settle */
            ;
    }

    /* Force 125 MHz reference for the 1 Gbps case. zcu102_eth_init()
     * downshifts this later if the PHY ends up at 100/10. */
    gem3_set_ref_clk(1000);
    uart_puts("GEM3 clk after : GEM3_REF_CTRL=");
    uart_puthex(*gem3ref);
    uart_puts("\n");
}

/* ---------------------------------------------------------------------
 * Public init
 * ------------------------------------------------------------------- */
int zcu102_eth_init(struct wolfIP_ll_dev *ll)
{
    uint8_t addr;
    uint16_t id1;
    int found_phy;
    int speed;
    int fd;
    int link_up;

    gem3_hw_reset();

    /* Disable everything before configuring. */
    GEM_NWCTRL = 0;
    GEM_IDR    = 0xFFFFFFFFu;
    (void)GEM_ISR;
    GEM_ISR    = 0xFFFFFFFFu;
    GEM_TSR    = 0xFFFFFFFFu;
    GEM_RSR    = RSR_BUFFNA | RSR_FRAMERX | RSR_RXOVR | RSR_HRESPNOK;

    /* Initial NWCFG: gigabit, full duplex, MDC=/96, 1536-byte frames,
     * strip FCS from RX, accept broadcasts, multicast via hash,
     * DWIDTH_64 because ZynqMP GEM hangs on a 64-bit AXI bus and
     * needs this bit for TX to actually transmit (matches U-Boot
     * ZYNQ_GEM_DBUS_WIDTH for CONFIG_ARM64).
     * COPYALL temporarily on for first-bring-up so we can confirm
     * the RX path is alive even if filtering is mis-set. */
    GEM_NWCFG = NWCFG_1000
              | NWCFG_FDEN
              | NWCFG_FCSREM
              | NWCFG_1536RXEN
              | NWCFG_MCASTHASHEN
              | NWCFG_COPYALL
              | NWCFG_DWIDTH_64
              | (5u << NWCFG_MDCDIV_SHIFT);

    /* DMACR: AHB fixed burst 16 beats, RX buffer 1536/64=24, TX/RX
     * packet buffer memory at max. Do NOT set bit 30 (DMA_ADDR_BUS_WIDTH
     * 64-bit): that selects 16-byte BD format with addr_hi, which would
     * break the 8-byte struct gem_bd layout (MAC would walk every other
     * BD and write to bogus high addresses, dropping the frame after
     * counting it - exactly the failure mode we hit). 64-bit AXI bus
     * width is set in NWCFG bit 21 instead. */
    GEM_DMACR = (24u << 16)   /* RX buffer size in 64-byte units */
              | (1u  << 10)   /* TX packet buffer memory size = max */
              | (3u  << 8)    /* RX packet buffer memory size = max */
              | 0x10u;        /* burst length = 16 */

    /* Set MAC address into SAB1/SAT1. SAB1L writes are latched on
     * SAB1H write per TRM, so write the high half last. */
    GEM_LADDR1L = (uint32_t)WOLFIP_MAC_0
                | ((uint32_t)WOLFIP_MAC_1 << 8)
                | ((uint32_t)WOLFIP_MAC_2 << 16)
                | ((uint32_t)WOLFIP_MAC_3 << 24);
    GEM_LADDR1H = (uint32_t)WOLFIP_MAC_4
                | ((uint32_t)WOLFIP_MAC_5 << 8);

    GEM_HASHL = 0;
    GEM_HASHH = 0;

    /* Build BD rings. */
    rx_ring_init();
    tx_ring_init();
    GEM_RXQBASE = (uint32_t)(uintptr_t)rx_ring;
    GEM_TXQBASE = (uint32_t)(uintptr_t)tx_ring;

    /* Disable priority queues 1-3 with dummy BDs. Without this, the
     * MAC may walk uninitialised q1/q2/q3 base pointers and hang
     * (TSR.TXGO sticks but no octets transmitted). */
    dummy_tx_bd.addr   = 0;
    dummy_tx_bd.status = TXBUF_USED | TXBUF_WRAP | TXBUF_LAST;
    dummy_rx_bd.addr   = RXBUF_WRAP | RXBUF_OWN_SW;
    dummy_rx_bd.status = 0;
    GEM_TXQ1BASE = (uint32_t)(uintptr_t)&dummy_tx_bd;
    GEM_TXQ2BASE = (uint32_t)(uintptr_t)&dummy_tx_bd;
    GEM_TXQ3BASE = (uint32_t)(uintptr_t)&dummy_tx_bd;
    GEM_RXQ1BASE = (uint32_t)(uintptr_t)&dummy_rx_bd;
    GEM_RXQ2BASE = (uint32_t)(uintptr_t)&dummy_rx_bd;
    GEM_RXQ3BASE = (uint32_t)(uintptr_t)&dummy_rx_bd;
    cache_clean(&dummy_tx_bd, sizeof(dummy_tx_bd));
    cache_clean(&dummy_rx_bd, sizeof(dummy_rx_bd));

    /* Clear any stale RX/TX packet classification screening. ZynqMP
     * GEM has SCREENING_TYPE_1 (TID match) at 0x500+ and SCREENING_TYPE_2
     * (compare) at 0x540+. If non-zero, frames may be routed to non-Q0
     * queues. Default 0 = all to Q0. */
    {
        uint32_t k;
        for (k = 0; k < 16; k++) {
            *(volatile uint32_t *)(GEM3_BASE + 0x500 + 4*k) = 0;
            *(volatile uint32_t *)(GEM3_BASE + 0x540 + 4*k) = 0;
        }
    }

    /* Enable MDIO so we can talk to the PHY. */
    GEM_NWCTRL |= NWCTRL_MDEN;

    /* Probe MDIO addresses 0..31 for a responsive PHY. ZCU102 routes
     * DP83867 to MDIO address 0x0C, but probing makes the driver
     * resilient to board variants. */
    found_phy = 0;
    for (addr = 0; addr < 32; addr++) {
        if (gem_mdio_read(addr, 0x02, &id1) == 0 && id1 != 0xFFFFu && id1 != 0) {
            found_phy = 1;
            break;
        }
    }
    if (!found_phy) {
        uart_puts("GEM3: no PHY responding on MDIO!\n");
        return -10;
    }
    phy_addr_used = addr;
    uart_puts("GEM3: PHY at MDIO addr=");
    uart_puthex(phy_addr_used);
    uart_puts("\n");

    if (dp83867_init(phy_addr_used, &speed, &fd) < 0) {
        uart_puts("GEM3: PHY init failed\n");
        return -11;
    }

    /* If PHY ended up at 10/100, downshift the MAC and re-program the
     * GEM3 reference clock to match (125 MHz / 25 MHz / 2.5 MHz). */
    if (speed != 1000) {
        uint32_t cfg = GEM_NWCFG;
        cfg &= ~NWCFG_1000;
        if (speed == 100)
            cfg |= NWCFG_SPEED100;
        else
            cfg &= ~NWCFG_SPEED100;
        if (!fd)
            cfg &= ~NWCFG_FDEN;
        GEM_NWCFG = cfg;
        gem3_set_ref_clk(speed);
    }

    /* Install RX ISR. */
    gic_register_handler(IRQ_GEM3, gem_isr);
    gic_enable_spi(IRQ_GEM3, 0xA0);

    /* Enable RX/TX and arm RX-side interrupts. */
    GEM_IER = IXR_FRAMERX | IXR_RXUSED | IXR_RXOVR | IXR_HRESPNOK;
    GEM_NWCTRL |= NWCTRL_RXEN | NWCTRL_TXEN;

    /* Populate wolfIP ll_dev. */
    ll->mac[0] = WOLFIP_MAC_0;
    ll->mac[1] = WOLFIP_MAC_1;
    ll->mac[2] = WOLFIP_MAC_2;
    ll->mac[3] = WOLFIP_MAC_3;
    ll->mac[4] = WOLFIP_MAC_4;
    ll->mac[5] = WOLFIP_MAC_5;
    memcpy(ll->ifname, "eth0", 5);
    ll->non_ethernet = 0;
    ll->mtu  = LINK_MTU;
    ll->poll = eth_poll;
    ll->send = eth_send;
    ll->priv = NULL;

    link_up = (dp83867_link_status(phy_addr_used) == 1) ? 1 : 0;
    return (link_up << 8) | (int)phy_addr_used;
}

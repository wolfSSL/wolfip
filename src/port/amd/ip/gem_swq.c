/* gem_swq.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Software RX queue + ISR for the swq-based GEM RX models (the AArch64
 * boards). gem_isr() drains the hardware BD ring into a lockless
 * single-producer/single-consumer ring; gem_swq_drain() consumes one
 * slot and recycles its BD. The gem_eth_poll policy (whether to call
 * gem_isr() from the main loop) lives in the per-board gem_rx_*.c.
 */
#include <string.h>
#include "gem_regs.h"
#include "gem_port.h"
#include "cache.h"
#include "board.h"
#include "gic.h"

/* Deeper than RX_RING_LEN on purpose: at most RX_RING_LEN buffer descriptors
 * are ever owned-by-software at once, so a swq this size can stage every
 * outstanding frame and the "queue full" path below never triggers. (When
 * SWQ_DEPTH == RX_RING_LEN the queue saturates under sustained RX and the
 * full-handling has to recycle/stall BDs, which wedged the RX ring under a
 * TCP-rate load that the UDP profile never produced.) */
#define SWQ_DEPTH           64

struct swq_slot {
    uint8_t  *buf;
    uint16_t  len;
    uint16_t  ring_idx;     /* into gem_rx_ring[] - recycle after consume */
};

static volatile struct swq_slot swq[SWQ_DEPTH];
static volatile uint32_t swq_head;    /* producer (gem_isr) */
static volatile uint32_t swq_tail;    /* consumer (gem_swq_drain) */

/* Fill swq[] from the RX BD ring. Single producer. */
void gem_isr(void)
{
    uint32_t isr;

    gem_irqs++;
    isr = GEM_ISR;
    GEM_ISR = isr;          /* clear-on-write */

    /* Invalidate the whole RX ring - the MAC may have written any BD. */
    cache_inval(gem_rx_ring, sizeof(gem_rx_ring));

    while (gem_rx_ring[gem_rx_next].addr & RXBUF_OWN_SW) {
        uint32_t status;
        uint32_t next_head = swq_head;
        uint32_t slot = next_head % SWQ_DEPTH;

        /* If the SW queue is full, stop draining and leave this BD owned by
         * software (enqueued, not yet recycled). Recycling it here would
         * hand a buffer still referenced by an outstanding swq slot back to
         * the MAC, which could DMA over a frame the consumer is about to
         * read. The MAC backpressures via BUFFNA (cleared below);
         * gem_swq_drain frees ring slots as the main loop consumes them.
         * A BD is therefore recycled ONLY in gem_swq_drain. */
        if ((next_head - swq_tail) >= SWQ_DEPTH)
            break;

        status = gem_rx_ring[gem_rx_next].status;
        gem_rxframes++;
        cache_inval(gem_rx_buf_pool[gem_rx_next], status & RXBUF_LEN_MASK);

        swq[slot].buf      = gem_rx_buf_pool[gem_rx_next];
        swq[slot].len      = (uint16_t)(status & RXBUF_LEN_MASK);
        swq[slot].ring_idx = (uint16_t)gem_rx_next;
        __asm__ volatile ("dsb sy" ::: "memory");
        swq_head = next_head + 1;

        gem_rx_next = (gem_rx_next + 1) % RX_RING_LEN;
    }

    if (isr & IXR_RXUSED)
        GEM_RSR = RSR_BUFFNA;
    if (isr & IXR_RXOVR)
        GEM_RSR = RSR_RXOVR;
}

/* Consume one swq slot into buf; recycle its BD to hardware. Single
 * consumer. Returns bytes copied (0 if empty). */
int gem_swq_drain(void *buf, uint32_t len)
{
    uint32_t tail = swq_tail;
    uint32_t slot;
    uint32_t copy;
    uint32_t addr;
    uint16_t idx;

    if (tail == swq_head)
        return 0;             /* SW queue empty */

    /* Acquire barrier paired with the producer's release (the dsb before
     * swq_head in gem_isr): once we have observed the new head, ensure the
     * slot's buf/len/ring_idx writes are visible before we read them. Needed
     * when the producer is gem_isr() in IRQ context (gem_rx_irq.c); a no-op
     * for the poll model where producer and consumer are the same thread. */
    __asm__ volatile ("dmb ld" ::: "memory");

    slot = tail % SWQ_DEPTH;
    copy = swq[slot].len;
    if (copy > len)
        copy = len;
    memcpy(buf, swq[slot].buf, copy);

    /* Recycle the BD back to hardware. */
    idx  = swq[slot].ring_idx;
    addr = (uint32_t)(uintptr_t)gem_rx_buf_pool[idx];
    addr &= RXBUF_ADDR_MASK;
    if (idx == RX_RING_LEN - 1)
        addr |= RXBUF_WRAP;
    gem_rx_ring[idx].status = 0;
    __asm__ volatile ("dsb sy" ::: "memory");
    gem_rx_ring[idx].addr   = addr;          /* OWN bit cleared = HW can write */
    cache_clean(&gem_rx_ring[idx], sizeof(gem_rx_ring[idx]));

    __asm__ volatile ("dsb sy" ::: "memory");
    swq_tail = tail + 1;

    return (int)copy;
}

/* gem_rx_poll.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Poll-only RX policy (Zynq-7000): gem_eth_poll() walks the hardware BD ring
 * directly; there is no SW queue and no GEM ISR. On the Cortex-A9 the GIC
 * delivers the GEM SPI and an enabled RX-complete IRQ storms the CPU, so
 * the GEM interrupt is left masked (GEM_IDR set in amd_eth_init) and
 * gem_rx_install() is a no-op.
 */
#include <string.h>
#include "gem_regs.h"
#include "gem_port.h"
#include "cache.h"

int gem_eth_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    uint32_t status;
    uint32_t frame_len;
    uint32_t copy;
    uint32_t addr;

    (void)ll;

    cache_inval(gem_rx_ring, sizeof(gem_rx_ring));
    if (!(gem_rx_ring[gem_rx_next].addr & RXBUF_OWN_SW)) {
        /* No frame. If the MAC hit "buffer not available" while the ring
         * was momentarily full, clear it so it re-walks the recycled ring
         * rather than wedging the RX path. */
        if (GEM_RSR & RSR_BUFFNA)
            GEM_RSR = RSR_BUFFNA;
        return 0;
    }

    status    = gem_rx_ring[gem_rx_next].status;
    frame_len = status & RXBUF_LEN_MASK;
    cache_inval(gem_rx_buf_pool[gem_rx_next], frame_len);
    copy = frame_len;
    if (copy > len)
        copy = len;
    memcpy(buf, gem_rx_buf_pool[gem_rx_next], copy);
    gem_rxframes++;

    /* Recycle the BD: clear status, then rewrite addr with OWN=0 (WRAP on
     * the last BD) and push it to memory so the MAC reuses the slot. */
    addr = (uint32_t)(uintptr_t)gem_rx_buf_pool[gem_rx_next];
    addr &= RXBUF_ADDR_MASK;
    if (gem_rx_next == RX_RING_LEN - 1)
        addr |= RXBUF_WRAP;
    gem_rx_ring[gem_rx_next].status = 0;
    __asm__ volatile ("dsb" ::: "memory");
    gem_rx_ring[gem_rx_next].addr = addr;        /* OWN=0 -> hardware can write */
    cache_clean(&gem_rx_ring[gem_rx_next], sizeof(gem_rx_ring[gem_rx_next]));
    __asm__ volatile ("dsb" ::: "memory");

    gem_rx_next = (gem_rx_next + 1) % RX_RING_LEN;
    return (int)copy;
}

void gem_rx_install(void)
{
    /* RX is polled; the GEM interrupt stays masked (GEM_IDR was set to
     * all-ones in amd_eth_init) and no SPI is enabled at the GIC. */
}

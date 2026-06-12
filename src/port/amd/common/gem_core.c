/* gem_core.c
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
 * Shared Cadence GEM core for the AMD/Xilinx ports. Owns the BD rings,
 * MDIO, polled TX (eth_send), the init sequence (amd_eth_init) and the
 * diagnostics. Everything that diverges per arch/SoC/board is reached
 * through hooks declared in gem_port.h: cache maintenance (arch cache.h),
 * clock/reset (board_gem.c), PHY dispatch (phy_dispatch_*.c) and the RX
 * delivery model (gem_rx_*.c).
 */
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "wolfip.h"
#include "board.h"
#include "uart.h"
#include "gem.h"
#include "gem_regs.h"
#include "gem_port.h"
#include "cache.h"

/* ---------------------------------------------------------------------
 * DMA-visible objects (BD rings, frame buffers, dummy BDs). The linker
 * places .dma_buffers in OCM (OCM layout) or a Normal-NC carve-out (DDR
 * layout); either way the MMU maps it Normal Non-Cacheable, so the rings
 * are inherently DMA-coherent. The cache_clean/cache_inval calls at each
 * BD hand-off are then no-ops, but stay correct should a future layout
 * map the rings cacheable.
 * ------------------------------------------------------------------- */
struct gem_bd gem_rx_ring[RX_RING_LEN]
    __attribute__((aligned(64), section(".dma_buffers")));
struct gem_bd gem_tx_ring[TX_RING_LEN]
    __attribute__((aligned(64), section(".dma_buffers")));
uint8_t gem_rx_buf_pool[RX_RING_LEN][BUF_LEN]
    __attribute__((aligned(64), section(".dma_buffers")));
uint8_t gem_tx_buf_pool[TX_RING_LEN][BUF_LEN]
    __attribute__((aligned(64), section(".dma_buffers")));

/* Dummy BD pair for disabling priority queues 1-3. The TX dummy has
 * USED=1 so the MAC ignores it; the RX dummy has the SW-OWN bit set so
 * the MAC won't write into queue 1-3 RX. */
static struct gem_bd dummy_tx_bd
    __attribute__((aligned(8), section(".dma_buffers")));
static struct gem_bd dummy_rx_bd
    __attribute__((aligned(8), section(".dma_buffers")));

volatile uint32_t gem_drops;
volatile uint32_t gem_irqs;
volatile uint32_t gem_rxframes;
volatile uint32_t gem_txsent;

uint32_t gem_rx_next;              /* next BD the SW will look at */
uint32_t gem_tx_next;              /* next BD the SW will try to TX */

uint8_t gem_phy_addr;

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
        uint32_t addr = (uint32_t)(uintptr_t)gem_rx_buf_pool[i];
        addr &= RXBUF_ADDR_MASK;
        if (i == RX_RING_LEN - 1)
            addr |= RXBUF_WRAP;
        gem_rx_ring[i].addr   = addr;          /* OWN=0 -> hardware can use */
        gem_rx_ring[i].status = 0;
    }
    gem_rx_next = 0;
    /* Clean the ring to the PoC so the MAC reads the BDs we just wrote
     * rather than stale memory (no-op when the ring is non-cacheable). */
    cache_clean(gem_rx_ring, sizeof(gem_rx_ring));
}

static void tx_ring_init(void)
{
    uint32_t i;
    /* Match u-boot zynq_gem: all BDs start as dummies with USED|LAST|WRAP,
     * addr=0. eth_send fills addr + length + LAST (and clears USED) when
     * actually transmitting. The WRAP bit on the last BD keeps the MAC
     * walker in our ring. */
    for (i = 0; i < TX_RING_LEN; i++) {
        gem_tx_ring[i].addr   = 0;
        gem_tx_ring[i].status = TXBUF_USED | TXBUF_LAST
                          | ((i == TX_RING_LEN - 1) ? TXBUF_WRAP : 0);
    }
    gem_tx_next = 0;
    cache_clean(gem_tx_ring, sizeof(gem_tx_ring));
}

/* ---------------------------------------------------------------------
 * eth_send (TX path; shared by all RX models)
 * ------------------------------------------------------------------- */
static int eth_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    uint32_t idx;
    uint32_t status;

    (void)ll;

    if (len > BUF_LEN)
        return -WOLFIP_EINVAL;       /* frame larger than a BD buffer */

    idx = gem_tx_next;
    /* Wait briefly for the BD to be free (USED=1 means MAC done). The
     * USED bit is written back by MAC DMA - invalidate the cache line so
     * the CPU does not see the stale USED=0 we wrote when we last armed
     * this BD. */
    {
        int spin;
        for (spin = 0; spin < 100000; spin++) {
            cache_inval(&gem_tx_ring[idx], sizeof(gem_tx_ring[idx]));
            if (gem_tx_ring[idx].status & TXBUF_USED)
                break;
        }
        if ((gem_tx_ring[idx].status & TXBUF_USED) == 0)
            return -WOLFIP_EAGAIN;   /* TX ring backed up - core retries */
    }

    memcpy(gem_tx_buf_pool[idx], buf, len);

    /* Pad to minimum Ethernet frame (60 bytes; MAC adds 4-byte FCS). */
    if (len < 60u) {
        memset(gem_tx_buf_pool[idx] + len, 0, 60u - len);
        len = 60u;
    }

    /* Flush the frame buffer from D-cache so MAC DMA reads see it. */
    cache_clean(gem_tx_buf_pool[idx], len);

    /* Re-arm BD: set buffer address, then clear USED with length+LAST
     * (preserve WRAP if this is the last BD). Buffer addr written before
     * status so MAC walking the ring sees a valid pair. */
    gem_tx_ring[idx].addr = (uint32_t)(uintptr_t)gem_tx_buf_pool[idx];
    status = (len & TXBUF_LEN_MASK) | TXBUF_LAST;
    if (idx == TX_RING_LEN - 1)
        status |= TXBUF_WRAP;
    gem_tx_ring[idx].status = status;        /* USED=0 -> ready for MAC */

    cache_clean(&gem_tx_ring[idx], sizeof(gem_tx_ring[idx]));
    GEM_NWCTRL |= NWCTRL_STARTTX;

    gem_txsent++;
    gem_tx_next = (idx + 1) % TX_RING_LEN;
    return (int)len;
}

/* ---------------------------------------------------------------------
 * Diagnostics
 * ------------------------------------------------------------------- */
uint32_t gem_irq_count(void) { return gem_irqs; }
uint32_t gem_rx_frames(void) { return gem_rxframes; }
uint32_t gem_tx_sent(void)   { return gem_txsent; }

void gem_dump_state(void)
{
    uint32_t i;
    uint32_t filled;
    uint32_t first_filled;
    cache_inval(gem_rx_ring, sizeof(gem_rx_ring));
    cache_inval(gem_tx_ring, sizeof(gem_tx_ring));
    uart_puts("GEM regs: NWCTRL="); uart_puthex(GEM_NWCTRL);
    uart_puts(" NWCFG=");           uart_puthex(GEM_NWCFG);
    uart_puts(" NWSR=");            uart_puthex(GEM_NWSR);
    uart_puts(" DMACR=");           uart_puthex(GEM_DMACR);
    uart_puts("\n          ISR=");  uart_puthex(GEM_ISR);
    uart_puts(" RSR=");             uart_puthex(GEM_RSR);
    uart_puts(" TSR=");             uart_puthex(GEM_TSR);
    uart_puts(" IMR=");             uart_puthex(GEM_IMR);
    uart_puts("\n          tx[0]="); uart_puthex(gem_tx_ring[0].addr);
    uart_puts("/");                 uart_puthex(gem_tx_ring[0].status);
    uart_puts(" rx[0]=");           uart_puthex(gem_rx_ring[0].addr);
    uart_puts("/");                 uart_puthex(gem_rx_ring[0].status);
    uart_puts("\n          irq=");  uart_putdec(gem_irqs);
    uart_puts(" rx_frm=");          uart_putdec(gem_rxframes);
    uart_puts(" tx_snt=");          uart_putdec(gem_txsent);
    uart_puts(" drops=");           uart_putdec(gem_drops);
    uart_puts("\n          HW counters: txoct="); uart_putdec(GEM_OCTTXL);
    uart_puts(" txcnt=");           uart_putdec(GEM_TXCNT);
    uart_puts(" rxoct=");           uart_putdec(GEM_OCTRXL);
    uart_puts(" rxcnt=");           uart_putdec(GEM_RXCNT);
    uart_puts(" rxfcs=");           uart_putdec(GEM_RXFCSCNT);
    uart_puts(" rxor=");            uart_putdec(GEM_RXORCNT);
    filled = 0;
    first_filled = 0xFFFF;
    for (i = 0; i < RX_RING_LEN; i++) {
        if (gem_rx_ring[i].addr & RXBUF_OWN_SW) {
            filled++;
            if (first_filled == 0xFFFF) first_filled = i;
        }
    }
    uart_puts(" rx_filled="); uart_putdec(filled);
    uart_puts(" first=");     uart_putdec(first_filled);
    uart_puts(" gem_rx_next=");   uart_putdec(gem_rx_next);
    uart_puts("\n");
}

/* ---------------------------------------------------------------------
 * Public init
 * ------------------------------------------------------------------- */
int amd_eth_init(struct wolfIP_ll_dev *ll)
{
    uint8_t addr;
    uint16_t id1;
    int found_phy;
    int speed;
    int fd;
    int link_up;
    uint32_t k;

    /* SoC-specific prerequisites (e.g. Zynq-7000 PL310 L2 disable). */
    gem_soc_pre_init();

    /* Bring the MAC to a known state on top of the platform clock. */
    gem_clk_reset();

    /* Disable everything before configuring. */
    GEM_NWCTRL = 0;
    GEM_IDR    = 0xFFFFFFFFu;
    (void)GEM_ISR;
    GEM_ISR    = 0xFFFFFFFFu;
    GEM_TSR    = 0xFFFFFFFFu;
    GEM_RSR    = RSR_BUFFNA | RSR_FRAMERX | RSR_RXOVR | RSR_HRESPNOK;

    /* Initial NWCFG: gigabit, full duplex, MDC=/96, 1536-byte frames,
     * strip FCS from RX, accept broadcasts, multicast via hash. Address
     * filtering is left on (no promiscuous COPYALL): broadcast (DHCP/ARP)
     * and our unicast / multicast-hash frames are received, which is all
     * the stack needs and avoids DMA'ing every frame on a busy LAN. */
    GEM_NWCFG = NWCFG_1000
              | NWCFG_FDEN
              | NWCFG_FCSREM
              | NWCFG_1536RXEN
              | NWCFG_MCASTHASHEN
              | (5u << NWCFG_MDCDIV_SHIFT);
#ifdef XILINX_AARCH64
    /* 64-bit AMBA data width: appropriate on the AArch64 SoCs (ZynqMP /
     * Versal). The Zynq-7000 GEM is fed by a 32-bit AXI master, where this
     * bit is inert, so it is left clear there. */
    GEM_NWCFG |= NWCFG_DWIDTH_64;
#endif

    /* DMACR: AHB fixed burst 16 beats, RX buffer 1536/64=24, TX/RX packet
     * buffer memory at max. Do NOT set bit 30 (DMA_ADDR_BUS_WIDTH 64-bit):
     * that selects 16-byte BD format with addr_hi and would break the
     * 8-byte struct gem_bd layout. */
    GEM_DMACR = (24u << 16)   /* RX buffer size in 64-byte units */
              | (1u  << 10)   /* TX packet buffer memory size = max */
              | (3u  << 8)    /* RX packet buffer memory size = max */
              | 0x10u;        /* burst length = 16 */

    /* Set MAC address into SAB1/SAT1. SAB1L latches on SAB1H write per
     * TRM, so write the high half last. */
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
    GEM_RXQBASE = (uint32_t)(uintptr_t)gem_rx_ring;
    GEM_TXQBASE = (uint32_t)(uintptr_t)gem_tx_ring;

    /* Disable priority queues 1-3 with dummy BDs (else the MAC may walk
     * uninitialised q1/q2/q3 base pointers and hang). */
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

    /* Clear any stale RX/TX packet classification screening (default 0 =
     * everything to Q0). */
    for (k = 0; k < 16; k++) {
        GEM_SCREEN_T1(k) = 0;
        GEM_SCREEN_T2(k) = 0;
    }

    /* Enable MDIO so we can talk to the PHY. */
    GEM_NWCTRL |= NWCTRL_MDEN;

    /* Scan all 32 MDIO addresses, reporting each responsive PHY's ID and
     * link status (BMSR reg 1, bit 2). A board may present more than one
     * PHY on the bus; prefer one that already has copper link so we
     * configure the PHY wired to the on-board RJ45 rather than the first
     * responder. */
    found_phy = 0;
    gem_phy_addr = 0;
    {
        uint16_t bmsr;
        for (addr = 0; addr < 32; addr++) {
            if (gem_mdio_read(addr, 0x02, &id1) != 0 || id1 == 0xFFFFu || id1 == 0)
                continue;
            bmsr = 0;
            (void)gem_mdio_read(addr, 0x01, &bmsr);
            uart_puts("MDIO scan: addr="); uart_puthex(addr);
            uart_puts(" id1=");            uart_puthex(id1);
            uart_puts(" bmsr=");           uart_puthex(bmsr);
            uart_puts((bmsr & 0x0004u) ? " LINK\n" : "\n");
            if (!found_phy || (bmsr & 0x0004u)) {
                found_phy = 1;
                gem_phy_addr = addr;
                if (bmsr & 0x0004u)
                    break;   /* linked PHY wins */
            }
        }
        if (!found_phy) {
            uart_puts("GEM: no PHY responding on MDIO!\n");
            return -10;
        }
    }
    /* Re-read id1 for the selected PHY so the vendor dispatch is correct
     * even when the scan broke early on a linked PHY. */
    (void)gem_mdio_read(gem_phy_addr, 0x02, &id1);
    uart_puts("GEM: PHY at MDIO addr=");
    uart_puthex(gem_phy_addr);
    uart_puts("\n");

    if (gem_phy_init(gem_phy_addr, id1, &speed, &fd) < 0) {
        uart_puts("GEM: PHY init failed\n");
        return -11;
    }

    /* If PHY ended up at 10/100, downshift the MAC and re-program the
     * RGMII reference clock to match (no-op on SoCs where the platform
     * firmware owns the GEM clock). */
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
        gem_set_ref_clk(speed);
    }

    /* Arm the RX delivery model (install IRQ handler, or leave masked for
     * poll-only ports) and enable RX/TX. */
    gem_rx_install();
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
    ll->poll = gem_eth_poll;
    ll->send = eth_send;
    ll->priv = NULL;

    link_up = (gem_phy_link_status(gem_phy_addr) == 1) ? 1 : 0;
    return (link_up << 8) | (int)gem_phy_addr;
}

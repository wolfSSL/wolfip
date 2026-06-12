/* gem_regs.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Cadence GEM register map, bit masks, buffer-descriptor layout and ring
 * sizing, shared by the AMD/Xilinx GEM core and its per-port hooks. The
 * register block base is GEM_BASE (each board.h selects the on-board GEM
 * instance, e.g. ZynqMP GEM3, Versal/Zynq-7000 GEM0).
 */
#ifndef AMD_GEM_REGS_H
#define AMD_GEM_REGS_H

#include <stdint.h>
#include "board.h"      /* GEM_BASE */

/* ---------------------------------------------------------------------
 * Register accessors (subset we use)
 * ------------------------------------------------------------------- */
#define GEM_NWCTRL          (*(volatile uint32_t *)(GEM_BASE + 0x000))
#define GEM_NWCFG           (*(volatile uint32_t *)(GEM_BASE + 0x004))
#define GEM_NWSR            (*(volatile uint32_t *)(GEM_BASE + 0x008))
#define GEM_DMACR           (*(volatile uint32_t *)(GEM_BASE + 0x010))
#define GEM_TSR             (*(volatile uint32_t *)(GEM_BASE + 0x014))
#define GEM_RXQBASE         (*(volatile uint32_t *)(GEM_BASE + 0x018))
#define GEM_TXQBASE         (*(volatile uint32_t *)(GEM_BASE + 0x01C))
#define GEM_RSR             (*(volatile uint32_t *)(GEM_BASE + 0x020))
#define GEM_ISR             (*(volatile uint32_t *)(GEM_BASE + 0x024))
#define GEM_IER             (*(volatile uint32_t *)(GEM_BASE + 0x028))
#define GEM_IDR             (*(volatile uint32_t *)(GEM_BASE + 0x02C))
#define GEM_IMR             (*(volatile uint32_t *)(GEM_BASE + 0x030))
#define GEM_PHYMNTNC        (*(volatile uint32_t *)(GEM_BASE + 0x034))
#define GEM_HASHL           (*(volatile uint32_t *)(GEM_BASE + 0x080))
#define GEM_HASHH           (*(volatile uint32_t *)(GEM_BASE + 0x084))
#define GEM_LADDR1L         (*(volatile uint32_t *)(GEM_BASE + 0x088))
#define GEM_LADDR1H         (*(volatile uint32_t *)(GEM_BASE + 0x08C))
/* Priority queue base addresses (queues 1-3). Cadence GEM has 4 TX and
 * 4 RX priority queues; if we don't point unused ones at a safe dummy
 * BD, the MAC will eventually try to fetch from queue1+ at power-on-
 * random addresses and hang (TSR.TXGO sticks with no octets sent).
 * U-Boot's zynq_gem and Linux's macb both set these. */
#define GEM_TXQ1BASE        (*(volatile uint32_t *)(GEM_BASE + 0x440))
#define GEM_TXQ2BASE        (*(volatile uint32_t *)(GEM_BASE + 0x444))
#define GEM_TXQ3BASE        (*(volatile uint32_t *)(GEM_BASE + 0x448))
#define GEM_RXQ1BASE        (*(volatile uint32_t *)(GEM_BASE + 0x480))
#define GEM_RXQ2BASE        (*(volatile uint32_t *)(GEM_BASE + 0x484))
#define GEM_RXQ3BASE        (*(volatile uint32_t *)(GEM_BASE + 0x488))
#define GEM_OCTTXL          (*(volatile uint32_t *)(GEM_BASE + 0x100))
#define GEM_TXCNT           (*(volatile uint32_t *)(GEM_BASE + 0x108))
#define GEM_OCTRXL          (*(volatile uint32_t *)(GEM_BASE + 0x150))
#define GEM_RXCNT           (*(volatile uint32_t *)(GEM_BASE + 0x158))
#define GEM_RXFCSCNT        (*(volatile uint32_t *)(GEM_BASE + 0x190))
#define GEM_RXORCNT         (*(volatile uint32_t *)(GEM_BASE + 0x1A4))
/* Packet-classification screening registers (cleared at init). */
#define GEM_SCREEN_T1(k)    (*(volatile uint32_t *)(GEM_BASE + 0x500 + 4*(k)))
#define GEM_SCREEN_T2(k)    (*(volatile uint32_t *)(GEM_BASE + 0x540 + 4*(k)))

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

/* GEM BD: two 32-bit words. */
struct gem_bd {
    uint32_t addr;
    uint32_t status;
};

/* Ring depth is kept small to fit text + DMA buffers + BSS (including the
 * per-socket TCP rx/tx windows) in the 256 KB OCM layout: bumping RX/TX to
 * 32/16 overflows OCM by ~12 KB. For a single busy-polled TCP stream the
 * shallow rings are not the bottleneck (the loop drains them every poll);
 * deeper rings for multi-stream / burst RX are a DDR-layout future lever. */
#define RX_RING_LEN         16
#define TX_RING_LEN         8
#define BUF_LEN             1536    /* multiple of 64, per DMACR.RXBS */

#endif /* AMD_GEM_REGS_H */

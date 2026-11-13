/* nxp_mcxe_enet.h
 *
 * NXP MCX E247 ethernet driver for wolfIP on the ENET MAC and the LAN8741 PHY
 * Defaults target the FRDM-MCXE247 board (RMII, PHY at MDIO 0, reset on PTC3).
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
 */
#ifndef WOLFIP_NXP_MCXE_ENET_H
#define WOLFIP_NXP_MCXE_ENET_H

#include <stdint.h>
#include "wolfip.h"

/* MDIO address of the PHY. */
#ifndef NXP_MCXE_ENET_PHY_ADDR
#define NXP_MCXE_ENET_PHY_ADDR  0U
#endif

/* Address used when nxp_mcxe_enet_init() is passed mac=NULL. Locally
 * administered: override it when more than one board shares a network. */
#ifndef NXP_MCXE_ENET_MAC
#define NXP_MCXE_ENET_MAC       { 0x02, 0x00, 0xE2, 0x47, 0x00, 0x01 }
#endif

/* 1: interrupt driven. The receive interrupt marks frames waiting, so
 * poll() returns at once when there are none, and send() sleeps in wfi
 * until the transmit interrupt when the transmit ring is full. The application must route ENET
 * interrupts 73 (transmit), 74 (receive) and 75 (error) to
 * nxp_mcxe_enet_irq_handler(). 0: polled, no interrupts. */
#ifndef NXP_MCXE_ENET_IRQ
#define NXP_MCXE_ENET_IRQ       0
#endif

/* NVIC priority of the ENET interrupts (upper 4 bits are used). */
#ifndef NXP_MCXE_ENET_IRQ_PRIO
#define NXP_MCXE_ENET_IRQ_PRIO  0x80U
#endif

/* 1: copy frames between the descriptor rings and the wolfIP buffers with
 * an eDMA channel instead of memcpy. The CPU waits for each copy, because
 * wolfIP needs the data when poll() or send() returns. */
#ifndef NXP_MCXE_ENET_EDMA
#define NXP_MCXE_ENET_EDMA      1
#endif

/* eDMA channel used for the copies; reserved for this driver. */
#ifndef NXP_MCXE_ENET_EDMA_CH
#define NXP_MCXE_ENET_EDMA_CH   0U
#endif

/* Shorter frames are copied with memcpy, which is faster than setting up
 * an eDMA transfer for a few bytes. */
#ifndef NXP_MCXE_ENET_EDMA_MIN
#define NXP_MCXE_ENET_EDMA_MIN  128U
#endif

/* 1: count frames and the core cycles (DWT) spent in the driver, for
 * throughput profiling. Read with nxp_mcxe_enet_stats_get(). */
#ifndef NXP_MCXE_ENET_STATS
#define NXP_MCXE_ENET_STATS     0
#endif

/* System oscillator frequency, used to work out the core clock when it
 * runs from SOSC or the SPLL. */
#ifndef NXP_MCXE_ENET_SOSC_HZ
#define NXP_MCXE_ENET_SOSC_HZ   8000000U
#endif

/* Reset the PHY, wait up to 5 s for link, start the MAC, and populate ll
 * with the MAC address, interface name and poll/send callbacks. May be
 * called again to restart the interface. Returns 0 when the MAC is running,
 * -2 when the PHY does not respond, -3 without link and -4 when the MAC
 * does not come out of reset. */
int nxp_mcxe_enet_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);

/* MDIO address of the PHY, or -1 before the PHY was found. */
int nxp_mcxe_enet_phy_addr(void);

/* MDIO clause-22 read of the PHY (0xFFFF on error). */
uint16_t nxp_mcxe_enet_phy_read(uint8_t reg);

/* Non-zero when the PHY reports link up. */
uint32_t nxp_mcxe_enet_link_up(void);

/* ENET DMA bus errors seen since start. */
uint32_t nxp_mcxe_enet_bus_errors(void);

#if NXP_MCXE_ENET_STATS
/* Driver counters since the last nxp_mcxe_enet_stats_reset(). Cycle counts
 * are core clock cycles; copy_cycles is included in rx_cycles and
 * tx_cycles, tx_wait_cycles in tx_cycles. */
struct nxp_mcxe_enet_stats {
    uint64_t rx_cycles;         /* poll() calls that returned a frame */
    uint64_t idle_cycles;       /* poll() calls that found no frame */
    uint64_t tx_cycles;         /* send() calls */
    uint64_t tx_wait_cycles;    /* send() waiting for a free descriptor */
    uint64_t copy_cycles;       /* frame copies, both directions */
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint32_t rx_frames;
    uint32_t tx_frames;
    uint32_t tx_ring_full;      /* send() calls that found the ring full */
    uint32_t core_hz;
};

void nxp_mcxe_enet_stats_get(struct nxp_mcxe_enet_stats *st);
void nxp_mcxe_enet_stats_reset(void);
#endif

#if NXP_MCXE_ENET_IRQ
/* Interrupt handler for ENET IRQs 73, 74 and 75. */
void nxp_mcxe_enet_irq_handler(void);
#endif

#endif /* WOLFIP_NXP_MCXE_ENET_H */

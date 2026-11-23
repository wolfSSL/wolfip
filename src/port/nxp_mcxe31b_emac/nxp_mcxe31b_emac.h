/* nxp_mcxe31b_emac.h
 *
 * NXP MCX E31B ethernet driver for wolfIP on the EMAC (Synopsys Ethernet
 * QoS) and the LAN8741 PHY. Defaults target the FRDM-MCXE31B board (RMII,
 * 50 MHz reference clock on PTD11, PHY at MDIO 0, reset on PTC3).
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
#ifndef WOLFIP_NXP_MCXE31B_EMAC_H
#define WOLFIP_NXP_MCXE31B_EMAC_H

#include <stdint.h>
#include "wolfip.h"

/* MDIO address of the PHY. */
#ifndef NXP_MCXE31B_EMAC_PHY_ADDR
#define NXP_MCXE31B_EMAC_PHY_ADDR  0U
#endif

/* Address used when nxp_mcxe31b_emac_init() is passed mac=NULL. Locally
 * administered: override it when more than one board shares a network. */
#ifndef NXP_MCXE31B_EMAC_MAC
#define NXP_MCXE31B_EMAC_MAC    { 0x02, 0x00, 0xE3, 0x1B, 0x00, 0x01 }
#endif

/* 1: interrupt driven. The receive interrupt marks frames waiting, so
 * poll() returns at once when there are none. The application must route
 * EMAC interrupt 105 (common) to nxp_mcxe31b_emac_irq_handler().
 * 0: polled, no interrupts. */
#ifndef NXP_MCXE31B_EMAC_IRQ
#define NXP_MCXE31B_EMAC_IRQ    0
#endif

/* NVIC priority of the EMAC interrupt (upper 4 bits are used). */
#ifndef NXP_MCXE31B_EMAC_IRQ_PRIO
#define NXP_MCXE31B_EMAC_IRQ_PRIO 0x80U
#endif

/* Receive and transmit descriptors */
#ifndef NXP_MCXE31B_EMAC_RX_DESC
#define NXP_MCXE31B_EMAC_RX_DESC 4U
#endif
#ifndef NXP_MCXE31B_EMAC_TX_DESC
#define NXP_MCXE31B_EMAC_TX_DESC 8U
#endif

/* DMA burst length in beats, 1, 2, 4, 8, 16 or 32. */
#ifndef NXP_MCXE31B_EMAC_PBL
#define NXP_MCXE31B_EMAC_PBL    8U
#endif

/* DMA_SysBus_Mode value: EMAC_DMA_SYSBUS_FB, _AAL and _MB of
 * nxp_mcxe31b_emac_regs.h, or 0 for the reset value (undefined length
 * bursts). The default, fixed address-aligned bursts (FB | AAL), measured
 * 2-4% faster than the reset value on transmit and bidirectional traffic. */
#ifndef NXP_MCXE31B_EMAC_SYSBUS
#define NXP_MCXE31B_EMAC_SYSBUS 0x1001U
#endif

/* 1: the transmit DMA fetches the next frame before the status of the
 * previous one is written back (DMA_CH0_TX_Control[OSF]). */
#ifndef NXP_MCXE31B_EMAC_TX_OSF
#define NXP_MCXE31B_EMAC_TX_OSF 1
#endif

/* 1: count frames and the core cycles (DWT) spent in the driver, for
 * throughput profiling. Read with nxp_mcxe31b_emac_stats_get(). */
#ifndef NXP_MCXE31B_EMAC_STATS
#define NXP_MCXE31B_EMAC_STATS  0
#endif

/* Crystal (FXOSC) frequency, used to work out the core and bus clocks when
 * they run from the PLL. */
#ifndef NXP_MCXE31B_EMAC_FXOSC_HZ
#define NXP_MCXE31B_EMAC_FXOSC_HZ 16000000U
#endif

/* Reset the PHY, wait up to 5 s for link, start the MAC, and populate ll
 * with the MAC address, interface name and poll/send callbacks. May be
 * called again to restart the interface. Returns 0 when the MAC is running,
 * -1 on a bad argument, -2 when the PHY does not respond, -3 without link,
 * -4 when the EMAC clocks do not start or the MAC does not come out of
 * reset, and -5 when the descriptor rings are not in the DTCM (they must be,
 * see README.md). */
int nxp_mcxe31b_emac_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);

/* MDIO address of the PHY, or -1 before the PHY was found. */
int nxp_mcxe31b_emac_phy_addr(void);

/* MDIO clause-22 read of the PHY (0xFFFF on error). */
uint16_t nxp_mcxe31b_emac_phy_read(uint8_t reg);

/* Non-zero when the PHY reports link up. */
uint32_t nxp_mcxe31b_emac_link_up(void);

/* EMAC DMA fatal bus errors seen since start. */
uint32_t nxp_mcxe31b_emac_bus_errors(void);

#if NXP_MCXE31B_EMAC_STATS
/* Driver counters since the last nxp_mcxe31b_emac_stats_reset(). Cycle
 * counts are core clock cycles; copy_cycles is included in rx_cycles and
 * tx_cycles, tx_wait_cycles in tx_cycles. */
struct nxp_mcxe31b_emac_stats {
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
    uint32_t rx_errors;         /* frames dropped with an error status */
    uint32_t core_hz;
};

void nxp_mcxe31b_emac_stats_get(struct nxp_mcxe31b_emac_stats *st);
void nxp_mcxe31b_emac_stats_reset(void);
#endif

#if NXP_MCXE31B_EMAC_IRQ
/* Interrupt handler for EMAC IRQ 105. */
void nxp_mcxe31b_emac_irq_handler(void);
#endif

#endif /* WOLFIP_NXP_MCXE31B_EMAC_H */

/* gem_port.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Internal interface between the shared GEM core (gem_core.c) and the
 * per-port / per-arch pieces it is composed with at build time:
 *   - cache maintenance      arch/<a>/cache.h   (cache_clean/cache_inval)
 *   - SoC clock/reset quirks  boards/<b>/board_gem.c
 *   - PHY vendor dispatch     ip/phy_dispatch_*.c
 *   - RX delivery model       ip/gem_rx_*.c  (+ ip/gem_swq.c for the swq
 *                             variants)
 * Not part of the public API (that is gem.h).
 */
#ifndef AMD_GEM_PORT_H
#define AMD_GEM_PORT_H

#include <stdint.h>
#include "wolfip.h"
#include "gem_regs.h"

/* --- State owned by gem_core.c, shared with the RX-model TU --- */
extern struct gem_bd gem_rx_ring[RX_RING_LEN];
extern struct gem_bd gem_tx_ring[TX_RING_LEN];
extern uint8_t gem_rx_buf_pool[RX_RING_LEN][BUF_LEN];
extern uint8_t gem_tx_buf_pool[TX_RING_LEN][BUF_LEN];
extern uint32_t gem_rx_next;
extern uint32_t gem_tx_next;
extern volatile uint32_t gem_irqs;
extern volatile uint32_t gem_rxframes;
extern volatile uint32_t gem_txsent;
extern volatile uint32_t gem_drops;
extern uint8_t gem_phy_addr;

/* --- SoC clock/reset hooks (boards/<b>/board_gem.c) --- */
void gem_soc_pre_init(void);          /* SoC quirks before MAC config */
void gem_clk_reset(void);             /* pulse MAC reset / base clock */
void gem_set_ref_clk(int speed_mbps); /* RGMII TX clock for link speed */

/* --- PHY vendor dispatch (ip/phy_dispatch_*.c). id1 = MII reg 2 from
 * the MDIO scan; sets *speed (10/100/1000) and *fd; returns 0 / <0. --- */
int gem_phy_init(uint8_t phy_addr, uint16_t id1, int *speed, int *full_duplex);
int gem_phy_link_status(uint8_t phy_addr);

/* --- RX delivery model (ip/gem_rx_*.c) --- */
void gem_rx_install(void);   /* arm the RX path (install IRQ, or mask) */
int  gem_eth_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len); /* ll->poll */

/* --- SW RX queue helpers (ip/gem_swq.c; swq RX models only) --- */
void gem_isr(void);                            /* fill swq from gem_rx_ring */
int  gem_swq_drain(void *buf, uint32_t len);   /* consume one swq slot */

#endif /* AMD_GEM_PORT_H */

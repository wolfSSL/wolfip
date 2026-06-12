/* gem.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Public API of the shared Cadence GEM driver for the AMD/Xilinx ports
 * (ZynqMP / Versal / Zynq-7000). Single-instance, RGMII, gigabit, polled
 * TX. The RX delivery model (IRQ-driven swq vs poll-only) is selected per
 * board by the gem_rx_*.c translation unit linked in.
 */
#ifndef AMD_GEM_H
#define AMD_GEM_H

#include <stdint.h>
#include "wolfip.h"

/* Initialize the GEM, its clock + reset, the PHY, and populate the wolfIP
 * link-layer device. Returns:
 *   < 0          on error (negated TRM code)
 *   bits [7:0]   PHY MDIO address used
 *   bit  [8]     link_up flag (1 = link is up at end of init)
 */
int amd_eth_init(struct wolfIP_ll_dev *ll);

/* MDIO helpers exposed for the PHY drivers. */
int gem_mdio_read(uint8_t phy_addr, uint8_t reg, uint16_t *out);
int gem_mdio_write(uint8_t phy_addr, uint8_t reg, uint16_t value);

/* Diagnostics: dump GEM registers and counters to UART. */
void gem_dump_state(void);
uint32_t gem_irq_count(void);
uint32_t gem_rx_frames(void);
uint32_t gem_tx_sent(void);

#endif /* AMD_GEM_H */

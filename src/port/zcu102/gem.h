/* gem.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * Cadence GEM driver for Xilinx UltraScale+ MPSoC GEM3 (on-board RJ45
 * on ZCU102). Single-instance, RGMII, gigabit, polled TX, IRQ-driven
 * RX.
 */
#ifndef ZCU102_GEM_H
#define ZCU102_GEM_H

#include <stdint.h>
#include "../../../wolfip.h"

/* Initialize GEM3, MMIO clock + reset, PHY, and populate the wolfIP
 * link-layer device. Returns:
 *   < 0          on error (negated TRM code)
 *   bits [7:0]   PHY MDIO address used
 *   bit  [8]     link_up flag (1 = link is up at end of init)
 */
int zcu102_eth_init(struct wolfIP_ll_dev *ll);

/* MDIO helpers exposed for the PHY driver (phy_dp83867.c). */
int gem_mdio_read(uint8_t phy_addr, uint8_t reg, uint16_t *out);
int gem_mdio_write(uint8_t phy_addr, uint8_t reg, uint16_t value);

/* Diagnostics: dump GEM registers and counters to UART. */
void gem_dump_state(void);
uint32_t gem_irq_count(void);
uint32_t gem_rx_frames(void);
uint32_t gem_tx_sent(void);

#endif /* ZCU102_GEM_H */

/* tc3xx_eth.h
 *
 * Infineon AURIX TC3xx GETH (RMII) driver for wolfIP, on top of the iLLD.
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
#ifndef TC3XX_ETH_H
#define TC3XX_ETH_H

#include <stdint.h>
#include "wolfip.h"

#define TC3XX_ETH_OK        0
#define TC3XX_ETH_EINVAL   (-1)   /* bad argument or wrong driver state */
#define TC3XX_ETH_EIO      (-2)   /* MDIO or DMA did not complete in time */
#define TC3XX_ETH_ENOPHY   (-3)   /* no PHY answered on MDIO */
#define TC3XX_ETH_ENOCLK   (-4)   /* no RMII reference clock from the PHY */

/* Bring up MAC and PHY, start the datapath and fill in ll; mac may be NULL.
 * TC3XX_ETH_OK even without link; succeeds once, EINVAL after that. */
int tc3xx_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);

/* Re-read the PHY and reprogram the MAC on a change: 1 up, 0 down,
 * TC3XX_ETH_EINVAL before a PHY is found, TC3XX_ETH_EIO on MDIO failure. */
int tc3xx_eth_link_update(void);

/* Clause 22 after init, phy_addr and reg 0..31; EIO if MDIO stays busy. Not
 * serialised with each other or link_update(): call all from one context. */
int tc3xx_eth_mdio_read(uint8_t phy_addr, uint8_t reg, uint16_t *value);
int tc3xx_eth_mdio_write(uint8_t phy_addr, uint8_t reg, uint16_t value);

/* PHY address in use, or -1 before tc3xx_eth_init() found one. */
int tc3xx_eth_phy_addr(void);

/* Cumulative since init; rx_dropped counts errored and oversize frames.
 * Any pointer may be NULL. */
void tc3xx_eth_get_stats(uint32_t *rx, uint32_t *tx, uint32_t *rx_dropped);

#if defined(TC3XX_ETH_RX_IRQ) && TC3XX_ETH_RX_IRQ
/* Called from the receive interrupt, e.g. to wake the task running
 * wolfIP_poll(). It must not call into wolfIP or this driver. */
void tc3xx_eth_set_rx_notify(void (*cb)(void));
#endif

#endif /* TC3XX_ETH_H */

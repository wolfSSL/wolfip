/* nxp_enetc.h
 *
 * NXP ENETC ethernet driver for wolfIP (LS1028A and other Layerscape parts
 * with the integrated-endpoint ENETC MAC). AArch64, little-endian.
 *
 * ENETC is a PCIe integrated endpoint: the MAC, its station interface (SI)
 * register space, and a shared MDIO controller appear as PCI functions on
 * an internal ECAM root complex (bus 0). This driver discovers the port
 * over ECAM, sets up one RX and one TX buffer-descriptor ring in memory,
 * brings up the MAC + PHY, and exposes the wolfIP poll/send callbacks.
 *
 * Board parameters (ECAM base, port/function index, PHY address, interface
 * mode) live in nxp_enetc_board.h and are overridable from CFLAGS.
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
#ifndef WOLFIP_NXP_ENETC_H
#define WOLFIP_NXP_ENETC_H

#include <stdint.h>
#include "wolfip.h"
#include "nxp_enetc_board.h"

/* ---- PCI / ECAM ------------------------------------------------------ */
/* Generic ECAM (bus 0): cfg addr = ECAM_CFG_BASE + (fn << 12) + reg. */
#define ENETC_PCI_VENDOR_ID     0x1957U    /* Freescale/NXP */
#define ENETC_PCI_DEV_ETH       0xE100U
#define ENETC_PCI_DEV_MDIO      0xEE01U

#define PCI_CFG_VENDOR_ID       0x00U
#define PCI_CFG_DEVICE_ID       0x02U
#define PCI_CFG_COMMAND         0x04U
#define PCI_CFG_BAR0            0x10U
#define PCI_CFG_BAR1            0x14U      /* high dword of 64-bit BAR0 */
#define PCI_CMD_MEMORY          0x0002U
#define PCI_CMD_MASTER          0x0004U
#define PCI_BAR_MEM_MASK        0xFFFFFFF0UL

/* ENETC port registers sit ENETC_PORT_REGS_OFF above the SI BAR0 base. */
#define ENETC_PORT_REGS_OFF     0x10000UL
/* MDIO function register block within its BAR0. */
#define ENETC_MDIO_REGS_OFF     0x1C00UL

/* ---- Station interface (SI) global registers (BAR0 + off) ------------ */
#define ENETC_SIMR              0x000UL
#define ENETC_SIMR_EN           (1UL << 31)
#define ENETC_SICAR0            0x040UL
/* 0x27276767 = coherent/snoopable DMA (matches U-Boot/Linux). Requires the
 * CCI-400 CPU-cluster snoop enabled in the wolfBoot HAL, else the snoop takes
 * a system bus error (SIUSBEDR[V]/TBSR[SBE]). */
#define ENETC_SICAR_VALUE       0x27276767UL

/* ---- Port registers (PORT = BAR0 + 0x10000) ------------------------- */
#define ENETC_PMR               0x0000UL
#define ENETC_PMR_SI0_EN        (1UL << 16)
/* PMR[11:8] PSPEED = port speed for the TX scheduler. Must match the link or
 * the scheduler stalls (TX BD consumer index never advances). Reset is 1000M
 * (0x300); a plain SI0_EN write would clear it. */
#define ENETC_PMR_PSPEED_1000M  (3UL << 8)
#define ENETC_PSICFGR0          0x0940UL
#define ENETC_PSICFGR_SET_TXBDR(n) ((uint32_t)(n) & 0xFFU)
#define ENETC_PSICFGR_SET_RXBDR(n) (((uint32_t)(n) & 0xFFU) << 16)
#define ENETC_PSIPMAR0          0x0100UL   /* MAC bytes [0..3] */
#define ENETC_PSIPMAR1          0x0104UL   /* MAC bytes [4..5] */
#define ENETC_PM_CC             0x8008UL   /* MAC command/config */
#define ENETC_PM_CC_RX_TX_EN    0x00008813UL
#define ENETC_PM_MAXFRM         0x8014UL
#define ENETC_PM_IF_MODE        0x8300UL
#define ENETC_PM_IF_MODE_AN_ENA (1UL << 15)
#define ENETC_PM_IF_MODE_RG     (1UL << 2)  /* RGMII interface select (BIT 2) */
#define ENETC_PM_IF_MODE_FULL_DPX (1UL << 12) /* full duplex (BIT 12) */
#define ENETC_PM_IFM_SSP_1000   (2UL << 13)
#define ENETC_PM_IFM_SSP_MASK   (3UL << 13)

/* ---- BD ring registers ----------------------------------------------- */
/* ring block = SI + 0x8000 + type*0x100 + n*0x200; type: TX=0, RX=1 */
#define ENETC_BDR_BASE(type, n) (0x8000UL + ((uint32_t)(type) * 0x100UL) + \
                                 ((uint32_t)(n) * 0x200UL))
#define ENETC_BDR_TX            0U
#define ENETC_BDR_RX            1U
#define ENETC_BDR_IDX_MASK      0xFFFFU

/* RX ring register offsets (within a ring block). */
#define ENETC_RBMR              0x00UL
#define ENETC_RBMR_EN           (1UL << 31)
#define ENETC_RBBSR             0x08UL     /* buffer size */
#define ENETC_RBCIR             0x0CUL     /* consumer index (SW) */
#define ENETC_RBBAR0            0x10UL     /* ring base lo */
#define ENETC_RBBAR1            0x14UL     /* ring base hi */
#define ENETC_RBPIR             0x18UL     /* producer index (HW) */
#define ENETC_RBLENR            0x20UL     /* ring length (#BDs) */

/* TX ring register offsets. */
#define ENETC_TBMR              0x00UL
#define ENETC_TBMR_EN           (1UL << 31)
#define ENETC_TBBAR0            0x10UL     /* ring base lo */
#define ENETC_TBBAR1            0x14UL     /* ring base hi */
#define ENETC_TBPIR             0x18UL     /* producer index (SW) */
#define ENETC_TBCIR             0x1CUL     /* consumer index (HW) */
#define ENETC_TBLENR            0x20UL     /* ring length (#BDs) */

/* ---- Internal MDIO (shared MDIO PF, regs at BAR0 + 0x1C00) ----------- */
#define ENETC_MDIO_CFG          0x00UL
#define ENETC_MDIO_CTL          0x04UL
#define ENETC_MDIO_DATA         0x08UL
#define ENETC_MDIO_STAT         0x0CUL
#define ENETC_MDIO_CFG_C22      0x00809508UL
#define ENETC_MDIO_CFG_BSY      (1UL << 0)
#define ENETC_MDIO_CFG_RD_ER    (1UL << 1)
#define ENETC_MDIO_CTL_READ     (1UL << 15)
#define ENETC_MDIO_CTL_ADDR(phy, reg) ((((uint32_t)(phy) & 0x1FU) << 5) | \
                                        ((uint32_t)(reg) & 0x1FU))

/* ---- Buffer descriptors (little-endian, 16 bytes) ------------------- */
struct enetc_tx_bd {
    volatile uint64_t addr;
    volatile uint16_t buf_len;
    volatile uint16_t frm_len;
    volatile uint16_t err_csum;
    volatile uint16_t flags;
};
#define ENETC_TXBD_FLAGS_F      (1U << 15)  /* final BD of the frame */

/* HW overwrites the BD with a writeback view: csum/parse/rss in bytes 0-7,
 * received length at +8, status (lstatus) at +12. lstatus: READY bit30,
 * FINAL bit31, error byte bits16-23 (cf. U-Boot fsl_enetc.c). */
struct enetc_rx_bd {
    volatile uint32_t addr_lo;     /* SW: buffer addr lo / WB: csum+parse */
    volatile uint32_t addr_hi;     /* SW: buffer addr hi / WB: rss hash   */
    volatile uint16_t buf_len;     /* WB: received length (offset 8)      */
    volatile uint16_t vlan_opt;    /* WB: vlan (offset 10)                */
    volatile uint32_t lstatus;     /* WB: status word (offset 12)         */
};
#define ENETC_RXBD_LSTATUS_READY(s) (((s) >> 30) & 1U)        /* bit 30 */
#define ENETC_RXBD_LSTATUS_FINAL(s) (((s) >> 31) & 1U)        /* bit 31 */
#define ENETC_RXBD_LSTATUS_ERR(s)   (((s) >> 16) & 0xFFU)     /* bits 16-23 */

/* ---- Ring / buffer sizing ------------------------------------------- */
#define ENETC_BD_ALIGN          128U   /* BD array alignment */
#define ENETC_BUF_ALIGN         64U    /* RX/TX buffer alignment */
#define ENETC_RX_RING_SIZE      8U     /* must be a multiple of 8 */
#define ENETC_TX_RING_SIZE      8U
#define ENETC_MAX_BUF_LEN       2048U
#define ENETC_POLL_TRIES        32000U

/* ---- Public API ------------------------------------------------------ */

/* Discover the ENETC port over ECAM, set up the BD rings, bring up the
 * MAC + PHY, and populate ll with the MAC address, interface name and
 * poll/send callbacks. Pass mac=NULL to use the built-in default address.
 * Returns a status word encoding the detected PHY id high byte, link bit
 * and PHY address; 0 if no PHY is detected (datapath up, link down,
 * nxp_enetc_phy_addr() returns -1); or a negative value on hard failure. */
int nxp_enetc_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);

/* Detected PHY MDIO address, or -1 if no external PHY was found. */
int nxp_enetc_phy_addr(void);

/* MDIO clause-22 read of the detected PHY (0xFFFF on error / no PHY). */
uint16_t nxp_enetc_phy_read(uint8_t reg);

/* Non-zero when the PHY reports link up. */
uint32_t nxp_enetc_link_up(void);

/* Optional debug log hook: the driver calls it at bring-up phase
 * boundaries. Pass NULL (default) to disable. */
void nxp_enetc_set_log(void (*log_fn)(const char *msg));

#endif /* WOLFIP_NXP_ENETC_H */

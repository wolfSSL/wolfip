/* nxp_etsec.h
 *
 * NXP eTSEC (Enhanced Three-Speed Ethernet Controller / Gianfar) driver for
 * wolfIP. Targets the eTSEC MAC on big-endian PowerPC QorIQ/PQ parts
 * (P1020/P1021/P2020, e500v2). Brings up one eTSEC in polled mode and
 * exposes the wolfIP poll/send callbacks.
 *
 * Board parameters (CCSRBAR, eTSEC index, interface mode, PHY address) live
 * in nxp_etsec_board.h and are overridable from CFLAGS.
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
#ifndef WOLFIP_NXP_ETSEC_H
#define WOLFIP_NXP_ETSEC_H

#include <stdint.h>
#include "wolfip.h"
#include "nxp_etsec_board.h"

/* ---- eTSEC block layout (offsets from CCSRBAR) ---------------------- */
/* eTSEC1=0x24000, eTSEC2=0x25000, eTSEC3=0x26000 (step 0x1000). */
#define ETSEC_BASE(n)           (NXP_ETSEC_CCSRBAR + 0x24000UL + \
                                 ((uint32_t)(n) * 0x1000UL))
/* The MDIO management block is in eTSEC1's window at +0x520. */
#define ETSEC_MDIO_OFFSET       0x520UL

/* ---- eTSEC register offsets (within a block) ------------------------ */
#define ETSEC_IEVENT            0x010UL
#define ETSEC_IMASK             0x014UL
#define ETSEC_ECNTRL            0x020UL
#define ETSEC_MINFLR            0x024UL
#define ETSEC_DMACTRL           0x02CUL
#define ETSEC_TBIPA             0x030UL
#define ETSEC_TCTRL             0x100UL
#define ETSEC_TSTAT             0x104UL
#define ETSEC_TBPTR             0x184UL
#define ETSEC_TBASE             0x204UL
#define ETSEC_RCTRL             0x300UL
#define ETSEC_RSTAT             0x304UL
#define ETSEC_MRBLR             0x340UL
#define ETSEC_RBPTR             0x384UL
#define ETSEC_RBASE             0x404UL
#define ETSEC_MACCFG1           0x500UL
#define ETSEC_MACCFG2           0x504UL
#define ETSEC_IPGIFG            0x508UL
#define ETSEC_HAFDUP            0x50CUL
#define ETSEC_MAXFRM            0x510UL
#define ETSEC_MACSTNADDR1       0x540UL
#define ETSEC_MACSTNADDR2       0x544UL
#define ETSEC_IADDR0            0x800UL
#define ETSEC_GADDR0            0x880UL
#define ETSEC_ATTR              0xBC8UL
#define ETSEC_ATTRELI           0xBCCUL

/* MACCFG1 */
#define MACCFG1_SOFT_RESET      0x80000000UL
#define MACCFG1_RX_FLOW         0x00000020UL
#define MACCFG1_TX_FLOW         0x00000010UL
#define MACCFG1_RX_EN           0x00000004UL
#define MACCFG1_TX_EN           0x00000001UL

/* MACCFG2 */
#define MACCFG2_INIT_SETTINGS   0x00007205UL
#define MACCFG2_FULL_DUPLEX     0x00000001UL
#define MACCFG2_IF_MASK         0x00000300UL
#define MACCFG2_GMII            0x00000200UL  /* byte (1000) */
#define MACCFG2_MII             0x00000100UL  /* nibble (10/100) */

/* ECNTRL */
#define ECNTRL_INIT_SETTINGS    0x00001000UL
#define ECNTRL_TBI_MODE         0x00000020UL
#define ECNTRL_REDUCED_MODE     0x00000010UL  /* RGMII/RMII reduced pins */
#define ECNTRL_R100             0x00000008UL  /* 100Mbps in reduced mode */
#define ECNTRL_REDUCED_MII      0x00000004UL  /* RMII */
#define ECNTRL_SGMII_MODE       0x00000002UL

/* DMACTRL */
#define DMACTRL_INIT_SETTINGS   0x000000C3UL  /* TDSEN|TBDSEN|WOP|... */
#define DMACTRL_GRS             0x00000010UL
#define DMACTRL_GTS             0x00000008UL

/* TSTAT / RSTAT (clear-on-write halt bits = ring doorbells). */
#define TSTAT_CLEAR_THALT       0x80000000UL
#define RSTAT_CLEAR_RHALT       0x00800000UL

/* IEVENT */
#define IEVENT_INIT_CLEAR       0xFFFFFFFFUL
#define IEVENT_BSY              0x20000000UL
#define IEVENT_GRSC             0x00000100UL
#define IEVENT_GTSC             0x02000000UL

/* RCTRL */
#define RCTRL_PROM              0x00000008UL

/* Misc init values. */
#define MINFLR_INIT_SETTINGS    0x00000040UL
#define ATTR_INIT_SETTINGS      0x000000C0UL

/* ---- MDIO management registers (eTSEC1 base + 0x520) ---------------- */
#define MIIM_CFG                0x00UL
#define MIIM_COM                0x04UL
#define MIIM_ADD                0x08UL
#define MIIM_CON                0x0CUL   /* write data */
#define MIIM_STAT               0x10UL   /* read data */
#define MIIM_IND                0x14UL
#define MIIMCFG_RESET_MGMT      0x80000000UL
#define MIIMCFG_INIT_VALUE      0x00000003UL  /* clock divider */
#define MIIMCOM_READ_CYCLE      0x00000001UL
#define MIIMADD_PHY_SHIFT       8
#define MIIMIND_BUSY            0x00000001UL
#define MIIMIND_NOTVALID        0x00000004UL

/* ---- Buffer descriptor (big-endian, 8 bytes) ------------------------ */
struct etsec_bd {
    volatile uint16_t status;
    volatile uint16_t length;
    volatile uint32_t bufptr;
};

/* RX status bits */
#define RXBD_EMPTY              0x8000U
#define RXBD_WRAP               0x2000U
#define RXBD_INTERRUPT          0x1000U
#define RXBD_LAST              0x0800U
#define RXBD_FIRST             0x0400U
#define RXBD_STATS             0x003FU  /* error mask (clean frame == 0) */

/* TX status bits */
#define TXBD_READY             0x8000U
#define TXBD_PADCRC            0x4000U
#define TXBD_WRAP              0x2000U
#define TXBD_INTERRUPT         0x1000U
#define TXBD_LAST             0x0800U
#define TXBD_CRC              0x0400U

/* ---- Ring / buffer sizing ------------------------------------------- */
#define ETSEC_RX_RING_SIZE      8U
#define ETSEC_TX_RING_SIZE      8U
#define ETSEC_MAX_BUF_LEN       1536U  /* MRBLR, multiple of 64, >= MAXFRM */
#define ETSEC_MAX_FRAME_LEN     1518U
#define ETSEC_BD_ALIGN          32U    /* e500v2 cache line */
#define ETSEC_BUF_ALIGN         64U
#define ETSEC_POLL_TRIES        1000000U

/* ---- Public API ------------------------------------------------------ */

/* Soft-reset and bring up the selected eTSEC (MAC, BD rings, MDIO, PHY) and
 * populate ll with the MAC address, interface name and poll/send callbacks.
 * Pass mac=NULL for the built-in default. Returns a status word encoding the
 * detected PHY id high byte (bits 16-23), the link bit (0x100) and the PHY
 * MDIO address (low byte), or a negative value on hard failure. Two special
 * encodings do NOT carry a PHY address in the low byte:
 *   0x1FF - fixed link (NXP_ETSEC_FIXED_LINK): link up, low byte 0xFF is a
 *           "no PHY" sentinel, not an address; nxp_etsec_phy_addr() == -1.
 *   0x000 - dynamic link but no PHY detected: link down; the datapath is
 *           still forced up, and nxp_etsec_phy_addr() == -1. */
int nxp_etsec_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);

/* Detected PHY MDIO address, or -1 (also -1 for a fixed link). */
int nxp_etsec_phy_addr(void);

/* MDIO clause-22 read of the detected PHY (0xFFFF on error / no PHY). */
uint16_t nxp_etsec_phy_read(uint8_t reg);

/* Non-zero when the link is up (always 1 for a fixed link). */
uint32_t nxp_etsec_link_up(void);

/* Optional debug log hook (NULL = disabled). */
void nxp_etsec_set_log(void (*log_fn)(const char *msg));

#endif /* WOLFIP_NXP_ETSEC_H */

/* nxp_fman.h
 *
 * NXP QorIQ FMan (Frame Manager) ethernet MAC/PHY driver for wolfIP.
 * Targets the multirate Ethernet MAC (mEMAC) and dedicated MDIO found on
 * T-series QorIQ parts (T2080, T1024, T1040). Big-endian PowerPC e5500/e6500.
 *
 * The FMan firmware (microcode) is uploaded by the boot stage (wolfBoot
 * hal_fman_init); this driver brings up a single mEMAC in polled
 * independent (BMI direct) mode and exposes wolfIP poll/send callbacks.
 *
 * Board parameters (CCSRBAR, mEMAC index, PHY address, interface mode)
 * live in nxp_fman_board.h and are overridable from CFLAGS.
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
#ifndef WOLFIP_NXP_FMAN_H
#define WOLFIP_NXP_FMAN_H

#include <stdint.h>
#include "wolfip.h"
#include "nxp_fman_board.h"

/* ---- FMan CCSR block layout (offsets from CCSRBAR) ------------------- */

#define FMAN_BASE               (NXP_FMAN_CCSRBAR + 0x400000UL)
#define FMAN_MURAM_BASE         (FMAN_BASE)

/* ---- mEMAC (multirate Ethernet MAC) ---------------------------------- */
/* mEMAC(n) base: n is 1-based. mEMAC1=0xE0000, step 0x2000. */
#define FMAN_MEMAC_BASE(n)      (FMAN_BASE + 0xE0000UL + ((((n) - 1) & 0x3U) * 0x2000UL))
#define FMAN_MEMAC_CMD_CFG(n)   (FMAN_MEMAC_BASE(n) + 0x008UL)
#define FMAN_MEMAC_MAC_ADDR_0(n) (FMAN_MEMAC_BASE(n) + 0x00CUL)
#define FMAN_MEMAC_MAC_ADDR_1(n) (FMAN_MEMAC_BASE(n) + 0x010UL)
#define FMAN_MEMAC_MAXFRMG(n)   (FMAN_MEMAC_BASE(n) + 0x014UL)
#define FMAN_MEMAC_HTBLE_CTRL(n) (FMAN_MEMAC_BASE(n) + 0x02CUL)
#define FMAN_MEMAC_IEVENT(n)    (FMAN_MEMAC_BASE(n) + 0x040UL)
#define FMAN_MEMAC_IMASK(n)     (FMAN_MEMAC_BASE(n) + 0x04CUL)
#define FMAN_MEMAC_IF_MODE(n)   (FMAN_MEMAC_BASE(n) + 0x300UL)
#define FMAN_MEMAC_IF_STATUS(n) (FMAN_MEMAC_BASE(n) + 0x304UL)

/* CMD_CFG bits */
#define MEMAC_CMD_CFG_RX_EN     0x00000002UL
#define MEMAC_CMD_CFG_TX_EN     0x00000001UL
#define MEMAC_CMD_CFG_NO_LEN_CHK 0x00020000UL

/* IF_MODE bits */
#define IF_MODE_MASK            0x00000003UL
#define IF_MODE_XGMII           0x00000000UL
#define IF_MODE_GMII            0x00000002UL
#define IF_MODE_RG              0x00000004UL
#define IF_MODE_RM              0x00000008UL
#define IF_MODE_EN_AUTO         0x00008000UL
#define IF_MODE_SETSP_10M       0x00002000UL
#define IF_MODE_SETSP_1000M     0x00004000UL
#define IF_MODE_SETSP_MASK      0x00006000UL

/* ---- Dedicated MDIO controller --------------------------------------- */
/* 1G MDIO at FMAN_BASE + 0xFC000; EMI index n is 1-based, step 0x1000. */
#define FMAN_MDIO_BASE(n)       (FMAN_BASE + 0xFC000UL + ((((n) - 1) & 0x1U) * 0x1000UL))
#define FMAN_MDIO_STAT(n)       (FMAN_MDIO_BASE(n) + 0x030UL) /* config/status */
#define FMAN_MDIO_CTRL(n)       (FMAN_MDIO_BASE(n) + 0x034UL)
#define FMAN_MDIO_DATA(n)       (FMAN_MDIO_BASE(n) + 0x038UL)
#define FMAN_MDIO_ADDR(n)       (FMAN_MDIO_BASE(n) + 0x03CUL)

/* MDIO_STAT (config) bits */
#define MDIO_STAT_CLKDIV(x)     (((((uint32_t)(x)) >> 1) & 0xFFU) << 8)
#define MDIO_STAT_BSY           (1UL << 0)
#define MDIO_STAT_RD_ER         (1UL << 1)
#define MDIO_STAT_PRE           (1UL << 5)
#define MDIO_STAT_EN_C45        (1UL << 6) /* clause 45 enable */
#define MDIO_STAT_NEG           (1UL << 23)

/* MDIO_CTRL bits */
#define MDIO_CTL_DEV_ADDR(x)    (((uint32_t)(x)) & 0x1FU)
#define MDIO_CTL_PORT_ADDR(x)   ((((uint32_t)(x)) & 0x1FU) << 5)
#define MDIO_CTL_READ           (1UL << 15)

#define MDIO_ADDR_VAL(x)        (((uint32_t)(x)) & 0xFFFFU)
#define MDIO_DATA_VAL(x)        (((uint32_t)(x)) & 0xFFFFU)
#define MDIO_DATA_BSY           (1UL << 31)

/* ---- FMan common blocks (offsets from FMAN_BASE) --------------------- */
#define FMAN_BMI_COMMON         (FMAN_BASE + 0x80000UL)
#define FMAN_QMI_COMMON         (FMAN_BASE + 0x80400UL)
#define FMAN_DMA                (FMAN_BASE + 0xC2000UL)
#define FMAN_FPM                (FMAN_BASE + 0xC3000UL)
#define FMAN_IRAM               (FMAN_BASE + 0xC4000UL)

/* BMI per-port register block. port[pid-1] sits at +0x80000 + pid*0x1000. */
#define FMAN_BMI_PORT(pid)      (FMAN_BASE + 0x80000UL + ((uint32_t)(pid) * 0x1000UL))
/* RX/TX BMI port-id bases for 1G mEMAC n (1-based). */
#define FMAN_RX_PORT_ID(n)      (0x08U + ((n) - 1U))
#define FMAN_TX_PORT_ID(n)      (0x28U + ((n) - 1U))

/* Internal per-mEMAC MDIO (SGMII PCS), one 4KB block above each mEMAC. */
#define FMAN_MEMAC_MDIO_BASE(n) (FMAN_MEMAC_BASE(n) + 0x1000UL)

/* ---- IRAM (microcode) ------------------------------------------------ */
#define FMAN_IRAM_IADD          (FMAN_IRAM + 0x000UL)
#define FMAN_IRAM_IDATA         (FMAN_IRAM + 0x004UL)
#define FMAN_IRAM_IREADY        (FMAN_IRAM + 0x00CUL)
#define IRAM_READY              0x80000000UL

/* ---- FPM (frame processing manager) registers ------------------------ */
#define FMAN_FPM_FPMPRC         (FMAN_FPM + 0x004UL) /* port-id control */
#define FMAN_FPM_FPMFLC         (FMAN_FPM + 0x00CUL) /* flush control */
#define FMAN_FPM_FMFPEE         (FMAN_FPM + 0x0DCUL) /* event and enable */
#define FMAN_FPM_FPMRCR         (FMAN_FPM + 0x070UL) /* rams control/event */
#define FMAN_FPM_FPMCEV(i)      (FMAN_FPM + 0x0E0UL + ((i) * 4UL)) /* CPU event */

#define FMFPPRC_PORTID_SHIFT    24
#define FMFPPRC_ORA_SHIFT       16
#define FMFPPRC_RISC1           0x00000001UL
#define FMFPPRC_RISC2           0x00000002UL
#define FMFP_FLC_DISP_LIM_NONE  0x00000000UL
#define FMFPEE_EHM              0x00000008UL
#define FMFPEE_UEC              0x00000004UL
#define FMFPEE_CER              0x00000002UL
#define FMFPEE_DER              0x00000001UL
#define FMFPEE_RFM              0x00010000UL
#define FMFPEE_DECC             0x80000000UL
#define FMFPEE_STL              0x40000000UL
#define FMFPEE_SECC             0x20000000UL
#define FMFPEE_CLEAR_EVENT      (FMFPEE_DECC | FMFPEE_STL | FMFPEE_SECC | \
                                 FMFPEE_EHM | FMFPEE_UEC | FMFPEE_CER | \
                                 FMFPEE_DER | FMFPEE_RFM)
#define FMFP_RCR_MDEC           0x00008000UL
#define FMFP_RCR_IDEC           0x00004000UL

/* ---- QMI common registers -------------------------------------------- */
#define FMAN_QMI_FMQM_GC        (FMAN_QMI_COMMON + 0x000UL)
#define FMAN_QMI_FMQM_EIE       (FMAN_QMI_COMMON + 0x008UL)
#define FMAN_QMI_FMQM_EIEN      (FMAN_QMI_COMMON + 0x00CUL)
#define FMAN_QMI_FMQM_IE        (FMAN_QMI_COMMON + 0x014UL)
#define FMAN_QMI_FMQM_IEN       (FMAN_QMI_COMMON + 0x018UL)
#define FMQM_GC_ENQ_EN          0x80000000UL
#define FMQM_GC_DEQ_EN          0x40000000UL
#define FMQM_EIE_CLEAR_ALL      0xC0000000UL
#define FMQM_IE_CLEAR_ALL       0x80000000UL

/* ---- DMA registers --------------------------------------------------- */
#define FMAN_DMA_FMDMSR         (FMAN_DMA + 0x000UL)
#define FMAN_DMA_FMDMMR         (FMAN_DMA + 0x004UL)
#define FMDMSR_CLEAR_ALL        0x0FF80000UL /* all ECC/bus err status bits */
#define FMDMMR_SBER             0x10000000UL

/* ---- BMI common registers -------------------------------------------- */
#define FMAN_BMI_FMBM_INIT      (FMAN_BMI_COMMON + 0x000UL)
#define FMAN_BMI_FMBM_CFG1      (FMAN_BMI_COMMON + 0x004UL)
#define FMAN_BMI_FMBM_IEVR      (FMAN_BMI_COMMON + 0x020UL)
#define FMAN_BMI_FMBM_IER       (FMAN_BMI_COMMON + 0x024UL)
#define FMAN_BMI_FMBM_PP(pid)   (FMAN_BMI_COMMON + 0x100UL + ((pid) * 4UL))
#define FMAN_BMI_FMBM_PFS(pid)  (FMAN_BMI_COMMON + 0x200UL + ((pid) * 4UL))
#define FMBM_INIT_START         0x80000000UL
#define FMBM_CFG1_FBPS_SHIFT    16
#define FMBM_IER_DISABLE_ALL    0x00000000UL
#define FMBM_IEVR_CLEAR_ALL     0xE0000000UL
#define FMBM_PP_MXT(x)          ((((uint32_t)(x) - 1U) << 24) & 0x3F000000UL)
#define FMBM_PFS_IFSZ(x)        ((uint32_t)(x) & 0x000003FFUL)

#define FM_MURAM_RES_SIZE       0x1000UL
#define FM_FREE_POOL_SIZE       0x20000UL
#define FM_FREE_POOL_ALIGN      256UL
/* Usable MURAM cap for the bump allocator. Held below the smallest QorIQ
 * FMan MURAM (T2080 is 384KB, T1024/T1040 smaller) so the same value is
 * safe on every supported part. */
#define FM_MURAM_TOTAL          0x28000UL

/* ---- BMI RX port registers (offsets within FMAN_BMI_PORT) ------------ */
#define BMI_RX_RCFG             0x000UL
#define BMI_RX_RST              0x004UL
#define BMI_RX_RIM              0x018UL
#define BMI_RX_RFNE             0x020UL
#define BMI_RX_RFCA             0x024UL
#define BMI_RX_RFQID            0x060UL
#define BMI_RX_RSTC             0x200UL
#define BMI_RX_RPC              0x280UL
#define FMBM_RCFG_EN            0x80000000UL
#define FMBM_RCFG_IM            0x01000000UL
#define FMBM_RST_BSY            0x80000000UL
#define FMBM_RFCA_ORDER         0x80000000UL
#define FMBM_RFCA_MR_MASK       0x003F0000UL
#define FMBM_RFCA_MR(x)         (((uint32_t)(x) << 16) & FMBM_RFCA_MR_MASK)
#define FMBM_RSTC_EN            0x80000000UL

/* ---- BMI TX port registers ------------------------------------------- */
#define BMI_TX_TCFG             0x000UL
#define BMI_TX_TST              0x004UL
#define BMI_TX_TFNE             0x018UL
#define BMI_TX_TFCA             0x01CUL
#define BMI_TX_TCFQID           0x020UL
#define BMI_TX_TFENE            0x028UL
#define BMI_TX_TSTC             0x200UL
#define BMI_TX_TPC              0x280UL
#define FMBM_TCFG_EN            0x80000000UL
#define FMBM_TCFG_IM            0x01000000UL
#define FMBM_TST_BSY            0x80000000UL
#define FMBM_TFCA_ORDER         0x80000000UL
#define FMBM_TFCA_MR_MASK       0x003F0000UL
#define FMBM_TFCA_MR(x)         (((uint32_t)(x) << 16) & FMBM_TFCA_MR_MASK)
#define FMBM_TSTC_EN            0x80000000UL

/* Next-invoked-action (RISC engine, IM action codes) */
#define NIA_ENG_RISC            0x00000000UL
#define NIA_RISC_AC_IM_TX       0x00000008UL
#define NIA_RISC_AC_IM_RX       0x0000000AUL

/* ---- mEMAC additional bits ------------------------------------------- */
#define MEMAC_CMD_CFG_RXTX_EN   (MEMAC_CMD_CFG_RX_EN | MEMAC_CMD_CFG_TX_EN)
#define MEMAC_MAXFRM_MASK       0x0000FFFFUL
#define IMASK_MASK_ALL          0x00000000UL
#define IEVENT_CLEAR_ALL        0xFFFFFFFFUL

/* SGMII PCS (TBI) auto-negotiation register values */
#define PHY_SGMII_CR_DEF_VAL        0x1140U
#define PHY_SGMII_CR_RESET_AN       0x0200U
#define PHY_SGMII_DEV_ABILITY_SGMII 0x4001U
#define PHY_SGMII_IF_MODE_AN        0x0002U
#define PHY_SGMII_IF_MODE_SGMII     0x0001U

/* ---- Buffer descriptor / queue descriptor (big-endian) --------------- */
/* BD status bits */
#define RxBD_EMPTY              0x8000U
#define RxBD_LAST               0x0800U
#define RxBD_PHYS_ERR           0x0008U
#define RxBD_SIZE_ERR           0x0004U
#define RxBD_ERROR              (RxBD_PHYS_ERR | RxBD_SIZE_ERR)
#define TxBD_READY              0x8000U
#define TxBD_LAST               0x0800U

/* PRAM */
#define PRAM_MODE_GLOBAL        0x20000000UL
#define PRAM_MODE_GRACEFUL_STOP 0x00800000UL
#define FM_PRAM_SIZE            256UL  /* sizeof(global pram), 256-aligned */
#define FM_PRAM_ALIGN           256UL
#define RX_BD_RING_SIZE         8U
#define TX_BD_RING_SIZE         8U
#define MAX_RXBUF_LOG2          11U
#define MAX_RXBUF_LEN           (1U << MAX_RXBUF_LOG2) /* 2048 */
/* TX buffers are sized the same as RX; named separately so the TX pool and
 * the eth_send() length bound do not depend on an RX-named constant. */
#define MAX_TXBUF_LEN           MAX_RXBUF_LEN

/* QD field offsets within a PRAM (rxqd @ +0x20, txqd @ +0x40). */
#define PRAM_OFF_MODE           0x00UL
#define PRAM_OFF_RXQD_PTR       0x04UL
#define PRAM_OFF_TXQD_PTR       0x08UL
#define PRAM_OFF_MRBLR          0x0CUL /* u16 */
#define PRAM_OFF_RXQD           0x20UL
#define PRAM_OFF_TXQD           0x40UL
/* fm_port_qd field offsets */
#define QD_OFF_GEN              0x00UL /* u16 */
#define QD_OFF_BD_BASE_HI       0x02UL /* u16 */
#define QD_OFF_BD_BASE_LO       0x04UL /* u32 */
#define QD_OFF_BD_RING_SIZE     0x08UL /* u16 */
#define QD_OFF_OFFSET_IN        0x0AUL /* u16 */
#define QD_OFF_OFFSET_OUT       0x0CUL /* u16 */

/* ---- Public API ------------------------------------------------------ */

/* Initialize the mEMAC/MDIO, detect the PHY, and populate ll with the
 * MAC address, interface name and poll/send callbacks. Pass mac=NULL to
 * use the built-in default address. Returns a status word encoding the
 * detected PHY id high byte, link bit and PHY address (see nxp_fman.c);
 * 0 if no PHY is detected (datapath up, link down, nxp_fman_phy_addr()
 * returns -1); or a negative value on hard failure. */
int nxp_fman_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);

/* Detected PHY MDIO address, or -1 if the bus scan failed. */
int nxp_fman_phy_addr(void);

/* MDIO clause-22 read of the detected PHY (0xFFFF if no PHY / bus error). */
uint16_t nxp_fman_phy_read(uint8_t reg);

/* MDIO clause-22 read of an explicit address (bus scan / diagnostics). */
uint16_t nxp_fman_phy_read_at(uint8_t addr, uint8_t reg);

/* Non-zero when the PHY reports link up. */
uint32_t nxp_fman_link_up(void);

/* Optional debug log hook: the driver calls it at bring-up phase
 * boundaries. Pass NULL (default) to disable. */
void nxp_fman_set_log(void (*log_fn)(const char *msg));

#endif /* WOLFIP_NXP_FMAN_H */

/* nxp_qe_uec.h
 *
 * NXP QUICC Engine (QE) UCC ethernet (UEC-GETH) driver for wolfIP.
 * Targets the QE UCC fast controller on big-endian PowerPC parts that carry
 * a QUICC Engine (e.g. P1021/P1025, e500v2). The QE microcode is uploaded
 * by the boot stage (wolfBoot hal_qe_init); this driver brings up one UCC in
 * polled mode and exposes the wolfIP poll/send callbacks.
 *
 * Board parameters (CCSRBAR, UCC index, PHY address, interface mode) live
 * in nxp_qe_uec_board.h and are overridable from CFLAGS.
 *
 * NOTE: the stock P1021RDB routes its copper through eTSEC (see the nxp_etsec
 * port), not the QE UCC. Use this port for boards with custom UCC-to-PHY
 * wiring (or P1025-style RMII).
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
#ifndef WOLFIP_NXP_QE_UEC_H
#define WOLFIP_NXP_QE_UEC_H

#include <stdint.h>
#include "wolfip.h"
#include "nxp_qe_uec_board.h"

/* ---- QE engine block (QE_IMMR) -------------------------------------- */
#define QE_IMMR                 (NXP_QE_CCSRBAR + NXP_QE_IMMR_OFFSET)

/* I-RAM (microcode) - uploaded by wolfBoot; we only confirm ready. */
#define QE_IRAM_IADD            (QE_IMMR + 0x000UL)
#define QE_IRAM_IDATA           (QE_IMMR + 0x004UL)
#define QE_IRAM_IREADY          (QE_IMMR + 0x00CUL)
#define QE_IRAM_READY           0x80000000UL

/* Command processor (CP). */
#define QE_CECR                 (QE_IMMR + 0x100UL)
#define QE_CECDR                (QE_IMMR + 0x108UL)
#define QE_CR_FLG               0x00010000UL
#define QE_CR_PROTOCOL_SHIFT    6
#define QE_CR_PROTOCOL_ETHERNET 0x0CUL
#define QE_CR_ASSIGN_PAGE_SNUM_SHIFT 17
/* Commands. */
#define QE_RESET                0x80000000UL
#define QE_INIT_TX_RX           0x00000000UL
#define QE_ASSIGN_PAGE          0x00000012UL
#define QE_RESTART_TX           0x00000006UL
#define QE_RESTART_RX           0x0000001BUL
/* Sub-block code for UCC fast n (ucc_num is 0-based: UCC1 -> 0). */
#define QE_CR_SUBBLOCK_UCCFAST(ucc) (0x02000000UL + (uint32_t)(ucc) * 0x00200000UL)

/* QE multiplexing (clock routing). */
#define QE_CMXGCR               (QE_IMMR + 0x140UL)
#define QE_CMXGCR_MII_ENET_MNG_MASK  0x00007000UL
#define QE_CMXGCR_MII_ENET_MNG_SHIFT 12
/* CMXUCR1 holds UCC1+UCC3, CMXUCR2 holds UCC5+UCC7, etc. */
#define QE_CMXUCR1              (QE_IMMR + 0x150UL)
#define QE_CMXUCR2              (QE_IMMR + 0x154UL)
#define QE_CMXUCR3              (QE_IMMR + 0x158UL)
#define QE_CMXUCR4              (QE_IMMR + 0x15CUL)

/* MURAM. */
#define QE_MURAM_BASE           (QE_IMMR + 0x10000UL)
#define QE_MURAM_SIZE           0x6000UL   /* P1021: 24KB */
#define QE_MURAM_RES            0x800UL    /* wolfBoot SDMA scratch at off 0 */

/* ---- UCC fast register block ---------------------------------------- */
/* UCC base for ucc_num (0-based): odd index -> 0x3000 page, even -> 0x2000. */
#define QE_UCC_BASE(ucc) (QE_IMMR + (((ucc) & 1U) ? 0x3000UL : 0x2000UL) + \
                          ((uint32_t)((ucc) >> 1) * 0x200UL))

#define UCCF_GUMR               0x00UL
#define UCCF_UPSMR              0x04UL
#define UCCF_UTODR              0x08UL     /* u16 */
#define UCCF_UCCE               0x10UL
#define UCCF_UCCM               0x14UL
#define UCCF_URFB               0x20UL
#define UCCF_URFS               0x24UL     /* u16 */
#define UCCF_URFET              0x28UL     /* u16 */
#define UCCF_URFSET             0x2AUL     /* u16 */
#define UCCF_UTFB               0x2CUL
#define UCCF_UTFS               0x30UL     /* u16 */
#define UCCF_UTFET              0x34UL     /* u16 */
#define UCCF_UTFTT              0x38UL     /* u16 */
#define UCCF_GUEMR              0x90UL     /* u8 */

#define UCC_GUEMR_INIT          0x13U      /* RESERVED3|FAST_RX|FAST_TX */
#define UCC_GUMR_ETH            0x0000000CUL
#define UCC_GUMR_ENR            0x00000020UL
#define UCC_GUMR_ENT            0x00000010UL
#define UCC_FAST_TOD            0x8000U

/* ---- UEC MAC register block (UCC base + 0x100) ---------------------- */
#define UEC_MAC_OFFSET          0x100UL
#define UEC_MACCFG1             0x00UL
#define UEC_MACCFG2             0x04UL
#define UEC_IPGIFG              0x08UL
#define UEC_HAFDUP              0x0CUL
#define UEC_MIIMCFG             0x20UL
#define UEC_MIIMCOM             0x24UL
#define UEC_MIIMADD             0x28UL
#define UEC_MIIMCON             0x2CUL
#define UEC_MIIMSTAT            0x30UL
#define UEC_MIIMIND             0x34UL
#define UEC_MACSTNADDR1         0x40UL
#define UEC_MACSTNADDR2         0x44UL
#define UEC_UTBIPAR            0x54UL

#define MACCFG1_ENABLE_RX       0x00000004UL
#define MACCFG1_ENABLE_TX       0x00000001UL
#define MACCFG2_INIT_VALUE      0x00007035UL  /* PREL|RES1|LC|PAD_CRC|FDX */
#define MACCFG2_FDX             0x00000001UL
#define MACCFG2_NIBBLE          0x00000100UL  /* 10/100 */
#define MACCFG2_BYTE            0x00000200UL  /* 1000 */
#define MACCFG2_IF_MODE_MASK    0x00000300UL
#define UPSMR_INIT_VALUE        0x02002000UL  /* HSE|RES1 */
#define UPSMR_RPM               0x00080000UL  /* RGMII */
#define UPSMR_R10M              0x00040000UL
#define UPSMR_TBIM              0x00010000UL
#define UPSMR_RMM               0x00001000UL  /* RMII */
#define UPSMR_SGMM              0x00000020UL  /* SGMII */

/* MII management bits. */
#define MIIMCFG_RESET_MGMT      0x80000000UL
#define MIIMCFG_CLK_DIV10       0x00000004UL
#define MIIMCOM_READ_CYCLE      0x00000001UL
#define MIIMADD_PHY_SHIFT       8
#define MIIMIND_BUSY            0x00000001UL
#define MIIMIND_NOTVALID        0x00000004UL

/* ---- Buffer descriptor (big-endian, 8 bytes) ------------------------ */
struct qe_bd {
    volatile uint16_t status;
    volatile uint16_t len;
    volatile uint32_t data;
};
#define QE_SIZEOFBD             8U

#define BD_WRAP                 0x2000U
#define BD_INT                  0x1000U
#define BD_LAST                 0x0800U
#define BD_CLEAN                0x3000U     /* keep WRAP|INT on recycle */
#define TxBD_READY              0x8000U
#define TxBD_PADCRC             0x4000U
#define TxBD_TXCRC              0x0400U
#define RxBD_EMPTY              0x8000U
#define RxBD_FIRST              0x0400U
#define RxBD_ERROR              0x003EU     /* LG|NO|SHORT|CRC|OVERRUN */

/* ---- Param RAM field offsets (in MURAM) ----------------------------- */
/* TX global param RAM (0x80 bytes, align 64). */
#define TXG_TEMODER             0x00UL  /* u16 */
#define TXG_SQPTR               0x38UL  /* u32 */
#define TXG_TSTATE              0x44UL  /* u32 */
#define TXG_TQPTR               0x70UL  /* u32 */
#define TXG_SIZE                0x80UL
#define TEMODER_INIT_VALUE      0xC000U
#define UEC_TSTATE_INIT         0x30000000UL  /* BMR_INIT (0x30) << 24 */
/* send-queue QD (align 32); entry 0 used. */
#define SQQD_BD_RING_BASE       0x00UL  /* u32 = TBASE */
#define SQQD_LAST_BD            0x0CUL  /* u32 */
#define SQQD_SIZE               0x40UL

/* RX global param RAM (0x100 bytes, align 64). */
#define RXG_REMODER             0x00UL  /* u32 */
#define RXG_RQPTR               0x04UL  /* u32 */
#define RXG_TYPEORLEN           0x20UL  /* u16 */
#define RXG_RSTATE              0x36UL  /* u8 */
#define RXG_MRBLR               0x46UL  /* u16 */
#define RXG_RBDQPTR             0x48UL  /* u32 */
#define RXG_MFLR                0x4CUL  /* u16 */
#define RXG_MINFLR              0x4EUL  /* u16 */
#define RXG_MAXD1               0x50UL  /* u16 */
#define RXG_MAXD2               0x52UL  /* u16 */
#define RXG_VLANTYPE            0x7CUL  /* u16 */
#define RXG_SIZE                0x100UL
#define UEC_RSTATE_INIT         0x30U   /* BMR_INIT byte */
/* RX-BD-queue entry (align 8). */
#define RBDQ_EXT_BD_BASE        0x08UL  /* u32 = RBASE */
#define RBDQ_SIZE               0x40UL

/* init-enet command block (align 4). */
#define INIT_RES0               0x00UL  /* u8 x4: 0x06,0x30,0xff,0x00 */
#define INIT_RES4               0x04UL  /* u16: 0x0400 */
#define INIT_RGF_TGF_RXG        0x08UL  /* u32 */
#define INIT_RXTHREAD           0x0CUL  /* u32 x (num_rx+1) */
#define INIT_TXGLOBAL           0x38UL  /* u32 */
#define INIT_TXTHREAD           0x3CUL  /* u32 x num_tx */
#define INIT_SIZE               0x60UL
#define ENET_INIT_RGF_SHIFT     28
#define ENET_INIT_TGF_SHIFT     24
#define ENET_INIT_SNUM_SHIFT    24
#define QE_RISC_RISC1           0x00000001UL

/* thread param sizes/alignments. */
#define UEC_THREAD_RX_PRAM_SIZE 128UL
#define UEC_THREAD_TX_PRAM_SIZE 64UL
#define UEC_THREAD_DATA_RX_SIZE 40UL
#define UEC_THREAD_DATA_TX_SIZE 136UL

/* ---- Ring / buffer sizing ------------------------------------------- */
#define QE_RX_RING_SIZE         8U     /* multiple of 4, min 8 */
#define QE_TX_RING_SIZE         8U     /* min 2 */
#define QE_MRBLR                1536U  /* multiple of 128 */
#define QE_MAX_FRAME_LEN        1518U
#define QE_BD_RING_ALIGN        32U
#define QE_BUF_ALIGN            64U
#define QE_POLL_TRIES           1000000U

/* ---- Public API ------------------------------------------------------ */

/* Bring up one UCC (param RAM, BD rings, MAC, PHY) and populate ll with the
 * MAC address, interface name and poll/send callbacks. Pass mac=NULL to use
 * the built-in default. Returns a status word encoding the detected PHY id
 * high byte, link bit and PHY address; 0 if no PHY is detected (datapath
 * up, link down, nxp_qe_uec_phy_addr() returns -1); or a negative value
 * on failure. */
int nxp_qe_uec_init(struct wolfIP_ll_dev *ll, const uint8_t *mac);

/* Detected PHY MDIO address, or -1 if the bus scan failed. */
int nxp_qe_uec_phy_addr(void);

/* MDIO clause-22 read of the detected PHY (0xFFFF on error / no PHY). */
uint16_t nxp_qe_uec_phy_read(uint8_t reg);

/* Non-zero when the PHY reports link up. */
uint32_t nxp_qe_uec_link_up(void);

/* Optional debug log hook (NULL = disabled). */
void nxp_qe_uec_set_log(void (*log_fn)(const char *msg));

#endif /* WOLFIP_NXP_QE_UEC_H */

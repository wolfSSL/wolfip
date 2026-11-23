/* nxp_mcxe_emac_regs.h
 *
 * Register definitions used by the NXP MCX E EMAC ethernet driver: the EMAC
 * (Synopsys Ethernet QoS) MAC, MTL and DMA, clock gating (MC_ME), the EMAC
 * clock muxes (MC_CGM), the RMII select (DCM_GPR), pin muxing (SIUL2) and
 * the Cortex-M7 NVIC, SCB and DWT. Offsets and bits are from the MCX E3
 * Reference Manual (MCXEP172M160FB0RM, Rev. 5), which covers the MCX E31B,
 * E327 and E32B that have the EMAC; the pin and input mux numbers are those
 * of the MCX E31B (its IOMUX attachment).
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
#ifndef WOLFIP_NXP_MCXE_EMAC_REGS_H
#define WOLFIP_NXP_MCXE_EMAC_REGS_H

#include <stdint.h>

#define EMAC_REG32(addr)        (*(volatile uint32_t *)(addr))
#define EMAC_REG8(addr)         (*(volatile uint8_t *)(addr))

/* EMAC: MAC */
#define EMAC_BASE               0x40480000UL
#define EMAC_MAC_CONFIG         EMAC_REG32(EMAC_BASE + 0x0000UL)
#define EMAC_MAC_PKT_FILTER     EMAC_REG32(EMAC_BASE + 0x0008UL)
#define EMAC_MAC_RXQ_CTRL0      EMAC_REG32(EMAC_BASE + 0x00A0UL)
#define EMAC_MAC_INT_ENABLE     EMAC_REG32(EMAC_BASE + 0x00B4UL)
#define EMAC_MAC_HW_FEATURE1    EMAC_REG32(EMAC_BASE + 0x0120UL)
#define EMAC_MAC_MDIO_ADDR      EMAC_REG32(EMAC_BASE + 0x0200UL)
#define EMAC_MAC_MDIO_DATA      EMAC_REG32(EMAC_BASE + 0x0204UL)
#define EMAC_MAC_ADDR0_HIGH     EMAC_REG32(EMAC_BASE + 0x0300UL)
#define EMAC_MAC_ADDR0_LOW      EMAC_REG32(EMAC_BASE + 0x0304UL)

#define EMAC_MAC_CONFIG_RE      (1UL << 0)
#define EMAC_MAC_CONFIG_TE      (1UL << 1)
#define EMAC_MAC_CONFIG_DM      (1UL << 13)     /* full duplex */
#define EMAC_MAC_CONFIG_FES     (1UL << 14)     /* 100 Mbit/s */
#define EMAC_MAC_CONFIG_PS      (1UL << 15)     /* MII/RMII port */
#define EMAC_MAC_CONFIG_ACS     (1UL << 20)     /* strip pad and FCS */
#define EMAC_MAC_CONFIG_CST     (1UL << 21)     /* strip FCS, all types */

#define EMAC_MAC_PKT_FILTER_PM  (1UL << 4)      /* pass all multicast */

#define EMAC_MAC_RXQ_CTRL0_RXQ0EN_DCB   (2UL << 0)

/* Transmit and receive FIFO sizes: 128 << n bytes */
#define EMAC_HW_FEATURE1_RXFIFOSIZE(r)  ((r) & 0x1FUL)
#define EMAC_HW_FEATURE1_TXFIFOSIZE(r)  (((r) >> 6) & 0x1FUL)

#define EMAC_MDIO_ADDR_GB       (1UL << 0)      /* busy */
#define EMAC_MDIO_ADDR_GOC_WRITE (1UL << 2)
#define EMAC_MDIO_ADDR_GOC_READ (3UL << 2)
#define EMAC_MDIO_ADDR_CR(x)    (((uint32_t)(x) & 0xFUL) << 8)
#define EMAC_MDIO_ADDR_CR_MASK  (0xFUL << 8)
#define EMAC_MDIO_ADDR_RDA(x)   (((uint32_t)(x) & 0x1FUL) << 16)
#define EMAC_MDIO_ADDR_PA(x)    (((uint32_t)(x) & 0x1FUL) << 21)
#define EMAC_MDIO_DATA_GD_MASK  0xFFFFUL

#define EMAC_MAC_ADDR_HIGH_AE   (1UL << 31)

/* EMAC: MMC counters */
#define EMAC_MMC_RX_INT_MASK    EMAC_REG32(EMAC_BASE + 0x070CUL)
#define EMAC_MMC_TX_INT_MASK    EMAC_REG32(EMAC_BASE + 0x0710UL)
#define EMAC_MMC_FPE_TX_INT_MASK EMAC_REG32(EMAC_BASE + 0x08A4UL)
#define EMAC_MMC_FPE_RX_INT_MASK EMAC_REG32(EMAC_BASE + 0x08C4UL)
#define EMAC_RX_CRC_ERRORS      EMAC_REG32(EMAC_BASE + 0x0794UL)
#define EMAC_RX_FIFO_OVERFLOWS  EMAC_REG32(EMAC_BASE + 0x07D4UL)

/* EMAC: MTL queue 0 */
#define EMAC_MTL_TXQ0_OP_MODE   EMAC_REG32(EMAC_BASE + 0x0D00UL)
#define EMAC_MTL_RXQ0_OP_MODE   EMAC_REG32(EMAC_BASE + 0x0D30UL)

#define EMAC_MTL_TXQ_OP_FTQ     (1UL << 0)      /* flush */
#define EMAC_MTL_TXQ_OP_TSF     (1UL << 1)      /* store and forward */
#define EMAC_MTL_TXQ_OP_TXQEN   (2UL << 2)      /* enabled */
#define EMAC_MTL_TXQ_OP_TQS(x)  (((uint32_t)(x) & 0x1FUL) << 16)
#define EMAC_MTL_RXQ_OP_RSF     (1UL << 5)      /* store and forward */
#define EMAC_MTL_RXQ_OP_RQS(x)  (((uint32_t)(x) & 0x1FUL) << 20)

/* EMAC: DMA and DMA channel 0 */
#define EMAC_DMA_MODE           EMAC_REG32(EMAC_BASE + 0x1000UL)
#define EMAC_DMA_SYSBUS_MODE    EMAC_REG32(EMAC_BASE + 0x1004UL)
#define EMAC_DMA_CH0_CTRL       EMAC_REG32(EMAC_BASE + 0x1100UL)
#define EMAC_DMA_CH0_TX_CTRL    EMAC_REG32(EMAC_BASE + 0x1104UL)
#define EMAC_DMA_CH0_RX_CTRL    EMAC_REG32(EMAC_BASE + 0x1108UL)
#define EMAC_DMA_CH0_TXDESC_LIST EMAC_REG32(EMAC_BASE + 0x1114UL)
#define EMAC_DMA_CH0_RXDESC_LIST EMAC_REG32(EMAC_BASE + 0x111CUL)
#define EMAC_DMA_CH0_TXDESC_TAIL EMAC_REG32(EMAC_BASE + 0x1120UL)
#define EMAC_DMA_CH0_RXDESC_TAIL EMAC_REG32(EMAC_BASE + 0x1128UL)
#define EMAC_DMA_CH0_TXDESC_RLEN EMAC_REG32(EMAC_BASE + 0x112CUL)
#define EMAC_DMA_CH0_RXDESC_RLEN EMAC_REG32(EMAC_BASE + 0x1130UL)
#define EMAC_DMA_CH0_INT_EN     EMAC_REG32(EMAC_BASE + 0x1134UL)
#define EMAC_DMA_CH0_STAT       EMAC_REG32(EMAC_BASE + 0x1160UL)
#define EMAC_DMA_CH0_MISS_FRAMES EMAC_REG32(EMAC_BASE + 0x1164UL)

#define EMAC_DMA_MODE_SWR       (1UL << 0)

/* DMA_SysBus_Mode (AHB master) */
#define EMAC_DMA_SYSBUS_FB      (1UL << 0)      /* fixed bursts */
#define EMAC_DMA_SYSBUS_AAL     (1UL << 12)     /* address-aligned beats */
#define EMAC_DMA_SYSBUS_MB      (1UL << 14)     /* mixed bursts */

#define EMAC_DMA_TX_CTRL_ST     (1UL << 0)
#define EMAC_DMA_TX_CTRL_OSF    (1UL << 4)      /* operate on second frame */
#define EMAC_DMA_TX_CTRL_TXPBL(x) (((uint32_t)(x) & 0x3FUL) << 16)
#define EMAC_DMA_RX_CTRL_SR     (1UL << 0)
/* Receive buffer size, in bytes, bits 13:2 of it in bits 14:3 */
#define EMAC_DMA_RX_CTRL_RBSZ(x) ((((uint32_t)(x) >> 2) & 0xFFFUL) << 3)
#define EMAC_DMA_RX_CTRL_RXPBL(x) (((uint32_t)(x) & 0x3FUL) << 16)

/* DMA_CH0_Interrupt_Enable and DMA_CH0_Status share the bit layout; the
 * status bits are write 1 to clear. */
#define EMAC_DMA_INT_TI         (1UL << 0)      /* transmit complete */
#define EMAC_DMA_INT_RI         (1UL << 6)      /* receive complete */
#define EMAC_DMA_INT_RBU        (1UL << 7)      /* receive buffer unavailable */
#define EMAC_DMA_INT_FBE        (1UL << 12)     /* fatal bus error */
#define EMAC_DMA_INT_AI         (1UL << 14)     /* abnormal summary */
#define EMAC_DMA_INT_NI         (1UL << 15)     /* normal summary */

/* Descriptors (read format written by the driver, write-back format
 * written by the DMA). RDES3 / TDES3: */
#define EMAC_DES3_OWN           (1UL << 31)
#define EMAC_RDES3_IOC          (1UL << 30)
#define EMAC_RDES3_BUF1V        (1UL << 24)
#define EMAC_RDES3_CTXT         (1UL << 30)     /* write-back */
#define EMAC_RDES3_FD           (1UL << 29)     /* write-back */
#define EMAC_RDES3_LD           (1UL << 28)     /* write-back */
#define EMAC_RDES3_ES           (1UL << 15)     /* write-back: error summary */
#define EMAC_RDES3_PL_MASK      0x7FFFUL        /* write-back: frame length */
#define EMAC_TDES2_B1L(x)       ((uint32_t)(x) & 0x3FFFUL)
#define EMAC_TDES3_FD           (1UL << 29)
#define EMAC_TDES3_LD           (1UL << 28)
#define EMAC_TDES3_FL(x)        ((uint32_t)(x) & 0x7FFFUL)

/* EMAC interrupt: IRQ 105 is the common line (sbd_intr), which carries
 * every DMA channel event while DMA_Mode[INTM] is 0 (reset value). */
#define EMAC_IRQN               105U

/* The EMAC reaches the CM7_0 DTCM through its backdoor port */
#define EMAC_DTCM_BASE          0x20000000UL
#define EMAC_DTCM_SIZE          0x00010000UL
#define EMAC_DTCM_BACKDOOR_OFFSET 0x01000000UL

/* MC_ME: EMAC clock is partition 2, COFB set 1, request 32 (bit 0) */
#define MC_ME_BASE              0x402DC000UL
#define MC_ME_CTL_KEY           EMAC_REG32(MC_ME_BASE + 0x000UL)
#define MC_ME_PRTN2_PCONF       EMAC_REG32(MC_ME_BASE + 0x500UL)
#define MC_ME_PRTN2_PUPD        EMAC_REG32(MC_ME_BASE + 0x504UL)
#define MC_ME_PRTN2_COFB1_STAT  EMAC_REG32(MC_ME_BASE + 0x514UL)
#define MC_ME_PRTN2_COFB1_CLKEN EMAC_REG32(MC_ME_BASE + 0x534UL)
#define MC_ME_KEY               0x5AF0UL
#define MC_ME_INVKEY            0xA50FUL
#define MC_ME_PCONF_PCE         (1UL << 0)
#define MC_ME_PUPD_PCUD         (1UL << 0)
#define MC_ME_EMAC_BIT          (1UL << 0)

/* MC_CGM: system clock mux 0 and the EMAC clock muxes 7 (RX), 8 (TX) and
 * 9 (timestamp). Mux n registers are 0x40 apart. */
#define MC_CGM_BASE             0x402D8000UL
#define MC_CGM_MUX_CSC(n)       EMAC_REG32(MC_CGM_BASE + 0x300UL + 0x40UL * (n))
#define MC_CGM_MUX_CSS(n)       EMAC_REG32(MC_CGM_BASE + 0x304UL + 0x40UL * (n))
#define MC_CGM_MUX_DC(n, d)     EMAC_REG32(MC_CGM_BASE + 0x308UL + \
                                          0x40UL * (n) + 4UL * (d))
#define MC_CGM_MUX_DIV_UPD_STAT(n) EMAC_REG32(MC_CGM_BASE + 0x33CUL + \
                                             0x40UL * (n))
#define MC_CGM_MUX_EMAC_RX      7U
#define MC_CGM_MUX_EMAC_TX      8U
#define MC_CGM_MUX_EMAC_TS      9U
#define MC_CGM_CSC_SELCTL(x)    (((uint32_t)(x) & 0x1FUL) << 24)
#define MC_CGM_CSC_CLK_SW       (1UL << 2)
#define MC_CGM_CSS_CLK_SW       (1UL << 2)
#define MC_CGM_CSS_SWIP         (1UL << 16)
#define MC_CGM_CSS_SELSTAT(r)   (((r) >> 24) & 0x1FUL)
#define MC_CGM_DC_DE            (1UL << 31)
#define MC_CGM_DC_DIV(x)        (((uint32_t)(x) & 0x3FUL) << 16)
#define MC_CGM_DC_GET_DIV(r)    (((r) >> 16) & 0x3FUL)
#define MC_CGM_DIV_UPD_STAT_BUSY (1UL << 0)
#define MC_CGM_SEL_FIRC         0U
#define MC_CGM_SEL_PLL_PHI0     8U
#define MC_CGM_SEL_EMAC_RMII_TX_CLK 24U         /* RMII reference clock pin */
/* Mux 0 dividers: 0 = core clock, 1 = AIPS_PLAT_CLK (EMAC CSR clock) */
#define MC_CGM_DIV_CORE         0U
#define MC_CGM_DIV_AIPS_PLAT    1U

/* PLLDIG, to work out PLL_PHI0 */
#define PLL_BASE                0x402E0000UL
#define PLL_PLLDV               EMAC_REG32(PLL_BASE + 0x08UL)
#define PLL_PLLODIV(n)          EMAC_REG32(PLL_BASE + 0x80UL + 4UL * (n))
#define PLL_PLLDV_MFI(r)        ((r) & 0xFFUL)
#define PLL_PLLDV_RDIV(r)       (((r) >> 12) & 0x7UL)
#define PLL_PLLDV_ODIV2(r)      (((r) >> 25) & 0x3FUL)
#define PLL_PLLODIV_DIV(r)      (((r) >> 16) & 0xFUL)

/* DCM_GPR: EMAC MII/RMII select, sampled when the EMAC is reset */
#define DCM_GPR_BASE            0x402AC000UL
#define DCM_GPR_DCMRWF1         EMAC_REG32(DCM_GPR_BASE + 0x600UL)
#define DCM_GPR_DCMRWF1_MAC_CONF_SEL_MASK (3UL << 6)
#define DCM_GPR_DCMRWF1_MAC_CONF_SEL_RMII (2UL << 6)  /* 00 MII, 01 RGMII */

/* SIUL2. MSCR and GPDO are indexed by the pad number (32 * port + pin);
 * IMCR by the input mux number (the SIUL_IMCR number of the IOMUX
 * attachment less 512). GPDO bytes are big-endian within each word. */
#define SIUL2_BASE              0x40290000UL
#define SIUL2_MSCR(n)           EMAC_REG32(SIUL2_BASE + 0x240UL + 4UL * (n))
#define SIUL2_IMCR(n)           EMAC_REG32(SIUL2_BASE + 0xA40UL + 4UL * (n))
#define SIUL2_GPDO(n)           EMAC_REG8(SIUL2_BASE + 0x1300UL + \
                                         (((n) & ~3UL) | (3UL - ((n) & 3UL))))
#define SIUL2_MSCR_OBE          (1UL << 21)
#define SIUL2_MSCR_IBE          (1UL << 19)
#define SIUL2_MSCR_SRC          (1UL << 14)     /* slow slew rate */
#define SIUL2_MSCR_SSS(x)       ((uint32_t)(x) & 0xFUL)

/* Cortex-M7 NVIC, SCB and DWT */
#define NVIC_ISER(n)            EMAC_REG32(0xE000E100UL + 4UL * (uint32_t)(n))
#define NVIC_ICER(n)            EMAC_REG32(0xE000E180UL + 4UL * (uint32_t)(n))
#define NVIC_ICPR(n)            EMAC_REG32(0xE000E280UL + 4UL * (uint32_t)(n))
#define NVIC_IPR(irq)           EMAC_REG8(0xE000E400UL + (uint32_t)(irq))
#define SCB_CCR                 EMAC_REG32(0xE000ED14UL)
#define SCB_CCR_DC              (1UL << 16)
#define DEMCR                   EMAC_REG32(0xE000EDFCUL)
#define DEMCR_TRCENA            (1UL << 24)
#define DWT_CTRL                EMAC_REG32(0xE0001000UL)
#define DWT_CTRL_CYCCNTENA      (1UL << 0)
#define DWT_CYCCNT              EMAC_REG32(0xE0001004UL)
#define DWT_LAR                 EMAC_REG32(0xE0001FB0UL)
#define DWT_LAR_KEY             0xC5ACCE55UL

#endif /* WOLFIP_NXP_MCXE_EMAC_REGS_H */

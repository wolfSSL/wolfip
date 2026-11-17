/* nxp_mcxe_enet_regs.h
 *
 * Register definitions used by the NXP MCX E247 ethernet driver: ENET MAC,
 * eDMA, clock gating, pin muxing, SCG and the Cortex-M4 NVIC and DWT.
 * Offsets and bits are from the MCXE24x Reference Manual (MCXE24XRM).
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
#ifndef WOLFIP_NXP_MCXE_ENET_REGS_H
#define WOLFIP_NXP_MCXE_ENET_REGS_H

#include <stdint.h>

#define MCXE_REG32(addr)        (*(volatile uint32_t *)(addr))
#define MCXE_REG16(addr)        (*(volatile uint16_t *)(addr))
#define MCXE_REG8(addr)         (*(volatile uint8_t *)(addr))

/* ENET MAC */
#define ENET_BASE               0x40079000UL
#define ENET_EIR                MCXE_REG32(ENET_BASE + 0x004UL)
#define ENET_EIMR               MCXE_REG32(ENET_BASE + 0x008UL)
#define ENET_RDAR               MCXE_REG32(ENET_BASE + 0x010UL)
#define ENET_TDAR               MCXE_REG32(ENET_BASE + 0x014UL)
#define ENET_ECR                MCXE_REG32(ENET_BASE + 0x024UL)
#define ENET_MMFR               MCXE_REG32(ENET_BASE + 0x040UL)
#define ENET_MSCR               MCXE_REG32(ENET_BASE + 0x044UL)
#define ENET_RCR                MCXE_REG32(ENET_BASE + 0x084UL)
#define ENET_TCR                MCXE_REG32(ENET_BASE + 0x0C4UL)
#define ENET_PALR               MCXE_REG32(ENET_BASE + 0x0E4UL)
#define ENET_PAUR               MCXE_REG32(ENET_BASE + 0x0E8UL)
#define ENET_IAUR               MCXE_REG32(ENET_BASE + 0x118UL)
#define ENET_IALR               MCXE_REG32(ENET_BASE + 0x11CUL)
#define ENET_GAUR               MCXE_REG32(ENET_BASE + 0x120UL)
#define ENET_GALR               MCXE_REG32(ENET_BASE + 0x124UL)
#define ENET_TFWR               MCXE_REG32(ENET_BASE + 0x144UL)
#define ENET_RDSR               MCXE_REG32(ENET_BASE + 0x180UL)
#define ENET_TDSR               MCXE_REG32(ENET_BASE + 0x184UL)
#define ENET_MRBR               MCXE_REG32(ENET_BASE + 0x188UL)
#define ENET_RSFL               MCXE_REG32(ENET_BASE + 0x190UL)
#define ENET_TACC               MCXE_REG32(ENET_BASE + 0x1C0UL)
#define ENET_RACC               MCXE_REG32(ENET_BASE + 0x1C4UL)

#define ENET_EIR_EBERR          (1UL << 22)
#define ENET_EIR_MII            (1UL << 23)
#define ENET_EIR_RXB            (1UL << 24)
#define ENET_EIR_RXF            (1UL << 25)
#define ENET_EIR_TXB            (1UL << 26)
#define ENET_EIR_TXF            (1UL << 27)
#define ENET_EIR_ALL            0x7FFFFFFFUL

#define ENET_RDAR_RDAR          (1UL << 24)
#define ENET_TDAR_TDAR          (1UL << 24)

#define ENET_ECR_RESET          (1UL << 0)
#define ENET_ECR_ETHEREN        (1UL << 1)
#define ENET_ECR_DBSWP          (1UL << 8)  /* little-endian descriptors */

#define ENET_MMFR_ST            (1UL << 30)
#define ENET_MMFR_OP_WRITE      (1UL << 28)
#define ENET_MMFR_OP_READ       (2UL << 28)
#define ENET_MMFR_PA(x)         (((uint32_t)(x) & 0x1FUL) << 23)
#define ENET_MMFR_RA(x)         (((uint32_t)(x) & 0x1FUL) << 18)
#define ENET_MMFR_TA            (2UL << 16)
#define ENET_MMFR_DATA_MASK     0xFFFFUL

#define ENET_MSCR_MII_SPEED(x)  (((uint32_t)(x) & 0x3FUL) << 1)
#define ENET_MSCR_HOLDTIME(x)   (((uint32_t)(x) & 0x7UL) << 8)

#define ENET_RCR_DRT            (1UL << 1)
#define ENET_RCR_MII_MODE       (1UL << 2)
#define ENET_RCR_RMII_MODE      (1UL << 8)
#define ENET_RCR_RMII_10T       (1UL << 9)
#define ENET_RCR_CRCFWD         (1UL << 14) /* strip the received CRC */
#define ENET_RCR_MAX_FL(x)      (((uint32_t)(x) & 0x3FFFUL) << 16)

#define ENET_TCR_FDEN           (1UL << 2)
#define ENET_TFWR_STRFWD        (1UL << 8)

/* Legacy buffer descriptor control bits (16-bit field) */
#define ENET_RXBD_EMPTY         0x8000U
#define ENET_RXBD_WRAP          0x2000U
#define ENET_RXBD_LAST          0x0800U
#define ENET_RXBD_LG            0x0020U
#define ENET_RXBD_NO            0x0010U
#define ENET_RXBD_CR            0x0004U
#define ENET_RXBD_OV            0x0002U
#define ENET_RXBD_TR            0x0001U
#define ENET_RXBD_ERRORS        (ENET_RXBD_LG | ENET_RXBD_NO | ENET_RXBD_CR | \
                                 ENET_RXBD_OV | ENET_RXBD_TR)

#define ENET_TXBD_READY         0x8000U
#define ENET_TXBD_WRAP          0x2000U
#define ENET_TXBD_LAST          0x0800U
#define ENET_TXBD_TC            0x0400U     /* append the CRC */

/* Interrupt numbers */
#define ENET_TX_IRQN            73U
#define ENET_RX_IRQN            74U
#define ENET_ERR_IRQN           75U

/* SIM, PCC: clock gating */
#define SIM_PLATCGC             MCXE_REG32(0x40048040UL)
#define SIM_PLATCGC_CGCDMA      (1UL << 2)

#define PCC_BASE                0x40065000UL
#define PCC_PORTB               MCXE_REG32(PCC_BASE + 0x128UL)
#define PCC_PORTC               MCXE_REG32(PCC_BASE + 0x12CUL)
#define PCC_PORTD               MCXE_REG32(PCC_BASE + 0x130UL)
#define PCC_PORTE               MCXE_REG32(PCC_BASE + 0x134UL)
#define PCC_ENET                MCXE_REG32(PCC_BASE + 0x1E4UL)
#define PCC_CGC                 (1UL << 30)

/* System MPU */
#define SYSMPU_CESR             MCXE_REG32(0x4000D000UL)
#define SYSMPU_CESR_VLD         (1UL << 0)

/* PORT pin control and GPIO */
#define PORTB_BASE              0x4004A000UL
#define PORTC_BASE              0x4004B000UL
#define PORTD_BASE              0x4004C000UL
#define PORTE_BASE              0x4004D000UL
#define PORT_PCR(base, pin)     MCXE_REG32((base) + 4UL * (uint32_t)(pin))
#define PORT_PCR_MUX(x)         (((uint32_t)(x) & 0x7UL) << 8)
#define PORT_PCR_DSE            (1UL << 6)

#define GPIOB_BASE              0x400FF040UL
#define GPIOC_BASE              0x400FF080UL
#define GPIO_PSOR(base)         MCXE_REG32((base) + 0x04UL)
#define GPIO_PCOR(base)         MCXE_REG32((base) + 0x08UL)
#define GPIO_PDDR(base)         MCXE_REG32((base) + 0x14UL)

/* SCG: core clock source and dividers */
#define SCG_CSR                 MCXE_REG32(0x40064010UL)
#define SCG_SPLLCFG             MCXE_REG32(0x40064608UL)
#define SCG_CSR_SCS(v)          (((v) >> 24) & 0xFUL)
#define SCG_CSR_DIVCORE(v)      (((v) >> 16) & 0xFUL)
#define SCG_SCS_SOSC            1UL
#define SCG_SCS_SIRC            2UL
#define SCG_SCS_FIRC            3UL
#define SCG_SCS_SPLL            6UL
#define SCG_SPLLCFG_PREDIV(v)   (((v) >> 8) & 0x7UL)
#define SCG_SPLLCFG_MULT(v)     (((v) >> 16) & 0x1FUL)

/* eDMA */
#define DMA_BASE                0x40008000UL
#define DMA_CR                  MCXE_REG32(DMA_BASE + 0x000UL)
#define DMA_CR_CX               (1UL << 17)     /* cancel the running channel */
#define DMA_ES                  MCXE_REG32(DMA_BASE + 0x004UL)
#define DMA_CDNE                MCXE_REG8(DMA_BASE + 0x01CUL)
#define DMA_CERR                MCXE_REG8(DMA_BASE + 0x01EUL)
#define DMA_ERR                 MCXE_REG32(DMA_BASE + 0x02CUL)
#define DMA_TCD(ch)             (DMA_BASE + 0x1000UL + 0x20UL * (uint32_t)(ch))
#define DMA_TCD_SADDR(ch)       MCXE_REG32(DMA_TCD(ch) + 0x00UL)
#define DMA_TCD_SOFF(ch)        MCXE_REG16(DMA_TCD(ch) + 0x04UL)
#define DMA_TCD_ATTR(ch)        MCXE_REG16(DMA_TCD(ch) + 0x06UL)
#define DMA_TCD_NBYTES(ch)      MCXE_REG32(DMA_TCD(ch) + 0x08UL)
#define DMA_TCD_SLAST(ch)       MCXE_REG32(DMA_TCD(ch) + 0x0CUL)
#define DMA_TCD_DADDR(ch)       MCXE_REG32(DMA_TCD(ch) + 0x10UL)
#define DMA_TCD_DOFF(ch)        MCXE_REG16(DMA_TCD(ch) + 0x14UL)
#define DMA_TCD_CITER(ch)       MCXE_REG16(DMA_TCD(ch) + 0x16UL)
#define DMA_TCD_DLASTSGA(ch)    MCXE_REG32(DMA_TCD(ch) + 0x18UL)
#define DMA_TCD_CSR(ch)         MCXE_REG16(DMA_TCD(ch) + 0x1CUL)
#define DMA_TCD_BITER(ch)       MCXE_REG16(DMA_TCD(ch) + 0x1EUL)
#define DMA_ATTR_SSIZE(x)       ((uint16_t)(((x) & 0x7U) << 8))
#define DMA_ATTR_DSIZE(x)       ((uint16_t)((x) & 0x7U))
#define DMA_SIZE_8BIT           0U
#define DMA_SIZE_16BIT          1U
#define DMA_SIZE_32BIT          2U
#define DMA_CSR_START           0x0001U
#define DMA_CSR_ACTIVE          0x0040U
#define DMA_CSR_DONE            0x0080U

/* Cortex-M4 NVIC and DWT */
#define NVIC_ISER(n)            MCXE_REG32(0xE000E100UL + 4UL * (uint32_t)(n))
#define NVIC_ICER(n)            MCXE_REG32(0xE000E180UL + 4UL * (uint32_t)(n))
#define NVIC_ICPR(n)            MCXE_REG32(0xE000E280UL + 4UL * (uint32_t)(n))
#define NVIC_IPR(irq)           MCXE_REG8(0xE000E400UL + (uint32_t)(irq))
#define DEMCR                   MCXE_REG32(0xE000EDFCUL)
#define DEMCR_TRCENA            (1UL << 24)
#define DWT_CTRL                MCXE_REG32(0xE0001000UL)
#define DWT_CTRL_CYCCNTENA      (1UL << 0)
#define DWT_CYCCNT              MCXE_REG32(0xE0001004UL)

#endif /* WOLFIP_NXP_MCXE_ENET_REGS_H */

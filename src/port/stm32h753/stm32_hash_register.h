/* stm32_hash_register.h
 *
 * STM32H753 HASH peripheral register definitions for bare-metal use.
 * Provides the types and constants needed by wolfSSL's STM32 HASH/HMAC port
 * (wolfcrypt/src/port/st/stm32.c) without requiring ST HAL or CMSIS headers.
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

#ifndef STM32_HASH_REGISTER_H
#define STM32_HASH_REGISTER_H

#include <stdint.h>

/* =========================================================================
 * HASH Peripheral Register Map (STM32H753, RM0433 Section 35)
 *
 * Base address: 0x48021400
 * The HASH peripheral supports MD5, SHA-1, SHA-224, SHA-256, and HMAC.
 * ========================================================================= */

#define HASH_BASE           0x48021400UL
#define HASH_DIGEST_BASE    (HASH_BASE + 0x310UL)

/* HASH register block (matches CMSIS HASH_TypeDef layout) */
typedef struct {
    volatile uint32_t CR;           /* 0x00: Control register */
    volatile uint32_t DIN;          /* 0x04: Data input register */
    volatile uint32_t STR;          /* 0x08: Start register */
    volatile uint32_t HR[5];        /* 0x0C-0x1C: Digest registers (first 20 bytes) */
    volatile uint32_t IMR;          /* 0x20: Interrupt enable register */
    volatile uint32_t SR;           /* 0x24: Status register */
    uint32_t RESERVED1[52];         /* 0x28-0xF4: Reserved */
    volatile uint32_t CSR[54];      /* 0xF8-0x1CC: Context swap registers */
} HASH_TypeDef;

/* Extended digest register block for SHA-224/SHA-256 (bytes 20-31) */
typedef struct {
    volatile uint32_t HR[8];        /* 0x310-0x32C: Extended digest registers */
} HASH_DIGEST_TypeDef;

/* Peripheral pointers */
#define HASH        ((HASH_TypeDef *)        HASH_BASE)
#define HASH_DIGEST ((HASH_DIGEST_TypeDef *) HASH_DIGEST_BASE)

/* =========================================================================
 * HASH_CR - Control Register (offset 0x00)
 * ========================================================================= */
#define HASH_CR_INIT        (1UL << 2)      /* Initialize message digest */
#define HASH_CR_DMAE        (1UL << 3)      /* DMA enable */
#define HASH_CR_DATATYPE    (3UL << 4)      /* Data type selection */
#define HASH_CR_MODE        (1UL << 6)      /* Mode: 0=hash, 1=HMAC */
#define HASH_CR_ALGO_0      (1UL << 7)      /* Algorithm selection bit 0 */
#define HASH_CR_ALGO        (0x00040080UL)  /* ALGO[1:0] mask: bit 18 | bit 7 */
#define HASH_CR_NBW         (0xFUL << 8)    /* Number of words in FIFO */
#define HASH_CR_DINNE       (1UL << 12)     /* DIN not empty */
#define HASH_CR_MDMAT       (1UL << 13)     /* Multiple DMA transfer */
#define HASH_CR_LKEY        (1UL << 16)     /* Long key flag (>block size) */
#define HASH_CR_ALGO_1      (1UL << 18)     /* Algorithm selection bit 1 */

/* =========================================================================
 * Algorithm Selection Values (written into CR register)
 *
 * ALGO[1:0] is at bits [18, 7].
 * NOTE: On STM32H753 (confirmed by direct hardware test), MD5 and SHA-1
 * are SWAPPED compared to RM0433 documentation:
 *   00 = SHA-1        (bit18=0, bit7=0) = 0x00000  (RM0433 says MD5)
 *   01 = MD5          (bit18=0, bit7=1) = 0x00080  (RM0433 says SHA-1)
 *   10 = SHA-224      (bit18=1, bit7=0) = 0x40000
 *   11 = SHA-256      (bit18=1, bit7=1) = 0x40080
 * ========================================================================= */
#define HASH_AlgoSelection_MD5      0x00000080UL
#define HASH_AlgoSelection_SHA1     0x00000000UL
#define HASH_AlgoSelection_SHA224   0x00040000UL
#define HASH_AlgoSelection_SHA256   0x00040080UL

/* Mode selection values (CR.MODE bit 6) */
#define HASH_ALGOMODE_HASH          0x00000000UL    /* Hash mode */
#define HASH_ALGOMODE_HMAC          0x00000040UL    /* HMAC mode */

/* Data type selection (CR.DATATYPE bits [5:4]) */
#define HASH_DATATYPE_32B           0x00000000UL    /* 32-bit, no swap */
#define HASH_DATATYPE_16B           0x00000010UL    /* 16-bit half-word swap */
#define HASH_DATATYPE_8B            0x00000020UL    /* 8-bit byte swap */
#define HASH_DATATYPE_1B            0x00000030UL    /* 1-bit bit swap */

/* =========================================================================
 * HASH_STR - Start Register (offset 0x08)
 * ========================================================================= */
#define HASH_STR_NBLW       (0x1FUL << 0)   /* Number of valid bits in last word */
#define HASH_STR_NBW        HASH_STR_NBLW   /* Alias used by wolfSSL */
#define HASH_STR_DCAL       (1UL << 8)      /* Digest calculation trigger */

/* =========================================================================
 * HASH_IMR - Interrupt Mask Register (offset 0x20)
 * ========================================================================= */
#define HASH_IMR_DINIE      (1UL << 0)      /* Data input interrupt enable */
#define HASH_IMR_DCIE       (1UL << 1)      /* Digest calculation complete IE */

/* =========================================================================
 * HASH_SR - Status Register (offset 0x24)
 * ========================================================================= */
#define HASH_SR_DINIS       (1UL << 0)      /* Data input interrupt status */
#define HASH_SR_DCIS        (1UL << 1)      /* Digest calculation complete */
#define HASH_SR_DMAS        (1UL << 2)      /* DMA status */
#define HASH_SR_BUSY        (1UL << 3)      /* Busy flag */

/* =========================================================================
 * Clock Enable/Disable Macros
 *
 * HASH is on AHB2, bit 5 of RCC_AHB2ENR (offset 0xDC from RCC base).
 * Override wolfSSL's default clock macros to use direct register access.
 * ========================================================================= */
#define RCC_BASE_ADDR       0x58024400UL
#define RCC_AHB2ENR_ADDR    (RCC_BASE_ADDR + 0xDCUL)

#define STM32_HASH_CLOCK_ENABLE(ctx)  do { \
    *(volatile uint32_t *)RCC_AHB2ENR_ADDR |= (1UL << 5); \
    /* Dummy readback ensures clock enable propagates (per STM32 errata) */ \
    (void)(*(volatile uint32_t *)RCC_AHB2ENR_ADDR); \
    (void)(ctx); \
} while(0)

#define STM32_HASH_CLOCK_DISABLE(ctx) do { \
    /* Keep HASH clock enabled - H753 may not reinit properly after  \
     * clock cycling. TODO: investigate if RCC reset is needed. */ \
    (void)(ctx); \
} while(0)

#endif /* STM32_HASH_REGISTER_H */

/* main.c
 *
 * wolfIP demo on STM32F437/F439.  Same chip family, two boards supported
 * via the BOARD make variable -- both end up at SYSCLK 168 MHz, PCLK1 42,
 * PCLK2 84, with the shared DWC GMAC driver in src/port/stm32f4/:
 *
 *   BOARD=nucleo_f439zi  (NUCLEO-F439ZI, default)
 *     - HSE: 8 MHz BYPASS from onboard ST-LINK MCO (no crystal)
 *     - VCP: USART3 on PD8 (TX) / PD9 (RX), AF7
 *     - PHY: LAN8742A at MDIO addr 0
 *     - RMII TXD1 on PB13
 *
 *   BOARD=stm32439i_eval  (STM32439I-EVAL)
 *     - HSE: 25 MHz crystal
 *     - VCP: UART4 on PC10 (TX) / PC11 (RX), AF8
 *     - PHY: DP83848 at MDIO addr 1
 *     - RMII TXD1 on PG14
 *
 * Brings up clocks, UART (ST-LINK VCP), SysTick, Ethernet, runs DHCP,
 * and answers TCP echo on port 7.  Pure register-level init -- no STM32
 * HAL dependency.
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "wolfip.h"
#include "stm32f4_eth.h"

#if !defined(BOARD_NUCLEO_F439ZI) && !defined(BOARD_STM32439I_EVAL)
#error "Define BOARD_NUCLEO_F439ZI or BOARD_STM32439I_EVAL (set BOARD= in make)"
#endif

#if defined(BOARD_NUCLEO_F439ZI)
#define BOARD_NAME "NUCLEO-F439ZI"
#define PHY_NAME   "LAN8742A"
#else
#define BOARD_NAME "STM32439I-EVAL"
#define PHY_NAME   "DP83848"
#endif

/* ===================================================================== */
/* Register definitions                                                  */
/* ===================================================================== */

#define RCC_BASE        0x40023800UL
#define RCC_CR          (*(volatile uint32_t *)(RCC_BASE + 0x00U))
#define RCC_PLLCFGR     (*(volatile uint32_t *)(RCC_BASE + 0x04U))
#define RCC_CFGR        (*(volatile uint32_t *)(RCC_BASE + 0x08U))
#define RCC_AHB1ENR     (*(volatile uint32_t *)(RCC_BASE + 0x30U))
#define RCC_AHB2ENR     (*(volatile uint32_t *)(RCC_BASE + 0x34U))
#define RCC_APB1ENR     (*(volatile uint32_t *)(RCC_BASE + 0x40U))
#define RCC_APB2ENR     (*(volatile uint32_t *)(RCC_BASE + 0x44U))
#define RCC_AHB1RSTR    (*(volatile uint32_t *)(RCC_BASE + 0x10U))

#define RCC_AHB2ENR_RNGEN (1U << 6)

/* Hardware RNG (RM0090 sec 24).  Clocked from PLL48CLK = 48 MHz (PLLQ=7). */
#define RNG_BASE        0x50060800UL
#define RNG_CR          (*(volatile uint32_t *)(RNG_BASE + 0x00U))
#define RNG_SR          (*(volatile uint32_t *)(RNG_BASE + 0x04U))
#define RNG_DR          (*(volatile uint32_t *)(RNG_BASE + 0x08U))
#define RNG_CR_RNGEN    (1U << 2)
#define RNG_SR_DRDY     (1U << 0)
#define RNG_SR_CECS     (1U << 1)
#define RNG_SR_SECS     (1U << 2)
#define RNG_SR_CEIS     (1U << 5)
#define RNG_SR_SEIS     (1U << 6)

#define RCC_CR_HSEON    (1U << 16)
#define RCC_CR_HSERDY   (1U << 17)
#define RCC_CR_HSEBYP   (1U << 18)
#define RCC_CR_PLLON    (1U << 24)
#define RCC_CR_PLLRDY   (1U << 25)

#define RCC_PLLCFGR_PLLSRC_HSE (1U << 22)

#define RCC_CFGR_SW_PLL  (2U << 0)
#define RCC_CFGR_SWS_PLL (2U << 2)
#define RCC_CFGR_HPRE_DIV1  (0U << 4)
#define RCC_CFGR_PPRE1_DIV4 (5U << 10)
#define RCC_CFGR_PPRE2_DIV2 (4U << 13)
#define RCC_CFGR_SW_MASK    (3U << 0)
#define RCC_CFGR_SWS_MASK   (3U << 2)
#define RCC_CFGR_HPRE_MASK  (0xFU << 4)
#define RCC_CFGR_PPRE1_MASK (7U << 10)
#define RCC_CFGR_PPRE2_MASK (7U << 13)

#define RCC_AHB1ENR_GPIOA   (1U << 0)
#define RCC_AHB1ENR_GPIOB   (1U << 1)
#define RCC_AHB1ENR_GPIOC   (1U << 2)
#define RCC_AHB1ENR_GPIOG   (1U << 6)
#define RCC_AHB1ENR_ETHMAC    (1U << 25)
#define RCC_AHB1ENR_ETHMACTX  (1U << 26)
#define RCC_AHB1ENR_ETHMACRX  (1U << 27)

#define RCC_APB1ENR_PWREN    (1U << 28)
#define RCC_APB1ENR_UART4EN  (1U << 19)
#define RCC_APB1ENR_USART3EN (1U << 18)
#define RCC_APB2ENR_SYSCFGEN (1U << 14)

#define RCC_AHB1RSTR_ETHMACRST (1U << 25)

#define FLASH_BASE      0x40023C00UL
#define FLASH_ACR       (*(volatile uint32_t *)(FLASH_BASE + 0x00U))
#define FLASH_ACR_LATENCY_5WS (5U << 0)
#define FLASH_ACR_PRFTEN     (1U << 8)
#define FLASH_ACR_ICEN       (1U << 9)
#define FLASH_ACR_DCEN       (1U << 10)

#define PWR_BASE        0x40007000UL
#define PWR_CR          (*(volatile uint32_t *)(PWR_BASE + 0x00U))
#define PWR_CR_VOS_SCALE1 (3U << 14)

#define SYSCFG_BASE     0x40013800UL
#define SYSCFG_PMC      (*(volatile uint32_t *)(SYSCFG_BASE + 0x04U))
#define SYSCFG_PMC_MII_RMII_SEL (1U << 23)

#define GPIOA_BASE      0x40020000UL
#define GPIOB_BASE      0x40020400UL
#define GPIOC_BASE      0x40020800UL
#define GPIOD_BASE      0x40020C00UL
#define GPIOG_BASE      0x40021800UL

#define RCC_AHB1ENR_GPIOD (1U << 3)

#define GPIO_MODER(b)   (*(volatile uint32_t *)((b) + 0x00U))
#define GPIO_OSPEEDR(b) (*(volatile uint32_t *)((b) + 0x08U))
#define GPIO_PUPDR(b)   (*(volatile uint32_t *)((b) + 0x0CU))
#define GPIO_AFRL(b)    (*(volatile uint32_t *)((b) + 0x20U))
#define GPIO_AFRH(b)    (*(volatile uint32_t *)((b) + 0x24U))

/* Per-board UART selection (both APB1). */
#if defined(BOARD_NUCLEO_F439ZI)
  #define UART_BASE         0x40004800UL  /* USART3 */
  #define UART_CLK_BIT      RCC_APB1ENR_USART3EN
  #define UART_PORT         GPIOD_BASE
  #define UART_RCC_GPIO_BIT RCC_AHB1ENR_GPIOD
  #define UART_TX_PIN       8U
  #define UART_RX_PIN       9U
  #define UART_AF           7U
#elif defined(BOARD_STM32439I_EVAL)
  #define UART_BASE         0x40004C00UL  /* UART4 */
  #define UART_CLK_BIT      RCC_APB1ENR_UART4EN
  #define UART_PORT         GPIOC_BASE
  #define UART_RCC_GPIO_BIT RCC_AHB1ENR_GPIOC
  #define UART_TX_PIN       10U
  #define UART_RX_PIN       11U
  #define UART_AF           8U
#endif

#define UART_SR         (*(volatile uint32_t *)(UART_BASE + 0x00U))
#define UART_DR         (*(volatile uint32_t *)(UART_BASE + 0x04U))
#define UART_BRR        (*(volatile uint32_t *)(UART_BASE + 0x08U))
#define UART_CR1        (*(volatile uint32_t *)(UART_BASE + 0x0CU))
#define USART_SR_TXE    (1U << 7)
#define USART_CR1_RE    (1U << 2)
#define USART_CR1_TE    (1U << 3)
#define USART_CR1_UE    (1U << 13)

/* SysTick (Cortex-M4 SCS) */
#define STK_CTRL        (*(volatile uint32_t *)0xE000E010UL)
#define STK_LOAD        (*(volatile uint32_t *)0xE000E014UL)
#define STK_VAL         (*(volatile uint32_t *)0xE000E018UL)
#define STK_CTRL_ENABLE   (1U << 0)
#define STK_CTRL_TICKINT  (1U << 1)
#define STK_CTRL_CLKSRC   (1U << 2)

/* FPU coprocessor access (CP10/CP11) */
#define SCB_CPACR       (*(volatile uint32_t *)0xE000ED88UL)

/* SCB fault registers (used by hard-fault dump) */
#define SCB_HFSR        (*(volatile uint32_t *)0xE000ED2CUL)
#define SCB_CFSR        (*(volatile uint32_t *)0xE000ED28UL)
#define SCB_BFAR        (*(volatile uint32_t *)0xE000ED38UL)
#define SCB_MMFAR       (*(volatile uint32_t *)0xE000ED34UL)

/* ===================================================================== */
/* Globals                                                               */
/* ===================================================================== */

#define SYSCLK_HZ       168000000U
#define HCLK_HZ         168000000U
#define PCLK1_HZ        42000000U
#define PCLK2_HZ        84000000U

volatile uint64_t HAL_time_ms;

uint32_t stm32f4_eth_hclk_hz(void)
{
    return HCLK_HZ;
}

static struct wolfIP *IPStack;

#define ECHO_PORT       7
#define RX_BUF_SIZE     1024
static uint8_t rx_buf[RX_BUF_SIZE];
static int listen_fd = -1;
static int client_fd = -1;

#define DHCP_TIMEOUT_MS 30000U
#define DHCP_REINIT_MS  10000U

/* ===================================================================== */
/* UART output -- peripheral selection is in the BOARD #if block above   */
/* ===================================================================== */

static void uart_putc(char c)
{
    while ((UART_SR & USART_SR_TXE) == 0U) { }
    UART_DR = (uint32_t)(uint8_t)c;
}

static void uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n')
            uart_putc('\r');
        uart_putc(*s++);
    }
}

static void uart_puthex(uint32_t val)
{
    const char hex[] = "0123456789ABCDEF";
    int i;
    uart_puts("0x");
    for (i = 28; i >= 0; i -= 4)
        uart_putc(hex[(val >> i) & 0xFU]);
}

int _write(int file, const char *ptr, int len)
{
    int i;
    (void)file;
    for (i = 0; i < len; i++) {
        if (ptr[i] == '\n')
            uart_putc('\r');
        uart_putc(ptr[i]);
    }
    return len;
}

/* ===================================================================== */
/* Hard fault handler -- dump frame via the board's UART                  */
/* ===================================================================== */

void hard_fault_handler_c(uint32_t *frame)
{
    uart_puts("\n\n*** HARD FAULT ***\n");
    uart_puts("  PC:   "); uart_puthex(frame[6]); uart_puts("\n");
    uart_puts("  LR:   "); uart_puthex(frame[5]); uart_puts("\n");
    uart_puts("  R0:   "); uart_puthex(frame[0]); uart_puts("\n");
    uart_puts("  R1:   "); uart_puthex(frame[1]); uart_puts("\n");
    uart_puts("  R2:   "); uart_puthex(frame[2]); uart_puts("\n");
    uart_puts("  R3:   "); uart_puthex(frame[3]); uart_puts("\n");
    uart_puts("  R12:  "); uart_puthex(frame[4]); uart_puts("\n");
    uart_puts("  xPSR: "); uart_puthex(frame[7]); uart_puts("\n");
    uart_puts("  HFSR: "); uart_puthex(SCB_HFSR); uart_puts("\n");
    uart_puts("  CFSR: "); uart_puthex(SCB_CFSR); uart_puts("\n");
    if (SCB_CFSR & 0x00008200U) {
        uart_puts("  BFAR: "); uart_puthex(SCB_BFAR); uart_puts("\n");
    }
    if (SCB_CFSR & 0x00000082U) {
        uart_puts("  MMFAR:"); uart_puthex(SCB_MMFAR); uart_puts("\n");
    }
    while (1) { }
}

void HardFault_Handler(void) __attribute__((naked));
void HardFault_Handler(void)
{
    __asm volatile (
        "tst lr, #4              \n"
        "ite eq                  \n"
        "mrseq r0, msp           \n"
        "mrsne r0, psp           \n"
        "b hard_fault_handler_c  \n"
    );
}

/* ===================================================================== */
/* SysTick - 1 ms tick                                                    */
/* ===================================================================== */

void SysTick_Handler(void)
{
    HAL_time_ms++;
}

static void systick_init(void)
{
    STK_LOAD  = (SYSCLK_HZ / 1000U) - 1U;
    STK_VAL   = 0U;
    STK_CTRL  = STK_CTRL_CLKSRC | STK_CTRL_TICKINT | STK_CTRL_ENABLE;
}

/* ===================================================================== */
/* Clock init: HSE -> PLL -> SYSCLK 168 MHz, HCLK=168, PCLK1=42, PCLK2=84 */
/* ===================================================================== */

/* PLLM is picked so VCO_in = HSE / PLLM = 1 MHz (within the spec 1..2
 * MHz range).  NUCLEO HSE = 8 MHz (ST-LINK MCO bypass), EVAL HSE = 25
 * MHz crystal.  All other PLL params (PLLN=336, PLLP=2, PLLQ=7) and
 * downstream prescalers are identical, so SYSCLK lands at 168 MHz on
 * both boards. */
#if defined(BOARD_NUCLEO_F439ZI)
#define PLLM_VAL  8U
#elif defined(BOARD_STM32439I_EVAL)
#define PLLM_VAL  25U
#endif

static int clock_init(void)
{
    uint32_t timeout;

    /* Enable PWR and select VOS scale 1 (required for SYSCLK > 144 MHz). */
    RCC_APB1ENR |= RCC_APB1ENR_PWREN;
    (void)RCC_APB1ENR;
    PWR_CR = (PWR_CR & ~(3U << 14)) | PWR_CR_VOS_SCALE1;

    /* HSE source.  NUCLEO uses HSE_BYPASS (8 MHz from ST-LINK MCO);
     * STM32439I-EVAL has a real 25 MHz crystal. */
#if defined(BOARD_NUCLEO_F439ZI)
    RCC_CR |= RCC_CR_HSEBYP;
#endif
    RCC_CR |= RCC_CR_HSEON;
    timeout = 1000000U;
    while (!(RCC_CR & RCC_CR_HSERDY) && (timeout > 0U)) {
        timeout--;
    }
    if (timeout == 0U)
        return -1;

    /* Flash latency 5 WS (3.3 V, 150-168 MHz HCLK), enable caches +
     * prefetch.  Must be set BEFORE switching SYSCLK to PLL. */
    FLASH_ACR = FLASH_ACR_LATENCY_5WS | FLASH_ACR_PRFTEN |
                FLASH_ACR_ICEN | FLASH_ACR_DCEN;

    /* PLL configuration -- see PLLM_VAL comment above for board math.
     * PLLP=2 is encoded as 0 in bits 17:16.  PLLQ=7 yields 48 MHz PLL48
     * (for OTG_FS / RNG / SDIO when added later). */
    RCC_CR &= ~RCC_CR_PLLON;
    timeout = 100000U;
    while ((RCC_CR & RCC_CR_PLLRDY) && (timeout > 0U)) {
        timeout--;
    }
    RCC_PLLCFGR = RCC_PLLCFGR_PLLSRC_HSE |
                  (PLLM_VAL << 0) |
                  (336U << 6)     |   /* PLLN = 336 */
                  (0U << 16)      |   /* PLLP = /2 */
                  (7U << 24);         /* PLLQ = /7 */
    RCC_CR |= RCC_CR_PLLON;
    timeout = 1000000U;
    while (!(RCC_CR & RCC_CR_PLLRDY) && (timeout > 0U)) {
        timeout--;
    }
    if (timeout == 0U)
        return -2;

    /* AHB/1, APB1/4 (=42 MHz), APB2/2 (=84 MHz). */
    RCC_CFGR = (RCC_CFGR & ~(RCC_CFGR_HPRE_MASK | RCC_CFGR_PPRE1_MASK |
                              RCC_CFGR_PPRE2_MASK)) |
               RCC_CFGR_HPRE_DIV1 | RCC_CFGR_PPRE1_DIV4 |
               RCC_CFGR_PPRE2_DIV2;

    /* Switch SYSCLK to PLL. */
    RCC_CFGR = (RCC_CFGR & ~RCC_CFGR_SW_MASK) | RCC_CFGR_SW_PLL;
    timeout = 100000U;
    while (((RCC_CFGR & RCC_CFGR_SWS_MASK) != RCC_CFGR_SWS_PLL) &&
           (timeout > 0U)) {
        timeout--;
    }
    return (timeout > 0U) ? 0 : -3;
}

/* ===================================================================== */
/* UART init -- pins/AF/peripheral chosen at compile time by BOARD       */
/* ===================================================================== */

static void uart_init(void)
{
    /* GPIO clock for the chosen TX/RX port. */
    RCC_AHB1ENR |= UART_RCC_GPIO_BIT;
    (void)RCC_AHB1ENR;

    /* MODER = AF (10b) for TX and RX pins. */
    GPIO_MODER(UART_PORT) &= ~((3U << (UART_TX_PIN * 2)) |
                                (3U << (UART_RX_PIN * 2)));
    GPIO_MODER(UART_PORT) |=  ((2U << (UART_TX_PIN * 2)) |
                                (2U << (UART_RX_PIN * 2)));

    /* High speed. */
    GPIO_OSPEEDR(UART_PORT) |= (3U << (UART_TX_PIN * 2)) |
                                (3U << (UART_RX_PIN * 2));

    /* AF mux.  Both TX and RX pins are >= 8 on both boards (PD8/PD9 or
     * PC10/PC11), so AFRH is the right register. */
    GPIO_AFRH(UART_PORT) &= ~((0xFU << ((UART_TX_PIN - 8U) * 4)) |
                              (0xFU << ((UART_RX_PIN - 8U) * 4)));
    GPIO_AFRH(UART_PORT) |=  ((UART_AF << ((UART_TX_PIN - 8U) * 4)) |
                              (UART_AF << ((UART_RX_PIN - 8U) * 4)));

    /* UART peripheral clock. */
    RCC_APB1ENR |= UART_CLK_BIT;
    (void)RCC_APB1ENR;

    /* 115200 8N1 @ PCLK1 = 42 MHz.  BRR = PCLK / baud (mantissa+fraction
     * is encoded together when oversampling 16). */
    UART_CR1 = 0U;
    UART_BRR = (PCLK1_HZ + (115200U / 2U)) / 115200U;
    UART_CR1 = USART_CR1_TE | USART_CR1_RE | USART_CR1_UE;
}

/* ===================================================================== */
/* Ethernet RCC + GPIO + SYSCFG                                          */
/*                                                                       */
/* Shared RMII pins (both boards):                                       */
/*   PA1  ETH_RMII_REF_CLK    AF11                                       */
/*   PA2  ETH_MDIO            AF11                                       */
/*   PA7  ETH_RMII_CRS_DV     AF11                                       */
/*   PC1  ETH_MDC             AF11                                       */
/*   PC4  ETH_RMII_RXD0       AF11                                       */
/*   PC5  ETH_RMII_RXD1       AF11                                       */
/*   PG11 ETH_RMII_TX_EN      AF11                                       */
/*   PG13 ETH_RMII_TXD0       AF11                                       */
/*                                                                       */
/* Board-specific:                                                       */
/*   NUCLEO-F439ZI (per UM1974):  RMII_TXD1 = PB13 AF11                  */
/*   STM32439I-EVAL (per UM1670): RMII_TXD1 = PG14 AF11                  */
/* ===================================================================== */

static void gpio_set_af(uint32_t base, uint32_t pin, uint32_t af)
{
    /* MODER = AF (10b) */
    GPIO_MODER(base) &= ~(3U << (pin * 2));
    GPIO_MODER(base) |=  (2U << (pin * 2));
    /* Push-pull (OTYPER=0 default) */
    /* Very high speed */
    GPIO_OSPEEDR(base) |= (3U << (pin * 2));
    /* No pull */
    GPIO_PUPDR(base)   &= ~(3U << (pin * 2));
    /* AF select */
    if (pin < 8U) {
        GPIO_AFRL(base) &= ~(0xFU << (pin * 4));
        GPIO_AFRL(base) |=  (af   << (pin * 4));
    } else {
        GPIO_AFRH(base) &= ~(0xFU << ((pin - 8U) * 4));
        GPIO_AFRH(base) |=  (af   << ((pin - 8U) * 4));
    }
}

static void eth_pins_init(void)
{
    /* Need GPIOA, GPIOC, GPIOG always; GPIOB only for NUCLEO TXD1. */
    RCC_AHB1ENR |= RCC_AHB1ENR_GPIOA | RCC_AHB1ENR_GPIOC | RCC_AHB1ENR_GPIOG;
#if defined(BOARD_NUCLEO_F439ZI)
    RCC_AHB1ENR |= RCC_AHB1ENR_GPIOB;
#endif
    (void)RCC_AHB1ENR;

    /* Port A */
    gpio_set_af(GPIOA_BASE, 1U, 11U); /* RMII_REF_CLK */
    gpio_set_af(GPIOA_BASE, 2U, 11U); /* MDIO */
    gpio_set_af(GPIOA_BASE, 7U, 11U); /* RMII_CRS_DV */

    /* Port C */
    gpio_set_af(GPIOC_BASE, 1U, 11U); /* MDC */
    gpio_set_af(GPIOC_BASE, 4U, 11U); /* RMII_RXD0 */
    gpio_set_af(GPIOC_BASE, 5U, 11U); /* RMII_RXD1 */

    /* Port G shared TX_EN + TXD0; TXD1 differs per board. */
    gpio_set_af(GPIOG_BASE, 11U, 11U); /* RMII_TX_EN */
    gpio_set_af(GPIOG_BASE, 13U, 11U); /* RMII_TXD0 */
#if defined(BOARD_NUCLEO_F439ZI)
    gpio_set_af(GPIOB_BASE, 13U, 11U); /* RMII_TXD1 (NUCLEO) */
#else
    gpio_set_af(GPIOG_BASE, 14U, 11U); /* RMII_TXD1 (EVAL)  */
#endif
}

static void eth_clk_init(void)
{
    /* SYSCFG clock so PMC.MII_RMII_SEL can be written. */
    RCC_APB2ENR |= RCC_APB2ENR_SYSCFGEN;
    (void)RCC_APB2ENR;

    /* Select RMII before enabling MAC clocks. */
    SYSCFG_PMC |= SYSCFG_PMC_MII_RMII_SEL;

    /* Enable MAC + TX + RX clocks. */
    RCC_AHB1ENR |= RCC_AHB1ENR_ETHMAC | RCC_AHB1ENR_ETHMACTX |
                   RCC_AHB1ENR_ETHMACRX;
    (void)RCC_AHB1ENR;

    /* Pulse MAC peripheral reset.  Hold ~1ms then release. */
    RCC_AHB1RSTR |= RCC_AHB1RSTR_ETHMACRST;
    { volatile uint32_t d; for (d = 0; d < 200000U; d++) { } }
    RCC_AHB1RSTR &= ~RCC_AHB1RSTR_ETHMACRST;
    { volatile uint32_t d; for (d = 0; d < 200000U; d++) { } }
}

/* ===================================================================== */
/* wolfIP random number source - STM32F4 hardware RNG                     */
/* ===================================================================== */

static void rng_init(void)
{
    RCC_AHB2ENR |= RCC_AHB2ENR_RNGEN;
    (void)RCC_AHB2ENR;
    RNG_CR = RNG_CR_RNGEN;
}

uint32_t wolfIP_getrandom(void)
{
    uint32_t sr;
    uint32_t retries = 100U;

    while (retries-- > 0U) {
        sr = RNG_SR;
        if (sr & (RNG_SR_CEIS | RNG_SR_SEIS)) {
            /* Clear error flags and restart the RNG.  CEIS indicates
             * PLL48CLK trouble; SEIS indicates a seed-quality failure.
             * Both are recoverable per RM0090. */
            RNG_SR = sr & ~(RNG_SR_CEIS | RNG_SR_SEIS);
            RNG_CR = 0U;
            RNG_CR = RNG_CR_RNGEN;
            continue;
        }
        if (sr & RNG_SR_DRDY)
            return RNG_DR;
    }
    /* RNG never produced data - fall back to a fixed value rather than
     * hanging the stack.  This should not happen on a healthy board. */
    return 0xDEADBEEFU;
}

/* ===================================================================== */
/* Echo server callback                                                  */
/* ===================================================================== */

static void uart_putip4(ip4 ip)
{
    printf("%u.%u.%u.%u",
        (unsigned)((ip >> 24) & 0xFFU),
        (unsigned)((ip >> 16) & 0xFFU),
        (unsigned)((ip >> 8)  & 0xFFU),
        (unsigned)( ip        & 0xFFU));
}

static void echo_cb(int fd, uint16_t event, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    int ret;

    if ((fd == listen_fd) && (event & CB_EVENT_READABLE) &&
        (client_fd == -1)) {
        client_fd = wolfIP_sock_accept(s, listen_fd, NULL, NULL);
        if (client_fd > 0) {
            printf("Echo: client connected (fd=%d)\n", client_fd);
            wolfIP_register_callback(s, client_fd, echo_cb, s);
        }
        return;
    }

    if ((fd == client_fd) && (event & CB_EVENT_READABLE)) {
        ret = wolfIP_sock_recvfrom(s, client_fd, rx_buf, sizeof(rx_buf),
                                   0, NULL, NULL);
        if (ret > 0) {
            (void)wolfIP_sock_sendto(s, client_fd, rx_buf, (uint32_t)ret,
                                     0, NULL, 0);
        } else if (ret == 0) {
            printf("Echo: client disconnected\n");
            wolfIP_sock_close(s, client_fd);
            client_fd = -1;
        }
    }

    if ((fd == client_fd) && (event & CB_EVENT_CLOSED)) {
        printf("Echo: connection closed\n");
        wolfIP_sock_close(s, client_fd);
        client_fd = -1;
    }
}

/* ===================================================================== */
/* main                                                                  */
/* ===================================================================== */

int main(void)
{
    struct wolfIP_ll_dev *ll;
    struct wolfIP_sockaddr_in addr;
    int ret;

    /* Enable FPU (CP10 + CP11 full access). */
    SCB_CPACR |= (0xFU << 20);
    __asm volatile ("dsb sy" ::: "memory");
    __asm volatile ("isb sy" ::: "memory");

    /* clock_init() can only fail if HSE/PLL never come ready.  If it
     * does, UART output won't make it out at the expected baud anyway,
     * so there is nothing useful to print -- just continue and let the
     * watchdog (or the user) catch the dead board. */
    (void)clock_init();

    systick_init();
    uart_init();
    rng_init();

    printf("\n\n=== wolfIP STM32F437/F439 (" BOARD_NAME ") ===\n");
    printf("Build: " __DATE__ " " __TIME__ "\n");
    printf("SYSCLK = %u Hz, HCLK = %u Hz, PCLK1 = %u Hz, PCLK2 = %u Hz\n",
           (unsigned)SYSCLK_HZ, (unsigned)HCLK_HZ,
           (unsigned)PCLK1_HZ, (unsigned)PCLK2_HZ);

    /* Bring up Ethernet RCC/GPIO/SYSCFG before wolfIP init. */
    eth_pins_init();
    eth_clk_init();

    wolfIP_init_static(&IPStack);

    printf("Initializing Ethernet (RMII + " PHY_NAME ")...\n");
    ll = wolfIP_getdev(IPStack);
    ret = stm32f4_eth_init(ll, NULL);
    if (ret == -2) {
        printf("  NOTE: PHY link down at startup -- continuing\n");
    } else if (ret < 0) {
        printf("  ERROR: stm32f4_eth_init failed (%d)\n", ret);
    }

#ifdef DHCP
    printf("Starting DHCP...\n");
    (void)wolfIP_poll(IPStack, stm32f4_hal_time_ms());
    (void)dhcp_client_init(IPStack);
#else
    {
        ip4 ip = atoip4(WOLFIP_IP);
        ip4 nm = atoip4(WOLFIP_NETMASK);
        ip4 gw = atoip4(WOLFIP_GW);
        printf("Static IP:\n");
        printf("  IP:   "); uart_putip4(ip); printf("\n");
        printf("  Mask: "); uart_putip4(nm); printf("\n");
        printf("  GW:   "); uart_putip4(gw); printf("\n");
        wolfIP_ipconfig_set(IPStack, ip, nm, gw);
    }
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = 0;
    addr.sin_port = ee16(ECHO_PORT);

    printf("TCP echo server on port %d\n", ECHO_PORT);
    listen_fd = wolfIP_sock_socket(IPStack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (listen_fd < 0) {
        printf("  ERROR: wolfIP_sock_socket failed (%d)\n", listen_fd);
        for (;;) { __asm volatile ("wfi"); }
    }
    wolfIP_register_callback(IPStack, listen_fd, echo_cb, IPStack);
    ret = wolfIP_sock_bind(IPStack, listen_fd,
                           (struct wolfIP_sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        printf("  ERROR: wolfIP_sock_bind failed (%d)\n", ret);
        for (;;) { __asm volatile ("wfi"); }
    }
    ret = wolfIP_sock_listen(IPStack, listen_fd, 1);
    if (ret < 0) {
        printf("  ERROR: wolfIP_sock_listen failed (%d)\n", ret);
        for (;;) { __asm volatile ("wfi"); }
    }

    printf("Ready! Test with:\n");
    printf("  ping <ip>\n");
    printf("  echo 'hello' | nc <ip> 7\n\n");

    {
        uint64_t last_diag_ms = 0;
#ifdef DHCP
        uint64_t dhcp_start_ms = stm32f4_hal_time_ms();
        uint64_t dhcp_reinit_ms = dhcp_start_ms;
        int dhcp_done = 0;
#endif

        for (;;) {
            uint64_t now = stm32f4_hal_time_ms();
            (void)wolfIP_poll(IPStack, now);

#ifdef DHCP
            if (!dhcp_done) {
                if (dhcp_bound(IPStack)) {
                    ip4 ip = 0, nm = 0, gw = 0;
                    wolfIP_ipconfig_get(IPStack, &ip, &nm, &gw);
                    printf("DHCP bound:\n");
                    printf("  IP:   "); uart_putip4(ip); printf("\n");
                    printf("  Mask: "); uart_putip4(nm); printf("\n");
                    printf("  GW:   "); uart_putip4(gw); printf("\n");
                    dhcp_done = 1;
                } else if ((now - dhcp_start_ms) > DHCP_TIMEOUT_MS) {
                    ip4 ip = 0, nm = 0, gw = 0;
                    wolfIP_ipconfig_get(IPStack, &ip, &nm, &gw);
                    if (ip == 0U) {
                        ip = atoip4(WOLFIP_IP);
                        nm = atoip4(WOLFIP_NETMASK);
                        gw = atoip4(WOLFIP_GW);
                        printf("DHCP timeout, using static fallback:\n");
                        wolfIP_ipconfig_set(IPStack, ip, nm, gw);
                    } else {
                        printf("DHCP assigned IP:\n");
                    }
                    printf("  IP:   "); uart_putip4(ip); printf("\n");
                    printf("  Mask: "); uart_putip4(nm); printf("\n");
                    printf("  GW:   "); uart_putip4(gw); printf("\n");
                    dhcp_done = 1;
                } else if ((now - dhcp_reinit_ms) > DHCP_REINIT_MS) {
                    (void)dhcp_client_init(IPStack);
                    dhcp_reinit_ms = now;
                }
            }
#endif

            if ((now - last_diag_ms) >= 10000U) {
                uint32_t pkts, tx_pkts, tx_errs;
                uint32_t mac_cfg, mac_dbg;
                stm32f4_eth_get_stats(NULL, &pkts, &tx_pkts, &tx_errs);
                stm32f4_eth_get_mac_diag(&mac_cfg, &mac_dbg);
                printf("[%lu] rx=%lu tx=%lu/%lu maccr=0x%08lX "
                       "macdbg=0x%08lX dmasr=0x%08lX\n",
                       (unsigned long)(now / 1000U),
                       (unsigned long)pkts,
                       (unsigned long)tx_pkts,
                       (unsigned long)tx_errs,
                       (unsigned long)mac_cfg,
                       (unsigned long)mac_dbg,
                       (unsigned long)stm32f4_eth_get_dma_status());
                last_diag_ms = now;
            }
        }
    }
}

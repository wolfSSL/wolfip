/* main.c
 *
 * STM32N6 (NUCLEO-N657X0-Q, Cortex-M55) wolfIP echo server.
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
#include <string.h>
#include "config.h"
#include "wolfip.h"
#include "stm32_eth.h"

/* Forward declarations */
static void uart_puts(const char *s);
static void delay(uint32_t count);

/* =========================================================================
 * RCC — Reset and Clock Control (base 0x56028000, secure bus)
 * ========================================================================= */
#define RCC_BASE          0x56028000UL

/* Control: direct read / set (+0x800) / clear (+0x1000) */
#define RCC_CR            (*(volatile uint32_t *)(RCC_BASE + 0x000u))
#define RCC_CSR           (*(volatile uint32_t *)(RCC_BASE + 0x800u))
#define RCC_CCR           (*(volatile uint32_t *)(RCC_BASE + 0x1000u))
#define RCC_CR_HSION      (1u << 3)
#define RCC_CR_PLL1ON     (1u << 8)

/* Status — ready flags */
#define RCC_SR            (*(volatile uint32_t *)(RCC_BASE + 0x04u))
#define RCC_SR_HSIRDY     (1u << 3)
#define RCC_SR_PLL1RDY    (1u << 8)

/* Clock switching */
#define RCC_CFGR1         (*(volatile uint32_t *)(RCC_BASE + 0x20u))
#define RCC_CFGR1_CPUSW_SHIFT   16u
#define RCC_CFGR1_CPUSW_MASK    (0x3u << 16u)
#define RCC_CFGR1_CPUSWS_SHIFT  20u
#define RCC_CFGR1_CPUSWS_MASK   (0x3u << 20u)
#define RCC_CFGR1_SYSSW_SHIFT   24u
#define RCC_CFGR1_SYSSW_MASK    (0x3u << 24u)
#define RCC_CFGR1_SYSSWS_SHIFT  28u
#define RCC_CFGR1_SYSSWS_MASK   (0x3u << 28u)

/* AHB/APB prescalers */
#define RCC_CFGR2         (*(volatile uint32_t *)(RCC_BASE + 0x24u))
#define RCC_CFGR2_HPRE_SHIFT  20u
#define RCC_CFGR2_HPRE_MASK   (0x7u << 20u)

/* PLL1 configuration */
#define RCC_PLL1CFGR1     (*(volatile uint32_t *)(RCC_BASE + 0x80u))
#define RCC_PLL1CFGR1_SEL_MASK   (0x7u << 28u)
#define RCC_PLL1CFGR1_DIVM_MASK  (0x3Fu << 20u)
#define RCC_PLL1CFGR1_DIVN_MASK  (0xFFFu << 8u)
#define RCC_PLL1CFGR1_BYP        (1u << 27u)
#define RCC_PLL1CFGR1_SEL_HSI    (0x0u << 28u)
#define RCC_PLL1CFGR1_DIVM_SHIFT 20u
#define RCC_PLL1CFGR1_DIVN_SHIFT 8u

#define RCC_PLL1CFGR2     (*(volatile uint32_t *)(RCC_BASE + 0x84u))

#define RCC_PLL1CFGR3     (*(volatile uint32_t *)(RCC_BASE + 0x88u))
#define RCC_PLL1CFGR3_PDIV1_SHIFT 27u
#define RCC_PLL1CFGR3_PDIV2_SHIFT 24u
#define RCC_PLL1CFGR3_MODSSDIS   (1u << 2u)
#define RCC_PLL1CFGR3_MODSSRST   (1u << 0u)
#define RCC_PLL1CFGR3_PDIVEN     (1u << 30u)

/* IC dividers */
#define RCC_IC1CFGR       (*(volatile uint32_t *)(RCC_BASE + 0xC4u))
#define RCC_IC2CFGR       (*(volatile uint32_t *)(RCC_BASE + 0xC8u))
#define RCC_IC6CFGR       (*(volatile uint32_t *)(RCC_BASE + 0xD8u))
#define RCC_IC11CFGR      (*(volatile uint32_t *)(RCC_BASE + 0xECu))
#define RCC_ICCFGR_INT_SHIFT  16u
#define RCC_ICCFGR_SEL_PLL1  (0x0u << 28u)

/* Divider enable: direct / set (+0x800) / clear (+0x1000) */
#define RCC_DIVENR        (*(volatile uint32_t *)(RCC_BASE + 0x240u))
#define RCC_DIVENSR       (*(volatile uint32_t *)(RCC_BASE + 0xA40u))
#define RCC_DIVENCR       (*(volatile uint32_t *)(RCC_BASE + 0x1240u))
#define RCC_DIVENR_IC1EN  (1u << 0u)
#define RCC_DIVENR_IC2EN  (1u << 1u)
#define RCC_DIVENR_IC6EN  (1u << 5u)
#define RCC_DIVENR_IC11EN (1u << 10u)

/* Peripheral clock enable — use SET registers (write 1s to set bits).
 * Direct ENR registers are read-only status; ENSR is the set register. */
#define RCC_AHB1ENR       (*(volatile uint32_t *)(RCC_BASE + 0x250u))  /* read */
#define RCC_AHB2ENR       (*(volatile uint32_t *)(RCC_BASE + 0x254u))  /* read */
#define RCC_AHB3ENR       (*(volatile uint32_t *)(RCC_BASE + 0x258u))  /* read */
#define RCC_AHB4ENR       (*(volatile uint32_t *)(RCC_BASE + 0x25Cu))  /* read */
#define RCC_AHB5ENR       (*(volatile uint32_t *)(RCC_BASE + 0x260u))  /* read */
#define RCC_APB2ENR       (*(volatile uint32_t *)(RCC_BASE + 0x26Cu))  /* read */
#define RCC_MEMENR        (*(volatile uint32_t *)(RCC_BASE + 0x24Cu))  /* read */

/* SET registers — write-only, bits written as 1 get set in ENR */
#define RCC_AHB2ENSR      (*(volatile uint32_t *)(RCC_BASE + 0xA54u))
#define RCC_AHB3ENSR      (*(volatile uint32_t *)(RCC_BASE + 0xA58u))
#define RCC_AHB4ENSR      (*(volatile uint32_t *)(RCC_BASE + 0xA5Cu))
#define RCC_AHB5ENSR      (*(volatile uint32_t *)(RCC_BASE + 0xA60u))
#define RCC_APB2ENSR      (*(volatile uint32_t *)(RCC_BASE + 0xA6Cu))
#define RCC_MEMENSR       (*(volatile uint32_t *)(RCC_BASE + 0xA4Cu))

/* Clock configuration — ETH PHY interface selection */
#define RCC_CCIPR2        (*(volatile uint32_t *)(RCC_BASE + 0x148u))
#define RCC_CCIPR2_ETH1SEL_RMII    (0x4u << 16u) /* bit 18 = RMII mode */

/* Peripheral reset */
#define RCC_AHB1RSTR      (*(volatile uint32_t *)(RCC_BASE + 0x210u))
#define RCC_AHB5RSTR      (*(volatile uint32_t *)(RCC_BASE + 0x220u))

/* =========================================================================
 * GPIO — secure bus addresses
 * ========================================================================= */
#define GPIOA_BASE        0x56020000UL
#define GPIOB_BASE        0x56020400UL
#define GPIOC_BASE        0x56020800UL
#define GPIOE_BASE        0x56021000UL
#define GPIOF_BASE        0x56021400UL
#define GPIOG_BASE        0x56021800UL
#define GPIOO_BASE        0x56023800UL

#define GPIO_MODER(base)   (*(volatile uint32_t *)((base) + 0x00u))
#define GPIO_OSPEEDR(base) (*(volatile uint32_t *)((base) + 0x08u))
#define GPIO_PUPDR(base)   (*(volatile uint32_t *)((base) + 0x0Cu))
#define GPIO_ODR(base)     (*(volatile uint32_t *)((base) + 0x14u))
#define GPIO_BSRR(base)    (*(volatile uint32_t *)((base) + 0x18u))
#define GPIO_AFRL(base)    (*(volatile uint32_t *)((base) + 0x20u))
#define GPIO_AFRH(base)    (*(volatile uint32_t *)((base) + 0x24u))

/* =========================================================================
 * PWR — Power Control (base 0x56024800)
 * ========================================================================= */
#define PWR_BASE          0x56024800UL
#define PWR_SVMCR1        (*(volatile uint32_t *)(PWR_BASE + 0x34u))
#define PWR_SVMCR2        (*(volatile uint32_t *)(PWR_BASE + 0x38u))
#define PWR_SVMCR3        (*(volatile uint32_t *)(PWR_BASE + 0x3Cu))
#define PWR_SVMCR1_VDDIO4SV  (1u << 8u)
#define PWR_SVMCR2_VDDIO5SV  (1u << 8u)
#define PWR_SVMCR3_VDDIO2SV  (1u << 8u)
#define PWR_SVMCR3_VDDIO3SV  (1u << 9u)

/* =========================================================================
 * USART1 — PE5 (TX) / PE6 (RX), AF7 (base 0x52001000)
 * ========================================================================= */
#define USART1_BASE       0x52001000UL
#define USART1_CR1        (*(volatile uint32_t *)(USART1_BASE + 0x00u))
#define USART1_CR2        (*(volatile uint32_t *)(USART1_BASE + 0x04u))
#define USART1_CR3        (*(volatile uint32_t *)(USART1_BASE + 0x08u))
#define USART1_BRR        (*(volatile uint32_t *)(USART1_BASE + 0x0Cu))
#define USART1_ISR        (*(volatile uint32_t *)(USART1_BASE + 0x1Cu))
#define USART1_TDR        (*(volatile uint32_t *)(USART1_BASE + 0x28u))

/* =========================================================================
 * SCB — Cortex-M55 cache control
 * ========================================================================= */
#define SCB_CCR           (*(volatile uint32_t *)(0xE000ED14UL))
#define SCB_CCR_IC        (1u << 17u)
#define SCB_CCR_DC        (1u << 16u)
#define SCB_ICIALLU       (*(volatile uint32_t *)(0xE000EF50UL))

/* =========================================================================
 * MPU — Cortex-M55 ARMv8.1-M Memory Protection Unit
 * ========================================================================= */
#define MPU_TYPE          (*(volatile uint32_t *)(0xE000ED90UL))
#define MPU_CTRL          (*(volatile uint32_t *)(0xE000ED94UL))
#define MPU_RNR           (*(volatile uint32_t *)(0xE000ED98UL))
#define MPU_RBAR          (*(volatile uint32_t *)(0xE000ED9CUL))
#define MPU_RLAR          (*(volatile uint32_t *)(0xE000EDA0UL))
#define MPU_MAIR0         (*(volatile uint32_t *)(0xE000EDC0UL))
#define MPU_MAIR1         (*(volatile uint32_t *)(0xE000EDC4UL))

/* =========================================================================
 * Fault registers
 * ========================================================================= */
#define SCB_HFSR          (*(volatile uint32_t *)0xE000ED2CUL)
#define SCB_CFSR          (*(volatile uint32_t *)0xE000ED28UL)
#define SCB_BFAR          (*(volatile uint32_t *)0xE000ED38UL)
#define SCB_MMFAR         (*(volatile uint32_t *)0xE000ED34UL)

/* =========================================================================
 * Barrier macros
 * ========================================================================= */
#define DSB() __asm volatile ("dsb sy" ::: "memory")
#define ISB() __asm volatile ("isb sy" ::: "memory")
#define DMB() __asm volatile ("dmb sy" ::: "memory")

/* =========================================================================
 * LED — LD1 green on PO1 (GPIOO), LD2 red on PG10 (GPIOG)
 * Note: These are from the N6570-DK DTS. NUCLEO board may differ.
 * ========================================================================= */
#define LED1_PORT         GPIOO_BASE
#define LED1_PIN          1u
#define LED1_RCC_BIT      14u   /* RCC_AHB4ENR bit for GPIOO */

#define ECHO_PORT 7
#define RX_BUF_SIZE 1024

static struct wolfIP *IPStack;
static int listen_fd = -1;
static int client_fd = -1;
static uint8_t rx_buf[RX_BUF_SIZE];

/* =========================================================================
 * HardFault Handler — safe version that won't cause LOCKUP
 *
 * IMPORTANT: Do NOT access USART or other peripherals here unless we know
 * their clocks are enabled. Accessing unclocked peripherals from the fault
 * handler causes a double-fault → CPU LOCKUP (unrecoverable without NRST).
 * ========================================================================= */
static volatile int uart_ready = 0;

#define FAULT_USART1_ISR  (*(volatile uint32_t *)(USART1_BASE + 0x1Cu))
#define FAULT_USART1_TDR  (*(volatile uint32_t *)(USART1_BASE + 0x28u))

static void fault_uart_putc(char c)
{
    while ((FAULT_USART1_ISR & (1u << 7)) == 0) { }
    FAULT_USART1_TDR = (uint32_t)c;
}

static void fault_uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') fault_uart_putc('\r');
        fault_uart_putc(*s++);
    }
}

static void fault_uart_puthex(uint32_t val)
{
    const char hex[] = "0123456789ABCDEF";
    fault_uart_puts("0x");
    for (int i = 28; i >= 0; i -= 4)
        fault_uart_putc(hex[(val >> i) & 0xF]);
}

void hard_fault_handler_c(uint32_t *frame)
{
    if (uart_ready) {
        fault_uart_puts("\n\n*** HARD FAULT ***\n");
        fault_uart_puts("  PC:   "); fault_uart_puthex(frame[6]); fault_uart_puts("\n");
        fault_uart_puts("  LR:   "); fault_uart_puthex(frame[5]); fault_uart_puts("\n");
        fault_uart_puts("  R0:   "); fault_uart_puthex(frame[0]); fault_uart_puts("\n");
        fault_uart_puts("  R1:   "); fault_uart_puthex(frame[1]); fault_uart_puts("\n");
        fault_uart_puts("  R2:   "); fault_uart_puthex(frame[2]); fault_uart_puts("\n");
        fault_uart_puts("  R3:   "); fault_uart_puthex(frame[3]); fault_uart_puts("\n");
        fault_uart_puts("  R12:  "); fault_uart_puthex(frame[4]); fault_uart_puts("\n");
        fault_uart_puts("  xPSR: "); fault_uart_puthex(frame[7]); fault_uart_puts("\n");
        fault_uart_puts("  HFSR: "); fault_uart_puthex(SCB_HFSR); fault_uart_puts("\n");
        fault_uart_puts("  CFSR: "); fault_uart_puthex(SCB_CFSR); fault_uart_puts("\n");
        if (SCB_CFSR & 0x00008200u) {
            fault_uart_puts("  BFAR: "); fault_uart_puthex(SCB_BFAR); fault_uart_puts("\n");
        }
        if (SCB_CFSR & 0x00000082u) {
            fault_uart_puts("  MMFAR:"); fault_uart_puthex(SCB_MMFAR); fault_uart_puts("\n");
        }
    }
    /* Bare spin — do NOT access any peripherals (GPIO, UART) here.
     * If the fault happens before peripheral clocks are enabled,
     * any peripheral access would cause a double-fault → LOCKUP.
     * Use GDB to inspect fault registers instead. */
    while (1) { }
}

void HardFault_Handler(void) __attribute__((naked));
void HardFault_Handler(void)
{
    __asm volatile(
        "tst lr, #4       \n"
        "ite eq            \n"
        "mrseq r0, msp     \n"
        "mrsne r0, psp     \n"
        "b hard_fault_handler_c \n"
    );
}

/* =========================================================================
 * Clock Configuration — PLL1 → 600 MHz CPU
 *
 * HSI 64 MHz → PLL1 (M=4, N=75) → VCO 1200 MHz → PDIV1=1 → 1200 MHz
 *   IC1 /2 = 600 MHz → CPU
 *   IC2 /3 = 400 MHz → AXI bus
 *   IC6 /4 = 300 MHz → system bus C
 *   IC11/3 = 400 MHz → system bus D
 * AHB prescaler /2 → HCLK = 300 MHz
 * ========================================================================= */
static void clock_config(void)
{
    uint32_t reg;

    /* Enable HSI 64 MHz */
    RCC_CSR = RCC_CR_HSION;
    while (!(RCC_SR & RCC_SR_HSIRDY))
        ;

    /* Disable PLL1 before reconfiguring */
    RCC_CCR = RCC_CR_PLL1ON;
    while (RCC_SR & RCC_SR_PLL1RDY)
        ;

    /* PLL1: HSI / 4 * 75 = 1200 MHz VCO.
     * Clear BYP — Boot ROM leaves it set. */
    reg = RCC_PLL1CFGR1;
    reg &= ~(RCC_PLL1CFGR1_SEL_MASK | RCC_PLL1CFGR1_DIVM_MASK |
             RCC_PLL1CFGR1_DIVN_MASK | RCC_PLL1CFGR1_BYP);
    reg |= RCC_PLL1CFGR1_SEL_HSI |
           (4u << RCC_PLL1CFGR1_DIVM_SHIFT) |
           (75u << RCC_PLL1CFGR1_DIVN_SHIFT);
    RCC_PLL1CFGR1 = reg;

    RCC_PLL1CFGR2 = 0; /* no fractional */

    /* PDIV1=1, PDIV2=1 → PLL output = VCO = 1200 MHz */
    RCC_PLL1CFGR3 = (1u << RCC_PLL1CFGR3_PDIV1_SHIFT) |
                    (1u << RCC_PLL1CFGR3_PDIV2_SHIFT) |
                    RCC_PLL1CFGR3_MODSSDIS |
                    RCC_PLL1CFGR3_MODSSRST |
                    RCC_PLL1CFGR3_PDIVEN;

    /* Enable PLL1, wait for lock */
    RCC_CSR = RCC_CR_PLL1ON;
    while (!(RCC_SR & RCC_SR_PLL1RDY))
        ;

    /* Configure IC dividers: disable → configure → re-enable */
    RCC_DIVENCR = RCC_DIVENR_IC1EN;
    RCC_IC1CFGR = RCC_ICCFGR_SEL_PLL1 | ((2u - 1u) << RCC_ICCFGR_INT_SHIFT);
    RCC_DIVENSR = RCC_DIVENR_IC1EN;

    RCC_DIVENCR = RCC_DIVENR_IC2EN;
    RCC_IC2CFGR = RCC_ICCFGR_SEL_PLL1 | ((3u - 1u) << RCC_ICCFGR_INT_SHIFT);
    RCC_DIVENSR = RCC_DIVENR_IC2EN;

    RCC_DIVENCR = RCC_DIVENR_IC6EN;
    RCC_IC6CFGR = RCC_ICCFGR_SEL_PLL1 | ((4u - 1u) << RCC_ICCFGR_INT_SHIFT);
    RCC_DIVENSR = RCC_DIVENR_IC6EN;

    RCC_DIVENCR = RCC_DIVENR_IC11EN;
    RCC_IC11CFGR = RCC_ICCFGR_SEL_PLL1 | ((3u - 1u) << RCC_ICCFGR_INT_SHIFT);
    RCC_DIVENSR = RCC_DIVENR_IC11EN;

    /* AHB prescaler /2 → HCLK = 300 MHz */
    reg = RCC_CFGR2;
    reg &= ~RCC_CFGR2_HPRE_MASK;
    reg |= (1u << RCC_CFGR2_HPRE_SHIFT);
    RCC_CFGR2 = reg;

    /* Switch CPU to IC1, system bus to IC2/IC6/IC11 */
    reg = RCC_CFGR1;
    reg &= ~(RCC_CFGR1_CPUSW_MASK | RCC_CFGR1_SYSSW_MASK);
    reg |= (0x3u << RCC_CFGR1_CPUSW_SHIFT) |
           (0x3u << RCC_CFGR1_SYSSW_SHIFT);
    RCC_CFGR1 = reg;
    while ((RCC_CFGR1 & RCC_CFGR1_CPUSWS_MASK) !=
           (0x3u << RCC_CFGR1_CPUSWS_SHIFT))
        ;
    while ((RCC_CFGR1 & RCC_CFGR1_SYSSWS_MASK) !=
           (0x3u << RCC_CFGR1_SYSSWS_SHIFT))
        ;
}

/* =========================================================================
 * Power — mark VDDIO supplies valid
 * ========================================================================= */
static void pwr_enable_io_supply(void)
{
    /* Enable PWR peripheral clock */
    RCC_AHB4ENSR = (1u << 18u); /* PWREN */
    DMB();
    PWR_SVMCR1 |= PWR_SVMCR1_VDDIO4SV;
    PWR_SVMCR2 |= PWR_SVMCR2_VDDIO5SV;
    PWR_SVMCR3 |= (1u << 4u) | PWR_SVMCR3_VDDIO2SV | PWR_SVMCR3_VDDIO3SV |
                  (1u << 12u) | (1u << 20u); /* Match CubeN6: 0x00101310 */
    DMB();
}

/* =========================================================================
 * Cache
 * ========================================================================= */
static void icache_enable(void)
{
    DSB(); ISB();
    SCB_ICIALLU = 0;
    DSB(); ISB();
    SCB_CCR |= SCB_CCR_IC;
    DSB(); ISB();
}

static void dcache_enable(void)
{
    DSB();
    SCB_CCR |= SCB_CCR_DC;
    DSB(); ISB();
}

/* =========================================================================
 * MPU — Configure ETH DMA buffer region as non-cacheable
 *
 * Cortex-M55 ARMv8.1-M MPU:
 *   RBAR: base address | AP[2:1] | XN[0]
 *   RLAR: limit address | AttrIdx[3:1] | EN[0]
 *   MAIR: attribute encoding per index
 *
 * ETH buffers (.eth_buffers) are in AXISRAM2 at 0x34100000.
 * ========================================================================= */
extern uint32_t _eth_start;
extern uint32_t _eth_end;

static void mpu_configure_eth_nocache(void)
{
    uint32_t base = (uint32_t)&_eth_start & ~0x1Fu; /* Align down to 32 */
    uint32_t limit = ((uint32_t)&_eth_end + 0x1Fu) & ~0x1Fu; /* Align up */

    /* Disable MPU */
    MPU_CTRL = 0;
    DSB();

    /* Region 0: ETH DMA descriptors + buffers, Normal Non-cacheable. */
    MPU_RNR = 0;
    MPU_RBAR = base | (1u << 1u) | (1u << 0u); /* AP=RW, XN=1 */
    MPU_RLAR = ((limit - 1u) & ~0x1Fu) | (2u << 1u) | 1u; /* AttrIdx=2, EN=1 */

    /* MAIR0: Attr2 (bits [23:16]) = 0x44 → Normal, Non-cacheable */
    MPU_MAIR0 = (0x44u << 16u);

    /* Enable MPU + PRIVDEFENA (default map for other regions) */
    MPU_CTRL = 5u;
    DSB(); ISB();
}

/* =========================================================================
 * Simple delay
 * ========================================================================= */
static void delay(uint32_t count)
{
    for (volatile uint32_t i = 0; i < count; i++) { }
}

/* =========================================================================
 * LED — LD1 green on PO1
 * ========================================================================= */
static void led_init(void)
{
    uint32_t moder;

    /* Enable GPIOO clock */
    RCC_AHB4ENSR = (1u << LED1_RCC_BIT);
    delay(100);

    /* Set PO1 as output */
    moder = GPIO_MODER(LED1_PORT);
    moder &= ~(3u << (LED1_PIN * 2u));
    moder |= (1u << (LED1_PIN * 2u));
    GPIO_MODER(LED1_PORT) = moder;
}

static void led_on(void)
{
    GPIO_BSRR(LED1_PORT) = (1u << LED1_PIN);
}

static void led_toggle(void)
{
    GPIO_ODR(LED1_PORT) ^= (1u << LED1_PIN);
}

/* =========================================================================
 * UART — USART1 on PE5 (TX) / PE6 (RX), AF7
 *
 * HCLK (APB2 clock after PLL) = 300 MHz
 * BRR = 300000000 / 115200 = 2604
 * ========================================================================= */
static void uart_init(void)
{
    uint32_t moder, afr;

    /* Enable GPIOE + USART1 clocks */
    RCC_AHB4ENSR = (1u << 4u);   /* GPIOEEN */
    RCC_APB2ENSR = (1u << 4u);   /* USART1EN */
    delay(100);

    /* PE5 + PE6 → AF mode */
    moder = GPIO_MODER(GPIOE_BASE);
    moder &= ~((3u << (5u * 2u)) | (3u << (6u * 2u)));
    moder |= (2u << (5u * 2u)) | (2u << (6u * 2u));
    GPIO_MODER(GPIOE_BASE) = moder;

    /* High speed */
    GPIO_OSPEEDR(GPIOE_BASE) |= (3u << (5u * 2u)) | (3u << (6u * 2u));

    /* AF7 for PE5 and PE6 (both in AFRL since pins < 8) */
    afr = GPIO_AFRL(GPIOE_BASE);
    afr &= ~((0xFu << (5u * 4u)) | (0xFu << (6u * 4u)));
    afr |= (7u << (5u * 4u)) | (7u << (6u * 4u));
    GPIO_AFRL(GPIOE_BASE) = afr;

    /* Configure USART1: 115200 baud using IC9 kernel clock (64 MHz).
     * BRR = 64000000 / 115200 = 556 (0x22C), matching CubeN6. */
    USART1_CR1 = 0;
    USART1_CR2 = 0;
    USART1_CR3 = 0;
    USART1_BRR = 64000000u / 115200u; /* 556 */
    DSB();
    delay(1000);
    USART1_CR1 = (1u << 0u) | (1u << 2u) | (1u << 3u); /* UE + RE + TE */
    delay(1000);
}

static void uart_putc(char c)
{
    volatile uint32_t timeout = 100000u;
    while ((USART1_ISR & (1u << 7u)) == 0 && --timeout) { }
    if (timeout == 0) return; /* USART kernel clock not running */
    USART1_TDR = (uint32_t)c;
}

static void uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') uart_putc('\r');
        uart_putc(*s++);
    }
}

static void uart_puthex(uint32_t val)
{
    const char hex[] = "0123456789ABCDEF";
    uart_puts("0x");
    for (int i = 28; i >= 0; i -= 4) {
        uart_putc(hex[(val >> i) & 0xF]);
    }
}

static void uart_puthex8(uint8_t val)
{
    const char hex[] = "0123456789ABCDEF";
    uart_putc(hex[(val >> 4) & 0xF]);
    uart_putc(hex[val & 0xF]);
}

static void uart_putdec(uint32_t val)
{
    char buf[12];
    int i = 0;
    if (val == 0) {
        uart_putc('0');
        return;
    }
    while (val > 0 && i < 11) {
        buf[i++] = '0' + (val % 10);
        val /= 10;
    }
    while (i > 0) {
        uart_putc(buf[--i]);
    }
}

static void uart_putip4(ip4 ip)
{
    uart_putdec((ip >> 24) & 0xFF);
    uart_putc('.');
    uart_putdec((ip >> 16) & 0xFF);
    uart_putc('.');
    uart_putdec((ip >> 8) & 0xFF);
    uart_putc('.');
    uart_putdec(ip & 0xFF);
}

/* wolfIP requires this symbol */
uint32_t wolfIP_getrandom(void)
{
    /* Simple LFSR-based PRNG — no HW RNG on initial bring-up.
     * Replace with TRNG when available. */
    static uint32_t state = 0xDEADBEEF;
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

/* =========================================================================
 * SYSCFG — I/O compensation for VDDIO3 (Ethernet GPIOF pins)
 *
 * SYSCFG base = 0x56008000 (secure, APB4 + 0x8000).
 * VDDIO3CCCR (offset 0x5C): compensation cell control for GPIOF.
 *   bit 8 = EN (enable compensation cell)
 *   bit 9 = CS (code selection: 0=auto, 1=manual)
 * VDDIO3CCSR (offset 0x60): compensation cell status (RDY bit).
 * ========================================================================= */
#define SYSCFG_BASE       0x56008000UL
#define SYSCFG_VDDIO3CCCR (*(volatile uint32_t *)(SYSCFG_BASE + 0x5Cu))
#define SYSCFG_VDDIO3CCSR (*(volatile uint32_t *)(SYSCFG_BASE + 0x60u))

/* RCC clock for SYSCFG — APB4ENR2 at offset 0x278, bit 0 = SYSCFGEN */
#define RCC_APB4ENR2      (*(volatile uint32_t *)(RCC_BASE + 0x278u))
#define RCC_APB4ENSR2     (*(volatile uint32_t *)(RCC_BASE + 0xA78u))

/* =========================================================================
 * Ethernet GPIO — RMII pin configuration (NUCLEO-N657X0-Q)
 *
 * Pin mapping (AF11) — all on GPIOF except MDC on PG11:
 *   PF4  — ETH_MDIO       PG11 — ETH_MDC
 *   PF7  — ETH_REF_CLK    PF10 — ETH_CRS_DV
 *   PF11 — ETH_TX_EN      PF12 — ETH_TXD0     PF13 — ETH_TXD1
 *   PF14 — ETH_RXD0       PF15 — ETH_RXD1
 * ========================================================================= */
static void gpio_eth_pin(uint32_t base, uint32_t pin)
{
    uint32_t moder, ospeedr, afr;
    uint32_t pos2 = pin * 2u;

    /* Alternate function mode (0b10) */
    moder = GPIO_MODER(base);
    moder &= ~(3u << pos2);
    moder |= (2u << pos2);
    GPIO_MODER(base) = moder;

    /* High speed (0b10) — match CubeN6. Very High (0b11) causes issues on N6. */
    ospeedr = GPIO_OSPEEDR(base);
    ospeedr &= ~(3u << pos2);
    ospeedr |= (2u << pos2);
    GPIO_OSPEEDR(base) = ospeedr;

    /* AF11 for Ethernet */
    if (pin < 8u) {
        afr = GPIO_AFRL(base);
        afr &= ~(0xFu << (pin * 4u));
        afr |= (11u << (pin * 4u));
        GPIO_AFRL(base) = afr;
    } else {
        afr = GPIO_AFRH(base);
        afr &= ~(0xFu << ((pin - 8u) * 4u));
        afr |= (11u << ((pin - 8u) * 4u));
        GPIO_AFRH(base) = afr;
    }
}

static void eth_gpio_init(void)
{
    /* Enable GPIO clocks: F and G */
    RCC_AHB4ENSR = (1u << 5u) | (1u << 6u); /* GPIOFEN + GPIOGEN */
    delay(1000);

    /* Power on AXISRAM2 for ETH DMA buffers.
     * AXISRAM2-6 are powered down by default after boot ROM. */
    {
        volatile uint32_t *ramcfg_sram2_cr = (volatile uint32_t *)0x52023080u;
        RCC_AHB2ENSR = (1u << 12u); /* RAMCFGEN */
        RCC_MEMENSR = (1u << 1u) |   /* AXISRAM2EN */
                      (1u << 4u) |   /* AHBSRAM1EN */
                      (1u << 5u);    /* AHBSRAM2EN */
        delay(100);
        *ramcfg_sram2_cr &= ~(1u << 20u); /* Clear SRAMSD → power on */
        DSB();
        delay(10000);
    }

    /* Open RISAF3 (AXISRAM2) to allow ETH DMA R+W access.
     * Default ENDR=0xFFF covers only 4KB — ETH buffers at offset 0xF8000 are blocked!
     * Extend to cover full 1MB. Leave RISAF2 (AXISRAM1) untouched (code runs there).
     * RISAF3_BASE = 0x54028000 */
    {
        /* RISAF3 REG0: cover full AXISRAM2 (1MB), all CIDs R+W, Secure.
         * CFGR: BREN=1 (bit 0), SEC=1 (bit 8) — must match secure bus alias. */
        *(volatile uint32_t *)0x54028044u = 0x00000000u; /* STARTR = 0 */
        *(volatile uint32_t *)0x54028048u = 0x000FFFFFu; /* ENDR = 1MB-1 */
        *(volatile uint32_t *)0x5402804Cu = 0x000F000Fu; /* CIDCFGR: CID0-3 R+W */
        *(volatile uint32_t *)0x54028040u = 0x00000101u; /* CFGR: BREN=1, SEC=1 */
        DSB();
    }

    /* Configure RIFSC: grant ETH1 DMA (RIMC master 6) memory access.
     * Matches CubeN6 RISAF_Config exactly:
     *   1. RIMC_ATTR6: CID=1, SEC, PRIV
     *   2. RISC slave: ETH1 peripheral marked SEC+PRIV
     * RIFSC_BASE = 0x54024000 */
    {
        volatile uint32_t *rimc_attr6 = (volatile uint32_t *)(0x54024000u + 0xC28u);
        RCC_AHB3ENSR = (1u << 9u); /* RIFSCEN */
        delay(100);
        /* RIMC: CID=1, DSEL=0, DSEC=1 (secure), DPRIV=1 — 0x301 */
        *rimc_attr6 = 0x1u | (1u << 8u) | (1u << 9u);
        /* RISC: Set ETH1 peripheral as Secure + Privileged.
         * ETH1 is bit 28 of SECCFGRx[1] and PRIVCFGRx[1]. */
        *(volatile uint32_t *)(0x54024000u + 0x14u) |= (1u << 28u); /* SEC */
        *(volatile uint32_t *)(0x54024000u + 0x34u) |= (1u << 28u); /* PRIV */
        DSB();
        uart_puts("  RIMC_ATTR6 (ETH1): ");
        uart_puthex(*rimc_attr6);
        uart_puts("\n");
    }

    /* Compensation cells per Errata Sheet ES0620 (from CubeN6 SystemInit).
     * ALL VDDIO domains get the same errata workaround value 0x287:
     * CS=1 (manual code selection) + specific NMOS/PMOS compensation codes. */
    RCC_APB4ENSR2 = (1u << 0u); /* SYSCFGEN */
    delay(100);
    /* VDDIO3 compensation per Errata ES0620 (CubeN6 SystemInit value) */
    SYSCFG_VDDIO3CCCR = 0x00000287u;
    DSB();

    /* Configure RMII pins (AF11) — NUCLEO-N657X0-Q pinout */
    gpio_eth_pin(GPIOF_BASE, 4);   /* MDIO */
    gpio_eth_pin(GPIOG_BASE, 11);  /* MDC */
    gpio_eth_pin(GPIOF_BASE, 7);   /* REF_CLK */
    gpio_eth_pin(GPIOF_BASE, 10);  /* CRS_DV */
    gpio_eth_pin(GPIOF_BASE, 11);  /* TX_EN */
    gpio_eth_pin(GPIOF_BASE, 12);  /* TXD0 */
    gpio_eth_pin(GPIOF_BASE, 13);  /* TXD1 */
    gpio_eth_pin(GPIOF_BASE, 14);  /* RXD0 */
    gpio_eth_pin(GPIOF_BASE, 15);  /* RXD1 */
}

/* =========================================================================
 * TCP echo callback — stack-agnostic, mirrors H563 implementation
 * ========================================================================= */
static void echo_cb(int fd, uint16_t event, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    int ret;

    if ((fd == listen_fd) && (event & CB_EVENT_READABLE) && (client_fd == -1)) {
        client_fd = wolfIP_sock_accept(s, listen_fd, NULL, NULL);
        if (client_fd > 0) {
            wolfIP_register_callback(s, client_fd, echo_cb, s);
        }
        return;
    }

    if ((fd == client_fd) && (event & CB_EVENT_READABLE)) {
        ret = wolfIP_sock_recvfrom(s, client_fd, rx_buf, sizeof(rx_buf), 0, NULL, NULL);
        if (ret > 0) {
            (void)wolfIP_sock_sendto(s, client_fd, rx_buf, (uint32_t)ret, 0, NULL, 0);
        } else if (ret == 0) {
            wolfIP_sock_close(s, client_fd);
            client_fd = -1;
        }
    }

    if ((fd == client_fd) && (event & CB_EVENT_CLOSED)) {
        wolfIP_sock_close(s, client_fd);
        client_fd = -1;
    }
}

/* =========================================================================
 * main
 * ========================================================================= */
int main(void)
{
    struct wolfIP_ll_dev *ll;
    struct wolfIP_sockaddr_in addr;
    uint64_t tick = 0;
    int ret;

    /* Set SAU ALLNS=1: all memory treated as Non-Secure.
     * This allows Non-Secure DMA masters to write to any memory region. */
    {
        volatile uint32_t *sau_ctrl = (volatile uint32_t *)0xE000EDD0u;
        volatile uint32_t *sau_rnr  = (volatile uint32_t *)0xE000EDD8u;
        volatile uint32_t *sau_rbar = (volatile uint32_t *)0xE000EDDCu;
        volatile uint32_t *sau_rlar = (volatile uint32_t *)0xE000EDE0u;
        int i;
        *sau_ctrl = 0;
        DSB();
        for (i = 0; i < 8; i++) {
            *sau_rnr  = (uint32_t)i;
            *sau_rbar = 0;
            *sau_rlar = 0;
        }
        *sau_ctrl = 2u; /* ALLNS=1, ENABLE=0 → all memory Non-Secure */
        DSB(); ISB();
    }

    pwr_enable_io_supply();

    led_init();
    led_on();

    /* PLL + IC dividers must be up before UART — boot ROM leaves IC dividers
     * disabled, so APB2 has no clock source and USART1 kernel clock is dead. */
    clock_config();

    /* Blink LED 3x fast to indicate PLL locked */
    {
        int blink;
        for (blink = 0; blink < 3; blink++) {
            led_toggle();
            delay(500000);
            led_toggle();
            delay(500000);
        }
    }

    /* Enable IC9 divider (USART1 kernel clock source on N6).
     * CubeN6 uses IC9CFGR=0x30000000 (SEL=3=HSI, INT=0=div1) → 64 MHz.
     * Then CCIPR13 USART1SEL=2 selects ic9_ck as USART1 kernel clock. */
    {
        volatile uint32_t *ic9cfgr = (volatile uint32_t *)(RCC_BASE + 0xE4u);
        volatile uint32_t *ccipr13 = (volatile uint32_t *)(RCC_BASE + 0x174u);
        /* Disable IC9, configure, re-enable */
        RCC_DIVENCR = (1u << 8u); /* IC9 disable */
        *ic9cfgr = 0x30000000u; /* SEL=3 (HSI), INT=0 (div 1) → 64 MHz */
        RCC_DIVENSR = (1u << 8u); /* IC9 enable */
        DSB();
        *ccipr13 = (*ccipr13 & ~0x7u) | 0x2u; /* USART1SEL = ic9_ck */
        DSB();
    }

    uart_init();
    uart_ready = 1;

    icache_enable();
    mpu_configure_eth_nocache();
    dcache_enable();

    /* Initialize wolfIP stack */
    wolfIP_init_static(&IPStack);

    /* ETH init sequence — matching CubeN6 HAL MspInit order:
     * 1. Enable ETH clocks (AHB5)
     * 2. Set RMII mode (CCIPR2)
     * 3. Configure GPIO + RIMC + compensation
     * CubeN6 HAL: MspInit enables clocks → HAL_ETH_Init sets CCIPR2 → SWR → config */

    /* Step 1: Enable Ethernet clocks */
    RCC_AHB5ENSR = (1u << 22u) | (1u << 23u) | (1u << 24u);
    DSB();
    delay(10000);

    /* Step 1b: RCC peripheral reset of ETH1 — deeper than SWR */
    RCC_AHB5RSTR = (1u << 22u); /* Assert ETH1MAC reset */
    DSB();
    delay(10000);
    RCC_AHB5RSTR = 0;           /* Release reset */
    DSB();
    delay(10000);

    /* Step 2: Select RMII mode (external REF_CLK from PHY).
     * RCC_CCIPR2 fields (from Zephyr stm32n6_clock.h):
     *   ETH1PTP_SEL  [1:0]  = 0 (default)
     *   ETH1CLK_SEL  [13:12]= 0 (default, bus clock)
     *   ETH1_SEL     [18:16]= 4 (RMII mode)
     *   ETH1REFCLK_SEL [20] = 0 (external REF_CLK from PHY)
     *   ETH1GTXCLK_SEL [24] = 0 (default) */
    RCC_CCIPR2 |= RCC_CCIPR2_ETH1SEL_RMII;
    DSB();
    delay(10000);

    /* Step 3: GPIO and peripheral setup (AFTER clocks + RMII selection) */
    eth_gpio_init();
    delay(100000); /* Wait for PHY REF_CLK */

    /* Initialize Ethernet MAC + PHY */
    uart_puts("Initializing Ethernet MAC...\n");
    ll = wolfIP_getdev(IPStack);
    ret = stm32_eth_init(ll, NULL);
    if (ret < 0) {
        uart_puts("  ERROR: stm32_eth_init failed (");
        uart_puthex((uint32_t)ret);
        uart_puts(")\n");
    } else {
        uart_puts("  PHY link: ");
        uart_puts((ret & 0x100) ? "UP" : "DOWN");
        uart_puts(", PHY addr: ");
        uart_puthex(ret & 0xFF);
        uart_puts("\n  MAC: ");
        {
            int mi;
            for (mi = 0; mi < 6; mi++) {
                if (mi > 0) uart_puts(":");
                uart_puthex8(ll->mac[mi]);
            }
        }
        uart_puts("\n");
    }

    /* Static IP configuration */
    {
        ip4 ip = atoip4(WOLFIP_IP);
        ip4 nm = atoip4(WOLFIP_NETMASK);
        ip4 gw = atoip4(WOLFIP_GW);
        uart_puts("Setting IP configuration:\n");
        uart_puts("  IP: ");
        uart_putip4(ip);
        uart_puts("\n  Mask: ");
        uart_putip4(nm);
        uart_puts("\n  GW: ");
        uart_putip4(gw);
        uart_puts("\n");
        wolfIP_ipconfig_set(IPStack, ip, nm, gw);
    }

    /* TCP echo server on port 7 */
    uart_puts("Creating TCP socket on port 7...\n");
    listen_fd = wolfIP_sock_socket(IPStack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    wolfIP_register_callback(IPStack, listen_fd, echo_cb, IPStack);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(ECHO_PORT);
    addr.sin_addr.s_addr = 0;
    (void)wolfIP_sock_bind(IPStack, listen_fd, (struct wolfIP_sockaddr *)&addr,
        sizeof(addr));
    (void)wolfIP_sock_listen(IPStack, listen_fd, 1);

    uart_puts("Entering main loop. Ready for connections!\n");
    uart_puts("  TCP Echo: port 7\n");

    for (;;) {
        (void)wolfIP_poll(IPStack, tick++);

        /* Toggle LED every ~256K iterations as heartbeat */
        if ((tick & 0x3FFFFu) == 0) {
            led_toggle();
        }
    }
    return 0;
}

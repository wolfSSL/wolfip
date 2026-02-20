/* main.c
 *
 * STM32H753ZI wolfIP Echo Server / TLS Client
 *
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 */
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "wolfip.h"
#include "stm32_eth.h"

#ifdef ENABLE_TLS
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfcrypt/test/test.h>
#endif

#ifdef ENABLE_TLS_CLIENT
#include "tls_client.h"
#define GOOGLE_IP "142.250.189.174"
#define GOOGLE_HOST "www.google.com"
#define GOOGLE_HTTPS_PORT 443
static int tls_client_test_started = 0;
static int tls_client_test_done = 0;
#endif

#ifdef ENABLE_HTTPS
#include <stdio.h>
#include "http/httpd.h"
#include "../certs.h"
#define HTTPS_WEB_PORT 443
#endif

#ifdef ENABLE_MQTT_BROKER
#include "mqtt_broker.h"
extern volatile unsigned long broker_uptime_sec;
#endif

#ifdef ENABLE_HTTPS
/* HTTPS server using wolfIP httpd */
static struct httpd https_server;
static WOLFSSL_CTX *https_ssl_ctx;
static uint32_t https_uptime_sec;
static ip4 https_device_ip;

/* Status page handler */
static int https_status_handler(struct httpd *httpd, struct http_client *hc,
    struct http_request *req)
{
    char response[512];
    char ip_str[16];
    char uptime_str[12];
    int len;

    (void)httpd;
    (void)req;

    /* Format IP address (stored in network byte order) */
    {
        uint8_t *b = (uint8_t *)&https_device_ip;
        char *p = ip_str;
        int i;
        for (i = 3; i >= 0; i--) {
            int val = b[i];
            if (val >= 100) { *p++ = '0' + val / 100; val %= 100; }
            if (val >= 10 || b[i] >= 100) { *p++ = '0' + val / 10; val %= 10; }
            *p++ = '0' + val;
            if (i > 0) *p++ = '.';
        }
        *p = '\0';
    }

    /* Format uptime */
    {
        uint32_t val = https_uptime_sec;
        char tmp[12];
        int i = 0, j = 0;
        if (val == 0) { uptime_str[0] = '0'; uptime_str[1] = '\0'; }
        else {
            while (val > 0) { tmp[i++] = '0' + (val % 10); val /= 10; }
            while (i > 0) { uptime_str[j++] = tmp[--i]; }
            uptime_str[j] = '\0';
        }
    }

    /* Build HTML response */
    len = snprintf(response, sizeof(response),
        "<!DOCTYPE html><html><head><title>wolfIP STM32H753</title>"
        "<style>body{font-family:sans-serif;margin:40px;}"
        "h1{color:#333;}table{border-collapse:collapse;}"
        "td{padding:8px 16px;border:1px solid #ddd;}</style></head>"
        "<body><h1>wolfIP Status</h1><table>"
        "<tr><td>Device</td><td>STM32H753</td></tr>"
        "<tr><td>IP Address</td><td>%s</td></tr>"
        "<tr><td>Uptime</td><td>%s sec</td></tr>"
        "<tr><td>TLS</td><td>TLS 1.3</td></tr>"
        "</table></body></html>",
        ip_str, uptime_str);

    http_send_response_headers(hc, HTTP_STATUS_OK, "OK", "text/html", len);
    http_send_response_body(hc, response, len);
    return 0;
}
#endif

#define ECHO_PORT 7
#define RX_BUF_SIZE 1024

/* =========================================================================
 * STM32H753ZI Register Definitions
 * ========================================================================= */

/* RCC (Reset and Clock Control) - APB4 */
#define RCC_BASE            0x58024400UL
#define RCC_CR              (*(volatile uint32_t *)(RCC_BASE + 0x00))
#define RCC_HSICFGR         (*(volatile uint32_t *)(RCC_BASE + 0x04))
#define RCC_CRRCR           (*(volatile uint32_t *)(RCC_BASE + 0x08))
#define RCC_CFGR            (*(volatile uint32_t *)(RCC_BASE + 0x10))
#define RCC_D1CFGR          (*(volatile uint32_t *)(RCC_BASE + 0x18))
#define RCC_D2CFGR          (*(volatile uint32_t *)(RCC_BASE + 0x1C))
#define RCC_D3CFGR          (*(volatile uint32_t *)(RCC_BASE + 0x20))
#define RCC_PLLCKSELR       (*(volatile uint32_t *)(RCC_BASE + 0x28))
#define RCC_PLLCFGR         (*(volatile uint32_t *)(RCC_BASE + 0x2C))
#define RCC_PLL1DIVR        (*(volatile uint32_t *)(RCC_BASE + 0x30))
#define RCC_PLL1FRACR       (*(volatile uint32_t *)(RCC_BASE + 0x34))
#define RCC_AHB1ENR         (*(volatile uint32_t *)(RCC_BASE + 0xD8))
#define RCC_AHB2ENR         (*(volatile uint32_t *)(RCC_BASE + 0xDC))
#define RCC_AHB4ENR         (*(volatile uint32_t *)(RCC_BASE + 0xE0))
#define RCC_APB1LENR        (*(volatile uint32_t *)(RCC_BASE + 0xE8))
#define RCC_APB4ENR         (*(volatile uint32_t *)(RCC_BASE + 0xF4))
#define RCC_AHB1RSTR        (*(volatile uint32_t *)(RCC_BASE + 0x80))
#define RCC_AHB1RSTR_ETHRST (1u << 15)  /* ETH1MACRST is bit 15, NOT 25 */

/* RCC_CR bits */
#define RCC_CR_HSION        (1u << 0)
#define RCC_CR_HSIRDY       (1u << 2)
#define RCC_CR_HSEON        (1u << 16)
#define RCC_CR_HSERDY       (1u << 17)
#define RCC_CR_HSEBYP       (1u << 18)
#define RCC_CR_PLL1ON       (1u << 24)
#define RCC_CR_PLL1RDY      (1u << 25)

/* RCC_CFGR bits */
#define RCC_CFGR_SW_HSI     (0u << 0)
#define RCC_CFGR_SW_HSE     (2u << 0)
#define RCC_CFGR_SW_PLL1    (3u << 0)
#define RCC_CFGR_SW_MASK    (7u << 0)
#define RCC_CFGR_SWS_MASK   (7u << 3)
#define RCC_CFGR_SWS_PLL1   (3u << 3)

/* PWR (Power Control) */
#define PWR_BASE            0x58024800UL
#define PWR_CR3             (*(volatile uint32_t *)(PWR_BASE + 0x0C))
#define PWR_CR3_LDOEN       (1u << 1)
#define PWR_CR3_SCUEN       (1u << 2)
#define PWR_D3CR            (*(volatile uint32_t *)(PWR_BASE + 0x18))
#define PWR_D3CR_VOSRDY     (1u << 13)
#define PWR_D3CR_VOS_MASK   (3u << 14)
#define PWR_D3CR_VOS_SCALE1 (3u << 14)

/* RCC APB4ENR bits */
#define RCC_APB4ENR_PWREN   (1u << 4)

/* Flash */
#define FLASH_BASE          0x52002000UL
#define FLASH_ACR           (*(volatile uint32_t *)(FLASH_BASE + 0x00))
#define FLASH_ACR_LATENCY_4WS (4u << 0)
#define FLASH_ACR_WRHIGHFREQ_2 (2u << 4)

/* GPIO base addresses (APB4/AHB4) */
#define GPIOA_BASE          0x58020000UL
#define GPIOB_BASE          0x58020400UL
#define GPIOC_BASE          0x58020800UL
#define GPIOD_BASE          0x58020C00UL
#define GPIOE_BASE          0x58021000UL
#define GPIOF_BASE          0x58021400UL
#define GPIOG_BASE          0x58021800UL

/* GPIO register offsets */
#define GPIO_MODER(base)    (*(volatile uint32_t *)((base) + 0x00))
#define GPIO_OTYPER(base)   (*(volatile uint32_t *)((base) + 0x04))
#define GPIO_OSPEEDR(base)  (*(volatile uint32_t *)((base) + 0x08))
#define GPIO_PUPDR(base)    (*(volatile uint32_t *)((base) + 0x0C))
#define GPIO_IDR(base)      (*(volatile uint32_t *)((base) + 0x10))
#define GPIO_ODR(base)      (*(volatile uint32_t *)((base) + 0x14))
#define GPIO_BSRR(base)     (*(volatile uint32_t *)((base) + 0x18))
#define GPIO_AFRL(base)     (*(volatile uint32_t *)((base) + 0x20))
#define GPIO_AFRH(base)     (*(volatile uint32_t *)((base) + 0x24))

/* SYSCFG for RMII selection */
#define SYSCFG_BASE         0x58000400UL
#define SYSCFG_PMCR         (*(volatile uint32_t *)(SYSCFG_BASE + 0x04))
#define SYSCFG_PMCR_EPIS_RMII (4U << 21)

/* RNG (hardware random number generator) */
#define RNG_BASE            0x48021800UL
#define RNG_CR              (*(volatile uint32_t *)(RNG_BASE + 0x00))
#define RNG_SR              (*(volatile uint32_t *)(RNG_BASE + 0x04))
#define RNG_DR              (*(volatile uint32_t *)(RNG_BASE + 0x08))
#define RNG_CR_RNGEN        (1u << 2)
#define RNG_SR_DRDY         (1u << 0)
#define RNG_SR_CECS         (1u << 1)
#define RNG_SR_SECS         (1u << 2)

/* USART3 for debug output (ST-Link VCP on NUCLEO-H753ZI: PD8=TX, PD9=RX) */
#define USART3_BASE         0x40004800UL
#define USART3_CR1          (*(volatile uint32_t *)(USART3_BASE + 0x00))
#define USART3_CR2          (*(volatile uint32_t *)(USART3_BASE + 0x04))
#define USART3_CR3          (*(volatile uint32_t *)(USART3_BASE + 0x08))
#define USART3_BRR          (*(volatile uint32_t *)(USART3_BASE + 0x0C))
#define USART3_ISR          (*(volatile uint32_t *)(USART3_BASE + 0x1C))
#define USART3_TDR          (*(volatile uint32_t *)(USART3_BASE + 0x28))

/* LED on NUCLEO-H753ZI: PB0 (LD1 Green), PB7 (LD2 Blue), PB14 (LD3 Red) */
#define LED1_PIN 0u   /* PB0 - Green */
#define LED2_PIN 7u   /* PB7 - Blue */
#define LED3_PIN 14u  /* PB14 - Red */

/* =========================================================================
 * HardFault Handler - prints crash info via UART
 * ========================================================================= */
#define SCB_HFSR   (*(volatile uint32_t *)0xE000ED2CUL)
#define SCB_CFSR   (*(volatile uint32_t *)0xE000ED28UL)
#define SCB_BFAR   (*(volatile uint32_t *)0xE000ED38UL)
#define SCB_MMFAR  (*(volatile uint32_t *)0xE000ED34UL)

static void fault_uart_putc(char c)
{
    while ((USART3_ISR & (1u << 7)) == 0) { }
    USART3_TDR = (uint32_t)c;
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
    /* Blink red LED */
    GPIO_BSRR(GPIOB_BASE) = (1u << LED3_PIN);
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
 * Global Variables
 * ========================================================================= */
static struct wolfIP *IPStack;
static int listen_fd = -1;
static int client_fd = -1;
static uint8_t rx_buf[RX_BUF_SIZE];

/* =========================================================================
 * Helper Functions
 * ========================================================================= */

/* Initialize STM32H7 hardware RNG */
static void rng_init(void)
{
    volatile uint32_t *rcc_cr = (volatile uint32_t *)(RCC_BASE + 0x00);
    volatile uint32_t *rcc_d2ccip2r = (volatile uint32_t *)(RCC_BASE + 0x54);
    uint32_t timeout;

    /* Enable HSI48 oscillator (RNG kernel clock source) */
    *rcc_cr |= (1u << 12);  /* HSI48ON */
    timeout = 100000;
    while (!(*rcc_cr & (1u << 13)) && --timeout) { }  /* Wait HSI48RDY */

    /* Select HSI48 as RNG clock: RCC_D2CCIP2R bits[9:8] = 00 (HSI48) */
    *rcc_d2ccip2r &= ~(3u << 8);

    /* Enable RNG clock (AHB2, bit 6) */
    RCC_AHB2ENR |= (1u << 6);
    /* Small delay for clock to stabilize */
    for (volatile int i = 0; i < 100; i++) { }
    /* Enable RNG */
    RNG_CR = RNG_CR_RNGEN;
}

/* Get one 32-bit random word from hardware RNG */
static int rng_get_word(uint32_t *out)
{
    uint32_t timeout = 10000;
    /* Wait for data ready */
    while ((RNG_SR & RNG_SR_DRDY) == 0) {
        if (--timeout == 0)
            return -1;
        /* Check for errors */
        if (RNG_SR & (RNG_SR_CECS | RNG_SR_SECS)) {
            /* Reset RNG on error */
            RNG_CR = 0;
            for (volatile int i = 0; i < 100; i++) { }
            RNG_CR = RNG_CR_RNGEN;
            timeout = 10000;
        }
    }
    *out = RNG_DR;
    return 0;
}

/* Required by wolfSSL (CUSTOM_RAND_GENERATE_BLOCK) */
int custom_rand_gen_block(unsigned char *output, unsigned int sz)
{
    uint32_t word;
    while (sz >= 4) {
        if (rng_get_word(&word) != 0)
            return -1;
        output[0] = (unsigned char)(word);
        output[1] = (unsigned char)(word >> 8);
        output[2] = (unsigned char)(word >> 16);
        output[3] = (unsigned char)(word >> 24);
        output += 4;
        sz -= 4;
    }
    if (sz > 0) {
        if (rng_get_word(&word) != 0)
            return -1;
        while (sz--) {
            *output++ = (unsigned char)(word);
            word >>= 8;
        }
    }
    return 0;
}

/* Required by wolfIP */
uint32_t wolfIP_getrandom(void)
{
    uint32_t val;
    if (rng_get_word(&val) == 0)
        return val;
    /* Fallback LFSR if HW RNG fails */
    static uint32_t lfsr = 0x1A2B3C4DU;
    lfsr ^= lfsr << 13;
    lfsr ^= lfsr >> 17;
    lfsr ^= lfsr << 5;
    return lfsr;
}

static void delay(uint32_t count)
{
    for (volatile uint32_t i = 0; i < count; i++) { }
}

/* =========================================================================
 * System Clock Configuration (HSE + PLL = 400MHz like SDK)
 *
 * NUCLEO-H753ZI has 8MHz HSE from ST-Link MCO
 * Configure: SYSCLK=400MHz, HCLK=200MHz, APBx=100MHz
 * ========================================================================= */
static int system_clock_config(void)
{
    uint32_t timeout;

    /* 0. Enable PWR clock first */
    RCC_APB4ENR |= RCC_APB4ENR_PWREN;
    __asm volatile ("dsb sy" ::: "memory");
    delay(100);

    /* 1. Ensure LDO is enabled (default after reset, but be sure) */
    PWR_CR3 |= PWR_CR3_LDOEN;
    PWR_CR3 &= ~PWR_CR3_SCUEN;  /* Disable supply configuration update */
    delay(100);

    /* 2. Set voltage scaling to Scale 1 (highest performance) */
    PWR_D3CR = (PWR_D3CR & ~PWR_D3CR_VOS_MASK) | PWR_D3CR_VOS_SCALE1;
    timeout = 100000;
    while (((PWR_D3CR & PWR_D3CR_VOSRDY) == 0) && --timeout) {}
    if (timeout == 0) return -1;

    /* 2. Enable D2 SRAM1/2/3 clocks (ETH DMA buffers are in D2 SRAM1 @ 0x30000000) */
    RCC_AHB2ENR |= (1u << 29) | (1u << 30) | (1u << 31);

    /* 3. Enable HSE with bypass (8MHz from ST-Link) */
    RCC_CR |= RCC_CR_HSEBYP;
    RCC_CR |= RCC_CR_HSEON;
    timeout = 100000;
    while (((RCC_CR & RCC_CR_HSERDY) == 0) && --timeout) {}
    if (timeout == 0) return -2;

    /* 4. Configure PLL1
     * Source: HSE (8MHz)
     * DIVM1 = 4  -> VCO input = 8/4 = 2MHz
     * DIVN1 = 400 -> VCO output = 2*400 = 800MHz
     * DIVP1 = 2  -> PLL1P = 800/2 = 400MHz (SYSCLK)
     * DIVQ1 = 4  -> PLL1Q = 800/4 = 200MHz
     * DIVR1 = 2  -> PLL1R = 800/2 = 400MHz
     */

    /* Disable PLL1 first */
    RCC_CR &= ~RCC_CR_PLL1ON;
    timeout = 100000;
    while ((RCC_CR & RCC_CR_PLL1RDY) && --timeout) {}

    /* PLL1 clock source = HSE, DIVM1 = 4 */
    RCC_PLLCKSELR = (4u << 4) |   /* DIVM1 = 4 */
                    (2u << 0);    /* PLLSRC = HSE */

    /* PLL1 configuration: wide VCO range, integer mode */
    RCC_PLLCFGR = (RCC_PLLCFGR & ~0x1FFu) |
                  (1u << 0) |     /* PLL1FRACEN = 0, then set DIVPEN etc */
                  (1u << 16) |    /* DIVP1EN */
                  (1u << 17) |    /* DIVQ1EN */
                  (1u << 18) |    /* DIVR1EN */
                  (2u << 2);      /* PLL1RGE = 2 (2-4MHz range) */
    RCC_PLLCFGR |= (1u << 1);     /* PLL1VCOSEL = 0 (wide VCO 192-836MHz) */
    RCC_PLLCFGR &= ~(1u << 1);    /* Clear for wide range */

    /* DIVN1=400, DIVP1=2, DIVQ1=4, DIVR1=2 (all -1 in register) */
    RCC_PLL1DIVR = ((2u - 1u) << 24) |   /* DIVR1 = 2 */
                   ((4u - 1u) << 16) |   /* DIVQ1 = 4 */
                   ((2u - 1u) << 9) |    /* DIVP1 = 2 */
                   ((400u - 1u) << 0);   /* DIVN1 = 400 */

    /* Clear fractional divider */
    RCC_PLL1FRACR = 0;

    /* 5. Enable PLL1 */
    RCC_CR |= RCC_CR_PLL1ON;
    timeout = 100000;
    while (((RCC_CR & RCC_CR_PLL1RDY) == 0) && --timeout) {}
    if (timeout == 0) return -3;

    /* 6. Configure Flash latency for 400MHz (4 wait states) */
    FLASH_ACR = FLASH_ACR_LATENCY_4WS | FLASH_ACR_WRHIGHFREQ_2;

    /* 7. Configure bus dividers
     * D1CPRE = /1 (SYSCLK = 400MHz)
     * HPRE = /2 (HCLK = 200MHz)  <- AHB clock for Ethernet
     * D1PPRE = /2 (APB3 = 100MHz)
     */
    RCC_D1CFGR = (0u << 8) |      /* D1CPRE = /1 */
                 (8u << 4) |      /* D1PPRE = /2 (8 = div2) */
                 (8u << 0);       /* HPRE = /2 */

    /* D2PPRE1 = /2, D2PPRE2 = /2 (APB1, APB2 = 100MHz) */
    RCC_D2CFGR = (4u << 8) |      /* D2PPRE2 = /2 */
                 (4u << 4);       /* D2PPRE1 = /2 */

    /* D3PPRE = /2 (APB4 = 100MHz) */
    RCC_D3CFGR = (4u << 4);       /* D3PPRE = /2 */

    /* 8. Switch system clock to PLL1 */
    RCC_CFGR = (RCC_CFGR & ~RCC_CFGR_SW_MASK) | RCC_CFGR_SW_PLL1;
    timeout = 100000;
    while (((RCC_CFGR & RCC_CFGR_SWS_MASK) != RCC_CFGR_SWS_PLL1) && --timeout) {}
    if (timeout == 0) return -4;

    return 0;  /* Success: SYSCLK=400MHz, HCLK=200MHz */
}

/* =========================================================================
 * LED Functions
 * ========================================================================= */

static void led_init(void)
{
    uint32_t moder;

    /* Enable GPIOB clock */
    RCC_AHB4ENR |= (1u << 1);
    delay(100);

    /* Set PB0, PB7, PB14 as outputs */
    moder = GPIO_MODER(GPIOB_BASE);
    moder &= ~((3u << (LED1_PIN * 2)) | (3u << (LED2_PIN * 2)) | (3u << (LED3_PIN * 2)));
    moder |= (1u << (LED1_PIN * 2)) | (1u << (LED2_PIN * 2)) | (1u << (LED3_PIN * 2));
    GPIO_MODER(GPIOB_BASE) = moder;
}

static void led_green_on(void)                     { GPIO_BSRR(GPIOB_BASE) = (1u << LED1_PIN); }
static void __attribute__((unused)) led_green_off(void) { GPIO_BSRR(GPIOB_BASE) = (1u << (LED1_PIN + 16)); }
static void led_blue_on(void)                      { GPIO_BSRR(GPIOB_BASE) = (1u << LED2_PIN); }
static void led_blue_off(void)                     { GPIO_BSRR(GPIOB_BASE) = (1u << (LED2_PIN + 16)); }
static void led_red_on(void)                       { GPIO_BSRR(GPIOB_BASE) = (1u << LED3_PIN); }
static void led_red_off(void)                      { GPIO_BSRR(GPIOB_BASE) = (1u << (LED3_PIN + 16)); }

static void led_toggle_green(void) { GPIO_ODR(GPIOB_BASE) ^= (1u << LED1_PIN); }

/* =========================================================================
 * UART Functions
 * ========================================================================= */

/* Early UART init using 64MHz HSI (before clock config) */
static void uart_init_early(void)
{
    uint32_t moder, afr;

    /* Enable GPIOD and USART3 clocks */
    RCC_AHB4ENR |= (1u << 3);   /* GPIOD */
    RCC_APB1LENR |= (1u << 18); /* USART3 */
    delay(100);

    /* Configure PD8 (TX) as AF7 (USART3_TX) */
    moder = GPIO_MODER(GPIOD_BASE);
    moder &= ~(3u << 16);  /* Clear PD8 mode */
    moder |= (2u << 16);   /* Alternate function */
    GPIO_MODER(GPIOD_BASE) = moder;

    GPIO_OSPEEDR(GPIOD_BASE) |= (3u << 16);  /* High speed for PD8 */

    /* AFRH: PD8 is bit 0-3 */
    afr = GPIO_AFRH(GPIOD_BASE);
    afr &= ~(0xFu << 0);
    afr |= (7u << 0);  /* AF7 = USART3 */
    GPIO_AFRH(GPIOD_BASE) = afr;

    /* Configure USART3: 115200 baud at 64MHz HSI */
    USART3_CR1 = 0;
    USART3_CR2 = 0;
    USART3_CR3 = 0;
    USART3_BRR = 64000000u / 115200u;  /* ~556 for 64MHz HSI */

    /* Enable transmitter and USART */
    USART3_CR1 = (1u << 3);  /* TE */
    delay(10);
    USART3_CR1 |= (1u << 0); /* UE */
    delay(100);
}

/* Reconfigure UART for 100MHz APB1 (after clock config) */
static void uart_reconfigure(void)
{
    /* Disable USART first */
    USART3_CR1 &= ~(1u << 0);
    delay(10);

    /* Reconfigure BRR for 100MHz APB1 */
    USART3_BRR = 100000000u / 115200u;  /* ~868 for 100MHz APB1 */

    /* Re-enable */
    USART3_CR1 |= (1u << 0);
    delay(10);
}

static void uart_putc(char c)
{
    while ((USART3_ISR & (1u << 7)) == 0) { }  /* Wait for TXE */
    USART3_TDR = (uint32_t)c;
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

/* =========================================================================
 * Ethernet GPIO Configuration for NUCLEO-H753ZI
 * ========================================================================= */

/* Configure a GPIO pin for Ethernet alternate function (AF11) */
static void gpio_eth_pin(uint32_t base, uint32_t pin)
{
    uint32_t moder, ospeedr, afr;
    uint32_t pos2 = pin * 2u;

    /* Set mode to alternate function (0b10) */
    moder = GPIO_MODER(base);
    moder &= ~(3u << pos2);
    moder |= (2u << pos2);
    GPIO_MODER(base) = moder;

    /* Set high speed */
    ospeedr = GPIO_OSPEEDR(base);
    ospeedr |= (3u << pos2);
    GPIO_OSPEEDR(base) = ospeedr;

    /* Set AF11 for Ethernet */
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

/* Initialize GPIO pins for RMII Ethernet (NUCLEO-H753ZI pinout) */
static void eth_gpio_init(void)
{
    uint32_t val;

    /* Enable GPIO clocks: A, B, C, G */
    RCC_AHB4ENR |= (1u << 0) | (1u << 1) | (1u << 2) | (1u << 6);

    /* Enable SYSCFG clock for RMII selection */
    RCC_APB4ENR |= (1u << 1);

    delay(1000);

    /* Set RMII mode in SYSCFG_PMCR and close analog switches.
     * STM32H7 PA0/PA1/PC2/PC3 have analog switches that default to OPEN,
     * which disconnects the digital AF path. PA1 is ETH_REF_CLK - the MAC
     * requires this 50MHz clock to function (registers read 0 without it).
     * Also enable the I/O booster for high-speed Ethernet signals. */
    val = SYSCFG_PMCR;
    val &= ~((0x7u << 21) |         /* Clear EPIS bits */
             (1u << 24) |            /* Close PA0 analog switch */
             (1u << 25) |            /* Close PA1 analog switch (ETH_REF_CLK!) */
             (1u << 26) |            /* Close PC2 analog switch */
             (1u << 27));            /* Close PC3 analog switch */
    val |= SYSCFG_PMCR_EPIS_RMII |  /* Set RMII mode */
           (1u << 8);               /* BOOSTE: enable I/O booster */
    SYSCFG_PMCR = val;

    /* Critical: dummy read forces APB4 write to complete before ETH
     * clock enable (STM32CubeH7 Issue #121). Without this, the RMII
     * mux may not be selected when the MAC first sees its clocks. */
    (void)SYSCFG_PMCR;
    __asm volatile ("dsb sy" ::: "memory");

    delay(1000);

    /* Configure RMII pins for NUCLEO-H753ZI:
     * PA1  - ETH_REF_CLK (AF11)
     * PA2  - ETH_MDIO (AF11)
     * PA7  - ETH_CRS_DV (AF11)
     * PC1  - ETH_MDC (AF11)
     * PC4  - ETH_RXD0 (AF11)
     * PC5  - ETH_RXD1 (AF11)
     * PB13 - ETH_TXD1 (AF11)  <-- Note: Different from H563!
     * PG11 - ETH_TX_EN (AF11)
     * PG13 - ETH_TXD0 (AF11)
     */
    gpio_eth_pin(GPIOA_BASE, 1);   /* REF_CLK */
    gpio_eth_pin(GPIOA_BASE, 2);   /* MDIO */
    gpio_eth_pin(GPIOA_BASE, 7);   /* CRS_DV */
    gpio_eth_pin(GPIOC_BASE, 1);   /* MDC */
    gpio_eth_pin(GPIOC_BASE, 4);   /* RXD0 */
    gpio_eth_pin(GPIOC_BASE, 5);   /* RXD1 */
    gpio_eth_pin(GPIOB_BASE, 13);  /* TXD1 */
    gpio_eth_pin(GPIOG_BASE, 11);  /* TX_EN */
    gpio_eth_pin(GPIOG_BASE, 13);  /* TXD0 */
}

/* =========================================================================
 * TLS Client Callback
 * ========================================================================= */

#ifdef ENABLE_TLS_CLIENT
static void tls_response_cb(const char *data, int len, void *ctx)
{
    (void)ctx;
    uart_puts("TLS Client received ");
    uart_putdec((uint32_t)len);
    uart_puts(" bytes:\n");

    /* Print first 200 chars of response */
    for (int i = 0; i < len && i < 200; i++) {
        uart_putc(data[i]);
    }
    if (len > 200) {
        uart_puts("\n... (truncated)\n");
    }
    uart_puts("\n");
    tls_client_test_done = 1;
}
#endif

/* =========================================================================
 * TCP Echo Server Callback
 * ========================================================================= */

static void echo_cb(int fd, uint16_t event, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    int ret;

    if ((fd == listen_fd) && (event & CB_EVENT_READABLE) && (client_fd == -1)) {
        client_fd = wolfIP_sock_accept(s, listen_fd, NULL, NULL);
        if (client_fd > 0) {
            wolfIP_register_callback(s, client_fd, echo_cb, s);
            led_blue_on();  /* Client connected */
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
            led_blue_off();
        }
    }

    if ((fd == client_fd) && (event & CB_EVENT_CLOSED)) {
        wolfIP_sock_close(s, client_fd);
        client_fd = -1;
        led_blue_off();
    }
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void)
{
    struct wolfIP_ll_dev *ll;
    struct wolfIP_sockaddr_in addr;
    uint64_t tick = 0;
    int ret;

    /* Initialize LEDs first - Green ON to show code is running */
    led_init();
    led_green_on();

    /* Early UART init at 64MHz HSI for debugging */
    uart_init_early();
    uart_puts("\n\n=== Clock Config Debug ===\n");
    uart_puts("Running at 64MHz HSI...\n");
    uart_puts("Configuring HSE + PLL (400MHz)...\n");

    /* Configure system clock: HSE + PLL -> 400MHz SYSCLK, 200MHz HCLK */
    ret = system_clock_config();
    if (ret != 0) {
        /* Clock config failed - print error and blink red LED */
        uart_puts("CLOCK CONFIG FAILED! Error: ");
        uart_puthex((uint32_t)ret);
        uart_puts("\n");
        led_red_on();
        while (1) {
            led_red_on();
            delay(500000);
            led_red_off();
            delay(500000);
        }
    }

    /* Reconfigure UART for 100MHz APB1 */
    uart_reconfigure();
    uart_puts("Clock config OK! Now at 400MHz SYSCLK, 200MHz HCLK\n");

    led_green_on();
    led_blue_off();
    led_red_off();

    /* Initialize hardware RNG */
    rng_init();
    {
        uint32_t rng_test;
        int rng_ok = rng_get_word(&rng_test);
        uart_puts("RNG init: ");
        uart_puts(rng_ok == 0 ? "OK" : "FAILED");
        if (rng_ok == 0) {
            uart_puts(" val="); uart_puthex(rng_test);
        }
        uart_puts("\n");
    }

#ifdef ENABLE_TLS
#ifdef DEBUG_HW
    /* Direct bare-metal HASH test - bypass wolfSSL entirely */
    uart_puts("\n--- Direct HASH Hardware Test ---\n");
    {
        volatile uint32_t *hash_cr  = (volatile uint32_t *)0x48021400UL;
        volatile uint32_t *hash_str = (volatile uint32_t *)0x48021408UL;
        volatile uint32_t *hash_hr  = (volatile uint32_t *)0x4802140CUL;
        volatile uint32_t *hash_sr  = (volatile uint32_t *)0x48021424UL;
        uint32_t timeout;
        int algo_idx;

        /* Enable HASH clock (AHB2 bit 5) */
        RCC_AHB2ENR |= (1u << 5);
        (void)RCC_AHB2ENR;
        for (volatile int d = 0; d < 1000; d++) {}

        /* Test hash of empty message with all 4 ALGO settings.
         * Expected digests (first word, big-endian in HR[0]):
         *   MD5("")    = d41d8cd9... → HR[0]=0xd98c1dd4
         *   SHA-1("")  = da39a3ee... → HR[0]=0xeea339da
         *   SHA-224("") = d14a028c... → HR[0]=0x8c024ad1 (if supported)
         *   SHA-256("") = e3b0c442... → HR[0]=0x42c4b0e3
         */
        struct { uint32_t bits; const char *name; } algos[4] = {
            { 0x00000000, "MD5    (ALGO=00)" },
            { 0x00000080, "SHA-1  (ALGO=01)" },
            { 0x00040000, "SHA-224(ALGO=10)" },
            { 0x00040080, "SHA-256(ALGO=11)" },
        };

        for (algo_idx = 0; algo_idx < 4; algo_idx++) {
            uart_puts("  ");
            uart_puts(algos[algo_idx].name);
            uart_puts(": CR=");

            /* Configure and init: algo + DATATYPE_8B + INIT */
            *hash_cr = algos[algo_idx].bits | 0x20 | 0x04;
            uart_puthex(*hash_cr);

            /* Set NBLW=0 (all bits valid) and trigger DCAL */
            *hash_str = 0;
            *hash_str = (1u << 8);  /* DCAL */

            /* Wait for digest complete */
            timeout = 100000;
            while ((*hash_sr & (1u << 1)) == 0 && --timeout) {}

            uart_puts(" HR0=");
            uart_puthex(hash_hr[0]);
            uart_puts(" HR1=");
            uart_puthex(hash_hr[1]);
            uart_puts(timeout == 0 ? " TIMEOUT" : " OK");
            uart_puts("\n");
        }

        /* Keep HASH clock enabled */
    }
#endif /* DEBUG_HW */

#ifdef DEBUG_HW
    /* Run wolfCrypt test to validate all crypto algorithms.
     * This confirms hardware HASH/HMAC is working correctly. */
    uart_puts("\n--- Running wolfCrypt Test ---\n");
    {
        typedef struct func_args {
            int    argc;
            char** argv;
            int    return_code;
        } func_args;
        func_args args;
        args.argc = 0;
        args.argv = NULL;
        args.return_code = 0;

        wolfCrypt_Init();
        wolfcrypt_test(&args);

        uart_puts("wolfCrypt Test: Return code ");
        if (args.return_code < 0) {
            uart_puts("-");
            uart_putdec((uint32_t)(-args.return_code));
        } else {
            uart_putdec((uint32_t)args.return_code);
        }
        uart_puts(args.return_code == 0 ? " (PASSED)\n" : " (FAILED)\n");
        wolfCrypt_Cleanup();

        if (args.return_code != 0) {
            uart_puts("ERROR: wolfCrypt test failed! Halting.\n");
            led_red_on();
            while (1) { }
        }
    }
#else
    wolfCrypt_Init();
#endif /* DEBUG_HW */
#endif /* ENABLE_TLS */

    uart_puts("\n\n=== wolfIP STM32H753ZI Echo Server ===\n");

#ifdef DEBUG_HW
    /* Read chip revision - critical for errata */
    uart_puts("Chip ID:\n");
    {
        volatile uint32_t *dbgmcu_idc = (volatile uint32_t *)(0x5C001000UL);
        uint32_t idc = *dbgmcu_idc;
        uart_puts("  DBGMCU_IDCODE: "); uart_puthex(idc); uart_puts("\n");
        uart_puts("  DEV_ID: "); uart_puthex(idc & 0xFFF);
        uart_puts(" REV_ID: "); uart_puthex((idc >> 16) & 0xFFFF);
        uart_puts("\n");
    }

    /* Dump clock prescaler config */
    uart_puts("Clock prescalers:\n");
    uart_puts("  RCC_D1CFGR: "); uart_puthex(*(volatile uint32_t *)(RCC_BASE + 0x18));
    uart_puts("\n");
    uart_puts("  RCC_D2CFGR: "); uart_puthex(*(volatile uint32_t *)(RCC_BASE + 0x1C));
    uart_puts("\n");
    uart_puts("  RCC_D3CFGR: "); uart_puthex(*(volatile uint32_t *)(RCC_BASE + 0x20));
    uart_puts("\n");
#endif

    uart_puts("Initializing wolfIP stack...\n");
    wolfIP_init_static(&IPStack);

    /* ================================================================
     * ETH Init: GPIO/SYSCFG first, then wait for PHY, then clocks.
     *
     * The LAN8742A PHY needs up to 167ms after hardware reset (which
     * is tied to NRST on the Nucleo board) to start outputting a
     * stable 50MHz REF_CLK. We must wait for this before enabling
     * the ETH MAC clocks, since the MAC's register interface won't
     * respond without a valid reference clock.
     *
     * Also enable the SYSCFG I/O compensation cell (required for
     * BOOSTE to take effect per RM0433).
     * ================================================================ */

    /* Step 1: Configure GPIO + SYSCFG RMII mode */
    eth_gpio_init();

#ifdef DEBUG_HW
    /* Verify GPIO config IMMEDIATELY after eth_gpio_init() */
    uart_puts("GPIO verification (after eth_gpio_init):\n");
    {
        uint32_t moder_a = GPIO_MODER(GPIOA_BASE);
        uint32_t afrl_a  = GPIO_AFRL(GPIOA_BASE);
        uint32_t moder_c = GPIO_MODER(GPIOC_BASE);
        uint32_t afrl_c  = GPIO_AFRL(GPIOC_BASE);
        uint32_t moder_g = GPIO_MODER(GPIOG_BASE);
        uint32_t afrh_g  = GPIO_AFRH(GPIOG_BASE);
        uint32_t moder_b = GPIO_MODER(GPIOB_BASE);
        uint32_t afrh_b  = GPIO_AFRH(GPIOB_BASE);
        uint32_t pmcr    = SYSCFG_PMCR;

        uart_puts("  GPIOA MODER: "); uart_puthex(moder_a);
        uart_puts("  AFRL: "); uart_puthex(afrl_a); uart_puts("\n");
        /* PA1: MODER[3:2]=10(AF), AFRL[7:4]=0xB(AF11) */
        uart_puts("    PA1 mode="); uart_puthex((moder_a >> 2) & 3);
        uart_puts(" af="); uart_puthex((afrl_a >> 4) & 0xF);
        uart_puts((((moder_a >> 2) & 3) == 2 && ((afrl_a >> 4) & 0xF) == 11) ?
                  " OK\n" : " WRONG!\n");
        /* PA2: MODER[5:4]=10, AFRL[11:8]=0xB */
        uart_puts("    PA2 mode="); uart_puthex((moder_a >> 4) & 3);
        uart_puts(" af="); uart_puthex((afrl_a >> 8) & 0xF);
        uart_puts((((moder_a >> 4) & 3) == 2 && ((afrl_a >> 8) & 0xF) == 11) ?
                  " OK\n" : " WRONG!\n");
        /* PA7: MODER[15:14]=10, AFRL[31:28]=0xB */
        uart_puts("    PA7 mode="); uart_puthex((moder_a >> 14) & 3);
        uart_puts(" af="); uart_puthex((afrl_a >> 28) & 0xF);
        uart_puts((((moder_a >> 14) & 3) == 2 && ((afrl_a >> 28) & 0xF) == 11) ?
                  " OK\n" : " WRONG!\n");

        uart_puts("  GPIOC MODER: "); uart_puthex(moder_c);
        uart_puts("  AFRL: "); uart_puthex(afrl_c); uart_puts("\n");
        /* PC1: MODER[3:2]=10, AFRL[7:4]=0xB */
        uart_puts("    PC1 mode="); uart_puthex((moder_c >> 2) & 3);
        uart_puts(" af="); uart_puthex((afrl_c >> 4) & 0xF);
        uart_puts((((moder_c >> 2) & 3) == 2 && ((afrl_c >> 4) & 0xF) == 11) ?
                  " OK\n" : " WRONG!\n");

        uart_puts("  GPIOB MODER: "); uart_puthex(moder_b);
        uart_puts("  AFRH: "); uart_puthex(afrh_b); uart_puts("\n");
        /* PB13: MODER[27:26]=10, AFRH[23:20]=0xB */
        uart_puts("    PB13 mode="); uart_puthex((moder_b >> 26) & 3);
        uart_puts(" af="); uart_puthex((afrh_b >> 20) & 0xF);
        uart_puts((((moder_b >> 26) & 3) == 2 && ((afrh_b >> 20) & 0xF) == 11) ?
                  " OK\n" : " WRONG!\n");

        uart_puts("  GPIOG MODER: "); uart_puthex(moder_g);
        uart_puts("  AFRH: "); uart_puthex(afrh_g); uart_puts("\n");
        /* PG11: MODER[23:22]=10, AFRH[15:12]=0xB */
        uart_puts("    PG11 mode="); uart_puthex((moder_g >> 22) & 3);
        uart_puts(" af="); uart_puthex((afrh_g >> 12) & 0xF);
        uart_puts((((moder_g >> 22) & 3) == 2 && ((afrh_g >> 12) & 0xF) == 11) ?
                  " OK\n" : " WRONG!\n");
        /* PG13: MODER[27:26]=10, AFRH[23:20]=0xB */
        uart_puts("    PG13 mode="); uart_puthex((moder_g >> 26) & 3);
        uart_puts(" af="); uart_puthex((afrh_g >> 20) & 0xF);
        uart_puts((((moder_g >> 26) & 3) == 2 && ((afrh_g >> 20) & 0xF) == 11) ?
                  " OK\n" : " WRONG!\n");

        uart_puts("  SYSCFG_PMCR: "); uart_puthex(pmcr);
        uart_puts(" EPIS="); uart_puthex((pmcr >> 21) & 7);
        uart_puts((((pmcr >> 21) & 7) == 4) ? " (RMII OK)" : " (WRONG!)");
        uart_puts(" switches="); uart_puthex((pmcr >> 24) & 0xF);
        uart_puts((((pmcr >> 24) & 0xF) == 0) ? " (closed OK)\n" : " (OPEN!)\n");
    }
#endif

    /* Step 2: Wait for PHY REF_CLK to stabilize after board reset.
     * LAN8742A power-on reset takes up to 167ms. We wait ~200ms to
     * be safe. The MAC needs REF_CLK for register access.
     * Calibration: volatile loop ~80ns/iter at 400MHz (12500 iters/ms) */
    delay(2500000);  /* ~200ms */
#ifdef DEBUG_HW
    {
        uint32_t pa1_samples = 0;
        int i;
        for (i = 0; i < 32; i++) {
            if (GPIO_IDR(GPIOA_BASE) & (1u << 1))
                pa1_samples |= (1u << i);
        }
        uart_puts("  PA1 (REF_CLK): "); uart_puthex(pa1_samples);
        uart_puts(pa1_samples == 0 ? " (ALL LOW!)\n" :
                   pa1_samples == 0xFFFFFFFF ? " (ALL HIGH!)\n" :
                   " (toggling OK)\n");
    }
#endif

    /* Step 3: Enable ETH clocks.
     * CRITICAL: ETH clock bits are 15,16,17 in AHB1ENR (NOT 25,26,27!)
     *   Bit 15: ETH1MACEN  (bus interface clock)
     *   Bit 16: ETH1TXEN   (TX clock, from REF_CLK in RMII)
     *   Bit 17: ETH1RXEN   (RX clock, from REF_CLK in RMII)
     * Bits 25-27 are USB OTG clocks - not ETH! */
    RCC_AHB1ENR |= (1u << 15) | (1u << 16) | (1u << 17);
    __asm volatile ("dsb sy" ::: "memory");
    delay(12500);  /* ~1ms for clocks to stabilize */

    /* Step 4: RCC reset ETH MAC (bit 15 in AHB1RSTR) */
    RCC_AHB1RSTR |= RCC_AHB1RSTR_ETHRST;
    __asm volatile ("dsb sy" ::: "memory");
    delay(12500);  /* ~1ms reset pulse */
    RCC_AHB1RSTR &= ~RCC_AHB1RSTR_ETHRST;
    __asm volatile ("dsb sy" ::: "memory");
    delay(125000);  /* ~10ms post-reset stabilization */

    uart_puts("Initializing Ethernet MAC...\n");
    ll = wolfIP_getdev(IPStack);
    ret = stm32_eth_init(ll, NULL);
    if (ret < 0) {
        uart_puts("  ERROR: stm32_eth_init failed (");
        uart_puthex((uint32_t)ret);
        uart_puts(")\n");
        led_red_on();
    } else {
        uart_puts("  PHY link: ");
        uart_puts((ret & 0x100) ? "UP" : "DOWN");
        uart_puts(", PHY addr: ");
        uart_puthex(ret & 0xFF);
        uart_puts("\n");
    }

#ifdef DEBUG_HW
    /* Debug: Read MDIO registers post-init */
    uart_puts("MDIO Debug (post-init register state):\n");
    {
        volatile uint32_t *macmdioar = (volatile uint32_t *)(0x40028000UL + 0x0200U);
        volatile uint32_t *macmdiodr = (volatile uint32_t *)(0x40028000UL + 0x0204U);
        volatile uint32_t *maccr     = (volatile uint32_t *)(0x40028000UL + 0x0000U);
        volatile uint32_t *dmamr     = (volatile uint32_t *)(0x40028000UL + 0x1000U);
        uint32_t cfg, timeout;

        uart_puts("  MACCR:     "); uart_puthex(*maccr); uart_puts("\n");
        uart_puts("  DMAMR:     "); uart_puthex(*dmamr); uart_puts("\n");
        uart_puts("  MACMDIOAR: "); uart_puthex(*macmdioar); uart_puts("\n");
        uart_puts("  MACMDIODR: "); uart_puthex(*macmdiodr); uart_puts("\n");
        uart_puts("  RCC_AHB1ENR: "); uart_puthex(RCC_AHB1ENR); uart_puts("\n");
        uart_puts("  RCC_AHB2ENR: "); uart_puthex(RCC_AHB2ENR); uart_puts("\n");
        uart_puts("  SYSCFG_PMCR: "); uart_puthex(SYSCFG_PMCR); uart_puts("\n");

        /* Try MDIO read of PHY ID1 (reg 2) at address 0 */
        timeout = 100000;
        while ((*macmdioar & 1) && --timeout) {}
        uart_puts("  MB clear wait timeout_left="); uart_putdec(timeout); uart_puts("\n");

        cfg = (4U << 8) |     /* CR=4 for HCLK/102 (200MHz HCLK) */
              (2U << 16) |    /* RDA=2 (PHY_REG_ID1) */
              (0U << 21) |    /* PA=0 (PHY addr 0) */
              (3U << 2);      /* GOC=3 (read) */
        *macmdioar = cfg | 1; /* Set MB bit */
        uart_puts("  MACMDIOAR wrote: "); uart_puthex(cfg | 1);
        uart_puts(" readback: "); uart_puthex(*macmdioar); uart_puts("\n");

        timeout = 100000;
        while ((*macmdioar & 1) && --timeout) {}
        uart_puts("  MDIO op done, timeout_left="); uart_putdec(timeout); uart_puts("\n");
        uart_puts("  MACMDIOAR: "); uart_puthex(*macmdioar); uart_puts("\n");
        uart_puts("  MACMDIODR (ID1@0): "); uart_puthex(*macmdiodr); uart_puts("\n");

        /* Try PHY address 1 */
        timeout = 100000;
        while ((*macmdioar & 1) && --timeout) {}
        cfg = (4U << 8) | (2U << 16) | (1U << 21) | (3U << 2);
        *macmdioar = cfg | 1;
        timeout = 100000;
        while ((*macmdioar & 1) && --timeout) {}
        uart_puts("  MACMDIODR (ID1@1): "); uart_puthex(*macmdiodr); uart_puts("\n");
    }
#endif

#ifdef DHCP
    {
        uint32_t dhcp_start_tick;
        uint32_t dhcp_timeout = 30000;

        ret = dhcp_client_init(IPStack);
        if (ret >= 0) {
            uart_puts("Waiting for DHCP...\n");
            dhcp_start_tick = tick;
            while (!dhcp_bound(IPStack)) {
                uint32_t elapsed = (uint32_t)(tick - dhcp_start_tick);
                (void)wolfIP_poll(IPStack, tick);
                tick++;
#ifdef DEBUG_HW
                if ((elapsed < 10) ||
                    (elapsed % 2000) == 0) {
                    uint32_t polls, pkts;
                    stm32_eth_get_stats(&polls, &pkts);
                    uart_puts("  tick=");
                    uart_putdec(elapsed);
                    uart_puts(" rx_polls=");
                    uart_putdec(polls);
                    uart_puts(" rx_pkts=");
                    uart_putdec(pkts);
                    uart_puts(" DMACSR=");
                    uart_puthex(stm32_eth_get_dmacsr());
                    uart_puts(" des3=");
                    uart_puthex(stm32_eth_get_rx_des3());
                    uart_puts("\n");
                }
#endif
                delay(100000);  /* ~8ms per poll */
                if (elapsed > dhcp_timeout)
                    break;
            }
            if (dhcp_bound(IPStack)) {
                ip4 ip = 0, nm = 0, gw = 0;
                wolfIP_ipconfig_get(IPStack, &ip, &nm, &gw);
                uart_puts("DHCP configuration received:\n");
                uart_puts("  IP: ");
                uart_putip4(ip);
                uart_puts("\n  Mask: ");
                uart_putip4(nm);
                uart_puts("\n  GW: ");
                uart_putip4(gw);
                uart_puts("\n");
            } else {
                uart_puts("DHCP timeout!\n");
            }
        }
    }
#else
    {
        ip4 ip = atoip4(WOLFIP_IP);
        ip4 nm = atoip4(WOLFIP_NETMASK);
        ip4 gw = atoip4(WOLFIP_GW);
        uart_puts("Using static IP configuration:\n");
        uart_puts("  IP: ");
        uart_putip4(ip);
        uart_puts("\n  Mask: ");
        uart_putip4(nm);
        uart_puts("\n  GW: ");
        uart_putip4(gw);
        uart_puts("\n");
        wolfIP_ipconfig_set(IPStack, ip, nm, gw);
    }
#endif

    /* Create TCP echo server on port 7 */
    uart_puts("Creating TCP echo server on port 7...\n");
    listen_fd = wolfIP_sock_socket(IPStack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    wolfIP_register_callback(IPStack, listen_fd, echo_cb, IPStack);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(ECHO_PORT);
    addr.sin_addr.s_addr = 0;
    (void)wolfIP_sock_bind(IPStack, listen_fd, (struct wolfIP_sockaddr *)&addr, sizeof(addr));
    (void)wolfIP_sock_listen(IPStack, listen_fd, 1);

#ifdef ENABLE_TLS_CLIENT
    uart_puts("Initializing TLS client...\n");
    if (tls_client_init(IPStack, uart_puts) < 0) {
        uart_puts("ERROR: TLS client init failed\n");
        led_red_on();
    }
    tls_client_set_sni(GOOGLE_HOST);
#endif

#ifdef ENABLE_HTTPS
    uart_puts("Initializing HTTPS server on port 443...\n");

    /* Create SSL context for HTTPS */
    https_ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (https_ssl_ctx) {
        wolfSSL_CTX_use_certificate_buffer(https_ssl_ctx,
            (const unsigned char *)server_cert_pem, strlen(server_cert_pem),
            SSL_FILETYPE_PEM);
        wolfSSL_CTX_use_PrivateKey_buffer(https_ssl_ctx,
            (const unsigned char *)server_key_pem, strlen(server_key_pem),
            SSL_FILETYPE_PEM);

        if (httpd_init(&https_server, IPStack, HTTPS_WEB_PORT, https_ssl_ctx) == 0) {
            httpd_register_handler(&https_server, "/", https_status_handler);
            uart_puts("HTTPS: Server ready on port 443\n");
        } else {
            uart_puts("ERROR: HTTPS server init failed\n");
        }
    } else {
        uart_puts("ERROR: HTTPS SSL context failed\n");
    }
#endif

#ifdef ENABLE_MQTT_BROKER
    uart_puts("Initializing MQTT broker on port 8883 (TLS)...\n");
    {
        mqtt_broker_config_t broker_config = {
            .port = 8883,
            .use_tls = 1
        };
        if (mqtt_broker_init(IPStack, &broker_config, uart_puts) < 0) {
            uart_puts("ERROR: MQTT broker init failed\n");
        }
    }
#endif

    uart_puts("Entering main loop. Ready for connections!\n");
    uart_puts("  TCP Echo: port 7\n");
#ifdef ENABLE_TLS_CLIENT
    uart_puts("  TLS Client: will connect to Google after ~2s\n");
#endif
#ifdef ENABLE_HTTPS
    uart_puts("  HTTPS Server: port 443\n");
#endif

    for (;;) {
        (void)wolfIP_poll(IPStack, tick++);
        delay(100000);  /* ~8ms per tick (volatile loop ~80ns/iter at 400MHz) */

#ifdef ENABLE_TLS_CLIENT
        /* TLS client test: connect to Google after network settles */
        if (!tls_client_test_started && tick > 250) {
            uart_puts("\n--- TLS Client Test: Connecting to Google ---\n");
            uart_puts("Target: ");
            uart_puts(GOOGLE_IP);
            uart_puts(":");
            uart_putdec(GOOGLE_HTTPS_PORT);
            uart_puts("\n");

            if (tls_client_connect(GOOGLE_IP, GOOGLE_HTTPS_PORT, tls_response_cb, NULL) == 0) {
                uart_puts("TLS Client: Connection initiated\n");
            } else {
                uart_puts("TLS Client: Failed to start connection\n");
            }
            tls_client_test_started = 1;
        }

        /* Poll TLS client state machine */
        tls_client_poll();

        /* Send HTTP request once TLS handshake completes */
        if (tls_client_is_connected() && !tls_client_test_done) {
            static int request_sent = 0;
            if (!request_sent) {
                const char *http_req = "GET / HTTP/1.1\r\n"
                                       "Host: " GOOGLE_HOST "\r\n"
                                       "Connection: close\r\n\r\n";
                uart_puts("TLS Client: Sending HTTP GET request...\n");
                if (tls_client_send(http_req, (int)strlen(http_req)) > 0) {
                    uart_puts("TLS Client: Request sent\n");
                } else {
                    uart_puts("TLS Client: Send failed\n");
                }
                request_sent = 1;
            }
        }
#endif

#ifdef ENABLE_HTTPS
        /* Update HTTPS server status info for handler */
        wolfIP_ipconfig_get(IPStack, &https_device_ip, NULL, NULL);
        https_uptime_sec = (uint32_t)(tick / 125);  /* ~8ms per tick */
#endif

#ifdef ENABLE_MQTT_BROKER
        /* Poll MQTT broker */
        mqtt_broker_poll();
        
        /* Update broker uptime counter */
        broker_uptime_sec = (unsigned long)(tick / 125);  /* ~8ms per tick */
#endif

        /* Toggle green LED every ~256K iterations as heartbeat */
        if ((tick & 0x3FFFF) == 0) {
            led_toggle_green();
        }
    }

    return 0;
}

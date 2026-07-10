/* main.c
 *
 * STM32C5A3ZG (NUCLEO-C5A3ZG) wolfIP Echo Server
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
#include "stm32c5a3xx.h"
#include "config.h"
#include "wolfip.h"
#include "stm32_eth.h"
#ifdef ENABLE_TLS_CLIENT
#include "tls_client.h"
#endif

#define ECHO_PORT 7
#define RX_BUF_SIZE 1024

#ifdef ENABLE_TLS_CLIENT
/* Milestone 3A.0 TLS mutual-auth client test state. */
static int tls_client_test_started = 0;
static int tls_client_test_done = 0;
static int tls_request_sent = 0;
#endif

/* NUCLEO-C5A3ZG: 144 MHz SYSCLK/HCLK (HSE 48 MHz -> PSI -> PSIS, prescalers /1). */
#define BOARD_SYSCLK_HZ 144000000u

#define HSE_TIMEOUT     0x100000u
#define PSI_TIMEOUT     0x100000u
#define SW_TIMEOUT      0x010000u

/* =========================================================================
 * Global Variables
 * ========================================================================= */
static struct wolfIP *IPStack;
static int listen_fd = -1;
static int client_fd = -1;
static uint8_t rx_buf[RX_BUF_SIZE];

/* CMSIS-Core hooks called by the vendor startup. SystemInit is a no-op (clocks
 * are set in clock_init); Default_IRQHandler_Hook parks on an unexpected IRQ. */
void SystemInit(void) { /* no-op */ }

__attribute__((weak)) void Default_IRQHandler_Hook(void)
{
    while (1) { }
}

/* Simple busy-wait delay. */
static void delay(uint32_t count)
{
    volatile uint32_t i;
    for (i = 0; i < count; i++) { }
}

/* =========================================================================
 * Clock init: HSE 48 MHz -> PSI -> PSIS = 144 MHz SYSCLK
 *
 * Lifted verbatim from the proven wolfBoot/STM32_Bare_Test C5A3 port:
 * HSE on, PSIREFSRC=HSE, PSIREF=48 MHz, PSIFREQ=144 MHz, enable PSIS, all
 * bus prescalers /1, flash 4 WS + prefetch + WRHIGHFREQ delay 2, switch
 * SYSCLK to PSIS. CK48 (the RNG kernel clock) is sourced from HSIDIV3 =
 * HSI/3 = 48 MHz (needed for the HW RNG later; harmless now). On any
 * timeout we leave the chip on its reset clock so boot still proceeds.
 * ========================================================================= */
static void clock_init(void)
{
    uint32_t reg;
    volatile uint32_t timeout;

    /* RNG kernel clock = CK48 (RCC_CCIPR2.CK48SEL), sourced from HSIDIV3
     * (HSI / 3 = 48 MHz). Validated on silicon. */
    RCC->CR1 |= RCC_CR1_HSIDIV3ON;
    timeout = HSE_TIMEOUT;
    while (((RCC->CR1 & RCC_CR1_HSIDIV3RDY) == 0u) && (--timeout != 0u)) {
        /* spin */
    }
    reg = RCC->CCIPR2 & ~RCC_CCIPR2_CK48SEL_Msk;
    reg |= RCC_CCIPR2_CK48SEL_1;   /* CK48 source = HSIDIV3 (HSI/3 = 48 MHz) */
    RCC->CCIPR2 = reg;

    /* 1. Enable HSE (48 MHz on NUCLEO-C5A3ZG soldered crystal). */
    if ((RCC->CR1 & RCC_CR1_HSEON) == 0u) {
        RCC->CR1 |= RCC_CR1_HSEON;
    }
    timeout = HSE_TIMEOUT;
    while (((RCC->CR1 & RCC_CR1_HSERDY) == 0u) && (--timeout != 0u)) {
        /* spin */
    }
    if (timeout == 0u) {
        return;
    }

    /* 2. Configure PSI: ref source = HSE (PSIREFSRC=00), ref = 48 MHz
     * (PSIREF = 110b), output = 144 MHz (PSIFREQ = 01b). */
    reg  = RCC->CR2 & ~(RCC_CR2_PSIREFSRC | RCC_CR2_PSIREF |
                        RCC_CR2_PSIFREQ);
    reg |= (0u)                                           /* PSIREFSRC = HSE */
        |  (RCC_CR2_PSIREF_2 | RCC_CR2_PSIREF_1)          /* PSIREF = 48 MHz */
        |  (RCC_CR2_PSIFREQ_0);                           /* PSIFREQ = 144 MHz */
    RCC->CR2 = reg;

    /* 3. Enable PSIS, wait for ready. */
    RCC->CR1 |= RCC_CR1_PSISON;
    timeout = PSI_TIMEOUT;
    while (((RCC->CR1 & RCC_CR1_PSISRDY) == 0u) && (--timeout != 0u)) {
        /* spin */
    }
    if (timeout == 0u) {
        return;
    }

    /* 4. All bus prescalers /1. Reset value already 0; explicit for intent. */
    RCC->CFGR2 = 0u;

    /* 5. Flash 4 WS + prefetch BEFORE switching SYSCLK to 144 MHz. */
    reg = FLASH->ACR & ~FLASH_ACR_LATENCY;
    reg |= (4u << FLASH_ACR_LATENCY_Pos) | FLASH_ACR_PRFTEN;
    FLASH->ACR = reg;
    while ((FLASH->ACR & FLASH_ACR_LATENCY) !=
           (4u << FLASH_ACR_LATENCY_Pos)) {
        /* spin */
    }

    /* 6. Switch SYSCLK to PSIS (SW = 11b). */
    reg = RCC->CFGR1 & ~RCC_CFGR1_SW;
    RCC->CFGR1 = reg | (RCC_CFGR1_SW_0 | RCC_CFGR1_SW_1);
    timeout = SW_TIMEOUT;
    while (((RCC->CFGR1 & RCC_CFGR1_SWS) !=
            (RCC_CFGR1_SWS_0 | RCC_CFGR1_SWS_1)) && (--timeout != 0u)) {
        /* spin */
    }
    if (timeout == 0u) {
        return;
    }

    /* 7. Programming delay 2 (required at HCLK >= 136 MHz). */
    reg = FLASH->ACR & ~FLASH_ACR_WRHIGHFREQ;
    FLASH->ACR = reg | (2u << FLASH_ACR_WRHIGHFREQ_Pos);
}

/* =========================================================================
 * USART2 init: PA2 (TX) / PA3 (RX), AF7 (ST-LINK V3 VCP)
 *
 * Lifted verbatim from the proven C5A3 port. PCLK1 = SYSCLK = 144 MHz
 * after clock_init(), so BRR = 144000000 / 115200.
 * ========================================================================= */
static void uart_init(void)
{
    /* Enable GPIOA on AHB2 */
    RCC->AHB2ENR |= RCC_AHB2ENR_GPIOAEN;
    (void)RCC->AHB2ENR;

    /* PA2 (TX), PA3 (RX): MODER=AF (10b), AF7 (USART2) */
    GPIOA->MODER &= ~(GPIO_MODER_MODE2_Msk | GPIO_MODER_MODE3_Msk);
    GPIOA->MODER |= (2u << GPIO_MODER_MODE2_Pos) |
                    (2u << GPIO_MODER_MODE3_Pos);
    GPIOA->OSPEEDR |= (3u << GPIO_OSPEEDR_OSPEED2_Pos) |
                      (3u << GPIO_OSPEEDR_OSPEED3_Pos);
    GPIOA->AFR[0] &= ~((0xFu << GPIO_AFRL_AFSEL2_Pos) |
                       (0xFu << GPIO_AFRL_AFSEL3_Pos));
    GPIOA->AFR[0] |= (7u << GPIO_AFRL_AFSEL2_Pos) |
                     (7u << GPIO_AFRL_AFSEL3_Pos);
    GPIOA->PUPDR &= ~(GPIO_PUPDR_PUPD2_Msk | GPIO_PUPDR_PUPD3_Msk);

    /* Enable USART2 clock (APB1L bit USART2EN) */
    RCC->APB1LENR |= RCC_APB1LENR_USART2EN;
    (void)RCC->APB1LENR;

    /* USART2: 8N1, oversample 16. */
    USART2->CR1 = 0;
    USART2->BRR = BOARD_SYSCLK_HZ / 115200u;
    USART2->CR1 = USART_CR1_TE | USART_CR1_RE | USART_CR1_UE;

    while ((USART2->ISR & (USART_ISR_TEACK | USART_ISR_REACK)) !=
           (USART_ISR_TEACK | USART_ISR_REACK)) {
        /* spin */
    }
}

/* =========================================================================
 * UART helpers
 * ========================================================================= */
static void uart_putc(char c)
{
    while ((USART2->ISR & USART_ISR_TXE_TXFNF) == 0u) { }
    USART2->TDR = (uint32_t)c & 0xFFu;
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
    int i;
    uart_puts("0x");
    for (i = 28; i >= 0; i -= 4) {
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
        buf[i++] = (char)('0' + (val % 10));
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
 * Fault reporting (override the weak while(1) HardFault in startup.c) so a
 * crash prints the fault registers + stacked PC/LR instead of hanging
 * silently. __StackTop/__StackLimit come from target.ld.
 * ========================================================================= */
extern uint32_t __StackLimit;
void hardfault_report(uint32_t *sp)
{
    uart_puts("\n!! HARDFAULT !!\n");
    uart_puts("  stacked PC = "); uart_puthex(sp[6]); uart_puts("\n");
    uart_puts("  stacked LR = "); uart_puthex(sp[5]); uart_puts("\n");
    uart_puts("  CFSR = "); uart_puthex(*(volatile uint32_t *)0xE000ED28u); uart_puts("\n");
    uart_puts("  HFSR = "); uart_puthex(*(volatile uint32_t *)0xE000ED2Cu); uart_puts("\n");
    uart_puts("  MMFAR= "); uart_puthex(*(volatile uint32_t *)0xE000ED34u); uart_puts("\n");
    uart_puts("  SP   = "); uart_puthex((uint32_t)sp); uart_puts("\n");
    uart_puts("  StackLimit = "); uart_puthex((uint32_t)&__StackLimit); uart_puts("\n");
    while (1) { }
}

__attribute__((naked)) void HardFault_Handler(void)
{
    __asm volatile(
        "tst lr, #4       \n"
        "ite eq           \n"
        "mrseq r0, msp    \n"
        "mrsne r0, psp    \n"
        "b hardfault_report \n"
    );
}

/* =========================================================================
 * RNG (required by wolfIP for TCP ISNs)
 *
 * The HW RNG kernel clock (CK48) was set up in clock_init(). Enable the
 * RNG clock + peripheral here. wolfIP_getrandom falls back to a runtime-
 * seeded LFSR if the HW RNG is unavailable.
 * ========================================================================= */
static void rng_init(void)
{
    /* Enable RNG peripheral clock (AHB2). */
    RCC->AHB2ENR |= RCC_AHB2ENR_RNGEN;
    (void)RCC->AHB2ENR;
    delay(100);
    /* CR.CED=1 disables the clock-error detector, which on C5 silicon
     * false-trips on the 48 MHz CK48 clock and stalls DRDY. */
    RNG->CR = RNG_CR_RNGEN | RNG_CR_CED;
}

static int rng_get_word(uint32_t *out)
{
    uint32_t timeout = 100000u;
    while ((RNG->SR & RNG_SR_DRDY) == 0u) {
        if ((RNG->SR & (RNG_SR_CECS | RNG_SR_SECS)) != 0u) {
            RNG->CR = 0;
            delay(100);
            RNG->CR = RNG_CR_RNGEN | RNG_CR_CED;
            timeout = 100000u;
        }
        if (--timeout == 0u) {
            return -1;
        }
    }
    *out = RNG->DR;
    return 0;
}

uint32_t wolfIP_getrandom(void)
{
    uint32_t val;
    if (rng_get_word(&val) == 0) {
        return val;
    }
    /* HW RNG failed: fall back to a runtime-seeded xorshift LFSR so a
     * degraded device does not emit a globally-identical sequence. Not a
     * cryptographic RNG. */
    {
        static uint32_t lfsr = 0u;
        if (lfsr == 0u) {
            lfsr = RNG->DR ^ 0x1A2B3C4DU;
            if (lfsr == 0u) {
                lfsr = 0x1A2B3C4DU;
            }
        }
        lfsr ^= lfsr << 13;
        lfsr ^= lfsr >> 17;
        lfsr ^= lfsr << 5;
        return lfsr;
    }
}

/* =========================================================================
 * Ethernet GPIO / SYSCFG (SBS) / RMII configuration
 *
 * NUCLEO-C5A3ZG RMII pinout (all AF10 = ETH1):
 *   PA1  - ETH_REF_CLK
 *   PC1  - ETH_MDC
 *   PE12 - ETH_MDIO  (board MDIO route; PA2 is the USART2 console TX)
 *   PD1  - ETH_CRS_DV
 *   PC4  - ETH_RXD0
 *   PC5  - ETH_RXD1
 *   PG11 - ETH_TX_EN
 *   PG13 - ETH_TXD0
 *   PG12 - ETH_TXD1
 * ========================================================================= */

/* Configure one GPIO as an Ethernet alternate-function pin. The ETH AF
 * number is NOT uniform on the C5A3: most RMII signals are AF10, but
 * RXD0 (PC4) is AF12 and RXD1 (PC5) is AF13 (per the NUCLEO-C5A3ZG
 * CubeC5 ETH example). Passing the wrong AF leaves the pin disconnected
 * from the MAC -- e.g. AF10 on the RXD pins silently kills the RX path
 * (link stays up via MDIO, but no frames are received). */
static void gpio_eth_pin(GPIO_TypeDef *port, uint32_t pin, uint32_t af)
{
    uint32_t pos2 = pin * 2u;

    /* Mode = alternate function (0b10) */
    port->MODER &= ~(3u << pos2);
    port->MODER |= (2u << pos2);

    /* Very-high speed (0b11) */
    port->OSPEEDR |= (3u << pos2);

    if (pin < 8u) {
        port->AFR[0] &= ~(0xFu << (pin * 4u));
        port->AFR[0] |= (af << (pin * 4u));
    } else {
        port->AFR[1] &= ~(0xFu << ((pin - 8u) * 4u));
        port->AFR[1] |= (af << ((pin - 8u) * 4u));
    }
}

static void eth_gpio_init(void)
{
    uint32_t val;

    /* Enable GPIO port clocks: A, C, D, E, G (AHB2ENR). */
    RCC->AHB2ENR |= RCC_AHB2ENR_GPIOAEN | RCC_AHB2ENR_GPIOCEN |
                    RCC_AHB2ENR_GPIODEN | RCC_AHB2ENR_GPIOEEN |
                    RCC_AHB2ENR_GPIOGEN;

    /* Enable SBS (System Bus / SYSCFG) clock for RMII select. */
    RCC->APB3ENR |= RCC_APB3ENR_SBSEN;
    (void)RCC->APB3ENR;
    delay(1000);

    /* Select RMII mode: SBS_PMCR.ETH1_SEL_PHY = 100b (RMII).
     * This is the C5 analog of the H5 SBS EPIS field and the H7
     * SYSCFG_PMCR EPIS field. */
    val = SBS->PMCR;
    val &= ~SBS_PMCR_ETH1_SEL_PHY_Msk;
    val |= SBS_PMCR_ETH1_SEL_PHY_2;   /* 0x04 << 24 = RMII */
    SBS->PMCR = val;
    (void)SBS->PMCR;
    __asm volatile ("dsb sy" ::: "memory");
    delay(1000);

    /* Configure RMII pins. Most are AF10; RXD0/RXD1 are AF12/AF13. */
    gpio_eth_pin(GPIOA, 1, 10);    /* REF_CLK */
    gpio_eth_pin(GPIOC, 1, 10);    /* MDC */
    gpio_eth_pin(GPIOE, 12, 10);   /* MDIO */
    gpio_eth_pin(GPIOD, 1, 10);    /* CRS_DV */
    gpio_eth_pin(GPIOC, 4, 12);    /* RXD0 (AF12) */
    gpio_eth_pin(GPIOC, 5, 13);    /* RXD1 (AF13) */
    gpio_eth_pin(GPIOG, 11, 10);   /* TX_EN */
    gpio_eth_pin(GPIOG, 13, 10);   /* TXD0 */
    gpio_eth_pin(GPIOG, 12, 10);   /* TXD1 */
}

/* =========================================================================
 * TLS Client Callback (milestone 3A.0)
 * ========================================================================= */
#ifdef ENABLE_TLS_CLIENT
static void tls_response_cb(const char *data, int len, void *ctx)
{
    int i;
    (void)ctx;
    uart_puts("TLS Client received ");
    uart_putdec((uint32_t)len);
    uart_puts(" bytes:\n");

    /* Print up to the first 200 bytes of the server response. */
    for (i = 0; (i < len) && (i < 200); i++) {
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
 * Main
 * ========================================================================= */
int main(void)
{
    struct wolfIP_ll_dev *ll;
    struct wolfIP_sockaddr_in addr;
    uint64_t tick = 0;
    int ret;

    /* Enable FPU CP10/CP11 full access (Cortex-M33F). */
    SCB->CPACR |= (0xFu << 20);
    __DSB();
    __ISB();

    /* System clock: HSE + PSI -> 144 MHz SYSCLK / HCLK. */
    clock_init();

    /* USART2 console (ST-LINK V3 VCP). */
    uart_init();

    uart_puts("\n\n=== wolfIP STM32C5A3ZG Echo Server ===\n");
    uart_puts("Clock: 144 MHz SYSCLK (HSE 48 MHz -> PSI)\n");

    /* Hardware RNG (kernel clock CK48 set up in clock_init). */
    rng_init();
    {
        uint32_t rng_test;
        int rng_ok = rng_get_word(&rng_test);
        uart_puts("RNG init: ");
        uart_puts(rng_ok == 0 ? "OK" : "FAILED");
        if (rng_ok == 0) {
            uart_puts(" val=");
            uart_puthex(rng_test);
        }
        uart_puts("\n");
    }

    uart_puts("Initializing wolfIP stack...\n");
    wolfIP_init_static(&IPStack);

    /* Step 1: Configure GPIO + SBS RMII mode BEFORE enabling ETH clocks. */
    uart_puts("Configuring GPIO for RMII...\n");
    eth_gpio_init();

    /* Step 2: Wait for the PHY REF_CLK to stabilize after board reset.
     * The MAC needs REF_CLK for register access. */
    delay(2500000);  /* ~200ms */

    /* Step 3: Enable ETH clocks: ETH1EN + ETH1TXEN + ETH1RXEN + ETH1CKEN. */
    uart_puts("Enabling Ethernet clocks...\n");
    RCC->AHB1ENR |= RCC_AHB1ENR_ETH1EN | RCC_AHB1ENR_ETH1TXEN |
                    RCC_AHB1ENR_ETH1RXEN | RCC_AHB1ENR_ETH1CKEN;
    __asm volatile ("dsb sy" ::: "memory");
    delay(12500);  /* ~1ms */

    /* Step 4: RCC reset of the ETH MAC (AHB1RSTR.ETH1RST). */
    uart_puts("Resetting Ethernet MAC...\n");
    RCC->AHB1RSTR |= RCC_AHB1RSTR_ETH1RST;
    __asm volatile ("dsb sy" ::: "memory");
    delay(12500);
    RCC->AHB1RSTR &= ~RCC_AHB1RSTR_ETH1RST;
    __asm volatile ("dsb sy" ::: "memory");
    delay(125000);  /* ~10ms post-reset stabilization */

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
        uart_puts("\n");
    }

#ifdef DHCP
    {
        uint32_t dhcp_start_tick;
        uint32_t dhcp_timeout = 5000;

        /* Prime the stack's last_tick before starting the DHCP client, so
         * the first DHCP timeout delta is sane (a zero last_tick makes the
         * client mis-time its DISCOVER retransmits). */
        (void)wolfIP_poll(IPStack, tick++);

        ret = dhcp_client_init(IPStack);
        if (ret >= 0) {
            uart_puts("Waiting for DHCP...\n");
            dhcp_start_tick = (uint32_t)tick;
            while (!dhcp_bound(IPStack) && dhcp_client_is_running(IPStack)) {
                uint32_t elapsed = (uint32_t)tick - dhcp_start_tick;
                (void)wolfIP_poll(IPStack, tick);
                tick++;
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
                ip4 ip = atoip4(WOLFIP_IP);
                ip4 nm = atoip4(WOLFIP_NETMASK);
                ip4 gw = atoip4(WOLFIP_GW);
                uart_puts("  DHCP timeout - falling back to static IP\n");
                uart_puts("  IP: ");
                uart_putip4(ip);
                uart_puts("\n  Mask: ");
                uart_putip4(nm);
                uart_puts("\n  GW: ");
                uart_putip4(gw);
                uart_puts("\n");
                wolfIP_ipconfig_set(IPStack, ip, nm, gw);
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
    /* Milestone 3A.0: bring up the TLS 1.3 mutual-auth client. The device
     * loads its client cert + SEC1 identity key inside tls_client_init(). */
    uart_puts("Initializing TLS client (mutual auth)...\n");
    if (tls_client_init(IPStack, uart_puts) < 0) {
        uart_puts("ERROR: TLS client init failed\n");
    }
#endif

    uart_puts("Entering main loop. Ready for connections!\n");
    uart_puts("  TCP Echo: port 7\n");
#ifdef ENABLE_TLS_CLIENT
    uart_puts("  TLS Client: will connect after network settles\n");
#endif

    for (;;) {
        (void)wolfIP_poll(IPStack, tick++);
        delay(100000);  /* ~8ms per tick */

#ifdef ENABLE_TLS_CLIENT
        /* Kick off the TLS connection once the stack has settled. */
        if (!tls_client_test_started && tick > 250) {
            uart_puts("\n--- TLS Client Test (3A.0 mutual auth) ---\n");
            uart_puts("Target: ");
            uart_puts(TLS_SERVER_IP);
            uart_puts(":");
            uart_putdec(TLS_SERVER_PORT);
            uart_puts("\n");

            if (tls_client_connect(TLS_SERVER_IP, TLS_SERVER_PORT,
                                   tls_response_cb, NULL) == 0) {
                uart_puts("TLS Client: Connection initiated\n");
            } else {
                uart_puts("TLS Client: Failed to start connection\n");
            }
            tls_client_test_started = 1;
        }

        /* Drive the TLS client state machine. */
        tls_client_poll();

        /* Send a short request once the handshake completes. */
        if (tls_client_is_connected() && !tls_client_test_done &&
            !tls_request_sent) {
            const char *req = "GET / \r\n";
            uart_puts("TLS Client: Sending request...\n");
            if (tls_client_send(req, (int)strlen(req)) > 0) {
                uart_puts("TLS Client: Request sent\n");
            } else {
                uart_puts("TLS Client: Send failed\n");
            }
            tls_request_sent = 1;
        }
#endif
    }

    return 0;
}

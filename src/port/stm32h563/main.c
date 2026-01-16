/* main.c
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
#include "stm32h5_eth.h"

#define ECHO_PORT 7
#define RX_BUF_SIZE 1024

#if TZEN_ENABLED
#define RCC_BASE 0x54020C00u  /* Secure alias */
#define ETH_BASE_DBG 0x50028000u  /* Secure ETH for debug */
#else
#define RCC_BASE 0x44020C00u  /* Non-secure alias */
#define ETH_BASE_DBG 0x40028000u  /* Non-secure ETH for debug */
#endif
#define RCC_AHB1ENR  (*(volatile uint32_t *)(RCC_BASE + 0x88u))
#define RCC_AHB2ENR  (*(volatile uint32_t *)(RCC_BASE + 0x8Cu))
#define RCC_APB3ENR  (*(volatile uint32_t *)(RCC_BASE + 0xA8u))
#define RCC_AHB1RSTR (*(volatile uint32_t *)(RCC_BASE + 0x60u))
#define RCC_AHB1RSTR_ETHRST (1u << 19)

/* SAU (Security Attribution Unit) - mark memory regions as non-secure */
#define SAU_CTRL   (*(volatile uint32_t *)0xE000EDD0u)
#define SAU_RNR    (*(volatile uint32_t *)0xE000EDD8u)
#define SAU_RBAR   (*(volatile uint32_t *)0xE000EDDCu)
#define SAU_RLAR   (*(volatile uint32_t *)0xE000EDE0u)

/* GTZC (Global TrustZone Controller) - unlock SRAM for DMA access */
#if TZEN_ENABLED
/* Secure addresses when running in secure mode with TZEN=1 */
#define GTZC1_BASE         0x50032400u  /* Secure alias */
#else
#define GTZC1_BASE         0x40032400u  /* Non-secure alias */
#endif
#define GTZC1_MPCBB1_CR    (*(volatile uint32_t *)(GTZC1_BASE + 0x800u))
#define GTZC1_MPCBB2_CR    (*(volatile uint32_t *)(GTZC1_BASE + 0xC00u))
#define GTZC1_MPCBB3_CR    (*(volatile uint32_t *)(GTZC1_BASE + 0x1000u))
/* MPCBB SECCFGR registers - each bit controls 256 bytes of SRAM */
#define GTZC1_MPCBB3_SECCFGR(n) (*(volatile uint32_t *)(GTZC1_BASE + 0x1000u + 0x100u + ((n) * 4u)))
/* MPCBB PRIVCFGR registers - each bit controls privilege for 256 bytes of SRAM */
#define GTZC1_MPCBB3_PRIVCFGR(n) (*(volatile uint32_t *)(GTZC1_BASE + 0x1000u + 0x200u + ((n) * 4u)))
/* TZSC SECCFGR registers - control peripheral security */
#define GTZC1_TZSC_SECCFGR1 (*(volatile uint32_t *)(GTZC1_BASE + 0x010u))
#define GTZC1_TZSC_SECCFGR2 (*(volatile uint32_t *)(GTZC1_BASE + 0x014u))
#define GTZC1_TZSC_SECCFGR3 (*(volatile uint32_t *)(GTZC1_BASE + 0x018u))

/* GPIO base addresses */
#if TZEN_ENABLED
#define GPIOA_BASE 0x52020000u  /* Secure alias */
#define GPIOB_BASE 0x52020400u
#define GPIOC_BASE 0x52020800u
#define GPIOG_BASE 0x52021800u
#else
#define GPIOA_BASE 0x42020000u  /* Non-secure alias */
#define GPIOB_BASE 0x42020400u
#define GPIOC_BASE 0x42020800u
#define GPIOG_BASE 0x42021800u
#endif

/* GPIO register offsets */
#define GPIO_MODER(base)   (*(volatile uint32_t *)((base) + 0x00u))
#define GPIO_OSPEEDR(base) (*(volatile uint32_t *)((base) + 0x08u))
#define GPIO_PUPDR(base)   (*(volatile uint32_t *)((base) + 0x0Cu))
#define GPIO_AFRL(base)    (*(volatile uint32_t *)((base) + 0x20u))
#define GPIO_AFRH(base)    (*(volatile uint32_t *)((base) + 0x24u))

/* SBS (System Bus Security) for RMII selection */
/* SBS register definitions - PMCR is at offset 0x100 in SBS structure */
#if TZEN_ENABLED
#define SBS_BASE        0x54000400u  /* Secure alias */
#else
#define SBS_BASE        0x44000400u  /* Non-secure alias */
#endif
#define SBS_PMCR        (*(volatile uint32_t *)(SBS_BASE + 0x100u))
#define SBS_PMCR_ETH_SEL_RMII (4u << 21)

/* USART3 for debug output (ST-Link VCP on NUCLEO-H563ZI) */
#define GPIOD_BASE 0x42020C00u
#define GPIOF_BASE 0x42021400u
#define RCC_APB1ENR (*(volatile uint32_t *)(RCC_BASE + 0x9Cu))
#define USART3_BASE 0x40004800u
#define USART3_CR1 (*(volatile uint32_t *)(USART3_BASE + 0x00u))
#define USART3_BRR (*(volatile uint32_t *)(USART3_BASE + 0x0Cu))
#define USART3_ISR (*(volatile uint32_t *)(USART3_BASE + 0x1Cu))
#define USART3_TDR (*(volatile uint32_t *)(USART3_BASE + 0x28u))

/* LED2 on PF4 */
#define GPIO_ODR(base)     (*(volatile uint32_t *)((base) + 0x14u))
#define GPIO_BSRR(base)    (*(volatile uint32_t *)((base) + 0x18u))
#define LED2_PIN 4u

static struct wolfIP *IPStack;
static int listen_fd = -1;
static int client_fd = -1;
static uint8_t rx_buf[RX_BUF_SIZE];

uint32_t wolfIP_getrandom(void)
{
    static uint32_t lfsr = 0x1A2B3C4DU;
    lfsr ^= lfsr << 13;
    lfsr ^= lfsr >> 17;
    lfsr ^= lfsr << 5;
    return lfsr;
}

/* Simple delay */
static void delay(uint32_t count)
{
    for (volatile uint32_t i = 0; i < count; i++) { }
}

/* Initialize LED2 on PF4 */
static void led_init(void)
{
    uint32_t moder;

    /* Enable GPIOF clock */
    RCC_AHB2ENR |= (1u << 5);
    delay(100);

    /* Set PF4 as output */
    moder = GPIO_MODER(GPIOF_BASE);
    moder &= ~(3u << (LED2_PIN * 2u));
    moder |= (1u << (LED2_PIN * 2u));  /* Output mode */
    GPIO_MODER(GPIOF_BASE) = moder;
}

static void led_on(void)
{
    GPIO_BSRR(GPIOF_BASE) = (1u << LED2_PIN);
}

static void led_off(void)
{
    GPIO_BSRR(GPIOF_BASE) = (1u << (LED2_PIN + 16u));
}

static void led_toggle(void)
{
    GPIO_ODR(GPIOF_BASE) ^= (1u << LED2_PIN);
}

/* USART3 additional registers */
#define USART3_CR2 (*(volatile uint32_t *)(USART3_BASE + 0x04u))
#define USART3_CR3 (*(volatile uint32_t *)(USART3_BASE + 0x08u))
#define USART3_PRESC (*(volatile uint32_t *)(USART3_BASE + 0x2Cu))

/* Initialize USART3 for debug output (115200 baud @ 64MHz HSI) */
static void uart_init(void)
{
    uint32_t moder, afr;

    /* Enable GPIOD clock */
    RCC_AHB2ENR |= (1u << 3);
    /* Enable USART3 clock (APB1LENR bit 18) */
    RCC_APB1ENR |= (1u << 18);

    delay(100);

    /* Configure PD8 (TX) as AF7, push-pull, high speed */
    moder = GPIO_MODER(GPIOD_BASE);
    moder &= ~(3u << 16);  /* Clear PD8 mode */
    moder |= (2u << 16);   /* Alternate function */
    GPIO_MODER(GPIOD_BASE) = moder;

    GPIO_OSPEEDR(GPIOD_BASE) |= (3u << 16);  /* High speed for PD8 */

    afr = GPIO_AFRH(GPIOD_BASE);
    afr &= ~(0xFu << 0);   /* PD8 is AFRH bit 0-3 */
    afr |= (7u << 0);      /* AF7 = USART3 */
    GPIO_AFRH(GPIOD_BASE) = afr;

    /* Disable USART before configuration */
    USART3_CR1 = 0;

    /* Configure USART3: 115200 baud, assuming PCLK1 = 32MHz */
    USART3_CR2 = 0;  /* 1 stop bit */
    USART3_CR3 = 0;  /* No flow control, disable FIFO */
    USART3_PRESC = 0;  /* No prescaler */
    USART3_BRR = 32000000u / 115200u;  /* 278 */

    /* Enable transmitter, then enable USART */
    USART3_CR1 = (1u << 3);  /* TE */
    delay(10);
    USART3_CR1 |= (1u << 0);  /* UE */
    delay(100);
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

/* Configure GPIO pin for Ethernet alternate function (AF11) */
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

/* Initialize GPIO pins for RMII Ethernet (NUCLEO-H563ZI pinout) */
static void eth_gpio_init(void)
{
    /* SBS->PMCR is at SBS_BASE + 0x100 = 0x44000400 + 0x100 = 0x44000500 */
    volatile uint32_t *sbs_pmcr = (volatile uint32_t *)(0x44000500u);
    uint32_t val;

    /* Enable GPIO clocks: A, B, C, G */
    RCC_AHB2ENR |= (1u << 0) | (1u << 1) | (1u << 2) | (1u << 6);

    /* Enable SBS clock for RMII selection - bit 1 in APB3ENR (RCC_APB3ENR_SBSEN) */
    RCC_APB3ENR |= (1u << 1);

    /* Delay for clock to stabilize */
    for (volatile int i = 0; i < 10000; i++) { }

    /* Set RMII mode: read-modify-write to preserve other bits */
    val = *sbs_pmcr;
    val &= ~(0x7u << 21);  /* Clear ETH_SEL bits */
    val |= (0x4u << 21);   /* Set ETH_SEL = 100 for RMII */
    *sbs_pmcr = val;
    for (volatile int i = 0; i < 1000; i++) { }

    /* Configure RMII pins for NUCLEO-H563ZI (from ST HAL):
     * PA1  - ETH_REF_CLK (AF11)
     * PA2  - ETH_MDIO (AF11)
     * PA7  - ETH_CRS_DV (AF11)
     * PC1  - ETH_MDC (AF11)
     * PC4  - ETH_RXD0 (AF11)
     * PC5  - ETH_RXD1 (AF11)
     * PB15 - ETH_TXD1 (AF11)
     * PG11 - ETH_TX_EN (AF11)
     * PG13 - ETH_TXD0 (AF11)
     */
    gpio_eth_pin(GPIOA_BASE, 1);   /* REF_CLK */
    gpio_eth_pin(GPIOA_BASE, 2);   /* MDIO */
    gpio_eth_pin(GPIOA_BASE, 7);   /* CRS_DV */
    gpio_eth_pin(GPIOC_BASE, 1);   /* MDC */
    gpio_eth_pin(GPIOC_BASE, 4);   /* RXD0 */
    gpio_eth_pin(GPIOC_BASE, 5);   /* RXD1 */
    gpio_eth_pin(GPIOB_BASE, 15);  /* TXD1 */
    gpio_eth_pin(GPIOG_BASE, 11);  /* TX_EN */
    gpio_eth_pin(GPIOG_BASE, 13);  /* TXD0 */
}

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

int main(void)
{
    struct wolfIP_ll_dev *ll;
    struct wolfIP_sockaddr_in addr;
    uint64_t tick = 0;
    int ret;

    /* Initialize LED first for debug - keep ON to confirm code is running */
    led_init();
    led_on();  /* LED ON = Reset_Handler ran, main() started */

    /* Initialize UART for debug output */
    uart_init();

    /* Blink to show UART init done */
    led_off();
    delay(200000);
    led_on();
    delay(200000);
    led_off();
    delay(200000);
    led_on();

    uart_puts("\n\n=== wolfIP STM32H563 Echo Server ===\n");

#if TZEN_ENABLED
    /* Configure TrustZone for Ethernet DMA access */
    uart_puts("Configuring TrustZone for Ethernet DMA...\n");
    {
        uint32_t i;

        /* Enable SAU with ALLNS mode (all undefined regions are non-secure) */
        SAU_CTRL = 0x03u;  /* ENABLE + ALLNS */
        __asm volatile ("dsb sy" ::: "memory");
        __asm volatile ("isb sy" ::: "memory");

        /* Mark MPCBB3 registers 36-39 as non-secure for ETHMEM */
        for (i = 36; i <= 39; i++) {
            GTZC1_MPCBB3_SECCFGR(i) = 0x00000000u;
            GTZC1_MPCBB3_PRIVCFGR(i) = 0x00000000u;
        }
        __asm volatile ("dsb sy" ::: "memory");

        /* Mark Ethernet MAC as non-secure in TZSC */
        GTZC1_TZSC_SECCFGR3 &= ~(1u << 11);
        __asm volatile ("dsb sy" ::: "memory");
    }
#endif

    uart_puts("Initializing wolfIP stack...\n");
    wolfIP_init_static(&IPStack);

    /* Initialize GPIO pins for RMII - MUST happen before Ethernet clocks! */
    uart_puts("Configuring GPIO for RMII...\n");
    eth_gpio_init();

    /* Enable Ethernet MAC, TX, RX clocks AFTER RMII mode is selected */
    uart_puts("Enabling Ethernet clocks...\n");
    RCC_AHB1ENR |= (1u << 19) | (1u << 20) | (1u << 21);
    delay(10000);  /* Allow clocks to stabilize */

    /* Reset Ethernet MAC via RCC - this is CRITICAL! (from FrostZone) */
    uart_puts("Resetting Ethernet MAC...\n");
    RCC_AHB1RSTR |= RCC_AHB1RSTR_ETHRST;
    __asm volatile ("dsb sy" ::: "memory");
    delay(1000);
    RCC_AHB1RSTR &= ~RCC_AHB1RSTR_ETHRST;
    __asm volatile ("dsb sy" ::: "memory");
    delay(10000);

    uart_puts("Initializing Ethernet MAC...\n");
    ll = wolfIP_getdev(IPStack);
    ret = stm32h5_eth_init(ll, NULL);
    if (ret < 0) {
        uart_puts("  ERROR: stm32h5_eth_init failed (");
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
        uint32_t dhcp_timeout;

        dhcp_timeout = 30000;  /* 30 seconds timeout */

        (void)wolfIP_poll(IPStack, tick);
        if (dhcp_client_init(IPStack) >= 0) {
            /* Poll immediately to send the DHCP discover packet */
            (void)wolfIP_poll(IPStack, tick);
            tick++;
            delay(1000);
            (void)wolfIP_poll(IPStack, tick);
            tick++;
            delay(1000);

            /* Wait for DHCP to complete - poll frequently */
            dhcp_start_tick = tick;
            while (!dhcp_bound(IPStack)) {
                /* Poll the stack - this processes received packets and sends pending data */
                (void)wolfIP_poll(IPStack, tick);
                /* Increment tick counter (approximate 1ms per iteration) */
                tick++;
                /* Small delay to allow Ethernet DMA to work */
                delay(1000);
                /* Check for timeout */
                if ((tick - dhcp_start_tick) > dhcp_timeout)
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
            }
        }
    }
#else
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
#endif

    uart_puts("Creating TCP socket on port 7...\n");
    listen_fd = wolfIP_sock_socket(IPStack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    wolfIP_register_callback(IPStack, listen_fd, echo_cb, IPStack);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(ECHO_PORT);
    addr.sin_addr.s_addr = 0;
    (void)wolfIP_sock_bind(IPStack, listen_fd, (struct wolfIP_sockaddr *)&addr, sizeof(addr));
    (void)wolfIP_sock_listen(IPStack, listen_fd, 1);

    uart_puts("Entering main loop. Ready for connections!\n");
    uart_puts("Loop starting...\n");

    for (;;) {
        (void)wolfIP_poll(IPStack, tick++);
        /* Toggle LED every ~256K iterations as heartbeat */
        if ((tick & 0x3FFFF) == 0) {
            led_toggle();
        }
    }
    return 0;
}

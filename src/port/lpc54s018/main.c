/* main.c
 *
 * LPC54S018M-EVK wolfIP Bare Metal Port
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
#include "lpc54s018_eth.h"

/* SYSCON (0x40000000) */
#define SYSCON_BASE         0x40000000UL
#define SYSCON_REG(off)     (*(volatile uint32_t *)(SYSCON_BASE + (off)))
#define AHBCLKCTRL2         SYSCON_REG(0x208U)
#define PRESETCTRL2         SYSCON_REG(0x108U)
#define AHBCLKCTRLSET0      SYSCON_REG(0x220U)
#define AHBCLKCTRLSET1      SYSCON_REG(0x224U)
#define AHBCLKCTRLSET2      SYSCON_REG(0x228U)
#define PRESETCTRLSET1      SYSCON_REG(0x124U)
#define PRESETCTRLCLR1      SYSCON_REG(0x144U)
#define ETHPHYSEL           SYSCON_REG(0x450U)
#define FCLKSEL0            SYSCON_REG(0x508U)
#define FROCTRL             SYSCON_REG(0x550U)
#define MAINCLKSELA         SYSCON_REG(0x280U)
#define MAINCLKSELB         SYSCON_REG(0x284U)
#define AHBCLKDIV           SYSCON_REG(0x380U)
#define FLASHCFG            SYSCON_REG(0x400U)

/* IOCON (0x40001000) */
#define IOCON_BASE          0x40001000UL
#define IOCON_PIN(port, pin) (*(volatile uint32_t *)(IOCON_BASE + ((port) * 32U + (pin)) * 4U))
#define IOCON_DIGITAL_EN    (1U << 8)
#define IOCON_INPFILT_OFF   (1U << 9)
#define IOCON_MODE_PULLUP   (2U << 4)

/* GPIO (0x4008C000) */
#define GPIO_BASE           0x4008C000UL
#define GPIO_DIR(port)      (*(volatile uint32_t *)(GPIO_BASE + 0x2000U + (port) * 4U))
#define GPIO_SET(port)      (*(volatile uint32_t *)(GPIO_BASE + 0x2200U + (port) * 4U))
#define GPIO_CLR(port)      (*(volatile uint32_t *)(GPIO_BASE + 0x2280U + (port) * 4U))
#define GPIO_NOT(port)      (*(volatile uint32_t *)(GPIO_BASE + 0x2300U + (port) * 4U))

/* Flexcomm0 / USART0 (0x40086000) */
#define FC0_BASE            0x40086000UL
#define FC0_REG(off)        (*(volatile uint32_t *)(FC0_BASE + (off)))
#define FC0_PSELID          FC0_REG(0xFF8U)
#define USART0_CFG          FC0_REG(0x000U)
#define USART0_BRG          FC0_REG(0x020U)
#define USART0_FIFOCFG      FC0_REG(0xE00U)

/* SysTick */
#define SYST_CSR            (*(volatile uint32_t *)0xE000E010UL)
#define SYST_RVR            (*(volatile uint32_t *)0xE000E014UL)
#define SYST_CVR            (*(volatile uint32_t *)0xE000E018UL)

/* System clock: 96 MHz (FRO HF) */
#define SYSTEM_CLOCK_HZ     96000000U

#define DHCP_TIMEOUT_MS     30000U
#define DHCP_REINIT_MS      10000U

static volatile uint64_t tick_ms;

void SysTick_Handler(void)
{
    tick_ms++;
}

/* Atomic read of 64-bit tick_ms on 32-bit Cortex-M4.
 * Briefly disables interrupts to prevent torn reads. */
static uint64_t get_tick_ms(void)
{
    uint64_t val;
    __asm volatile ("cpsid i" ::: "memory");
    val = tick_ms;
    __asm volatile ("cpsie i" ::: "memory");
    return val;
}

uint32_t wolfIP_getrandom(void)
{
    static uint32_t lfsr;
    static int seeded = 0;
    if (!seeded) {
        lfsr = (uint32_t)get_tick_ms();
        if (lfsr == 0U) lfsr = 0x1A2B3C4DU;
        seeded = 1;
    }
    lfsr ^= lfsr << 13;
    lfsr ^= lfsr >> 17;
    lfsr ^= lfsr << 5;
    return lfsr;
}

static void delay_ms(uint32_t ms)
{
    uint64_t target = get_tick_ms() + ms;
    while (get_tick_ms() < target) { }
}

static void clock_init(void)
{
    AHBCLKCTRLSET0 = (1U << 3) | (1U << 4) | (1U << 5) | (1U << 6);
    AHBCLKCTRLSET0 = (1U << 13) | (1U << 14) | (1U << 15) |
                     (1U << 16) | (1U << 17);
    AHBCLKCTRLSET2 = (1U << 2) | (1U << 3);

    FROCTRL |= (1U << 30);  /* FRO HF 96 MHz */
    FLASHCFG = (FLASHCFG & ~0xFU) | 0x4U;  /* 4 wait states for 96 MHz */
    MAINCLKSELA = 3;  /* FRO HF */
    MAINCLKSELB = 0;  /* MAINCLKSELA output */
    AHBCLKDIV = 0;
}

static void usart0_init(void)
{
    AHBCLKCTRLSET1 = (1U << 11);
    PRESETCTRLSET1 = (1U << 11);
    for (volatile uint32_t i = 0; i < 100; i++) { }
    PRESETCTRLCLR1 = (1U << 11);

    FCLKSEL0 = 4U;  /* FRO_HF 96 MHz */
    IOCON_PIN(0, 30) = 1U | IOCON_DIGITAL_EN;
    IOCON_PIN(0, 29) = 1U | IOCON_DIGITAL_EN;
    FC0_PSELID = 1U;
    USART0_CFG = 0;
    USART0_BRG = 51U;  /* 96M / (16*52) = 115384 baud */
    USART0_FIFOCFG = (1U << 0) | (1U << 1);
    USART0_CFG = (1U << 0) | (1U << 2);
}

static void systick_init(void)
{
    SYST_RVR = (SYSTEM_CLOCK_HZ / 1000U) - 1U;
    SYST_CVR = 0;
    SYST_CSR = 0x07U;
}

static void eth_gpio_init(void)
{
    IOCON_PIN(4,  8) = 1U | IOCON_DIGITAL_EN | IOCON_INPFILT_OFF;  /* TXD0 */
    IOCON_PIN(0, 17) = 7U | IOCON_DIGITAL_EN | IOCON_INPFILT_OFF;  /* TXD1 */
    IOCON_PIN(4, 13) = 1U | IOCON_DIGITAL_EN | IOCON_INPFILT_OFF;  /* TX_EN */
    IOCON_PIN(4, 11) = 1U | IOCON_DIGITAL_EN | IOCON_INPFILT_OFF;  /* RXD0 */
    IOCON_PIN(4, 12) = 1U | IOCON_DIGITAL_EN | IOCON_INPFILT_OFF;  /* RXD1 */
    IOCON_PIN(4, 10) = 1U | IOCON_DIGITAL_EN | IOCON_INPFILT_OFF;  /* RX_DV */
    IOCON_PIN(4, 14) = 1U | IOCON_DIGITAL_EN | IOCON_INPFILT_OFF;  /* REF_CLK */
    IOCON_PIN(1, 16) = 1U | IOCON_DIGITAL_EN | IOCON_INPFILT_OFF;  /* MDC */
    IOCON_PIN(1, 23) = 4U | IOCON_DIGITAL_EN | IOCON_INPFILT_OFF;  /* MDIO */

    IOCON_PIN(2, 26) = 0U | IOCON_DIGITAL_EN | IOCON_MODE_PULLUP;
    GPIO_DIR(2) |= (1U << 26);
    GPIO_SET(2) = (1U << 26);
}

static void phy_reset(void)
{
    GPIO_CLR(2) = (1U << 26);
    delay_ms(1);
    GPIO_SET(2) = (1U << 26);
    delay_ms(50);
}

static void eth_clk_init(void)
{
    AHBCLKCTRLSET2 = (1U << 8);
    PRESETCTRL2 = (1U << 8);
    PRESETCTRL2 &= ~(1U << 8);
    ETHPHYSEL |= (1U << 2);  /* RMII before DMA reset */
}

static void led_init(void)
{
    IOCON_PIN(3, 14) = 0U | IOCON_DIGITAL_EN;
    GPIO_DIR(3) |= (1U << 14);
    GPIO_CLR(3) = (1U << 14);
}

static void led_toggle(void)
{
    GPIO_NOT(3) = (1U << 14);
}

static struct wolfIP *IPStack;

/* TCP Echo Server (port 7) */
#define ECHO_PORT 7
static int listen_fd = -1;
static int client_fd = -1;
static uint8_t rx_buf[512];

static void echo_cb(int fd, uint16_t event, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    int ret;

    if ((fd == listen_fd) && (event & CB_EVENT_READABLE) && (client_fd == -1)) {
        client_fd = wolfIP_sock_accept(s, listen_fd, NULL, NULL);
        if (client_fd > 0)
            wolfIP_register_callback(s, client_fd, echo_cb, s);
        return;
    }

    if ((fd == client_fd) && (event & CB_EVENT_READABLE)) {
        ret = wolfIP_sock_recvfrom(s, client_fd, rx_buf, sizeof(rx_buf),
                                   0, NULL, NULL);
        if (ret > 0) {
            (void)wolfIP_sock_sendto(s, client_fd, rx_buf, (uint32_t)ret,
                                     0, NULL, 0);
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
    int ret;

    clock_init();
    usart0_init();
    systick_init();
    led_init();

    printf("\r\n=== wolfIP LPC54S018M-EVK ===\r\n");

    eth_gpio_init();
    phy_reset();
    eth_clk_init();

    wolfIP_init_static(&IPStack);

    ll = wolfIP_getdev(IPStack);
    ret = lpc54s018_eth_init(ll, NULL);
    if (ret < 0) {
        printf("ETH init failed (%d)\r\n", ret);
    } else {
        printf("PHY addr=%d link=%s\r\n",
               ret & 0xFF, (ret & 0x100) ? "UP" : "DOWN");
    }

    /* IP configuration: DHCP or static fallback */
#ifdef DHCP
    printf("Starting DHCP...\r\n");
    (void)wolfIP_poll(IPStack, get_tick_ms());  /* Prime last_tick */
    (void)dhcp_client_init(IPStack);
#else
    {
        ip4 ip = atoip4(WOLFIP_IP);
        ip4 nm = atoip4(WOLFIP_NETMASK);
        ip4 gw = atoip4(WOLFIP_GW);
        wolfIP_ipconfig_set(IPStack, ip, nm, gw);
        printf("Static IP: %s\r\n", WOLFIP_IP);
    }
#endif

    /* TCP echo server on port 7 */
    {
        struct wolfIP_sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = ee16(ECHO_PORT);
        addr.sin_addr.s_addr = 0;
        listen_fd = wolfIP_sock_socket(IPStack, AF_INET, IPSTACK_SOCK_STREAM, 0);
        wolfIP_register_callback(IPStack, listen_fd, echo_cb, IPStack);
        (void)wolfIP_sock_bind(IPStack, listen_fd,
                               (struct wolfIP_sockaddr *)&addr, sizeof(addr));
        (void)wolfIP_sock_listen(IPStack, listen_fd, 1);
    }

    printf("Ready! ping <ip> / echo test | nc <ip> 7\r\n");

    /* Main loop */
    {
        uint64_t last_led_ms = 0;
#ifdef DHCP
        uint64_t dhcp_start_ms = get_tick_ms();
        uint64_t dhcp_reinit_ms = get_tick_ms();
        int dhcp_done = 0;
#endif

        for (;;) {
            uint64_t now = get_tick_ms();
            (void)wolfIP_poll(IPStack, now);

#ifdef DHCP
            if (!dhcp_done) {
                if (dhcp_bound(IPStack)) {
                    ip4 ip = 0, nm = 0, gw = 0;
                    wolfIP_ipconfig_get(IPStack, &ip, &nm, &gw);
                    printf("DHCP bound: %u.%u.%u.%u\r\n",
                        (unsigned)((ip >> 24) & 0xFF),
                        (unsigned)((ip >> 16) & 0xFF),
                        (unsigned)((ip >> 8) & 0xFF),
                        (unsigned)(ip & 0xFF));
                    dhcp_done = 1;
                } else if ((now - dhcp_start_ms) > DHCP_TIMEOUT_MS) {
                    ip4 ip = 0, nm = 0, gw = 0;
                    wolfIP_ipconfig_get(IPStack, &ip, &nm, &gw);
                    if (ip == 0) {
                        printf("DHCP timeout, using static IP\r\n");
                        wolfIP_ipconfig_set(IPStack,
                            atoip4(WOLFIP_IP), atoip4(WOLFIP_NETMASK),
                            atoip4(WOLFIP_GW));
                    }
                    dhcp_done = 1;
                } else if ((now - dhcp_reinit_ms) > DHCP_REINIT_MS) {
                    (void)dhcp_client_init(IPStack);
                    dhcp_reinit_ms = now;
                }
            }
#endif

            if ((now - last_led_ms) >= 2000U) {
                led_toggle();
                last_led_ms = now;
            }
        }
    }

    return 0;
}

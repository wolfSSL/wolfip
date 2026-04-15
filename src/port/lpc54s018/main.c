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
#define PRESETCTRLSET2      SYSCON_REG(0x128U)
#define PRESETCTRLCLR2      SYSCON_REG(0x148U)
#define AHBCLKCTRLSET0      SYSCON_REG(0x220U)
#define AHBCLKCTRLSET1      SYSCON_REG(0x224U)
#define AHBCLKCTRLSET2      SYSCON_REG(0x228U)
#define PRESETCTRLSET1      SYSCON_REG(0x124U)
#define PRESETCTRLCLR1      SYSCON_REG(0x144U)
#define ETHPHYSEL           SYSCON_REG(0x450U)
#define FCLKSEL0            SYSCON_REG(0x2B0U)
#define FROCTRL             SYSCON_REG(0x550U)
#define MAINCLKSELA         SYSCON_REG(0x280U)
#define MAINCLKSELB         SYSCON_REG(0x284U)
#define AHBCLKDIV           SYSCON_REG(0x380U)
#define FLASHCFG            SYSCON_REG(0x400U)
#define PRESETCTRL1         SYSCON_REG(0x104U)

/* IOCON (0x40001000) */
#define IOCON_BASE          0x40001000UL
#define IOCON_PIN(port, pin) (*(volatile uint32_t *)(IOCON_BASE + ((port) * 32U + (pin)) * 4U))
#define IOCON_DIGITAL_EN    (1U << 8)
#define IOCON_INPFILT_OFF   (1U << 9)
#define IOCON_MODE_PULLUP   (2U << 4)
#define IOCON_OD            (1U << 11)  /* Open-drain (for bidirectional pins) */

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
#define USART0_OSR          FC0_REG(0x028U)
#define USART0_FIFOCFG      FC0_REG(0xE00U)

/* SysTick */
#define SYST_CSR            (*(volatile uint32_t *)0xE000E010UL)
#define SYST_RVR            (*(volatile uint32_t *)0xE000E014UL)
#define SYST_CVR            (*(volatile uint32_t *)0xE000E018UL)

/* System clock: 48 MHz (FRO_HF 96 MHz / AHBCLKDIV=2 left by boot ROM) */
#define SYSTEM_CLOCK_HZ     48000000U

#define DHCP_TIMEOUT_MS     30000U
#define DHCP_REINIT_MS      10000U

static volatile uint64_t tick_ms;

void SysTick_Handler(void)
{
    tick_ms++;
}

/* Atomic read of 64-bit tick_ms on 32-bit Cortex-M4.
 * Briefly disables interrupts to prevent torn reads while preserving
 * the caller's prior interrupt mask state (save/restore PRIMASK rather
 * than blindly re-enabling). */
static uint64_t get_tick_ms(void)
{
    uint64_t val;
    uint32_t primask;
    __asm volatile ("mrs %0, primask" : "=r" (primask) :: "memory");
    __asm volatile ("cpsid i" ::: "memory");
    val = tick_ms;
    __asm volatile ("msr primask, %0" :: "r" (primask) : "memory");
    return val;
}

uint32_t wolfIP_getrandom(void)
{
    static uint32_t lfsr;
    static int seeded = 0;
    if (!seeded) {
        /* Mix tick_ms with SysTick CVR (24-bit free-running, fast). Even
         * a few ms of jitter at boot gives ~10 bits of entropy. NOTE: this
         * is NOT a cryptographic RNG; for production use a HW RNG or
         * wolfCrypt RNG seeded via a real entropy source. */
        lfsr = (uint32_t)get_tick_ms() ^ (SYST_CVR << 8);
        if (lfsr == 0U) lfsr = 0x1A2B3C4DU;
        seeded = 1;
    }
    /* Mix in SysTick CVR each call so xact timing jitter feeds entropy. */
    lfsr ^= SYST_CVR;
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
    /* Enable peripheral clocks only. Do NOT change MAINCLKSELA/FROCTRL —
     * the boot ROM already configured the main clock for SPIFI XIP.
     * Changing MAINCLK before UART init would break FCLKSEL=0 (FRO 12MHz)
     * if FCLKSEL=0 routes through the main clock mux. wolfBoot HAL also
     * leaves boot ROM clock setup untouched. */
    AHBCLKCTRLSET0 = (1U << 13) | (1U << 14) | (1U << 15) |
                     (1U << 16) | (1U << 17);  /* IOCON, GPIO0-3 */
    AHBCLKCTRLSET2 = (1U << 2) | (1U << 3);    /* GPIO4-5 */
}

static void usart0_init(void)
{
    volatile int i;

    /* Pin mux: P0_30=FC0_TXD, P0_29=FC0_RXD (function 1, digital) */
    IOCON_PIN(0, 30) = 1U | IOCON_DIGITAL_EN;
    IOCON_PIN(0, 29) = 1U | IOCON_DIGITAL_EN;

    /* Select FRO 12 MHz as Flexcomm0 clock source (FCLKSEL0 at 0x2B0 per wolfBoot HAL) */
    FCLKSEL0 = 0U;

    /* Enable Flexcomm0 clock (atomic SET) */
    AHBCLKCTRLSET1 = (1U << 11);

    /* Reset Flexcomm0: SET=assert (bit→1), CLR=deassert (bit→0).
     * LPC54S018 PRESETCTRL polarity: 1=in-reset, 0=released. */
    PRESETCTRLSET1 = (1U << 11);
    while (!(PRESETCTRL1 & (1U << 11))) { }
    PRESETCTRLCLR1 = (1U << 11);
    while (PRESETCTRL1 & (1U << 11)) { }

    /* Small delay after reset deassertion */
    for (i = 0; i < 100; i++) { }

    /* Select USART mode */
    FC0_PSELID = 1U;

    /* Configure 8N1 (disabled initially) */
    USART0_CFG = (1U << 2);

    /* Baud: 12 MHz / (13 * 8) = 115384 (matches wolfBoot HAL proven config) */
    USART0_OSR = 12U;
    USART0_BRG = 7U;

    /* Enable and flush FIFOs */
    USART0_FIFOCFG = (1U << 0) | (1U << 1) | (1U << 16) | (1U << 17);

    /* Enable USART */
    USART0_CFG |= (1U << 0);
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
    /* MDIO is bidirectional (open-drain with external pull-up on the PHY).
     * Without IOCON_MODE_PULLUP/OD set, the pin floats when MAC releases it
     * and PHY responses can be missed - leading to phy_detect() failure. */
    IOCON_PIN(1, 23) = 4U | IOCON_DIGITAL_EN | IOCON_INPFILT_OFF |
                       IOCON_MODE_PULLUP | IOCON_OD;  /* MDIO */

    IOCON_PIN(2, 26) = 0U | IOCON_DIGITAL_EN | IOCON_MODE_PULLUP;
    GPIO_DIR(2) |= (1U << 26);
    GPIO_SET(2) = (1U << 26);
}

static void phy_reset(void)
{
    GPIO_CLR(2) = (1U << 26);
    delay_ms(10);
    GPIO_SET(2) = (1U << 26);
    /* LAN8742A needs ~167ms post-release for REF_CLK to stabilize before
     * MDIO is reliable. STM32H753 port uses ~200ms. */
    delay_ms(200);
}

static void eth_clk_init(void)
{
    AHBCLKCTRLSET2 = (1U << 8);
    PRESETCTRLSET2 = (1U << 8);   /* Assert ENET reset */
    for (volatile uint32_t i = 0; i < 100; i++) { }
    PRESETCTRLCLR2 = (1U << 8);   /* Release ENET reset */
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
    } else if (lpc_enet_phy_addr() >= 0) {
        uint16_t id1 = lpc_enet_phy_read(2);  /* PHY_ID1 */
        uint16_t id2 = lpc_enet_phy_read(3);  /* PHY_ID2 */
        uint16_t bsr = lpc_enet_phy_read(1);  /* BSR */
        printf("PHY: addr=%d ID=%04x:%04x BSR=%04x autoneg=%s link=%s\r\n",
               lpc_enet_phy_addr(), id1, id2, bsr,
               (bsr & 0x20) ? "OK" : "no",
               (bsr & 0x04) ? "UP" : "DOWN");
    }
    /* If MDIO management plane isn't responding, the MAC still runs on PHY
     * power-on defaults (auto-negotiation enabled). We silently continue -
     * link will come up and DHCP will proceed. The PHY helpers remain
     * available via lpc_enet_phy_addr()/lpc_enet_phy_read() for future
     * diagnostics. */

    /* IP configuration: DHCP or static fallback */
#ifdef DHCP
    /* If PHY MDIO management is responsive, wait up to 5s for link UP.
     * Otherwise proceed: PHY auto-negotiates from power-on defaults and
     * DHCP retries every 10s until bound (or 30s fallback to static IP). */
    if (ret >= 0 && lpc_enet_phy_addr() >= 0) {
        uint64_t deadline = get_tick_ms() + 5000U;
        while (get_tick_ms() < deadline) {
            uint16_t bsr = lpc_enet_phy_read(1);
            bsr |= lpc_enet_phy_read(1);  /* latch trick for link bit */
            if (bsr & 0x04U) break;
            delay_ms(50);
        }
        printf("PHY link: %s\r\n",
               (lpc_enet_phy_read(1) & 0x04U) ? "UP"
                                              : "DOWN (DHCP will retry on link-up)");
    }

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
        if (listen_fd < 0) {
            printf("Echo server socket failed (%d)\r\n", listen_fd);
        } else {
            wolfIP_register_callback(IPStack, listen_fd, echo_cb, IPStack);
            (void)wolfIP_sock_bind(IPStack, listen_fd,
                                   (struct wolfIP_sockaddr *)&addr, sizeof(addr));
            (void)wolfIP_sock_listen(IPStack, listen_fd, 1);
        }
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
                    /* Only re-issue DISCOVER when PHY link is UP -
                     * avoids flooding when cable is unplugged. If PHY
                     * isn't detected, retry unconditionally (PHY power-on
                     * defaults may still be negotiating). */
                    if (lpc_enet_phy_addr() < 0 ||
                        (lpc_enet_phy_read(1) & 0x04U)) {
                        (void)dhcp_client_init(IPStack);
                    }
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

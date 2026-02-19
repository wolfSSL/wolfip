/* main.c
 *
 * VA416xx wolfIP Echo Server Test Application
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
#include "va416xx_eth.h"

#include "va416xx.h"
#include "va416xx_hal.h"
#include "va416xx_hal_uart.h"
#include "va416xx_hal_ioconfig.h"
#include "va416xx_hal_clkgen.h"
#include "board.h"

/* HAL_time_ms: millisecond tick counter maintained by SysTick ISR (10ms
 * resolution by default).  Used as the wolfIP `now` parameter so that all
 * stack timers (DHCP, ARP, TCP retransmit, etc.) run in real wall-clock
 * time rather than depending on CPU loop speed. */
extern volatile uint64_t HAL_time_ms;

#define ECHO_PORT       7
#define RX_BUF_SIZE     1024

/* DHCP timeout in milliseconds */
#define DHCP_TIMEOUT_MS 60000U

static struct wolfIP *IPStack;
static int listen_fd = -1;
static int client_fd = -1;
static uint8_t rx_buf[RX_BUF_SIZE];

/* ========================================================================= */
/* wolfIP random number generator (required by stack)                        */
/* ========================================================================= */

uint32_t wolfIP_getrandom(void)
{
    static uint32_t lfsr = 0x1A2B3C4DU;
    lfsr ^= lfsr << 13;
    lfsr ^= lfsr >> 17;
    lfsr ^= lfsr << 5;
    return lfsr;
}

/* ========================================================================= */
/* LED on EVK top board (PORTG pin 5)                                        */
/* ========================================================================= */

static void led_init(void)
{
    /* Enable PORTG clock (HAL_Init already does this, but be safe) */
    VOR_SYSCONFIG->PERIPHERAL_CLK_ENABLE |=
        SYSCONFIG_PERIPHERAL_CLK_ENABLE_PORTG_Msk;

    /* Set PORTG pin 5 as output */
    EVK_LED_BANK.DIR |= (1U << EVK_LED_PIN);
}

static void led_on(void)
{
    EVK_LED_BANK.SETOUT = (1U << EVK_LED_PIN);
}

static void led_toggle(void)
{
    EVK_LED_BANK.TOGOUT = (1U << EVK_LED_PIN);
}

/* ========================================================================= */
/* UART0 Debug Output (PORTG pins 0=TX, 1=RX, funsel=1)                     */
/* ========================================================================= */

static void uart_init(void)
{
    /* Configure UART0 pins: PORTG[0]=TX, PORTG[1]=RX, funsel=1
     * (matches PEB1 EVK routing / wolfBoot configuration) */
    HAL_Iocfg_PinMux(VOR_PORTG, 0, 1);
    HAL_Iocfg_PinMux(VOR_PORTG, 1, 1);

    /* Initialize UART0 at 115200 8N1 */
    HAL_Uart_Init(VOR_UART0, UART_CFG_115K_8N1);
}

/* ========================================================================= */
/* Ethernet MII Pin Configuration                                            */
/* PORTA[8-15] and PORTB[0-10], all funsel=1                                */
/* ========================================================================= */

static void eth_gpio_init(void)
{
    uint32_t pin;

    /* Enable PORTA and PORTB clocks */
    VOR_SYSCONFIG->PERIPHERAL_CLK_ENABLE |=
        SYSCONFIG_PERIPHERAL_CLK_ENABLE_PORTA_Msk |
        SYSCONFIG_PERIPHERAL_CLK_ENABLE_PORTB_Msk;

    /* PORTA pins 8-15: MII signals */
    for (pin = 8; pin <= 15; pin++) {
        HAL_Iocfg_PinMux(VOR_PORTA, pin, 1);
    }

    /* PORTB pins 0-10: MII signals */
    for (pin = 0; pin <= 10; pin++) {
        HAL_Iocfg_PinMux(VOR_PORTB, pin, 1);
    }
}

/* ========================================================================= */
/* Ethernet Peripheral Clock and Reset                                       */
/* ========================================================================= */

static void eth_clk_init(void)
{
    /* Enable ETH peripheral clock */
    VOR_SYSCONFIG->PERIPHERAL_CLK_ENABLE |=
        SYSCONFIG_PERIPHERAL_CLK_ENABLE_ETH_Msk;

    /* Assert ETH reset (clear bit), then release (set bit)
     * All SDK peripheral drivers use this clear-then-set pattern */
    VOR_SYSCONFIG->PERIPHERAL_RESET &=
        ~SYSCONFIG_PERIPHERAL_RESET_ETH_Msk;
    for (volatile uint32_t i = 0; i < 1000; i++) { }
    VOR_SYSCONFIG->PERIPHERAL_RESET |=
        SYSCONFIG_PERIPHERAL_RESET_ETH_Msk;

    /* Brief delay for clock to stabilize */
    for (volatile uint32_t i = 0; i < 10000; i++) { }
}

/* ========================================================================= */
/* UART Debug Helpers                                                        */
/* ========================================================================= */

static void uart_putip4(ip4 ip)
{
    printf("%u.%u.%u.%u",
        (unsigned)((ip >> 24) & 0xFF),
        (unsigned)((ip >> 16) & 0xFF),
        (unsigned)((ip >> 8) & 0xFF),
        (unsigned)(ip & 0xFF));
}

/* ========================================================================= */
/* TCP Echo Server Callback                                                  */
/* ========================================================================= */

static void echo_cb(int fd, uint16_t event, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    int ret;

    if ((fd == listen_fd) && (event & CB_EVENT_READABLE) && (client_fd == -1)) {
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

/* ========================================================================= */
/* Main                                                                      */
/* ========================================================================= */

int main(void)
{
    struct wolfIP_ll_dev *ll;
    struct wolfIP_sockaddr_in addr;
    int ret;

    /* 1. HAL init: clocks (GPIO, IOCONFIG, CLKGEN), SysTick, IRQ router */
    HAL_Init();

    /* 2. Update SystemCoreClock, then configure PLL for 100MHz
     * PEB1 EVK has 40MHz crystal, * 2.5 = 100MHz */
    SystemCoreClockUpdate();
    (void)HAL_Clkgen_PLL(CLK_CTRL0_XTAL_N_PLL2P5X);

    /* 3. Disable Watchdog (should be disabled out of reset, but be safe) */
    VOR_WATCH_DOG->WDOGLOCK    = 0x1ACCE551;
    VOR_WATCH_DOG->WDOGCONTROL = 0x0;
    NVIC_ClearPendingIRQ(WATCHDOG_IRQn);

    /* 4. LED on immediately to confirm code is running */
    led_init();
    led_on();

    /* 5. UART0 for debug output */
    uart_init();

    printf("\n\n=== wolfIP VA416xx Echo Server ===\n");
    printf("Build: " __DATE__ " " __TIME__ "\n");

    /* 6. Configure ETH GPIO pins (MII) */
    eth_gpio_init();

    /* 7. Enable ETH peripheral clock and release reset */
    eth_clk_init();

    /* 8. Initialize wolfIP stack */
    wolfIP_init_static(&IPStack);

    /* 9. Initialize Ethernet driver */
    printf("Initializing Ethernet...\n");
    ll = wolfIP_getdev(IPStack);
    ret = va416xx_eth_init(ll, NULL);
    if (ret < 0) {
        printf("  ERROR: va416xx_eth_init failed (%d)\n", ret);
    }

    /* 8. IP configuration: DHCP with static fallback */
#ifdef DHCP
    {
        uint64_t dhcp_start_ms;

        printf("Starting DHCP...\n");
        /* Prime wolfIP's last_tick before starting DHCP.  Without this,
         * last_tick=0 but HAL_time_ms is already ~2000 (boot time elapsed),
         * so the first DHCP timer expires immediately. */
        (void)wolfIP_poll(IPStack, HAL_time_ms);
        if (dhcp_client_init(IPStack) >= 0) {
            dhcp_start_ms = HAL_time_ms;
            while (!dhcp_bound(IPStack)) {
                (void)wolfIP_poll(IPStack, HAL_time_ms);
                if ((HAL_time_ms - dhcp_start_ms) > DHCP_TIMEOUT_MS)
                    break;
            }
            if (dhcp_bound(IPStack)) {
                ip4 ip = 0, nm = 0, gw = 0;
                wolfIP_ipconfig_get(IPStack, &ip, &nm, &gw);
                printf("DHCP bound:\n");
                printf("  IP:   "); uart_putip4(ip); printf("\n");
                printf("  Mask: "); uart_putip4(nm); printf("\n");
                printf("  GW:   "); uart_putip4(gw); printf("\n");
            } else {
                printf("DHCP timeout, using static IP\n");
                {
                    ip4 ip = atoip4("10.0.4.90");
                    ip4 nm = atoip4("255.255.255.0");
                    ip4 gw = atoip4("10.0.4.1");
                    wolfIP_ipconfig_set(IPStack, ip, nm, gw);
                    printf("  IP:   "); uart_putip4(ip); printf("\n");
                }
            }
        } else {
            printf("DHCP init failed, using static IP\n");
            {
                ip4 ip = atoip4("192.168.1.100");
                ip4 nm = atoip4("255.255.255.0");
                ip4 gw = atoip4("192.168.1.1");
                wolfIP_ipconfig_set(IPStack, ip, nm, gw);
            }
        }
    }
#else
    {
        ip4 ip = atoip4(WOLFIP_IP);
        ip4 nm = atoip4(WOLFIP_NETMASK);
        ip4 gw = atoip4(WOLFIP_GW);
        printf("Static IP configuration:\n");
        printf("  IP:   "); uart_putip4(ip); printf("\n");
        printf("  Mask: "); uart_putip4(nm); printf("\n");
        printf("  GW:   "); uart_putip4(gw); printf("\n");
        wolfIP_ipconfig_set(IPStack, ip, nm, gw);
    }
#endif

    /* 9. Create TCP echo server on port 7 */
    printf("Creating TCP echo server on port %d...\n", ECHO_PORT);
    listen_fd = wolfIP_sock_socket(IPStack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    wolfIP_register_callback(IPStack, listen_fd, echo_cb, IPStack);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(ECHO_PORT);
    addr.sin_addr.s_addr = 0;
    (void)wolfIP_sock_bind(IPStack, listen_fd,
                           (struct wolfIP_sockaddr *)&addr, sizeof(addr));
    (void)wolfIP_sock_listen(IPStack, listen_fd, 1);

    printf("Ready! Test with:\n");
    printf("  ping <ip>\n");
    printf("  echo 'hello' | nc <ip> 7\n");
    printf("\nEntering main loop...\n");

    /* 10. Main loop — use HAL_time_ms (SysTick-based, 10ms resolution)
     * so wolfIP timers (TCP, ARP, etc.) run in real wall-clock time. */
    {
        uint64_t last_led_ms = 0;
        uint64_t last_diag_ms = 0;

        for (;;) {
            uint64_t now = HAL_time_ms;
            (void)wolfIP_poll(IPStack, now);

            /* LED heartbeat: toggle every ~2 seconds */
            if ((now - last_led_ms) >= 2000U) {
                led_toggle();
                last_led_ms = now;
            }

            /* Periodic diagnostics every ~10 seconds */
            if ((now - last_diag_ms) >= 10000U) {
                uint32_t polls, pkts, tx_pkts, tx_errs;
                va416xx_eth_get_stats(&polls, &pkts, &tx_pkts, &tx_errs);
                printf("[%lu ms] rx=%lu tx=%lu tx_err=%lu\n",
                       (unsigned long)now, (unsigned long)pkts,
                       (unsigned long)tx_pkts, (unsigned long)tx_errs);
                last_diag_ms = now;
            }
        }
    }

    return 0;
}

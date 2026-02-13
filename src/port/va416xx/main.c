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
#include "board.h"

#define ECHO_PORT       7
#define RX_BUF_SIZE     1024

/* DHCP timeout in milliseconds */
#define DHCP_TIMEOUT_MS 30000U

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
/* UART0 Debug Output (PORTG pins 2=TX, 3=RX, funsel=1)                     */
/* ========================================================================= */

static void uart_init(void)
{
    /* Configure UART0 pins: PORTG[2]=TX, PORTG[3]=RX, funsel=1 */
    HAL_Iocfg_PinMux(VOR_PORTG, 2, 1);
    HAL_Iocfg_PinMux(VOR_PORTG, 3, 1);

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

    /* Release ETH from reset */
    VOR_SYSCONFIG->PERIPHERAL_RESET |=
        SYSCONFIG_PERIPHERAL_RESET_ETH_Msk;

    /* Brief delay for clock to stabilize */
    for (volatile uint32_t i = 0; i < 10000; i++) { }
}

/* ========================================================================= */
/* UART Debug Helpers (supplement printf for hex/ip formatting)              */
/* ========================================================================= */

static void uart_puthex(uint32_t val)
{
    const char hex[] = "0123456789ABCDEF";
    char buf[11];
    int i;
    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 8; i++) {
        buf[2 + i] = hex[(val >> (28 - i * 4)) & 0xF];
    }
    buf[10] = '\0';
    printf("%s", buf);
}

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
    uint64_t tick = 0;
    int ret;

    /* 1. HAL init: clocks (GPIO, IOCONFIG, CLKGEN), SysTick, IRQ router */
    HAL_Init();

    /* 2. LED on immediately to confirm code is running */
    led_init();
    led_on();

    /* 3. UART0 for debug output */
    uart_init();

    printf("\n\n=== wolfIP VA416xx Echo Server ===\n");
    printf("Build: " __DATE__ " " __TIME__ "\n");

    /* 4. Configure ETH GPIO pins (MII) */
    printf("Configuring MII pins...\n");
    eth_gpio_init();

    /* 5. Enable ETH peripheral clock and release reset */
    printf("Enabling ETH clock...\n");
    eth_clk_init();

    /* 6. Initialize wolfIP stack */
    printf("Initializing wolfIP stack...\n");
    wolfIP_init_static(&IPStack);

    /* 7. Initialize Ethernet driver */
    printf("Initializing Ethernet MAC + PHY...\n");
    ll = wolfIP_getdev(IPStack);
    ret = va416xx_eth_init(ll, NULL);
    if (ret < 0) {
        printf("  ERROR: va416xx_eth_init failed (");
        uart_puthex((uint32_t)ret);
        printf(")\n");
    } else {
        printf("  PHY link: UP\n");
    }

    /* 8. IP configuration: DHCP with static fallback */
#ifdef DHCP
    {
        uint32_t dhcp_start_tick;

        printf("Starting DHCP...\n");
        if (dhcp_client_init(IPStack) >= 0) {
            dhcp_start_tick = (uint32_t)tick;
            while (!dhcp_bound(IPStack)) {
                (void)wolfIP_poll(IPStack, tick);
                tick++;
                for (volatile uint32_t i = 0; i < 1000; i++) { }
                if ((tick - dhcp_start_tick) > DHCP_TIMEOUT_MS)
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
                    ip4 ip = atoip4("192.168.1.100");
                    ip4 nm = atoip4("255.255.255.0");
                    ip4 gw = atoip4("192.168.1.1");
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

    /* 10. Main loop */
    for (;;) {
        (void)wolfIP_poll(IPStack, tick++);

        /* LED heartbeat: toggle every ~256K iterations */
        if ((tick & 0x3FFFFU) == 0) {
            led_toggle();
        }
    }

    return 0;
}

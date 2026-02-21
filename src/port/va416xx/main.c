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

#define RX_BUF_SIZE     1024

/* DHCP timeout: total time to wait for DHCP before static IP fallback.
 * wolfIP's internal DHCP state machine only retries for ~8 seconds
 * (DHCP_DISCOVER_RETRIES=3 × 2s timeout).  After that it sets state to
 * DHCP_OFF and the UDP socket stops accepting unicast DHCP responses
 * (because DHCP_IS_RUNNING becomes false).  We re-init periodically to
 * keep trying, but must space re-inits apart to avoid socket churn
 * (close/reopen loses in-flight responses). */
#define DHCP_TIMEOUT_MS     120000U  /* 120s total before static fallback */
#define DHCP_REINIT_MS      15000U   /* 15s between DHCP re-init attempts */

static struct wolfIP *IPStack;
static uint8_t rx_buf[RX_BUF_SIZE];

#ifdef SPEED_TEST

/* Combined speed test service (port 9)
 * - RX test: host sends data, device counts bytes (discard)
 * - TX test: device sends data as fast as possible (chargen)
 * Both directions measured simultaneously on one connection. */
#define SPEED_PORT      9
static int speed_listen_fd = -1;
static int speed_client_fd = -1;
static uint32_t speed_rx_bytes;
static uint32_t speed_tx_bytes;
static uint64_t speed_start_ms;

#else

/* Echo server (port 7) */
#define ECHO_PORT       7
static int listen_fd = -1;
static int client_fd = -1;

#endif /* SPEED_TEST */

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

#ifdef SPEED_TEST

/* ========================================================================= */
/* Combined Speed Test Callback (port 9)                                     */
/* Measures RX (discard incoming) and TX (chargen outgoing) simultaneously.  */
/*   RX test: dd if=/dev/zero bs=1460 count=700 | nc <ip> 9                 */
/*   TX test: nc <ip> 9 </dev/null | pv >/dev/null                          */
/* ========================================================================= */

static void speed_cb(int fd, uint16_t event, void *arg)
{
    struct wolfIP *s = (struct wolfIP *)arg;
    int ret;

    /* Accept new connection */
    if ((fd == speed_listen_fd) && (event & CB_EVENT_READABLE) &&
        (speed_client_fd == -1)) {
        speed_client_fd = wolfIP_sock_accept(s, speed_listen_fd, NULL, NULL);
        if (speed_client_fd > 0) {
            printf("Speed: client connected (fd=%d)\n", speed_client_fd);
            wolfIP_register_callback(s, speed_client_fd, speed_cb, s);
            speed_rx_bytes = 0;
            speed_tx_bytes = 0;
            speed_start_ms = HAL_time_ms;
        }
        return;
    }

    if (fd != speed_client_fd)
        return;

    /* RX: read and discard incoming data */
    if (event & CB_EVENT_READABLE) {
        ret = wolfIP_sock_recvfrom(s, speed_client_fd, rx_buf, sizeof(rx_buf),
                                    0, NULL, NULL);
        if (ret > 0) {
            speed_rx_bytes += (uint32_t)ret;
        } else if (ret == 0) {
            goto speed_done;
        }
    }

    /* TX: send pattern data when buffer has space */
    if (event & CB_EVENT_WRITABLE) {
        ret = wolfIP_sock_send(s, speed_client_fd, rx_buf, 1460, 0);
        if (ret > 0) {
            speed_tx_bytes += (uint32_t)ret;
        }
    }

    if (event & CB_EVENT_CLOSED) {
speed_done:
        {
            uint32_t elapsed = (uint32_t)(HAL_time_ms - speed_start_ms);
            uint32_t rx_bps = 0, tx_bps = 0;
            if (elapsed > 0) {
                rx_bps = speed_rx_bytes / (elapsed / 1000U + 1U);
                tx_bps = speed_tx_bytes / (elapsed / 1000U + 1U);
            }
            printf("Speed: %lu ms, RX %lu bytes (~%lu B/s), "
                   "TX %lu bytes (~%lu B/s)\n",
                   (unsigned long)elapsed,
                   (unsigned long)speed_rx_bytes, (unsigned long)rx_bps,
                   (unsigned long)speed_tx_bytes, (unsigned long)tx_bps);
        }
        wolfIP_sock_close(s, speed_client_fd);
        speed_client_fd = -1;
    }
}

#else /* !SPEED_TEST */

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

#endif /* SPEED_TEST */

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

    /* 8. IP configuration: DHCP (non-blocking) or static */
#ifdef DHCP
    printf("Starting DHCP...\n");
    /* Prime wolfIP's last_tick before starting DHCP.  Without this,
     * last_tick=0 but HAL_time_ms is already ~2000 (boot time elapsed),
     * so the first DHCP timer expires immediately. */
    (void)wolfIP_poll(IPStack, HAL_time_ms);
    (void)dhcp_client_init(IPStack);
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

    /* Create TCP services */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = 0;

#ifdef SPEED_TEST
    printf("=== Speed Test Mode ===\n");

    /* Speed test service on port 9 (RX + TX throughput) */
    printf("Creating TCP speed test service on port %d...\n", SPEED_PORT);
    speed_listen_fd = wolfIP_sock_socket(IPStack, AF_INET,
                                          IPSTACK_SOCK_STREAM, 0);
    wolfIP_register_callback(IPStack, speed_listen_fd, speed_cb, IPStack);
    addr.sin_port = ee16(SPEED_PORT);
    (void)wolfIP_sock_bind(IPStack, speed_listen_fd,
                           (struct wolfIP_sockaddr *)&addr, sizeof(addr));
    (void)wolfIP_sock_listen(IPStack, speed_listen_fd, 1);

    printf("Ready! Test with:\n");
    printf("  ping <ip>\n");
    printf("  dd if=/dev/zero bs=1460 count=700 | nc <ip> 9  (RX test)\n");
    printf("  nc <ip> 9 </dev/null | pv >/dev/null  (TX test)\n");
#else
    /* Echo server on port 7 */
    printf("Creating TCP echo server on port %d...\n", ECHO_PORT);
    listen_fd = wolfIP_sock_socket(IPStack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    wolfIP_register_callback(IPStack, listen_fd, echo_cb, IPStack);
    addr.sin_port = ee16(ECHO_PORT);
    (void)wolfIP_sock_bind(IPStack, listen_fd,
                           (struct wolfIP_sockaddr *)&addr, sizeof(addr));
    (void)wolfIP_sock_listen(IPStack, listen_fd, 1);

    printf("Ready! Test with:\n");
    printf("  ping <ip>\n");
    printf("  echo 'hello' | nc <ip> 7\n");
#endif
    printf("\nEntering main loop...\n");

#ifdef TX_SELFTEST
    /* TX Self-Test: send gratuitous ARP frames directly via ll->send() to
     * exercise the TX path at startup before any external traffic arrives.
     * The per-TX diagnostic in eth_send() will print TXFSTS (TX FIFO fill
     * level) at 3 time points: pre-kick, +10µs, +500µs.
     * If hw_tx > 0 after this, the MAC is transmitting to the wire.
     * If hw_tx == 0, the diagnostic TXFSTS values tell us where it breaks. */
    {
        uint8_t garp[42];
        ip4 self_ip = 0, dummy_nm = 0, dummy_gw = 0;
        int i;

        wolfIP_ipconfig_get(IPStack, &self_ip, &dummy_nm, &dummy_gw);

        /* Ethernet header: broadcast dst, our src MAC, ARP ethertype */
        memset(garp, 0xFF, 6);              /* dst: broadcast */
        memcpy(garp + 6, ll->mac, 6);       /* src: our MAC */
        garp[12] = 0x08; garp[13] = 0x06;  /* ethertype: ARP (0x0806) */

        /* ARP payload (28 bytes, gratuitous request) */
        garp[14] = 0x00; garp[15] = 0x01;  /* htype = Ethernet */
        garp[16] = 0x08; garp[17] = 0x00;  /* ptype = IPv4 */
        garp[18] = 6;                       /* hlen = 6 */
        garp[19] = 4;                       /* plen = 4 */
        garp[20] = 0x00; garp[21] = 0x01;  /* op = ARP request */
        memcpy(garp + 22, ll->mac, 6);      /* sha = our MAC */
        garp[28] = (uint8_t)((self_ip >> 24) & 0xFF); /* spa = our IP */
        garp[29] = (uint8_t)((self_ip >> 16) & 0xFF);
        garp[30] = (uint8_t)((self_ip >>  8) & 0xFF);
        garp[31] = (uint8_t)( self_ip        & 0xFF);
        memset(garp + 32, 0, 6);            /* tha = 0:0:0:0:0:0 */
        garp[38] = garp[28]; garp[39] = garp[29]; /* tpa = our IP */
        garp[40] = garp[30]; garp[41] = garp[31];

        printf("TX Self-Test: sending 3 gratuitous ARP frames via ll->send()\n");
        printf("  self_ip=%lu.%lu.%lu.%lu src_mac=%02X:%02X:%02X:%02X:%02X:%02X\n",
               (unsigned long)((self_ip >> 24) & 0xFF),
               (unsigned long)((self_ip >> 16) & 0xFF),
               (unsigned long)((self_ip >>  8) & 0xFF),
               (unsigned long)( self_ip        & 0xFF),
               ll->mac[0], ll->mac[1], ll->mac[2],
               ll->mac[3], ll->mac[4], ll->mac[5]);

        for (i = 0; i < 3; i++) {
            int r = ll->send(ll, garp, 42);
            printf("  send[%d] = %d\n", i, r);
            /* ~50ms delay (at 100MHz: 5M cycles) */
            for (volatile uint32_t d = 0; d < 5000000U; d++) { }
        }

        /* Wait ~200ms then sample MAC MMC counters */
        for (volatile uint32_t d = 0; d < 20000000U; d++) { }
        {
            uint32_t mac_cfg2, mac_dbg2, hw_tx2;
            uint32_t dma_st2;
            va416xx_eth_get_mac_diag(&mac_cfg2, &mac_dbg2, &hw_tx2);
            dma_st2 = va416xx_eth_get_dma_status();
            printf("  Post self-test: hw_tx=%lu dbg=0x%08lX dma=0x%08lX TS=%lu\n",
                   (unsigned long)hw_tx2,
                   (unsigned long)mac_dbg2,
                   (unsigned long)dma_st2,
                   (unsigned long)((dma_st2 >> 20) & 0x7U));
            if (hw_tx2 > 0)
                printf("  *** TX OK: MAC IS TRANSMITTING - issue is MII/PHY ***\n");
            else
                printf("  *** TX FAIL: hw_tx=0 - DMA->MAC TX FIFO path broken ***\n");
        }
    }
#endif /* MAC_LOOPBACK_TEST */

    /* 10. Main loop — use HAL_time_ms (SysTick-based, 10ms resolution)
     * so wolfIP timers (TCP, ARP, etc.) run in real wall-clock time. */
    {
        uint64_t last_led_ms = 0;
        uint64_t last_diag_ms = 0;
#ifdef DHCP
        uint64_t dhcp_start_ms = HAL_time_ms;
        uint64_t dhcp_reinit_ms = HAL_time_ms;
        int dhcp_done = 0;
#endif

        for (;;) {
            uint64_t now = HAL_time_ms;
            (void)wolfIP_poll(IPStack, now);

#ifdef DHCP
            /* Non-blocking DHCP handling.
             *
             * wolfIP's internal DHCP state machine gives up after ~8s
             * (3 retries × 2s).  When state goes to DHCP_OFF, the UDP
             * socket stops accepting unicast DHCP responses (the
             * DHCP_IS_RUNNING check in udp_process fails).
             *
             * We periodically re-init DHCP (every 15s) to restart the
             * state machine and keep the UDP socket accepting responses.
             * Must space re-inits apart to avoid socket churn (the
             * close/reopen cycle can lose in-flight responses). */
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
                    /* Final timeout: check for partial IP from DHCP offer */
                    ip4 ip = 0, nm = 0, gw = 0;
                    wolfIP_ipconfig_get(IPStack, &ip, &nm, &gw);
                    if (ip != 0) {
                        printf("DHCP assigned IP:\n");
                    } else {
                        printf("DHCP timeout, using static IP\n");
                        ip = atoip4("10.0.4.90");
                        nm = atoip4("255.255.255.0");
                        gw = atoip4("10.0.4.1");
                        wolfIP_ipconfig_set(IPStack, ip, nm, gw);
                    }
                    printf("  IP:   "); uart_putip4(ip); printf("\n");
                    printf("  Mask: "); uart_putip4(nm); printf("\n");
                    printf("  GW:   "); uart_putip4(gw); printf("\n");
                    dhcp_done = 1;
                } else if ((now - dhcp_reinit_ms) > DHCP_REINIT_MS) {
                    /* Re-init DHCP if internal state machine expired.
                     * dhcp_client_init only succeeds when state==DHCP_OFF,
                     * so this is a no-op while DHCP is still active. */
                    (void)dhcp_client_init(IPStack);
                    dhcp_reinit_ms = now;
                }
            }
#endif

            /* LED heartbeat: toggle every ~2 seconds */
            if ((now - last_led_ms) >= 2000U) {
                led_toggle();
                last_led_ms = now;
            }

            /* Periodic diagnostics every ~10 seconds */
            if ((now - last_diag_ms) >= 10000U) {
                uint32_t polls, pkts, tx_pkts, tx_errs;
                uint32_t mac_cfg, mac_dbg, hw_tx, dma_st;
                va416xx_eth_get_stats(&polls, &pkts, &tx_pkts, &tx_errs);
                va416xx_eth_get_mac_diag(&mac_cfg, &mac_dbg, &hw_tx);
                dma_st = va416xx_eth_get_dma_status();
                /* mac_dbg full 32-bit: TX bits are in [22:16] (TWCSTS=22,
                 * TRCSTS=[21:20], TFCSTS=[18:17], TPESTS=16).
                 * Masking with 0xFFFF would hide all TX activity. */
                printf("[%lu] rx=%lu tx=%lu/%lu hw_tx=%lu "
                       "cfg=0x%04lX dbg=0x%08lX "
                       "dma=0x%08lX TS=%lu\n",
                       (unsigned long)(now / 1000U),
                       (unsigned long)pkts,
                       (unsigned long)tx_pkts,
                       (unsigned long)tx_errs,
                       (unsigned long)hw_tx,
                       (unsigned long)(mac_cfg & 0xFFFF),
                       (unsigned long)mac_dbg,
                       (unsigned long)dma_st,
                       (unsigned long)((dma_st >> 20) & 0x7U));
                last_diag_ms = now;
            }
        }
    }

    return 0;
}

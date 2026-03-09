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
#include "va416xx_hal_ethernet.h"

#include "va416xx.h"
#include "va416xx_hal.h"
#include "va416xx_hal_uart.h"
#include "va416xx_hal_ioconfig.h"
#include "va416xx_hal_clkgen.h"
#include "board.h"

/* HAL_time_ms: millisecond tick counter maintained by SysTick ISR (1ms
 * resolution; SYSTICK_INTERVAL_MS=1 in hal_config.h).  Used as the wolfIP
 * `now` parameter so that all stack timers (DHCP, ARP, TCP retransmit, etc.)
 * run in real wall-clock time rather than depending on CPU loop speed. */
extern volatile uint64_t HAL_time_ms;

#define RX_BUF_SIZE     1024

/* DHCP timeout: total time to wait for DHCP before static IP fallback.
 * wolfIP's internal DHCP state machine retries for a finite period based
 * on DHCP_DISCOVER_RETRIES and DHCP_REQUEST_RETRIES (wolfIP defaults are 3).
 * After the stack gives up it sets state to DHCP_OFF and the UDP socket
 * stops accepting unicast DHCP responses (because DHCP_IS_RUNNING becomes
 * false).  We re-init periodically to keep trying, but must space re-inits
 * far enough apart to avoid socket churn (close/reopen loses in-flight
 * responses) and to ensure the previous DHCP attempt has fully timed out. */
#define DHCP_TIMEOUT_MS     30000U   /* 30s total before static fallback */
#define DHCP_REINIT_MS      10000U   /* 10s between DHCP re-init attempts */

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
    static uint32_t lfsr;
    static int seeded = 0;

    if (!seeded) {
        /* Seed from boot time so ISNs and ephemeral ports vary per power-up.
         * HAL_time_ms at first wolfIP call is typically 1-5 s into boot.
         * Note: not cryptographically secure; suitable for embedded demo use. */
        lfsr = (uint32_t)HAL_time_ms;
        if (lfsr == 0U)
            lfsr = 0x1A2B3C4DU;  /* LFSR must never be zero */
        seeded = 1;
    }
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
        ret = wolfIP_sock_send(s, speed_client_fd, rx_buf, sizeof(rx_buf), 0);
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
                rx_bps = (uint32_t)((uint64_t)speed_rx_bytes * 1000U / elapsed);
                tx_bps = (uint32_t)((uint64_t)speed_tx_bytes * 1000U / elapsed);
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
    if (ret == -2) {
        /* PHY link was down when auto-negotiation timed out.  MAC/DMA
         * are fully initialized and running; the device will respond
         * to traffic once the link comes up (e.g. cable or switch
         * powered on after the board). */
        printf("  NOTE: PHY link down at startup (cable disconnected?)"
               " — continuing\n");
    } else if (ret < 0) {
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

        /* --- MMC Counter Sanity Check ---
         * RXFRAMECOUNT_GB should be > 0 because we received external ARP/etc
         * traffic (rx_pkt_count > 0).  If RXFRAMECOUNT_GB is also 0, the MMC
         * counters are frozen/broken and TXFRAMECOUNT_GB (hw_tx) cannot be
         * trusted either.  If RXFRAMECOUNT_GB > 0, MMC counters work and TX
         * is truly silent. */
        {
            uint32_t rx_frames_gb = VOR_ETH->RXFRAMECOUNT_GB;
            uint32_t tx_octs_gb   = VOR_ETH->TXOCTETCOUNT_GB;
            uint32_t tx_under     = VOR_ETH->TXUNDERERR;
            uint32_t tx_carrier   = VOR_ETH->TXCARRIERERROR;
            uint32_t tx_latecol   = VOR_ETH->TXLATECOL;
            uint32_t mmc_ctrl     = VOR_ETH->MMC_CNTRL;
            printf("  MMC_CNTRL=0x%02lX RXFRAMES_GB=%lu TXOCTS_GB=%lu "
                   "TXUNDERERR=%lu TXCARRIER=%lu TXLATECOL=%lu\n",
                   (unsigned long)mmc_ctrl,
                   (unsigned long)rx_frames_gb,
                   (unsigned long)tx_octs_gb,
                   (unsigned long)tx_under,
                   (unsigned long)tx_carrier,
                   (unsigned long)tx_latecol);
            if (rx_frames_gb == 0)
                printf("  *** WARNING: RXFRAMES_GB=0 - MMC counters may be frozen ***\n");
            else
                printf("  MMC: RXFRAMES_GB=%lu TXOCTS_GB=%lu\n",
                       (unsigned long)rx_frames_gb, (unsigned long)tx_octs_gb);
        }

        /* --- MAC Internal Loopback Test ---
         * Enable MAC_CONFIG.LM (bit 12): TX data loops internally back to RX
         * without going through the MII/PHY.  In loopback mode the DWC GMAC
         * uses an internal clock, so missing TXCLK from the PHY is irrelevant.
         *
         * If rx_pkt_count increases after ll->send() in loopback mode:
         *   TX works internally => problem is TXCLK/MII/PHY (external path)
         * If rx_pkt_count stays flat:
         *   MAC TX engine broken even internally (DMA->FIFO or FIFO->MAC TX) */
        {
            uint32_t dummy_p, rx_before = 0, dummy_tx, dummy_e;
            int lbk_i;

            va416xx_eth_get_stats(&dummy_p, &rx_before, &dummy_tx, &dummy_e);

            /* Enable MAC loopback */
            VOR_ETH->MAC_CONFIG |= ETH_MAC_CONFIG_LM_Msk;
            __DSB();
            { volatile uint32_t _d; for (_d = 0; _d < 100000U; _d++) { } } /* ~1ms */

            printf("  MAC Loopback test (LM=1): rx_before=%lu\n",
                   (unsigned long)rx_before);
            for (lbk_i = 0; lbk_i < 3; lbk_i++) {
                ll->send(ll, garp, 42);
                { volatile uint32_t _d; for (_d = 0; _d < 1000000U; _d++) { } } /* ~10ms */
                (void)wolfIP_poll(IPStack, HAL_time_ms);
            }
            /* Extra settle + poll */
            { volatile uint32_t _d; for (_d = 0; _d < 5000000U; _d++) { } } /* ~50ms */
            (void)wolfIP_poll(IPStack, HAL_time_ms);

            {
                uint32_t rx_after = 0;
                va416xx_eth_get_stats(NULL, &rx_after, NULL, NULL);
                printf("  MAC Loopback result: rx_after=%lu delta=%lu\n",
                       (unsigned long)rx_after,
                       (unsigned long)(rx_after - rx_before));
                if (rx_after > rx_before)
                    printf("  *** LOOPBACK OK: MAC TX works! Problem is TXCLK/MII/PHY ***\n");
                else
                    printf("  *** LOOPBACK FAIL: MAC TX broken even in internal mode ***\n");
            }

            /* Disable MAC loopback */
            VOR_ETH->MAC_CONFIG &= ~ETH_MAC_CONFIG_LM_Msk;
            __DSB();
        }

        /* === PHY Register Dump ===
         * Read key PHY registers post-AN to confirm speed and link state.
         * BMSR bit2=link, bit5=AN_done.  BMCR bit13=speed100, bit8=FD.
         * PHY_CTRL2 bits[6:4]=OpMode: 1=10HD 2=100HD 5=10FD 6=100FD.
         * Isolate (BMCR bit10) or PowerDown (BMCR bit11) would suppress TXCLK. */
        {
#define MDIO_S() do { volatile uint32_t _s; for (_s=0; _s<5000U; _s++) {} } while(0)
            uint16_t bmcr, bmsr, an_adv, an_lpa, ctrl1, ctrl2;
            HAL_ReadPhyReg(PHY_CONTROL_REG,      &bmcr);   MDIO_S();
            HAL_ReadPhyReg(PHY_CONTROL_REG,      &bmcr);   MDIO_S();
            HAL_ReadPhyReg(PHY_STATUS_REG,       &bmsr);   MDIO_S();
            HAL_ReadPhyReg(PHY_STATUS_REG,       &bmsr);   MDIO_S();
            HAL_ReadPhyReg(PHY_AN_ADV_REG,       &an_adv); MDIO_S();
            HAL_ReadPhyReg(PHY_AN_ADV_REG,       &an_adv); MDIO_S();
            HAL_ReadPhyReg(PHY_LNK_PART_ABl_REG, &an_lpa); MDIO_S();
            HAL_ReadPhyReg(PHY_LNK_PART_ABl_REG, &an_lpa); MDIO_S();
            HAL_ReadPhyReg(PHY_CONTROL_ONE,      &ctrl1);  MDIO_S();
            HAL_ReadPhyReg(PHY_CONTROL_ONE,      &ctrl1);  MDIO_S();
            HAL_ReadPhyReg(PHY_CONTROL_TWO,      &ctrl2);  MDIO_S();
            HAL_ReadPhyReg(PHY_CONTROL_TWO,      &ctrl2);  MDIO_S();
#undef MDIO_S
            printf("  PHY BMCR=0x%04X BMSR=0x%04X AN_ADV=0x%04X AN_LPA=0x%04X\n",
                   bmcr, bmsr, an_adv, an_lpa);
            printf("  PHY CTRL1=0x%04X CTRL2=0x%04X OpMode[6:4]=%u\n",
                   ctrl1, ctrl2, (unsigned)((ctrl2 >> 4) & 7U));
            printf("  PHY: link=%u AN_done=%u isolate=%u pwrdn=%u speed100=%u FD=%u\n",
                   (unsigned)((bmsr >> 2) & 1),
                   (unsigned)((bmsr >> 5) & 1),
                   (unsigned)((bmcr >> 10) & 1),
                   (unsigned)((bmcr >> 11) & 1),
                   (unsigned)((bmcr >> 13) & 1),
                   (unsigned)((bmcr >> 8) & 1));
        }

#ifdef DEBUG_ETH
        /* === GPIO Pin Activity Scan ===
         * One-time bring-up tool: identifies which ETH pins carry PHY-driven
         * clocks (TXCLK, RXCLK) by briefly sampling them as GPIO inputs.
         * Hardware is now characterized (TXCLK=PB02, RXCLK=PA15 at 2.5 MHz
         * for 10M; FES read-only=0 confirmed), so this section is only
         * compiled in with DEBUG_ETH to keep TX_SELFTEST UART output concise.
         *
         * Each pin is briefly switched to GPIO input (funsel=0), sampled
         * 64 times in a tight loop (~2µs at 100MHz), then restored to
         * funsel=1.  At 2.5MHz TXCLK (10Mbps), 64 samples span ~5 clock
         * periods, enough to see both high and low states.
         * Pins marked <<CLOCK>> have both high and low samples. */
        printf("  GPIO Pin Activity Scan (detecting TXCLK/RXCLK):\n");
        {
            uint32_t pin, i, ones, zeros;
            /* PORTA[8:15] */
            for (pin = 8; pin <= 15; pin++) {
                HAL_Iocfg_PinMux(VOR_PORTA, pin, 0);
                VOR_PORTA->DIR &= ~(1U << pin);
                { volatile uint32_t _s; for (_s = 0; _s < 20U; _s++) {} }
                ones = 0; zeros = 0;
                for (i = 0; i < 64U; i++) {
                    if (VOR_PORTA->DATAIN & (1U << pin)) ones++; else zeros++;
                }
                HAL_Iocfg_PinMux(VOR_PORTA, pin, 1);
                { volatile uint32_t _s; for (_s = 0; _s < 20U; _s++) {} }
                printf("    PA%02lu: hi=%02lu lo=%02lu%s\n",
                       (unsigned long)pin, (unsigned long)ones, (unsigned long)zeros,
                       (ones > 0 && zeros > 0) ? " <<CLOCK>>" : "");
            }
            /* PORTB[0:10] */
            for (pin = 0; pin <= 10; pin++) {
                HAL_Iocfg_PinMux(VOR_PORTB, pin, 0);
                VOR_PORTB->DIR &= ~(1U << pin);
                { volatile uint32_t _s; for (_s = 0; _s < 20U; _s++) {} }
                ones = 0; zeros = 0;
                for (i = 0; i < 64U; i++) {
                    if (VOR_PORTB->DATAIN & (1U << pin)) ones++; else zeros++;
                }
                HAL_Iocfg_PinMux(VOR_PORTB, pin, 1);
                { volatile uint32_t _s; for (_s = 0; _s < 20U; _s++) {} }
                printf("    PB%02lu: hi=%02lu lo=%02lu%s\n",
                       (unsigned long)pin, (unsigned long)ones, (unsigned long)zeros,
                       (ones > 0 && zeros > 0) ? " <<CLOCK>>" : "");
            }
        }

        /* === FES=1 TX Attempt ===
         * If PHY negotiated 100M (TXCLK=25MHz) but MAC has FES=0 (expects
         * 2.5MHz), the TX clock domain is mismatched.  Try forcing FES=1
         * (100M) and see if a frame exits the MAC (TXFRAMECOUNT_GB delta).
         * Result: FES is confirmed read-only=0 on this silicon; MAC always
         * runs at 10M.  Gated under DEBUG_ETH as silicon is characterized. */
        {
            uint32_t hw_tx_before = 0, hw_tx_after = 0;
            uint32_t cfg_save;
            va416xx_eth_get_mac_diag(NULL, NULL, &hw_tx_before);
            cfg_save = VOR_ETH->MAC_CONFIG;
            VOR_ETH->MAC_CONFIG = cfg_save | ETH_MAC_CONFIG_FES_Msk;
            __DSB();
            printf("  FES=1 TX attempt: MAC_CONFIG=0x%08lX (FES=%lu)\n",
                   (unsigned long)VOR_ETH->MAC_CONFIG,
                   (unsigned long)!!(VOR_ETH->MAC_CONFIG & ETH_MAC_CONFIG_FES_Msk));
            ll->send(ll, garp, 42);
            { volatile uint32_t _d; for (_d = 0; _d < 20000000U; _d++) {} }
            va416xx_eth_get_mac_diag(NULL, NULL, &hw_tx_after);
            printf("  FES=1: hw_tx before=%lu after=%lu delta=%lu%s\n",
                   (unsigned long)hw_tx_before, (unsigned long)hw_tx_after,
                   (unsigned long)(hw_tx_after - hw_tx_before),
                   (hw_tx_after > hw_tx_before) ? " *** TX WORKS AT FES=1 ***" : " (still silent)");
            VOR_ETH->MAC_CONFIG = cfg_save;  /* restore original speed */
            __DSB();
        }
#endif /* DEBUG_ETH */
    }
#endif /* TX_SELFTEST */

    /* 10. Main loop — use HAL_time_ms (SysTick-based, 1ms resolution)
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
             * wolfIP's internal DHCP state machine retries for a finite
             * period based on DHCP_DISCOVER_RETRIES and
             * DHCP_REQUEST_RETRIES (wolfIP defaults are 3).  When the
             * state machine gives up and state goes to DHCP_OFF, the UDP
             * socket stops accepting unicast DHCP responses (the
             * DHCP_IS_RUNNING check in udp_process fails).
             *
             * We periodically re-init DHCP (every 10s) to restart the
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
                        ip = atoip4(WOLFIP_IP);
                        nm = atoip4(WOLFIP_NETMASK);
                        gw = atoip4(WOLFIP_GW);
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

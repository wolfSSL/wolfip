/* main.c - Pi Pico 2 W (RP2350 + CYW43439) wolfIP demo
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
 * Wires the CYW43439 driver into the wolfIP link-layer abstraction and
 * leaves a clear hook where the wolfSupplicant attach happens once the
 * cross-compiled wolfSSL is in place. Until the driver implementation
 * returns 0 from cyw43_init() (Task #46), this prints the bring-up
 * banner and parks the CPU on wfi.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "board.h"
#include "config.h"
#include "wolfip.h"

#include "cyw43439_driver.h"
#include "cyw43439_wifi.h"
#include "rp2350_clocks.h"

#if defined(WOLFIP_WITH_SUPPLICANT)
#include "supplicant.h"
#endif

extern void rp2350_uart_init(void);

/* wolfIP entropy hook. The RP2350 ROSC (ring oscillator) jitter at
 * 0x400C8000 + 0x1C provides one random bit per read - good for ISN /
 * ephemeral-port seeding but not for crypto. For SAE keying material
 * the supplicant pulls entropy directly from wolfCrypt's RNG. */
uint32_t wolfIP_getrandom(void)
{
    static uint32_t lfsr;
    uint32_t bit;
    int i;
    if (lfsr == 0U) {
        for (i = 0; i < 32; i++) {
            bit = (*(volatile uint32_t *)0x400C801CUL) & 1U;
            lfsr = (lfsr << 1) | bit;
        }
        if (lfsr == 0U) lfsr = 0xDEADBEEFU;
    }
    /* Mix in one fresh ROSC bit per call on top of the LFSR. */
    bit = (*(volatile uint32_t *)0x400C801CUL) & 1U;
    /* Unsigned wrap (0 or 0xFFFFFFFF) for the feedback mask - avoids the
     * signed-overflow cppcheck flags on -(int32_t)(...). */
    lfsr = (lfsr >> 1) ^ ((0U - (lfsr & 1U)) & 0xD0000001U);
    lfsr ^= bit;
    return lfsr;
}

/* wolfIP state - opaque struct allocated by wolfIP_init_static. */
static struct wolfIP        *g_wolfip;
static struct wolfIP_ll_dev *g_wlan;

#define UDP_ECHO_PORT 7U
#define HTON16(x) ((uint16_t)((((x) & 0xFFU) << 8) | (((x) >> 8) & 0xFFU)))
/* Host (wolfIP ip4, first octet in the MSB) -> network byte order, as
 * wolfIP_sock_bind expects in sin_addr.s_addr (it applies ee32). */
#define HTON32(x) ((uint32_t)((((x) >> 24) & 0xFFU) | (((x) >> 8) & 0xFF00U) \
                   | (((x) << 8) & 0xFF0000U) | (((x) << 24) & 0xFF000000U)))

/* Monotonic milliseconds. clk_sys is pinned to 12 MHz, so the Cortex-M33
 * DWT cycle counter gives a real timebase (12000 cycles per ms) for the
 * wolfIP timers (and the supplicant deadlines). The 64-bit accumulator
 * absorbs the 32-bit CYCCNT wrap (sampled every poll, far more often than
 * the ~358 s wrap). */
static uint64_t now_ms(void)
{
    static uint64_t acc;
    static uint32_t last;
    static int inited;
#if defined(__ARM_ARCH)
    uint32_t now;
    if (!inited) {
        *(volatile uint32_t *)0xE000EDFCUL |= (1U << 24); /* DEMCR.TRCENA */
        *(volatile uint32_t *)0xE0001000UL |= (1U << 0);  /* DWT CYCCNTENA */
        *(volatile uint32_t *)0xE0001004UL = 0U;          /* DWT_CYCCNT = 0 */
        last = 0U;
        inited = 1;
    }
    now  = *(volatile uint32_t *)0xE0001004UL;
    acc += (uint64_t)(now - last);
    last = now;
    return acc / 12000ULL;
#else
    (void)last;
    (void)inited;
    return ++acc;
#endif
}

/* Full restart. A non-keyed association wedges the CYW43439's CDC/bsscfg
 * state so badly that EVERY subsequent ioctl - including WLC_DOWN - returns
 * BCME_ERROR; no in-firmware re-join recovers it. The only clean reset is to
 * reload the firmware from scratch, i.e. reboot. Keying succeeds on ~half of
 * cold attempts, so a reboot-until-keyed loop converges in a few tries. */
static void mcu_reset(void)
{
#if defined(__ARM_ARCH)
    /* Cortex-M33 system reset: AIRCR = VECTKEY(0x5FA) | SYSRESETREQ(bit 2). */
    __asm volatile("dsb");
    *(volatile uint32_t *)0xE000ED0CUL = 0x05FA0004UL;
    __asm volatile("dsb");
#else
    /* Hazard3 (RISC-V) has no SCB / SYSRESETREQ; use the core-agnostic RP2350
     * watchdog manual trigger (WATCHDOG_CTRL.TRIGGER = bit 31, base
     * 0x400D8000) so the reboot-until-keyed loop recovers here too, instead of
     * silently wedging in wfi. */
    *(volatile uint32_t *)0x400D8000UL = (1UL << 31);
#endif
    /* Fallback if the reset request has not taken effect yet. */
    for (;;) {
        __asm volatile("wfi");
    }
}

/* Once the link is authenticated: DHCP lease, then a UDP echo server on
 * port 7. wolfIP owns the radio poll here (ll->poll calls cyw43_poll).
 * Does not return. */
static void run_dhcp_echo(void)
{
    int echo_fd = -1;
    int bound = 0;
    uint64_t last_kick = now_ms();
    uint64_t last_beat = last_kick;

    (void)dhcp_client_init(g_wolfip);
    printf("  dhcp: requesting lease...\n");
    for (;;) {
        uint64_t now = now_ms();
        (void)wolfIP_poll(g_wolfip, now);

        /* Heartbeat: proves the CPU/poll loop is alive even when no
         * frames arrive - distinguishes a WiFi link drop (beats keep
         * printing, rx stops climbing) from a CPU hang (beats stop). */
        if ((now - last_beat) > 5000ULL) {
            printf("  alive: rx=%u bound=%d keyed=%d assoc=%d\n",
                   (unsigned)cyw43_rx_count(), bound,
                   cyw43_keyed(), cyw43_assoc_up());
            last_beat = now;
        }

        /* Hold the association once joined: re-issuing the radio join
         * (SET_WSEC / sup_wpa / SET_SSID) while already associated
         * desyncs the firmware immediately. If the lease is slow, re-kick
         * ONLY the DHCP client - that resends DISCOVER without touching
         * the firmware association, so it is safe to repeat. */
        if (!bound && (now - last_kick) > 15000ULL) {
            printf("  dhcp: re-requesting lease...\n");
            (void)dhcp_client_init(g_wolfip);
            last_kick = now;
        }

        if (!bound && dhcp_bound(g_wolfip)) {
            ip4 ip = 0, mask = 0, gw = 0;
            struct wolfIP_sockaddr_in sa;
            bound = 1;
            wolfIP_ipconfig_get(g_wolfip, &ip, &mask, &gw);
            printf("  dhcp: lease %u.%u.%u.%u\n",
                   (unsigned)((ip >> 24) & 0xFFU),
                   (unsigned)((ip >> 16) & 0xFFU),
                   (unsigned)((ip >> 8) & 0xFFU),
                   (unsigned)(ip & 0xFFU));
            echo_fd = wolfIP_sock_socket(g_wolfip, AF_INET,
                                         IPSTACK_SOCK_DGRAM, 0);
            if (echo_fd >= 0) {
                memset(&sa, 0, sizeof(sa));
                sa.sin_family = AF_INET;
                sa.sin_port   = HTON16(UDP_ECHO_PORT);
                /* Bind to the leased IP, not INADDR_ANY: wolfIP only
                 * matches a 0-bound UDP socket while DHCP is running.
                 * Once the lease is bound the match requires
                 * local_ip == dst_ip, so bind the actual address. */
                sa.sin_addr.s_addr = HTON32(ip);
                if (wolfIP_sock_bind(g_wolfip, echo_fd,
                        (struct wolfIP_sockaddr *)&sa, sizeof(sa)) != 0) {
                    printf("  udp: bind failed\n");
                    echo_fd = -1;
                }
                else {
                    printf("  udp echo: ready on port %u\n", UDP_ECHO_PORT);
                }
            }
        }

        if (echo_fd >= 0) {
            uint8_t buf[256];
            struct wolfIP_sockaddr_in from;
            socklen_t fl = sizeof(from);
            int n = wolfIP_sock_recvfrom(g_wolfip, echo_fd, buf, sizeof(buf),
                                         0, (struct wolfIP_sockaddr *)&from,
                                         &fl);
            if (n > 0) {
                (void)wolfIP_sock_sendto(g_wolfip, echo_fd, buf, (size_t)n, 0,
                                         (struct wolfIP_sockaddr *)&from, fl);
            }
        }
    }
}

#if defined(WOLFIP_WITH_SUPPLICANT)
static struct wolfip_supplicant g_supp;

/* Supplicant glue kept for the cases the host CAN own on this FullMAC
 * radio - WPA3-SAE external-auth and 802.1X/EAP (those forward EAPOL to
 * the host). The CYW43439 firmware owns the WPA2-PSK 4-way, so the host
 * supplicant is NOT used for PSK here (see cyw43_join_psk). */
static int supp_send_eapol(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    /* Contract match: the supplicant send_eapol ops treats 0 as success and
     * non-zero as failure, and cyw43_tx_eapol() returns 0 = ok / -1 = fail, so
     * the value passes through unchanged (cf. the H563 0=success lesson). */
    return cyw43_tx_eapol(frame, len);
}

static int supp_install_key(void *ctx, wolfip_supplicant_keytype_t kt,
                            uint8_t key_idx, const uint8_t *key, size_t key_len)
{
    (void)ctx;
    return cyw43_set_key((kt == SUPP_KEY_PAIRWISE) ? 0 : 1,
                         key_idx, key, key_len);
}

/* Inbound EAPOL from the radio -> the supplicant (SAE/EAP paths). */
static int supp_eapol_rx(void *ctx, const uint8_t *frame, size_t len)
{
    return wolfip_supplicant_rx((struct wolfip_supplicant *)ctx,
                                frame, len, now_ms());
}
#endif /* WOLFIP_WITH_SUPPLICANT */

int main(void)
{
    int rc;

    /* Source clk_peri from the 12 MHz crystal so the UART baud is stable.
     * Must run before rp2350_uart_init(). */
    rp2350_clocks_init();
    rp2350_uart_init();
    printf("\n=== wolfIP on Pi Pico 2 W (RP2350) ===\n");
    printf("  target SSID  : " WOLFIP_WIFI_SSID "\n");

    rc = cyw43_init();
#if DEBUG_BRINGUP
    /* Report both gSPI test-register reads regardless of rc. 0xFEEDBEAD
     * in either confirms the SPI link is alive; pre (swapped mode) tells
     * us the initial handshake works even if the 32-bit config write
     * doesn't. */
    printf("  gSPI test    : pre 0x%08lX  post 0x%08lX (want FEEDBEAD)\n",
           (unsigned long)cyw43_last_bus_test_pre(),
           (unsigned long)cyw43_last_bus_test());
    printf("  ALP clock    : %s (CSR 0x%02lX, want bit 0x40)\n",
           cyw43_last_alp_ok() ? "AVAIL" : "no",
           (unsigned long)cyw43_last_alp_csr());
    printf("  chip id      : 0x%04lX (want 0xA9A6)\n",
           (unsigned long)cyw43_last_chip_id());
#endif
    printf("  firmware     : %s (init rc=%d)\n",
           cyw43_firmware_ready() ? "RUNNING (F2 ready)" :
           (rc == -2 ? "no blob linked" : "load failed"), rc);
    if (rc != 0) {
        printf("  cyw43_init   : rc=%d (firmware-load bring-up TODO)\n", rc);
        goto park;
    }
    printf("  cyw43_init   : OK\n");

    rc = cyw43_wifi_up("XX");
    if (rc != 0) {
        printf("  cyw43_wifi_up: FAILED rc=%d\n", rc);
        goto park;
    }
    printf("  cyw43_wifi_up: OK\n");

    wolfIP_init_static(&g_wolfip);
    g_wlan = wolfIP_getdev(g_wolfip);
    if (g_wlan == NULL) {
        printf("  wolfIP_getdev: FAILED\n");
        goto park;
    }
    rc = cyw43_wifi_attach(g_wlan);
    if (rc != 0) {
        printf("  cyw43_attach : FAILED rc=%d\n", rc);
        goto park;
    }
    printf("  wifi attached: MAC=%02X:%02X:%02X:%02X:%02X:%02X\n",
           g_wlan->mac[0], g_wlan->mac[1], g_wlan->mac[2],
           g_wlan->mac[3], g_wlan->mac[4], g_wlan->mac[5]);

    /* Firmware-offload WPA2-PSK join: the CYW43439 firmware runs the 4-way
     * (host-run PSK is not supported on this FullMAC firmware). Push the
     * passphrase, then bring up IP once the firmware authenticates the
     * link. (WPA3-SAE / 802.1X-EAP would instead drive the in-tree
     * wolfSupplicant - kept linked under WOLFIP_WITH_SUPPLICANT.) */
    /* One clean join attempt per boot, gated on the link being fully KEYED.
     * Root-caused on hardware: the CYW43439 firmware's internal 4-way only
     * completes intermittently on a cold join (RF/timing on a busy 2.4 GHz
     * channel). When it keys (WLC_E_PSK_SUP/WLC_SUP_KEYED) the whole data
     * path works (DHCP + UDP echo verified); when it does not, no data flows.
     * cyw43_keyed() distinguishes the two precisely.
     *
     * A non-keyed association wedges the firmware so any in-firmware re-join
     * (even WLC_DOWN) returns BCME_ERROR, so the only clean recovery is a
     * reboot (reloads firmware). Before resetting we DISASSOC so the AP drops
     * our STA entry - skipping that leaves a stale association that times out
     * the next boot's auth, which doubles the boots needed to converge. */
    {
        uint64_t t0;
        rc = cyw43_join_psk((const uint8_t *)WOLFIP_WIFI_SSID,
                            strlen(WOLFIP_WIFI_SSID),
                            WOLFIP_WIFI_PSK, strlen(WOLFIP_WIFI_PSK));
        printf("  cyw43_join_psk: rc=%d (SSID %s)\n", rc, WOLFIP_WIFI_SSID);
        t0 = now_ms();
        while ((now_ms() - t0) < 12000ULL && !cyw43_keyed()) {
            (void)cyw43_poll();
        }
        if (cyw43_keyed()) {
            printf("  join: KEYED (4-way complete) - starting DHCP\n");
            /* Leave firmware power-save at its default: forcing PM_OFF (CAM)
             * keeps the radio always-on and floods the F2 FIFO with the AP's
             * broadcast/multicast traffic, which overruns the slow SPI host
             * and stalls RX far sooner. */
            run_dhcp_echo();   /* holds the association; does not return */
        }
        printf("  join: %s after 12s - disassoc + reboot to retry\n",
               cyw43_assoc_up() ? "associated but NOT keyed"
                                : "no association");
        /* Tell the AP we are leaving so it drops the stale STA entry, then
         * reboot for a fresh firmware load + clean cold attempt. */
        (void)cyw43_disconnect();
        t0 = now_ms();
        while ((now_ms() - t0) < 500ULL) {
            (void)cyw43_poll();   /* drain the disassoc + let UART flush */
        }
        mcu_reset();
    }

park:
    printf("  parked on wfi\n");
    while (1) {
        __asm volatile("wfi");
    }
    return 0;
}

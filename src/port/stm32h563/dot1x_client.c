/* dot1x_client.c
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

/* Wired IEEE 802.1X EAP-TLS demo.
 *
 * The CYW43439 (Pi Pico 2 W) is FullMAC and runs WPA2-PSK in firmware, so
 * the in-tree wolfSupplicant is never exercised there. This demo drives the
 * supplicant's EAP-TLS path over a WIRED Ethernet link instead, where the
 * host owns the EAPOL exchange end to end - the cleanest way to validate
 * the supplicant on real hardware with no RF variance.
 *
 * Transport: a wolfIP packet socket (AF_PACKET / SOCK_RAW) bound to the
 * EAPOL ethertype 0x888E. The supplicant deals only in bare EAPOL payloads;
 * this file owns the 802.3 framing (dst = PAE group 01:80:C2:00:00:03,
 * src = our MAC, ethertype 0x888E) on TX and strips it on RX.
 */

#include <stdint.h>
#include <string.h>
#include "config.h"
#include "wolfip.h"
#include "supplicant.h"
#include "eap_tls_engine.h"
#include "dot1x_client.h"
#include "dot1x_certs.h"

#define DOT1X_EAPOL_ETHERTYPE 0x888EU
#define DOT1X_ETH_HDR_LEN     14U
#define DOT1X_FRAME_MAX       1600
/* Loop bound (iterations, not ms): the EAP exchange is event-driven and
 * completes in a handful of round-trips; this is a generous backstop. */
#define DOT1X_MAX_ITERS       4000000UL

/* ---- Real millisecond clock (SysTick) ----------------------------------
 * The supplicant timeout (WOLFIP_SUPPLICANT_HS_TIMEOUT_MS) and M2-retransmit
 * timing are in milliseconds. The bare-metal H563 build otherwise has no ms
 * timebase (SysTick is an unused infinite-loop weak alias in ivt.c), so a
 * per-iteration counter would couple the 10 s timeout to loop count rather
 * than wall time. We arm SysTick for a 1 kHz interrupt and count ms here.
 * HCLK = HSI 64 MHz / HSIDIV /2 = 32 MHz - the STM32H5 TZEN=0 reset default
 * this demo runs at (ENABLE_DOT1X forces TZEN=0; the PLL is never engaged) -
 * so reload = 32000 - 1. SysTick_Handler below is a strong symbol that
 * overrides the weak ivt.c alias; the dot1x demo is bare-metal, not FreeRTOS
 * (where SysTick belongs to the RTOS). */
#define SYST_CSR  (*(volatile uint32_t *)0xE000E010UL)  /* control / status */
#define SYST_RVR  (*(volatile uint32_t *)0xE000E014UL)  /* reload value     */
#define SYST_CVR  (*(volatile uint32_t *)0xE000E018UL)  /* current value    */
#define SYST_RELOAD_1MS  (32000U - 1U)                  /* 32 MHz HCLK       */

static volatile uint32_t g_dot1x_ms;

void SysTick_Handler(void)
{
    g_dot1x_ms++;
}

static void dot1x_systick_arm_1khz(void)
{
    SYST_CVR = 0U;
    SYST_RVR = SYST_RELOAD_1MS;
    /* bit2 CLKSOURCE = processor clock, bit1 TICKINT = enable IRQ,
     * bit0 ENABLE. */
    SYST_CSR = (1U << 2) | (1U << 1) | (1U << 0);
}

/* IEEE 802.1X PAE group address - the standard multicast dst for supplicant
 * EAPOL. Works on a point-to-point link, but 802.1D switches do NOT forward
 * this reserved link-local address, so on a switched segment the
 * authenticator never sees it. */
static const uint8_t DOT1X_PAE_GROUP_MAC[6] = {
    0x01, 0x80, 0xC2, 0x00, 0x00, 0x03
};

/* Destination MAC for outbound EAPOL. On a switched segment this must be the
 * authenticator's unicast MAC (hostapd's NIC) so frames traverse the switch;
 * the PAE group multicast above is dropped by 802.1D bridges. Override with
 * -DDOT1X_AUTH_MAC0..5 for a different authenticator, or set all to the
 * PAE_GROUP bytes for a direct point-to-point link. */
#ifndef DOT1X_AUTH_MAC0
#define DOT1X_AUTH_MAC0 0xBC
#define DOT1X_AUTH_MAC1 0xFC
#define DOT1X_AUTH_MAC2 0xE7
#define DOT1X_AUTH_MAC3 0x3A
#define DOT1X_AUTH_MAC4 0x25
#define DOT1X_AUTH_MAC5 0x0F   /* enp6s0 (direct point-to-point link) */
#endif
static const uint8_t DOT1X_AUTH_MAC[6] = {
    DOT1X_AUTH_MAC0, DOT1X_AUTH_MAC1, DOT1X_AUTH_MAC2,
    DOT1X_AUTH_MAC3, DOT1X_AUTH_MAC4, DOT1X_AUTH_MAC5
};

struct dot1x_ctx {
    struct wolfIP *stack;
    void         (*log)(const char *msg);
    int            sock;
    uint8_t        local_mac[6];
};

/* Single-threaded, synchronous demo: file-scope frame buffers avoid large
 * stack allocations on the MCU. */
static uint8_t dot1x_txframe[DOT1X_FRAME_MAX];
static uint8_t dot1x_rxframe[DOT1X_FRAME_MAX];

static void dot1x_log(const struct dot1x_ctx *c, const char *msg)
{
    if (c->log != NULL) {
        c->log(msg);
    }
}

/* Supplicant send_eapol op: prepend the 802.3 header and push the full
 * frame out the packet socket. wolfIP fills the source MAC from the
 * interface; we set it too so the frame is well formed regardless. */
static int dot1x_send_eapol(void *vctx, const uint8_t *frame, size_t len)
{
    struct dot1x_ctx *c = (struct dot1x_ctx *)vctx;
    size_t total = DOT1X_ETH_HDR_LEN + len;
    int r;

    if (total > sizeof(dot1x_txframe)) {
        return -1;
    }
    memcpy(&dot1x_txframe[0], DOT1X_AUTH_MAC, 6);
    memcpy(&dot1x_txframe[6], c->local_mac, 6);
    dot1x_txframe[12] = (uint8_t)((DOT1X_EAPOL_ETHERTYPE >> 8) & 0xFFU);
    dot1x_txframe[13] = (uint8_t)(DOT1X_EAPOL_ETHERTYPE & 0xFFU);
    memcpy(&dot1x_txframe[DOT1X_ETH_HDR_LEN], frame, len);

    r = wolfIP_sock_sendto(c->stack, c->sock, dot1x_txframe, total, 0,
                           NULL, 0);
    /* The supplicant's send_eapol op contract is 0 = success, non-zero =
     * error (it does `if (send_eapol(...) != 0) fail`). wolfIP_sock_sendto
     * returns the byte count on success, so map a positive result to 0. */
    return (r > 0) ? 0 : -1;
}

/* Supplicant install_key op: a wired 802.1X exchange performs no WPA 4-way,
 * so the supplicant never installs keys. Present only so the ops table is
 * complete. */
static int dot1x_install_key(void *vctx, wolfip_supplicant_keytype_t kt,
                             uint8_t key_idx, const uint8_t *key,
                             size_t key_len)
{
    (void)vctx;
    (void)kt;
    (void)key_idx;
    (void)key;
    (void)key_len;
    return 0;
}

int dot1x_eaptls_run(struct wolfIP *stack, void (*log)(const char *msg))
{
    static struct wolfip_supplicant supp;   /* .bss - allocation-free */
    struct wolfip_supplicant_cfg     cfg;
    struct dot1x_ctx                 ctx;
    struct wolfIP_ll_dev            *ll;
    uint64_t                         now = 0;
    unsigned long                    iter;
    int                              proto;
    int                              rc;
    int                              result = -1;

    memset(&ctx, 0, sizeof(ctx));
    ctx.stack = stack;
    ctx.log   = log;
    ctx.sock  = -1;

    ll = wolfIP_getdev(stack);
    if (ll == NULL) {
        dot1x_log(&ctx, "dot1x: no network device\n");
        return -1;
    }
    memcpy(ctx.local_mac, ll->mac, 6);

    /* Packet socket bound to the EAPOL ethertype. AF_PACKET protocol is
     * compared against the on-the-wire (big-endian) ethertype, so pass it
     * in network byte order. */
    proto = (int)(((DOT1X_EAPOL_ETHERTYPE & 0xFFU) << 8) |
                  ((DOT1X_EAPOL_ETHERTYPE >> 8) & 0xFFU));
    ctx.sock = wolfIP_sock_socket(stack, AF_PACKET, IPSTACK_SOCK_RAW, proto);
    if (ctx.sock < 0) {
        dot1x_log(&ctx, "dot1x: EAPOL packet socket failed\n");
        return -1;
    }

    /* EAP-TLS supplicant configuration (certs embedded in dot1x_certs.h). */
    memset(&cfg, 0, sizeof(cfg));
    cfg.ssid         = "wired-8021x";          /* cosmetic on a wired link */
    cfg.ssid_len     = 11;
    cfg.auth_mode    = WOLFIP_AUTH_EAP_TLS;
    cfg.identity     = DOT1X_EAP_IDENTITY;
    cfg.identity_len = strlen(DOT1X_EAP_IDENTITY);

    cfg.eap_tls.ca                 = dot1x_ca_cert;
    cfg.eap_tls.ca_len             = dot1x_ca_cert_len;
    cfg.eap_tls.ca_format          = WOLFIP_EAP_TLS_FMT_DER;
    cfg.eap_tls.client_cert        = dot1x_client_cert;
    cfg.eap_tls.client_cert_len    = dot1x_client_cert_len;
    cfg.eap_tls.client_cert_format = WOLFIP_EAP_TLS_FMT_DER;
    cfg.eap_tls.client_key         = dot1x_client_key;
    cfg.eap_tls.client_key_len     = dot1x_client_key_len;
    cfg.eap_tls.client_key_format  = WOLFIP_EAP_TLS_FMT_DER;

    /* PAE group is the "peer" on wired; sta_mac is our own. Both only feed
     * key derivation, which the wired path never completes. */
    memcpy(cfg.sta_mac, ctx.local_mac, 6);
    memcpy(cfg.ap_mac, DOT1X_PAE_GROUP_MAC, 6);

    cfg.ops.send_eapol  = dot1x_send_eapol;
    cfg.ops.install_key = dot1x_install_key;
    cfg.ops.ctx         = &ctx;

    rc = wolfip_supplicant_init(&supp, &cfg);
    if (rc != 0) {
        dot1x_log(&ctx, "dot1x: supplicant init failed\n");
        wolfIP_sock_close(stack, ctx.sock);
        return -1;
    }

    /* Arm the real ms clock and feed wall-clock milliseconds to the supplicant
     * and the poll loop, so the handshake timeout is time-based not iteration-
     * based. DOT1X_MAX_ITERS remains the absolute backstop. */
    dot1x_systick_arm_1khz();
    now = g_dot1x_ms;

    dot1x_log(&ctx, "dot1x: EAP-TLS start (EAPOL-Start) as "
                    DOT1X_EAP_IDENTITY "\n");
    wolfip_supplicant_kick(&supp, now);

    for (iter = 0; iter < DOT1X_MAX_ITERS; iter++) {
        wolfip_supplicant_state_t st;
        int n;

        now = g_dot1x_ms;
        (void)wolfIP_poll(stack, now);

        n = wolfIP_sock_recvfrom(stack, ctx.sock, dot1x_rxframe,
                                 sizeof(dot1x_rxframe), 0, NULL, NULL);
        if (n > (int)DOT1X_ETH_HDR_LEN) {
            /* Skip our own transmitted frames echoed back by the stack. */
            if (memcmp(&dot1x_rxframe[6], ctx.local_mac, 6) != 0) {
                (void)wolfip_supplicant_rx(&supp,
                        &dot1x_rxframe[DOT1X_ETH_HDR_LEN],
                        (size_t)(n - (int)DOT1X_ETH_HDR_LEN), now);
            }
        }
        wolfip_supplicant_tick(&supp, now);

        st = wolfip_supplicant_state(&supp);
        if (st == SUPP_STATE_4WAY_M1_WAIT) {
            /* EAP-Success received; PMK derived. On wired there is no
             * 4-way, so this is the terminal success state. */
            dot1x_log(&ctx, "dot1x: EAP-TLS SUCCESS - authenticated, "
                            "PMK derived\n");
            result = 0;
            break;
        }
        if (st == SUPP_STATE_FAILED) {
            dot1x_log(&ctx, "dot1x: EAP-TLS FAILED\n");
            result = -1;
            break;
        }
    }
    if (result != 0 && iter >= DOT1X_MAX_ITERS) {
        dot1x_log(&ctx, "dot1x: timeout waiting for EAP-Success\n");
    }

    wolfip_supplicant_deinit(&supp);
    wolfIP_sock_close(stack, ctx.sock);
    return result;
}

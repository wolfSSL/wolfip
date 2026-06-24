/* cyw43439_wifi.c - wolfIP_wifi_ops vtable + 802.3 link glue
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
 * Glue layer between wolfIP's link-layer abstraction
 * (struct wolfIP_ll_dev + struct wolfIP_wifi_ops) and the CYW43439
 * driver. Provides:
 *
 *   - a vtable for the supplicant's scan/connect/set_key plumbing
 *   - send / poll callbacks for normal 802.3 traffic
 *   - an EAPOL bridge that routes incoming 0x888E frames to the
 *     supplicant before they hit the IP stack
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfip.h"

#include "cyw43439_driver.h"
#include "cyw43439_wifi.h"

/* Local 1500-byte RX scratch (reused inside the poll loop). */
static uint8_t g_rx_scratch[1536];
static int     g_rx_len;

static int cyw43_eapol_rx_cb(void *ctx, const uint8_t *frame, size_t len)
{
    /* The driver presents an EAPOL payload (no MAC header) on the
     * F2 BDC channel. wolfIP's 0x888E demux (wolfIP_recv_on) expects a
     * full Ethernet frame, so we synthesise the MAC header here using
     * the radio's MAC + the BSSID. */
    struct wolfIP_ll_dev *ll = (struct wolfIP_ll_dev *)ctx;
    uint8_t pkt[1536];
    uint8_t bssid[6];
    size_t  total;

    if (len + 14U > sizeof(pkt)) return -1;
    /* src = AP BSSID (EAPOL RX only occurs post-association, so it is
     * valid); NOT our own STA MAC. */
    if (cyw43_get_bssid(bssid) != 0) return -1;

    /* dst = our MAC; src = AP MAC; ethertype = 0x888E. */
    memcpy(&pkt[0], ll->mac, 6);
    memcpy(&pkt[6], bssid,   6);
    pkt[12] = 0x88;
    pkt[13] = 0x8E;
    memcpy(&pkt[14], frame, len);
    total = 14U + len;

    /* Stash for the next poll() invocation. wolfIP's poll loop will
     * pull this through the standard ll->poll() entry point. */
    if (total > sizeof(g_rx_scratch)) return -1;
    memcpy(g_rx_scratch, pkt, total);
    g_rx_len = (int)total;
    return 0;
}

static int cyw43_data_rx_cb(void *ctx, const uint8_t *frame, size_t len)
{
    /* 802.3 data path - hand directly to wolfIP's RX queue. The
     * driver already gave us a full Ethernet frame. */
    (void)ctx;
    if (len > sizeof(g_rx_scratch)) return -1;
    memcpy(g_rx_scratch, frame, len);
    g_rx_len = (int)len;
    return 0;
}

/* ---- wolfIP_ll_dev send/poll ---- */

int cyw43_ll_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    const uint8_t *eth = (const uint8_t *)buf;
    (void)ll;
    if (eth == NULL || len < 14U) return -1;
    /* EAPOL frames take the dedicated 0x888E TX path so the radio can
     * still queue them while in the unauthenticated assoc state. */
    if (eth[12] == 0x88 && eth[13] == 0x8E) {
        return cyw43_tx_eapol(&eth[14], (size_t)(len - 14U));
    }
    return cyw43_tx_eth(eth, (size_t)len);
}

int cyw43_ll_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    int copied;
    (void)ll;
    /* Service the radio first - this populates g_rx_scratch via the
     * registered callbacks if anything new arrived. */
    (void)cyw43_poll();
    if (g_rx_len == 0) return 0;
    if ((uint32_t)g_rx_len > len) {
        /* Staged frame cannot fit the caller's buffer. Drop it (free the
         * single-slot stage) so the poll loop cannot wedge re-reporting the
         * same too-large frame on every call. */
        g_rx_len = 0;
        return -1;
    }
    memcpy(buf, g_rx_scratch, (size_t)g_rx_len);
    copied = g_rx_len;
    g_rx_len = 0;
    return copied;
}

/* ---- wolfIP_wifi_ops impl ---- */

static int op_scan(struct wolfIP_ll_dev *ll,
                   struct wolfIP_wifi_scan_entry *out, int max_entries)
{
    (void)ll; (void)out; (void)max_entries;
    /* TODO(hardware): WLC_SCAN ioctl + harvest results. Until then return a
     * not-implemented error rather than success-with-zero-results, so a
     * caller can tell "scan unsupported" from "scan found no networks". */
    return -1;
}

static int op_connect(struct wolfIP_ll_dev *ll,
                      const uint8_t *ssid, uint8_t ssid_len,
                      const uint8_t bssid[6])
{
    (void)ll;
    /* For WPA2/WPA3 the supplicant owns the keying material; the radio
     * does 802.11 open auth + assoc carrying the RSN IE (open_auth = 0
     * selects the WPA2-PSK/CCMP path), then EAPOL flows through the
     * 0x888E TX/RX path for the host-run 4-way. */
    return cyw43_connect(ssid, ssid_len, bssid, 0, 0);
}

static int op_disconnect(struct wolfIP_ll_dev *ll)
{
    (void)ll;
    return cyw43_disconnect();
}

static int op_set_key(struct wolfIP_ll_dev *ll, int key_type,
                      uint8_t key_idx, const uint8_t *key, uint16_t key_len)
{
    (void)ll;
    return cyw43_set_key(key_type, key_idx, key, (size_t)key_len);
}

static int op_get_bssid(struct wolfIP_ll_dev *ll, uint8_t out_bssid[6])
{
    (void)ll;
    return cyw43_get_bssid(out_bssid);
}

const struct wolfIP_wifi_ops cyw43_wifi_ops = {
    .scan       = op_scan,
    .connect    = op_connect,
    .disconnect = op_disconnect,
    .set_key    = op_set_key,
    .get_bssid  = op_get_bssid,
};

int cyw43_wifi_attach(struct wolfIP_ll_dev *ll)
{
    if (ll == NULL) return -1;
    if (cyw43_get_mac(ll->mac) != 0) return -1;
    ll->mtu      = 1500U;
    ll->poll     = cyw43_ll_poll;
    ll->send     = cyw43_ll_send;
    ll->wifi_ops = &cyw43_wifi_ops;
    memcpy(ll->ifname, "wlan0", 6);
    cyw43_set_rx_callbacks(cyw43_eapol_rx_cb, cyw43_data_rx_cb, ll);
    return 0;
}

void cyw43_wifi_route_eapol(cyw43_eapol_cb_t eapol_cb, void *ctx)
{
    /* Route inbound EAPOL (0x888E) straight to the host supplicant while
     * keeping 802.3 data flowing into wolfIP via the existing data path
     * (cyw43_data_rx_cb -> g_rx_scratch -> cyw43_ll_poll). The data cb
     * ignores its ctx, so the supplicant pointer can be the shared ctx. */
    cyw43_set_rx_callbacks(eapol_cb, cyw43_data_rx_cb, ctx);
}

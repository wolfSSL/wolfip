/* wolfip_rtl8735b.c
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
 *
 * wolfIP <-> AmebaPro2 (RTL8735B) mbed Ethernet HAL glue. Polled RX: wolfIP's
 * poll() drains the RX ring via ethernet_receive()/ethernet_read(); the MAC
 * IRQ hook only latches link up/down.
 */

#include <stdint.h>
#include <string.h>
#include "config.h"          /* LINK_MTU */
#include "wolfip.h"
#include "wolfip_rtl8735b.h"

/* Vendor FreeRTOS SDK headers (AmebaPro2). Present only in the SDK build. */
#include "ethernet_api.h"
#include "ethernet_ex_api.h"
#include "hal_trng_sec.h"

/* TX/RX descriptor counts, matching the vendor ethernet_mii reference. */
#ifndef RTL8735B_TX_DESC_NO
#define RTL8735B_TX_DESC_NO     8
#endif
#ifndef RTL8735B_RX_DESC_NO
#define RTL8735B_RX_DESC_NO     8
#endif

/* MAC IRQ event codes (EthInt* enum in the vendor fwlib rtl8735b_eth.h), given
 * numerically to avoid pulling in the deep SoC CMSIS header. */
#define RTL_ETH_EVT_LINK_UP     7
#define RTL_ETH_EVT_LINK_DOWN   8

/* Descriptor rings live in the reserved RAM_REV SRAM region (DMA-reachable,
 * 32-byte aligned) exposed by the linker, as in the vendor driver. */
extern uint32_t __sram_rev_start__[];

/* Vendor heap allocator; DMA packet buffers come from heap region index 1. */
extern void *pvPortMallocExt(size_t size, int idx);
extern void vPortFree(void *pv);

static uint8_t *tx_pkt_buf = NULL;
static uint8_t *rx_pkt_buf = NULL;
static volatile int link_up = 0;

/* Release the DMA packet buffers (idempotent). */
static void free_eth_bufs(void)
{
    if (tx_pkt_buf != NULL) {
        vPortFree(tx_pkt_buf);
        tx_pkt_buf = NULL;
    }
    if (rx_pkt_buf != NULL) {
        vPortFree(rx_pkt_buf);
        rx_pkt_buf = NULL;
    }
}

/* ethernet_write()/ethernet_read() require a 32-byte-aligned data buffer;
 * wolfIP frame buffers are not, so stage every frame through these. */
static uint8_t tx_bounce[ETH_PKT_BUF_SIZE] __attribute__((aligned(32)));
static uint8_t rx_bounce[ETH_PKT_BUF_SIZE] __attribute__((aligned(32)));

static void rtl8735b_eth_irq(uint32_t event, uint32_t data)
{
    (void)data;
    if (event == RTL_ETH_EVT_LINK_UP)
        link_up = 1;
    else if (event == RTL_ETH_EVT_LINK_DOWN)
        link_up = 0;
}

/* wolfIP RX pull: return one frame's length (>0), 0 if none. */
static int eth_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    int sz;
    (void)ll;

    sz = ethernet_receive();
    if (sz <= 0)
        return 0;
    if ((uint32_t)sz > sizeof(rx_bounce))
        sz = (int)sizeof(rx_bounce);
    (void)ethernet_read((char *)rx_bounce, sz);
    if ((uint32_t)sz > len)
        sz = (int)len;
    memcpy(buf, rx_bounce, (size_t)sz);
    return sz;
}

/* wolfIP TX: send one complete Ethernet frame (MAC auto-pads short frames). */
static int eth_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;

    if (buf == NULL || len == 0 || len > sizeof(tx_bounce))
        return -1;
    memcpy(tx_bounce, buf, len);
    if (ethernet_write((const char *)tx_bounce, (int)len) <= 0)
        return -2;
    /* ethernet_send() returns the transmitted frame size; <= 0 means the DMA
     * did not accept it, so report the failure to wolfIP. */
    if (ethernet_send() <= 0)
        return -3;
    return (int)len;
}

/* Read one word from the secure hardware TRNG (lazy init). Returns 0 on
 * success, -1 if the TRNG is unavailable. Single source for both the stack
 * entropy and the wolfCrypt seed so init lives in one place. */
static int rtl8735b_trng_read(uint32_t *out)
{
    static int inited = 0;

    if (inited == 0 && hal_trng_sec_init() == 0)
        inited = 1;
    if (!inited)
        return -1;
    *out = (uint32_t)hal_trng_sec_get_rand();
    return 0;
}

/* wolfIP entropy for TCP ISNs, ephemeral ports and DHCP xids. wolfIP_getrandom
 * has no error channel, so on TRNG failure fall back to a non-constant LCG
 * (weak, but avoids fixed values); the crypto seed path below fails closed
 * instead. */
uint32_t wolfIP_getrandom(void)
{
    static uint32_t lcg = 0x2545F491u;
    uint32_t r;

    if (rtl8735b_trng_read(&r) == 0)
        return r;
    lcg = (lcg * 1664525u) + 1013904223u;
    return lcg;
}

/* wolfCrypt RNG seed hook (user_settings CUSTOM_RAND_GENERATE_SEED). Fails
 * closed: if the TRNG is unavailable it returns an error rather than seeding
 * the DRBG from a predictable fallback. Referenced only in the TLS build. */
int rtl8735b_rand_seed(unsigned char *output, unsigned int sz)
{
    unsigned int i, n;
    uint32_t r;

    for (i = 0; i < sz; ) {
        if (rtl8735b_trng_read(&r) != 0)
            return -1;
        n = (sz - i) < 4u ? (sz - i) : 4u;
        memcpy(output + i, &r, n);
        i += n;
    }
    return 0;
}

int rtl8735b_eth_link_up(void)
{
    return link_up;
}

void rtl8735b_eth_phy_maintain(void)
{
    if (link_up)
        ethernet_detect_phy_state();
}

int rtl8735b_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    uint8_t local_mac[6];
    uint8_t *tx_desc;
    uint8_t *rx_desc;

    if (ll == NULL)
        return -1;

    /* Descriptor rings in reserved SRAM: TX first, RX right after. */
    tx_desc = (uint8_t *)__sram_rev_start__;
    rx_desc = tx_desc + (RTL8735B_TX_DESC_NO * ETH_TX_DESC_SIZE);

    /* DMA packet buffers from the vendor DMA-capable heap. */
    tx_pkt_buf = (uint8_t *)pvPortMallocExt(RTL8735B_TX_DESC_NO * ETH_PKT_BUF_SIZE, 1);
    rx_pkt_buf = (uint8_t *)pvPortMallocExt(RTL8735B_RX_DESC_NO * ETH_PKT_BUF_SIZE, 1);
    if (tx_pkt_buf == NULL || rx_pkt_buf == NULL) {
        free_eth_bufs();
        return -2;
    }

    memset(tx_desc, 0, RTL8735B_TX_DESC_NO * ETH_TX_DESC_SIZE);
    memset(rx_desc, 0, RTL8735B_RX_DESC_NO * ETH_RX_DESC_SIZE);
    memset(tx_pkt_buf, 0, RTL8735B_TX_DESC_NO * ETH_PKT_BUF_SIZE);
    memset(rx_pkt_buf, 0, RTL8735B_RX_DESC_NO * ETH_PKT_BUF_SIZE);

    /* MAC: caller-supplied, else efuse, else locally-administered. */
    if (mac == NULL) {
        ethernet_address((char *)local_mac);
        if ((local_mac[0] | local_mac[1] | local_mac[2] |
             local_mac[3] | local_mac[4] | local_mac[5]) == 0) {
            local_mac[0] = 0x02; local_mac[1] = 0xE0; local_mac[2] = 0x4C;
            local_mac[3] = 0x87; local_mac[4] = 0x35; local_mac[5] = 0xB0;
        }
        mac = local_mac;
    }

    /* Hook link events, wire rings/buffers/MAC into the HAL, then start. */
    ethernet_irq_hook(rtl8735b_eth_irq);
    ethernet_set_descnum(RTL8735B_TX_DESC_NO, RTL8735B_RX_DESC_NO);
    ethernet_trx_pre_setting(tx_desc, rx_desc, tx_pkt_buf, rx_pkt_buf);
    ethernet_set_address((char *)mac);
    if (ethernet_init() != 0) {
        free_eth_bufs();
        return -3;
    }
    if (ethernet_link())
        link_up = 1;

    memcpy(ll->mac, mac, sizeof(ll->mac));
    strncpy(ll->ifname, "eth0", sizeof(ll->ifname) - 1);
    ll->ifname[sizeof(ll->ifname) - 1] = '\0';
    ll->non_ethernet = 0;
    ll->mtu = LINK_MTU;   /* full L2 frame buffer size, not the IP MTU */
    ll->poll = eth_poll;
    ll->send = eth_send;

    return 0;
}

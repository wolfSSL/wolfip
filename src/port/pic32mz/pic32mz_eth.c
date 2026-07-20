/* pic32mz_eth.c
 *
 * PIC32MZ Ethernet controller (EMAC) driver for wolfIP.
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
#include <xc.h>
#include <stddef.h>
#include <string.h>
#include "config.h"
#include "pic32mz_eth.h"
#include "phy_lan8740.h"
#include "cache.h"

/* Bring-up tracing: build with EXTRA_CFLAGS=-DPIC32_ETH_TRACE to emit a marker
 * before each EMAC register-access group. If the console stops after a given
 * marker, the following register access is stalling the CPU bus (typically a
 * disabled/unclocked module). */
#ifdef PIC32_ETH_TRACE
#include <stdio.h>
#define ETH_TRACE(s)   do { printf("[EMAC] " s "\r\n"); } while (0)
#else
#define ETH_TRACE(s)   do { } while (0)
#endif

/* MII management clock divisor (EMAC1MCFG.CLKSEL).
 * 0b1010 = host clock / 50. At SYSCLK = 200 MHz this gives MDC ~= 4 MHz, the
 * lowest the divider offers; LAN8740 tolerates it. */
#define MII_CLKSEL_DIV50    0x0Au

/* Bounded spin used to wait for MII management to finish a transfer. */
#define MII_TIMEOUT         1000000u

static void short_delay(void)
{
    volatile int i;

    /* The MIIMBUSY flag takes a few host-clock cycles to assert after a
     * command is issued; give it time before polling. */
    for (i = 0; i < 64; i++) {
    }
}

int pic32mz_emac_mii_init(void)
{
    volatile int i;
    uint32_t timeout;

    /* The Ethernet module is clocked by PBCLK5 and gated by PMD6.ETHMD. If
     * PBCLK5 is off or the module is PMD-disabled, the first ETH/EMAC register
     * access stalls the CPU bus forever (and wedges the ICSP debugger). Enable
     * both before touching any EMAC register. These are behind the system
     * unlock (SYSKEY); PMDLOCK is left unlocked afterwards to avoid the
     * PMDL1WAY one-way trap. */
    ETH_TRACE("z0: enable PBCLK5");
    if (PB5DIVbits.ON == 0) {
        SYSKEY = 0x00000000;
        SYSKEY = 0xAA996655;
        SYSKEY = 0x556699AA;
        PB5DIVbits.ON = 1;
        SYSKEY = 0x33333333;
    }
    ETH_TRACE("z1: enable ETH module (PMD6.ETHMD=0)");
    if (PMD6bits.ETHMD != 0) {
        SYSKEY = 0x00000000;
        SYSKEY = 0xAA996655;
        SYSKEY = 0x556699AA;
        CFGCONbits.PMDLOCK = 0;
        PMD6bits.ETHMD = 0;
        SYSKEY = 0x33333333;
    }

    /* Disable the Ethernet controller and wait for it to go idle.
     * If marker "a" prints but "b" never does, the ETHCON1 access below is
     * still stalling (module clock/enable issue). */
    ETH_TRACE("a: ETHCON1 off");
    ETHCON1CLR = _ETHCON1_ON_MASK;
    timeout = MII_TIMEOUT;
    while ((ETHSTAT & _ETHSTAT_ETHBUSY_MASK) && (timeout != 0))
        timeout--;
    if (timeout == 0) {
        /* Controller never went idle; the EMAC state is unreliable, so bail
         * rather than proceed into MDIO with a stuck module. */
        ETH_TRACE("a: ETHBUSY stuck - abort");
        return -1;
    }

    /* Enable the module (required to access the EMAC1 register block). */
    ETH_TRACE("b: ETHCON1 on");
    ETHCON1CLR = _ETHCON1_TXRTS_MASK | _ETHCON1_RXEN_MASK;
    ETHCON1SET = _ETHCON1_ON_MASK;

    /* Reset the MAC: assert all soft resets, then release. */
    ETH_TRACE("c: EMAC1CFG1 reset");
    EMAC1CFG1 = _EMAC1CFG1_SOFTRESET_MASK | _EMAC1CFG1_SIMRESET_MASK |
                _EMAC1CFG1_RESETRMCS_MASK | _EMAC1CFG1_RESETRFUN_MASK |
                _EMAC1CFG1_RESETTMCS_MASK | _EMAC1CFG1_RESETTFUN_MASK;
    for (i = 0; i < 1000; i++) {
    }
    EMAC1CFG1 = 0;

    /* Reset the RMII logic. */
    ETH_TRACE("d: EMAC1SUPP RMII reset");
    EMAC1SUPPSET = _EMAC1SUPP_RESETRMII_MASK;
    for (i = 0; i < 1000; i++) {
    }
    EMAC1SUPPCLR = _EMAC1SUPP_RESETRMII_MASK;

    /* Reset MII management, then set the MDC clock divisor. */
    ETH_TRACE("e: EMAC1MCFG");
    EMAC1MCFGSET = _EMAC1MCFG_RESETMGMT_MASK;
    for (i = 0; i < 100; i++) {
    }
    EMAC1MCFGCLR = _EMAC1MCFG_RESETMGMT_MASK;
    EMAC1MCFGbits.CLKSEL = MII_CLKSEL_DIV50;
    ETH_TRACE("f: mii init done");
    return 0;
}

int pic32mz_mdio_read(uint8_t phy_addr, uint8_t reg, uint16_t *val)
{
    uint32_t timeout;

    if (val == NULL)
        return -1;

    EMAC1MADR = ((uint32_t)phy_addr << _EMAC1MADR_PHYADDR_POSITION) |
                ((uint32_t)reg << _EMAC1MADR_REGADDR_POSITION);

    /* Issue a single read command. */
    EMAC1MCMDSET = _EMAC1MCMD_READ_MASK;
    short_delay();

    timeout = MII_TIMEOUT;
    while ((EMAC1MIND & _EMAC1MIND_MIIMBUSY_MASK) && (timeout != 0))
        timeout--;

    EMAC1MCMDCLR = _EMAC1MCMD_READ_MASK;

    if (timeout == 0)
        return -1;

    *val = (uint16_t)(EMAC1MRDD & _EMAC1MRDD_MRDD_MASK);
    return 0;
}

int pic32mz_mdio_write(uint8_t phy_addr, uint8_t reg, uint16_t val)
{
    uint32_t timeout;

    EMAC1MADR = ((uint32_t)phy_addr << _EMAC1MADR_PHYADDR_POSITION) |
                ((uint32_t)reg << _EMAC1MADR_REGADDR_POSITION);

    /* Writing the data register initiates the management write. */
    EMAC1MWTD = (uint32_t)val;
    short_delay();

    timeout = MII_TIMEOUT;
    while ((EMAC1MIND & _EMAC1MIND_MIIMBUSY_MASK) && (timeout != 0))
        timeout--;

    if (timeout == 0)
        return -1;
    return 0;
}

/* ==== Ethernet DMA: descriptor rings, poll/send, full MAC bring-up ======== */

/* PIC32 Ethernet descriptor header bits (FRM section 35). */
#define ED_EOWN         (1u << 7)       /* 1 = owned by the Ethernet DMA */
#define ED_NPV          (1u << 8)       /* next-descriptor pointer valid */
#define ED_COUNT_POS    16              /* byte count field, bits 16..26 */
#define ED_COUNT_MASK   0x07FF0000u
#define ED_EOP          (1u << 30)
#define ED_SOP          (1u << 31)

/* Four-word (16-byte) hardware descriptor (PIC32 FRM / LiteBSD layout). The
 * DMA writes ctl/status back into words 2-3 on completion, so those words MUST
 * be part of the descriptor -- an 8-byte descriptor lets the write-back corrupt
 * the next descriptor. With NPV=0 the DMA advances to the next CONTIGUOUS
 * descriptor (linear); only the last data descriptor sets NPV=1 and its NEXT_ED
 * (the hdr of the trailing "link" descriptor after it) points back to desc 0. */
typedef struct {
    volatile uint32_t hdr;              /* EOWN/NPV/EOP/SOP + TX byte count */
    volatile uint32_t addr;             /* physical buffer address */
    volatile uint32_t ctl;              /* control (TX) / filter status (RX) */
    volatile uint32_t status;           /* DMA status; RX size = status & 0xFFFF */
} eth_dcpt_t;

#define RX_DESC_COUNT   8
#define TX_DESC_COUNT   8

/* DMA memory: XC32 'coherent' places it uncached, so no cache maintenance is
 * needed; the EMAC gets physical addresses (KVA_TO_PA). One extra "link"
 * descriptor per ring holds the wrap pointer (see above). */
static eth_dcpt_t rx_desc[RX_DESC_COUNT + 1] __attribute__((coherent, aligned(8)));
static eth_dcpt_t tx_desc[TX_DESC_COUNT + 1] __attribute__((coherent, aligned(8)));
static uint8_t rx_buf[RX_DESC_COUNT][LINK_MTU] __attribute__((coherent, aligned(16)));
static uint8_t tx_buf[TX_DESC_COUNT][LINK_MTU] __attribute__((coherent, aligned(16)));

static int rx_idx, tx_idx;
static uint32_t rx_count, tx_count;

/* PHY link state, tracked so pic32mz_eth_link_update() can re-apply the MAC
 * speed/duplex when the link changes after init. phy_addr / link_valid are set
 * once the PHY is located in pic32mz_eth_init(); cur_* hold what is currently
 * programmed into the MAC. */
static uint8_t phy_addr;
static uint8_t link_valid;
static uint8_t cur_link_up;
static uint8_t cur_speed_100;
static uint8_t cur_full_duplex;

#ifdef PIC32_ETH_TRACE
/* First bytes of the most recent RX/TX frame, for the diagnostic dump. */
static uint8_t dbg_rx[32], dbg_tx[32];
static uint32_t dbg_rx_len, dbg_tx_len;
#endif

static void eth_rings_init(void)
{
    int i;

    for (i = 0; i < RX_DESC_COUNT; i++) {
        rx_desc[i].addr = PIC32_KVA_TO_PA(rx_buf[i]);
        /* NPV=0 -> linear advance; last data descriptor wraps via the link. */
        rx_desc[i].hdr  = ED_EOWN |
                          ((i == RX_DESC_COUNT - 1) ? ED_NPV : 0u);
    }
    rx_desc[RX_DESC_COUNT].hdr = PIC32_KVA_TO_PA(&rx_desc[0]);   /* wrap link */
    rx_idx = 0;

    for (i = 0; i < TX_DESC_COUNT; i++) {
        tx_desc[i].addr = PIC32_KVA_TO_PA(tx_buf[i]);
        tx_desc[i].hdr  = (i == TX_DESC_COUNT - 1) ? ED_NPV : 0u; /* CPU-owned */
    }
    tx_desc[TX_DESC_COUNT].hdr = PIC32_KVA_TO_PA(&tx_desc[0]);   /* wrap link */
    tx_idx = 0;
}

/* wolfIP RX poll: one frame (>0), 0 if none. */
static int eth_poll(struct wolfIP_ll_dev *ll, void *frame, uint32_t len)
{
    eth_dcpt_t *d = &rx_desc[rx_idx];
    uint32_t n;

    (void)ll;
    if (d->hdr & ED_EOWN)
        return 0;                               /* still owned by the DMA */

    n = d->status & 0xFFFFu;                    /* RX frame size is in status */
    if (n > 4u)
        n -= 4u;                                /* drop the 4-byte FCS */
    if (n > len)
        n = len;
    memcpy(frame, rx_buf[rx_idx], n);
#ifdef PIC32_ETH_TRACE
    memcpy(dbg_rx, frame, (n > 32u) ? 32u : n);
    dbg_rx_len = n;
#endif

    /* Re-arm: EOWN back to the DMA, keeping the wrap flag on the last one. */
    d->hdr = ED_EOWN | ((rx_idx == RX_DESC_COUNT - 1) ? ED_NPV : 0u);
    ETHCON1SET = _ETHCON1_BUFCDEC_MASK;         /* a buffer became free */
    rx_idx = (rx_idx + 1) % RX_DESC_COUNT;
    rx_count++;
    return (int)n;
}

/* wolfIP TX send: bytes queued, or <0 if the TX ring is full or len exceeds
 * LINK_MTU. */
static int eth_send(struct wolfIP_ll_dev *ll, void *frame, uint32_t len)
{
    eth_dcpt_t *d = &tx_desc[tx_idx];

    (void)ll;
    if ((d->hdr & ED_EOWN) || (len > LINK_MTU))
        return -1;                              /* ring slot still in flight */

    memcpy(tx_buf[tx_idx], frame, len);
#ifdef PIC32_ETH_TRACE
    memcpy(dbg_tx, frame, (len > 32u) ? 32u : len);
    dbg_tx_len = len;
#endif
    d->addr = PIC32_KVA_TO_PA(tx_buf[tx_idx]);
    d->hdr  = ED_SOP | ED_EOP |
              ((tx_idx == TX_DESC_COUNT - 1) ? ED_NPV : 0u) |
              ((len << ED_COUNT_POS) & ED_COUNT_MASK) | ED_EOWN;
    tx_idx = (tx_idx + 1) % TX_DESC_COUNT;
    ETHCON1SET = _ETHCON1_TXRTS_MASK;           /* resume TX from the ring */
    tx_count++;
    return (int)len;
}

void pic32mz_eth_stats(uint32_t *rx, uint32_t *tx)
{
    if (rx != NULL)
        *rx = rx_count;
    if (tx != NULL)
        *tx = tx_count;
}

#ifdef PIC32_ETH_TRACE
#include <stdio.h>
void pic32mz_eth_diag(void)
{
    printf("[ETH] CON1=%08lX STAT=%08lX IRQ=%08lX RXFC=%08lX CON2=%08lX\r\n",
           (unsigned long)ETHCON1, (unsigned long)ETHSTAT,
           (unsigned long)ETHIRQ, (unsigned long)ETHRXFC,
           (unsigned long)ETHCON2);
    printf("[ETH] CFG1=%08lX CFG2=%08lX SUPP=%08lX RXST=%08lX TXST=%08lX\r\n",
           (unsigned long)EMAC1CFG1, (unsigned long)EMAC1CFG2,
           (unsigned long)EMAC1SUPP, (unsigned long)ETHRXST,
           (unsigned long)ETHTXST);
    printf("[ETH] rx_idx=%d rxhdr: %08lX %08lX %08lX %08lX link=%08lX rx=%lu tx=%lu\r\n",
           rx_idx,
           (unsigned long)rx_desc[0].hdr, (unsigned long)rx_desc[1].hdr,
           (unsigned long)rx_desc[2].hdr, (unsigned long)rx_desc[3].hdr,
           (unsigned long)rx_desc[RX_DESC_COUNT].hdr,
           (unsigned long)rx_count, (unsigned long)tx_count);
    {
        uint32_t i;
        printf("[ETH] rx[%lu]:", (unsigned long)dbg_rx_len);
        for (i = 0; (i < dbg_rx_len) && (i < 32u); i++)
            printf(" %02X", dbg_rx[i]);
        printf("\r\n[ETH] tx[%lu]:", (unsigned long)dbg_tx_len);
        for (i = 0; (i < dbg_tx_len) && (i < 32u); i++)
            printf(" %02X", dbg_tx[i]);
        printf("\r\n");
    }
}
#endif

static void eth_default_mac(uint8_t mac[6])
{
    mac[0] = 0x02;  /* locally administered */
    mac[1] = 0x11;
    mac[2] = 0xAA;
    mac[3] = 0xBB;
    mac[4] = 0x32;  /* "32" for PIC32 */
    mac[5] = 0x4D;
}

/* Program the link-dependent MAC registers from a resolved PHY link. The
 * fixed EMAC1IPGR/CLRT/MAXF are set once in pic32mz_eth_init(). */
static void mac_apply_link(const struct phy_link *link)
{
    /* MAC: auto pad + CRC, duplex + speed from the PHY. */
    EMAC1CFG2 = _EMAC1CFG2_PADENABLE_MASK | _EMAC1CFG2_CRCENABLE_MASK |
                (link->full_duplex ? _EMAC1CFG2_FULLDPLX_MASK : 0u);
    EMAC1IPGT = link->full_duplex ? 0x15 : 0x12;
    EMAC1SUPPbits.SPEEDRMII = link->speed_100 ? 1 : 0;
}

int pic32mz_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    struct phy_link link;
    uint8_t addr[6];
    int ret;

    if (mac != NULL)
        memcpy(addr, mac, 6);
    else
        eth_default_mac(addr);

    /* RMII pins that share an analog function must be forced digital
     * (ANSEL=0). On the 144-pin default (FETHIO=ON) pinout the 50 MHz
     * reference clock EREFCLK is on RJ11, which is also AN4/C1INB: left
     * analog, the MAC data path gets no clock, so TX stalls mid-frame and RX
     * never clocks in (MDIO/link still work on their own MDC clock). */
    ANSELJCLR = (1u << 11) | (1u << 8) | (1u << 9); /* RJ11 EREFCLK, RJ8/RJ9 ETXD0/1 */
    ANSELHCLR = (1u << 4)  | (1u << 5);             /* RH4/RH5 ERXERR/ERXD1 */

    ret = pic32mz_emac_mii_init();
    if (ret != 0)
        return ret;

    /* LAN8740 link. On -2 (link down) bringup leaves link_up/speed/duplex 0;
     * the MAC is programmed for that here and pic32mz_eth_link_update() re-
     * applies the negotiated speed/duplex once the link comes up. */
    ret = phy_lan8740_bringup(pic32mz_mdio_read, pic32mz_mdio_write, 5000u,
                              &link);
    /* -2 means "link down" (non-fatal); anything else non-zero is a genuine
     * PHY/MDIO failure -- fail fast rather than masking it. */
    if (ret != 0 && ret != -2)
        return ret;

    /* PHY located: remember its address and current link so the run-time
     * poller can re-apply the MAC config on a later link change. */
    phy_addr = link.addr;
    link_valid = 1;
    cur_link_up = link.link_up;
    cur_speed_100 = link.speed_100;
    cur_full_duplex = link.full_duplex;

    /* MAC: auto pad + CRC, duplex + speed from the PHY. */
    mac_apply_link(&link);
    EMAC1IPGR = 0x0C12;
    EMAC1CLRT = 0x370F;
    EMAC1MAXF = LINK_MTU;

    /* Station address: EMAC1SA2/1/0 hold MAC bytes 0..5, low byte first. */
    EMAC1SA2 = ((uint32_t)addr[1] << 8) | addr[0];
    EMAC1SA1 = ((uint32_t)addr[3] << 8) | addr[2];
    EMAC1SA0 = ((uint32_t)addr[5] << 8) | addr[4];

    EMAC1CFG1SET = _EMAC1CFG1_RXENABLE_MASK;    /* MAC receive on */

    eth_rings_init();
    ETHCON2 = (LINK_MTU / 16) << 4;             /* RX buffer size (16B units) */
    ETHRXST = PIC32_KVA_TO_PA(&rx_desc[0]);
    ETHTXST = PIC32_KVA_TO_PA(&tx_desc[0]);
    ETHRXFC = _ETHRXFC_UCEN_MASK | _ETHRXFC_BCEN_MASK | _ETHRXFC_CRCOKEN_MASK;
    ETHCON1SET = _ETHCON1_RXEN_MASK;            /* controller RX on */

    memcpy(ll->mac, addr, 6);
    strncpy(ll->ifname, "eth0", sizeof(ll->ifname) - 1);
    ll->non_ethernet = 0;
    ll->mtu = LINK_MTU;
    ll->poll = eth_poll;
    ll->send = eth_send;
    ll->priv = NULL;

    return ret;                                 /* 0 = link up, -2 = link down */
}

int pic32mz_eth_link_update(void)
{
    struct phy_link st;
    int ret;

    if (!link_valid)
        return 0;                   /* no PHY located; nothing to poll */

    ret = phy_lan8740_link_status(pic32mz_mdio_read, phy_addr, &st);
    if (ret != 0)
        return ret;                 /* MDIO error */

    /* Re-apply the MAC only on an actual change so an established link is not
     * disturbed. Speed/duplex only matter (and are only valid) while up. */
    if (st.link_up != cur_link_up ||
        (st.link_up && (st.speed_100 != cur_speed_100 ||
                        st.full_duplex != cur_full_duplex))) {
        if (st.link_up)
            mac_apply_link(&st);
        cur_link_up = st.link_up;
        cur_speed_100 = st.speed_100;
        cur_full_duplex = st.full_duplex;
    }

    return cur_link_up ? 1 : 0;
}

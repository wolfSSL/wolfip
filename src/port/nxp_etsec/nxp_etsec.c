/* nxp_etsec.c
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
 * NXP eTSEC (Gianfar) ethernet driver for wolfIP.
 *
 * Brings up one eTSEC in polled mode: soft reset, MAC config, BD rings in
 * DRAM, MDIO clause-22 + external PHY (or a fixed link), and the polled
 * poll/send datapath. Ported from the U-Boot eTSEC driver (drivers/net/
 * tsec.c, fsl_mdio.c). e500v2, big-endian.
 */

#include <stdint.h>
#include <stddef.h>
#include "config.h"
#include "nxp_etsec.h"
/* Byte-loop mem helpers (nxp_memcpy/nxp_memset); no libc in bare-metal. */
#include "../common/nxp_mem.h"

/* ---- Big-endian register access (sync/twi/isync like wolfBoot) ------- */
#if defined(__powerpc__) || defined(__PPC__) || defined(__ppc__)
static inline uint32_t rd32(uintptr_t a)
{
    uint32_t r;
    __asm__ __volatile__("sync;\n" "lwz %0,0(%1);\n" "twi 0,%0,0;\n" "isync"
                         : "=r"(r) : "r"(a) : "memory");
    return r;
}
static inline void wr32(uintptr_t a, uint32_t v)
{
    __asm__ __volatile__("sync;\n" "stw %0,0(%1)" : : "r"(v), "r"(a) : "memory");
}
static inline void etsec_sync(void)
{
    __asm__ __volatile__("sync" ::: "memory");
}
/* e500v2 data cache line = 32 bytes; low DDR is cacheable-non-coherent, so
 * flush (dcbf) BDs/buffers around DMA. */
static void dcache_flush(const void *p, uint32_t len)
{
    uintptr_t a = (uintptr_t)p & ~31UL;
    uintptr_t end = (uintptr_t)p + len;
    for (; a < end; a += 32)
        __asm__ __volatile__("dcbf 0,%0" : : "r"(a) : "memory");
    etsec_sync();
}
#else
static inline uint32_t rd32(uintptr_t a) { return *(volatile uint32_t *)a; }
static inline void wr32(uintptr_t a, uint32_t v) { *(volatile uint32_t *)a = v; }
static inline void etsec_sync(void) { }
static void dcache_flush(const void *p, uint32_t len) { (void)p; (void)len; }
#endif

#define dcache_inval(p, l) dcache_flush((p), (l))

/* Optional debug log hook. */
static void (*g_log)(const char *) = 0;
void nxp_etsec_set_log(void (*log_fn)(const char *)) { g_log = log_fn; }
#define TLOG(s) do { if (g_log) g_log(s); } while (0)

/* ---- Driver state ---------------------------------------------------- */
static uintptr_t reg_base;   /* selected eTSEC register block */
static uintptr_t mdio_base;  /* external MDIO (eTSEC1 + 0x520) */
static uintptr_t local_mdio; /* selected eTSEC's own MDIO (+0x520) */
static uint32_t  rx_idx;
static uint32_t  tx_idx;
static int32_t   phy_addr = -1;

static struct etsec_bd rx_bd_ring[ETSEC_RX_RING_SIZE]
    __attribute__((aligned(ETSEC_BD_ALIGN)));
static struct etsec_bd tx_bd_ring[ETSEC_TX_RING_SIZE]
    __attribute__((aligned(ETSEC_BD_ALIGN)));
static uint8_t rx_buf_pool[ETSEC_RX_RING_SIZE][ETSEC_MAX_BUF_LEN]
    __attribute__((aligned(ETSEC_BUF_ALIGN)));
static uint8_t tx_buf_pool[ETSEC_TX_RING_SIZE][ETSEC_MAX_BUF_LEN]
    __attribute__((aligned(ETSEC_BUF_ALIGN)));

/* Shared clause-22 PHY register defines + bring-up helpers. A fixed-link board
 * has no MDIO write path (no PHY to drive), so pull in the helpers only for the
 * PHY case; the register defines come in either way. */
#if !NXP_ETSEC_FIXED_LINK
static uint16_t phy_read(uint32_t phy, uint32_t reg);
static int phy_write(uint32_t phy, uint32_t reg, uint16_t val);
#define NXP_MDIO_READ  phy_read
#define NXP_MDIO_WRITE phy_write
#define NXP_PHY_HELPERS
#endif
#include "../common/nxp_phy.h"

/* ---- MDIO clause-22 (controller base parameterized) ------------------ */
static void mdio_setup(uintptr_t mbase)
{
    uint32_t t = MDIO_TIMEOUT;
    wr32(mbase + MIIM_CFG, MIIMCFG_RESET_MGMT);
    wr32(mbase + MIIM_CFG, MIIMCFG_INIT_VALUE);
    while ((rd32(mbase + MIIM_IND) & MIIMIND_BUSY) && --t) {
    }
}

static uint16_t mdio_read_base(uintptr_t mbase, uint32_t phy, uint32_t reg)
{
    uint32_t t = MDIO_TIMEOUT;
    wr32(mbase + MIIM_ADD, ((phy & 0x1FU) << MIIMADD_PHY_SHIFT) | (reg & 0x1FU));
    wr32(mbase + MIIM_COM, 0);
    etsec_sync();
    wr32(mbase + MIIM_COM, MIIMCOM_READ_CYCLE);
    while ((rd32(mbase + MIIM_IND) & (MIIMIND_NOTVALID | MIIMIND_BUSY)) && --t) {
    }
    if (t == 0)
        return 0xFFFFU;
    return (uint16_t)(rd32(mbase + MIIM_STAT) & 0xFFFFU);
}

#if !NXP_ETSEC_FIXED_LINK || NXP_ETSEC_IF_SGMII
static int mdio_write_base(uintptr_t mbase, uint32_t phy, uint32_t reg,
        uint16_t val)
{
    uint32_t t = MDIO_TIMEOUT;
    wr32(mbase + MIIM_ADD, ((phy & 0x1FU) << MIIMADD_PHY_SHIFT) | (reg & 0x1FU));
    wr32(mbase + MIIM_CON, (uint32_t)val);
    etsec_sync();
    while ((rd32(mbase + MIIM_IND) & MIIMIND_BUSY) && --t) {
    }
    return t ? 0 : -1;
}
#endif

static uint16_t phy_read(uint32_t phy, uint32_t reg)
{
    return mdio_read_base(mdio_base, phy, reg);
}
#if !NXP_ETSEC_FIXED_LINK
static int phy_write(uint32_t phy, uint32_t reg, uint16_t val)
{
    return mdio_write_base(mdio_base, phy, reg, val);
}
#endif

/* ---- PHY discovery / link -------------------------------------------- */
int nxp_etsec_phy_addr(void) { return (int)phy_addr; }

uint16_t nxp_etsec_phy_read(uint8_t reg)
{
    if (phy_addr < 0)
        return 0xFFFFU;
    return phy_read((uint32_t)phy_addr, reg);
}

uint32_t nxp_etsec_link_up(void)
{
#if NXP_ETSEC_FIXED_LINK
    return 1U;
#else
    uint16_t bsr;
    if (phy_addr < 0)
        return 0;
    bsr = phy_read((uint32_t)phy_addr, PHY_BMSR);
    bsr = phy_read((uint32_t)phy_addr, PHY_BMSR);
    return (bsr & BMSR_LINK) ? 1U : 0U;
#endif
}

#if NXP_ETSEC_IF_SGMII
/* Configure the internal TBI/SerDes for SGMII via the eTSEC's own (local)
 * MDIO at the TBIPA address. VERIFY the TBI register values on hardware. */
static void configure_serdes(void)
{
    wr32(reg_base + ETSEC_TBIPA, NXP_ETSEC_TBIPA);
    mdio_write_base(local_mdio, NXP_ETSEC_TBIPA, 0x00, 0x8000); /* TBI_CR reset */
    mdio_write_base(local_mdio, NXP_ETSEC_TBIPA, 0x04, 0x4001); /* TBI_ANA SGMII */
    mdio_write_base(local_mdio, NXP_ETSEC_TBIPA, 0x11, 0x0020); /* TBICON clk */
    mdio_write_base(local_mdio, NXP_ETSEC_TBIPA, 0x00, 0x1140); /* aneg+1G+FD */
}
#endif

/* ---- MAC bring-up ---------------------------------------------------- */
static void mac_reset(void)
{
    wr32(reg_base + ETSEC_MACCFG1, MACCFG1_SOFT_RESET);
    etsec_sync();
    wr32(reg_base + ETSEC_MACCFG1, 0);
}

static void mac_set_addr(const uint8_t *mac)
{
    uint32_t a1, a2;
    a1 = ((uint32_t)mac[5] << 24) | ((uint32_t)mac[4] << 16) |
         ((uint32_t)mac[3] << 8) | (uint32_t)mac[2];
    a2 = ((uint32_t)mac[1] << 24) | ((uint32_t)mac[0] << 16);
    wr32(reg_base + ETSEC_MACSTNADDR1, a1);
    wr32(reg_base + ETSEC_MACSTNADDR2, a2);
}

static void init_registers(void)
{
    uint32_t i;

    wr32(reg_base + ETSEC_IEVENT, IEVENT_INIT_CLEAR);
    wr32(reg_base + ETSEC_IMASK, 0);          /* polled: mask all */
    for (i = 0; i < 8U; i++) {
        wr32(reg_base + ETSEC_IADDR0 + i * 4U, 0);
        wr32(reg_base + ETSEC_GADDR0 + i * 4U, 0);
    }
    wr32(reg_base + ETSEC_MRBLR, ETSEC_MAX_BUF_LEN);
    wr32(reg_base + ETSEC_MINFLR, MINFLR_INIT_SETTINGS);
    wr32(reg_base + ETSEC_ATTR, ATTR_INIT_SETTINGS);
    wr32(reg_base + ETSEC_ATTRELI, 0);
    wr32(reg_base + ETSEC_MAXFRM, ETSEC_MAX_FRAME_LEN);
    wr32(reg_base + ETSEC_RCTRL, 0);
    wr32(reg_base + ETSEC_TCTRL, 0);
}

/* Program MACCFG2/ECNTRL for the link speed and interface. */
static void adjust_link(uint32_t speed, int full_duplex)
{
    uint32_t ecntrl = rd32(reg_base + ETSEC_ECNTRL) & ~ECNTRL_R100;
    uint32_t cfg2 = rd32(reg_base + ETSEC_MACCFG2) &
                    ~(MACCFG2_IF_MASK | MACCFG2_FULL_DUPLEX);

    if (full_duplex)
        cfg2 |= MACCFG2_FULL_DUPLEX;
    if (speed >= 1000U) {
        cfg2 |= MACCFG2_GMII;
    }
    else {
        cfg2 |= MACCFG2_MII;
        if (speed >= 100U)
            ecntrl |= ECNTRL_R100;
    }
    wr32(reg_base + ETSEC_ECNTRL, ecntrl);
    wr32(reg_base + ETSEC_MACCFG2, cfg2);
}

static void setup_bd_rings(void)
{
    uint32_t i;

    for (i = 0; i < ETSEC_RX_RING_SIZE; i++) {
        rx_bd_ring[i].status = RXBD_EMPTY;
        rx_bd_ring[i].length = 0;
        rx_bd_ring[i].bufptr = (uint32_t)(uintptr_t)&rx_buf_pool[i][0];
    }
    rx_bd_ring[ETSEC_RX_RING_SIZE - 1].status = RXBD_EMPTY | RXBD_WRAP;
    for (i = 0; i < ETSEC_TX_RING_SIZE; i++) {
        tx_bd_ring[i].status = 0;
        tx_bd_ring[i].length = 0;
        tx_bd_ring[i].bufptr = 0;
    }
    tx_bd_ring[ETSEC_TX_RING_SIZE - 1].status = TXBD_WRAP;
    dcache_flush(rx_bd_ring, sizeof(rx_bd_ring));
    dcache_flush(tx_bd_ring, sizeof(tx_bd_ring));
    /* Clean+invalidate the RX buffers before the DMA owns them so a later
     * write-back of a dirty line cannot clobber a DMA-written frame. */
    dcache_flush(rx_buf_pool, sizeof(rx_buf_pool));

    wr32(reg_base + ETSEC_TBASE, (uint32_t)(uintptr_t)tx_bd_ring);
    wr32(reg_base + ETSEC_RBASE, (uint32_t)(uintptr_t)rx_bd_ring);
    rx_idx = 0;
    tx_idx = 0;
}

/* ---- wolfIP poll/send callbacks -------------------------------------- */
static int eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct etsec_bd *bd = &tx_bd_ring[tx_idx];
    uint16_t wrap;
    uint32_t tries;
    (void)dev;

    if (len == 0 || len > ETSEC_MAX_BUF_LEN)
        return -1;

    dcache_inval(bd, sizeof(*bd));
    if (bd->status & TXBD_READY)
        return -2; /* ring full */

    nxp_memcpy(tx_buf_pool[tx_idx], frame, len);
    if (len < 60U) {
        nxp_memset(tx_buf_pool[tx_idx] + len, 0, 60U - len);
        len = 60U;
    }
    dcache_flush(tx_buf_pool[tx_idx], len);

    wrap = bd->status & TXBD_WRAP;
    bd->bufptr = (uint32_t)(uintptr_t)tx_buf_pool[tx_idx];
    bd->length = (uint16_t)len;
    etsec_sync();
    bd->status = wrap | TXBD_READY | TXBD_PADCRC | TXBD_LAST | TXBD_CRC;
    dcache_flush(bd, sizeof(*bd));

    /* doorbell: clear TX halt */
    wr32(reg_base + ETSEC_TSTAT, TSTAT_CLEAR_THALT);

    /* wait (bounded) for the BD to be consumed so the buffer is reusable */
    tries = ETSEC_POLL_TRIES;
    do {
        dcache_inval(bd, sizeof(*bd));
    } while ((bd->status & TXBD_READY) && --tries);

    tx_idx = (tx_idx + 1U) % ETSEC_TX_RING_SIZE;
    return tries ? (int)len : -1;
}

static int eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct etsec_bd *bd = &rx_bd_ring[rx_idx];
    uint16_t status, wrap, flen = 0;
    int err;
    (void)dev;

    dcache_inval(bd, sizeof(*bd));
    status = bd->status;
    if (status & RXBD_EMPTY) {
        /* recover from an out-of-buffers stall */
        if (rd32(reg_base + ETSEC_IEVENT) & IEVENT_BSY) {
            wr32(reg_base + ETSEC_IEVENT, IEVENT_BSY);
            wr32(reg_base + ETSEC_RSTAT, RSTAT_CLEAR_RHALT);
        }
        return 0;
    }

    err = (status & RXBD_STATS) ? 1 : 0;
    if (!err) {
        flen = bd->length;            /* includes 4-byte FCS */
        if (flen >= 4U)
            flen -= 4U;
        else
            flen = 0;
        if (flen > ETSEC_MAX_BUF_LEN)
            flen = ETSEC_MAX_BUF_LEN;
        if (flen > len)
            flen = (uint16_t)len;
        if (flen > 0) {
            dcache_inval(rx_buf_pool[rx_idx], flen);
            nxp_memcpy(frame, rx_buf_pool[rx_idx], flen);
        }
    }

    /* recycle the BD */
    wrap = status & RXBD_WRAP;
    bd->length = 0;
    etsec_sync();
    bd->status = wrap | RXBD_EMPTY;
    dcache_flush(bd, sizeof(*bd));

    /* re-arm RX in case the controller halted on an empty ring */
    wr32(reg_base + ETSEC_RSTAT, RSTAT_CLEAR_RHALT);

    rx_idx = (rx_idx + 1U) % ETSEC_RX_RING_SIZE;
    return err ? 0 : (int)flen;
}

/* ---- Public init ----------------------------------------------------- */
int nxp_etsec_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    static const uint8_t default_mac[6] = {
        0x02, 0x11, 0x20, 0x10, 0x21, 0x01
    };
    uint32_t v;

    if (ll == NULL)
        return -1;
    if (mac == NULL)
        mac = default_mac;

    nxp_memcpy(ll->mac, mac, 6);
    nxp_memset(ll->ifname, 0, sizeof(ll->ifname));
    nxp_memcpy(ll->ifname, "eth0", 4);
    ll->mtu = LINK_MTU;
    ll->poll = eth_poll;
    ll->send = eth_send;

    reg_base = ETSEC_BASE(NXP_ETSEC_INDEX);
    mdio_base = ETSEC_BASE(0) + ETSEC_MDIO_OFFSET;     /* eTSEC1 window */
    local_mdio = reg_base + ETSEC_MDIO_OFFSET;

    TLOG("reset");
    mac_reset();

    /* MAC + interface base config. */
    TLOG("maccfg");
    wr32(reg_base + ETSEC_MACCFG2, MACCFG2_INIT_SETTINGS);
    v = ECNTRL_INIT_SETTINGS;
#if NXP_ETSEC_IF_SGMII
    v |= ECNTRL_SGMII_MODE;
#else
    v |= ECNTRL_REDUCED_MODE;   /* RGMII */
#endif
    wr32(reg_base + ETSEC_ECNTRL, v);
    mac_set_addr(mac);

    TLOG("regs");
    init_registers();
    wr32(reg_base + ETSEC_TBIPA, NXP_ETSEC_TBIPA);

    TLOG("rings");
    setup_bd_rings();

    /* Enable MAC + DMA, then release the rings. */
    TLOG("enable");
    v = rd32(reg_base + ETSEC_MACCFG1);
    wr32(reg_base + ETSEC_MACCFG1, v | MACCFG1_RX_EN | MACCFG1_TX_EN);
    v = rd32(reg_base + ETSEC_DMACTRL);
    wr32(reg_base + ETSEC_DMACTRL, v | DMACTRL_INIT_SETTINGS);
    wr32(reg_base + ETSEC_TSTAT, TSTAT_CLEAR_THALT);
    wr32(reg_base + ETSEC_RSTAT, RSTAT_CLEAR_RHALT);
    v = rd32(reg_base + ETSEC_DMACTRL);
    wr32(reg_base + ETSEC_DMACTRL, v & ~(DMACTRL_GRS | DMACTRL_GTS));

    /* MDIO + PHY (or fixed link). */
    TLOG("mdio");
    mdio_setup(mdio_base);
#if NXP_ETSEC_IF_SGMII
    if (local_mdio != mdio_base)
        mdio_setup(local_mdio);
    configure_serdes();
#endif

#if NXP_ETSEC_FIXED_LINK
    adjust_link(NXP_ETSEC_SPEED, 1);
    return (int)0x1FF; /* datapath up, fixed link */
#else
    {
        uint16_t id1, bsr;
        phy_addr = nxp_phy_detect(NXP_ETSEC_PHY_ADDR);
        if (phy_addr < 0) {
            adjust_link(NXP_ETSEC_SPEED, 1);
            /* MAC datapath forced up, but no PHY: report link down;
             * nxp_etsec_phy_addr() returns -1 to signal absence. */
            return 0;
        }
        if (nxp_phy_init((uint32_t)phy_addr) < 0)
            return -5; /* hard PHY-init failure */
        id1 = phy_read((uint32_t)phy_addr, PHY_ID1);
        bsr = phy_read((uint32_t)phy_addr, PHY_BMSR);
        adjust_link(NXP_ETSEC_SPEED, 1);
        return (int)(((uint32_t)(id1 & 0xFF00U) << 8) |
                     ((bsr & BMSR_LINK) ? 0x100U : 0U) |
                     ((uint32_t)phy_addr & 0xFFU));
    }
#endif
}

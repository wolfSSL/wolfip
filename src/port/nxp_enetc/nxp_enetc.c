/* nxp_enetc.c
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
 * NXP ENETC ethernet driver for wolfIP (LS1028A and other Layerscape parts).
 *
 * ENETC is a PCIe integrated endpoint on an internal ECAM root complex. The
 * driver discovers the ethernet port and the shared MDIO controller over
 * ECAM (bus 0), sets up one RX and one TX buffer-descriptor ring in memory,
 * brings up the MAC + (SGMII PCS or RGMII) interface and the external PHY,
 * and exposes the polled wolfIP poll/send callbacks. AArch64, little-endian.
 * Ported from the U-Boot ENETC driver (drivers/net/fsl_enetc.c).
 */

#include <stdint.h>
#include <stddef.h>
#include "config.h"
#include "nxp_enetc.h"
/* Byte-loop mem helpers (nxp_memcpy/nxp_memset); no libc in the bare-metal
 * images this links into. */
#include "../common/nxp_mem.h"

/* ---- Register access (LE, no swap on AArch64) ------------------------ */
static inline uint32_t rd32(uintptr_t a)
{
    return *(volatile uint32_t *)a;
}
static inline void wr32(uintptr_t a, uint32_t v)
{
    *(volatile uint32_t *)a = v;
}
/* Order BD/buffer stores before the doorbell. DDR is cacheable, so callers
 * also clean (TX) / invalidate (RX) the rings and buffers for DMA coherency. */
#define ENETC_DCACHE_LINE   64UL
#if defined(__aarch64__)
static inline void enetc_dmb(void)
{
    __asm__ __volatile__("dmb sy" ::: "memory");
}
/* Clean & invalidate the D-cache over [p, p+len): push CPU writes to memory. */
static inline void enetc_dcache_clean(const void *p, uint32_t len)
{
    uintptr_t a = (uintptr_t)p & ~(ENETC_DCACHE_LINE - 1UL);
    uintptr_t e = (uintptr_t)p + len;
    for (; a < e; a += ENETC_DCACHE_LINE)
        __asm__ __volatile__("dc civac, %0" :: "r"(a) : "memory");
    __asm__ __volatile__("dsb sy" ::: "memory");
}
/* Invalidate the D-cache over [p, p+len): drop stale lines before reading
 * DMA-written data. Uses clean+invalidate so a partially-cached line is not
 * lost (the buffers/BDs are cache-line aligned, so this is safe). */
static inline void enetc_dcache_inval(const void *p, uint32_t len)
{
    enetc_dcache_clean(p, len);
}
#else
static inline void enetc_dmb(void)
{
    __asm__ __volatile__("" ::: "memory");
}
static inline void enetc_dcache_clean(const void *p, uint32_t len)
{
    (void)p; (void)len;
}
static inline void enetc_dcache_inval(const void *p, uint32_t len)
{
    (void)p; (void)len;
}
#endif

/* Optional debug log hook (set by the application). */
static void (*g_log)(const char *) = 0;
void nxp_enetc_set_log(void (*log_fn)(const char *)) { g_log = log_fn; }
#define ELOG(s) do { if (g_log) g_log(s); } while (0)

/* ---- PCI ECAM config access (bus 0) ---------------------------------- */
static uintptr_t pci_cfg_addr(uint32_t fn, uint32_t off)
{
    return (uintptr_t)((uint64_t)NXP_ENETC_ECAM_BASE +
                       (((uint64_t)fn & 0x7U) << 12) + (off & 0xFFFU));
}
static uint32_t pci_cfg_rd32(uint32_t fn, uint32_t off)
{
    return rd32(pci_cfg_addr(fn, off & ~3U));
}
static void pci_cfg_wr32(uint32_t fn, uint32_t off, uint32_t val)
{
    wr32(pci_cfg_addr(fn, off & ~3U), val);
}
static uint16_t pci_cfg_rd16(uint32_t fn, uint32_t off)
{
    uint32_t w = pci_cfg_rd32(fn, off);
    return (uint16_t)((off & 2U) ? (w >> 16) : (w & 0xFFFFU));
}

/* Enable PCI memory space (and optionally bus-master) for a function. */
static void pci_enable(uint32_t fn, int master)
{
    uint32_t w = pci_cfg_rd32(fn, PCI_CFG_COMMAND);
    uint32_t cmd = (w & 0xFFFFU) | PCI_CMD_MEMORY;
    if (master)
        cmd |= PCI_CMD_MASTER;
    pci_cfg_wr32(fn, PCI_CFG_COMMAND, (w & 0xFFFF0000UL) | (cmd & 0xFFFFU));
}

/* PCIe FLR: reset the ENETC function before bring-up to clear stale boot-ROM
 * DMA/BD state (else the TX ring engine stays wedged). Resets BARs, so run
 * before pci_bar0()/pci_enable(). */
#define PCI_CFG_CAP_PTR     0x34U
#define PCI_CAP_ID_EXP      0x10U
#define PCIE_DEVCAP         0x04U       /* offset within the PCIe cap */
#define PCIE_DEVCAP_FLR     0x10000000UL
#define PCIE_DEVCTL         0x08U
#define PCIE_DEVCTL_FLR     0x00008000UL

static void enetc_flr(uint32_t fn)
{
    uint32_t cap, off, devcap, devctl;
    volatile uint32_t spin;
    int i;

    off = pci_cfg_rd32(fn, PCI_CFG_CAP_PTR) & 0xFFU;
    for (i = 0; (i < 48) && (off >= 0x40U); i++) {
        cap = pci_cfg_rd32(fn, off);
        if ((cap & 0xFFU) == PCI_CAP_ID_EXP) {
            devcap = pci_cfg_rd32(fn, off + PCIE_DEVCAP);
            if ((devcap & PCIE_DEVCAP_FLR) != 0U) {
                devctl = pci_cfg_rd32(fn, off + PCIE_DEVCTL);
                pci_cfg_wr32(fn, off + PCIE_DEVCTL,
                             devctl | PCIE_DEVCTL_FLR);
                for (spin = 0; spin < 0x4000000U; spin++) {
                }
            }
            return;
        }
        off = (cap >> 8) & 0xFFU;
    }
}

/* Read the live BAR0 (IERB programs it from reset). A zero BAR is unexpected
 * on silicon; fabricate one in the BAR window and flag it (may alias). */
static uint64_t pci_bar0(uint32_t fn, int *fabricated)
{
    uint32_t lo = pci_cfg_rd32(fn, PCI_CFG_BAR0);
    uint32_t hi = pci_cfg_rd32(fn, PCI_CFG_BAR1);
    uint64_t bar = (((uint64_t)hi) << 32) | (lo & PCI_BAR_MEM_MASK);

    if (fabricated != NULL)
        *fabricated = 0;
    if (bar == 0) {
        /* PF base offsets are NOT a uniform stride: PF3 (EMDIO) jumps to
         * WINDOW+0x100000; a uniform stride aliased port3 SI0 and faulted. */
        static const uint64_t pf_base_off[8] = {
            0x000000ULL, /* PF0 - port0 SI0   (0x1F800_0000) */
            0x040000ULL, /* PF1 - port1 SI0   (0x1F804_0000) */
            0x080000ULL, /* PF2 - switch port (0x1F808_0000) */
            0x100000ULL, /* PF3 - EMDIO       (0x1F810_0000) */
            0x120000ULL, /* PF4               (0x1F812_0000) */
            0x140000ULL, /* PF5               (0x1F814_0000) */
            0x060000ULL, /* PF6 - port6 SI0   (0x1F806_0000) */
            0x160000ULL  /* PF7 (reserved)                   */
        };
        bar = (uint64_t)NXP_ENETC_BAR_WINDOW + pf_base_off[fn & 0x7U];
        pci_cfg_wr32(fn, PCI_CFG_BAR0, (uint32_t)(bar & PCI_BAR_MEM_MASK));
        pci_cfg_wr32(fn, PCI_CFG_BAR1, (uint32_t)(bar >> 32));
        if (fabricated != NULL)
            *fabricated = 1;
    }
    return bar;
}

/* ---- Driver state ---------------------------------------------------- */
static uintptr_t si_base;    /* ENETC port station-interface BAR0 */
static uintptr_t port_base;  /* si_base + ENETC_PORT_REGS_OFF */
static uintptr_t ext_mdio;   /* external MDIO regs (MDIO PF BAR0 + 0x1C00) */
static uintptr_t pcs_mdio;   /* internal PCS MDIO (port_base + 0x8030) */
static uintptr_t tx_ring_reg;/* TX ring register block (si_base + 0x8000) */
static uintptr_t rx_ring_reg;/* RX ring register block (si_base + 0x8100) */
static uint32_t  tx_prod;
static uint32_t  rx_idx;
static int32_t   phy_addr = -1;

#define ENETC_PM_IMDIO_BASE     0x8030UL

static struct enetc_rx_bd rx_bd_ring[ENETC_RX_RING_SIZE]
    __attribute__((aligned(ENETC_BD_ALIGN)));
static struct enetc_tx_bd tx_bd_ring[ENETC_TX_RING_SIZE]
    __attribute__((aligned(ENETC_BD_ALIGN)));
static uint8_t rx_buf_pool[ENETC_RX_RING_SIZE][ENETC_MAX_BUF_LEN]
    __attribute__((aligned(ENETC_BUF_ALIGN)));
static uint8_t tx_buf_pool[ENETC_TX_RING_SIZE][ENETC_MAX_BUF_LEN]
    __attribute__((aligned(ENETC_BUF_ALIGN)));

/* Shared clause-22 PHY register map + bring-up (nxp_phy_detect/nxp_phy_init).
 * Forward-declare the MDIO accessors (defined below) so the shared helpers can
 * reach them via the NXP_MDIO_READ/WRITE macros. */
static uint16_t phy_read(uint32_t phy, uint32_t reg);
static int phy_write(uint32_t phy, uint32_t reg, uint16_t val);
#define NXP_MDIO_READ  phy_read
#define NXP_MDIO_WRITE phy_write
#define NXP_PHY_HELPERS
#include "../common/nxp_phy.h"

/* ---- MDIO clause-22 (controller base parameterized) ------------------ */
static int mdio_wait_bsy(uintptr_t mbase)
{
    uint32_t t = MDIO_TIMEOUT;
    while ((rd32(mbase + ENETC_MDIO_CFG) & ENETC_MDIO_CFG_BSY) && --t) {
    }
    return t ? 0 : -1;
}

static uint16_t mdio_read_base(uintptr_t mbase, uint32_t phy, uint32_t reg)
{
    wr32(mbase + ENETC_MDIO_CFG, ENETC_MDIO_CFG_C22);
    if (mdio_wait_bsy(mbase) != 0)
        return 0xFFFFU;
    wr32(mbase + ENETC_MDIO_CTL, ENETC_MDIO_CTL_READ | ENETC_MDIO_CTL_ADDR(phy, reg));
    if (mdio_wait_bsy(mbase) != 0)
        return 0xFFFFU;
    if (rd32(mbase + ENETC_MDIO_CFG) & ENETC_MDIO_CFG_RD_ER)
        return 0xFFFFU;
    return (uint16_t)(rd32(mbase + ENETC_MDIO_DATA) & 0xFFFFU);
}

static int mdio_write_base(uintptr_t mbase, uint32_t phy, uint32_t reg,
        uint16_t val)
{
    wr32(mbase + ENETC_MDIO_CFG, ENETC_MDIO_CFG_C22);
    if (mdio_wait_bsy(mbase) != 0)
        return -1;
    wr32(mbase + ENETC_MDIO_CTL, ENETC_MDIO_CTL_ADDR(phy, reg));
    if (mdio_wait_bsy(mbase) != 0)
        return -1;
    wr32(mbase + ENETC_MDIO_DATA, (uint32_t)val);
    if (mdio_wait_bsy(mbase) != 0)
        return -1;
    return 0;
}

/* External PHY accessors use the shared MDIO PF controller. */
static uint16_t phy_read(uint32_t phy, uint32_t reg)
{
    return mdio_read_base(ext_mdio, phy, reg);
}
static int phy_write(uint32_t phy, uint32_t reg, uint16_t val)
{
    return mdio_write_base(ext_mdio, phy, reg, val);
}

/* ---- PHY discovery / link -------------------------------------------- */
int nxp_enetc_phy_addr(void)
{
    return (int)phy_addr;
}

uint16_t nxp_enetc_phy_read(uint8_t reg)
{
    if (phy_addr < 0)
        return 0xFFFFU;
    return phy_read((uint32_t)phy_addr, reg);
}

uint32_t nxp_enetc_link_up(void)
{
    uint16_t bsr;
    if (phy_addr < 0)
        return 0;
    bsr = phy_read((uint32_t)phy_addr, PHY_BMSR);
    bsr = phy_read((uint32_t)phy_addr, PHY_BMSR);
    return (bsr & BMSR_LINK) ? 1U : 0U;
}

/* ---- SGMII PCS (internal MDIO, PCS at phy addr 0) -------------------- */
#if NXP_ENETC_IF_SGMII
#define PCS_PHY_ADDR            0U
#define PCS_CR                  0x00U
#define PCS_DEV_ABILITY         0x04U
#define PCS_LINK_TIMER1         0x12U
#define PCS_LINK_TIMER2         0x13U
#define PCS_IF_MODE             0x14U
#define PCS_CR_DEF_VAL          0x0140U
#define PCS_CR_RESET_AN         0x1200U
#define PCS_DEV_ABILITY_SGMII   0x4001U
#define PCS_IF_MODE_SGMII       0x0001U
#define PCS_IF_MODE_SGMII_AN    0x0002U
#define PCS_LINK_TIMER1_VAL     0x06A0U
#define PCS_LINK_TIMER2_VAL     0x0003U

static void enetc_init_sgmii(void)
{
    uint32_t v;

    mdio_write_base(pcs_mdio, PCS_PHY_ADDR, PCS_IF_MODE,
                    PCS_IF_MODE_SGMII | PCS_IF_MODE_SGMII_AN);
    mdio_write_base(pcs_mdio, PCS_PHY_ADDR, PCS_DEV_ABILITY,
                    PCS_DEV_ABILITY_SGMII);
    mdio_write_base(pcs_mdio, PCS_PHY_ADDR, PCS_LINK_TIMER1,
                    PCS_LINK_TIMER1_VAL);
    mdio_write_base(pcs_mdio, PCS_PHY_ADDR, PCS_LINK_TIMER2,
                    PCS_LINK_TIMER2_VAL);
    mdio_write_base(pcs_mdio, PCS_PHY_ADDR, PCS_CR,
                    PCS_CR_DEF_VAL | PCS_CR_RESET_AN);

    /* MAC PM_IF_MODE resets to RGMII select with no SGMII speed/duplex, so frames
     * never clock out (TX consumer index stalls). Clear RGMII, force 1G/full,
     * disable MAC in-band AN (the PCS does SGMII AN). */
    v = rd32(port_base + ENETC_PM_IF_MODE);
    v &= ~ENETC_PM_IF_MODE_RG;
    v &= ~ENETC_PM_IF_MODE_AN_ENA;
    v &= ~ENETC_PM_IFM_SSP_MASK;
    v |= ENETC_PM_IFM_SSP_1000;
    v |= ENETC_PM_IF_MODE_FULL_DPX;
    wr32(port_base + ENETC_PM_IF_MODE, v);
}
#endif /* NXP_ENETC_IF_SGMII */

#if !NXP_ENETC_IF_SGMII
/* For RGMII, force the MAC to the (assumed gigabit/full) link and disable
 * the unreliable in-band signalling. */
static void enetc_init_rgmii(void)
{
    uint32_t v = rd32(port_base + ENETC_PM_IF_MODE);
    v &= ~ENETC_PM_IF_MODE_AN_ENA;
    v &= ~ENETC_PM_IFM_SSP_MASK;
    v |= ENETC_PM_IFM_SSP_1000;
    v |= ENETC_PM_IF_MODE_FULL_DPX;
    wr32(port_base + ENETC_PM_IF_MODE, v);
}
#endif /* !NXP_ENETC_IF_SGMII */

/* ---- MAC / SI bring-up ----------------------------------------------- */
static void enetc_set_mac(const uint8_t *mac)
{
    static const int8_t devfn_to_pf[7] = { 0, 1, 2, -1, -1, -1, 3 };
    uint32_t a0, a1;
    int pf;

    a0 = ((uint32_t)mac[3] << 24) | ((uint32_t)mac[2] << 16) |
         ((uint32_t)mac[1] << 8) | (uint32_t)mac[0];
    a1 = ((uint32_t)mac[5] << 8) | (uint32_t)mac[4];

    /* Immediate (port) MAC address. */
    wr32(port_base + ENETC_PSIPMAR0, a0);
    wr32(port_base + ENETC_PSIPMAR1, a1);

    /* Persistent (IERB) MAC address for the matching PF. */
    pf = (NXP_ENETC_PORT_FN < 7U) ? devfn_to_pf[NXP_ENETC_PORT_FN] : -1;
    if (pf >= 0) {
        uintptr_t ie = (uintptr_t)((uint64_t)NXP_ENETC_IERB_BASE + 0x8000UL +
                                   (uint32_t)pf * 0x100UL);
        wr32(ie + 0x00UL, a0);
        wr32(ie + 0x04UL, a1);
    }
}

static void enetc_enable_si_port(void)
{
    wr32(port_base + ENETC_PSICFGR0,
         ENETC_PSICFGR_SET_TXBDR(1) | ENETC_PSICFGR_SET_RXBDR(1));
    wr32(port_base + ENETC_PM_MAXFRM, LINK_MTU);
    wr32(port_base + ENETC_PM_CC, ENETC_PM_CC_RX_TX_EN);
    wr32(port_base + ENETC_PMR, ENETC_PMR_SI0_EN | ENETC_PMR_PSPEED_1000M);
    wr32(si_base + ENETC_SICAR0, ENETC_SICAR_VALUE);
    wr32(si_base + ENETC_SIMR, ENETC_SIMR_EN);
}

/* ---- BD ring setup --------------------------------------------------- */
static void enetc_setup_tx_bdr(void)
{
    uint64_t base = (uint64_t)(uintptr_t)tx_bd_ring;
    uint32_t i;

    for (i = 0; i < ENETC_TX_RING_SIZE; i++) {
        tx_bd_ring[i].addr = 0;
        tx_bd_ring[i].buf_len = 0;
        tx_bd_ring[i].frm_len = 0;
        tx_bd_ring[i].err_csum = 0;
        tx_bd_ring[i].flags = 0;
    }
    wr32(tx_ring_reg + ENETC_TBBAR0, (uint32_t)(base & 0xFFFFFFFFUL));
    wr32(tx_ring_reg + ENETC_TBBAR1, (uint32_t)(base >> 32));
    wr32(tx_ring_reg + ENETC_TBLENR, ENETC_TX_RING_SIZE);
    wr32(tx_ring_reg + ENETC_TBCIR, 0);
    wr32(tx_ring_reg + ENETC_TBPIR, 0);
    enetc_dcache_clean((const void *)tx_bd_ring, sizeof(tx_bd_ring));
    wr32(tx_ring_reg + ENETC_TBMR, ENETC_TBMR_EN);
    tx_prod = 0;
}

static void enetc_setup_rx_bdr(void)
{
    uint64_t base = (uint64_t)(uintptr_t)rx_bd_ring;
    uint64_t buf;
    uint32_t i;

    for (i = 0; i < ENETC_RX_RING_SIZE; i++) {
        buf = (uint64_t)(uintptr_t)&rx_buf_pool[i][0];
        rx_bd_ring[i].addr_lo = (uint32_t)(buf & 0xFFFFFFFFUL);
        rx_bd_ring[i].addr_hi = (uint32_t)(buf >> 32);
        rx_bd_ring[i].buf_len = 0;
        rx_bd_ring[i].vlan_opt = 0;
        rx_bd_ring[i].lstatus = 0;
    }
    wr32(rx_ring_reg + ENETC_RBBAR0, (uint32_t)(base & 0xFFFFFFFFUL));
    wr32(rx_ring_reg + ENETC_RBBAR1, (uint32_t)(base >> 32));
    wr32(rx_ring_reg + ENETC_RBLENR, ENETC_RX_RING_SIZE);
    wr32(rx_ring_reg + ENETC_RBBSR, ENETC_MAX_BUF_LEN);
    wr32(rx_ring_reg + ENETC_RBCIR, 0);
    wr32(rx_ring_reg + ENETC_RBPIR, 0);
    /* Clean the RX buffers (not just the BDs) before the ENETC DMA owns them, so
     * a later write-back of a dirty (BSS-zeroed) line cannot clobber a DMA-
     * written frame -- matching the sibling drivers (belt-and-suspenders given
     * the coherent SICAR DMA on this part). */
    enetc_dcache_clean((const void *)rx_buf_pool, sizeof(rx_buf_pool));
    enetc_dcache_clean((const void *)rx_bd_ring, sizeof(rx_bd_ring));
    enetc_dmb();
    wr32(rx_ring_reg + ENETC_RBMR, ENETC_RBMR_EN);
    rx_idx = 0;
}

/* ---- wolfIP poll/send callbacks -------------------------------------- */
static int eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct enetc_tx_bd *bd = &tx_bd_ring[tx_prod];
    uint32_t ci, tries;
    (void)dev;

    if (len == 0 || len > ENETC_MAX_BUF_LEN)
        return -1;

    ci = rd32(tx_ring_reg + ENETC_TBCIR) & ENETC_BDR_IDX_MASK;
    if (((tx_prod + 1U) % ENETC_TX_RING_SIZE) == ci)
        return -2; /* ring full */

    nxp_memcpy(tx_buf_pool[tx_prod], frame, len);
    if (len < 60U) {
        nxp_memset(tx_buf_pool[tx_prod] + len, 0, 60U - len);
        len = 60U;
    }

    bd->addr = (uint64_t)(uintptr_t)tx_buf_pool[tx_prod];
    bd->buf_len = (uint16_t)len;
    bd->frm_len = (uint16_t)len;
    bd->err_csum = 0;
    bd->flags = ENETC_TXBD_FLAGS_F;
    /* Push the frame buffer and the BD to memory so the DMA reads the new
     * data, then order before the doorbell. */
    enetc_dcache_clean(tx_buf_pool[tx_prod], len);
    enetc_dcache_clean((const void *)bd, sizeof(*bd));
    enetc_dmb();

    tx_prod = (tx_prod + 1U) % ENETC_TX_RING_SIZE;
    wr32(tx_ring_reg + ENETC_TBPIR, tx_prod);

    /* Wait (bounded) for HW to consume the BD so the buffer is reusable. */
    tries = ENETC_POLL_TRIES;
    while (--tries &&
           (tx_prod != (rd32(tx_ring_reg + ENETC_TBCIR) & ENETC_BDR_IDX_MASK))) {
    }
    return tries ? (int)len : -1;
}

static int eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct enetc_rx_bd *bd = &rx_bd_ring[rx_idx];
    uint64_t buf;
    uint32_t status, flen, err;
    (void)dev;

    /* Drop any stale cache lines so we read the DMA-written BD writeback. */
    enetc_dcache_inval((const void *)bd, sizeof(*bd));
    enetc_dmb();
    status = bd->lstatus;
    if (!ENETC_RXBD_LSTATUS_READY(status))
        return 0;

    err = ENETC_RXBD_LSTATUS_ERR(status) ? 1U : 0U;
    flen = bd->buf_len;
    if (flen > ENETC_MAX_BUF_LEN)
        flen = ENETC_MAX_BUF_LEN;
    if (flen > len)
        flen = len;
    if (!err && flen > 0U) {
        enetc_dcache_inval(rx_buf_pool[rx_idx], flen);
        nxp_memcpy(frame, rx_buf_pool[rx_idx], flen);
    }

    /* Recycle the BD: restore the buffer address, clear the writeback. */
    buf = (uint64_t)(uintptr_t)&rx_buf_pool[rx_idx][0];
    bd->addr_lo = (uint32_t)(buf & 0xFFFFFFFFUL);
    bd->addr_hi = (uint32_t)(buf >> 32);
    bd->buf_len = 0;
    bd->vlan_opt = 0;
    bd->lstatus = 0;
    /* Push the recycled BD to memory so the DMA reuses it. */
    enetc_dcache_clean((const void *)bd, sizeof(*bd));
    enetc_dmb();

    rx_idx = (rx_idx + 1U) % ENETC_RX_RING_SIZE;
    wr32(rx_ring_reg + ENETC_RBCIR, rx_idx);

    return err ? 0 : (int)flen;
}

/* ---- Public init ----------------------------------------------------- */
int nxp_enetc_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    static const uint8_t default_mac[6] = {
        0x02, 0x11, 0x20, 0x28, 0x00, 0x01
    };
    uint64_t port_bar, mdio_bar;
    uint16_t id1, bsr;
    int fab_port = 0, fab_mdio = 0;

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

    /* Confirm the ENETC port function is present over ECAM. */
    ELOG("ecam");
    if (pci_cfg_rd16(NXP_ENETC_PORT_FN, PCI_CFG_VENDOR_ID) != ENETC_PCI_VENDOR_ID)
        return -3;

    /* Reset the function to a clean state before configuring it (clears any
     * stale BD-ring/DMA state from the boot ROM). Must precede pci_bar0(). */
    enetc_flr(NXP_ENETC_PORT_FN);

    /* Resolve BARs and enable the functions. A fabricated (fallback) BAR is
     * unexpected on real silicon -- warn but proceed (hardware-verify). */
    ELOG("bar");
    port_bar = pci_bar0(NXP_ENETC_PORT_FN, &fab_port);
    pci_enable(NXP_ENETC_PORT_FN, 1);
    mdio_bar = pci_bar0(NXP_ENETC_MDIO_FN, &fab_mdio);
    pci_enable(NXP_ENETC_MDIO_FN, 0);
    if (fab_port || fab_mdio)
        ELOG("bar-fallback");

    si_base = (uintptr_t)port_bar;
    port_base = si_base + ENETC_PORT_REGS_OFF;
    ext_mdio = (uintptr_t)mdio_bar + ENETC_MDIO_REGS_OFF;
    pcs_mdio = port_base + ENETC_PM_IMDIO_BASE;
    tx_ring_reg = si_base + ENETC_BDR_BASE(ENETC_BDR_TX, 0);
    rx_ring_reg = si_base + ENETC_BDR_BASE(ENETC_BDR_RX, 0);

    /* Configure the interface mode before SI/MAC enable: the mEMAC latches it when
     * PM_CC RX_TX_EN is set; later writes are ignored. */
    ELOG("iface");
#if NXP_ENETC_IF_SGMII
    enetc_init_sgmii();
#else
    enetc_init_rgmii();
#endif

    ELOG("si");
    enetc_enable_si_port();
    enetc_set_mac(mac);

    ELOG("rings");
    enetc_setup_tx_bdr();
    enetc_setup_rx_bdr();

    /* Bring up the external PHY over the shared MDIO. */
    ELOG("phy");
    phy_addr = nxp_phy_detect(NXP_ENETC_PHY_ADDR);
    if (phy_addr < 0)
        return 0; /* datapath up, no PHY: link down; nxp_enetc_phy_addr()==-1 */

    if (nxp_phy_init((uint32_t)phy_addr) < 0)
        return -5; /* hard PHY-init failure */
    id1 = phy_read((uint32_t)phy_addr, PHY_ID1);
    bsr = phy_read((uint32_t)phy_addr, PHY_BMSR);

    return (int)(((uint32_t)(id1 & 0xFF00U) << 8) |
                 ((bsr & BMSR_LINK) ? 0x100U : 0U) |
                 ((uint32_t)phy_addr & 0xFFU));
}

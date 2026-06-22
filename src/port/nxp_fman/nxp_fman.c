/* nxp_fman.c
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
 * NXP QorIQ FMan (Frame Manager) ethernet driver for wolfIP.
 *
 * Common to the DPAA1 QorIQ parts (T2080/e6500, T1024 and T1040/e5500):
 * a single mEMAC in polled independent (BMI-direct) mode, no QMan/BMan.
 * The FMan microcode is uploaded by the boot stage (wolfBoot
 * hal_fman_init); this driver runs the FMan common init (QMI/FPM/BMI),
 * per-port parameter RAM, BMI ports, mEMAC + (SGMII or RGMII) PHY
 * interface, and the polled RX/TX buffer-descriptor datapath. Ported
 * from the QorIQ U-Boot FMan driver (drivers/net/fm/). All board-specific
 * values (CCSRBAR, mEMAC index, PHY address, interface mode) come from
 * nxp_fman_board.h so the one driver serves every QorIQ board.
 */

#include <stdint.h>
#include <stddef.h>
#include "config.h"
#include "nxp_fman.h"

/* Byte-loop mem helpers (nxp_memcpy/nxp_memset); no libc in bare-metal. */
#include "../common/nxp_mem.h"

/* ---- Big-endian CCSR register access (sync/twi/isync like wolfBoot) --- */
#if defined(__powerpc__) || defined(__PPC__) || defined(__ppc__)
static inline uint32_t fman_rd32(uintptr_t addr)
{
    uint32_t ret;
    __asm__ __volatile__(
        "sync;\n" "lwz %0,0(%1);\n" "twi 0,%0,0;\n" "isync"
        : "=r"(ret) : "r"(addr) : "memory");
    return ret;
}
static inline void fman_wr32(uintptr_t addr, uint32_t val)
{
    __asm__ __volatile__(
        "sync;\n" "stw %0,0(%1)" : : "r"(val), "r"(addr) : "memory");
}
static inline void fman_sync(void)
{
    __asm__ __volatile__("sync" ::: "memory");
}
/* e5500/e6500 data cache line = 64 bytes. We use dcbf (flush + invalidate)
 * for both directions: dcbi (invalidate-only) is privileged/unreliable on
 * Book-E e5500/e6500, and for our access pattern the descriptor/buffer lines
 * are clean when re-read (flushed at recycle, not re-dirtied), so dcbf acts
 * as an invalidate (no stale write-back) before the FMan-DMA'd data is read. */
static void dcache_flush(const void *p, uint32_t len)
{
    uintptr_t a = (uintptr_t)p & ~63UL;
    uintptr_t end = (uintptr_t)p + len;
    for (; a < end; a += 64)
        __asm__ __volatile__("dcbf 0,%0" : : "r"(a) : "memory");
    fman_sync();
}
static void dcache_inval(const void *p, uint32_t len)
{
    dcache_flush(p, len);
}
#else
/* Portable fallbacks so the file compiles for host syntax checks. */
static inline uint32_t fman_rd32(uintptr_t addr) { return *(volatile uint32_t *)addr; }
static inline void fman_wr32(uintptr_t addr, uint32_t val) { *(volatile uint32_t *)addr = val; }
static inline void fman_sync(void) { }
static void dcache_flush(const void *p, uint32_t len) { (void)p; (void)len; }
static void dcache_inval(const void *p, uint32_t len) { (void)p; (void)len; }
#endif

/* Optional debug log hook (set by the application). */
static void (*g_log)(const char *) = 0;
void nxp_fman_set_log(void (*log_fn)(const char *)) { g_log = log_fn; }
#define FLOG(s) do { if (g_log) g_log(s); } while (0)

/* MURAM is 32-bit access only; 16-bit fields need a read-modify-write of
 * the containing 32-bit big-endian word. */
static void muram_writew(uintptr_t addr, uint16_t val)
{
    uintptr_t w = addr & ~3UL;
    uint32_t cur = fman_rd32(w);
    if (addr & 2)
        cur = (cur & 0xFFFF0000UL) | (uint32_t)val;
    else
        cur = (cur & 0x0000FFFFUL) | ((uint32_t)val << 16);
    fman_wr32(w, cur);
}
static uint16_t muram_readw(uintptr_t addr)
{
    uint32_t cur = fman_rd32(addr & ~3UL);
    return (addr & 2) ? (uint16_t)(cur & 0xFFFFU) : (uint16_t)(cur >> 16);
}

/* ---- MURAM bump allocator -------------------------------------------- */
static uint32_t muram_ptr;
static uint32_t muram_end;

static void muram_init(void)
{
    muram_ptr = (uint32_t)FMAN_MURAM_BASE + (uint32_t)FM_MURAM_RES_SIZE;
    muram_end = (uint32_t)FMAN_MURAM_BASE + (uint32_t)FM_MURAM_TOTAL;
}

static uint32_t muram_alloc(uint32_t size, uint32_t align)
{
    uint32_t off, ret, a;
    off = muram_ptr & (align - 1U);
    if (off != 0U)
        muram_ptr += (align - off);
    off = size & (align - 1U);
    if (off != 0U)
        size += (align - off);
    if ((muram_ptr + size) >= muram_end)
        return 0; /* out of MURAM */
    ret = muram_ptr;
    muram_ptr += size;
    for (a = ret; a < ret + size; a += 4U)
        fman_wr32(a, 0);
    return ret;
}

/* ---- Buffer descriptor (big-endian, 16 bytes) ------------------------ */
struct fm_bd {
    volatile uint16_t status;
    volatile uint16_t len;
    volatile uint32_t res0;
    volatile uint16_t res1;
    volatile uint16_t buf_ptr_hi;
    volatile uint32_t buf_ptr_lo;
};

static struct fm_bd rx_bd_ring[RX_BD_RING_SIZE] __attribute__((aligned(64)));
static struct fm_bd tx_bd_ring[TX_BD_RING_SIZE] __attribute__((aligned(64)));
static uint8_t rx_buf_pool[RX_BD_RING_SIZE][MAX_RXBUF_LEN] __attribute__((aligned(64)));
static uint8_t tx_buf_pool[TX_BD_RING_SIZE][MAX_TXBUF_LEN] __attribute__((aligned(64)));

static uint32_t rx_pram;   /* MURAM address of RX parameter RAM */
static uint32_t tx_pram;   /* MURAM address of TX parameter RAM */
static uint32_t rx_idx;
static uint32_t tx_idx;
static int32_t  phy_addr = -1;

/* Shared clause-22 PHY register map + bring-up (nxp_phy_detect/nxp_phy_init).
 * Forward-declare the MDIO accessors (defined below) so the shared helpers can
 * reach them via the NXP_MDIO_READ/WRITE macros. */
static uint16_t mdio_read(uint32_t phy, uint32_t reg);
static int mdio_write(uint32_t phy, uint32_t reg, uint16_t value);
#define NXP_MDIO_READ  mdio_read
#define NXP_MDIO_WRITE mdio_write
#define NXP_PHY_HELPERS
#include "../common/nxp_phy.h"

/* MDIO controller register offsets relative to a controller base. */
#define MDIO_OFF_STAT       0x30UL
#define MDIO_OFF_CTRL       0x34UL
#define MDIO_OFF_DATA       0x38UL
#define MDIO_OFF_ADDR       0x3CUL

#define DEDICATED_MDIO_BASE FMAN_MDIO_BASE(NXP_FMAN_MDIO_EMI)

/* ---- MDIO clause-22 access (controller base parameterized) ----------- */
static void mdio_setup(uintptr_t mbase)
{
    fman_wr32(mbase + MDIO_OFF_STAT,
              MDIO_STAT_CLKDIV(NXP_FMAN_MDIO_CLKDIV) | MDIO_STAT_NEG);
}

static int mdio_wait_bsy(uintptr_t mbase)
{
    uint32_t t = MDIO_TIMEOUT;
    while ((fman_rd32(mbase + MDIO_OFF_STAT) & MDIO_STAT_BSY) && --t) {
    }
    return t ? 0 : -1;
}

static int mdio_wait_data(uintptr_t mbase)
{
    uint32_t t = MDIO_TIMEOUT;
    while ((fman_rd32(mbase + MDIO_OFF_DATA) & MDIO_DATA_BSY) && --t) {
    }
    return t ? 0 : -1;
}

static uint16_t mdio_read_base(uintptr_t mbase, uint32_t phy, uint32_t reg)
{
    uint32_t cfg, ctl;

    cfg = fman_rd32(mbase + MDIO_OFF_STAT);
    fman_wr32(mbase + MDIO_OFF_STAT, cfg & ~MDIO_STAT_EN_C45);
    if (mdio_wait_bsy(mbase) != 0)
        return 0xFFFFU;

    ctl = MDIO_CTL_PORT_ADDR(phy) | MDIO_CTL_DEV_ADDR(reg);
    fman_wr32(mbase + MDIO_OFF_CTRL, ctl);
    if (mdio_wait_bsy(mbase) != 0)
        return 0xFFFFU;

    fman_wr32(mbase + MDIO_OFF_CTRL, ctl | MDIO_CTL_READ);
    if (mdio_wait_data(mbase) != 0)
        return 0xFFFFU;
    if (fman_rd32(mbase + MDIO_OFF_STAT) & MDIO_STAT_RD_ER)
        return 0xFFFFU;

    return (uint16_t)(fman_rd32(mbase + MDIO_OFF_DATA) & 0xFFFFU);
}

static int mdio_write_base(uintptr_t mbase, uint32_t phy, uint32_t reg,
        uint16_t value)
{
    uint32_t cfg;

    cfg = fman_rd32(mbase + MDIO_OFF_STAT);
    fman_wr32(mbase + MDIO_OFF_STAT, cfg & ~MDIO_STAT_EN_C45);
    if (mdio_wait_bsy(mbase) != 0)
        return -1;

    fman_wr32(mbase + MDIO_OFF_CTRL, MDIO_CTL_PORT_ADDR(phy) | MDIO_CTL_DEV_ADDR(reg));
    if (mdio_wait_bsy(mbase) != 0)
        return -1;

    fman_wr32(mbase + MDIO_OFF_DATA, MDIO_DATA_VAL(value));
    if (mdio_wait_data(mbase) != 0)
        return -1;
    return 0;
}

/* PHY accessors use the dedicated 1G MDIO bus. */
static uint16_t mdio_read(uint32_t phy, uint32_t reg)
{
    return mdio_read_base(DEDICATED_MDIO_BASE, phy, reg);
}
static int mdio_write(uint32_t phy, uint32_t reg, uint16_t value)
{
    return mdio_write_base(DEDICATED_MDIO_BASE, phy, reg, value);
}

/* ---- PHY discovery / link -------------------------------------------- */
int nxp_fman_phy_addr(void)
{
    return (int)phy_addr;
}

uint16_t nxp_fman_phy_read(uint8_t reg)
{
    if (phy_addr < 0)
        return 0xFFFFU;
    return mdio_read((uint32_t)phy_addr, reg);
}

/* Read a register from an explicit MDIO address (bus diagnostics / scan).
 * Unlike nxp_fman_phy_read() this does not use the auto-detected phy_addr,
 * so it can probe every address on the shared MDIO bus. Requires the FMan
 * MDIO to have been set up (nxp_fman_init() called first). */
uint16_t nxp_fman_phy_read_at(uint8_t addr, uint8_t reg)
{
    return mdio_read((uint32_t)addr, reg);
}

uint32_t nxp_fman_link_up(void)
{
    uint16_t bsr;
    if (phy_addr < 0)
        return 0;
    bsr = mdio_read((uint32_t)phy_addr, PHY_BMSR);
    bsr = mdio_read((uint32_t)phy_addr, PHY_BMSR);
    return (bsr & BMSR_LINK) ? 1U : 0U;
}

/* ---- FMan common init (QMI / FPM / DMA / BMI) ------------------------- */
static void fm_init_qmi(void)
{
    uint32_t v = fman_rd32(FMAN_QMI_FMQM_GC);
    fman_wr32(FMAN_QMI_FMQM_GC, v & ~(FMQM_GC_ENQ_EN | FMQM_GC_DEQ_EN));
    fman_wr32(FMAN_QMI_FMQM_EIEN, 0);
    fman_wr32(FMAN_QMI_FMQM_EIE, FMQM_EIE_CLEAR_ALL);
    fman_wr32(FMAN_QMI_FMQM_IEN, 0);
    fman_wr32(FMAN_QMI_FMQM_IE, FMQM_IE_CLEAR_ALL);
}

static uint32_t fm_assign_risc(uint32_t port_id)
{
    uint32_t risc_sel, val;
    risc_sel = (port_id & 0x1U) ? FMFPPRC_RISC2 : FMFPPRC_RISC1;
    val = (port_id << FMFPPRC_PORTID_SHIFT) & 0x3F000000UL;
    val |= ((risc_sel << FMFPPRC_ORA_SHIFT) | risc_sel);
    return val;
}

static void fm_init_fpm(uint32_t rx_pid, uint32_t tx_pid)
{
    uint32_t v;
    int i;

    v = fman_rd32(FMAN_FPM_FMFPEE);
    fman_wr32(FMAN_FPM_FMFPEE,
              v | (FMFPEE_EHM | FMFPEE_UEC | FMFPEE_CER | FMFPEE_DER));

    /* Assign the RISC engine for our RX and TX IM ports. */
    fman_wr32(FMAN_FPM_FPMPRC, fm_assign_risc(rx_pid));
    fman_wr32(FMAN_FPM_FPMPRC, fm_assign_risc(tx_pid));

    fman_wr32(FMAN_FPM_FPMFLC, FMFP_FLC_DISP_LIM_NONE);
    fman_wr32(FMAN_FPM_FMFPEE, FMFPEE_CLEAR_EVENT);
    for (i = 0; i < 4; i++)
        fman_wr32(FMAN_FPM_FPMCEV(i), 0xFFFFFFFFUL);
    fman_wr32(FMAN_FPM_FPMRCR, FMFP_RCR_MDEC | FMFP_RCR_IDEC);
}

static void fm_init_dma(void)
{
    uint32_t v;
    v = fman_rd32(FMAN_DMA_FMDMSR);
    fman_wr32(FMAN_DMA_FMDMSR, v | FMDMSR_CLEAR_ALL);
    v = fman_rd32(FMAN_DMA_FMDMMR);
    fman_wr32(FMAN_DMA_FMDMMR, v | FMDMMR_SBER);
}

static int fm_init_bmi(uint32_t rx_pid, uint32_t tx_pid)
{
    uint32_t base, offset, val, blk;

    base = muram_alloc((uint32_t)FM_FREE_POOL_SIZE, (uint32_t)FM_FREE_POOL_ALIGN);
    if (base == 0)
        return -1;
    offset = base - (uint32_t)FMAN_MURAM_BASE;

    val = offset / 256U;
    blk = (uint32_t)FM_FREE_POOL_SIZE / 256U;
    val |= ((blk - 1U) << FMBM_CFG1_FBPS_SHIFT);
    fman_wr32(FMAN_BMI_FMBM_CFG1, val);

    fman_wr32(FMAN_BMI_FMBM_IER, FMBM_IER_DISABLE_ALL);
    fman_wr32(FMAN_BMI_FMBM_IEVR, FMBM_IEVR_CLEAR_ALL);

    /* size the FIFO for our 1G RX and TX ports (4 tasks, 4KB FIFO) */
    fman_wr32(FMAN_BMI_FMBM_PP(rx_pid), FMBM_PP_MXT(4));
    fman_wr32(FMAN_BMI_FMBM_PFS(rx_pid), FMBM_PFS_IFSZ(0xF));
    fman_wr32(FMAN_BMI_FMBM_PP(tx_pid), FMBM_PP_MXT(4));
    fman_wr32(FMAN_BMI_FMBM_PFS(tx_pid), FMBM_PFS_IFSZ(0xF));

    fman_wr32(FMAN_BMI_FMBM_INIT, FMBM_INIT_START);
    return 0;
}

/* ---- Per-port parameter RAM + BD rings ------------------------------- */
static int fm_rx_param_init(uint32_t rx_pid)
{
    uint32_t page_off, qd;
    uint32_t i;

    rx_pram = muram_alloc((uint32_t)FM_PRAM_SIZE, (uint32_t)FM_PRAM_ALIGN);
    if (rx_pram == 0)
        return -1;
    page_off = rx_pram - (uint32_t)FMAN_MURAM_BASE;

    fman_wr32(rx_pram + PRAM_OFF_MODE, PRAM_MODE_GLOBAL);
    fman_wr32(rx_pram + PRAM_OFF_RXQD_PTR, page_off + (uint32_t)PRAM_OFF_RXQD);
    muram_writew(rx_pram + PRAM_OFF_MRBLR, MAX_RXBUF_LOG2);

    for (i = 0; i < RX_BD_RING_SIZE; i++) {
        rx_bd_ring[i].status = RxBD_EMPTY;
        rx_bd_ring[i].len = 0;
        rx_bd_ring[i].buf_ptr_hi = 0;
        rx_bd_ring[i].buf_ptr_lo = (uint32_t)(uintptr_t)&rx_buf_pool[i][0];
    }
    dcache_flush(rx_bd_ring, sizeof(rx_bd_ring));
    /* Clean+invalidate the RX buffers before the FMan DMA owns them, so a
     * later write-back of a dirty (e.g. BSS-zeroed) line cannot clobber a
     * DMA-written frame. */
    dcache_flush(rx_buf_pool, sizeof(rx_buf_pool));

    qd = rx_pram + (uint32_t)PRAM_OFF_RXQD;
    muram_writew(qd + QD_OFF_GEN, 0);
    muram_writew(qd + QD_OFF_BD_BASE_HI, 0);
    fman_wr32(qd + QD_OFF_BD_BASE_LO, (uint32_t)(uintptr_t)rx_bd_ring);
    muram_writew(qd + QD_OFF_BD_RING_SIZE,
                 (uint16_t)(sizeof(struct fm_bd) * RX_BD_RING_SIZE));
    muram_writew(qd + QD_OFF_OFFSET_IN, 0);
    muram_writew(qd + QD_OFF_OFFSET_OUT, 0);

    fman_wr32(FMAN_BMI_PORT(rx_pid) + BMI_RX_RFQID, page_off);
    rx_idx = 0;
    return 0;
}

static int fm_tx_param_init(uint32_t tx_pid)
{
    uint32_t page_off, qd;
    uint32_t i;

    tx_pram = muram_alloc((uint32_t)FM_PRAM_SIZE, (uint32_t)FM_PRAM_ALIGN);
    if (tx_pram == 0)
        return -1;
    page_off = tx_pram - (uint32_t)FMAN_MURAM_BASE;

    fman_wr32(tx_pram + PRAM_OFF_MODE, PRAM_MODE_GLOBAL);
    fman_wr32(tx_pram + PRAM_OFF_TXQD_PTR, page_off + (uint32_t)PRAM_OFF_TXQD);

    for (i = 0; i < TX_BD_RING_SIZE; i++) {
        tx_bd_ring[i].status = TxBD_LAST;
        tx_bd_ring[i].len = 0;
        tx_bd_ring[i].buf_ptr_hi = 0;
        tx_bd_ring[i].buf_ptr_lo = 0;
    }
    dcache_flush(tx_bd_ring, sizeof(tx_bd_ring));

    qd = tx_pram + (uint32_t)PRAM_OFF_TXQD;
    muram_writew(qd + QD_OFF_BD_BASE_HI, 0);
    fman_wr32(qd + QD_OFF_BD_BASE_LO, (uint32_t)(uintptr_t)tx_bd_ring);
    muram_writew(qd + QD_OFF_BD_RING_SIZE,
                 (uint16_t)(sizeof(struct fm_bd) * TX_BD_RING_SIZE));
    muram_writew(qd + QD_OFF_OFFSET_IN, 0);
    muram_writew(qd + QD_OFF_OFFSET_OUT, 0);

    fman_wr32(FMAN_BMI_PORT(tx_pid) + BMI_TX_TCFQID, page_off);
    tx_idx = 0;
    return 0;
}

/* ---- BMI ports (independent mode) ------------------------------------ */
static void bmi_rx_port_init(uint32_t rx_pid)
{
    uintptr_t b = FMAN_BMI_PORT(rx_pid);
    uint32_t v;

    fman_wr32(b + BMI_RX_RCFG, FMBM_RCFG_IM);
    fman_wr32(b + BMI_RX_RIM, 0);
    fman_wr32(b + BMI_RX_RFNE, NIA_ENG_RISC | NIA_RISC_AC_IM_RX);
    v = fman_rd32(b + BMI_RX_RFCA);
    v &= ~(FMBM_RFCA_ORDER | FMBM_RFCA_MR_MASK);
    v |= FMBM_RFCA_MR(4);
    fman_wr32(b + BMI_RX_RFCA, v);
    fman_wr32(b + BMI_RX_RSTC, FMBM_RSTC_EN);
    fman_wr32(b + BMI_RX_RPC, 0);
}

static void bmi_tx_port_init(uint32_t tx_pid)
{
    uintptr_t b = FMAN_BMI_PORT(tx_pid);
    uint32_t v;

    fman_wr32(b + BMI_TX_TCFG, FMBM_TCFG_IM);
    fman_wr32(b + BMI_TX_TFNE, NIA_ENG_RISC | NIA_RISC_AC_IM_TX);
    fman_wr32(b + BMI_TX_TFENE, NIA_ENG_RISC | NIA_RISC_AC_IM_TX);
    v = fman_rd32(b + BMI_TX_TFCA);
    v &= ~(FMBM_TFCA_ORDER | FMBM_TFCA_MR_MASK);
    v |= FMBM_TFCA_MR(4);
    fman_wr32(b + BMI_TX_TFCA, v);
    fman_wr32(b + BMI_TX_TSTC, FMBM_TSTC_EN);
    fman_wr32(b + BMI_TX_TPC, 0);
}

/* ---- mEMAC + SGMII PCS ----------------------------------------------- */
static void memac_init(uint32_t idx, const uint8_t *mac)
{
    uint32_t a0, a1;

    fman_wr32(FMAN_MEMAC_IMASK(idx), IMASK_MASK_ALL);
    fman_wr32(FMAN_MEMAC_IEVENT(idx), IEVENT_CLEAR_ALL);
    fman_wr32(FMAN_MEMAC_MAXFRMG(idx), MAX_RXBUF_LEN & MEMAC_MAXFRM_MASK);
    fman_wr32(FMAN_MEMAC_HTBLE_CTRL(idx), 0);

    /* MAC 0x..:..:CD -> ADDR_0=0x..3210, ADDR_1=0x0000..54 */
    a0 = ((uint32_t)mac[3] << 24) | ((uint32_t)mac[2] << 16) |
         ((uint32_t)mac[1] << 8) | (uint32_t)mac[0];
    a1 = (((uint32_t)mac[5] << 8) | (uint32_t)mac[4]) & 0x0000FFFFUL;
    fman_wr32(FMAN_MEMAC_MAC_ADDR_0(idx), a0);
    fman_wr32(FMAN_MEMAC_MAC_ADDR_1(idx), a1);
}

/* Select the mEMAC-to-PHY interface. SGMII drives the GMII pins behind the
 * internal PCS; RGMII selects the RGMII pins (IF_MODE_RG). Both follow the
 * link speed/duplex via in-band signalling (EN_AUTO). A board that needs a
 * fixed speed can clear EN_AUTO and set IF_MODE_SETSP_* instead. */
static void memac_set_interface(uint32_t idx)
{
    uint32_t v = fman_rd32(FMAN_MEMAC_IF_MODE(idx));
    v &= ~(IF_MODE_MASK | IF_MODE_RG | IF_MODE_RM);
    v |= IF_MODE_GMII | IF_MODE_EN_AUTO;
#if !NXP_FMAN_IF_SGMII
    v |= IF_MODE_RG;
#endif
    fman_wr32(FMAN_MEMAC_IF_MODE(idx), v);
}

#if NXP_FMAN_IF_SGMII
/* Program the internal SGMII PCS (TBI) for auto-negotiation. */
static void sgmii_configure_serdes(uint32_t idx)
{
    uintptr_t pcs = FMAN_MEMAC_MDIO_BASE(idx);
    mdio_setup(pcs);
    mdio_write_base(pcs, 0, 0x14,
                    PHY_SGMII_IF_MODE_AN | PHY_SGMII_IF_MODE_SGMII);
    mdio_write_base(pcs, 0, 0x04, PHY_SGMII_DEV_ABILITY_SGMII);
    mdio_write_base(pcs, 0, 0x13, 0x0003);
    mdio_write_base(pcs, 0, 0x12, 0x0D40);
    mdio_write_base(pcs, 0, 0x00,
                    PHY_SGMII_CR_DEF_VAL | PHY_SGMII_CR_RESET_AN);
}
#endif /* NXP_FMAN_IF_SGMII */

static void fm_port_enable(uint32_t rx_pid, uint32_t tx_pid, uint32_t idx)
{
    uintptr_t brx = FMAN_BMI_PORT(rx_pid);
    uintptr_t btx = FMAN_BMI_PORT(tx_pid);
    uint32_t v;

    v = fman_rd32(brx + BMI_RX_RCFG);
    fman_wr32(brx + BMI_RX_RCFG, v | FMBM_RCFG_EN);

    v = fman_rd32(FMAN_MEMAC_CMD_CFG(idx));
    fman_wr32(FMAN_MEMAC_CMD_CFG(idx),
              v | MEMAC_CMD_CFG_RXTX_EN | MEMAC_CMD_CFG_NO_LEN_CHK);

    v = fman_rd32(btx + BMI_TX_TCFG);
    fman_wr32(btx + BMI_TX_TCFG, v | FMBM_TCFG_EN);

    /* release TX from graceful stop */
    v = fman_rd32(tx_pram + PRAM_OFF_MODE);
    fman_wr32(tx_pram + PRAM_OFF_MODE, v & ~PRAM_MODE_GRACEFUL_STOP);
}

/* ---- wolfIP poll/send callbacks -------------------------------------- */
static int eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct fm_bd *bd = &tx_bd_ring[tx_idx];
    uint32_t qd = tx_pram + (uint32_t)PRAM_OFF_TXQD;
    uint16_t off_in, ring_sz;
    (void)dev;

    if (len == 0 || len > MAX_TXBUF_LEN)
        return -1;

    dcache_inval(bd, sizeof(*bd));
    if (bd->status & TxBD_READY)
        return -2; /* ring full */

    nxp_memcpy(tx_buf_pool[tx_idx], frame, len);
    if (len < 60U) {
        nxp_memset(tx_buf_pool[tx_idx] + len, 0, 60U - len);
        len = 60U;
    }
    dcache_flush(tx_buf_pool[tx_idx], len);

    bd->buf_ptr_hi = 0;
    bd->buf_ptr_lo = (uint32_t)(uintptr_t)tx_buf_pool[tx_idx];
    bd->len = (uint16_t)len;
    fman_sync();
    bd->status = TxBD_READY | TxBD_LAST;
    dcache_flush(bd, sizeof(*bd));

    /* doorbell: advance TxQD offset_in (kicks the RISC) */
    off_in = muram_readw(qd + QD_OFF_OFFSET_IN);
    ring_sz = muram_readw(qd + QD_OFF_BD_RING_SIZE);
    off_in += (uint16_t)sizeof(struct fm_bd);
    if (off_in >= ring_sz)
        off_in = 0;
    muram_writew(qd + QD_OFF_OFFSET_IN, off_in);
    fman_sync();

    tx_idx = (tx_idx + 1U) % TX_BD_RING_SIZE;
    return (int)len;
}

static int eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct fm_bd *bd = &rx_bd_ring[rx_idx];
    uint32_t qd = rx_pram + (uint32_t)PRAM_OFF_RXQD;
    uint16_t status, flen = 0, off_out, ring_sz;
    int err;
    (void)dev;

    dcache_inval(bd, sizeof(*bd));
    status = bd->status;
    if (status & RxBD_EMPTY)
        return 0;

    err = (status & RxBD_ERROR) ? 1 : 0;
    if (!err) {
        flen = bd->len;
        if (flen > MAX_RXBUF_LEN)
            flen = MAX_RXBUF_LEN;
        if (flen > len)
            flen = (uint16_t)len;
        if (flen > 0) {
            dcache_inval(rx_buf_pool[rx_idx], flen);
            nxp_memcpy(frame, rx_buf_pool[rx_idx], flen);
        }
    }

    /* recycle the BD */
    bd->status = RxBD_EMPTY;
    bd->len = 0;
    dcache_flush(bd, sizeof(*bd));

    off_out = muram_readw(qd + QD_OFF_OFFSET_OUT);
    ring_sz = muram_readw(qd + QD_OFF_BD_RING_SIZE);
    off_out += (uint16_t)sizeof(struct fm_bd);
    if (off_out >= ring_sz)
        off_out = 0;
    muram_writew(qd + QD_OFF_OFFSET_OUT, off_out);
    fman_sync();

    rx_idx = (rx_idx + 1U) % RX_BD_RING_SIZE;
    return err ? 0 : (int)flen;
}

/* ---- Public init ----------------------------------------------------- */
int nxp_fman_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    static const uint8_t default_mac[6] = {
        0x02, 0x11, 0x20, 0x80, 0x00, 0x01
    };
    uint32_t rx_pid, tx_pid, idx;
    uint16_t id1, bsr;

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

    idx = NXP_FMAN_MEMAC_IDX;
    rx_pid = FMAN_RX_PORT_ID(idx);
    tx_pid = FMAN_TX_PORT_ID(idx);

    /* Confirm the boot stage uploaded + enabled the FMan microcode. */
    FLOG("iready");
    if (!(fman_rd32(FMAN_IRAM_IREADY) & IRAM_READY))
        return -3;

    /* FMan common init (wolfBoot does not run this). */
    FLOG("muram");
    muram_init();
    FLOG("qmi");
    fm_init_qmi();
    FLOG("fpm");
    fm_init_fpm(rx_pid, tx_pid);
    FLOG("dma");
    fm_init_dma();
    FLOG("bmi-common");
    if (fm_init_bmi(rx_pid, tx_pid) != 0)
        return -4;

    /* Per-port parameter RAM, BD rings, BMI ports. */
    FLOG("rx-param");
    if (fm_rx_param_init(rx_pid) != 0)
        return -4;
    FLOG("tx-param");
    if (fm_tx_param_init(tx_pid) != 0)
        return -4;
    FLOG("memac");
    memac_init(idx, mac);
#if NXP_FMAN_IF_SGMII
    FLOG("sgmii");
    sgmii_configure_serdes(idx);
#endif
    memac_set_interface(idx);
    FLOG("bmi-ports");
    bmi_rx_port_init(rx_pid);
    bmi_tx_port_init(tx_pid);
    FLOG("enable");
    fm_port_enable(rx_pid, tx_pid, idx);
    FLOG("enabled");

    /* Bring up the external PHY over the dedicated MDIO. */
    mdio_setup(DEDICATED_MDIO_BASE);
    phy_addr = nxp_phy_detect(NXP_FMAN_PHY_ADDR);
    if (phy_addr < 0)
        return 0; /* datapath up, no PHY: link down; nxp_fman_phy_addr()==-1 */

    /* A hard PHY-init failure (reset stuck / MDIO error) is propagated; a
     * positive return (autoneg incomplete) is not fatal -- the live link
     * state is encoded in the status word below. */
    if (nxp_phy_init((uint32_t)phy_addr) < 0)
        return -5;
    id1 = mdio_read((uint32_t)phy_addr, PHY_ID1);
    bsr = mdio_read((uint32_t)phy_addr, PHY_BMSR);

    return (int)(((uint32_t)(id1 & 0xFF00U) << 8) |
                 ((bsr & BMSR_LINK) ? 0x100U : 0U) |
                 ((uint32_t)phy_addr & 0xFFU));
}

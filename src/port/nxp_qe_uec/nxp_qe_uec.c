/* nxp_qe_uec.c
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
 * NXP QUICC Engine UCC ethernet (UEC-GETH) driver for wolfIP.
 *
 * Brings up one UCC fast controller in polled mode: clock routing, UCC fast
 * init (GUMR/VFIFOs), MAC config + MDIO/PHY, parameter RAM in QE MURAM, BD
 * rings in DRAM, the INIT_TX_RX command, and the polled poll/send datapath.
 * The QE microcode is uploaded by the boot stage (wolfBoot hal_qe_init).
 * Ported from the U-Boot QE UEC driver (drivers/qe/uec.c). e500v2, BE.
 *
 * Several items are board/silicon specific and must be verified on hardware
 * (flagged inline): the CMXUCRn per-UCC clock-route field layout, the
 * assign-page requirement, and the PHY interface/address.
 */

#include <stdint.h>
#include <stddef.h>
#include "config.h"
#include "nxp_qe_uec.h"

/* Byte-loop mem helpers (nxp_memcpy/nxp_memset); no libc in bare-metal. */
#include "../common/nxp_mem.h"

/* ---- Big-endian register access (sync/twi/isync like wolfBoot) ------- */
#if defined(__powerpc__) || defined(__PPC__) || defined(__ppc__)
static inline uint32_t qe_rd32(uintptr_t a)
{
    uint32_t r;
    __asm__ __volatile__("sync;\n" "lwz %0,0(%1);\n" "twi 0,%0,0;\n" "isync"
                         : "=r"(r) : "r"(a) : "memory");
    return r;
}
static inline void qe_wr32(uintptr_t a, uint32_t v)
{
    __asm__ __volatile__("sync;\n" "stw %0,0(%1)" : : "r"(v), "r"(a) : "memory");
}
static inline void qe_wr16(uintptr_t a, uint16_t v)
{
    __asm__ __volatile__("sync" ::: "memory");
    *(volatile uint16_t *)a = v;
}
static inline void qe_wr8(uintptr_t a, uint8_t v)
{
    __asm__ __volatile__("sync" ::: "memory");
    *(volatile uint8_t *)a = v;
}
static inline void qe_sync(void)
{
    __asm__ __volatile__("sync" ::: "memory");
}
/* e500v2 data cache line = 32 bytes. dcbf (flush+invalidate) for both
 * directions; BMR_GLB also enables QE snooping of the CSB. */
static void dcache_flush(const void *p, uint32_t len)
{
    uintptr_t a = (uintptr_t)p & ~31UL;
    uintptr_t end = (uintptr_t)p + len;
    for (; a < end; a += 32)
        __asm__ __volatile__("dcbf 0,%0" : : "r"(a) : "memory");
    qe_sync();
}
#else
/* Portable fallbacks for host syntax checks. */
static inline uint32_t qe_rd32(uintptr_t a) { return *(volatile uint32_t *)a; }
static inline void qe_wr32(uintptr_t a, uint32_t v) { *(volatile uint32_t *)a = v; }
static inline void qe_wr16(uintptr_t a, uint16_t v) { *(volatile uint16_t *)a = v; }
static inline void qe_wr8(uintptr_t a, uint8_t v) { *(volatile uint8_t *)a = v; }
static inline void qe_sync(void) { }
static void dcache_flush(const void *p, uint32_t len) { (void)p; (void)len; }
#endif

#define dcache_inval(p, l) dcache_flush((p), (l))

/* Optional debug log hook. */
static void (*g_log)(const char *) = 0;
void nxp_qe_uec_set_log(void (*log_fn)(const char *)) { g_log = log_fn; }
#define QLOG(s) do { if (g_log) g_log(s); } while (0)

/* ---- Driver state ---------------------------------------------------- */
static uintptr_t ucc_base;   /* UCC fast register block */
static uintptr_t mac_base;   /* UEC MAC block (ucc_base + 0x100) */
static uint32_t  tx_glbl_off; /* MURAM offsets */
static uint32_t  tx_pram_off;
static uint32_t  rx_idx;
static uint32_t  tx_idx;
static int32_t   phy_addr = -1;

#define MURAM_ADDR(off)         (QE_MURAM_BASE + (uintptr_t)(off))

static struct qe_bd rx_bd_ring[QE_RX_RING_SIZE]
    __attribute__((aligned(QE_BD_RING_ALIGN)));
static struct qe_bd tx_bd_ring[QE_TX_RING_SIZE]
    __attribute__((aligned(QE_BD_RING_ALIGN)));
static uint8_t rx_buf_pool[QE_RX_RING_SIZE][QE_MRBLR]
    __attribute__((aligned(QE_BUF_ALIGN)));
static uint8_t tx_buf_pool[QE_TX_RING_SIZE][QE_MRBLR]
    __attribute__((aligned(QE_BUF_ALIGN)));

/* ---- MURAM bump allocator -------------------------------------------- */
static uint32_t muram_ptr;

static void muram_init(void)
{
    muram_ptr = (uint32_t)QE_MURAM_RES;
}

static uint32_t muram_alloc(uint32_t size, uint32_t align)
{
    uint32_t off, a;
    off = (muram_ptr + (align - 1U)) & ~(align - 1U);
    if (off + size > (uint32_t)QE_MURAM_SIZE)
        return 0xFFFFFFFFUL;
    muram_ptr = off + size;
    for (a = 0; a < size; a += 4U)
        qe_wr32(MURAM_ADDR(off + a), 0);
    return off;
}

/* ---- QE command register --------------------------------------------- */
static int qe_issue_cmd(uint32_t cmd, uint32_t sbc, uint8_t mcn,
        uint32_t cmd_data)
{
    uint32_t t = QE_POLL_TRIES;

    if (cmd == QE_RESET) {
        qe_wr32(QE_CECR, cmd | QE_CR_FLG);
    }
    else {
        qe_wr32(QE_CECDR, cmd_data);
        qe_wr32(QE_CECR, sbc | QE_CR_FLG |
                ((uint32_t)mcn << QE_CR_PROTOCOL_SHIFT) | cmd);
    }
    while ((qe_rd32(QE_CECR) & QE_CR_FLG) && --t) {
    }
    return t ? 0 : -1;
}

/* Assign a MURAM page to a serial number. U-Boot's qe_init does this for
 * every snum; wolfBoot reset the engine but did not, so replicate it for the
 * snums we use. VERIFY: exact CECDR page encoding on the target silicon. */
static int qe_assign_page(uint32_t snum)
{
    uint32_t t = QE_POLL_TRIES;
    qe_wr32(QE_CECDR, 0);
    qe_wr32(QE_CECR, QE_ASSIGN_PAGE | QE_CR_FLG |
            (snum << QE_CR_ASSIGN_PAGE_SNUM_SHIFT));
    while ((qe_rd32(QE_CECR) & QE_CR_FLG) && --t) {
    }
    return t ? 0 : -1;
}

/* ---- MDIO clause-22 (UEC MAC MII block) ------------------------------ */
/* Shared clause-22 PHY register map + bring-up (nxp_phy_detect/nxp_phy_init).
 * Forward-declare the MDIO accessors (defined below) so the shared helpers can
 * reach them via the NXP_MDIO_READ/WRITE macros. */
static uint16_t mdio_read(uint32_t phy, uint32_t reg);
static int mdio_write(uint32_t phy, uint32_t reg, uint16_t val);
#define NXP_MDIO_READ  mdio_read
#define NXP_MDIO_WRITE mdio_write
#define NXP_PHY_HELPERS
#include "../common/nxp_phy.h"

static void mii_init(void)
{
    uint32_t t = MDIO_TIMEOUT;
    qe_wr32(mac_base + UEC_MIIMCFG, MIIMCFG_RESET_MGMT);
    qe_wr32(mac_base + UEC_MIIMCFG, MIIMCFG_CLK_DIV10);
    while ((qe_rd32(mac_base + UEC_MIIMIND) & MIIMIND_BUSY) && --t) {
    }
}

static uint16_t mdio_read(uint32_t phy, uint32_t reg)
{
    uint32_t t = MDIO_TIMEOUT;
    qe_wr32(mac_base + UEC_MIIMADD,
            ((phy & 0x1FU) << MIIMADD_PHY_SHIFT) | (reg & 0x1FU));
    qe_wr32(mac_base + UEC_MIIMCOM, 0);
    qe_sync();
    qe_wr32(mac_base + UEC_MIIMCOM, MIIMCOM_READ_CYCLE);
    while ((qe_rd32(mac_base + UEC_MIIMIND) &
            (MIIMIND_NOTVALID | MIIMIND_BUSY)) && --t) {
    }
    qe_wr32(mac_base + UEC_MIIMCOM, 0);
    if (t == 0)
        return 0xFFFFU;
    return (uint16_t)(qe_rd32(mac_base + UEC_MIIMSTAT) & 0xFFFFU);
}

static int mdio_write(uint32_t phy, uint32_t reg, uint16_t val)
{
    uint32_t t = MDIO_TIMEOUT;
    qe_wr32(mac_base + UEC_MIIMCOM, 0);
    qe_wr32(mac_base + UEC_MIIMADD,
            ((phy & 0x1FU) << MIIMADD_PHY_SHIFT) | (reg & 0x1FU));
    qe_wr32(mac_base + UEC_MIIMCON, (uint32_t)val);
    qe_sync();
    while ((qe_rd32(mac_base + UEC_MIIMIND) & MIIMIND_BUSY) && --t) {
    }
    return t ? 0 : -1;
}

/* ---- PHY discovery / link -------------------------------------------- */
int nxp_qe_uec_phy_addr(void) { return (int)phy_addr; }

uint16_t nxp_qe_uec_phy_read(uint8_t reg)
{
    if (phy_addr < 0)
        return 0xFFFFU;
    return mdio_read((uint32_t)phy_addr, reg);
}

uint32_t nxp_qe_uec_link_up(void)
{
    uint16_t bsr;
    if (phy_addr < 0)
        return 0;
    bsr = mdio_read((uint32_t)phy_addr, PHY_BMSR);
    bsr = mdio_read((uint32_t)phy_addr, PHY_BMSR);
    return (bsr & BMSR_LINK) ? 1U : 0U;
}

/* ---- Clock routing --------------------------------------------------- */
/* Route the MII management clock to this UCC and set the UCC RX/TX clock
 * source. VERIFY: the CMXUCRn per-UCC 4-bit RX/TX clock field layout is not
 * in the U-Boot sources used; consult the P1021 RM "QE Multiplexing". The
 * MII-management routing (CMXGCR) is well defined. */
static void qe_clock_route(uint32_t ucc_num)
{
    uint32_t v = qe_rd32(QE_CMXGCR);
    v &= ~QE_CMXGCR_MII_ENET_MNG_MASK;
    v |= (ucc_num << QE_CMXGCR_MII_ENET_MNG_SHIFT) &
         QE_CMXGCR_MII_ENET_MNG_MASK;
    qe_wr32(QE_CMXGCR, v);
}

/* ---- UCC fast + MAC bring-up ----------------------------------------- */
static int uccf_init(uint32_t speed)
{
    uint32_t rx_vfifo, tx_vfifo;
    uint16_t urfs, urfet, urfset, utfs, utfet, utftt;

    qe_wr8(ucc_base + UCCF_GUEMR, UCC_GUEMR_INIT);
    qe_wr32(ucc_base + UCCF_GUMR, UCC_GUMR_ETH);

    if (speed >= 1000U) {
        urfs = 4096; urfet = 2048; urfset = 3072;
        utfs = 8192; utfet = 4096; utftt = 0x400;
    }
    else {
        urfs = 512; urfet = 256; urfset = 384;
        utfs = 512; utfet = 256; utftt = 128;
    }
    rx_vfifo = muram_alloc((uint32_t)urfs + 8U, 8U);
    tx_vfifo = muram_alloc((uint32_t)utfs, 8U);
    if (rx_vfifo == 0xFFFFFFFFUL || tx_vfifo == 0xFFFFFFFFUL)
        return -1;              /* out of MURAM; propagate to the caller */

    qe_wr32(ucc_base + UCCF_URFB, rx_vfifo);
    qe_wr16(ucc_base + UCCF_URFS, urfs);
    qe_wr16(ucc_base + UCCF_URFET, urfet);
    qe_wr16(ucc_base + UCCF_URFSET, urfset);
    qe_wr32(ucc_base + UCCF_UTFB, tx_vfifo);
    qe_wr16(ucc_base + UCCF_UTFS, utfs);
    qe_wr16(ucc_base + UCCF_UTFET, utfet);
    qe_wr16(ucc_base + UCCF_UTFTT, utftt);

    qe_wr32(ucc_base + UCCF_UCCM, 0);            /* polled: mask all */
    qe_wr32(ucc_base + UCCF_UCCE, 0xFFFFFFFFUL); /* clear events (W1C) */
    return 0;
}

static void mac_init(const uint8_t *mac, uint32_t speed)
{
    uint32_t cfg2, upsmr;
    uint32_t a1, a2;

    qe_wr32(mac_base + UEC_MACCFG1, 0);
    cfg2 = MACCFG2_INIT_VALUE;
    upsmr = UPSMR_INIT_VALUE;

    cfg2 &= ~MACCFG2_IF_MODE_MASK;
    cfg2 |= (speed >= 1000U) ? MACCFG2_BYTE : MACCFG2_NIBBLE;

#if (NXP_QE_IF_MODE == 2)        /* RGMII */
    upsmr |= UPSMR_RPM;
    if (speed < 100U)
        upsmr |= UPSMR_R10M;
#elif (NXP_QE_IF_MODE == 1)      /* RMII */
    upsmr |= UPSMR_RMM;
    if (speed < 100U)
        upsmr |= UPSMR_R10M;
#endif                           /* else MII: no extra UPSMR bits */

    qe_wr32(mac_base + UEC_MACCFG2, cfg2);
    qe_wr32(ucc_base + UCCF_UPSMR, upsmr);

    /* Station address: MACSTNADDR1 = mac[5..2], MACSTNADDR2 = mac[1..0]. */
    a1 = ((uint32_t)mac[5] << 24) | ((uint32_t)mac[4] << 16) |
         ((uint32_t)mac[3] << 8) | (uint32_t)mac[2];
    a2 = ((uint32_t)mac[1] << 24) | ((uint32_t)mac[0] << 16);
    qe_wr32(mac_base + UEC_MACSTNADDR1, a1);
    qe_wr32(mac_base + UEC_MACSTNADDR2, a2);
}

/* ---- Parameter RAM + BD rings ---------------------------------------- */
static int build_param_ram(void)
{
    uint32_t sq, tx_data, rx_glbl, rx_data, rbdq, rx_thr, init;
    uint64_t txbd = (uint64_t)(uintptr_t)tx_bd_ring;
    uint64_t rxbd = (uint64_t)(uintptr_t)rx_bd_ring;
    uint32_t i;

    tx_glbl_off = muram_alloc((uint32_t)TXG_SIZE, 64U);
    sq          = muram_alloc((uint32_t)SQQD_SIZE, 32U);
    /* TX thread data: num_tx*136 (+32 pad when num_tx==1). */
    tx_data     = muram_alloc((uint32_t)UEC_THREAD_DATA_TX_SIZE + 32U, 256U);
    tx_pram_off = muram_alloc((uint32_t)UEC_THREAD_TX_PRAM_SIZE, 64U);
    rx_glbl     = muram_alloc((uint32_t)RXG_SIZE, 64U);
    rx_data     = muram_alloc((uint32_t)UEC_THREAD_DATA_RX_SIZE, 256U);
    rbdq        = muram_alloc((uint32_t)RBDQ_SIZE, 8U);
    rx_thr      = muram_alloc((uint32_t)UEC_THREAD_RX_PRAM_SIZE, 128U);
    init        = muram_alloc((uint32_t)INIT_SIZE, 4U);

    if (tx_glbl_off == 0xFFFFFFFFUL || sq == 0xFFFFFFFFUL ||
        tx_data == 0xFFFFFFFFUL ||
        tx_pram_off == 0xFFFFFFFFUL || rx_glbl == 0xFFFFFFFFUL ||
        rx_data == 0xFFFFFFFFUL || rbdq == 0xFFFFFFFFUL ||
        rx_thr == 0xFFFFFFFFUL || init == 0xFFFFFFFFUL)
        return -1;

    /* TX global param RAM. */
    qe_wr16(MURAM_ADDR(tx_glbl_off) + TXG_TEMODER, TEMODER_INIT_VALUE);
    qe_wr32(MURAM_ADDR(tx_glbl_off) + TXG_SQPTR, sq);
    qe_wr32(MURAM_ADDR(sq) + SQQD_BD_RING_BASE, (uint32_t)(txbd & 0xFFFFFFFFUL));
    qe_wr32(MURAM_ADDR(sq) + SQQD_LAST_BD,
            (uint32_t)((txbd + (uint64_t)(QE_TX_RING_SIZE - 1U) * QE_SIZEOFBD)
                       & 0xFFFFFFFFUL));
    qe_wr32(MURAM_ADDR(tx_glbl_off) + TXG_TSTATE, UEC_TSTATE_INIT);
    qe_wr32(MURAM_ADDR(tx_glbl_off) + TXG_TQPTR, tx_data);

    /* RX global param RAM. */
    qe_wr32(MURAM_ADDR(rx_glbl) + RXG_REMODER, 0);
    qe_wr32(MURAM_ADDR(rx_glbl) + RXG_RQPTR, rx_data);
    qe_wr16(MURAM_ADDR(rx_glbl) + RXG_TYPEORLEN, 3072);
    qe_wr8(MURAM_ADDR(rx_glbl) + RXG_RSTATE, UEC_RSTATE_INIT);
    qe_wr16(MURAM_ADDR(rx_glbl) + RXG_MRBLR, QE_MRBLR);
    qe_wr32(MURAM_ADDR(rx_glbl) + RXG_RBDQPTR, rbdq);
    qe_wr32(MURAM_ADDR(rbdq) + RBDQ_EXT_BD_BASE,
            (uint32_t)(rxbd & 0xFFFFFFFFUL));
    qe_wr16(MURAM_ADDR(rx_glbl) + RXG_MFLR, QE_MAX_FRAME_LEN);
    qe_wr16(MURAM_ADDR(rx_glbl) + RXG_MINFLR, 64);
    qe_wr16(MURAM_ADDR(rx_glbl) + RXG_MAXD1, 1520);
    qe_wr16(MURAM_ADDR(rx_glbl) + RXG_MAXD2, 1520);
    qe_wr16(MURAM_ADDR(rx_glbl) + RXG_VLANTYPE, 0x8100);

    /* init-enet command block. */
    qe_wr8(MURAM_ADDR(init) + INIT_RES0 + 0, 0x06);
    qe_wr8(MURAM_ADDR(init) + INIT_RES0 + 1, 0x30);
    qe_wr8(MURAM_ADDR(init) + INIT_RES0 + 2, 0xFF);
    qe_wr8(MURAM_ADDR(init) + INIT_RES0 + 3, 0x00);
    qe_wr16(MURAM_ADDR(init) + INIT_RES4, 0x0400);
    qe_wr32(MURAM_ADDR(init) + INIT_RGF_TGF_RXG,
            (1UL << ENET_INIT_RGF_SHIFT) | (1UL << ENET_INIT_TGF_SHIFT) |
            rx_glbl | QE_RISC_RISC1);
    /* RX thread table: num_rx+1 entries (entry 0 uses offset 0). */
    qe_wr32(MURAM_ADDR(init) + INIT_RXTHREAD + 0,
            ((uint32_t)NXP_QE_SNUM_RX << ENET_INIT_SNUM_SHIFT) | QE_RISC_RISC1);
    qe_wr32(MURAM_ADDR(init) + INIT_RXTHREAD + 4,
            ((uint32_t)NXP_QE_SNUM_RX2 << ENET_INIT_SNUM_SHIFT) | rx_thr |
            QE_RISC_RISC1);
    qe_wr32(MURAM_ADDR(init) + INIT_TXGLOBAL, tx_glbl_off | QE_RISC_RISC1);
    qe_wr32(MURAM_ADDR(init) + INIT_TXTHREAD + 0,
            ((uint32_t)NXP_QE_SNUM_TX << ENET_INIT_SNUM_SHIFT) | tx_pram_off |
            QE_RISC_RISC1);

    /* BD rings in DRAM. */
    for (i = 0; i < QE_TX_RING_SIZE; i++) {
        tx_bd_ring[i].status = 0;
        tx_bd_ring[i].len = 0;
        tx_bd_ring[i].data = 0;
    }
    tx_bd_ring[QE_TX_RING_SIZE - 1].status = BD_WRAP;
    for (i = 0; i < QE_RX_RING_SIZE; i++) {
        rx_bd_ring[i].status = RxBD_EMPTY;
        rx_bd_ring[i].len = 0;
        rx_bd_ring[i].data = (uint32_t)(uintptr_t)&rx_buf_pool[i][0];
    }
    rx_bd_ring[QE_RX_RING_SIZE - 1].status = BD_WRAP | RxBD_EMPTY;
    dcache_flush(tx_bd_ring, sizeof(tx_bd_ring));
    dcache_flush(rx_bd_ring, sizeof(rx_bd_ring));
    /* Clean+invalidate the RX buffers before the QE DMA owns them so a later
     * write-back of a dirty line cannot clobber a DMA-written frame. */
    dcache_flush(rx_buf_pool, sizeof(rx_buf_pool));

    qe_sync();
    return qe_issue_cmd(QE_INIT_TX_RX, QE_CR_SUBBLOCK_UCCFAST(NXP_QE_UCC_NUM),
                        (uint8_t)QE_CR_PROTOCOL_ETHERNET, init);
}

/* ---- wolfIP poll/send callbacks -------------------------------------- */
static int eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct qe_bd *bd = &tx_bd_ring[tx_idx];
    uint16_t wrap;
    (void)dev;

    if (len == 0 || len > QE_MRBLR)
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

    wrap = bd->status & BD_WRAP;
    bd->data = (uint32_t)(uintptr_t)tx_buf_pool[tx_idx];
    bd->len = (uint16_t)len;
    qe_sync();
    bd->status = wrap | TxBD_READY | BD_LAST | TxBD_PADCRC | TxBD_TXCRC;
    dcache_flush(bd, sizeof(*bd));

    qe_wr16(ucc_base + UCCF_UTODR, UCC_FAST_TOD); /* transmit on demand */
    qe_sync();

    tx_idx = (tx_idx + 1U) % QE_TX_RING_SIZE;
    return (int)len;
}

static int eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct qe_bd *bd = &rx_bd_ring[rx_idx];
    uint16_t status, wrap, flen = 0;
    int err;
    (void)dev;

    dcache_inval(bd, sizeof(*bd));
    status = bd->status;
    if (status & RxBD_EMPTY)
        return 0;

    err = (status & RxBD_ERROR) ? 1 : 0;
    if (!err) {
        flen = bd->len;
        if (flen > QE_MRBLR)
            flen = QE_MRBLR;
        if (flen > len)
            flen = (uint16_t)len;
        if (flen > 0) {
            dcache_inval(rx_buf_pool[rx_idx], flen);
            nxp_memcpy(frame, rx_buf_pool[rx_idx], flen);
        }
    }

    wrap = status & BD_WRAP;
    bd->len = 0;
    qe_sync();
    bd->status = wrap | RxBD_EMPTY;
    dcache_flush(bd, sizeof(*bd));

    rx_idx = (rx_idx + 1U) % QE_RX_RING_SIZE;
    return err ? 0 : (int)flen;
}

/* ---- Public init ----------------------------------------------------- */
int nxp_qe_uec_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    static const uint8_t default_mac[6] = {
        0x02, 0x11, 0x20, 0x10, 0x21, 0x01
    };
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

    ucc_base = QE_UCC_BASE(NXP_QE_UCC_NUM);
    mac_base = ucc_base + UEC_MAC_OFFSET;

    /* Confirm the boot stage uploaded + enabled the QE microcode. */
    QLOG("iready");
    if (!(qe_rd32(QE_IRAM_IREADY) & QE_IRAM_READY))
        return -3;

    QLOG("muram");
    muram_init();
    QLOG("snum");
    if (qe_assign_page(NXP_QE_SNUM_RX) != 0 ||
        qe_assign_page(NXP_QE_SNUM_RX2) != 0 ||
        qe_assign_page(NXP_QE_SNUM_TX) != 0)
        return -5; /* QE command processor wedged */

    QLOG("clk");
    qe_clock_route(NXP_QE_UCC_NUM);

    QLOG("uccf");
    if (uccf_init(NXP_QE_SPEED) != 0)
        return -4;              /* out of MURAM */
    QLOG("mac");
    mac_init(mac, NXP_QE_SPEED);

    /* Allocate MURAM, fill the TX/RX global param RAM + init-enet block,
     * set up the BD rings, and issue INIT_TX_RX. */
    QLOG("param");
    if (build_param_ram() != 0)
        return -4;

    /* Enable MAC + UCC, then kick the RISC threads. */
    QLOG("enable");
    qe_wr32(mac_base + UEC_MACCFG1,
            qe_rd32(mac_base + UEC_MACCFG1) |
            MACCFG1_ENABLE_RX | MACCFG1_ENABLE_TX);
    qe_wr32(ucc_base + UCCF_GUMR,
            qe_rd32(ucc_base + UCCF_GUMR) | UCC_GUMR_ENT | UCC_GUMR_ENR);
    if (qe_issue_cmd(QE_RESTART_TX, QE_CR_SUBBLOCK_UCCFAST(NXP_QE_UCC_NUM),
                     (uint8_t)QE_CR_PROTOCOL_ETHERNET, 0) != 0 ||
        qe_issue_cmd(QE_RESTART_RX, QE_CR_SUBBLOCK_UCCFAST(NXP_QE_UCC_NUM),
                     (uint8_t)QE_CR_PROTOCOL_ETHERNET, 0) != 0)
        return -6; /* RESTART_TX/RX command timed out */

    /* Bring up the external PHY. */
    QLOG("phy");
    mii_init();
    phy_addr = nxp_phy_detect(NXP_QE_PHY_ADDR);
    if (phy_addr < 0)
        return 0; /* datapath up, no PHY: link down; nxp_qe_uec_phy_addr()==-1 */
    if (nxp_phy_init((uint32_t)phy_addr) < 0)
        return -5; /* hard PHY-init failure */
    id1 = mdio_read((uint32_t)phy_addr, PHY_ID1);
    bsr = mdio_read((uint32_t)phy_addr, PHY_BMSR);

    return (int)(((uint32_t)(id1 & 0xFF00U) << 8) |
                 ((bsr & BMSR_LINK) ? 0x100U : 0U) |
                 ((uint32_t)phy_addr & 0xFFU));
}

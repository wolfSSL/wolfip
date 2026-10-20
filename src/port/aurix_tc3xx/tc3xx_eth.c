/* tc3xx_eth.c
 *
 * Infineon AURIX TC3xx GETH (RMII) driver for wolfIP, on top of the iLLD.
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
#include <stddef.h>
#include <string.h>

#include "Ifx_Types.h"
#include "IfxCpu.h"
#include "IfxGeth_Eth.h"
#include "IfxScuCcu.h"
#include "IfxSrc.h"
#include "IfxStm.h"

#include "config.h"
#include "tc3xx_eth.h"
#include "tc3xx_eth_board.h"

/* iLLD programs the ring length from these, so they are not a free choice. */
#define TC3XX_ETH_RX_DESC   ((uint32_t)IFXGETH_MAX_RX_DESCRIPTORS)
#define TC3XX_ETH_TX_DESC   ((uint32_t)IFXGETH_MAX_TX_DESCRIPTORS)
#define TC3XX_ETH_BUF_SIZE  1536u
#define TC3XX_ETH_FCS_LEN   4u

#define TC3XX_ETH_MDIO_POLLS  100000u
#define TC3XX_ETH_LINK_POLL_MS  10u
#define TC3XX_ETH_REFCLK_TIMEOUT_MS  100u

#ifndef TC3XX_ETH_RING_ATTR
#define TC3XX_ETH_RING_ATTR
#endif

#ifndef TC3XX_ETH_DELAY_MS
#define TC3XX_ETH_DELAY_MS(ms) \
    IfxStm_waitTicks(&MODULE_STM0, \
                     IfxStm_getTicksFromMilliseconds(&MODULE_STM0, (ms)))
#endif

#if TC3XX_ETH_BUF_SIZE < LINK_MTU
#error "LINK_MTU exceeds the GETH buffer size"
#endif

static IFX_ALIGN(8) IfxGeth_TxDescr s_tx_desc[TC3XX_ETH_TX_DESC]
    TC3XX_ETH_RING_ATTR;
static IFX_ALIGN(8) IfxGeth_RxDescr s_rx_desc[TC3XX_ETH_RX_DESC]
    TC3XX_ETH_RING_ATTR;
static IFX_ALIGN(8) uint8 s_tx_buf[TC3XX_ETH_TX_DESC][TC3XX_ETH_BUF_SIZE]
    TC3XX_ETH_RING_ATTR;
static IFX_ALIGN(8) uint8 s_rx_buf[TC3XX_ETH_RX_DESC][TC3XX_ETH_BUF_SIZE]
    TC3XX_ETH_RING_ATTR;

static IfxGeth_Eth s_geth;
static int         s_mdio_ready;
static int         s_started;
static int         s_phy_addr = -1;
static int         s_mac_speed_100 = -1;
static int         s_mac_full_duplex;
static uint32      s_tx_next;

static volatile uint32_t s_rx_frames;
static volatile uint32_t s_tx_frames;
static volatile uint32_t s_rx_dropped;

#define TC3XX_ETH_LOCK(state)    ((state) = IfxCpu_disableInterrupts())
#define TC3XX_ETH_UNLOCK(state)  IfxCpu_restoreInterrupts(state)

static const IfxGeth_Eth_RmiiPins s_rmii_pins = {
    .crsDiv = (IfxGeth_Crsdv_In *)&TC3XX_ETH_PIN_CRSDV,
    .refClk = (IfxGeth_Refclk_In *)&TC3XX_ETH_PIN_REFCLK,
    .rxd0   = (IfxGeth_Rxd_In *)&TC3XX_ETH_PIN_RXD0,
    .rxd1   = (IfxGeth_Rxd_In *)&TC3XX_ETH_PIN_RXD1,
    .mdio   = (IfxGeth_Mdio_InOut *)&TC3XX_ETH_PIN_MDIO,
    .txd0   = (IfxGeth_Txd_Out *)&TC3XX_ETH_PIN_TXD0,
    .mdc    = (IfxGeth_Mdc_Out *)&TC3XX_ETH_PIN_MDC,
    .txd1   = (IfxGeth_Txd_Out *)&TC3XX_ETH_PIN_TXD1,
    .txEn   = (IfxGeth_Txen_Out *)&TC3XX_ETH_PIN_TXEN,
};

static int mdio_wait_idle(void)
{
    uint32_t spins;

    for (spins = TC3XX_ETH_MDIO_POLLS; spins != 0u; --spins) {
        if (TC3XX_ETH_MODULE.MAC_MDIO_ADDRESS.B.GB == 0u) {
            return TC3XX_ETH_OK;
        }
    }
    return TC3XX_ETH_EIO;
}

/* MAC_MDIO_ADDRESS.CR keeping MDC under 2.5 MHz, or -1 when none fits.
 * CR 0..5 divide by 42, 62, 16, 26, 102 and 124. */
static int mdio_cr(uint32_t hz)
{
    if (hz == 0u || hz > 300000000u) {
        return -1;
    }
    if (hz < 35000000u) {
        return 2;
    }
    if (hz < 60000000u) {
        return 3;
    }
    if (hz < 100000000u) {
        return 0;
    }
    if (hz < 150000000u) {
        return 1;
    }
    if (hz < 250000000u) {
        return 4;
    }
    return 5;
}

/* goc: 3 = read, 1 = write. */
static int mdio_transact(uint8_t phy_addr, uint8_t reg, uint32 goc)
{
    Ifx_GETH_MAC_MDIO_ADDRESS addr;
    float32                   f = IfxScuCcu_getGethFrequency();
    int                       cr = -1;

    /* The iLLD's helpers hardcode the 60-100 MHz range. The negated test also
     * catches the inf or NaN of a stopped GETH clock before the conversion. */
    if (f > 0.0f && f <= 300000000.0f) {
        cr = mdio_cr((uint32_t)f);
    }
    if (cr < 0 || mdio_wait_idle() != TC3XX_ETH_OK) {
        return TC3XX_ETH_EIO;
    }

    addr.U       = 0u;
    addr.B.PA    = phy_addr;
    addr.B.RDA   = reg;
    addr.B.CR    = (uint32)cr;
    addr.B.GOC_0 = goc & 1u;
    addr.B.GOC_1 = (goc >> 1) & 1u;
    addr.B.GB    = 1u;
    TC3XX_ETH_MODULE.MAC_MDIO_ADDRESS.U = addr.U;
    __dsync();

    return mdio_wait_idle();
}

int tc3xx_eth_mdio_read(uint8_t phy_addr, uint8_t reg, uint16_t *value)
{
    int rc;

    if (!s_mdio_ready || value == NULL || phy_addr > 31u || reg > 31u) {
        return TC3XX_ETH_EINVAL;
    }
    rc = mdio_transact(phy_addr, reg, 3u);
    if (rc == TC3XX_ETH_OK) {
        *value = (uint16_t)TC3XX_ETH_MODULE.MAC_MDIO_DATA.B.GD;
    }
    return rc;
}

int tc3xx_eth_mdio_write(uint8_t phy_addr, uint8_t reg, uint16_t value)
{
    if (!s_mdio_ready || phy_addr > 31u || reg > 31u) {
        return TC3XX_ETH_EINVAL;
    }
    if (mdio_wait_idle() != TC3XX_ETH_OK) {
        return TC3XX_ETH_EIO;
    }
    TC3XX_ETH_MODULE.MAC_MDIO_DATA.U = (uint32)value;
    return mdio_transact(phy_addr, reg, 1u);
}

#define AURIX_MDIO_READ   tc3xx_eth_mdio_read
#define AURIX_MDIO_WRITE  tc3xx_eth_mdio_write
#define AURIX_DELAY_MS    TC3XX_ETH_DELAY_MS
#include "../common/aurix_phy.h"

/* The DMA reset needs the RMII clock the PHY drives, so a SWR bit that never
 * clears means no reference clock; iLLD's initModule would hang on it. */
static int refclk_present(void)
{
    uint32_t waited;

    IfxGeth_dma_applySoftwareReset(&TC3XX_ETH_MODULE);
    for (waited = 0u; waited < TC3XX_ETH_REFCLK_TIMEOUT_MS; waited++) {
        if (TC3XX_ETH_MODULE.DMA_MODE.B.SWR == 0u) {
            return 1;
        }
        TC3XX_ETH_DELAY_MS(1u);
    }
    return 0;
}

static void mac_init(const uint8_t *mac)
{
    IfxGeth_Eth_Config cfg;

    /* iLLD's descriptor init leaves TDES3 alone, so a residual OWN bit from
     * before a warm reset would fail every send. */
    memset((void *)s_tx_desc, 0, sizeof(s_tx_desc));
    memset((void *)s_rx_desc, 0, sizeof(s_rx_desc));
    s_tx_next = 0u;
    /* initModule puts the MAC back to its default mode. */
    s_mac_speed_100 = -1;

    IfxGeth_Eth_initModuleConfig(&cfg, &TC3XX_ETH_MODULE);
    cfg.phyInterfaceMode = IfxGeth_PhyInterfaceMode_rmii;
    cfg.pins.rmiiPins    = &s_rmii_pins;
    memcpy(cfg.mac.macAddress, mac, 6);

    /* 4 KiB per queue, in 256-byte units minus one. */
    cfg.mtl.rxQueue[0].queueEnable     = TRUE;
    cfg.mtl.rxQueue[0].storeAndForward = TRUE;
    cfg.mtl.rxQueue[0].rxQueueSize     = (IfxGeth_QueueSize)((4096 >> 8) - 1);
    cfg.mtl.txQueue[0].queueEnable     = TRUE;
    cfg.mtl.txQueue[0].storeAndForward = TRUE;
    cfg.mtl.txQueue[0].txQueueSize     = (IfxGeth_QueueSize)((4096 >> 8) - 1);

    cfg.dma.txChannel[0].channelEnable         = TRUE;
    cfg.dma.txChannel[0].channelId             = IfxGeth_TxDmaChannel_0;
    cfg.dma.txChannel[0].maxBurstLength        = IfxGeth_DmaBurstLength_16;
    cfg.dma.txChannel[0].txDescrList           =
        (IfxGeth_TxDescrList *)s_tx_desc;
    cfg.dma.txChannel[0].txBuffer1Size         = TC3XX_ETH_BUF_SIZE;
    cfg.dma.txChannel[0].txBuffer1StartAddress = (uint32 *)(void *)s_tx_buf;

    cfg.dma.rxChannel[0].channelEnable         = TRUE;
    cfg.dma.rxChannel[0].channelId             = IfxGeth_RxDmaChannel_0;
    cfg.dma.rxChannel[0].maxBurstLength        = IfxGeth_DmaBurstLength_16;
    cfg.dma.rxChannel[0].rxDescrList           =
        (IfxGeth_RxDescrList *)s_rx_desc;
    cfg.dma.rxChannel[0].rxBuffer1Size         = TC3XX_ETH_BUF_SIZE;
    cfg.dma.rxChannel[0].rxBuffer1StartAddress = (uint32 *)(void *)s_rx_buf;

    cfg.dma.numOfTxChannels = 1;
    cfg.dma.numOfRxChannels = 1;

#if TC3XX_ETH_RX_IRQ
    cfg.dma.rxInterrupt[0].channelId = IfxGeth_DmaChannel_0;
    cfg.dma.rxInterrupt[0].priority  = TC3XX_ETH_RX_IRQ_PRIO;
    cfg.dma.rxInterrupt[0].provider  = TC3XX_ETH_RX_IRQ_TOS;
#endif

    IfxGeth_Eth_initModule(&s_geth, &cfg);
}

static void mac_set_link(int speed_100, int full_duplex)
{
    IfxGeth_mac_setLineSpeed(&TC3XX_ETH_MODULE,
                             speed_100 ? IfxGeth_LineSpeed_100Mbps
                                       : IfxGeth_LineSpeed_10Mbps);
    IfxGeth_mac_setDuplexMode(&TC3XX_ETH_MODULE,
                              full_duplex ? IfxGeth_DuplexMode_fullDuplex
                                          : IfxGeth_DuplexMode_halfDuplex);
}

int tc3xx_eth_link_update(void)
{
    int speed_100 = 0;
    int full_duplex = 0;
    int up;

    if (s_phy_addr < 0) {
        return TC3XX_ETH_EINVAL;
    }
    up = aurix_phy_link((uint8_t)s_phy_addr, &speed_100, &full_duplex);
    if (up < 0) {
        return TC3XX_ETH_EIO;
    }
    /* A renegotiation between two calls never shows as a link-down edge. */
    if (up && (speed_100 != s_mac_speed_100 ||
               full_duplex != s_mac_full_duplex)) {
        mac_set_link(speed_100, full_duplex);
        s_mac_speed_100   = speed_100;
        s_mac_full_duplex = full_duplex;
    }
    return up;
}

/* Not IfxGeth_Eth_freeReceiveBuffer: on TC3xx it never restores RDES0, which
 * the DMA overwrote with status. */
static void rx_release_locked(uint32 index)
{
    volatile IfxGeth_RxDescr *descr = &s_rx_desc[index];
    IfxGeth_RxDescr3          rdes3;

    descr->RDES0.U = (uint32)(void *)s_rx_buf[index];
    descr->RDES1.U = 0u;
    descr->RDES2.U = 0u;
    __dsync();

    rdes3.U       = 0u;
    rdes3.R.BUF1V = 1u;
    rdes3.R.IOC   = 1u;
    rdes3.R.OWN   = 1u;
    descr->RDES3.U = rdes3.U;

    IfxGeth_Eth_shuffleRxDescriptor(&s_geth, IfxGeth_RxDmaChannel_0);

    /* TriCore does not order a store to RAM against one to a GETH SFR. */
    __dsync();
    IfxGeth_Eth_wakeupReceiver(&s_geth, IfxGeth_RxDmaChannel_0);
}

static int eth_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    volatile IfxGeth_RxDescr *descr;
    IfxGeth_RxDescr3_WF_Bits  wb;
    uint32                    index;
    uint32                    tries;
    uint32_t                  got = 0u;
    boolean                   irq;

    (void)ll;
    TC3XX_ETH_LOCK(irq);
    /* Keep going past dropped frames: wolfIP reads 0 as an empty ring. */
    for (tries = 0u; s_started && got == 0u && tries < TC3XX_ETH_RX_DESC;
         tries++) {
        if (!IfxGeth_Eth_isRxDataAvailable(&s_geth, IfxGeth_RxDmaChannel_0)) {
            break;
        }
        descr = IfxGeth_Eth_getActualRxDescriptor(&s_geth,
                                                  IfxGeth_RxDmaChannel_0);
        index = (uint32)(descr - IfxGeth_Eth_getBaseRxDescriptor(&s_geth,
                                                   IfxGeth_RxDmaChannel_0));
        if (index >= TC3XX_ETH_RX_DESC) {
            break;
        }

        /* PL is the whole frame, FCS included, and bounds the copy. */
        wb = descr->RDES3.W;
        if (wb.CTXT || wb.ES || !wb.FD || !wb.LD ||
            wb.PL <= TC3XX_ETH_FCS_LEN || wb.PL > TC3XX_ETH_BUF_SIZE ||
            wb.PL - TC3XX_ETH_FCS_LEN > len) {
            s_rx_dropped++;
        }
        else {
            got = wb.PL - TC3XX_ETH_FCS_LEN;
            memcpy(buf, s_rx_buf[index], got);
            s_rx_frames++;
        }
        rx_release_locked(index);
    }
    TC3XX_ETH_UNLOCK(irq);
    return (int)got;
}

/* Written out rather than IfxGeth_Eth_sendTransmitBuffer(), which stores OWN
 * and then kicks the tail pointer with no barrier in between. */
static int eth_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    volatile IfxGeth_TxDescr *descr;
    IfxGeth_TxDescr2          tdes2;
    IfxGeth_TxDescr3          tdes3;
    uint32                    index;
    boolean                   irq;
    int                       ret = -1;

    (void)ll;
    if (buf == NULL || len == 0u || len > TC3XX_ETH_BUF_SIZE) {
        return -1;
    }

    TC3XX_ETH_LOCK(irq);
    index = s_tx_next;
    descr = &s_tx_desc[index];
    if (!s_started) {
        ret = -1;
    }
    else if (descr->TDES3.R.OWN != 0u) {
        ret = -WOLFIP_EAGAIN;
    }
    else {
        memcpy(s_tx_buf[index], buf, len);
        descr->TDES0.U = (uint32)(void *)s_tx_buf[index];
        descr->TDES1.U = 0u;

        tdes2.U       = 0u;
        tdes2.R.B1L   = len;
        tdes2.R.IOC   = 1u;
        descr->TDES2.U = tdes2.U;

        /* CRC and pad insertion on; wolfIP computes the checksums itself. */
        tdes3.U         = 0u;
        tdes3.R.FL_TPL  = len;
        tdes3.R.CIC_TPL = 0u;
        tdes3.R.FD      = 1u;
        tdes3.R.LD      = 1u;
        tdes3.R.OWN     = 1u;
        descr->TDES3.U  = tdes3.U;

        __dsync();
        s_tx_next = (index + 1u) % TC3XX_ETH_TX_DESC;
        IfxGeth_dma_setTxDescriptorTailPointer(&TC3XX_ETH_MODULE,
                                               IfxGeth_TxDmaChannel_0,
                                               (uint32)&s_tx_desc[s_tx_next]);
        IfxGeth_Eth_wakeupTransmitter(&s_geth, IfxGeth_TxDmaChannel_0);
        s_tx_frames++;
        ret = (int)len;
    }
    TC3XX_ETH_UNLOCK(irq);
    return ret;
}

#if TC3XX_ETH_RX_IRQ
static void (*volatile s_rx_notify)(void);

void tc3xx_eth_set_rx_notify(void (*cb)(void))
{
    s_rx_notify = cb;
}

/* Only clears the request: the ring is serialised by disabling interrupts,
 * which a handler cannot take part in. */
IFX_INTERRUPT(tc3xx_eth_rx_isr, TC3XX_ETH_RX_IRQ_VECTAB, TC3XX_ETH_RX_IRQ_PRIO)
{
    void (*cb)(void) = s_rx_notify;
    Ifx_GETH_DMA_CH_STATUS clr;

    clr.U     = 0u;
    clr.B.RI  = 1u;
    clr.B.NIS = 1u;
    TC3XX_ETH_MODULE.DMA_CH[0].STATUS.U = clr.U;
    __dsync();

    if (cb != NULL) {
        cb();
    }
}
#endif

int tc3xx_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    static const uint8_t default_mac[6] = TC3XX_ETH_DEFAULT_MAC;
    uint32_t steps;
    uint32_t waited;
    int      phy;

    if (ll == NULL || s_started) {
        return TC3XX_ETH_EINVAL;
    }
    if (mac == NULL) {
        mac = default_mac;
    }

    s_geth.gethSFR = &TC3XX_ETH_MODULE;
    IfxGeth_enableModule(&TC3XX_ETH_MODULE);
    IfxGeth_setPhyInterfaceMode(&TC3XX_ETH_MODULE,
                                IfxGeth_PhyInterfaceMode_rmii);
    IfxGeth_Eth_setupRmiiOutputPins(&s_geth, &s_rmii_pins);
    IfxGeth_Eth_setupRmiiInputPins(&s_geth, &s_rmii_pins);
    s_mdio_ready = 1;

    phy = aurix_phy_detect(TC3XX_ETH_PHY_ADDR, TC3XX_ETH_PHY_TIMEOUT_MS);
    if (phy < 0) {
        return (phy == AURIX_PHY_EMDIO) ? TC3XX_ETH_EIO : TC3XX_ETH_ENOPHY;
    }
    if (aurix_phy_reset((uint8_t)phy) != 0) {
        return TC3XX_ETH_EIO;
    }
    s_phy_addr = phy;

    if (!refclk_present()) {
        return TC3XX_ETH_ENOCLK;
    }
    mac_init(mac);

    if (aurix_phy_start_autoneg((uint8_t)phy) != 0) {
        return TC3XX_ETH_EIO;
    }
    steps = TC3XX_ETH_LINK_TIMEOUT_MS / TC3XX_ETH_LINK_POLL_MS +
            ((TC3XX_ETH_LINK_TIMEOUT_MS % TC3XX_ETH_LINK_POLL_MS) != 0u);
    for (waited = 0u; waited <= steps; waited++) {
        if (tc3xx_eth_link_update() > 0) {
            break;
        }
        if (waited < steps) {
            TC3XX_ETH_DELAY_MS(TC3XX_ETH_LINK_POLL_MS);
        }
    }

    IfxGeth_Eth_startReceiver(&s_geth, IfxGeth_RxDmaChannel_0);
    IfxGeth_Eth_startTransmitter(&s_geth, IfxGeth_TxDmaChannel_0);
    s_started = 1;

    memcpy(ll->mac, mac, 6);
    strncpy(ll->ifname, "eth0", sizeof(ll->ifname) - 1u);
    ll->ifname[sizeof(ll->ifname) - 1u] = '\0';
    ll->mtu  = LINK_MTU;
    ll->poll = eth_poll;
    ll->send = eth_send;
    return TC3XX_ETH_OK;
}

int tc3xx_eth_phy_addr(void)
{
    return s_phy_addr;
}

void tc3xx_eth_get_stats(uint32_t *rx, uint32_t *tx, uint32_t *rx_dropped)
{
    if (rx != NULL) {
        *rx = s_rx_frames;
    }
    if (tx != NULL) {
        *tx = s_tx_frames;
    }
    if (rx_dropped != NULL) {
        *rx_dropped = s_rx_dropped;
    }
}

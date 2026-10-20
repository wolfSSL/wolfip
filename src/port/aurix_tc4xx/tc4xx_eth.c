/* tc4xx_eth.c
 *
 * Infineon AURIX TC4xx GETH0 (RMII via the HSPHY) driver for wolfIP, on top of
 * the iLLD.
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
#include "IfxClock.h"
#include "IfxCpu.h"
#include "IfxGeth_Eth.h"
#include "IfxHsphy.h"
#include "IfxPmsEvr.h"
#include "IfxPort.h"
#include "IfxStm.h"
#include "IfxVmt.h"

#include "config.h"
#include "tc4xx_eth.h"
#include "tc4xx_eth_board.h"

/* iLLD programs the ring length from these, so they are not a free choice. */
#define TC4XX_ETH_RX_DESC   ((uint32_t)IFXGETH_MAX_RX_DESCRIPTORS)
#define TC4XX_ETH_TX_DESC   ((uint32_t)IFXGETH_MAX_TX_DESCRIPTORS)
#define TC4XX_ETH_BUF_SIZE  1536u
#define TC4XX_ETH_FCS_LEN   4u

#define TC4XX_ETH_MDIO_POLLS  100000u
#define TC4XX_ETH_LINK_POLL_MS  10u
#define TC4XX_ETH_REFCLK_TIMEOUT_MS  100u

/* MAC_TX_CONFIGURATION.SS for MII/RMII. */
#define TC4XX_ETH_SS_100M   4u
#define TC4XX_ETH_SS_10M    7u

#ifndef TC4XX_ETH_RING_ATTR
#define TC4XX_ETH_RING_ATTR
#endif

#ifndef TC4XX_ETH_DELAY_MS
#define TC4XX_ETH_DELAY_MS(ms) \
    IfxStm_waitTicks(&MODULE_CPU0, IfxStm_getTicksFromMilliseconds(ms))
#endif

#if TC4XX_ETH_BUF_SIZE < LINK_MTU
#error "LINK_MTU exceeds the GETH buffer size"
#endif

#define TC4XX_CORE  MODULE_GETH0.PORT[IfxGeth_PortIndex_0].CORE
#define TC4XX_MDIO  TC4XX_CORE.MDIO

static IFX_ALIGN(8) IfxGeth_TxDescr s_tx_desc[TC4XX_ETH_TX_DESC]
    TC4XX_ETH_RING_ATTR;
static IFX_ALIGN(8) IfxGeth_RxDescr s_rx_desc[TC4XX_ETH_RX_DESC]
    TC4XX_ETH_RING_ATTR;
static IFX_ALIGN(8) uint8 s_tx_buf[TC4XX_ETH_TX_DESC][TC4XX_ETH_BUF_SIZE]
    TC4XX_ETH_RING_ATTR;
static IFX_ALIGN(8) uint8 s_rx_buf[TC4XX_ETH_RX_DESC][TC4XX_ETH_BUF_SIZE]
    TC4XX_ETH_RING_ATTR;

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

#define TC4XX_ETH_LOCK(state)    ((state) = IfxCpu_disableInterrupts())
#define TC4XX_ETH_UNLOCK(state)  IfxCpu_restoreInterrupts(state)

/* The HSPHY routes these, one call per direction. */
static const IfxHsphy_Geth_RmiiPins s_rmii_pins = {
    .rxd0   = &TC4XX_ETH_PIN_RXD0,
    .rxd1   = &TC4XX_ETH_PIN_RXD1,
    .crsDiv = &TC4XX_ETH_PIN_CRSDV,
    .refClk = &TC4XX_ETH_PIN_REFCLK,
    .txd0   = &TC4XX_ETH_PIN_TXD0,
    .txd1   = &TC4XX_ETH_PIN_TXD1,
    .txEn   = &TC4XX_ETH_PIN_TXEN,
};

/* SINGLE_COMMAND_CONTROL_DATA.CR keeping MDC under 2.5 MHz, or -1 when none
 * fits. CR 0..5 divide by 62, 102, 122, 142, 162 and 202. */
static int mdio_cr(uint32_t hz)
{
    if (hz == 0u || hz > 500000000u) {
        return -1;
    }
    if (hz >= 400000000u) {
        return 5;
    }
    if (hz >= 350000000u) {
        return 4;
    }
    if (hz >= 300000000u) {
        return 3;
    }
    if (hz >= 250000000u) {
        return 2;
    }
    if (hz >= 150000000u) {
        return 1;
    }
    return 0;
}

static int mdio_setup(void)
{
    Ifx_GETH_PORT_CORE_MDIO_SINGLE_COMMAND_CONTROL_DATA ctl;
    int cr = mdio_cr(IfxClock_getXGeth0Frequency());

    if (cr < 0) {
        return TC4XX_ETH_EIO;
    }

    MODULE_GETH0.MACEN.U |= 1u << IfxGeth_PortIndex_0;
    ctl.U    = 0u;
    ctl.B.CR = (uint32)cr;
    TC4XX_MDIO.SINGLE_COMMAND_CONTROL_DATA.U = ctl.U;
    return TC4XX_ETH_OK;
}

static int mdio_wait_idle(void)
{
    uint32_t spins;

    for (spins = TC4XX_ETH_MDIO_POLLS; spins != 0u; --spins) {
        if (TC4XX_MDIO.SINGLE_COMMAND_CONTROL_DATA.B.SBUSY == 0u) {
            return TC4XX_ETH_OK;
        }
    }
    return TC4XX_ETH_EIO;
}

/* Written out: the iLLD's clause-22 helpers spin on SBUSY unbounded.
 * cmd: 3 = read, 1 = write. */
static int mdio_transact(uint8_t phy_addr, uint8_t reg, uint32 cmd,
                         uint16_t data)
{
    Ifx_GETH_PORT_CORE_MDIO_SINGLE_COMMAND_ADDRESS      addr;
    Ifx_GETH_PORT_CORE_MDIO_SINGLE_COMMAND_CONTROL_DATA ctl;

    if (!s_mdio_ready || phy_addr > 31u || reg > 31u) {
        return TC4XX_ETH_EINVAL;
    }
    if (mdio_wait_idle() != TC4XX_ETH_OK) {
        return TC4XX_ETH_EIO;
    }

    TC4XX_MDIO.CLAUSE_22_PORT.U |= 1u << phy_addr;

    addr.U    = 0u;
    addr.B.PA = phy_addr;
    addr.B.RA = reg;
    ctl.U       = TC4XX_MDIO.SINGLE_COMMAND_CONTROL_DATA.U;
    ctl.B.CMD   = cmd;
    ctl.B.SDATA = data;
    ctl.B.SBUSY = 1u;
    TC4XX_MDIO.SINGLE_COMMAND_ADDRESS.U      = addr.U;
    TC4XX_MDIO.SINGLE_COMMAND_CONTROL_DATA.U = ctl.U;

    return mdio_wait_idle();
}

int tc4xx_eth_mdio_read(uint8_t phy_addr, uint8_t reg, uint16_t *value)
{
    int rc;

    if (value == NULL) {
        return TC4XX_ETH_EINVAL;
    }
    rc = mdio_transact(phy_addr, reg, 3u, 0u);
    if (rc == TC4XX_ETH_OK) {
        *value = (uint16_t)TC4XX_MDIO.SINGLE_COMMAND_CONTROL_DATA.B.SDATA;
    }
    return rc;
}

int tc4xx_eth_mdio_write(uint8_t phy_addr, uint8_t reg, uint16_t value)
{
    return mdio_transact(phy_addr, reg, 1u, value);
}

#define AURIX_MDIO_READ   tc4xx_eth_mdio_read
#define AURIX_MDIO_WRITE  tc4xx_eth_mdio_write
#define AURIX_DELAY_MS    TC4XX_ETH_DELAY_MS
#include "../common/aurix_phy.h"

/* GETH sits behind the HSPHY: without its rails and interface mode the MAC
 * initialises cleanly and every RMII input reads static. */
static int hsphy_setup(void)
{
    IfxGeth_Mdc_Out    *mdc  = &TC4XX_ETH_PIN_MDC;
    IfxGeth_Mdio_InOut *mdio = &TC4XX_ETH_PIN_MDIO;

    IfxPmsEvr_enableVoltageRail(&MODULE_PMS,
        IfxPmsEvr_PrimaryMonitorVoltageSource_vddphphy0);
    IfxPmsEvr_enableVoltageRail(&MODULE_PMS,
        IfxPmsEvr_PrimaryMonitorVoltageSource_vddphy0);
    IfxPmsEvr_enableVoltageRail(&MODULE_PMS,
        IfxPmsEvr_PrimaryMonitorVoltageSource_vddphphy1);
    IfxPmsEvr_enableVoltageRail(&MODULE_PMS,
        IfxPmsEvr_PrimaryMonitorVoltageSource_vddphy1);
    IfxPmsEvr_enableVoltageRail(&MODULE_PMS,
        IfxPmsEvr_PrimaryMonitorVoltageSource_vddphphy2);
    IfxPmsEvr_enableVoltageRail(&MODULE_PMS,
        IfxPmsEvr_PrimaryMonitorVoltageSource_vddphy2);
    IfxPmsEvr_enableVoltageRail(&MODULE_PMS,
        IfxPmsEvr_PrimaryMonitorVoltageSource_vddhsif);

    if (IfxHsphy_enableModule(&MODULE_HSPHY) != FALSE) {
        return TC4XX_ETH_EIO;
    }
    MODULE_HSPHY.ETH[0].B.EPR    = IfxHsphy_EthCtrlExtPhySel_rmii;
    MODULE_HSPHY.ETH[0].B.MDIO   = mdio->inSelect;
    MODULE_HSPHY.ETH[0].B.MDIOEN = 1u;
    MODULE_HSPHY.CMNCFG.B.FSR    = 1u;

    IfxPort_setPinModeInput(mdio->pin.port, mdio->pin.pinIndex,
                            IfxPort_InputMode_noPullDevice);
    IfxPort_setPinPadDriver(mdio->pin.port, mdio->pin.pinIndex,
                            IfxPort_PadDriver_cmosAutomotiveSpeed3);
    IfxPort_setPinModeOutput(mdc->pin.port, mdc->pin.pinIndex,
                             IfxPort_OutputMode_pushPull, mdc->select);
    IfxPort_setPinPadDriver(mdc->pin.port, mdc->pin.pinIndex,
                            IfxPort_PadDriver_cmosAutomotiveSpeed3);

    /* Routing only the inputs leaves the receive path working and transmit
     * silently dead. */
    IfxHsphy_Geth_setupRmiiInputPins(&MODULE_HSPHY, IfxHsphy_EthIndex_0,
                                     &s_rmii_pins);
    IfxHsphy_Geth_setupRmiiOutputPins(&MODULE_HSPHY, &s_rmii_pins);
    return TC4XX_ETH_OK;
}

/* The DMA reset needs the RMII clock the PHY drives, so a SWR bit that never
 * clears means no reference clock; iLLD's initModule would hang on it. */
static int refclk_present(void)
{
    uint32_t waited;

    IfxGeth_Dma_applySoftwareReset(&MODULE_GETH0);
    for (waited = 0u; waited < TC4XX_ETH_REFCLK_TIMEOUT_MS; waited++) {
        if (MODULE_GETH0.DMA.MODE.B.SWR == 0u) {
            return 1;
        }
        TC4XX_ETH_DELAY_MS(1u);
    }
    return 0;
}

static void mac_init(const uint8_t *mac)
{
    IfxGeth_Eth_Config cfg;

    /* iLLD's descriptor init never writes TDES3, so a residual OWN bit would
     * fail every send. */
    memset((void *)s_tx_desc, 0, sizeof(s_tx_desc));
    memset((void *)s_rx_desc, 0, sizeof(s_rx_desc));
    s_tx_next = 0u;
    /* initModule puts the MAC back to its default mode. */
    s_mac_speed_100 = -1;

    /* The MAC SRAMs come up with ECC unprimed and only a write primes it. */
    IfxVmt_clearSram(IfxVmt_MbistSel_ethermacAxi);
    IfxVmt_clearSram(IfxVmt_MbistSel_ethermacDmi);
    IfxVmt_clearSram(IfxVmt_MbistSel_ethermac0Gcl);
    IfxVmt_clearSram(IfxVmt_MbistSel_ethermac1Gcl);
    IfxVmt_clearSram(IfxVmt_MbistSel_ethermac0RxEven);
    IfxVmt_clearSram(IfxVmt_MbistSel_ethermac0RxOdd);
    IfxVmt_clearSram(IfxVmt_MbistSel_ethermac1RxEven);
    IfxVmt_clearSram(IfxVmt_MbistSel_ethermac1RxOdd);
    IfxVmt_clearSram(IfxVmt_MbistSel_ethermac0TxEven);
    IfxVmt_clearSram(IfxVmt_MbistSel_ethermac0TxOdd);
    IfxVmt_clearSram(IfxVmt_MbistSel_ethermac1TxEven);
    IfxVmt_clearSram(IfxVmt_MbistSel_ethermac1TxOdd);

    IfxGeth_Eth_initModuleConfig(&cfg, &MODULE_GETH0);
    cfg.port[IfxGeth_PortIndex_0].phyInterfaceMode =
        IfxGeth_PhyInterfaceMode_rmii_100;
    cfg.port[IfxGeth_PortIndex_0].mac.disableCrcCheck = FALSE;
    memcpy(cfg.port[IfxGeth_PortIndex_0].mac.macAddress, mac, 6);

    /* 4 KiB per queue, in 256-byte units minus one. */
    cfg.port[IfxGeth_PortIndex_0].mtl.rxQueue[0].enable = TRUE;
    cfg.port[IfxGeth_PortIndex_0].mtl.rxQueue[0].enableDynamicDmaChannelMap =
        TRUE;
    cfg.port[IfxGeth_PortIndex_0].mtl.rxQueue[0].rxQueueSize = (4096 >> 8) - 1;
    cfg.port[IfxGeth_PortIndex_0].mtl.txQueue[0].enable = TRUE;
    cfg.port[IfxGeth_PortIndex_0].mtl.txQueue[0].txQueueSize = (4096 >> 8) - 1;

    cfg.dma.addressAlignedBeatsEnabled = TRUE;
    cfg.dma.burstLength                = IfxGeth_DmaBurstLength_16;
    cfg.dma.undefinedBurstLength       = FALSE;
    memset(cfg.dma.burstLengthMultiplierEnable, FALSE,
           sizeof(cfg.dma.burstLengthMultiplierEnable));

    cfg.dma.txChannel[0].channelEnable         = TRUE;
    cfg.dma.txChannel[0].maxBurstLength        = IfxGeth_TxBurstLength_16;
    cfg.dma.txChannel[0].txDescrList           =
        (IfxGeth_TxDescrList *)s_tx_desc;
    cfg.dma.txChannel[0].txBuffer1Size         = TC4XX_ETH_BUF_SIZE;
    cfg.dma.txChannel[0].txBuffer1StartAddress = (uint32 *)(void *)s_tx_buf;

    cfg.dma.rxChannel[0].channelEnable         = TRUE;
    cfg.dma.rxChannel[0].maxBurstLength        = IfxGeth_RxBurstLength_16;
    cfg.dma.rxChannel[0].rxDescrList           =
        (IfxGeth_RxDescrList *)s_rx_desc;
    cfg.dma.rxChannel[0].rxBuffer1Size         = TC4XX_ETH_BUF_SIZE;
    cfg.dma.rxChannel[0].rxBuffer1StartAddress = (uint32 *)(void *)s_rx_buf;

#if TC4XX_ETH_RX_IRQ
    cfg.dma.rxInterrupt[0].priority = TC4XX_ETH_RX_IRQ_PRIO;
    cfg.dma.rxInterrupt[0].provider = TC4XX_ETH_RX_IRQ_TOS;
#endif

    cfg.bridge.mode = IfxGeth_BridgePortMode_singlePort0;

    IfxGeth_Eth_initModule(&s_geth, &cfg);
}

static void mac_set_link(int speed_100, int full_duplex)
{
    TC4XX_CORE.MAC_TX_CONFIGURATION.B.SS =
        speed_100 ? TC4XX_ETH_SS_100M : TC4XX_ETH_SS_10M;
    TC4XX_CORE.MAC_EXTENDED_CONFIGURATION.B.HD =
        full_duplex ? IfxGeth_DuplexMode_fullDuplex
                    : IfxGeth_DuplexMode_halfDuplex;
}

int tc4xx_eth_link_update(void)
{
    int speed_100 = 0;
    int full_duplex = 0;
    int up;

    if (s_phy_addr < 0) {
        return TC4XX_ETH_EINVAL;
    }
    up = aurix_phy_link((uint8_t)s_phy_addr, &speed_100, &full_duplex);
    if (up < 0) {
        return TC4XX_ETH_EIO;
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

/* IfxGeth_Eth_freeReceiveBuffer(), with the barrier it lacks between re-arming
 * the descriptor behind the tail pointer and moving the tail pointer. */
static void rx_release_locked(void)
{
    volatile IfxGeth_RxDescr *descr;
    uint32                    cur;
    uint32                    off;
    uint32                    tail;

    /* Advance first: returning with it unmoved would replay the same frame. */
    cur = (uint32)(s_geth.rxChannel[IfxGeth_RxDmaChannel_0].rxDescrPtr -
                   s_rx_desc);
    s_geth.rxChannel[IfxGeth_RxDmaChannel_0].rxDescrPtr =
        &s_rx_desc[(cur + 1u) % TC4XX_ETH_RX_DESC];

    off = MODULE_GETH0.DMA.CH[0].RXDESC_TAIL_LPOINTER.U -
          (uint32)(void *)s_rx_desc;
    if ((off % sizeof(IfxGeth_RxDescr)) != 0u ||
        off / sizeof(IfxGeth_RxDescr) >= TC4XX_ETH_RX_DESC) {
        return;
    }
    tail = off / sizeof(IfxGeth_RxDescr);
    descr = &s_rx_desc[tail];
    descr->RDES0.U = (uint32)(void *)s_rx_buf[tail];
    descr->RDES3.U = (1u << 30) | (1u << 31);   /* IOC | OWN */

    /* TriCore does not order a store to RAM against one to a GETH SFR. */
    __dsync();
    MODULE_GETH0.DMA.CH[0].RXDESC_TAIL_LPOINTER.U =
        (uint32)&s_rx_desc[(tail + 1u) % TC4XX_ETH_RX_DESC];
    IfxGeth_Eth_wakeupReceiver(&s_geth, IfxGeth_PortIndex_0,
                               IfxGeth_RxDmaChannel_0);
}

static int eth_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    IfxGeth_Eth_RxDescStatus  status;
    volatile IfxGeth_RxDescr *descr;
    void                     *frame;
    uint32                    tries;
    uint32_t                  got = 0u;
    boolean                   irq;

    (void)ll;
    TC4XX_ETH_LOCK(irq);
    /* Keep going past dropped frames: wolfIP reads 0 as an empty ring. */
    for (tries = 0u; s_started && got == 0u && tries < TC4XX_ETH_RX_DESC;
         tries++) {
        frame = IfxGeth_Eth_getReceiveBuffer(&s_geth, IfxGeth_RxDmaChannel_0);
        if (frame == NULL_PTR) {
            break;
        }

        /* iLLD writes only `context` for a context descriptor and still
         * returns TRUE, so `normal` must start zeroed. */
        memset(&status, 0, sizeof(status));
        descr = IfxGeth_Eth_getActualRxDescriptor(&s_geth,
                                                  IfxGeth_RxDmaChannel_0);
        /* PL is the whole frame, FCS included, and bounds the copy. */
        if (!IfxGeth_Eth_getRxDescriptorStatus(&s_geth,
                                               (IfxGeth_RxDescr *)descr,
                                               &status) ||
            status.normal.CTXT || status.normal.ES || !status.normal.FD ||
            !status.normal.LD || status.normal.PL <= TC4XX_ETH_FCS_LEN ||
            status.normal.PL > TC4XX_ETH_BUF_SIZE ||
            status.normal.PL - TC4XX_ETH_FCS_LEN > len) {
            s_rx_dropped++;
        }
        else {
            got = status.normal.PL - TC4XX_ETH_FCS_LEN;
            memcpy(buf, frame, got);
            s_rx_frames++;
        }
        rx_release_locked();
    }
    TC4XX_ETH_UNLOCK(irq);
    return (int)got;
}

/* Written out rather than IfxGeth_Eth_sendTransmitBuffer(), which stores OWN
 * and then kicks the tail pointer with no barrier in between. */
static int eth_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    const IfxGeth_Eth_TxChannel *ch = &s_geth.txChannel[IfxGeth_TxDmaChannel_0];
    volatile IfxGeth_TxDescr    *descr;
    IfxGeth_TxDescr2             tdes2;
    IfxGeth_TxDescr3             tdes3;
    uint32                       index;
    boolean                      irq;
    int                          ret = -1;

    (void)ll;
    if (buf == NULL || len == 0u || len > TC4XX_ETH_BUF_SIZE) {
        return -1;
    }

    TC4XX_ETH_LOCK(irq);
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

        tdes2.U        = 0u;
        tdes2.R.B1L    = len;
        tdes2.R.VTIR   = ch->vlanTagControl;
        tdes2.R.TTSE   = ch->timeStampEnable;
        tdes2.R.IOC    = 1u;
        descr->TDES2.U = tdes2.U;

        tdes3.U         = 0u;
        tdes3.R.FL      = len;
        /* wolfIP computes the checksums itself. */
        tdes3.R.CIC     = IfxGeth_ChecksumControl_disabled;
        tdes3.R.SLOTNUM = ch->avbSlotNumber;
        tdes3.R.SAIC    = ch->sourceAddressControl;
        tdes3.R.CPC     = ch->crcControl;
        tdes3.R.FD      = 1u;
        tdes3.R.LD      = 1u;
        tdes3.R.OWN     = 1u;
        descr->TDES3.U  = tdes3.U;

        __dsync();
        s_tx_next = (index + 1u) % TC4XX_ETH_TX_DESC;
        MODULE_GETH0.DMA.CH[0].TXDESC_TAIL_LPOINTER.U =
            (uint32)&s_tx_desc[s_tx_next];
        IfxGeth_Eth_wakeupTransmitter(&s_geth, IfxGeth_PortIndex_0,
                                      IfxGeth_TxDmaChannel_0);
        s_tx_frames++;
        ret = (int)len;
    }
    TC4XX_ETH_UNLOCK(irq);
    return ret;
}

#if TC4XX_ETH_RX_IRQ
static void (*volatile s_rx_notify)(void);

void tc4xx_eth_set_rx_notify(void (*cb)(void))
{
    s_rx_notify = cb;
}

/* Only clears the request: the ring is serialised by disabling interrupts,
 * which a handler cannot take part in. */
IFX_INTERRUPT(tc4xx_eth_rx_isr, TC4XX_ETH_RX_IRQ_VECTAB, TC4XX_ETH_RX_IRQ_PRIO)
{
    void (*cb)(void) = s_rx_notify;
    Ifx_GETH_DMA_CH_STATUS clr;

    clr.U     = 0u;
    clr.B.RI  = 1u;
    clr.B.NIS = 1u;
    MODULE_GETH0.DMA.CH[0].STATUS.U = clr.U;
    __dsync();

    if (cb != NULL) {
        cb();
    }
}
#endif

int tc4xx_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    static const uint8_t default_mac[6] = TC4XX_ETH_DEFAULT_MAC;
    uint32_t steps;
    uint32_t waited;
    int      phy;

    if (ll == NULL || s_started) {
        return TC4XX_ETH_EINVAL;
    }
    if (mac == NULL) {
        mac = default_mac;
    }

    if (hsphy_setup() != TC4XX_ETH_OK) {
        return TC4XX_ETH_EIO;
    }
    IfxGeth_enableModule(&MODULE_GETH0);
    if (mdio_setup() != TC4XX_ETH_OK) {
        return TC4XX_ETH_EIO;
    }
    s_mdio_ready = 1;

    phy = aurix_phy_detect(TC4XX_ETH_PHY_ADDR, TC4XX_ETH_PHY_TIMEOUT_MS);
    if (phy < 0) {
        return (phy == AURIX_PHY_EMDIO) ? TC4XX_ETH_EIO : TC4XX_ETH_ENOPHY;
    }
    if (aurix_phy_reset((uint8_t)phy) != 0) {
        return TC4XX_ETH_EIO;
    }
    s_phy_addr = phy;

    if (!refclk_present()) {
        return TC4XX_ETH_ENOCLK;
    }
    mac_init(mac);
    /* initModule kernel-resets the module, MDIO registers included. */
    if (mdio_setup() != TC4XX_ETH_OK) {
        return TC4XX_ETH_EIO;
    }

    if (aurix_phy_start_autoneg((uint8_t)phy) != 0) {
        return TC4XX_ETH_EIO;
    }
    steps = TC4XX_ETH_LINK_TIMEOUT_MS / TC4XX_ETH_LINK_POLL_MS +
            ((TC4XX_ETH_LINK_TIMEOUT_MS % TC4XX_ETH_LINK_POLL_MS) != 0u);
    for (waited = 0u; waited <= steps; waited++) {
        if (tc4xx_eth_link_update() > 0) {
            break;
        }
        if (waited < steps) {
            TC4XX_ETH_DELAY_MS(TC4XX_ETH_LINK_POLL_MS);
        }
    }

    IfxGeth_Eth_startReceiver(&s_geth, IfxGeth_PortIndex_0,
                              IfxGeth_RxDmaChannel_0);
    IfxGeth_Eth_startTransmitter(&s_geth, IfxGeth_PortIndex_0,
                                 IfxGeth_TxDmaChannel_0);
    s_started = 1;

    memcpy(ll->mac, mac, 6);
    strncpy(ll->ifname, "eth0", sizeof(ll->ifname) - 1u);
    ll->ifname[sizeof(ll->ifname) - 1u] = '\0';
    ll->mtu  = LINK_MTU;
    ll->poll = eth_poll;
    ll->send = eth_send;
    return TC4XX_ETH_OK;
}

int tc4xx_eth_phy_addr(void)
{
    return s_phy_addr;
}

void tc4xx_eth_get_stats(uint32_t *rx, uint32_t *tx, uint32_t *rx_dropped)
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

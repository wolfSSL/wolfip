/* va416xx_eth.c
 *
 * VA416xx Ethernet driver for wolfIP
 * Synopsys DesignWare GMAC with normal (legacy) descriptor format
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "va416xx_eth.h"
#include "va416xx.h"
#include "va416xx_hal_ethernet.h"

/* Define DEBUG_ETH to enable verbose hardware diagnostic output.
 * Without it, only essential status messages (link up/down, errors,
 * speed/duplex result) are printed. */
#ifdef DEBUG_ETH
#define ETH_DEBUG(...) printf(__VA_ARGS__)
#else
#define ETH_DEBUG(...) do {} while(0)
#endif

/* ========================================================================= */
/* Normal (Legacy) DMA Descriptor Bit Definitions                            */
/*                                                                           */
/* The VA416xx uses the Synopsys DesignWare GMAC with normal descriptors.    */
/* This is fundamentally different from the STM32H5 enhanced/QoS format:    */
/*   - OWN/FS/LS/FL are in des0 (not des3)                                  */
/*   - Buffer address is in des2 (not des0)                                  */
/*   - Ring wraps via TER/RER bits (not tail pointer registers)             */
/*   - DMA kicked via poll demand registers (not tail pointer updates)       */
/* ========================================================================= */

/* --- TX Descriptor TDES0 bits --- */
#define TDES0_OWN       (1U << 31)  /* DMA owns descriptor */
#define TDES0_IC        (1U << 30)  /* Interrupt on Completion */
#define TDES0_LS        (1U << 29)  /* Last Segment */
#define TDES0_FS        (1U << 28)  /* First Segment */
#define TDES0_DC        (1U << 27)  /* Disable CRC */
#define TDES0_DP        (1U << 26)  /* Disable Padding */
#define TDES0_TER       (1U << 21)  /* Transmit End of Ring */
#define TDES0_TCH       (1U << 20)  /* Second Address Chained */

/* --- TX Descriptor TDES1 bits --- */
#define TDES1_TBS1_MASK  0x1FFFU    /* Buffer 1 Size [12:0] */
#define TDES1_TBS2_SHIFT 16
#define TDES1_TBS2_MASK  0x1FFF0000U /* Buffer 2 Size [28:16] */

/* --- RX Descriptor RDES0 bits --- */
#define RDES0_OWN       (1U << 31)  /* DMA owns descriptor */
#define RDES0_AFM       (1U << 30)  /* DA Filter Fail */
#define RDES0_FL_SHIFT  16          /* Frame Length shift */
#define RDES0_FL_MASK   0x3FFF0000U /* Frame Length [29:16] */
#define RDES0_ES        (1U << 15)  /* Error Summary */
#define RDES0_FS        (1U <<  9)  /* First Descriptor */
#define RDES0_LS        (1U <<  8)  /* Last Descriptor */

/* --- RX Descriptor RDES1 bits --- */
#define RDES1_DIC       (1U << 31)  /* Disable Interrupt on Completion */
#define RDES1_RER       (1U << 25)  /* Receive End of Ring */
#define RDES1_RCH       (1U << 24)  /* Second Address Chained */
#define RDES1_RBS2_SHIFT 11
#define RDES1_RBS2_MASK  0x003FF800U /* Buffer 2 Size [21:11] */
#define RDES1_RBS1_MASK  0x000007FFU /* Buffer 1 Size [10:0] */

/* --- KSZ8041TL PHY-specific registers --- */
/* PHY Control 2 register (reg 0x1F), encoded for SDK HAL (reg_num << 6).
 * Bits [6:4] = Operation Mode Indication after AN:
 *   001 = 10BASE-T HD,  010 = 100BASE-TX HD,
 *   101 = 10BASE-T FD,  110 = 100BASE-TX FD */
#define PHY_CTRL2_REG       (0x1FU << 6)  /* reg 0x1F, GMII encoding */
#define PHY_CTRL2_OPMODE_SHIFT  4
#define PHY_CTRL2_OPMODE_MASK   0x7U
#define PHY_CTRL2_OPMODE_10HD   1U
#define PHY_CTRL2_OPMODE_100HD  2U
#define PHY_CTRL2_OPMODE_10FD   5U
#define PHY_CTRL2_OPMODE_100FD  6U

/* ========================================================================= */
/* DMA Descriptor Structure (4 x 32-bit words, 16 bytes)                    */
/* ========================================================================= */

struct eth_desc {
    volatile uint32_t des0;  /* TX: status/OWN/FS/LS  RX: status/OWN/FL */
    volatile uint32_t des1;  /* TX: TBS1/TBS2         RX: RBS1/RBS2/RER */
    volatile uint32_t des2;  /* Buffer 1 address */
    volatile uint32_t des3;  /* Buffer 2 / next descriptor address */
};

/* ========================================================================= */
/* Static Buffers and Descriptor Rings                                       */
/* ========================================================================= */

#define RX_DESC_COUNT   3U
#define TX_DESC_COUNT   3U
#define RX_BUF_SIZE     LINK_MTU
#define TX_BUF_SIZE     LINK_MTU
#define FRAME_MIN_LEN   60U

/* All DMA descriptors and buffers MUST be in .dma_bss (RAM1, 0x20000000+).
 * The Ethernet DMA is an AHB system bus master and cannot access RAM0
 * (0x1FFF8000, code bus / D-Code bus). */
static struct eth_desc rx_ring[RX_DESC_COUNT]
    __attribute__((aligned(16), section(".dma_bss")));
static struct eth_desc tx_ring[TX_DESC_COUNT]
    __attribute__((aligned(16), section(".dma_bss")));
static uint8_t rx_buffers[RX_DESC_COUNT][RX_BUF_SIZE]
    __attribute__((aligned(4), section(".dma_bss")));
static uint8_t tx_buffers[TX_DESC_COUNT][TX_BUF_SIZE]
    __attribute__((aligned(4), section(".dma_bss")));
static uint8_t rx_staging_buffer[RX_BUF_SIZE]
    __attribute__((aligned(4), section(".dma_bss")));

static uint32_t rx_idx;
static uint32_t tx_idx;

static uint32_t rx_poll_count;
static uint32_t rx_pkt_count;
static uint32_t tx_pkt_count;
static uint32_t tx_err_count;

/* ========================================================================= */
/* Hardware Reset                                                            */
/* ========================================================================= */

static int eth_hw_reset(void)
{
    uint32_t timeout = 1000000U;

    /* DMA software reset */
    VOR_ETH->DMA_BUS_MODE |= ETH_DMA_BUS_MODE_SWR_Msk;
    while ((VOR_ETH->DMA_BUS_MODE & ETH_DMA_BUS_MODE_SWR_Msk) && (timeout > 0U)) {
        timeout--;
    }
    return (timeout > 0U) ? 0 : -1;
}

/* ========================================================================= */
/* MAC Configuration                                                         */
/* ========================================================================= */

static void eth_config_mac(const uint8_t *mac)
{
    /* Set MAC address via SDK HAL */
    HAL_SetMacAddr((uint8_t *)mac);

    /* Initial MAC config: PS=1 (MII port select), ACS (Auto Pad/CRC Strip),
     * IPC (IP Checksum).  Speed (FES) and duplex (DM) are configured later
     * by eth_config_speed_duplex() based on actual PHY negotiation result. */
    VOR_ETH->MAC_CONFIG = ETH_MAC_CONFIG_PS_Msk |
                          ETH_MAC_CONFIG_ACS_Msk |
                          ETH_MAC_CONFIG_IPC_Msk;

    /* Frame filter: promiscuous for initial bring-up */
    VOR_ETH->MAC_FRAME_FLTR = ETH_MAC_FRAME_FLTR_PR_Msk;
}

/* ========================================================================= */
/* MDIO Settling Delay                                                       */
/*                                                                           */
/* The SDK HAL's MDIO busy-wait loop has inverted polarity: it checks        */
/* !(GB) instead of (GB), so it exits immediately after setting GB=1         */
/* rather than waiting for the MDIO transaction to complete (~27 µs).        */
/* Back-to-back HAL_ReadPhyReg / HAL_WritePhyReg calls overlap on the       */
/* wire: a new transaction starts while the previous one is still in         */
/* progress.  This can silently corrupt reads and lose writes entirely.      */
/*                                                                           */
/* Workaround: insert a ~50 µs delay after every MDIO operation to          */
/* guarantee the previous transaction has finished before starting the       */
/* next one.  At 100 MHz, 5000 loop iterations ≈ 50 µs.                     */
/* ========================================================================= */

static void mdio_settle(void)
{
    volatile uint32_t d;
    for (d = 0; d < 5000U; d++) { }
}

/* ========================================================================= */
/* Speed/Duplex Configuration from PHY                                       */
/* ========================================================================= */

static void eth_config_speed_duplex(void)
{
    uint32_t maccr, readback;
    uint16_t ctrl2;
    uint32_t opmode;
    int full_duplex, speed_100;
    int actual_100;

    /* Read KSZ8041TL PHY Control 2 (reg 0x1F) to determine the actual
     * negotiated speed/duplex.  The BMCR speed/duplex bits are unreliable
     * after AN; PHY Ctrl2 OpMode[6:4] is the authoritative source. */
    HAL_ReadPhyReg(PHY_CTRL2_REG, &ctrl2);
    mdio_settle();
    HAL_ReadPhyReg(PHY_CTRL2_REG, &ctrl2); /* double-read */
    mdio_settle();
    opmode = (ctrl2 >> PHY_CTRL2_OPMODE_SHIFT) & PHY_CTRL2_OPMODE_MASK;
    full_duplex = (opmode == PHY_CTRL2_OPMODE_10FD ||
                   opmode == PHY_CTRL2_OPMODE_100FD);
    speed_100 = (opmode == PHY_CTRL2_OPMODE_100HD ||
                 opmode == PHY_CTRL2_OPMODE_100FD);
    ETH_DEBUG("  PHY Ctrl2: 0x%04X OpMode=%lu\n",
              ctrl2, (unsigned long)opmode);

    /* Configure MAC speed and duplex.
     * PS=1:   MII port select (required for VA416xx 10/100 MAC)
     * FES:    1=100Mbps, 0=10Mbps (may be read-only on some variants)
     * DM:     Always set to Full Duplex.  In Half Duplex mode the DWC GMAC
     *         checks CRS before transmitting; CRS is unreliable on this
     *         silicon so MAC defers indefinitely in HD mode.
     * DCRS=1: Explicitly disable CRS check.  This is a no-op in FD mode
     *         but provides defense-in-depth in case DM is somehow ignored.
     * ACS:    Auto pad/CRC strip (RX)
     * IPC:    IP checksum offload (RX)
     * LM:     Loopback mode — compile with -DMAC_LOOPBACK_TEST to enable.
     *         Loops TX back to RX internally (bypasses MII).  Used to verify
     *         whether the DMA→MAC TX path works independently of the PHY. */
    maccr = ETH_MAC_CONFIG_PS_Msk |
            ETH_MAC_CONFIG_DM_Msk |
            ETH_MAC_CONFIG_DCRS_Msk |
            ETH_MAC_CONFIG_ACS_Msk |
            ETH_MAC_CONFIG_IPC_Msk;
    if (speed_100)
        maccr |= ETH_MAC_CONFIG_FES_Msk;
#ifdef MAC_LOOPBACK_TEST
    maccr |= ETH_MAC_CONFIG_LM_Msk;
    printf("  *** MAC LOOPBACK MODE ENABLED ***\n");
#endif

    VOR_ETH->MAC_CONFIG = maccr;

    /* Read back to verify — FES/DM may be read-only on some variants */
    readback = VOR_ETH->MAC_CONFIG;
    actual_100 = !!(readback & ETH_MAC_CONFIG_FES_Msk);
    printf("  PHY: %s %s Duplex (negotiated)\n",
           speed_100 ? "100M" : "10M",
           full_duplex ? "Full" : "Half");
    printf("  MAC: %s %s Duplex (MAC_CONFIG=0x%08lX)\n",
           actual_100 ? "100M" : "10M",
           (readback & ETH_MAC_CONFIG_DM_Msk) ? "Full" : "Half",
           (unsigned long)readback);
    if (speed_100 && !actual_100)
        printf("  NOTE: FES read-only, MAC limited to 10M\n");
    if (!(readback & ETH_MAC_CONFIG_DM_Msk))
        printf("  WARNING: DM bit not retained! MAC stuck in Half Duplex\n");
}

/* ========================================================================= */
/* DMA Configuration                                                         */
/* ========================================================================= */

static void eth_config_dma(void)
{
    /* DMA Bus Mode: PBL=8 only.
     * FB (Fixed Burst) and AAL (Address-Aligned Beats) are intentionally
     * omitted: they require 32-byte-aligned buffers and can silently cause
     * AHB bus errors when the DMA tries to issue misaligned fixed-length
     * bursts.  Plain INCR bursts (no FB) work with any 4-byte-aligned
     * address and are the safest default for bring-up. */
    VOR_ETH->DMA_BUS_MODE = (8U << ETH_DMA_BUS_MODE_PBL_Pos);

    /* Operation Mode:
     * - TX: Threshold mode TTC=7 (16-byte threshold).  Previous testing with
     *   TSF (Store-and-Forward) showed TXFSTS=0 at ALL times including the
     *   10µs post-kick sample window, proving the DMA was NOT writing frame
     *   data to the TX FIFO in TSF mode.  TTC threshold mode starts MAC TX
     *   as soon as 16 bytes are in the FIFO rather than waiting for the
     *   complete frame, which may work if TSF's "frame complete" gating
     *   is the issue on this silicon.
     * - RX: Store-and-Forward (RSF=1) - keeps working as before. */
    VOR_ETH->DMA_OPER_MODE = ETH_DMA_OPER_MODE_RSF_Msk |
                              (7U << ETH_DMA_OPER_MODE_TTC_Pos); /* TTC=7 = 16B threshold */

    /* Disable all DMA interrupts (polling mode) */
    VOR_ETH->DMA_INTR_EN = 0;
}

/* ========================================================================= */
/* Descriptor Ring Initialization                                            */
/* ========================================================================= */

static void eth_init_desc(void)
{
    uint32_t i;

    /* Clear all TX descriptors - CPU owns (OWN=0).
     *
     * Use CHAIN mode (TCH=1 in TDES0, des3 = next descriptor pointer).
     *
     * Why NOT ring mode (TER):
     *   TER lives in TDES0 bit 21.  The DWC GMAC TX DMA overwrites the
     *   entire des0 word when it writes back completion status (making
     *   des0 = 0x00000000 on success).  If the DMA then re-reads des0 to
     *   decide the next address, TER=0 → no wrap → the DMA runs linearly
     *   past the last descriptor into adjacent memory (RX ring), corrupting
     *   it and processing garbage as TX frames.
     *
     * Why chain mode works:
     *   In TCH mode the DMA follows des3 (the chain pointer) to find the
     *   next descriptor.  The DMA ONLY writes back to des0; des1/des2/des3
     *   are never touched.  So des3 chain pointers survive indefinitely and
     *   the ring wraps reliably without re-reading des0. */
    for (i = 0; i < TX_DESC_COUNT; i++) {
        tx_ring[i].des0 = 0;
        tx_ring[i].des1 = 0;
        tx_ring[i].des2 = (uint32_t)tx_buffers[i];
        /* Chain: each descriptor points to the next; last wraps to first */
        tx_ring[i].des3 = (uint32_t)&tx_ring[(i + 1U) % TX_DESC_COUNT];
    }
    /* No TDES0_TER needed - chain pointers in des3 replace ring-mode wrap */

    /* Initialize RX descriptors - DMA owns (OWN=1) */
    for (i = 0; i < RX_DESC_COUNT; i++) {
        rx_ring[i].des0 = RDES0_OWN;
        rx_ring[i].des1 = (RX_BUF_SIZE & RDES1_RBS1_MASK);
        rx_ring[i].des2 = (uint32_t)rx_buffers[i];
        rx_ring[i].des3 = 0;
    }
    /* Set RER on last RX descriptor for ring wrap */
    rx_ring[RX_DESC_COUNT - 1U].des1 |= RDES1_RER;

    rx_idx = 0;
    tx_idx = 0;

    __DSB();

    /* Program descriptor list base addresses */
    VOR_ETH->DMA_RX_DESC_LIST_ADDR = (uint32_t)&rx_ring[0];
    VOR_ETH->DMA_TX_DESC_LIST_ADDR = (uint32_t)&tx_ring[0];

    __DSB();
}

/* ========================================================================= */
/* Start / Stop                                                              */
/* ========================================================================= */

static void eth_start(void)
{
    /* Ensure MMC counters are not frozen (bit 3 = freeze) */
    VOR_ETH->MMC_CNTRL &= ~(1U << 3);

    /* Enable MAC TX and RX */
    VOR_ETH->MAC_CONFIG |= ETH_MAC_CONFIG_TE_Msk | ETH_MAC_CONFIG_RE_Msk;

    /* Settling delay after TE/RE assertion.
     * The DWC GMAC needs time for the TX/RX FIFO controllers to initialize
     * after TE/RE are set.  Without sufficient delay, the DMA may start
     * before the FIFOs are ready, causing silent frame drops.
     * 100K cycles at 100MHz = ~1ms — matches delay previously provided
     * by debug printf statements between init steps. */
    { volatile uint32_t _d; for (_d = 0; _d < 100000U; _d++) { } }

    /* Start DMA TX and RX via DMA_OPER_MODE */
    VOR_ETH->DMA_OPER_MODE |= ETH_DMA_OPER_MODE_ST_Msk |
                               ETH_DMA_OPER_MODE_SR_Msk;

    __DSB();

    /* Settling delay after DMA start.
     * NOTE: FTF (Flush TX FIFO, bit 20) is intentionally NOT set here.
     * Testing showed FTF (even after ST=1) may latch on this silicon and
     * permanently flush any data the DMA writes to the TX FIFO, keeping
     * hw_tx=0. The TX FIFO is already empty after SWR so no flush is needed. */
    { volatile uint32_t _d; for (_d = 0; _d < 100000U; _d++) { } }

    {
        uint32_t oper = VOR_ETH->DMA_OPER_MODE;
        printf("  DMA_OPER_MODE=0x%08lX (FTF=%lu TSF=%lu TTC=%lu ST=%lu)\n",
               (unsigned long)oper,
               (unsigned long)!!(oper & ETH_DMA_OPER_MODE_FTF_Msk),
               (unsigned long)!!(oper & ETH_DMA_OPER_MODE_TSF_Msk),
               (unsigned long)((oper & ETH_DMA_OPER_MODE_TTC_Msk) >> ETH_DMA_OPER_MODE_TTC_Pos),
               (unsigned long)!!(oper & ETH_DMA_OPER_MODE_ST_Msk));
    }

    /* Kick RX DMA to start processing descriptors */
    VOR_ETH->DMA_RX_POLL_DEMAND = 0;

    ETH_DEBUG("  MAC_CONFIG:    0x%08lX\n",
              (unsigned long)VOR_ETH->MAC_CONFIG);
    ETH_DEBUG("  DMA_BUS_MODE:  0x%08lX\n",
              (unsigned long)VOR_ETH->DMA_BUS_MODE);
    ETH_DEBUG("  DMA_OPER_MODE: 0x%08lX\n",
              (unsigned long)VOR_ETH->DMA_OPER_MODE);
}

static void eth_stop(void)
{
    /* Stop DMA TX and RX */
    VOR_ETH->DMA_OPER_MODE &= ~(ETH_DMA_OPER_MODE_ST_Msk |
                                  ETH_DMA_OPER_MODE_SR_Msk);

    /* Disable MAC TX and RX */
    VOR_ETH->MAC_CONFIG &= ~(ETH_MAC_CONFIG_TE_Msk | ETH_MAC_CONFIG_RE_Msk);
}

/* ========================================================================= */
/* PHY Initialization (uses SDK HAL)                                         */
/* ========================================================================= */

static int eth_phy_init(void)
{
    uint16_t phy_status;
    uint16_t phy_id_hi;
    uint32_t timeout;

    /* Set GMII clock divider in MAC_GMII_ADDR.CR field
     * PEB1 EVK: 40MHz crystal * PLL 2.5x = 100MHz -> DIV42 (60-100MHz)
     * MDIO clock: 100MHz / 42 = 2.38MHz (within 1-2.5MHz spec)
     */
    VOR_ETH->MAC_GMII_ADDR = (VOR_ETH->MAC_GMII_ADDR &
        ~ETH_MAC_GMII_ADDR_CR_Msk) |
        (PHY_MACMII_CR_DIV42 << ETH_MAC_GMII_ADDR_CR_Pos);

    /* Read PHY ID to verify communication */
    if (HAL_ReadPhyReg(PHY_ID_HI_REG, &phy_id_hi) != hal_status_ok) {
        printf("  PHY: MDIO read failed\n");
        return -1; /* MDIO communication failed */
    }
    mdio_settle();
    HAL_ReadPhyReg(PHY_ID_HI_REG, &phy_id_hi); /* double-read */
    mdio_settle();
    ETH_DEBUG("  PHY ID: 0x%04X\n", phy_id_hi);
    if (phy_id_hi == 0xFFFFU || phy_id_hi == 0x0000U) {
        printf("  PHY: not found (ID=0x%04X)\n", phy_id_hi);
        return -1; /* PHY not found */
    }

    /* Reset PHY */
    HAL_ResetPHY();

    /* Wait for PHY reset to complete.
     * KSZ8041TL datasheet: reset completes in ~100-300 ms.
     * Previous wait of 100K cycles (~1 ms) was far too short — the PHY
     * was still resetting when we started configuring it, so the AN
     * advertisement write was likely lost.
     * 50M iterations at 100 MHz ≈ 500 ms — conservative but safe. */
    ETH_DEBUG("  PHY: waiting for reset (~500ms)...\n");
    for (volatile uint32_t i = 0; i < 50000000U; i++) { }

    /* Verify PHY reset completed: bit 15 (RESET) in BMCR should auto-clear */
    {
        uint16_t cr;
        HAL_ReadPhyReg(PHY_CONTROL_REG, &cr);
        mdio_settle();
        HAL_ReadPhyReg(PHY_CONTROL_REG, &cr);
        mdio_settle();
        ETH_DEBUG("  PHY BMCR after reset: 0x%04X (bit15=%u)\n",
                  cr, (unsigned)((cr >> 15) & 1));
    }

    /* Configure Auto-Negotiation advertisement.
     *
     * Why AN instead of forced mode:
     *   With AN disabled and the PHY forced to a specific speed/duplex,
     *   the link partner (switch) still runs auto-negotiation.  Without
     *   an AN exchange it detects speed (from link pulses) but defaults
     *   to Half Duplex.  Result: duplex mismatch → switch drops our FD
     *   TX frames as "collisions" while RX still works.
     *
     *   With AN enabled, both sides agree on speed and duplex — no
     *   mismatch.
     *
     * PHY AN Advertisement Register (reg 4) bit layout:
     *   [8] 100BASE-TX FD  [7] 100BASE-TX HD  [6] 10BASE-T FD
     *   [5] 10BASE-T HD    [4:0] selector (00001 = 802.3)
     *
     * Advertise all supported speeds (10M + 100M, HD + FD).
     * eth_config_speed_duplex() will configure the MAC to match whatever
     * the PHY actually negotiates.  If the MAC FES bit is read-only=0,
     * 100M TX won't work but the driver logs a warning. */
    {
        uint16_t an_adv, an_readback;
        HAL_ReadPhyReg(PHY_AN_ADV_REG, &an_adv);
        mdio_settle();
        HAL_ReadPhyReg(PHY_AN_ADV_REG, &an_adv); /* double-read */
        mdio_settle();
        ETH_DEBUG("  PHY AN adv (before): 0x%04X\n", an_adv);
        an_adv &= ~0x0200U;  /* clear 100BASE-T4 (not supported) */
        an_adv |=  0x01E0U;  /* set 100M-FD, 100M-HD, 10M-FD, 10M-HD */
        HAL_WritePhyReg(PHY_AN_ADV_REG, an_adv);
        mdio_settle();

        /* Readback verification: confirm the write actually reached the PHY.
         * If this doesn't match, the MDIO write was lost. */
        HAL_ReadPhyReg(PHY_AN_ADV_REG, &an_readback);
        mdio_settle();
        HAL_ReadPhyReg(PHY_AN_ADV_REG, &an_readback); /* double-read */
        mdio_settle();
        ETH_DEBUG("  PHY AN adv: wrote=0x%04X read=0x%04X %s\n",
                  an_adv, an_readback,
                  (an_readback == an_adv) ? "OK" : "MISMATCH!");
    }

    /* Enable AN and restart it */
    HAL_SetPhyAutoNegotiate(PHYAUTONEGEN);
    mdio_settle();
    {
        uint16_t cr;
        HAL_ReadPhyReg(PHY_CONTROL_REG, &cr);
        mdio_settle();
        HAL_ReadPhyReg(PHY_CONTROL_REG, &cr); /* double-read */
        mdio_settle();
        cr |= 0x0200U; /* restart AN (bit 9) */
        HAL_WritePhyReg(PHY_CONTROL_REG, cr);
        mdio_settle();
    }
    ETH_DEBUG("  PHY AN: enabled, restart issued\n");

    /* Wait for link up.
     *
     * With MDIO settling delays (~50 µs each), each loop iteration now
     * takes real wall time.  With double-read + 2x settle = ~100 µs per
     * iteration, 50K iterations ≈ 5 seconds — enough for AN to complete
     * (typically 1-2 seconds). */
    timeout = 50000U;
    do {
        HAL_ReadPhyReg(PHY_STATUS_REG, &phy_status);
        mdio_settle();
        HAL_ReadPhyReg(PHY_STATUS_REG, &phy_status); /* double-read: latch */
        mdio_settle();
    } while (!(phy_status & MIISTATUS_PHY_LINK) && --timeout);

    printf("  PHY link: %s\n",
           (phy_status & MIISTATUS_PHY_LINK) ? "UP" : "DOWN");

    /* Read KSZ8041TL PHY Control 2 (reg 0x1F) to confirm actual
     * negotiated speed/duplex.  Bits [6:4] = Operation Mode:
     *   001=10HD  010=100HD  101=10FD  110=100FD */
    {
        uint16_t ctrl2;
        HAL_ReadPhyReg(PHY_CTRL2_REG, &ctrl2);
        mdio_settle();
        HAL_ReadPhyReg(PHY_CTRL2_REG, &ctrl2); /* double-read */
        mdio_settle();
        ETH_DEBUG("  PHY Ctrl2: 0x%04X OpMode[6:4]=%u\n",
                  ctrl2, (unsigned)((ctrl2 >> 4) & 0x7));
    }

    /* Read BMCR and BMSR for diagnostics */
    {
        uint16_t cr, sr;
        HAL_ReadPhyReg(PHY_CONTROL_REG, &cr);
        mdio_settle();
        HAL_ReadPhyReg(PHY_CONTROL_REG, &cr);
        mdio_settle();
        HAL_ReadPhyReg(PHY_STATUS_REG, &sr);
        mdio_settle();
        HAL_ReadPhyReg(PHY_STATUS_REG, &sr);
        mdio_settle();
        ETH_DEBUG("  PHY BMCR=0x%04X BMSR=0x%04X\n", cr, sr);
        ETH_DEBUG("    AN_complete=%u link=%u speed100=%u duplex=%u\n",
                  (unsigned)((sr >> 5) & 1),
                  (unsigned)((sr >> 2) & 1),
                  (unsigned)((cr >> 13) & 1),
                  (unsigned)((cr >> 8) & 1));
    }

    return (phy_status & MIISTATUS_PHY_LINK) ? 0 : -2;
}

/* ========================================================================= */
/* Poll (RX) - Called from wolfIP_poll()                                     */
/* ========================================================================= */

static int eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct eth_desc *desc;
    uint32_t status;
    uint32_t frame_len = 0;

    (void)dev;
    rx_poll_count++;

    desc = &rx_ring[rx_idx];

    /* Check if DMA still owns this descriptor */
    if (desc->des0 & RDES0_OWN)
        return 0;

    rx_pkt_count++;
    status = desc->des0;

    /* Check for complete single-frame (FS + LS) with no errors */
    if (((status & (RDES0_FS | RDES0_LS)) == (RDES0_FS | RDES0_LS)) &&
        !(status & RDES0_ES)) {
        /* Extract frame length from RDES0[29:16] */
        frame_len = (status & RDES0_FL_MASK) >> RDES0_FL_SHIFT;
        if (frame_len > len)
            frame_len = len;

        /* Copy via staging buffer (avoids DMA/CPU bus contention) */
        memcpy(rx_staging_buffer, rx_buffers[rx_idx], frame_len);
        memcpy(frame, rx_staging_buffer, frame_len);

#ifdef DEBUG_ETH
        /* Print header of first 10 received frames for diagnostics */
        if (rx_pkt_count <= 10 && frame_len >= 14) {
            uint8_t *f = (uint8_t *)frame;
            ETH_DEBUG("RX[%lu] len=%lu dst=%02X:%02X:%02X:%02X:%02X:%02X "
                      "src=%02X:%02X:%02X:%02X:%02X:%02X type=%02X%02X\n",
                      (unsigned long)rx_pkt_count, (unsigned long)frame_len,
                      f[0], f[1], f[2], f[3], f[4], f[5],
                      f[6], f[7], f[8], f[9], f[10], f[11],
                      f[12], f[13]);
            if (f[12] == 0x08 && f[13] == 0x06 && frame_len >= 42) {
                ETH_DEBUG("  ARP op=%u target=%u.%u.%u.%u\n",
                          (unsigned)((f[20] << 8) | f[21]),
                          f[38], f[39], f[40], f[41]);
            }
        }
#endif
    }

    /* Re-arm descriptor: give back to DMA */
    desc->des0 = RDES0_OWN;
    desc->des1 = (RX_BUF_SIZE & RDES1_RBS1_MASK);
    /* Preserve RER on last descriptor */
    if (rx_idx == (RX_DESC_COUNT - 1U))
        desc->des1 |= RDES1_RER;

    __DSB();

    /* Clear RU (Receive Buffer Unavailable) if set */
    if (VOR_ETH->DMA_STATUS & ETH_DMA_STATUS_RU_Msk) {
        VOR_ETH->DMA_STATUS = ETH_DMA_STATUS_RU_Msk;
    }

    /* Kick RX DMA to resume polling */
    VOR_ETH->DMA_RX_POLL_DEMAND = 0;

    rx_idx = (rx_idx + 1U) % RX_DESC_COUNT;
    return (int)frame_len;
}

/* ========================================================================= */
/* Send (TX) - Called from wolfIP stack                                      */
/* ========================================================================= */

static int eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct eth_desc *desc;
    uint32_t dma_len;

    (void)dev;
    if (len == 0 || len > TX_BUF_SIZE) {
        tx_err_count++;
        return -1;
    }

    desc = &tx_ring[tx_idx];

    /* Check if CPU owns this descriptor (OWN=0) */
    if (desc->des0 & TDES0_OWN) {
        tx_err_count++;
        return -2;
    }

    tx_pkt_count++;

#ifdef DEBUG_ETH
    /* Print frame header for first few packets */
    if (tx_pkt_count <= 8) {
        uint8_t *f = (uint8_t *)frame;
        ETH_DEBUG("TX[%lu] len=%lu dst=%02X:%02X:%02X:%02X:%02X:%02X "
                  "src=%02X:%02X:%02X:%02X:%02X:%02X type=%02X%02X\n",
                  (unsigned long)tx_idx, (unsigned long)len,
                  f[0], f[1], f[2], f[3], f[4], f[5],
                  f[6], f[7], f[8], f[9], f[10], f[11],
                  f[12], f[13]);
        if (f[12] == 0x08 && f[13] == 0x06 && len >= 42) {
            ETH_DEBUG("  ARP op=%u sender=%u.%u.%u.%u target=%u.%u.%u.%u\n",
                      (unsigned)((f[20] << 8) | f[21]),
                      f[28], f[29], f[30], f[31],
                      f[38], f[39], f[40], f[41]);
        }
    }
#endif

    /* Copy frame to DMA buffer */
    memcpy(tx_buffers[tx_idx], frame, len);

    /* Pad to minimum frame size */
    dma_len = (len < FRAME_MIN_LEN) ? FRAME_MIN_LEN : len;
    if (dma_len > len)
        memset(tx_buffers[tx_idx] + len, 0, dma_len - len);

    /* Set buffer address in des2 */
    desc->des2 = (uint32_t)tx_buffers[tx_idx];

    /* Set buffer size in des1 */
    desc->des1 = (dma_len & TDES1_TBS1_MASK);

    __DSB();

    /* Set des0: OWN + FS + LS + IC + TCH (chain mode).
     * TCH=1 tells the DMA to follow des3 (chain pointer) to find the
     * next descriptor rather than advancing linearly.  des3 was set
     * permanently in eth_init_desc() and is never overwritten by DMA
     * writeback, so it reliably wraps the ring.
     * Build complete value first to avoid race with DMA. */
    {
        uint32_t des0_val = TDES0_OWN | TDES0_FS | TDES0_LS |
                            TDES0_IC  | TDES0_TCH;
        desc->des0 = des0_val;
    }

    __DSB();

    /* Capture MAC_DEBUG BEFORE kick for first few TX diagnostics.
     * TXFSTS bits [25:24] show TX FIFO fill level from any previous frame.
     * If TXFSTS≠0 before kick, prior frame is still in FIFO (MAC not draining). */
    {
        uint32_t mac_dbg_before = (tx_pkt_count <= 5U) ? VOR_ETH->MAC_DEBUG : 0U;

        /* Clear TU (Transmit Buffer Unavailable) if set */
        if (VOR_ETH->DMA_STATUS & ETH_DMA_STATUS_TU_Msk) {
            VOR_ETH->DMA_STATUS = ETH_DMA_STATUS_TU_Msk;
        }

        /* Kick TX DMA to start polling descriptors */
        VOR_ETH->DMA_TX_POLL_DEMAND = 0;

        /* Diagnostic: dump DMA state and TX FIFO status at three time points.
         *
         * At 10M MII a 60-byte frame takes ~48µs to transmit (2.5MHz nibble clock).
         * Sampling MAC_DEBUG at ~10µs catches the MAC mid-transmission.
         * Sampling at ~500µs should show an empty FIFO if MAC TX worked.
         *
         * MAC_DEBUG bits of interest:
         *   [25:24] TXFSTS  — TX FIFO fill: 0=empty,1=≥threshold,2=full,3=not-empty
         *   [21:20] TRCSTS  — MAC TX read state: 0=idle,1=waiting,2=pause,3=transfer
         *   [18:17] TFCSTS  — MAC TX flow-ctrl: 0=idle,1=wait,2=pause,3=xfr-data
         *   [16]    TPESTS  — MAC TX paused
         * If TXFSTS≠0 at 10µs but =0 at 500µs → MAC transmitted ✓
         * If TXFSTS≠0 at both → MAC TX stuck (TXCLK missing or FIFO not draining)
         * If TXFSTS=0 at both → DMA did NOT write to TX FIFO! */
        if (tx_pkt_count <= 5U) {
            volatile uint32_t _d;
            uint32_t mac_dbg_imm, mac_dbg_10us, mac_dbg_500us;
            uint32_t dma_st, dma_oper, des0_wb, cur_desc, cur_bufr;

            /* Sample immediately after kick (DMA just started, FIFO not yet filled) */
            mac_dbg_imm = VOR_ETH->MAC_DEBUG;

            /* ~10µs: DMA has written frame to FIFO, MAC may be mid-transmission */
            for (_d = 0; _d < 1000U; _d++) { }
            mac_dbg_10us = VOR_ETH->MAC_DEBUG;

            /* ~500µs: well past 10M 60-byte TX time (48µs), FIFO should be empty */
            for (_d = 0; _d < 50000U; _d++) { }
            mac_dbg_500us = VOR_ETH->MAC_DEBUG;

            dma_st   = VOR_ETH->DMA_STATUS;
            dma_oper = VOR_ETH->DMA_OPER_MODE;
            des0_wb  = desc->des0;
            cur_desc = VOR_ETH->DMA_CURR_TX_DESC;
            cur_bufr = VOR_ETH->DMA_CURR_TX_BUFR_ADDR;

            printf("  TX#%lu: des0_set=0x%08lX des0_wb=0x%08lX "
                   "des1=0x%08lX des2=0x%08lX des3=0x%08lX\n",
                   (unsigned long)tx_pkt_count,
                   (unsigned long)(TDES0_OWN | TDES0_FS | TDES0_LS |
                                   TDES0_IC  | TDES0_TCH),
                   (unsigned long)des0_wb,
                   (unsigned long)desc->des1,
                   (unsigned long)desc->des2,
                   (unsigned long)desc->des3);
            printf("  DMA_STATUS=0x%08lX TS=%lu cur_desc=0x%08lX cur_bufr=0x%08lX\n",
                   (unsigned long)dma_st,
                   (unsigned long)((dma_st >> 20) & 0x7U),
                   (unsigned long)cur_desc,
                   (unsigned long)cur_bufr);
            printf("  DMA_OPER=0x%08lX FTF=%lu TSF=%lu ST=%lu\n",
                   (unsigned long)dma_oper,
                   (unsigned long)!!(dma_oper & ETH_DMA_OPER_MODE_FTF_Msk),
                   (unsigned long)!!(dma_oper & ETH_DMA_OPER_MODE_TSF_Msk),
                   (unsigned long)!!(dma_oper & ETH_DMA_OPER_MODE_ST_Msk));
            printf("  MAC_DEBUG: bef=0x%08lX imm=0x%08lX @10us=0x%08lX @500us=0x%08lX\n",
                   (unsigned long)mac_dbg_before,
                   (unsigned long)mac_dbg_imm,
                   (unsigned long)mac_dbg_10us,
                   (unsigned long)mac_dbg_500us);
            printf("  TXFSTS: bef=%lu imm=%lu @10us=%lu @500us=%lu  "
                   "TRCSTS: @10us=%lu @500us=%lu\n",
                   (unsigned long)((mac_dbg_before >> 24) & 3U),
                   (unsigned long)((mac_dbg_imm    >> 24) & 3U),
                   (unsigned long)((mac_dbg_10us   >> 24) & 3U),
                   (unsigned long)((mac_dbg_500us  >> 24) & 3U),
                   (unsigned long)((mac_dbg_10us   >> 20) & 3U),
                   (unsigned long)((mac_dbg_500us  >> 20) & 3U));
            if (dma_st & (1U << 13))
                printf("  *** FATAL BUS ERROR (FBI) ***\n");
            if (des0_wb & (1U << 15))
                printf("  *** TX ERROR SUMMARY (ES): des0=0x%08lX ***\n",
                       (unsigned long)des0_wb);
            if (dma_oper & ETH_DMA_OPER_MODE_FTF_Msk)
                printf("  *** FTF IS STILL SET - TX FIFO STUCK IN FLUSH ***\n");
        }
    }

    tx_idx = (tx_idx + 1U) % TX_DESC_COUNT;
    return (int)len;
}

/* ========================================================================= */
/* Default MAC Address                                                       */
/* ========================================================================= */

static void va416xx_eth_generate_mac(uint8_t mac[6])
{
    mac[0] = 0x02;  /* locally administered */
    mac[1] = 0x11;
    mac[2] = 0xAA;
    mac[3] = 0xBB;
    mac[4] = 0x44; /* '4' for VA416xx */
    mac[5] = 0x16;
}

/* ========================================================================= */
/* Statistics                                                                */
/* ========================================================================= */

void va416xx_eth_get_stats(uint32_t *polls, uint32_t *pkts, uint32_t *tx_pkts,
                           uint32_t *tx_errs)
{
    if (polls)    *polls    = rx_poll_count;
    if (pkts)     *pkts     = rx_pkt_count;
    if (tx_pkts)  *tx_pkts  = tx_pkt_count;
    if (tx_errs)  *tx_errs  = tx_err_count;
}

uint32_t va416xx_eth_get_dma_status(void)
{
    return VOR_ETH->DMA_STATUS;
}

void va416xx_eth_get_mac_diag(uint32_t *mac_cfg, uint32_t *mac_dbg,
                               uint32_t *tx_frames_gb)
{
    if (mac_cfg)      *mac_cfg      = VOR_ETH->MAC_CONFIG;
    if (mac_dbg)      *mac_dbg      = VOR_ETH->MAC_DEBUG;
    if (tx_frames_gb) *tx_frames_gb = VOR_ETH->TXFRAMECOUNT_GB;
}

/* ========================================================================= */
/* Initialization                                                            */
/* ========================================================================= */

int va416xx_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    uint8_t local_mac[6];
    int ret;

    if (ll == NULL)
        return -1;

    if (mac == NULL) {
        va416xx_eth_generate_mac(local_mac);
        mac = local_mac;
    }

    memcpy(ll->mac, mac, 6);
    strncpy(ll->ifname, "eth0", sizeof(ll->ifname) - 1);
    ll->ifname[sizeof(ll->ifname) - 1] = '\0';
    ll->poll = eth_poll;
    ll->send = eth_send;

    /* 1. Stop any running DMA/MAC */
    eth_stop();

    /* 2. DMA Software Reset */
    if (eth_hw_reset() != 0)
        return -2;

    /* 3. Configure DMA (bus mode, operation mode) */
    eth_config_dma();

    /* 4. Initialize descriptor rings */
    eth_init_desc();

    /* 5. Configure MAC (address, speed, duplex, filter) */
    eth_config_mac(mac);

    /* 6. Initialize PHY via SDK HAL */
    ret = eth_phy_init();

    /* 7. Configure MAC speed/duplex.  Always run this regardless of link
     *    state so MAC_CONFIG is correct even if link came up late. */
    eth_config_speed_duplex();

    /* Settling delay between MAC config and DMA start.
     * The MAC clock domain needs time to stabilize after speed/duplex
     * changes before the DMA engines are started.  Previously, debug
     * printf statements between these steps provided ~10-50ms of implicit
     * delay; now we add it explicitly. */
    { volatile uint32_t _d; for (_d = 0; _d < 500000U; _d++) { } } /* ~5ms */

    /* 8. Start MAC and DMA */
    eth_start();

    return ret;
}

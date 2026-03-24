/* stm32_eth.c
 *
 * Common Ethernet MAC/PHY driver for STM32H5, STM32H7 and STM32N6.
 *
 * Copyright (C) 2024-2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 */
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "stm32_eth.h"

#if !defined(STM32H5) && !defined(STM32H7) && !defined(STM32N6)
#error "Define STM32H5, STM32H7 or STM32N6 for stm32_eth.c"
#endif

#if defined(STM32H5)
#if TZEN_ENABLED
#define ETH_BASE            0x50028000UL  /* Secure alias */
#else
#define ETH_BASE            0x40028000UL  /* Non-secure alias */
#endif
#define STM32_ETH_NEEDS_MDIO_DELAY 0
#elif defined(STM32H7)
#define ETH_BASE            0x40028000UL
#define STM32_ETH_NEEDS_MDIO_DELAY 1
#elif defined(STM32N6)
#define ETH_BASE            0x58036000UL  /* ETH1 on AHB5, secure alias */
#define STM32_ETH_NEEDS_MDIO_DELAY 1     /* M55 at 600MHz needs stabilization */
#endif

/* MDIO clock divider: CR field in ETH_MACMDIOAR.
 * CR=0: 20-35MHz, CR=1: 35-60MHz, CR=2: 60-100MHz,
 * CR=3: 100-150MHz, CR=4: 150-250MHz, CR=5: 250-300MHz
 * STM32N6 at HSI: HCLK ~32MHz → CR=0
 * STM32N6 at PLL: HCLK 250-300MHz → CR=5
 * STM32H5/H7: HCLK 150-250MHz → CR=4 */
#if defined(STM32N6)
#define MDIO_CR_VALUE 4U  /* PLL: AHB5 ~200MHz → CR=4 (150-250MHz range) */
#else
#define MDIO_CR_VALUE 4U
#endif

#define ETH_REG(offset)     (*(volatile uint32_t *)(ETH_BASE + (offset)))
#define ETH_TPDR            ETH_REG(0x1180U)

/* MAC registers */
#define ETH_MACCR           ETH_REG(0x0000U)
#define ETH_MACECR          ETH_REG(0x0004U)  /* Extended Configuration */
#define ETH_MACPFR          ETH_REG(0x0008U)  /* Packet Filter */
#define ETH_MACWTR          ETH_REG(0x000CU)  /* Watchdog Timeout */
#define ETH_MACQ0TXFCR      ETH_REG(0x0070U)  /* TX Flow Control Q0 */
#define ETH_MACRXFCR        ETH_REG(0x0090U)  /* RX Flow Control */
#define ETH_MAC1USTCR       ETH_REG(0x00DCU)
#define ETH_MACA0HR         ETH_REG(0x0300U)
#define ETH_MACA0LR         ETH_REG(0x0304U)
#if defined(STM32H7) || defined(STM32N6)
#define ETH_MACRXQC0R       ETH_REG(0x00A0U)
#endif

/* MTL registers */
#define ETH_MTLOMR          ETH_REG(0x0C00U)  /* MTL Operation Mode */
#define ETH_MTLTXQOMR       ETH_REG(0x0D00U)  /* MTL TX Q0 Operation Mode */
#define ETH_MTLRXQOMR       ETH_REG(0x0D30U)  /* MTL RX Q0 Operation Mode */
#define ETH_MTLRXQDMAMR     ETH_REG(0x0C30U)  /* RX Queue to DMA Mapping */

/* DMA registers */
#define ETH_DMAMR           ETH_REG(0x1000U)
#define ETH_DMASBMR         ETH_REG(0x1004U)
#define ETH_DMACCR          ETH_REG(0x1100U)
#define ETH_DMACTXCR        ETH_REG(0x1104U)
#define ETH_DMACRXCR        ETH_REG(0x1108U)
#define ETH_DMACTXDLAR      ETH_REG(0x1114U)
#define ETH_DMACRXDLAR      ETH_REG(0x111CU)
#define ETH_DMACTXDTPR      ETH_REG(0x1120U)
#define ETH_DMACRXDTPR      ETH_REG(0x1128U)
#define ETH_DMACTXRLR       ETH_REG(0x112CU)
#define ETH_DMACRXRLR       ETH_REG(0x1130U)
#define ETH_DMACSR          ETH_REG(0x1160U)
#define ETH_DMACIER         ETH_REG(0x1134U)  /* DMA CH0 Interrupt Enable */
#define ETH_DMACIER_NIE     (1U << 15)  /* Normal Interrupt Summary Enable */
#define ETH_DMACIER_AIE     (1U << 14)  /* Abnormal Interrupt Summary Enable */
#define ETH_DMACIER_RBUE    (1U << 7)   /* RX Buffer Unavailable Enable */
#define ETH_DMACIER_RIE     (1U << 6)   /* Receive Interrupt Enable */
#define ETH_DMACIER_TIE     (1U << 0)   /* Transmit Interrupt Enable */
#define ETH_MACMDIOAR       ETH_REG(0x0200U)
#define ETH_MACMDIODR       ETH_REG(0x0204U)

/* N6 DMA Channel 1 registers (offset 0x80 from CH0) */
#if defined(STM32N6)
#define ETH_DMAC1CR         ETH_REG(0x1180U)
#define ETH_DMAC1TXCR       ETH_REG(0x1184U)
#define ETH_DMAC1RXCR       ETH_REG(0x1188U)
#define ETH_DMAC1TXDLAR     ETH_REG(0x1194U)
#define ETH_DMAC1RXDLAR     ETH_REG(0x119CU)
#define ETH_DMAC1TXDTPR     ETH_REG(0x11A0U)
#define ETH_DMAC1RXDTPR     ETH_REG(0x11A8U)
#define ETH_DMAC1TXRLR      ETH_REG(0x11ACU)
#define ETH_DMAC1RXRLR      ETH_REG(0x11B0U)
#define ETH_DMAC1SR         ETH_REG(0x11E0U)
#define ETH_DMAC1IER        ETH_REG(0x11B4U)  /* DMA CH1 Interrupt Enable */
#define ETH_MTLTXQ1OMR      ETH_REG(0x0D40U)
#endif

/* MAC control bits */
#define ETH_MACCR_RE        (1U << 0)
#define ETH_MACCR_TE        (1U << 1)
#define ETH_MACCR_DM        (1U << 13)
#define ETH_MACCR_FES       (1U << 14)
#define ETH_MACCR_PS        (1U << 15)  /* Port Select: 1=MII/RMII, 0=GMII */

/* DMA bits */
#define ETH_DMAMR_SWR       (1U << 0)
#define ETH_DMASBMR_FB      (1U << 0)
#define ETH_DMASBMR_AAL     (1U << 12)

#define ETH_DMACTXCR_ST     (1U << 0)
#define ETH_DMACTXCR_OSF    (1U << 4)
#define ETH_DMACRXCR_SR     (1U << 0)
#define ETH_DMACRXCR_RBSZ_SHIFT 1
#define ETH_DMACSR_TBU      (1U << 2)
#define ETH_DMACTXCR_TPBL_SHIFT 16
#define ETH_DMACTXCR_TPBL(val) (((uint32_t)(val) & 0x3FU) << ETH_DMACTXCR_TPBL_SHIFT)
#define ETH_DMACRXCR_RPBL_SHIFT 16
#define ETH_DMACRXCR_RPBL(val) (((uint32_t)(val) & 0x3FU) << ETH_DMACRXCR_RPBL_SHIFT)

/* MTL bits */
#define ETH_MTLTXQOMR_FTQ           (1U << 0)
#define ETH_MTLTXQOMR_TSF           (1U << 1)
#define ETH_MTLTXQOMR_TXQEN_SHIFT   2
#define ETH_MTLTXQOMR_TXQEN_ENABLE  (2U << ETH_MTLTXQOMR_TXQEN_SHIFT)
#define ETH_MTLTXQOMR_TQS_SHIFT     16  /* TX Queue Size */
#define ETH_MTLTXQOMR_TQS_2048      (0x7U << ETH_MTLTXQOMR_TQS_SHIFT)  /* 2KB */
#define ETH_MTLTXQOMR_MASK          0x00070072U
#define ETH_MTLRXQOMR_RSF           (1U << 5)
#define ETH_MTLRXQOMR_RQS_SHIFT     20  /* RX Queue Size */
#define ETH_MTLRXQOMR_RQS_4096      (0xFU << ETH_MTLRXQOMR_RQS_SHIFT)  /* 4KB */
#define ETH_MTLRXQOMR_DEHF          (1U << 6)  /* Drop Error Half Frame */
#define ETH_MTLRXQOMR_MASK          0x00F0007FU

/* MDIO bits */
#define ETH_MACMDIOAR_MB        (1U << 0)
#define ETH_MACMDIOAR_GOC_SHIFT 2
#define ETH_MACMDIOAR_GOC_WRITE 0x1U
#define ETH_MACMDIOAR_GOC_READ  0x3U
#define ETH_MACMDIOAR_CR_SHIFT  8
#define ETH_MACMDIOAR_RDA_SHIFT 16
#define ETH_MACMDIOAR_PA_SHIFT  21

/* PHY registers */
#define PHY_REG_BCR      0x00U
#define PHY_REG_BSR      0x01U
#define PHY_REG_ID1      0x02U
#define PHY_REG_ANAR     0x04U

/* PHY BCR bits */
#define PHY_BCR_RESET            (1U << 15)
#define PHY_BCR_SPEED_100        (1U << 13)
#define PHY_BCR_AUTONEG_ENABLE   (1U << 12)
#define PHY_BCR_POWER_DOWN       (1U << 11)
#define PHY_BCR_ISOLATE          (1U << 10)
#define PHY_BCR_RESTART_AUTONEG  (1U << 9)
#define PHY_BCR_FULL_DUPLEX      (1U << 8)

/* PHY BSR bits */
#define PHY_BSR_LINK_STATUS      (1U << 2)
#define PHY_BSR_AUTONEG_COMPLETE (1U << 5)
#define PHY_BSR_10_HALF          (1U << 11)
#define PHY_BSR_10_FULL          (1U << 12)
#define PHY_BSR_100_HALF         (1U << 13)
#define PHY_BSR_100_FULL         (1U << 14)

#define PHY_ANAR_DEFAULT 0x01E1U

/* DMA descriptor structure.
 * On N6 GMAC v5.20, DSL=1 skips 1 doubleword (8 bytes) between
 * 16-byte descriptors → stride = 24 bytes. HAL uses 6-field struct
 * (DESC0-3 + BackupAddr0/1). */
struct eth_desc {
    volatile uint32_t des0;
    volatile uint32_t des1;
    volatile uint32_t des2;
    volatile uint32_t des3;
#if defined(STM32N6)
    volatile uint32_t _pad[2]; /* DSL=1: 8-byte skip (1 doubleword) */
#endif
};

/* Descriptor bits */
#define ETH_TDES3_OWN      (1U << 31)
#define ETH_TDES3_FD       (1U << 29)
#define ETH_TDES3_LD       (1U << 28)
#define ETH_TDES2_B1L_MASK (0x3FFFU)
#define ETH_TDES3_FL_MASK  (0x7FFFU)

#define ETH_RDES3_OWN      (1U << 31)
#define ETH_RDES3_IOC      (1U << 30)
#define ETH_RDES3_BUF1V    (1U << 24)
#define ETH_RDES3_FS       (1U << 29)
#define ETH_RDES3_LS       (1U << 28)
#define ETH_RDES3_PL_MASK  (0x3FFFU)

/* Configuration */
#define RX_DESC_COUNT  4U
#define TX_DESC_COUNT  3U
#define RX_BUF_SIZE    LINK_MTU
#define TX_BUF_SIZE    LINK_MTU
#define FRAME_MIN_LEN  60U
#define DMA_TPBL       32U
#define DMA_RPBL       32U

#if defined(STM32H7) || defined(STM32N6)
#define ETH_SECTION __attribute__((section(".eth_buffers")))
#elif defined(STM32H5)
#if TZEN_ENABLED
#define ETH_SECTION __attribute__((section(".eth_buffers")))
#else
#define ETH_SECTION
#endif
#endif

/* DMA buffer address — use secure alias (0x34), matching RISAF SEC=1. */
#define ETH_DMA_ADDR(ptr) ((uint32_t)(ptr))

static struct eth_desc rx_ring[RX_DESC_COUNT] __attribute__((aligned(32))) ETH_SECTION;
static struct eth_desc tx_ring[TX_DESC_COUNT] __attribute__((aligned(32))) ETH_SECTION;
static uint8_t rx_buffers[RX_DESC_COUNT][RX_BUF_SIZE] __attribute__((aligned(32))) ETH_SECTION;
static uint8_t tx_buffers[TX_DESC_COUNT][TX_BUF_SIZE] __attribute__((aligned(32))) ETH_SECTION;

#if defined(STM32N6)
/* DMA Channel 1 descriptor rings and buffers */
static struct eth_desc rx_ring1[RX_DESC_COUNT] __attribute__((aligned(32))) ETH_SECTION;
static struct eth_desc tx_ring1[TX_DESC_COUNT] __attribute__((aligned(32))) ETH_SECTION;
static uint8_t rx_buffers1[RX_DESC_COUNT][RX_BUF_SIZE] __attribute__((aligned(32))) ETH_SECTION;
#endif

static uint32_t rx_idx;
static uint32_t tx_idx;
static int32_t phy_addr = -1;

static uint32_t rx_poll_count = 0;
static uint32_t rx_pkt_count = 0;

static uint16_t eth_mdio_read(uint32_t phy, uint32_t reg);
static void eth_mdio_write(uint32_t phy, uint32_t reg, uint16_t value);

#if STM32_ETH_NEEDS_MDIO_DELAY
static void eth_delay(uint32_t count)
{
    for (volatile uint32_t i = 0; i < count; i++) { }
}
#endif

static int eth_hw_reset(void)
{
    uint32_t timeout;

#if defined(STM32N6)
    /* On N6, SWR requires REF_CLK from PHY. Use a very long timeout
     * (HAL uses 1 second). Do NOT manually clear SWR — it corrupts DMA. */
    timeout = 50000000U; /* ~80ms at 600MHz */
#else
    timeout = 1000000U;
#endif

    ETH_DMAMR |= ETH_DMAMR_SWR;
    while ((ETH_DMAMR & ETH_DMAMR_SWR) && (timeout > 0U)) {
        timeout--;
    }
    if (timeout == 0U) return -1;

#if STM32_ETH_NEEDS_MDIO_DELAY
    /* Wait for MAC internal state to stabilize after reset. */
    eth_delay(400000); /* ~1ms at 400MHz SYSCLK */

    /* Pre-configure MDIO clock divider before PHY access. */
    ETH_MACMDIOAR = (MDIO_CR_VALUE << ETH_MACMDIOAR_CR_SHIFT);
#endif

    return 0;
}

#if !defined(STM32N6)
static void eth_trigger_tx(void)
{
    ETH_TPDR = 0U;
    __asm volatile ("dsb sy" ::: "memory");
}
#endif

static void eth_config_mac(const uint8_t mac[6])
{
    uint32_t maccr;

    /* Build MACCR value to match HAL defaults:
     * - AutomaticPadCRCStrip = ENABLE (bit 20)
     * - CRCStripTypePacket = ENABLE (bit 21)
     * - ChecksumOffload = ENABLE (bit 27)
     * - Watchdog = ENABLE (bit 19 = 0)
     * - Jabber = ENABLE (bit 17 = 0)
     * - InterPacketGap = 96bit (bits 26:24 = 0)
     * - DuplexMode = Full (bit 13)
     * - Speed = 100Mbps (bit 14)
     * - PortSelect = MII/RMII (bit 15) for N6
     */
    maccr = (1U << 20) |  /* ACS - Auto Pad/CRC Strip */
            (1U << 21) |  /* CST - CRC Strip Type */
            (1U << 27) |  /* IPC - Checksum Offload */
            ETH_MACCR_DM | ETH_MACCR_FES;

#if defined(STM32N6)
    /* PS=1 selects MII/RMII port (vs GMII).
     * SARC=0: don't modify source address (wolfIP constructs full frame). */
    maccr |= ETH_MACCR_PS;
    /* Configure 1µs tick counter — required for MAC internal timing.
     * Value = (HCLK_Hz / 1000000) - 1. With PLL: HCLK ~200MHz → 199. */
    ETH_MAC1USTCR = 199U;
#endif
    ETH_MACCR = maccr;

    /* Default packet filter: unicast (our MAC) + broadcast.
     * Promiscuous mode disabled to avoid flooding wolfIP with irrelevant traffic. */
    ETH_MACPFR = 0;

    /* Configure MACECR (Extended Config) - HAL defaults:
     * - GiantPacketSizeLimit = 0x618 (1560 bytes)
     * - CRCCheckingRxPackets = ENABLE (bit 16 = 0)
     */
    ETH_MACECR = 0x618U;  /* Giant packet size limit */

    /* Configure MACWTR (Watchdog Timeout) - HAL defaults:
     * - WatchdogTimeout = 2KB (bits 3:0 = 0)
     * - ProgrammableWatchdog = DISABLE (bit 8 = 0)
     */
    ETH_MACWTR = 0x0U;

    /* Configure flow control - HAL defaults: disabled */
    ETH_MACQ0TXFCR = (1U << 7);  /* Zero Quanta Pause disabled (DZPQ=1) */
    ETH_MACRXFCR = 0x0U;

#if defined(STM32N6)
    /* Enable both RX queues — N6 requires both DMA channels active */
    ETH_MACRXQC0R = 0x0Au;
#elif defined(STM32H7)
    ETH_MACRXQC0R = 0x02u;
#endif

    ETH_MACA0HR = ((uint32_t)mac[5] << 8) | (uint32_t)mac[4];
    ETH_MACA0LR = ((uint32_t)mac[3] << 24) |
                  ((uint32_t)mac[2] << 16) |
                  ((uint32_t)mac[1] << 8) |
                   (uint32_t)mac[0];
}

static void eth_config_speed_duplex(void)
{
    uint32_t maccr;
    uint16_t bsr;

    if (phy_addr < 0) return;

    maccr = ETH_MACCR;
    maccr &= ~(ETH_MACCR_FES | ETH_MACCR_DM);

    /* Read BSR twice (latched low). */
    bsr = eth_mdio_read((uint32_t)phy_addr, PHY_REG_BSR);
    bsr |= eth_mdio_read((uint32_t)phy_addr, PHY_REG_BSR);

    if ((bsr & PHY_BSR_100_FULL) != 0U) {
        maccr |= ETH_MACCR_FES | ETH_MACCR_DM;
    } else if ((bsr & PHY_BSR_100_HALF) != 0U) {
        maccr |= ETH_MACCR_FES;
    } else if ((bsr & PHY_BSR_10_FULL) != 0U) {
        maccr |= ETH_MACCR_DM;
    }
    ETH_MACCR = maccr;
}

static void eth_config_mtl(void)
{
    uint32_t txqomr;
    uint32_t rxqomr;

    /* Configure MTL Operation Mode (MTLOMR) - HAL defaults:
     * - TxSchedulingAlgorithm = Strict Priority (bits 6:5 = 0)
     * - ReceiveArbitrationAlgorithm = Strict Priority (bit 8 = 0)
     * - TransmitStatus = ENABLE (bit 1 = 0, DTXSTS=0)
     */
    /* CubeN6 sets 0x60: bits 6:5 = Strict Priority arbitration */
    ETH_MTLOMR = 0x00000060u;

#if defined(STM32N6)
    /* Map RX Queue 0 to DMA Channel 0 (MTLRXQDMAMR) */
    ETH_MTLRXQDMAMR = 0x0U;  /* Q0 -> CH0, Q1 -> CH1 */
#endif

    /* Configure TX Queue 0 Operation Mode:
     * - TSF = Transmit Store and Forward (bit 1)
     * - TXQEN = Enabled (bits 3:2 = 2)
     * - TQS = 2KB (bits 22:16 = 0x7)
     */
    txqomr = ETH_MTLTXQOMR;
    txqomr &= ~ETH_MTLTXQOMR_MASK;
    txqomr |= ETH_MTLTXQOMR_TSF | ETH_MTLTXQOMR_TXQEN_ENABLE | ETH_MTLTXQOMR_TQS_2048;
    ETH_MTLTXQOMR = txqomr;

    /* Configure RX Queue 0 Operation Mode:
     * - RSF = Receive Store and Forward (bit 5)
     * - RQS = 4KB (bits 23:20 = 0xF)
     * - DEHF = Drop Error Half Frames (bit 6 = 0, disabled by HAL)
     */
    rxqomr = ETH_MTLRXQOMR;
    rxqomr &= ~ETH_MTLRXQOMR_MASK;
    rxqomr |= ETH_MTLRXQOMR_RSF | ETH_MTLRXQOMR_RQS_4096;
    ETH_MTLRXQOMR = rxqomr;
}

static void eth_init_desc(void)
{
    uint32_t i;

    /* Clear all descriptors (HAL flow: init empty, arm later via eth_start). */
    for (i = 0; i < TX_DESC_COUNT; i++) {
        tx_ring[i].des0 = 0; tx_ring[i].des1 = 0;
        tx_ring[i].des2 = 0; tx_ring[i].des3 = 0;
    }
    for (i = 0; i < RX_DESC_COUNT; i++) {
        rx_ring[i].des0 = 0; rx_ring[i].des1 = 0;
        rx_ring[i].des2 = 0; rx_ring[i].des3 = 0;
    }
    rx_idx = 0;
    tx_idx = 0;

    /* Configure DMA descriptor registers with EMPTY descriptors. */
    __asm volatile ("dsb sy" ::: "memory");
    ETH_DMACTXDLAR = ETH_DMA_ADDR(&tx_ring[0]);
    ETH_DMACRXDLAR = ETH_DMA_ADDR(&rx_ring[0]);
    ETH_DMACTXRLR = TX_DESC_COUNT - 1U;
    ETH_DMACRXRLR = RX_DESC_COUNT - 1U;
    ETH_DMACTXDTPR = ETH_DMA_ADDR(&tx_ring[0]);
    ETH_DMACRXDTPR = ETH_DMA_ADDR(&rx_ring[RX_DESC_COUNT - 1U]);
    __asm volatile ("dsb sy" ::: "memory");

    /* TX descriptors: set buffer addresses (no OWN, host owns them). */
    for (i = 0; i < TX_DESC_COUNT; i++) {
        *(volatile uint32_t *)&tx_ring[i].des0 = ETH_DMA_ADDR(tx_buffers[i]);
    }
    /* RX descriptors: do NOT set OWN yet — will be armed by eth_start
     * via ETH_UpdateDescriptor-style flow (matching CubeN6 HAL). */

#if defined(STM32N6)
    /* Initialize DMA Channel 1 descriptors (N6 has 2 channels) */
    for (i = 0; i < TX_DESC_COUNT; i++) {
        tx_ring1[i].des0 = 0; tx_ring1[i].des1 = 0;
        tx_ring1[i].des2 = 0; tx_ring1[i].des3 = 0;
    }
    for (i = 0; i < RX_DESC_COUNT; i++) {
        rx_ring1[i].des0 = 0; rx_ring1[i].des1 = 0;
        rx_ring1[i].des2 = 0; rx_ring1[i].des3 = 0;
    }
    __asm volatile ("dsb sy" ::: "memory");
    ETH_DMAC1TXDLAR = ETH_DMA_ADDR(&tx_ring1[0]);
    ETH_DMAC1RXDLAR = ETH_DMA_ADDR(&rx_ring1[0]);
    ETH_DMAC1TXRLR = TX_DESC_COUNT - 1U;
    ETH_DMAC1RXRLR = RX_DESC_COUNT - 1U;
    ETH_DMAC1TXDTPR = ETH_DMA_ADDR(&tx_ring1[0]);
    ETH_DMAC1RXDTPR = ETH_DMA_ADDR(&rx_ring1[RX_DESC_COUNT - 1U]);
#endif

    /* Final barrier. */
    __asm volatile ("dsb sy" ::: "memory");
}

#define ETH_DMACCR_DSL_0BIT  (0x00000000u)

/* DMA System Bus Mode Register bits */
#define ETH_DMASBMR_RX_OSR_LIMIT_3  (0x3U << 16)  /* RX Outstanding requests limit */
#define ETH_DMASBMR_TX_OSR_LIMIT_3  (0x3U << 24)  /* TX Outstanding requests limit */
#define ETH_DMASBMR_BLEN4           (1U << 1)     /* AXI Burst Length 4 */

static void eth_config_dma(void)
{
    /* Configure DMA System Bus Mode (DMASBMR) - HAL defaults:
     * - AddressAlignedBeats = ENABLE (bit 12)
     * - BurstMode = Fixed (bit 0)
     * - RxOSRLimit = 3 (bits 17:16)
     * - TxOSRLimit = 3 (bits 25:24)
     * - AXIBLENMaxSize = 4 (bit 1)
     */
    /* DMA System Bus Mode (matching CubeN6) */
    ETH_DMASBMR = 0x03031003u;

    /* DMACCR: DSL=1 (skip 1 doubleword = 8 bytes between 16-byte descriptors,
     * stride = 24 bytes matching HAL ETH_DMADescTypeDef). MSS=536. */
#if defined(STM32N6)
    ETH_DMACCR = 0x40218u;
#else
    ETH_DMACCR = ETH_DMACCR_DSL_0BIT;
#endif

    /* Configure RX DMA:
     * - RBSZ = buffer size
     * - RPBL = 32 beat burst
     */
    ETH_DMACRXCR = ((RX_BUF_SIZE & ETH_RDES3_PL_MASK) << ETH_DMACRXCR_RBSZ_SHIFT) |
                   ETH_DMACRXCR_RPBL(DMA_RPBL);

    /* Configure TX DMA:
     * - TPBL = 32 beat burst
     * - OSF = Operate on Second Frame (bit 4) - N6 does NOT use OSF (per CubeN6/Oryx)
     */
#if defined(STM32N6)
    ETH_DMACTXCR = ETH_DMACTXCR_TPBL(DMA_TPBL);

    /* Configure DMA Channel 1 (N6 has 2 TX queues / DMA channels) */
    ETH_DMAC1CR = 0x40218u; /* DSL=1, MSS=536 — same as CH0 */
    ETH_DMAC1RXCR = ((RX_BUF_SIZE & ETH_RDES3_PL_MASK) << ETH_DMACRXCR_RBSZ_SHIFT) |
                    ETH_DMACRXCR_RPBL(DMA_RPBL);
    ETH_DMAC1TXCR = ETH_DMACTXCR_TPBL(DMA_TPBL);

    /* MTL TX Queue 1: same as Q0 */
    ETH_MTLTXQ1OMR = ETH_MTLTXQOMR_TSF | ETH_MTLTXQOMR_TXQEN_ENABLE |
                     ETH_MTLTXQOMR_TQS_2048;

    /* Map RX Q1 → DMA CH1 */
    ETH_MTLRXQDMAMR = (1u << 8); /* Q1MDMACH = 1 */
#else
    ETH_DMACTXCR = ETH_DMACTXCR_OSF | ETH_DMACTXCR_TPBL(DMA_TPBL);
#endif
}

#define ETH_DMACSR_TPS  (1U << 1)
#define ETH_DMACSR_RPS  (1U << 8)

static void eth_arm_rx_descriptors(void)
{
    uint32_t i;
    /* Arm RX descriptors: set buffer address + OWN bit (HAL ETH_UpdateDescriptor flow).
     * Must be done AFTER DMA is started. */
    for (i = 0; i < RX_DESC_COUNT; i++) {
        rx_ring[i].des0 = ETH_DMA_ADDR(rx_buffers[i]);
        rx_ring[i].des1 = 0;
        rx_ring[i].des2 = 0;
        __asm volatile ("dsb sy" ::: "memory");
        rx_ring[i].des3 = ETH_RDES3_OWN | ETH_RDES3_IOC | ETH_RDES3_BUF1V;
    }
    __asm volatile ("dmb sy" ::: "memory");
    ETH_DMACRXDTPR = ETH_DMA_ADDR(&rx_ring[RX_DESC_COUNT - 1U]);
}

static void eth_start(void)
{
    ETH_MACCR |= ETH_MACCR_TE | ETH_MACCR_RE;
    ETH_MTLTXQOMR |= ETH_MTLTXQOMR_FTQ;
    ETH_DMACTXCR |= ETH_DMACTXCR_ST;
    ETH_DMACRXCR |= ETH_DMACRXCR_SR;

#if defined(STM32N6)
    /* N6 has 2 DMA channels. Both must be started for MAC RX to work.
     * CubeN6 configures both channels identically. */
    ETH_MTLTXQ1OMR |= ETH_MTLTXQOMR_FTQ;
    ETH_DMAC1TXCR |= ETH_DMACTXCR_ST;
    ETH_DMAC1RXCR |= ETH_DMACRXCR_SR;
    ETH_DMAC1SR = 0xFFFF; /* Clear all status */
    __asm volatile ("dsb sy" ::: "memory");
    ETH_DMAC1RXDTPR = ETH_DMA_ADDR(&rx_ring1[RX_DESC_COUNT - 1U]);
#endif

    /* Enable DMA interrupt flags (matching CubeN6 HAL_ETH_Start_IT).
     * Even in polled mode, some GMAC implementations need these enabled
     * for the DMA to process descriptors. */
    ETH_DMACIER = ETH_DMACIER_NIE | ETH_DMACIER_AIE | ETH_DMACIER_RBUE |
                  ETH_DMACIER_RIE | ETH_DMACIER_TIE;
#if defined(STM32N6)
    ETH_DMAC1IER = ETH_DMACIER_NIE | ETH_DMACIER_AIE | ETH_DMACIER_RBUE |
                   ETH_DMACIER_RIE | ETH_DMACIER_TIE;
#endif

    /* Clear TX and RX process stopped flags + RBU (bit 7). */
    ETH_DMACSR = ETH_DMACSR_TPS | ETH_DMACSR_RPS | (1U << 7);

    __asm volatile ("dsb sy" ::: "memory");

    /* Arm RX descriptors AFTER DMA is started (HAL_ETH_Start_IT flow).
     * This tells the DMA about available descriptors via tail pointer. */
    eth_arm_rx_descriptors();
#if defined(STM32N6)
    {
        uint32_t j;
        for (j = 0; j < RX_DESC_COUNT; j++) {
            rx_ring1[j].des0 = ETH_DMA_ADDR(rx_buffers1[j]);
            rx_ring1[j].des1 = 0; rx_ring1[j].des2 = 0;
            __asm volatile ("dsb sy" ::: "memory");
            rx_ring1[j].des3 = ETH_RDES3_OWN | ETH_RDES3_IOC | ETH_RDES3_BUF1V;
        }
        __asm volatile ("dmb sy" ::: "memory");
        ETH_DMAC1RXDTPR = ETH_DMA_ADDR(&rx_ring1[RX_DESC_COUNT - 1U]);
    }
#endif
}

static void eth_stop(void)
{
    ETH_DMACTXCR &= ~ETH_DMACTXCR_ST;
    ETH_DMACRXCR &= ~ETH_DMACRXCR_SR;
    ETH_MACCR &= ~ETH_MACCR_RE;
    ETH_MTLTXQOMR |= ETH_MTLTXQOMR_FTQ;
    ETH_MACCR &= ~ETH_MACCR_TE;
}

static void eth_mdio_wait_ready(void)
{
    uint32_t timeout = 100000U;
    while ((ETH_MACMDIOAR & ETH_MACMDIOAR_MB) != 0U && timeout != 0U) {
        timeout--;
    }
}

static uint16_t eth_mdio_read(uint32_t phy, uint32_t reg)
{
    uint32_t cfg;
    eth_mdio_wait_ready();
    cfg = (MDIO_CR_VALUE << ETH_MACMDIOAR_CR_SHIFT) |
          (reg << ETH_MACMDIOAR_RDA_SHIFT) |
          (phy << ETH_MACMDIOAR_PA_SHIFT) |
          (ETH_MACMDIOAR_GOC_READ << ETH_MACMDIOAR_GOC_SHIFT);
    ETH_MACMDIOAR = cfg | ETH_MACMDIOAR_MB;
    eth_mdio_wait_ready();
    return (uint16_t)(ETH_MACMDIODR & 0xFFFFU);
}

static void eth_mdio_write(uint32_t phy, uint32_t reg, uint16_t value)
{
    uint32_t cfg;
    eth_mdio_wait_ready();
    ETH_MACMDIODR = (uint32_t)value;
    cfg = (MDIO_CR_VALUE << ETH_MACMDIOAR_CR_SHIFT) |
          (reg << ETH_MACMDIOAR_RDA_SHIFT) |
          (phy << ETH_MACMDIOAR_PA_SHIFT) |
          (ETH_MACMDIOAR_GOC_WRITE << ETH_MACMDIOAR_GOC_SHIFT);
    ETH_MACMDIOAR = cfg | ETH_MACMDIOAR_MB;
    eth_mdio_wait_ready();
}

static int32_t eth_detect_phy(void)
{
    uint32_t addr;
    for (addr = 0U; addr < 32U; addr++) {
        uint16_t id1 = eth_mdio_read(addr, PHY_REG_ID1);
        if (id1 != 0xFFFFU && id1 != 0x0000U) {
            return (int32_t)addr;
        }
    }
    return -1;
}

static void eth_phy_init(void)
{
    uint32_t timeout;
    uint16_t ctrl;
    uint16_t bsr;

    if (phy_addr < 0) {
        phy_addr = eth_detect_phy();
        if (phy_addr < 0) {
            phy_addr = 0;
            return; /* No PHY found — skip init to avoid long timeouts */
        }
    }

    /* Reset PHY. */
    eth_mdio_write((uint32_t)phy_addr, PHY_REG_BCR, PHY_BCR_RESET);
    timeout = 100000U;
    do {
        ctrl = eth_mdio_read((uint32_t)phy_addr, PHY_REG_BCR);
    } while ((ctrl & PHY_BCR_RESET) != 0U && --timeout != 0U);

    /* Configure PHY for auto-negotiation. */
    ctrl &= ~(PHY_BCR_POWER_DOWN | PHY_BCR_ISOLATE | PHY_BCR_SPEED_100 | PHY_BCR_FULL_DUPLEX);
    eth_mdio_write((uint32_t)phy_addr, PHY_REG_ANAR, PHY_ANAR_DEFAULT);
    ctrl |= PHY_BCR_AUTONEG_ENABLE | PHY_BCR_RESTART_AUTONEG;
    eth_mdio_write((uint32_t)phy_addr, PHY_REG_BCR, ctrl);

    /* Wait for auto-negotiation complete. */
    timeout = 100000U;
    do {
        bsr = eth_mdio_read((uint32_t)phy_addr, PHY_REG_BSR);
        bsr |= eth_mdio_read((uint32_t)phy_addr, PHY_REG_BSR);
    } while ((bsr & PHY_BSR_AUTONEG_COMPLETE) == 0U && --timeout != 0U);

    /* Wait for link up. */
    timeout = 100000U;
    do {
        bsr = eth_mdio_read((uint32_t)phy_addr, PHY_REG_BSR);
        bsr |= eth_mdio_read((uint32_t)phy_addr, PHY_REG_BSR);
    } while ((bsr & PHY_BSR_LINK_STATUS) == 0U && --timeout != 0U);
}

#define ETH_DMACSR_RBU      (1U << 7)

static int eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct eth_desc *desc;
    uint32_t status;
    uint32_t frame_len = 0;

    (void)dev;
    rx_poll_count++;

    /* Recover from RBU (Receive Buffer Unavailable) — DMA stops after
     * exhausting all descriptors. Clear the status and kick the DMA. */
    if (ETH_DMACSR & ETH_DMACSR_RBU) {
        ETH_DMACSR = ETH_DMACSR_RBU; /* W1C */
        __asm volatile ("dsb sy" ::: "memory");
        ETH_DMACRXDTPR = ETH_DMA_ADDR(&rx_ring[RX_DESC_COUNT - 1U]);
    }

    desc = &rx_ring[rx_idx];
    if (desc->des3 & ETH_RDES3_OWN) return 0;

    rx_pkt_count++;
    status = desc->des3;

    if ((status & (ETH_RDES3_FS | ETH_RDES3_LS)) == (ETH_RDES3_FS | ETH_RDES3_LS)) {
        frame_len = status & ETH_RDES3_PL_MASK;
        if (frame_len > len) frame_len = len;
        if (frame_len > 0) {
            memcpy(frame, rx_buffers[rx_idx], frame_len);
        }
    }

    /* Reinitialize descriptor — must restore des0 (buffer address) since
     * DMA writeback overwrites it with timestamp data. */
    desc->des0 = ETH_DMA_ADDR(rx_buffers[rx_idx]);
    desc->des1 = 0;
    desc->des2 = 0;
    __asm volatile ("dsb sy" ::: "memory");
    desc->des3 = ETH_RDES3_OWN | ETH_RDES3_IOC | ETH_RDES3_BUF1V;
    __asm volatile ("dsb sy" ::: "memory");
    ETH_DMACRXDTPR = ETH_DMA_ADDR(desc);
    rx_idx = (rx_idx + 1U) % RX_DESC_COUNT;

    return (int)frame_len;
}

static int eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct eth_desc *desc;
    uint32_t dma_len;
    uint32_t next_idx;

    (void)dev;
    if (len == 0 || len > TX_BUF_SIZE) return -1;

    desc = &tx_ring[tx_idx];
    if (desc->des3 & ETH_TDES3_OWN) return -2;

    /* Copy frame to TX buffer. */
    memcpy(tx_buffers[tx_idx], frame, len);

    /* Pad to minimum frame length. */
    dma_len = (len < FRAME_MIN_LEN) ? FRAME_MIN_LEN : len;
    if (dma_len > len) memset(tx_buffers[tx_idx] + len, 0, dma_len - len);

    /* Setup descriptor. */
    desc->des0 = ETH_DMA_ADDR(tx_buffers[tx_idx]);
    desc->des1 = 0;
    desc->des2 = (dma_len & ETH_TDES2_B1L_MASK);
    __asm volatile ("dsb sy" ::: "memory");
    desc->des3 = (dma_len & ETH_TDES3_FL_MASK) |
                 ETH_TDES3_FD |
                 ETH_TDES3_LD |
                 ETH_TDES3_OWN;
    __asm volatile ("dsb sy" ::: "memory");

    ETH_DMACSR = ETH_DMACSR_TBU;
#if !defined(STM32N6)
    /* TPDR (0x1180) is a separate TX poll register on H5/H7.
     * On N6, offset 0x1180 is DMAC1CR — writing 0 would clobber CH1 config. */
    if (tx_idx == 0U) eth_trigger_tx();
#endif

    next_idx = (tx_idx + 1U) % TX_DESC_COUNT;
    ETH_DMACTXDTPR = ETH_DMA_ADDR(&tx_ring[next_idx]);
    tx_idx = next_idx;

    return (int)len;
}

static void stm32_eth_generate_mac(uint8_t mac[6])
{
    /* Generate a locally-administered MAC address. */
    mac[0] = 0x02;
    mac[1] = 0x11;
#if defined(STM32H7)
    mac[2] = 0x22;
    mac[3] = 0x33;
    mac[4] = 0x44;
    mac[5] = 0x55;
#elif defined(STM32N6)
    mac[2] = 0xCC;
    mac[3] = 0xDD;
    mac[4] = 0x55;
    mac[5] = 0x66;
#else
    mac[2] = 0xAA;
    mac[3] = 0xBB;
    mac[4] = 0x22;
    mac[5] = 0x33;
#endif
}

void stm32_eth_get_stats(uint32_t *polls, uint32_t *pkts)
{
    if (polls) *polls = rx_poll_count;
    if (pkts) *pkts = rx_pkt_count;
}


uint32_t stm32_eth_get_rx_des3(void)
{
    return rx_ring[0].des3;
}


int stm32_eth_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    uint8_t local_mac[6];
    uint16_t phy_id1, phy_bsr;

    if (ll == NULL) return -1;

    if (mac == NULL) {
        stm32_eth_generate_mac(local_mac);
        mac = local_mac;
    }

    memcpy(ll->mac, mac, 6);
    strncpy(ll->ifname, "eth0", sizeof(ll->ifname) - 1);
    ll->ifname[sizeof(ll->ifname) - 1] = '\0';
    ll->poll = eth_poll;
    ll->send = eth_send;

    eth_stop();
    if (eth_hw_reset() != 0) {
        return -2;
    }
    eth_config_mac(mac);
    eth_config_mtl();
    eth_config_dma();    /* DMA mode config BEFORE descriptor setup (per CubeN6 HAL) */
    eth_init_desc();
    eth_phy_init();
    eth_config_speed_duplex();
    eth_start();

    phy_id1 = eth_mdio_read((uint32_t)phy_addr, PHY_REG_ID1);
    phy_bsr = eth_mdio_read((uint32_t)phy_addr, PHY_REG_BSR);

    return ((phy_id1 & 0xFF00u) << 8) | ((phy_bsr & 0x04u) ? 0x100 : 0) | (phy_addr & 0xFF);
}

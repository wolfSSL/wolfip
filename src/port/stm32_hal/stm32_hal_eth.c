/* stm32_hal_eth.c
 *
 * Copyright (C) 2024-2025 wolfSSL Inc.
 *
 * HAL-based Ethernet driver for wolfIP - portable across STM32 families
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

#include "stm32_hal_eth.h"
#include "main.h"
#include <string.h>
#ifdef WOLFIP_USE_FREERTOS
#include "bsd_socket.h"
#endif

/*
 * Supported STM32 families for automatic RMII/MII configuration:
 *
 * | Family   | Interface Register | Method                        |
 * |----------|-------------------|-------------------------------|
 * | STM32H5  | SBS->PMCR         | HAL_SBS_ETHInterfaceSelect()  |
 * | STM32H7  | SYSCFG->PMCR      | Direct register write         |
 * | STM32F4  | SYSCFG->PMC       | Direct register write         |
 * | STM32F7  | SYSCFG->PMC       | Direct register write         |
 * | Others   | (manual)          | User configures in MspInit    |
 */

/* External references to HAL ETH handle and TX config (from CubeMX-generated code) */
extern ETH_HandleTypeDef heth;
extern ETH_TxPacketConfigTypeDef TxConfig;

/* Track if interface has been configured */
static uint8_t interface_configured = 0;

/**
 * @brief Configure RMII/MII interface based on STM32 family
 *
 * This function automatically configures the Ethernet interface (RMII/MII)
 * based on the detected STM32 family. It uses compile-time macros defined
 * by the STM32 HAL to determine the correct configuration method.
 *
 * IMPORTANT: For best results, call this function BEFORE HAL_ETH_Init().
 * The ideal location is at the start of HAL_ETH_MspInit() in your
 * stm32xxxx_hal_msp.c file, before enabling ETH clocks.
 *
 * If using the wolfIP CMSIS pack, this is called automatically during
 * stm32_hal_eth_init(). However, some families may require earlier
 * configuration - see documentation for your specific board.
 *
 * @return 0 if configuration succeeded or family auto-detected
 * @return 1 if unknown family (user must configure manually in MspInit)
 */
int stm32_hal_eth_configure_interface(void)
{
    if (interface_configured) {
        return 0; /* Already configured */
    }

#if defined(STM32H5) || defined(STM32H563xx) || defined(STM32H573xx) || \
    defined(STM32H503xx) || defined(STM32H533xx) || defined(STM32H562xx)
    /* STM32H5 series: Use SBS for RMII selection */
    __HAL_RCC_SBS_CLK_ENABLE();
    HAL_SBS_ETHInterfaceSelect(SBS_ETH_RMII);
    interface_configured = 1;
    return 0;

#elif defined(STM32H7) || defined(STM32H743xx) || defined(STM32H753xx) || \
      defined(STM32H747xx) || defined(STM32H757xx) || defined(STM32H723xx) || \
      defined(STM32H733xx) || defined(STM32H725xx) || defined(STM32H735xx) || \
      defined(STM32H730xx) || defined(STM32H750xx) || defined(STM32H742xx) || \
      defined(STM32H745xx) || defined(STM32H755xx)
    /* STM32H7 series: Use SYSCFG PMCR for RMII selection */
    __HAL_RCC_SYSCFG_CLK_ENABLE();
    /* Clear EPIS bits and set for RMII */
    SYSCFG->PMCR &= ~SYSCFG_PMCR_EPIS_SEL;
    SYSCFG->PMCR |= SYSCFG_PMCR_EPIS_SEL_2;  /* RMII mode */
    interface_configured = 1;
    return 0;

#elif defined(STM32F4) || defined(STM32F407xx) || defined(STM32F417xx) || \
      defined(STM32F427xx) || defined(STM32F429xx) || defined(STM32F437xx) || \
      defined(STM32F439xx) || defined(STM32F446xx) || defined(STM32F469xx) || \
      defined(STM32F479xx)
    /* STM32F4 series: Use SYSCFG PMC for RMII selection */
    __HAL_RCC_SYSCFG_CLK_ENABLE();
    SYSCFG->PMC |= SYSCFG_PMC_MII_RMII_SEL;  /* RMII mode */
    interface_configured = 1;
    return 0;

#elif defined(STM32F7) || defined(STM32F745xx) || defined(STM32F746xx) || \
      defined(STM32F756xx) || defined(STM32F765xx) || defined(STM32F767xx) || \
      defined(STM32F769xx) || defined(STM32F777xx) || defined(STM32F779xx) || \
      defined(STM32F722xx) || defined(STM32F723xx) || defined(STM32F730xx) || \
      defined(STM32F732xx) || defined(STM32F733xx)
    /* STM32F7 series: Use SYSCFG PMC for RMII selection */
    __HAL_RCC_SYSCFG_CLK_ENABLE();
    SYSCFG->PMC |= SYSCFG_PMC_MII_RMII_SEL;  /* RMII mode */
    interface_configured = 1;
    return 0;

#else
    /* Unknown family - user must configure in HAL_ETH_MspInit() */
    /* This is not an error - just means manual configuration needed */
    return 1;
#endif
}

/* RX buffers for HAL ETH - must be 32-byte aligned for DMA on STM32H5/H7.
 * HAL_ETH_ReadData() hands a descriptor back to the DMA with a fresh buffer
 * before it returns the frame, so one more buffer than descriptors keeps the
 * buffer being copied out of the DMA's reach. This relies on the HAL detaching
 * every descriptor it consumes, in ring order, which it only does while
 * HAL_ETH_RxLinkCallback() keeps *pStart set. */
#define ETH_RX_BUFFER_SIZE 1536
#define ETH_RX_BUFFER_CNT  (ETH_RX_DESC_CNT + 1)
static uint8_t rx_buffers[ETH_RX_BUFFER_CNT][ETH_RX_BUFFER_SIZE]
    __attribute__((aligned(32)));
static uint32_t rx_buffer_next = 0;

/* Frame returned by the last HAL_ETH_ReadData() */
static uint8_t *rx_frame_buf = NULL;
static uint32_t rx_frame_length = 0;
static uint32_t rx_frame_segs = 0;

#if defined(__DCACHE_PRESENT) && (__DCACHE_PRESENT == 1U)
    #define ETH_DCACHE_ENABLED() ((SCB->CCR & SCB_CCR_DC_Msk) != 0U)
#endif

/**
 * @brief HAL ETH RX allocation callback
 * Called by HAL when it needs a buffer to store received data
 */
void HAL_ETH_RxAllocateCallback(uint8_t **buff)
{
    *buff = rx_buffers[rx_buffer_next];
    rx_buffer_next = (rx_buffer_next + 1) % ETH_RX_BUFFER_CNT;
}

/**
 * @brief HAL ETH RX link callback
 * Called by HAL for each descriptor of a received frame
 */
void HAL_ETH_RxLinkCallback(void **pStart, void **pEnd, uint8_t *buff, uint16_t Length)
{
    (void)pEnd;

    if (*pStart == NULL) {
        *pStart = buff;
        rx_frame_buf = buff;
        rx_frame_length = Length;
        rx_frame_segs = 1;
    }
    else {
        rx_frame_segs++;
    }
}

/**
 * @brief HAL ETH RX Complete Callback
 * Called by HAL from ETH IRQ handler when a frame has been received.
 * With the FreeRTOS port, wakes the poll task. The RX interrupt is left
 * enabled: masking it here races the HAL handler, which clears RI and NIS
 * only while RIE is set, and a frame landing in between leaves NIS stuck
 * with nothing to clear it.
 */
void HAL_ETH_RxCpltCallback(ETH_HandleTypeDef *heth_ptr)
{
    (void)heth_ptr;
#ifdef WOLFIP_USE_FREERTOS
    wolfip_freertos_notify_from_isr();
#endif
}

/**
 * @brief Poll for received Ethernet frames
 *
 * Returns one frame per call; wolfIP keeps calling until it returns 0, so
 * every frame already in the RX ring is delivered in one poll cycle. A frame
 * that spans several descriptors does not fit one RX buffer and is dropped.
 */
static int hal_eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    uint32_t frame_len;
    uint32_t segs;
    uint32_t i;
    void *payload = NULL;

    (void)dev;

    /* Check if ETH is started */
    if (heth.gState != HAL_ETH_STATE_STARTED) {
        return 0;
    }

    for (i = 0; ; i++) {
        if (i == ETH_RX_DESC_CNT ||
                HAL_ETH_ReadData(&heth, &payload) != HAL_OK) {
            return 0;
        }
        segs = rx_frame_segs;
        rx_frame_segs = 0;
        if (segs == 1) {
            break;
        }
    }

    frame_len = rx_frame_length;
    if (frame_len > len) {
        frame_len = len;
    }
#ifdef ETH_DCACHE_ENABLED
    if (ETH_DCACHE_ENABLED()) {
        SCB_InvalidateDCache_by_Addr((uint32_t *)rx_frame_buf,
            (int32_t)ETH_RX_BUFFER_SIZE);
    }
#endif
    memcpy(frame, rx_frame_buf, frame_len);
    return (int)frame_len;
}

/* wolfIP builds outgoing frames on the caller's stack. Sending from a static
 * buffer keeps the DMA off that stack, which it cannot reach when the stack
 * is in core-coupled memory (DTCM, CCM). On by default for STM32H7R/S, where
 * the vendor linker scripts put the main stack in DTCM. Like rx_buffers, the
 * buffer must be linked into memory the DMA can reach. */
#if defined(STM32H7RS) && !defined(STM32_HAL_ETH_NO_TX_BOUNCE) && \
    !defined(STM32_HAL_ETH_TX_BOUNCE)
    #define STM32_HAL_ETH_TX_BOUNCE
#endif
#ifdef STM32_HAL_ETH_TX_BOUNCE
static uint8_t tx_frame[ETH_RX_BUFFER_SIZE] __attribute__((aligned(32)));
#endif

/**
 * @brief Send an Ethernet frame
 */
static int hal_eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    ETH_BufferTypeDef tx_buffer;
    HAL_StatusTypeDef status;

    (void)dev;

    if (len == 0 || len > ETH_RX_BUFFER_SIZE) {
        return -1;
    }

#ifdef STM32_HAL_ETH_TX_BOUNCE
    memcpy(tx_frame, frame, len);
    frame = tx_frame;
#endif

#ifdef ETH_DCACHE_ENABLED
    if (ETH_DCACHE_ENABLED()) {
        SCB_CleanDCache_by_Addr((uint32_t *)frame, (int32_t)len);
    }
#endif

    /* Configure TX buffer */
    tx_buffer.buffer = frame;
    tx_buffer.len = len;
    tx_buffer.next = NULL;

    /* Update TX config */
    TxConfig.Length = len;
    TxConfig.TxBuffer = &tx_buffer;
    TxConfig.pData = NULL;

    /* Transmit frame - 100ms timeout */
    status = HAL_ETH_Transmit(&heth, &TxConfig, 100);

    if (status == HAL_OK) {
        return (int)len;
    }

    return -1;
}

/**
 * @brief Initialize the HAL-based Ethernet driver
 *
 * This function automatically configures RMII/MII for the detected STM32
 * family, reinitializes the ETH peripheral with correct settings, and
 * starts the Ethernet MAC.
 *
 * No manual configuration needed - works automatically on all supported
 * STM32 families (F4, F7, H5, H7).
 */
int stm32_hal_eth_init(struct wolfIP_ll_dev *ll)
{
    HAL_StatusTypeDef status;

    if (ll == NULL) {
        return -1;
    }

    /*
     * Auto-configure RMII/MII interface for this STM32 family.
     * Then reinitialize ETH to apply the settings.
     * This allows fully automatic setup with zero user code in MspInit.
     */
    if (stm32_hal_eth_configure_interface() == 0) {
        /* Family was auto-detected - reinit ETH to apply RMII/MII config */
        HAL_ETH_DeInit(&heth);
        if (HAL_ETH_Init(&heth) != HAL_OK) {
            return -3;
        }
    }
    /* If configure returned 1 (unknown family), assume user configured in MspInit */

    /* Copy MAC address from HAL handle */
    memcpy(ll->mac, heth.Init.MACAddr, 6);
    strncpy(ll->ifname, "eth0", sizeof(ll->ifname) - 1);
    ll->ifname[sizeof(ll->ifname) - 1] = '\0';

    /* Set wolfIP callbacks */
    ll->poll = hal_eth_poll;
    ll->send = hal_eth_send;

    /* Start the Ethernet MAC in interrupt mode for RX */
    status = HAL_ETH_Start_IT(&heth);
    if (status != HAL_OK) {
        return -2;
    }

    return 0;
}

/* wolfIP callbacks for CubeMX builds */
#ifdef WOLFIP_STM32_CUBEMX

uint64_t wolfip_get_time_ms(void)
{
    return (uint64_t)HAL_GetTick();
}

#endif /* WOLFIP_STM32_CUBEMX */

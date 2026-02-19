/* stm32_hal_eth.h
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

/**
 * @file stm32_hal_eth.h
 * @brief Portable STM32 HAL Ethernet driver for wolfIP
 *
 * This driver provides a portable Ethernet interface that works across all
 * STM32 families with Ethernet peripheral (F4, F7, H5, H7, etc.) using the
 * STM32 HAL library.
 *
 * ## Supported STM32 Families (Auto-Detected)
 *
 * | Family   | Interface Config    | Status        |
 * |----------|---------------------|---------------|
 * | STM32F4  | SYSCFG->PMC         | Auto          |
 * | STM32F7  | SYSCFG->PMC         | Auto          |
 * | STM32H5  | SBS->PMCR           | Auto          |
 * | STM32H7  | SYSCFG->PMCR        | Auto          |
 * | Others   | Manual in MspInit   | Fallback      |
 *
 * ## Quick Start - Zero Configuration!
 *
 * Just add wolfIP code to main.c - NO changes to MspInit needed:
 *
 * @code
 * #include "wolfip.h"
 * #include "stm32_hal_eth.h"
 *
 * int main(void)
 * {
 *     struct wolfIP *ipstack;
 *
 *     // CubeMX-generated initialization
 *     HAL_Init();
 *     SystemClock_Config();
 *     MX_GPIO_Init();
 *     MX_ETH_Init();
 *
 *     // Initialize wolfIP (same code on ALL STM32 boards)
 *     wolfIP_init_static(&ipstack);
 *     stm32_hal_eth_init(wolfIP_getdev(ipstack));  // Auto-configures RMII/MII!
 *     wolfIP_ipconfig_set(ipstack,
 *         atoip4("192.168.1.100"),
 *         atoip4("255.255.255.0"),
 *         atoip4("192.168.1.1"));
 *
 *     // Main loop
 *     while (1) {
 *         wolfIP_poll(ipstack, HAL_GetTick());
 *     }
 * }
 * @endcode
 *
 * ## CubeMX Configuration Requirements
 *
 * 1. **ETH Peripheral** (Connectivity -> ETH)
 *    - Mode: RMII (or MII depending on your board's PHY)
 *
 * 2. **NVIC Settings** (System Core -> NVIC) - CRITICAL
 *    - ETH global interrupt: **ENABLED**
 *    - Without this, received frames will not be detected
 *
 * 3. **GPIO Configuration**
 *    - CubeMX auto-configures correct pins for NUCLEO boards
 *
 * ## How It Works
 *
 * The driver automatically:
 * 1. Detects your STM32 family at compile time
 * 2. Configures RMII/MII interface (SBS/SYSCFG)
 * 3. Reinitializes ETH with correct settings
 * 4. Starts the MAC in interrupt mode
 *
 * No manual MspInit changes required for supported families!
 *
 * ## Implementation Notes
 *
 * - Uses hybrid RX: interrupt-driven (HAL_ETH_Start_IT) + periodic polling
 * - DMA buffers are 32-byte aligned (required for STM32H5/H7)
 * - Assumes CubeMX generates `heth` and `TxConfig` as extern globals
 */

#ifndef WOLFIP_STM32_HAL_ETH_H
#define WOLFIP_STM32_HAL_ETH_H

#include <stdint.h>
#include "wolfip.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Configure RMII/MII interface for the detected STM32 family
 *
 * This function is called automatically by stm32_hal_eth_init().
 * You typically don't need to call this directly.
 *
 * For unsupported families, returns 1 and user must configure
 * RMII/MII manually in HAL_ETH_MspInit().
 *
 * @return 0 on success (family detected and configured)
 * @return 1 if unknown family (manual configuration required)
 */
int stm32_hal_eth_configure_interface(void);

/**
 * @brief Initialize the HAL-based Ethernet driver for wolfIP
 *
 * This function automatically:
 * 1. Configures RMII/MII for the detected STM32 family
 * 2. Reinitializes ETH peripheral with correct settings
 * 3. Copies MAC address to wolfIP device
 * 4. Registers poll/send callbacks
 * 5. Starts the Ethernet MAC in interrupt mode
 *
 * Prerequisites:
 * - HAL_ETH_Init() called (via MX_ETH_Init)
 * - ETH global interrupt enabled in CubeMX NVIC settings
 *
 * NO changes to MspInit required for supported families (F4, F7, H5, H7)!
 *
 * @param ll Pointer to wolfIP low-level device structure
 *           (obtained via wolfIP_getdev())
 *
 * @return 0 on success
 * @return -1 if ll is NULL
 * @return -2 if HAL_ETH_Start_IT() fails
 * @return -3 if HAL_ETH_Init() fails during reinit
 */
int stm32_hal_eth_init(struct wolfIP_ll_dev *ll);

#ifdef __cplusplus
}
#endif

#endif /* WOLFIP_STM32_HAL_ETH_H */

/* board.h
 *
 * Copyright (C) 2024-2026 wolfSSL Inc.
 *
 * Minimal board configuration for STM32H563ZI Nucleo-144
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

#ifndef BOARD_H
#define BOARD_H

#include <stdint.h>
#include <stddef.h>
#include <wolfHAL/wolfHAL.h>
#include <wolfHAL/platform/st/stm32h563xx.h>
#include <wolfHAL/eth_phy/lan8742a_eth_phy.h>

extern whal_Timeout g_whalTimeout;
extern volatile uint64_t g_tick;

/* The generic wolfIP port (main.c, wolfhal_eth.c, syscalls.c) references the
 * board's Ethernet, PHY, RNG, and UART devices through these names. Under the
 * current wolfHAL API these are single-instance drivers whose device structs
 * live in the driver translation units (built from the WHAL_CFG_*_DEV
 * initializers below), so we alias the documented g_whal* names onto those
 * driver-owned device structs. */
#define g_whalEth     (*(whal_Eth *)&whal_Stm32h5_Eth_Dev)
#define g_whalEthPhy  (*(whal_EthPhy *)&whal_Lan8742a_Dev)
#define g_whalRng     (*(whal_Rng *)&whal_Stm32h5_Rng_Dev)
#define g_whalUart    (*(whal_Uart *)&whal_Stm32h5_Uart_Dev)

/* Ethernet PHY: LAN8742A on MDIO address 0 */
#define BOARD_ETH_PHY_ADDR 0

enum {
    UART_TX_PIN,
    UART_RX_PIN,
    ETH_RMII_REF_CLK_PIN,
    ETH_RMII_MDIO_PIN,
    ETH_RMII_MDC_PIN,
    ETH_RMII_CRS_DV_PIN,
    ETH_RMII_RXD0_PIN,
    ETH_RMII_RXD1_PIN,
    ETH_RMII_TX_EN_PIN,
    ETH_RMII_TXD0_PIN,
    ETH_RMII_TXD1_PIN,
    PIN_COUNT,
};

/* GPIO dev initializer — device struct defined in the gpio driver code.
 * Only the USART3 (ST-Link VCP) and Ethernet RMII pins are configured. */
#define WHAL_CFG_STM32H5_GPIO_DEV { \
    .base = WHAL_STM32H563_GPIO_BASE, \
    .cfg  = (void *)&(const whal_Stm32h5_Gpio_Cfg){ \
        .pinCfg = (const whal_Stm32h5_Gpio_PinCfg[PIN_COUNT]){ \
            /* USART3 TX on PD8, AF7 (ST-Link VCP) */ \
            [UART_TX_PIN] = WHAL_STM32H5_GPIO_PIN( \
                WHAL_STM32H5_GPIO_PORT_D, 8, WHAL_STM32H5_GPIO_MODE_ALTFN, \
                WHAL_STM32H5_GPIO_OUTTYPE_PUSHPULL, WHAL_STM32H5_GPIO_SPEED_FAST, \
                WHAL_STM32H5_GPIO_PULL_UP, 7), \
            /* USART3 RX on PD9, AF7 (ST-Link VCP) */ \
            [UART_RX_PIN] = WHAL_STM32H5_GPIO_PIN( \
                WHAL_STM32H5_GPIO_PORT_D, 9, WHAL_STM32H5_GPIO_MODE_ALTFN, \
                WHAL_STM32H5_GPIO_OUTTYPE_PUSHPULL, WHAL_STM32H5_GPIO_SPEED_FAST, \
                WHAL_STM32H5_GPIO_PULL_UP, 7), \
            [ETH_RMII_REF_CLK_PIN] = WHAL_STM32H5_GPIO_PIN( \
                WHAL_STM32H5_GPIO_PORT_A, 1, WHAL_STM32H5_GPIO_MODE_ALTFN, \
                WHAL_STM32H5_GPIO_OUTTYPE_PUSHPULL, WHAL_STM32H5_GPIO_SPEED_HIGH, \
                WHAL_STM32H5_GPIO_PULL_NONE, 11), \
            [ETH_RMII_MDIO_PIN] = WHAL_STM32H5_GPIO_PIN( \
                WHAL_STM32H5_GPIO_PORT_A, 2, WHAL_STM32H5_GPIO_MODE_ALTFN, \
                WHAL_STM32H5_GPIO_OUTTYPE_PUSHPULL, WHAL_STM32H5_GPIO_SPEED_HIGH, \
                WHAL_STM32H5_GPIO_PULL_NONE, 11), \
            [ETH_RMII_MDC_PIN] = WHAL_STM32H5_GPIO_PIN( \
                WHAL_STM32H5_GPIO_PORT_C, 1, WHAL_STM32H5_GPIO_MODE_ALTFN, \
                WHAL_STM32H5_GPIO_OUTTYPE_PUSHPULL, WHAL_STM32H5_GPIO_SPEED_HIGH, \
                WHAL_STM32H5_GPIO_PULL_NONE, 11), \
            [ETH_RMII_CRS_DV_PIN] = WHAL_STM32H5_GPIO_PIN( \
                WHAL_STM32H5_GPIO_PORT_A, 7, WHAL_STM32H5_GPIO_MODE_ALTFN, \
                WHAL_STM32H5_GPIO_OUTTYPE_PUSHPULL, WHAL_STM32H5_GPIO_SPEED_HIGH, \
                WHAL_STM32H5_GPIO_PULL_NONE, 11), \
            [ETH_RMII_RXD0_PIN] = WHAL_STM32H5_GPIO_PIN( \
                WHAL_STM32H5_GPIO_PORT_C, 4, WHAL_STM32H5_GPIO_MODE_ALTFN, \
                WHAL_STM32H5_GPIO_OUTTYPE_PUSHPULL, WHAL_STM32H5_GPIO_SPEED_HIGH, \
                WHAL_STM32H5_GPIO_PULL_NONE, 11), \
            [ETH_RMII_RXD1_PIN] = WHAL_STM32H5_GPIO_PIN( \
                WHAL_STM32H5_GPIO_PORT_C, 5, WHAL_STM32H5_GPIO_MODE_ALTFN, \
                WHAL_STM32H5_GPIO_OUTTYPE_PUSHPULL, WHAL_STM32H5_GPIO_SPEED_HIGH, \
                WHAL_STM32H5_GPIO_PULL_NONE, 11), \
            [ETH_RMII_TX_EN_PIN] = WHAL_STM32H5_GPIO_PIN( \
                WHAL_STM32H5_GPIO_PORT_G, 11, WHAL_STM32H5_GPIO_MODE_ALTFN, \
                WHAL_STM32H5_GPIO_OUTTYPE_PUSHPULL, WHAL_STM32H5_GPIO_SPEED_HIGH, \
                WHAL_STM32H5_GPIO_PULL_NONE, 11), \
            [ETH_RMII_TXD0_PIN] = WHAL_STM32H5_GPIO_PIN( \
                WHAL_STM32H5_GPIO_PORT_G, 13, WHAL_STM32H5_GPIO_MODE_ALTFN, \
                WHAL_STM32H5_GPIO_OUTTYPE_PUSHPULL, WHAL_STM32H5_GPIO_SPEED_HIGH, \
                WHAL_STM32H5_GPIO_PULL_NONE, 11), \
            [ETH_RMII_TXD1_PIN] = WHAL_STM32H5_GPIO_PIN( \
                WHAL_STM32H5_GPIO_PORT_B, 15, WHAL_STM32H5_GPIO_MODE_ALTFN, \
                WHAL_STM32H5_GPIO_OUTTYPE_PUSHPULL, WHAL_STM32H5_GPIO_SPEED_HIGH, \
                WHAL_STM32H5_GPIO_PULL_NONE, 11), \
        }, \
        .pinCount = PIN_COUNT, \
    }, \
}

/* RNG dev initializer — device struct defined in the rng driver code. */
#define WHAL_CFG_STM32H5_RNG_DEV { \
    .base = WHAL_STM32H563_RNG_BASE, \
    .cfg  = (void *)&(const whal_Stm32h5_Rng_Cfg){ \
        .timeout = &g_whalTimeout, \
    }, \
}

/* UART dev initializer — device struct defined in the UART driver code. Named
 * WHAL_CFG_STM32WB_UART_DEV (not _STM32H5_) because the STM32H5 USART reuses
 * the shared STM32WB UART driver, which instantiates the device from that
 * exact name. USART3 on the ST-Link VCP; BRR for PCLK 168 MHz @ 115200. */
#define WHAL_CFG_STM32WB_UART_DEV { \
    .base = WHAL_STM32H563_USART3_BASE, \
    .cfg  = (void *)&(const whal_Stm32h5_Uart_Cfg){ \
        .brr = WHAL_STM32H5_UART_BRR(168000000, 115200), \
        .timeout = &g_whalTimeout, \
    }, \
}

/* ETH descriptor rings + buffer pool — defined in board.c, captured by the
 * ETH device's cfg below (expanded in the eth driver code). */
#define BOARD_ETH_TX_DESC_COUNT 3
#define BOARD_ETH_RX_DESC_COUNT 4
#define BOARD_ETH_TX_BUF_SIZE   1536
#define BOARD_ETH_RX_BUF_SIZE   1536

extern whal_Stm32h5_Eth_TxDesc ethTxDescs[BOARD_ETH_TX_DESC_COUNT];
extern whal_Stm32h5_Eth_RxDesc ethRxDescs[BOARD_ETH_RX_DESC_COUNT];
extern uint8_t ethTxBufs[BOARD_ETH_TX_DESC_COUNT * BOARD_ETH_TX_BUF_SIZE];
extern uint8_t ethRxBufs[BOARD_ETH_RX_DESC_COUNT * BOARD_ETH_RX_BUF_SIZE];

#ifndef BOARD_MAC_ADDR
#define BOARD_MAC_ADDR {0x00, 0x80, 0xE1, 0x00, 0x00, 0x01}
#endif

/* ETH dev initializer — device struct defined in the eth driver code. */
#define WHAL_CFG_STM32H5_ETH_DEV { \
    .base    = WHAL_STM32H563_ETH_BASE, \
    .macAddr = BOARD_MAC_ADDR, \
    .cfg     = (void *)&(const whal_Stm32h5_Eth_Cfg){ \
        .txDescs     = ethTxDescs, \
        .txBufs      = ethTxBufs, \
        .txDescCount = BOARD_ETH_TX_DESC_COUNT, \
        .txBufSize   = BOARD_ETH_TX_BUF_SIZE, \
        .rxDescs     = ethRxDescs, \
        .rxBufs      = ethRxBufs, \
        .rxDescCount = BOARD_ETH_RX_DESC_COUNT, \
        .rxBufSize   = BOARD_ETH_RX_BUF_SIZE, \
        .mdioCr      = 4, /* HCLK 168 MHz -> MDC = 168/102 ~= 1.6 MHz */ \
        .timeout     = &g_whalTimeout, \
    }, \
}

/* LAN8742A PHY dev initializer — device struct defined in the phy driver code. */
#define WHAL_CFG_LAN8742A_DEV { \
    .eth  = NULL, \
    .addr = BOARD_ETH_PHY_ADDR, \
    .cfg  = (void *)&(const whal_Lan8742a_Cfg){ \
        .timeout = &g_whalTimeout, \
    }, \
}

/* SysTick dev initializer — device struct defined in the systick driver code. */
#define WHAL_CFG_SYSTICK_DEV { \
    .base = WHAL_CORTEX_M33_SYSTICK_BASE, \
    .cfg  = (void *)&(const whal_SysTick_Cfg){ \
        .cyclesPerTick = (168000000-1) / 1000, \
        .clkSrc  = WHAL_SYSTICK_CLKSRC_SYSCLK, \
        .tickInt = WHAL_SYSTICK_TICKINT_ENABLED, \
    }, \
}

whal_Error board_init(void);
whal_Error board_deinit(void);
uint64_t board_get_tick(void);

#endif /* BOARD_H */

/* board.c
 *
 * Copyright (C) 2024-2026 wolfSSL Inc.
 *
 * Minimal board configuration for STM32H563ZI Nucleo-144
 * Only sets up what's needed for wolfIP: clocks, GPIO, Ethernet, PHY.
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
#include <stddef.h>
#include "board.h"
#include <wolfHAL/platform/st/stm32h563xx.h>
#include <wolfHAL/eth_phy/lan8742a_eth_phy.h>

/* SysTick timing */
volatile uint32_t g_tick = 0;

void SysTick_Handler(void)
{
    g_tick++;
}

uint32_t board_get_tick(void)
{
    return g_tick;
}

whal_Timeout g_whalTimeout = {
    .timeoutTicks = 1000,
    .GetTick = board_get_tick,
};

/* Clock: PLL1 from HSI to 168 MHz */
static whal_Clock clock = {
    .regmap = { WHAL_STM32H563_RCC_REGMAP },
};

static const whal_Stm32h5_Rcc_PeriphClk clocks[] = {
    {WHAL_STM32H563_GPIOA_CLOCK},
    {WHAL_STM32H563_GPIOB_CLOCK},
    {WHAL_STM32H563_GPIOC_CLOCK},
    {WHAL_STM32H563_GPIOD_CLOCK},
    {WHAL_STM32H563_GPIOG_CLOCK},
    {WHAL_STM32H563_USART3_CLOCK},
    {WHAL_STM32H563_RNG_CLOCK},
    {WHAL_STM32H563_SBS_CLOCK},
};
#define CLOCK_COUNT (sizeof(clocks) / sizeof(clocks[0]))

static const whal_Stm32h5_Rcc_PeriphClk eth_clocks[] = {
    {WHAL_STM32H563_ETH_CLOCK},
    {WHAL_STM32H563_ETHTX_CLOCK},
    {WHAL_STM32H563_ETHRX_CLOCK},
};
#define ETH_CLOCK_COUNT (sizeof(eth_clocks) / sizeof(eth_clocks[0]))

/* GPIO: only RMII pins */
static whal_Gpio gpio = {
    .regmap = { WHAL_STM32H563_GPIO_REGMAP },
    /* .driver: direct API mapping */

    .cfg = &(whal_Stm32h5_Gpio_Cfg) {
        .pinCfg = (whal_Stm32h5_Gpio_PinCfg[PIN_COUNT]) {
            /* USART3 TX on PD8, AF7 (ST-Link VCP) */
            [UART_TX_PIN] = WHAL_STM32H5_GPIO_PIN(
                WHAL_STM32H5_GPIO_PORT_D, 8, WHAL_STM32H5_GPIO_MODE_ALTFN,
                WHAL_STM32H5_GPIO_OUTTYPE_PUSHPULL, WHAL_STM32H5_GPIO_SPEED_FAST,
                WHAL_STM32H5_GPIO_PULL_UP, 7),
            /* USART3 RX on PD9, AF7 (ST-Link VCP) */
            [UART_RX_PIN] = WHAL_STM32H5_GPIO_PIN(
                WHAL_STM32H5_GPIO_PORT_D, 9, WHAL_STM32H5_GPIO_MODE_ALTFN,
                WHAL_STM32H5_GPIO_OUTTYPE_PUSHPULL, WHAL_STM32H5_GPIO_SPEED_FAST,
                WHAL_STM32H5_GPIO_PULL_UP, 7),
            [ETH_RMII_REF_CLK_PIN] = WHAL_STM32H5_GPIO_PIN(
                WHAL_STM32H5_GPIO_PORT_A, 1, WHAL_STM32H5_GPIO_MODE_ALTFN,
                0, WHAL_STM32H5_GPIO_SPEED_HIGH,
                WHAL_STM32H5_GPIO_PULL_NONE, 11),
            [ETH_RMII_MDIO_PIN] = WHAL_STM32H5_GPIO_PIN(
                WHAL_STM32H5_GPIO_PORT_A, 2, WHAL_STM32H5_GPIO_MODE_ALTFN,
                0, WHAL_STM32H5_GPIO_SPEED_HIGH,
                WHAL_STM32H5_GPIO_PULL_NONE, 11),
            [ETH_RMII_MDC_PIN] = WHAL_STM32H5_GPIO_PIN(
                WHAL_STM32H5_GPIO_PORT_C, 1, WHAL_STM32H5_GPIO_MODE_ALTFN,
                0, WHAL_STM32H5_GPIO_SPEED_HIGH,
                WHAL_STM32H5_GPIO_PULL_NONE, 11),
            [ETH_RMII_CRS_DV_PIN] = WHAL_STM32H5_GPIO_PIN(
                WHAL_STM32H5_GPIO_PORT_A, 7, WHAL_STM32H5_GPIO_MODE_ALTFN,
                0, WHAL_STM32H5_GPIO_SPEED_HIGH,
                WHAL_STM32H5_GPIO_PULL_NONE, 11),
            [ETH_RMII_RXD0_PIN] = WHAL_STM32H5_GPIO_PIN(
                WHAL_STM32H5_GPIO_PORT_C, 4, WHAL_STM32H5_GPIO_MODE_ALTFN,
                0, WHAL_STM32H5_GPIO_SPEED_HIGH,
                WHAL_STM32H5_GPIO_PULL_NONE, 11),
            [ETH_RMII_RXD1_PIN] = WHAL_STM32H5_GPIO_PIN(
                WHAL_STM32H5_GPIO_PORT_C, 5, WHAL_STM32H5_GPIO_MODE_ALTFN,
                0, WHAL_STM32H5_GPIO_SPEED_HIGH,
                WHAL_STM32H5_GPIO_PULL_NONE, 11),
            [ETH_RMII_TX_EN_PIN] = WHAL_STM32H5_GPIO_PIN(
                WHAL_STM32H5_GPIO_PORT_G, 11, WHAL_STM32H5_GPIO_MODE_ALTFN,
                0, WHAL_STM32H5_GPIO_SPEED_HIGH,
                WHAL_STM32H5_GPIO_PULL_NONE, 11),
            [ETH_RMII_TXD0_PIN] = WHAL_STM32H5_GPIO_PIN(
                WHAL_STM32H5_GPIO_PORT_G, 13, WHAL_STM32H5_GPIO_MODE_ALTFN,
                0, WHAL_STM32H5_GPIO_SPEED_HIGH,
                WHAL_STM32H5_GPIO_PULL_NONE, 11),
            [ETH_RMII_TXD1_PIN] = WHAL_STM32H5_GPIO_PIN(
                WHAL_STM32H5_GPIO_PORT_B, 15, WHAL_STM32H5_GPIO_MODE_ALTFN,
                0, WHAL_STM32H5_GPIO_SPEED_HIGH,
                WHAL_STM32H5_GPIO_PULL_NONE, 11),
        },
        .pinCount = PIN_COUNT,
    },
};

/* Timer: SysTick at 1 ms */
static whal_Timer timer = {
    .regmap = { WHAL_CORTEX_M33_SYSTICK_REGMAP },
    /* .driver: direct API mapping */

    .cfg = &(whal_SysTick_Cfg) {
        .cyclesPerTick = 168000000 / 1000,
        .clkSrc = WHAL_SYSTICK_CLKSRC_SYSCLK,
        .tickInt = WHAL_SYSTICK_TICKINT_ENABLED,
    },
};

/* Ethernet MAC */
#define ETH_TX_DESC_COUNT 4
#define ETH_RX_DESC_COUNT 4
#define ETH_TX_BUF_SIZE   1536
#define ETH_RX_BUF_SIZE   1536

static whal_Stm32h5_Eth_TxDesc eth_tx_descs[ETH_TX_DESC_COUNT]
    __attribute__((aligned(16)));
static whal_Stm32h5_Eth_RxDesc eth_rx_descs[ETH_RX_DESC_COUNT]
    __attribute__((aligned(16)));
static uint8_t eth_tx_bufs[ETH_TX_DESC_COUNT * ETH_TX_BUF_SIZE]
    __attribute__((aligned(4)));
static uint8_t eth_rx_bufs[ETH_RX_DESC_COUNT * ETH_RX_BUF_SIZE]
    __attribute__((aligned(4)));

#ifndef BOARD_MAC_ADDR
#define BOARD_MAC_ADDR {0x00, 0x80, 0xE1, 0x00, 0x00, 0x01}
#endif

whal_Eth g_whalEth = {
    .regmap = { WHAL_STM32H563_ETH_REGMAP },
    /* .driver: direct API mapping */

    .macAddr = BOARD_MAC_ADDR,
    .cfg = &(whal_Stm32h5_Eth_Cfg) {
        .txDescs = eth_tx_descs,
        .txBufs = eth_tx_bufs,
        .txDescCount = ETH_TX_DESC_COUNT,
        .txBufSize = ETH_TX_BUF_SIZE,
        .rxDescs = eth_rx_descs,
        .rxBufs = eth_rx_bufs,
        .rxDescCount = ETH_RX_DESC_COUNT,
        .rxBufSize = ETH_RX_BUF_SIZE,
        .timeout = &g_whalTimeout,
    },
};

/* Ethernet PHY (LAN8742A) */
whal_EthPhy g_whalEthPhy = {
    .eth = &g_whalEth,
    .addr = BOARD_ETH_PHY_ADDR,
    /* .driver: direct API mapping */

    .cfg = &(whal_Lan8742a_Cfg) {
        .timeout = &g_whalTimeout,
    },
};

/* UART: USART2 on ST-Link VCP */
whal_Uart g_whalUart = {
    .regmap = { WHAL_STM32H563_USART3_REGMAP },
    /* .driver: direct API mapping */

    .cfg = &(whal_Stm32h5_Uart_Cfg) {
        .brr = WHAL_STM32H5_UART_BRR(168000000, 115200),
        .timeout = &g_whalTimeout,
    },
};

/* RNG */
whal_Rng g_whalRng = {
    .regmap = { WHAL_STM32H563_RNG_REGMAP },
    /* .driver: direct API mapping */

    .cfg = &(whal_Stm32h5_Rng_Cfg) {
        .timeout = &g_whalTimeout,
    },
};

/* Flash: needed for latency configuration before clock increase */
static whal_Flash flash = {
    .regmap = { WHAL_STM32H563_FLASH_REGMAP },
    /* .driver: direct API mapping */

    .cfg = &(whal_Stm32h5_Flash_Cfg) {
        .startAddr = 0x08000000,
        .size = 0x200000,
        .timeout = &g_whalTimeout,
    },
};

/* 5 wait states + WRHIGHFREQ=2 for 168 MHz */
#define FLASH_LATENCY_168MHZ ((2 << 4) | 5)

whal_Error board_init(void)
{
    whal_Error err;
    size_t i;

    /* Set flash latency before increasing clock speed */
    err = whal_Stm32h5_Flash_Ext_SetLatency(&flash, FLASH_LATENCY_168MHZ);
    if (err)
        return err;

    /* HSI 64 MHz -> PLL1 (HSI/8 * 63 / 3 = 168 MHz) -> SYSCLK = PLL1 */

    /* RCC_CR.HSIDIV resets to /4 (16 MHz) on H5, not /1. Force it back to
     * /1 so the PLL sees 64 MHz; otherwise the divider chain below silently
     * lands on 42 MHz instead of 168 MHz. */
    err = whal_Stm32h5_Rcc_SetHsiDiv(&clock, 0);
    if (err)
        return err;

    err = whal_Stm32h5_Rcc_EnableOsc(&clock,
        &(whal_Stm32h5_Rcc_OscCfg){WHAL_STM32H5_RCC_HSI_CFG});
    if (err)
        return err;

    err = whal_Stm32h5_Rcc_EnablePll1(&clock, &(whal_Stm32h5_Rcc_PllCfg){
        .clkSrc = WHAL_STM32H5_RCC_PLLCLK_SRC_HSI,
        .m = 8, .n = 62, .p = 2, .q = 2, .r = 2,
    });
    if (err)
        return err;

    err = whal_Stm32h5_Rcc_SetSysClock(&clock, WHAL_STM32H5_RCC_SYSCLK_SRC_PLL1);
    if (err)
        return err;

    for (i = 0; i < CLOCK_COUNT; i++) {
        err = whal_Stm32h5_Rcc_EnablePeriphClk(&clock, &clocks[i]);
        if (err)
            return err;
    }

    /* Select RMII mode in SBS_PMCR before enabling ETH clocks */
    #define SBS_PMCR       (*(volatile uint32_t *)0x44000500)
    #define SBS_PMCR_ETH_SEL_Msk  (7UL << 21)
    #define SBS_PMCR_ETH_SEL_RMII (4UL << 21)
    SBS_PMCR = (SBS_PMCR & ~SBS_PMCR_ETH_SEL_Msk) | SBS_PMCR_ETH_SEL_RMII;

    for (i = 0; i < ETH_CLOCK_COUNT; i++) {
        err = whal_Stm32h5_Rcc_EnablePeriphClk(&clock, &eth_clocks[i]);
        if (err)
            return err;
    }

    err = whal_Gpio_Init(&gpio);
    if (err)
        return err;

    err = whal_Uart_Init(&g_whalUart);
    if (err)
        return err;

    /* Enable HSI48 for RNG kernel clock */
    err = whal_Stm32h5_Rcc_EnableOsc(&clock,
        &(whal_Stm32h5_Rcc_OscCfg){WHAL_STM32H5_RCC_HSI48_CFG});
    if (err)
        return err;

    err = whal_Rng_Init(&g_whalRng);
    if (err)
        return err;

    err = whal_Eth_Init(&g_whalEth);
    if (err)
        return err;

    err = whal_EthPhy_Init(&g_whalEthPhy);
    if (err)
        return err;

    err = whal_Timer_Init(&timer);
    if (err)
        return err;

    err = whal_Timer_Start(&timer);
    if (err)
        return err;

    return WHAL_SUCCESS;
}

whal_Error board_deinit(void)
{
    whal_Error err;
    size_t i;

    err = whal_Timer_Stop(&timer);
    if (err)
        return err;

    err = whal_Timer_Deinit(&timer);
    if (err)
        return err;

    err = whal_EthPhy_Deinit(&g_whalEthPhy);
    if (err)
        return err;

    err = whal_Eth_Deinit(&g_whalEth);
    if (err)
        return err;

    err = whal_Rng_Deinit(&g_whalRng);
    if (err)
        return err;

    err = whal_Uart_Deinit(&g_whalUart);
    if (err)
        return err;

    err = whal_Gpio_Deinit(&gpio);
    if (err)
        return err;

    for (i = 0; i < ETH_CLOCK_COUNT; i++) {
        err = whal_Stm32h5_Rcc_DisablePeriphClk(&clock, &eth_clocks[i]);
        if (err)
            return err;
    }

    for (i = 0; i < CLOCK_COUNT; i++) {
        err = whal_Stm32h5_Rcc_DisablePeriphClk(&clock, &clocks[i]);
        if (err)
            return err;
    }

    err = whal_Stm32h5_Rcc_SetSysClock(&clock, WHAL_STM32H5_RCC_SYSCLK_SRC_HSI);
    if (err)
        return err;
    err = whal_Stm32h5_Rcc_DisablePll1(&clock);
    if (err)
        return err;

    return WHAL_SUCCESS;
}

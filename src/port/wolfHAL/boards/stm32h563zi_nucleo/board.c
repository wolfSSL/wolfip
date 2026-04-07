/* board.c
 *
 * Copyright (C) 2024-2026 wolfSSL Inc.
 *
 * Minimal board configuration for STM32H563ZI Nucleo-144
 * Only sets up what's needed for wolfIP: clocks, GPIO, Ethernet, PHY, RNG.
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

/* Peripheral clocks enabled before bringing up the peripherals (ETH clocks
 * are enabled separately, after RMII mode is selected in SBS). */
static const whal_Stm32h5_Rcc_PeriphClk g_periphClks[] = {
    {WHAL_STM32H563_GPIOA_CLOCK},
    {WHAL_STM32H563_GPIOB_CLOCK},
    {WHAL_STM32H563_GPIOC_CLOCK},
    {WHAL_STM32H563_GPIOD_CLOCK},
    {WHAL_STM32H563_GPIOG_CLOCK},
    {WHAL_STM32H563_USART3_CLOCK},
    {WHAL_STM32H563_RNG_CLOCK},
    {WHAL_STM32H563_SBS_CLOCK},
};
#define PERIPH_CLK_COUNT (sizeof(g_periphClks) / sizeof(g_periphClks[0]))

static const whal_Stm32h5_Rcc_PeriphClk g_ethClocks[] = {
    {WHAL_STM32H563_ETH_CLOCK},
    {WHAL_STM32H563_ETHTX_CLOCK},
    {WHAL_STM32H563_ETHRX_CLOCK},
};
#define ETH_CLOCK_COUNT (sizeof(g_ethClocks) / sizeof(g_ethClocks[0]))

/* Ethernet descriptor rings + buffer pool. Referenced by the ETH singleton's
 * cfg (WHAL_CFG_STM32H5_ETH_DEV in board.h), so these must be global. */
whal_Stm32h5_Eth_TxDesc ethTxDescs[BOARD_ETH_TX_DESC_COUNT]
    __attribute__((aligned(16)));
whal_Stm32h5_Eth_RxDesc ethRxDescs[BOARD_ETH_RX_DESC_COUNT]
    __attribute__((aligned(16)));
uint8_t ethTxBufs[BOARD_ETH_TX_DESC_COUNT * BOARD_ETH_TX_BUF_SIZE]
    __attribute__((aligned(4)));
uint8_t ethRxBufs[BOARD_ETH_RX_DESC_COUNT * BOARD_ETH_RX_BUF_SIZE]
    __attribute__((aligned(4)));

/* UART: USART3 on the ST-Link VCP (caller-allocated, multi-instance driver) */
whal_Uart g_whalUart = {
    .base = WHAL_STM32H563_USART3_BASE,
    /* .driver: direct API mapping */
    .cfg = &(whal_Stm32h5_Uart_Cfg) {
        .brr = WHAL_STM32H5_UART_BRR(168000000, 115200),
        .timeout = &g_whalTimeout,
    },
};

/*
 * FLASH_ACR (0x40022000): LATENCY[3:0] = 5 wait states for 168 MHz,
 * WRHIGHFREQ[5:4] = 2. Must be set before raising the clock.
 */
#define FLASH_ACR_ADDR 0x40022000
#define FLASH_ACR_LATENCY_168MHZ ((2 << 4) | 5)

/* RMII mode select lives in SBS_PMCR (0x44000500), bits [23:21] = 0b100. */
#define SBS_PMCR              (*(volatile uint32_t *)0x44000500)
#define SBS_PMCR_ETH_SEL_Msk  (7UL << 21)
#define SBS_PMCR_ETH_SEL_RMII (4UL << 21)

whal_Error board_init(void)
{
    whal_Error err;
    size_t i;

    /* Set flash latency before increasing clock speed */
    *(volatile uint32_t *)FLASH_ACR_ADDR = FLASH_ACR_LATENCY_168MHZ;

    /* HSI 64 MHz -> PLL1 (HSI/8 * 63 / 3 = 168 MHz) -> SYSCLK = PLL1 */

    /* RCC_CR.HSIDIV resets to /4 (16 MHz) on H5, not /1. Force it back to
     * /1 so the PLL sees 64 MHz; otherwise the divider chain below silently
     * lands on 42 MHz instead of 168 MHz. */
    err = whal_Stm32h5_Rcc_SetHsiDiv(0);
    if (err)
        return err;

    err = whal_Stm32h5_Rcc_EnableOsc(
        &(whal_Stm32h5_Rcc_OscCfg){WHAL_STM32H5_RCC_HSI_CFG});
    if (err)
        return err;

    err = whal_Stm32h5_Rcc_EnablePll1(&(whal_Stm32h5_Rcc_PllCfg){
        .clkSrc = WHAL_STM32H5_RCC_PLLCLK_SRC_HSI,
        .m = 8, .n = 62, .p = 2, .q = 2, .r = 2,
    });
    if (err)
        return err;

    err = whal_Stm32h5_Rcc_SetSysClock(WHAL_STM32H5_RCC_SYSCLK_SRC_PLL1);
    if (err)
        return err;

    /* Enable peripheral clocks (ETH excluded — needs SBS RMII config first) */
    for (i = 0; i < PERIPH_CLK_COUNT; i++) {
        err = whal_Stm32h5_Rcc_EnablePeriphClk(&g_periphClks[i]);
        if (err)
            return err;
    }

    /* Select RMII mode before enabling the ETH clocks */
    SBS_PMCR = (SBS_PMCR & ~SBS_PMCR_ETH_SEL_Msk) | SBS_PMCR_ETH_SEL_RMII;

    for (i = 0; i < ETH_CLOCK_COUNT; i++) {
        err = whal_Stm32h5_Rcc_EnablePeriphClk(&g_ethClocks[i]);
        if (err)
            return err;
    }

    /* Enable HSI48 for the RNG kernel clock */
    err = whal_Stm32h5_Rcc_EnableOsc(
        &(whal_Stm32h5_Rcc_OscCfg){WHAL_STM32H5_RCC_HSI48_CFG});
    if (err)
        return err;

    err = whal_Gpio_Init(WHAL_INTERNAL_DEV);
    if (err)
        return err;

    err = whal_Uart_Init(&g_whalUart);
    if (err)
        return err;

    err = whal_Rng_Init(WHAL_INTERNAL_DEV);
    if (err)
        return err;

    err = whal_Timer_Init(WHAL_INTERNAL_DEV);
    if (err)
        return err;

    err = whal_Timer_Start(WHAL_INTERNAL_DEV);
    if (err)
        return err;

    err = whal_Eth_Init(WHAL_INTERNAL_DEV);
    if (err)
        return err;

    err = whal_EthPhy_Init(WHAL_INTERNAL_DEV);
    if (err)
        return err;

    return WHAL_SUCCESS;
}

whal_Error board_deinit(void)
{
    whal_Error err;
    size_t i;

    err = whal_Timer_Stop(WHAL_INTERNAL_DEV);
    if (err)
        return err;

    err = whal_Timer_Deinit(WHAL_INTERNAL_DEV);
    if (err)
        return err;

    err = whal_EthPhy_Deinit(WHAL_INTERNAL_DEV);
    if (err)
        return err;

    err = whal_Eth_Deinit(WHAL_INTERNAL_DEV);
    if (err)
        return err;

    err = whal_Rng_Deinit(WHAL_INTERNAL_DEV);
    if (err)
        return err;

    err = whal_Uart_Deinit(&g_whalUart);
    if (err)
        return err;

    err = whal_Gpio_Deinit(WHAL_INTERNAL_DEV);
    if (err)
        return err;

    for (i = 0; i < ETH_CLOCK_COUNT; i++) {
        err = whal_Stm32h5_Rcc_DisablePeriphClk(&g_ethClocks[i]);
        if (err)
            return err;
    }

    for (i = 0; i < PERIPH_CLK_COUNT; i++) {
        err = whal_Stm32h5_Rcc_DisablePeriphClk(&g_periphClks[i]);
        if (err)
            return err;
    }

    err = whal_Stm32h5_Rcc_SetSysClock(WHAL_STM32H5_RCC_SYSCLK_SRC_HSI);
    if (err)
        return err;
    err = whal_Stm32h5_Rcc_DisablePll1();
    if (err)
        return err;

    return WHAL_SUCCESS;
}

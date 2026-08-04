# wolfHAL-specific build settings for the STM32H563ZI Nucleo board.
#
# Included by the port Makefile only when ENABLE_WOLFHAL=1. The port
# Makefile owns the toolchain, base CFLAGS, include paths, and linker
# script; this fragment contributes only the wolfHAL driver selection
# and the wolfHAL driver translation units. WOLFHAL_ROOT is set by the
# port Makefile.

# Direct-API-mapping driver selection: one concrete driver TU per domain,
# no generic dispatch layer (which would redefine the top-level symbols).
CFLAGS += -DPLATFORM_STM32H5
CFLAGS += -DWHAL_CFG_STM32H5_GPIO_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_STM32H5_RCC_PLL_DRIVER
CFLAGS += -DWHAL_CFG_STM32H5_RCC_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_STM32H5_UART_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_STM32H5_UART_SINGLE_INSTANCE
CFLAGS += -DWHAL_CFG_STM32H5_RNG_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_STM32H5_ETH_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_LAN8742A_ETH_PHY_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_STM32H5_FLASH_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_SYSTICK_TIMER_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_64BIT_TICK

# wolfHAL driver translation units. Built with relaxed warnings via the
# port Makefile's $(WOLFHAL_ROOT)/%.o rule.
SRCS += $(WOLFHAL_ROOT)/src/reg.c
SRCS += $(WOLFHAL_ROOT)/src/eth/stm32h5_eth.c
SRCS += $(WOLFHAL_ROOT)/src/eth_phy/lan8742a_eth_phy.c
SRCS += $(WOLFHAL_ROOT)/src/gpio/stm32h5_gpio.c
SRCS += $(WOLFHAL_ROOT)/src/uart/stm32h5_uart.c
SRCS += $(WOLFHAL_ROOT)/src/rng/stm32h5_rng.c
SRCS += $(WOLFHAL_ROOT)/src/timer/systick.c

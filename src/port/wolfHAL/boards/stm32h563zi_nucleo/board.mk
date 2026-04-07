_WOLFIP_BOARD_DIR := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))

WOLFHAL_ROOT ?= $(ROOT)/../wolfHAL

GCC = $(GCC_PATH)arm-none-eabi-gcc
LD = $(GCC_PATH)arm-none-eabi-ld
OBJCOPY = $(GCC_PATH)arm-none-eabi-objcopy

CFLAGS += -Wall -Werror -g3 -ffreestanding -nostdlib -mcpu=cortex-m33 -Os
CFLAGS += -DPLATFORM_STM32H5 -MMD -MP
CFLAGS += -DWHAL_CFG_STM32H5_GPIO_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_STM32H5_RCC_PLL_DRIVER
CFLAGS += -DWHAL_CFG_STM32H5_RCC_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_STM32H5_UART_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_STM32H5_RNG_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_STM32H5_ETH_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_LAN8742A_ETH_PHY_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_STM32H5_FLASH_DIRECT_API_MAPPING
CFLAGS += -DWHAL_CFG_SYSTICK_TIMER_DIRECT_API_MAPPING
CFLAGS += -I$(WOLFHAL_ROOT) -I$(_WOLFIP_BOARD_DIR)
CFLAGS += -I$(ROOT) -I$(ROOT)/src -I$(PORT_DIR)

CFLAGS += -fdata-sections -ffunction-sections

LDFLAGS = -nostdlib -Wl,-gc-sections
LDLIBS = -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group
LINKER_SCRIPT ?= $(_WOLFIP_BOARD_DIR)/linker.ld

BOARD_SOURCE = $(_WOLFIP_BOARD_DIR)/startup.c
BOARD_SOURCE += $(_WOLFIP_BOARD_DIR)/ivt.c
BOARD_SOURCE += $(_WOLFIP_BOARD_DIR)/board.c
BOARD_SOURCE += $(_WOLFIP_BOARD_DIR)/syscalls.c

# wolfHAL drivers
# Domains with WHAL_CFG_*_API_MAPPING_* set include only the driver TU;
# the generic dispatch TU would redefine the top-level symbols.
BOARD_SOURCE += $(WOLFHAL_ROOT)/src/eth/stm32h5_eth.c
BOARD_SOURCE += $(WOLFHAL_ROOT)/src/eth_phy/lan8742a_eth_phy.c
BOARD_SOURCE += $(WOLFHAL_ROOT)/src/clock/stm32h5_rcc.c
BOARD_SOURCE += $(WOLFHAL_ROOT)/src/gpio/stm32h5_gpio.c
BOARD_SOURCE += $(WOLFHAL_ROOT)/src/uart/stm32h5_uart.c
BOARD_SOURCE += $(WOLFHAL_ROOT)/src/rng/stm32h5_rng.c
BOARD_SOURCE += $(WOLFHAL_ROOT)/src/flash/stm32h5_flash.c
BOARD_SOURCE += $(WOLFHAL_ROOT)/src/timer/systick.c

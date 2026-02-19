CC ?= arm-none-eabi-gcc
OBJCOPY ?= arm-none-eabi-objcopy
SIZE ?= arm-none-eabi-size

ROOT := ../../..

# VA416xx SDK path (default: sibling directory to wolfip repo)
SDK_ROOT ?= ../../../../VA416xx_SDK

# Base compiler flags (Cortex-M4, no FPU)
CFLAGS := -mcpu=cortex-m4 -mthumb -mfloat-abi=soft -Os -ffreestanding
CFLAGS += -fdata-sections -ffunction-sections
CFLAGS += -g -ggdb -Wall -Wextra -Werror

# Optional extra flags (e.g., EXTRA_CFLAGS=-DDEBUG_ETH for verbose ETH diagnostics)
CFLAGS += $(EXTRA_CFLAGS)

# Include paths
CFLAGS += -I. -I$(ROOT) -I$(ROOT)/src
CFLAGS += -I$(SDK_ROOT)/common/mcu/hdr
CFLAGS += -I$(SDK_ROOT)/common/drivers/hdr
CFLAGS += -I$(SDK_ROOT)/common/BSP/evk/hdr

# Relaxed warnings for SDK and external sources
CFLAGS_EXT := $(filter-out -Werror,$(CFLAGS))
CFLAGS_EXT += -Wno-unused-variable -Wno-unused-function -Wno-unused-parameter
CFLAGS_EXT += -Wno-sign-compare -Wno-missing-field-initializers
# Workaround SDK typo: en_iocfg_dir_input vs en_iocfg_dir__input
CFLAGS_EXT += -Den_iocfg_dir_input=en_iocfg_dir__input
# HBO (Heart Beat Oscillator) not exposed in a shared header
CFLAGS_EXT += -DHBO=20000000UL

LDFLAGS := -nostdlib -T target.ld -Wl,-gc-sections

# Application sources (compiled with strict flags)
APP_SRCS := startup.c ivt.c syscalls.c main.c va416xx_eth.c
APP_OBJS := $(patsubst %.c,%.o,$(APP_SRCS))

# wolfIP core source
WOLFIP_SRC := $(ROOT)/src/wolfip.c
WOLFIP_OBJ := wolfip.o

# SDK sources (compiled with relaxed flags, objects go in local sdk/ dir)
SDK_SRC_DIR := $(SDK_ROOT)/common
SDK_SRCS := \
    $(SDK_SRC_DIR)/mcu/src/system_va416xx.c \
    $(SDK_SRC_DIR)/drivers/src/va416xx_hal.c \
    $(SDK_SRC_DIR)/drivers/src/va416xx_hal_ethernet.c \
    $(SDK_SRC_DIR)/drivers/src/va416xx_hal_uart.c \
    $(SDK_SRC_DIR)/drivers/src/va416xx_hal_ioconfig.c \
    $(SDK_SRC_DIR)/drivers/src/va416xx_hal_irqrouter.c \
    $(SDK_SRC_DIR)/drivers/src/va416xx_hal_clkgen.c

# Build SDK objects locally (avoids polluting SDK tree)
SDK_OBJS := $(notdir $(patsubst %.c,%.o,$(SDK_SRCS)))

ALL_OBJS := $(APP_OBJS) $(WOLFIP_OBJ) $(SDK_OBJS)

all: app.bin
	@echo "Built VA416xx wolfIP port"
	@$(SIZE) app.elf

app.elf: $(ALL_OBJS) target.ld
	$(CC) $(CFLAGS) $(ALL_OBJS) $(LDFLAGS) \
	    -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group -o $@

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@

# Application objects (strict warnings)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# wolfIP core (relaxed warnings)
$(WOLFIP_OBJ): $(WOLFIP_SRC)
	$(CC) $(CFLAGS_EXT) -c $< -o $@

# SDK objects (relaxed warnings, built locally)
system_va416xx.o: $(SDK_SRC_DIR)/mcu/src/system_va416xx.c
	$(CC) $(CFLAGS_EXT) -c $< -o $@

va416xx_hal.o: $(SDK_SRC_DIR)/drivers/src/va416xx_hal.c
	$(CC) $(CFLAGS_EXT) -c $< -o $@

va416xx_hal_ethernet.o: $(SDK_SRC_DIR)/drivers/src/va416xx_hal_ethernet.c
	$(CC) $(CFLAGS_EXT) -c $< -o $@

va416xx_hal_uart.o: $(SDK_SRC_DIR)/drivers/src/va416xx_hal_uart.c
	$(CC) $(CFLAGS_EXT) -c $< -o $@

va416xx_hal_ioconfig.o: $(SDK_SRC_DIR)/drivers/src/va416xx_hal_ioconfig.c
	$(CC) $(CFLAGS_EXT) -c $< -o $@

va416xx_hal_irqrouter.o: $(SDK_SRC_DIR)/drivers/src/va416xx_hal_irqrouter.c
	$(CC) $(CFLAGS_EXT) -c $< -o $@

va416xx_hal_clkgen.o: $(SDK_SRC_DIR)/drivers/src/va416xx_hal_clkgen.c
	$(CC) $(CFLAGS_EXT) -c $< -o $@

clean:
	rm -f *.o app.elf app.bin

# Show memory usage
size: app.elf
	@echo "=== Memory Usage ==="
	@$(SIZE) app.elf
	@echo ""
	@echo "Flash usage: $$($(SIZE) app.elf | awk 'NR==2{printf "%.1f%% (%d / %d bytes)", ($$1+$$2)*100/262144, $$1+$$2, 262144}')"
	@echo "RAM usage (static): $$($(SIZE) app.elf | awk 'NR==2{printf "%.1f%% (%d / %d bytes)", ($$2+$$3)*100/65536, $$2+$$3, 65536}')"

.PHONY: all clean size help

help:
	@echo "VA416xx wolfIP Build System"
	@echo ""
	@echo "Usage: make [target] [options]"
	@echo ""
	@echo "Targets:"
	@echo "  all      Build app.bin (default)"
	@echo "  clean    Remove build artifacts"
	@echo "  size     Show memory usage statistics"
	@echo "  help     Show this help"
	@echo ""
	@echo "Options:"
	@echo "  SDK_ROOT=   Path to VA416xx SDK (default: ../../../../VA416xx_SDK)"
	@echo "  CC=         C compiler (default: arm-none-eabi-gcc)"
	@echo ""
	@echo "Testing:"
	@echo "  ping <ip>                  # ICMP ping"
	@echo "  echo 'hello' | nc <ip> 7   # TCP echo"

CC      ?= arm-none-eabi-gcc
OBJCOPY ?= arm-none-eabi-objcopy
SIZE    ?= arm-none-eabi-size

ROOT := ../../..

# Cortex-M4F with FPU (hardware float, single-precision).  Both NUCLEO-F439ZI
# and STM32439I-EVAL ship STM32F437/F439 silicon with the same FPU.
CFLAGS := -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard
CFLAGS += -Os -ffreestanding -fdata-sections -ffunction-sections
CFLAGS += -g -ggdb -Wall -Wextra -Werror

# Include paths
CFLAGS += -I. -I$(ROOT) -I$(ROOT)/src -I$(ROOT)/src/port/stm32f4

# Board selection.  Both supported boards use STM32F437/F439 silicon (same
# DWC GMAC + same register layout) but differ in PHY addr, UART pinmux,
# HSE source, and RMII TXD1 pin.  Set BOARD on the make command line:
#   BOARD=nucleo_f439zi    NUCLEO-F439ZI dev board (LAN8742A, USART3, HSE 8MHz bypass)
#   BOARD=stm32439i_eval   STM32439I-EVAL eval board (DP83848, UART4, HSE 25MHz crystal)
BOARD ?= nucleo_f439zi

ifeq ($(BOARD),nucleo_f439zi)
  CFLAGS += -DBOARD_NUCLEO_F439ZI -DSTM32F4_ETH_PHY_ADDR=0
else ifeq ($(BOARD),stm32439i_eval)
  CFLAGS += -DBOARD_STM32439I_EVAL -DSTM32F4_ETH_PHY_ADDR=1
else
  $(error Unknown BOARD '$(BOARD)' - use nucleo_f439zi or stm32439i_eval)
endif

EXTRA_CFLAGS ?=
CFLAGS += $(EXTRA_CFLAGS)

# Relaxed warnings for wolfIP core (some unused-param noise on small builds)
CFLAGS_EXT := $(filter-out -Werror,$(CFLAGS))
CFLAGS_EXT += -Wno-unused-variable -Wno-unused-function -Wno-unused-parameter

LDFLAGS := -nostdlib -T target.ld -Wl,-gc-sections

# Application sources (strict warnings)
APP_SRCS := startup.c ivt.c syscalls.c main.c \
            $(ROOT)/src/port/stm32f4/stm32f4_eth.c
APP_OBJS := startup.o ivt.o syscalls.o main.o stm32f4_eth.o

# wolfIP core (relaxed warnings)
WOLFIP_OBJ := wolfip.o

ALL_OBJS := $(APP_OBJS) $(WOLFIP_OBJ)

all: app.bin
	@echo "Built STM32F439 wolfIP port (BOARD=$(BOARD))"
	@$(SIZE) app.elf

app.elf: $(ALL_OBJS) target.ld
	$(CC) $(CFLAGS) $(ALL_OBJS) $(LDFLAGS) \
	    -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group -o $@

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@

# Local sources -- strict warnings
startup.o: startup.c
	$(CC) $(CFLAGS) -c $< -o $@
ivt.o: ivt.c
	$(CC) $(CFLAGS) -c $< -o $@
syscalls.o: syscalls.c
	$(CC) $(CFLAGS) -c $< -o $@
main.o: main.c
	$(CC) $(CFLAGS) -c $< -o $@

# Shared F4 ETH driver (strict warnings)
stm32f4_eth.o: $(ROOT)/src/port/stm32f4/stm32f4_eth.c
	$(CC) $(CFLAGS) -c $< -o $@

# wolfIP core (relaxed warnings)
$(WOLFIP_OBJ): $(ROOT)/src/wolfip.c
	$(CC) $(CFLAGS_EXT) -c $< -o $@

clean:
	rm -f *.o app.elf app.bin

# Show memory usage
size: app.elf
	@echo "=== Memory Usage ==="
	@$(SIZE) app.elf
	@echo ""
	@echo "Flash usage: $$($(SIZE) app.elf | awk 'NR==2{printf "%.2f%% (%d / %d bytes)", ($$1+$$2)*100/2097152, $$1+$$2, 2097152}')"
	@echo "RAM usage (static): $$($(SIZE) app.elf | awk 'NR==2{printf "%.2f%% (%d / %d bytes)", ($$2+$$3)*100/196608, $$2+$$3, 196608}')"

.PHONY: all clean size help

help:
	@echo "STM32F439 wolfIP Build System (supports F437/F439 silicon)"
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
	@echo "  BOARD=nucleo_f439zi        NUCLEO-F439ZI (default; LAN8742A, USART3, HSE 8MHz bypass)"
	@echo "  BOARD=stm32439i_eval       STM32439I-EVAL (DP83848, UART4, HSE 25MHz crystal)"
	@echo "  EXTRA_CFLAGS=-DDEBUG_ETH   Verbose ETH driver diagnostics"
	@echo "  CC=                        C compiler (default: arm-none-eabi-gcc)"
	@echo ""
	@echo "Testing:"
	@echo "  ping <ip>                  # ICMP ping"
	@echo "  echo 'hello' | nc <ip> 7   # TCP echo"

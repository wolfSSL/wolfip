CC := arm-none-eabi-gcc
OBJCOPY := arm-none-eabi-objcopy
SIZE := arm-none-eabi-size

ROOT := ../../..

CFLAGS := -mcpu=cortex-m4 -mthumb -mfloat-abi=soft
CFLAGS += -Os -ffreestanding -fdata-sections -ffunction-sections
CFLAGS += -g -ggdb -Wall -Wextra -Werror
CFLAGS += -I. -I$(ROOT) -I$(ROOT)/src -I$(ROOT)/src/port/lpc_enet

CFLAGS_EXT := $(filter-out -Werror,$(CFLAGS))
CFLAGS_EXT += -Wno-unused-variable -Wno-unused-function -Wno-unused-parameter
CFLAGS_EXT += -Wno-sign-compare -Wno-missing-field-initializers

LDSCRIPT ?= target_ram.ld
LDFLAGS := -nostdlib -T $(LDSCRIPT) -Wl,-gc-sections

APP_SRCS := startup.c ivt.c syscalls.c main.c
APP_OBJS := $(patsubst %.c,%.o,$(APP_SRCS))

# Shared LPC ENET driver (src/port/lpc_enet/)
LPC_ENET_SRC := $(ROOT)/src/port/lpc_enet/lpc_enet.c
LPC_ENET_OBJ := lpc_enet.o

# wolfIP core
WOLFIP_SRC := $(ROOT)/src/wolfip.c
WOLFIP_OBJ := wolfip.o

ALL_OBJS := $(APP_OBJS) $(LPC_ENET_OBJ) $(WOLFIP_OBJ)

all: app.bin
	@echo "Built LPC54S018M-EVK wolfIP port"
	@$(SIZE) app.elf

app.elf: $(ALL_OBJS) $(LDSCRIPT)
	$(CC) $(CFLAGS) $(ALL_OBJS) $(LDFLAGS) \
	    -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group -o $@

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@
	python3 fix_checksum.py $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Shared LPC ENET driver (include board header for LPC_ENET_* defines)
$(LPC_ENET_OBJ): $(LPC_ENET_SRC)
	$(CC) $(CFLAGS) -include lpc54s018_eth.h -c $< -o $@

$(WOLFIP_OBJ): $(WOLFIP_SRC)
	$(CC) $(CFLAGS_EXT) -c $< -o $@

clean:
	rm -f *.o app.elf app.bin

size: app.elf
	@$(SIZE) app.elf

.PHONY: all clean size help

help:
	@echo "LPC54S018M-EVK wolfIP Build System"
	@echo ""
	@echo "  make                Build app.bin"
	@echo "  make clean          Remove build artifacts"
	@echo "  make size           Show memory usage"
	@echo ""
	@echo "Flashing (on-board Link2 CMSIS-DAP):"
	@echo "  pyocd flash -t lpc54608 app.elf"
	@echo ""
	@echo "Testing:"
	@echo "  ping 192.168.0.200"

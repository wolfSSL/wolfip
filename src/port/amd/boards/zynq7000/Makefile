# Xilinx Zynq-7000 (Cortex-A9, ARMv7-A 32-bit) wolfIP bare-metal port
#
# Build:    make CROSS_COMPILE=arm-none-eabi-
#
# Toolchain: ARM GNU arm-none-eabi-gcc (tested with 13.2).
#
# Brought up on a ZC702 (Cortex-A9): DHCP, ICMP ping and UDP echo work.

CROSS_COMPILE ?= arm-none-eabi-
CC      := $(CROSS_COMPILE)gcc
OBJCOPY := $(CROSS_COMPILE)objcopy
SIZE    := $(CROSS_COMPILE)size

ROOT := ../../../../..
AMD    := $(ROOT)/src/port/amd
COMMON := $(AMD)/common
IP     := $(AMD)/ip
ARCH   := $(AMD)/arch/armv7

# Cortex-A9, ARMv7-A 32-bit, no NEON in cert paths.
CFLAGS  := -mcpu=cortex-a9 -marm
CFLAGS  += -Os -ffreestanding -fno-builtin -fno-common
CFLAGS  += -fdata-sections -ffunction-sections
CFLAGS  += -g -Wall -Wextra -Werror -Wno-unused-parameter
CFLAGS  += -std=gnu99
CFLAGS  += -I. -I$(COMMON) -I$(ARCH) -I$(IP) -I$(ROOT) -I$(ROOT)/src -I$(ROOT)/src/port
CFLAGS  += -DZYNQ7000 -DXILINX_ARMV7
CFLAGS  += $(CFLAGS_EXTRA)

ASFLAGS := -mcpu=cortex-a9 -marm

LDSCRIPT := target.ld
LDFLAGS  := -nostdlib -nostartfiles -T $(LDSCRIPT) -Wl,-gc-sections
# Override newlib's memset/memcpy with bytewise variants in main.c
# (the same "fast memset uses an instruction the bare-metal setup
# does not tolerate" pattern we hit on the AArch64 port).
LDFLAGS  += -Wl,--wrap=memset -Wl,--wrap=memcpy

LOCAL_C := app.c board.c uart_cadence.c uart_util.c mmu_armv7.c gic_gicv2.c \
           gem_core.c board_gem.c gem_rx_poll.c \
           phy_dp83867.c phy_marvell.c phy_dispatch_multi.c entropy.c
LOCAL_S := startup_armv7.S
LOCAL_OBJS := $(LOCAL_C:.c=.o) $(LOCAL_S:.S=.o)

WOLFIP_OBJ := wolfip.o
OBJS := $(LOCAL_OBJS) $(WOLFIP_OBJ)

# Shared sources live outside this board dir; find them by vpath so the
# .o files still land here (keeps clean + JTAG app.elf-in-place working).
vpath %.c $(COMMON):$(ARCH):$(IP)
vpath %.S $(ARCH)

all: app.elf
	@echo "Built: app.elf"
	@$(SIZE) app.elf

app.elf: $(OBJS) $(LDSCRIPT)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) \
	    -Wl,--start-group -lc -lgcc -Wl,--end-group -o $@

$(WOLFIP_OBJ): $(ROOT)/src/wolfip.c
	$(CC) $(CFLAGS) -Wno-zero-length-bounds -Wno-type-limits -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(ASFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) app.elf BOOT.BIN

.PHONY: all clean help

help:
	@echo "Zynq-7000 wolfIP build (Cortex-A9):"
	@echo "  make                         - build app.elf"
	@echo "  make clean                   - remove artifacts"
	@echo ""
	@echo "Override CROSS_COMPILE if your toolchain prefix differs."

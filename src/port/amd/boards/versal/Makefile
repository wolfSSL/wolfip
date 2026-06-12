# Xilinx Versal Gen 1 (VMK180, Cortex-A72) wolfIP bare-metal port
#
# Build:    make CROSS_COMPILE=aarch64-none-elf-
#
# Toolchain: ARM GNU aarch64-none-elf-gcc (tested with 14.3.rel1).
#
# Brought up on a VMK180 (Cortex-A72): DHCP, ICMP ping and UDP echo work.

CROSS_COMPILE ?= aarch64-none-elf-
CC      := $(CROSS_COMPILE)gcc
OBJCOPY := $(CROSS_COMPILE)objcopy
SIZE    := $(CROSS_COMPILE)size

ROOT := ../../../../..
AMD    := $(ROOT)/src/port/amd
COMMON := $(AMD)/common
IP     := $(AMD)/ip
ARCH   := $(AMD)/arch/aarch64

# Cortex-A72, AArch64, EL3 single-EL bare-metal. No SIMD/FP in the
# wolfIP/driver paths - keep -mgeneral-regs-only to catch any
# accidental FP use and make the ABI deterministic for cert.
CFLAGS  := -mcpu=cortex-a72 -mgeneral-regs-only
CFLAGS  += -Os -ffreestanding -fno-builtin -fno-common
CFLAGS  += -fdata-sections -ffunction-sections
CFLAGS  += -g -Wall -Wextra -Werror -Wno-unused-parameter
CFLAGS  += -std=gnu99
CFLAGS  += -I. -I$(COMMON) -I$(ARCH) -I$(IP) -I$(ROOT) -I$(ROOT)/src -I$(ROOT)/src/port
CFLAGS  += -DVERSAL -DXILINX_AARCH64
# Append extra defines for investigation builds, e.g.:
#   make CFLAGS_EXTRA="-DDEBUG_GEM -DDEBUG_PHY"
CFLAGS  += $(CFLAGS_EXTRA)

ASFLAGS := -mcpu=cortex-a72 -DUART_EARLY_TX_OFF=0x00

# Layout selector. Default ocm keeps the OCM-only layout that the JTAG
# iteration scripts depend on (everything in OCM @ 0xFFFC0000). Pass
# LAYOUT=ddr to relink for DDR @ 0x10000000 -- which is what wolfBoot
# uses (WOLFBOOT_LOAD_ADDRESS in zynqmp.config also applies to Versal
# when adapted).
LAYOUT ?= ocm
ifeq ($(LAYOUT),ddr)
    LDSCRIPT := target_ddr.ld
    CFLAGS   += -DAMD_LAYOUT_DDR
else ifeq ($(LAYOUT),ocm)
    LDSCRIPT := target.ld
    CFLAGS   += -DAMD_LAYOUT_OCM
else
    $(error LAYOUT must be 'ocm' or 'ddr')
endif

LDFLAGS  := -nostdlib -nostartfiles -T $(LDSCRIPT) -Wl,-gc-sections
# Replace newlib's aarch64 memset/memcpy (which use 'dc zva' and may
# hang on a similar Cortex-A72 setup; the safe pattern is to override
# them as we did on ZCU102).
LDFLAGS  += -Wl,--wrap=memset -Wl,--wrap=memcpy

LOCAL_C := app.c board.c uart_pl011.c uart_util.c mmu_aarch64.c gic_gicv3.c \
           gem_core.c board_gem.c gem_swq.c gem_rx_swq_poll.c \
           phy_dp83867.c phy_dispatch_dp83867.c entropy.c exception_aarch64.c
LOCAL_S := startup_aarch64.S
LOCAL_OBJS := $(LOCAL_C:.c=.o) $(LOCAL_S:.S=.o)

WOLFIP_OBJ := wolfip.o
OBJS := $(LOCAL_OBJS) $(WOLFIP_OBJ)

# Shared sources live outside this board dir; find them by vpath so the
# .o files still land here (keeps clean + JTAG app.elf-in-place working).
vpath %.c $(COMMON):$(ARCH):$(IP)
vpath %.S $(ARCH)

# Keep 'all' the default goal even though the layout-stamp rules below
# are defined before it.
.DEFAULT_GOAL := all

# A change in LAYOUT must force a full rebuild: OCM objects link against
# 0xFFFC0000 and a DDR build against 0x10000000, so reusing stale objects
# across a layout switch silently produces a wrong image. The stamp
# records the last LAYOUT; its mtime only bumps when LAYOUT actually
# changes, so same-layout incremental builds are unaffected.
LAYOUT_STAMP := .layout_stamp
.PHONY: FORCE
FORCE:
$(LAYOUT_STAMP): FORCE
	@if [ "`cat $@ 2>/dev/null`" != "$(LAYOUT)" ]; then \
	    echo "LAYOUT -> $(LAYOUT) (was `cat $@ 2>/dev/null`); forcing rebuild"; \
	    echo "$(LAYOUT)" > $@; \
	fi
$(OBJS): $(LAYOUT_STAMP)

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
	rm -f $(OBJS) app.elf BOOT.BIN $(LAYOUT_STAMP)

.PHONY: all clean help

help:
	@echo "Versal Gen 1 wolfIP build (Cortex-A72):"
	@echo "  make                         - build app.elf (OCM layout)"
	@echo "  make LAYOUT=ddr              - DDR layout for wolfBoot"
	@echo "  make clean                   - remove artifacts"
	@echo ""
	@echo "Override CROSS_COMPILE if your toolchain prefix differs."

# Xilinx ZCU102 (UltraScale+ MPSoC, Cortex-A53) wolfIP bare-metal port
#
# Build:    make CROSS_COMPILE=aarch64-none-elf-
# Bootbin:  FSBL_ELF=/path/to/fsbl.elf make bootbin
#
# Toolchain: ARM GNU aarch64-none-elf-gcc (tested with 14.3.rel1).

CROSS_COMPILE ?= aarch64-none-elf-
CC      := $(CROSS_COMPILE)gcc
OBJCOPY := $(CROSS_COMPILE)objcopy
SIZE    := $(CROSS_COMPILE)size

ROOT := ../../../../..
AMD    := $(ROOT)/src/port/amd
COMMON := $(AMD)/common
IP     := $(AMD)/ip
ARCH   := $(AMD)/arch/aarch64

# Cortex-A53, AArch64, EL3 single-EL bare-metal. No SIMD/FP in the
# wolfIP/driver paths - keep -mgeneral-regs-only to catch any
# accidental FP use and make the ABI deterministic for cert.
CFLAGS  := -mcpu=cortex-a53 -mgeneral-regs-only
CFLAGS  += -Os -ffreestanding -fno-builtin -fno-common
CFLAGS  += -fdata-sections -ffunction-sections
CFLAGS  += -g -Wall -Wextra -Werror -Wno-unused-parameter
CFLAGS  += -std=gnu99
CFLAGS  += -I. -I$(COMMON) -I$(ARCH) -I$(IP) -I$(ROOT) -I$(ROOT)/src -I$(ROOT)/src/port
CFLAGS  += -DZCU102 -DXILINX_AARCH64
# Append extra defines for investigation builds, e.g.:
#   make CFLAGS_EXTRA="-DDEBUG_GEM -DDEBUG_PHY"
CFLAGS  += $(CFLAGS_EXTRA)

ASFLAGS := -mcpu=cortex-a53 -DUART_EARLY_TX_OFF=0x30

# Entry exception level: 3 (default - JTAG / FSBL / PLM->BL31 drop us at EL3)
# or 2 (wolfBoot chain-loads the image at EL2). EL=2 retargets the
# EL-specific system registers in startup_aarch64.S + mmu_aarch64.c.
EL ?= 3
ifeq ($(EL),2)
    CFLAGS  += -DWOLFIP_EL2
    ASFLAGS += -DWOLFIP_EL2
else ifneq ($(EL),3)
    $(error EL must be 2 or 3)
endif

# Layout selector. Default ocm keeps the OCM-only layout that the JTAG
# iteration scripts depend on (everything in OCM @ 0xFFFC0000). Pass
# LAYOUT=ddr to relink for DDR @ 0x10000000 -- this is the layout
# wolfBoot expects (WOLFBOOT_LOAD_ADDRESS in zynqmp.config).
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
# Replace newlib's aarch64 memset/memcpy (which use 'dc zva' and hang
# on this Cortex-A53 setup) with our bytewise versions in main.c.
LDFLAGS  += -Wl,--wrap=memset -Wl,--wrap=memcpy

LOCAL_C := app.c board.c uart_cadence.c uart_util.c mmu_aarch64.c gic_gicv2.c \
           gem_core.c board_gem.c gem_swq.c gem_rx_swq_poll.c \
           phy_dp83867.c phy_dispatch_dp83867.c entropy.c exception_aarch64.c
LOCAL_S := startup_aarch64.S
LOCAL_OBJS := $(LOCAL_C:.c=.o) $(LOCAL_S:.S=.o)

# Compile wolfIP core into our directory (don't reuse the upstream .o,
# which may have been built for a different ABI).
WOLFIP_OBJ := wolfip.o
OBJS := $(LOCAL_OBJS) $(WOLFIP_OBJ)

# Shared sources live outside this board dir; find them by vpath so the
# .o files still land here (keeps clean + JTAG app.elf-in-place working).
vpath %.c $(COMMON):$(ARCH):$(IP)
vpath %.S $(ARCH)

# Keep 'all' the default goal even though the layout-stamp rules below
# are defined before it.
.DEFAULT_GOAL := all

# A change in LAYOUT must force a full rebuild. OCM objects link against
# 0xFFFC0000 and a DDR build against 0x10000000; reusing stale objects
# across a layout switch silently produces a wrong image. In particular a
# BOOT.BIN built from OCM-layout objects collides with the FSBL (which
# also lives in OCM) and never hands off. The stamp records the last
# LAYOUT; its mtime only bumps when LAYOUT actually changes, so
# same-layout incremental builds are unaffected.
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

# wolfIP core: -Wno-zero-length-bounds is needed because wolfIP sizes
# its timer heap as MAX_TIMERS = MAX_TCPSOCKETS * 3. With our minimum
# of MAX_TCPSOCKETS=2 (forced by DHCP/ARP timer scheduling, see
# README), the heap is 6 entries which is fine. The warning fires
# anyway on the zero-length-array code path that wolfIP includes for
# the MAX_TCPSOCKETS=0 profile we'd actually like to use; the [0]
# accesses are runtime-guarded by heap->size > 0 so this is a false
# positive. Drop the suppression once core decouples the timer count
# from MAX_TCPSOCKETS.
$(WOLFIP_OBJ): $(ROOT)/src/wolfip.c
	$(CC) $(CFLAGS) -Wno-zero-length-bounds -Wno-type-limits -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(ASFLAGS) -c $< -o $@

# Build a bootable BOOT.BIN. Requires FSBL_ELF env var pointing to a
# pre-built ZCU102 FSBL (built in Vitis or PetaLinux). bootgen itself
# is part of Vitis or available standalone.
#
# BOOT.BIN must use the DDR layout: the OCM layout links at 0xFFFC0000,
# exactly where the FSBL runs from, so an OCM-layout BOOT.BIN clobbers
# the FSBL and never reaches the app. Force a DDR (re)build here
# regardless of any LAYOUT passed on the command line.
bootbin:
	@if [ -z "$$FSBL_ELF" ]; then \
	    echo "ERROR: FSBL_ELF must point to a prebuilt ZCU102 FSBL ELF."; \
	    exit 1; \
	fi
	$(MAKE) LAYOUT=ddr app.elf
	FSBL_ELF=$$FSBL_ELF APP_ELF=$$PWD/app.elf bootgen/build_bootbin.sh

clean:
	rm -f $(OBJS) app.elf BOOT.BIN $(LAYOUT_STAMP)

.PHONY: all clean bootbin help

help:
	@echo "ZCU102 wolfIP build:"
	@echo "  make                         - build app.elf"
	@echo "  FSBL_ELF=... make bootbin    - build BOOT.BIN"
	@echo "  make clean                   - remove artifacts"
	@echo ""
	@echo "Override CROSS_COMPILE if your toolchain prefix differs."

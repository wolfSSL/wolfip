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

ROOT := ../../..

# Cortex-A53, AArch64, EL3 single-EL bare-metal. No SIMD/FP in the
# wolfIP/driver paths - keep -mgeneral-regs-only to catch any
# accidental FP use and make the ABI deterministic for cert.
CFLAGS  := -mcpu=cortex-a53 -mgeneral-regs-only
CFLAGS  += -Os -ffreestanding -fno-builtin -fno-common
CFLAGS  += -fdata-sections -ffunction-sections
CFLAGS  += -g -Wall -Wextra -Werror -Wno-unused-parameter
CFLAGS  += -std=gnu99
CFLAGS  += -I. -I$(ROOT) -I$(ROOT)/src -I$(ROOT)/src/port
CFLAGS  += -DZCU102 -DXILINX_AARCH64
# Append extra defines for investigation builds, e.g.:
#   make CFLAGS_EXTRA="-DDEBUG_GIC -DDEBUG_GEM -DDEBUG_PHY"
CFLAGS  += $(CFLAGS_EXTRA)

ASFLAGS := -mcpu=cortex-a53

# Layout selector. Default ocm keeps the OCM-only layout that the JTAG
# iteration scripts depend on (everything in OCM @ 0xFFFC0000). Pass
# LAYOUT=ddr to relink for DDR @ 0x10000000 -- this is the layout
# wolfBoot expects (WOLFBOOT_LOAD_ADDRESS in zynqmp.config).
LAYOUT ?= ocm
ifeq ($(LAYOUT),ddr)
    LDSCRIPT := target_ddr.ld
    CFLAGS   += -DZCU102_LAYOUT_DDR
else ifeq ($(LAYOUT),ocm)
    LDSCRIPT := target.ld
    CFLAGS   += -DZCU102_LAYOUT_OCM
else
    $(error LAYOUT must be 'ocm' or 'ddr')
endif

LDFLAGS  := -nostdlib -nostartfiles -T $(LDSCRIPT) -Wl,-gc-sections
# Replace newlib's aarch64 memset/memcpy (which use 'dc zva' and hang
# on this Cortex-A53 setup) with our bytewise versions in main.c.
LDFLAGS  += -Wl,--wrap=memset -Wl,--wrap=memcpy

LOCAL_C := main.c uart.c mmu.c gic.c gem.c phy_dp83867.c entropy.c
LOCAL_S := startup.S
LOCAL_OBJS := $(LOCAL_C:.c=.o) $(LOCAL_S:.S=.o)

# Compile wolfIP core into our directory (don't reuse the upstream .o,
# which may have been built for a different ABI).
WOLFIP_OBJ := wolfip.o
OBJS := $(LOCAL_OBJS) $(WOLFIP_OBJ)

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
bootbin: app.elf
	@if [ -z "$$FSBL_ELF" ]; then \
	    echo "ERROR: FSBL_ELF must point to a prebuilt ZCU102 FSBL ELF."; \
	    exit 1; \
	fi
	FSBL_ELF=$$FSBL_ELF APP_ELF=$$PWD/app.elf bootgen/build_bootbin.sh

clean:
	rm -f $(OBJS) app.elf BOOT.BIN

.PHONY: all clean bootbin help

help:
	@echo "ZCU102 wolfIP build:"
	@echo "  make                         - build app.elf"
	@echo "  FSBL_ELF=... make bootbin    - build BOOT.BIN"
	@echo "  make clean                   - remove artifacts"
	@echo ""
	@echo "Override CROSS_COMPILE if your toolchain prefix differs."

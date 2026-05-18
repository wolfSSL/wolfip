# Xilinx Versal Gen 1 (VMK180, Cortex-A72) wolfIP bare-metal port
#
# Build:    make CROSS_COMPILE=aarch64-none-elf-
#
# Toolchain: ARM GNU aarch64-none-elf-gcc (tested with 14.3.rel1).
#
# UNTESTED ON HARDWARE -- structural scaffold mirroring src/port/zcu102/.

CROSS_COMPILE ?= aarch64-none-elf-
CC      := $(CROSS_COMPILE)gcc
OBJCOPY := $(CROSS_COMPILE)objcopy
SIZE    := $(CROSS_COMPILE)size

ROOT := ../../..

# Cortex-A72, AArch64, EL3 single-EL bare-metal. No SIMD/FP in the
# wolfIP/driver paths - keep -mgeneral-regs-only to catch any
# accidental FP use and make the ABI deterministic for cert.
CFLAGS  := -mcpu=cortex-a72 -mgeneral-regs-only
CFLAGS  += -Os -ffreestanding -fno-builtin -fno-common
CFLAGS  += -fdata-sections -ffunction-sections
CFLAGS  += -g -Wall -Wextra -Werror -Wno-unused-parameter
CFLAGS  += -std=gnu99
CFLAGS  += -I. -I$(ROOT) -I$(ROOT)/src -I$(ROOT)/src/port
CFLAGS  += -DVERSAL -DXILINX_AARCH64
# Append extra defines for investigation builds, e.g.:
#   make CFLAGS_EXTRA="-DDEBUG_GIC -DDEBUG_GEM -DDEBUG_PHY"
CFLAGS  += $(CFLAGS_EXTRA)

ASFLAGS := -mcpu=cortex-a72

# Layout selector. Default ocm keeps the OCM-only layout that the JTAG
# iteration scripts depend on (everything in OCM @ 0xFFFC0000). Pass
# LAYOUT=ddr to relink for DDR @ 0x10000000 -- which is what wolfBoot
# uses (WOLFBOOT_LOAD_ADDRESS in zynqmp.config also applies to Versal
# when adapted).
LAYOUT ?= ocm
ifeq ($(LAYOUT),ddr)
    LDSCRIPT := target_ddr.ld
    CFLAGS   += -DVERSAL_LAYOUT_DDR
else ifeq ($(LAYOUT),ocm)
    LDSCRIPT := target.ld
    CFLAGS   += -DVERSAL_LAYOUT_OCM
else
    $(error LAYOUT must be 'ocm' or 'ddr')
endif

LDFLAGS  := -nostdlib -nostartfiles -T $(LDSCRIPT) -Wl,-gc-sections
# Replace newlib's aarch64 memset/memcpy (which use 'dc zva' and may
# hang on a similar Cortex-A72 setup; the safe pattern is to override
# them as we did on ZCU102).
LDFLAGS  += -Wl,--wrap=memset -Wl,--wrap=memcpy

LOCAL_C := main.c uart.c mmu.c gic.c gem.c phy_dp83867.c entropy.c
LOCAL_S := startup.S
LOCAL_OBJS := $(LOCAL_C:.c=.o) $(LOCAL_S:.S=.o)

WOLFIP_OBJ := wolfip.o
OBJS := $(LOCAL_OBJS) $(WOLFIP_OBJ)

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
	@echo "Versal Gen 1 wolfIP build (scaffold, untested):"
	@echo "  make                         - build app.elf (OCM layout)"
	@echo "  make LAYOUT=ddr              - DDR layout for wolfBoot"
	@echo "  make clean                   - remove artifacts"
	@echo ""
	@echo "Override CROSS_COMPILE if your toolchain prefix differs."

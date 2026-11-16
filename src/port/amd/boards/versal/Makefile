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

# Fixed address instead of DHCP, for a direct cable to a host:
#   make STATIC_IP=192.168.2.2 STATIC_GW=192.168.2.1
ifneq ($(strip $(STATIC_IP)),)
    STATIC_GW ?= $(STATIC_IP)
    CFLAGS += -DWOLFIP_ENABLE_DHCP=0 -DWOLFIP_IP='"$(STATIC_IP)"' \
        -DWOLFIP_GW='"$(STATIC_GW)"'
endif

ASFLAGS := -mcpu=cortex-a72 -DUART_EARLY_TX_OFF=0x00

# Entry exception level: 3 (default - JTAG / PLM drops us at EL3) or 2
# (wolfBoot chain-loads the image at EL2 as BL33 under BL31). EL=2 retargets
# the EL-specific system registers in startup_aarch64.S + mmu_aarch64.c and
# leaves the GIC to BL31.
EL ?= 3
ifeq ($(EL),2)
    CFLAGS  += -DWOLFIP_EL2
    ASFLAGS += -DWOLFIP_EL2
else ifneq ($(EL),3)
    $(error EL must be 2 or 3)
endif

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

# Network firmware update into the wolfBoot QSPI slots. WOLFBOOT must point
# at a wolfBoot tree already built with the matching Versal QSPI config: its
# flash driver and slot-state code are compiled into the app and take the
# partition layout from its generated include/target.h.
OTA ?= 0
ifeq ($(OTA),1)
    ifeq ($(LAYOUT),ocm)
        $(error OTA=1 requires LAYOUT=ddr)
    endif
    ifneq ($(EL),2)
        $(error OTA=1 requires EL=2: wolfBoot enters the application at EL2)
    endif
    ifeq ($(strip $(WOLFBOOT)),)
        $(error OTA=1 requires WOLFBOOT=/path/to/wolfBoot)
    endif
    OTA_VERSION ?= 1
    # wolfBoot built with encrypted images keeps the slot trailer below a
    # key + nonce area (32 + 16 bytes for AES-256). The slot code compiled
    # in here is built without encryption, so give it the same offset.
    OTA_TRAILER_SKIP ?= 48
    CFLAGS += -DWOLFIP_OTA -DOTA_APP_VERSION=$(OTA_VERSION)
    WB_OBJS := versal.o libwolfboot.o
    OTA_OBJS := ota_store.o syscalls_stub.o $(WB_OBJS)
    # Transport: https (TLS 1.3, ML-KEM hybrid, mutual authentication) or
    # tftp. https needs WOLFSSL=/path/to/wolfssl and OTA_CERTS=<dir holding
    # ota_certs.h with ca_cert_der, device_cert_der and device_key_der>.
    OTA_TRANSPORT ?= https
    ifeq ($(OTA_TRANSPORT),tftp)
        CFLAGS += -I$(ROOT)/src/tftp
        OTA_OBJS += ota_tftp.o wolftftp.o
        vpath %.c $(ROOT)/src/tftp
    else ifeq ($(OTA_TRANSPORT),https)
        ifeq ($(strip $(WOLFSSL)),)
            $(error OTA_TRANSPORT=https requires WOLFSSL=/path/to/wolfssl)
        endif
        ifeq ($(strip $(OTA_CERTS)),)
            $(error OTA_TRANSPORT=https requires OTA_CERTS=/path/to/certs)
        endif
        OTA_SERVER_IP ?= 10.0.4.24
        WSSL_OBJS := $(addprefix wssl_,ssl.o internal.o keys.o tls.o tls13.o \
            wolfio.o) $(addprefix wcrypt_,aes.o asn.o coding.o ecc.o error.o \
            hash.o hmac.o kdf.o logging.o memory.o random.o sha256.o \
            sha512.o sha3.o sp_int.o wc_encrypt.o wc_mlkem.o wc_mlkem_poly.o \
            wc_port.o wolfentropy.o wolfmath.o)
        OTA_OBJS += ota.o httpc.o wolfssl_io.o $(WSSL_OBJS)
        vpath %.c $(ROOT)/src/http
        # A closed connection holds its socket until the close completes.
        CFLAGS += -DMAX_TCPSOCKETS=4 -I$(ROOT)/src/http
        TLS_CFLAGS := -DWOLFSSL_USER_SETTINGS -DWOLFSSL_WOLFIP -I$(WOLFSSL)
        $(WSSL_OBJS) wolfssl_io.o: CFLAGS += $(TLS_CFLAGS) -Wno-error
        ota.o: CFLAGS += $(TLS_CFLAGS) -I$(OTA_CERTS) \
            -DOTA_SERVER_IP='"$(OTA_SERVER_IP)"' \
            -DOTA_BUILD_EPOCH=$(shell date +%s)
        syscalls_stub.o: CFLAGS += -DOTA_HEAP_SIZE=0x200000
    else
        $(error OTA_TRANSPORT must be 'https' or 'tftp')
    endif
    OBJS += $(OTA_OBJS)
    vpath %.c $(AMD)/boards/zcu102
    vpath %.c $(WOLFBOOT)/hal
    vpath %.c $(WOLFBOOT)/src
    WB_CFLAGS := -I$(WOLFBOOT)/include -I$(WOLFBOOT) \
        -DTARGET_versal -DARCH_AARCH64 -DMMU -DNO_XIP -DWOLFBOOT_DUALBOOT \
        -DEXT_FLASH=1 -DPART_BOOT_EXT=1 -DPART_UPDATE_EXT=1 \
        -DWOLFBOOT_NO_PRINTF -DTRAILER_SKIP=$(OTA_TRAILER_SKIP)
    ota_store.o: CFLAGS += $(WB_CFLAGS)
    # Vendored wolfBoot sources: own UART helpers renamed out of the way.
    $(WB_OBJS): CFLAGS += $(WB_CFLAGS) -Duart_init=wb_uart_init \
        -Duart_write=wb_uart_write -Duart_rx=wb_uart_rx \
        -Wno-error -Wno-unused-function -Wno-unused-variable
endif

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

# make cannot see CFLAGS_EXTRA, EL or OTA as a dependency, so changing either
# would silently relink objects built with the previous value.
CFLAGS_EXTRA_STAMP := .cflags_extra_stamp
$(CFLAGS_EXTRA_STAMP): FORCE
	@if [ ! -f $@ ]; then \
	    echo "EL=$(EL) OTA=$(OTA) $(OTA_VERSION) $(OTA_TRANSPORT) $(WOLFBOOT) $(WOLFSSL) $(OTA_SERVER_IP) $(OTA_CERTS) $(OTA_TRAILER_SKIP) $(STATIC_IP) $(STATIC_GW) $(CFLAGS_EXTRA)" > $@; \
	elif [ "`cat $@`" != "EL=$(EL) OTA=$(OTA) $(OTA_VERSION) $(OTA_TRANSPORT) $(WOLFBOOT) $(WOLFSSL) $(OTA_SERVER_IP) $(OTA_CERTS) $(OTA_TRAILER_SKIP) $(STATIC_IP) $(STATIC_GW) $(CFLAGS_EXTRA)" ]; then \
	    echo "build options changed; forcing rebuild"; \
	    echo "EL=$(EL) OTA=$(OTA) $(OTA_VERSION) $(OTA_TRANSPORT) $(WOLFBOOT) $(WOLFSSL) $(OTA_SERVER_IP) $(OTA_CERTS) $(OTA_TRAILER_SKIP) $(STATIC_IP) $(STATIC_GW) $(CFLAGS_EXTRA)" > $@; \
	fi
$(OBJS): $(CFLAGS_EXTRA_STAMP)

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

wssl_%.o: $(WOLFSSL)/src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

wcrypt_%.o: $(WOLFSSL)/wolfcrypt/src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

wolfssl_io.o: $(ROOT)/src/port/wolfssl_io.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(ASFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) app.elf BOOT.BIN $(LAYOUT_STAMP) $(CFLAGS_EXTRA_STAMP)

.PHONY: all clean help

help:
	@echo "Versal Gen 1 wolfIP build (Cortex-A72):"
	@echo "  make                         - build app.elf (OCM layout)"
	@echo "  make LAYOUT=ddr              - DDR layout for wolfBoot"
	@echo "  make LAYOUT=ddr EL=2         - chain-loaded by wolfBoot at EL2"
	@echo "  make clean                   - remove artifacts"
	@echo ""
	@echo "Override CROSS_COMPILE if your toolchain prefix differs."

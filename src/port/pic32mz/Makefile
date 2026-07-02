# wolfIP PIC32MZ EF port - build with Microchip XC32
#
# Copyright (C) 2026 wolfSSL Inc.  Part of the wolfIP TCP/IP stack (GPLv3).
#
# Phase 0: clocks + UART2 console + heartbeat.
# Phase 1: wolfCrypt PIC32MZ hardware TRNG self-test.
# Phase 2: MDIO + LAN8740 PHY link bring-up.
# (Full Ethernet RX/TX driver + wolfIP core are added in later phases.)
#
# Usage:
#   make                       # build app.hex
#   make flash                 # program over the on-board debugger (v6.20 IPE)
#   make clean
# Overridable:
#   XC32_BIN=   XC32 bin dir   (default /opt/microchip/xc32/v5.10/bin)
#   DFP=        device family pack version dir
#   DEVICE=     32MZ2048EFM144
#   WOLFSSL_ROOT= path to wolfssl checkout (used from Phase 1 on)
#   MDB=        MPLAB X MDB CLI (default v6.20; v6.30 dropped the EF SK debugger)

XC32_BIN ?= /opt/microchip/xc32/v5.10/bin
DFP      ?= /opt/microchip/mplabx/v6.30/packs/Microchip/PIC32MZ-EF_DFP/1.5.173
DEVICE   ?= 32MZ2048EFM144

CC      := $(XC32_BIN)/xc32-gcc
BIN2HEX := $(XC32_BIN)/xc32-bin2hex
SIZE    := $(XC32_BIN)/xc32-size

# Flashing via MDB (Microchip DeBugger CLI). The headless ipecmd cannot resolve
# device packs ("Unable to locate DFP"), but MDB launches the full platform and
# resolves them like the IDE/IPE GUI does. Default tool is an MPLAB ICD 5 on the
# ICSP header; the EF Starter Kit's flaky on-board debugger (MDB tool type "sk",
# only in v6.20) proved unreliable over USB, so an external debugger is preferred.
MDB        ?= /opt/microchip/mplabx/v6.30/mplab_platform/bin/mdb.sh
MDB_DEVICE ?= PIC32MZ2048EFM144
MDB_TOOL   ?= icd5

ROOT         := ../../..
# Default to a wolfssl checkout sitting beside the wolfip repo.
WOLFSSL_ROOT ?= $(ROOT)/../wolfssl

# -O1 is available in the free XC32 edition (-O2/-Os/-O3 need a PRO license).
CFLAGS := -mprocessor=$(DEVICE) -mdfp="$(DFP)"
CFLAGS += -O1 -g -Wall -Wextra -ffunction-sections -fdata-sections
CFLAGS += -I. -I$(ROOT) -I$(ROOT)/src
CFLAGS += -DWOLFSSL_USER_SETTINGS -I$(WOLFSSL_ROOT)
CFLAGS += $(EXTRA_CFLAGS)

# Heap for the Hash-DRBG (wc_InitRng allocates the DRBG state).
LDFLAGS := -mprocessor=$(DEVICE) -mdfp="$(DFP)"
LDFLAGS += -Wl,--defsym,_min_heap_size=0x8000
LDFLAGS += -Wl,--gc-sections -Wl,-Map=app.map,--cref

# Port + application sources (strict warnings)
APP_SRCS := device_config.c clock_init.c uart_console.c timebase.c \
            wolf_compat.c rng_selftest.c pic32mz_eth.c phy_lan8740.c main.c
APP_OBJS := $(patsubst %.c,%.o,$(APP_SRCS))

# wolfcrypt sources for the RNG self-test (compiled with relaxed warnings).
# Pulled directly from the sibling wolfssl checkout, no copy.
WC_SRC  := $(WOLFSSL_ROOT)/wolfcrypt/src
WC_NAMES := random sha256 hash wc_port logging memory error
WC_OBJS := $(addsuffix .o,$(addprefix wc_,$(WC_NAMES)))
CFLAGS_WC := -mprocessor=$(DEVICE) -mdfp="$(DFP)" -O1 -g \
             -ffunction-sections -fdata-sections \
             -DWOLFSSL_USER_SETTINGS -I. -I$(WOLFSSL_ROOT)

# wolfIP core stack (relaxed warnings; does not need wolfssl).
CFLAGS_CORE := -mprocessor=$(DEVICE) -mdfp="$(DFP)" -O1 -g \
               -ffunction-sections -fdata-sections -I. -I$(ROOT) -I$(ROOT)/src

ALL_OBJS := $(APP_OBJS) wolfip.o $(WC_OBJS)

all: app.hex
	@echo "Built PIC32MZ wolfIP port"
	@$(SIZE) app.elf

app.elf: $(ALL_OBJS)
	$(CC) $(CFLAGS) $(ALL_OBJS) $(LDFLAGS) -o $@

app.hex: app.elf
	$(BIN2HEX) $<

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

wc_%.o: $(WC_SRC)/%.c
	$(CC) $(CFLAGS_WC) -c $< -o $@

wolfip.o: $(ROOT)/src/wolfip.c
	$(CC) $(CFLAGS_CORE) -c $< -o $@

# Program the hex over an MPLAB ICD 5 (on the ICSP/debug header) via MDB. Close
# the MPLAB X IPE/IDE GUI first so it isn't holding the tool. Command script:
#   set programoptions.eraseb4program true  -> full chip erase before program
#   hwtool icd5 -p                          -> connect the ICD 5 for programming
#   program <app.hex> / Reset               -> program, then release from reset
# The trailing "Reset" is required: -p alone leaves the target held in reset.
# The ICD 5 connects to the target's ICSP/debug header; select a different
# supported tool with MDB_TOOL= (e.g. icd4, pickit4, snap). See Microchip's
# MPLAB ICD 5 User's Guide for connection and wiring details.
flash: app.hex
	@printf 'device %s\nset programoptions.eraseb4program true\nhwtool %s -p\nprogram %s\nReset\nquit\n' \
	    "$(MDB_DEVICE)" "$(MDB_TOOL)" "$(CURDIR)/app.hex" > mdb_flash.cmd
	cd $(dir $(MDB)) && sh ./$(notdir $(MDB)) $(CURDIR)/mdb_flash.cmd

clean:
	rm -f *.o app.elf app.hex app.map mdb_flash.cmd MPLABXLog.* log.*

.PHONY: all clean flash

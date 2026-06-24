# Pi Pico 2 W (RP2350 + CYW43439) port Makefile
#
# Build: make CORE=m33      (default - Cortex-M33)
#        make CORE=hazard3  (Hazard3 RISC-V variant)
#
# Optional:
#   WIFI_SSID, WIFI_PSK : compile-time Wi-Fi credentials
#                         (override config.h defaults)
#
# Output: app.elf + app.uf2 (UF2 via picotool, if available on PATH).
#         picotool load app.uf2  flashes via BOOTSEL.

CORE ?= m33

# The CORE switch forces the toolchain unconditionally. To use a
# different cross compiler (e.g. a vendored toolchain), pass it on the
# command line: `make CORE=m33 CC=/opt/arm/bin/arm-none-eabi-gcc`.
ifeq ($(CORE),m33)
CROSS_PREFIX ?= arm-none-eabi-
ARCH_CFLAGS  := -mcpu=cortex-m33+nodsp -mthumb -mfloat-abi=soft
ARCH_LDFLAGS := -T target_m33.ld
STARTUP_SRC  := startup_m33.c
else ifeq ($(CORE),hazard3)
# The Debian/Ubuntu cross toolchain ships as riscv64-unknown-elf-* and
# selects rv32 via -march/-mabi. Override CROSS_PREFIX if you have a
# native riscv32-unknown-elf-* build (e.g. from SiFive or upstream).
CROSS_PREFIX ?= riscv64-unknown-elf-
ARCH_CFLAGS  := -march=rv32imac -mabi=ilp32
ARCH_LDFLAGS := -T target_hazard3.ld
STARTUP_SRC  := startup_hazard3.c
else
$(error CORE must be m33 or hazard3 (got '$(CORE)'))
endif

CC      := $(CROSS_PREFIX)gcc
OBJCOPY := $(CROSS_PREFIX)objcopy
SIZE    := $(CROSS_PREFIX)size

ROOT := ../../..

CFLAGS := $(ARCH_CFLAGS) -Os -ffreestanding
CFLAGS += -fdata-sections -ffunction-sections
CFLAGS += -g -ggdb -Wall -Wextra -Werror
CFLAGS += -I. -I$(ROOT) -I$(ROOT)/src
CFLAGS += $(EXTRA_CFLAGS)

ifdef WIFI_SSID
CFLAGS += -DWOLFIP_WIFI_SSID="\"$(WIFI_SSID)\""
endif
ifdef WIFI_PSK
CFLAGS += -DWOLFIP_WIFI_PSK="\"$(WIFI_PSK)\""
endif

# Host WPA2-PSK supplicant (tier 3): set WITH_SUPPLICANT=1 to link the
# in-tree supplicant plus a minimal wolfCrypt (PSK only) so the 4-way
# handshake runs on the host. Needs wolfSSL cloned alongside wolfip, or
# set WOLFSSL_ROOT=/path/to/wolfssl. EAP-TLS / SAE are compiled out.
WITH_SUPPLICANT ?= 0
WOLFSSL_ROOT    ?= $(ROOT)/../wolfssl

ifeq ($(WITH_SUPPLICANT),1)
ifeq ($(wildcard $(WOLFSSL_ROOT)/wolfssl/ssl.h),)
$(error wolfSSL not found at $(WOLFSSL_ROOT); clone it or set WOLFSSL_ROOT=/path/to/wolfssl)
endif
SUPP_DIR := $(ROOT)/src/supplicant
WC_DIR   := $(WOLFSSL_ROOT)/wolfcrypt/src
CFLAGS += -DWOLFIP_WITH_SUPPLICANT
CFLAGS += -DWOLFIP_ENABLE_EAP_TLS=0 -DWOLFIP_ENABLE_SAE=0
CFLAGS += -DWOLFIP_ENABLE_PEAP_MSCHAPV2=0
CFLAGS += -DWOLFSSL_USER_SETTINGS -DWOLFSSL_NO_OPTIONS_H
CFLAGS += -I$(WOLFSSL_ROOT) -I$(SUPP_DIR)
endif

LDFLAGS := -nostdlib $(ARCH_LDFLAGS) -Wl,-gc-sections

APP_SRCS := $(STARTUP_SRC) syscalls.c main.c rp2350_uart.c \
            rp2350_clocks.c rp2350_spi.c rp2350_pio.c \
            cyw43439_driver.c cyw43_sdpcm.c cyw43439_wifi.c
ifeq ($(WITH_SUPPLICANT),1)
APP_SRCS += rp2350_rng.c
endif

# CYW43439 firmware blob (NOT in the repo - third-party license, RP
# silicon only). When fw_local/cyw43_fw_blob.c is present it is compiled
# in and the firmware download runs; otherwise the weak accessors return
# NULL and bring-up stops cleanly after the backplane/ALP stage.
ifneq ($(wildcard fw_local/cyw43_fw_blob.c),)
APP_SRCS += fw_local/cyw43_fw_blob.c
CFLAGS   += -Ifw_local
endif
APP_OBJS := $(APP_SRCS:.c=.o)

WOLFIP_SRC := $(ROOT)/src/wolfip.c
WOLFIP_OBJ := wolfip.o

ALL_OBJS := $(APP_OBJS) $(WOLFIP_OBJ)

# Keep `all` the default goal even though the supplicant rules below
# introduce targets ahead of it.
.DEFAULT_GOAL := all

# Supplicant + minimal wolfCrypt objects (PSK-only) when WITH_SUPPLICANT=1.
ifeq ($(WITH_SUPPLICANT),1)
SUPP_OBJS := supplicant.o wpa_crypto.o eapol.o rsn_ie.o
WC_OBJS   := aes.o sha.o sha256.o hmac.o hash.o pwdbased.o random.o \
             wc_port.o memory.o logging.o error.o
ALL_OBJS  += $(SUPP_OBJS) $(WC_OBJS)
# Third-party / supplicant sources build without -Werror.
CFLAGS_RELAX := $(filter-out -Werror,$(CFLAGS)) \
                -Wno-unused-variable -Wno-unused-function \
                -Wno-unused-parameter -Wno-sign-compare \
                -Wno-missing-field-initializers
$(SUPP_OBJS): %.o: $(SUPP_DIR)/%.c
	$(CC) $(CFLAGS_RELAX) -c $< -o $@
$(WC_OBJS): %.o: $(WC_DIR)/%.c
	$(CC) $(CFLAGS_RELAX) -c $< -o $@
# main.c pulls in wolfSSL headers via supplicant.h - build it relaxed too.
main.o: main.c
	$(CC) $(CFLAGS_RELAX) -c $< -o $@
endif

all: app.uf2
	@echo "Built RP2350+CYW43439 wolfIP port (CORE=$(CORE))"
	@$(SIZE) app.elf

app.elf: $(ALL_OBJS) target_$(CORE).ld
	$(CC) $(CFLAGS) $(ALL_OBJS) $(LDFLAGS) \
	    -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group -o $@

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@

# Convert ELF to UF2. Prefers picotool when available; falls back to
# the bundled tools/elf2uf2.py (~100 lines of Python, no deps) when
# not. Both produce the same UF2 a BOOTSEL drive will accept.
ifeq ($(CORE),m33)
UF2_FAMILY := arm
else
UF2_FAMILY := riscv
endif

app.uf2: app.elf
	@if command -v picotool >/dev/null 2>&1; then \
	    picotool uf2 convert $< $@ ; \
	else \
	    python3 tools/elf2uf2.py $< $@ --family $(UF2_FAMILY) ; \
	fi

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(WOLFIP_OBJ): $(WOLFIP_SRC)
	$(CC) $(CFLAGS) -Wno-unused-variable -Wno-unused-function \
	    -Wno-unused-parameter -Wno-sign-compare \
	    -Wno-missing-field-initializers -c $< -o $@

flash: app.uf2
	picotool load -f app.uf2

clean:
	rm -f *.o fw_local/*.o app.elf app.bin app.uf2 \
	    selftest.elf selftest.bin selftest.uf2

.PHONY: all clean flash

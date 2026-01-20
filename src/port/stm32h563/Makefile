CC ?= arm-none-eabi-gcc
OBJCOPY ?= arm-none-eabi-objcopy

ROOT := ../../..

# TrustZone support: set TZEN=1 for TrustZone enabled builds
# Default is TZEN=0 (TrustZone disabled)
TZEN ?= 0

# TLS support: set ENABLE_TLS=1 to include wolfSSL TLS server
# Requires wolfSSL cloned alongside wolfip (or set WOLFSSL_ROOT)
ENABLE_TLS ?= 0

# Library paths - default to sibling directories (clone alongside pattern)
WOLFSSL_ROOT ?= $(ROOT)/../wolfssl

# Base compiler flags
CFLAGS := -mcpu=cortex-m33 -mthumb -mcmse -Os -ffreestanding -fdata-sections -ffunction-sections
CFLAGS += -g -ggdb -Wall -Wextra -Werror
CFLAGS += -I. -I$(ROOT) -I$(ROOT)/src

# Relaxed warnings for external libraries (wolfSSL has many unused var warnings)
CFLAGS_WOLFSSL := $(CFLAGS)
CFLAGS_WOLFSSL := $(filter-out -Werror,$(CFLAGS_WOLFSSL))
CFLAGS_WOLFSSL += -Wno-unused-variable -Wno-unused-function

# Select linker script based on TZEN setting
ifeq ($(TZEN),1)
  LDSCRIPT := target_tzen.ld
  CFLAGS += -DTZEN_ENABLED=1
else
  LDSCRIPT := target.ld
  CFLAGS += -DTZEN_ENABLED=0
endif

LDFLAGS := -nostdlib -T $(LDSCRIPT) -Wl,-gc-sections

# Base source files
SRCS := startup.c ivt.c syscalls.c main.c stm32h5_eth.c $(ROOT)/src/wolfip.c

# -----------------------------------------------------------------------------
# TLS Support (wolfSSL)
# -----------------------------------------------------------------------------
ifeq ($(ENABLE_TLS),1)

# Validate wolfSSL exists
ifeq ($(wildcard $(WOLFSSL_ROOT)/wolfssl/ssl.h),)
  $(error wolfSSL not found at $(WOLFSSL_ROOT). Clone it: git clone https://github.com/wolfSSL/wolfssl.git)
endif

CFLAGS += -DENABLE_TLS
CFLAGS += -DWOLFSSL_USER_SETTINGS
CFLAGS += -DWOLFSSL_WOLFIP
CFLAGS += -I$(WOLFSSL_ROOT)

# TLS server, client, and wolfIP-wolfSSL glue
SRCS += tls_server.c
SRCS += tls_client.c
SRCS += $(ROOT)/src/port/wolfssl_io.c

# wolfSSL source files (minimal set for TLS 1.3 server with ECC)
WOLFSSL_SRCS := \
    $(WOLFSSL_ROOT)/wolfcrypt/src/aes.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/sha.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/sha256.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/sha512.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/hmac.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/hash.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/kdf.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/random.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/ecc.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/asn.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/coding.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/wc_port.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/memory.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/wolfmath.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/sp_int.c \
    $(WOLFSSL_ROOT)/src/ssl.c \
    $(WOLFSSL_ROOT)/src/tls.c \
    $(WOLFSSL_ROOT)/src/tls13.c \
    $(WOLFSSL_ROOT)/src/internal.c \
    $(WOLFSSL_ROOT)/src/keys.c \
    $(WOLFSSL_ROOT)/src/wolfio.c

# ChaCha20-Poly1305 (optional, comment out to save space)
WOLFSSL_SRCS += \
    $(WOLFSSL_ROOT)/wolfcrypt/src/chacha.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/chacha20_poly1305.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/poly1305.c

# RSA for certificate verification (most servers use RSA certs)
WOLFSSL_SRCS += \
    $(WOLFSSL_ROOT)/wolfcrypt/src/rsa.c

SRCS += $(WOLFSSL_SRCS)

endif # ENABLE_TLS

# -----------------------------------------------------------------------------
# Build rules
# -----------------------------------------------------------------------------
OBJS := $(patsubst %.c,%.o,$(SRCS))

all: app.bin
	@echo "Built with TZEN=$(TZEN) ENABLE_TLS=$(ENABLE_TLS)"
ifeq ($(ENABLE_TLS),1)
	@echo "  wolfSSL: $(WOLFSSL_ROOT)"
endif

app.elf: $(OBJS) $(LDSCRIPT)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group -o $@

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# wolfSSL objects use relaxed warnings
$(WOLFSSL_ROOT)/%.o: $(WOLFSSL_ROOT)/%.c
	$(CC) $(CFLAGS_WOLFSSL) -c $< -o $@

clean:
	rm -f *.o app.elf app.bin
	rm -f $(ROOT)/src/*.o
	rm -f $(ROOT)/src/port/*.o
ifeq ($(ENABLE_TLS),1)
	rm -f $(WOLFSSL_ROOT)/wolfcrypt/src/*.o
	rm -f $(WOLFSSL_ROOT)/src/*.o
endif

.PHONY: all clean

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
help:
	@echo "STM32H563 wolfIP Build System"
	@echo ""
	@echo "Usage: make [target] [options]"
	@echo ""
	@echo "Targets:"
	@echo "  all      Build app.bin (default)"
	@echo "  clean    Remove build artifacts"
	@echo "  help     Show this help"
	@echo ""
	@echo "Options:"
	@echo "  TZEN=1         Enable TrustZone support"
	@echo "  ENABLE_TLS=1   Enable TLS server (requires wolfSSL)"
	@echo "  WOLFSSL_ROOT=  Path to wolfSSL (default: ../wolfssl)"
	@echo ""
	@echo "Examples:"
	@echo "  make                          # Basic build"
	@echo "  make TZEN=1                   # TrustZone enabled"
	@echo "  make ENABLE_TLS=1             # With TLS server"
	@echo "  make TZEN=1 ENABLE_TLS=1      # Both"
	@echo ""
	@echo "Testing TLS server:"
	@echo "  echo 'Hello' | openssl s_client -connect <ip>:8443 -quiet"

.PHONY: help

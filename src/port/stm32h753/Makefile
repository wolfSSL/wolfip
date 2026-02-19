CC ?= arm-none-eabi-gcc
OBJCOPY ?= arm-none-eabi-objcopy

ROOT := ../../..

# TLS support: set ENABLE_TLS=1 to include wolfSSL TLS client
# Requires wolfSSL cloned alongside wolfip (or set WOLFSSL_ROOT)
ENABLE_TLS ?= 0

# HTTPS web server: set ENABLE_HTTPS=1 to include HTTPS web server (requires TLS)
ENABLE_HTTPS ?= 0

# Library paths - default to sibling directories
WOLFSSL_ROOT ?= $(ROOT)/../wolfssl

# STM32H753ZI - Cortex-M7 with FPU
CFLAGS := -mcpu=cortex-m7 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard
CFLAGS += -Os -ffreestanding -fdata-sections -ffunction-sections
CFLAGS += -g -ggdb -Wall -Wextra -Werror
CFLAGS += -I. -I$(ROOT) -I$(ROOT)/src -I$(ROOT)/src/port/stm32
CFLAGS += -DSTM32H7

# Relaxed warnings for external libraries
CFLAGS_WOLFSSL := $(CFLAGS)
CFLAGS_WOLFSSL := $(filter-out -Werror,$(CFLAGS_WOLFSSL))
CFLAGS_WOLFSSL += -Wno-unused-variable -Wno-unused-function

LDSCRIPT := target.ld
LDFLAGS := -nostdlib -T $(LDSCRIPT) -Wl,-gc-sections

# Base source files
SRCS := startup.c ivt.c syscalls.c main.c $(ROOT)/src/port/stm32/stm32_eth.c $(ROOT)/src/wolfip.c

# -----------------------------------------------------------------------------
# TLS Support (wolfSSL)
# -----------------------------------------------------------------------------
ifeq ($(ENABLE_TLS),1)

# Validate wolfSSL exists
ifeq ($(wildcard $(WOLFSSL_ROOT)/wolfssl/ssl.h),)
  $(error wolfSSL not found at $(WOLFSSL_ROOT). Clone it or set WOLFSSL_ROOT)
endif

CFLAGS += -DENABLE_TLS
CFLAGS += -DWOLFSSL_USER_SETTINGS
CFLAGS += -DWOLFSSL_WOLFIP
CFLAGS += -I$(WOLFSSL_ROOT)

# TLS client and wolfIP-wolfSSL glue
SRCS += tls_client.c
SRCS += $(ROOT)/src/port/wolfssl_io.c

# HTTPS web server (requires TLS)
ifeq ($(ENABLE_HTTPS),1)
CFLAGS += -DENABLE_HTTPS
SRCS += $(ROOT)/src/http/httpd.c
endif

# wolfSSL source files (minimal set for TLS 1.3 client with ECC)
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
    $(WOLFSSL_ROOT)/wolfcrypt/src/sp_c32.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/sp_cortexm.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/port/st/stm32.c \
    $(WOLFSSL_ROOT)/src/ssl.c \
    $(WOLFSSL_ROOT)/src/tls.c \
    $(WOLFSSL_ROOT)/src/tls13.c \
    $(WOLFSSL_ROOT)/src/internal.c \
    $(WOLFSSL_ROOT)/src/keys.c \
    $(WOLFSSL_ROOT)/src/wolfio.c

# ChaCha20-Poly1305 (optional)
WOLFSSL_SRCS += \
    $(WOLFSSL_ROOT)/wolfcrypt/src/chacha.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/chacha20_poly1305.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/poly1305.c

# RSA for certificate verification
WOLFSSL_SRCS += \
    $(WOLFSSL_ROOT)/wolfcrypt/src/rsa.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/signature.c

# wolfCrypt test (validates all crypto algorithms including HW HASH/HMAC)
WOLFSSL_SRCS += \
    $(WOLFSSL_ROOT)/wolfcrypt/test/test.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/logging.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/error.c \
    $(WOLFSSL_ROOT)/wolfcrypt/src/wc_encrypt.c

SRCS += $(WOLFSSL_SRCS)

endif # ENABLE_TLS

# -----------------------------------------------------------------------------
# Build rules
# -----------------------------------------------------------------------------
OBJS := $(patsubst %.c,%.o,$(SRCS))

all: app.bin
	@echo "Built with ENABLE_TLS=$(ENABLE_TLS) ENABLE_HTTPS=$(ENABLE_HTTPS)"
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
	$(CC) $(CFLAGS_WOLFSSL) -DWOLFSSL_USER_SETTINGS -I$(WOLFSSL_ROOT) -c $< -o $@

clean:
	rm -f *.o app.elf app.bin
	rm -f $(ROOT)/src/*.o
	rm -f $(ROOT)/src/port/*.o
	rm -f $(ROOT)/src/port/stm32/*.o
	rm -f $(ROOT)/src/http/*.o
ifeq ($(ENABLE_TLS),1)
	rm -f $(WOLFSSL_ROOT)/wolfcrypt/src/*.o
	rm -f $(WOLFSSL_ROOT)/wolfcrypt/src/port/st/*.o
	rm -f $(WOLFSSL_ROOT)/wolfcrypt/test/*.o
	rm -f $(WOLFSSL_ROOT)/src/*.o
endif

# Show memory usage
size: app.elf
	@echo "=== Memory Usage ==="
	@arm-none-eabi-size app.elf
	@echo ""
	@echo "Flash usage: $$(arm-none-eabi-size app.elf | awk 'NR==2{printf "%.1f%% (%d / %d bytes)", ($$1+$$2)*100/1048576, $$1+$$2, 1048576}')"
	@echo "RAM usage (static): $$(arm-none-eabi-size app.elf | awk 'NR==2{printf "%.1f%% (%d / %d bytes)", ($$2+$$3)*100/524288, $$2+$$3, 524288}')"

# Flash using ST-Link
flash: app.bin
	st-flash write app.bin 0x08000000

.PHONY: all clean size flash

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
help:
	@echo "STM32H753ZI wolfIP Build System"
	@echo ""
	@echo "Usage: make [target] [options]"
	@echo ""
	@echo "Targets:"
	@echo "  all      Build app.bin (default)"
	@echo "  clean    Remove build artifacts"
	@echo "  size     Show memory usage statistics"
	@echo "  flash    Flash to device using st-flash"
	@echo "  help     Show this help"
	@echo ""
	@echo "Options:"
	@echo "  ENABLE_TLS=1    Enable TLS 1.3 client (requires wolfSSL)"
	@echo "  ENABLE_HTTPS=1  Enable HTTPS web server (requires TLS)"
	@echo "  WOLFSSL_ROOT=   Path to wolfSSL (default: ../wolfssl)"
	@echo "  CC=             C compiler (default: arm-none-eabi-gcc)"
	@echo ""
	@echo "Examples:"
	@echo "  make                              # Basic TCP echo (port 7)"
	@echo "  make ENABLE_TLS=1                 # TLS 1.3 client"
	@echo "  make ENABLE_TLS=1 ENABLE_HTTPS=1  # TLS + HTTPS server"
	@echo ""
	@echo "Testing:"
	@echo "  nc <ip> 7                         # TCP echo test"
	@echo "  curl -k https://<ip>/             # HTTPS test"

.PHONY: help

CC ?= arm-none-eabi-gcc
OBJCOPY ?= arm-none-eabi-objcopy

ROOT := ../../..

# TrustZone support: set TZEN=1 for TrustZone enabled builds
# Default is TZEN=0 (TrustZone disabled)
TZEN ?= 0

# TLS support: set ENABLE_TLS=1 to include wolfSSL TLS server
# Requires wolfSSL cloned alongside wolfip (or set WOLFSSL_ROOT)
ENABLE_TLS ?= 0

# HTTPS web server: set ENABLE_HTTPS=1 to include HTTPS web server
# Automatically enables TLS if needed
ENABLE_HTTPS ?= 0

# SSH support: set ENABLE_SSH=1 to include wolfSSH server
# Automatically enables TLS if needed
ENABLE_SSH ?= 0

# MQTT support: set ENABLE_MQTT=1 to include wolfMQTT client
# Automatically enables TLS if needed
ENABLE_MQTT ?= 0

# Auto-enable TLS when any feature that requires it is enabled
ifeq ($(ENABLE_HTTPS),1)
  ENABLE_TLS = 1
endif
ifeq ($(ENABLE_SSH),1)
  ENABLE_TLS = 1
endif
ifeq ($(ENABLE_MQTT),1)
  ENABLE_TLS = 1
endif

# Library paths - default to sibling directories (clone alongside pattern)
WOLFSSL_ROOT ?= $(ROOT)/../wolfssl
WOLFSSH_ROOT ?= $(ROOT)/../wolfssh
WOLFMQTT_ROOT ?= $(ROOT)/../wolfmqtt

# Base compiler flags
CFLAGS := -mcpu=cortex-m33 -mthumb -mcmse -Os -ffreestanding -fdata-sections -ffunction-sections
CFLAGS += -g -ggdb -Wall -Wextra -Werror
CFLAGS += -I. -I$(ROOT) -I$(ROOT)/src -I$(ROOT)/src/port -I$(ROOT)/src/port/stm32
CFLAGS += -DSTM32H5

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
SRCS := startup.c ivt.c syscalls.c main.c $(ROOT)/src/port/stm32/stm32_eth.c $(ROOT)/src/wolfip.c

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

# TLS server, client and wolfIP-wolfSSL glue
SRCS += tls_server.c
SRCS += tls_client.c
SRCS += $(ROOT)/src/port/wolfssl_io.c

# HTTPS web server - uses existing wolfIP httpd
ifeq ($(ENABLE_HTTPS),1)
CFLAGS += -DENABLE_HTTPS
SRCS += $(ROOT)/src/http/httpd.c
endif

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

# Signature verification (required for wolfSSH)
ifeq ($(ENABLE_SSH),1)
WOLFSSL_SRCS += \
    $(WOLFSSL_ROOT)/wolfcrypt/src/signature.c
endif

SRCS += $(WOLFSSL_SRCS)

endif # ENABLE_TLS

# -----------------------------------------------------------------------------
# SSH Support (wolfSSH)
# -----------------------------------------------------------------------------
ifeq ($(ENABLE_SSH),1)

# Validate wolfSSH exists
ifeq ($(wildcard $(WOLFSSH_ROOT)/wolfssh/ssh.h),)
  $(error wolfSSH not found at $(WOLFSSH_ROOT). Clone it: git clone https://github.com/wolfSSL/wolfssh.git)
endif

CFLAGS += -DENABLE_SSH
CFLAGS += -DWOLFSSH_USER_SETTINGS
CFLAGS += -I$(WOLFSSH_ROOT)

# SSH server and wolfSSH-wolfIP glue
SRCS += ssh_server.c
SRCS += $(ROOT)/src/port/wolfssh_io.c

# wolfSSH source files (minimal set for SSH server)
WOLFSSH_SRCS := \
    $(WOLFSSH_ROOT)/src/ssh.c \
    $(WOLFSSH_ROOT)/src/internal.c \
    $(WOLFSSH_ROOT)/src/io.c \
    $(WOLFSSH_ROOT)/src/keygen.c \
    $(WOLFSSH_ROOT)/src/log.c \
    $(WOLFSSH_ROOT)/src/port.c

SRCS += $(WOLFSSH_SRCS)

# wolfSSH objects use relaxed warnings + SSH/SSL include paths + user_settings.h
$(WOLFSSH_ROOT)/%.o: $(WOLFSSH_ROOT)/%.c
	$(CC) $(CFLAGS_WOLFSSL) -DENABLE_SSH -DWOLFSSL_USER_SETTINGS -DWOLFSSH_USER_SETTINGS -I$(WOLFSSH_ROOT) -I$(WOLFSSL_ROOT) -c $< -o $@

endif # ENABLE_SSH

# -----------------------------------------------------------------------------
# MQTT Support (wolfMQTT)
# -----------------------------------------------------------------------------
ifeq ($(ENABLE_MQTT),1)

# Validate wolfMQTT exists
ifeq ($(wildcard $(WOLFMQTT_ROOT)/wolfmqtt/mqtt_client.h),)
  $(error wolfMQTT not found at $(WOLFMQTT_ROOT). Clone it: git clone https://github.com/wolfSSL/wolfMQTT.git)
endif

CFLAGS += -DENABLE_MQTT
CFLAGS += -DWOLFMQTT_USER_SETTINGS
CFLAGS += -I$(WOLFMQTT_ROOT)

# MQTT client and wolfMQTT-wolfIP glue
SRCS += mqtt_client.c
SRCS += $(ROOT)/src/port/wolfmqtt_io.c

# wolfMQTT source files (minimal set for MQTT client)
WOLFMQTT_SRCS := \
    $(WOLFMQTT_ROOT)/src/mqtt_client.c \
    $(WOLFMQTT_ROOT)/src/mqtt_packet.c \
    $(WOLFMQTT_ROOT)/src/mqtt_socket.c

SRCS += $(WOLFMQTT_SRCS)

# wolfMQTT objects use relaxed warnings + MQTT/SSL include paths + user_settings.h
$(WOLFMQTT_ROOT)/%.o: $(WOLFMQTT_ROOT)/%.c
	$(CC) $(CFLAGS_WOLFSSL) -DENABLE_MQTT -DWOLFSSL_USER_SETTINGS -DWOLFMQTT_USER_SETTINGS -I$(WOLFMQTT_ROOT) -I$(WOLFSSL_ROOT) -c $< -o $@

endif # ENABLE_MQTT

# -----------------------------------------------------------------------------
# Build rules
# -----------------------------------------------------------------------------
OBJS := $(patsubst %.c,%.o,$(SRCS))

all: app.bin
	@echo "Built with TZEN=$(TZEN) ENABLE_TLS=$(ENABLE_TLS) ENABLE_HTTPS=$(ENABLE_HTTPS) ENABLE_SSH=$(ENABLE_SSH) ENABLE_MQTT=$(ENABLE_MQTT)"
ifeq ($(ENABLE_TLS),1)
	@echo "  wolfSSL: $(WOLFSSL_ROOT)"
endif
ifeq ($(ENABLE_SSH),1)
	@echo "  wolfSSH: $(WOLFSSH_ROOT)"
endif
ifeq ($(ENABLE_MQTT),1)
	@echo "  wolfMQTT: $(WOLFMQTT_ROOT)"
endif

app.elf: $(OBJS) $(LDSCRIPT)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group -o $@

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# wolfSSL objects use relaxed warnings + user_settings.h + include paths
$(WOLFSSL_ROOT)/%.o: $(WOLFSSL_ROOT)/%.c
	$(CC) $(CFLAGS_WOLFSSL) -DWOLFSSL_USER_SETTINGS $(if $(filter 1,$(ENABLE_SSH)),-DENABLE_SSH) -I$(WOLFSSL_ROOT) -c $< -o $@

clean:
	rm -f *.o app.elf app.bin
	rm -f $(ROOT)/src/*.o
	rm -f $(ROOT)/src/port/*.o
	rm -f $(ROOT)/src/port/stm32/*.o
ifeq ($(ENABLE_TLS),1)
	rm -f $(WOLFSSL_ROOT)/wolfcrypt/src/*.o
	rm -f $(WOLFSSL_ROOT)/src/*.o
endif
ifeq ($(ENABLE_SSH),1)
	rm -f $(WOLFSSH_ROOT)/src/*.o
endif
ifeq ($(ENABLE_MQTT),1)
	rm -f $(WOLFMQTT_ROOT)/src/*.o
endif

# Verify what features are compiled into the binary
verify: app.bin
	@echo "=== Build Verification ==="
	@echo "Checking compiled features in app.bin..."
	@strings app.bin | grep -q "Initializing TLS server" && echo "  ✓ TLS server enabled" || echo "  ✗ TLS server disabled"
	@strings app.bin | grep -q "Initializing HTTPS server" && echo "  ✓ HTTPS server enabled" || echo "  ✗ HTTPS server disabled"
	@strings app.bin | grep -q "Initializing SSH server" && echo "  ✓ SSH server enabled" || echo "  ✗ SSH server disabled"
	@strings app.bin | grep -q "Initializing MQTT client" && echo "  ✓ MQTT client enabled" || echo "  ✗ MQTT client disabled"
	@echo ""
	@echo "Binary size: $$(ls -lh app.bin | awk '{print $$5}')"
	@echo "Build flags: TZEN=$(TZEN) ENABLE_TLS=$(ENABLE_TLS) ENABLE_HTTPS=$(ENABLE_HTTPS) ENABLE_SSH=$(ENABLE_SSH) ENABLE_MQTT=$(ENABLE_MQTT)"

# Show memory usage
size: app.elf
	@echo "=== Memory Usage ==="
	@arm-none-eabi-size app.elf
	@echo ""
	@echo "Flash usage: $$(arm-none-eabi-size app.elf | awk 'NR==2{printf "%.1f%% (%d / %d bytes)", ($$1+$$2)*100/2097152, $$1+$$2, 2097152}')"
	@echo "RAM usage (static): $$(arm-none-eabi-size app.elf | awk 'NR==2{printf "%.1f%% (%d / %d bytes)", ($$2+$$3)*100/655360, $$2+$$3, 655360}')"

.PHONY: all clean verify size

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
	@echo "  verify   Check which features are compiled in"
	@echo "  size     Show memory usage statistics"
	@echo "  help     Show this help"
	@echo ""
	@echo "Options:"
	@echo "  TZEN=1          Enable TrustZone support"
	@echo "  ENABLE_TLS=1    Enable TLS server (requires wolfSSL)"
	@echo "  ENABLE_HTTPS=1  Enable HTTPS web server (requires TLS)"
	@echo "  ENABLE_SSH=1    Enable SSH server (requires TLS + wolfSSH)"
	@echo "  ENABLE_MQTT=1   Enable MQTT client (requires TLS + wolfMQTT)"
	@echo "  WOLFSSL_ROOT=   Path to wolfSSL (default: ../wolfssl)"
	@echo "  WOLFSSH_ROOT=   Path to wolfSSH (default: ../wolfssh)"
	@echo "  WOLFMQTT_ROOT=  Path to wolfMQTT (default: ../wolfmqtt)"
	@echo "  CC=             C compiler (default: arm-none-eabi-gcc)"
	@echo "  OBJCOPY=        Objcopy tool (default: arm-none-eabi-objcopy)"
	@echo ""
	@echo "Examples:"
	@echo "  make                                                        # Basic TCP echo (port 7)"
	@echo "  make ENABLE_TLS=1                                           # TLS echo server (port 8443)"
	@echo "  make ENABLE_TLS=1 ENABLE_HTTPS=1                            # TLS + HTTPS web (port 443)"
	@echo "  make ENABLE_TLS=1 ENABLE_SSH=1                              # TLS + SSH shell (port 22)"
	@echo "  make ENABLE_TLS=1 ENABLE_MQTT=1                             # TLS + MQTT client"
	@echo "  make ENABLE_TLS=1 ENABLE_HTTPS=1 ENABLE_SSH=1 ENABLE_MQTT=1 # Full featured"
	@echo ""
	@echo "Full Build Command (recommended):"
	@echo "  CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy \\"
	@echo "  make ENABLE_TLS=1 ENABLE_HTTPS=1 ENABLE_SSH=1 ENABLE_MQTT=1"
	@echo ""
	@echo "Testing:"
	@echo "  nc <ip> 7                                      # TCP echo"
	@echo "  echo 'Hello' | openssl s_client -connect <ip>:8443 -quiet  # TLS echo"
	@echo "  curl -k https://<ip>/                          # HTTPS web server"
	@echo "  ssh admin@<ip>                                 # SSH (password: wolfip)"
	@echo "  mosquitto_sub -h test.mosquitto.org -t 'wolfip/status' -v  # MQTT subscribe"

.PHONY: help

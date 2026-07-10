CC ?= arm-none-eabi-gcc
OBJCOPY ?= arm-none-eabi-objcopy

ROOT := ../../..

# TLS support: set ENABLE_TLS=1 to include wolfSSL
# Requires wolfSSL cloned alongside wolfip (or set WOLFSSL_ROOT)
ENABLE_TLS ?= 0

# TLS client test: set ENABLE_TLS_CLIENT=1 to include TLS client (Google test)
# Automatically enables TLS if needed
ENABLE_TLS_CLIENT ?= 0

# HTTPS web server: set ENABLE_HTTPS=1 to include HTTPS web server
# Automatically enables TLS if needed
ENABLE_HTTPS ?= 0

# MQTT Broker: set ENABLE_MQTT_BROKER=1 to include wolfMQTT broker (requires TLS)
ENABLE_MQTT_BROKER ?= 0

# Auto-enable TLS when any feature that requires it is enabled
ifeq ($(ENABLE_TLS_CLIENT),1)
  ENABLE_TLS = 1
endif
ifeq ($(ENABLE_HTTPS),1)
  ENABLE_TLS = 1
endif
ifeq ($(ENABLE_MQTT_BROKER),1)
  ENABLE_TLS = 1
endif

# WOLFSSL_ROOT/WOLFMQTT_ROOT defaults + the shared wolfSSL source list and
# $(WOLFSSL_ROOT)/%.o rule come from the shared fragment (included below).

# STM32H753ZI - Cortex-M7 with FPU
CFLAGS := -mcpu=cortex-m7 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard
CFLAGS += -Os -ffreestanding -fdata-sections -ffunction-sections
CFLAGS += -g -ggdb -Wall -Wextra -Werror
CFLAGS += -I. -I$(ROOT) -I$(ROOT)/src -I$(ROOT)/src/port -I$(ROOT)/src/port/stm32
CFLAGS += -DSTM32H7

# Relaxed warnings for external libraries
CFLAGS_WOLFSSL := $(CFLAGS)
CFLAGS_WOLFSSL := $(filter-out -Werror,$(CFLAGS_WOLFSSL))
CFLAGS_WOLFSSL += -Wno-unused-variable -Wno-unused-function

# Shared wolfSSL build plumbing: WOLFSSL_ROOT/WOLFMQTT_ROOT defaults, the base
# WOLFSSL_SRCS list, and the $(WOLFSSL_ROOT)/%.o relaxed-warning rule.
include $(ROOT)/src/port/stm32/wolfssl.mk

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
  $(error wolfSSL not found at $(WOLFSSL_ROOT). Clone it: git clone https://github.com/wolfSSL/wolfssl.git)
endif

CFLAGS += -DENABLE_TLS
CFLAGS += -DWOLFSSL_USER_SETTINGS
CFLAGS += -DWOLFSSL_WOLFIP
CFLAGS += -I$(WOLFSSL_ROOT)

# wolfIP-wolfSSL glue
SRCS += $(ROOT)/src/port/wolfssl_io.c

# TLS client (Google test) -- shared state machine, plain one-way client.
# Keep the historical 100-poll settle before the handshake.
ifeq ($(ENABLE_TLS_CLIENT),1)
CFLAGS += -DENABLE_TLS_CLIENT -DTLS_CLIENT_SETTLE_POLLS=100
SRCS += $(ROOT)/src/port/tls_client.c
endif

# Base wolfSSL/wolfCrypt set comes from wolfssl.mk. H753 adds the logging/error/
# encrypt group, the STM32 HW HASH/HMAC port, and the wolfcrypt self-test.
WOLFSSL_SRCS += $(WOLFSSL_LOG_SRCS)
WOLFSSL_SRCS += \
    $(WOLFSSL_ROOT)/wolfcrypt/src/port/st/stm32.c \
    $(WOLFSSL_ROOT)/wolfcrypt/test/test.c

SRCS += $(WOLFSSL_SRCS)

endif # ENABLE_TLS

# -----------------------------------------------------------------------------
# HTTPS web server (requires TLS) - uses existing wolfIP httpd
# -----------------------------------------------------------------------------
ifeq ($(ENABLE_HTTPS),1)
CFLAGS += -DENABLE_HTTPS
SRCS += $(ROOT)/src/http/httpd.c
endif

# -----------------------------------------------------------------------------
# MQTT Broker Support (wolfMQTT broker) - requires TLS
# -----------------------------------------------------------------------------
ifeq ($(ENABLE_MQTT_BROKER),1)

# MQTT Broker requires TLS
ifeq ($(ENABLE_TLS),0)
  $(error ENABLE_MQTT_BROKER=1 requires ENABLE_TLS=1)
endif

# Validate wolfMQTT exists
ifeq ($(wildcard $(WOLFMQTT_ROOT)/wolfmqtt/mqtt_broker.h),)
  $(error wolfMQTT (with broker) not found at $(WOLFMQTT_ROOT). Clone it: git clone https://github.com/wolfSSL/wolfMQTT.git)
endif

CFLAGS += -DENABLE_MQTT_BROKER
CFLAGS += -DWOLFMQTT_USER_SETTINGS
CFLAGS += -I$(WOLFMQTT_ROOT)

# MQTT broker wrapper
SRCS += mqtt_broker.c

# wolfIP-wolfMQTT glue
SRCS += $(ROOT)/src/port/wolfmqtt_io.c

# wolfMQTT broker source files
WOLFMQTT_BROKER_SRCS := \
    $(WOLFMQTT_ROOT)/src/mqtt_broker.c \
    $(WOLFMQTT_ROOT)/src/mqtt_client.c \
    $(WOLFMQTT_ROOT)/src/mqtt_packet.c \
    $(WOLFMQTT_ROOT)/src/mqtt_socket.c

SRCS += $(WOLFMQTT_BROKER_SRCS)

# wolfMQTT objects use relaxed warnings + include paths + user_settings.h
$(WOLFMQTT_ROOT)/%.o: $(WOLFMQTT_ROOT)/%.c
	$(CC) $(CFLAGS_WOLFSSL) -DENABLE_MQTT_BROKER -DWOLFSSL_USER_SETTINGS -DWOLFMQTT_USER_SETTINGS -I$(WOLFMQTT_ROOT) -I$(WOLFSSL_ROOT) -I$(ROOT)/src -c $< -o $@
endif # ENABLE_MQTT_BROKER

# -----------------------------------------------------------------------------
# Build rules
# -----------------------------------------------------------------------------
OBJS := $(patsubst %.c,%.o,$(SRCS))

all: app.bin
	@echo "Built with ENABLE_TLS=$(ENABLE_TLS) ENABLE_TLS_CLIENT=$(ENABLE_TLS_CLIENT) ENABLE_HTTPS=$(ENABLE_HTTPS) ENABLE_MQTT_BROKER=$(ENABLE_MQTT_BROKER)"
ifeq ($(ENABLE_TLS),1)
	@echo "  wolfSSL: $(WOLFSSL_ROOT)"
endif
ifeq ($(ENABLE_MQTT_BROKER),1)
	@echo "  wolfMQTT (broker): $(WOLFMQTT_ROOT)"
endif

app.elf: $(OBJS) $(LDSCRIPT)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group -o $@

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# The $(WOLFSSL_ROOT)/%.o relaxed-warning rule comes from wolfssl.mk.

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
ifeq ($(ENABLE_MQTT_BROKER),1)
	rm -f $(WOLFMQTT_ROOT)/src/*.o
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
	@echo "  ENABLE_TLS=1             Enable wolfSSL TLS support"
	@echo "  ENABLE_TLS_CLIENT=1      Enable TLS client test (Google)"
	@echo "  ENABLE_HTTPS=1           Enable HTTPS web server (port 443)"
	@echo "  ENABLE_MQTT_BROKER=1     Enable MQTT broker (port 8883 with TLS)"
	@echo "  WOLFSSL_ROOT=            Path to wolfSSL (default: ../wolfssl)"
	@echo "  WOLFMQTT_ROOT=           Path to wolfMQTT (default: ../wolfmqtt)"
	@echo "  CC=                      C compiler (default: arm-none-eabi-gcc)"
	@echo ""
	@echo "Examples:"
	@echo "  make                                        # Basic TCP echo (port 7)"
	@echo "  make ENABLE_HTTPS=1                         # HTTPS web server"
	@echo "  make ENABLE_TLS_CLIENT=1                    # TLS client (Google test)"
	@echo "  make ENABLE_MQTT_BROKER=1                   # MQTT broker with TLS"
	@echo "  make ENABLE_TLS_CLIENT=1 ENABLE_HTTPS=1 ENABLE_MQTT_BROKER=1  # All features"
	@echo ""
	@echo "Testing:"
	@echo "  nc <ip> 7                                   # TCP echo test"
	@echo "  curl -k https://<ip>/                       # HTTPS test"
	@echo "  mosquitto_pub -h <ip> -p 8883 --insecure -t test -m hello  # MQTT broker test"

.PHONY: help

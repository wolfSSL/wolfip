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

# Library paths - default to sibling directories. The TLS client uses the
# STM32C5 HW-crypto arm, so it needs the wolfSSL worktree that carries the
# STM32C5 DHUK/BARE port. (?= means an explicit WOLFSSL_ROOT= still wins.)
ifeq ($(ENABLE_TLS_CLIENT),1)
  WOLFSSL_ROOT ?= $(ROOT)/../wolfssl-c5tls
endif
# Sibling WOLFSSL_ROOT/WOLFMQTT_ROOT fallbacks + the shared wolfSSL source list
# and $(WOLFSSL_ROOT)/%.o rule come from the shared fragment (included below).

# -----------------------------------------------------------------------------
# Device headers / CMSIS
# -----------------------------------------------------------------------------
# STM32C5 device header (stm32c5a3xx.h) from the CubeC5 DFP.
CUBEC5_INC ?= $(HOME)/GitHub/STM32CubeC5/stm32c5xx_dfp/Include

# Cortex-M33 CMSIS-Core. No C5 pack ships it, so borrow from the U5 pack
# (overridable, matching the STM32_Bare_Test board.mk convention).
STM32CUBE_FW_U5 ?= $(HOME)/STM32Cube/Repository/STM32Cube_FW_U5_V1.8.0
CMSIS_CORE ?= $(STM32CUBE_FW_U5)/Drivers/CMSIS/Core/Include

# STM32C5A3ZG - Cortex-M33F with single-precision FPU
CFLAGS := -mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard
CFLAGS += -Os -ffreestanding -fdata-sections -ffunction-sections
CFLAGS += -g -ggdb -Wall -Wextra -Werror
CFLAGS += -I. -I$(ROOT) -I$(ROOT)/src -I$(ROOT)/src/port -I$(ROOT)/src/port/stm32
CFLAGS += -I$(CUBEC5_INC) -I$(CMSIS_CORE)
CFLAGS += -DSTM32C5 -DSTM32C5A3xx

# Relaxed warnings for external libraries
CFLAGS_WOLFSSL := $(CFLAGS)
CFLAGS_WOLFSSL := $(filter-out -Werror,$(CFLAGS_WOLFSSL))
CFLAGS_WOLFSSL += -Wno-unused-variable -Wno-unused-function

# Shared wolfSSL build plumbing: WOLFSSL_ROOT/WOLFMQTT_ROOT defaults, the base
# WOLFSSL_SRCS list, and the $(WOLFSSL_ROOT)/%.o relaxed-warning rule.
include $(ROOT)/src/port/stm32/wolfssl.mk

LDSCRIPT := target.ld
# The vendor startup (startup.c) uses the CMSIS __PROGRAM_START flow:
# __cmsis_start runs the .copy.table/.zero.table init then calls newlib's
# _start (crt0), which runs __libc_init_array and main. So we link the
# newlib crt0 via nano/nosys specs rather than -nostartfiles/-nostdlib.
LDFLAGS := -T $(LDSCRIPT) --specs=nano.specs --specs=nosys.specs -Wl,-gc-sections

# Base source files. The vector table lives in startup.c (vendor startup
# with full M33 IVT), so there is no separate ivt.c.
SRCS := startup.c syscalls.c main.c $(ROOT)/src/port/stm32/stm32_eth.c $(ROOT)/src/wolfip.c

# -----------------------------------------------------------------------------
# TLS Support (wolfSSL)
# -----------------------------------------------------------------------------
ifeq ($(ENABLE_TLS),1)

# Validate wolfSSL exists
ifeq ($(wildcard $(WOLFSSL_ROOT)/wolfssl/ssl.h),)
  $(error wolfSSL not found at $(WOLFSSL_ROOT). Clone it: git clone https://github.com/wolfSSL/wolfssl.git)
endif

# ENABLE_TLS is on for the whole build (drives the -DENABLE_TLS #ifdef in
# main.c), but WOLFSSL_WOLFIP / WOLFSSL_STM32C5 / the wolfSSL include must NOT
# reach the plain port sources (stm32_eth.c, wolfip.c, startup.c, ...). Those
# files include wolfip.h, and wolfip.h pulls in wolfssl settings.h when
# WOLFSSL_WOLFIP is set; with WOLFSSL_STM32C5 that in turn pulls the CubeC5
# device header (stm32c5xx.h) whose ETH_* defines collide with stm32_eth.c's
# private fallback macros. So the wolfSSL-facing defines live only in the
# wolfSSL/glue compile flags below, not in the global CFLAGS.
CFLAGS += -DENABLE_TLS

# Defines needed by every object that actually consumes wolfSSL headers:
# the wolfcrypt/ssl sources and the two wolfIP<->wolfSSL glue files.
TLS_WOLFSSL_DEFS := -DWOLFSSL_USER_SETTINGS -DWOLFSSL_WOLFIP -I$(WOLFSSL_ROOT)

# wolfIP-wolfSSL glue (compiled with the wolfSSL-facing flags, see rule below)
SRCS += $(ROOT)/src/port/wolfssl_io.c

# TLS client (3A.0 mutual-auth against openssl s_server)
ifeq ($(ENABLE_TLS_CLIENT),1)
CFLAGS += -DENABLE_TLS_CLIENT
SRCS += $(ROOT)/src/port/tls_client.c

# Milestone 3A.1: set ENABLE_DHUK_KEY=1 to sign CertificateVerify with the
# DHUK-wrapped identity key via a PK callback (identity scalar never in SW).
ENABLE_DHUK_KEY ?= 0
ifeq ($(ENABLE_DHUK_KEY),1)
TLS_WOLFSSL_DEFS += -DENABLE_DHUK_KEY
endif

# STM32C5 HW-crypto arm for the TLS client. WOLFSSL_STM32C5 also gates the C5
# arm in user_settings.h. These join the wolfSSL-facing flags so only the
# wolfSSL/glue objects see them.
TLS_WOLFSSL_DEFS += -DWOLFSSL_STM32C5 -DWOLFSSL_DHUK -DWOLF_CRYPTO_CB

# STM32 DHUK/BARE port + crypto-callback dispatcher for the C5 arm.
SRCS += $(WOLFSSL_ROOT)/wolfcrypt/src/port/st/stm32.c
SRCS += $(WOLFSSL_ROOT)/wolfcrypt/src/cryptocb.c
endif

# CFLAGS_WOLFSSL was captured (:=) before this block; append the wolfSSL-facing
# defines so the wolfcrypt/ssl objects build against the C5 arm and user
# settings. The wolfSSL objects use the $(WOLFSSL_ROOT)/%.o rule (relaxed
# warnings) further down. The two glue files (tls_client.c, wolfssl_io.c) get
# explicit compile rules near the build rules at the bottom -- placing target
# rules here (before "all:") would hijack the default goal.
CFLAGS_WOLFSSL += $(TLS_WOLFSSL_DEFS)

# wolfSSL/wolfCrypt source set comes from the shared wolfssl.mk (included above),
# plus the logging/error/encrypt group.
WOLFSSL_SRCS += $(WOLFSSL_LOG_SRCS)
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

# The two wolfIP<->wolfSSL glue files live in the app/port tree but include
# wolfssl/ssl.h, so they need the wolfSSL-facing defines (WOLFSSL_WOLFIP /
# WOLFSSL_STM32C5 / -I$(WOLFSSL_ROOT)). Keep -Werror (our code). These are
# defined only when ENABLE_TLS is on, and sit after "all:" so they do not
# hijack the default goal.
ifeq ($(ENABLE_TLS),1)
# Shared TLS client: mutual auth (client cert from tls_certs.h) + forced suite.
$(ROOT)/src/port/tls_client.o: $(ROOT)/src/port/tls_client.c
	$(CC) $(CFLAGS) $(TLS_WOLFSSL_DEFS) -DTLS_CLIENT_MUTUAL_AUTH -DTLS_CLIENT_CIPHER='"TLS_AES_128_GCM_SHA256"' -c $< -o $@

$(ROOT)/src/port/wolfssl_io.o: $(ROOT)/src/port/wolfssl_io.c
	$(CC) $(CFLAGS) $(TLS_WOLFSSL_DEFS) -c $< -o $@
endif

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
	@echo "RAM usage (static): $$(arm-none-eabi-size app.elf | awk 'NR==2{printf "%.1f%% (%d / %d bytes)", ($$2+$$3)*100/262144, $$2+$$3, 262144}')"

# Flash using STM32CubeProgrammer over SWD (ST-LINK V3 on NUCLEO-C5A3ZG)
flash: app.bin
	STM32_Programmer_CLI -c port=swd sn=003D00203235510F37333439 mode=UR -e all -d app.bin 0x08000000 -v -rst

.PHONY: all clean size flash

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
help:
	@echo "STM32C5A3ZG wolfIP Build System"
	@echo ""
	@echo "Usage: make [target] [options]"
	@echo ""
	@echo "Targets:"
	@echo "  all      Build app.bin (default)"
	@echo "  clean    Remove build artifacts"
	@echo "  size     Show memory usage statistics"
	@echo "  flash    Flash to device using STM32_Programmer_CLI"
	@echo "  help     Show this help"
	@echo ""
	@echo "Options:"
	@echo "  ENABLE_TLS=1             Enable wolfSSL TLS support"
	@echo "  ENABLE_TLS_CLIENT=1      Enable TLS client test (Google)"
	@echo "  ENABLE_HTTPS=1           Enable HTTPS web server (port 443)"
	@echo "  ENABLE_MQTT_BROKER=1     Enable MQTT broker (port 8883 with TLS)"
	@echo "  WOLFSSL_ROOT=            Path to wolfSSL (default: ../wolfssl)"
	@echo "  WOLFMQTT_ROOT=           Path to wolfMQTT (default: ../wolfmqtt)"
	@echo "  CUBEC5_INC=              Path to CubeC5 DFP Include (stm32c5a3xx.h)"
	@echo "  CMSIS_CORE=              Path to Cortex-M33 CMSIS-Core"
	@echo "  CC=                      C compiler (default: arm-none-eabi-gcc)"
	@echo ""
	@echo "Testing:"
	@echo "  nc <ip> 7                                   # TCP echo test"

.PHONY: help

CC?=gcc
CFLAGS:=-Wall -Werror -Wextra -I. -D_GNU_SOURCE
CFLAGS+=-g -ggdb -Wdeclaration-after-statement
EXTRA_CFLAGS?=
CFLAGS+=$(EXTRA_CFLAGS)
LDFLAGS+=-pthread
# debug flags:
#   CFLAGS+=-DDEBUG
#   CFLAGS+=-DDEBUG_TAP
#   CFLAGS+=-DDEBUG_ETH
#   CFLAGS+=-DDEBUG_IP
#   CFLAGS+=-DDEBUG_UDP
#   CFLAGS+=-DDEBUG_ESP

UNAME_S:=$(shell uname -s)
UNAME_M:=$(shell uname -m)
UNAME_LC:=$(shell echo $(UNAME_S) | tr 'A-Z' 'a-z')
ifeq ($(UNAME_S),FreeBSD)
  CFLAGS+=-I/usr/local/include
  LDFLAGS+=-L/usr/local/lib
endif
ifeq ($(UNAME_S),Darwin)
  BREW_PREFIX?=$(shell brew --prefix 2>/dev/null)
  ifeq ($(filter command\ line environment,$(origin BREW_PREFIX)),)
    ifeq ($(UNAME_M),arm64)
      ARM_BREW_PREFIX:=$(shell /opt/homebrew/bin/brew --prefix 2>/dev/null)
      ifneq ($(ARM_BREW_PREFIX),)
        BREW_PREFIX:=$(ARM_BREW_PREFIX)
      endif
    endif
  endif
  ifeq ($(BREW_PREFIX),)
    BREW_PREFIX:=/opt/homebrew
  endif
  WOLFSSL_PREFIX?=$(shell brew --prefix wolfssl 2>/dev/null)
  ifeq ($(filter command\ line environment,$(origin WOLFSSL_PREFIX)),)
    ifeq ($(UNAME_M),arm64)
      ARM_WOLFSSL_PREFIX:=$(shell /opt/homebrew/bin/brew --prefix wolfssl 2>/dev/null)
      ifneq ($(ARM_WOLFSSL_PREFIX),)
        WOLFSSL_PREFIX:=$(ARM_WOLFSSL_PREFIX)
      endif
    endif
  endif
  ifneq ($(WOLFSSL_PREFIX),)
    CFLAGS+=-I$(WOLFSSL_PREFIX)/include
    LDFLAGS+=-L$(WOLFSSL_PREFIX)/lib
  endif
  CHECK_PREFIX?=$(shell brew --prefix check 2>/dev/null)
  ifeq ($(filter command\ line environment,$(origin CHECK_PREFIX)),)
    ifeq ($(UNAME_M),arm64)
      ARM_CHECK_PREFIX:=$(shell /opt/homebrew/bin/brew --prefix check 2>/dev/null)
      ifneq ($(ARM_CHECK_PREFIX),)
        CHECK_PREFIX:=$(ARM_CHECK_PREFIX)
      endif
    endif
  endif
  ifeq ($(CHECK_PREFIX),)
    CHECK_PREFIX:=$(BREW_PREFIX)
  endif
  ifneq ($(CHECK_PREFIX),)
    UNIT_CFLAGS+=-I$(CHECK_PREFIX)/include
    UNIT_LDFLAGS+=-L$(CHECK_PREFIX)/lib
  endif
endif


# Network device driver selection
# Default to TAP for local examples/tests. Use BUILD_VDE=1 to opt in VDE.
BUILD_VDE ?= 0
ifeq ($(BUILD_VDE),1)
  # VDE (Virtual Distributed Ethernet) driver
  NETDEV_SRC:=src/port/vde2/vde_device.c
  NETDEV_OBJ:=$(patsubst src/%.c,build/%.o,$(NETDEV_SRC))
  NETDEV_PIE_OBJ:=$(patsubst src/%.c,build/pie/%.o,$(NETDEV_SRC))
  CFLAGS+=-DWOLFIP_USE_VDE=1
  LDFLAGS+=-lvdeplug
else
  # TAP device driver (default)
  TAP_SRC:=src/port/posix/tap_$(UNAME_LC).c
  ifeq ($(wildcard $(TAP_SRC)),)
    TAP_SRC:=src/port/posix/tap_linux.c
  endif
  NETDEV_SRC:=$(TAP_SRC)
  NETDEV_OBJ:=$(patsubst src/%.c,build/%.o,$(TAP_SRC))
  NETDEV_PIE_OBJ:=$(patsubst src/%.c,build/pie/%.o,$(TAP_SRC))
endif

# Legacy aliases for backward compatibility
TAP_OBJ:=$(NETDEV_OBJ)
TAP_PIE_OBJ:=$(NETDEV_PIE_OBJ)

# Optional TFTP module. Default to off to match config.h
# (WOLFIP_ENABLE_TFTP == 0); set WOLFIP_ENABLE_TFTP=1 on the command
# line to compile and link the TFTP client/server objects.
WOLFIP_ENABLE_TFTP ?= 0
ifeq ($(WOLFIP_ENABLE_TFTP),1)
WOLFIP_TFTP_SRC:=$(wildcard src/tftp/*.c)
WOLFIP_TFTP_OBJ:=$(patsubst src/%.c,build/%.o,$(WOLFIP_TFTP_SRC))
WOLFIP_TFTP_PIE_OBJ:=$(patsubst src/%.c,build/pie/%.o,$(WOLFIP_TFTP_SRC))
CFLAGS+=-DWOLFIP_ENABLE_TFTP=1
else
WOLFIP_TFTP_SRC:=
WOLFIP_TFTP_OBJ:=
WOLFIP_TFTP_PIE_OBJ:=
endif

ifeq ($(UNAME_S),Darwin)
  BEGIN_GROUP:=
  END_GROUP:=
  OPEN_CMD?=open
else
  BEGIN_GROUP:=-Wl,--start-group
  END_GROUP:=-Wl,--end-group
  OPEN_CMD?=xdg-open
endif

CHECK_PKG_CFLAGS:=$(shell pkg-config --cflags check 2>/dev/null)
CHECK_PKG_LIBS:=$(shell pkg-config --libs check 2>/dev/null)

ifneq ($(CHECK_PKG_CFLAGS),)
  UNIT_CFLAGS+=$(CHECK_PKG_CFLAGS)
endif
UNIT_CFLAGS+=-Isrc/test/unit/mocks

CPPCHECK=cppcheck
CPPCHECK_FLAGS=--enable=warning,performance,portability,missingInclude \
			   --suppress=missingIncludeSystem \
			   -i src/test \
			   --suppress=unusedFunction --suppress=unusedVariable \
			   --suppress=missingInclude --suppress=variableScope \
			   --suppress=constVariable --suppress=constVariablePointer \
			   --suppress=constParameterPointer \
			   --suppress=constParameterCallback \
			   --suppress=toomanyconfigs \
			   --suppress=unmatchedSuppression --inconclusive \
			   --suppress=comparePointers:src/port/stm32h563/startup.c \
			   --suppress=comparePointers:src/port/stm32h563/syscalls.c \
			   --suppress=comparePointers:src/port/stm32h753/startup.c \
			   --suppress=comparePointers:src/port/stm32h753/syscalls.c \
			   --suppress=comparePointers:src/port/stm32n6/startup.c \
			   --suppress=comparePointers:src/port/stm32n6/syscalls.c \
			   --suppress=comparePointers:src/port/va416xx/startup.c \
			   --suppress=comparePointers:src/port/va416xx/syscalls.c \
			   --suppress=comparePointers:src/port/lpc54s018/startup.c \
			   --suppress=comparePointers:src/port/lpc54s018/syscalls.c \
			   --suppress=comparePointers:src/port/stm32f439/startup.c \
			   --suppress=comparePointers:src/port/stm32f439/syscalls.c \
			   --suppress=comparePointers:src/port/rp2350_cyw43439/startup_m33.c \
			   --suppress=comparePointers:src/port/rp2350_cyw43439/startup_hazard3.c \
			   --suppress=comparePointers:src/port/rp2350_cyw43439/syscalls.c \
			   --suppress=unknownMacro:src/port/stm32h563/dot1x_client.c \
			   --suppress=preprocessorErrorDirective:src/supplicant/supplicant_features.h \
			   --disable=style \
			   --std=c99 --language=c \
			   --platform=unix64 \
			   --check-level=exhaustive \
			   --error-exitcode=1 --xml --xml-version=2

OBJ=build/wolfip.o \
	$(WOLFIP_TFTP_OBJ) \
	$(TAP_OBJ)

IPFILTER_OBJ=build/ipfilter/wolfip.o \
	$(WOLFIP_TFTP_OBJ) \
	$(TAP_OBJ)

ESP_OBJ=build/esp/wolfip.o \
	$(WOLFIP_TFTP_OBJ) \
	$(TAP_OBJ)

# When WOLFSSL_PREFIX is set (e.g. CI builds wolfSSL into a cached prefix),
# the include dir is only folded into CFLAGS inside the Darwin block above and
# into WOLFSSL_CFLAGS further below - neither is in scope for this probe on
# Linux. Add the prefix include here so the probe matches how the supplicant
# objects are actually compiled; otherwise a perfectly good prefixed wolfSSL
# is reported "not found" and the build aborts.
HAVE_WOLFSSL:=$(shell printf "#include <wolfssl/options.h>\nint main(void){return 0;}\n" | $(CC) $(CFLAGS) $(if $(WOLFSSL_PREFIX),-I$(WOLFSSL_PREFIX)/include) -x c - -c -o /dev/null 2>/dev/null && echo 1)

# Require wolfSSL unless the requested goals are wolfSSL-independent (unit/cppcheck/clean).
REQ_WOLFSSL_GOALS:=$(filter-out unit cppcheck clean,$(MAKECMDGOALS))
ifeq ($(strip $(MAKECMDGOALS)),)
  ifeq ($(HAVE_WOLFSSL),)
    $(warning wolfSSL headers not found. Skipping wolfSSL-dependent targets)
  endif
else
  ifneq ($(REQ_WOLFSSL_GOALS),)
    ifeq ($(HAVE_WOLFSSL),)
      $(error wolfSSL headers not found. Please install wolfSSL or adjust include paths)
    endif
  endif
endif

EXE=build/tcpecho build/tcp_netcat_poll build/tcp_netcat_select \
	build/test-evloop build/test-dns build/test-wolfssl-forwarding \
	build/test-ttl-expired build/test-wolfssl build/test-httpd \
	build/test-http-smuggle build/test-http-arg-oob \
	build/test-http-close-notify \
	build/test-freertos-close-last-ack \
	build/test-posix-errno \
	build/ipfilter-logger \
	build/test-esp build/esp-server
ifeq ($(UNAME_S),Linux)
  EXE+= build/test-evloop-tun
endif
LIB=libwolfip.so

PREFIX=/usr/local


all: $(EXE) $(LIB)

#Static library
static: CFLAGS+=-static
static: libtcpip.a



libtcpip.a: $(OBJ)
	@ar rcs $@ $^

libwolfip.so:CFLAGS+=-fPIC
libwolfip.so:  build/pie/port/posix/bsd_socket.o build/pie/wolfip.o \
	$(WOLFIP_TFTP_PIE_OBJ) \
	$(TAP_PIE_OBJ)
	@mkdir -p `dirname $@` || true
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -shared -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(END_GROUP)


clean:
	@rm -rf build
	@rm -f *.so

asan: $(EXE) $(LIB)
asan:CFLAGS+=-fsanitize=address
asan:LDFLAGS+=-static-libasan

ubsan: $(EXE) $(LIB)
ubsan:CFLAGS+=-fsanitize=undefined -fno-sanitize-recover=all
ubsan:LDFLAGS+=-fsanitize=undefined

leaksan: $(EXE) $(LIB)
leaksan:CFLAGS+=-fsanitize=leak
leaksan:LDFLAGS+=-fsanitize=leak

ESP_CFLAGS = \
    -DWOLFIP_ESP  -DWOLFSSL_WOLFIP

# wolfGuard (FIPS WireGuard)
WOLFGUARD_CFLAGS = -DWOLFGUARD -Wno-cpp
WOLFGUARD_SRC := src/wolfguard/wolfguard.c \
                 src/wolfguard/wg_noise.c \
                 src/wolfguard/wg_crypto.c \
                 src/wolfguard/wg_cookie.c \
                 src/wolfguard/wg_allowedips.c \
                 src/wolfguard/wg_packet.c \
                 src/wolfguard/wg_timers.c
WOLFGUARD_OBJ := $(patsubst src/%.c,build/wolfguard/%.o,$(WOLFGUARD_SRC))

# wolfSupplicant - per-feature build flags. Core (PSK + 4-way + EAP
# framing) is always built; the per-method modules below are gated.
#
#   WOLFIP_ENABLE_EAP_TLS=1        WPA2-Enterprise EAP-TLS (default on)
#   WOLFIP_ENABLE_PEAP_MSCHAPV2=1  WPA2-Enterprise PEAPv0/MSCHAPv2
#                                  (default off - pulls in deprecated
#                                  MD4 + DES; needs wolfSSL built with
#                                  --enable-md4 --enable-des3)
#   WOLFIP_ENABLE_SAE=1            WPA3-Personal SAE dragonfly
#                                  (default on - needs WOLFSSL_PUBLIC_MP
#                                  in the linked wolfSSL build for the
#                                  mp_* / sp_* math ABI)
#   WOLFIP_ENABLE_SAE_H2E=1        WPA3-SAE Hash-to-Element PWE
#                                  (default on; requires WOLFIP_ENABLE_SAE.
#                                  Off = legacy hunt-and-peck only.)
#   WOLFIP_ENABLE_SAE_HNP=1        WPA3-SAE hunt-and-peck PWE
#                                  (default on; set to 0 in H2E-only
#                                  builds to drop ~600 B of text from
#                                  sae_compute_pwe_hnp).
#
# WOLFSSL_PREFIX is optional. When set, the build links against that
# wolfSSL tree (-I, -L, -Wl,-rpath) instead of the system one.
WOLFIP_ENABLE_EAP_TLS       ?= 1
WOLFIP_ENABLE_PEAP_MSCHAPV2 ?= 0
WOLFIP_ENABLE_SAE           ?= 1
WOLFIP_ENABLE_SAE_H2E       ?= 1
WOLFIP_ENABLE_SAE_HNP       ?= 1

ifneq ($(WOLFSSL_PREFIX),)
WOLFSSL_CFLAGS := -I$(WOLFSSL_PREFIX)/include
WOLFSSL_LIBS   := -L$(WOLFSSL_PREFIX)/lib -lwolfssl \
                  -Wl,-rpath,$(WOLFSSL_PREFIX)/lib
endif

# Core (always present). eap_tls.c is just EAP-TLS framing (L/M/S flag
# handling + reassembly buffers) - no wolfSSL TLS engine, so it stays
# in core for use by unit tests even when EAP-TLS is disabled.
SUPPLICANT_SRC := src/supplicant/wpa_crypto.c \
                  src/supplicant/eapol.c \
                  src/supplicant/rsn_ie.c \
                  src/supplicant/eap.c \
                  src/supplicant/eap_tls.c \
                  src/supplicant/supplicant.c

ifeq ($(WOLFIP_ENABLE_EAP_TLS),1)
SUPPLICANT_SRC += src/supplicant/eap_tls_engine.c
CFLAGS += -DWOLFIP_ENABLE_EAP_TLS=1
endif

ifeq ($(WOLFIP_ENABLE_PEAP_MSCHAPV2),1)
SUPPLICANT_SRC += src/supplicant/mschapv2.c \
                  src/supplicant/eap_peap.c
CFLAGS += -DWOLFIP_ENABLE_PEAP_MSCHAPV2=1
# PEAP/MSCHAPv2 transitively requires EAP-TLS for the outer TLS engine.
ifneq ($(WOLFIP_ENABLE_EAP_TLS),1)
$(error WOLFIP_ENABLE_PEAP_MSCHAPV2=1 requires WOLFIP_ENABLE_EAP_TLS=1)
endif
endif

ifeq ($(WOLFIP_ENABLE_SAE),1)
SUPPLICANT_SRC += src/supplicant/sae_crypto.c
CFLAGS += -DWOLFIP_ENABLE_SAE=1
ifeq ($(WOLFIP_ENABLE_SAE_H2E),1)
CFLAGS += -DWOLFIP_ENABLE_SAE_H2E=1
endif
ifeq ($(WOLFIP_ENABLE_SAE_HNP),0)
CFLAGS += -DWOLFIP_ENABLE_SAE_HNP=0
# At least one PWE method must remain enabled.
ifneq ($(WOLFIP_ENABLE_SAE_H2E),1)
$(error WOLFIP_ENABLE_SAE_HNP=0 requires WOLFIP_ENABLE_SAE_H2E=1)
endif
endif
else
ifeq ($(WOLFIP_ENABLE_SAE_H2E),1)
$(error WOLFIP_ENABLE_SAE_H2E=1 requires WOLFIP_ENABLE_SAE=1)
endif
endif

SUPPLICANT_OBJ := $(patsubst src/%.c,build/%.o,$(SUPPLICANT_SRC))

# Header-dependency tracking for the supplicant + its host glue. Without
# this, editing a supplicant header (e.g. a struct in supplicant.h) would
# not rebuild the dependent test objects, silently linking objects that
# disagree on a struct's size -> stack/heap corruption at runtime. The
# -MMD -MP above emit a .d per object; pull them in if present.
-include $(SUPPLICANT_OBJ:.o=.d)
-include build/supplicant/*.d
-include build/nl80211_sta.d build/wolfsta_main.d

build/supplicant/%.o: src/supplicant/%.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) $(WOLFSSL_CFLAGS) $(NL80211_CFLAGS) -MMD -MP -Isrc/supplicant -c $< -o $@

# WOLFSSL_LIBS / WOLFSSL_CFLAGS may already be set above when
# WOLFSSL_PREFIX is provided. Otherwise default to pkg-config detection
# and a plain -lwolfssl fallback.
ifeq ($(WOLFSSL_LIBS),)
WOLFSSL_LIBS:=$(shell pkg-config --libs wolfssl 2>/dev/null)
endif
ifeq ($(WOLFSSL_LIBS),)
WOLFSSL_LIBS:=-lwolfssl
endif
ifeq ($(WOLFSSL_CFLAGS),)
WOLFSSL_CFLAGS:=$(shell pkg-config --cflags wolfssl 2>/dev/null)
endif

build/test-wpa-crypto: $(SUPPLICANT_OBJ) build/supplicant/test_wpa_crypto.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(END_GROUP)

build/test-supplicant-4way: $(SUPPLICANT_OBJ) build/supplicant/test_supplicant_4way.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(END_GROUP)

build/test-supplicant-pmksa: $(SUPPLICANT_OBJ) build/supplicant/test_supplicant_pmksa.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(END_GROUP)

build/test-eap-framing: $(SUPPLICANT_OBJ) build/supplicant/test_eap_framing.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(END_GROUP)

# CYW43439 driver SDPCM/BDC framing unit test - pure logic, host-compiled,
# no wolfSSL, no Pico (cyw43_sdpcm.c includes only stdint/string).
build/port/rp2350_cyw43439/%.o: src/port/rp2350_cyw43439/%.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -Isrc/port/rp2350_cyw43439 -c $< -o $@

build/test-cyw43-sdpcm: build/port/rp2350_cyw43439/cyw43_sdpcm.o \
                        build/port/rp2350_cyw43439/test_cyw43_sdpcm.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(^)

ifeq ($(WOLFIP_ENABLE_EAP_TLS),1)
build/test-eap-tls-engine: $(SUPPLICANT_OBJ) build/supplicant/test_eap_tls_engine.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(END_GROUP)
endif

ifeq ($(WOLFIP_ENABLE_EAP_TLS),1)
build/test-supplicant-eap-tls: $(SUPPLICANT_OBJ) build/supplicant/test_supplicant_eap_tls.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(END_GROUP)

build/test-supplicant-hostapd: $(SUPPLICANT_OBJ) build/supplicant/test_supplicant_hostapd.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(END_GROUP)

# WPA2-Enterprise (EAP-TLS) over the SoftMAC nl80211 path on mac80211_hwsim
# (full enterprise join: 802.1X assoc + EAP-TLS + MSK-keyed 4-way).
build/test-supplicant-hwsim-eap-softmac: $(SUPPLICANT_OBJ) \
		build/supplicant/test_supplicant_hwsim_eap_softmac.o \
		build/nl80211_sta.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(NL80211_LIBS) $(END_GROUP)

supplicant-hwsim-eap-softmac-test: build/test-supplicant-hwsim-eap-softmac build/test-eap-tls-engine
	@sudo ./tools/hostapd/run_hwsim_eap_softmac_test.sh
endif

build/test-supplicant-hostapd-psk: $(SUPPLICANT_OBJ) build/supplicant/test_supplicant_hostapd_psk.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(END_GROUP)

ifeq ($(WOLFIP_ENABLE_SAE),1)
build/test-sae-crypto: $(SUPPLICANT_OBJ) build/supplicant/test_sae_crypto.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(END_GROUP)

build/test-supplicant-sae: $(SUPPLICANT_OBJ) build/supplicant/test_supplicant_sae.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(END_GROUP)

# WPA3-SAE hostapd interop via mac80211_hwsim + nl80211 external auth.
build/test-supplicant-hostapd-sae: $(SUPPLICANT_OBJ) build/supplicant/test_supplicant_hostapd_sae.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(NL80211_LIBS) $(END_GROUP)

supplicant-hwsim-sae-test: build/test-supplicant-hostapd-sae
	@sudo ./tools/hostapd/run_hwsim_sae_test.sh

# Same harness but configures hostapd with sae_pwe=2 (H2E only) and tells
# the supplicant test binary to use RFC 9380 SSWU PWE. Subject to the
# same hwsim FullMAC limitation noted in tools/hostapd/README.md.
supplicant-hwsim-sae-h2e-test: build/test-supplicant-hostapd-sae
	@sudo env WOLFIP_SAE_H2E=1 ./tools/hostapd/run_hwsim_sae_test.sh

# WPA3-SAE over the SoftMAC nl80211 path (AUTHENTICATE + SAE_DATA, then
# ASSOCIATE) via tools/hostapd/nl80211_sta.c. Unlike the FullMAC
# external-auth binary above, this one is what mac80211_hwsim actually
# supports, so it validates green under hwsim with no hardware - and the
# same code drives a real SoftMAC USB radio (e.g. a TP-Link card).
build/test-supplicant-hwsim-sae-softmac: $(SUPPLICANT_OBJ) \
		build/supplicant/test_supplicant_hwsim_sae_softmac.o \
		build/nl80211_sta.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(NL80211_LIBS) $(END_GROUP)

build/test-supplicant-hwsim-pmksa-softmac: $(SUPPLICANT_OBJ) \
		build/supplicant/test_supplicant_hwsim_pmksa_softmac.o \
		build/nl80211_sta.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(NL80211_LIBS) $(END_GROUP)

supplicant-hwsim-sae-softmac-test: build/test-supplicant-hwsim-sae-softmac
	@sudo ./tools/hostapd/run_hwsim_sae_softmac_test.sh

# WPA3-SAE PMKSA fast reconnect: full SAE then a cached-PMKSA reconnect.
supplicant-hwsim-pmksa-test: build/test-supplicant-hwsim-pmksa-softmac
	@sudo ./tools/hostapd/run_hwsim_pmksa_softmac_test.sh

supplicant-hwsim-sae-softmac-h2e-test: build/test-supplicant-hwsim-sae-softmac
	@sudo ./tools/hostapd/run_hwsim_sae_softmac_h2e_test.sh

# WPA3-SAE over hwsim for ECC groups 20 (P-384) and 21 (P-521), H&P + H2E.
supplicant-hwsim-sae-softmac-g20-test: build/test-supplicant-hwsim-sae-softmac
	@sudo ./tools/hostapd/run_hwsim_sae_softmac_g20_test.sh
supplicant-hwsim-sae-softmac-g21-test: build/test-supplicant-hwsim-sae-softmac
	@sudo ./tools/hostapd/run_hwsim_sae_softmac_g21_test.sh
supplicant-hwsim-sae-softmac-g20-h2e-test: build/test-supplicant-hwsim-sae-softmac
	@sudo ./tools/hostapd/run_hwsim_sae_softmac_g20_h2e_test.sh
supplicant-hwsim-sae-softmac-g21-h2e-test: build/test-supplicant-hwsim-sae-softmac
	@sudo ./tools/hostapd/run_hwsim_sae_softmac_g21_h2e_test.sh

# Negative test: a wrong SAE password must be cleanly rejected (no hang/crash).
supplicant-hwsim-sae-softmac-badpw-test: build/test-supplicant-hwsim-sae-softmac
	@sudo ./tools/hostapd/run_hwsim_sae_softmac_badpw_test.sh

# wolfsta - host STA app: wolfIP + wolfSupplicant bound to a real radio
# netdev (PSK or SAE) over the SoftMAC nl80211 path, then DHCP. Needs
# WOLFIP_ENABLE_SAE=1 (default). Validate on mac80211_hwsim first, then
# run unchanged against a TP-Link SoftMAC card.
build/wolfsta_main.o: tools/wolfsta/wolfsta.c
	@mkdir -p build || true
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) $(WOLFSSL_CFLAGS) $(NL80211_CFLAGS) -MMD -MP -Isrc/supplicant -Itools/hostapd -c $< -o $@

build/wolfsta: build/wolfip.o $(WOLFIP_TFTP_OBJ) $(SUPPLICANT_OBJ) \
		build/nl80211_sta.o build/wolfsta_main.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(NL80211_LIBS) $(END_GROUP)

wolfsta: build/wolfsta

# End-to-end wolfsta over mac80211_hwsim: join (SAE/PSK) -> DHCP -> ping +
# UDP echo. AUTH=psk for the WPA2-PSK variant; WOLFIP_SAE_H2E=1 for H2E.
supplicant-hwsim-wolfsta-dhcp-test: build/wolfsta
	@sudo ./tools/hostapd/run_hwsim_wolfsta_dhcp_test.sh
supplicant-hwsim-wolfsta-dhcp-psk-test: build/wolfsta
	@sudo ./tools/hostapd/run_hwsim_wolfsta_dhcp_psk_test.sh
endif

# MSCHAPv2 crypto-only test + full hostapd-PEAP interop. Only built
# when PEAP/MSCHAPv2 is enabled.
ifeq ($(WOLFIP_ENABLE_PEAP_MSCHAPV2),1)
build/test-mschapv2: build/supplicant/mschapv2.o build/supplicant/test_mschapv2.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(END_GROUP)

build/test-supplicant-hostapd-peap: $(SUPPLICANT_OBJ) build/supplicant/test_supplicant_hostapd_peap.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(WOLFSSL_LIBS) $(END_GROUP)

supplicant-hostapd-peap-test: build/test-supplicant-hostapd-peap build/test-eap-tls-engine
	@sudo MODE=peap ./tools/hostapd/run_hostapd_test.sh
endif

SUPPLICANT_TEST_BINS := build/test-wpa-crypto build/test-supplicant-4way \
                        build/test-supplicant-pmksa build/test-eap-framing \
                        build/test-cyw43-sdpcm
ifeq ($(WOLFIP_ENABLE_EAP_TLS),1)
SUPPLICANT_TEST_BINS += build/test-eap-tls-engine build/test-supplicant-eap-tls
endif
ifeq ($(WOLFIP_ENABLE_SAE),1)
SUPPLICANT_TEST_BINS += build/test-sae-crypto build/test-supplicant-sae
endif

supplicant-tests: $(SUPPLICANT_TEST_BINS)
	@for t in $(SUPPLICANT_TEST_BINS); do echo "==> $$t"; $$t || exit 1; done

# Real-authenticator interop tests. Both require hostapd installed and
# root (veth pair + AF_PACKET raw socket). Not part of supplicant-tests
# because of those constraints.
supplicant-hostapd-test: build/test-supplicant-hostapd build/test-eap-tls-engine
	@sudo ./tools/hostapd/run_hostapd_test.sh

supplicant-hostapd-psk-test: build/test-supplicant-hostapd-psk
	@sudo MODE=psk ./tools/hostapd/run_hostapd_test.sh

# nl80211 helper used by the hwsim path - small libnl-genl-3 client that
# drives the STA's open auth + WPA2 association so hostapd will start
# the real 4-way handshake. EAPOL itself flows via AF_PACKET as usual.
NL80211_CFLAGS:=$(shell pkg-config --cflags libnl-genl-3.0 libnl-3.0 2>/dev/null)
NL80211_LIBS:=$(shell pkg-config --libs libnl-genl-3.0 libnl-3.0 2>/dev/null)

build/nl80211_connect: tools/hostapd/nl80211_connect.c
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(NL80211_CFLAGS) -o $@ $< $(NL80211_LIBS)

# Reusable SoftMAC STA radio glue, linked by the SoftMAC SAE test binary
# (and by the wolfsta host app). Needs the nl80211 + supplicant headers.
build/nl80211_sta.o: tools/hostapd/nl80211_sta.c
	@mkdir -p build || true
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) $(NL80211_CFLAGS) -MMD -MP -Isrc/supplicant -c $< -o $@

supplicant-hwsim-psk-test: build/test-supplicant-hostapd-psk build/nl80211_connect
	@sudo ./tools/hostapd/run_hwsim_psk_test.sh

# Test

ifeq ($(CHECK_PKG_LIBS),)
  UNIT_LIBS=-lcheck -lm -lpthread -lrt -ldl -lsubunit
  ifeq ($(UNAME_S),Darwin)
    UNIT_LIBS=-lcheck -lm -lpthread
  else ifeq ($(UNAME_S),FreeBSD)
    UNIT_LIBS=-lcheck -lm -lpthread
  endif
else
  UNIT_LIBS=$(CHECK_PKG_LIBS)
endif

unit:LDFLAGS+=$(UNIT_LIBS)
build/test-evloop: $(OBJ) build/test/test_eventloop.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(END_GROUP)

build/test-evloop-tun: $(OBJ) build/test/test_eventloop_tun.o build/port/posix/linux_tun.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(END_GROUP)

build/test-multicast-interop: CFLAGS+=-DIP_MULTICAST
build/test-multicast-interop: build/multicast/wolfip.o build/test/test_multicast_interop.o build/port/posix/tap_linux.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(END_GROUP)

build/multicast/wolfip.o: src/wolfip.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $< (multicast)"
	@$(CC) $(CFLAGS) -DIP_MULTICAST -c $< -o $@

build/test-dns: $(OBJ) build/test/test_dhcp_dns.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(END_GROUP)

# Bidirectional TFTP interop test against tftpd-hpa / tftp-hpa.
# Forces WOLFIP_ENABLE_TFTP=1 and uses a single-session server so the
# default UDP socket pool can hold both the listen and the transfer
# socket without raising MAX_UDPSOCKETS.
build/tftp-interop/wolfip.o: src/wolfip.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $< (tftp-interop)"
	@$(CC) $(CFLAGS) -DWOLFIP_ENABLE_TFTP=1 -c $< -o $@

build/tftp-interop/wolftftp.o: src/tftp/wolftftp.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $< (tftp-interop)"
	@$(CC) $(CFLAGS) -DWOLFIP_ENABLE_TFTP=1 -DWOLFTFTP_SERVER_MAX_SESSIONS=1 \
		-c $< -o $@

build/test/test_tftp_interop.o: src/test/test_tftp_interop.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -DWOLFIP_ENABLE_TFTP=1 -DWOLFTFTP_SERVER_MAX_SESSIONS=1 \
		-c $< -o $@

build/test-tftp-interop: build/tftp-interop/wolfip.o \
		build/tftp-interop/wolftftp.o $(TAP_OBJ) \
		build/test/test_tftp_interop.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(END_GROUP)

.PHONY: tftp-interop-test
tftp-interop-test: build/test-tftp-interop
	@echo "[RUN] $< (requires root, tftpd-hpa and tftp-hpa)"
	@sudo -n true >/dev/null 2>&1 || { echo "tftp-interop-test needs to run as root (sudo)"; exit 1; }
	@sudo ./build/test-tftp-interop all

build/tcpecho: $(OBJ) build/port/posix/bsd_socket.o build/test/tcp_echo.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(END_GROUP)

build/tcp_netcat_poll: $(OBJ) build/port/posix/bsd_socket.o build/test/tcp_netcat_poll.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(END_GROUP)

build/tcp_netcat_select: $(OBJ) build/port/posix/bsd_socket.o build/test/tcp_netcat_select.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(END_GROUP)

build/raw_ping: $(OBJ) build/port/posix/bsd_socket.o build/test/raw_ping.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(END_GROUP)

build/packet_ping: $(OBJ) build/port/posix/bsd_socket.o build/test/packet_ping.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(END_GROUP)

# F-4950 regression: test_posix_errno.c #includes bsd_socket.c directly, so the
# shim object must not be linked again here.
build/test-posix-errno: $(OBJ) build/test/test_posix_errno.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(END_GROUP)

.PHONY: posix-errno-test
posix-errno-test: build/test-posix-errno
	@echo "[RUN] $<"
	@./build/test-posix-errno


build/test-wolfssl:CFLAGS+=-Wno-cpp -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP
build/test-httpd:CFLAGS+=-Wno-cpp -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP -Isrc/http
build/test/test_httpd.o:CFLAGS+=-Wno-cpp -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP -DWOLFIP_ENABLE_HTTP -Isrc/http
build/http/httpd.o:CFLAGS+=-Wno-cpp -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP -DWOLFIP_ENABLE_HTTP -Isrc/http
build/test-wolfssl-forwarding:CFLAGS+=-Wno-cpp -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP -DWOLFIP_MAX_INTERFACES=2 -DWOLFIP_ENABLE_FORWARDING=1

build/test-wolfssl: $(OBJ) build/test/test_native_wolfssl.o build/port/wolfssl_io.o build/certs/server_key.o build/certs/ca_cert.o build/certs/server_cert.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) -lwolfssl $(END_GROUP)

build/ipfilter-logger: $(IPFILTER_OBJ) build/test/ipfilter_logger.o build/port/wolfssl_io.o build/certs/server_key.o build/certs/ca_cert.o build/certs/server_cert.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) -lwolfssl $(END_GROUP)

build/ipfilter/wolfip.o: src/wolfip.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $< (ipfilter)"
	@$(CC) $(CFLAGS) -DCONFIG_IPFILTER=1 -c $< -o $@

build/test/ipfilter_logger.o: CFLAGS+=-DCONFIG_IPFILTER=1

# ipsec esp
build/esp/wolfip.o: src/wolfip.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $< (esp)"
	@$(CC) $(CFLAGS) $(ESP_CFLAGS) -c $< -o $@

build/test/test_esp.o: src/test/esp/test_esp.c
	@echo "[CC] $@"
	@$(CC) $(CFLAGS) $(ESP_CFLAGS) -c $< -o $@

build/test-esp: $(ESP_OBJ) build/test/test_esp.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(ESP_CFLAGS) $(LDFLAGS) -o $@ $(BEGIN_GROUP) $(^) -lwolfssl $(END_GROUP)

build/test/esp_server.o: src/test/esp/esp_server.c
	@echo "[CC] $@"
	@$(CC) $(CFLAGS) $(ESP_CFLAGS) -c $< -o $@

build/esp-server: $(ESP_OBJ) build/port/posix/bsd_socket.o build/test/esp_server.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(ESP_CFLAGS) $(LDFLAGS) -o $@ $(BEGIN_GROUP) $(^) -lwolfssl $(END_GROUP)

build/test-wolfssl-forwarding: build/test/test_wolfssl_forwarding.o build/test/wolfip_forwarding.o $(WOLFIP_TFTP_OBJ) $(TAP_OBJ) build/port/wolfssl_io.o build/certs/server_key.o build/certs/ca_cert.o build/certs/server_cert.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) -lwolfssl $(END_GROUP)

build/test/test_wolfssl_forwarding.o: CFLAGS+=-DWOLFIP_MAX_INTERFACES=2 -DWOLFIP_ENABLE_FORWARDING=1

build/test/wolfip_forwarding.o: src/wolfip.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $< (forwarding)"
	@$(CC) $(CFLAGS) -DWOLFIP_MAX_INTERFACES=2 -DWOLFIP_ENABLE_FORWARDING=1 -c $< -o $@

build/test/test_ttl_expired.o: CFLAGS+=-DWOLFIP_MAX_INTERFACES=2 -DWOLFIP_ENABLE_FORWARDING=1
build/test-ttl-expired: build/test/test_ttl_expired.o build/test/wolfip_forwarding.o $(WOLFIP_TFTP_OBJ)
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) $(END_GROUP)

build/test-httpd: $(OBJ) build/test/test_httpd.o build/port/wolfssl_io.o build/certs/server_key.o build/certs/server_cert.o build/http/httpd.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(LDFLAGS) -lwolfssl $(END_GROUP)

# Standalone regression test for HTTP request framing (F-5259). It #includes
# httpd.c directly to reach the static parser and stubs the wolfIP/wolfSSL I/O.
build/test-http-smuggle:CFLAGS+=-Wno-cpp -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP -DWOLFIP_ENABLE_HTTP -Isrc/http
build/test-http-smuggle: src/test/test_http_smuggle.c src/http/httpd.c
	@mkdir -p build || true
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ src/test/test_http_smuggle.c $(LDFLAGS) -lwolfssl

# Standalone regression test for the httpd_get_request_arg OOB read (F-5258).
build/test-http-arg-oob:CFLAGS+=-Wno-cpp -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP -DWOLFIP_ENABLE_HTTP -Isrc/http
build/test-http-arg-oob: src/test/test_http_arg_oob.c src/http/httpd.c
	@mkdir -p build || true
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ src/test/test_http_arg_oob.c $(LDFLAGS) -lwolfssl

# Standalone regression test for TLS close_notify on every close path (F-5732).
# It #includes httpd.c directly and stubs the wolfSSL teardown calls to record
# their order, so it does not link the real wolfSSL library.
build/test-http-close-notify:CFLAGS+=-Wno-cpp -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP -DWOLFIP_ENABLE_HTTP -Isrc/http
build/test-http-close-notify: src/test/test_http_close_notify.c src/http/httpd.c
	@mkdir -p build || true
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ src/test/test_http_close_notify.c $(LDFLAGS)

# Standalone regression test for the FreeRTOS BSD close() wrapper when
# CB_EVENT_CLOSED is delivered synchronously during LAST_ACK teardown.
build/test-freertos-close-last-ack: src/test/test_freertos_close_last_ack.c src/port/freeRTOS/bsd_socket.c
	@mkdir -p build || true
	@echo "[LD] $@"
	@$(CC) -Isrc/test/freertos_mocks $(CFLAGS) -o $@ src/test/test_freertos_close_last_ack.c $(LDFLAGS)

build/%.o: src/%.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -c $< -o $@

build/pie/%.o: src/%.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -c $< -o $@

build/certs/%.o: build/certs/%.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -c $< -o $@

build/http/%.o: build/http/%.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -c $< -o $@

build/certs/ca_cert.c:
	@echo "[MKCERTS] `dirname $@`"
	@tools/certs/mkcerts.sh

build/certs/server_key.c:
	@echo "[MKCERTS] `dirname $@`"
	@tools/certs/mkcerts.sh

build/certs/server_cert.c:
	@echo "[MKCERTS] `dirname $@`"
	@tools/certs/mkcerts.sh

build/certs/server_key.o: build/certs/server_key.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -c $< -o $@

UNIT_TEST_SRCS:=src/test/unit/unit.c \
	src/test/unit/unit_shared.c \
	src/test/unit/unit_tests_fifo.c \
	src/test/unit/unit_tests_api.c \
	src/test/unit/unit_tests_dns_dhcp.c \
	src/test/unit/unit_tests_tcp_ack.c \
	src/test/unit/unit_tests_tcp_flow.c \
	src/test/unit/unit_tests_proto.c \
	src/test/unit/unit_tests_multicast.c \
	src/test/unit/unit_tests_tftp.c \
	src/test/unit/unit_tests_branches.c \
	src/test/unit/unit_tests_socket_api_arms.c \
	src/test/unit/unit_tests_tcp_state.c \
	src/test/unit/unit_tests_poll_dispatcher.c \
	src/test/unit/unit_tests_dhcp_edges.c \
	src/test/unit/unit_tests_ip_arp_recv.c \
	src/test/unit/unit_tests_dns_edges.c \
	src/test/unit/unit_tests_misc_edges.c \
	src/test/unit/unit_tests_vlan.c

unit: build/test/unit

build/test/unit: $(UNIT_TEST_SRCS)
	@mkdir -p build/test/
	@echo "[CC] unit.c"
	@$(CC) $(UNIT_CFLAGS) $(CFLAGS) -c src/test/unit/unit.c -o build/test/unit.o
	@echo "[LD] $@"
	@$(CC) build/test/unit.o -o build/test/unit $(UNIT_LDFLAGS) $(LDFLAGS)

unit-multicast: CFLAGS+=-DIP_MULTICAST
unit-multicast: clean-unit unit

unit-vlan: CFLAGS+=-DWOLFIP_VLAN=1 -DWOLFIP_MAX_INTERFACES=6
unit-vlan: clean-unit unit

ESP_UNIT_CHECK_CFLAGS := $(CHECK_PKG_CFLAGS)
ifeq ($(UNAME_S),Darwin)
	ifneq ($(CHECK_PREFIX),)
	ESP_UNIT_CHECK_CFLAGS += -I$(CHECK_PREFIX)/include
endif
endif

unit-esp: build/test/unit-esp

unit-noeth: build/test/unit-noeth.o

build/test/unit-noeth.o: src/test/unit/unit_noeth.c
	@mkdir -p build/test/
	@echo "[CC] unit_noeth.c"
	@$(CC) $(CFLAGS) -c src/test/unit/unit_noeth.c -o build/test/unit-noeth.o

build/test/unit-esp: src/test/unit/unit_esp.c
	@mkdir -p build/test/
	@echo "[CC] unit_esp.c"
	@$(CC) $(CFLAGS) $(ESP_CFLAGS) $(ESP_UNIT_CHECK_CFLAGS) \
		-c src/test/unit/unit_esp.c -o build/test/unit_esp.o
	@echo "[LD] $@"
	@$(CC) build/test/unit_esp.o -o $@ \
		$(UNIT_LDFLAGS) $(LDFLAGS) $(UNIT_LIBS) -lwolfssl

# Unit tests with sanitizers
# Force clean rebuild to ensure sanitizer flags are applied
clean-unit:
	@rm -f build/test/unit build/test/unit.o

clean-unit-esp:
	@rm -f build/test/unit-esp build/test/unit_esp.o

unit-esp-asan: CFLAGS+=-fsanitize=address
unit-esp-asan: LDFLAGS+=-fsanitize=address $(UNIT_LIBS)
unit-esp-asan: clean-unit-esp build/test/unit-esp

unit-esp-ubsan: CFLAGS+=-fsanitize=undefined -fno-sanitize-recover=all
unit-esp-ubsan: LDFLAGS+=-fsanitize=undefined $(UNIT_LIBS)
unit-esp-ubsan: clean-unit-esp build/test/unit-esp

unit-esp-leaksan: CFLAGS+=-fsanitize=leak
unit-esp-leaksan: LDFLAGS+=-fsanitize=leak $(UNIT_LIBS)
unit-esp-leaksan: clean-unit-esp build/test/unit-esp

unit-asan: CFLAGS+=-fsanitize=address
unit-asan: LDFLAGS+=-fsanitize=address $(UNIT_LIBS)
unit-asan: clean-unit build/test/unit

unit-ubsan: CFLAGS+=-fsanitize=undefined -fno-sanitize-recover=all
unit-ubsan: LDFLAGS+=-fsanitize=undefined $(UNIT_LIBS)
unit-ubsan: clean-unit build/test/unit

unit-leaksan: CFLAGS+=-fsanitize=leak
unit-leaksan: LDFLAGS+=-fsanitize=leak $(UNIT_LIBS)
unit-leaksan: clean-unit build/test/unit

COV_DIR:=build/coverage
COV_UNIT:=$(COV_DIR)/unit
COV_UNIT_O:=$(COV_DIR)/unit.o
COV_MCAST_UNIT:=$(COV_DIR)/unit-multicast
COV_MCAST_UNIT_O:=$(COV_DIR)/unit-multicast.o
COV_VLAN_UNIT:=$(COV_DIR)/unit-vlan
COV_VLAN_UNIT_O:=$(COV_DIR)/unit-vlan.o

$(COV_UNIT_O): $(UNIT_TEST_SRCS)
	@mkdir -p $(COV_DIR)
	@echo "[CC] unit.c (coverage)"
	@$(CC) $(UNIT_CFLAGS) $(CFLAGS) --coverage -c src/test/unit/unit.c -o $(COV_UNIT_O)

$(COV_UNIT): LDFLAGS+=--coverage $(UNIT_LIBS)
$(COV_UNIT): $(COV_UNIT_O)
	@echo "[LD] $@"
	@$(CC) $(COV_UNIT_O) -o $(COV_UNIT) $(UNIT_LDFLAGS) $(LDFLAGS)

$(COV_MCAST_UNIT_O): $(UNIT_TEST_SRCS)
	@mkdir -p $(COV_DIR)
	@echo "[CC] unit.c (multicast coverage)"
	@$(CC) $(UNIT_CFLAGS) $(CFLAGS) -DIP_MULTICAST --coverage -c src/test/unit/unit.c -o $(COV_MCAST_UNIT_O)

$(COV_MCAST_UNIT): LDFLAGS+=--coverage $(UNIT_LIBS)
$(COV_MCAST_UNIT): $(COV_MCAST_UNIT_O)
	@echo "[LD] $@"
	@$(CC) $(COV_MCAST_UNIT_O) -o $(COV_MCAST_UNIT) $(UNIT_LDFLAGS) $(LDFLAGS)

cov: unit $(COV_UNIT)
	@echo "[RUN] unit (coverage)"
	@rm -f $(COV_DIR)/*.gcda
	@rm -f $(COV_DIR)/unit-multicast $(COV_DIR)/unit-multicast.o \
		$(COV_DIR)/unit-multicast.gcno $(COV_DIR)/unit-multicast.gcda
	@$(COV_UNIT)
	@echo "[COV] gcovr html"
	@mkdir -p build/coverage
	@gcovr -r . --exclude "src/test/unit/.*" \
		--gcov-ignore-errors=no_working_dir_found \
		--gcov-ignore-parse-errors=all \
		--merge-mode-functions=merge-use-line-min \
		--html-details -o build/coverage/index.html
	@$(OPEN_CMD) build/coverage/index.html

autocov: unit $(COV_UNIT)
	@echo "[RUN] unit (coverage)"
	@rm -f $(COV_DIR)/*.gcda
	@rm -f $(COV_DIR)/unit-multicast $(COV_DIR)/unit-multicast.o \
		$(COV_DIR)/unit-multicast.gcno $(COV_DIR)/unit-multicast.gcda
	@$(COV_UNIT)
	@echo "[COV] gcovr html"
	@mkdir -p build/coverage
	@gcovr -r . --exclude "src/test/unit/.*" \
		--gcov-ignore-errors=no_working_dir_found \
		--gcov-ignore-parse-errors=all \
		--merge-mode-functions=merge-use-line-min \
		--html-details -o build/coverage/index.html

autocov-multicast: unit-multicast $(COV_MCAST_UNIT)
	@echo "[RUN] unit multicast (coverage)"
	@rm -f $(COV_DIR)/*.gcda
	@$(COV_MCAST_UNIT)
	@echo "[COV] gcovr multicast html"
	@mkdir -p build/coverage
	@gcovr -r . --exclude "src/test/unit/.*" \
		--gcov-ignore-errors=no_working_dir_found \
		--gcov-ignore-parse-errors=all \
		--merge-mode-functions=merge-use-line-min \
		--html-details -o build/coverage/multicast.html

cov-multicast: unit-multicast $(COV_MCAST_UNIT)
	@echo "[RUN] unit multicast (coverage)"
	@rm -f $(COV_DIR)/*.gcda
	@$(COV_MCAST_UNIT)
	@echo "[COV] gcovr multicast html"
	@mkdir -p build/coverage
	@gcovr -r . --exclude "src/test/unit/.*" \
		--gcov-ignore-errors=no_working_dir_found \
		--gcov-ignore-parse-errors=all \
		--merge-mode-functions=merge-use-line-min \
		--html-details -o build/coverage/multicast.html
	@$(OPEN_CMD) build/coverage/multicast.html

$(COV_VLAN_UNIT_O): $(UNIT_TEST_SRCS)
	@mkdir -p $(COV_DIR)
	@echo "[CC] unit.c (vlan coverage)"
	@$(CC) $(UNIT_CFLAGS) $(CFLAGS) -DWOLFIP_VLAN=1 -DWOLFIP_MAX_INTERFACES=6 --coverage -c src/test/unit/unit.c -o $(COV_VLAN_UNIT_O)

$(COV_VLAN_UNIT): LDFLAGS+=--coverage $(UNIT_LIBS)
$(COV_VLAN_UNIT): $(COV_VLAN_UNIT_O)
	@echo "[LD] $@"
	@$(CC) $(COV_VLAN_UNIT_O) -o $(COV_VLAN_UNIT) $(UNIT_LDFLAGS) $(LDFLAGS)

cov-vlan: unit-vlan $(COV_VLAN_UNIT)
	@echo "[RUN] unit vlan (coverage)"
	@rm -f $(COV_DIR)/*.gcda
	@$(COV_VLAN_UNIT)
	@echo "[COV] gcovr vlan html"
	@mkdir -p build/coverage
	@gcovr -r . --exclude "src/test/unit/.*" \
		--gcov-ignore-errors=no_working_dir_found \
		--gcov-ignore-parse-errors=all \
		--merge-mode-functions=merge-use-line-min \
		--html-details -o build/coverage/vlan.html
	@$(OPEN_CMD) build/coverage/vlan.html

autocov-vlan: unit-vlan $(COV_VLAN_UNIT)
	@echo "[RUN] unit vlan (coverage)"
	@rm -f $(COV_DIR)/*.gcda
	@$(COV_VLAN_UNIT)
	@echo "[COV] gcovr vlan html"
	@mkdir -p build/coverage
	@gcovr -r . --exclude "src/test/unit/.*" \
		--gcov-ignore-errors=no_working_dir_found \
		--gcov-ignore-parse-errors=all \
		--merge-mode-functions=merge-use-line-min \
		--html-details -o build/coverage/vlan.html

# Install dynamic library to re-link linux applications
#
install:
	install libwolfip.so $(PREFIX)/lib
	ldconfig

# wolfGuard object files
build/wolfguard/%.o: src/%.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $< (wolfguard)"
	@$(CC) $(CFLAGS) $(WOLFGUARD_CFLAGS) -c $< -o $@

# wolfGuard unit tests
WG_UNIT_CHECK_CFLAGS := $(CHECK_PKG_CFLAGS)
ifeq ($(UNAME_S),Darwin)
	ifneq ($(CHECK_PREFIX),)
	WG_UNIT_CHECK_CFLAGS += -I$(CHECK_PREFIX)/include
endif
endif

unit-wolfguard: build/test/unit-wolfguard

build/test/unit-wolfguard: src/test/unit/unit_wolfguard.c
	@mkdir -p build/test/
	@echo "[CC] unit_wolfguard.c"
	@$(CC) $(CFLAGS) $(WOLFGUARD_CFLAGS) $(WG_UNIT_CHECK_CFLAGS) \
		-c src/test/unit/unit_wolfguard.c -o build/test/unit_wolfguard.o
	@echo "[LD] $@"
	@$(CC) build/test/unit_wolfguard.o -o $@ \
		$(UNIT_LDFLAGS) $(LDFLAGS) $(UNIT_LIBS) -lwolfssl

clean-unit-wolfguard:
	@rm -f build/test/unit-wolfguard build/test/unit_wolfguard.o

unit-wolfguard-asan: CFLAGS+=-fsanitize=address
unit-wolfguard-asan: LDFLAGS+=-fsanitize=address $(UNIT_LIBS)
unit-wolfguard-asan: clean-unit-wolfguard build/test/unit-wolfguard

unit-wolfguard-ubsan: CFLAGS+=-fsanitize=undefined -fno-sanitize-recover=all
unit-wolfguard-ubsan: LDFLAGS+=-fsanitize=undefined $(UNIT_LIBS)
unit-wolfguard-ubsan: clean-unit-wolfguard build/test/unit-wolfguard

# wolfGuard integration tests (loopback)
test-wolfguard-loopback: build/test/test-wolfguard-loopback

build/test/test-wolfguard-loopback: src/test/test_wolfguard_loopback.c
	@mkdir -p build/test/
	@echo "[CC] test_wolfguard_loopback.c"
	@$(CC) $(CFLAGS) $(WOLFGUARD_CFLAGS) $(WG_UNIT_CHECK_CFLAGS) \
		-c src/test/test_wolfguard_loopback.c -o build/test/test_wolfguard_loopback.o
	@echo "[LD] $@"
	@$(CC) build/test/test_wolfguard_loopback.o -o $@ \
		$(UNIT_LDFLAGS) $(LDFLAGS) $(UNIT_LIBS) -lwolfssl

clean-test-wolfguard-loopback:
	@rm -f build/test/test-wolfguard-loopback build/test/test_wolfguard_loopback.o

test-wolfguard-loopback-asan: CFLAGS+=-fsanitize=address
test-wolfguard-loopback-asan: LDFLAGS+=-fsanitize=address $(UNIT_LIBS)
test-wolfguard-loopback-asan: clean-test-wolfguard-loopback build/test/test-wolfguard-loopback

test-wolfguard-loopback-ubsan: CFLAGS+=-fsanitize=undefined -fno-sanitize-recover=all
test-wolfguard-loopback-ubsan: LDFLAGS+=-fsanitize=undefined $(UNIT_LIBS)
test-wolfguard-loopback-ubsan: clean-test-wolfguard-loopback build/test/test-wolfguard-loopback

# wolfGuard benchmark
bench-wolfguard: build/test/bench-wolfguard

build/test/bench-wolfguard: src/test/bench_wolfguard.c
	@mkdir -p build/test/
	@echo "[CC] bench_wolfguard.c"
	@$(CC) $(CFLAGS) -O2 $(WOLFGUARD_CFLAGS) \
		-c src/test/bench_wolfguard.c -o build/test/bench_wolfguard.o
	@echo "[LD] $@"
	@$(CC) build/test/bench_wolfguard.o -o $@ \
		$(LDFLAGS) -lwolfssl

clean-bench-wolfguard:
	@rm -f build/test/bench-wolfguard build/test/bench_wolfguard.o

# wolfGuard interop test (wolfIP <-> kernel wolfGuard via TUN)
test-wolfguard-interop: build/test/test-wolfguard-interop

build/test/test-wolfguard-interop: src/test/test_wolfguard_interop.c src/port/posix/linux_tun.c
	@mkdir -p build/test/
	@echo "[CC] test_wolfguard_interop.c"
	@$(CC) $(CFLAGS) $(WOLFGUARD_CFLAGS) \
		-c src/test/test_wolfguard_interop.c -o build/test/test_wolfguard_interop.o
	@echo "[CC] linux_tun.c"
	@$(CC) $(CFLAGS) $(WOLFGUARD_CFLAGS) \
		-c src/port/posix/linux_tun.c -o build/test/linux_tun.o
	@echo "[LD] $@"
	@$(CC) build/test/test_wolfguard_interop.o build/test/linux_tun.o -o $@ \
		$(LDFLAGS) -lwolfssl

clean-test-wolfguard-interop:
	@rm -f build/test/test-wolfguard-interop build/test/test_wolfguard_interop.o build/test/linux_tun.o

.PHONY: clean all static cppcheck cov autocov autocov-multicast cov-multicast unit-multicast unit-vlan cov-vlan autocov-vlan unit-asan unit-ubsan unit-leaksan clean-unit \
        unit-esp-asan unit-esp-ubsan unit-esp-leaksan clean-unit-esp \
        unit-wolfguard unit-wolfguard-asan unit-wolfguard-ubsan clean-unit-wolfguard \
        test-wolfguard-loopback test-wolfguard-loopback-asan test-wolfguard-loopback-ubsan \
        clean-test-wolfguard-loopback \
        bench-wolfguard clean-bench-wolfguard \
        test-wolfguard-interop clean-test-wolfguard-interop

cppcheck:
	$(CPPCHECK) $(CPPCHECK_FLAGS) src/ 2>cppcheck_results.xml

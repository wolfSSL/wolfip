CC?=gcc
CFLAGS:=-Wall -Werror -Wextra -I. -D_GNU_SOURCE
CFLAGS+=-g -ggdb -Wdeclaration-after-statement
LDFLAGS+=-pthread

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


TAP_SRC:=src/port/posix/tap_$(UNAME_LC).c
ifeq ($(wildcard $(TAP_SRC)),)
  TAP_SRC:=src/port/posix/tap_linux.c
endif
TAP_OBJ:=$(patsubst src/%.c,build/%.o,$(TAP_SRC))
TAP_PIE_OBJ:=$(patsubst src/%.c,build/pie/%.o,$(TAP_SRC))

ifeq ($(UNAME_S),Darwin)
  BEGIN_GROUP:=
  END_GROUP:=
else
  BEGIN_GROUP:=-Wl,--start-group
  END_GROUP:=-Wl,--end-group
endif

CHECK_PKG_CFLAGS:=$(shell pkg-config --cflags check 2>/dev/null)
CHECK_PKG_LIBS:=$(shell pkg-config --libs check 2>/dev/null)

ifneq ($(CHECK_PKG_CFLAGS),)
  UNIT_CFLAGS+=$(CHECK_PKG_CFLAGS)
endif

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
			   --disable=style \
			   --std=c99 --language=c \
			   --platform=unix64 \
			   --check-level=exhaustive \
			   --error-exitcode=1 --xml --xml-version=2

OBJ=build/wolfip.o \
	$(TAP_OBJ)

IPFILTER_OBJ=build/ipfilter/wolfip.o \
	$(TAP_OBJ)

HAVE_WOLFSSL:=$(shell printf "#include <wolfssl/options.h>\nint main(void){return 0;}\n" | $(CC) $(CFLAGS) -x c - -c -o /dev/null 2>/dev/null && echo 1)

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
	build/ipfilter-logger
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
	$(TAP_PIE_OBJ)
	@mkdir -p `dirname $@` || true
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $(BEGIN_GROUP) $(^) $(END_GROUP)


clean:
	@rm -rf build
	@rm -f *.so

asan: $(EXE) $(LIB)
asan:CFLAGS+=-fsanitize=address
asan:LDFLAGS+=-static-libasan


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
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(END_GROUP)

build/test-dns: $(OBJ) build/test/test_dhcp_dns.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(END_GROUP)

build/tcpecho: $(OBJ) build/port/posix/bsd_socket.o build/test/tcp_echo.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(END_GROUP)

build/tcp_netcat_poll: $(OBJ) build/port/posix/bsd_socket.o build/test/tcp_netcat_poll.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(END_GROUP)

build/tcp_netcat_select: $(OBJ) build/port/posix/bsd_socket.o build/test/tcp_netcat_select.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(END_GROUP)


build/test-wolfssl:CFLAGS+=-Wno-cpp -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP
build/test-httpd:CFLAGS+=-Wno-cpp -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP -Isrc/http
build/test-wolfssl-forwarding:CFLAGS+=-Wno-cpp -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP -DWOLFIP_MAX_INTERFACES=2 -DWOLFIP_ENABLE_FORWARDING=1

build/test-wolfssl: $(OBJ) build/test/test_native_wolfssl.o build/port/wolfssl_io.o build/certs/server_key.o build/certs/ca_cert.o build/certs/server_cert.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BEGIN_GROUP) $(^) -lwolfssl $(END_GROUP)

build/ipfilter-logger: $(IPFILTER_OBJ) build/test/ipfilter_logger.o build/port/wolfssl_io.o build/certs/server_key.o build/certs/ca_cert.o build/certs/server_cert.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BEGIN_GROUP) $(^) -lwolfssl $(END_GROUP)

build/ipfilter/wolfip.o: src/wolfip.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $< (ipfilter)"
	@$(CC) $(CFLAGS) -DCONFIG_IPFILTER=1 -c $< -o $@

build/test/ipfilter_logger.o: CFLAGS+=-DCONFIG_IPFILTER=1

build/test-wolfssl-forwarding: build/test/test_wolfssl_forwarding.o build/test/wolfip_forwarding.o $(TAP_OBJ) build/port/wolfssl_io.o build/certs/server_key.o build/certs/ca_cert.o build/certs/server_cert.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BEGIN_GROUP) $(^) -lwolfssl $(END_GROUP)

build/test/test_wolfssl_forwarding.o: CFLAGS+=-DWOLFIP_MAX_INTERFACES=2 -DWOLFIP_ENABLE_FORWARDING=1

build/test/wolfip_forwarding.o: src/wolfip.c
	@mkdir -p `dirname $@` || true
	@echo "[CC] $< (forwarding)"
	@$(CC) $(CFLAGS) -DWOLFIP_MAX_INTERFACES=2 -DWOLFIP_ENABLE_FORWARDING=1 -c $< -o $@

build/test/test_ttl_expired.o: CFLAGS+=-DWOLFIP_MAX_INTERFACES=2 -DWOLFIP_ENABLE_FORWARDING=1
build/test-ttl-expired: build/test/test_ttl_expired.o build/test/wolfip_forwarding.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BEGIN_GROUP) $(^) $(END_GROUP)

build/test-httpd: $(OBJ) build/test/test_httpd.o build/port/wolfssl_io.o build/certs/server_key.o build/certs/server_cert.o build/http/httpd.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BEGIN_GROUP) $(^) -lwolfssl $(END_GROUP)

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

unit: build/test/unit

build/test/unit:
	@mkdir -p build/test/
	@echo "[CC] unit.c"
	@$(CC) $(CFLAGS) $(UNIT_CFLAGS) -c src/test/unit/unit.c -o build/test/unit.o
	@echo "[LD] $@"
	@$(CC) build/test/unit.o -o build/test/unit $(UNIT_LDFLAGS) $(LDFLAGS)

# Install dynamic library to re-link linux applications
#
install:
	install libwolfip.so $(PREFIX)/lib
	ldconfig

.PHONY: clean all static cppcheck

cppcheck:
	$(CPPCHECK) $(CPPCHECK_FLAGS) src/ 2>cppcheck_results.xml

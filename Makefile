CC?=gcc
CFLAGS:=-Wall -Werror -Wextra -I. -D_GNU_SOURCE
CFLAGS+=-g -ggdb
LDFLAGS+=-pthread

# Debug flags:
# CFLAGS+=-DDEBUG_TAP
# print ethernet headers
# CFLAGS+=-DDEBUG_ETH
# print ip headers
 CFLAGS+=-DDEBUG_IP
# print tcp headers
# CFLAGS+=-DDEBUG_TCP
# print esp header data
CFLAGS+=-DWOLFIP_DEBUG_ESP
#CFLAGS+=-DWOLFIP_DEBUG_ESP_VERBOSE

# ESP support
 CFLAGS+=-DWOLFIP_ESP
 CFLAGS+=-DWOLFSSL_WOLFIP
 LDFLAGS+=-lwolfssl

CPPCHECK=cppcheck
CPPCHECK_FLAGS=--enable=all --suppress=missingIncludeSystem \
			   --suppress=unusedFunction --suppress=unusedVariable \
			   --suppress=missingInclude --suppress=variableScope \
			   --suppress=constVariable --suppress=constVariablePointer \
			   --suppress=constParameterPointer \
			   --suppress=constParameterCallback \
			   --suppress=toomanyconfigs \
			   --suppress=unmatchedSuppression --inconclusive \
			   --std=c99 --language=c \
			   --platform=unix64 \
			   --error-exitcode=1 --xml --xml-version=2

OBJ=build/wolfip.o \
	build/port/posix/linux_tap.o

EXE=build/tcpecho build/tcp_netcat_poll build/tcp_netcat_select \
	build/test-evloop build/test-dns
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
	build/pie/port/posix/linux_tap.o
	@mkdir -p `dirname $@` || true
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--start-group $(^) -Wl,--end-group


clean:
	@rm -rf build
	@rm -f *.so

asan: $(EXE) $(LIB)
asan:CFLAGS+=-fsanitize=address
asan:LDFLAGS+=-static-libasan


# Test

unit:LDFLAGS+=-lcheck -lm -lpthread -lrt -ldl -lsubunit
build/test-evloop: $(OBJ) build/test/test_linux_eventloop.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -Wl,--start-group $(^) -Wl,--end-group

build/test-dns: $(OBJ) build/test/test_linux_dhcp_dns.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -Wl,--start-group $(^) -Wl,--end-group

build/tcpecho: $(OBJ) build/port/posix/bsd_socket.o build/test/tcp_echo.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -Wl,--start-group $(^) -Wl,--end-group

build/tcp_netcat_poll: $(OBJ) build/port/posix/bsd_socket.o build/test/tcp_netcat_poll.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -Wl,--start-group $(^) -Wl,--end-group

build/tcp_netcat_select: $(OBJ) build/port/posix/bsd_socket.o build/test/tcp_netcat_select.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -Wl,--start-group $(^) -Wl,--end-group


build/test-wolfssl:CFLAGS+=-Wno-cpp -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP
build/test-httpd:CFLAGS+=-Wno-cpp -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP -Isrc/http


build/test-wolfssl: $(OBJ) build/test/test_native_wolfssl.o build/port/wolfssl_io.o build/certs/server_key.o build/certs/ca_cert.o build/certs/server_cert.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -Wl,--start-group $(^) -lwolfssl -Wl,--end-group

build/test-httpd: $(OBJ) build/test/test_httpd.o build/port/wolfssl_io.o build/certs/server_key.o build/certs/server_cert.o build/http/httpd.o
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -Wl,--start-group $(^) -lwolfssl -Wl,--end-group

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
	@$(CC) $(CFLAGS) -c src/test/unit/unit.c -o build/test/unit.o
	@echo "[LD] $@"
	@$(CC) -o build/test/unit build/test/unit.o $(LDFLAGS)

# Install dynamic library to re-link linux applications
#
install:
	install libwolfip.so $(PREFIX)/lib
	ldconfig

.PHONY: clean all static cppcheck

cppcheck:
	$(CPPCHECK) $(CPPCHECK_FLAGS) src/ 2>cppcheck_results.xml

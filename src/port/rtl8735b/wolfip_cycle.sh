#!/usr/bin/env bash
# Build -> flash -> read the wolfIP RTL8735B (AmebaPro2) demo, hands-free.
#
# Syncs this port's sources into the RealTek FreeRTOS SDK, does a CLEAN cmake
# reconfigure (incremental rebuilds intermittently drop project/src/main.c's
# include path), `make flash`, flashes via amebapro2_flash.sh, then tails the
# console for a window (the demo runs a server forever; there is no done marker).
#
# Usage:
#   wolfip_cycle.sh            # milestone 1: DHCP + echo
#   wolfip_cycle.sh --tls      # milestone 2: also build the TLS client
#
# Env overrides (defaults shown):
#   WOLFIP_ROOT=~/GitHub/wolfip   WOLFSSL_ROOT=~/GitHub/wolfssl
#   SDK=~/GitHub/ameba-rtos-pro2
#   ASDK_BIN=~/ameba-pro2-workspace/asdk/asdk-10.3.0/linux/newlib/bin
#   LABEL=GENERIC_UART_ttyUSB5   WATCH_SECS=40
#   UART_LOG=/tmp/uart-monitor/latest/$LABEL.log
#   FLASH=~/.claude/skills/amebapro2-flash/amebapro2_flash.sh
set -uo pipefail
TLS=OFF
[ "${1:-}" = "--tls" ] && TLS=ON

: "${WOLFIP_ROOT:=$HOME/GitHub/wolfip}"
: "${WOLFSSL_ROOT:=$HOME/GitHub/wolfssl}"
: "${SDK:=$HOME/GitHub/ameba-rtos-pro2}"
: "${ASDK_BIN:=$HOME/ameba-pro2-workspace/asdk/asdk-10.3.0/linux/newlib/bin}"
: "${LABEL:=GENERIC_UART_ttyUSB5}"
: "${WATCH_SECS:=40}"
: "${UART_LOG:=/tmp/uart-monitor/latest/$LABEL.log}"
: "${FLASH:=$HOME/.claude/skills/amebapro2-flash/amebapro2_flash.sh}"
export PATH="$ASDK_BIN:$PATH"   # ASDK 10.3.0; system arm-none-eabi-gcc FAILS

EXAMPLE=wolfip_eth
SRC="$WOLFIP_ROOT/src/port/rtl8735b"
PROJ="$SDK/project/realtek_amebapro2_v0_example"
COMP="$SDK/component/example/$EXAMPLE"
BDIR="$PROJ/GCC-RELEASE/build_$EXAMPLE"
BIN="$BDIR/flash_ntz.bin"
L="$UART_LOG"

# Sync sources into the SDK example dir + the project main.c.
mkdir -p "$COMP"
cp "$SRC/main.c" "$PROJ/src/main.c"
cp "$SRC/main.c" "$SRC/user_settings.h" "$SRC/wolfip_eth.cmake" "$COMP/"

# Clean reconfigure every cycle (reliable; incremental drops the include path).
cd "$PROJ/GCC-RELEASE"
rm -rf "build_$EXAMPLE" && mkdir "build_$EXAMPLE" && cd "build_$EXAMPLE"
CMAKE_ARGS=(.. -G"Unix Makefiles" -DCMAKE_TOOLCHAIN_FILE=../toolchain.cmake
    -DBUILD_FPGA=OFF -DBUILD_PXP=OFF -DEXAMPLE="$EXAMPLE"
    -DWOLFIP_ROOT="$WOLFIP_ROOT" -DWOLFIP_ENABLE_TLS="$TLS")
[ "$TLS" = "ON" ] && CMAKE_ARGS+=(-DWOLFSSL_ROOT="$WOLFSSL_ROOT")
cmake "${CMAKE_ARGS[@]}" > /tmp/wolfip_cycle_cfg.log 2>&1

if ! make flash -j8 > /tmp/wolfip_cycle_build.log 2>&1; then
    echo "=== BUILD FAIL (TLS=$TLS) ==="
    grep -nE ": error:|undefined reference|fatal error" /tmp/wolfip_cycle_build.log \
      | grep -viE "video_dprintf|CHK_MSG|\"error|error: only|error:invalid|error:model|error: model" \
      | head -30
    exit 1
fi
echo "=== build ok (TLS=$TLS); flashing ==="

"$FLASH" "$BIN" > /tmp/wolfip_cycle_flash.log 2>&1
grep -E "download mode|uartfwburn" /tmp/wolfip_cycle_flash.log | sed 's/\x1b\[[0-9;]*m//g'

# Tail the console for a window; anchor on the last LOG CLEARED (boot POR).
CLEAR_MARK="--- LOG CLEARED"
run_slice() {
    awk -v c="$CLEAR_MARK" '
        index($0,c){buf=""}
        {buf = buf $0 ORS}
        END{printf "%s", buf}' "$L" 2>/dev/null
}
for _ in $(seq 1 $((WATCH_SECS / 2))); do
    run_slice | grep -qiE "DHCP bound|Link up|echo server listening" && break
    sleep 2
done
echo "=== UART (this run) ==="
run_slice | sed 's/\x1b\[[0-9;]*m//g'

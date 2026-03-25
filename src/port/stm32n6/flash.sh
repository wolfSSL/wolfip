#!/bin/bash
# Flash wolfIP to STM32N6 AXISRAM via OpenOCD
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="${SCRIPT_DIR}/app.bin"
CFG="${SCRIPT_DIR}/openocd.cfg"

[ -f "$BIN" ] || { echo "app.bin not found. Run 'make' first."; exit 1; }

# Extract initial SP (word 0) and entry point (word 1) from vector table
INIT_SP=$(od -A n -t x4 -N 4 "$BIN" | awk '{print "0x"$1}')
ENTRY=$(od -A n -j 4 -t x4 -N 4 "$BIN" | awk '{print "0x"$1}')
ENTRY_THUMB=$(printf "0x%08x" $(( ENTRY | 1 )))

echo "Loading app.bin to AXISRAM1 (0x34000000)"
echo "  SP: ${INIT_SP}, Entry: ${ENTRY_THUMB}"

# Try normal reset init first. If it fails (CPU in LOCKUP), try recovery
# via AP0 AIRCR write, then retry.
openocd -f "$CFG" -c "
    reset init;
    load_image ${BIN} 0x34000000 bin;
    reg msplim_s 0x00000000;
    reg psplim_s 0x00000000;
    reg msp ${INIT_SP};
    mww 0xE000ED08 0x34000000;
    mww 0xE000ED28 0xFFFFFFFF;
    resume ${ENTRY_THUMB};
    shutdown
" 2>&1
STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo ""
    echo "*** Normal flash failed (CPU may be in LOCKUP state) ***"
    echo "Please press the RESET button on the NUCLEO board, then re-run this script."
    echo ""
    echo "If the board is unrecoverable, unplug and replug the USB cable."
    exit 1
fi

echo "Done. Monitor UART: picocom -b 115200 /dev/ttyACM0"

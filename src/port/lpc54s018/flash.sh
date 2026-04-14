#!/bin/bash
# Flash wolfIP to LPC54S018M-EVK SPIFI flash via pyocd (on-board Link2 CMSIS-DAP)
#
# This is the recommended flash mode. The boot ROM completes its full
# initialization before jumping to user code, leaving the chip in a state
# where Flexcomm0 (UART) responds correctly.
#
# For the SRAM-loaded development build (faster iteration but no UART), see
# flash_ram.sh.
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="${SCRIPT_DIR}/app.bin"

[ -f "$BIN" ] || { echo "app.bin not found. Run 'make' first."; exit 1; }

PYOCD_TARGET="lpc54s018j4met180"
PYOCD_UID="${PYOCD_UID:-EQAQBQLQ}"

echo "Programming SPIFI flash via pyocd ($PYOCD_TARGET)..."
pyocd flash -t "$PYOCD_TARGET" -u "$PYOCD_UID" \
    --base-address 0x10000000 "$BIN"

echo "Done. Monitor UART log: tail -f /tmp/uart-monitor/latest/LPC54S018M-EVK_UART.log"

#!/usr/bin/env bash
#
# JTAG iteration helper: power-cycles the ZCU102, restarts hw_server,
# clears the UART log, JTAG-loads the app, and dumps the resulting
# UART output. Useful for headless iteration without physical access
# to the board.
#
# Everything that touches your specific bench is parameterised through
# env vars. Defaults are no-ops so you must set them per developer.
#
# Required env (in addition to whatever boot.sh requires):
#   POWER_OFF_CMD  - shell command to power the board OFF (e.g.
#                    "ssh pi@Pi4 'raspi-gpio set 20 op dl'")
#   POWER_ON_CMD   - shell command to power the board ON (e.g.
#                    "ssh pi@Pi4 'raspi-gpio set 20 op dh'")
#   HW_SERVER      - path to the Vitis hw_server binary
#                    (e.g. /opt/Xilinx/2025.2/Vitis/bin/hw_server)
#   UART_LABEL     - uart-monitor board label for the ZCU102 USB-UART
#                    (e.g. ZYNQMP_ZCU102_UART0)
#
# Optional env:
#   OFF_DELAY      - seconds to hold OFF before ON (default 4)
#   BOOT_DELAY     - seconds to wait after ON before JTAG (default 10)
#   POST_DELAY     - seconds to wait after boot.sh before dumping
#                    UART (default 5)
#   UART_LOG       - path to the live log file
#                    (default /tmp/uart-monitor/latest/$UART_LABEL.log)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT_DIR="$(dirname "${SCRIPT_DIR}")"

: "${POWER_OFF_CMD:?POWER_OFF_CMD is required (shell cmd that powers the board off)}"
: "${POWER_ON_CMD:?POWER_ON_CMD is required (shell cmd that powers the board on)}"
: "${HW_SERVER:?HW_SERVER is required (path to Vitis hw_server)}"
: "${UART_LABEL:?UART_LABEL is required (uart-monitor board label)}"
OFF_DELAY="${OFF_DELAY:-4}"
BOOT_DELAY="${BOOT_DELAY:-10}"
POST_DELAY="${POST_DELAY:-5}"
UART_LOG="${UART_LOG:-/tmp/uart-monitor/latest/${UART_LABEL}.log}"

echo "=== Power cycle (POWER_OFF_CMD / POWER_ON_CMD) ==="
eval "${POWER_OFF_CMD}"
sleep "${OFF_DELAY}"
eval "${POWER_ON_CMD}"
echo "Powered on, waiting ${BOOT_DELAY}s for CSU bootROM..."
sleep "${BOOT_DELAY}"

echo
echo "=== Restart hw_server (clears stale JTAG state) ==="
pkill -f hw_server || true
sleep 1
"${HW_SERVER}" -d >/dev/null 2>&1 &
sleep 3

echo
echo "=== Clear UART log (${UART_LABEL}) ==="
uart-monitor clear "${UART_LABEL}"

echo
echo "=== JTAG boot FSBL + app ==="
"${SCRIPT_DIR}/boot.sh"

echo
echo "=== Waiting ${POST_DELAY}s for app to produce output ==="
sleep "${POST_DELAY}"

echo
echo "=== UART output (${UART_LOG}) ==="
cat "${UART_LOG}"

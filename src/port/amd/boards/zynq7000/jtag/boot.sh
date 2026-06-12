#!/usr/bin/env bash
#
# Boot the wolfIP Zynq-7000 (ZC702) app via JTAG. Assumes a hw_server
# reachable on localhost (the default when Vitis is local).
#
# The prebuilt FSBL brings the PS up (ps7_init: DDR/MIO/clocks/UART) and
# parks; jtag/boot.tcl then loads the app ELF over the top and starts it
# in SVC mode. No psu_init.tcl and no PDI -- Zynq-7000 has neither.
#
# Set the ZC702 boot-mode straps to JTAG (SW16 = all OFF) and power-cycle
# before use.
#
# Required env (no built-in defaults; set per-developer):
#   XSDB       - path to Vitis xsdb binary
#                (e.g. /opt/Xilinx/2025.2/Vitis/bin/xsdb)
#   FSBL_ELF   - path to a prebuilt Zynq-7000 FSBL ELF (e.g. from
#                wolfSSL/soc-prebuilt-firmware zc702-zynq/zynq_fsbl.elf,
#                or a Vitis/PetaLinux build)
#
# Optional env (sensible defaults):
#   APP_ELF    - default: ${PORT_DIR}/app.elf
#   READELF    - default: arm-none-eabi-readelf (reads the app entry)
#
# Usage (from the port directory):
#   XSDB=/opt/Xilinx/2025.2/Vitis/bin/xsdb \
#   FSBL_ELF=/path/to/zynq_fsbl.elf \
#   ./jtag/boot.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT_DIR="$(dirname "${SCRIPT_DIR}")"

: "${XSDB:?XSDB is required (path to Vitis xsdb binary)}"
: "${FSBL_ELF:?FSBL_ELF is required (path to a prebuilt Zynq-7000 FSBL ELF)}"
APP_ELF="${APP_ELF:-${PORT_DIR}/app.elf}"
export READELF="${READELF:-arm-none-eabi-readelf}"

if ! command -v "${XSDB}" >/dev/null 2>&1 && [[ ! -x "${XSDB}" ]]; then
    echo "ERROR: xsdb not found / not executable: ${XSDB}" >&2
    exit 1
fi
if [[ ! -f "${FSBL_ELF}" ]]; then
    echo "ERROR: FSBL_ELF not found at ${FSBL_ELF}" >&2
    exit 1
fi
if [[ ! -f "${APP_ELF}" ]]; then
    echo "ERROR: app.elf not found at ${APP_ELF}. Run 'make' first." >&2
    exit 1
fi

echo "JTAG boot Zynq-7000 (ZC702) wolfIP app"
echo "  xsdb     : ${XSDB}"
echo "  fsbl     : ${FSBL_ELF}"
echo "  app.elf  : ${APP_ELF}"
echo

export APP_ELF FSBL_ELF

"${XSDB}" "${SCRIPT_DIR}/boot.tcl"

echo
echo "App is running. Watch UART:"
echo "  uart-monitor tail <ZC702 UART label>"

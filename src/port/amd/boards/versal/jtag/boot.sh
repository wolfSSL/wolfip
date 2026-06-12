#!/usr/bin/env bash
#
# Boot the wolfIP Versal (VMK180) app via JTAG. Assumes a hw_server
# reachable on localhost (the default when Vitis is local).
#
# Unlike the ZynqMP flow there is no psu_init.tcl and no objcopy step:
# the Versal PLM brings the platform up from a boot PDI (programmed over
# JTAG), and we load the app ELF directly with xsdb `dow`.
#
# IMPORTANT: set the VMK180 boot-mode switch SW1 to JTAG (mode pins
# 0000, all OFF) and power-cycle first. In a flash/SD boot mode the board
# boots Linux, whose macb driver owns GEM0 and runtime-suspends its
# clock -- our bare-metal driver then stalls on the GEM registers.
#
# Required env (no built-in defaults; set per-developer):
#   XSDB       - path to Vitis xsdb binary
#                (e.g. /opt/Xilinx/2025.2/Vitis/bin/xsdb)
#   BOOT_PDI   - path to a VMK180 boot PDI. The PLM in this PDI configures
#                PMC/PSM/NoC/DDR/MIO/clocks. A prebuilt vmk180 PDI works.
#
# Optional env (sensible defaults):
#   APP_ELF    - default: ${PORT_DIR}/app.elf (build with LAYOUT=ddr so
#                the app loads to DDR, which the PLM has trained)
#
# Usage (from the port directory):
#   XSDB=/opt/Xilinx/2025.2/Vitis/bin/xsdb \
#   BOOT_PDI=/path/to/vmk180_boot.pdi \
#   ./jtag/boot.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT_DIR="$(dirname "${SCRIPT_DIR}")"

: "${XSDB:?XSDB is required (path to Vitis xsdb binary)}"
: "${BOOT_PDI:?BOOT_PDI is required (path to a VMK180 boot PDI)}"
APP_ELF="${APP_ELF:-${PORT_DIR}/app.elf}"

if ! command -v "${XSDB}" >/dev/null 2>&1 && [[ ! -x "${XSDB}" ]]; then
    echo "ERROR: xsdb not found / not executable: ${XSDB}" >&2
    exit 1
fi
if [[ ! -f "${BOOT_PDI}" ]]; then
    echo "ERROR: BOOT_PDI not found at ${BOOT_PDI}" >&2
    exit 1
fi
if [[ ! -f "${APP_ELF}" ]]; then
    echo "ERROR: app.elf not found at ${APP_ELF}. Run 'make LAYOUT=ddr' first." >&2
    exit 1
fi

echo "JTAG boot Versal (VMK180) wolfIP app"
echo "  xsdb     : ${XSDB}"
echo "  boot pdi : ${BOOT_PDI}"
echo "  app.elf  : ${APP_ELF}"
echo

export APP_ELF BOOT_PDI

"${XSDB}" "${SCRIPT_DIR}/boot.tcl"

echo
echo "App is running. Watch UART (PS console is FT4232 interface 1):"
echo "  uart-monitor status | jq -r '.ports[].label' | grep VERSAL"
echo "  uart-monitor tail VERSAL_VMK180_UART1"

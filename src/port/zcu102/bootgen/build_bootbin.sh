#!/usr/bin/env bash
#
# Build BOOT.BIN for the wolfIP ZCU102 bare-metal app.
#
# Required env vars:
#   FSBL_ELF   - path to a prebuilt ZynqMP FSBL ELF (A53-0, EL3, NS).
#                Build this once in Vitis (helloworld template -> zynqmp_fsbl)
#                or in PetaLinux; we do not vendor FSBL sources here.
#   APP_ELF    - path to the wolfIP app ELF. The Makefile's "bootbin"
#                target sets this for you to $PWD/app.elf.
#
# Optional:
#   BOOTGEN    - path to the bootgen binary (default: from $PATH).
#   OUT_DIR    - where to place BOOT.BIN (default: parent of this script).
#
set -euo pipefail

if [[ -z "${FSBL_ELF:-}" ]]; then
    echo "ERROR: FSBL_ELF env var must point to a ZynqMP FSBL ELF." >&2
    exit 1
fi
if [[ -z "${APP_ELF:-}" ]]; then
    echo "ERROR: APP_ELF env var must point to the wolfIP app ELF." >&2
    exit 1
fi
if [[ ! -f "${FSBL_ELF}" ]]; then
    echo "ERROR: FSBL_ELF '${FSBL_ELF}' not found." >&2
    exit 1
fi
if [[ ! -f "${APP_ELF}" ]]; then
    echo "ERROR: APP_ELF '${APP_ELF}' not found." >&2
    exit 1
fi

BOOTGEN="${BOOTGEN:-bootgen}"
if ! command -v "${BOOTGEN}" >/dev/null 2>&1; then
    echo "ERROR: bootgen not found. Source Vitis (settings64.sh) first." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-$(dirname "${SCRIPT_DIR}")}"
BIF_TEMPLATE="${SCRIPT_DIR}/boot.bif"
BIF_RENDERED="$(mktemp -t wolfip-zcu102-bif.XXXXXX)"
trap 'rm -f "${BIF_RENDERED}"' EXIT

# Substitute ${FSBL_ELF} and ${APP_ELF} in the bif template.
sed \
    -e "s|\${FSBL_ELF}|${FSBL_ELF}|g" \
    -e "s|\${APP_ELF}|${APP_ELF}|g" \
    "${BIF_TEMPLATE}" > "${BIF_RENDERED}"

cd "${OUT_DIR}"
"${BOOTGEN}" -arch zynqmp -image "${BIF_RENDERED}" -w on -o BOOT.BIN

echo "BOOT.BIN written to: ${OUT_DIR}/BOOT.BIN"

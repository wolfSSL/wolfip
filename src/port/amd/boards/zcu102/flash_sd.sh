#!/usr/bin/env bash
#
# flash_sd.sh - copy wolfIP ZCU102 BOOT.BIN to the SD card's boot partition.
#
# Usage:
#   ./flash_sd.sh                       # uses /dev/sdb (default), src/port/zcu102/BOOT.BIN
#   SD_DEV=/dev/sdc ./flash_sd.sh
#   BOOTBIN=/path/to/BOOT.BIN ./flash_sd.sh
#
# Defensive: refuses to write to a device that is not flagged removable
# by the kernel, or any device larger than 128 GiB (so it cannot ever
# scribble on your system SSD by accident).
#
set -euo pipefail

SD_DEV="${SD_DEV:-/dev/sdb}"
# mmcblk/nvme devices suffix partitions with 'p' (e.g. mmcblk0p1); sdX
# style devices just append the number (sdb1).
case "${SD_DEV}" in
    *[0-9]) PART="${SD_DEV}p1" ;;
    *)      PART="${SD_DEV}1"  ;;
esac
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTBIN="${BOOTBIN:-${SCRIPT_DIR}/BOOT.BIN}"

red()   { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
note()  { printf '  %s\n' "$*"; }

# --- Sanity checks -------------------------------------------------------

if [[ ! -b "${SD_DEV}" ]]; then
    red "ERROR: ${SD_DEV} is not a block device."
    exit 1
fi
if [[ ! -b "${PART}" ]]; then
    red "ERROR: boot partition ${PART} not found."
    red "       Did you insert the card and pick the right SD_DEV?"
    exit 1
fi

RM=$(lsblk -dn -o RM "${SD_DEV}" | tr -d '[:space:]')
if [[ "${RM}" != "1" ]]; then
    red "ERROR: ${SD_DEV} is not marked removable (RM=${RM})."
    red "       Refusing to write - this looks like a fixed disk."
    exit 1
fi

SIZE_BYTES=$(lsblk -dn -o SIZE -b "${SD_DEV}" | tr -d '[:space:]')
SIZE_GIB=$(( SIZE_BYTES / 1024 / 1024 / 1024 ))
if (( SIZE_GIB > 128 )); then
    red "ERROR: ${SD_DEV} is ${SIZE_GIB} GiB - too large for an SD card."
    red "       Refusing to write."
    exit 1
fi

if [[ ! -f "${BOOTBIN}" ]]; then
    red "ERROR: ${BOOTBIN} not found. Did you run 'make bootbin'?"
    exit 1
fi

note "SD device     : ${SD_DEV} (${SIZE_GIB} GiB, removable)"
note "Boot partition: ${PART}"
note "Source        : ${BOOTBIN}"
echo

# --- Mount (idempotent) --------------------------------------------------

MNT=$(lsblk -no MOUNTPOINT "${PART}")
WE_MOUNTED=0
if [[ -z "${MNT}" ]]; then
    note "Mounting ${PART} via udisksctl..."
    udisksctl mount -b "${PART}" >/dev/null
    MNT=$(lsblk -no MOUNTPOINT "${PART}")
    WE_MOUNTED=1
fi
if [[ -z "${MNT}" ]]; then
    red "ERROR: ${PART} did not mount."
    exit 1
fi
note "Mountpoint    : ${MNT}"

# Verify FAT - cheap heuristic: check filesystem type via lsblk.
FSTYPE=$(lsblk -no FSTYPE "${PART}")
if [[ "${FSTYPE}" != "vfat" && "${FSTYPE}" != "exfat" && "${FSTYPE}" != "msdos" ]]; then
    red "WARN: ${PART} filesystem is '${FSTYPE}', expected vfat for ZCU102 SD boot."
fi

# --- Backup and copy -----------------------------------------------------

if [[ -f "${MNT}/BOOT.BIN" ]]; then
    OLD_SZ=$(stat -c%s "${MNT}/BOOT.BIN")
    cp --preserve=timestamps "${MNT}/BOOT.BIN" "${MNT}/BOOT.BIN.bak"
    note "Backed up existing BOOT.BIN (${OLD_SZ} bytes) -> BOOT.BIN.bak"
fi

cp "${BOOTBIN}" "${MNT}/BOOT.BIN"
sync
NEW_SZ=$(stat -c%s "${MNT}/BOOT.BIN")
note "Wrote ${NEW_SZ} bytes to ${MNT}/BOOT.BIN"

# --- Unmount -------------------------------------------------------------

if (( WE_MOUNTED == 1 )); then
    note "Unmounting ${PART}..."
    udisksctl unmount -b "${PART}" >/dev/null
fi
sync

green "Done. Safe to remove the SD card and boot the board."
echo
note "Watch UART log: tail -f /tmp/uart-monitor/latest/ZYNQMP_ZCU102_UART0.log"
note "Or:             uart-monitor tail ZYNQMP_ZCU102_UART0"

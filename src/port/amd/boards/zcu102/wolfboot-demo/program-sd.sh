#!/usr/bin/env bash
#
# Program an SD card for the ZCU102 wolfBoot + wolfIP demo.
#
# Expects an MBR card laid out like zynqmp_sdcard.config (a stock PetaLinux
# ZCU102 SD card works):
#   p1  boot   FAT32, bootable   <- BOOT.BIN      (FSBL+PMUFW+BL31+wolfBoot)
#   p2  OFP_A  raw               <- signed app    (wolfBoot's primary image)
#   p3  OFP_B  raw               (update slot - written over the network at run time)
#   p4  rootfs                   (unused by this bare-metal demo)
#
# wolfBoot reads the *raw* OFP_A partition (WOLFBOOT_NO_PARTITIONS, BOOT_PART_A=1),
# so the signed image is dd'd to the start of p2 (this needs root). Copying
# BOOT.BIN into the FAT p1 does not.
#
# Usage:  SD=/dev/sdX ./program-sd.sh         (X = your card reader, NOT a board)
#         WIPE_OFP_B=1 SD=/dev/sdX ./program-sd.sh   also zero OFP_B so the board
#                                     boots A:v1 fresh (for a clean A->B update demo)
#
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/out"
VERSION="${VERSION:-1}"
SIGNED="$OUT/wolfip_app_v${VERSION}_signed.bin"
SD="${SD:?set SD=/dev/sdX (your SD card reader block device - double-check with lsblk!)}"

[ -f "$OUT/BOOT.BIN" ] || { echo "missing $OUT/BOOT.BIN - run ./build.sh first" >&2; exit 1; }
[ -f "$SIGNED" ]       || { echo "missing $SIGNED - run ./build.sh first" >&2; exit 1; }
[ -b "$SD" ]           || { echo "$SD is not a block device" >&2; exit 1; }

# Partition node suffix: /dev/sdX -> sdX1 ; /dev/mmcblkN|nvmeN|loopN -> ...p1
case "$SD" in
    *[0-9]) P="p" ;;
    *)      P=""  ;;
esac

echo "Target $SD:"; lsblk -o NAME,SIZE,TYPE,LABEL,FSTYPE "$SD"
read -r -p "Write BOOT.BIN to ${SD}${P}1 (FAT) and the signed app to ${SD}${P}2 (raw)? [y/N] " a
[ "$a" = y ] || { echo "aborted"; exit 1; }

echo "== BOOT.BIN -> ${SD}${P}1 (FAT boot partition) =="
MNT="$(mktemp -d)"
# Ensure the partition is unmounted and the temp dir removed even if a step
# below fails under 'set -e' or the script is interrupted.
trap 'sudo umount "$MNT" 2>/dev/null || true; rmdir "$MNT" 2>/dev/null || true' EXIT
sudo mount "${SD}${P}1" "$MNT"
sudo cp "$OUT/BOOT.BIN" "$MNT/BOOT.BIN"
sync

echo "== signed app -> ${SD}${P}2 (OFP_A, raw) =="
sudo dd if="$SIGNED" of="${SD}${P}2" bs=1M conv=fsync status=progress

# Clean slate: zero the start of OFP_B so wolfBoot sees no valid update there
# (version 0) and boots A:v1, ready for a fresh A->B update demo.
if [ "${WIPE_OFP_B:-0}" = 1 ]; then
    echo "== wiping OFP_B header -> ${SD}${P}3 =="
    sudo dd if=/dev/zero of="${SD}${P}3" bs=1M count=1 conv=fsync status=none
fi

sync
echo "Done. Put the card in the ZCU102, set SW6=SD, and power on."

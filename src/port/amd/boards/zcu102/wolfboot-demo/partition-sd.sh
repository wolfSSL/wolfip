#!/usr/bin/env bash
#
# Partition a BLANK SD card for the ZCU102 wolfBoot + wolfIP demo, matching the
# zynqmp_sdcard.config MBR layout. A stock PetaLinux ZCU102 card already has
# this layout - use this script only when starting from a blank/repurposed card:
#   p1  boot   128M  FAT32, bootable  <- BOOT.BIN
#   p2  OFP_A  200M  raw              <- signed app (primary)
#   p3  OFP_B  200M  raw              <- update slot
#   p4  rootfs rest  (unused by this bare-metal demo)
#
# DESTRUCTIVE: erases the entire target disk. Double-check with lsblk!
#
# Usage:  SD=/dev/sdX ./partition-sd.sh
#
set -euo pipefail

SD="${SD:?set SD=/dev/sdX (your card reader - NOT a board, NOT your system disk!)}"
[ -b "$SD" ] || { echo "$SD is not a block device" >&2; exit 1; }

# Partition node suffix: /dev/sdX -> sdX1 ; /dev/mmcblkN|nvmeN|loopN -> ...p1
case "$SD" in
    *[0-9]) P="p" ;;
    *)      P=""  ;;
esac

# Refuse if anything on the device is mounted.
if lsblk -nro MOUNTPOINT "$SD" | grep -q .; then
    echo "ERROR: $SD has mounted partitions - unmount them first:" >&2
    lsblk -o NAME,SIZE,TYPE,MOUNTPOINT "$SD" >&2
    exit 1
fi

echo "Target $SD:"; lsblk -o NAME,SIZE,TYPE,LABEL,FSTYPE "$SD"
echo
echo "This ERASES ALL DATA on $SD and writes the ZCU102 demo MBR layout."
read -r -p "Type the device path ($SD) to confirm: " a
[ "$a" = "$SD" ] || { echo "aborted"; exit 1; }

echo "== writing MBR partition table =="
# 1 MiB align; 128M boot (FAT32, bootable), 200M OFP_A, 200M OFP_B, rest rootfs.
sudo sfdisk "$SD" <<'EOF'
label: dos
unit: sectors
start=2048,  size=262144, type=c, bootable
size=409600, type=83
size=409600, type=83
type=83
EOF

sudo partprobe "$SD" 2>/dev/null || true
sync; sleep 1

echo "== formatting ${SD}${P}1 as FAT32 (boot) =="
sudo mkfs.vfat -F 32 -n BOOT "${SD}${P}1" >/dev/null

sync
echo "Done. $SD now has boot / OFP_A / OFP_B / rootfs."
echo "Next: SD=$SD ./program-sd.sh"

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
# It refuses a partition, a non-removable disk, or one bigger than MAX_GB.
#
# Usage:  SD=/dev/sdX ./partition-sd.sh
#         FORCE=1 SD=... ./partition-sd.sh   skip the removable/size checks
#                                            (unusual card reader)
#         MAX_GB=N SD=... ./partition-sd.sh  raise the size cap (default 256)
#
set -euo pipefail

SD="${SD:?set SD=/dev/sdX (your card reader - NOT a board, NOT your system disk!)}"
[ -b "$SD" ] || { echo "$SD is not a block device" >&2; exit 1; }

# Reject obviously-wrong targets before anything destructive happens: a
# partition instead of a whole disk, a fixed (non-removable) drive such as your
# system disk, or a device far larger than any demo SD card. FORCE=1 overrides
# the removable and size checks; MAX_GB= raises the size cap.
check_target_disk() {
    local devtype removable hotplug bytes maxbytes

    devtype="$(lsblk -ndo TYPE "$SD" | tr -d '[:space:]')"
    if [ "$devtype" != "disk" ]; then
        echo "ERROR: $SD is a '$devtype', not a whole disk - pass the card" >&2
        echo "       reader itself (/dev/sdX), not a partition (/dev/sdX1)." >&2
        exit 1
    fi

    # lsblk pads a column to its (suppressed) header width, hence the tr. A
    # reader that reports RM=0 but HOTPLUG=1 (PCIe/rtsx, some USB bridges) is
    # still fine.
    removable="$(lsblk -ndo RM "$SD" | tr -d '[:space:]')"
    hotplug="$(lsblk -ndo HOTPLUG "$SD" | tr -d '[:space:]')"
    if [ "$removable" != 1 ] && [ "$hotplug" != 1 ] && [ "${FORCE:-0}" != 1 ]; then
        echo "ERROR: $SD is not removable or hotplug (RM=$removable," >&2
        echo "       HOTPLUG=$hotplug) - refusing. Set FORCE=1 to override." >&2
        exit 1
    fi

    bytes="$(lsblk -ndbo SIZE "$SD" | tr -d '[:space:]')"
    maxbytes=$(( ${MAX_GB:-256} * 1024 * 1024 * 1024 ))
    if [ "$bytes" -gt "$maxbytes" ] && [ "${FORCE:-0}" != 1 ]; then
        echo "ERROR: $SD is $((bytes / 1024 / 1024 / 1024))GB, over the" >&2
        echo "       ${MAX_GB:-256}GB sanity limit - refusing. Set MAX_GB= or FORCE=1." >&2
        exit 1
    fi
}
check_target_disk

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

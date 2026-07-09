#!/usr/bin/env bash
#
# Trigger the network firmware update for the ZCU102 wolfBoot + wolfIP demo.
#
# Stages the signed update image (out/wolfip_update.bin, from build.sh) into a
# TFTP root, then sends the "UPDATE" trigger to the running app. The app fetches
# the image from the *sender's* host over TFTP, writes it to OFP_B, and resets;
# wolfBoot then verifies and boots the higher version.
#
# Assumes a TFTP server is already running on THIS host and serving $TFTP_ROOT
# (e.g. tftpd-hpa at /srv/tftp), reachable from the board's subnet. (The app
# fetches from the sender's IP, so the TFTP server must be on the machine that
# runs this script.)
#
# Usage:  BOARD_IP=10.0.4.140 [TFTP_ROOT=/srv/tftp] ./update.sh
#
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BOARD_IP="${BOARD_IP:?set BOARD_IP=<the board IP shown on its console>}"
TFTP_ROOT="${TFTP_ROOT:-/srv/tftp}"
IMG="${IMG:-$HERE/out/wolfip_update.bin}"
PORT="${PORT:-7}"   # the app's UDP echo/control port

[ -f "$IMG" ]       || { echo "ERROR: $IMG not found - run ./build.sh first" >&2; exit 1; }
[ -d "$TFTP_ROOT" ] || { echo "ERROR: TFTP_ROOT $TFTP_ROOT is not a directory - start a TFTP server or set TFTP_ROOT=" >&2; exit 1; }
[ -w "$TFTP_ROOT" ] || { echo "ERROR: TFTP_ROOT $TFTP_ROOT not writable by $(id -un) - fix perms or set TFTP_ROOT= to a writable dir" >&2; exit 1; }
command -v nc >/dev/null || { echo "ERROR: 'nc' (netcat) not found" >&2; exit 1; }

echo "Staging $(basename "$IMG") -> $TFTP_ROOT/wolfip_update.bin"
cp "$IMG" "$TFTP_ROOT/wolfip_update.bin"

echo "Triggering update on $BOARD_IP:$PORT ..."
printf 'UPDATE' | nc -u -w1 "$BOARD_IP" "$PORT"

echo
echo "Watch the board console: it fetches wolfip_update.bin over TFTP, writes"
echo "OFP_B, resets (intentional), and wolfBoot then boots the higher version."

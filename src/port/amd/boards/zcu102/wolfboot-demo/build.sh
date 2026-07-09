#!/usr/bin/env bash
#
# Build the ZCU102 wolfBoot + wolfIP secure-boot demo end to end:
#   FSBL -> PMUFW -> BL31 (EL3) -> wolfBoot (EL2) -> signed wolfIP app (EL2).
#
# Produces, in out/:
#   BOOT.BIN                  - bootloader chain (FSBL+PMUFW+BL31+wolfBoot)
#   wolfip_app_v1_signed.bin  - the app signed v1 (programmed to OFP_A)
#   wolfip_app_v2_signed.bin  - the same app signed v2 (the network update)
#   wolfip_update.bin         - a copy of the v2 image (the name update.sh serves)
#
# Dependencies (see README.md):
#   - wolfIP:   this repo. This script lives in the ZCU102 port at
#               src/port/amd/boards/zcu102/wolfboot-demo/, and builds the app
#               in the parent directory - no external wolfIP clone needed.
#   - wolfBoot: an external checkout (default ../wolfBoot next to this repo;
#               override with WOLFBOOT=). Provides the SD config, sign tools,
#               and the SD/disk drivers the OTA app compiles in.
#   - FSBL/PMUFW/BL31: build for the ZCU102 with Vitis/PetaLinux; point FW= at them
#   - aarch64-none-elf toolchain and bootgen (Vitis) on PATH
# Override any path with the matching env var.
#
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The wolfIP ZCU102 app lives in the parent directory of this demo.
APPDIR="$(cd "$HERE/.." && pwd)"
# wolfIP repo root: six levels up from src/port/amd/boards/zcu102/wolfboot-demo.
WOLFIP_ROOT="$(cd "$HERE/../../../../../.." && pwd)"

WOLFBOOT="${WOLFBOOT:-$WOLFIP_ROOT/../wolfBoot}"
FW="${FW:-$WOLFIP_ROOT/../soc-prebuilt-firmware/zcu102-zynqmp}"  # zynqmp_fsbl.elf, pmufw.elf, bl31.elf
CROSS="${CROSS_COMPILE:-aarch64-none-elf-}"
UPDATE_VERSION="${UPDATE_VERSION:-2}"
MAC5="${MAC5:-0x33}"
OUT="$HERE/out"
mkdir -p "$OUT"

# Fail fast on missing dependencies (clearer than a build error halfway through).
[ -d "$WOLFBOOT/src" ] || { echo "ERROR: wolfBoot not at $WOLFBOOT - clone wolfSSL/wolfBoot next to this repo or set WOLFBOOT=" >&2; exit 1; }
[ -f "$APPDIR/Makefile" ] || { echo "ERROR: wolfIP ZCU102 app Makefile not at $APPDIR - run this from within the wolfIP tree" >&2; exit 1; }
[ -f "$FW/zynqmp_fsbl.elf" ] || { echo "ERROR: FSBL/PMUFW/BL31 not in $FW - build them (see README) and set FW=" >&2; exit 1; }

echo "== 1/3  wolfBoot (ZynqMP SD, RSA4096/SHA3) =="
cp "$WOLFBOOT/config/examples/zynqmp_sdcard.config" "$WOLFBOOT/.config"
# Build inside $WOLFBOOT (its Makefile resolves the sign tool via $(PWD)). The
# build generates the signing key, reused so a v2 update verifies against the
# same wolfBoot. If a stale key with a different algorithm is present, run
# 'make keysclean' in wolfBoot once.
( cd "$WOLFBOOT" && make keytools >/dev/null )
( cd "$WOLFBOOT" && make clean >/dev/null 2>&1 || true )
( cd "$WOLFBOOT" && make CROSS_COMPILE="$CROSS" wolfboot.elf )
cp "$WOLFBOOT/wolfboot.elf" "$OUT/"

echo "== 2/3  wolfIP app (EL2, DDR, OTA) + sign v1 + v$UPDATE_VERSION =="
# OTA=1 compiles wolfBoot's own SD/disk drivers ($WOLFBOOT/src/{sdhci,disk,gpt}.c)
# straight into the app so the running image can fetch a signed update over TFTP
# and stage it to OFP_B itself - no runtime hand-off from wolfBoot.
make -C "$APPDIR" clean >/dev/null 2>&1 || true
make -C "$APPDIR" CROSS_COMPILE="$CROSS" EL=2 LAYOUT=ddr OTA=1 WOLFBOOT="$WOLFBOOT" \
    CFLAGS_EXTRA="-DWOLFIP_MAC_5=$MAC5"
"${CROSS}objcopy" -O binary "$APPDIR/app.elf" "$OUT/wolfip_app.bin"
# Sign the same image at v1 (boots from OFP_A) and at the update version (served
# over the network). wolfBoot boots the higher version, so v1 updates to v2.
KEY="$WOLFBOOT/wolfboot_signing_private_key.der"
"$WOLFBOOT/tools/keytools/sign" --rsa4096 --sha3 "$OUT/wolfip_app.bin" "$KEY" 1
"$WOLFBOOT/tools/keytools/sign" --rsa4096 --sha3 "$OUT/wolfip_app.bin" "$KEY" "$UPDATE_VERSION"
cp "$OUT/wolfip_app_v${UPDATE_VERSION}_signed.bin" "$OUT/wolfip_update.bin"

echo "== 3/3  BOOT.BIN (FSBL+PMUFW+BL31+wolfBoot) =="
# Escape the replacement strings: '\', '&' and the '|' delimiter are special to
# sed's RHS, so a path containing them would otherwise corrupt boot.bif.
sed_escape() { printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'; }
sed -e "s|@FW@|$(sed_escape "$FW")|g" \
    -e "s|@WOLFBOOT@|$(sed_escape "$OUT")|g" \
    "$HERE/boot.bif.in" > "$OUT/boot.bif"
bootgen -arch zynqmp -image "$OUT/boot.bif" -w on -o "$OUT/BOOT.BIN"

echo
echo "Done. Artifacts in $OUT:"
ls -la "$OUT"/BOOT.BIN "$OUT"/wolfip_app_v1_signed.bin "$OUT"/wolfip_update.bin
echo "Next:  SD=/dev/sdX ./program-sd.sh      (writes BOOT.BIN + the v1 app)"
echo "       boot ZCU102 (SW6=SD), then  BOARD_IP=<ip> ./update.sh   to update to v$UPDATE_VERSION"

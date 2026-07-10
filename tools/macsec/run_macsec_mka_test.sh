#!/bin/bash
# run_macsec_mka_test.sh
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# MKA control-plane interop between the wolfIP MKA participant (build/macsec-sta)
# and Linux wpa_supplicant (driver macsec_linux), over a veth pair. Uses a
# static pre-shared CAK/CKN. wpa_supplicant has the higher priority (lower
# value) so it is elected Key Server, generates the SAK, and distributes it;
# the wolfIP participant must discover it, become mutually live, unwrap the SAK with the
# shared KEK, and install it. Success = wolfmka prints SAK-INSTALLED (exit 0).
#
# Requires root (veth + wpa_supplicant + macsec). Run on Linux:
#   sudo bash tools/macsec/run_macsec_mka_test.sh

set -u
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STA="$REPO_ROOT/build/macsec-sta"

NSA=mk2-a; NSB=mk2-b; VA=mk2v-a; VB=mk2v-b
CAK="0123456789abcdef0123456789abcdef"
CKN="000102030405060708090a0b0c0d0e0f"

cleanup() {
    pkill -f "wpa_supplicant.*$VA" 2>/dev/null
    ip netns del "$NSA" 2>/dev/null
    ip netns del "$NSB" 2>/dev/null
}
trap cleanup EXIT INT TERM

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
[ -x "$STA" ] || { echo "missing $STA (make WOLFIP_ENABLE_MACSEC=1 WOLFMKA_DIR=... build/macsec-sta)" >&2; exit 1; }
command -v wpa_supplicant >/dev/null || { echo "wpa_supplicant not installed" >&2; exit 1; }
modprobe macsec 2>/dev/null

cleanup; sleep 0.3
set -e
ip netns add "$NSA"; ip netns add "$NSB"
ip link add "$VA" netns "$NSA" type veth peer name "$VB" netns "$NSB"
ip -n "$NSA" link set "$VA" up
ip -n "$NSB" link set "$VB" up
set +e

WPACONF=$(mktemp)
cat > "$WPACONF" <<CFG
ctrl_interface=/tmp/wpa_mka2_ctrl
eapol_version=3
ap_scan=0
network={
    key_mgmt=NONE
    eapol_flags=0
    macsec_policy=1
    mka_cak=$CAK
    mka_ckn=$CKN
    mka_priority=10
}
CFG

WPALOG=$(mktemp)
echo "[macsec-mka] starting wpa_supplicant (Key Server, prio 10) on $VA"
ip netns exec "$NSA" wpa_supplicant -i "$VA" -D macsec_linux -c "$WPACONF" \
    -dd -f "$WPALOG" -B
sleep 1

echo "[macsec-mka] starting macsec_sta (member, prio 20) on $VB"
OUT=$(ip netns exec "$NSB" "$STA" "$VB" "$CAK" "$CKN" 20 18 2>&1)
RC=$?
echo "----- macsec_sta output -----"
echo "$OUT"
echo "--------------------------"

echo "[macsec-mka] wpa_supplicant MKA log (key lines):"
grep -iE "live peer|peer detected|new SAK|distribut|Key Server|CKN|create MKA|MKPDU" "$WPALOG" \
    2>/dev/null | tail -20 | sed 's/^/    /'
echo "[macsec-mka] kernel macsec on wpa side:"
ip -n "$NSA" macsec show 2>/dev/null | sed 's/^/    /' || echo "    (none)"

rm -f "$WPACONF" "$WPALOG"

echo
if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "SAK-INSTALLED"; then
    echo "PASS: wolfIP MKA agreed a SAK with wpa_supplicant"
    exit 0
else
    echo "FAIL: no SAK agreement (macsec_sta rc=$RC)"
    exit 1
fi

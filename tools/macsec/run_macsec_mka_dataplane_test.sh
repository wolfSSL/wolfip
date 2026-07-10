#!/bin/bash
# run_macsec_mka_dataplane_test.sh
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# End-to-end MACsec data-plane test: the wolfIP MKA participant (build/macsec-sta,
# wolfMKA backend) agrees a SAK with Linux wpa_supplicant, programs the agreed
# SAK into a kernel macsec device, and a ping is exchanged over the encrypted
# link. Proves the whole stack: wolfMKA control plane + kernel SecY data plane +
# wpa_supplicant interop.
#
# Requires root (veth + wpa_supplicant + kernel macsec) and build/macsec-sta
# built with WOLFMKA_DIR set. Run on Linux:
#   sudo bash tools/macsec/run_macsec_mka_dataplane_test.sh

set -u
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STA="$REPO_ROOT/build/macsec-sta"

NSA=md-a; NSB=md-b; VA=mdv-a; VB=mdv-b
CAK="0123456789abcdef0123456789abcdef"
CKN="000102030405060708090a0b0c0d0e0f"
IP_A=10.9.9.1; IP_B=10.9.9.2

cleanup() {
    pkill -f "wpa_supplicant.*$VA" 2>/dev/null
    ip netns del "$NSA" 2>/dev/null
    ip netns del "$NSB" 2>/dev/null
}
trap cleanup EXIT INT TERM

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
[ -x "$STA" ] || { echo "missing $STA (WOLFIP_ENABLE_MACSEC=1 WOLFMKA_DIR=... build/macsec-sta)" >&2; exit 1; }
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
ctrl_interface=/tmp/wpa_mkadp_ctrl
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
echo "[dp] starting wpa_supplicant (Key Server) on $VA"
ip netns exec "$NSA" wpa_supplicant -i "$VA" -D macsec_linux -c "$WPACONF" \
    -dd -f "$WPALOG" -B
sleep 1.5

# wpa_supplicant created its own macsec device; find it and give it an IP.
WPA_MACSEC=$(ip -n "$NSA" -o link show type macsec 2>/dev/null | awk -F': ' 'NR==1{print $2}' | cut -d@ -f1)
if [ -z "$WPA_MACSEC" ]; then
    echo "FAIL: wpa_supplicant did not create a macsec device"; exit 1
fi
ip -n "$NSA" addr add "$IP_A/24" dev "$WPA_MACSEC" 2>/dev/null
ip -n "$NSA" link set "$WPA_MACSEC" up
echo "[dp] wpa macsec dev=$WPA_MACSEC ip=$IP_A"

# wolfIP side: create the kernel macsec device that macsec_sta will key.
ip -n "$NSB" link add link "$VB" macsec0 type macsec encrypt on
ip -n "$NSB" link set macsec0 up
ip -n "$NSB" addr add "$IP_B/24" dev macsec0
echo "[dp] wolfIP macsec dev=macsec0 ip=$IP_B"

echo "[dp] running macsec_sta (wolfMKA, kernel SecY) on $VB"
STA_OUT=$(mktemp)
ip netns exec "$NSB" env MACSEC_KERNEL_DEV=macsec0 \
    "$STA" "$VB" "$CAK" "$CKN" 20 25 > "$STA_OUT" 2>&1 &
STA_PID=$!

# Wait for the SAK to be programmed into the kernel device.
for i in $(seq 1 20); do
    grep -q "MACSEC-UP" "$STA_OUT" && break
    sleep 0.5
done

echo "----- macsec_sta output -----"; cat "$STA_OUT"; echo "-----------------------------"
if ! grep -q "MACSEC-UP" "$STA_OUT"; then
    echo "FAIL: macsec_sta never programmed the kernel"; kill "$STA_PID" 2>/dev/null; exit 1
fi

echo "[dp] ping $IP_A over the encrypted link"
PINGLOG=$(mktemp)
if ip netns exec "$NSB" ping -c3 -W2 "$IP_A" >"$PINGLOG" 2>&1; then
    PING_OK=1
else
    PING_OK=0
fi
sed 's/^/    /' "$PINGLOG"

echo "[dp] macsec counters (wolfIP side, header + values):"
ip -n "$NSB" -s macsec show 2>/dev/null | grep -iA1 "OutPktsEncrypted\|InPktsOK" | sed 's/^/    /'

kill "$STA_PID" 2>/dev/null
rm -f "$WPACONF" "$WPALOG" "$STA_OUT" "$PINGLOG"

echo
if [ "$PING_OK" = 1 ]; then
    echo "PASS: ping succeeded over the MACsec link (wolfMKA + kernel SecY + wpa_supplicant)"
    exit 0
else
    echo "FAIL: ping did not succeed over the MACsec link"
    exit 1
fi

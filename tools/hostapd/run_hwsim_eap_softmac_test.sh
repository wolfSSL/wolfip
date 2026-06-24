#!/bin/bash
# run_hwsim_eap_softmac_test.sh
#
# WPA2-Enterprise (EAP-TLS) interop over a mac80211_hwsim radio: hostapd
# runs an EAP-TLS server, and the wolfIP supplicant joins via the SoftMAC
# nl80211 path (NL80211_CMD_CONNECT with AKM 802.1X), runs the EAP-TLS
# handshake, then the 4-way handshake keyed by the EAP MSK, to
# AUTHENTICATED. This exercises the enterprise path over a real radio
# (the wired veth test stops at EAP-Success).
#
# Requires: root, mac80211_hwsim, hostapd (with EAP server), openssl, iw,
# libnl-genl-3, and a wolfSSL with TLS 1.3 / AES key wrap / keying-material.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SSID="${SSID:-wolfIP-EAP}"
IDENTITY="${IDENTITY:-alice@wolfip.local}"
CERT_DIR="${CERT_DIR:-/tmp/wolfip_eap_certs}"
HOSTAPD_CONF="/tmp/wolfip_hwsim_eap_hostapd.conf"
HOSTAPD_LOG="/tmp/wolfip_hwsim_eap_hostapd.log"
USER_FILE="/tmp/wolfip_hwsim_eap_users"
TEST_BIN="${TEST_BIN:-$REPO_ROOT/build/test-supplicant-hwsim-eap-softmac}"
CERT_TOOL="${CERT_TOOL:-$REPO_ROOT/build/test-eap-tls-engine}"

die()  { echo "ERROR: $*" >&2; exit 1; }
note() { echo "[hwsim-eap] $*"; }

[ "$(id -u)" -eq 0 ] || die "run as root"
command -v hostapd >/dev/null 2>&1 || die "hostapd not installed"
command -v iw      >/dev/null 2>&1 || die "iw not installed"
[ -x "$TEST_BIN" ] || die "$TEST_BIN not built"

cleanup() {
    set +e
    [ -n "${HOSTAPD_PID:-}" ] && kill "$HOSTAPD_PID" 2>/dev/null
    wait 2>/dev/null
    rmmod mac80211_hwsim 2>/dev/null
    rm -f "$HOSTAPD_CONF" "$USER_FILE"
    rm -rf /tmp/wolfip_hostapd_ctrl
}
trap cleanup EXIT INT TERM

# Mint the throwaway PKI (idempotent) into $CERT_DIR. The supplicant test
# binary loads the matching client/CA DER from the same directory.
if [ ! -f "$CERT_DIR/ca.crt" ]; then
    note "generating EAP test certs"
    [ -x "$CERT_TOOL" ] || die "$CERT_TOOL not built (needed to mint certs)"
    "$CERT_TOOL" >/dev/null 2>&1 || true
    [ -f "$CERT_DIR/ca.crt" ] || die "cert generation failed ($CERT_DIR)"
fi

rmmod mac80211_hwsim 2>/dev/null || true
modprobe mac80211_hwsim radios=2 || die "modprobe failed"
sleep 0.3

PHYS=( $(ls /sys/class/ieee80211/) )
[ "${#PHYS[@]}" -ge 2 ] || die "expected >=2 phys"
AP_PHY="${PHYS[-2]}"; STA_PHY="${PHYS[-1]}"
AP_IF=$(ls /sys/class/ieee80211/$AP_PHY/device/net/ | head -1)
STA_IF=$(ls /sys/class/ieee80211/$STA_PHY/device/net/ | head -1)
note "AP=$AP_IF ($AP_PHY)  STA=$STA_IF ($STA_PHY)"
iw dev "$STA_IF" set type managed 2>/dev/null || true
ip link set "$AP_IF" up
ip link set "$STA_IF" up

printf '"%s"\tTLS\n*\tTLS\n' "$IDENTITY" > "$USER_FILE"
sed -e "s|@IFACE@|$AP_IF|g" -e "s|@SSID@|$SSID|g" \
    -e "s|@USER_FILE@|$USER_FILE|g" \
    -e "s|@CA_CERT@|$CERT_DIR/ca.crt|g" \
    -e "s|@SERVER_CERT@|$CERT_DIR/server.crt|g" \
    -e "s|@SERVER_KEY@|$CERT_DIR/server.key|g" \
    "$REPO_ROOT/tools/hostapd/hostapd_eap_hwsim.conf.template" > "$HOSTAPD_CONF"

note "starting hostapd (EAP-TLS server)"
hostapd -t "$HOSTAPD_CONF" >"$HOSTAPD_LOG" 2>&1 &
HOSTAPD_PID=$!
sleep 1
kill -0 "$HOSTAPD_PID" 2>/dev/null || { cat "$HOSTAPD_LOG"; die "hostapd died"; }
AP_MAC=$(cat "/sys/class/net/$AP_IF/address")
note "hostapd up BSSID=$AP_MAC"
sleep 1

note "running EAP-TLS supplicant test on $STA_IF"
set +e
"$TEST_BIN" "$STA_IF" "$SSID" "$IDENTITY" "$AP_MAC" 2412
TEST_RC=$?
set -e

echo "--- hostapd log (grep) ---"
grep -E "EAP|TLS|WPA|4-Way|key handshake|STA |authorized|RADIUS" "$HOSTAPD_LOG" \
    | grep -aviE 'hexdump' | tail -40
echo "--------------------------"
exit $TEST_RC

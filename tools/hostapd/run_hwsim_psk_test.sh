#!/bin/bash
# run_hwsim_psk_test.sh
#
# Validate the wolfIP supplicant's WPA2-PSK 4-way handshake against
# real hostapd over a mac80211_hwsim virtual radio. This is the proper
# wireless path (the wired hostapd driver routes everything through
# 802.1X EAP and cannot exercise the PSK 4-way).
#
# Requires:
#   - root
#   - mac80211_hwsim kernel module
#   - hostapd
#   - libnl-genl-3 (for tools/hostapd/nl80211_connect)
#   - iw

set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SSID="${SSID:-wolfIP-PSKNet}"
PSK="${PSK:-ThisIsAPassword!}"
HOSTAPD_CONF="${HOSTAPD_CONF:-/tmp/wolfip_hwsim_hostapd.conf}"
HOSTAPD_LOG="${HOSTAPD_LOG:-/tmp/wolfip_hwsim_hostapd.log}"
CONNECT_BIN="${CONNECT_BIN:-$REPO_ROOT/build/nl80211_connect}"
TEST_BIN="${TEST_BIN:-$REPO_ROOT/build/test-supplicant-hostapd-psk}"

die()  { echo "ERROR: $*" >&2; exit 1; }
note() { echo "[hwsim-psk] $*"; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
command -v hostapd >/dev/null 2>&1 || die "hostapd not installed"
command -v iw      >/dev/null 2>&1 || die "iw not installed"
[ -x "$CONNECT_BIN" ] || die "$CONNECT_BIN not built"
[ -x "$TEST_BIN"    ] || die "$TEST_BIN not built"

cleanup() {
    set +e
    [ -n "${CONNECT_PID:-}" ] && kill "$CONNECT_PID" 2>/dev/null
    [ -n "${HOSTAPD_PID:-}" ] && kill "$HOSTAPD_PID" 2>/dev/null
    wait 2>/dev/null
    rmmod mac80211_hwsim 2>/dev/null
    rm -f "$HOSTAPD_CONF"
    rm -rf /tmp/wolfip_hostapd_ctrl
}
trap cleanup EXIT INT TERM

# Drop existing instance, load with two radios.
rmmod mac80211_hwsim 2>/dev/null || true
modprobe mac80211_hwsim radios=2 || die "modprobe mac80211_hwsim failed"
sleep 0.3

# mac80211_hwsim creates wlan0 and wlan1 (after our radios, but the
# kernel may auto-pick higher numbers if hardware/other wireless
# devices exist). Resolve names dynamically.
PHYS=( $(ls /sys/class/ieee80211/) )
[ "${#PHYS[@]}" -ge 2 ] || die "expected >=2 phys, got ${#PHYS[@]}"
AP_PHY="${PHYS[-2]}"
STA_PHY="${PHYS[-1]}"
AP_IF=$(ls /sys/class/ieee80211/$AP_PHY/device/net/ | head -1)
STA_IF=$(ls /sys/class/ieee80211/$STA_PHY/device/net/ | head -1)
note "AP=$AP_IF ($AP_PHY)  STA=$STA_IF ($STA_PHY)"

ip link set "$AP_IF"  up
ip link set "$STA_IF" up

# Render hostapd config and start.
sed -e "s|@IFACE@|$AP_IF|g" \
    -e "s|@SSID@|$SSID|g" \
    -e "s|@PSK@|$PSK|g" \
    "$REPO_ROOT/tools/hostapd/hostapd_psk_hwsim.conf.template" \
    > "$HOSTAPD_CONF"

note "starting hostapd on $AP_IF"
hostapd -t -dd "$HOSTAPD_CONF" >"$HOSTAPD_LOG" 2>&1 &
HOSTAPD_PID=$!
sleep 1
if ! kill -0 "$HOSTAPD_PID" 2>/dev/null; then
    cat "$HOSTAPD_LOG"
    die "hostapd died"
fi

AP_MAC=$(cat "/sys/class/net/$AP_IF/address")
note "hostapd up, BSSID=$AP_MAC"

# Start the test binary FIRST so its AF_PACKET socket is bound and
# listening before hostapd transmits M1 - otherwise M1 races past the
# kernel's netdev RX queue. The supplicant times out at 10s so it'll
# wait while the nl80211 assoc is in flight.
note "starting supplicant test on $STA_IF (background)"
WOLFIP_SUPP_SKIP_HOSTAPD_CLI=1 \
    "$TEST_BIN" "$STA_IF" "$SSID" "$PSK" "$AP_MAC" &
TEST_PID=$!
sleep 0.4

# Now associate via nl80211. CONNECT_BIN holds the connection alive.
note "associating $STA_IF to $SSID via nl80211"
"$CONNECT_BIN" "$STA_IF" "$SSID" "$AP_MAC" &
CONNECT_PID=$!

# Wait for the test to finish (or timeout).
set +e
wait "$TEST_PID"
TEST_RC=$?
set -e

# Sanity check: did the kernel actually associate?
LINK=$(iw dev "$STA_IF" link 2>&1)
note "iw link after test: $(echo "$LINK" | tr '\n' ' ' | head -c 200)"

echo "--- hostapd log (grep 'EAPOL|WPA|4-Way|STA|wpa_') ---"
grep -E "EAPOL|WPA|4-Way|STA |wpa_auth|key handshake|EAP-" "$HOSTAPD_LOG" \
    | tail -80
echo "----------------------------------------------------"
exit $TEST_RC

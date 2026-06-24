#!/bin/bash
# run_hwsim_sae_test.sh
#
# Run the wolfIP supplicant's software WPA3-SAE state machine against
# real hostapd over a mac80211_hwsim virtual radio. Mirrors
# run_hwsim_psk_test.sh but with SAE config and nl80211 external-auth
# instead of plain CONNECT.
#
# Requires:
#   - root (TAP / hwsim load / AF_PACKET / nl80211 frame inject)
#   - mac80211_hwsim, hostapd, iw, libnl-genl-3
#   - wolfSSL built with WOLFSSL_PUBLIC_MP (the sae_crypto module needs
#     the mp_*/sp_* math ABI; see tools/hostapd/README.md)
#
# KNOWN LIMITATION:
#   The test binary uses NL80211_CMD_CONNECT + EXTERNAL_AUTH_SUPPORT,
#   which is the cfg80211 surface for FullMAC drivers (brcmfmac on
#   CYW43439). mac80211_hwsim is SoftMAC and only supports SAE via
#   NL80211_CMD_AUTHENTICATE; it ignores EXTERNAL_AUTH_SUPPORT and
#   falls back to open auth (which hostapd rejects). Expect the test
#   to print "kernel never fired NL80211_CMD_EXTERNAL_AUTH" and exit
#   non-zero on hwsim. The same binary validates green on CYW43439
#   hardware in Phase D. See the header comment of the test source
#   for the SoftMAC rewrite option.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SSID="${SSID:-wolfIP-SAE}"
PSK="${PSK:-ThisIsAPassword!}"
HOSTAPD_CONF="${HOSTAPD_CONF:-/tmp/wolfip_hwsim_sae_hostapd.conf}"
HOSTAPD_LOG="${HOSTAPD_LOG:-/tmp/wolfip_hwsim_sae_hostapd.log}"
TEST_BIN="${TEST_BIN:-$REPO_ROOT/build/test-supplicant-hostapd-sae}"
# WOLFIP_SAE_H2E=1: drive hostapd with sae_pwe=2 (H2E only) and tell
# the test binary to use RFC 9380 SSWU PWE. Default is H&P.
WOLFIP_SAE_H2E="${WOLFIP_SAE_H2E:-0}"
case "$WOLFIP_SAE_H2E" in
    1) SAE_PWE_MODE=2 ;;
    *) SAE_PWE_MODE=0 ;;
esac

die()  { echo "ERROR: $*" >&2; exit 1; }
note() { echo "[hwsim-sae] $*"; }

[ "$(id -u)" -eq 0 ] || die "run as root"
command -v hostapd >/dev/null 2>&1 || die "hostapd not installed"
command -v iw      >/dev/null 2>&1 || die "iw not installed"
[ -x "$TEST_BIN" ] || die "$TEST_BIN not built"

cleanup() {
    set +e
    [ -n "${HOSTAPD_PID:-}" ] && kill "$HOSTAPD_PID" 2>/dev/null
    wait 2>/dev/null
    rmmod mac80211_hwsim 2>/dev/null
    rm -f "$HOSTAPD_CONF"
    rm -rf /tmp/wolfip_hostapd_ctrl
}
trap cleanup EXIT INT TERM

rmmod mac80211_hwsim 2>/dev/null || true
modprobe mac80211_hwsim radios=2 || die "modprobe failed"
sleep 0.3

# mac80211_hwsim phys come after any real wireless (e.g. brcmfmac on Pi5).
PHYS=( $(ls /sys/class/ieee80211/) )
[ "${#PHYS[@]}" -ge 2 ] || die "expected >=2 phys"
AP_PHY="${PHYS[-2]}"
STA_PHY="${PHYS[-1]}"
AP_IF=$(ls /sys/class/ieee80211/$AP_PHY/device/net/ | head -1)
STA_IF=$(ls /sys/class/ieee80211/$STA_PHY/device/net/ | head -1)
note "AP=$AP_IF ($AP_PHY)  STA=$STA_IF ($STA_PHY)"
# Force station mode on STA before bringing up (default but make sure).
iw dev "$STA_IF" set type managed 2>/dev/null || true
ip link set "$AP_IF"  up
ip link set "$STA_IF" up

sed -e "s|@IFACE@|$AP_IF|g" \
    -e "s|@SSID@|$SSID|g" \
    -e "s|@PSK@|$PSK|g" \
    -e "s|@SAE_PWE@|$SAE_PWE_MODE|g" \
    "$REPO_ROOT/tools/hostapd/hostapd_sae_hwsim.conf.template" \
    > "$HOSTAPD_CONF"
note "hostapd sae_pwe=$SAE_PWE_MODE (WOLFIP_SAE_H2E=$WOLFIP_SAE_H2E)"

note "starting hostapd"
hostapd -t -dd "$HOSTAPD_CONF" >"$HOSTAPD_LOG" 2>&1 &
HOSTAPD_PID=$!
sleep 1
if ! kill -0 "$HOSTAPD_PID" 2>/dev/null; then
    cat "$HOSTAPD_LOG"; die "hostapd died"
fi
AP_MAC=$(cat "/sys/class/net/$AP_IF/address")
note "hostapd up, BSSID=$AP_MAC"

note "running supplicant SAE test on $STA_IF"
set +e
"$TEST_BIN" "$STA_IF" "$SSID" "$PSK" "$AP_MAC" 2412
TEST_RC=$?
set -e

echo "--- hostapd log (grep) ---"
grep -E "SAE|wpa_auth|EAPOL|WPA|Phase|STA |key handshake" "$HOSTAPD_LOG" \
    | tail -80
echo "--------------------------"
exit $TEST_RC

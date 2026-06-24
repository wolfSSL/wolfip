#!/bin/bash
# run_hwsim_sae_softmac_test.sh
#
# Run the wolfIP supplicant's WPA3-SAE state machine against real hostapd
# over a mac80211_hwsim virtual radio, using the SoftMAC nl80211 path
# (NL80211_CMD_AUTHENTICATE + SAE_DATA, then NL80211_CMD_ASSOCIATE) driven
# by tools/hostapd/nl80211_sta.c.
#
# Unlike run_hwsim_sae_test.sh (which uses the FullMAC CONNECT +
# EXTERNAL_AUTH_SUPPORT surface that mac80211_hwsim silently ignores),
# this path is the one hwsim actually supports for SAE, so it is expected
# to reach AUTHENTICATED with no hardware. The same binary then drives a
# real SoftMAC USB radio (e.g. a TP-Link ath9k_htc / rtl8xxxu / mt76).
#
# Requires:
#   - root (hwsim load / AF_PACKET / nl80211 auth+assoc+key install)
#   - mac80211_hwsim, hostapd, iw, libnl-genl-3
#   - wolfSSL built with WOLFSSL_PUBLIC_MP (sae_crypto needs the mp_*/sp_*
#     math ABI; see tools/hostapd/README.md)
#
# Env:
#   WOLFIP_SAE_H2E=1   drive hostapd with sae_pwe=2 (H2E only) and tell the
#                      supplicant to use RFC 9380 SSWU PWE. Default is H&P.
#   SAE_GROUPS         hostapd sae_groups (default "19 20 21").

set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SSID="${SSID:-wolfIP-SAE}"
PSK="${PSK:-ThisIsAPassword!}"
HOSTAPD_CONF="${HOSTAPD_CONF:-/tmp/wolfip_hwsim_sae_softmac_hostapd.conf}"
HOSTAPD_LOG="${HOSTAPD_LOG:-/tmp/wolfip_hwsim_sae_softmac_hostapd.log}"
TEST_BIN="${TEST_BIN:-$REPO_ROOT/build/test-supplicant-hwsim-sae-softmac}"
SAE_GROUPS="${SAE_GROUPS:-19 20 21}"
WOLFIP_SAE_H2E="${WOLFIP_SAE_H2E:-0}"
case "$WOLFIP_SAE_H2E" in
    1) SAE_PWE_MODE=2 ;;
    *) SAE_PWE_MODE=0 ;;
esac

die()  { echo "ERROR: $*" >&2; exit 1; }
note() { echo "[hwsim-sae-softmac] $*"; }

[ "$(id -u)" -eq 0 ] || die "run as root"
command -v hostapd >/dev/null 2>&1 || die "hostapd not installed"
command -v iw      >/dev/null 2>&1 || die "iw not installed"
[ -x "$TEST_BIN" ] || die "$TEST_BIN not built (make build/test-supplicant-hwsim-sae-softmac)"

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

# mac80211_hwsim phys come after any real wireless (e.g. brcmfmac on a Pi).
PHYS=( $(ls /sys/class/ieee80211/) )
[ "${#PHYS[@]}" -ge 2 ] || die "expected >=2 phys"
AP_PHY="${PHYS[-2]}"
STA_PHY="${PHYS[-1]}"
AP_IF=$(ls /sys/class/ieee80211/$AP_PHY/device/net/ | head -1)
STA_IF=$(ls /sys/class/ieee80211/$STA_PHY/device/net/ | head -1)
note "AP=$AP_IF ($AP_PHY)  STA=$STA_IF ($STA_PHY)"
iw dev "$STA_IF" set type managed 2>/dev/null || true
ip link set "$AP_IF"  up
ip link set "$STA_IF" up

sed -e "s|@IFACE@|$AP_IF|g" \
    -e "s|@SSID@|$SSID|g" \
    -e "s|@PSK@|$PSK|g" \
    -e "s|@SAE_PWE@|$SAE_PWE_MODE|g" \
    "$REPO_ROOT/tools/hostapd/hostapd_sae_hwsim.conf.template" \
    > "$HOSTAPD_CONF"
# Pin sae_groups so we exercise the requested ECC groups.
if grep -q '^sae_groups' "$HOSTAPD_CONF"; then
    sed -i "s|^sae_groups.*|sae_groups=$SAE_GROUPS|" "$HOSTAPD_CONF"
else
    echo "sae_groups=$SAE_GROUPS" >> "$HOSTAPD_CONF"
fi
note "hostapd sae_pwe=$SAE_PWE_MODE sae_groups='$SAE_GROUPS' (WOLFIP_SAE_H2E=$WOLFIP_SAE_H2E)"

note "starting hostapd"
hostapd -t -dd "$HOSTAPD_CONF" >"$HOSTAPD_LOG" 2>&1 &
HOSTAPD_PID=$!
sleep 1
if ! kill -0 "$HOSTAPD_PID" 2>/dev/null; then
    cat "$HOSTAPD_LOG"; die "hostapd died"
fi
AP_MAC=$(cat "/sys/class/net/$AP_IF/address")
note "hostapd up, BSSID=$AP_MAC"

# The test binary triggers its own scan (so it can wait for the
# NEW_SCAN_RESULTS event and avoid the BSS-cache race); give hostapd a
# moment to start beaconing first.
sleep 1

# Negative test: give the supplicant the WRONG password (hostapd keeps the
# right one). Success then means the join is cleanly rejected (no crash /
# no hang / no false AUTHENTICATED).
if [ -n "${WOLFIP_SAE_BADPW:-}" ]; then
    STA_PW="wrongPassword-$$"
    note "NEGATIVE test: supplicant uses a wrong password"
else
    STA_PW="$PSK"
fi

note "running SoftMAC SAE supplicant test on $STA_IF"
set +e
WOLFIP_SAE_H2E="$WOLFIP_SAE_H2E" WOLFIP_SAE_GROUP="${WOLFIP_SAE_GROUP:-19}" \
    "$TEST_BIN" "$STA_IF" "$SSID" "$STA_PW" "$AP_MAC" 2412
TEST_RC=$?
set -e

if [ -n "${WOLFIP_SAE_BADPW:-}" ]; then
    if [ "$TEST_RC" -ne 0 ]; then
        note "PASS: wrong password rejected cleanly (rc=$TEST_RC, not AUTHENTICATED)"
        exit 0
    fi
    note "FAIL: supplicant AUTHENTICATED with a wrong password!"
    exit 1
fi

echo "--- hostapd log (grep) ---"
grep -E "SAE|wpa_auth|EAPOL|WPA|Phase|STA |key handshake|AUTH" "$HOSTAPD_LOG" \
    | tail -80
echo "--------------------------"
exit $TEST_RC

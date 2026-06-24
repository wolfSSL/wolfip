#!/bin/bash
# run_hwsim_wolfsta_dhcp_test.sh
#
# End-to-end wolfsta test over a mac80211_hwsim radio pair: the wolfsta
# host app (wolfIP + wolfSupplicant) joins a hostapd AP (WPA3-SAE by
# default, or WPA2-PSK), obtains a DHCP lease over the encrypted link
# (dnsmasq on the AP), and the link is then exercised two ways:
#   - external `ping` of the leased IP        (tests wolfIP's ICMP responder)
#   - wolfsta's own UDP echo probe to the AP   (tests wolfIP UDP client)
#
# Success gate = DHCP lease obtained. Ping + UDP echo are reported as
# additional signals. This validates the full stack (SAE/4-way + key
# install + wolfIP DHCP/ARP/ICMP/UDP) with no Wi-Fi hardware; the same
# wolfsta binary then drives a real SoftMAC USB card unchanged.
#
# Requires: root, mac80211_hwsim, hostapd, dnsmasq, socat, iw, libnl-genl-3,
# and a wolfSSL with WOLFSSL_PUBLIC_MP (for SAE).
#
# Env:
#   AUTH=sae|psk          auth mode (default sae)
#   WOLFIP_SAE_H2E=1      SAE H2E (sae_pwe=2) instead of H&P (sae only)

set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AUTH="${AUTH:-sae}"
SSID="${SSID:-wolfIP-STA}"
PSK="${PSK:-ThisIsAPassword!}"
AP_IP="${AP_IP:-192.168.4.1}"
ECHO_PORT="${ECHO_PORT:-7777}"
HOSTAPD_CONF="/tmp/wolfip_wolfsta_hostapd.conf"
HOSTAPD_LOG="/tmp/wolfip_wolfsta_hostapd.log"
WOLFSTA_LOG="/tmp/wolfip_wolfsta.log"
WOLFIP_SAE_H2E="${WOLFIP_SAE_H2E:-0}"
case "$WOLFIP_SAE_H2E" in 1) SAE_PWE_MODE=2 ;; *) SAE_PWE_MODE=0 ;; esac

die()  { echo "ERROR: $*" >&2; exit 1; }
note() { echo "[wolfsta-dhcp] $*"; }

[ "$(id -u)" -eq 0 ] || die "run as root"
for t in hostapd dnsmasq socat iw; do
    command -v "$t" >/dev/null 2>&1 || die "$t not installed"
done
[ -x "$REPO_ROOT/build/wolfsta" ] || die "build/wolfsta not built (make wolfsta)"

HOSTAPD_PID=""; DNSMASQ_PID=""; SOCAT_PID=""; WOLFSTA_PID=""
cleanup() {
    set +e
    for p in "$WOLFSTA_PID" "$SOCAT_PID" "$DNSMASQ_PID" "$HOSTAPD_PID"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null
    done
    wait 2>/dev/null
    [ -n "${AP_IF:-}" ] && ip addr flush dev "$AP_IF" 2>/dev/null
    rmmod mac80211_hwsim 2>/dev/null
    rm -f "$HOSTAPD_CONF"
    rm -rf /tmp/wolfip_hostapd_ctrl
}
trap cleanup EXIT INT TERM

rmmod mac80211_hwsim 2>/dev/null || true
modprobe mac80211_hwsim radios=2 || die "modprobe failed"
sleep 0.3

PHYS=( $(ls /sys/class/ieee80211/) )
[ "${#PHYS[@]}" -ge 2 ] || die "expected >=2 phys"
AP_PHY="${PHYS[-2]}"; STA_PHY="${PHYS[-1]}"
AP_IF=$(ls /sys/class/ieee80211/$AP_PHY/device/net/ | head -1)
STA_IF=$(ls /sys/class/ieee80211/$STA_PHY/device/net/ | head -1)
note "AUTH=$AUTH  AP=$AP_IF ($AP_PHY)  STA=$STA_IF ($STA_PHY)"
iw dev "$STA_IF" set type managed 2>/dev/null || true
ip link set "$AP_IF" up
ip link set "$STA_IF" up
ip addr flush dev "$STA_IF" 2>/dev/null   # wolfIP owns L3 on the STA

# Build the hostapd config for the chosen auth mode.
if [ "$AUTH" = "psk" ]; then
    sed -e "s|@IFACE@|$AP_IF|g" -e "s|@SSID@|$SSID|g" -e "s|@PSK@|$PSK|g" \
        "$REPO_ROOT/tools/hostapd/hostapd_psk_hwsim.conf.template" > "$HOSTAPD_CONF"
    STA_MODE=psk
else
    sed -e "s|@IFACE@|$AP_IF|g" -e "s|@SSID@|$SSID|g" -e "s|@PSK@|$PSK|g" \
        -e "s|@SAE_PWE@|$SAE_PWE_MODE|g" \
        "$REPO_ROOT/tools/hostapd/hostapd_sae_hwsim.conf.template" > "$HOSTAPD_CONF"
    STA_MODE=sae
fi

note "starting hostapd"
hostapd -t "$HOSTAPD_CONF" >"$HOSTAPD_LOG" 2>&1 &
HOSTAPD_PID=$!
sleep 1
kill -0 "$HOSTAPD_PID" 2>/dev/null || { cat "$HOSTAPD_LOG"; die "hostapd died"; }
AP_MAC=$(cat "/sys/class/net/$AP_IF/address")

# AP-side IP + DHCP server + UDP echo server.
ip addr add "$AP_IP/24" dev "$AP_IF"
dnsmasq --no-daemon --interface="$AP_IF" --bind-interfaces \
        --dhcp-range="192.168.4.50,192.168.4.150,255.255.255.0,2m" \
        --dhcp-authoritative --no-resolv --no-hosts \
        --pid-file=/tmp/wolfip_dnsmasq.pid >/tmp/wolfip_dnsmasq.log 2>&1 &
DNSMASQ_PID=$!
socat UDP4-RECVFROM:"$ECHO_PORT",fork,reuseaddr EXEC:/bin/cat >/dev/null 2>&1 &
SOCAT_PID=$!
note "hostapd up BSSID=$AP_MAC; dnsmasq + socat echo on $AP_IP:$ECHO_PORT"
sleep 1

note "running wolfsta on $STA_IF (mode=$STA_MODE)"
WOLFIP_SAE_H2E="$WOLFIP_SAE_H2E" WOLFSTA_ECHO="$AP_IP:$ECHO_PORT" \
    WOLFSTA_HOLD_SECS=12 \
    "$REPO_ROOT/build/wolfsta" "$STA_IF" "$SSID" "$STA_MODE" "$PSK" \
    "$AP_MAC" 2412 19 >"$WOLFSTA_LOG" 2>&1 &
WOLFSTA_PID=$!

# Wait for the DHCP lease line.
LEASE_IP=""; waited=0
while [ "$waited" -lt 25 ]; do
    LEASE_IP=$(grep -aoE 'DHCP bound: ip=[0-9.]+' "$WOLFSTA_LOG" 2>/dev/null \
               | head -1 | sed 's/.*ip=//')
    [ -n "$LEASE_IP" ] && break
    kill -0 "$WOLFSTA_PID" 2>/dev/null || break
    sleep 1; waited=$((waited+1))
done

RC=1
if [ -n "$LEASE_IP" ]; then
    note "DHCP lease obtained: $LEASE_IP"
    RC=0
    if ping -c 2 -W 2 "$LEASE_IP" >/dev/null 2>&1; then
        note "PASS: ping $LEASE_IP (wolfIP ICMP responder OK)"
    else
        note "WARN: no ping reply from $LEASE_IP"
    fi
    sleep 2
    if grep -aq 'UDP echo OK' "$WOLFSTA_LOG"; then
        note "PASS: wolfsta UDP echo OK (wolfIP UDP client OK)"
    else
        note "WARN: wolfsta UDP echo not confirmed"
    fi
else
    note "FAIL: no DHCP lease"
fi

echo "--- wolfsta log ---"; grep -aE '\[wolfsta\]|\[nl80211_sta\]' "$WOLFSTA_LOG" | tail -20
echo "-------------------"
exit $RC

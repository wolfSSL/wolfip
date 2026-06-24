#!/bin/bash
# End-to-end wolfIP + wolfSupplicant over a REAL SoftMAC radio: join an AP
# (WPA3-SAE or WPA2-PSK), run the 4-way, install keys in the kernel, then bring
# up wolfIP's own L3 (DHCP lease + UDP echo) over AF_PACKET on the same netdev.
# Any AP works; the reference bench is a TP-Link TL-WN722N v1 (AR9271 /
# ath9k_htc) STA and a Raspberry Pi 5 hostapd AP with dnsmasq (DHCP) and a UDP
# echo server - see the "Real hardware validation" section of
# tools/hostapd/README.md.
#
# Passes when the log shows "DHCP bound: ip=" and "UDP echo OK". Needs root.
#
# Usage: sudo ./run_realcard_wolfsta_test.sh [IFACE]
#   IFACE              STA netdev (auto-detected from the SoftMAC radio if omitted)
# Environment (all optional):
#   SSID PSK           AP credentials (default wolfIP-RT / ThisIsAPassword!)
#   MODE               sae (default) or psk
#   BSSID FREQ         AP BSSID / channel freq in MHz (auto-discovered by scan)
#   APIP ECHO_PORT     AP IP and UDP echo port to probe (default 192.168.50.1 7777)
#   WOLFIP_SAE_H2E     1 = Hash-to-Element (default), 0 = hunt-and-peck (SAE only)
#   WOLFIP_SAE_GROUP   SAE ECC group 19/20/21 (default 19)
#   WOLFSTA_HOLD_SECS  seconds to keep the link up after the probe (default 12)
set -u
D="$(cd "$(dirname "$0")" && pwd)"; R="$(cd "$D/../.." && pwd)"
. "$D/realcard_common.sh"

case "${1:-}" in -h|--help) sed -n '2,22p' "$0"; exit 0;; esac

SSID="${SSID:-wolfIP-RT}"; PSK="${PSK:-ThisIsAPassword!}"; MODE="${MODE:-sae}"
H2E="${WOLFIP_SAE_H2E:-1}"; GROUP="${WOLFIP_SAE_GROUP:-19}"
APIP="${APIP:-192.168.50.1}"; ECHO_PORT="${ECHO_PORT:-7777}"
HOLD="${WOLFSTA_HOLD_SECS:-12}"
BIN="$R/build/wolfsta"
[ -x "$BIN" ] || rc_die "missing $BIN (run: make build/wolfsta)"

IF="$(rc_iface "${1:-}")" || rc_die "no SoftMAC STA iface found; pass IFACE or set IF"
rc_bring_up "$IF"
SCAN="$(rc_scan "$IF" "$SSID")" \
    || rc_die "SSID '$SSID' not found in scan; set BSSID and FREQ explicitly"
BSSID="${SCAN%% *}"; FREQ="${SCAN##* }"
LOG="$(mktemp /tmp/wolfsta-realcard.XXXXXX.log)"

rc_note "IF=$IF SSID=$SSID MODE=$MODE BSSID=$BSSID FREQ=$FREQ ECHO=$APIP:$ECHO_PORT"
# wolfsta CLI: <if> <ssid> <mode> <secret> <bssid> [freq] [sae_group].
# The post-DHCP echo target and the linger time come from the environment.
env WOLFIP_SAE_H2E="$H2E" WOLFSTA_ECHO="$APIP:$ECHO_PORT" \
    WOLFSTA_HOLD_SECS="$HOLD" \
    "$BIN" "$IF" "$SSID" "$MODE" "$PSK" "$BSSID" "$FREQ" "$GROUP" \
    >"$LOG" 2>&1
echo "---- $LOG ----"; tail -n 40 "$LOG"
if grep -q "DHCP bound: ip=" "$LOG" && grep -q "UDP echo OK" "$LOG"; then
    rc_note "PASS"; exit 0
fi
rc_note "FAIL"; exit 1

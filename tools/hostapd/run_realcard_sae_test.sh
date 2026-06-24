#!/bin/bash
# Drive the wolfSupplicant WPA3-SAE STA over a REAL SoftMAC radio against an
# external WPA3-SAE access point. Any SAE-capable AP works; the reference bench
# is a TP-Link TL-WN722N v1 (Atheros AR9271 / ath9k_htc) STA and a Raspberry Pi
# 5 hostapd AP - see the "Real hardware validation" section of
# tools/hostapd/README.md for card identification and a generic AP setup.
#
# Reaches AUTHENTICATED (SAE Commit/Confirm + 4-way + key install) and exits
# non-zero on failure. Needs root (rfkill / nl80211 / AF_PACKET).
#
# Usage: sudo ./run_realcard_sae_test.sh [IFACE]
#   IFACE              STA netdev (auto-detected from the SoftMAC radio if omitted)
# Environment (all optional):
#   SSID PSK           AP credentials (default wolfIP-RT / ThisIsAPassword!)
#   BSSID FREQ         AP BSSID / channel freq in MHz (auto-discovered by scan)
#   WOLFIP_SAE_H2E     1 = Hash-to-Element (default), 0 = hunt-and-peck
#   WOLFIP_SAE_GROUP   SAE ECC group 19/20/21 (default 19)
set -u
D="$(cd "$(dirname "$0")" && pwd)"; R="$(cd "$D/../.." && pwd)"
. "$D/realcard_common.sh"

case "${1:-}" in -h|--help) sed -n '2,18p' "$0"; exit 0;; esac

SSID="${SSID:-wolfIP-RT}"; PSK="${PSK:-ThisIsAPassword!}"
H2E="${WOLFIP_SAE_H2E:-1}"; GROUP="${WOLFIP_SAE_GROUP:-19}"
# Radio-agnostic binary; the "hwsim" in the name is historical.
BIN="$R/build/test-supplicant-hwsim-sae-softmac"
[ -x "$BIN" ] || rc_die "missing $BIN (run: make build/$(basename "$BIN"))"

IF="$(rc_iface "${1:-}")" || rc_die "no SoftMAC STA iface found; pass IFACE or set IF"
rc_bring_up "$IF"
SCAN="$(rc_scan "$IF" "$SSID")" \
    || rc_die "SSID '$SSID' not found in scan; set BSSID and FREQ explicitly"
BSSID="${SCAN%% *}"; FREQ="${SCAN##* }"

rc_note "IF=$IF SSID=$SSID BSSID=$BSSID FREQ=$FREQ H2E=$H2E GROUP=$GROUP"
exec env WOLFIP_SAE_H2E="$H2E" WOLFIP_SAE_GROUP="$GROUP" \
    "$BIN" "$IF" "$SSID" "$PSK" "$BSSID" "$FREQ"

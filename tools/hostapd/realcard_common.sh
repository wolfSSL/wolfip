#!/bin/bash
# Shared helpers for the run_realcard_*.sh SoftMAC test runners.
# This file is meant to be sourced, not executed directly.

rc_die()  { echo "[realcard] error: $*" >&2; exit 1; }
rc_note() { echo "[realcard] $*"; }

# Resolve the SoftMAC STA netdev: use $1 (CLI arg) or $IF if given, otherwise
# the first ath9k_htc / rtl8xxxu / mt76 radio under /sys/class/ieee80211.
# Echoes the interface name; returns non-zero if none is found.
rc_iface() {
    local want="${1:-${IF:-}}" p drv
    if [ -n "$want" ]; then echo "$want"; return 0; fi
    for p in /sys/class/ieee80211/*; do
        drv=$(basename "$(readlink -f "$p/device/driver" 2>/dev/null)" \
              2>/dev/null)
        case "$drv" in
            ath9k_htc|rtl8xxxu|mt76*)
                ls "$p/device/net/" 2>/dev/null | head -1; return 0;;
        esac
    done
    return 1
}

# Put the interface in managed mode and bring it up. wolfIP owns L3 on this
# netdev, so flush any kernel-assigned addresses.
rc_bring_up() {
    rfkill unblock wifi 2>/dev/null || true
    iw dev "$1" set type managed 2>/dev/null || true
    ip link set "$1" up || rc_die "cannot bring $1 up (run as root)"
    ip addr flush dev "$1" 2>/dev/null || true
}

# Discover "<bssid> <freq_mhz>" for SSID $2 on interface $1 by scanning (a few
# retries, since the first scan after bring-up can come back empty). A preset
# $BSSID / $FREQ in the environment overrides the scanned value for that field.
# Echoes "bssid freq"; returns non-zero if the SSID is not found and no BSSID
# was preset.
rc_scan() {
    local ifc="$1" ssid="$2" out bss freq tries
    out=""
    for tries in 1 2 3; do
        out=$(iw dev "$ifc" scan 2>/dev/null | awk -v s="$ssid" '
            /^BSS/         { b=$2; sub(/\(.*/, "", b) }
            /^[ \t]*freq:/ { f=$2 }
            /^[ \t]*SSID:/ { n=$0; sub(/^[ \t]*SSID:[ \t]?/, "", n);
                             if (n == s) { print b, f; exit } }')
        [ -n "$out" ] && break
        sleep 1
    done
    bss="${BSSID:-$(echo "$out" | awk '{print $1}')}"
    freq="${FREQ:-$(echo "$out" | awk '{print $2}')}"
    [ -n "$bss" ] || return 1
    [ -n "$freq" ] || freq=2462
    echo "$bss $freq"
}

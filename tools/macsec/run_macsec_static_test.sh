#!/bin/bash
# run_macsec_static_test.sh
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# Byte-level interop between the wolfIP software SecY and the Linux kernel
# MACsec module, using a static (pre-shared) SAK - no MKA, no wpa_supplicant.
# Proves the wolfIP 802.1AE framing (SecTAG layout, SCI||PN nonce,
# DA||SA||SecTAG AAD, GCM-AES-128) matches the kernel byte for byte, in both
# directions:
#
#   1. kernel -> wolfIP: the kernel encrypts a frame; macsec-probe validates
#      it and recovers the plaintext MSDU.
#   2. wolfIP -> kernel: macsec-probe protects a frame; it is injected on the
#      wire and the kernel's InPktsOK counter must increment.
#
# Requires root (network namespaces + kernel macsec). Run on Linux:
#   sudo WOLFSSL_PREFIX=/path/to/wolfssl bash tools/macsec/run_macsec_static_test.sh
#
# The build/macsec-probe binary must exist (make WOLFIP_ENABLE_MACSEC=1
# build/macsec-probe).

set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROBE="$REPO_ROOT/build/macsec-probe"

NS_K="mk-kern"
NS_W="mk-wolf"
VETH_K="mkv-k"
VETH_W="mkv-w"

# Static test vectors.
SAK="ad7a2bd03eac835a6f620fdcb506b345"          # GCM-AES-128 SAK
KEY_ID_TX="01"
KEY_ID_RX="02"
WOLF_SCI="0200000000330001"                       # SCI wolfIP uses for TX
WOLF_MAC="020000000033"

PASS=0
FAIL=0

log()  { echo "[macsec-static] $*"; }
ok()   { echo "  [OK]   $*"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

cleanup() {
    ip netns del "$NS_K" 2>/dev/null
    ip netns del "$NS_W" 2>/dev/null
}
trap cleanup EXIT INT TERM

if [ "$(id -u)" != "0" ]; then
    echo "must run as root (network namespaces + kernel macsec)" >&2
    exit 1
fi
if [ ! -x "$PROBE" ]; then
    echo "missing $PROBE - run: make WOLFIP_ENABLE_MACSEC=1 build/macsec-probe" >&2
    exit 1
fi
if ! modprobe macsec 2>/dev/null && ! lsmod | grep -q '^macsec'; then
    echo "kernel macsec module unavailable" >&2
    exit 1
fi

cleanup
set -e
ip netns add "$NS_K"
ip netns add "$NS_W"
ip link add "$VETH_K" netns "$NS_K" type veth peer name "$VETH_W" netns "$NS_W"
ip -n "$NS_K" link set "$VETH_K" up
ip -n "$NS_W" link set "$VETH_W" up

# Kernel MACsec device on the kernel side, full encryption, static TX SA.
ip -n "$NS_K" link add link "$VETH_K" macsec0 type macsec encrypt on
ip -n "$NS_K" macsec add macsec0 tx sa 0 pn 1 on key "$KEY_ID_TX" "$SAK"
# RX SC/SA for the wolfIP peer (for the reverse direction).
ip -n "$NS_K" macsec add macsec0 rx sci "$WOLF_SCI" on
ip -n "$NS_K" macsec add macsec0 rx sci "$WOLF_SCI" sa 0 pn 1 on key "$KEY_ID_RX" "$SAK"
ip -n "$NS_K" link set macsec0 up
ip -n "$NS_K" addr add 10.9.9.1/24 dev macsec0
set +e

# Kernel's own SCI = veth-k MAC || port 0001.
KMAC=$(ip -n "$NS_K" link show "$VETH_K" | awk '/link\/ether/{print $2}' | tr -d ':')
KSCI="${KMAC}0001"
log "kernel SCI=$KSCI  wolfIP SCI=$WOLF_SCI"

# ---- Direction 1: kernel -> wolfIP ----
log "capturing a kernel-encrypted frame..."
CAP=$(mktemp)
ip netns exec "$NS_W" timeout 4 tcpdump -i "$VETH_W" -c1 -xx -nn 'ether proto 0x88e5' \
    > "$CAP" 2>/dev/null &
TCPD=$!
sleep 0.5
# Trigger traffic through macsec0 (ARP for the unused .2 goes out encrypted).
ip -n "$NS_K" neigh flush all 2>/dev/null
ip netns exec "$NS_K" ping -c2 -W1 10.9.9.2 >/dev/null 2>&1
wait "$TCPD" 2>/dev/null
FRAME=$(grep '0x' "$CAP" | sed 's/^.*: //; s/ //g' | tr -d '\n')
rm -f "$CAP"

if [ -z "$FRAME" ]; then
    bad "no kernel MACsec frame captured"
else
    log "captured frame: ${FRAME:0:48}... (${#FRAME} hex chars)"
    OUT=$("$PROBE" validate "$SAK" "$KSCI" 0 "$FRAME")
    if [ "$OUT" != "FAIL" ] && [ -n "$OUT" ]; then
        ok "wolfIP validated a kernel-encrypted frame (MSDU=${OUT:0:16}...)"
    else
        bad "wolfIP could not validate the kernel frame"
    fi
fi

# Sum every InPktsOK counter in `ip -s macsec show`. The output is a
# two-line format: a "stats:" header line of labels, then a line of values.
# Find InPktsOK's column in the header (the value line lacks the leading
# "stats:" token, hence the -1) and read that column from the next line.
macsec_inpktsok() {
    ip -n "$NS_K" -s macsec show 2>/dev/null | awk '
        $1 == "stats:" {
            col = 0;
            for (i = 2; i <= NF; i++) if ($i == "InPktsOK") col = i - 1;
            if (getline == 1 && col > 0) s += $col;
            next;
        }
        END { print s + 0 }'
}

# ---- Direction 2: wolfIP -> kernel ----
log "protecting a frame with wolfIP and injecting it..."
# Inner MSDU: an ARP-shaped payload is fine; the kernel just needs to
# authenticate + decrypt and count it. DA must be the kernel veth MAC.
KMAC_COLON=$(ip -n "$NS_K" link show "$VETH_K" | awk '/link\/ether/{print $2}')
DA_HEX=$(echo "$KMAC_COLON" | tr -d ':')
PAYLOAD="0800450000200001000040007ce70a0909020a090901"   # dummy IPv4-ish
WFRAME=$("$PROBE" protect "$SAK" "$WOLF_SCI" 0 1 1 0 "$DA_HEX" "$WOLF_MAC" "$PAYLOAD")

BEFORE=$(macsec_inpktsok)
ip netns exec "$NS_W" python3 - "$VETH_W" "$WFRAME" <<'PY' 2>/dev/null
import socket, sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((sys.argv[1], 0))
s.send(bytes.fromhex(sys.argv[2]))
PY
sleep 0.5
AFTER=$(macsec_inpktsok)
if [ "$AFTER" -gt "$BEFORE" ]; then
    ok "kernel accepted a wolfIP-protected frame (InPktsOK $BEFORE -> $AFTER)"
else
    bad "kernel did not accept the wolfIP frame (InPktsOK $BEFORE -> $AFTER)"
    log "diagnostic: kernel RXSC stats:"
    ip -n "$NS_K" -s macsec show 2>/dev/null | sed 's/^/    /'
fi

echo
if [ "$FAIL" -eq 0 ]; then
    echo "PASS: macsec static interop ($PASS checks)"
    exit 0
else
    echo "FAIL: macsec static interop ($FAIL of $((PASS+FAIL)) checks failed)"
    exit 1
fi

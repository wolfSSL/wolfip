#!/bin/bash
# run_hostapd_test.sh
#
# Drive the wolfIP supplicant against a real hostapd EAP server over a
# Linux veth pair. Validates EAP-TLS framing, identity exchange, TLS
# handshake, and EAP-Success against a non-wolfSSL implementation.
#
# Requires:
#   - hostapd installed (apt install hostapd)
#   - root (or CAP_NET_ADMIN + CAP_NET_RAW) for veth + raw socket
#   - openssl (used by the test binary to mint certs into
#     /tmp/wolfip_eap_certs/)
#
# Cleanup is best-effort: hostapd is killed, the veth pair is removed.

set -u

# MODE selects the hostapd config / test binary. Default "eaptls" uses
# the EAP-TLS path. "psk" uses WPA2-PSK to exercise the 4-way handshake.
MODE="${MODE:-eaptls}"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# Two ends of a veth pair: hostapd binds to the AUTH side, our supplicant
# binds to the SUPP side. Frames sent on one peer arrive as RX on the
# other - which is what AF_PACKET sockets need to actually exchange
# packets (a single TAP doesn't loop back between two AF_PACKET sockets).
AUTH_IF="${AUTH_IF:-wolfip-auth}"
SUPP_IF="${SUPP_IF:-wolfip-supp}"
# Pin the supplicant-side MAC so hostapd_cli new_sta uses the same value
# the test binary reads from SIOCGIFHWADDR. Without a fixed MAC, the
# veth gets a random LAA each boot and the PTK derivation would diverge
# from hostapd's.
SUPP_MAC="${SUPP_MAC:-02:00:00:00:00:22}"
PSK_SSID="${PSK_SSID:-wolfIP-PSKNet}"
PSK_PASS="${PSK_PASS:-ThisIsAPassword!}"
CERT_DIR="${CERT_DIR:-/tmp/wolfip_eap_certs}"
USER_FILE="${USER_FILE:-/tmp/wolfip_eap_users}"
HOSTAPD_CONF="${HOSTAPD_CONF:-/tmp/wolfip_hostapd.conf}"
HOSTAPD_LOG="${HOSTAPD_LOG:-/tmp/wolfip_hostapd.log}"

case "$MODE" in
    eaptls) TEST_BIN_DEFAULT="$REPO_ROOT/build/test-supplicant-hostapd"
            CONF_TEMPLATE="$REPO_ROOT/tools/hostapd/hostapd.conf.template"
            EAP_USERS_SRC="$REPO_ROOT/tools/hostapd/eap_users" ;;
    psk)    TEST_BIN_DEFAULT="$REPO_ROOT/build/test-supplicant-hostapd-psk"
            CONF_TEMPLATE="$REPO_ROOT/tools/hostapd/hostapd_psk.conf.template" ;;
    peap)   TEST_BIN_DEFAULT="$REPO_ROOT/build/test-supplicant-hostapd-peap"
            CONF_TEMPLATE="$REPO_ROOT/tools/hostapd/hostapd.conf.template"
            EAP_USERS_SRC="$REPO_ROOT/tools/hostapd/eap_users_peap" ;;
    *)      echo "ERROR: unknown MODE=$MODE (eaptls|psk|peap)" >&2; exit 2 ;;
esac
TEST_BIN="${TEST_BIN:-$TEST_BIN_DEFAULT}"

die()  { echo "ERROR: $*" >&2; exit 1; }
note() { echo "[run_hostapd_test] mode=$MODE $*"; }

# Sanity.
command -v hostapd >/dev/null 2>&1 \
  || die "hostapd not in PATH. Install with: sudo apt install -y hostapd"
[ -x "$TEST_BIN" ] || die "$TEST_BIN not built. Build the appropriate test binary first"
[ "$(id -u)" -eq 0 ] || die "run as root (sudo) - need veth + raw socket"

cleanup() {
    set +e
    if [ -n "${HOSTAPD_PID:-}" ]; then
        note "killing hostapd pid=$HOSTAPD_PID"
        kill "$HOSTAPD_PID" 2>/dev/null
        wait "$HOSTAPD_PID" 2>/dev/null
    fi
    # Deleting one end of a veth pair also removes its peer.
    ip link delete "$AUTH_IF" 2>/dev/null || true
    rm -f "$HOSTAPD_CONF" "$USER_FILE"
    rm -rf /tmp/wolfip_hostapd_ctrl
}
trap cleanup EXIT INT TERM

if [ "$MODE" = "eaptls" ] || [ "$MODE" = "peap" ]; then
    # Mint test certs by running the engine test once (idempotent).
    if [ ! -f "$CERT_DIR/ca.crt" ]; then
        note "generating certs via engine test"
        "$REPO_ROOT/build/test-eap-tls-engine" >/dev/null
    fi
    cp "$EAP_USERS_SRC" "$USER_FILE"

    sed -e "s|@IFACE@|$AUTH_IF|g" \
        -e "s|@USER_FILE@|$USER_FILE|g" \
        -e "s|@CA_CERT@|$CERT_DIR/ca.crt|g" \
        -e "s|@SERVER_CERT@|$CERT_DIR/server.crt|g" \
        -e "s|@SERVER_KEY@|$CERT_DIR/server.key|g" \
        "$CONF_TEMPLATE" > "$HOSTAPD_CONF"
else
    # Dummy EAP user file (PSK path won't consult it, but the validator
    # demands it when ieee8021x=1).
    cp "$REPO_ROOT/tools/hostapd/eap_users" "$USER_FILE"
    sed -e "s|@IFACE@|$AUTH_IF|g" \
        -e "s|@SSID@|$PSK_SSID|g" \
        -e "s|@PSK@|$PSK_PASS|g" \
        -e "s|@USER_FILE@|$USER_FILE|g" \
        "$CONF_TEMPLATE" > "$HOSTAPD_CONF"
fi

# Clean any leftover veth from a previous failed run.
ip link delete "$AUTH_IF" 2>/dev/null || true

# Create the veth pair and bring both ends up.
ip link add "$AUTH_IF" type veth peer name "$SUPP_IF"
# Pin the SUPP-side MAC so test_supplicant_hostapd_psk and hostapd_cli
# new_sta agree on the value used in PTK derivation.
ip link set "$SUPP_IF" address "$SUPP_MAC"
ip link set "$AUTH_IF" up
ip link set "$SUPP_IF" up
note "veth $AUTH_IF <-> $SUPP_IF up (supp MAC=$SUPP_MAC)"

# Launch hostapd on the AUTH side in the background. -t prepends ts;
# -dd raises log level (verbose debug) for PSK diagnostics.
note "starting hostapd on $AUTH_IF"
HOSTAPD_FLAGS="-t"
[ "$MODE" = "psk" ]  && HOSTAPD_FLAGS="-t -dd"
[ "$MODE" = "peap" ] && HOSTAPD_FLAGS="-t -dd"
hostapd $HOSTAPD_FLAGS "$HOSTAPD_CONF" >"$HOSTAPD_LOG" 2>&1 &
HOSTAPD_PID=$!
sleep 1
if ! kill -0 "$HOSTAPD_PID" 2>/dev/null; then
    echo "--- hostapd log ---"
    cat "$HOSTAPD_LOG"
    echo "-------------------"
    HOSTAPD_PID=""
    die "hostapd died on startup"
fi
note "hostapd pid=$HOSTAPD_PID"

# Look up the hostapd-side MAC (PSK test needs it for PTK derivation).
AUTH_MAC=$(cat "/sys/class/net/$AUTH_IF/address")
note "hostapd-side MAC: $AUTH_MAC"

# Run the test binary on the SUPP side. It will open AF_PACKET there
# and drive the supplicant.
note "running supplicant test on $SUPP_IF"
set +e
if [ "$MODE" = "eaptls" ] || [ "$MODE" = "peap" ]; then
    "$TEST_BIN" "$SUPP_IF"
    TEST_RC=$?
else
    # PSK: the test binary itself preloads hostapd's PMKSA cache and
    # issues NEW_STA via the control socket; we just run it in the
    # foreground.
    "$TEST_BIN" "$SUPP_IF" "$PSK_SSID" "$PSK_PASS" "$AUTH_MAC"
    TEST_RC=$?
fi
set -e

# Always print hostapd log for postmortem.
echo "--- hostapd log ---"
cat "$HOSTAPD_LOG"
echo "-------------------"

exit $TEST_RC

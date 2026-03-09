#!/bin/bash
#
# wolfIP STM32H563 Trade Show Demo Script
#
# Demonstrates HTTPS server, SSH server, and MQTT broker running on
# a bare-metal Cortex-M33 with wolfIP + wolfSSL + wolfSSH + wolfMQTT.
#
# Usage: ./demo.sh [--auto] [board-ip]
#   --auto    Skip pauses and interactive prompts (for automated testing)
#   board-ip defaults to 192.168.12.11
#

AUTO=0
if [[ "$1" == "--auto" ]]; then
    AUTO=1
    shift
fi
BOARD_IP="${1:-192.168.12.11}"

# wolfMQTT client binary (override with MQTTCLIENT env var)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
MQTTCLIENT="${MQTTCLIENT:-${REPO_ROOT}/../wolfmqtt/examples/mqttclient/mqttclient}"
if [[ ! -x "$MQTTCLIENT" ]]; then
    echo "Error: wolfMQTT client not found at: $MQTTCLIENT" >&2
    echo "  Build wolfMQTT or set MQTTCLIENT=/path/to/mqttclient" >&2
    exit 1
fi

# Validate BOARD_IP to block shell metacharacter injection into constructed shell commands (e.g. via bash -c)
if [[ "$BOARD_IP" == -* ]] || ! [[ "$BOARD_IP" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "Error: Invalid board IP/hostname: $BOARD_IP" >&2
    exit 1
fi

# Colors
BLD='\033[1m'
DIM='\033[2m'
CYN='\033[1;36m'
GRN='\033[1;32m'
YLW='\033[1;33m'
MAG='\033[1;35m'
RED='\033[1;31m'
RST='\033[0m'

# TLS certificate (self-signed ECC P-256, embedded in firmware)
CERT_FILE=$(mktemp /tmp/wolfip_cert.XXXXXX.pem)
cat > "$CERT_FILE" << 'CERTEOF'
-----BEGIN CERTIFICATE-----
MIIByTCCAW+gAwIBAgIUW3k96+M3BtW7CJRDEO/u5BaaGjgwCgYIKoZIzj0EAwIw
OjEZMBcGA1UEAwwQd29sZklQLVNUTTMySDU2MzEQMA4GA1UECgwHd29sZlNTTDEL
MAkGA1UEBhMCVVMwHhcNMjYwMTIwMTgwMjU0WhcNMzYwMTE4MTgwMjU0WjA6MRkw
FwYDVQQDDBB3b2xmSVAtU1RNMzJINTYzMRAwDgYDVQQKDAd3b2xmU1NMMQswCQYD
VQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIIoRSUxD9kkXV67s06t
7yjcC7TZMIvoCwg8AJLFn/lcy9QklySeAkgWWXJrUHTM0XPYhqX9BRjF9aT4AdJ7
RTyjUzBRMB0GA1UdDgQWBBRxfBfKe/Ew5d8SArakH1z9DjxK9jAfBgNVHSMEGDAW
gBRxfBfKe/Ew5d8SArakH1z9DjxK9jAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
BAMCA0gAMEUCIEUB8ArsbYI58PGtcy9KIdR6A3z5KCQblTXZWnIE7EDUAiEA8Oyi
LwVAHQ4M2+TcVwe4LQ+xG9F6uSmu4t/psG0IT+s=
-----END CERTIFICATE-----
CERTEOF
trap "rm -f $CERT_FILE /tmp/wolfip_sub.*" EXIT

banner() {
    echo ""
    echo -e "${CYN}================================================================${RST}"
    echo -e "${CYN}  $1${RST}"
    echo -e "${CYN}================================================================${RST}"
    echo ""
}

step() {
    echo -e "  ${YLW}>>>${RST} ${BLD}$1${RST}"
}

cmd_show() {
    echo -e "  ${DIM}\$ $1${RST}"
}

pause() {
    if [[ $AUTO -eq 1 ]]; then
        sleep 1
        return
    fi
    echo ""
    echo -ne "  ${DIM}[Press Enter to continue]${RST}"
    read -r
    echo ""
}

run_cmd() {
    cmd_show "$1"
    echo ""
    bash -c "$1" 2>&1 | sed 's/^/    /'
    echo ""
}

# ---------------------------------------------------------------------------
clear
echo ""
echo -e "${BLD}${CYN}"
cat << 'LOGO'
                 _  __ ___ ____
   __      ___  | |/ _|_ _|  _ \
   \ \ /\ / / _ \ | |_ | || |_) |
    \ V  V / (_) | |  _|| ||  __/
     \_/\_/ \___/|_|_| |___|_|
LOGO
echo -e "${RST}"
echo -e "  ${BLD}Embedded TCP/IP Stack on STM32H563 (Cortex-M33)${RST}"
echo -e "  ${DIM}wolfSSL | wolfSSH | wolfMQTT | TLS 1.3 | Bare Metal${RST}"
echo ""
echo -e "  Board IP:  ${GRN}${BOARD_IP}${RST}"
echo -e "  Services:  HTTPS :443  |  SSH :22  |  MQTT :8883"
echo ""

pause

# ---------------------------------------------------------------------------
# 1) PING
# ---------------------------------------------------------------------------
banner "1. Network Connectivity"

step "Verify the board is reachable"
run_cmd "ping -c 3 -W 1 ${BOARD_IP}"

pause

# ---------------------------------------------------------------------------
# 2) TCP Echo
# ---------------------------------------------------------------------------
banner "2. TCP Echo Server (Port 7)"

step "Send a message to the plaintext echo server"
run_cmd "echo 'Hello wolfIP!' | nc -w 2 ${BOARD_IP} 7"

pause

# ---------------------------------------------------------------------------
# 3) HTTPS Server
# ---------------------------------------------------------------------------
banner "3. HTTPS Web Server (Port 443) - TLS 1.3"

step "Fetch the status page and inspect TLS 1.3 handshake"
cmd_show "curl -vs --cacert cert.pem --resolve wolfIP-STM32H563:443:${BOARD_IP} --max-time 10 https://wolfIP-STM32H563/"
echo ""
CURL_OUT=$(curl -vs --cacert "$CERT_FILE" \
    --resolve "wolfIP-STM32H563:443:${BOARD_IP}" \
    --max-time 10 "https://wolfIP-STM32H563/" 2>&1)
RC=$?
if [[ $RC -ne 0 && -z "$CURL_OUT" ]]; then
    echo -e "    ${RED}Connection failed (curl exit $RC)${RST}"
else
    # Show TLS handshake details (lines starting with "* ")
    echo "$CURL_OUT" | grep -E '^\* +(SSL|Server cert|subject|issuer|start date|expire)' | sed 's/^/    /'
    echo ""
    # Show page content (lines not starting with *, >, <space, or <header)
    echo "$CURL_OUT" | grep -v '^[*><{} ]' | \
        sed 's/<\/\(tr\|h1\|title\)>/\n/g; s/<[^>]*>//g; s/^[[:space:]]*//; /^$/d' | \
        sed 's/^/    /'
fi
echo ""

pause

# ---------------------------------------------------------------------------
# 4) SSH Server
# ---------------------------------------------------------------------------
banner "4. SSH Server (Port 22) - wolfSSH"

step "Connect and run commands (admin/wolfip)"
echo -e "  ${DIM}NOTE: This opens an interactive SSH session.${RST}"
echo -e "  ${DIM}Try: help, info, uptime, then exit${RST}"
echo ""
if [[ $AUTO -eq 1 ]]; then
    ssh_choice="s"
else
    echo -ne "  ${YLW}>>>${RST} Open SSH session? ${DIM}[Enter=yes, s=skip]${RST} "
    read -r ssh_choice
fi
if [[ "$ssh_choice" != "s" ]]; then
    TMP_KNOWN_HOSTS="$(mktemp /tmp/wolfip_known_hosts.XXXXXX)"
    if ! ssh-keyscan -H "${BOARD_IP}" > "${TMP_KNOWN_HOSTS}" 2>/dev/null || \
       [[ ! -s "${TMP_KNOWN_HOSTS}" ]]; then
        echo -e "  ${RED}Error: could not retrieve SSH host key from ${BOARD_IP}${RST}"
        rm -f "${TMP_KNOWN_HOSTS}"
    else
        ACTUAL_FPR="$(ssh-keygen -lf "${TMP_KNOWN_HOSTS}" 2>/dev/null | awk 'NR==1{print $2}')"
        EXPECTED_FPR="${WOLFIP_SSH_FINGERPRINT:-}"
        PROCEED_SSH=0
        if [[ -n "${EXPECTED_FPR}" ]]; then
            # Pinned fingerprint provided — verify it
            if [[ "${ACTUAL_FPR}" == "${EXPECTED_FPR}" ]]; then
                PROCEED_SSH=1
            else
                echo -e "  ${RED}Error: SSH host key fingerprint mismatch for ${BOARD_IP}${RST}" >&2
                echo -e "  ${DIM}Expected: ${EXPECTED_FPR}${RST}" >&2
                echo -e "  ${DIM}Actual:   ${ACTUAL_FPR}${RST}" >&2
            fi
        elif [[ $AUTO -eq 1 ]]; then
            echo -e "  ${RED}Error: WOLFIP_SSH_FINGERPRINT not set; refusing auto-accept in --auto mode${RST}" >&2
        else
            echo -e "  ${DIM}SSH host key fingerprint: ${ACTUAL_FPR}${RST}"
            echo -ne "  ${YLW}>>>${RST} Trust this key for this session? ${DIM}[y/N]${RST} "
            read -r trust_choice
            [[ "${trust_choice}" == "y" || "${trust_choice}" == "Y" ]] && PROCEED_SSH=1
        fi
        if [[ ${PROCEED_SSH} -eq 1 ]]; then
            cmd_show "ssh -o UserKnownHostsFile=${TMP_KNOWN_HOSTS} admin@${BOARD_IP}"
            echo ""
            ssh -o UserKnownHostsFile="${TMP_KNOWN_HOSTS}" \
                -o PubkeyAuthentication=no \
                "admin@${BOARD_IP}" 2>/dev/null
            echo ""
        fi
        rm -f "${TMP_KNOWN_HOSTS}"
    fi
fi

pause

# ---------------------------------------------------------------------------
# 5) MQTT Broker
# ---------------------------------------------------------------------------
banner "5. MQTT Broker (Port 8883) - TLS 1.3"

step "Start a subscriber in the background"
cmd_show "mqttclient -h ${BOARD_IP} -p 8883 -t -A cert.pem -n 'demo/#'"
echo ""

SUB_OUT=$(mktemp /tmp/wolfip_sub.XXXXXX)
"$MQTTCLIENT" -h "${BOARD_IP}" -p 8883 -t -A "$CERT_FILE" \
    -n "demo/#" > "$SUB_OUT" 2>/dev/null &
SUB_PID=$!

echo -e "    ${DIM}Subscriber listening on demo/# (pid ${SUB_PID})${RST}"
echo -e "    ${DIM}Waiting for TLS handshake...${RST}"
sleep 10

step "Publish messages to the broker"
echo ""
for i in 1 2 3; do
    MSG="Hello from wolfIP demo (message ${i})"
    cmd_show "mqttclient -h ${BOARD_IP} -p 8883 -t -A cert.pem -n 'demo/hello' -m '${MSG}' -x"
    "$MQTTCLIENT" -h "${BOARD_IP}" -p 8883 -t -A "$CERT_FILE" \
        -n "demo/hello" -m "$MSG" -x 2>/dev/null
    sleep 8
done

echo ""
step "Subscriber received:"
sleep 2
if [[ -s "$SUB_OUT" ]]; then
    sed 's/^/    /' "$SUB_OUT"
else
    echo -e "    ${DIM}(no messages received)${RST}"
fi
echo ""

# Cleanup subscriber
kill $SUB_PID 2>/dev/null
wait $SUB_PID 2>/dev/null
rm -f "$SUB_OUT"

pause

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
banner "Demo Complete"

echo -e "  ${GRN}All services running on bare-metal STM32H563 (Cortex-M33)${RST}"
echo ""
echo -e "  ${BLD}What's running on the MCU:${RST}"
echo -e "    - wolfIP   TCP/IP stack (no OS, no libc)"
echo -e "    - wolfSSL  TLS 1.3 with ECC P-256"
echo -e "    - wolfSSH  SSH server with shell"
echo -e "    - wolfMQTT MQTT broker (TLS-only)"
echo ""
echo -e "  ${BLD}Ports:${RST}"
echo -e "    TCP Echo    :7      HTTPS   :443"
echo -e "    SSH         :22     MQTT    :8883"
echo ""
echo -e "  ${DIM}https://www.wolfssl.com${RST}"
echo ""

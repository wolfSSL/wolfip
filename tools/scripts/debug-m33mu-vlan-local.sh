#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/scripts/debug-m33mu-vlan-local.sh

Build and run the STM32H563 demo against m33mu over an 802.1Q VLAN. The host
sets up tap0 with a VLAN sub-interface (tap0.<VID>) carrying IP 10.10.<VID>.1.
The firmware (built with ENABLE_VLAN=1) is expected to:
  - tag every outgoing frame with TPID=0x8100 and the configured VID,
  - accept incoming frames matching the same VID,
  - serve the built-in TCP echo service on port 7 over the VLAN.

Verification:
  1. Connect to <dev_ip>:7 from the host over tap0.<VID>, send a probe string,
     and assert it is echoed back byte-for-byte (proves TCP+VLAN+ARP works
     in both directions at L4).
  2. Capture a pcap on tap0 (the parent, where tagged frames are visible)
     and assert via tshark that 802.1Q-tagged traffic flowed in BOTH
     directions on the configured VID.

Environment:
  VLAN_VID=<1-4094>      VLAN ID (default: 100)
  VLAN_PCP=<0-7>         Priority code point (default: 0)
  M33MU_TIMEOUT=<secs>   m33mu run timeout (default: 30)
  ECHO_PAYLOAD=<string>  Bytes to send through the TCP echo
                         (default: "hello-vlan-<epoch>")

Outputs:
  /tmp/m33mu-vlan.log         UART/stdout from m33mu
  /tmp/m33mu-vlan.pcap        Packet capture on tap0 (sees tagged frames)
  /tmp/m33mu-vlan-tshark.txt  tshark filter output
  /tmp/m33mu-vlan-echo.txt    Bytes received from the TCP echo
EOF
}

resolve_m33mu_bin() {
  if [ -x /workspace/m33mu/build/m33mu ]; then
    printf '%s\n' /workspace/m33mu/build/m33mu
  elif [ -x /usr/local/bin/m33mu ]; then
    printf '%s\n' /usr/local/bin/m33mu
  else
    printf '%s\n' m33mu
  fi
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

vid="${VLAN_VID:-100}"
pcp="${VLAN_PCP:-0}"
m33mu_timeout="${M33MU_TIMEOUT:-30}"
echo_payload="${ECHO_PAYLOAD:-hello-vlan-$(date +%s)}"

if ! [[ "${vid}" =~ ^[0-9]+$ ]] || [ "${vid}" -lt 1 ] || [ "${vid}" -gt 4094 ]; then
  echo "VLAN_VID must be an integer in [1, 4094]" >&2
  exit 2
fi

host_ip="10.10.${vid}.1"
dev_ip="10.10.${vid}.2"
mask="255.255.255.0"
echo_port=7

cleanup() {
  local rc=$?
  set +e
  if [ -f /tmp/m33mu-vlan.pid ]; then
    kill "$(cat /tmp/m33mu-vlan.pid)" 2>/dev/null || true
  fi
  if [ -f /tmp/tcpdump-vlan.pid ]; then
    kill "$(cat /tmp/tcpdump-vlan.pid)" 2>/dev/null || true
  fi
  pkill -x m33mu 2>/dev/null || true
  ip link del "tap0.${vid}" 2>/dev/null || true
  ip link del tap0 2>/dev/null || true
  exit "${rc}"
}
trap cleanup EXIT

rm -f /tmp/m33mu-vlan.log /tmp/m33mu-vlan.pcap /tmp/m33mu-vlan-tshark.txt \
  /tmp/m33mu-vlan-echo.txt /tmp/m33mu-vlan.pid /tmp/tcpdump-vlan.pid

echo "==> Building STM32H563 firmware with VLAN_VID=${vid} VLAN_PCP=${pcp}"
make -C src/port/stm32h563 clean \
  CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy >/dev/null
make -C src/port/stm32h563 \
  CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy \
  TZEN=0 ENABLE_VLAN=1 \
  VLAN_VID="${vid}" VLAN_PCP="${pcp}" \
  VLAN_IP="${dev_ip}" VLAN_MASK="${mask}" VLAN_GW="${host_ip}"

echo "==> Setting up tap0 + tap0.${vid} VLAN sub-interface"
# Use ${USER:-root} so the script works both on a multi-user dev box (where
# $USER is set) and inside a GitHub Actions container (where it may not be).
ip tuntap add dev tap0 mode tap user "${USER:-root}"
ip link set tap0 up
ip link add link tap0 name "tap0.${vid}" type vlan id "${vid}"
ip addr add "${host_ip}/24" dev "tap0.${vid}"
ip link set "tap0.${vid}" up

echo "==> Starting tcpdump on tap0 (parent; sees tagged frames)"
tcpdump -i tap0 -nn -U -w /tmp/m33mu-vlan.pcap > /dev/null 2>&1 &
printf '%s\n' "$!" > /tmp/tcpdump-vlan.pid
sleep 1

echo "==> Starting m33mu"
"$(resolve_m33mu_bin)" src/port/stm32h563/app.bin \
  --cpu stm32h563 --tap:tap0 --uart-stdout \
  --timeout "${m33mu_timeout}" --quit-on-faults \
  > /tmp/m33mu-vlan.log 2>&1 &
printf '%s\n' "$!" > /tmp/m33mu-vlan.pid

echo "==> Waiting for firmware to reach the main loop (TCP echo ready)"
ready=0
for _ in $(seq 1 $((m33mu_timeout + 5))); do
  if grep -q "Entering main loop" /tmp/m33mu-vlan.log 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done

if [ "${ready}" = "1" ]; then
  echo "FW_READY=yes"
else
  echo "FW_READY=no"
fi

echo "==> Probing TCP echo at ${dev_ip}:${echo_port} via tap0.${vid}"
echo_ok=0
echo_recv=""
if [ "${ready}" = "1" ]; then
  # Use bash's /dev/tcp so we don't depend on a particular nc variant.
  # Try a few times because the firmware's listen socket may take a moment
  # to become accept()-ready after the log message.
  for try in 1 2 3 4 5; do
    if exec 3<>"/dev/tcp/${dev_ip}/${echo_port}" 2>/dev/null; then
      printf '%s\n' "${echo_payload}" >&3
      if IFS= read -r -t 5 echo_recv <&3; then
        echo_ok=1
      fi
      exec 3<&- 2>/dev/null || true
      exec 3>&- 2>/dev/null || true
      [ "${echo_ok}" = "1" ] && break
    fi
    sleep 1
  done
fi
printf '%s\n' "${echo_recv}" > /tmp/m33mu-vlan-echo.txt
echo "ECHO_SENT=${echo_payload}"
echo "ECHO_RECV=${echo_recv}"

# Give tcpdump a moment to flush
sleep 2
kill "$(cat /tmp/tcpdump-vlan.pid)" 2>/dev/null || true
sleep 1

echo "==> Asserting 802.1Q tagged traffic on VID=${vid}"
fw_mac=""
egress=0
ingress=0
tshark_out=""

# Pull the firmware's Ethernet MAC out of the UART log. The demo prints it
# as a line "  MAC: XX:XX:XX:XX:XX:XX" right after eth init. Anchor on the
# "  MAC:" prefix so we ignore unrelated lines from m33mu like
# "[ETH_MAC] assigned MAC ..." that emit during boot.
fw_mac="$(sed -nE 's/^[[:space:]]+MAC:[[:space:]]+([0-9A-Fa-f:]+).*/\1/p' \
            /tmp/m33mu-vlan.log \
            | head -n1 \
            | tr 'A-F' 'a-f')"
echo "FW_MAC=${fw_mac:-<unknown>}"

if ! command -v tshark >/dev/null 2>&1; then
  echo "WARNING: tshark not installed; skipping pcap assertion." >&2
else
  # Tab-separated columns: frame eth.src eth.dst vlan eth.type ip.src ip.dst
  # tcp.sport tcp.dport info
  tshark_out="$(tshark -r /tmp/m33mu-vlan.pcap -n \
      -Y "vlan.id==${vid}" \
      -T fields \
        -e frame.number -e eth.src -e eth.dst -e vlan.id -e eth.type \
        -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e _ws.col.Info \
      2>/dev/null || true)"
  printf '%s\n' "${tshark_out}" > /tmp/m33mu-vlan-tshark.txt

  if [ -n "${fw_mac}" ] && [ -n "${tshark_out}" ]; then
    # tshark -T fields uses tab as the column separator. Field 2 is eth.src
    # (egress when == fw_mac), field 3 is eth.dst (ingress when == fw_mac).
    # `grep -cFx` exits 1 when no matches; `|| true` keeps set -o pipefail
    # from aborting on an empty direction.
    egress=$(printf '%s\n' "${tshark_out}" \
              | cut -f2 | tr 'A-F' 'a-f' \
              | grep -cFx "${fw_mac}" || true)
    ingress=$(printf '%s\n' "${tshark_out}" \
              | cut -f3 | tr 'A-F' 'a-f' \
              | grep -cFx "${fw_mac}" || true)
  fi
fi
echo "EGRESS_FRAMES=${egress} INGRESS_FRAMES=${ingress}"

echo "--- m33mu log tail ---"
tail -n 60 /tmp/m33mu-vlan.log || true
echo "--- tshark (vlan.id==${vid}) ---"
head -n 20 /tmp/m33mu-vlan-tshark.txt 2>/dev/null || true
echo "--- pcap summary ---"
ls -l /tmp/m33mu-vlan.pcap || true

rc=0
if [ "${ready}" != "1" ]; then
  echo "FAIL: firmware did not reach main loop within ${m33mu_timeout}s." >&2
  rc=1
fi
if [ "${echo_ok}" != "1" ]; then
  echo "FAIL: TCP echo probe did not receive a response from ${dev_ip}:${echo_port}." >&2
  rc=1
elif [ "${echo_recv}" != "${echo_payload}" ]; then
  echo "FAIL: TCP echo payload mismatch (sent='${echo_payload}', recv='${echo_recv}')." >&2
  rc=1
else
  echo "OK: TCP echo over VLAN returned the expected payload."
fi

if command -v tshark >/dev/null 2>&1; then
  if [ -z "${tshark_out}" ]; then
    echo "FAIL: no frames with VID=${vid} captured on tap0." >&2
    rc=1
  else
    echo "OK: captured 802.1Q frames with VID=${vid}."
  fi

  if [ -z "${fw_mac}" ]; then
    echo "FAIL: could not determine firmware MAC from UART log; cannot verify bidirectional VLAN traffic." >&2
    rc=1
  else
    if [ "${egress}" -eq 0 ]; then
      echo "FAIL: no egress VLAN frames from firmware MAC ${fw_mac} on VID=${vid}." >&2
      rc=1
    else
      echo "OK: ${egress} egress VLAN frames from firmware MAC ${fw_mac}."
    fi
    if [ "${ingress}" -eq 0 ]; then
      echo "FAIL: no ingress VLAN frames to firmware MAC ${fw_mac} on VID=${vid}." >&2
      rc=1
    else
      echo "OK: ${ingress} ingress VLAN frames to firmware MAC ${fw_mac}."
    fi
  fi
fi

exit "${rc}"

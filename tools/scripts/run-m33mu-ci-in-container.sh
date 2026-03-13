#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/scripts/run-m33mu-ci-in-container.sh <workflow> [job]
EOF
}

resolve_m33mu_bin() {
  if [ -x /workspace/m33mu/build/m33mu ]; then
    printf '%s\n' /workspace/m33mu/build/m33mu
  else
    printf '%s\n' m33mu
  fi
}

run_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

require_repo_root() {
  if [ ! -f "Makefile" ] || [ ! -d ".github/workflows" ]; then
    echo "Run this script from the wolfip repository root." >&2
    exit 1
  fi
}

install_host_tools() {
  run_root apt-get update
  run_root apt-get install -y \
    sudo dnsmasq iproute2 netcat-openbsd curl git tcpdump \
    mosquitto-clients openssh-client sshpass openssl
}

ensure_repo() {
  local name="$1"
  local url="$2"
  if [ ! -d "../${name}/.git" ]; then
    git clone --depth 1 "${url}" "../${name}"
  fi
}

ensure_repo_at() {
  local path="$1"
  local url="$2"
  if [ ! -d "${path}/.git" ]; then
    git clone --depth 1 "${url}" "${path}"
  fi
}

build_echo() {
  make -C src/port/stm32h563 \
    CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy
}

build_full() {
  ensure_repo wolfssl https://github.com/wolfSSL/wolfssl.git
  ensure_repo wolfssh https://github.com/wolfSSL/wolfssh.git
  ensure_repo wolfmqtt https://github.com/wolfSSL/wolfmqtt.git
  make -C src/port/stm32h563 \
    WOLFSSL_ROOT=../../../../wolfssl \
    ENABLE_HTTPS=1 ENABLE_MQTT_BROKER=1 ENABLE_SSH=1 \
    WOLFSSL_SP_NO_ASM=1 \
    CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy
}

build_https_tls13() {
  ensure_repo wolfssl https://github.com/wolfSSL/wolfssl.git
  make -C src/port/stm32h563 clean TZEN=0 ENABLE_HTTPS=1 \
    WOLFSSL_SP_NO_ASM=1 \
    CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy
  make -C src/port/stm32h563 TZEN=0 ENABLE_HTTPS=1 \
    WOLFSSL_SP_NO_ASM=1 \
    CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy
  strings src/port/stm32h563/app.bin > /tmp/wolfip-app.strings
  grep -Fq "Initializing HTTPS server" /tmp/wolfip-app.strings
}

build_https_freertos() {
  ensure_repo wolfssl https://github.com/wolfSSL/wolfssl.git
  ensure_repo FreeRTOS_Kernel https://github.com/FreeRTOS/FreeRTOS-Kernel.git
  make -C src/port/stm32h563 clean TZEN=0 FREERTOS=1 ENABLE_HTTPS=1 \
    WOLFSSL_SP_NO_ASM=1 \
    CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy
  make -C src/port/stm32h563 TZEN=0 FREERTOS=1 ENABLE_HTTPS=1 \
    WOLFSSL_SP_NO_ASM=1 \
    CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy
  strings src/port/stm32h563/app.bin > /tmp/wolfip-app.strings
  grep -Fq "FreeRTOS BSD socket layer" /tmp/wolfip-app.strings
  grep -Fq "HTTPS/FreeRTOS: Server ready on port" /tmp/wolfip-app.strings
}

build_echo_freertos() {
  ensure_repo FreeRTOS_Kernel https://github.com/FreeRTOS/FreeRTOS-Kernel.git
  make -C src/port/stm32h563 clean TZEN=0 FREERTOS=1 \
    CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy
  make -C src/port/stm32h563 TZEN=0 FREERTOS=1 \
    CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy
  strings src/port/stm32h563/app.bin > /tmp/wolfip-app.strings
  grep -Fq "FreeRTOS BSD socket layer" /tmp/wolfip-app.strings
  grep -Fq "Echo/FreeRTOS: Server ready on port" /tmp/wolfip-app.strings
}

build_ssh_tzen() {
  ensure_repo wolfssl https://github.com/wolfSSL/wolfssl.git
  ensure_repo wolfssh https://github.com/wolfSSL/wolfssh.git
  make -C src/port/stm32h563 clean TZEN=1 ENABLE_SSH=1
  make -C src/port/stm32h563 TZEN=1 ENABLE_SSH=1 \
    CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy
  sleep 2
  strings src/port/stm32h563/app.bin > /tmp/wolfip-app.strings
  grep -Fq "Initializing SSH server" /tmp/wolfip-app.strings
}

cleanup_runtime() {
  set +e
  if [ -f /tmp/m33mu.pid ]; then
    run_root kill "$(cat /tmp/m33mu.pid)" 2>/dev/null || true
  fi
  if [ -f /tmp/tcpdump.pid ]; then
    run_root kill "$(cat /tmp/tcpdump.pid)" 2>/dev/null || true
  fi
  run_root pkill -x m33mu 2>/dev/null || true
  if [ -f /tmp/dnsmasq.pid ]; then
    run_root kill "$(cat /tmp/dnsmasq.pid)" 2>/dev/null || true
  fi
  run_root ip link del tap0 2>/dev/null || true
}

setup_tap_and_dnsmasq() {
  rm -f /tmp/dnsmasq.leases /tmp/m33mu.log /tmp/curl.log /tmp/ssh.log /tmp/tcpdump.log /tmp/https-test.pcap
  run_root ip tuntap add dev tap0 mode tap
  run_root ip addr add 192.168.12.1/24 dev tap0
  run_root ip link set tap0 up

  cat > /tmp/dnsmasq.conf <<'EOF'
interface=tap0
bind-interfaces
dhcp-range=192.168.12.50,192.168.12.100,255.255.255.0,12h
dhcp-leasefile=/tmp/dnsmasq.leases
log-dhcp
EOF
  run_root dnsmasq --conf-file=/tmp/dnsmasq.conf --pid-file=/tmp/dnsmasq.pid
}

start_m33mu() {
  local timeout_s="$1"
  local m33mu_bin
  shift
  m33mu_bin="$(resolve_m33mu_bin)"
  run_root "${m33mu_bin}" src/port/stm32h563/app.bin \
    --cpu stm32h563 --tap:tap0 --uart-stdout --timeout "${timeout_s}" "$@" \
    2>&1 | tee /tmp/m33mu.log &
  sleep 1
  local m33mu_pid
  m33mu_pid="$(pgrep -n -x m33mu || true)"
  if [ -n "${m33mu_pid}" ]; then
    printf '%s\n' "${m33mu_pid}" > /tmp/m33mu.pid
  fi
}

start_tcpdump() {
  run_root tcpdump -i tap0 -nn -U -w /tmp/https-test.pcap > /tmp/tcpdump.log 2>&1 &
  printf '%s\n' "$!" > /tmp/tcpdump.pid
}

wait_for_lease() {
  local retries="$1"
  local ip=""
  for _ in $(seq 1 "${retries}"); do
    if [ -s /tmp/dnsmasq.leases ]; then
      ip="$(tail -n1 /tmp/dnsmasq.leases | cut -d' ' -f3)"
    fi
    if [ -n "${ip}" ]; then
      printf '%s\n' "${ip}"
      return 0
    fi
    sleep 1
  done
  echo "No DHCP lease acquired." >&2
  tail -n 200 /tmp/m33mu.log || true
  return 1
}

check_alive() {
  if ! pgrep -x m33mu >/dev/null 2>&1; then
    echo "m33mu exited unexpectedly." >&2
    tail -n 200 /tmp/m33mu.log || true
    exit 1
  fi
}

extract_mqtt_cert() {
  sed -n '/server_cert_pem\[\]/,/^"-----END CERTIFICATE-----\\n";$/p' src/port/certs.h \
    | sed 's/^"//; s/\\n";$//; s/\\n"$//; s/"$//' \
    | grep -v '^static\|^;' > /tmp/wolfip_cert.pem
}

job_echo() {
  echo "==> Building stm32h563_m33mu_echo"
  build_echo
  echo "==> Running stm32h563_m33mu_echo"
  trap cleanup_runtime EXIT
  setup_tap_and_dnsmasq
  start_m33mu 120
  local ip
  ip="$(wait_for_lease 60)"
  echo "Leased IP: ${ip}"
  local ok=0
  for _ in $(seq 1 20); do
    check_alive
    if printf "ping" | nc -w 2 "${ip}" 7 | grep -q "ping"; then
      ok=1
      break
    fi
    sleep 0.2
  done
  [ "${ok}" -eq 1 ] || {
    echo "Echo test failed." >&2
    tail -n 200 /tmp/m33mu.log || true
    exit 1
  }
  echo "Echo test succeeded."
  cleanup_runtime
  trap - EXIT
}

job_full() {
  echo "==> Building stm32h563_m33mu_full"
  build_full
  echo "==> Running stm32h563_m33mu_full"
  trap cleanup_runtime EXIT
  setup_tap_and_dnsmasq
  start_m33mu 240
  local ip
  ip="$(wait_for_lease 60)"
  echo "Leased IP: ${ip}"

  echo "=== Test 1: TCP Echo ==="
  local ok=0
  for _ in $(seq 1 20); do
    check_alive
    if printf "ping" | nc -w 2 "${ip}" 7 | grep -q "ping"; then
      ok=1
      break
    fi
    sleep 0.5
  done
  [ "${ok}" -eq 1 ] || {
    echo "FAIL: Echo test." >&2
    tail -n 200 /tmp/m33mu.log || true
    exit 1
  }
  echo "PASS: Echo test."

  echo "=== Test 2: HTTPS Server ==="
  sleep 3
  ok=0
  for _ in $(seq 1 10); do
    check_alive
    local resp
    resp="$(curl -k -s --tlsv1.3 --max-time 20 "https://${ip}/" 2>/tmp/curl_err.log || true)"
    if echo "${resp}" | grep -q "wolfIP Status"; then
      ok=1
      break
    fi
    sleep 2
  done
  [ "${ok}" -eq 1 ] || {
    echo "FAIL: HTTPS test." >&2
    cat /tmp/curl_err.log || true
    tail -n 200 /tmp/m33mu.log || true
    exit 1
  }
  echo "PASS: HTTPS test."

  echo "=== Test 3: TLS Echo ==="
  sleep 5
  ok=0
  for _ in $(seq 1 5); do
    check_alive
    local tls_resp
    tls_resp="$(echo "TLS-ping" | timeout 10 openssl s_client -connect "${ip}:8443" -quiet 2>/dev/null || true)"
    if echo "${tls_resp}" | grep -q "TLS-ping"; then
      ok=1
      break
    fi
    sleep 3
  done
  [ "${ok}" -eq 1 ] || {
    echo "FAIL: TLS echo test." >&2
    tail -n 200 /tmp/m33mu.log || true
    exit 1
  }
  echo "PASS: TLS echo test."

  echo "=== Test 4: MQTT Broker ==="
  sleep 5
  extract_mqtt_cert
  ok=0
  for _ in $(seq 1 5); do
    check_alive
    local mqtt_out
    mqtt_out="$(mosquitto_pub -h "${ip}" -p 8883 \
      --cafile /tmp/wolfip_cert.pem --insecure \
      -t "ci/test" -m "hello" -d 2>&1 || true)"
    if echo "${mqtt_out}" | grep -q "CONNACK"; then
      ok=1
      break
    fi
    sleep 5
  done
  [ "${ok}" -eq 1 ] || {
    echo "FAIL: MQTT broker test." >&2
    tail -n 200 /tmp/m33mu.log || true
    exit 1
  }
  echo "PASS: MQTT broker test."

  echo "=== Test 5: SSH Server ==="
  sleep 5
  ok=0
  for _ in $(seq 1 5); do
    check_alive
    local ssh_resp
    ssh_resp="$(timeout 10 bash -c "echo '' | nc -w 5 ${ip} 22" 2>/dev/null || true)"
    if echo "${ssh_resp}" | grep -qi "ssh"; then
      ok=1
      break
    fi
    sleep 3
  done
  [ "${ok}" -eq 1 ] || {
    echo "FAIL: SSH banner test." >&2
    tail -n 200 /tmp/m33mu.log || true
    exit 1
  }
  echo "PASS: SSH banner test."
  echo "=== All tests passed ==="
  cleanup_runtime
  trap - EXIT
}

job_https_tls13() {
  echo "==> Building stm32h563_m33mu_https_tls13"
  build_https_tls13
  echo "==> Running stm32h563_m33mu_https_tls13"
  trap cleanup_runtime EXIT
  setup_tap_and_dnsmasq
  start_tcpdump
  start_m33mu 180 --quit-on-faults
  local ip
  ip="$(wait_for_lease 90)"
  echo "Leased IP: ${ip}"
  local ok=0
  for _ in $(seq 1 60); do
    check_alive
    if curl --silent --show-error --fail --insecure --tlsv1.3 \
        --connect-timeout 10 --max-time 20 \
        "https://${ip}/" | tee /tmp/curl.log | grep -q "wolfIP"; then
      ok=1
      break
    fi
    sleep 0.5
  done
  [ "${ok}" -eq 1 ] || {
    echo "HTTPS test failed." >&2
    tail -n 200 /tmp/m33mu.log || true
    tail -n 200 /tmp/curl.log || true
    tail -n 50 /tmp/tcpdump.log || true
    exit 1
  }
  echo "HTTPS test succeeded."
  cleanup_runtime
  trap - EXIT
}

job_https_freertos() {
  echo "==> Building stm32h563_m33mu_https_freertos"
  build_https_freertos
  echo "==> Running stm32h563_m33mu_https_freertos"
  trap cleanup_runtime EXIT
  setup_tap_and_dnsmasq
  start_tcpdump
  start_m33mu 180 --quit-on-faults
  local ip
  ip="$(wait_for_lease 90)"
  echo "Leased IP: ${ip}"
  local ok=0
  for _ in $(seq 1 60); do
    check_alive
    if curl --silent --show-error --fail --insecure --tlsv1.3 \
        --connect-timeout 10 --max-time 20 \
        "https://${ip}/" | tee /tmp/curl.log | grep -q "FreeRTOS BSD sockets"; then
      ok=1
      break
    fi
    sleep 0.5
  done
  [ "${ok}" -eq 1 ] || {
    echo "FreeRTOS HTTPS test failed." >&2
    tail -n 200 /tmp/m33mu.log || true
    tail -n 200 /tmp/curl.log || true
    tail -n 50 /tmp/tcpdump.log || true
    exit 1
  }
  echo "FreeRTOS HTTPS test succeeded."
  cleanup_runtime
  trap - EXIT
}

job_echo_freertos() {
  echo "==> Building stm32h563_m33mu_echo_freertos"
  build_echo_freertos
  echo "==> Running stm32h563_m33mu_echo_freertos"
  trap cleanup_runtime EXIT
  setup_tap_and_dnsmasq
  start_m33mu 180 --quit-on-faults
  local ip
  ip="$(wait_for_lease 90)"
  echo "Leased IP: ${ip}"
  local ok=0
  for _ in $(seq 1 60); do
    check_alive
    if timeout 10s bash -lc "printf 'wolfip-freertos-echo' | nc -w 5 '${ip}' 7" \
        | tee /tmp/echo.log | grep -q "^wolfip-freertos-echo$"; then
      ok=1
      break
    fi
    sleep 0.5
  done
  [ "${ok}" -eq 1 ] || {
    echo "FreeRTOS echo test failed." >&2
    tail -n 200 /tmp/m33mu.log || true
    tail -n 200 /tmp/echo.log || true
    exit 1
  }
  echo "FreeRTOS echo test succeeded."
  cleanup_runtime
  trap - EXIT
}

job_ssh_tzen() {
  echo "==> Building stm32h563_m33mu_ssh_tzen"
  build_ssh_tzen
  echo "==> Running stm32h563_m33mu_ssh_tzen"
  trap cleanup_runtime EXIT
  setup_tap_and_dnsmasq
  start_m33mu 180 --quit-on-faults
  local ip
  ip="$(wait_for_lease 90)"
  echo "Leased IP: ${ip}"
  local ok=0
  for _ in $(seq 1 60); do
    check_alive
    if timeout 10s bash -lc "printf '' | nc -w 5 '${ip}' 22" \
        | tee /tmp/ssh.log | grep -q "^SSH-2.0-"; then
      ok=1
      break
    fi
    sleep 0.5
  done
  [ "${ok}" -eq 1 ] || {
    echo "SSH test failed." >&2
    tail -n 200 /tmp/m33mu.log || true
    tail -n 200 /tmp/ssh.log || true
    exit 1
  }
  echo "SSH test succeeded."
  cleanup_runtime
  trap - EXIT
}

run_job() {
  case "$1" in
    stm32h563_m33mu_echo) job_echo ;;
    stm32h563_m33mu_echo_freertos) job_echo_freertos ;;
    stm32h563_m33mu_full) job_full ;;
    stm32h563_m33mu_https_tls13) job_https_tls13 ;;
    stm32h563_m33mu_https_freertos) job_https_freertos ;;
    stm32h563_m33mu_ssh_tzen) job_ssh_tzen ;;
    *)
      echo "Unsupported job: $1" >&2
      exit 1
      ;;
  esac
}

run_workflow() {
  case "$1" in
    stm32h563-m33mu)
      run_job stm32h563_m33mu_echo
      run_job stm32h563_m33mu_full
      run_job stm32h563_m33mu_https_tls13
      ;;
    stm32h563-m33mu-freertos)
      run_job stm32h563_m33mu_echo_freertos
      ;;
    stm32h563-m33mu-ssh-tzen)
      run_job stm32h563_m33mu_ssh_tzen
      ;;
    *)
      echo "Unsupported workflow: $1" >&2
      exit 1
      ;;
  esac
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  usage
  exit 1
fi

workflow="$1"
job="${2:-}"

require_repo_root
install_host_tools

if [ -n "${job}" ]; then
  run_job "${job}"
else
  run_workflow "${workflow}"
fi

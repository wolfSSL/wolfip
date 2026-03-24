#!/bin/bash
#
# test-interop-wolfguard.sh
#
# Interoperability test: wolfIP wolfGuard <-> kernel wolfGuard
#
# Designed to run inside a privileged container (or a VM with root access).
# Builds wolfSSL + kernel wolfGuard from source, then runs a bidirectional
# UDP echo test through the tunnel.
#
# Requirements:
#   - Root privileges (kernel modules, TUN, network config)
#   - Internet access (git clone)
#   - Kernel headers matching the running kernel
#   - Build tools (gcc, make, autoconf, libtool, etc.)
#
# Usage:
#   sudo ./tools/test-interop-wolfguard.sh
#
# Exit codes:
#   0 - interop test passed
#   1 - build or setup failure
#   2 - interop test failed
#
# Copyright (C) 2026 wolfSSL Inc.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WOLFIP_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORK_DIR="/tmp/wolfguard-interop-build"
KEY_DIR="/tmp/wolfguard-interop-keys"

# Network config
TUN_NAME="wgtun0"
HOST_TUN_IP="192.168.77.1"
WOLFIP_TUN_IP="192.168.77.2"
KERNEL_WG_IP="10.0.0.1"
WOLFIP_WG_IP="10.0.0.2"
KERNEL_WG_PORT=51820
WOLFIP_WG_PORT=51821
ECHO_PORT=7777

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }

cleanup() {
    log "Cleaning up..."

    # Kill background processes
    [ -n "${TCPDUMP_PID:-}" ] && kill "$TCPDUMP_PID" 2>/dev/null || true
    [ -n "${WOLFIP_PID:-}" ] && kill "$WOLFIP_PID" 2>/dev/null || true
    [ -n "${SOCAT_PID:-}" ] && kill "$SOCAT_PID" 2>/dev/null || true

    # Remove kernel wg0
    ip link del wg0 2>/dev/null || true

    # Remove ready markers
    rm -f /tmp/wolfguard-interop-ready /tmp/wolfguard-kernel-ready /tmp/wolfguard-phase2-ready /tmp/wolfguard-kernel-ready

    # Unload modules (optional, don't fail)
    rmmod wolfguard 2>/dev/null || true
    rmmod libwolfssl 2>/dev/null || true

    log "Cleanup done."
}

trap cleanup EXIT

#
# Step 1: Check prerequisites
#

log "Step 1: Checking prerequisites..."

if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (or with sudo)"
    exit 1
fi

KERNEL_VERSION=$(uname -r)
log "Kernel: $KERNEL_VERSION"

# Check for /dev/net/tun
if [ ! -c /dev/net/tun ]; then
    warn "/dev/net/tun not found, creating..."
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 666 /dev/net/tun
fi

# Enable kernel dynamic debug for wolfguard (if available)
mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
if [ -f /sys/kernel/debug/dynamic_debug/control ]; then
    echo 'module wolfguard +p' > /sys/kernel/debug/dynamic_debug/control 2>/dev/null || true
    log "Kernel dynamic debug enabled for wolfguard"
fi

#
# Step 2: Install build dependencies
#

log "Step 2: Installing build dependencies..."

if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
        build-essential autoconf automake libtool pkg-config \
        linux-headers-"$KERNEL_VERSION" \
        linux-modules-extra-"$KERNEL_VERSION" \
        iproute2 socat kmod git check tcpdump 2>&1 | tail -1
elif command -v dnf &>/dev/null; then
    dnf install -y -q \
        gcc make autoconf automake libtool pkgconfig \
        kernel-devel-"$KERNEL_VERSION" \
        iproute socat kmod git check-devel
else
    warn "Unknown package manager — assuming dependencies are installed"
fi

#
# Step 3: Build wolfSSL (userspace library + kernel module)
#

log "Step 3: Building wolfSSL..."

mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

if [ ! -d wolfssl ]; then
    log "Cloning wolfssl..."
    git clone --depth 1 https://github.com/wolfssl/wolfssl --branch nightly-snapshot
    (cd wolfssl && ./autogen.sh)
fi

cd wolfssl

# 3a: Userspace library
log "Building wolfSSL userspace library..."
./configure --quiet --enable-wolfguard --enable-all-asm 2>&1 | tail -3
make -j"$(nproc)" 2>&1 | tail -3
make install 2>&1 | tail -1
ldconfig

# 3b: Kernel module (must distclean first to avoid stale userspace objects)
log "Building wolfSSL kernel module..."
LINUX_SRC="/usr/src/linux"
[ ! -d "$LINUX_SRC" ] && LINUX_SRC="/lib/modules/$KERNEL_VERSION/build"

make distclean 2>&1 | tail -1
./configure --quiet \
    --enable-wolfguard \
    --enable-cryptonly \
    --enable-intelasm \
    --enable-linuxkm \
    --with-linux-source="$LINUX_SRC" \
    --prefix="$(pwd)/linuxkm/build" 2>&1 | tail -3

make -j"$(nproc)" module 2>&1 | tail -3
make install 2>&1 | tail -1

# wolfSSL's make install doesn't copy linuxkm subheaders into the prefix.
# The wolfguard Kbuild includes them via linuxkm/build/include, so we symlink.
mkdir -p "$(pwd)/linuxkm/build/include/wolfssl/wolfcrypt/linuxkm"
ln -sf "$(pwd)/linuxkm/linuxkm_memory.h" \
       "$(pwd)/linuxkm/build/include/wolfssl/wolfcrypt/linuxkm/linuxkm_memory.h"
# Also link the linuxkm dir at the wolfcrypt level for any other relative includes
ln -sf "$(pwd)/linuxkm" \
       "$(pwd)/linuxkm/build/include/linuxkm" 2>/dev/null || true

# Load wolfguard kernel dependencies (udp_tunnel, ip6_udp_tunnel)
modprobe udp_tunnel 2>/dev/null || true
modprobe ip6_udp_tunnel 2>/dev/null || true

log "Loading libwolfssl kernel module..."
depmod -a 2>/dev/null || true
WOLFSSL_KO="$(find /lib/modules/$KERNEL_VERSION -name 'libwolfssl.ko' 2>/dev/null | head -1)"
if [ -z "$WOLFSSL_KO" ]; then
    WOLFSSL_KO="$(find "$(pwd)" -name 'libwolfssl.ko' 2>/dev/null | head -1)"
fi
if [ -n "$WOLFSSL_KO" ]; then
    insmod "$WOLFSSL_KO" 2>/dev/null || true  # ignore "File exists" if already loaded
else
    modprobe libwolfssl 2>/dev/null || true
fi
log "libwolfssl module ready"

cd "$WORK_DIR"

#
# Step 4: Build wolfGuard (kernel module + wg-fips tool)
#

log "Step 4: Building wolfGuard..."

if [ ! -d wolfguard ]; then
    log "Cloning wolfguard..."
    git clone --depth 1 https://github.com/wolfssl/wolfguard
fi

cd wolfguard

# 4a: wg-fips user tool
log "Building wg-fips..."
cd user-src
make -j"$(nproc)" 2>&1 | tail -3
make install 2>&1 | tail -1
cd ..

# 4b: Kernel module
log "Building wolfguard kernel module..."
cd kernel-src
WOLFSSL_SRC="$WORK_DIR/wolfssl"
make -j"$(nproc)" KERNELDIR="$LINUX_SRC" KERNELRELEASE="$KERNEL_VERSION" \
    EXTRA_CFLAGS="-I$WOLFSSL_SRC" 2>&1 | tail -5
make install KERNELDIR="$LINUX_SRC" KERNELRELEASE="$KERNEL_VERSION" 2>&1 | tail -1
cd ..

log "Loading wolfguard kernel module..."
depmod -a 2>/dev/null || true
WG_KO="$(find /lib/modules/$KERNEL_VERSION -name 'wolfguard.ko' 2>/dev/null | head -1)"
if [ -z "$WG_KO" ]; then
    WG_KO="$(find "$(pwd)" -name 'wolfguard.ko' 2>/dev/null | head -1)"
fi
if [ -n "$WG_KO" ]; then
    insmod "$WG_KO" 2>/dev/null || true  # ignore "File exists" if already loaded
else
    modprobe wolfguard 2>/dev/null || true
fi
# Verify: try creating a wolfguard interface (proves the module works)
ip link add wg_test type wolfguard 2>/dev/null && ip link del wg_test 2>/dev/null || \
    { err "wolfguard module not functional"; exit 1; }
log "wolfguard module ready"

# Enable dynamic debug for wolfguard NOW (after module is loaded)
if [ -f /sys/kernel/debug/dynamic_debug/control ]; then
    echo 'module wolfguard +p' > /sys/kernel/debug/dynamic_debug/control 2>/dev/null && \
        log "Dynamic debug enabled for wolfguard" || true
fi

cd "$WOLFIP_DIR"

#
# Step 5: Generate keys
#

log "Step 5: Generating keys..."

mkdir -p "$KEY_DIR"

# Kernel side keys
wg-fips genkey > "$KEY_DIR/kernel_priv_b64"
wg-fips pubkey < "$KEY_DIR/kernel_priv_b64" > "$KEY_DIR/kernel_pub_b64"

# wolfIP side keys
wg-fips genkey > "$KEY_DIR/wolfip_priv_b64"
wg-fips pubkey < "$KEY_DIR/wolfip_priv_b64" > "$KEY_DIR/wolfip_pub_b64"

# Decode to raw binary for the wolfIP test binary
base64 -d < "$KEY_DIR/wolfip_priv_b64" > "$KEY_DIR/wolfip_priv.bin"
base64 -d < "$KEY_DIR/kernel_pub_b64"  > "$KEY_DIR/kernel_pub.bin"
# Verify key sizes
PRIV_SIZE=$(wc -c < "$KEY_DIR/wolfip_priv.bin")
PUB_SIZE=$(wc -c < "$KEY_DIR/kernel_pub.bin")
log "wolfIP private key: $PRIV_SIZE bytes (expect 32)"
log "Kernel public key: $PUB_SIZE bytes (expect 65)"

if [ "$PRIV_SIZE" -ne 32 ] || [ "$PUB_SIZE" -ne 65 ]; then
    err "Key sizes don't match expected FIPS P-256 sizes"
    exit 1
fi

log "Keys generated successfully"

#
# Step 6: Build wolfIP interop test binary
#

log "Step 6: Building wolfIP interop test binary..."

cd "$WOLFIP_DIR"
make test-wolfguard-interop 2>&1 | tail -5
log "Binary built: build/test/test-wolfguard-interop"

#
# Step 7: Launch wolfIP process (creates TUN)
#

log "Step 7: Launching wolfIP interop process..."

rm -f /tmp/wolfguard-interop-ready /tmp/wolfguard-kernel-ready

./build/test/test-wolfguard-interop \
    "$KEY_DIR/wolfip_priv.bin" \
    "$KEY_DIR/kernel_pub.bin" &
WOLFIP_PID=$!

# Wait for TUN to be created (up to 10s)
log "Waiting for TUN interface..."
for i in $(seq 1 100); do
    if [ -f /tmp/wolfguard-interop-ready ]; then
        break
    fi
    sleep 0.1
done

if ! ip link show "$TUN_NAME" &>/dev/null; then
    err "TUN interface $TUN_NAME did not appear"
    exit 1
fi
log "TUN $TUN_NAME is up"

#
# Step 8: Configure kernel wolfGuard
#

log "Step 8: Configuring kernel wolfGuard..."

# Create kernel wg0 interface (wolfguard type, not wireguard)
ip link add wg0 type wolfguard

# Set private key and listen port
wg-fips set wg0 \
    private-key "$KEY_DIR/kernel_priv_b64" \
    listen-port "$KERNEL_WG_PORT"

# Add wolfIP as peer
WOLFIP_PUB_B64=$(cat "$KEY_DIR/wolfip_pub_b64")
wg-fips set wg0 \
    peer "$WOLFIP_PUB_B64" \
    endpoint "${WOLFIP_TUN_IP}:${WOLFIP_WG_PORT}" \
    allowed-ips "${WOLFIP_WG_IP}/32"

# Assign tunnel IP and bring up
ip addr add "${KERNEL_WG_IP}/24" dev wg0
ip link set wg0 up

log "Kernel wg0 configured:"
wg-fips show wg0

# Start echo server before signaling (so it's ready when data flows)
log "Step 9: Starting UDP echo server on ${KERNEL_WG_IP}:${ECHO_PORT}..."
socat UDP4-LISTEN:${ECHO_PORT},bind=${KERNEL_WG_IP},fork EXEC:'/bin/cat' &
SOCAT_PID=$!
sleep 0.5
log "Echo server running (PID=$SOCAT_PID)"

# Signal wolfIP process that kernel is ready, this triggers Phase 1:
# wolfIP initiates handshake, sends probes, gets echo reply
touch /tmp/wolfguard-kernel-ready
log "Signaled wolfIP process: kernel ready (Phase 1: wolfIP → kernel)"

#
# Step 10: Phase 2, kernel initiates handshake to wolfIP
#

# Wait for wolfIP to signal that phase 2 is ready (it has reset its
# wolfGuard state and is waiting for a kernel-initiated handshake)
log "Waiting for wolfIP phase 2 ready..."
for i in $(seq 1 600); do
    if [ -f /tmp/wolfguard-phase2-ready ]; then
        break
    fi
    # Check if wolfIP died (phase 1 failed)
    if ! kill -0 "$WOLFIP_PID" 2>/dev/null; then
        warn "wolfIP process exited before phase 2"
        break
    fi
    sleep 0.1
done

if [ -f /tmp/wolfguard-phase2-ready ]; then
    log "Phase 2: Recreating kernel wg0 for fresh handshake..."

    # Fully recreate wg0 to clear all session state
    ip link del wg0 2>/dev/null || true
    ip link add wg0 type wolfguard
    wg-fips set wg0 \
        private-key "$KEY_DIR/kernel_priv_b64" \
        listen-port "$KERNEL_WG_PORT"
    WOLFIP_PUB_B64=$(cat "$KEY_DIR/wolfip_pub_b64")
    wg-fips set wg0 \
        peer "$WOLFIP_PUB_B64" \
        endpoint "${WOLFIP_TUN_IP}:${WOLFIP_WG_PORT}" \
        allowed-ips "${WOLFIP_WG_IP}/32"
    ip addr add "${KERNEL_WG_IP}/24" dev wg0
    ip link set wg0 up
    sleep 0.5

    # Send UDP probes from kernel to wolfIP through the tunnel.
    # This triggers the kernel to initiate a fresh handshake.
    log "Phase 2: Sending UDP probes to ${WOLFIP_WG_IP}:9999..."
    for i in $(seq 1 10); do
        echo "kernel-phase2-probe-$i" | socat - UDP4:${WOLFIP_WG_IP}:9999 2>/dev/null || true
        sleep 1
    done &
    PROBE_PID=$!
fi

# Wait for wolfIP process to finish (handles both phases)
log "Waiting for wolfIP process to complete..."

set +e
wait "$WOLFIP_PID"
RESULT=$?
set -e
WOLFIP_PID=""

[ -n "${PROBE_PID:-}" ] && kill "$PROBE_PID" 2>/dev/null || true

#
# Final report
#

echo ""
log "Kernel wolfguard status:"
wg-fips show wg0 2>&1 || true
echo ""

if [ "$RESULT" -eq 0 ]; then
    log "============================================"
    log "  ALL INTEROP TESTS PASSED"
    log "============================================"
    exit 0
else
    err "============================================"
    err "  INTEROP TEST FAILED (exit code: $RESULT)"
    err "============================================"
    exit 2
fi

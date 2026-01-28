#!/bin/bash
# Local testing script for m33mu TLS client/server demo with VDE networking
#
# This script demonstrates how to run the same test locally that runs in CI.
# It starts a VDE switch, launches the TLS server, waits for it to initialize,
# then launches the TLS client. Both communicate over a virtual network.
#
# Prerequisites:
# - m33mu emulator installed and in PATH
# - vde_switch installed (VDE virtual distributed ethernet)
# - wolfSSL cloned alongside wolfip (or WOLFSSL_ROOT set)
# - ARM GCC toolchain (arm-none-eabi-gcc)

set -e

# Configuration
VDE_SOCKET="/tmp/vde-switch.ctl"
TIMEOUT=60  # 60 seconds
WOLFSSL_ROOT="${WOLFSSL_ROOT:-$(pwd)/../../../wolfssl}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "  m33mu TLS Test - Local Execution"
echo "=========================================="
echo ""

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v m33mu &> /dev/null; then
    echo -e "${RED}ERROR: m33mu not found in PATH${NC}"
    echo "Install m33mu emulator first"
    exit 1
fi

if ! command -v vde_switch &> /dev/null; then
    echo -e "${RED}ERROR: vde_switch not found in PATH${NC}"
    echo "Install VDE: sudo apt install vde2 (Ubuntu/Debian)"
    exit 1
fi

if ! command -v arm-none-eabi-gcc &> /dev/null; then
    echo -e "${RED}ERROR: arm-none-eabi-gcc not found in PATH${NC}"
    echo "Install ARM GCC toolchain: sudo apt install gcc-arm-none-eabi"
    exit 1
fi

if [ ! -d "$WOLFSSL_ROOT" ]; then
    echo -e "${RED}ERROR: wolfSSL not found at $WOLFSSL_ROOT${NC}"
    echo "Clone wolfSSL: git clone https://github.com/wolfSSL/wolfssl.git"
    echo "Or set WOLFSSL_ROOT environment variable"
    exit 1
fi

echo -e "${GREEN}✓ All prerequisites found${NC}"
echo ""

# Build binaries
echo "Building TLS server binary..."
make clean > /dev/null
if ! CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy \
     make test-server WOLFSSL_ROOT="$WOLFSSL_ROOT"; then
    echo -e "${RED}ERROR: Server build failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Server binary built: $(ls -lh app-server.bin | awk '{print $5}')${NC}"

echo "Building TLS client binary..."
make clean > /dev/null
if ! CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy \
     make test-client WOLFSSL_ROOT="$WOLFSSL_ROOT"; then
    echo -e "${RED}ERROR: Client build failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Client binary built: $(ls -lh app-client.bin | awk '{print $5}')${NC}"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    killall vde_switch 2>/dev/null || true
    killall m33mu 2>/dev/null || true
    rm -rf "$VDE_SOCKET"
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

# Set trap to cleanup on exit
trap cleanup EXIT INT TERM

# Start VDE switch
echo "Starting VDE switch..."
echo vde_switch -s "$VDE_SOCKET" -d 
vde_switch -s "$VDE_SOCKET" -d 
VDE_RET=$?
sleep 2

if ! [ $VDE_RET -eq 0 ]; then
    echo -e "${RED}ERROR: VDE switch failed to start${NC}"
    exit 1
fi
echo -e "${GREEN}✓ VDE switch started ${NC}"
echo ""

# Start server
echo "Starting TLS server (m33mu)..."
echo "  MAC: $SERVER_MAC"
echo "  IP: 192.168.100.10:8443"
echo "  Expecting breakpoint: 0x7f (success)"
echo "  Timeout: ${TIMEOUT}ms"

m33mu --vde "$VDE_SOCKET" \
      --expect-bkpt 0x7f \
      --timeout $TIMEOUT \
      app-server.bin > server.log 2>&1 &
SERVER_PID=$!

echo -e "${GREEN}✓ Server started (PID: $SERVER_PID)${NC}"
echo ""

# Wait for server to initialize
echo "Waiting 5 seconds for server initialization..."
sleep 5

echo "Server log (initialization):"
echo "----------------------------"
head -30 server.log
echo "----------------------------"
echo ""

# Start client
echo "Starting TLS client (m33mu)..."
echo "  IP: 192.168.100.20"
echo "  Target: 192.168.100.10:8443"
echo "  Expecting breakpoint: 0x7f (success)"
echo "  Timeout: ${TIMEOUT}ms"

m33mu --vde "$VDE_SOCKET" \
      --expect-bkpt 0x7f \
      --timeout $TIMEOUT \
      app-client.bin > client.log 2>&1
CLIENT_EXIT=$?

echo ""
echo "Client log:"
echo "----------------------------"
cat client.log
echo "----------------------------"
echo ""

# Wait for server
echo "Waiting for server to complete..."
sleep 2

if kill -0 $SERVER_PID 2>/dev/null; then
    wait $SERVER_PID 2>/dev/null || true
fi
SERVER_EXIT=$?

echo ""
echo "Server log:"
echo "----------------------------"
cat server.log
echo "----------------------------"
echo ""

# Check results
echo "=========================================="
echo "  Test Results"
echo "=========================================="
echo ""

echo "Client exit code: $CLIENT_EXIT"
echo "Server exit code: $SERVER_EXIT"
echo ""

if [ $CLIENT_EXIT -eq 0 ] && { [ $SERVER_EXIT -eq 0 ] || [ $SERVER_EXIT -eq 143 ]; }; then
    echo -e "${GREEN}✓ TEST PASSED${NC}"
    echo ""
    echo "Both server and client successfully completed TLS handshake"
    echo "and data exchange. The test executed correctly!"
    exit 0
else
    echo -e "${RED}✗ TEST FAILED${NC}"
    echo ""
    echo "Expected:"
    echo "  - Client exit code: 0 (breakpoint 0x7f hit)"
    echo "  - Server exit code: 0 or 143"
    echo ""
    echo "Actual:"
    echo "  - Client exit code: $CLIENT_EXIT"
    echo "  - Server exit code: $SERVER_EXIT"
    echo ""
    echo "Check the logs above for error messages."
    echo "Common issues:"
    echo "  - Network not initialized: Check for 'Setting static IP' in logs"
    echo "  - Handshake timeout: Emulator might be too slow, increase timeout"
    echo "  - Connection refused: Server not listening yet, increase wait time"
    exit 1
fi

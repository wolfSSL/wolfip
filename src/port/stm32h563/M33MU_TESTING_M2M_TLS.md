# m33mu TLS Testing with VDE Networking

This document describes how to test the STM32H563 TLS client/server demo using the m33mu emulator with VDE (Virtual Distributed Ethernet) networking.

## Overview

The test setup consists of:
- **VDE Switch**: Virtual Ethernet switch that connects the emulator instances
- **TLS Server**: Runs on `192.168.100.10:8443`, echoes received data back
- **TLS Client**: Runs on `192.168.100.20`, connects to server and sends test message
- **Success Detection**: Both binaries trigger breakpoint `0x7f` on successful completion

This same test runs automatically in CI via GitHub Actions.

## Prerequisites

### Software Requirements

- **m33mu**: ARM Cortex-M33 emulator (`man m33mu` for documentation)
- **vde_switch**: Virtual Distributed Ethernet switch
- **arm-none-eabi-gcc**: ARM GCC toolchain for building
- **wolfSSL**: TLS library (clone alongside wolfip)

### Installation (Ubuntu/Debian)

```bash
# Install VDE
sudo apt install vde2

# Install ARM GCC toolchain
sudo apt install gcc-arm-none-eabi

# Clone wolfSSL (if not already done)
cd /path/to/parent
git clone https://github.com/wolfSSL/wolfssl.git
# wolfip should be at /path/to/parent/wolfip
```

For m33mu installation, refer to the m33mu documentation.

## Quick Start: Automated Script

The easiest way to run the test locally is using the provided script:

```bash
cd src/port/stm32h563
./test-m33mu-local.sh
```

The script will:
1. Check prerequisites
2. Build both server and client binaries
3. Start VDE switch
4. Launch server in background
5. Launch client (connects to server)
6. Display logs and results
7. Clean up automatically

Expected output on success:
```
==========================================
  Test Results
==========================================

Client exit code: 0
Server exit code: 0

✓ TEST PASSED

Both server and client successfully completed TLS handshake
and data exchange. The test executed correctly!
```

## Manual Step-by-Step Testing

For more control or debugging, you can run each component manually.

### Step 1: Build Binaries

```bash
cd src/port/stm32h563

# Build TLS server
make clean
CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy \
  make test-server WOLFSSL_ROOT=/path/to/wolfssl

# Build TLS client
make clean
CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy \
  make test-client WOLFSSL_ROOT=/path/to/wolfssl
```

This creates:
- `app-server.bin`: TLS server binary (echoes data on port 8443)
- `app-client.bin`: TLS client binary (connects and sends test message)

### Step 2: Start VDE Switch (Terminal 1)

The VDE switch provides a virtual Ethernet network for the emulators.

```bash
mkdir -p /tmp/vde
vde_switch -s /tmp/vde/switch.ctl -d
```

Options:
- `-s /tmp/vde/switch.ctl`: Socket path for VDE switch
- `-d`: Run as daemon

Leave this running throughout the test.

### Step 3: Start TLS Server (Terminal 2)

```bash
cd src/port/stm32h563

m33mu --vde /tmp/vde/switch.ctl \
      --vde-mac 52:54:00:12:34:56 \
      --expect-bkpt 0x7f \
      --timeout 60000 \
      app-server.bin
```

Parameters:
- `--vde /tmp/vde/switch.ctl`: Connect to VDE switch
- `--vde-mac 52:54:00:12:34:56`: MAC address for server
- `--expect-bkpt 0x7f`: Exit successfully (code 0) when this breakpoint is hit
- `--timeout 60000`: Fail after 60 seconds if breakpoint not hit
- `app-server.bin`: Server binary to execute

The server will:
1. Initialize wolfIP stack
2. Configure static IP: 192.168.100.10
3. Start TLS server on port 8443
4. Wait for client connection
5. Echo received data back
6. Trigger breakpoint 0x7f on successful echo
7. Exit with code 0

### Step 4: Wait for Server Initialization

Wait **5 seconds** for the server to fully initialize before starting the client.

```bash
sleep 5
```

### Step 5: Start TLS Client (Terminal 3)

```bash
cd src/port/stm32h563

m33mu --vde /tmp/vde/switch.ctl \
      --vde-mac 52:54:00:12:34:57 \
      --expect-bkpt 0x7f \
      --timeout 60000 \
      app-client.bin
```

Parameters:
- `--vde /tmp/vde/switch.ctl`: Connect to same VDE switch as server
- `--vde-mac 52:54:00:12:34:57`: Different MAC address for client
- `--expect-bkpt 0x7f`: Exit successfully when breakpoint hit
- `--timeout 60000`: 60 second timeout
- `app-client.bin`: Client binary to execute

The client will:
1. Initialize wolfIP stack
2. Configure static IP: 192.168.100.20
3. Connect to 192.168.100.10:8443
4. Perform TLS 1.3 handshake
5. Send test message: "Hello TLS Server!\n"
6. Receive echoed response
7. Trigger breakpoint 0x7f on success
8. Exit with code 0

### Step 6: Check Exit Codes

```bash
echo $?
```

- **Exit code 0**: Success (breakpoint 0x7f was hit)
- **Exit code != 0**: Failure (timeout, connection error, or breakpoint 0x7e hit)

### Step 7: Cleanup

```bash
# Kill VDE switch
killall vde_switch

# Kill any remaining m33mu processes
killall m33mu

# Remove VDE directory
rm -rf /tmp/vde
```

## Network Configuration

| Component | MAC Address | IP Address | Port |
|-----------|-------------|------------|------|
| TLS Server | 52:54:00:12:34:56 | 192.168.100.10 | 8443 |
| TLS Client | 52:54:00:12:34:57 | 192.168.100.20 | - |

Network: 192.168.100.0/24

## Breakpoint Codes

The test uses ARM Cortex-M breakpoint instructions for success/failure detection:

| Breakpoint | Hex | Meaning |
|------------|-----|---------|
| `bkpt #0x7f` | 0xBE7F | Test passed - m33mu exits with code 0 |
| `bkpt #0x7e` | 0xBE7E | Test failed - m33mu exits with non-zero code |

When m33mu encounters the expected breakpoint (via `--expect-bkpt`), it exits gracefully with code 0.

## Expected Output

### Server Log (Success)

```
=== wolfIP STM32H563 Echo Server ===
Initializing wolfIP stack...
M33MU_TEST: Setting static IP configuration:
  IP: 192.168.100.10
  Mask: 255.255.255.0
  GW: 192.168.100.1
Initializing TLS server on port 8443...
TLS: Server ready on port 8443
Entering main loop. Ready for connections!
TLS: Client connected, starting handshake
TLS: Handshake complete
M33MU_TEST: TLS server echoed data successfully
M33MU_TEST: TLS server test PASSED
```

### Client Log (Success)

```
=== wolfIP STM32H563 Echo Server ===
Initializing wolfIP stack...
M33MU_TEST: Setting static IP configuration:
  IP: 192.168.100.20
  Mask: 255.255.255.0
  GW: 192.168.100.1
Initializing TLS client...
TLS Client: Initialized
Entering main loop. Ready for connections!

--- M33MU TLS Client Test: Connecting to TLS server ---
Target: 192.168.100.10:8443
TLS Client: Connection initiated
TLS Client: Connected!
TLS Client: Sending test message...
TLS Client: Message sent
TLS Client received 19 bytes:
Hello TLS Server!

M33MU_TEST: TLS client test PASSED
```

## Troubleshooting

### VDE Switch Not Starting

**Symptom:** `vde_switch` command not found

**Solution:**
```bash
sudo apt install vde2
```

### m33mu Not Found

**Symptom:** `m33mu: command not found`

**Solution:** Install m33mu emulator and add to PATH

### Server/Client Timeout (60 seconds)

**Symptoms:**
- No "TLS: Handshake complete" message
- m33mu exits after 60 seconds
- No breakpoint hit

**Possible Causes:**
1. **Client started too early**: Increase wait time between server and client start
   ```bash
   sleep 10  # Instead of 5
   ```

2. **Wrong IP addresses**: Verify server and client use correct IPs
   - Check UART output for "Setting static IP configuration"

3. **VDE not connected**: Ensure both use same VDE socket path

4. **Binary built without M33MU_TEST**: Rebuild with test targets
   ```bash
   make test-server
   make test-client
   ```

### Connection Refused

**Symptom:** Client gets "Connection failed" immediately

**Cause:** Server not fully initialized

**Solution:** Increase delay between server and client start

### Breakpoint 0x7e Hit (Failure)

**Symptom:** Exit code != 0, log shows "test FAILED"

**Cause:** Explicit failure detected in code (connection error, send failed)

**Solution:** Check logs for specific error message before breakpoint

### Build Fails - wolfSSL Not Found

**Symptom:**
```
wolfssl/options.h: No such file or directory
```

**Solution:**
```bash
# Clone wolfSSL
cd /path/to/parent
git clone https://github.com/wolfSSL/wolfssl.git

# Or set WOLFSSL_ROOT
export WOLFSSL_ROOT=/path/to/wolfssl
make test-server WOLFSSL_ROOT=/path/to/wolfssl
```

## GitHub Actions CI

The same test runs automatically on every push/PR via GitHub Actions.

**Workflow:** `.github/workflows/stm32h5-tls-m33mu.yml`

The CI:
1. Uses pre-built container: `ghcr.io/danielinux/m33mu-ci:1.3`
2. Clones wolfSSL
3. Builds both binaries
4. Starts VDE switch
5. Runs server in background
6. Runs client
7. Checks both exit codes
8. Uploads logs as artifacts

View workflow runs at: https://github.com/YOUR_ORG/wolfip/actions

## Advanced: Running Without TAP Interface

The VDE setup runs entirely in userspace and does **not** require:
- Root/sudo privileges (for packet capture)
- TAP interface configuration
- Network capabilities

This makes it ideal for:
- Sandboxed CI environments
- Containerized testing
- Non-privileged users

The emulators communicate through the VDE switch socket, which is a simple UNIX domain socket.

## Development: Modifying Tests

### Changing IP Addresses

Edit `src/port/stm32h563/main.c`:

```c
#ifdef M33MU_TEST
  #ifdef BUILD_TLS_SERVER_ONLY
    #define TEST_SERVER_IP "192.168.100.10"  // Change here
  #endif
  #ifdef BUILD_TLS_CLIENT_ONLY
    #define TEST_SERVER_IP "192.168.100.10"  // Must match server
    #define TEST_CLIENT_IP "192.168.100.20"  // Change here
  #endif
  #define TEST_NETMASK "255.255.255.0"
  #define TEST_GATEWAY "192.168.100.1"
#endif
```

### Changing Test Message

Edit the client section in `main.c`:

```c
#ifdef M33MU_TEST
    const char *test_msg = "Hello TLS Server!\n";  // Change message here
```

### Adjusting Timeouts

For slower systems, increase timeout:

```bash
m33mu --timeout 120000 ...  # 2 minutes instead of 60 seconds
```

Or increase initialization wait:

```bash
sleep 10  # 10 seconds instead of 5
```

## References

- **m33mu Documentation**: `man m33mu`
- **VDE Documentation**: https://github.com/virtualsquare/vde-2
- **wolfSSL**: https://www.wolfssl.com/documentation/
- **wolfIP README**: See main project README.md

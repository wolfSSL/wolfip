# wolfIP STM32H563 Port

This directory contains a bare-metal port of wolfIP for the STM32H563 microcontroller, featuring an Ethernet driver and TCP/IP echo server example.

## Hardware Requirements

- STM32H563 development board (e.g., NUCLEO-H563ZI)
- Ethernet connection (RMII interface)
- ST-LINK debugger (built-in on NUCLEO boards)
- USB cable for serial output

## Software Requirements

- ARM GCC toolchain (`arm-none-eabi-gcc`)
- OpenOCD (STMicroelectronics fork recommended)
- Serial terminal (e.g., minicom, screen, or picocom)

### Installing Dependencies (Ubuntu/Debian)

```bash
sudo apt install gcc-arm-none-eabi openocd
```

## Building

### Default Build (TrustZone Disabled - Recommended)

```bash
cd src/port/stm32h563
make
```

This produces `app.elf` and `app.bin` for use with TZEN=0 (TrustZone disabled).

### TrustZone Enabled Build

```bash
make TZEN=1
```

This builds firmware for execution in TrustZone secure mode with proper SAU, GTZC, and MPCBB configuration for Ethernet DMA access.

## Disabling TrustZone (Option Bytes)

If your board has TrustZone enabled, you must disable it via option bytes before using the TZEN=0 build. Use STM32CubeProgrammer or OpenOCD:

### Using STM32CubeProgrammer (Recommended)

1. Open STM32CubeProgrammer
2. Connect to the target
3. Go to **Option Bytes** tab
4. Find **TZEN** under "User Configuration"
5. Set TZEN to **0xC3** (disabled)
6. Click **Apply**

## TrustZone Support (TZEN=1)

The TZEN=1 build provides full TrustZone support for running wolfIP in secure mode:

- **SAU Configuration:** Enables ALLNS mode for non-secure DMA access to all undefined regions
- **GTZC/MPCBB:** Configures SRAM3 blocks (registers 36-39) as non-secure for Ethernet DMA buffers
- **TZSC:** Marks Ethernet MAC peripheral as non-secure for DMA operation
- **Secure Aliases:** Uses secure peripheral addresses (0x5xxxxxxx) for RCC, GPIO, GTZC
- **Separate ETHMEM:** Places Ethernet TX/RX buffers in dedicated non-secure SRAM region

### Enabling TrustZone (Option Bytes)

To use the TZEN=1 build, TrustZone must be enabled in the option bytes:

1. Open STM32CubeProgrammer
2. Connect to the target
3. Go to **Option Bytes** tab
4. Find **TZEN** under "User Configuration"
5. Set TZEN to **0xB4** (enabled)
6. Click **Apply**

### Using OpenOCD

```bash
openocd -f interface/stlink-dap.cfg -f target/stm32h5x.cfg -c "init" -c "halt" -c "stm32h5x option_write 0 0x5200201C 0xC3B6" -c "reset" -c "exit"
```

> **Warning:** Modifying option bytes can lock the device. Ensure you understand the process before proceeding.

### Verifying TrustZone Status

When flashing, OpenOCD will report TrustZone status:

```
Info : TZEN = 0xC3 : TrustZone disabled by option bytes   # Good for TZEN=0
Info : TZEN = 0xB4 : TrustZone enabled by option bytes    # Requires TZEN=1 build
```

## Flashing

```bash
openocd -f interface/stlink-dap.cfg -f target/stm32h5x.cfg \
    -c "program app.elf verify reset exit"
```

## Serial Console

Connect to the USB serial port (typically `/dev/ttyACM0`) at 115200 baud:

```bash
# Using screen
screen /dev/ttyACM0 115200

# Using minicom
minicom -D /dev/ttyACM0 -b 115200

# Using picocom
picocom -b 115200 /dev/ttyACM0
```

## Example Output

When the firmware boots successfully with DHCP (default), you should see output similar to:

```
=== wolfIP STM32H563 Echo Server ===
Initializing wolfIP stack...
Configuring GPIO for RMII...
Enabling Ethernet clocks...
Resetting Ethernet MAC...
Initializing Ethernet MAC...
  PHY link: UP, PHY addr: 0x00000000
Setting IP configuration:
  IP: 192.168.12.11
  Mask: 255.255.255.0
  GW: 192.168.12.1
Creating TCP socket on port 7...
Entering main loop. Ready for connections!
Loop starting...
```

When static IP is enabled, the output will show "Setting IP configuration:" instead of "DHCP configuration received:".

The "PHY link: UP" message indicates the Ethernet PHY has established a link with the network.

## Network Configuration

The example can be configured to use either DHCP or static IP. By default, DHCP is enabled.

### DHCP Configuration (Default)

By default, the device uses DHCP to automatically obtain IP address, subnet mask, gateway, and DNS server from a DHCP server on the network. The obtained configuration will be displayed on the serial console.

**Note:** When DHCP is enabled, the device will wait up to 30 seconds for a DHCP server response during initialization. If no DHCP server is available, the device will timeout and continue without network configuration.

### Static IP Configuration

To use static IP instead of DHCP, set `WOLFIP_ENABLE_DHCP` to `0` in `config.h`:

```c
#define WOLFIP_ENABLE_DHCP 0
```

Or compile with:

```bash
make CFLAGS+="-DWOLFIP_ENABLE_DHCP=0"
```

When static IP is enabled, the example configures the following:

| Setting | Value |
|---------|-------|
| IP Address | 192.168.12.11 |
| Subnet Mask | 255.255.255.0 |
| Gateway | 192.168.12.1 |

Configure your host PC's Ethernet interface to be on the same subnet:

```bash
sudo ip addr add 192.168.12.1/24 dev <interface>
sudo ip link set <interface> up
```

Replace `<interface>` with your Ethernet interface name (e.g., `eth0`, `enp5s0`).

## Testing TCP Echo Server

The default build provides a TCP echo server on port 7.

### Building default build

```bash
make
```

### Expected Serial Output

```
=== wolfIP STM32H563 Echo Server ===
Initializing wolfIP stack...
Configuring GPIO for RMII...
Enabling Ethernet clocks...
Resetting Ethernet MAC...
Initializing Ethernet MAC...
  PHY link: UP, PHY addr: 0x00000000
DHCP configuration received:
  IP: 192.168.0.197
  Mask: 255.255.255.0
  GW: 192.168.0.1
Creating TCP socket on port 7...
Entering main loop. Ready for connections!
```

### Testing Echo Server

```bash
# Get the device IP from serial output (DHCP) or use static IP

# Test ICMP connectivity
ping <device-ip>

# Test TCP echo server (port 7)
echo "Hello wolfIP!" | nc <device-ip> 7
# Expected: "Hello wolfIP!" echoed back

# Interactive TCP test
nc <device-ip> 7
# Type messages and see them echoed back
```

## TLS

The port includes optional TLS 1.3 support using wolfSSL. This enables secure encrypted communication.

### Prerequisites

Clone wolfSSL alongside wolfip:

```bash
cd /path/to/parent
git clone https://github.com/wolfSSL/wolfssl.git
# wolfip should be at /path/to/parent/wolfip
```

### Building with TLS

```bash
make ENABLE_TLS=1
```

Or specify a custom wolfSSL path:

```bash
make ENABLE_TLS=1 WOLFSSL_ROOT=/path/to/wolfssl
```

### Building with HTTPS Web Server

The HTTPS web server provides a status page accessible via browser:

```bash
make ENABLE_TLS=1 ENABLE_HTTPS=1
```

### Building with SSH Server

SSH server requires both wolfSSL and wolfSSH:

```bash
# Clone wolfSSH alongside wolfip
cd /path/to/parent
git clone https://github.com/wolfSSL/wolfssh.git

# Build with SSH support
make ENABLE_TLS=1 ENABLE_SSH=1
```

Or specify a custom wolfSSH path:

```bash
make ENABLE_TLS=1 ENABLE_SSH=1 WOLFSSH_ROOT=/path/to/wolfssh
```

### Full Featured Build

Build with all features (TLS echo, HTTPS web server, and SSH shell):

```bash
make ENABLE_TLS=1 ENABLE_HTTPS=1 ENABLE_SSH=1
```

This provides:
- TCP echo server on port 7
- TLS echo server on port 8443
- HTTPS web server on port 443
- SSH shell on port 22

### TLS Example Output

With TLS enabled, you'll see additional output including the TLS server startup and TLS client test:

```
=== wolfIP STM32H563 Echo Server ===
Initializing wolfIP stack...
...
DHCP configuration received:
  IP: 192.168.0.197
  Mask: 255.255.255.0
  GW: 192.168.0.1
Creating TCP socket on port 7...
Initializing TLS server on port 8443...
TLS: Initializing wolfSSL
TLS: Loading certificate
TLS: Loading private key
TLS: Server ready on port 8443
Initializing HTTPS server on port 443...
HTTPS: Initializing wolfSSL
HTTPS: Loading certificate
HTTPS: Loading private key
HTTPS: Server ready
Initializing TLS client...
TLS Client: Initializing wolfSSL
TLS Client: Initialized
Entering main loop. Ready for connections!
Loop starting...

--- TLS Client Test: Connecting to Google ---
Target: 142.250.189.174:443
TLS Client: Connecting...
TLS Client: TLS handshake...
TLS Client: Connected!
TLS Client: Sending HTTP GET request...
TLS Client received 851 bytes:
HTTP/1.1 301 Moved Permanently
...
TLS Client: Passed! Connection closed after response
```

### Building TLS Mode

```bash
make ENABLE_TLS=1
```

### Testing the TLS Server

The TLS echo server listens on port 8443. Test with OpenSSL:

```bash
# Basic TLS connection test
(echo "Hello TLS!"; sleep 2) | openssl s_client -connect <device-ip>:8443 -quiet

# View full handshake details
openssl s_client -connect <device-ip>:8443 -tls1_3

# View TLS session details
openssl s_client -connect <device-ip>:8443 -tls1_3 -brief
```

### Expected TLS Test Output

```
depth=0 CN = wolfIP-STM32H563, O = wolfSSL, C = US
verify error:num=18:self-signed certificate
Hello TLS!
```

The self-signed certificate warning is expected for development. Replace with a valid certificate for production.

### TLS Client (Google Test)

The TLS build includes a client example that connects to Google over HTTPS to verify outbound TLS connectivity. This runs automatically ~5 seconds after boot.

**Example Output:**
```
--- TLS Client Test: Connecting to Google ---
Target: 142.250.189.174:443
TLS Client: Connecting...
TLS Client: Connection initiated
TLS Client: TLS handshake...
TLS Client: Connected!
TLS Client: Sending HTTP GET request...
TLS Client: Request sent
TLS Client received 851 bytes:
HTTP/1.1 301 Moved Permanently
Location: https://www.google.com/
...
TLS Client: Passed! Connection closed after response
```

The 301 redirect is expected - Google redirects `google.com` to `www.google.com`. The "Passed!" message confirms the full TLS 1.3 handshake completed successfully.

### TLS Configuration

The TLS configuration is in `user_settings.h`:

| Setting | Description |
|---------|-------------|
| TLS 1.3 only | `WOLFSSL_TLS13`, `NO_OLD_TLS` |
| Key Exchange | ECDHE with P-256 (secp256r1) |
| Cert Verify | RSA (most servers use RSA certs) |
| Ciphers | AES-GCM, ChaCha20-Poly1305 |
| SNI | Server Name Indication enabled |

### TLS Files

| File | Description |
|------|-------------|
| `user_settings.h` | wolfSSL compile-time configuration |
| `certs.h` | Embedded ECC P-256 test certificate |
| `tls_server.c/h` | TLS echo server implementation |
| `tls_client.c/h` | TLS client (for outbound connections) |

### Generating Custom Certificates

The included test certificate is for development only. Generate your own:

```bash
# Generate ECC P-256 key and self-signed certificate
openssl ecparam -genkey -name prime256v1 -out server_key.pem
openssl req -new -x509 -key server_key.pem -out server_cert.pem \
    -days 3650 -subj "/CN=my-device/O=my-org/C=US"

# Convert to C header (update certs.h)
# Copy PEM content into certs.h as string literals
```

## HTTPS Web Server

When built with `ENABLE_HTTPS=1`, the device serves a status web page on port 443.

### Building HTTPS Mode

```bash
make ENABLE_TLS=1 ENABLE_HTTPS=1
```

### Expected Serial Output (HTTPS Mode)

```
=== wolfIP STM32H563 Echo Server ===
...
DHCP configuration received:
  IP: 192.168.0.197
  Mask: 255.255.255.0
  GW: 192.168.0.1
Creating TCP socket on port 7...
Initializing TLS server on port 8443...
TLS: Server ready on port 8443
Initializing HTTPS server on port 443...
HTTPS: Initializing wolfSSL
HTTPS: Loading certificate
HTTPS: Loading private key
HTTPS: Server ready
Entering main loop. Ready for connections!
```

### Testing HTTPS

```bash
# Using curl (skip certificate verification for self-signed cert)
curl -k https://<device-ip>/

# Using openssl to see TLS details
openssl s_client -connect <device-ip>:443 -tls1_3

# Using a browser
# Navigate to https://<device-ip>/ and accept the self-signed certificate warning
```

### Expected HTTPS Response

```html
<!DOCTYPE html><html><head><title>wolfIP STM32H563</title>
...
<h1>wolfIP Status</h1>
<table>
<tr><td class="label">Device</td><td class="value">STM32H563</td></tr>
<tr><td class="label">IP Address</td><td class="value">192.168.0.197</td></tr>
<tr><td class="label">Uptime</td><td class="value">1234 sec</td></tr>
<tr><td class="label">TLS</td><td class="value">TLS 1.3</td></tr>
<tr><td class="label">Cipher</td><td class="value">ECC P-256</td></tr>
</table>
...
```

### HTTPS Status Page

The status page displays:
- Device type (STM32H563)
- IP address (dynamically updated from DHCP or static config)
- Uptime in seconds (continuously updated)
- TLS version (TLS 1.3)
- Cipher suite (ECC P-256)

## SSH Server

When built with `ENABLE_SSH=1`, the device provides an SSH shell on port 22.

### Building SSH Mode

```bash
# First, clone wolfSSH alongside wolfip
cd /path/to/parent
git clone https://github.com/wolfSSL/wolfssh.git

# Build with SSH support (requires TLS)
cd wolfip/src/port/stm32h563
make ENABLE_TLS=1 ENABLE_SSH=1
```

### Expected Serial Output (SSH Mode)

```
=== wolfIP STM32H563 Echo Server ===
...
Initializing TLS server on port 8443...
TLS: Server ready on port 8443
Initializing SSH server on port 22...
SSH: Initializing wolfSSH
SSH: Loading host key
SSH: Server ready on port 22
Entering main loop. Ready for connections!
```

### SSH Credentials

| Username | Password |
|----------|----------|
| admin    | wolfip   |

**Warning:** These are default credentials for testing. Change them in `ssh_server.c` for production use.

### Testing SSH

```bash
# Connect via SSH
ssh admin@<device-ip>

# Enter password: wolfip
```

### SSH Shell Commands

Once connected, the following commands are available:

| Command | Description |
|---------|-------------|
| help    | Show available commands |
| info    | Show device information |
| uptime  | Show uptime in seconds |
| exit    | Close SSH session |

### SSH Example Session

```
$ ssh admin@192.168.0.197
admin@192.168.0.197's password:
=== wolfIP SSH Shell ===
Type 'help' for available commands.

wolfip> info

Device: STM32H563
Stack:  wolfIP
SSH:    wolfSSH
TLS:    wolfSSL TLS 1.3

wolfip> uptime

Uptime: 1234 seconds

wolfip> exit

Goodbye!
Connection to 192.168.0.197 closed.
```

### Generating Custom SSH Host Key

The included test host key is for development only. Generate your own:

```bash
# Generate ECC P-256 key
openssl ecparam -genkey -name prime256v1 -out ssh_host_key.pem
openssl ec -in ssh_host_key.pem -outform DER -out ssh_host_key.der

# Convert to C header
xxd -i ssh_host_key.der > ssh_keys.h

# Update the array name in ssh_keys.h to ssh_host_key_der
```

## MQTT Client

When built with `ENABLE_MQTT=1`, the device includes an MQTT client that publishes status messages to a broker.

### Prerequisites

Clone wolfMQTT alongside wolfip:

```bash
cd /path/to/parent
git clone https://github.com/wolfSSL/wolfMQTT.git
# wolfip should be at /path/to/parent/wolfip
```

### Building MQTT Mode

```bash
# MQTT requires TLS
make ENABLE_TLS=1 ENABLE_MQTT=1
```

Or specify a custom wolfMQTT path:

```bash
make ENABLE_TLS=1 ENABLE_MQTT=1 WOLFMQTT_ROOT=/path/to/wolfmqtt
```

### Expected Serial Output (MQTT Mode)

```
=== wolfIP STM32H563 Echo Server ===
...
Initializing TLS server on port 8443...
TLS: Server ready on port 8443
Initializing MQTT client...
MQTT: Initializing client
MQTT: Initialized, connecting to 54.36.178.49:8883
Entering main loop. Ready for connections!
Loop starting...
MQTT: Connecting...
MQTT: TCP connected
MQTT: TLS handshake...
MQTT: TLS connected
MQTT: Sending CONNECT...
MQTT: Connected to broker
```

### MQTT Configuration

| Setting | Default Value |
|---------|--------------|
| Broker IP | 54.36.178.49 (test.mosquitto.org) |
| Broker Port | 8883 (TLS) |
| Client ID | wolfip-stm32h563 |
| Publish Topic | wolfip/status |
| Keep-alive | 60 seconds |
| QoS | 0 (fire and forget) |

### Subscribing to Device Messages

To see messages published by the device:

```bash
# Subscribe to the status topic
mosquitto_sub -h test.mosquitto.org -t "wolfip/status" -v

# Expected output (every 60 seconds):
# wolfip/status STM32H563 online, uptime: 60s
# wolfip/status STM32H563 online, uptime: 120s
```

### Full Featured Build

Build with all features (TLS, HTTPS, SSH, and MQTT):

```bash
make ENABLE_TLS=1 ENABLE_HTTPS=1 ENABLE_SSH=1 ENABLE_MQTT=1
```

This provides:
- TCP echo server on port 7
- TLS echo server on port 8443
- HTTPS web server on port 443
- SSH shell on port 22
- MQTT client publishing to test.mosquitto.org

### MQTT Files

| File | Description |
|------|-------------|
| `mqtt_client.c/h` | MQTT client state machine and API |
| `../wolfmqtt_io.c` | wolfMQTT I/O glue layer for wolfIP sockets |
| `user_settings.h` | wolfMQTT compile-time configuration |

## Files

| File | Description |
|------|-------------|
| `main.c` | Application entry point, wolfIP initialization, echo server |
| `stm32h5_eth.c` | Ethernet MAC/DMA driver for STM32H5 |
| `stm32h5_eth.h` | Ethernet driver header |
| `startup.c` | Startup code and data initialization |
| `ivt.c` | Interrupt vector table |
| `syscalls.c` | Newlib syscall stubs |
| `target.ld` | Linker script for TZEN=0 |
| `target_tzen.ld` | Linker script for TZEN=1 |
| `config.h` | Build configuration |
| `Makefile` | Build system |
| `user_settings.h` | wolfSSL/wolfSSH configuration |
| `certs.h` | Embedded TLS certificates (TLS builds only) |
| `tls_server.c/h` | TLS echo server (TLS builds only) |
| `tls_client.c/h` | TLS client for outbound connections (TLS builds only) |
| `https_server.c/h` | HTTPS web server (HTTPS builds only) |
| `ssh_server.c/h` | SSH shell server (SSH builds only) |
| `ssh_keys.h` | Embedded SSH host key (SSH builds only) |
| `mqtt_client.c/h` | MQTT client state machine (MQTT builds only) |
| `../wolfmqtt_io.c` | wolfMQTT I/O callbacks for wolfIP (MQTT builds only) |

## Troubleshooting

### No Serial Output

- Check USB connection and correct serial port
- Verify baud rate is 115200
- Try resetting the board

### OpenOCD Connection Fails

- Ensure ST-LINK drivers are installed
- Try `sudo` if permission denied
- Check that no other debugger is connected

### Ethernet Not Responding

- Verify physical Ethernet connection
- Check that host PC is on same subnet (192.168.12.x)
- Confirm PHY link is up (check serial output for "link" status)

### TrustZone Errors

If you see `stm32h5x.cpu in Secure state` but built with TZEN=0:
- The board has TrustZone enabled
- Either rebuild with `make TZEN=1` or disable TrustZone via option bytes

## License

This code is part of wolfIP and is licensed under GPLv3. See the LICENSE file in the repository root for details.

Copyright (C) 2026 wolfSSL Inc.

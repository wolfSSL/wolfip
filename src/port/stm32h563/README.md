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
make TZEN=0
```

This produces `app.elf` and `app.bin` for use with TZEN=0 (TrustZone disabled).

### TrustZone Enabled Build (Experimental)

```bash
make TZEN=1
```

> **Note:** TZEN=1 support is experimental. The Ethernet driver currently has issues receiving packets when TrustZone is enabled.

## Disabling TrustZone (Option Bytes)

If your board has TrustZone enabled, you must disable it via option bytes before using the TZEN=0 build. Use STM32CubeProgrammer or OpenOCD:

### Using STM32CubeProgrammer (Recommended)

1. Open STM32CubeProgrammer
2. Connect to the target
3. Go to **Option Bytes** tab
4. Find **TZEN** under "User Configuration"
5. Set TZEN to **0xC3** (disabled)
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

When the firmware boots successfully, you should see output similar to:

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

The "PHY link: UP" message indicates the Ethernet PHY has established a link with the network.

## Network Configuration

The example configures the following static IP:

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

## Testing

Once running, the echo server listens on TCP port 7:

```bash
# Test with netcat
echo "Hello wolfIP!" | nc 192.168.12.11 7

# Test with ping
ping 192.168.12.11
```

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

## TrustZone Support (TZEN=1) - Experimental

The TZEN=1 build adds TrustZone support:

- **SAU Configuration:** Marks memory regions for non-secure DMA access
- **GTZC/MPCBB:** Configures SRAM3 blocks for Ethernet DMA
- **Secure Aliases:** Uses secure peripheral addresses (0x5xxxxxxx)
- **Separate ETHMEM:** Places Ethernet buffers in dedicated non-secure SRAM

### Current Limitations

The TZEN=1 build compiles and runs, but the Ethernet driver experiences RBU (Receive Buffer Unavailable) errors. This appears to be a DMA access issue that requires further investigation.

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

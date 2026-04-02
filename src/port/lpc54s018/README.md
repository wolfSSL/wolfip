# wolfIP LPC54S018M-EVK Port

Bare-metal port of wolfIP for the NXP LPCXpresso54S018M development board, featuring an Ethernet driver and TCP/IP echo server example.

## Quick Start

1. **Build:**
   ```bash
   cd src/port/lpc54s018
   make
   ```

2. **Flash to board:**
   ```bash
   pyocd flash -t lpc54608 app.elf
   ```

3. **Monitor UART output** (115200 baud on /dev/ttyACM0):
   ```bash
   screen /dev/ttyACM0 115200
   ```
   Get the device IP address from the DHCP output.

4. **Test** (replace `<device-ip>` with IP from step 3):
   ```bash
   # TCP Echo
   echo "Hello" | nc <device-ip> 7

   # Ping
   ping <device-ip>
   ```

## Hardware Requirements

- LPCXpresso54S018M development board (NXP OM40003)
- Ethernet connection (RMII, RJ45 at J4)
- USB cable for debug (J8, on-board Link2 CMSIS-DAP)

## Software Requirements

- ARM GCC toolchain (`arm-none-eabi-gcc`)
- pyocd (`pip install pyocd`)
- Serial terminal (screen, minicom, picocom)

### Installing Dependencies (Ubuntu/Debian)

```bash
sudo apt install gcc-arm-none-eabi
pip install pyocd
```

## Building

```bash
cd src/port/lpc54s018
make
```

This produces `app.elf` and `app.bin`.

### Checking Memory Usage

```bash
make size
```

```
   text    data     bss     dec     hex filename
  52000    1732   53076  106808   1a138 app.elf
```

## Flashing

```bash
pyocd flash -t lpc54608 app.elf
```

Note: use `-t lpc54608` as the target type since `lpc54s018` is not in pyocd's built-in list.

## Serial Console

Connect to the USB serial port at 115200 baud:

```bash
screen /dev/ttyACM0 115200
```

## Example Output

```
=== wolfIP LPC54S018M-EVK ===
PHY addr=0 link=UP
Starting DHCP...
Ready! ping <ip> / echo test | nc <ip> 7
DHCP bound: 192.168.0.138
```

## Network Configuration

### DHCP (Default)

DHCP is enabled by default. The board obtains its IP automatically and prints it to UART. Falls back to static IP after 30 seconds if no DHCP server responds.

### Static IP

Set `WOLFIP_ENABLE_DHCP` to `0` in `config.h`:

```c
#define WOLFIP_ENABLE_DHCP      0
#define WOLFIP_IP               "192.168.1.10"
#define WOLFIP_NETMASK          "255.255.255.0"
#define WOLFIP_GW               "192.168.1.1"
```

## Testing TCP Echo Server

```bash
# Test ICMP
ping <device-ip>

# Test TCP echo (port 7)
echo "Hello wolfIP!" | nc <device-ip> 7

# Interactive
nc <device-ip> 7
```

## Jumper Settings

| Jumper | Position | Function |
|--------|----------|----------|
| JP11 | 1-2 (default) | Ethernet TXD/RXD |
| JP12 | 1-2 (default) | Ethernet TXD/RXD |
| JP14 | 1-2 (EN) | ENET MDC |
| JP15 | 1-2 (EN) | ENET MDIO |
| JP5 | Open (default) | Link2 normal boot |

## Files

| File | Description |
|------|-------------|
| `main.c` | Application entry, wolfIP init, echo server |
| `../lpc_enet/lpc_enet.c` | Ethernet MAC/DMA driver (shared) |
| `../lpc_enet/lpc_enet.h` | Ethernet driver header (shared) |
| `lpc54s018_eth.h` | Board-specific ENET parameters |
| `startup.c` | Startup code and data initialization |
| `ivt.c` | Interrupt vector table + SPIFI config |
| `syscalls.c` | Newlib syscall stubs |
| `target_ram.ld` | Linker script (RAM execution) |
| `target.ld` | Linker script (SPIFI flash boot) |
| `config.h` | wolfIP stack configuration |
| `fix_checksum.py` | LPC boot ROM vector checksum tool |
| `Makefile` | Build system |

## Troubleshooting

### No Serial Output
- Check J8 (USB Debug-Link) is connected, not J1
- Check JP5 is open (not shunted)
- Verify baud rate is 115200

### Ethernet Not Responding
- Verify cable is in J4, check RJ45 link LEDs are lit
- Check JP14 and JP15 are both in EN position
- If using static IP, ensure host is on the same subnet

### pyocd Cannot Find Target
- Use `-t lpc54608` as target type
- Add udev rule: `SUBSYSTEM=="usb", ATTR{idVendor}=="1fc9", MODE="0666"`

## License

This code is part of wolfIP and is licensed under GPLv3. See the LICENSE file in the repository root for details.

Copyright (C) 2026 wolfSSL Inc.

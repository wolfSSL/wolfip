# wolfIP LPC54S018M-EVK Port

Bare-metal port of wolfIP for the NXP LPCXpresso54S018M development board, featuring an Ethernet driver and TCP/IP echo server example.

## Quick Start

1. **Install pyocd target pack** (one-time):
   ```bash
   pyocd pack install lpc54s018j4met180
   ```

2. **Build for SPIFI flash boot:**
   ```bash
   cd src/port/lpc54s018
   make
   ```

3. **Program SPIFI flash and reset:**
   ```bash
   bash flash.sh
   ```

4. **Monitor UART output** (115200 baud on /dev/ttyACM0):
   ```bash
   screen /dev/ttyACM0 115200
   ```
   Get the device IP address from the DHCP output.

5. **Test** (replace `<device-ip>` with IP from step 4):
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

### SPIFI Flash Boot (Recommended)

```bash
bash flash.sh
```

The flash script programs `app.bin` to SPIFI flash at `0x10000000` via pyocd
using the `lpc54s018j4met180` target pack, then resets the board so the
boot ROM runs and jumps into our firmware. The boot ROM validates the
enhanced boot header at offset `0x160` and the vector checksum at `0x1C`
(both written by `fix_checksum.py`).

### SRAM-Loaded Build (Development)

For fast iteration without re-programming SPIFI flash:

```bash
make ram        # Build with target_ram.ld
bash flash_ram.sh
```

This loads the firmware into SRAM via pyocd and starts execution from
`0x20000181`. UART may be unreliable in this mode because the boot ROM
clock setup is bypassed; use SPIFI flash boot for verified UART operation.

## Notes

### LPC54S018 PRESETCTRL register polarity

The LPC54018/LPC54S018 PRESETCTRL registers use this convention (matches
the NXP MCUXpresso SDK `fsl_reset.c`):

- Bit = **1** means peripheral is **in reset** (asserted)
- Bit = **0** means peripheral is **out of reset** (released)

Therefore: `PRESETCTRLSET` (bit -> 1) **asserts** reset, and
`PRESETCTRLCLR` (bit -> 0) **deasserts** reset.

### DHCP / Link Behavior

The PHY (LAN8742A on the LPCXpresso54S018M-EVK) is held in reset via GPIO
P2.26 and needs ~167ms after release before its REF_CLK stabilizes and MDIO
is reliable. The port waits 200ms then runs PHY auto-negotiation.

After ETH init the firmware prints PHY diagnostics:
```
PHY: addr=0 ID=0007:c130 BSR=786d autoneg=OK link=UP
```
- `ID` = `PHY_ID1:PHY_ID2`. LAN8742A reports `0007:c130`.
- `BSR` = full Basic Status Register value (raw).
- `autoneg`/`link` are decoded from BSR bit 5 / bit 2.

Before starting DHCP the firmware waits up to 5s for link UP. If the cable
is plugged in later, DHCP DISCOVER is re-issued every 10s only when the PHY
reports link UP — this avoids flooding the network with discovers when the
cable is unplugged. After 30s total, it falls back to the static IP defined
in `config.h`.

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
| `target.ld` | Linker script (SPIFI flash boot - default) |
| `target_ram.ld` | Linker script (RAM execution - dev only) |
| `flash.sh` | Program SPIFI flash and reset (recommended) |
| `flash_ram.sh` | Load firmware to SRAM and run (dev only, no UART) |
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

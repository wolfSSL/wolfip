# wolfIP VA416xx Port

Bare-metal port of wolfIP for the VORAGO VA416xx Cortex-M4 microcontroller, targeting the PEB1 EVK board with KSZ8041TL Ethernet PHY over MII.

## Hardware

- **MCU:** VA416xx (Cortex-M4, no FPU)
- **Flash:** 256KB @ 0x00000000
- **SRAM:** 64KB (RAM0 32KB @ 0x1FFF8000 + RAM1 32KB @ 0x20000000, contiguous)
- **Ethernet:** Synopsys DesignWare GMAC (normal/legacy descriptor format)
- **PHY:** KSZ8041TL via MII (PORTA[8-15], PORTB[0-10])
- **Debug UART:** UART0 on PORTG[2] TX / PORTG[3] RX, 115200 8N1
- **LED:** PORTG pin 5 (heartbeat)
- **Board:** PEB1 VA416xx EVK

## Prerequisites

- ARM GCC toolchain (`arm-none-eabi-gcc`)
- VA416xx SDK (default location: `../../../../VA416xx_SDK` relative to this directory, or sibling to the wolfip repo)
- Serial terminal (minicom, screen, or picocom)
- JTAG/SWD debugger (Segger J-Link, etc.)

### Installing ARM Toolchain (Ubuntu/Debian)

```bash
sudo apt install gcc-arm-none-eabi
```

## Quick Start

1. **Build:**
   ```bash
   cd src/port/va416xx
   make CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy SIZE=arm-none-eabi-size
   ```

2. **Flash** `app.bin` to the EVK using your debugger.

3. **Monitor UART output** (115200 baud):
   ```bash
   screen /dev/ttyUSB0 115200
   ```

4. **Test:**
   ```bash
   ping <device-ip>
   echo "Hello" | nc <device-ip> 7
   ```

## Building

### Default Build

```bash
make CC=arm-none-eabi-gcc OBJCOPY=arm-none-eabi-objcopy SIZE=arm-none-eabi-size
```

Produces `app.elf` and `app.bin`.

### Custom SDK Path

```bash
make SDK_ROOT=/path/to/VA416xx_SDK CC=arm-none-eabi-gcc \
     OBJCOPY=arm-none-eabi-objcopy SIZE=arm-none-eabi-size
```

### Memory Usage

```bash
make size CC=arm-none-eabi-gcc SIZE=arm-none-eabi-size
```

Example output:
```
=== Memory Usage ===
   text    data     bss     dec     hex filename
  38436    1760   44500   84696   14ad8 app.elf

Flash usage: 15.3% (40196 / 262144 bytes)
RAM usage (static): 70.6% (46260 / 65536 bytes)
```

### Static IP (No DHCP)

To disable DHCP and use a static IP, set `WOLFIP_ENABLE_DHCP` to `0` in `config.h`:

```c
#define WOLFIP_ENABLE_DHCP 0
```

Default static IP settings (defined in `config.h`):

| Setting     | Value           |
|-------------|-----------------|
| IP Address  | 192.168.1.100   |
| Subnet Mask | 255.255.255.0   |
| Gateway     | 192.168.1.1     |

## Example Output

```
=== wolfIP VA416xx Echo Server ===
Build: Feb 12 2026 10:30:00
Configuring MII pins...
Enabling ETH clock...
Initializing wolfIP stack...
Initializing Ethernet MAC + PHY...
  PHY link: UP
Starting DHCP...
DHCP bound:
  IP:   192.168.1.50
  Mask: 255.255.255.0
  GW:   192.168.1.1
Creating TCP echo server on port 7...
Ready! Test with:
  ping <ip>
  echo 'hello' | nc <ip> 7

Entering main loop...
```

## Testing

### ICMP Ping

```bash
ping <device-ip>
```

### TCP Echo (Port 7)

```bash
# Single message
echo "Hello wolfIP!" | nc <device-ip> 7

# Interactive
nc <device-ip> 7
```

### Wireshark Verification

Capture on the same network segment and verify:
- ARP request/reply (device responds to ARP)
- ICMP echo request/reply (ping)
- TCP 3-way handshake on port 7
- DHCP DISCOVER/OFFER/REQUEST/ACK (if DHCP enabled)

## Architecture

### Ethernet Driver (`va416xx_eth.c`)

The driver uses the Synopsys DesignWare GMAC with **normal (legacy) descriptor format**, which differs significantly from the STM32H5 port's enhanced/QoS format:

| Feature | VA416xx (Normal) | STM32H5 (Enhanced) |
|---------|-----------------|-------------------|
| OWN/FS/LS/FL | des0 | des3 |
| Buffer address | des2 | des0 |
| Ring wrap | TER/RER bits | Tail pointer + ring length |
| DMA kick | Poll demand registers | Tail pointer update |
| MTL layer | None (DMA_OPER_MODE) | Separate MTL registers |

**DMA Configuration:**
- 3 RX + 3 TX descriptors (16-byte aligned)
- 1536-byte buffers per descriptor
- Store-and-forward mode (TSF + RSF)
- PBL=8, Fixed Burst, Address-Aligned Beats
- Polling mode (interrupts disabled)

**PHY Access:** Uses VA416xx SDK HAL functions (`HAL_ReadPhyReg`, `HAL_WritePhyReg`, `HAL_ResetPHY`, `HAL_SetPhyAutoNegotiate`, `HAL_SetMacAddr`) which handle the Synopsys MDIO double-read workaround and pre-shifted register addresses.

### Memory Budget (64KB SRAM)

| Component | Size |
|-----------|------|
| DMA descriptors (6 x 16B) | 96 B |
| DMA buffers (6 x 1536B) | 9,216 B |
| RX staging buffer | 1,536 B |
| Socket buffers (4 sockets x 6144B) | 24,576 B |
| wolfIP stack internals | ~8 KB |
| Stack + heap | ~19 KB |
| **Total** | **~64 KB** |

### SDK Workarounds

The Makefile includes two workarounds for VA416xx SDK issues:

1. **`en_iocfg_dir_input` typo** - The SDK's `va416xx_hal_ioconfig.c` references `en_iocfg_dir_input` but the enum is `en_iocfg_dir__input` (double underscore). Fixed with `-Den_iocfg_dir_input=en_iocfg_dir__input`.

2. **`HBO` macro not exported** - The Heart Beat Oscillator frequency (20MHz) is defined locally in `system_va416xx.c` but needed by `va416xx_hal_clkgen.c`. Fixed with `-DHBO=20000000UL`.

## Files

| File | Description |
|------|-------------|
| `main.c` | Echo server application: HAL init, UART, ETH GPIO, wolfIP, DHCP, TCP echo |
| `va416xx_eth.c` | Ethernet MAC/DMA driver (normal descriptor format) |
| `va416xx_eth.h` | Ethernet driver header |
| `config.h` | wolfIP configuration (memory-optimized for 64KB SRAM) |
| `startup.c` | Cortex-M4 reset handler (.data copy, .bss clear) |
| `ivt.c` | Interrupt vector table (16 system + 64 external IRQs) |
| `syscalls.c` | Newlib stubs (_write routes to UART0) |
| `target.ld` | Linker script (Flash 256K, RAM 64K) |
| `hal_config.h` | SDK HAL configuration (SysTick 1ms) |
| `board.h` | Board selection (includes PEB1 EVK header) |
| `Makefile` | Build system with SDK integration |

## Troubleshooting

### No Serial Output

- Verify UART0 connection (PORTG[2] TX, PORTG[3] RX)
- Check baud rate is 115200
- Ensure the EVK's USB-UART bridge is connected
- LED should turn on immediately at boot (confirms code is running)

### PHY Init Fails

- Check Ethernet cable connection
- Verify PHY ID reads back non-zero/non-0xFFFF (KSZ8041TL OUI = 0x0022)
- GMII clock divider may need adjustment if not using default 20MHz HBO clock
- Ensure ETH peripheral clock is enabled and reset released before driver init

### No DHCP Response

- Verify a DHCP server is available on the network
- The device will timeout after 30 seconds and fall back to static IP (192.168.1.100)
- Check Wireshark for DHCP DISCOVER packets from the device's MAC (02:11:AA:BB:44:16)

### Build Fails

- Ensure `arm-none-eabi-gcc` is in PATH
- Verify SDK_ROOT points to a valid VA416xx SDK installation
- Run `make clean` before rebuilding after SDK path changes

## License

This code is part of wolfIP and is licensed under GPLv3. See the LICENSE file in the repository root for details.

Copyright (C) 2026 wolfSSL Inc.

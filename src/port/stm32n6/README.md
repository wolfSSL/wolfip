# wolfIP STM32N6 Port

This port provides a bare-metal wolfIP TCP/IP stack implementation for the
STM32N6 microcontroller (NUCLEO-N657X0-Q board). The STM32N6 is ST's first
Cortex-M55 microcontroller, running at 600 MHz (up to 800 MHz) with Helium
vector extensions, targeting high-performance edge AI workloads.

## Features

- **TCP/IP Stack**: Full wolfIP stack with TCP, UDP, ICMP, ARP
- **600 MHz Cortex-M55**: PLL1 configured for 600 MHz CPU clock
- **Ethernet**: RMII interface with LAN8742 PHY, dual DMA channels
- **Bare Metal**: No HAL, no CMSIS, no RTOS — fully self-contained
- **JTAG-to-SRAM**: Loads directly into AXISRAM via OpenOCD (no flash required)

## Hardware Requirements

- NUCLEO-N657X0-Q development board (STM32N657X0H, MB1940)
- Ethernet cable connected to a switch or directly to host PC
- USB cable for ST-Link programming and debug UART

## About the STM32N6

The STM32N6 is built around the Arm Cortex-M55 core running at 600 MHz,
with support for up to 800 MHz at Voltage Scale 0. Unlike most STM32 parts,
the N6 has no internal flash — all firmware resides on external NOR flash
(XSPI2) or is loaded directly into on-chip SRAM. The device provides over
4.2 MB of on-chip SRAM across multiple regions (AXISRAM1-6, AHBSRAM, DTCM).

Key differences from STM32H5/H7:
- **GMAC v5.20**: Dual-channel DMA with 24-byte descriptor stride (DSL=1)
- **RISAF firewall**: Memory access requires explicit RISAF region configuration
- **RIMC/RISC**: ETH DMA bus master identity (CID) must match RISAF grants
- **SAU/IDAU**: Security attribution affects DMA memory access paths
- **No internal flash**: Code runs from SRAM (JTAG load) or external XSPI flash

## Clock Configuration

```
HSI 64 MHz -> PLL1 (M=4, N=75) -> VCO 1200 MHz -> PDIV1=1 -> 1200 MHz
  IC1  /2 = 600 MHz -> CPU
  IC2  /3 = 400 MHz -> AXI bus
  IC6  /4 = 300 MHz -> System bus C
  IC11 /3 = 400 MHz -> System bus D
AHB prescaler /2 -> HCLK = 300 MHz
USART1 kernel clock: IC9 -> HSI 64 MHz
```

## Pin Configuration (NUCLEO-N657X0-Q RMII)

| Pin  | Function     | Description        |
|------|--------------|--------------------|
| PF4  | ETH_MDIO     | PHY management     |
| PG11 | ETH_MDC      | PHY clock          |
| PF7  | ETH_REF_CLK  | 50 MHz reference   |
| PF10 | ETH_CRS_DV   | Carrier sense      |
| PF11 | ETH_TX_EN    | Transmit enable    |
| PF12 | ETH_TXD0     | Transmit data 0    |
| PF13 | ETH_TXD1     | Transmit data 1    |
| PF14 | ETH_RXD0     | Receive data 0     |
| PF15 | ETH_RXD1     | Receive data 1     |
| PE5  | USART1_TX    | Debug output       |
| PE6  | USART1_RX    | Debug input        |
| PO1  | LED LD1      | Green heartbeat    |

All Ethernet pins use AF11. USART1 uses AF7.

## Building

### Prerequisites

- ARM GCC toolchain (`arm-none-eabi-gcc`)
- OpenOCD (STMicroelectronics fork with STM32N6 support)

```bash
# Ubuntu/Debian
sudo apt install gcc-arm-none-eabi
```

### Build

```bash
cd src/port/stm32n6
CC=arm-none-eabi-gcc make
```

This produces `app.elf` and `app.bin` for loading into AXISRAM via JTAG.

### Memory Usage

```bash
make size
```

| Configuration | Code + Data | BSS (static RAM) |
|---------------|-------------|------------------|
| TCP Echo only | ~25 KB      | ~146 KB          |

## Flashing

The N6 port loads firmware directly into AXISRAM1 (0x34000000) via JTAG.
No flash programming is needed.

```bash
make flash
# or
bash flash.sh
```

The `flash.sh` script:
1. Resets the CPU via OpenOCD
2. Loads `app.bin` to AXISRAM1 at 0x34000000
3. Sets VTOR, stack pointer, and entry point
4. Resumes execution

## Serial Console

Connect to the ST-Link VCP at 115200 baud:

```bash
picocom -b 115200 /dev/ttyACM0
# or
make monitor
```

### Expected Boot Output

```
  RIMC_ATTR6 (ETH1): 0x00000301
Initializing Ethernet MAC...
  PHY link: UP, PHY addr: 0x00000000
  MAC: 02:11:CC:DD:55:66
Setting IP configuration:
  IP: 192.168.12.11
  Mask: 255.255.255.0
  GW: 192.168.12.1
Creating TCP socket on port 7...
Entering main loop. Ready for connections!
  TCP Echo: port 7
```

## Network Configuration

The port uses static IP by default (DHCP disabled).

| Setting     | Value           |
|-------------|-----------------|
| IP Address  | 192.168.12.11   |
| Subnet Mask | 255.255.255.0   |
| Gateway     | 192.168.12.1    |

Configure your host PC to be on the same subnet:

```bash
sudo ip addr add 192.168.12.1/24 dev eth0
sudo ip link set eth0 up
```

Replace `eth0` with your Ethernet interface name.

## Testing

### Ping

```bash
ping 192.168.12.11
```

Expected: sub-millisecond replies (~0.15 ms RTT).

### TCP Echo (Port 7)

```bash
echo "Hello STM32N6!" | nc -q1 -w2 192.168.12.11 7
```

Expected: `Hello STM32N6!` echoed back.

## Memory Map

| Region    | Address      | Size   | Usage                                 |
|-----------|--------------|--------|---------------------------------------|
| AXISRAM1  | 0x34000000   | 512 KB | Code, data, BSS, heap, stack          |
| AXISRAM2  | 0x341F8000   | 32 KB  | ETH DMA descriptors + buffers         |

ETH DMA buffers are placed at the end of AXISRAM2 (matching the CubeN6 HAL
descriptor placement). The MPU marks this region as Normal Non-cacheable for
DMA coherency.

## N6-Specific Initialization

The STM32N6 requires several security and bus fabric configurations that
other STM32 ports do not need:

### SAU (Security Attribution Unit)
All SAU regions are cleared and `ALLNS=1` is set, making all memory
non-secure. This matches the CubeN6 SystemInit behavior.

### RISAF3 (AXISRAM2 Firewall)
The default RISAF3 base region covers only 4 KB. The ETH DMA buffers at
offset 0xF8000 are outside this range and would be blocked. The port extends
RISAF3 REG0 to cover the full 1 MB of AXISRAM2 with all CIDs granted
read+write access (`SEC=1` for secure-alias compatibility).

### RIMC (Resource Isolation Master Control)
The ETH DMA bus master is configured with `CID=1` (matching the CPU),
`SEC=1`, `PRIV=1`. This matches the CubeN6 HAL `RISAF_Config()`.

### RISC (Resource Isolation Slave Control)
The ETH1 peripheral is marked as Secure + Privileged in the RIFSC slave
security registers.

### RCC ETH Reset
A full RCC peripheral reset of ETH1 is performed before MAC initialization
to ensure a clean state.

## Debugging

### GDB

```bash
make debug
```

This starts OpenOCD and connects GDB with the firmware loaded.

### HardFault Handler

The port includes a detailed HardFault handler that prints register state
via UART (PC, LR, R0-R3, R12, xPSR, HFSR, CFSR, BFAR, MMFAR). The handler
only accesses UART if `uart_ready` is set, preventing double-faults during
early boot.

## File Structure

```
stm32n6/
  Makefile          Build system
  README.md         This file
  config.h          wolfIP configuration (static IP, socket counts)
  target.ld         Linker script (AXISRAM1 code + AXISRAM2 ETH buffers)
  openocd.cfg       OpenOCD configuration for NUCLEO-N657X0-Q
  flash.sh          JTAG load script (SRAM execution)
  startup.c         Cortex-M55 startup code
  ivt.c             Interrupt vector table
  syscalls.c        Newlib syscall stubs
  main.c            Application: clocks, GPIO, UART, SAU, RISAF, RIMC, ETH
  ../stm32/stm32_eth.c   Shared Ethernet MAC/PHY driver (H5, H7, N6)
  ../stm32/stm32_eth.h   Shared Ethernet driver header
```

## License

Copyright (C) 2026 wolfSSL Inc.

This project is licensed under GPLv3. See the wolfIP LICENSE file for details.

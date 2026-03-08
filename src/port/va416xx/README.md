# wolfIP VA416xx Port

Bare-metal port of wolfIP for the VORAGO VA416xx Cortex-M4 microcontroller, targeting the PEB1 EVK board with KSZ8041TL Ethernet PHY over MII.

## Hardware

- **MCU:** VA416xx (Cortex-M4, no FPU, 100 MHz via 40 MHz crystal × PLL 2.5×)
- **Flash:** 256 KB @ 0x00000000
- **SRAM:** 64 KB (RAM0 32 KB @ 0x1FFF8000 + RAM1 32 KB @ 0x20000000, contiguous)
- **Ethernet:** Synopsys DesignWare GMAC (normal/legacy descriptor format), MII
- **PHY:** KSZ8041TL via MII (PORTA[8-15], PORTB[0-10], funsel=1)
- **Debug UART:** UART0 on PORTG[0] TX / PORTG[1] RX, 115200 8N1
- **LED:** PORTG pin 5 (heartbeat)
- **Board:** PEB1 VA416xx EVK

## Prerequisites

- ARM GCC toolchain: `arm-none-eabi-gcc`
- VA416xx SDK at `../../../../VA416xx_SDK` (sibling directory to the wolfip repo)
- Serial terminal (minicom, screen, picocom) at 115200 baud
- JTAG/SWD debugger (Segger J-Link, OpenOCD, etc.)

### Installing ARM Toolchain (Ubuntu/Debian)

```bash
sudo apt install gcc-arm-none-eabi
```

## Quick Start

```bash
# 1. Build
cd src/port/va416xx
make CC=arm-none-eabi-gcc

# 2. Flash app.bin to the EVK via your debugger

# 3. Monitor UART (115200 baud)
screen /dev/ttyUSB0 115200

# 4. Test
ping <device-ip>
echo "Hello" | nc <device-ip> 7
```

## Build Variants

| Command | Description |
|---------|-------------|
| `make CC=arm-none-eabi-gcc` | Production build (48 KB) |
| `make CC=arm-none-eabi-gcc EXTRA_CFLAGS=-DDEBUG_ETH` | Per-frame ETH diagnostics on UART |
| `make CC=arm-none-eabi-gcc EXTRA_CFLAGS=-DTX_SELFTEST` | Startup TX self-test (sends gratuitous ARPs, checks hw_tx, runs loopback) |
| `make CC=arm-none-eabi-gcc EXTRA_CFLAGS="-DTX_SELFTEST -DDEBUG_ETH"` | Full debug output |
| `make CC=arm-none-eabi-gcc EXTRA_CFLAGS=-DSPEED_TEST` | Replace echo server with throughput test service on port 9 |

## Memory Usage (production build)

```
   text    data     bss     dec     hex filename
  48028    1740   52920  102688   19120 app.elf

Flash: 48 KB / 256 KB (19%)
RAM (static BSS): 52 KB / 64 KB (81%)
```

## Example Output

Normal boot with DHCP and echo server:

```
=== wolfIP VA416xx Echo Server ===
Build: Feb 23 2026 13:30:13
Initializing Ethernet...
  PHY link: UP
  PHY: 10M Half Duplex (negotiated)
  MAC: 10M Full Duplex (MAC_CONFIG=0x00018C80)
Starting DHCP...
Creating TCP echo server on port 7...
Ready! Test with:
  ping <ip>
  echo 'hello' | nc <ip> 7

Entering main loop...
[46] rx=0 tx=1/0 hw_tx=0 cfg=0x8C8C dbg=0x01100000 dma=0x00260400 TS=2
DHCP bound:
  IP:   192.168.12.11
  Mask: 255.255.255.0
  GW:   192.168.12.1
[56] rx=12 tx=4/0 hw_tx=4 cfg=0x8C8C dbg=0x00000000 dma=0x00660445 TS=6
Echo: client connected (fd=257)
[196] rx=208 tx=14/0 hw_tx=14 cfg=0x8C8C dbg=0x00000000 dma=0x00660445 TS=6
Echo: client disconnected
```

Periodic diagnostic fields: `[time_s] rx=<frames> tx=<sent>/<errs> hw_tx=<mac_count> cfg=<MAC_CONFIG_lo16> dbg=<MAC_DEBUG> dma=<DMA_STATUS> TS=<tx_state>`

## Testing

### ICMP Ping

```bash
ping <device-ip>
```

### TCP Echo (Port 7)

```bash
echo "Hello wolfIP!" | nc <device-ip> 7
nc <device-ip> 7          # interactive
```

### Throughput Test (Port 9, with `-DSPEED_TEST`)

```bash
# RX throughput: host → device; Ctrl+C nc after dd finishes
dd if=/dev/zero bs=1460 count=700 | nc <device-ip> 9
^C

# TX throughput: device → host; Ctrl+C after desired duration
nc <device-ip> 9 </dev/null | pv >/dev/null
^C
```

#### Measured Results (PEB1 EVK, 10M Full Duplex)

| Direction | Host-measured | Device-measured | Notes |
|-----------|--------------|-----------------|-------|
| RX (host→device) | **1.2 MB/s** | 1,022,000 bytes received | dd: 1,022,000 B in 0.86 s; ≈98% of 10 Mbps theoretical max |
| TX (device→host) | ~736 KB/s peak | **136 KB/s avg** | Peak early; average limited by wolfIP TCP window cycling |

Theoretical maximum for 10 Mbps MII (1460-byte segments, ~4% Ethernet overhead):
`10 Mbps × 0.96 / 8 ≈ 1,200 KB/s`

**Device UART output (RX test then TX test):**
```
Speed: client connected (fd=257)
Speed: 1549643 ms, RX 1022000 bytes (~659 B/s), TX 3336 bytes (~2 B/s)
Speed: client connected (fd=257)
Speed: 170096 ms, RX 0 bytes (~0 B/s), TX 23195968 bytes (~136369 B/s)
```

> **RX elapsed time** reflects how long `nc` held the connection open after `dd`
> finished — TCP has no application-level EOF, so the connection stays alive until
> `nc` is killed. The device-reported rate for RX is therefore meaningless; use
> host `dd` timing instead (0.86 s for 1 MB → 1.2 MB/s).
>
> **TX average** (136 KB/s) is lower than the peak visible in `pv` (~736 KB/s)
> because wolfIP's TCP send window cycles: the device transmits until the remote
> receive window fills, then waits for ACKs to reopen it before sending more.

## Known Limitations

### PHY Link Down at Startup

If the Ethernet cable is not connected (or the switch is powering up) when the board boots, auto-negotiation will time out after 5 seconds and `va416xx_eth_init` reports:

```
  PHY link: DOWN
  NOTE: PHY link down at startup (cable disconnected?) — continuing
```

The MAC and DMA are fully initialized and running. The device will respond to traffic once the link comes up — no reboot required.

## Architecture

### Ethernet Driver (`va416xx_eth.c`)

The driver uses the Synopsys DesignWare GMAC with the **normal (legacy) descriptor format**.

#### Descriptor Layout

| Word | TX (TDES) | RX (RDES) |
|------|-----------|-----------|
| des0 | OWN (bit 31) doorbell; TX status bits written back by DMA | OWN (bit 31); RX status + frame length written back by DMA |
| des1 | IC/LS/FS/TCH control bits + TBS1 buffer size | DIC/RER/RCH bits + RBS1 buffer size |
| des2 | Buffer 1 address | Buffer 1 address |
| des3 | Next descriptor address (chain mode) | Unused |

**Critical:** In the normal format, TX frame control bits (FS/LS/IC/TCH) belong in **TDES1**, not TDES0. TDES0 is a status-only word — the CPU must set only OWN=1 as a doorbell. Setting control bits in TDES0 causes the DMA to advance linearly (ignoring des3) and never transmit.

TX uses chain mode (TCH in TDES1, des3 = next descriptor pointer). RX uses ring mode (RER in RDES1 on the last descriptor). Ring mode (TER in TDES0) is not used for TX because the DMA overwrites des0 on writeback, clearing the TER bit.

#### DMA Configuration

- 3 RX + 3 TX descriptors (16-byte aligned, in `.dma_bss` / RAM1)
- 1536-byte per-descriptor buffers (`.dma_bss`)
- TX: threshold mode, TTC=16B (starts MAC TX as soon as 16 bytes in FIFO)
- RX: store-and-forward (RSF=1)
- PBL=8 (programmable burst length), no Fixed Burst (AAL/FB omitted for safety)
- Polling mode (DMA interrupts disabled)
- FTF (Flush TX FIFO) applied once before ST=1 during init; self-clears in ~30 AHB cycles

#### PHY (KSZ8041TL)

Auto-negotiation is restricted to **10M only** (10M-FD + 10M-HD in AN advertisement) because the FES bit (MAC_CONFIG bit 14) is read-only=0 on this silicon variant — the MAC is permanently configured for 10 Mbps (TXCLK = 2.5 MHz). Advertising 100M would cause speed mismatch if the link partner selected 100M.

The MAC is forced to Full Duplex (DM=1) regardless of PHY negotiation result. Half-duplex mode checks CRS before transmitting; CRS is unreliable on this silicon causing indefinite TX deferral.

#### SDK Workarounds

| Issue | Fix |
|-------|-----|
| MDIO HAL busy-wait has inverted polarity (exits immediately instead of waiting) | 50 µs software settle after every `HAL_ReadPhyReg`/`HAL_WritePhyReg` call |
| PHY reset completes in 100–300 ms (KSZ8041TL datasheet) | 500 ms wait after `HAL_ResetPHY()` |
| `en_iocfg_dir_input` typo in SDK IOCONFIG driver | `-Den_iocfg_dir_input=en_iocfg_dir__input` in Makefile |
| `HBO` oscillator constant not exported from `system_va416xx.c` | `-DHBO=20000000UL` in Makefile |

### vs. STM32H5 Port

| Feature | VA416xx (Normal) | STM32H5 (Enhanced) |
|---------|-----------------|-------------------|
| TX control bits | TDES1 | TDES0 |
| Buffer address | des2 | des0 |
| Ring wrap | TER/RER in des1 | Tail pointer register |
| DMA kick | `DMA_TX_POLL_DEMAND` | Tail pointer update |
| MTL layer | None (`DMA_OPER_MODE`) | Separate MTL registers |
| Speed | 10M (FES read-only=0) | 100M/1G |

### Memory Budget (64 KB SRAM)

| Component | Size |
|-----------|------|
| DMA TX descriptors (3 × 16 B) | 48 B |
| DMA RX descriptors (3 × 16 B) | 48 B |
| DMA TX buffers (3 × 1536 B) | 4,608 B |
| DMA RX buffers (3 × 1536 B) | 4,608 B |
| RX staging buffer | 1,536 B |
| wolfIP stack + sockets | ~42 KB |
| Stack + stack frame | ~4 KB |
| **Static BSS total** | **~52 KB** |

All DMA descriptors and buffers are placed in `.dma_bss` (RAM1, 0x20000000+). The Ethernet DMA is an AHB system bus master and cannot access RAM0 (code bus / D-Code bus).

## Files

| File | Description |
|------|-------------|
| `main.c` | Application: HAL init, UART, ETH GPIO, wolfIP, DHCP, TCP echo/speed-test |
| `va416xx_eth.c` | Ethernet MAC/DMA driver (normal descriptor format, chain TX, ring RX) |
| `va416xx_eth.h` | Ethernet driver public API |
| `config.h` | wolfIP configuration (memory-optimized for 64 KB SRAM) |
| `startup.c` | Cortex-M4 reset handler (.data copy, .bss clear, SysTick enable) |
| `ivt.c` | Interrupt vector table (16 system + 64 external IRQs) |
| `syscalls.c` | Newlib stubs (`_write` routes to UART0) |
| `target.ld` | Linker script (Flash 256 KB, RAM 64 KB, `.dma_bss` in RAM1) |
| `hal_config.h` | SDK HAL configuration (`SYSTICK_INTERVAL_MS=1`, 1 ms SysTick tick) |
| `board.h` | Board selection (includes PEB1 EVK header) |
| `Makefile` | Build system with SDK integration |

## License

This code is part of wolfIP and is licensed under GPLv3. See the LICENSE file in the repository root for details.

Copyright (C) 2026 wolfSSL Inc.

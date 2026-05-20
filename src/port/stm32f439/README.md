# wolfIP on STM32F437/F439

Bare-metal wolfIP port for STMicro STM32F437/F439 silicon.  Supports two
boards from one source tree, selected at compile time via `BOARD=`:

| Board            | MCU          | PHY       | VCP UART               | HSE                        | RMII TXD1 |
|------------------|--------------|-----------|------------------------|----------------------------|-----------|
| `nucleo_f439zi`  | STM32F439ZIT | LAN8742A  | USART3 (PD8/PD9, AF7)  | 8 MHz BYPASS (ST-LINK MCO) | PB13      |
| `stm32439i_eval` | STM32F437IIH | DP83848   | UART4 (PC10/PC11, AF8) | 25 MHz crystal             | PG14      |

Brings up Ethernet (RMII), runs DHCP, and exposes a TCP echo server on
port 7 plus ICMP ping.

**Status:** `nucleo_f439zi` has been booted end-to-end on hardware (no
cable -- clocks/UART/MAC/MDIO/PHY-ID verified; link-up + DHCP path not
yet exercised).  `stm32439i_eval` is compile-tested only; the build
artifact has not yet been validated on the STM32439I-EVAL hardware.

## Hardware

- MCU: Cortex-M4F @ 168 MHz, 2 MB flash, 256 KB RAM (192 KB main SRAM +
  64 KB CCM; this port keeps everything in main SRAM since the GMAC DMA
  cannot reach CCM).
- Clock: HSE -> PLL -> SYSCLK 168 MHz, HCLK 168 MHz, PCLK1 42 MHz,
  PCLK2 84 MHz.  PLL pre-divider differs per board (PLLM=8 for NUCLEO
  HSE_BYPASS 8 MHz, PLLM=25 for EVAL 25 MHz crystal); the post-divider
  chain and SYSCLK target are identical.
- Ethernet: Synopsys DWC GMAC (legacy 16-byte descriptors, ATDS=0) in
  RMII mode.  Driver in `src/port/stm32f4/`.

## RMII pin map (shared, with the per-board TXD1 noted)

| Signal           | Pin                            | AF  |
|------------------|--------------------------------|-----|
| ETH_RMII_REF_CLK | PA1                            | 11  |
| ETH_MDIO         | PA2                            | 11  |
| ETH_RMII_CRS_DV  | PA7                            | 11  |
| ETH_MDC          | PC1                            | 11  |
| ETH_RMII_RXD0    | PC4                            | 11  |
| ETH_RMII_RXD1    | PC5                            | 11  |
| ETH_RMII_TX_EN   | PG11                           | 11  |
| ETH_RMII_TXD0    | PG13                           | 11  |
| ETH_RMII_TXD1    | PB13 (NUCLEO) / PG14 (EVAL)    | 11  |

## Build

```
make clean
make                          # default: BOARD=nucleo_f439zi
make BOARD=stm32439i_eval     # for the STM32439I-EVAL
```

Outputs `app.bin` (raw binary for ST-LINK) and `app.elf` (with debug
info for GDB / addr2line).

Verbose ETH bring-up diagnostics:

```
make clean
make EXTRA_CFLAGS=-DDEBUG_ETH
```

Memory usage report:

```
make size
```

## Flash

Via ST-LINK CLI:

```
st-flash write app.bin 0x08000000
```

If multiple ST-LINKs are connected, target a specific probe by serial:

```
st-flash --serial <ST-LINK-serial> --reset write app.bin 0x08000000
```

Or via STM32CubeProgrammer with the onboard ST-LINK/V2-1.

## Expected UART output

```
=== wolfIP STM32F437/F439 (NUCLEO-F439ZI) ===
Build: <date> <time>
SYSCLK = 168000000 Hz, HCLK = 168000000 Hz, ...
Initializing Ethernet (RMII + LAN8742A)...
  PHY ID at addr 0: 0x0007 / 0xC131
  PHY link: UP, AN: complete
Starting DHCP...
DHCP bound:
  IP:   <ip>
  Mask: <mask>
  GW:   <gw>
TCP echo server on port 7
Ready! Test with:
  ping <ip>
  echo 'hello' | nc <ip> 7
```

Every 10 s the main loop prints a diagnostic line with packet counters
and MAC/DMA register snapshots (useful when the link isn't coming up):

```
[30] rx=0 tx=3/343030 maccr=0x0000848C macdbg=0x01120000 dmasr=0x00260400
```

For the EVAL build, the banner shows `STM32439I-EVAL` and `DP83848` /
PHY addr 1 instead.

## Test

From a host on the same subnet as the device:

```
ping <ip>
echo 'hello' | nc <ip> 7
```

## Out of scope (milestone 1)

- TLS / HTTPS / SSH / MQTT (the H563 port shows the wolfSSL hook-in
  pattern; can be ported here once basic eth works).
- wolfBoot / TFTP partition update.
- FreeRTOS.
- IRQ-driven RX (this port uses poll mode like the VA416xx milestone-1).

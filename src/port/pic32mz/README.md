# wolfIP PIC32MZ EF Port

Bare-metal [wolfIP](../../../README.md) port for the **Microchip PIC32MZ EF**
(PIC32MZ2048EFM144, MIPS32 M-class) with a **LAN8740** PHY over RMII. Built
with the Microchip XC32 toolchain; no MPLAB X project or Harmony framework
required. Also exercises wolfCrypt's built-in hardware TRNG
(`WOLFSSL_PIC32MZ_RNG`).

## Hardware

- **MCU:** PIC32MZ2048EFM144 (200 MHz, 2 MB flash, 512 KB RAM), EF Starter Kit.
- **PHY:** LAN8740 daughter board over RMII (PHY drives the 50 MHz reference clock).
- **Console:** UART2, `U2TX` on RPB14 / `U2RX` on RPG6, 115200 8N1.
- **Programmer:** MPLAB ICD 5 on the ICSP/debug header; program with `make flash` (see the Makefile `flash` target, which drives the ICD 5 over MDB).

## Layout

| File | Purpose |
|------|---------|
| `device_config.c` | DEVCFG config words: 200 MHz PLL (POSC EC 24 MHz), RMII, watchdog off. |
| `clock_init.c/.h` | Flash wait-states + prefetch. Reusable early bring-up (wolfBoot). |
| `cache.h` | MIPS KSEG0/KSEG1 + virtual/physical helpers for DMA memory. |
| `uart_console.c/.h` | UART2 console + XC32 `_mon_putc` `printf` retarget. |
| `timebase.c/.h` | 64-bit `millis()` from the CP0 core timer. |
| `pic32mz_eth.c/.h` | EMAC + RMII + MDIO bring-up, DMA descriptor rings, `poll`/`send`. |
| `phy_lan8740.c/.h` | MAC-agnostic clause-22 LAN8740 driver (scan, autoneg, link). |
| `rng_selftest.c/.h` | wolfCrypt hardware-TRNG self-test. |
| `user_settings.h` | wolfCrypt configuration (`WOLFSSL_MICROCHIP_PIC32MZ`). |
| `config.h` | wolfIP profile (MTU, socket counts, DHCP). |
| `main.c` | TRNG self-test, DHCP, and a TCP echo / throughput server. |

## Build

Requires XC32 (>= v5.10) and the PIC32MZ-EF DFP, plus a wolfssl checkout beside
the wolfip repo (override with `WOLFSSL_ROOT=`).

```sh
make                     # -> app.hex
make SPEED_TEST=1 EXTRA_CFLAGS=-DSPEED_TEST   # throughput server on port 9
make flash               # program over MPLAB ICD 5 (MDB)
make clean
```

Overridable: `XC32_BIN`, `DFP`, `DEVICE`, `WOLFSSL_ROOT`, `MDB`, `MDB_TOOL`.

## Test

Console at 115200 8N1. On boot the firmware prints the banner, the RNG
self-test result, the resolved PHY link, and (once bound) the DHCP address:

```
=== wolfIP PIC32MZ EF port ===
[RNG] self-test: PASS
Ethernet init (LAN8740 over RMII)...
DHCP bound: 10.0.4.x
TCP service listening on port 7
```

Then, from a host on the same network:

```sh
ping <ip>
echo hello | nc <ip> 7                          # echo (default build)
dd if=/dev/zero bs=1460 count=700 | nc <ip> 9    # RX throughput (SPEED_TEST build)
nc <ip> 9 </dev/null | pv >/dev/null             # TX throughput (SPEED_TEST build)
```

## Notes

- DMA descriptors/buffers use XC32 `__attribute__((coherent))` (uncached), so
  no cache maintenance is needed; the EMAC is given physical addresses.
- The Ethernet module needs PBCLK5 enabled and `PMD6.ETHMD` cleared before any
  EMAC register access — `pic32mz_emac_mii_init()` does this first.
- The PIC32 Ethernet DMA descriptor is 4 words (16 bytes): header, buffer
  address, and two words the DMA writes back. The received frame length comes
  from the status word (`status & 0xFFFF`), not the header.
- The echo server holds transfers in the per-socket buffers
  (`RXBUF_SIZE`/`TXBUF_SIZE`), so a single burst larger than that will stall
  the simple echo callback; raise the buffers or use the throughput server
  (`-DSPEED_TEST`) for large streams.
- Build with `EXTRA_CFLAGS=-DPIC32_ETH_TRACE` to trace the EMAC bring-up.

# wolfIP NXP QUICC Engine UCC (UEC) port

Ethernet driver for the NXP QUICC Engine (QE) UCC fast controller in UEC-GETH (ethernet) mode, for big-endian PowerPC parts that carry a QE (e.g. P1021/P1025, e500v2). Brings up one UCC in polled mode and exposes the wolfIP poll/send callbacks.

## Important: which P1021 MAC?

The **stock P1021RDB routes its copper through eTSEC (Gianfar) + a VSC7385 switch, not the QE UCC** -- the QE-UEC ethernet path is a P1025RDB-style configuration. On a stock P1021RDB the QE only drives the switch firmware. Use the **`nxp_etsec` port** for stock P1021RDB hardware. Use this `nxp_qe_uec` port for boards with custom UCC-to-PHY wiring (or P1025-style RMII).

## Model

The board (DDR, clocks, UART, pin-mux) and the QE microcode are brought up by the boot stage (wolfBoot `hal_qe_init`, which uploads the microcode, sets IRAM-ready, configures SDMA, resets the engine, and muxes the UCC pins). This driver runs in the booted application: it routes the UCC clocks, runs UCC-fast init (GUMR + virtual FIFOs), configures the MAC + MDIO/PHY, builds the parameter RAM in QE MURAM, sets up the BD rings in DRAM, issues the `INIT_TX_RX` command, and polls the rings.

**Single instance.** All per-device state (base addresses, ring indices, PHY address, BD rings, buffer pools) is held in file-scope `static` variables and `WOLFIP_MAX_INTERFACES` defaults to 1, so the driver drives exactly one MAC. A second port of the same MAC type in one image would share that state; move it behind `ll->priv` first.

## Files

- `nxp_qe_uec.h` - public API + QE engine / UCC fast / UEC MAC / MII / BD / param-RAM register map.
- `nxp_qe_uec.c` - driver: BE register access, MURAM allocator, QE command register, MDIO clause-22, PHY bring-up, UCC-fast + MAC init, parameter RAM, BD-ring datapath.
- `nxp_qe_uec_board.h` - board parameters (CCSRBAR, UCC index, PHY address, interface mode, speed, SNUMs). All overridable from CFLAGS.
- `config.h` - wolfIP compile-time configuration for this port.

## Board parameters

| Define | Default | Notes |
|---|---|---|
| `NXP_QE_CCSRBAR` | `0xFF700000` | P1021 reset default (kept by wolfBoot for the QE block) |
| `NXP_QE_IMMR_OFFSET` | `0x80000` | QE_IMMR = CCSRBAR + 0x80000 |
| `NXP_QE_UCC_NUM` | `0` | 0-based UCC index (UCC1=0; wolfBoot muxes UCC1=MII, UCC5=RMII) |
| `NXP_QE_PHY_ADDR` | `0x0` | external PHY (probed first, then bus scan) |
| `NXP_QE_IF_MODE` | `0` | 0=MII, 1=RMII, 2=RGMII |
| `NXP_QE_SPEED` | `100` | 10/100/1000 (selects VFIFO sizes and MAC byte/nibble mode) |
| `NXP_QE_SNUM_RX/RX2/TX` | `0x04/0x0C/0x05` | serial numbers from the P1021 28-snum pool |

## Status

Build-validated (compiles clean for e500 BE in MII, RMII and RGMII/gigabit modes). The polled `eth_poll`/`eth_send` ring datapath (index/wrap/ring-full and length-clamp bookkeeping) is NOT yet exercised by any host or hardware test. Hardware bring-up is pending suitable QE/UCC hardware. The bring-up follows the U-Boot QE UEC driver (drivers/qe/uec.c). Hardware-verify items, flagged inline in the source:

- The CMXUCRn per-UCC RX/TX clock-route 4-bit field layout is not in the U-Boot sources and must be taken from the P1021 RM "QE Multiplexing" -- `qe_clock_route()` currently only programs the well-defined MII-management routing (CMXGCR).
- Whether `qe_assign_page()` is required after wolfBoot's engine reset, and its exact CECDR page encoding.
- The PHY interface mode and MDIO address (board-specific; the stock P1021RDB does not use this path at all).

## Cache coherency

e500v2 has no I/O cache snooping and wolfBoot maps low DDR cacheable-but-non-coherent, so the driver does explicit `dcbf` cache maintenance (32-byte lines) around the BD rings and buffers. `TSTATE`/`RSTATE` also set the QE `BMR_GLB` snoop bit.

## Build

```
powerpc-linux-gnu-gcc -mcpu=e500mc -mbig-endian -I<wolfip-root> -Isrc/port/nxp_qe_uec \
    -c src/port/nxp_qe_uec/nxp_qe_uec.c
```

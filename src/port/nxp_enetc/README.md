# wolfIP NXP ENETC port

Ethernet driver for the NXP ENETC integrated-endpoint MAC found on Layerscape parts (lead target: LS1028A, Cortex-A72, AArch64, little-endian). ENETC appears as PCI functions on an internal ECAM root complex (bus 0); this driver discovers the port over ECAM, runs one RX and one TX buffer-descriptor ring, brings up the MAC + PHY, and exposes the wolfIP poll/send callbacks.

## Model

The board (DDR, clocks, MMU, UART, PCIe/ECAM) is brought up by the boot stage (wolfBoot). This driver runs in the booted application: it enumerates the ENETC port and the shared MDIO controller over ECAM, programs the station-interface (SI) and port registers, sets up the BD rings in memory, and polls them. There is no interrupt path.

It is consumed by the wolfBoot test-app (which links wolfIP core + this driver + the TFTP client). `nxp_enetc.c` is the reusable driver; board parameters live in `nxp_enetc_board.h`.

**Single instance.** All per-device state (base addresses, ring indices, PHY address, BD rings, buffer pools) is held in file-scope `static` variables and `WOLFIP_MAX_INTERFACES` defaults to 1, so the driver drives exactly one MAC. A second port of the same MAC type in one image would share that state; move it behind `ll->priv` first.

## Files

- `nxp_enetc.h` - public API + PCI/ECAM, SI, port, BD-ring and MDIO register map.
- `nxp_enetc.c` - driver: ECAM config access + BAR setup, MDIO clause-22, PHY detect/reset/autoneg, SGMII PCS / RGMII interface select, BD-ring datapath, wolfIP poll/send callbacks.
- `nxp_enetc_board.h` - board parameters (ECAM base, port/MDIO function index, PHY address, interface mode). All overridable from CFLAGS.
- `config.h` - wolfIP compile-time configuration for this port.

## Board parameters

All overridable from CFLAGS. Defaults target the LS1028A-RDB (port 0, external SGMII PHY at MDIO address 0x2 reached through the shared MDIO PF). `nxp_enetc_init()` scans the MDIO bus, so a board with the PHY elsewhere is still detected.

| Define | LS1028A value | Notes |
|---|---|---|
| `NXP_ENETC_ECAM_BASE` | `0x01F0000000` | ECAM config space (bus 0) |
| `NXP_ENETC_IERB_BASE` | `0x01F0800000` | IERB (persistent MAC address) |
| `NXP_ENETC_PORT_FN` | `0` | ECAM function for the ENETC port (fn0 = port0 SGMII) |
| `NXP_ENETC_MDIO_FN` | `3` | ECAM function for the shared MDIO controller |
| `NXP_ENETC_PHY_ADDR` | `0x2` | external PHY on port0 (probed first, then bus scan) |
| `NXP_ENETC_IF_SGMII` | `1` | `1` = SGMII (configures the internal PCS), `0` = RGMII |

On LS1028A the ENETC ports are: fn0 = port0 (external SGMII PHY on the RDB), fn1 = port1, fn2 = port2 (internal 2.5G to the Felix L2 switch), fn6 = port3, fn3 = the shared MDIO controller. Port0 is the wire-facing path with a real PHY; the internal ports need switch configuration to reach a jack.

## Endianness and cache

ENETC registers and buffer descriptors are little-endian, matching the AArch64 host, so register/BD access needs no byte swap. wolfBoot runs this target with the MMU and D-cache ON and DDR cacheable (required for coherency with the ENETC coherent DMA, SICAR=0x27276767), so the driver does `dc civac` (TX clean) / `dc ivac` (RX invalidate) maintenance around the rings and buffers, plus a `dmb` between BD/buffer stores and the ring doorbell.

## Status

Hardware-verified on the LS1028A-RDB: PHY/link up, DHCP lease, and TCP throughput (~62 MB/s RX, ~30 MB/s TX). The polled `eth_poll`/`eth_send` ring datapath (producer/consumer index, wrap, ring-full and length-clamp bookkeeping) runs on silicon. The bring-up sequence (ECAM discovery, BAR enable, SI/port enable, ring setup, PCS/PHY) follows the U-Boot ENETC driver. Per-PF BAR0 is read live (fallback-assigned only if zero); the MAC address is written via both the SI `PSIPMAR` and the IERB; DMA uses 1:1 addressing (the MMU maps DDR cacheable identity).

`nxp_enetc_init()` populates the `struct wolfIP_ll_dev` (mac/ifname/mtu/poll/send). `eth_poll()`/`eth_send()` move frames through the BD rings with `dmb` ordering and `dc civac`/`dc ivac` cache maintenance.

## Build

The driver is built by its consumer (the wolfBoot test-app) with the AArch64 cross-compiler, e.g.:

```
aarch64-linux-gnu-gcc -I<wolfip-root> -Isrc/port/nxp_enetc \
    -c src/port/nxp_enetc/nxp_enetc.c
```

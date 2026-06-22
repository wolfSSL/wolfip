# wolfIP NXP eTSEC (Gianfar) port

Ethernet driver for the NXP eTSEC (Enhanced Three-Speed Ethernet Controller, a.k.a. Gianfar) MAC on big-endian PowerPC QorIQ/PQ parts (P1020/P1021/P2020, e500v2). Brings up one eTSEC in polled mode and exposes the wolfIP poll/send callbacks. This is the stock-P1021RDB ethernet path (eTSEC + RGMII PHYs / VSC7385 switch).

## Model

The board (DDR, clocks, UART, L1/L2, TLBs, LAWs) is brought up by the boot stage (wolfBoot). This driver runs in the booted application: soft-reset the eTSEC, configure the MAC and interface, set up one RX and one TX BD ring in DRAM, bring up the external PHY (or use a fixed link), and poll the rings.

**Single instance.** All per-device state (base addresses, ring indices, PHY address, BD rings, buffer pools) is held in file-scope `static` variables and `WOLFIP_MAX_INTERFACES` defaults to 1, so the driver drives exactly one MAC. A second port of the same MAC type in one image would share that state; move it behind `ll->priv` first.

## Files

- `nxp_etsec.h` - public API + eTSEC / MDIO / BD register map.
- `nxp_etsec.c` - driver: BE register access, MDIO clause-22, PHY bring-up, MAC/interface config, BD-ring datapath, wolfIP poll/send callbacks.
- `nxp_etsec_board.h` - board parameters (CCSRBAR, eTSEC index, interface mode, PHY address, fixed-link). All overridable from CFLAGS.
- `config.h` - wolfIP compile-time configuration for this port.

## Board parameters

| Define | Default | Notes |
|---|---|---|
| `NXP_ETSEC_CCSRBAR` | `0xFFE00000` | CCSRBAR as relocated by wolfBoot (NOT the 0xFF700000 reset default) |
| `NXP_ETSEC_INDEX` | `0` | 0=eTSEC1, 1=eTSEC2, 2=eTSEC3 |
| `NXP_ETSEC_IF_SGMII` | `0` | 0=RGMII, 1=SGMII (configures the internal TBI/SerDes) |
| `NXP_ETSEC_FIXED_LINK` | `1` | 1=skip PHY autoneg, force NXP_ETSEC_SPEED (eTSEC1->VSC7385 uplink) |
| `NXP_ETSEC_SPEED` | `1000` | forced/expected speed in Mbps |
| `NXP_ETSEC_PHY_ADDR` | `0x1` | external PHY (probed first, then bus scan); P1021RDB uses 0/1/2 |
| `NXP_ETSEC_TBIPA` | `0x1F` | internal TBI MDIO address (kept off the external range) |

eTSEC register block: eTSEC1 = CCSRBAR + 0x24000, step 0x1000. The MDIO management block for all eTSECs lives in eTSEC1's window at +0x520; the per-eTSEC internal TBI is reached through that eTSEC's own +0x520 window at the TBIPA address.

## P1021RDB wiring

eTSEC1 is RGMII to the VSC7385 5-port switch (a fixed link, no external MDIO PHY -- the switch is eLBC-attached and its firmware is loaded by the boot stage); use the default `NXP_ETSEC_FIXED_LINK=1`. eTSEC2/eTSEC3 are SGMII to external PHYs (MDIO addresses 0x1/0x2 by convention) when the SerDes protocol selects SGMII on those lanes. All external MDIO goes through eTSEC1's window.

## Cache coherency

e500v2 has no I/O cache snooping and wolfBoot maps low DDR cacheable-but-non-coherent (MAS2_G, no M bit), so the driver does explicit `dcbf` cache maintenance (32-byte lines) around the BD rings and packet buffers before/after DMA.

## Status

Build-validated (compiles clean for e500 BE in RGMII fixed-link, RGMII+PHY, and SGMII+PHY configurations; BD struct verified to be 8 bytes). The polled `eth_poll`/`eth_send` ring datapath (index/wrap/ring-full and length-clamp bookkeeping) is NOT yet exercised by any host or hardware test. Hardware bring-up on the P1021RDB is pending board availability. The bring-up follows the U-Boot eTSEC driver (drivers/net/tsec.c, fsl_mdio.c). Hardware-verify items: the eTSEC129 RX-init erratum workaround (early P1021 silicon) is not implemented; the SGMII TBI register values in `configure_serdes()` should be confirmed (flagged inline in the source); and the exact P1021RDB PHY addresses/interface come from the board DTS/schematic.

## Build

```
powerpc-linux-gnu-gcc -mcpu=e500mc -mbig-endian -I<wolfip-root> -Isrc/port/nxp_etsec \
    -c src/port/nxp_etsec/nxp_etsec.c
```

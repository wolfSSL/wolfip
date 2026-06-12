# wolfIP port: Xilinx Zynq-7000 (Cortex-A9, ARMv7-A 32-bit)

**STATUS: brought up on a ZC702.** DHCP, ICMP ping and the UDP echo demo all work on real hardware (Cortex-A9, Marvell 88E1518 PHY). See "Hardware bring-up notes" below for the Zynq-7000-specific differences that mattered.

## What this port is

Bare-metal wolfIP port for the Xilinx Zynq-7000 family (Z-7020 etc., e.g. ZC702 / ZedBoard / MicroZed dev boards). Cortex-A9 in SVC mode, GCC bare-metal, no Xilinx Standalone BSP, no FreeRTOS. Targets the same deterministic UDP/IPv4 profile as the ZCU102 port.

## What differs from ZCU102

| Subsystem | ZCU102 (ZynqMP) | Zynq-7000 | Where it lives |
|-----------|-----------------|-----------|----------------|
| Architecture | ARMv8-A AArch64 | ARMv7-A 32-bit | toolchain prefix |
| CPU core | Cortex-A53 | Cortex-A9 | `Makefile` (-mcpu) |
| Bootloader handoff | FSBL -> EL3 | FSBL -> SVC | `startup_armv7.S` |
| Toolchain | `aarch64-none-elf-gcc` | `arm-none-eabi-gcc` | `Makefile` |
| Exception model | EL3 vectors | ARMv7 exception modes | `startup_armv7.S` rewritten |
| MMU | 4-level long descriptor | 1-level short descriptor | `mmu_armv7.c` rewritten |
| Cache ops | DC CVAC / DC IVAC | MCR p15 c7 (DCCMVAC/DCIMVAC) | `gem_core.c` |
| Generic timer | `mrs cntpct_el0` | `mrrc p15, 0, ..., c14` | `timer.h`, `entropy.c` |
| GIC | GIC-400 (GICv2) | GIC-390 (GICv2) | `gic_gicv2.c` (same driver, different base) |
| GIC base addrs | `0xF901xxxx` | `0xF8F0xxxx` | `board.h` |
| UART | Cadence at 0xFF000000 | Cadence at 0xE0000000 | `board.h` (same driver) |
| Clock + reset | CRL_APB at 0xFF5E0000 | SLCR at 0xF8000000 | `board.h` (gem.c clock helper needs rewrite) |
| GEM count | 4 (GEM0-3) | 2 (GEM0-1) | `board.h` |
| On-board RJ45 | GEM3 (INTID 95) | GEM0 (INTID 54) | `board.h` |
| BD format | 8-byte (DMACR[30]=0) | 8-byte (no 64-bit option) | `gem_core.c` (unchanged) |

## Build

```
cd src/port/amd/boards/zynq7000
make CROSS_COMPILE=arm-none-eabi-
```

Output: `app.elf`.

## JTAG boot (ZC702)

The ZC702 boots its onboard JTAG over the Digilent USB module; set SW10
to the on-board (USB) JTAG position and SW16 to JTAG boot mode, then:

```
XSDB=/opt/Xilinx/<ver>/Vitis/bin/xsdb \
FSBL_ELF=/path/to/zynq_fsbl.elf \
./jtag/boot.sh
```

`jtag/boot.tcl` runs the prebuilt FSBL (ps7_init brings up DDR/MIO/clocks/
UART), remaps all four OCM banks high (`SLCR.OCM_CFG`) so the app can load
at `0xFFFC0000`, then loads `app.elf` and starts it in SVC mode. The
console is on **UART1** (the ZC702 USB-UART), not UART0. After a run the
A9 must be power-cycled to be JTAG-loadable again.

## Hardware bring-up notes (what was Zynq-7000-specific)

These are the things that differed from the AArch64 ports and had to be
fixed for the ZC702 to reach DHCP/ping/echo:

- **No ARM generic timer.** The Cortex-A9 does not implement CNTPCT/CNTFRQ
  (CP15 c14); those encodings are UNDEFINED and trap. `timer.h` and
  `entropy.c` use the MPCore **Global Timer** at `0xF8F00200` (333 MHz)
  instead.
- **Console is UART1.** The ZC702 routes the USB console to Cadence UART1
  (`0xE0001000`); `uart_cadence.c` trusts the FSBL's baud config rather than
  reprogramming the divisor (the UART_REF_CLK is not the ZynqMP value).
- **Marvell 88E1518 PHY, not DP83867.** The ZC702 fits a Marvell PHY
  (OUI `0x0141`) at MDIO addr 7. `phy_marvell.c` handles its paged RGMII
  delay registers + autoneg; `gem_core.c` dispatches on the PHY ID.
- **GEM clock via SLCR, write-protected.** `SLCR.GEM0_CLK_CTRL`
  (`0xF8000140`) has a different layout than ZynqMP's CRL_APB and is
  write-locked. `gem0_set_ref_clk` unlocks the SLCR (`0xDF0D`) and writes
  `0x00100801` for 125 MHz (1 Gbps). `SLCR.GEM0_RCLK_CTRL` (`0xF8000138`)
  must also be set to source the RGMII RX clock from the PHY, or the MAC
  receives nothing (matches Xilinx ps7_init).
- **Poll-driven RX, GEM IRQ masked.** Unlike the Versal GICv3, the A9 GIC
  delivers the GEM SPI, and an enabled RX-complete interrupt storms the
  CPU. RX is polled from `eth_poll` and the GEM interrupt is left masked.
- **Non-cacheable OCM for DMA.** The 8-byte GEM descriptors share 32-byte
  cache lines, so per-descriptor cache maintenance corrupts neighbours'
  OWN bits and stalls RX. The OCM section is mapped Normal non-cacheable
  (`mmu_armv7.c`) so the descriptor rings and buffers are DMA-coherent. (The
  PL310 L2 is also disabled as a belt-and-braces measure.) Note the A9
  L1 cache line is 32 bytes, not the 64 of the AArch64 cores.
- `NWCFG_DWIDTH_64` (NWCFG bit 21) is set to mirror the validated
  U-Boot/Linux register state, but is a no-op here: the A9 GEM AXI
  master path is 32-bit and the BDs stay 8 bytes (DMACR[30]=0).

## Files

See `src/port/amd/README.md` for the shared-tree layout. The Zynq-7000
extras are `ip/phy_marvell.c` / `phy_marvell.h` (the ZC702 PHY) selected
via `ip/phy_dispatch_multi.c`, and this board dir's `jtag/` (FSBL-based
JTAG loader).

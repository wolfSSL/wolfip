# wolfIP port: Xilinx Versal Gen 1 (VMK180)

**STATUS: brought up on a VMK180.** DHCP, ICMP ping and the UDP echo demo all work on real hardware (Cortex-A72 EL3, GEM0 + DP83867). See "Hardware bring-up notes" below for the Versal-specific differences.

## What this port is

Bare-metal wolfIP port for the AMD/Xilinx Versal ACAP Gen 1, demoed on the VMK180 dev board. Cortex-A72 APU 0 at EL3, GCC bare-metal, no Xilinx Standalone BSP, no FreeRTOS. Targets the same deterministic UDP/IPv4 profile as the ZCU102 port for DO-178C DAL-C qualification.

## What differs from ZCU102

| Subsystem | ZCU102 | Versal Gen 1 | Where it lives |
|-----------|--------|--------------|----------------|
| APU core | Cortex-A53 | Cortex-A72 | `Makefile` (-mcpu) |
| Bootloader handoff | FSBL -> EL3 | PLM -> BL31 -> EL3 (or EL2) | `startup_aarch64.S` |
| GIC | GIC-400 (GICv2) | GIC-600 (GICv3) | `gic_gicv3.c` rewritten for GICv3 system regs + GICR |
| UART | Cadence | ARM PL011 | `uart_pl011.c` rewritten |
| GEM count | 4 (GEM0-3) | 2 (GEM0-1) | `board.h` |
| On-board RJ45 | GEM3 (INTID 95) | GEM0 (INTID 88) | `board.h` |
| GEM IP | Cadence GEM3 | Cadence GEM3 | `gem_core.c` unchanged (just base addr / INTID) |
| PHY | DP83867 RGMII | DP83867 RGMII (VMK180) | `phy_dp83867.c` unchanged |
| MMU | EL3 ARMv8 | EL3 ARMv8 | `mmu_aarch64.c` unchanged |
| RNG | memuse entropy | memuse entropy | `entropy.c` unchanged |

The reused 90% (`gem_core.c`, `phy_dp83867.c`, `mmu_aarch64.c`, `entropy.c`, `app.c`, `target.ld`, `target_ddr.ld`) is identical to the ZCU102 port; only `board.h`, `uart_pl011.c`, `gic_gicv3.c`, and the startup/Makefile breadcrumbs are Versal-specific.

## Build

```
cd src/port/amd/boards/versal
make CROSS_COMPILE=aarch64-none-elf-                 # OCM layout (default)
make CROSS_COMPILE=aarch64-none-elf- LAYOUT=ddr      # DDR layout for wolfBoot
```

Output: `app.elf`. Size info is printed at the end of the build.

## JTAG boot (VMK180)

The VMK180 must be in **JTAG boot mode** (SW1 mode pins = 0000) and
power-cycled so the BootROM does not auto-boot Linux from SD/QSPI -- a
booted Linux owns GEM0 and runtime-suspends its clock, which stalls the
bare-metal driver. Then:

```
XSDB=/opt/Xilinx/<ver>/Vitis/bin/xsdb \
BOOT_PDI=/path/to/vmk180_boot.pdi \
./jtag/boot.sh
```

`jtag/boot.tcl` does `rst -system`, programs the boot PDI through the PMC
(the PLM brings up DDR/clocks/MIO and de-isolates the A72), then resets
A72 #0 (`-skip-activate-subsystem`, which lands at EL3) and loads
`app.elf`. The PS console is on FT4232 **interface 1**
(`VERSAL_VMK180_UART1`).

## Hardware bring-up notes (what was Versal-specific)

- **GEM RX is poll-driven.** The GICv3 CPU interface did not deliver the
  GEM SPI in this EL3 bring-up, so `eth_poll` polls `gem_isr` from the
  main loop to drain the RX ring (the IRQ path stays registered but
  dormant).
- **GEM clock is owned by the PLM.** The CRL block is PMC/PLM-protected;
  a direct APU write to `CRL.GEM0_REF_CTRL` (`0xFF5E0118`, not the ZynqMP
  `+0x50`) stalls the bus. The PLM already configures the GEM clock, so
  `gem_core.c` does not touch it. The correct Versal offsets are documented in
  `board.h` for reference.
- **Two DP83867 PHYs.** The VMK180 presents more than one PHY on the MDIO
  bus; `gem_core.c` scans all 32 addresses and prefers the one reporting copper
  link (the on-board RJ45 PHY answered at addr 1). Make sure the cable is
  in the **PS-GEM** RJ45, not the System Controller jack.
- `SCR_EL3` IRQ/FIQ/EA routing is carried over from the ZCU102 fix and is
  harmless on the A72.

## Files

See `src/port/amd/README.md` for the shared-tree layout. This board dir
holds `board.h`, `board.c`, `board_gem.c`, `config.h`, the linker scripts
and `jtag/` (PDI-based JTAG loader). The differences listed in the table
above are the only substantive Versal-specific code.

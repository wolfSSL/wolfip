# wolfIP port: Xilinx Versal Gen 1 (VMK180)

**STATUS: UNTESTED ON HARDWARE.** Structural scaffold mirroring `src/port/zcu102/`. The code compiles cleanly with `aarch64-none-elf-gcc` but has not been brought up on a real VMK180 board. Lab verification is a Phase 3 milestone once the bench is available.

## What this port is

Bare-metal wolfIP port for the AMD/Xilinx Versal ACAP Gen 1, demoed on the VMK180 dev board. Cortex-A72 APU 0 at EL3, GCC bare-metal, no Xilinx Standalone BSP, no FreeRTOS. Targets the same deterministic UDP/IPv4 profile as the ZCU102 port for DO-178C DAL-C qualification.

## What differs from ZCU102

| Subsystem | ZCU102 | Versal Gen 1 | Where it lives |
|-----------|--------|--------------|----------------|
| APU core | Cortex-A53 | Cortex-A72 | `Makefile` (-mcpu) |
| Bootloader handoff | FSBL -> EL3 | PLM -> BL31 -> EL3 (or EL2) | `startup.S` |
| GIC | GIC-400 (GICv2) | GIC-600 (GICv3) | `gic.c` rewritten for GICv3 system regs + GICR |
| UART | Cadence | ARM PL011 | `uart.c` rewritten |
| GEM count | 4 (GEM0-3) | 2 (GEM0-1) | `board.h` |
| On-board RJ45 | GEM3 (INTID 95) | GEM0 (INTID 88) | `board.h` |
| GEM IP | Cadence GEM3 | Cadence GEM3 | `gem.c` unchanged (just base addr / INTID) |
| PHY | DP83867 RGMII | DP83867 RGMII (VMK180) | `phy_dp83867.c` unchanged |
| MMU | EL3 ARMv8 | EL3 ARMv8 | `mmu.c` unchanged |
| RNG | memuse entropy | memuse entropy | `entropy.c` unchanged |

The reused 90% (`gem.c`, `phy_dp83867.c`, `mmu.c`, `entropy.c`, `main.c`, `target.ld`, `target_ddr.ld`) is identical to the ZCU102 port; only `board.h`, `uart.c`, `gic.c`, and the startup/Makefile breadcrumbs are Versal-specific.

## Build

```
cd src/port/versal
make CROSS_COMPILE=aarch64-none-elf-                 # OCM layout (default)
make CROSS_COMPILE=aarch64-none-elf- LAYOUT=ddr      # DDR layout for wolfBoot
```

Output: `app.elf`. Size info is printed at the end of the build.

## Known unknowns (to validate on hardware)

- `gic.c` `gic_init` order may need rework if BL31 owns the distributor on Versal -- the safer path is to skip distributor init entirely and only set up the redistributor + CPU interface. The current code re-initialises the distributor defensively; this may be redundant or actively wrong depending on BL31 settings.
- `CRL_APB_GEM0_REF_CTRL` offset in `board.h` is a placeholder (0x50). Cross-check against the Versal LPD clock register map before bring-up.
- The on-board PHY MDIO address on VMK180 needs confirmation; the ZCU102 used `0x0C`, VMK180 may be different.
- PL011 baud assumes `UARTCLK = 100 MHz`. Versal PLM typically configures this but the rate could differ; confirm from the LPD clock tree.
- `SCR_EL3` routing convention (set `IRQ`+`FIQ`+`EA` bits) is carried over from the ZCU102 fix. Cortex-A72 may not require it; harmless to leave for now.
- DDR DAP write reliability on Versal (the issue we hit on ZCU102 for JTAG iteration to DDR) may behave differently -- VMK180 uses LPDDR4 with PLM-controlled training. Expect SD/QSPI boot to be the easier first test path.

## Files

Identical layout to `src/port/zcu102/`. See that port's README for per-file responsibilities. The differences listed in the table above are the only substantive Versal-specific code.

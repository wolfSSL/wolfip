# wolfIP port: Xilinx Zynq-7000 (Cortex-A9, ARMv7-A 32-bit)

**STATUS: UNTESTED ON HARDWARE.** Structural scaffold mirroring `src/port/zcu102/`. The code compiles cleanly with `arm-none-eabi-gcc` but has not been brought up on a real Zynq-7000 board.

## What this port is

Bare-metal wolfIP port for the Xilinx Zynq-7000 family (Z-7020 etc., e.g. ZC702 / ZedBoard / MicroZed dev boards). Cortex-A9 in SVC mode, GCC bare-metal, no Xilinx Standalone BSP, no FreeRTOS. Targets the same deterministic UDP/IPv4 profile as the ZCU102 port.

## What differs from ZCU102

| Subsystem | ZCU102 (ZynqMP) | Zynq-7000 | Where it lives |
|-----------|-----------------|-----------|----------------|
| Architecture | ARMv8-A AArch64 | ARMv7-A 32-bit | toolchain prefix |
| CPU core | Cortex-A53 | Cortex-A9 | `Makefile` (-mcpu) |
| Bootloader handoff | FSBL -> EL3 | FSBL -> SVC | `startup.S` |
| Toolchain | `aarch64-none-elf-gcc` | `arm-none-eabi-gcc` | `Makefile` |
| Exception model | EL3 vectors | ARMv7 exception modes | `startup.S` rewritten |
| MMU | 4-level long descriptor | 1-level short descriptor | `mmu.c` rewritten |
| Cache ops | DC CVAC / DC IVAC | MCR p15 c7 (DCCMVAC/DCIMVAC) | `gem.c` |
| Generic timer | `mrs cntpct_el0` | `mrrc p15, 0, ..., c14` | `timer.h`, `entropy.c` |
| GIC | GIC-400 (GICv2) | GIC-390 (GICv2) | `gic.c` (same driver, different base) |
| GIC base addrs | `0xF901xxxx` | `0xF8F0xxxx` | `board.h` |
| UART | Cadence at 0xFF000000 | Cadence at 0xE0000000 | `board.h` (same driver) |
| Clock + reset | CRL_APB at 0xFF5E0000 | SLCR at 0xF8000000 | `board.h` (gem.c clock helper needs rewrite) |
| GEM count | 4 (GEM0-3) | 2 (GEM0-1) | `board.h` |
| On-board RJ45 | GEM3 (INTID 95) | GEM0 (INTID 54) | `board.h` |
| BD format | 8-byte (DMACR[30]=0) | 8-byte (no 64-bit option) | `gem.c` (unchanged) |

## Build

```
cd src/port/zynq7000
make CROSS_COMPILE=arm-none-eabi-
```

Output: `app.elf`.

## Known unknowns (to validate on hardware)

- `gem.c` still has `NWCFG_DWIDTH_64` available; it must not be set on Zynq-7000 (the A9 AXI master path is 32-bit; the older GEM revision does not implement that bit). Confirm `GEM_NWCFG` bit 21 stays clear during bring-up.
- `gem.c` clock + reset code references `SLCR_GEM0_CLK_CTRL` / `SLCR_GEM_RST_CTRL`. The actual sequence will need an unlock (`SLCR_UNLOCK = 0xDF0D`) wrapper that does not exist in the AArch64 port.
- DP83867 MDIO address on Zynq-7000 boards varies (ZedBoard uses a Marvell 88E1518; ZC702 / MicroZed differ). The shipped `phy_dp83867.c` only covers DP83867; confirm the actual on-board PHY before flashing.
- `entropy.c` uses ARMv7 `MRRC p15, 1, ..., c14` for `cntvct_el0` (virtual counter). Cortex-A9 implements the generic timer differently from later cores; if `CNTFRQ` reads 0 the fallback (333 MHz) may be way off, causing `delay_us` to misbehave. Check `CNTFRQ` first thing during bring-up.
- ARMv7 IRQ trampoline in `startup.S` uses `srsdb` + `rfeia` -- standard but assumes the IRQ-mode stack is reachable; an early IRQ before SVC stack init would fault. The current code disables IRQ until `irq_enable` is called after wolfIP/GEM init, which avoids the race.
- `mmu.c` uses 1 MB sections (16 KB L1 table). All of DDR (1 GB) is mapped Normal-WB cacheable; the OCM high mapping at 0xFFFC0000 is in section 0xFFF mapped Normal-WB. PS peripherals are Device. The DMA carve-out logic from the AArch64 port is dropped because cache_clean/cache_inval handles coherency; reintroduce if the GEM exhibits coherency issues.

## What was reused unchanged from ZCU102

- `gem.c` core logic (BD ring, ISR, eth_send, eth_poll, MDIO) -- only the cache ops were rewritten for ARMv7 CP15.
- `phy_dp83867.c` -- the DP83867 driver is host-architecture-independent.
- `main.c` -- mostly identical; the AArch64-specific `exception_report` was dropped, the DEBUG_GIC self-test was `#if 0`-ed pending ARMv7 equivalents.
- `entropy.c` -- only the timer-read primitive was rewritten.

## Files

Same layout as `src/port/zcu102/`. See that port's README for per-file responsibilities.

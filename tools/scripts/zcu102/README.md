# ZCU102 JTAG bare-metal loader

`jtag_load.tcl` is a generic AArch64 bare-metal JTAG loader for the
Xilinx ZCU102 (ZynqMP Cortex-A53 EL3). It lets you iterate on
bare-metal firmware without swapping the SD card.

The src/port/amd/boards/zcu102/ directory has a wolfIP-specific wrapper around
this same pattern at `src/port/amd/boards/zcu102/jtag/boot.tcl`; this directory
holds the standalone reference so the pattern can be cloned into
other wolfSSL projects (wolfBoot, wolfTPM, wolfHSM, etc.) targeting
the same SoC.

## Usage

```sh
source /opt/Xilinx/2025.2/Vitis/settings64.sh

# Build and produce a flat binary for the loader.
aarch64-none-elf-objcopy -O binary myapp.elf myapp.bin

APP_ELF=$PWD/myapp.elf \
APP_BIN=$PWD/myapp.bin \
FSBL_PSU_INIT_TCL=/path/to/petalinux/hw-description/psu_init.tcl \
xsdb tools/scripts/zcu102/jtag_load.tcl
```

ZCU102 must be in JTAG boot mode (SW6 = all ON). The loader expects
hw_server already running on localhost (Vitis starts it by default).

## What it does

1. `rst -system`, then `mwr 0xFF5E0200 0x0100` to force CSU JTAG bootmode
2. `psu_init` + `psu_post_config` to bring DDR / clocks / MIO / UART up
3. Re-initialize UART0 baud (psu_init alone doesn't always finish this)
4. Load `APP_BIN` word-by-word via `mwr -force` to OCM (0xFFFC0000)
5. Install a `b .` bootloop at the default RVBAR (0xFFFF0000)
6. `rst -processor` + `stop` + `rwr pc <entry>` + `con`

## Constraints

- App `.text` + `.rodata` + `.data` must fit in OCM (256 KiB).
- App `.bss`, page tables, DMA buffers go in DDR, **above 0x10000**
  (the first 16 KiB of DDR has a JTAG-DAP alias bug; avoid).
- MMU page tables must map the OCM 2 MiB block (entry 511 of an L2
  covering 0xC0000000..0xFFFFFFFF) as Normal + executable. Otherwise
  `mmu_enable` faults on the next instruction fetch.

## Five traps this loader avoids

The corresponding wolfIP-specific loader at `src/port/amd/boards/zcu102/jtag/boot.tcl`
has inline comments at each step. The traps are:

1. DDR DAP 16-KiB alias at low addresses (use OCM).
2. MMU L1 needs OCM carved out as Normal+exec (not Device+XN).
3. CSU JTAG bootmode bit must be written before psu_init.
4. `dow` to DDR breaks after psu_init - use `mwr -force` per word.
5. RVBAR bootloop at 0xFFFF0000 lets `rst -processor` be safe.

## Related

- `src/port/amd/boards/zcu102/jtag/boot.tcl` -- wolfIP-specific instance
- `tools/scripts/zynq7000/jtag_load.tcl` in `wolfBoot` -- ARMv7 analog

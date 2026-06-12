# wolfIP port: Xilinx ZCU102 (UltraScale+ MPSoC)

Bare-metal wolfIP port for the AMD/Xilinx Zynq UltraScale+ MPSoC, demoed
on the ZCU102 dev board. Targets a single Cortex-A53 core (APU 0) at
EL3, GCC bare-metal, no Xilinx Standalone BSP, no FreeRTOS, no wolfBoot.

This first milestone is aimed at a deterministic UDP-only profile
suitable for DO-178C DAL-C qualification. The application opens a
UDP echo socket on port 7 and runs a DHCP client to acquire a lease.

## What this port covers

- PS-GEM3 (on-board RJ45) at 1 Gbps via the TI DP83867IR PHY (RGMII).
- Poll-driven RX and TX (`gem_isr()` is called from the main loop via
  `gem_rx_swq_poll`, the same model as the Versal/ZC702 ports). The GEM
  RX interrupt is left unarmed: an enabled RX-complete interrupt storms
  the CPU under sustained TCP-rate RX and wedges the stack. The GICv2 +
  `SCR_EL3.IRQ=1` IRQ plumbing in `startup_aarch64.S` / `gic_gicv2.c`
  remains in place but dormant.
- Clean-room Cadence GEM driver - no XEmacPs, no Xilinx Standalone BSP,
  no `xparameters.h`. All register base addresses live in `board.h`.
- MMU at EL3 with a static page table: DDR Normal WB, peripherals
  Device-nGnRnE, and an OCM (0xFFFC0000+) Normal-WB executable block
  where this app currently lives (text, data, BSS, page tables, and
  the GEM BDs/frame buffers all in OCM). GEM DMA coherency is handled
  with explicit DC CVAC / IVAC ops in `gem_core.c`. A Normal-NC DMA
  carve-out is reserved in the L2_DDR table for a future layout that
  spills `.dma_buffers` into DDR but is dormant today.
- PS-UART0 polled console (USB-UART on the ZCU102 board, channel 0).
- DHCP client and a UDP echo demo (port 7); ICMP echo reply works
  through the wolfIP core.

## What is explicitly NOT in this port yet

- Software VLAN (Daniele has a separate wolfIP-core PR in flight).
- uC/OS-II socket port (planned follow-up; trivially adapts an existing
  `bsd_socket.c`).
- Additional GEM instances (GEM0/1/2). Driver is single-instance.
- Versal Gen 1, Zynq-7000.
- wolfBoot integration. Stock Xilinx FSBL hands control directly to
  `app.elf`.
- TLS / wolfSSL.

## Hardware

- AMD/Xilinx ZCU102 evaluation board (XCZU9EG-2FFVB1156). Rev 1.0 or
  1.1 are both fine.
- USB-UART via the on-board FTDI FT4232 (host sees four `/dev/ttyUSB*`
  channels; UART0 is the standard one, typically `/dev/ttyUSB0` or the
  channel labelled "MIO" depending on board / udev).
- Ethernet via the on-board RJ45 (PS-GEM3 -> DP83867 PHY @ MDIO 0x0C).

## Build

Toolchain: ARM GNU `aarch64-none-elf-gcc`. The default is on `$PATH`;
override with `CROSS_COMPILE=...-` if needed.

```
cd src/port/amd/boards/zcu102
make CROSS_COMPILE=aarch64-none-elf-
```

Output: `app.elf`. Section sizes are printed at the end of the build.

## Build BOOT.BIN

You need a pre-built ZCU102 FSBL ELF. The simplest way to obtain one
is the Vitis "zynqmp_fsbl" template (single-click build), or PetaLinux
`petalinux-build -c bootloader`. We deliberately do NOT vendor FSBL
sources here; FSBL is a Xilinx-provided component and stock works.

Source Vitis first (so `bootgen` is on `$PATH`), then:

```
FSBL_ELF=/path/to/zynqmp_fsbl.elf make bootbin
```

Output: `BOOT.BIN` in the port directory.

The `bootbin` target always builds the app with the **DDR layout**
(`LAYOUT=ddr`, app at `0x10000000`) regardless of any `LAYOUT=` on the
command line, and forces a rebuild if the previous build used a
different layout. This is deliberate: the OCM layout links the app at
`0xFFFC0000`, which is exactly where the FSBL runs from, so an
OCM-layout `BOOT.BIN` would clobber the FSBL and never reach the app.
The FSBL initialises DDR, loads `app.elf` to `0x10000000`, and hands off
at EL3.

## Boot

### SD card boot

1. Format a microSD as FAT32.
2. Copy `BOOT.BIN` to the root of the SD card.
3. Set ZCU102 boot mode DIP SW6 to SD (positions 1-4 = ON, OFF, OFF, OFF).
4. Insert the card and power-cycle the board.

### JTAG boot (Vitis xsct)

```
xsct
% connect
% targets -set -filter {name =~ "PSU"}
% rst -system
% loadhw -hw /path/to/your-design.xsa
% targets -set -filter {name =~ "Cortex-A53 #0"}
% dow /path/to/wolfip/src/port/amd/boards/zcu102/app.elf
% con
```

If you do not have an XSA from your own design, the stock ZCU102 base
design from Vitis is fine - we only depend on the PS configuration
(DDR controller, MIO pinmuxing, IOPLL clocks) which is identical
across base designs.

### JTAG iteration (no SD swap)

This port ships a self-contained xsdb loader under `jtag/` that
power-cycles the board (via remote Pi GPIO, optional), forces JTAG
boot mode, runs `psu_init`, loads `app.elf` into OCM, and releases
A53-0 at the OCM entry. The whole app + BSS + page tables + DMA
buffers fit in the 256 KB OCM, so DDR-via-JTAG flakiness is avoided.

```
./jtag/boot.sh                  # one-shot
./jtag/boot_iter.sh             # build + power-cycle + load loop
```

See `jtag/boot.tcl` for the actual xsdb sequence.

## Expected UART output

```
=== wolfIP ZCU102 (UltraScale+ A53-0 EL3) ===
MMU on, caches on. Bringing up GIC-400...
Initializing wolfIP stack...
Bringing up GEM3 (RGMII, DP83867)...
GEM3: PHY at MDIO addr=0x0000000C
DP83867: ID1=0x00002000 ID2=0x0000A231
DP83867 link: 1000 Mbps FD
  link UP, PHY=0x0000000C
Starting DHCP client...
DHCP bound:
  IP: 192.168.1.50
  Mask: 255.255.255.0
  GW:   192.168.1.1
Opening UDP echo socket on port 7
Ready. Try: nc -u <leased-ip> 7
```

## Verification

From a host on the same subnet as the board:

```
$ ping -c 3 192.168.1.50
$ echo "hello wolfip" | nc -u -w1 192.168.1.50 7
hello wolfip
```

UART capture via the `uart-monitor` skill (add a board entry pointing
at `/dev/ttyUSB0` and 115200 8N1).

## Files

| File                | Purpose |
|---------------------|---------|
| `Makefile`          | Build app.elf and BOOT.BIN |
| `target.ld`         | aarch64 EL3 linker script - separate RX/RW segments, 2 MB DMA region |
| `startup_aarch64.S`         | EL3 vectors, BSS clear, MMU/main bring-up, IRQ trampoline |
| `board.h`           | PS register base addresses, GIC SPI IDs |
| `mmu_aarch64.c` / `.h`      | EL3 page tables (T0SZ=32, 1 GB L1 + 2 MB L2 for DDR + DMA carve-out) |
| `gic_gicv2.c` / `.h`      | GIC-400 (GICv2) minimal driver |
| `uart_cadence.c` / `.h`     | PS-UART0 polled console |
| `gem_core.c` / `.h`      | Cadence GEM driver (PS-GEM3): BDs, polled-RX/TX, MDIO, cache maintenance |
| `phy_dp83867.c` / `.h` | TI DP83867IR init + RGMII skew + AN + RX_CTRL strap quirk |
| `app.c`            | wolfIP init, DHCP client, UDP echo on port 7, memset/memcpy wrappers |
| `config.h`          | wolfIP build profile (UDP-only intent) |
| `bootgen/boot.bif`  | bootgen template (substitutes `${FSBL_ELF}` and `${APP_ELF}`) |
| `bootgen/build_bootbin.sh` | renders the bif and invokes bootgen |
| `jtag/boot.sh` / `.tcl` | xsdb loader for OCM-only JTAG iteration |

## Notes for cert / DAL-C

- No Xilinx Standalone BSP linked in. `aarch64-none-elf-gcc` newlib
  provides `memcpy`/`memset` only.
- No dynamic allocation. All buffers static in BSS or `.dma_buffers`.
- No floating point (`-mgeneral-regs-only`).
- The MAC address is hard-coded in `board.h`. Replace with a
  per-board value (e.g., read from EEPROM or PS_VERSION fuses) for
  production; we keep static for repeatability in the lab.
- The wolfIP core currently sizes its timer heap as
  `MAX_TIMERS = MAX_TCPSOCKETS * 3`. This port sets `MAX_TCPSOCKETS=2`
  in `config.h` so DHCP / ARP can schedule timers; the application
  does not open any TCP sockets. A core wolfIP follow-up should
  decouple the timer count from TCP so the TCP code can be fully
  excluded from a DAL-C build.
- The wolfIP core triggers two false-positive GCC warnings
  (`-Wzero-length-bounds`, `-Wtype-limits`) when `MAX_TCPSOCKETS`
  reaches its lower bound. We suppress them on the wolfip.c compile
  only; the diagnostics on this port's source remain at `-Wall -Wextra
  -Werror`.
- newlib's aarch64 `memset`/`memcpy` use `dc zva`, which hangs on this
  Cortex-A53 setup even with `SCTLR_EL3.DZE=1`. We override both with
  bytewise versions in `app.c` via `-Wl,--wrap`.

## Known issues

- `MAX_TCPSOCKETS=2` is the minimum for the current wolfIP core - see
  the timer-heap note above.

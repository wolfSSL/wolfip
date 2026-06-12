# wolfIP AMD/Xilinx bare-metal ports

Bare-metal wolfIP ports for AMD/Xilinx PS-GEM SoCs, sharing one tree:

- **ZCU102** - ZynqMP, Cortex-A53, AArch64, EL3
- **Versal Gen 1 / VMK180** - Cortex-A72, AArch64, EL3
- **Zynq-7000 / ZC702** - Cortex-A9, ARMv7-A, SVC

All three are brought up on real hardware (DHCP, ICMP ping, UDP echo).

## Layout

Shared code lives once; each board's Makefile selects which components to
compile (build-selected files, not `#ifdef` forks).

```
common/    arch- and SoC-independent
  app.c app.h          shared UDP-echo + DHCP demo (board hooks: board.c)
  gem_core.c gem.h     shared Cadence GEM core (init, MDIO, polled TX, diag)
  gem_regs.h gem_port.h  GEM register map / internal hook interface
  uart_util.c          shared UART helpers (puts/puthex/putdec/putip4)
  entropy.c            memuse-pattern RNG (counter via arch_counter64)
  wolfip_config.h      shared wolfIP profile (board config.h includes it)
  gic.h uart.h mmu.h   driver API headers

arch/aarch64/  cache.h timer.h mmu_aarch64.c startup_aarch64.S exception_aarch64.c
arch/armv7/    cache.h timer.h mmu_armv7.c   startup_armv7.S

ip/        per-IP-block drivers (build-selected)
  uart_cadence.c uart_pl011.c          UART
  gic_gicv2.c gic_gicv3.c              GIC
  gem_swq.c gem_rx_swq_poll.c gem_rx_poll.c   RX delivery model (all boards poll)
  gem_rx_irq.c                         reference IRQ-driven RX (not built; see file)
  phy_dp83867.c phy_marvell.c          PHY drivers
  phy_dispatch_dp83867.c phy_dispatch_multi.c   PHY vendor dispatch

boards/<board>/   the build root for each board (keeps app.elf + JTAG in place)
  board.h board.c board_gem.c config.h Makefile target*.ld jtag/ [bootgen/]
```

## Component selection per board

| Component | ZCU102 | Versal | Zynq-7000 |
|-----------|--------|--------|-----------|
| arch      | aarch64 | aarch64 | armv7 |
| UART      | cadence | pl011 | cadence |
| GIC       | gicv2 | gicv3 | gicv2 |
| GEM RX    | gem_rx_swq_poll + gem_swq | gem_rx_swq_poll + gem_swq | gem_rx_poll |
| PHY       | dp83867 | dp83867 | dp83867 + marvell (multi) |
| GEM inst  | GEM3 | GEM0 | GEM0 |

## Build

```
cd boards/zcu102   && make CROSS_COMPILE=aarch64-none-elf-
cd boards/versal   && make CROSS_COMPILE=aarch64-none-elf-
cd boards/zynq7000 && make CROSS_COMPILE=arm-none-eabi-
```

Output is `app.elf` in the board directory. See each board's `README.md`
for the JTAG / BOOT.BIN flow and bring-up notes.

## Throughput test (SPEED_TEST)

The default build runs the UDP echo + DHCP demo. Building with
`CFLAGS_EXTRA=-DSPEED_TEST` instead brings up a TCP throughput server on
**port 9** (a discard/chargen-style sink + source, in the spirit of iperf but
without iperf3's JSON control channel, which is impractical on bare metal). On
each accepted connection the board sinks everything the host sends (RX) and, in
the same window, sources chargen data whenever the socket is writable (TX); on
close it prints the byte totals and an average rate over the UART:

```
cd boards/zcu102 && make CROSS_COMPILE=aarch64-none-elf- CFLAGS_EXTRA=-DSPEED_TEST
```

Measure from a host on the same subnet as the board (replace `<ip>` with the
leased address printed at DHCP bind):

```
# RX (host -> board): how fast the board sinks
dd if=/dev/zero bs=1460 count=20000 | nc -q1 <ip> 9

# TX (board -> host): how fast the board sources
nc <ip> 9 </dev/null | pv -r >/dev/null
```

The board's own `SPEED done ... RX/TX bytes (~B/s)` UART line is the
authoritative figure (it times the connection with the hardware clock). Note
the RX and TX counters cover the same connection window, so during the RX run
the board is also back-sourcing; the printed RX B/s is the host->board goodput
under that concurrent load. iperf3 host-to-host on the same link is a useful
*link* reference, but the board is not an iperf3 endpoint.

The `SPEED_TEST` build also widens the TCP window (`RXBUF_SIZE`/`TXBUF_SIZE` to
`LINK_MTU * 6` in `config.h`) and trims the UDP socket count to keep the larger
per-socket buffers inside the 256 KB OCM budget.

### Results

Single Cortex core, 1 Gbps RGMII link, MTU 1500, host on the same switch.
RX is the board's UART `~B/s` line (host -> board); TX is host-measured
(board -> host). Bytes x8 for Mbps.

| Board (SoC, core)            | Layout / boot   | RX Mbps | TX Mbps |
|------------------------------|-----------------|--------:|--------:|
| VMK180 (Versal, A72 @ EL3)   | DDR (JTAG)      |   ~300  |   ~334  |
| ZCU102 (ZynqMP, A53 @ EL3)   | DDR (SD boot)   |   ~126  |   ~194  |
| ZC702 (Zynq-7000, A9 @ SVC)  | OCM (JTAG)      |    ~22  |    ~19  |
| ZCU102 (ZynqMP, A53 @ EL3)   | OCM (JTAG)      |    ~10  |     ~9  |

The single dominant factor is the **memory layout**: the OCM layout runs *all*
code (and the rings) from Normal non-cacheable OCM, so every instruction fetch
and frame copy is uncached. The DDR layout keeps code+data in cacheable DDR and
maps only the GEM DMA region non-cacheable - ~13-30x faster, as the two ZCU102
rows show directly (same SoC/core, OCM ~10/9 vs DDR ~126/194 Mbps). The faster
A72 (Versal) reaches ~300/334 on DDR.

How each DDR number was loaded: Versal's PLM trains DDR from a boot PDI, so the
DDR app loads cleanly over JTAG. On ZynqMP, JTAG writes into DDR after a bare
`psu_init` are unreliable (the load goes through the A53 with a cache flush and
either errors or lands corrupt - DDR itself is fine, a direct DAP memtest passes),
so the ZCU102 DDR figure is from an **SD boot**: `FSBL_ELF=.../zynqmp_fsbl.elf
make bootbin` produces a DDR-layout `BOOT.BIN` that the FSBL trains DDR for and
DMA-loads (no JTAG memory writes). Copy it to the SD card's FAT boot partition
and set SW6 = SD. The same applies to ZC702 (its OCM-only port has no DDR layout
yet; a DDR profile is future work).

What it took to get here:

1. **NC-map the DMA rings in the DDR layout (correctness, not just speed).**
   The DDR layout had mapped the GEM BD rings cacheable with per-BD
   `cache_clean`. Because the 8-byte BDs share 64-byte cache lines, cleaning one
   BD wrote stale neighbours back over MAC-set OWN bits and wedged the RX ring
   under sustained (TCP-rate) load - the UDP-only profile never had two BDs live
   in a line at once. The DMA region is now Normal-NC in both layouts, with
   `.dma_buffers` in its own 2 MB block so `.text` stays cacheable.
2. **Main-loop poll cadence.** The original loop called `wolfIP_poll()` then
   `delay_ms(1)`, capping the stack at ~1 poll/ms (~12 Mbps) and feeding wolfIP
   a `tick++` counter that only approximated real milliseconds. It now
   busy-polls with a real-millisecond clock from the hardware timer
   (`timer_now()/timer_freq()`), which also de-skews every DHCP/TCP/ARP timeout.
3. **Drain RX fully, bounded TX per event.** Reading one chunk per READABLE
   left the advertised TCP window stuck (~2 KB) and deadlocked; the SPEED server
   now drains the rx buffer each event and does a bounded tx fill.
4. **Word-wise `memcpy`/`memset`.** Frame-staging copies are 8 bytes at a time
   (bytewise tail), which matters for the non-cacheable DMA buffers.

Notes / remaining levers: ZCU102 uses the same poll-driven RX as the other two
boards - its original IRQ-driven RX storms the CPU under sustained RX load.
A DDR/BOOT.BIN profile for the OCM boards (cached code) and draining more than
one frame per poll are the next levers.

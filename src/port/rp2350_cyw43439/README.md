# wolfIP port: Pi Pico 2 W (RP2350 + CYW43439)

Bare-metal wolfIP port for the [Raspberry Pi Pico 2 W](https://www.raspberrypi.com/products/raspberry-pi-pico-2/) board (RP2350 dual-arch SoC + Infineon CYW43439 Wi-Fi radio).

## Highlights

- **Dual-arch build**. `make CORE=m33` for Cortex-M33, `make CORE=hazard3` for Hazard3 RISC-V. Same wolfIP + supplicant source, different toolchain and entry stub.
- **Firmware-loader-only CYW43439 driver**. Clean-room gSPI transport + SDPCM/CDC/BDC ioctl shim. No `cyw43-driver`, no WHD source reuse. The Infineon firmware blob is loaded into the radio's RAM at boot and is the only binary artifact carried over.
- **WPA2-PSK is firmware-offload**. The CYW43439 is a FullMAC radio: its firmware runs the WPA2-PSK 4-way handshake internally once the host pushes the passphrase (`WLC_SET_WSEC_PMK` + `sup_wpa=1`). Host-run PSK is not supported on this firmware. The in-tree `src/supplicant/` (linked under `WOLFIP_WITH_SUPPLICANT`) is for the paths where EAPOL *does* reach the host: WPA3-SAE external-auth and 802.1X/EAP. It is kept cross-built and linked so those paths are ready, but it is not on the PSK data path.

## Status

| Milestone                         | State |
|-----------------------------------|-------|
| Scaffolding (linker, startup)     | done  |
| Boot + clocks + UART console      | done, hardware-proven |
| gSPI/PIO transport + 32-bit mode  | done, hardware-proven |
| Backplane + ALP + firmware load   | done, hardware-proven (firmware RUNNING) |
| SDPCM/CDC ioctl control plane     | done, hardware-proven (WLC_UP + STA MAC read) |
| Join + event-driven assoc state   | done, hardware-proven (`cyw43_join_psk` associates to a real AP; `cyw43_poll` decodes `WLC_E_AUTH`/`ASSOC`/`PSK_SUP`) |
| WPA2-PSK firmware 4-way (offload)  | done, hardware-proven on a keyed boot (`WLC_E_PSK_SUP` fires) |
| BDC 802.3 TX/RX data path          | done, hardware-proven (DHCP exchange + bidirectional ICMP) |
| DHCP lease on real AP              | done, hardware-proven (lease bound, e.g. `10.0.4.164`) |
| Bidirectional IP                   | done, hardware-proven (ARP replies + ICMP echo 5/5, ~9 ms RTT) |
| `wolfIP_wifi_ops` impl            | done (scan still a stub) |
| Link robustness (sustained uptime) | **partial - intermittent stall + boot-to-boot keying variance** (see Open items) |
| UDP echo round-trip demo          | blocked on a keyed live window (not a wolfIP bug; see Open items) |

The control plane (boot -> firmware -> ioctl), the **join + firmware 4-way**, **DHCP**, and **bidirectional IP** are proven on a real Pico 2 W against a WPA2 AP: on a keyed boot the radio authenticates, `WLC_E_PSK_SUP` fires, DHCP binds a lease, and ICMP round-trips 5/5. What remains is link *robustness* - see "Open items" below.

Hardware validation runs against a real AP on the desk - hwsim does not validate this port (see `tools/hostapd/README.md` for the FullMAC limitation).

## Build

Requires:

- `arm-none-eabi-gcc` (M33 path) and/or `riscv32-unknown-elf-gcc` (Hazard3 path)
- `picotool` on PATH (for UF2 conversion + flash)
- A wolfSSL install with `WOLFSSL_PUBLIC_MP` if you enable SAE

```sh
# Cortex-M33 build (default)
make

# Hazard3 RISC-V build
make CORE=hazard3

# Override the SSID / PSK baked into the binary
make WIFI_SSID="my-ap" WIFI_PSK="my-passphrase"
```

## Flash and run

```sh
# Hold BOOTSEL on the Pico 2 W, plug USB, then:
make flash
# or copy app.uf2 to the RPI-RP2 mass-storage drive.

# Watch the UART console (GP0/GP1, 115200 8N1):
stty -F /dev/ttyACM0 115200 raw -echo
cat /dev/ttyACM0
```

A Picoprobe (CMSIS-DAP) attached over SWD gives you live GDB:

```sh
openocd -f interface/cmsis-dap.cfg -c "transport select swd" \
        -f target/rp2350.cfg -c "init"
gdb-multiarch app.elf -ex 'target remote localhost:3333'
```

## Pin map

| Function          | RP2350 GPIO | Notes                                          |
|-------------------|------------:|------------------------------------------------|
| UART0 TX          | GP0         | console out                                    |
| UART0 RX          | GP1         | console in                                     |
| CYW43 WL_REG_ON   | GP23        | active high; pulses radio power                |
| CYW43 SPI DATA    | GP24        | shared MOSI/MISO via 470 ohm series resistor; PIO-driven; also the chip's host-IRQ line when idle |
| CYW43 SPI CS      | GP25        | active low; CPU-driven                          |
| CYW43 SPI CLK     | GP29        | PIO side-set clock                             |

## Memory budget

| Region   | Size | Notes                                                   |
|----------|------|---------------------------------------------------------|
| Flash    | 4 MB | XIP from QSPI. ~225 KB consumed by CYW43439 blob.       |
| SRAM     | 520 KB | Generous; wolfIP + supplicant + 8 TCP + driver < 200 KB|
| Stack    | 16 KB | Reserved at top of SRAM by `target_*.ld`.               |

## Known constraints

- The CYW43439 gSPI bus is single-data-line and shares MOSI/MISO via a 470 ohm series resistor on the Pico 2 W carrier. The clean-room driver in `cyw43439_driver.c` accounts for this (PIO transport in `rp2350_pio.c`).
- The DATA line (GP24) is owned by the PIO state machine, so the chip's host-IRQ-when-idle signal cannot be read via SIO. `cyw43_poll()` therefore polls `SPI_STATUS` (F2-packet-available) rather than a GPIO; IRQ-driven RX is deferred (RP2350 erratum E9 also makes edge-IRQ GPIO modes risky).
- Bring-up logging is gated by `DEBUG_BRINGUP` (default 1 in `cyw43439_driver.h`). Build with `EXTRA_CFLAGS=-DDEBUG_BRINGUP=0` to compile out the gSPI/firmware/ioctl progress prints for a production image.
- The supplicant defaults to WPA2-PSK with `mfp_capable=1`. For WPA3-SAE targets, build with `WOLFIP_ENABLE_SAE=1 WOLFSSL_PUBLIC_MP` and set `cfg.auth_mode=WOLFIP_AUTH_SAE`.

## Open items / not yet validated

Validated end-to-end on real silicon (a WPA2 AP on the desk): on a keyed boot the radio authenticates, the firmware 4-way completes (`WLC_E_PSK_SUP`), DHCP binds a lease, and ICMP round-trips both ways. The data path (BDC 802.3 TX/RX, inbound `data_offset` handling) is exercised by the DHCP + ICMP traffic. Note: `cyw43_rsn_ie_wpa2_psk[]` MUST match the firmware's expectation (WPA2-PSK/CCMP, MFP off).

Fixes landed this pass (all hardware-validated to the point noted):

- **UDP bind to the leased IP, not `INADDR_ANY`**: wolfIP only matches a 0-bound UDP socket while DHCP is running; once the lease binds, the match needs `local_ip == dst_ip`, so the echo socket binds the actual address (`main.c`).
- **Patient DHCP, no data-path re-join**: re-issuing the radio join (SET_WSEC / sup_wpa / SET_SSID) while already associated desyncs the firmware immediately. Once associated the link is held and only the DHCP client is re-kicked (`run_dhcp_echo`).
- **gSPI interrupt servicing** (`gspi_service_irq`): the firmware gates F2 RX until latched FIFO error bits are W1C-acknowledged at register `0x04`; on a FIFO over/underflow the corrupt in-flight frame is also aborted via `SPI_FRAME_CONTROL`. Without this the RX path wedged after a burst (`[irq] cleared 0x04` confirms overflows occur).

Open robustness milestone (the real remaining work):

1. **Boot-to-boot 4-way keying variance**: `WLC_E_PSK_SUP` fires on roughly half of boots. On a non-keyed boot the firmware still associates (`WLC_E_ASSOC`) but never keys, so no data flows (`rx=0`) and DHCP spins. Candidate: gate "associated" on `PSK_SUP` (type 46) rather than `ASSOC` (type 7) and fail/retry cleanly - but a full re-join wedges the firmware after a couple of cycles, so the retry has to be careful (likely a clean DISASSOC + settle, not a bare SET_SSID).
2. **Intermittent RX stall on keyed boots**: RX freezes after a few hundred frames. The W1C-ack + F2-abort recovery pushed the stall out (98 -> 373+ frames) but did not eliminate it. WiFi power-save (`cyw43_set_powersave`, `WLC_SET_PM=0`/CAM) is a candidate cause, but the ioctl cannot be applied cleanly in the data path - it races the SDPCM control/data stream and returns `rc=-1`. Disabling power-save likely needs a control/data sequencing rework (deliver inbound frames while awaiting an ioctl response).
3. **UDP echo demo**: the round-trip is blocked only by catching a keyed live window before a stall - the bind fix above is in place and the wolfIP UDP-socket match path is verified. `tcpdump` on the host confirms both ICMP and UDP-to-port-7 egress with the correct Pico dest MAC, so the host side is not the issue.

The manual BOOTSEL-per-boot loop is the iteration bottleneck for the above - an automated BOOTSEL + reset rig (host GPIO -> the BOOTSEL test point TP6 and the RUN pin) is the recommended next investment so the keying/stall variance can be characterized over many fast cycles.

Other gaps: `op_scan` is a stub (join-by-known-SSID only); the `now_ms()` time source in `main.c` is a DWT cycle counter (fixed 12000 cyc/ms) and should move to a real RP2350 timer; the PMKSA-cache reuse path (PSK re-init) is exercised only by construction, not by a dedicated unit test; SAE-on-hardware stays software-validated this pass (the supplicant's `src/supplicant/` SAE/EAP paths are the next hardware target - see the testing note below).

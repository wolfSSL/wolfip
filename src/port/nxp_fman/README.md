# wolfIP NXP QorIQ FMan port

Ethernet driver for the NXP QorIQ Frame Manager (FMan) multirate Ethernet MAC (mEMAC) and MDIO, shared across the big-endian PowerPC DPAA1 QorIQ parts: T2080 (e6500), T1024 and T1040 (e5500). One driver serves every board; all board-specific values come from `nxp_fman_board.h`. Lead bring-up target: Curtiss-Wright VPX3-152 (T2080, FM1@DTSEC1).

## Model

The board (DDR, clocks, MMU, UART) and the FMan firmware microcode are brought up by the boot stage (wolfBoot `hal_fman_init`). This driver runs in the booted application: it brings up a single mEMAC in polled independent (BMI direct) mode and exposes the two wolfIP link-device callbacks via `struct wolfIP_ll_dev` (`poll`/`send`). There is no QMan/BMan/DPAA datapath.

It is consumed by the wolfBoot test-app (which links wolfIP core + this driver + the TFTP client). `nxp_fman.c` is the reusable driver; board parameters live in `nxp_fman_board.h`.

**Single instance.** All per-device state (base addresses, ring indices, PHY address, BD rings, buffer pools) is held in file-scope `static` variables and `WOLFIP_MAX_INTERFACES` defaults to 1, so the driver drives exactly one MAC. A second port of the same MAC type in one image would share that state; move it behind `ll->priv` first.

## Files

- `nxp_fman.h` - public API + mEMAC/MDIO register map (offsets from `FMAN_BASE`).
- `nxp_fman.c` - driver: big-endian register access, MDIO clause-22 read/write, PHY detect/reset/autoneg, SGMII PCS or RGMII interface select, and the wolfIP poll/send callbacks.
- `nxp_fman_board.h` - board parameters (CCSRBAR, mEMAC index, PHY address, MDIO clock divider, interface mode). All overridable from CFLAGS.
- `config.h` - wolfIP compile-time configuration for this port.

## Board parameters

All overridable from CFLAGS. The CCSRBAR default tracks the board define (`BOARD_CW_VPX3152` -> relocated `0xEF000000`, otherwise the QorIQ reset default `0xFE000000` for the RDB / NAII 68PPC2 / T1024 / T1040). `nxp_fman_init()` probes `NXP_FMAN_PHY_ADDR` first, then scans the MDIO bus and returns the first responder. On a multi-port board several DTSEC PHYs share one MDIO bus, so the scan can return the wrong port's PHY -- set `NXP_FMAN_PHY_ADDR` explicitly to the PHY wired to your `NXP_FMAN_MEMAC_IDX` port (read it from the board device tree). Likewise set the MAC-to-PHY interface (SGMII vs RGMII via `NXP_FMAN_IF_SGMII`) and the mEMAC/FM port per board if they differ from FM1@DTSEC1.

| Define | VPX3-152 value | Notes |
|---|---|---|
| `NXP_FMAN_CCSRBAR` | `0xEF000000` | CW relocates CCSRBAR; RDB/NAII/T1024/T1040 default `0xFE000000` (auto by board define) |
| `NXP_FMAN_MEMAC_IDX` | `1` | FM1@DTSEC1 -> mEMAC1 |
| `NXP_FMAN_MDIO_EMI` | `1` | Dedicated 1G MDIO at `FMAN_BASE + 0xFC000` |
| `NXP_FMAN_PHY_ADDR` | `0x2` | AR8031 on FM1@DTSEC1 (probed first, then bus scan). Set explicitly on multi-port boards -- the scan returns the first responder, which may be another port's PHY (NAII DTSEC3 = addr `0x0`) |
| `NXP_FMAN_MDIO_CLKDIV` | `258` | QorIQ default |
| `NXP_FMAN_IF_SGMII` | `1` | `1` = SGMII (configures the internal PCS), `0` = RGMII |

## Interface mode

`NXP_FMAN_IF_SGMII=1` (default) programs the internal SGMII PCS/TBI for in-band auto-negotiation and sets the mEMAC `IF_MODE` to GMII. `NXP_FMAN_IF_SGMII=0` selects RGMII (`IF_MODE_RG`) and skips the PCS step. Both modes follow the PHY speed/duplex via in-band signalling; a board needing a fixed speed can clear `IF_MODE_EN_AUTO` and set `IF_MODE_SETSP_*` instead.

## Status

Hardware-verified on three boards (two T2080/e6500, one T1040/e5500):

- **Curtiss-Wright VPX3-152** (FM1@DTSEC1, SGMII, AR8031 @ addr 2): MDIO clause-22 + PHY bring-up (id `0x004DD074`), SGMII PCS + mEMAC enable, and the full FMan independent-mode RX/TX datapath (MURAM parameter RAM, BMI ports, buffer-descriptor rings). The booted test-app reaches a DHCP lease, fetches a file over TFTP (checksum verified), and the TCP throughput benchmark (`WOLFIP_SPEED_TEST`) measures roughly 123 Mbps receive / 62 Mbps transmit from the polled single-loop stack (single-run, host driver via `nc`).
- **NAII 68PPC2** (FM1@DTSEC3 PRIME, **RGMII**, Marvell 88E1xxx id `0x0141` @ addr **0**): same driver, RGMII path (`NXP_FMAN_IF_SGMII=0`). Config flags `NXP_FMAN_MEMAC_IDX=3 NXP_FMAN_IF_SGMII=0 NXP_FMAN_PHY_ADDR=0` (from the board device tree `ethernet@e4000`); no driver code change. Booted test-app: `link=UP`, DHCP lease `10.0.4.247`, `WOLFIP_TEST: PASS`. This validated both interface modes (SGMII + RGMII) and the explicit-PHY-address path.

- **T1040D4RDB** (e5500, FM1@DTSEC4 = the "ETH0" front port, **RGMII**, Realtek RTL8211 id `0x001CC915` @ addr **4**): same driver, two-stage wolfBoot boot. Config flags `NXP_FMAN_MEMAC_IDX=4 NXP_FMAN_IF_SGMII=0 NXP_FMAN_PHY_ADDR=4`; the cabled port was identified with the test app's `-DWOLFIP_PHY_SCAN` MDIO scan (only addr 4 reported link=UP). Booted test-app: DHCP lease `10.0.4.247`, `WOLFIP_TEST: PASS`. First e5500 datapath validation (the prior two boards are e6500).

The T1024 reuses the driver unchanged (same FMan offsets, reset-default CCSRBAR); its demo is build-validated and awaits hardware.

### Per-board bring-up matrix

The driver is one file; each board differs only in which FMan port is cabled and how its PHY is wired. Set these from the board device tree (or run the test app's `-DWOLFIP_PHY_SCAN` once to find the port whose PHY reports `link=UP`). All values are `CFLAGS_EXTRA+=-D...`.

| Board | `NXP_FMAN_MEMAC_IDX` | `NXP_FMAN_IF_SGMII` | `NXP_FMAN_PHY_ADDR` | PHY | Throughput RX/TX |
|---|---|---|---|---|---|
| CW VPX3-152 (T2080) | 1 (default) | 1 (default) | 2 | AR8031 | ~123 / ~62 Mbps |
| NAII 68PPC2 (T2080) | 3 | 0 | 0 | Marvell 88E1xxx | (not benchmarked) |
| T1040D4RDB | 4 | 0 | 4 | Realtek RTL8211 | (not benchmarked) |
| T1024RDB | TBD | TBD | TBD | TBD | (awaits hardware) |

Finding the port on a new board: build the test app with `-DWOLFIP_PHY_SCAN`, boot, and read the `wolfIP: MDIO scan` lines -- the address reporting `link=UP` is the cabled port. Cross-reference the board DTB (`ethernet@eN000` `phy-handle` -> `ethernet-phy@A reg=<A>` and `phy-connection-type`) to confirm the mEMAC index and SGMII-vs-RGMII.

### Running the throughput benchmark

Build with `WOLFIP_SPEED_TEST=1`; the board acquires a DHCP lease then runs a one-connection TCP server on port 9 that both sinks (RX) and sources (TX), printing `SPEED done <ms> RX <B> (~<B/s>) TX <B> (~<B/s>)` when the connection closes. Drive each direction separately from a host on the same subnet (`<ip>` = the board's DHCP address):

```
# RX (board receives ~73 MB, then prints): -q1 closes the socket on EOF
dd if=/dev/zero bs=1460 count=50000 | nc -q1 <ip> 9 >/dev/null
# TX (board sources for ~8 s, host reads): timeout closes the socket
timeout 8 nc <ip> 9 </dev/null | pv -r >/dev/null
```

`nxp_fman_init()` populates the `struct wolfIP_ll_dev` (mac/ifname/mtu/poll/send), runs the FMan common init + per-port setup + interface config + enable, then detects the PHY (`nxp_fman_phy_read()` reads PHY registers for diagnostics). `eth_poll()`/`eth_send()` move frames through the BD rings with explicit e5500/e6500 cache maintenance (`dcbf`).

## Build

The driver is built by its consumer (the wolfBoot test-app) with the PowerPC cross-compiler, e.g.:

```
powerpc-linux-gnu-gcc -mcpu=e6500 -mbig-endian -I<wolfip-root> -Isrc/port/nxp_fman \
    -c src/port/nxp_fman/nxp_fman.c
```

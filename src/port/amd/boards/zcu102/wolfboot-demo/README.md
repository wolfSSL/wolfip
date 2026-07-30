# wolfBoot + wolfIP on AMD/Xilinx ZynqMP (ZCU102)

Secure boot of a bare-metal **wolfIP** TCP/IP application with **wolfBoot** on the ZCU102, booting from SD card. wolfBoot verifies the application's RSA-4096 / SHA3 signature before every boot, and the running application fetches a signed firmware update over the network and applies it to the SD card itself.

## Boot chain

```
BootROM -> FSBL -> PMUFW -> BL31 (ATF, EL3) -> wolfBoot (EL2) -> wolfIP app (EL2)
                                                   |
                                                   +-- verify RSA-4096 / SHA3 signature, then load
```

`BOOT.BIN` (on the FAT boot partition) carries FSBL + PMUFW + BL31 + wolfBoot. The wolfIP application is a **separate signed image** on the `OFP_A` SD partition; wolfBoot authenticates it and loads it to DDR `0x10000000` (matching the app's `LAYOUT=ddr` link address), then hands off at EL2. The app runs DHCP, a UDP echo/control service, and the network update logic.

This demo lives inside the wolfIP ZCU102 port (`src/port/amd/boards/zcu102/`). It builds the app in the parent directory (with the `OTA=1 EL=2 LAYOUT=ddr` options added by the OTA support) and drives an external wolfBoot checkout to sign it and assemble `BOOT.BIN`. For the plain bare-metal port (stock FSBL -> app, no wolfBoot), see the parent [`../README.md`](../README.md), `../bootgen/`, and `../flash_sd.sh`; this `wolfboot-demo/` is the secure-boot + OTA variant.

## Prerequisites

- **wolfIP** - this repo (no external clone needed); the app is built in the parent directory.
- **wolfBoot** - an external checkout of [wolfSSL/wolfBoot](https://github.com/wolfSSL/wolfBoot), by default `../wolfBoot` next to this wolfIP checkout: `git clone https://github.com/wolfSSL/wolfBoot ../../wolfBoot` (override with `WOLFBOOT=/path/to/wolfBoot`). Provides the `zynqmp_sdcard.config`, the sign/keygen tools, and the SD/disk drivers the OTA app compiles in.
- **FSBL / PMUFW / BL31** - board- and tool-specific. Either use the AMD-hosted prebuilts (`git clone --branch xlnx_rel_v2024.2 https://github.com/Xilinx/soc-prebuilt-firmware.git`, then `FW=<path>/soc-prebuilt-firmware/zcu102-zynqmp`), or build your own (FSBL + PMUFW from Vitis/PetaLinux; BL31 from Arm Trusted Firmware, `make PLAT=zynqmp RESET_TO_BL31=1`). Point `FW=` at a directory holding `zynqmp_fsbl.elf`, `pmufw.elf`, `bl31.elf`.
- **Toolchain + tools** - the `aarch64-none-elf-` (bare-metal newlib) GCC and `bootgen` (Vitis) on `PATH`.

## Build

```
./build.sh
```

This builds wolfBoot for the ZynqMP SD config (`zynqmp_sdcard.config`, RSA-4096 / SHA3, generating a signing key), builds and signs the `EL=2 LAYOUT=ddr` wolfIP app at **both v1 and v2**, and assembles `out/BOOT.BIN`. Outputs:

| File | Purpose |
|------|---------|
| `out/BOOT.BIN` | bootloader chain (FSBL+PMUFW+BL31+wolfBoot) |
| `out/wolfip_app_v1_signed.bin` | the app signed v1 - goes to `OFP_A` |
| `out/wolfip_app_v2_signed.bin` / `out/wolfip_update.bin` | signed v2 - the network update |

## Program the SD card

A stock PetaLinux ZCU102 SD card (MBR: boot / OFP_A / OFP_B / rootfs) works as-is. For a blank or repurposed card, create that layout first (this ERASES the disk):

```
SD=/dev/sdX ./partition-sd.sh
```

Then write the bootloader + app:

```
SD=/dev/sdX ./program-sd.sh
```

This copies `BOOT.BIN` into the FAT boot partition and `dd`s the signed v1 app to the raw `OFP_A` partition (needs root). Add `WIPE_OFP_B=1` to also clear `OFP_B` so the board boots `A:v1` fresh (handy for demoing the update). Then put the card in the ZCU102, set boot-mode `SW6 = SD`, and power on.

## Run

On the serial console (PS-UART0, 115200 8N1) you should see FSBL -> wolfBoot (which verifies the signature) -> the wolfIP banner, DHCP bind, and `Ready`. A modified or unsigned `OFP_A` image fails wolfBoot's check and is not booted.

## Signed firmware update (over the network)

The running app fetches a newer signed image over **TFTP**, writes it to the `OFP_B` SD partition, and resets. The config is version-selecting (`WOLFBOOT_NO_PARTITIONS=1`, "boot the higher version"), so no update flag is needed: wolfBoot verifies both `OFP_A` (v1) and `OFP_B` (v2), boots the higher version, and rolls back to `OFP_A` if `OFP_B` ever fails to verify.

What makes this notable is *how* the app reaches the SD card: it reuses **wolfBoot's own SD-host and disk drivers** (`$WOLFBOOT/src/sdhci.c`, `disk.c`, `gpt.c`) by compiling that same source straight into the application (the `OTA=1` path in the app `Makefile`), behind a small EL2 platform shim (`boards/zcu102/sdhci_shim.c`: register access, timer, SDMA cache maintenance). One driver, two consumers, no runtime hand-off.

Run it once the app is at `Ready` (the app fetches from the sender's host, so run this on a machine on the board's subnet that has a TFTP server serving `TFTP_ROOT`):

```
BOARD_IP=<board-ip> ./update.sh
```

`update.sh` stages `out/wolfip_update.bin` into the TFTP root (default `/srv/tftp`, override `TFTP_ROOT=`) and sends the `UPDATE` trigger to the board's port 7.

### Expected console

```
Versions, A:1 B:0
Attempting boot from P:A
Verifying image signature...done
Firmware Valid.
=== wolfIP ZCU102 (UltraScale+ A53-0 EL2) ===
DHCP bound:
  IP: 10.0.4.140
Ready. Try: nc -u <leased-ip> 7

UDP echo: 6 bytes from 10.0.4.24
OTA: init SD card...
OTA: SD ready, reading MBR...
OTA: requesting 'wolfip_update.bin' from 10.0.4.24
OTA: staging update to RAM
......
OTA: writing 110208 bytes to OFP_B (part 2)...
OTA: update staged to OFP_B
OTA: transfer complete - resetting to apply update      <- intentional reset, not a crash

[board resets]
Versions, A:1 B:2
Attempting boot from P:B                                <- now boots the v2 update
Verifying image signature...done
Firmware Valid.
```

The reset after "update staged" is intentional - the app reboots so wolfBoot re-evaluates and picks the higher version. A tampered or unsigned download simply fails wolfBoot's signature check on the next boot and the board stays on v1.

### Notes

- **Security model** - the `UPDATE` trigger itself is unauthenticated, but every image is RSA-4096 / SHA3 verified by wolfBoot before it ever boots, so the trust boundary is the signature, not the trigger. The worst a rogue trigger can do is cause a download that wolfBoot then rejects.
- **TFTP options** - the client uses 512-byte blocks and windowsize 1: the most compatible settings, which also keep large UDP bursts off the app's poll-driven receive path.

## Layout

| File | Purpose |
|------|---------|
| `build.sh` | Build wolfBoot + sign the app (v1 + v2) + assemble `BOOT.BIN` |
| `program-sd.sh` | Write `BOOT.BIN` + signed app to an SD card (`WIPE_OFP_B=1` for a clean slate) |
| `partition-sd.sh` | Create the demo MBR layout on a blank card |
| `update.sh` | Stage the update image + trigger it over the network |
| `boot.bif.in` | bootgen template (FSBL/PMUFW/BL31/wolfBoot) |
| `out/` | Build output |
